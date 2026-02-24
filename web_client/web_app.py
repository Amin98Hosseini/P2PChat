#!/usr/bin/env python3
"""
Web bridge for P2PChat.

This adds browser access without modifying existing desktop/server files.
The bridge logs into the existing TCP server as a normal client and exposes
WebSocket events to the browser.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import secrets
import socket
import threading
from urllib.parse import parse_qs
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

HOST = "127.0.0.1"
PORT = 8000
MAX_MESSAGE_LEN = 64 * 1024
MAX_FILE_LEN = 25 * 1024 * 1024
WEB_GATE_PASSWORD = os.getenv("WEB_GATE_PASSWORD", "admin1234")
AUTH_COOKIE = "p2pchat_web_auth"


def derive_key(password: str, length: int = 32) -> bytes:
    return hashlib.sha256(password.encode("utf-8")).digest()[:length]


def encrypt_text(msg: str, password: str) -> str:
    key = derive_key(password)
    plain = msg.encode("utf-8")
    cipher = bytearray(b ^ key[i % len(key)] for i, b in enumerate(plain))
    return base64.b64encode(cipher).decode("utf-8")


def decrypt_text(enc_msg: str, password: str) -> str:
    key = derive_key(password)
    cipher = base64.b64decode(enc_msg.encode("utf-8"))
    plain = bytearray(b ^ key[i % len(key)] for i, b in enumerate(cipher))
    return plain.decode("utf-8")


def encrypt_file_data(data: bytes, password: str) -> bytes:
    key = derive_key(password)
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def decrypt_file_data(data: bytes, password: str) -> bytes:
    key = derive_key(password)
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def recv_until_newline(sock: socket.socket) -> str | None:
    data = bytearray()
    try:
        while True:
            chunk = sock.recv(1)
            if not chunk:
                return None
            if chunk == b"\n":
                break
            data.extend(chunk)
        return data.decode(errors="ignore")
    except OSError:
        return None


class RelayClient:
    def __init__(self, username: str, server_ip: str, server_port: int, group_password: str):
        self.username = username
        self.server_ip = server_ip
        self.server_port = server_port
        self.group_password = group_password
        self.group_id = hashlib.sha256(group_password.encode()).hexdigest()

        self.sock: socket.socket | None = None
        self.stop_event = threading.Event()
        self.thread: threading.Thread | None = None

        self.loop = asyncio.get_running_loop()
        self.queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self.verified_group_members: set[str] = {username}

    def _queue_event(self, payload: dict[str, Any]) -> None:
        self.loop.call_soon_threadsafe(self.queue.put_nowait, payload)

    def _connect(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((self.server_ip, self.server_port))
        sock.settimeout(None)

        sock.sendall(f"LOGIN {self.username}\n".encode())
        login_resp = recv_until_newline(sock)
        if not login_resp:
            sock.close()
            raise RuntimeError("Server closed during login")
        if not login_resp.startswith("OK"):
            sock.close()
            if login_resp.startswith("ERROR"):
                raise RuntimeError(login_resp.replace("ERROR", "", 1).strip() or "Login failed")
            raise RuntimeError(f"Unexpected login response: {login_resp}")

        sock.sendall(f"GROUP {self.group_id}\n".encode())
        self.sock = sock

    def start(self) -> None:
        self._connect()
        assert self.sock is not None
        self.sock.sendall(b"GET_ONLINE_USERS\n")
        self._send_group_beacon()

        self.thread = threading.Thread(target=self._receiver_loop, daemon=True)
        self.thread.start()
        self._queue_event(
            {
                "type": "connected",
                "username": self.username,
                "group_id_prefix": self.group_id[:8],
            }
        )

    def close(self) -> None:
        self.stop_event.set()
        try:
            if self.sock:
                self.sock.close()
        except OSError:
            pass
        self.sock = None

    def send_message(self, target: str, msg: str) -> None:
        if not self.sock:
            raise RuntimeError("Not connected")
        enc = encrypt_text(msg, self.group_password)
        payload = enc.encode("utf-8")
        if len(payload) > MAX_MESSAGE_LEN:
            raise RuntimeError("Message is too large")
        header = f"SEND_MSG {target} {len(payload)}\n".encode()
        self.sock.sendall(header + payload)

    def send_file(self, target: str, filename: str, file_data: bytes) -> None:
        if not self.sock:
            raise RuntimeError("Not connected")
        if len(file_data) > MAX_FILE_LEN:
            raise RuntimeError("File is too large")

        enc_filename = encrypt_text(filename, self.group_password)
        enc_data = encrypt_file_data(file_data, self.group_password)
        header = f"SEND {target} {enc_filename} {len(enc_data)}\n".encode()
        self.sock.sendall(header + enc_data)

    def request_online(self) -> None:
        if self.sock:
            self.sock.sendall(b"GET_ONLINE_USERS\n")

    def _send_group_beacon(self) -> None:
        if not self.sock:
            return
        beacon = f"GROUP_BEACON:{self.username}"
        enc = encrypt_text(beacon, self.group_password).encode("utf-8")
        header = f"SEND_MSG BROADCAST {len(enc)}\n".encode()
        self.sock.sendall(header + enc)

    def _receiver_loop(self) -> None:
        assert self.sock is not None
        while not self.stop_event.is_set():
            header = recv_until_newline(self.sock)
            if header is None:
                self._queue_event({"type": "closed"})
                return

            parts = header.split()
            if not parts:
                continue

            if parts[0].upper() == "ONLINE_LIST":
                users = parts[1:] if len(parts) > 1 else []
                self._queue_event({"type": "online_list", "users": users})
                continue

            if len(parts) == 2 and parts[0].upper() == "NEW":
                peer = parts[1]
                self._queue_event({"type": "new_user", "user": peer})
                self._send_group_beacon()
                continue

            if len(parts) == 2 and parts[0].upper() == "LEFT":
                peer = parts[1]
                if peer in self.verified_group_members:
                    self.verified_group_members.discard(peer)
                self._queue_event({"type": "peer_left", "user": peer})
                continue

            if len(parts) == 3 and parts[0].upper() == "SEND_MSG":
                sender = parts[1]
                try:
                    total = int(parts[2])
                except ValueError:
                    self._queue_event({"type": "log", "message": "Invalid message size"})
                    continue

                data = bytearray()
                while len(data) < total:
                    chunk = self.sock.recv(min(4096, total - len(data)))
                    if not chunk:
                        self._queue_event({"type": "closed"})
                        return
                    data.extend(chunk)

                enc_text = data.decode("utf-8", errors="ignore")
                try:
                    plain = decrypt_text(enc_text, self.group_password)
                except Exception:
                    self._queue_event({"type": "decrypt_error", "sender": sender})
                    continue

                if plain.startswith("GROUP_BEACON:"):
                    peer_name = plain.split(":", 1)[1]
                    if peer_name and peer_name != self.username:
                        self.verified_group_members.add(peer_name)
                        self._queue_event(
                            {
                                "type": "verified_members",
                                "members": sorted(self.verified_group_members),
                            }
                        )
                    continue

                if sender != self.username:
                    self.verified_group_members.add(sender)
                self._queue_event(
                    {
                        "type": "message",
                        "sender": sender,
                        "message": plain,
                        "members": sorted(self.verified_group_members),
                    }
                )
                continue

            if len(parts) == 4 and parts[0].upper() == "SEND":
                sender, enc_name, size_str = parts[1], parts[2], parts[3]
                try:
                    total = int(size_str)
                except ValueError:
                    self._queue_event({"type": "log", "message": "Invalid file size"})
                    continue

                if total > MAX_FILE_LEN:
                    self._queue_event({"type": "log", "message": "Incoming file too large"})
                    remaining = total
                    while remaining > 0:
                        chunk = self.sock.recv(min(65536, remaining))
                        if not chunk:
                            break
                        remaining -= len(chunk)
                    continue

                data = bytearray()
                while len(data) < total:
                    chunk = self.sock.recv(min(65536, total - len(data)))
                    if not chunk:
                        self._queue_event({"type": "closed"})
                        return
                    data.extend(chunk)

                try:
                    filename = decrypt_text(enc_name, self.group_password)
                    file_bytes = decrypt_file_data(bytes(data), self.group_password)
                except Exception:
                    self._queue_event({"type": "log", "message": "Unable to decrypt incoming file"})
                    continue

                token = secrets.token_urlsafe(12)
                self._queue_event(
                    {
                        "type": "file_received",
                        "sender": sender,
                        "filename": filename,
                        "size_encrypted": total,
                        "size_decrypted": len(file_bytes),
                        "file_token": token,
                        "file_bytes_b64": base64.b64encode(file_bytes).decode("ascii"),
                    }
                )
                continue

            self._queue_event({"type": "log", "message": f"Unknown protocol: {header}"})


app = FastAPI(title="P2PChat Web Bridge")
STATIC_DIR = Path(__file__).resolve().parent / "static"
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/")
def index(request: Request):
    if request.cookies.get(AUTH_COOKIE) != "ok":
        return RedirectResponse("/login", status_code=303)
    return FileResponse(str(STATIC_DIR / "index.html"))


@app.get("/login")
def login_page() -> FileResponse:
    return FileResponse(str(STATIC_DIR / "login.html"))


@app.post("/login")
async def login_submit(request: Request):
    body = (await request.body()).decode("utf-8", errors="ignore")
    password = parse_qs(body).get("password", [""])[0]
    if password == WEB_GATE_PASSWORD:
        response = RedirectResponse("/", status_code=303)
        response.set_cookie(
            AUTH_COOKIE,
            "ok",
            httponly=True,
            samesite="lax",
            max_age=60 * 60 * 12,
        )
        return response
    return RedirectResponse("/login?error=1", status_code=303)


@app.get("/logout")
def logout():
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(AUTH_COOKIE)
    return response


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket) -> None:
    if ws.cookies.get(AUTH_COOKIE) != "ok":
        await ws.close(code=1008)
        return
    await ws.accept()

    relay: RelayClient | None = None
    send_task: asyncio.Task[Any] | None = None

    async def send_events() -> None:
        assert relay is not None
        while True:
            event = await relay.queue.get()
            await ws.send_text(json.dumps(event))

    try:
        first_raw = await ws.receive_text()
        first = json.loads(first_raw)
        if first.get("action") != "connect":
            await ws.send_text(json.dumps({"type": "error", "message": "First action must be connect"}))
            return

        username = str(first.get("username", "")).strip()
        server_ip = str(first.get("server_ip", "")).strip()
        group_password = str(first.get("group_password", ""))
        try:
            server_port = int(first.get("server_port", 12345))
        except Exception:
            await ws.send_text(json.dumps({"type": "error", "message": "Invalid server port"}))
            return

        if not username or not server_ip or not group_password:
            await ws.send_text(json.dumps({"type": "error", "message": "username/server/group password are required"}))
            return

        relay = RelayClient(
            username=username,
            server_ip=server_ip,
            server_port=server_port,
            group_password=group_password,
        )

        try:
            relay.start()
        except Exception as ex:
            await ws.send_text(json.dumps({"type": "error", "message": str(ex)}))
            return

        send_task = asyncio.create_task(send_events())

        while True:
            raw = await ws.receive_text()
            payload = json.loads(raw)
            action = payload.get("action")

            if action == "refresh_online":
                relay.request_online()
            elif action == "send_message":
                target = str(payload.get("target", "")).strip()
                message = str(payload.get("message", ""))
                if not target or not message.strip():
                    await ws.send_text(json.dumps({"type": "error", "message": "target and message are required"}))
                    continue
                relay.send_message(target, message)
            elif action == "send_file":
                target = str(payload.get("target", "")).strip()
                filename = str(payload.get("filename", "")).strip()
                file_b64 = str(payload.get("file_b64", ""))
                if not target or not filename or not file_b64:
                    await ws.send_text(json.dumps({"type": "error", "message": "target/filename/file are required"}))
                    continue
                try:
                    data = base64.b64decode(file_b64.encode("ascii"), validate=True)
                except Exception:
                    await ws.send_text(json.dumps({"type": "error", "message": "file payload is invalid"}))
                    continue
                relay.send_file(target, filename, data)
                await ws.send_text(
                    json.dumps(
                        {
                            "type": "file_sent",
                            "target": target,
                            "filename": filename,
                            "size": len(data),
                        }
                    )
                )
            elif action == "disconnect":
                break
            else:
                await ws.send_text(json.dumps({"type": "error", "message": f"Unknown action: {action}"}))

    except WebSocketDisconnect:
        pass
    finally:
        if send_task:
            send_task.cancel()
        if relay:
            relay.close()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("web_client.web_app:app", host=HOST, port=PORT, reload=False)
