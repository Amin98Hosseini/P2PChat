#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Peer‑to‑peer file / text client – GUI version.
------------------------------------------------

Features
--------
* Connect / disconnect to an arbitrary server (IP + port).
* Register with a local user id.
* Send text messages → <peer_id>  :  SEND_MSG <peer_id> <size>
* Send files       → <peer_id>  :  SEND     <peer_id> <filename> <size>
* Show incoming peers, received files and chat messages in real time.

Requirements
------------
Python 3.7+ (Tkinter is part of the stdlib)
"""

import os, socket, threading, queue
from pathlib import Path
from datetime import datetime
import tkinter as tk
from tkinter import filedialog
import base64, hashlib

# ----------------------------------------------------------------------
# -------------   Encryption helpers (XOR + Base‑64)  ------------------
my_password = "1234"          # change per user if you wish

def _derive_key(password: str, length: int = 32) -> bytes:
    return hashlib.sha256(password.encode('utf-8')).digest()[:length]

def encrypt(msg: str, password: str) -> str:
    key   = _derive_key(password)
    cipher_bytes = bytearray(b ^ key[i % len(key)] for i,b in enumerate(msg.encode()))
    return base64.b64encode(cipher_bytes).decode('utf-8')

def decrypt(encoded_msg: str, password: str) -> str:
    key  = _derive_key(password)
    cipher_bytes = base64.b64decode(encoded_msg.encode())
    plain_bytes  = bytearray(b ^ key[i % len(key)] for i,b in enumerate(cipher_bytes))
    return plain_bytes.decode('utf-8')
# ----------------------------------------------------------------------
def recv_until_newline(sock: socket.socket) -> str | None:
    data = bytearray()
    while True:
        try:
            chunk = sock.recv(1)
        except ConnectionResetError:
            return None
        if not chunk:          # remote closed
            return None
        if chunk == b"\n":
            break
        data.extend(chunk)
    return data.decode(errors="ignore")

# ----------------------------------------------------------------------
def receiver_thread(sock: socket.socket,
                    download_dir: Path,
                    ev_queue: queue.Queue,
                    stop_event: threading.Event):
    while not stop_event.is_set():
        header = recv_until_newline(sock)
        if header is None:            # socket closed
            ev_queue.put(("closed",))
            break

        parts = header.split(maxsplit=3)

        # NEW <id>
        if len(parts) == 2 and parts[0].upper() == "NEW":
            ev_queue.put(("new_user", parts[1]))

        # SEND <from> <filename> <size>
        elif len(parts) == 4 and parts[0].upper() == "SEND":
            from_id, filename, size_str = parts[1], parts[2], parts[3]
            try:
                total_bytes = int(size_str)
            except ValueError:
                ev_queue.put(("log",
                              f"[CLIENT] Bad file size sent by {from_id}"))
                continue

            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            dest_path = download_dir / f"{ts}_{from_id}_{filename}"
            ev_queue.put(("log",
                          f"Receiving {total_bytes} bytes from "
                          f"{from_id} → {dest_path}"))

            with open(dest_path, "wb") as fp:
                remaining = total_bytes
                while remaining > 0:
                    chunk = sock.recv(min(4096, remaining))
                    if not chunk:
                        ev_queue.put(("log",
                                      "[CLIENT] Connection lost mid‑file"))
                        return
                    fp.write(chunk)
                    remaining -= len(chunk)

            ev_queue.put(("file_received", from_id, dest_path))

        # SEND_MSG <from> <size>
        elif len(parts) == 3 and parts[0].upper() == "SEND_MSG":
            from_id, size_str = parts[1], parts[2]
            try:
                total_bytes = int(size_str)
            except ValueError:
                ev_queue.put(("log",
                              f"[CLIENT] Bad message size sent by {from_id}"))
                continue

            msg_bytes = bytearray()
            remaining = total_bytes
            while remaining > 0:
                chunk = sock.recv(min(4096, remaining))
                if not chunk:
                    ev_queue.put(("log",
                                  "[CLIENT] Connection lost mid‑message"))
                    return
                msg_bytes.extend(chunk)
                remaining -= len(chunk)

            # ---------- 1️⃣ Decrypt the received ciphertext ----------
            encrypted_text = msg_bytes.decode("utf-8")
            try:
                text = decrypt(encrypted_text, my_password)   # ← here!
            except Exception as exc:
                text = f"<decrypt error: {exc}>"
            ev_queue.put(("msg_received", from_id, text))

        else:   # unknown header – ignore but keep the loop going
            ev_queue.put(("log",
                          f"[CLIENT] Unrecognized protocol line: {header!r}"))
    ev_queue.put(("closed",))
# ----------------------------------------------------------------------
class P2PClientGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Peer‑to‑peer Client – GUI")
        self.geometry("700x550")

        # ----------------------------------------------
        # Networking state
        self.sock: socket.socket | None = None
        self.recv_thread: threading.Thread | None = None
        self.stop_event = threading.Event()
        self.ev_queue: queue.Queue[tuple] = queue.Queue()

        # Directory to store received files
        self.download_dir = Path.home() / "client_received"
        self.download_dir.mkdir(parents=True, exist_ok=True)

        self._build_widgets()
        self.after(100, self._process_events)   # start event loop

    # ----------------------------------------------
    def _build_widgets(self):
        """Create all UI elements."""
        pad = {"padx": 5, "pady": 3}

        # ==== Connection frame ====
        conn_frame = tk.LabelFrame(self, text="Connection")
        conn_frame.pack(fill=tk.X, **pad)

        tk.Label(conn_frame, text="Server IP:").grid(row=0, column=0,
                                                    sticky=tk.W, **pad)
        self.ip_var = tk.StringVar(value="192.168.1.101")
        tk.Entry(conn_frame, width=15, textvariable=self.ip_var).grid(
            row=0, column=1, **pad)

        tk.Label(conn_frame, text="Port:").grid(row=0, column=2,
                                                sticky=tk.W, **pad)
        self.port_var = tk.StringVar(value="12345")
        tk.Entry(conn_frame, width=6, textvariable=self.port_var).grid(
            row=0, column=3, **pad)

        tk.Label(conn_frame, text="Your ID:").grid(row=0, column=4,
                                                   sticky=tk.W, **pad)
        self.id_var = tk.StringVar(value="alice")
        tk.Entry(conn_frame, width=10, textvariable=self.id_var).grid(
            row=0, column=5, **pad)

        self.connect_btn = tk.Button(conn_frame, text="Connect",
                                     command=self._connect)
        self.connect_btn.grid(row=0, column=6, **pad)

        self.disconnect_btn = tk.Button(conn_frame, text="Disconnect",
                                        state=tk.DISABLED,
                                        command=self._disconnect)
        self.disconnect_btn.grid(row=0, column=7, **pad)

        # ==== Peer selection & message frame ====
        peer_msg_frame = tk.LabelFrame(self, text="Message")
        peer_msg_frame.pack(fill=tk.X, **pad)

        tk.Label(peer_msg_frame, text="Send to ID:").grid(row=0,
                                                        column=0,
                                                        sticky=tk.W, **pad)
        self.peer_id_var = tk.StringVar()
        tk.Entry(peer_msg_frame, width=10, textvariable=self.peer_id_var).grid(
            row=0, column=1, **pad)

        tk.Label(peer_msg_frame, text="Message:").grid(row=0,
                                                       column=2,
                                                       sticky=tk.W, **pad)
        self.msg_entry = tk.Entry(peer_msg_frame, width=40)
        self.msg_entry.grid(row=0, column=3, **pad)

        tk.Button(peer_msg_frame, text="Send Msg",
                  command=self._send_msg).grid(row=0, column=4,
                                               sticky=tk.W, **pad)

        # ==== File transfer frame ====
        file_frame = tk.LabelFrame(self, text="File Transfer")
        file_frame.pack(fill=tk.X, **pad)

        tk.Label(file_frame, text="Send to ID:").grid(row=0,
                                                     column=0,
                                                     sticky=tk.W, **pad)
        self.file_peer_id_var = tk.StringVar()
        tk.Entry(file_frame, width=10,
                 textvariable=self.file_peer_id_var).grid(row=0, column=1,
                                                          **pad)

        tk.Label(file_frame, text="File:").grid(row=0,
                                                column=2,
                                                sticky=tk.W, **pad)
        self.file_path_var = tk.StringVar()
        tk.Entry(file_frame, width=30,
                 textvariable=self.file_path_var).grid(row=0, column=3,
                                                       **pad)

        tk.Button(file_frame, text="Browse",
                  command=self._browse_file).grid(row=0, column=4,
                                                  sticky=tk.W, **pad)
        tk.Button(file_frame, text="Send File",
                  command=self._send_file).grid(row=0, column=5,
                                                sticky=tk.W, **pad)

        # ==== Received messages / logs ====
        recv_frame = tk.LabelFrame(self, text="Received")
        recv_frame.pack(fill=tk.BOTH, expand=True, **pad)

        self.recv_text = tk.Text(recv_frame, state=tk.DISABLED)
        self.recv_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar = tk.Scrollbar(recv_frame,
                                 command=self.recv_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.recv_text['yscrollcommand'] = scrollbar.set

    # ----------------------------------------------
    def _connect(self):
        """Open socket and start receiver thread."""
        if self.sock:
            return  # already connected
        host = self.ip_var.get()
        try:
            port = int(self.port_var.get())
        except ValueError:
            self._log("Invalid port number")
            return

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((host, port))
            # send REGISTER <id>
            sock.sendall(f"REGISTER {self.id_var.get()}\n".encode())
        except Exception as exc:
            self._log(f"[CLIENT] Could not connect: {exc}")
            return

        self.sock = sock
        self.stop_event.clear()

        # Start receiver thread
        self.recv_thread = threading.Thread(
            target=receiver_thread,
            args=(self.sock, self.download_dir, self.ev_queue,
                  self.stop_event),
            daemon=True)
        self.recv_thread.start()

        # UI changes
        self.connect_btn.config(state=tk.DISABLED)
        self.disconnect_btn.config(state=tk.NORMAL)
        self._log(f"[CLIENT] Connected to {host}:{port} as "
                  f"{self.id_var.get()}")

    def _disconnect(self):
        """Close socket and stop the receiver thread."""
        if not self.sock:
            return
        try:
            self.stop_event.set()
            self.sock.shutdown(socket.SHUT_RDWR)
            self.sock.close()
        except Exception:
            pass  # ignore errors during shutdown

        self.sock = None
        self.recv_thread = None
        self.connect_btn.config(state=tk.NORMAL)
        self.disconnect_btn.config(state=tk.DISABLED)
        self._log("[CLIENT] Disconnected")

    # ----------------------------------------------
    def _send_msg(self):
        """Send a text message to the selected peer – encrypted."""
        if not self.sock:
            self._log("[CLIENT] Not connected")
            return
        target = self.peer_id_var.get().strip()
        msg = self.msg_entry.get()
        if not target or not msg:
            self._log("[CLIENT] Peer ID and message required")
            return

        # ---------- 1️⃣ Encrypt ----------
        encrypted_text = encrypt(msg, my_password)          # base‑64 string
        body   = encrypted_text.encode('utf-8')             # bytes that will be sent
        header = f"SEND_MSG {target} {len(body)}\n".encode()

        try:
            self.sock.sendall(header + body)
            self._log(f"[ME → {target}] (encrypted) {msg}")   # plain text still logged
            self.msg_entry.delete(0, tk.END)
        except Exception as exc:
            self._log(f"[CLIENT] Error sending msg: {exc}")

    def _browse_file(self):
        """Open file dialog and store chosen path."""
        path = tk.filedialog.askopenfilename()
        if path:
            self.file_path_var.set(path)

    def _send_file(self):
        """Send the selected file to the given peer."""
        if not self.sock:
            self._log("[CLIENT] Not connected")
            return
        target = self.file_peer_id_var.get().strip()
        path_str = self.file_path_var.get().strip()
        if not target or not path_str:
            self._log("[CLIENT] Peer ID and file required")
            return

        p = Path(path_str)
        if not p.is_file():
            self._log(f"[CLIENT] File does not exist: {p}")
            return
        try:
            size = p.stat().st_size
            header = f"SEND {target} {p.name} {size}\n".encode()
            with open(p, "rb") as fp:
                data = fp.read()
            self.sock.sendall(header + data)
            self._log(f"[ME → {target}] Sent file {p.name}")
            self.file_path_var.set("")
        except Exception as exc:
            self._log(f"[CLIENT] Error sending file: {exc}")

    # ----------------------------------------------
    def _process_events(self):
        """Poll the queue and update UI accordingly."""
        try:
            while True:
                ev = self.ev_queue.get_nowait()
                kind = ev[0]
                if kind == "new_user":
                    peer_id = ev[1]
                    self._log(f"[SERVER] New user joined: {peer_id}")

                elif kind == "msg_received":
                    from_id, text = ev[1], ev[2]
                    self._log(f"[{from_id}] {text}")

                elif kind == "file_received":
                    from_id, path = ev[1], ev[2]
                    self._log(f"File received from {from_id}: {path}")

                elif kind == "closed":
                    self._disconnect()   # clean up UI
                    break

                else:  # generic log entry
                    msg = ev[1] if len(ev) > 1 else ""
                    self._log(msg)
        except queue.Empty:
            pass
        finally:
            self.after(100, self._process_events)

    def _log(self, message: str):
        """Append a line to the read‑only text widget."""
        self.recv_text.config(state=tk.NORMAL)
        self.recv_text.insert(tk.END, f"{datetime.now():%H:%M:%S} {message}\n")
        self.recv_text.see(tk.END)
        self.recv_text.config(state=tk.DISABLED)

# ----------------------------------------------------------------------
if __name__ == "__main__":
    app = P2PClientGUI()
    app.mainloop()
