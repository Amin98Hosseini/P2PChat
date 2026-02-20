#!/usr/bin/env python3
import socket, threading, time

# FIX: Set to 0.0.0.0 to allow connections from any interface (localhost & LAN)
HOST = "0.0.0.0"  
PORT = 12345

clients_lock = threading.Lock()
clients = {}        # id -> socket
clients_group = {}  # id -> group hash

# ======================= HELPERS =====================
def recv_until_newline(sock):
    data = bytearray()
    try:
        while True:
            chunk = sock.recv(1)
            if not chunk:
                return None
            if chunk == b"\n":
                break
            data.extend(chunk)
        return data.decode()
    except:
        return None

def send_online_list(sock, requester):
    with clients_lock:
        g = clients_group.get(requester)
        users_in_group = [
            u for u in clients
            if clients_group.get(u) == g and u != requester
        ]
    sock.sendall(("ONLINE_LIST " + " ".join(users_in_group) + "\n").encode())

def broadcast_new(user):
    with clients_lock:
        g = clients_group.get(user)
        for u, s in clients.items():
            if u != user and clients_group.get(u) == g:
                try:
                    s.sendall(f"NEW {user}\n".encode())
                except:
                    pass

def broadcast_left(user):
    with clients_lock:
        g = clients_group.get(user)
        for u, s in clients.items():
            if u != user and clients_group.get(u) == g:
                try:
                    s.sendall(f"LEFT {user}\n".encode())
                except:
                    pass

# ======================= CONNECTION ==================
def handle(conn, addr):
    user = None
    try:
        # -------- LOGIN ----------
        while user is None:
            line = recv_until_newline(conn)
            if not line:
                return
            p = line.split()
            if len(p) < 2:
                return
            if p[0] == "LOGIN":
                u = p[1]
                with clients_lock:
                    if u in clients:
                        # FIX 1: Clear error message format
                        conn.sendall(b"ERROR Username already exists\n")
                        return
                    else:
                        clients[u] = conn
                        user = u
                        conn.sendall(b"OK\n")

        # -------- GROUP (FIX: Wait for Group Command) ----------
        line = recv_until_newline(conn)
        if not line:
            return
        p = line.split()
        if len(p) >= 2 and p[0] == "GROUP":
            with clients_lock:
                clients_group[user] = p[1]
            send_online_list(conn, user)
            broadcast_new(user)
        else:
            return 

        # -------- MAIN LOOP ----------
        while True:
            line = recv_until_newline(conn)
            if not line:
                break
            p = line.split()
            if len(p) < 2:
                continue

            if p[0] == "GET_ONLINE_USERS":
                send_online_list(conn, user)

            elif p[0] == "SEND_MSG":
                if len(p) < 3:
                    continue

                target = p[1]
                size = int(p[2])

                data = bytearray()
                while len(data) < size:
                    chunk = conn.recv(size - len(data))
                    if not chunk:
                        return
                    data.extend(chunk)

                with clients_lock:
                    sender_group = clients_group.get(user)

                    # ⭐⭐⭐ BROADCAST SUPPORT ⭐⭐⭐
                    if target == "BROADCAST":
                        for u, tsock in clients.items():
                            if u != user and clients_group.get(u) == sender_group:
                                try:
                                    tsock.sendall(
                                        f"SEND_MSG {user} {size}\n".encode() + data
                                    )
                                except:
                                    pass
                        continue

                    # normal direct message
                    if clients_group.get(target) != sender_group:
                        continue

                    tsock = clients.get(target)

                if tsock:
                    try:
                        tsock.sendall(
                            f"SEND_MSG {user} {size}\n".encode() + data
                        )
                    except:
                        pass

            elif p[0] == "SEND":
                if len(p) < 4:
                    continue
                target = p[1]
                enc_filename = p[2]
                size = int(p[3])

                data = bytearray()
                while len(data) < size:
                    chunk = conn.recv(size - len(data))
                    if not chunk:
                        return
                    data.extend(chunk)

                with clients_lock:
                    if clients_group.get(target) != clients_group.get(user):
                        continue
                    tsock = clients.get(target)

                if tsock:
                    try:
                        tsock.sendall(
                            f"SEND {user} {enc_filename} {size}\n".encode() + data
                        )
                    except:
                        pass

    except Exception as e:
        print(f"Error handling {addr}: {e}")
    finally:
        if user:
            broadcast_left(user)
            with clients_lock:
                clients.pop(user, None)
                clients_group.pop(user, None)
        try:
            conn.close()
        except:
            pass

# ======================= MAIN ========================
def main():
    with socket.socket() as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        print(f"Server running on {HOST}:{PORT} (No Passwords, Ephemeral)...")
        while True:
            c, a = s.accept()
            threading.Thread(target=handle, args=(c,a), daemon=True).start()

if __name__ == "__main__":
    main()