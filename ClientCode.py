#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Peer-to-peer file/text client – GUI version with Group-Based Encryption
FIXED: Timeout & Protocol Issues
NOW WITH: File Content Encryption
"""
import os
import socket
import threading
import queue
import shutil
from pathlib import Path
from datetime import datetime
import tkinter as tk
from tkinter import filedialog, ttk, messagebox
import base64, hashlib
import re

# ----------------------------------------------------------------------
# Persian/Arabic/Hebrew (RTL) text detection
# ----------------------------------------------------------------------
def is_rtl_text(text):
    """Detects if text contains RTL characters (Persian/Arabic/Hebrew)"""
    rtl_ranges = [
        (0x0600, 0x06FF),  # Arabic
        (0x0750, 0x077F),  # Arabic Supplement
        (0x08A0, 0x08FF),  # Arabic Extended-A
        (0xFB50, 0xFDFF),  # Arabic Presentation Forms-A
        (0xFE70, 0xFEFF),  # Arabic Presentation Forms-B
        (0x0590, 0x05FF),  # Hebrew
    ]
    
    for char in text:
        ord_char = ord(char)
        for start, end in rtl_ranges:
            if start <= ord_char <= end:
                return True
    return False

def apply_rtl_correction(text):
    """Apply RTL correction using Unicode control characters"""
    if is_rtl_text(text):
        # Add RTL mark at beginning and end
        return "\u202B" + text + "\u202C"
    return text

# ----------------------------------------------------------------------
# Encryption helpers
# ----------------------------------------------------------------------
def _derive_key(password: str, length: int = 32) -> bytes:
    return hashlib.sha256(password.encode('utf-8')).digest()[:length]

def encrypt(msg: str, password: str) -> str:
    if not password:
        raise ValueError("Password cannot be empty")
    key = _derive_key(password)
    cipher_bytes = bytearray(b ^ key[i % len(key)] for i, b in enumerate(msg.encode()))
    return base64.b64encode(cipher_bytes).decode('utf-8')

def decrypt(encoded_msg: str, password: str) -> str:
    if not password:
        raise ValueError("Password cannot be empty")
    key = _derive_key(password)
    cipher_bytes = base64.b64decode(encoded_msg.encode())
    plain_bytes = bytearray(b ^ key[i % len(key)] for i, b in enumerate(cipher_bytes))
    return plain_bytes.decode('utf-8')

# New functions for file content encryption
def encrypt_file_data(file_data: bytes, password: str) -> bytes:
    """Encrypt file data using XOR with derived key"""
    if not password:
        raise ValueError("Password cannot be empty")
    key = _derive_key(password)
    
    # Encrypt file data with XOR
    encrypted = bytearray()
    for i, b in enumerate(file_data):
        encrypted.append(b ^ key[i % len(key)])
    
    return bytes(encrypted)

def decrypt_file_data(encrypted_data: bytes, password: str) -> bytes:
    """Decrypt file data using XOR with derived key"""
    if not password:
        raise ValueError("Password cannot be empty")
    key = _derive_key(password)
    
    # Decrypt file data with XOR
    decrypted = bytearray()
    for i, b in enumerate(encrypted_data):
        decrypted.append(b ^ key[i % len(key)])
    
    return bytes(decrypted)

# ----------------------------------------------------------------------
def recv_until_newline(sock: socket.socket, timeout: float = None) -> str | None:
    sock.settimeout(timeout)
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
    except (socket.timeout, ConnectionResetError, OSError):
        return None
    finally:
        sock.settimeout(None)

# ----------------------------------------------------------------------
def connect_to_server(server_ip: str, port: int, timeout: int = 5) -> socket.socket | None:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((server_ip, port))
        sock.settimeout(None)
        return sock
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        messagebox.showerror("Connection Error", f"Cannot connect to server {server_ip}:{port}\n{str(e)}")
        return None

# ----------------------------------------------------------------------
def authenticate_user(sock: socket.socket, username: str) -> bool:
    try:
        sock.sendall(f"LOGIN {username}\n".encode())
        response = recv_until_newline(sock, timeout=5.0)
        if not response:
            messagebox.showerror("Authentication Error", "Server closed connection unexpectedly")
            return False
        if response.startswith("OK"):
            return True
        elif response.startswith("ERROR"):
            msg = response.replace("ERROR", "").strip()
            if not msg:
                msg = "Username already in use. Choose another username."
            messagebox.showerror("Login Failed", msg)
            return False
        else:
            messagebox.showwarning("Authentication Failed", response)
            return False
    except Exception as e:
        messagebox.showerror("Authentication Error", f"Network error: {str(e)}")
        return False

# ----------------------------------------------------------------------
def receiver_thread(sock: socket.socket, download_dir: Path, ev_queue: queue.Queue, stop_event: threading.Event):
    while not stop_event.is_set():
        header = recv_until_newline(sock, timeout=None)
        if header is None:
            ev_queue.put(("closed",))
            break
        parts = header.split()
        
        if len(parts) >= 1 and parts[0].upper() == "ONLINE_LIST":
            online_users = parts[1:] if len(parts) > 1 else []
            ev_queue.put(("online_list", online_users))
        elif len(parts) == 2 and parts[0].upper() == "NEW":
            ev_queue.put(("new_user", parts[1]))
        elif len(parts) == 2 and parts[0].upper() == "LEFT":
            ev_queue.put(("peer_left", parts[1]))
        elif len(parts) == 4 and parts[0].upper() == "SEND":
            from_id, encrypted_filename, size_str = parts[1], parts[2], parts[3]
            try:
                total_bytes = int(size_str)
            except ValueError:
                ev_queue.put(("log", f"[CLIENT] Bad file size from {from_id}"))
                continue
            
            # Receive encrypted file data
            encrypted_data = bytearray()
            remaining = total_bytes
            while remaining > 0 and not stop_event.is_set():
                try:
                    chunk = sock.recv(min(65536, remaining))
                    if not chunk:
                        break
                    encrypted_data.extend(chunk)
                    remaining -= len(chunk)
                except Exception as e:
                    ev_queue.put(("log", f"[CLIENT] Error receiving file: {str(e)}"))
                    break
            
            if remaining == 0:
                # Send encrypted data to queue (decryption happens in main thread)
                ev_queue.put(("file_received_encrypted", from_id, encrypted_filename, total_bytes, bytes(encrypted_data)))
            else:
                ev_queue.put(("log", f"[CLIENT] Incomplete file from {from_id}"))
                
        elif len(parts) == 3 and parts[0].upper() == "SEND_MSG":
            from_id, size_str = parts[1], parts[2]
            try:
                total_bytes = int(size_str)
            except ValueError:
                ev_queue.put(("log", f"[CLIENT] Bad message size from {from_id}"))
                continue
            msg_bytes = bytearray()
            remaining = total_bytes
            while remaining > 0 and not stop_event.is_set():
                try:
                    chunk = sock.recv(min(4096, remaining))
                    if not chunk:
                        break
                    msg_bytes.extend(chunk)
                    remaining -= len(chunk)
                except Exception:
                    break
            if remaining == 0:
                encrypted_text = msg_bytes.decode("utf-8", errors="ignore")
                ev_queue.put(("msg_received", from_id, encrypted_text))
            else:
                ev_queue.put(("log", f"[CLIENT] Incomplete message from {from_id}"))
        else:
            ev_queue.put(("log", f"[CLIENT] Unknown protocol: {header!r}"))

# ----------------------------------------------------------------------
class GroupPasswordDialog:
    def __init__(self, username, server_ip, port):
        self.root = tk.Tk()
        self.root.title("🔐 Join Secure Group")
        self.root.geometry("480x260")
        self.root.resizable(True, True)
        self.root.configure(bg="#f5f5f5")
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.username = username
        self.server_ip = server_ip
        self.port = port
        self.result_password = None
        self._build_widgets()
        self.root.mainloop()

    def _build_widgets(self):
        header = tk.Frame(self.root, bg="#1976d2", height=70)
        header.pack(fill=tk.X)
        header.pack_propagate(False)
        tk.Label(header, text=f"Welcome, {self.username}!", font=("Arial", 16, "bold"), fg="white", bg="#1976d2").pack(pady=15)
        main = tk.Frame(self.root, bg="#f5f5f5", padx=30, pady=20)
        main.pack(fill=tk.BOTH, expand=True)
        tk.Label(main, text="Enter Group Password", font=("Arial", 14, "bold"), bg="#f5f5f5", fg="#1976d2").pack(pady=(0, 10))
        info = ("Users with the same password form a private secure group.\n"
                "Only group members can see and communicate with each other.")
        tk.Label(main, text=info, font=("Arial", 10), bg="#f5f5f5", fg="#546e7a", justify=tk.CENTER, wraplength=400).pack(pady=(0, 20))
        self.pass_var = tk.StringVar()
        entry = tk.Entry(main, textvariable=self.pass_var, show="●", width=35, font=("Arial", 12), relief=tk.SOLID, borderwidth=1)
        entry.pack(pady=5)
        entry.focus_set()
        btn_frame = tk.Frame(main, bg="#f5f5f5")
        btn_frame.pack(pady=20)
        tk.Button(btn_frame, text="Join Group", command=self._submit, bg="#4CAF50", fg="white", font=("Arial", 11, "bold"), width=15, height=2, relief=tk.FLAT).pack(side=tk.LEFT, padx=10)
        tk.Button(btn_frame, text="Cancel", command=self._cancel, bg="#f44336", fg="white", font=("Arial", 11, "bold"), width=15, height=2, relief=tk.FLAT).pack(side=tk.LEFT, padx=10)
        self.root.bind("<Return>", lambda e: self._submit())

    def _submit(self):
        pwd = self.pass_var.get().strip()
        if not pwd:
            messagebox.showwarning("Warning", "Group password cannot be empty!")
            return
        self.result_password = pwd
        self.root.destroy()

    def _cancel(self):
        if messagebox.askyesno("Confirm Exit", "Are you sure you want to exit?\nYou must join a group to communicate."):
            self.result_password = None
            self.root.destroy()

    def _on_close(self):
        self._cancel()

    def get_password(self):
        return self.result_password

# ----------------------------------------------------------------------
class LoginWindow:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Peer-to-Peer Client - Login")
        self.root.geometry("450x380")
        self.root.resizable(False, False)
        self.root.configure(bg="#f5f5f5")
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.username = None
        self.server_ip = None
        self.port = None
        self.authenticated = False
        self._build_widgets()

    def _build_widgets(self):
        header = tk.Frame(self.root, bg="#1976d2", height=80)
        header.pack(fill=tk.X)
        header.pack_propagate(False)
        tk.Label(header, text="🔐 Secure Peer-to-Peer Messenger", font=("Arial", 18, "bold"), fg="white", bg="#1976d2").pack(pady=20)
        form = tk.Frame(self.root, bg="#f5f5f5", padx=40, pady=25)
        form.pack(fill=tk.BOTH, expand=True)
        
        tk.Label(form, text="👤 Username:", font=("Arial", 11, "bold"), bg="#f5f5f5").grid(row=0, column=0, sticky="w", pady=12)
        self.username_var = tk.StringVar()
        tk.Entry(form, textvariable=self.username_var, width=30, font=("Arial", 11), relief=tk.SOLID, borderwidth=1).grid(row=0, column=1, pady=12, padx=10)
        
        tk.Label(form, text="🌐 Server IP:", font=("Arial", 11, "bold"), bg="#f5f5f5").grid(row=1, column=0, sticky="w", pady=12)
        self.server_ip_var = tk.StringVar(value="127.0.0.1")
        tk.Entry(form, textvariable=self.server_ip_var, width=30, font=("Arial", 11), relief=tk.SOLID, borderwidth=1).grid(row=1, column=1, pady=12, padx=10)
        
        tk.Label(form, text="🔌 Port:", font=("Arial", 11, "bold"), bg="#f5f5f5").grid(row=2, column=0, sticky="w", pady=12)
        self.port_var = tk.StringVar(value="12345")
        tk.Entry(form, textvariable=self.port_var, width=30, font=("Arial", 11), relief=tk.SOLID, borderwidth=1).grid(row=2, column=1, pady=12, padx=10)
        
        btn_frame = tk.Frame(self.root, bg="#f5f5f5", pady=15)
        btn_frame.pack(fill=tk.X)
        tk.Button(btn_frame, text="🔓 Login", command=self._login, bg="#4CAF50", fg="white", font=("Arial", 12, "bold"), width=15, height=2, relief=tk.FLAT).pack(side=tk.LEFT, padx=25)
        
        info = tk.Label(self.root, text="No registration needed.\nJust pick a username and join.", font=("Arial", 9), fg="#546e7a", bg="#f5f5f5", justify=tk.CENTER)
        info.pack(pady=10)
        self.root.bind("<Return>", lambda e: self._login())

    def _validate_inputs(self):
        username = self.username_var.get().strip()
        server_ip = self.server_ip_var.get().strip()
        port = self.port_var.get().strip()
        if not username:
            messagebox.showwarning("Input Error", "Username is required!")
            return None, None, None
        if not server_ip or not port:
            messagebox.showwarning("Input Error", "Server IP and Port are required!")
            return None, None, None
        try:
            port = int(port)
        except ValueError:
            messagebox.showwarning("Input Error", "Port must be a number!")
            return None, None, None
        return username, server_ip, port

    def _login(self):
        username, server_ip, port = self._validate_inputs()
        if not username:
            return
        sock = connect_to_server(server_ip, port)
        if not sock:
            return
        if authenticate_user(sock, username):
            sock.close()
            self.username = username
            self.server_ip = server_ip
            self.port = port
            self.authenticated = True
            self.root.destroy()

    def _on_close(self):
        if messagebox.askokcancel("Quit", "Do you want to exit the application?"):
            self.root.destroy()
            os._exit(0)

    def run(self):
        self.root.mainloop()
        return self.authenticated, self.username, self.server_ip, self.port

# ----------------------------------------------------------------------
class P2PClientGUI:
    def __init__(self, username, server_ip, port, group_pass):
        self.root = tk.Tk()
        self.root.title(f"Peer-to-peer Client - {username} 🔒 Group Member")
        self.root.geometry("1200x750")
        self.root.minsize(1100, 600)
        self.root.configure(bg="#f0f0f0")
        self.root.protocol("WM_DELETE_WINDOW", self._on_closing)
        
        self.sock = None
        self.username = username
        self.server_ip = server_ip
        self.port = port
        self.group_password = group_pass
        self.group_id = hashlib.sha256(group_pass.encode()).hexdigest()
        
        self.verified_group_members = set([username])
        self.recv_thread = None
        self.stop_event = threading.Event()
        self.ev_queue = queue.Queue()
        
        import sys
        if getattr(sys, 'frozen', False):  
            base_dir = Path(sys.executable).parent
        else:  
            base_dir = Path(__file__).resolve().parent

        self.download_dir = base_dir / "Downloads"
        self.download_dir.mkdir(parents=True, exist_ok=True)

        
        self.peers_status = {}
        self._build_widgets()
        self._connect_and_start()
        self.root.after(100, self._process_events)

    def _connect_and_start(self):
        self.sock = connect_to_server(self.server_ip, self.port)
        if not self.sock:
            self._log("❌ Failed to reconnect to server after group join")
            self.root.after(3000, self._on_closing)
            return
        if not authenticate_user(self.sock, self.username):
            self._log("❌ Re-authentication failed")
            self.sock.close()
            self.root.after(3000, self._on_closing)
            return
        
        try:
            self.sock.sendall(f"GROUP {self.group_id}\n".encode())
        except Exception as e:
            self._log(f"⚠️ Error sending GROUP command: {str(e)}")

        self.stop_event.clear()
        self.recv_thread = threading.Thread(target=receiver_thread, args=(self.sock, self.download_dir, self.ev_queue, self.stop_event), daemon=True)
        self.recv_thread.start()
        try:
            self.sock.sendall(b"GET_ONLINE_USERS\n")
            self.root.after(1000, self._send_group_beacon)
            self._log(f"✅ Connected to server as '{self.username}'")
            self._log(f"🔐 Joined secure group (ID: {self.group_id[:8]}...)")
        except Exception as e:
            self._log(f"⚠️ Error after connection: {str(e)[:60]}")

    def _build_widgets(self):
        pad = {"padx": 10, "pady": 8}
        
        # Header
        header = tk.Frame(self.root, bg="#1976d2", height=70)
        header.pack(fill=tk.X, **pad)
        header.pack_propagate(False)
        
        tk.Label(header, text=f"👤 {self.username} | 🔒 Secure Group Member | 🌐 {self.server_ip}:{self.port}", 
                font=("Arial", 13, "bold"), fg="white", bg="#1976d2").pack(side=tk.LEFT, padx=20, pady=15)
        tk.Button(header, text="🔌 Disconnect", command=self._disconnect, 
                 bg="#d32f2f", fg="white", font=("Arial", 11, "bold"), 
                 relief=tk.FLAT, padx=20, pady=8).pack(side=tk.RIGHT, padx=20, pady=15)
        
        # Main content
        main = tk.Frame(self.root, bg="#f0f0f0")
        main.pack(fill=tk.BOTH, expand=True, **pad)
        
        # Left panel - Users
        left = tk.LabelFrame(main, text="👥 Online Users (🔒 = Group Member)", 
                            font=("Arial", 11, "bold"), bg="#ffffff", padx=5, pady=5)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, **pad)
        
        tree_frame = tk.Frame(left, bg="#ffffff")
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        
        style = ttk.Style()
        style.configure("Treeview", font=("Arial", 10))
        style.configure("Treeview.Heading", font=("Arial", 10, "bold"))
        
        self.peer_tree = ttk.Treeview(tree_frame, columns=('status', 'last_seen'), 
                                      show='tree headings', height=22)
        self.peer_tree.column('#0', width=180, anchor='w')
        self.peer_tree.heading('#0', text='User ID')
        self.peer_tree.column('status', width=110, anchor='center')
        self.peer_tree.heading('status', text='Status')
        self.peer_tree.column('last_seen', width=100, anchor='center')
        self.peer_tree.heading('last_seen', text='Last Seen')
        self.peer_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(tree_frame, orient='vertical', command=self.peer_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.peer_tree.configure(yscrollcommand=scrollbar.set)
        
        self.peer_tree.tag_configure('self', background='#e3f2fd', font=('Arial', 10, 'bold'))
        self.peer_tree.tag_configure('group', background='#e8f5e9', foreground='#1b5e20', font=('Arial', 10, 'bold'))
        self.peer_tree.tag_configure('other', background='#fff3e0', foreground='#e65100')
        self.peer_tree.tag_configure('offline', background='#ffebee', foreground='#c62828')
        
        # Right panel - Chat and Controls
        right = tk.Frame(main, bg="#f0f0f0")
        right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, **pad)
        
        # Chat area
        chat_frame = tk.LabelFrame(right, text="💬 Group Chat", font=("Arial", 11, "bold"), 
                                  bg="#ffffff", padx=5, pady=5)
        chat_frame.pack(fill=tk.BOTH, expand=True, **pad)
        
        # Create Text widget
        self.chat_text = tk.Text(chat_frame, wrap=tk.WORD, 
                                 font=("Arial", 10), bg="#fafafa", padx=12, pady=12,
                                 selectbackground="#a6c8ff", selectforeground="black")
        
        # Configure tags - no justify for the whole text
        self.chat_text.tag_configure("timestamp", foreground="#888888", font=("Arial", 9))
        self.chat_text.tag_configure("sender", foreground="#000000", font=("Arial", 10, "bold"))
        self.chat_text.tag_configure("recv", foreground="#1565c0")
        self.chat_text.tag_configure("sent", foreground="#2e7d32")
        self.chat_text.tag_configure("recv_file", foreground="#c2185b", font=("Arial", 10, "bold"))
        self.chat_text.tag_configure("group", foreground="#00695c", background="#e0f2f1")
        self.chat_text.tag_configure("status", foreground="#f57c00")
        
        self.chat_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        chat_scroll = tk.Scrollbar(chat_frame, command=self.chat_text.yview)
        chat_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.chat_text.configure(yscrollcommand=chat_scroll.set)
        self.chat_text.config(state=tk.DISABLED)
        
        # Right-click copy menu
        self._create_context_menu()
        
        # Message controls
        msg_frame = tk.LabelFrame(right, text="✏️ Send Message to Group Members", 
                                  font=("Arial", 11, "bold"), bg="#f0f0f0", padx=5, pady=8)
        msg_frame.pack(fill=tk.X, expand=False, **pad)
        
        msg_controls = tk.Frame(msg_frame, bg="#f0f0f0")
        msg_controls.pack(fill=tk.X, padx=5)
        
        tk.Label(msg_controls, text="To:", font=("Arial", 10, "bold"), bg="#f0f0f0", width=3).pack(side=tk.LEFT)
        self.peer_var = tk.StringVar()
        self.peer_combo = ttk.Combobox(msg_controls, textvariable=self.peer_var, width=15, 
                                       state="readonly", font=("Arial", 10))
        self.peer_combo.pack(side=tk.LEFT, padx=5)
        
        tk.Label(msg_controls, text="Msg:", font=("Arial", 10, "bold"), bg="#f0f0f0", width=3).pack(side=tk.LEFT, padx=(10,0))
        
        self.msg_entry = tk.Entry(msg_controls, width=30, font=("Arial", 10), relief=tk.SOLID, borderwidth=1)
        self.msg_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        # Right-click menu for Entry
        self._create_entry_context_menu()
        
        self.msg_entry.bind('<KeyRelease>', self._check_entry_rtl)
        self.msg_entry.bind("<Return>", lambda e: self._send_msg())
        self.msg_entry.bind("<Button-3>", self._show_entry_menu)
        
        tk.Button(msg_controls, text="📤 Send", command=self._send_msg, 
                 bg="#4CAF50", fg="white", font=("Arial", 10, "bold"), 
                 relief=tk.FLAT, padx=15).pack(side=tk.LEFT, padx=5)
        
        # File controls
        file_frame = tk.LabelFrame(right, text="📁 Send File to Group Members (Encrypted)", 
                                   font=("Arial", 11, "bold"), bg="#f0f0f0", padx=5, pady=8)
        file_frame.pack(fill=tk.X, expand=False, **pad)
        
        file_controls = tk.Frame(file_frame, bg="#f0f0f0")
        file_controls.pack(fill=tk.X, padx=5)
        
        tk.Label(file_controls, text="To:", font=("Arial", 10, "bold"), bg="#f0f0f0", width=3).pack(side=tk.LEFT)
        self.file_peer_var = tk.StringVar()
        self.file_peer_combo = ttk.Combobox(file_controls, textvariable=self.file_peer_var, width=15, 
                                            state="readonly", font=("Arial", 10))
        self.file_peer_combo.pack(side=tk.LEFT, padx=5)
        
        tk.Label(file_controls, text="File:", font=("Arial", 10, "bold"), bg="#f0f0f0", width=3).pack(side=tk.LEFT, padx=(10,0))
        self.file_path_var = tk.StringVar()
        file_entry = tk.Entry(file_controls, textvariable=self.file_path_var, width=25, 
                              font=("Arial", 10), relief=tk.SOLID, borderwidth=1)
        file_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        tk.Button(file_controls, text="📂 Browse", command=self._browse_file, 
                 bg="#FF9800", fg="white", font=("Arial", 10, "bold"), 
                 relief=tk.FLAT, padx=12).pack(side=tk.LEFT, padx=2)
        
        tk.Button(file_controls, text="📤 Send Encrypted", command=self._send_file, 
                 bg="#4CAF50", fg="white", font=("Arial", 10, "bold"), 
                 relief=tk.FLAT, padx=12).pack(side=tk.LEFT, padx=2)

    def _create_context_menu(self):
        """Create right-click context menu for copy"""
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="📋 Copy", command=self._copy_selected)
        self.context_menu.add_command(label="📋 Copy All", command=self._copy_all)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="🗑️ Clear Chat", command=self._clear_chat)
        
        self.chat_text.bind("<Button-3>", self._show_context_menu)

    def _create_entry_context_menu(self):
        """Create right-click context menu for Entry"""
        self.entry_menu = tk.Menu(self.root, tearoff=0)
        self.entry_menu.add_command(label="📋 Cut", command=lambda: self.msg_entry.event_generate("<<Cut>>"))
        self.entry_menu.add_command(label="📋 Copy", command=lambda: self.msg_entry.event_generate("<<Copy>>"))
        self.entry_menu.add_command(label="📋 Paste", command=lambda: self.msg_entry.event_generate("<<Paste>>"))
        self.entry_menu.add_separator()
        self.entry_menu.add_command(label="🗑️ Clear", command=lambda: self.msg_entry.delete(0, tk.END))

    def _show_context_menu(self, event):
        """Show context menu for Text widget"""
        try:
            self.context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.context_menu.grab_release()

    def _show_entry_menu(self, event):
        """Show context menu for Entry widget"""
        try:
            self.entry_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.entry_menu.grab_release()

    def _copy_selected(self):
        """Copy selected text to clipboard"""
        try:
            selected_text = self.chat_text.get(tk.SEL_FIRST, tk.SEL_LAST)
            self.root.clipboard_clear()
            self.root.clipboard_append(selected_text)
        except tk.TclError:
            pass

    def _copy_all(self):
        """Copy all chat text to clipboard"""
        all_text = self.chat_text.get(1.0, tk.END)
        self.root.clipboard_clear()
        self.root.clipboard_append(all_text)

    def _clear_chat(self):
        """Clear the chat display"""
        if messagebox.askyesno("Clear Chat", "Are you sure you want to clear the chat?"):
            self.chat_text.config(state=tk.NORMAL)
            self.chat_text.delete(1.0, tk.END)
            self.chat_text.config(state=tk.DISABLED)

    def _check_entry_rtl(self, event=None):
        """Auto-detect text direction in Entry"""
        text = self.msg_entry.get()
        if is_rtl_text(text):
            self.msg_entry.config(justify='right')
        else:
            self.msg_entry.config(justify='left')

    def _send_group_beacon(self):
        if not self.sock or not self.group_password:
            return
        try:
            beacon = f"GROUP_BEACON:{self.username}"
            encrypted = encrypt(beacon, self.group_password)
            header = f"SEND_MSG BROADCAST {len(encrypted)}\n".encode()
            self.sock.sendall(header + encrypted.encode())
        except Exception as e:
            self._log(f"⚠️ Beacon send failed: {str(e)[:50]}")

    def _refresh_peers(self):
        for item in self.peer_tree.get_children():
            self.peer_tree.delete(item)
        self.peer_tree.insert('', 'end', text=f"👤 {self.username} (You)", values=('✅ You', 'Now'), tags=('self',))
        group_members = []
        for peer_id in sorted(self.peers_status.keys()):
            if peer_id == self.username:
                continue
            info = self.peers_status[peer_id]
            status = info['status']
            last_seen = info['last_seen']
            if isinstance(last_seen, datetime):
                last_seen_str = last_seen.strftime("%H:%M:%S")
            else:
                last_seen_str = str(last_seen)
            if status == 'online':
                if peer_id in self.verified_group_members:
                    tag = 'group'
                    status_text = '🔒 Group'
                    display = f"🔒 {peer_id}"
                    group_members.append(peer_id)
                else:
                    tag = 'other'
                    status_text = '👥 Other'
                    display = peer_id
            else:
                tag = 'offline'
                status_text = '🔴 Offline'
                display = peer_id
            self.peer_tree.insert('', 'end', text=display, values=(status_text, last_seen_str), tags=(tag,))
        self.peer_combo['values'] = group_members
        self.file_peer_combo['values'] = group_members
        if group_members:
            self.peer_var.set(group_members[0])
            self.file_peer_var.set(group_members[0])
        else:
            self.peer_var.set('')
            self.file_peer_var.set('')

    def _send_msg(self):
        if not self.sock:
            self._log("❌ Not connected to server")
            return
        target = self.peer_var.get().strip()
        msg = self.msg_entry.get().strip()
        if not target:
            self._log("⚠️ Select a group member (🔒 users only)")
            return
        if not msg:
            self._log("⚠️ Message cannot be empty")
            return
        try:
            encrypted = encrypt(msg, self.group_password)
            header = f"SEND_MSG {target} {len(encrypted)}\n".encode()
            self.sock.sendall(header + encrypted.encode())
            
            # Display outgoing message with RTL correction
            self._display_message(self.username, target, msg, is_outgoing=True)
            
            self.msg_entry.delete(0, tk.END)
            self.msg_entry.config(justify='left')
        except Exception as e:
            self._log(f"❌ Send failed: {str(e)[:60]}")

    def _display_message(self, sender, target, message, is_outgoing=False):
        """Display message with proper RTL handling"""
        self.chat_text.config(state=tk.NORMAL)
        
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Insert timestamp (always left-aligned)
        self.chat_text.insert(tk.END, f"[{timestamp}] ", "timestamp")
        
        if is_outgoing:
            # Outgoing message
            self.chat_text.insert(tk.END, "📤 ", "sent")
            self.chat_text.insert(tk.END, f"You → {target}: ", ("sender", "sent"))
            
            # Apply RTL correction for text
            if is_rtl_text(message):
                # For Persian text, use directional formatting
                self.chat_text.insert(tk.END, "\u202B")  # Start RTL
                for char in message:
                    self.chat_text.insert(tk.END, char)
                self.chat_text.insert(tk.END, "\u202C")  # End RTL
            else:
                # Normal English text
                self.chat_text.insert(tk.END, message)
            self.chat_text.insert(tk.END, "\n")
        else:
            # Incoming message
            self.chat_text.insert(tk.END, "📩 ", "recv")
            self.chat_text.insert(tk.END, f"{sender}: ", ("sender", "recv"))
            
            # Apply RTL correction for text
            if is_rtl_text(message):
                # For Persian text, use directional formatting
                self.chat_text.insert(tk.END, "\u202B")  # Start RTL
                for char in message:
                    self.chat_text.insert(tk.END, char)
                self.chat_text.insert(tk.END, "\u202C")  # End RTL
            else:
                # Normal English text
                self.chat_text.insert(tk.END, message)
            self.chat_text.insert(tk.END, "\n")
        
        self.chat_text.see(tk.END)
        self.chat_text.config(state=tk.DISABLED)

    def _browse_file(self):
        path = filedialog.askopenfilename(title="Select file to send")
        if path:
            self.file_path_var.set(path)

    def _send_file(self):
        if not self.sock:
            self._log("❌ Not connected to server")
            return
        target = self.file_peer_var.get().strip()
        path = self.file_path_var.get().strip()
        if not target:
            self._log("⚠️ Select a group member for file transfer")
            return
        if not path:
            self._log("⚠️ Select a file to send")
            return
        p = Path(path)
        if not p.is_file():
            self._log(f"❌ File not found: {p}")
            return
        try:
            # Encrypt filename
            encrypted_name = encrypt(p.name, self.group_password)
            
            # Read and encrypt file content
            with open(p, "rb") as f:
                file_data = f.read()
            
            # Encrypt file content
            encrypted_data = encrypt_file_data(file_data, self.group_password)
            size = len(encrypted_data)  # Size of encrypted data
            
            header = f"SEND {target} {encrypted_name} {size}\n".encode()
            
            # Send header + encrypted data
            self.sock.sendall(header + encrypted_data)
            
            self._log(f"📤 You → {target}: 📁 {p.name} ({size:,} bytes) [Encrypted]")
            self.file_path_var.set("")
        except Exception as e:
            self._log(f"❌ File send failed: {str(e)[:60]}")

    def _process_events(self):
        try:
            while True:
                ev = self.ev_queue.get_nowait()
                kind = ev[0]
                if kind == "online_list":
                    users = ev[1]
                    current_online = set(users)
                    for user in list(self.peers_status.keys()):
                        if user not in current_online and user != self.username:
                            self.peers_status[user] = {'status': 'offline', 'last_seen': datetime.now()}
                    for user in users:
                        if user != self.username:
                            if user not in self.peers_status:
                                self.peers_status[user] = {'status': 'online', 'last_seen': datetime.now()}
                            else:
                                self.peers_status[user]['status'] = 'online'
                                self.peers_status[user]['last_seen'] = datetime.now()
                    self._refresh_peers()
                    
                elif kind == "new_user":
                    peer = ev[1]
                    if peer != self.username:
                        self.peers_status[peer] = {'status': 'online', 'last_seen': datetime.now()}
                        self._refresh_peers()
                        self._log(f"🟢 {peer} joined")
                        self._send_group_beacon()
                        
                elif kind == "peer_left":
                    peer = ev[1]
                    if peer in self.peers_status:
                        self.peers_status[peer]['status'] = 'offline'
                        self.peers_status[peer]['last_seen'] = datetime.now()
                        if peer in self.verified_group_members:
                            self.verified_group_members.discard(peer)
                        self._refresh_peers()
                        self._log(f"🔴 {peer} left")
                        
                elif kind == "msg_received":
                    sender, encrypted = ev[1], ev[2]
                    try:
                        decrypted = decrypt(encrypted, self.group_password)
                        if decrypted.startswith("GROUP_BEACON:"):
                            peer_name = decrypted.split(":", 1)[1]
                            if peer_name != self.username and peer_name not in self.verified_group_members:
                                self.verified_group_members.add(peer_name)
                                self._refresh_peers()
                                self._log(f"✅ New group member: {peer_name}")
                            continue
                        
                        # Display incoming message
                        if sender in self.verified_group_members or sender == self.username:
                            self._display_message(sender, None, decrypted, is_outgoing=False)
                        else:
                            self.verified_group_members.add(sender)
                            self._refresh_peers()
                            self._log(f"🆕 New group member: {sender}")
                            self._display_message(sender, None, decrypted, is_outgoing=False)
                            
                    except Exception as e:
                        self._log(f"❌ Error decrypting message: {str(e)}")
                        
                elif kind == "file_received_encrypted":
                    sender, enc_name, size, encrypted_data = ev[1], ev[2], ev[3], ev[4]
                    try:
                        # Decrypt filename
                        filename = decrypt(enc_name, self.group_password)
                        
                        if sender not in self.verified_group_members and sender != self.username:
                            continue
                        
                        # Decrypt file content
                        try:
                            file_data = decrypt_file_data(encrypted_data, self.group_password)
                        except Exception as e:
                            self._log(f"❌ Error decrypting file content: {str(e)}")
                            continue
                            
                        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                        dest_path = self.download_dir / f"{timestamp}_{sender}_{filename}"
                        
                        # Save decrypted file
                        with open(dest_path, "wb") as f:
                            f.write(file_data)
                        
                        self._log(f"📥 {sender} sent '{filename}' to you ({size:,} bytes encrypted, {len(file_data):,} bytes decrypted)")
                        
                        self.root.after(0, lambda: messagebox.showinfo(
                            "✅ File Received & Decrypted",
                            f"{sender} sent you an encrypted file:\n\n📁 {filename}\n📦 Encrypted: {size:,} bytes\n📦 Decrypted: {len(file_data):,} bytes\n\n💾 Saved to:\n{dest_path}"
                        ))
                        
                    except Exception as e:
                        self._log(f"❌ Error processing file: {str(e)}")
                        
                elif kind == "closed":
                    self._log("🔌 Connection closed by server")
                    self._disconnect()
                    break
                    
                elif kind == "log":
                    self._log(ev[1])
                    
        except queue.Empty:
            pass
        finally:
            if not self.stop_event.is_set():
                self.root.after(100, self._process_events)

    def _log(self, msg):
        """Simple log for system messages"""
        self.chat_text.config(state=tk.NORMAL)
        ts = datetime.now().strftime("%H:%M:%S")
        
        if msg.startswith("📥"):
            self.chat_text.insert(tk.END, f"[{ts}] {msg}\n", "recv_file")
        elif msg.startswith("✅") or msg.startswith("🆕"):
            self.chat_text.insert(tk.END, f"[{ts}] {msg}\n", "group")
        elif msg.startswith("🟢") or msg.startswith("🔴"):
            self.chat_text.insert(tk.END, f"[{ts}] {msg}\n", "status")
        else:
            self.chat_text.insert(tk.END, f"[{ts}] {msg}\n")
            
        self.chat_text.see(tk.END)
        self.chat_text.config(state=tk.DISABLED)

    def _disconnect(self):
        if self.sock:
            try:
                self.stop_event.set()
                if self.recv_thread and self.recv_thread.is_alive():
                    self.recv_thread.join(timeout=1.0)
                self.sock.close()
            except Exception:
                pass
            self.sock = None
            self._log("🔴 Disconnected from server")
            self.root.after(1500, self.root.destroy)

    def _on_closing(self):
        if messagebox.askokcancel("Quit", "Disconnect from server and exit?\nYou will leave your secure group."):
            self._disconnect()
            try:
                if self.download_dir.exists():
                    shutil.rmtree(self.download_dir)
                    print(f"Cleanup: Deleted {self.download_dir}")
            except Exception as e:
                print(f"Cleanup failed: {e}")
            self.root.destroy()

    def run(self):
        self.root.mainloop()

# ----------------------------------------------------------------------
def main():
    login = LoginWindow()
    authenticated, username, server_ip, port = login.run()
    if not authenticated:
        os._exit(0)
    group_dialog = GroupPasswordDialog(username, server_ip, port)
    group_pass = group_dialog.get_password()
    if not group_pass:
        os._exit(0)
    app = P2PClientGUI(username, server_ip, port, group_pass)
    app.run()

# ----------------------------------------------------------------------
if __name__ == "__main__":
    main()