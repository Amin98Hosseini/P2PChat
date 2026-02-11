# P2P Chat & File Transfer – Python GUI Client + Simple Server

Lightweight **peer-to-peer** chat and file transfer application with:

- Tkinter GUI client
- Encrypted text messages (simple XOR + base64)
- File sending/receiving
- Real-time peer list updates
- Basic TCP server for message & file relaying

> **Current status (Feb 2026):** educational prototype – **not secure for real-world usage**

## Features

| Feature                        | Client | Server | Notes                              |
|-------------------------------|--------|--------|------------------------------------|
| Connect / Disconnect           | ✓      | —      | arbitrary IP:port                  |
| Register with custom user ID   | ✓      | ✓      | e.g. "alice", "bob"                |
| Send encrypted text messages   | ✓      | ✓      | XOR + base64 (very basic crypto)   |
| Send files                     | ✓      | ✓      | any file type                      |
| Receive files automatically    | ✓      | —      | saved to `~/client_received/`      |
| Real-time received messages    | ✓      | —      | scrollable text area               |
| Connection status & logs       | ✓      | console| basic feedback                     |

## Project Structure
```text
p2p-chat/
├── ClientCode.py ← GUI client (Tkinter)
├── ServerCode.py ← simple TCP relay server (JSON based)
└── README.md
```


## Requirements

- Python 3.7 – 3.11 (Tkinter is included in standard library)
- No external packages needed

## Quick Start

### 1. Start the Server

```bash
python ServerCode.py
```

- Default listen address: 192.168.1.101:8888
- (You can change host/port directly in the code)

### 2. Run one or more Clients

```bash
python ClientCode.py
```

### 3. In the GUI

- Enter server IP and port (default: 192.168.1.101:12345 ← change to match server)
- Choose your user ID (alice, bob, etc.)
- Click Connect
- Type peer ID + message → Send Msg
- Or select file + peer ID → Send File

Received messages and files appear in the bottom text area.

Files are automatically saved to:
```text
~/client_received/YYYYMMDD_HHMMSS_fromUser_originalName.ext
```
### Security Warning

This encryption is NOT secure:

```python
# XOR with SHA-256-derived key + base64
# → easily broken with known-plaintext or frequency analysis
```

Use only for learning purposes or local trusted networks.

#### For real applications consider:

- TLS (e.g. with ssl module)
- Proper key exchange (Diffie-Hellman / libsodium)
- Authenticated encryption (ChaCha20-Poly1305, AES-GCM)

### Known Limitations
- No end-to-end file encryption (only text messages are encrypted)
- Server stores no history – pure relay
- No offline message delivery
- No user discovery / directory service
- Very basic error handling
- Single-threaded file receive (can block UI on huge files)

### Possible Improvements
- Switch text protocol to JSON or length-prefixed binary
- Add proper message acknowledgements 
- Implement file resume / chunking 
- Add real asymmetric encryption (e.g. RSA or X25519) 
- Show online users list in GUI 
- Dark mode / better UI styling 
- Tray icon / notifications

### Contributing
I'm really happy you're interested in this little project!
Feel free to fork, experiment, break things, fix things — everything is welcome.
Whether you want to:

- fix a bug you found
- add one of the improvements listed above
- create a completely new feature
- modernize the UI
- replace the toy encryption with something better
- improve documentation
- add tests
- … or anything else you think would make it cooler

→ Pull requests are very welcome! ♥

Just open an issue first if you're planning something big, so we can talk about the direction.

Happy coding and thank you for any contribution — even small ones make me smile 😊

## License
MIT License (add a LICENSE file if you want to publish)

Feel free to fork, improve and PR!

Happy coding!