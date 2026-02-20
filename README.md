# P2P Chat & File Transfer – Python GUI Client + Simple Server

Lightweight **peer-to-peer** chat and file transfer application with:

* Tkinter GUI client
* Encrypted text messages (simple XOR + SHA256-based key + base64)
* File sending/receiving
* Group support (shared group password)
* Real-time peer list updates
* Basic TCP server for message & file relaying

> **Current status (Feb 2026):** educational prototype – **not secure for real-world usage**

## Features

| Feature                         | Client | Server  | Notes                                             |
| ------------------------------- | ------ | ------- | ------------------------------------------------- |
| Connect / Disconnect            | ✓      | —       | arbitrary IP:port                                 |
| Register with custom user ID    | ✓      | ✓       | e.g. "alice", "bob"                               |
| Send encrypted text messages    | ✓      | ✓       | XOR + SHA256-derived key + base64                 |
| Send files                      | ✓      | ✓       | any file type                                     |
| Receive files automatically     | ✓      | —       | saved to `~/client_received/`                     |
| Real-time received messages     | ✓      | —       | scrollable text area                              |
| Group support (shared password) | ✓      | ✓       | only peers with same group key see messages/files |
| Connection status & logs        | ✓      | console | basic feedback                                    |

## Project Structure

```text
p2p-chat/
├── client_gui.py ← GUI client (Tkinter)
├── server.py     ← simple TCP relay server
├── README.md
└── Downloads/    ← received files are saved here
```

## Requirements

* Python 3.10 – 3.12 (Tkinter included in standard library)
* No external packages required

## Quick Start

### 1. Start the Server

```bash
python server.py
```

* Default listen address: 0.0.0.0:12345
* Change host/port directly in the code if needed

### 2. Run one or more Clients

```bash
python client_gui.py
```

### 3. In the GUI

* Enter server IP and port (default: 127.0.0.1:12345)
* Choose your user ID (alice, bob, etc.)
* Enter **group password**
* Click Connect
* Type peer ID + message → Send Msg
* Or select file + peer ID → Send File

Received messages and files appear in the bottom text area.

Files are automatically saved to:

```text
~/client_received/YYYYMMDD_HHMMSS_fromUser_originalName.ext
```

### Security Warning

This encryption is **NOT secure**:

```python
# XOR with SHA-256-derived key + base64
# → easily broken with known-plaintext or frequency analysis
```

Use only for learning purposes or local trusted networks.

#### For real applications consider:

* TLS (e.g. with `ssl` module)
* Proper key exchange (Diffie-Hellman / libsodium)
* Authenticated encryption (ChaCha20-Poly1305, AES-GCM)

### Known Limitations

* Only simple XOR-based encryption (text & files)
* Server stores no message/file history – pure relay
* No offline message delivery
* No user discovery / directory service
* Single-threaded file receive (can block UI on huge files)
* Basic error handling

### Possible Improvements

* Switch text protocol to JSON or length-prefixed binary
* Add proper message acknowledgements
* Implement file resume / chunking
* Add real asymmetric encryption (e.g. RSA, X25519)
* Show online users list in GUI
* Dark mode / better UI styling
* Tray icon / notifications

### Contributing

I’m really happy you’re interested in this little project!
Feel free to fork, experiment, break things, fix things — everything is welcome.

Whether you want to:

* fix a bug you found
* add one of the improvements listed above
* create a completely new feature
* modernize the UI
* replace the toy encryption with something better
* improve documentation
* add tests
* … or anything else you think would make it cooler

→ Pull requests are very welcome! ♥

Just open an issue first if you’re planning something big, so we can discuss the direction.

Happy coding and thank you for any contribution — even small ones make me smile 😊

## License

MIT License (add a LICENSE file if you want to publish)

Feel free to fork, improve, and PR!

Happy coding!
