# P2PChat

P2PChat is a lightweight encrypted group chat system with two client options:
- Desktop app client (`ClientCode.py`, Tkinter GUI)
- Web client (`web_client/`, browser UI)

Both clients connect to the same Python relay server (`ServerCode.py`) and can chat/file-share together when they use the same group password.

Important: this project currently uses educational XOR-based encryption, not production-grade security.

## Project Overview

### Components
- `ServerCode.py`: TCP relay server (login, group isolation, message/file forwarding)
- `ClientCode.py`: desktop GUI client (chat, file transfer, group-based encryption)
- `web_client/web_app.py`: web bridge server (FastAPI + WebSocket)
- `web_client/static/`: browser interface files (`index.html`, `app.js`, `style.css`)
- `run_all.py`: launcher to run server + web backend together with one command

### How it works
1. User logs in with a unique username.
2. User joins a group using a password.
3. Group password is used by clients for encryption/decryption.
4. Server relays data only between users in the same group.
5. Desktop and web users can communicate with each other.

## Run All on One Server (`run_all.py`)

Use `run_all.py` when you want one machine (for example Raspberry Pi) to run both:
- TCP chat server (`ServerCode.py`)
- Web backend (`web_client.web_app`)

### Install once
```bash
pip install -r requirements.txt
```

### Run both services with one command
```bash
python run_all.py --host 0.0.0.0 --web-port 8000
```

This starts:
- Chat server on `12345`
- Web app on `8000`

### Connect from other devices
- Open browser: `http://<server-ip>:8000`
- In web form use:
  - `Server IP`: `127.0.0.1` (because chat server is on same machine)
  - `Port`: `12345`

Stop both services with `Ctrl+C`.

## Server

### What the server does
- Accepts TCP clients on `0.0.0.0:12345` by default
- Handles commands:
  - `LOGIN <username>`
  - `GROUP <group_hash>`
  - `GET_ONLINE_USERS`
  - `SEND_MSG <target|BROADCAST> <size>`
  - `SEND <target> <encrypted_filename> <size>`
- Forwards messages/files only within the same group

### Install (server machine)
1. Install Python 3.10+.
2. Place project files on the machine.
3. No external package is required for `ServerCode.py`.

### Run server
```powershell
cd D:\Project\P2PChat
python ServerCode.py
```

Expected output:
```text
Server running on 0.0.0.0:12345 (No Passwords, Ephemeral)...
```

### Server network notes
- If clients connect from other machines, open TCP port `12345` in firewall/router.
- Use server LAN/WAN IP in clients (not `127.0.0.1` unless local).

## Web Client

The web client is an additional layer for users who do not have the desktop app.

### What it provides
- Browser login to existing P2PChat server
- Online users list
- Encrypted text chat
- Encrypted file transfer and browser download
- Theme toggle (light/dark)
- Access password gate before opening chat UI

### Install (web host machine)
1. Install Python 3.10+.
2. Install dependencies:
```powershell
cd D:\Project\P2PChat
pip install -r requirements.txt
```

### Run web client backend
```powershell
cd D:\Project\P2PChat
python -m web_client.web_app
```

Open in browser:
```text
http://127.0.0.1:8000
```

### Web access password gate
- Users first see `/login` page.
- Only users with the access password can open the web app.
- Default password is `admin1234`.
- Change it with env var `WEB_GATE_PASSWORD`.

PowerShell example:
```powershell
$env:WEB_GATE_PASSWORD = "yourStrongPassword"
python -m web_client.web_app
```

Bash example:
```bash
WEB_GATE_PASSWORD=yourStrongPassword python -m web_client.web_app
```

### Using web client
1. Fill `Username`.
2. Fill `Server IP` and `Port` (usually `12345`).
3. Enter `Group Password`.
4. Click `Connect`.
5. Select target user and send message/file.

Requirement: web users must enter the same group password as desktop users to communicate in the same group.
Also, they must pass the web access password gate first.

## Desktop App Client

### What it provides
- GUI login and group join
- Encrypted one-to-one/group member messaging
- Encrypted file sending/receiving
- Online/left user updates

### Install (client machine)
1. Install Python 3.10+ with Tkinter (standard Python installer on Windows includes it).
2. Copy project files.
3. No extra package required for `ClientCode.py`.

### Run desktop app
```powershell
cd D:\Project\P2PChat
python ClientCode.py
```

### Using desktop app
1. Enter username, server IP, and port.
2. Login.
3. Enter group password.
4. Chat and send files to group members.

## Full Deployment Scenarios

### Scenario A: Only desktop users
1. Start `ServerCode.py` on server machine.
2. Run `ClientCode.py` on each user machine.
3. All users connect to same server IP/port and same group password.

### Scenario B: Mixed desktop + web users
1. Start `ServerCode.py`.
2. Start `python -m web_client.web_app`.
3. Desktop users run `ClientCode.py`.
4. Browser users open `http://<web-host>:8000`.
5. All users use same server IP/port and same group password.

### Scenario C: Run server + web backend with one command
1. Install dependencies once:
```powershell
cd D:\Project\P2PChat
pip install -r requirements.txt
```
2. Run both services:
```powershell
python run_all.py --host 0.0.0.0 --web-port 8000
```
3. Open from other devices:
```text
http://<server-ip>:8000
```
4. In web login form use:
- `Server IP`: `127.0.0.1` (when both services run on same machine)
- `Port`: `12345`

## Troubleshooting

### `No module named 'web_client'`
Cause: command executed from wrong directory.
Fix:
```powershell
cd D:\Project\P2PChat
python -m web_client.web_app
```

### WebSocket warnings: `No supported WebSocket library detected`
Fix:
```powershell
pip install websockets wsproto
```

### Browser cannot connect to server
- Confirm `ServerCode.py` is running.
- Check IP/port entered in web/desktop client.
- Check firewall for TCP `12345`.

### Cannot open web app page directly
This is expected now. `/` redirects to `/login`.
Enter the correct web access password first.

## Security Notice

Current encryption method is XOR with SHA-256-derived key and is not secure for production use.
Use this project for learning/prototyping in trusted environments.

## License

MIT (see `LICENSE`).
