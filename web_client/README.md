# P2PChat Web Client

This folder adds browser access to your existing chat system without changing `ServerCode.py` or `ClientCode.py`.

## What it does
- Browser users connect to the same TCP server protocol as desktop users.
- Same login/group model.
- Same message and file encryption algorithm used by your current client.
- Online users list.
- Message send/receive.
- File send/receive and browser download.

## Run
1. Start your current server first:
   python ServerCode.py
2. Install web dependencies:
   pip install -r web_client/requirements.txt
3. Start web app:
   python -m web_client.web_app
4. Open:
   http://127.0.0.1:8000

## Notes
- Web users must use the same group password as desktop users.
- Browser and desktop clients can chat with each other in same group.
- This is protocol-compatible with your current code.
