(() => {
  let ws = null;
  let username = "";
  let verifiedMembers = new Set();
  let onlineUsers = [];

  const el = {
    username: document.getElementById("username"),
    serverIp: document.getElementById("server_ip"),
    serverPort: document.getElementById("server_port"),
    groupPassword: document.getElementById("group_password"),
    connectBtn: document.getElementById("connect-btn"),
    disconnectBtn: document.getElementById("disconnect-btn"),
    refreshBtn: document.getElementById("refresh-btn"),
    status: document.getElementById("status"),
    onlineList: document.getElementById("online-list"),
    messageTarget: document.getElementById("message-target"),
    fileTarget: document.getElementById("file-target"),
    messageInput: document.getElementById("message-input"),
    sendMessageBtn: document.getElementById("send-message-btn"),
    fileInput: document.getElementById("file-input"),
    sendFileBtn: document.getElementById("send-file-btn"),
    chatLog: document.getElementById("chat-log"),
    filesList: document.getElementById("files-list"),
    themeBtn: document.getElementById("theme-btn"),
  };

  function applyTheme(theme) {
    const dark = theme === "dark";
    document.body.classList.toggle("dark", dark);
    if (el.themeBtn) {
      el.themeBtn.textContent = dark ? "Light Theme" : "Dark Theme";
    }
    localStorage.setItem("p2pchat_theme", dark ? "dark" : "light");
  }

  function toggleTheme() {
    const dark = document.body.classList.contains("dark");
    applyTheme(dark ? "light" : "dark");
  }

  function setConnectedState(connected) {
    el.connectBtn.disabled = connected;
    el.disconnectBtn.disabled = !connected;
    el.refreshBtn.disabled = !connected;
    el.sendMessageBtn.disabled = !connected;
    el.sendFileBtn.disabled = !connected;
    el.status.textContent = connected ? "Connected" : "Disconnected";
  }

  function logLine(text, kind = "system") {
    const t = new Date().toLocaleTimeString();
    const line = document.createElement("div");
    line.className = kind === "message" ? "log-message" : "log-system";
    line.textContent = `[${t}] ${text}`;
    el.chatLog.appendChild(line);
    el.chatLog.scrollTop = el.chatLog.scrollHeight;
  }

  function updateTargets() {
    const targets = onlineUsers
      .filter((u) => u !== username)
      .filter((u) => verifiedMembers.has(u));

    for (const select of [el.messageTarget, el.fileTarget]) {
      select.innerHTML = "";
      for (const peer of targets) {
        const opt = document.createElement("option");
        opt.value = peer;
        opt.textContent = peer;
        select.appendChild(opt);
      }
    }
  }

  function renderOnlineList() {
    el.onlineList.innerHTML = "";

    const all = [username, ...onlineUsers.filter((u) => u !== username)];
    for (const user of all) {
      const li = document.createElement("li");
      if (user === username) {
        li.textContent = `${user} (You)`;
      } else if (verifiedMembers.has(user)) {
        li.textContent = `LOCK ${user} (Group Member)`;
      } else {
        li.textContent = `${user} (Online)`;
      }
      el.onlineList.appendChild(li);
    }
    updateTargets();
  }

  function addDownloadFile(sender, filename, fileBytesB64) {
    const data = atob(fileBytesB64);
    const buf = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i += 1) {
      buf[i] = data.charCodeAt(i);
    }

    const blob = new Blob([buf]);
    const url = URL.createObjectURL(blob);

    const li = document.createElement("li");
    const a = document.createElement("a");
    a.href = url;
    a.download = `${sender}_${filename}`;
    a.textContent = `Download ${filename} from ${sender}`;
    li.appendChild(a);
    el.filesList.prepend(li);
  }

  function sendJson(payload) {
    if (!ws || ws.readyState !== WebSocket.OPEN) {
      logLine("WebSocket is not connected");
      return;
    }
    ws.send(JSON.stringify(payload));
  }

  function connect() {
    username = el.username.value.trim();
    const serverIp = el.serverIp.value.trim();
    const serverPort = Number(el.serverPort.value);
    const groupPassword = el.groupPassword.value;

    if (!username || !serverIp || !serverPort || !groupPassword) {
      logLine("Username, server, port, and group password are required");
      return;
    }

    const wsProto = location.protocol === "https:" ? "wss" : "ws";
    ws = new WebSocket(`${wsProto}://${location.host}/ws`);

    ws.onopen = () => {
      sendJson({
        action: "connect",
        username,
        server_ip: serverIp,
        server_port: serverPort,
        group_password: groupPassword,
      });
    };

    ws.onmessage = (event) => {
      const msg = JSON.parse(event.data);

      if (msg.type === "connected") {
        setConnectedState(true);
        verifiedMembers = new Set([username]);
        logLine(`Connected as ${username}; group ${msg.group_id_prefix}...`);
        return;
      }

      if (msg.type === "error") {
        logLine(`Error: ${msg.message}`);
        return;
      }

      if (msg.type === "online_list") {
        onlineUsers = msg.users || [];
        renderOnlineList();
        return;
      }

      if (msg.type === "new_user") {
        if (!onlineUsers.includes(msg.user)) {
          onlineUsers.push(msg.user);
        }
        renderOnlineList();
        logLine(`${msg.user} joined`);
        return;
      }

      if (msg.type === "peer_left") {
        onlineUsers = onlineUsers.filter((u) => u !== msg.user);
        verifiedMembers.delete(msg.user);
        renderOnlineList();
        logLine(`${msg.user} left`);
        return;
      }

      if (msg.type === "verified_members") {
        verifiedMembers = new Set(msg.members || []);
        verifiedMembers.add(username);
        renderOnlineList();
        return;
      }

      if (msg.type === "message") {
        if (Array.isArray(msg.members)) {
          verifiedMembers = new Set(msg.members);
          verifiedMembers.add(username);
          renderOnlineList();
        }
        logLine(`${msg.sender}: ${msg.message}`, "message");
        return;
      }

      if (msg.type === "file_sent") {
        logLine(`You sent file ${msg.filename} (${msg.size} bytes) to ${msg.target}`);
        return;
      }

      if (msg.type === "file_received") {
        logLine(
          `${msg.sender} sent file ${msg.filename} (${msg.size_encrypted} encrypted bytes, ${msg.size_decrypted} decrypted bytes)`
        );
        addDownloadFile(msg.sender, msg.filename, msg.file_bytes_b64);
        return;
      }

      if (msg.type === "decrypt_error") {
        logLine(`Could not decrypt message from ${msg.sender}`);
        return;
      }

      if (msg.type === "closed") {
        logLine("Connection closed by server");
        disconnect();
        return;
      }

      if (msg.type === "log") {
        logLine(msg.message || "log");
      }
    };

    ws.onclose = () => {
      setConnectedState(false);
      logLine("Disconnected");
    };

    ws.onerror = () => {
      logLine("WebSocket error");
    };
  }

  function disconnect() {
    if (ws && ws.readyState === WebSocket.OPEN) {
      sendJson({ action: "disconnect" });
      ws.close();
    }
    ws = null;
    onlineUsers = [];
    verifiedMembers = new Set();
    renderOnlineList();
    setConnectedState(false);
  }

  function sendMessage() {
    const target = el.messageTarget.value;
    const message = el.messageInput.value;
    if (!target || !message.trim()) {
      logLine("Select a target and type a message");
      return;
    }
    sendJson({ action: "send_message", target, message });
    logLine(`You -> ${target}: ${message}`, "message");
    el.messageInput.value = "";
  }

  async function sendFile() {
    const target = el.fileTarget.value;
    const file = el.fileInput.files[0];
    if (!target || !file) {
      logLine("Select target and file first");
      return;
    }

    const bytes = new Uint8Array(await file.arrayBuffer());
    let binary = "";
    for (const b of bytes) {
      binary += String.fromCharCode(b);
    }
    const fileB64 = btoa(binary);

    sendJson({
      action: "send_file",
      target,
      filename: file.name,
      file_b64: fileB64,
    });

    el.fileInput.value = "";
  }

  el.connectBtn.addEventListener("click", connect);
  el.disconnectBtn.addEventListener("click", disconnect);
  el.refreshBtn.addEventListener("click", () => sendJson({ action: "refresh_online" }));
  el.sendMessageBtn.addEventListener("click", sendMessage);
  el.sendFileBtn.addEventListener("click", sendFile);
  el.themeBtn.addEventListener("click", toggleTheme);
  el.messageInput.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter") {
      sendMessage();
    }
  });

  applyTheme(localStorage.getItem("p2pchat_theme") || "light");
  setConnectedState(false);
})();
