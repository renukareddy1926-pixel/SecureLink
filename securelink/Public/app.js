const $ = (id) => document.getElementById(id);

const modeSelect = $("mode");
const passphraseInput = $("passphrase");
const prepareButton = $("prepareButton");
const keyStatus = $("keyStatus");
const connectionStatus = $("connectionStatus");
const senderPanel = $("senderPanel");
const receiverPanel = $("receiverPanel");
const sendButton = $("sendButton");
const tamperButton = $("tamperButton");
const forgeButton = $("forgeButton");
const replayButton = $("replayButton");
const senderPacket = $("senderPacket");
const receiverPacket = $("receiverPacket");
const receivedMessage = $("receivedMessage");
const logs = $("logs");

let socket;
let publicSalt;
let cryptoKey;
let lastPacket;
let seenPacketIds = new Set();
let senderId = "NODE-A-" + crypto.randomUUID();

function log(message, type = "info") {
  const item = document.createElement("div");
  item.className = `log-entry ${type}`;
  item.textContent = `${new Date().toLocaleTimeString()} — ${message}`;
  logs.prepend(item);

  while (logs.children.length > 60) {
    logs.lastChild.remove();
  }
}

function bytesToBase64(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64ToBytes(value) {
  const binary = atob(value);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

function bytesToHex(bytes) {
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function showPacket(element, packet, statusText) {
  element.className = "packet";
  element.textContent =
    `Status: ${statusText}\n` +
    `Packet ID: ${packet.id}\n` +
    `Sender: ${packet.senderId}\n` +
    `Nonce (hex): ${bytesToHex(base64ToBytes(packet.nonce))}\n` +
    `Ciphertext (base64): ${packet.ciphertext}\n` +
    `Authentication tag (base64): ${packet.tag}`;
}

function showConnection(connected) {
  connectionStatus.textContent = connected ? "Connected" : "Disconnected";
  connectionStatus.className = connected ? "status online" : "status offline";
}

function connectSocket() {
  const scheme = location.protocol === "https:" ? "wss:" : "ws:";
  socket = new WebSocket(`${scheme}//${location.host}/ws`);

  socket.addEventListener("open", () => {
    showConnection(true);
    log("Connected to packet relay server.", "success");
  });

  socket.addEventListener("close", () => {
    showConnection(false);
    log("Connection closed. Refresh the page to reconnect.", "error");
  });

  socket.addEventListener("error", () => {
    log("WebSocket connection error.", "error");
  });

  socket.addEventListener("message", async (event) => {
    let packet;

    try {
      packet = JSON.parse(event.data);
    } catch {
      log("Malformed packet received.", "error");
      return;
    }

    if (modeSelect.value === "receiver") {
      await receivePacket(packet);
    }
  });
}

async function loadConfig() {
  try {
    const response = await fetch("/api/config");
    if (!response.ok) throw new Error("Could not load server configuration.");

    const config = await response.json();
    publicSalt = base64ToBytes(config.salt);
    log("Public key-derivation salt loaded.", "info");
  } catch (error) {
    log(error.message, "error");
  }
}

async function prepareEncryption() {
  try {
    if (!publicSalt) {
      throw new Error("Server configuration is not ready. Refresh the page.");
    }

    const passphrase = passphraseInput.value;
    if (passphrase.length < 8) {
      throw new Error("Use the same demo passphrase with at least 8 characters.");
    }

    const encoder = new TextEncoder();
    const material = await crypto.subtle.importKey(
      "raw",
      encoder.encode(passphrase),
      "PBKDF2",
      false,
      ["deriveKey"]
    );

    cryptoKey = await crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: publicSalt,
        iterations: 310000,
        hash: "SHA-256"
      },
      material,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );

    keyStatus.textContent = "Encryption key prepared in this browser.";
    log("AES-256-GCM key derived locally. Key was not sent to server.", "success");
  } catch (error) {
    cryptoKey = undefined;
    keyStatus.textContent = error.message;
    log(error.message, "error");
  }
}

function sendPacket(packet) {
  if (!socket || socket.readyState !== WebSocket.OPEN) {
    log("Not connected. Wait for the server connection.", "error");
    return false;
  }

  socket.send(JSON.stringify(packet));
  return true;
}

async function encryptAndSend() {
  try {
    if (!cryptoKey) throw new Error("Prepare encryption first.");

    const message = $("messageInput").value;
    if (!message.trim()) throw new Error("Type a message first.");

    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const encodedMessage = new TextEncoder().encode(message);

    // Web Crypto AES-GCM output contains ciphertext followed by a 16-byte tag.
    const encrypted = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: nonce, tagLength: 128 },
        cryptoKey,
        encodedMessage
      )
    );

    const ciphertext = encrypted.slice(0, -16);
    const tag = encrypted.slice(-16);

    const packet = {
      type: "encrypted-packet",
      id: crypto.randomUUID(),
      senderId,
      nonce: bytesToBase64(nonce),
      ciphertext: bytesToBase64(ciphertext),
      tag: bytesToBase64(tag),
      createdAt: new Date().toISOString()
    };

    if (sendPacket(packet)) {
      lastPacket = packet;
      showPacket(senderPacket, packet, "ENCRYPTED — SENT");
      tamperButton.disabled = false;
      forgeButton.disabled = false;
      replayButton.disabled = false;
      log("Message encrypted in browser; packet sent without plaintext.", "success");
    }
  } catch (error) {
    log(error.message || "Encryption failed.", "error");
  }
}

async function receivePacket(packet) {
  if (
    packet.type !== "encrypted-packet" ||
    typeof packet.id !== "string" ||
    typeof packet.nonce !== "string" ||
    typeof packet.ciphertext !== "string" ||
    typeof packet.tag !== "string" ||
    typeof packet.senderId !== "string"
  ) {
    log("Rejected malformed packet.", "error");
    return;
  }

  showPacket(receiverPacket, packet, "RECEIVED — VERIFYING");

  // Only count a packet ID as seen after successful authentication.
  if (seenPacketIds.has(packet.id)) {
    receivedMessage.className = "received rejected";
    receivedMessage.textContent = "REJECTED: Replay detected. Duplicate packet ID.";
    showPacket(receiverPacket, packet, "REJECTED — REPLAY");
    log(`Replay rejected: ${packet.id}`, "error");
    return;
  }

  if (!cryptoKey) {
    receivedMessage.className = "received rejected";
    receivedMessage.textContent = "Enter the shared passphrase and prepare encryption first.";
    log("Packet not decrypted: receiver key is not prepared.", "error");
    return;
  }

  try {
    const nonce = base64ToBytes(packet.nonce);
    const ciphertext = base64ToBytes(packet.ciphertext);
    const tag = base64ToBytes(packet.tag);

    if (nonce.length !== 12 || tag.length !== 16) {
      throw new Error("Invalid nonce or authentication-tag length.");
    }

    // AES-GCM verifies the tag before returning any plaintext.
    const combined = new Uint8Array(ciphertext.length + tag.length);
    combined.set(ciphertext);
    combined.set(tag, ciphertext.length);

    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce, tagLength: 128 },
      cryptoKey,
      combined
    );

    const message = new TextDecoder().decode(plaintext);
    seenPacketIds.add(packet.id);

    receivedMessage.className = "received accepted";
    receivedMessage.textContent = `AUTHENTICATED & DECRYPTED:\n${message}`;
    showPacket(receiverPacket, packet, "ACCEPTED — AUTHENTICATED");
    log(`Packet authenticated and decrypted: ${packet.id}`, "success");
  } catch {
    receivedMessage.className = "received rejected";
    receivedMessage.textContent =
      "REJECTED: Authentication failed. Plaintext was not released.";
    showPacket(receiverPacket, packet, "REJECTED — AUTHENTICATION FAILED");
    log("Authentication failed; packet discarded without plaintext.", "error");
  }
}

function sendTamperedPacket() {
  if (!lastPacket) return;

  const packet = structuredClone(lastPacket);
  const ciphertext = base64ToBytes(packet.ciphertext);

  if (ciphertext.length === 0) {
    log("Cannot tamper with an empty ciphertext.", "error");
    return;
  }

  ciphertext[0] ^= 1;
  packet.ciphertext = bytesToBase64(ciphertext);

  sendPacket(packet);
  log("Tamper test sent: ciphertext bit flipped.", "info");
}

function sendForgedTag() {
  if (!lastPacket) return;

  const packet = structuredClone(lastPacket);
  const tag = base64ToBytes(packet.tag);

  tag[0] ^= 1;
  packet.tag = bytesToBase64(tag);

  sendPacket(packet);
  log("Forged-tag test sent.", "info");
}

function replayLastPacket() {
  if (!lastPacket) return;

  sendPacket(lastPacket);
  log("Replay test sent: same packet ID reused.", "info");
}

function updateMode() {
  const isSender = modeSelect.value === "sender";
  senderPanel.classList.toggle("hidden", !isSender);
  receiverPanel.classList.toggle("hidden", isSender);
}

prepareButton.addEventListener("click", prepareEncryption);
sendButton.addEventListener("click", encryptAndSend);
tamperButton.addEventListener("click", sendTamperedPacket);
forgeButton.addEventListener("click", sendForgedTag);
replayButton.addEventListener("click", replayLastPacket);
modeSelect.addEventListener("change", updateMode);

$("clearLogButton").addEventListener("click", () => {
  logs.replaceChildren();
});

updateMode();
loadConfig();
connectSocket();
log("SecureLink loaded. Choose the device role.", "info");