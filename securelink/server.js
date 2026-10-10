const express = require("express");
const http = require("http");
const crypto = require("crypto");
const path = require("path");
const { WebSocketServer, WebSocket } = require("ws");

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: "/ws" });

const PORT = process.env.PORT || 3000;

// Public salt: both browsers use this to derive the same key.
// It is NOT the secret encryption key.
const publicSalt = crypto.randomBytes(16).toString("base64");

app.use(express.static(path.join(__dirname, "public")));

app.get("/api/config", (req, res) => {
  res.json({ salt: publicSalt });
});

wss.on("connection", (socket) => {
  socket.on("message", (rawData) => {
    let packet;

    try {
      packet = JSON.parse(rawData.toString());
    } catch {
      return;
    }

    // Relay only encrypted packet data, never plaintext or keys.
    if (
      packet.type !== "encrypted-packet" ||
      typeof packet.id !== "string" ||
      typeof packet.nonce !== "string" ||
      typeof packet.ciphertext !== "string" ||
      typeof packet.tag !== "string" ||
      typeof packet.senderId !== "string"
    ) {
      return;
    }

    // Do not print or store packet contents on the server.
    const outgoing = JSON.stringify(packet);

    for (const client of wss.clients) {
      if (client !== socket && client.readyState === WebSocket.OPEN) {
        client.send(outgoing);
      }
    }
  });
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`SecureLink server running on port ${PORT}`);
  console.log(`Open on laptop: http://localhost:${PORT}`);
});