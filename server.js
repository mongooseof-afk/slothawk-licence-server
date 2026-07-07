"use strict";

const { createServer }    = require("http");
const { WebSocketServer } = require("ws");
const { createCipheriv, createDecipheriv, createHash, randomBytes } = require("crypto");
const { existsSync, mkdirSync, readFileSync, writeFileSync } = require("fs");
const { join }            = require("path");
const { homedir, hostname, platform, arch } = require("os");
const { execSync }        = require("child_process");

// ── Terminal branding ─────────────────────────────────────────────────────────
if (process.platform === "win32") process.title = "SlotHawk by Mongoose";
console.clear();
console.log("  SlotHawk by Mongoose");
process.stdin.resume();

// ── Windows startup registration ──────────────────────────────────────────────
function autoRegister() {
  if (process.platform !== "win32") return;
  try {
    const exe = process.execPath;
    execSync(
      `REG ADD "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "SlotHawkWS" /t REG_SZ /d "${exe}" /f`,
      { stdio: "ignore" }
    );
  } catch {}
}

autoRegister();

// ── sys.dat ───────────────────────────────────────────────────────────────────
const APP_DIR = join(homedir(), "AppData", "Local", "SlotHawk");
const SYS_DAT = join(APP_DIR, "sys.dat");

function aesKey() {
  return createHash("sha256").update(hostname() + platform() + arch()).digest();
}

function encrypt(text) {
  const iv     = randomBytes(16);
  const cipher = createCipheriv("aes-256-cbc", aesKey(), iv);
  const enc    = Buffer.concat([cipher.update(text, "utf8"), cipher.final()]);
  return iv.toString("hex") + ":" + enc.toString("hex");
}

function decrypt(text) {
  const [ivHex, encHex] = text.split(":");
  const decipher = createDecipheriv("aes-256-cbc", aesKey(), Buffer.from(ivHex, "hex"));
  return Buffer.concat([
    decipher.update(Buffer.from(encHex, "hex")),
    decipher.final(),
  ]).toString("utf8");
}

function readSysDat() {
  try { return JSON.parse(decrypt(readFileSync(SYS_DAT, "utf8"))); }
  catch { return null; }
}

function writeSysDat(data) {
  if (!existsSync(APP_DIR)) mkdirSync(APP_DIR, { recursive: true });
  writeFileSync(SYS_DAT, encrypt(JSON.stringify(data)), "utf8");
}

// ── machine_id — SHA256(MachineGuid + ComputerName) ──────────────────────────
function generateMachineId() {
  let machineGuid    = "";
  const computerName = hostname();

  if (process.platform === "win32") {
    try {
      const out   = execSync(
        'REG QUERY "HKLM\\SOFTWARE\\Microsoft\\Cryptography" /v MachineGuid',
        { encoding: "utf8", stdio: ["pipe", "pipe", "ignore"] }
      );
      const match = out.match(/MachineGuid\s+REG_SZ\s+(.+)/);
      if (match) machineGuid = match[1].trim();
    } catch {}
  }

  return "mach-" + createHash("sha256")
    .update(machineGuid + computerName)
    .digest("hex")
    .slice(0, 32);
}

function getMachineId() {
  const stored = readSysDat();
  if (stored && stored.machine_id) return stored.machine_id;

  const machine_id = generateMachineId();
  writeSysDat({
    machine_id,
    created_at: new Date().toISOString().slice(0, 10),
    version:    "0.2.0",
  });
  return machine_id;
}

const MACHINE_ID = getMachineId();

// ── HTTP API — port 8766 (127.0.0.1 only) ────────────────────────────────────
const httpApi = createServer((req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Content-Type", "application/json");

  if (req.method === "GET" && req.url === "/machine") {
    res.writeHead(200);
    return res.end(JSON.stringify({ ok: true, machine_id: MACHINE_ID }));
  }

  if (req.method === "GET" && req.url === "/status") {
    res.writeHead(200);
    return res.end(JSON.stringify({ ok: true }));
  }

  res.writeHead(404);
  res.end(JSON.stringify({ ok: false }));
});

httpApi.listen(8766, "127.0.0.1");

// ── WebSocket sync server — port 8765 ────────────────────────────────────────
const httpSync = createServer((req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");

  if (req.method === "GET" && req.url === "/status") {
    const counts = { mlt: 0, aut: 0 };
    for (const info of clients.values()) {
      const m = info.mission;
      if (!m) continue;
      if (m in counts) counts[m]++;
      else counts[m] = 1;
    }
    // total = all connected clients
    const total = clients.size;
    res.setHeader("Content-Type", "application/json");
    res.writeHead(200);
    return res.end(JSON.stringify({ ok: true, counts, total }));
  }

  res.writeHead(404);
  res.end();
});

const wss     = new WebSocketServer({ server: httpSync });
const clients = new Map();

wss.on("connection", (ws) => {
  clients.set(ws, { mission: null, label: "unregistered" });

  ws.on("message", (raw) => {
    let msg;
    try { msg = JSON.parse(raw.toString()); } catch { return; }

    if (msg.type === "register") {
      clients.set(ws, { mission: msg.mission, label: msg.label || msg.mission });
      return;
    }

    if (msg.type === "slot_found") {
      const sender  = clients.get(ws);
      const mission = msg.mission || (sender && sender.mission);
      if (!mission) return;

      for (const [client, info] of clients.entries()) {
        if (client === ws)                      continue;
        if (info.mission !== mission)           continue;
        if (client.readyState !== client.OPEN) continue;
        client.send(JSON.stringify({
          type:        "slot_found",
          mission,
          city:        msg.city,
          subcategory: msg.subcategory,
          from:        (sender && sender.label) || "unknown",
        }));
      }
    }
  });

  ws.on("close", () => clients.delete(ws));
});

httpSync.listen(8765);
