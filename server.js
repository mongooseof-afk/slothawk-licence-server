/**
 * SlotHawk Licence Server v7.3
 * Auto-revoke duplicate machine + devices/sessions tracking
 */

require("dotenv").config();
const http   = require("http");
const crypto = require("crypto");
const jwt    = require("jsonwebtoken");
const { Pool } = require("pg");
const { v4: uuidv4 } = require("uuid");
const { WebSocketServer } = require("ws");

const PORT        = parseInt(process.env.PORT) || 8765;
const JWT_SECRET  = process.env.JWT_SECRET;
const JWT_EXPIRES = process.env.JWT_EXPIRES_IN || "7d";
const SESSION_GAP = 10 * 60 * 1000;
// A panel that stopped reporting is no longer shown online quickly, while a
// short grace period avoids flapping when Chrome throttles a background tab.
const PANEL_SESSION_GAP = 3 * 60 * 1000;
// Shared only with the Dashboard backend. Never ship this value to the
// browser/extension: it protects all administrative licence operations.
const DASHBOARD_API_KEY = process.env.DASHBOARD_API_KEY || "";

// VPS ingress is disabled until this 32+ byte secret is configured on BOTH
// the VPS and this server. It never ships to the extension or Telegram.
const VPS_SIGNAL_KEY_ID = (process.env.VPS_SIGNAL_KEY_ID || "vps-primary").trim();
const VPS_SIGNAL_HMAC_SECRET = process.env.VPS_SIGNAL_HMAC_SECRET || "";
const VPS_SIGNAL_ENABLED = Buffer.byteLength(VPS_SIGNAL_HMAC_SECRET, "utf8") >= 32;
const VPS_SIGNAL_MAX_AGE_MS = 30_000;
const VPS_SIGNAL_BODY_LIMIT_BYTES = 4 * 1024;
const VPS_SIGNAL_RATE_LIMIT = 12;
const VPS_SIGNAL_RATE_WINDOW_MS = 60_000;


// ── Telegram alert config ────────────────────────────────────────────
// Extension no longer holds the bot token — it POSTs to /alert/telegram
// with a JWT, and this server verifies + forwards to Telegram.
const TELEGRAM_BOT_TOKEN     = process.env.TELEGRAM_BOT_TOKEN     || "";
// Legacy channel — kept for existing subscribers who receive alerts on
// a 10-minute delay so the Pro channel keeps a real head start.
const TELEGRAM_CHAT_ID       = process.env.TELEGRAM_CHAT_ID       || "";
// Pro channel — receives every alert immediately. Configured via env
// so rotation doesn't need a code change. Same bot token as the legacy
// channel: the bot just needs to be an admin in both chats.
const TELEGRAM_PRO_CHAT_ID   = process.env.TELEGRAM_PRO_CHAT_ID   || "";
// How long to wait before mirroring an alert into the legacy channel.
// 10 min at the moment; env-configurable so tuning it doesn't require
// a code change either.
const TELEGRAM_LEGACY_DELAY_MS = Number(process.env.TELEGRAM_LEGACY_DELAY_MS || 10 * 60 * 1000);

const TELEGRAM_ENABLED       = !!(TELEGRAM_BOT_TOKEN && (TELEGRAM_CHAT_ID || TELEGRAM_PRO_CHAT_ID));
if (!TELEGRAM_ENABLED) {
  console.warn("[TELEGRAM] Disabled — set TELEGRAM_BOT_TOKEN and at least one of TELEGRAM_CHAT_ID / TELEGRAM_PRO_CHAT_ID env vars to enable alerts");
} else {
  console.log(`[TELEGRAM] Enabled — Pro=${TELEGRAM_PRO_CHAT_ID ? "set" : "unset"}, Legacy=${TELEGRAM_CHAT_ID ? "set" : "unset"}, LegacyDelay=${TELEGRAM_LEGACY_DELAY_MS}ms`);
}

// Rate limit: max 20 alerts / minute per licence key (in-memory).
// Resets on server restart — acceptable, since a fresh burst quota
// after a redeploy is not exploitable.
const ALERT_RATE_LIMIT      = 20;
const ALERT_RATE_WINDOW_MS  = 60_000;
const alertRateMap = new Map(); // license_key → [timestamps]
const vpsSignalRateMap = new Map(); // issuer key id → [timestamps]
const signalSessionRateMap = new Map(); // licence key + IP → [timestamps]

// ── Global Signal relay ──────────────────────────────────────────────
// Connections stay only in process memory. A signal deliberately carries
// no VFS token, applicant, or appointment-date data: it is just a fast
// "check now" wake-up for other licensed SlotHawk profiles.
const SIGNAL_AUTH_TIMEOUT_MS = 10_000;
const SIGNAL_RATE_LIMIT      = 12;
const SIGNAL_RATE_WINDOW_MS  = 60_000;
const signalRooms            = new Map(); // channel → Set<WebSocket>
const signalRateMap          = new Map(); // licence key → [timestamps]

function signalChannel(mission, city, subcategory) {
  const fields = [mission, city, subcategory].map(v => String(v || "").trim());
  if (fields.some(v => !v || v.length > 120)) return "";
  return fields.join("::");
}

function checkSignalRateLimit(key) {
  const now = Date.now();
  const hits = (signalRateMap.get(key) || []).filter(t => now - t < SIGNAL_RATE_WINDOW_MS);
  if (hits.length >= SIGNAL_RATE_LIMIT) {
    signalRateMap.set(key, hits);
    return false;
  }
  hits.push(now);
  signalRateMap.set(key, hits);
  return true;
}

function disconnectSignalDevice(licenceKey, machineId) {
  for (const room of signalRooms.values()) {
    for (const peer of room) {
      if (peer.signalLicenceKey === licenceKey && peer.signalMachineId === machineId) peer.close(4005, "device_removed");
    }
  }
}

function disconnectSignalLicence(licenceKey) {
  for (const room of signalRooms.values()) {
    for (const peer of room) {
      if (peer.signalLicenceKey === licenceKey) peer.close(4006, "licence_disabled");
    }
  }
}
function leaveSignalRoom(ws) {
  const channel = ws.signalChannel;
  if (!channel) return;
  const room = signalRooms.get(channel);
  if (!room) return;
  room.delete(ws);
  if (room.size === 0) signalRooms.delete(channel);
  ws.signalChannel = "";
}

// A server-originated signal is emitted when the trusted notification
// endpoint receives a confirmed slot alert. It uses the same room protocol
// as browser-originated signals, but the server generates the event id so
// every connected profile receives one canonical wake-up event.
function broadcastServerSlotFound({ mission, city, subcategory }) {
  const channel = signalChannel(mission, city, subcategory);
  if (!channel) return { sent: false, recipients: 0 };
  const payload = JSON.stringify({
    type: "slot_found",
    eventId: `server-${uuidv4()}`,
    mission: String(mission).trim(),
    city: String(city).trim(),
    subcategory: String(subcategory).trim(),
    sentAt: new Date().toISOString(),
    source: "telegram_alert",
  });
  let recipients = 0;
  for (const peer of signalRooms.get(channel) || []) {
    if (peer.readyState === 1) {
      peer.send(payload);
      recipients += 1;
    }
  }
  return { sent: true, recipients };
}

async function authenticateSignalToken(token) {
  let decoded;
  try { decoded = jwt.verify(String(token || ""), JWT_SECRET); }
  catch { return null; }

  const licenceKey = decoded.license_key;
  if (!licenceKey) return null;
  const { rows } = await pool.query(
    `SELECT status, expires_at, deactivated, blocked, active, machine_id, known_devices, max_devices, username, signal_sessions FROM licences WHERE license_key = $1`,
    [licenceKey]
  );
  const licence = rows[0];
  if (!licence || licence.deactivated || licence.blocked ||
      licence.status !== "active" ||
      (licence.expires_at && new Date() > new Date(licence.expires_at))) return null;
  if (!isDeviceAllowed(licence, decoded.machine_id)) return null;
  return { licenceKey, machineId: decoded.machine_id };
}

function checkAlertRateLimit(key) {
  const now = Date.now();
  const arr = (alertRateMap.get(key) || []).filter(t => now - t < ALERT_RATE_WINDOW_MS);
  if (arr.length >= ALERT_RATE_LIMIT) {
    alertRateMap.set(key, arr);
    return false;
  }
  arr.push(now);
  alertRateMap.set(key, arr);
  return true;
}

function checkSignalSessionRateLimit(key, ip) {
  const rateKey = `${String(key || "")}::${String(ip || "").slice(0, 128)}`;
  const now = Date.now();
  const hits = (signalSessionRateMap.get(rateKey) || []).filter((time) => now - time < 60_000);
  if (hits.length >= 20) {
    signalSessionRateMap.set(rateKey, hits);
    return false;
  }
  hits.push(now);
  signalSessionRateMap.set(rateKey, hits);
  return true;
}

function checkVpsSignalRateLimit(issuer) {
  const now = Date.now();
  const hits = (vpsSignalRateMap.get(issuer) || []).filter(
    (time) => now - time < VPS_SIGNAL_RATE_WINDOW_MS
  );
  if (hits.length >= VPS_SIGNAL_RATE_LIMIT) {
    vpsSignalRateMap.set(issuer, hits);
    return false;
  }
  hits.push(now);
  vpsSignalRateMap.set(issuer, hits);
  return true;
}

// Periodic cleanup so the Map doesn't grow unbounded over the process
// lifetime. Runs every 5 minutes, drops entries with no recent hits.
setInterval(() => {
  const now = Date.now();
  for (const [key, arr] of alertRateMap.entries()) {
    const filtered = arr.filter(t => now - t < ALERT_RATE_WINDOW_MS);
    if (filtered.length === 0) alertRateMap.delete(key);
    else alertRateMap.set(key, filtered);
  }
  for (const [key, hits] of signalRateMap.entries()) {
    const filtered = hits.filter(t => now - t < SIGNAL_RATE_WINDOW_MS);
    if (filtered.length === 0) signalRateMap.delete(key);
    else signalRateMap.set(key, filtered);
  }
  for (const [issuer, hits] of vpsSignalRateMap.entries()) {
    const filtered = hits.filter(t => now - t < VPS_SIGNAL_RATE_WINDOW_MS);
    if (filtered.length === 0) vpsSignalRateMap.delete(issuer);
    else vpsSignalRateMap.set(issuer, filtered);
  }
  for (const [key, hits] of signalSessionRateMap.entries()) {
    const filtered = hits.filter(t => now - t < 60_000);
    if (filtered.length === 0) signalSessionRateMap.delete(key);
    else signalSessionRateMap.set(key, filtered);
  }
}, 5 * 60_000);

if (!JWT_SECRET) { console.error("FATAL: JWT_SECRET missing"); process.exit(1); }

const pool = process.env.DATABASE_URL
  ? new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } })
  : new Pool({ host: process.env.DB_HOST, port: parseInt(process.env.DB_PORT), database: process.env.DB_NAME, user: process.env.DB_USER, password: process.env.DB_PASSWORD });

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS licences (
      id                 TEXT PRIMARY KEY,
      license_key        TEXT UNIQUE NOT NULL,
      username           TEXT NOT NULL DEFAULT '',
      machine_id         TEXT,
      status             TEXT NOT NULL DEFAULT 'pending',
      active             BOOLEAN NOT NULL DEFAULT TRUE,
      plan               TEXT NOT NULL DEFAULT 'standard',
      notes              TEXT NOT NULL DEFAULT '',
      duration           INTEGER NOT NULL DEFAULT 30,
      expires_at         TIMESTAMPTZ,
      created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      activated_at       TIMESTAMPTZ,
      last_seen          TIMESTAMPTZ,
      first_ip           TEXT,
      last_ip            TEXT,
      current_version    TEXT,
      browser_info       JSONB,
      deactivated        BOOLEAN NOT NULL DEFAULT FALSE,
      blocked            BOOLEAN NOT NULL DEFAULT FALSE,
      suspicious         BOOLEAN NOT NULL DEFAULT FALSE,
      suspicious_reason  TEXT,
      known_devices      JSONB NOT NULL DEFAULT '[]',
      heartbeat_history  JSONB NOT NULL DEFAULT '[]',
      activation_history JSONB NOT NULL DEFAULT '[]',
      sessions           JSONB NOT NULL DEFAULT '[]',
      booking_events     JSONB NOT NULL DEFAULT '[]',
      signal_sessions    JSONB NOT NULL DEFAULT '[]',
      signal_events      JSONB NOT NULL DEFAULT '[]',
      max_devices        INTEGER NOT NULL DEFAULT 1
    )
  `);
  // Existing Render databases may predate booking_events. CREATE TABLE IF
  // NOT EXISTS does not add new columns to an already-created table.
  await pool.query(`ALTER TABLE licences ADD COLUMN IF NOT EXISTS booking_events JSONB NOT NULL DEFAULT '[]'::jsonb`);
  await pool.query(`ALTER TABLE licences ADD COLUMN IF NOT EXISTS max_devices INTEGER NOT NULL DEFAULT 1`);
  await pool.query(`ALTER TABLE licences ADD COLUMN IF NOT EXISTS signal_sessions JSONB NOT NULL DEFAULT '[]'::jsonb`);
  await pool.query(`ALTER TABLE licences ADD COLUMN IF NOT EXISTS signal_events JSONB NOT NULL DEFAULT '[]'::jsonb`);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS vps_signal_events (
      event_id UUID PRIMARY KEY,
      received_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS vps_signal_events_received_at_idx
      ON vps_signal_events (received_at)
  `);
  await pool.query(`
    DELETE FROM vps_signal_events
      WHERE received_at < NOW() - INTERVAL '24 hours'
  `);
  console.log("[DB] Tables ready");
}

const CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
function generateSegment(len = 5) {
  let seg = ""; const bytes = crypto.randomBytes(len * 2);
  for (let i = 0; i < len; i++) seg += CHARS[bytes[i] % CHARS.length];
  return seg;
}
function generateLicenceKey() { return [1,2,3,4,5].map(() => generateSegment(5)).join("-"); }

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", chunk => (data += chunk));
    req.on("end", () => { try { resolve(JSON.parse(data || "{}")); } catch { resolve({}); } });
    req.on("error", reject);
  });
}

function readRawBody(req, maxBytes = VPS_SIGNAL_BODY_LIMIT_BYTES) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let bytes = 0;
    let tooLarge = false;
    req.on("data", (chunk) => {
      bytes += chunk.length;
      if (bytes > maxBytes) {
        tooLarge = true;
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      if (tooLarge) {
        const error = new Error("payload_too_large");
        error.code = "PAYLOAD_TOO_LARGE";
        return reject(error);
      }
      resolve(Buffer.concat(chunks));
    });
    req.on("error", reject);
  });
}

function equalTextConstantTime(expected, supplied) {
  if (typeof supplied !== "string") return false;
  const expectedBuffer = Buffer.from(expected);
  const suppliedBuffer = Buffer.from(supplied);
  return expectedBuffer.length === suppliedBuffer.length &&
    crypto.timingSafeEqual(expectedBuffer, suppliedBuffer);
}

function verifiedVpsIssuer(req, rawBody) {
  if (!VPS_SIGNAL_ENABLED) return "";
  const keyId = req.headers["x-slothawk-key-id"];
  const timestamp = req.headers["x-slothawk-timestamp"];
  const signature = req.headers["x-slothawk-signature"];

  if (!equalTextConstantTime(VPS_SIGNAL_KEY_ID, keyId) ||
      typeof timestamp !== "string" ||
      !/^\d{10}$/.test(timestamp) ||
      typeof signature !== "string" ||
      !/^[a-f0-9]{64}$/i.test(signature)) {
    return "";
  }

  const timestampMs = Number(timestamp) * 1000;
  if (!Number.isSafeInteger(timestampMs) ||
      Math.abs(Date.now() - timestampMs) > VPS_SIGNAL_MAX_AGE_MS) {
    return "";
  }

  const expectedSignature = crypto
    .createHmac("sha256", VPS_SIGNAL_HMAC_SECRET)
    .update(timestamp, "utf8")
    .update(".", "utf8")
    .update(rawBody)
    .digest("hex");

  return equalTextConstantTime(expectedSignature, signature) ? keyId : "";
}

function normalizeVpsSignal(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) return null;
  const allowedKeys = new Set(["eventId", "mission", "city", "subcategory", "foundAt"]);
  if (Object.keys(body).some((key) => !allowedKeys.has(key))) return null;

  const eventId = String(body.eventId || "").trim();
  const mission = String(body.mission || "").trim().toLowerCase();
  const city = String(body.city || "").trim();
  const subcategory = String(body.subcategory || "").trim();
  const target = VPS_SIGNAL_TARGETS[mission];

  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(eventId) ||
      !target ||
      !target.cities.has(city) ||
      !/^[A-Za-z0-9][A-Za-z0-9 .&()/_-]{0,63}$/.test(subcategory)) {
    return null;
  }

  if (body.foundAt !== undefined) {
    const foundAt = String(body.foundAt);
    if (foundAt.length > 40 || Number.isNaN(Date.parse(foundAt))) return null;
  }

  return { eventId, mission, city, subcategory, missionName: target.missionName };
}

const DEVICE_LIMIT_MIN = 1;
const DEVICE_LIMIT_MAX = 50;

function normalizeDeviceId(value) {
  const id = String(value || "").trim();
  return /^[A-Za-z0-9_-]{16,128}$/.test(id) ? id : "";
}

function normaliseDeviceLimit(value) {
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed >= DEVICE_LIMIT_MIN && parsed <= DEVICE_LIMIT_MAX
    ? parsed
    : DEVICE_LIMIT_MIN;
}

function parseRequestedDeviceLimit(value) {
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed >= DEVICE_LIMIT_MIN && parsed <= DEVICE_LIMIT_MAX
    ? parsed
    : null;
}

function normaliseKnownDevices(value) {
  const source = Array.isArray(value) ? value : [];
  const byMachine = new Map();
  for (const item of source) {
    const machineId = normalizeDeviceId(item?.machineId || item?.machine_id);
    if (!machineId || byMachine.has(machineId)) continue;
    byMachine.set(machineId, {
      machineId,
      ip: typeof item?.ip === "string" ? item.ip.slice(0, 128) : null,
      firstSeenAt: typeof item?.firstSeenAt === "string" ? item.firstSeenAt : null,
      browserInfo: item?.browserInfo && typeof item.browserInfo === "object" ? item.browserInfo : null,
      active: item?.active !== false && !item?.removedAt,
      removedAt: typeof item?.removedAt === "string" ? item.removedAt : null,
    });
  }
  return Array.from(byMachine.values());
}

function activeDevices(value) {
  return normaliseKnownDevices(value).filter((device) => device.active && !device.removedAt);
}

// Profile sessions are display-only presence IDs, distinct from the signed
// Windows device identity. They are accepted only after the JWT and device
// checks in /heartbeat have passed and never affect max_devices.
const PROFILE_SESSION_ID_RE = /^prf-[a-f0-9]{32}\.tab-[1-9][0-9]{0,9}$/i;
const MAX_PROFILE_SESSIONS_PER_HEARTBEAT = 40;

function normaliseProfileSessionIds(value) {
  if (!Array.isArray(value)) return [];
  const ids = [];
  const seen = new Set();
  for (const item of value) {
    const id = String(item || "").trim().toLowerCase();
    if (!PROFILE_SESSION_ID_RE.test(id) || seen.has(id)) continue;
    seen.add(id);
    ids.push(id);
    if (ids.length >= MAX_PROFILE_SESSIONS_PER_HEARTBEAT) break;
  }
  return ids;
}

function sessionProfileId(session) {
  const id = String(session?.profileSessionId || "").trim().toLowerCase();
  return PROFILE_SESSION_ID_RE.test(id) ? id : "";
}

// This is Signal-derived telemetry from the authenticated loopback relay.
// It is intentionally bounded and never changes a licence device limit.
const MAX_SIGNAL_PROFILE_COUNT = MAX_PROFILE_SESSIONS_PER_HEARTBEAT;
function normaliseSignalProfileCount(value) {
  return Number.isInteger(value) && value >= 0 && value <= MAX_SIGNAL_PROFILE_COUNT ? value : null;
}

function isDeviceAllowed(licence, machineId) {
  const id = normalizeDeviceId(machineId);
  if (!id || !licence) return false;
  const devices = normaliseKnownDevices(licence.known_devices);
  const known = devices.find((device) => device.machineId === id);
  if (known) return known.active && !known.removedAt;
  return devices.length === 0 && String(licence.machine_id || "") === id;
}

function licenceStatusReason(licence) {
  if (!licence) return "invalid";
  if (licence.deactivated || licence.status === "revoked" || licence.status === "deactivated") return "revoked";
  if (licence.blocked) return "machine_blocked";
  if (licence.expires_at && new Date() > new Date(licence.expires_at)) return "expired";
  if (licence.status !== "pending" && licence.status !== "active") return "licence_inactive";
  return "";
}

function upsertActiveDevice(value, machineId, ip, browserInfo, nowIso) {
  const id = normalizeDeviceId(machineId);
  const devices = normaliseKnownDevices(value);
  const index = devices.findIndex((device) => device.machineId === id);
  if (index >= 0) {
    if (!devices[index].active || devices[index].removedAt) return { ok: false, devices };
    devices[index] = { ...devices[index], ip, browserInfo, active: true };
    return { ok: true, devices };
  }
  devices.push({ machineId: id, ip, firstSeenAt: nowIso, browserInfo, active: true, removedAt: null });
  return { ok: true, devices };
}

const DEVICE_SECURITY_ENFORCED = String(process.env.DEVICE_SECURITY_ENFORCED || "").toLowerCase() === "true";
const DEVICE_CHALLENGE_PURPOSE = "slothawk-device-attestation-v1";
const DEVICE_CHALLENGE_TTL_SECONDS = 120;
const SECURE_DEVICE_ID_RE = /^sh-[0-9a-f]{32}$/i;
const DEVICE_BROWSER_FAMILIES = new Set(["chrome", "edge", "brave", "opera", "firefox"]);
const usedDeviceChallenges = new Map();

function isLegacyDeviceId(value) {
  return /^(?:dev-[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|fp-[0-9a-f]{16})$/i.test(String(value || ""));
}

function cleanDeviceBrowserFamily(value) {
  const family = String(value || "").trim().toLowerCase();
  return DEVICE_BROWSER_FAMILIES.has(family) ? family : "";
}

function deviceBrowserFamily(device) {
  return cleanDeviceBrowserFamily(device?.browserInfo?.browser_family);
}

function base64UrlBuffer(value) {
  const text = String(value || "");
  if (!/^[A-Za-z0-9_-]+$/.test(text)) return null;
  const padded = text.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((text.length + 3) % 4);
  try { return Buffer.from(padded, "base64"); } catch { return null; }
}

function secureDeviceIdFromPublicKey(publicKey) {
  if (!publicKey || publicKey.kty !== "RSA") return "";
  const modulus = String(publicKey.n || "");
  const exponent = String(publicKey.e || "");
  if (!/^[A-Za-z0-9_-]{300,800}$/.test(modulus) || !/^[A-Za-z0-9_-]{2,16}$/.test(exponent)) return "";
  return "sh-" + crypto.createHash("sha256").update(`v1\n${modulus}\n${exponent}`, "utf8").digest("hex").slice(0, 32);
}

function pruneUsedDeviceChallenges(now = Date.now()) {
  for (const [id, expiresAt] of usedDeviceChallenges) {
    if (expiresAt <= now) usedDeviceChallenges.delete(id);
  }
  while (usedDeviceChallenges.size > 2048) {
    const oldest = usedDeviceChallenges.keys().next().value;
    if (!oldest) break;
    usedDeviceChallenges.delete(oldest);
  }
}

function consumeDeviceChallenge(id) {
  const key = String(id || "");
  if (!/^[0-9a-f-]{36}$/i.test(key)) return false;
  const now = Date.now();
  pruneUsedDeviceChallenges(now);
  if (usedDeviceChallenges.has(key)) return false;
  usedDeviceChallenges.set(key, now + DEVICE_CHALLENGE_TTL_SECONDS * 1000);
  return true;
}

function issueDeviceChallenge(key) {
  return jwt.sign({
    purpose: DEVICE_CHALLENGE_PURPOSE,
    licence_key: key,
    challenge_id: uuidv4(),
    nonce: crypto.randomBytes(24).toString("base64url"),
  }, JWT_SECRET, { expiresIn: DEVICE_CHALLENGE_TTL_SECONDS });
}

function verifyDeviceAttestation(raw, licenceKey, expectedMachineId) {
  const attestation = raw && typeof raw === "object" && !Array.isArray(raw) ? raw : null;
  if (!attestation) return { ok: false, reason: "device_attestation_required" };

  const challengeText = String(attestation.challenge || "");
  const browserFamily = cleanDeviceBrowserFamily(attestation.browser_family);
  const publicKey = attestation.public_key;
  const signature = base64UrlBuffer(attestation.signature);
  const machineId = String(expectedMachineId || "").trim().toLowerCase();
  if (!SECURE_DEVICE_ID_RE.test(machineId) || !browserFamily || !signature || signature.length < 128 || signature.length > 1024) {
    return { ok: false, reason: "invalid_device_attestation" };
  }

  let challenge;
  try { challenge = jwt.verify(challengeText, JWT_SECRET); }
  catch { return { ok: false, reason: "invalid_device_attestation" }; }

  if (challenge?.purpose !== DEVICE_CHALLENGE_PURPOSE ||
      String(challenge?.licence_key || "") !== String(licenceKey || "") ||
      !/^[0-9a-f-]{36}$/i.test(String(challenge?.challenge_id || ""))) {
    return { ok: false, reason: "invalid_device_attestation" };
  }

  const derivedMachineId = secureDeviceIdFromPublicKey(publicKey);
  if (!derivedMachineId || !equalTextConstantTime(derivedMachineId, machineId)) {
    return { ok: false, reason: "invalid_device_attestation" };
  }

  try {
    const verifier = crypto.createPublicKey({ key: { kty: "RSA", n: publicKey.n, e: publicKey.e }, format: "jwk" });
    const message = Buffer.from(`v1\n${challengeText}\n${machineId}\n${browserFamily}`, "utf8");
    if (!crypto.verify("RSA-SHA256", message, verifier, signature)) {
      return { ok: false, reason: "invalid_device_attestation" };
    }
  } catch {
    return { ok: false, reason: "invalid_device_attestation" };
  }

  if (!consumeDeviceChallenge(challenge.challenge_id)) return { ok: false, reason: "replayed_device_attestation" };
  return { ok: true, browserInfo: { browser_family: browserFamily } };
}

function normaliseAttestedBrowserInfo(attestationResult, body) {
  const version = String(body?.browser_info?.extension_version || "").replace(/[\u0000-\u001F\u007F]/g, "").trim().slice(0, 32);
  return { extension_version: version, browser_family: attestationResult.browserInfo.browser_family };
}

function hasBrowserMismatch(device, browserInfo) {
  const bound = deviceBrowserFamily(device);
  const presented = cleanDeviceBrowserFamily(browserInfo?.browser_family);
  return !!bound && !!presented && bound !== presented;
}

function buildLicenceToken(key, machineId, username, expiresAt) {
  return jwt.sign(
    { license_key: key, machine_id: machineId, username: username || "", expires_at: expiresAt instanceof Date ? expiresAt.toISOString() : expiresAt },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES }
  );
}


const SIGNAL_CHALLENGE_PURPOSE = "slothawk-signal-challenge-v1";
const SIGNAL_SESSION_PURPOSE = "slothawk-signal-session-v1";
const SIGNAL_CHALLENGE_TTL_SECONDS = 90;
const SIGNAL_SESSION_TTL_SECONDS = 10 * 60;
const SIGNAL_SESSION_HISTORY_LIMIT = 50;
const SIGNAL_EVENT_HISTORY_LIMIT = 50;
const usedSignalChallenges = new Map();

function pruneUsedSignalChallenges(now = Date.now()) {
  for (const [id, expiresAt] of usedSignalChallenges) {
    if (expiresAt <= now) usedSignalChallenges.delete(id);
  }
  while (usedSignalChallenges.size > 2048) {
    const oldest = usedSignalChallenges.keys().next().value;
    if (!oldest) break;
    usedSignalChallenges.delete(oldest);
  }
}

function consumeSignalChallenge(id) {
  const value = String(id || "");
  if (!/^[0-9a-f-]{36}$/i.test(value)) return false;
  pruneUsedSignalChallenges();
  if (usedSignalChallenges.has(value)) return false;
  usedSignalChallenges.set(value, Date.now() + SIGNAL_CHALLENGE_TTL_SECONDS * 1000);
  return true;
}

function issueSignalChallenge(key) {
  return jwt.sign({
    purpose: SIGNAL_CHALLENGE_PURPOSE,
    licence_key: key,
    challenge_id: uuidv4(),
    nonce: crypto.randomBytes(24).toString("base64url"),
  }, JWT_SECRET, { expiresIn: SIGNAL_CHALLENGE_TTL_SECONDS });
}

function normaliseSignalSessions(value) {
  if (!Array.isArray(value)) return [];
  const sessions = [];
  for (const raw of value) {
    const id = String(raw?.id || "");
    const machineId = normalizeDeviceId(raw?.machineId);
    const issuedAt = typeof raw?.issuedAt === "string" ? raw.issuedAt : null;
    const expiresAt = typeof raw?.expiresAt === "string" ? raw.expiresAt : null;
    if (!/^[0-9a-f-]{36}$/i.test(id) || !machineId || !issuedAt || !expiresAt) continue;
    sessions.push({
      id,
      machineId,
      issuedAt,
      expiresAt,
      lastVerifiedAt: typeof raw?.lastVerifiedAt === "string" ? raw.lastVerifiedAt : issuedAt,
      version: typeof raw?.version === "string" ? raw.version.slice(0, 32) : "",
      ip: typeof raw?.ip === "string" ? raw.ip.slice(0, 128) : "",
      revokedAt: typeof raw?.revokedAt === "string" ? raw.revokedAt : null,
      revokeReason: typeof raw?.revokeReason === "string" ? raw.revokeReason.slice(0, 48) : null,
    });
    if (sessions.length >= SIGNAL_SESSION_HISTORY_LIMIT) break;
  }
  return sessions;
}

function normaliseSignalEvents(value) {
  if (!Array.isArray(value)) return [];
  const events = [];
  for (const raw of value) {
    const type = String(raw?.type || "").slice(0, 48);
    const at = typeof raw?.at === "string" ? raw.at : "";
    if (!type || !at) continue;
    events.push({
      id: /^[0-9a-f-]{36}$/i.test(String(raw?.id || "")) ? raw.id : uuidv4(),
      type,
      at,
      machineId: normalizeDeviceId(raw?.machineId) || null,
      ip: typeof raw?.ip === "string" ? raw.ip.slice(0, 128) : "",
      detail: typeof raw?.detail === "string" ? raw.detail.slice(0, 96) : "",
    });
    if (events.length >= SIGNAL_EVENT_HISTORY_LIMIT) break;
  }
  return events;
}

function addSignalEvent(events, type, machineId, ip, detail = "") {
  const next = normaliseSignalEvents(events);
  next.unshift({ id: uuidv4(), type, at: new Date().toISOString(), machineId: normalizeDeviceId(machineId) || null, ip: String(ip || "").slice(0, 128), detail: String(detail || "").slice(0, 96) });
  if (next.length > SIGNAL_EVENT_HISTORY_LIMIT) next.length = SIGNAL_EVENT_HISTORY_LIMIT;
  return next;
}

function issueSignalSession(key, machineId, sessionId) {
  return jwt.sign({
    purpose: SIGNAL_SESSION_PURPOSE,
    licence_key: key,
    machine_id: machineId,
    signal_session_id: sessionId,
  }, JWT_SECRET, { expiresIn: SIGNAL_SESSION_TTL_SECONDS });
}

function verifySignalAttestation(body, licenceKey, expectedMachineId) {
  const challengeText = String(body?.challenge || "");
  const publicKey = body?.public_key;
  const signature = base64UrlBuffer(body?.signature);
  const machineId = String(expectedMachineId || "").trim().toLowerCase();
  if (!SECURE_DEVICE_ID_RE.test(machineId) || !signature || signature.length < 128 || signature.length > 1024) {
    return { ok: false, reason: "invalid_signal_attestation" };
  }

  let challenge;
  try { challenge = jwt.verify(challengeText, JWT_SECRET); }
  catch { return { ok: false, reason: "invalid_signal_attestation" }; }

  if (challenge?.purpose !== SIGNAL_CHALLENGE_PURPOSE ||
      String(challenge?.licence_key || "") !== String(licenceKey || "") ||
      !/^[0-9a-f-]{36}$/i.test(String(challenge?.challenge_id || ""))) {
    return { ok: false, reason: "invalid_signal_attestation" };
  }

  const derivedMachineId = secureDeviceIdFromPublicKey(publicKey);
  if (!derivedMachineId || !equalTextConstantTime(derivedMachineId, machineId)) {
    return { ok: false, reason: "invalid_signal_attestation" };
  }

  try {
    const verifier = crypto.createPublicKey({ key: { kty: "RSA", n: publicKey.n, e: publicKey.e }, format: "jwk" });
    const message = Buffer.from(`signal-v1\n${challengeText}\n${machineId}`, "utf8");
    if (!crypto.verify("RSA-SHA256", message, verifier, signature)) {
      return { ok: false, reason: "invalid_signal_attestation" };
    }
  } catch {
    return { ok: false, reason: "invalid_signal_attestation" };
  }

  if (!consumeSignalChallenge(challenge.challenge_id)) return { ok: false, reason: "replayed_signal_attestation" };
  return { ok: true };
}

function verifyActiveSignalSession(rawToken, licenceKey, machineId, sessions) {
  const token = String(rawToken || "");
  if (!token) return { ok: false, reason: "signal_required" };
  let decoded;
  try { decoded = jwt.verify(token, JWT_SECRET); }
  catch { return { ok: false, reason: "signal_session_invalid" }; }

  const sessionId = String(decoded?.signal_session_id || "");
  if (decoded?.purpose !== SIGNAL_SESSION_PURPOSE ||
      String(decoded?.licence_key || "") !== String(licenceKey || "") ||
      String(decoded?.machine_id || "") !== String(machineId || "") ||
      !/^[0-9a-f-]{36}$/i.test(sessionId)) {
    return { ok: false, reason: "signal_session_invalid" };
  }
  const session = normaliseSignalSessions(sessions).find((item) => item.id === sessionId && item.machineId === machineId);
  const expiry = Date.parse(session?.expiresAt || "");
  if (!session || session.revokedAt || !Number.isFinite(expiry) || expiry <= Date.now()) {
    return { ok: false, reason: "signal_session_invalid" };
  }
  return { ok: true, sessionId };
}

function requiresSignalSession(browserInfo) {
  const major = Number(String(browserInfo?.extension_version || "").split(".")[0]);
  return Number.isInteger(major) && major >= 2;
}

function signalSecuritySummary(row) {
  const now = Date.now();
  const sessions = normaliseSignalSessions(row?.signal_sessions);
  const active = sessions.filter((session) => !session.revokedAt && Date.parse(session.expiresAt) > now);
  return {
    active: active.length > 0,
    activeSessionCount: active.length,
    sessions: sessions.map((session) => ({
      machineId: session.machineId,
      issuedAt: session.issuedAt,
      lastVerifiedAt: session.lastVerifiedAt,
      expiresAt: session.expiresAt,
      revokedAt: session.revokedAt,
      version: session.version,
    })),
    events: normaliseSignalEvents(row?.signal_events),
  };
}

function legacyDeviceFromLicence(licence, devices, machineId) {
  const known = devices.find((device) => device.machineId === machineId);
  if (known) return known;
  if (!devices.length && String(licence?.machine_id || "") === machineId) {
    return { machineId, ip: null, firstSeenAt: licence?.activated_at ? new Date(licence.activated_at).toISOString() : null, browserInfo: null, active: true, removedAt: null };
  }
  return null;
}

function json(res, statusCode, body) {
  res.writeHead(statusCode, {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, PATCH, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-API-Key",
  });
  res.end(JSON.stringify(body));
}

function isAdminRoute(url) {
  return url === "/admin/licences" ||
    url.startsWith("/admin/licences/") ||
    url === "/api/admin/licences" ||
    url.startsWith("/api/admin/licences/");
}

function hasValidDashboardApiKey(req) {
  const supplied = req.headers["x-api-key"];
  if (!DASHBOARD_API_KEY || typeof supplied !== "string") return false;

  const expected = Buffer.from(DASHBOARD_API_KEY);
  const actual = Buffer.from(supplied);
  return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
}

function getClientIp(req) {
  return (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").split(",")[0].trim();
}

function extractIdFromUrl(url) {
  const parts = url.split("/").filter(Boolean);
  return parts[parts.length - 2];
}

function mapRow(r) {
  if (!r) return null;
  const now = Date.now();
  const knownDevices = normaliseKnownDevices(r.known_devices);
  const activeDeviceCount = activeDevices(knownDevices).length;
  const activeMachineIds = new Set(activeDevices(knownDevices).map((device) => device.machineId));
  const legacyMachineId = normalizeDeviceId(r.machine_id);
  if (activeMachineIds.size === 0 && legacyMachineId) activeMachineIds.add(legacyMachineId);

  const onlineSessions = (Array.isArray(r.sessions) ? r.sessions : [])
    .filter((session) => {
      const machineId = normalizeDeviceId(session?.machineId);
      const lastPingAt = Date.parse(session?.lastPingAt || "");
      return Boolean(
        machineId &&
        activeMachineIds.has(machineId) &&
        !session?.endedAt &&
        Number.isFinite(lastPingAt) &&
        now - lastPingAt <= PANEL_SESSION_GAP
      );
    });
  // New clients report one signed-device-authorised session per open VFS
  // panel. Legacy clients keep the former one-profile-per-machine fallback.
  const machinesWithPanelSessions = new Set(
    onlineSessions.filter((session) => sessionProfileId(session))
      .map((session) => normalizeDeviceId(session.machineId))
  );
  const onlineProfilesByMachine = new Map();
  for (const session of onlineSessions) {
    const panelId = sessionProfileId(session);
    const machineId = normalizeDeviceId(session.machineId);
    if (!machineId) continue;
    if (!onlineProfilesByMachine.has(machineId)) onlineProfilesByMachine.set(machineId, new Set());
    if (panelId) onlineProfilesByMachine.get(machineId).add(panelId);
    else if (!machinesWithPanelSessions.has(machineId)) onlineProfilesByMachine.get(machineId).add(`legacy:${machineId}`);
  }

  // Prefer the live count from SlotHawk Signal whenever it is present for a
  // currently active device. Older clients retain the heartbeat-panel count.
  const freshSignalCounts = new Map();
  for (const heartbeat of (Array.isArray(r.heartbeat_history) ? r.heartbeat_history : [])) {
    const machineId = normalizeDeviceId(heartbeat?.machineId);
    const count = normaliseSignalProfileCount(heartbeat?.signalProfileCount);
    const at = Date.parse(heartbeat?.createdAt || "");
    if (!machineId || !activeMachineIds.has(machineId) || count === null || !Number.isFinite(at) || now - at > PANEL_SESSION_GAP) continue;
    const previous = freshSignalCounts.get(machineId);
    if (!previous || at > previous.at) freshSignalCounts.set(machineId, { count, at });
  }

  let onlineProfileCount = 0;
  for (const machineId of activeMachineIds) {
    const signalCount = freshSignalCounts.get(machineId);
    onlineProfileCount += signalCount ? signalCount.count : (onlineProfilesByMachine.get(machineId)?.size || 0);
  }

  return {
    id: r.id,
    key: r.license_key, licenseKey: r.license_key, licenceKey: r.license_key, license_key: r.license_key,
    username: r.username || '',
    machineId: r.machine_id, machine_id: r.machine_id,
    status: r.status, active: r.active, plan: r.plan, notes: r.notes || '', duration: r.duration,
    expiresAt: r.expires_at, expires_at: r.expires_at,
    createdAt: r.created_at, created_at: r.created_at,
    activatedAt: r.activated_at, activated_at: r.activated_at,
    lastSeen: r.last_seen, last_seen: r.last_seen,
    firstIp: r.first_ip, first_ip: r.first_ip,
    lastIp: r.last_ip, last_ip: r.last_ip,
    currentVersion: r.current_version, current_version: r.current_version,
    browserInfo: r.browser_info, browser_info: r.browser_info,
    deactivated: r.deactivated || false, blocked: r.blocked || false,
    suspicious: r.suspicious || false,
    suspiciousReason: r.suspicious_reason, suspicious_reason: r.suspicious_reason,
    knownDevices, known_devices: knownDevices,
    maxDevices: normaliseDeviceLimit(r.max_devices), max_devices: normaliseDeviceLimit(r.max_devices),
    activeDeviceCount, active_device_count: activeDeviceCount,
    onlineProfileCount, online_profile_count: onlineProfileCount,
    heartbeatHistory: r.heartbeat_history || [], heartbeat_history: r.heartbeat_history || [],
    activationHistory: r.activation_history || [], activation_history: r.activation_history || [],
    sessions: r.sessions || [],
    bookingEvents: r.booking_events || [], booking_events: r.booking_events || [],
    signalSecurity: signalSecuritySummary(r), signal_security: signalSecuritySummary(r),
  };
}

// ── Telegram message builder ─────────────────────────────────────────
// Moved server-side so the format can evolve without shipping a new
// extension release. Extension only sends structured alert data; the
// final rendered message is built here.
//
// IMPORTANT: the availability date is NEVER included in the alert. If a
// subscriber could read the date from Telegram, they could book the
// slot themselves without needing the extension, which defeats the
// point of the subscription. Only country, category, and city ship out.
function escapeMarkdownV2(text) {
  return String(text).replace(/[_*[\]()~`>#+\-=|{}.!\\]/g, ch => `\\${ch}`);
}

function formatMoroccoTimestamp(date) {
  // Morocco is UTC+1 during DST; shift so the printed time matches the
  // subscriber's wall clock.
  const shifted = new Date(date.getTime() + 60 * 60 * 1000);
  const pad = n => String(n).padStart(2, "0");
  return `${pad(shifted.getUTCHours())}:${pad(shifted.getUTCMinutes())}:${pad(shifted.getUTCSeconds())}`;
}

const MISSION_FLAGS = {
  Malta: "🇲🇹", Austria: "🇦🇹", Finland: "🇫🇮", Sweden: "🇸🇪",
  Croatia: "🇭🇷", Netherlands: "🇳🇱",
};
const CITY_NAMES = {
  MLMCS: "Casablanca", MLMRBT: "Rabat", MLMTGR: "Tangier",
  ASCA: "Casablanca", ASRB: "Rabat", TVC: "Tangier",
  NER: "Rabat", NTTG: "Tangier", Rbt: "Rabat", SWRA: "Rabat", CVARC: "Rabat",
};

// The VPS can only signal destinations SlotHawk explicitly supports. The
// human-readable country/city strings are server-owned, never trusted input.
const VPS_SIGNAL_TARGETS = Object.freeze({
  mlt: Object.freeze({ missionName: "Malta",       cities: new Set(["MLMCS", "MLMRBT", "MLMTGR"]) }),
  aut: Object.freeze({ missionName: "Austria",     cities: new Set(["ASCA", "ASRB", "TVC"]) }),
  fin: Object.freeze({ missionName: "Finland",     cities: new Set(["Rbt"]) }),
  swe: Object.freeze({ missionName: "Sweden",      cities: new Set(["SWRA"]) }),
  hrv: Object.freeze({ missionName: "Croatia",     cities: new Set(["CVARC"]) }),
  nld: Object.freeze({ missionName: "Netherlands", cities: new Set(["NER", "NTTG"]) }),
});

function buildSlotAlertMessage({ missionName, city, subcategory }) {
  const flag     = MISSION_FLAGS[missionName] || "🌍";
  const cityName = CITY_NAMES[city] || city || "Unknown";
  const time     = formatMoroccoTimestamp(new Date());

  return [
    "🦅 *SLOTHAWK SPOTTED A SLOT* 🦅",
    "▬▬▬▬▬▬▬▬▬▬▬▬▬▬",
    `PAYS: ${escapeMarkdownV2(missionName)} ${flag}`,
    `TYPE: ${escapeMarkdownV2(subcategory)}`,
    `📍 *${escapeMarkdownV2(cityName)}*`,
    `Spotted at ${escapeMarkdownV2(time)}`,
    "🛩️ *DIVE IN NOW*",
  ].join("\n");
}

// Post a pre-built message to one Telegram chat. Returns {ok, error?}
// so callers can decide whether to abort a request or continue with
// other channels. Empty chatId is treated as a soft no-op so the same
// call site works whether only one of Pro/Legacy is configured.
async function sendTelegramToChat(chatId, message, contextLabel) {
  if (!chatId) return { ok: false, error: "chat_id_not_configured" };
  try {
    const tgRes = await fetch(
      `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          chat_id:    chatId,
          text:       message,
          parse_mode: "MarkdownV2",
        }),
      }
    );
    const data = await tgRes.json().catch(() => null);
    if (!tgRes.ok || !data?.ok) {
      const desc = data?.description || `HTTP ${tgRes.status}`;
      console.error(`[TELEGRAM][${contextLabel}] Send failed to ${chatId}: ${desc}`);
      return { ok: false, error: desc };
    }
    return { ok: true };
  } catch (err) {
    console.error(`[TELEGRAM][${contextLabel}] Fetch error for ${chatId}: ${err.message}`);
    return { ok: false, error: err.message };
  }
}

// Schedule a legacy-channel send after TELEGRAM_LEGACY_DELAY_MS. Uses
// in-memory setTimeout (Q1 = A "Simple") — a redeploy or crash during
// the 10-min window will drop the pending sends, which is accepted as
// the cost of not maintaining a persistent queue. Errors are logged
// only; they can't propagate back to the caller by then.
function scheduleLegacyTelegramSend(message, licenceKey) {
  if (!TELEGRAM_CHAT_ID) return;
  setTimeout(async () => {
    const result = await sendTelegramToChat(TELEGRAM_CHAT_ID, message, "LEGACY");
    if (result.ok) {
      console.log(`[ALERT] Delayed legacy send for ${licenceKey} succeeded (${TELEGRAM_LEGACY_DELAY_MS}ms after Pro)`);
    }
    // Errors already logged by sendTelegramToChat; nothing else we can
    // do — the request that scheduled this returned long ago.
  }, TELEGRAM_LEGACY_DELAY_MS).unref?.();
  // unref() lets Node exit cleanly even if a pending timer is queued,
  // which matters for graceful shutdown on Render redeploys.
}

const server = http.createServer(async (req, res) => {
  if (req.method === "OPTIONS") {
    res.writeHead(204, {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, PATCH, DELETE, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization, X-API-Key",
    });
    return res.end();
  }

  const url = req.url.split("?")[0];

  // The dashboard backend is the only allowed caller for licence-admin
  // routes. All extension endpoints keep their existing JWT-based access.
  if (isAdminRoute(url) && !hasValidDashboardApiKey(req)) {
    return json(res, 401, { ok: false, error: "Unauthorized" });
  }

  if (req.method === "GET" && url === "/health") {
    return json(res, 200, { status: "ok", version: "7.3.0", requiredExtensionVersion: process.env.REQUIRED_VERSION || "0.2.10" });
  }
  if (req.method === "GET" && url === "/version") {
    return json(res, 200, { required: process.env.REQUIRED_VERSION || "0.2.10" });
  }
  if (req.method === "GET" && url === "/status") {
    return json(res, 200, { ok: true, counts: { mlt: 0, aut: 0 } });
  }

  // ── POST /admin/licences/generate ─────────────────────────────────────────
  if (req.method === "POST" && (url === "/api/admin/licences/generate" || url === "/admin/licences/generate")) {
    const body     = await readBody(req);
    const duration = parseInt(body.duration_days || body.duration) || 30;
    const username = body.username || "";
    const plan     = body.plan || "standard";
    const requestedMaxDevices = parseRequestedDeviceLimit(body.maxDevices ?? body.max_devices ?? 1);
    if (requestedMaxDevices === null) return json(res, 400, { ok: false, error: "maxDevices must be an integer between 1 and 50" });
    const key      = generateLicenceKey();
    const id       = uuidv4();
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + duration);
    try {
      const { rows } = await pool.query(
        `INSERT INTO licences (id, license_key, username, plan, status, duration, expires_at, max_devices) VALUES ($1, $2, $3, $4, 'pending', $5, $6, $7) RETURNING *`,
        [id, key, username, plan, duration, expiresAt, requestedMaxDevices]
      );
      console.log(`[GENERATE] key=${key}`);
      return json(res, 200, { ok: true, key, license_key: key, id, duration_days: duration, licences: [mapRow(rows[0])] });
    } catch (err) {
      console.error("[GENERATE] error:", err.message);
      return json(res, 500, { ok: false, error: err.message });
    }
  }

  // ── GET /admin/licences (list) ────────────────────────────────────────────
  if (req.method === "GET" && (url === "/api/admin/licences" || url === "/admin/licences")) {
    try {
      const { rows } = await pool.query(`SELECT * FROM licences ORDER BY created_at DESC LIMIT 100`);
      const mapped = rows.map(mapRow);
      return json(res, 200, { data: mapped, licences: mapped, total: mapped.length, page: 1, limit: 100, totalPages: 1 });
    } catch (err) {
      return json(res, 500, { ok: false, error: err.message });
    }
  }


  // ── PATCH /admin/licences/:id/signal/reset|revoke ─────────────────────────
  if (req.method === "PATCH" && (url.endsWith("/signal/reset") || url.endsWith("/signal/revoke"))) {
    const parts = url.split("/").filter(Boolean);
    const marker = parts.lastIndexOf("licences");
    const id = marker >= 0 ? parts[marker + 1] : "";
    if (!id) return json(res, 400, { ok: false, error: "Licence not found" });
    const action = url.endsWith("/signal/revoke") ? "revoked_by_admin" : "reset_by_admin";
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const locked = await client.query(`SELECT * FROM licences WHERE id = $1 OR license_key = $1 FOR UPDATE`, [id]);
      const licence = locked.rows[0];
      if (!licence) { await client.query("ROLLBACK"); return json(res, 404, { ok: false, error: "Licence not found" }); }
      const now = new Date().toISOString();
      const sessions = normaliseSignalSessions(licence.signal_sessions).map((session) => (
        session.revokedAt ? session : { ...session, revokedAt: now, revokeReason: action }
      ));
      const events = addSignalEvent(licence.signal_events, action, "", getClientIp(req), "");
      const updated = await client.query(`UPDATE licences SET signal_sessions = $1, signal_events = $2 WHERE id = $3 RETURNING *`, [JSON.stringify(sessions), JSON.stringify(events), licence.id]);
      await client.query("COMMIT");
      return json(res, 200, { ok: true, licence: mapRow(updated.rows[0]) });
    } catch {
      await client.query("ROLLBACK").catch(() => {});
      return json(res, 500, { ok: false, error: "DB error" });
    } finally { client.release(); }
  }

  // ── PATCH /admin/licences/:id/device-limit ─────────────────────────────
  if (req.method === "PATCH" && url.endsWith("/device-limit")) {
    const id = extractIdFromUrl(url);
    const body = await readBody(req);
    const requestedMaxDevices = parseRequestedDeviceLimit(body.maxDevices ?? body.max_devices);
    if (requestedMaxDevices === null) return json(res, 400, { ok: false, error: "maxDevices must be an integer between 1 and 50" });
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const locked = await client.query(`SELECT * FROM licences WHERE id = $1 OR license_key = $1 FOR UPDATE`, [id]);
      const licence = locked.rows[0];
      if (!licence) { await client.query("ROLLBACK"); return json(res, 404, { ok: false, error: "Licence not found" }); }
      const devices = activeDevices(licence.known_devices);
      if (requestedMaxDevices < devices.length) {
        await client.query("ROLLBACK");
        return json(res, 409, { ok: false, error: "Device limit cannot be below the number of active devices" });
      }
      const updated = await client.query(`UPDATE licences SET max_devices = $1 WHERE id = $2 RETURNING *`, [requestedMaxDevices, licence.id]);
      await client.query("COMMIT");
      return json(res, 200, { ok: true, licence: mapRow(updated.rows[0]) });
    } catch (err) {
      await client.query("ROLLBACK").catch(() => {});
      return json(res, 500, { ok: false, error: "DB error" });
    } finally { client.release(); }
  }

  // ── PATCH /admin/licences/:id/devices/remove ────────────────────────────
  if (req.method === "PATCH" && url.endsWith("/devices/remove")) {
    const parts = url.split("/").filter(Boolean);
    const deviceIndex = parts.lastIndexOf("devices");
    const id = deviceIndex > 0 ? parts[deviceIndex - 1] : "";
    const body = await readBody(req);
    const machineId = normalizeDeviceId(body.machineId);
    if (!id || !machineId) return json(res, 400, { ok: false, error: "Invalid device" });
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const locked = await client.query(`SELECT * FROM licences WHERE id = $1 OR license_key = $1 FOR UPDATE`, [id]);
      const licence = locked.rows[0];
      if (!licence) { await client.query("ROLLBACK"); return json(res, 404, { ok: false, error: "Licence not found" }); }
      const devices = normaliseKnownDevices(licence.known_devices);
      const index = devices.findIndex((device) => device.machineId === machineId && device.active && !device.removedAt);
      if (index < 0) { await client.query("ROLLBACK"); return json(res, 404, { ok: false, error: "Active device not found" }); }
      devices[index] = { ...devices[index], active: false, removedAt: new Date().toISOString() };
      const updated = await client.query(`UPDATE licences SET known_devices = $1 WHERE id = $2 RETURNING *`, [JSON.stringify(devices), licence.id]);
      await client.query("COMMIT");
      disconnectSignalDevice(licence.license_key, machineId);
      return json(res, 200, { ok: true, licence: mapRow(updated.rows[0]) });
    } catch (err) {
      await client.query("ROLLBACK").catch(() => {});
      return json(res, 500, { ok: false, error: "DB error" });
    } finally { client.release(); }
  }
  // ── PATCH /admin/licences/:id/devices/restore ───────────────────────────
  if (req.method === "PATCH" && url.endsWith("/devices/restore")) {
    const parts = url.split("/").filter(Boolean);
    const devicesIndex = parts.lastIndexOf("devices");
    const id = devicesIndex > 0 ? parts[devicesIndex - 1] : "";
    const body = await readBody(req);
    const machineId = normalizeDeviceId(body.machineId);
    if (!id || !machineId) return json(res, 400, { ok: false, error: "Invalid device" });

    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const locked = await client.query(`SELECT * FROM licences WHERE id = $1 OR license_key = $1 FOR UPDATE`, [id]);
      const licence = locked.rows[0];
      if (!licence) {
        await client.query("ROLLBACK");
        return json(res, 404, { ok: false, error: "Licence not found" });
      }

      const devices = normaliseKnownDevices(licence.known_devices);
      const index = devices.findIndex((device) => device.machineId === machineId && (!device.active || device.removedAt));
      if (index < 0) {
        await client.query("ROLLBACK");
        return json(res, 404, { ok: false, error: "Removed device not found" });
      }

      if (activeDevices(devices).length >= normaliseDeviceLimit(licence.max_devices)) {
        await client.query("ROLLBACK");
        return json(res, 409, { ok: false, error: "Device limit reached. Increase the limit before restoring this device." });
      }

      devices[index] = { ...devices[index], active: true, removedAt: null };
      const updated = await client.query(
        `UPDATE licences SET known_devices = $1 WHERE id = $2 RETURNING *`,
        [JSON.stringify(devices), licence.id]
      );
      await client.query("COMMIT");
      return json(res, 200, { ok: true, licence: mapRow(updated.rows[0]) });
    } catch (err) {
      await client.query("ROLLBACK").catch(() => {});
      return json(res, 500, { ok: false, error: "DB error" });
    } finally {
      client.release();
    }
  }

  // ── PATCH /admin/licences/:id/username ────────────────────────────────────
  if (req.method === "PATCH" && url.endsWith("/username")) {
    const id = extractIdFromUrl(url);
    const body = await readBody(req);
    const username = typeof body.username === "string" ? body.username.trim().replace(/\s+/g, " ") : "";
    if (!username || username.length > 60) {
      return json(res, 400, { ok: false, error: "Username must be between 1 and 60 characters" });
    }
    try {
      const result = await pool.query(
        `UPDATE licences SET username = $1 WHERE id = $2 OR license_key = $2 RETURNING *`,
        [username, id]
      );
      if (!result.rows.length) return json(res, 404, { ok: false, error: "Licence not found" });
      return json(res, 200, { ok: true, licence: mapRow(result.rows[0]) });
    } catch (err) {
      return json(res, 500, { ok: false, error: "DB error" });
    }
  }

  // ── PATCH /admin/licences/:id/revoke ──────────────────────────────────────
  if (req.method === "PATCH" && url.includes("/revoke")) {
    const id = extractIdFromUrl(url);
    try {
      const result = await pool.query(`UPDATE licences SET status = 'revoked', active = FALSE, blocked = TRUE WHERE id = $1 OR license_key = $1 RETURNING license_key`, [id]);
      for (const licence of result.rows) disconnectSignalLicence(licence.license_key);
      console.log(`[REVOKE] id=${id} rows=${result.rowCount}`);
      return json(res, 200, { ok: true });
    } catch (err) { return json(res, 500, { ok: false, error: err.message }); }
  }

  // ── PATCH /admin/licences/:id/reset-machine ───────────────────────────────
  if (req.method === "PATCH" && url.includes("/reset-machine")) {
    const id = extractIdFromUrl(url);
    try {
      const result = await pool.query(`UPDATE licences SET machine_id = NULL, status = 'pending', active = FALSE, blocked = FALSE, suspicious = FALSE, suspicious_reason = NULL, known_devices = '[]' WHERE id = $1 OR license_key = $1 RETURNING license_key`, [id]);
      for (const licence of result.rows) disconnectSignalLicence(licence.license_key);
      console.log(`[RESET-MACHINE] id=${id} rows=${result.rowCount}`);
      return json(res, 200, { ok: true });
    } catch (err) { return json(res, 500, { ok: false, error: err.message }); }
  }

  // ── PATCH /admin/licences/:id/reactivate ──────────────────────────────────
  if (req.method === "PATCH" && url.includes("/reactivate")) {
    const id = extractIdFromUrl(url);
    try {
      const result = await pool.query(`UPDATE licences SET status = CASE WHEN machine_id IS NOT NULL THEN 'active' ELSE 'pending' END, active = TRUE, deactivated = FALSE, blocked = FALSE, suspicious = FALSE, suspicious_reason = NULL WHERE id = $1 OR license_key = $1`, [id]);
      console.log(`[REACTIVATE] id=${id} rows=${result.rowCount}`);
      return json(res, 200, { ok: true });
    } catch (err) { return json(res, 500, { ok: false, error: err.message }); }
  }

  // ── PATCH /admin/licences/:id/deactivate ──────────────────────────────────
  if (req.method === "PATCH" && url.includes("/deactivate")) {
    const id = extractIdFromUrl(url);
    try {
      const result = await pool.query(`UPDATE licences SET status = 'deactivated', active = FALSE, deactivated = TRUE WHERE id = $1 OR license_key = $1 RETURNING license_key`, [id]);
      for (const licence of result.rows) disconnectSignalLicence(licence.license_key);
      console.log(`[DEACTIVATE] id=${id} rows=${result.rowCount}`);
      return json(res, 200, { ok: true });
    } catch (err) { return json(res, 500, { ok: false, error: err.message }); }
  }

  // ── PATCH /admin/licences/:id/clear-block ─────────────────────────────────
  if (req.method === "PATCH" && url.includes("/clear-block")) {
    const id = extractIdFromUrl(url);
    try {
      // Clear Block is the operator's "let this user continue" action.
      // Previously it removed only the block flags while leaving status
      // revoked, so a correctly cleared licence was still rejected by every
      // extension authentication/heartbeat call. Keep the bound machine and
      // restore an unexpired licence to active; an expired licence remains
      // expired and an unbound licence returns to pending activation.
      const result = await pool.query(
        `UPDATE licences SET
          blocked = FALSE,
          suspicious = FALSE,
          suspicious_reason = NULL,
          deactivated = FALSE,
          active = CASE WHEN expires_at IS NULL OR expires_at > NOW() THEN TRUE ELSE FALSE END,
          status = CASE
            WHEN expires_at IS NOT NULL AND expires_at <= NOW() THEN 'expired'
            WHEN machine_id IS NOT NULL THEN 'active'
            ELSE 'pending'
          END
         WHERE id = $1 OR license_key = $1`,
        [id]
      );
      console.log(`[CLEAR-BLOCK] id=${id} rows=${result.rowCount}`);
      return json(res, 200, { ok: true });
    } catch (err) { return json(res, 500, { ok: false, error: err.message }); }
  }

  // ── PATCH /admin/licences/:id/extend ──────────────────────────────────────
  if (req.method === "PATCH" && url.includes("/extend")) {
    const id = extractIdFromUrl(url);
    const body = await readBody(req);
    const days = parseInt(body.days) || 30;
    try {
      const result = await pool.query(
        `UPDATE licences SET expires_at = GREATEST(expires_at, NOW()) + ($1 * INTERVAL '1 day'), duration = duration + $1 WHERE id = $2 OR license_key = $2`,
        [days, id]
      );
      console.log(`[EXTEND] id=${id} days=${days} rows=${result.rowCount}`);
      return json(res, 200, { ok: true });
    } catch (err) { return json(res, 500, { ok: false, error: err.message }); }
  }

  // ── GET /admin/licences/:id (detail) ──────────────────────────────────────
  if (req.method === "GET" && (url.match(/\/api\/admin\/licences\/.+/) || url.match(/\/admin\/licences\/.+/))) {
    const id = url.split("/").pop();
    try {
      const { rows } = await pool.query(`SELECT * FROM licences WHERE id = $1 OR license_key = $1`, [id]);
      if (!rows.length) return json(res, 404, { ok: false, error: "Licence not found" });
      return json(res, 200, mapRow(rows[0]));
    } catch (err) {
      return json(res, 500, { ok: false, error: err.message });
    }
  }

  // ── DELETE /admin/licences/:id ────────────────────────────────────────────
  if (req.method === "DELETE" && (url.startsWith("/api/admin/licences/") || url.startsWith("/admin/licences/"))) {
    const id = url.split("/").filter(Boolean).pop();
    try {
      await pool.query(`DELETE FROM licences WHERE id = $1 OR license_key = $1`, [id]);
      return json(res, 200, { ok: true });
    } catch (err) { return json(res, 500, { ok: false, error: err.message }); }
  }

  // ── POST /generate-licence (legacy) ───────────────────────────────────────
  if (req.method === "POST" && url === "/generate-licence") {
    if (!hasValidDashboardApiKey(req)) return json(res, 401, { ok: false, error: "Unauthorized" });
    const body     = await readBody(req);
    const duration = parseInt(body.duration_days) || 30;
    const requestedMaxDevices = parseRequestedDeviceLimit(body.maxDevices ?? body.max_devices ?? 1);
    if (requestedMaxDevices === null) return json(res, 400, { ok: false, error: "maxDevices must be an integer between 1 and 50" });
    const key      = generateLicenceKey();
    const id       = uuidv4();
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + duration);
    try {
      await pool.query(
        `INSERT INTO licences (id, license_key, status, duration, expires_at, max_devices) VALUES ($1, $2, 'pending', $3, $4, $5)`,
        [id, key, duration, expiresAt, requestedMaxDevices]
      );
      return json(res, 200, { ok: true, key, duration_days: duration });
    } catch (err) {
      return json(res, 500, { ok: false, error: err.message });
    }
  }


  // ── SlotHawk Signal automatic device session ───────────────────────────────
  // The Signal executable proves possession of its Windows-DPAPI RSA key.
  // The returned JWT is short lived, server-tracked, and never persisted by
  // either Signal or the browser extension.
  if (req.method === "POST" && url === "/signal/challenge") {
    const body = await readBody(req);
    const key = String(body?.key || "").trim().toUpperCase();
    if (!key) return json(res, 400, { ok: false, reason: "invalid" });
    if (!checkSignalSessionRateLimit(key, getClientIp(req))) return json(res, 429, { ok: false, reason: "rate_limited" });
    try {
      const { rows } = await pool.query(`SELECT status, expires_at, deactivated, blocked FROM licences WHERE license_key = $1`, [key]);
      const reason = licenceStatusReason(rows[0]);
      if (reason) return json(res, 200, { ok: false, reason });
      return json(res, 200, { ok: true, challenge: issueSignalChallenge(key) });
    } catch {
      return json(res, 500, { ok: false, reason: "signal_unavailable" });
    }
  }

  if (req.method === "POST" && url === "/signal/authorize") {
    const body = await readBody(req);
    const key = String(body?.key || "").trim().toUpperCase();
    const machineId = normalizeDeviceId(body?.machine_id);
    const version = String(body?.version || "").replace(/[\u0000-\u001F\u007F]/g, "").slice(0, 32);
    const ip = getClientIp(req);
    if (!key || !SECURE_DEVICE_ID_RE.test(machineId)) return json(res, 200, { ok: false, reason: "invalid_signal_attestation" });
    const attestation = verifySignalAttestation(body, key, machineId);
    if (!attestation.ok) return json(res, 200, { ok: false, reason: attestation.reason });

    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const locked = await client.query(`SELECT * FROM licences WHERE license_key = $1 FOR UPDATE`, [key]);
      const licence = locked.rows[0];
      const stateReason = licenceStatusReason(licence);
      // The shared status policy deliberately permits a pending licence so its
      // already-registered device can complete the signed Signal bootstrap.
      // Activation still promotes the licence to active; revoked, blocked and
      // expired licences are rejected above.
      if (stateReason) {
        await client.query("ROLLBACK");
        return json(res, 200, { ok: false, reason: stateReason });
      }

      const devices = activeDevices(licence.known_devices);
      const knownDevice = devices.find((device) => device.machineId === machineId);
      // One legacy installation may bootstrap the secure 2.0 migration. It
      // cannot activate a second device: /migrate-device must still prove the
      // valid legacy extension JWT before it replaces that legacy record.
      const legacyBootstrap = !knownDevice && devices.length === 1 && isLegacyDeviceId(devices[0]?.machineId);
      if (!knownDevice && !legacyBootstrap) {
        await client.query("ROLLBACK");
        return json(res, 200, { ok: false, reason: "signal_device_unregistered" });
      }

      const now = new Date();
      const nowIso = now.toISOString();
      const expiresAt = new Date(now.getTime() + SIGNAL_SESSION_TTL_SECONDS * 1000).toISOString();
      const sessions = normaliseSignalSessions(licence.signal_sessions);
      for (const session of sessions) {
        if (!session.revokedAt && session.machineId === machineId) {
          session.revokedAt = nowIso;
          session.revokeReason = "replaced";
        }
      }
      const sessionId = uuidv4();
      sessions.unshift({ id: sessionId, machineId, issuedAt: nowIso, lastVerifiedAt: nowIso, expiresAt, version, ip, revokedAt: null, revokeReason: null });
      if (sessions.length > SIGNAL_SESSION_HISTORY_LIMIT) sessions.length = SIGNAL_SESSION_HISTORY_LIMIT;
      const events = addSignalEvent(licence.signal_events, legacyBootstrap ? "bootstrap_authorized" : "authorized", machineId, ip, version);
      const updated = await client.query(
        `UPDATE licences SET signal_sessions = $1, signal_events = $2 WHERE id = $3 RETURNING *`,
        [JSON.stringify(sessions), JSON.stringify(events), licence.id]
      );
      await client.query("COMMIT");
      return json(res, 200, { ok: true, token: issueSignalSession(key, machineId, sessionId), expiresAt, signalSecurity: signalSecuritySummary(updated.rows[0]) });
    } catch (err) {
      await client.query("ROLLBACK").catch(() => {});
      return json(res, 500, { ok: false, reason: "signal_unavailable" });
    } finally { client.release(); }
  }

  if (req.method === "POST" && url === "/signal/heartbeat") {
    const body = await readBody(req);
    const token = String(body?.token || "").trim();
    let decoded;
    try { decoded = jwt.verify(token, JWT_SECRET); }
    catch { return json(res, 200, { ok: false, reason: "signal_session_invalid" }); }
    const key = String(decoded?.licence_key || "").trim().toUpperCase();
    const machineId = normalizeDeviceId(decoded?.machine_id);
    const sessionId = String(decoded?.signal_session_id || "");
    if (decoded?.purpose !== SIGNAL_SESSION_PURPOSE || !key || !SECURE_DEVICE_ID_RE.test(machineId) || !/^[0-9a-f-]{36}$/i.test(sessionId)) {
      return json(res, 200, { ok: false, reason: "signal_session_invalid" });
    }

    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const locked = await client.query(`SELECT * FROM licences WHERE license_key = $1 FOR UPDATE`, [key]);
      const licence = locked.rows[0];
      const stateReason = licenceStatusReason(licence);
      // Keep the renewal rule identical to /signal/authorize. A previously
      // accepted pending bootstrap remains usable until activation completes.
      if (stateReason || !isDeviceAllowed(licence, machineId)) {
        await client.query("ROLLBACK");
        return json(res, 200, { ok: false, reason: stateReason || "device_removed" });
      }
      const sessions = normaliseSignalSessions(licence.signal_sessions);
      const index = sessions.findIndex((session) => session.id === sessionId && session.machineId === machineId);
      if (index < 0 || sessions[index].revokedAt) {
        await client.query("ROLLBACK");
        return json(res, 200, { ok: false, reason: "signal_session_invalid" });
      }
      const now = new Date();
      const expiresAt = new Date(now.getTime() + SIGNAL_SESSION_TTL_SECONDS * 1000).toISOString();
      sessions[index] = { ...sessions[index], lastVerifiedAt: now.toISOString(), expiresAt };
      await client.query(`UPDATE licences SET signal_sessions = $1 WHERE id = $2`, [JSON.stringify(sessions), licence.id]);
      await client.query("COMMIT");
      return json(res, 200, { ok: true, token: issueSignalSession(key, machineId, sessionId), expiresAt });
    } catch {
      await client.query("ROLLBACK").catch(() => {});
      return json(res, 500, { ok: false, reason: "signal_unavailable" });
    } finally { client.release(); }
  }

  // ── POST /device-challenge ────────────────────────────────────────────────
  // A short-lived server challenge is signed by the DPAPI-protected key inside
  // the local Signal helper. The helper's public key deterministically produces
  // the secure device ID, so another PC cannot reuse a copied browser profile.
  if (req.method === "POST" && url === "/device-challenge") {
    const body = await readBody(req);
    const key = (body.key || "").trim().toUpperCase();
    if (!key) return json(res, 400, { ok: false, error: "Missing key" });
    try {
      const { rows } = await pool.query(`SELECT status, expires_at, deactivated, blocked FROM licences WHERE license_key = $1`, [key]);
      const licence = rows[0];
      const stateReason = licenceStatusReason(licence);
      if (stateReason) return json(res, 200, { ok: false, reason: stateReason });
      return json(res, 200, { ok: true, challenge: issueDeviceChallenge(key) });
    } catch {
      return json(res, 500, { ok: false, error: "device_challenge_failed" });
    }
  }

  // ── POST /activate-licence ────────────────────────────────────────────────
  if (req.method === "POST" && url === "/activate-licence") {
    const body       = await readBody(req);
    const key        = (body.key || "").trim().toUpperCase();
    const machine_id = normalizeDeviceId(body.machine_id);
    const ip         = getClientIp(req);

    if (!key) return json(res, 400, { ok: false, error: "Missing key" });
    if (!machine_id) return json(res, 200, { ok: false, reason: "invalid_device" });

    const isSecureDevice = SECURE_DEVICE_ID_RE.test(machine_id);
    let attestation = null;
    let browserInfo = null;
    if (isSecureDevice) {
      attestation = verifyDeviceAttestation(body.device_attestation, key, machine_id);
      if (!attestation.ok) return json(res, 200, { ok: false, reason: attestation.reason });
      browserInfo = normaliseAttestedBrowserInfo(attestation, body);
    } else {
      if (DEVICE_SECURITY_ENFORCED) return json(res, 200, { ok: false, reason: "update_required" });
      browserInfo = body.browser_info && typeof body.browser_info === "object" ? body.browser_info : null;
    }

    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const lockedResult = await client.query(`SELECT * FROM licences WHERE license_key = $1 FOR UPDATE`, [key]);
      const licence = lockedResult.rows[0];
      if (!licence) { await client.query("ROLLBACK"); return json(res, 200, { ok: false, reason: "invalid" }); }

      const stateReason = licenceStatusReason(licence);
      if (stateReason) { await client.query("ROLLBACK"); return json(res, 200, { ok: false, reason: stateReason }); }

      const now = new Date();
      const nowIso = now.toISOString();
      const devices = normaliseKnownDevices(licence.known_devices);
      const existingDevice = devices.find((device) => device.machineId === machine_id);
      if (existingDevice && (!existingDevice.active || existingDevice.removedAt)) {
        await client.query("ROLLBACK");
        return json(res, 200, { ok: false, reason: "device_removed" });
      }
      // A brand-new device may complete its first signed activation while
      // Signal is still checking. Existing v2 devices must present Signal's
      // short-lived server session on every activation attempt.
      if (existingDevice && isSecureDevice && requiresSignalSession(browserInfo)) {
        const signalSession = verifyActiveSignalSession(body.signal_session, key, machine_id, licence.signal_sessions);
        if (!signalSession.ok) {
          await client.query("ROLLBACK");
          return json(res, 200, { ok: false, reason: signalSession.reason });
        }
      }
      if (existingDevice && isSecureDevice && hasBrowserMismatch(existingDevice, browserInfo)) {
        await client.query("ROLLBACK");
        return json(res, 200, { ok: false, reason: "browser_mismatch" });
      }
      // First secure activation binds this Windows host to the browser family
      // signed by SlotHawk Signal. Chrome, Brave and Edge are all valid first
      // browsers; later requests from a different family are rejected by
      // hasBrowserMismatch above and on every authenticated endpoint.
            if (!existingDevice && activeDevices(devices).length >= normaliseDeviceLimit(licence.max_devices)) {
        await client.query("ROLLBACK");
        return json(res, 200, { ok: false, reason: "device_limit_reached" });
      }

      const deviceUpdate = upsertActiveDevice(devices, machine_id, ip, browserInfo, nowIso);
      if (!deviceUpdate.ok) { await client.query("ROLLBACK"); return json(res, 200, { ok: false, reason: "device_removed" }); }

      const expiresAt = licence.expires_at || (() => { const d = new Date(now); d.setDate(d.getDate() + licence.duration); return d; })();
      const actHistory = Array.isArray(licence.activation_history) ? licence.activation_history : [];
      actHistory.unshift({ id: uuidv4(), machineId: machine_id, ip, version: browserInfo?.extension_version || "", browser: browserInfo?.browser_family || "", createdAt: nowIso });
      if (actHistory.length > 20) actHistory.length = 20;

      await client.query(
`UPDATE licences SET
        status = 'active', active = TRUE,
        machine_id = COALESCE(machine_id, $1),
        activated_at = COALESCE(activated_at, $2),
        expires_at = COALESCE(expires_at, $3),
        last_seen = $2,
        first_ip = COALESCE(first_ip, $4),
        last_ip = $4,
        known_devices = $5,
        activation_history = $6
       WHERE license_key = $7`,
        [machine_id, now, expiresAt, ip, JSON.stringify(deviceUpdate.devices), JSON.stringify(actHistory), key]
      );

      await client.query("COMMIT");
      const token = buildLicenceToken(key, machine_id, licence.username || "", expiresAt);
      console.log("[ACTIVATE] OK key=" + key + " device=" + machine_id.slice(0, 12));
      return json(res, 200, { ok: true, token, username: licence.username || "", expiresAt: expiresAt instanceof Date ? expiresAt.toISOString() : expiresAt });
    } catch (err) {
      await client.query("ROLLBACK").catch(() => {});
      console.error("[ACTIVATE] error:", err.message);
      return json(res, 500, { ok: false, error: "DB error" });
    } finally { client.release(); }
  }

  // ── POST /migrate-device ──────────────────────────────────────────────────
  // Only a still-valid legacy session can exchange its old per-profile ID for
  // the secure host identity. It is a replacement, not an additional slot.
  if (req.method === "POST" && url === "/migrate-device") {
    const body = await readBody(req);
    const key = (body.key || "").trim().toUpperCase();
    const token = (body.token || "").trim();
    const machineId = normalizeDeviceId(body.machine_id);
    const ip = getClientIp(req);
    if (!key || !token || !SECURE_DEVICE_ID_RE.test(machineId)) return json(res, 200, { ok: false, reason: "invalid_device" });

    let decoded;
    try { decoded = jwt.verify(token, JWT_SECRET); }
    catch { return json(res, 200, { ok: false, reason: "invalid_token" }); }
    const legacyMachineId = normalizeDeviceId(decoded.machine_id);
    if (decoded.license_key !== key || !isLegacyDeviceId(legacyMachineId)) {
      return json(res, 200, { ok: false, reason: "migration_not_allowed" });
    }

    const attestation = verifyDeviceAttestation(body.device_attestation, key, machineId);
    if (!attestation.ok) return json(res, 200, { ok: false, reason: attestation.reason });
    const browserInfo = normaliseAttestedBrowserInfo(attestation, body);
    // Migration records the first verified browser family with the new
    // DPAPI-backed host identity. The same family remains required afterwards.

    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const locked = await client.query(`SELECT * FROM licences WHERE license_key = $1 FOR UPDATE`, [key]);
      const licence = locked.rows[0];
      const stateReason = licenceStatusReason(licence);
      if (stateReason) { await client.query("ROLLBACK"); return json(res, 200, { ok: false, reason: stateReason }); }

      const devices = normaliseKnownDevices(licence.known_devices);
      const legacy = legacyDeviceFromLicence(licence, devices, legacyMachineId);
      if (!legacy || !legacy.active || legacy.removedAt) {
        await client.query("ROLLBACK");
        return json(res, 200, { ok: false, reason: "device_removed" });
      }

      const now = new Date();
      const nowIso = now.toISOString();
      const existingSecure = devices.find((device) => device.machineId === machineId);
      if (existingSecure && (!existingSecure.active || existingSecure.removedAt)) {
        await client.query("ROLLBACK");
        return json(res, 200, { ok: false, reason: "device_removed" });
      }
      if (existingSecure && hasBrowserMismatch(existingSecure, browserInfo)) {
        await client.query("ROLLBACK");
        return json(res, 200, { ok: false, reason: "browser_mismatch" });
      }

      const nextDevices = devices.filter((device) => device.machineId !== legacyMachineId);
      if (existingSecure) {
        const index = nextDevices.findIndex((device) => device.machineId === machineId);
        nextDevices[index] = { ...nextDevices[index], ip, browserInfo, active: true, removedAt: null };
      } else {
        nextDevices.push({
          machineId,
          ip,
          firstSeenAt: legacy.firstSeenAt || nowIso,
          browserInfo,
          active: true,
          removedAt: null,
        });
      }

      const actHistory = Array.isArray(licence.activation_history) ? licence.activation_history : [];
      actHistory.unshift({ id: uuidv4(), type: "device_migration", from: legacyMachineId, to: machineId, ip, browser: browserInfo.browser_family, createdAt: nowIso });
      if (actHistory.length > 20) actHistory.length = 20;

      const primaryMachine = String(licence.machine_id || "") === legacyMachineId ? machineId : licence.machine_id;
      await client.query(
        `UPDATE licences SET machine_id = $1, known_devices = $2, activation_history = $3, last_seen = $4, last_ip = $5 WHERE license_key = $6`,
        [primaryMachine, JSON.stringify(nextDevices), JSON.stringify(actHistory), now, ip, key]
      );
      await client.query("COMMIT");

      const expiresAt = licence.expires_at;
      const nextToken = buildLicenceToken(key, machineId, licence.username || "", expiresAt);
      console.log("[MIGRATE] OK key=" + key + " device=" + machineId.slice(0, 12));
      return json(res, 200, { ok: true, token: nextToken, username: licence.username || "", expiresAt });
    } catch (err) {
      await client.query("ROLLBACK").catch(() => {});
      console.error("[MIGRATE] error:", err.message);
      return json(res, 500, { ok: false, error: "DB error" });
    } finally { client.release(); }
  }
  // ── POST /validate-licence ────────────────────────────────────────────────
  if (req.method === "POST" && url === "/validate-licence") {
    const body  = await readBody(req);
    const token = (body.token || "").trim();
    const key   = (body.key   || "").trim().toUpperCase();
    const machineId = normalizeDeviceId(body.machine_id);

    if (!token) return json(res, 200, { ok: false, reason: "missing_token" });

    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      if (key && decoded.license_key !== key) return json(res, 200, { ok: false, reason: "key_mismatch" });
      if (machineId && decoded.machine_id !== machineId) return json(res, 200, { ok: false, reason: "machine_blocked" });

      const boundMachineId = normalizeDeviceId(decoded.machine_id);
      const isSecureDevice = SECURE_DEVICE_ID_RE.test(boundMachineId);
      let browserInfo = null;
      if (isSecureDevice) {
        if (machineId !== boundMachineId) return json(res, 200, { ok: false, reason: "machine_blocked" });
        const attestation = verifyDeviceAttestation(body.device_attestation, decoded.license_key, boundMachineId);
        if (!attestation.ok) return json(res, 200, { ok: false, reason: attestation.reason });
        browserInfo = normaliseAttestedBrowserInfo(attestation, body);
      } else if (DEVICE_SECURITY_ENFORCED) {
        return json(res, 200, { ok: false, reason: "update_required" });
      }

      const { rows } = await pool.query(
        `SELECT status, expires_at, deactivated, blocked, active, machine_id, known_devices, max_devices, username, signal_sessions FROM licences WHERE license_key = $1`,
        [decoded.license_key]
      );

      if (!rows.length) return json(res, 200, { ok: false, reason: "invalid_session" });
      const l = rows[0];
      if (l.deactivated || l.status === "revoked" || l.status === "deactivated") return json(res, 200, { ok: false, reason: "revoked" });
      if (l.blocked) return json(res, 200, { ok: false, reason: "machine_blocked" });
      if (l.status !== "active") return json(res, 200, { ok: false, reason: "licence_inactive" });
      if (l.expires_at && new Date() > new Date(l.expires_at)) return json(res, 200, { ok: false, reason: "licence_expired" });
      if (!isDeviceAllowed(l, boundMachineId)) return json(res, 200, { ok: false, reason: "device_removed" });

      const boundDevice = normaliseKnownDevices(l.known_devices).find((device) => device.machineId === boundMachineId);
      if (isSecureDevice && hasBrowserMismatch(boundDevice, browserInfo)) return json(res, 200, { ok: false, reason: "browser_mismatch" });
      if (isSecureDevice && requiresSignalSession(browserInfo)) {
        const signalSession = verifyActiveSignalSession(body.signal_session, decoded.license_key, boundMachineId, l.signal_sessions);
        if (!signalSession.ok) return json(res, 200, { ok: false, reason: signalSession.reason });
      }

      return json(res, 200, { ok: true, username: l.username || "", expiresAt: l.expires_at });
    } catch {
      return json(res, 200, { ok: false, reason: "invalid_token" });
    }
  }

  // ── POST /refresh-token ───────────────────────────────────────────────────
  if (req.method === "POST" && url === "/refresh-token") {
    const body       = await readBody(req);
    const token      = (body.token      || "").trim();
    const machineId  = normalizeDeviceId(body.machine_id);

    if (!token || !machineId) return json(res, 400, { ok: false, error: "Missing params" });

    try {
      let decoded;
      try { decoded = jwt.verify(token, JWT_SECRET, { ignoreExpiration: true }); }
      catch { return json(res, 200, { ok: false, reason: "invalid_token" }); }
      if (decoded.machine_id !== machineId) return json(res, 200, { ok: false, reason: "machine_blocked" });

      const isSecureDevice = SECURE_DEVICE_ID_RE.test(machineId);
      let browserInfo = null;
      if (isSecureDevice) {
        const attestation = verifyDeviceAttestation(body.device_attestation, decoded.license_key, machineId);
        if (!attestation.ok) return json(res, 200, { ok: false, reason: attestation.reason });
        browserInfo = normaliseAttestedBrowserInfo(attestation, body);
      } else if (DEVICE_SECURITY_ENFORCED) {
        return json(res, 200, { ok: false, reason: "update_required" });
      }

      const { rows } = await pool.query(
        `SELECT status, expires_at, deactivated, blocked, active, machine_id, known_devices, max_devices, username, signal_sessions FROM licences WHERE license_key = $1`,
        [decoded.license_key]
      );
      if (!rows.length) return json(res, 200, { ok: false, reason: "not_found" });
      const l = rows[0];
      if (l.deactivated || l.status === "revoked" || l.status === "deactivated") return json(res, 200, { ok: false, reason: "revoked" });
      if (l.status !== "active") return json(res, 200, { ok: false, reason: "licence_inactive" });
      if (l.expires_at && new Date() > new Date(l.expires_at)) return json(res, 200, { ok: false, reason: "licence_expired" });
      if (!isDeviceAllowed(l, machineId)) return json(res, 200, { ok: false, reason: "device_removed" });
      const boundDevice = normaliseKnownDevices(l.known_devices).find((device) => device.machineId === machineId);
      if (isSecureDevice && hasBrowserMismatch(boundDevice, browserInfo)) return json(res, 200, { ok: false, reason: "browser_mismatch" });
      if (isSecureDevice && requiresSignalSession(browserInfo)) {
        const signalSession = verifyActiveSignalSession(body.signal_session, decoded.license_key, machineId, l.signal_sessions);
        if (!signalSession.ok) return json(res, 200, { ok: false, reason: signalSession.reason });
      }

      const newToken = buildLicenceToken(decoded.license_key, machineId, l.username || "", l.expires_at);
      await pool.query(`UPDATE licences SET last_seen = NOW() WHERE license_key = $1`, [decoded.license_key]);
      return json(res, 200, { ok: true, token: newToken, username: l.username || "" });
    } catch {
      return json(res, 500, { ok: false, error: "DB error" });
    }
  }

  // ── POST /revoke-licence ──────────────────────────────────────────────────
  if (req.method === "POST" && url === "/revoke-licence") {
    if (!hasValidDashboardApiKey(req)) return json(res, 401, { ok: false, error: "Unauthorized" });
    const body = await readBody(req);
    const key  = (body.key || "").trim().toUpperCase();
    if (!key) return json(res, 400, { ok: false, error: "Missing key" });
    try {
      const result = await pool.query(`UPDATE licences SET status = 'revoked', active = FALSE, blocked = TRUE WHERE license_key = $1 RETURNING license_key`, [key]);
      for (const licence of result.rows) disconnectSignalLicence(licence.license_key);
      return json(res, 200, { ok: true });
    } catch (err) { return json(res, 500, { ok: false, error: "DB error" }); }
  }

  // ── POST /heartbeat ───────────────────────────────────────────────────────
  if (req.method === "POST" && url === "/heartbeat") {
    const body       = await readBody(req);
    const token      = (body.token      || "").trim();
    const machine_id = normalizeDeviceId(body.machine_id);
    const version    = String(body?.browser_info?.extension_version || "").slice(0, 32);
    const ip         = getClientIp(req);

    if (!token) return json(res, 200, { ok: false, reason: "missing_token" });

    try {
      const decoded = jwt.verify(token, JWT_SECRET);

      if (decoded.machine_id !== machine_id)
        return json(res, 200, { ok: false, reason: "machine_blocked" });

      const isSecureDevice = SECURE_DEVICE_ID_RE.test(machine_id);
      let browserInfo = null;
      if (isSecureDevice) {
        const attestation = verifyDeviceAttestation(body.device_attestation, decoded.license_key, machine_id);
        if (!attestation.ok) return json(res, 200, { ok: false, reason: attestation.reason });
        browserInfo = normaliseAttestedBrowserInfo(attestation, body);
      } else if (DEVICE_SECURITY_ENFORCED) {
        return json(res, 200, { ok: false, reason: "update_required" });
      }

      const { rows } = await pool.query(`SELECT * FROM licences WHERE license_key = $1`, [decoded.license_key]);

      if (!rows.length) return json(res, 200, { ok: false, reason: "invalid" });
      const licence = rows[0];
      if (licence.deactivated || licence.status === "revoked" || licence.status === "deactivated") return json(res, 200, { ok: false, reason: "revoked" });
      if (licence.blocked) return json(res, 200, { ok: false, reason: "machine_blocked" });
      if (licence.status !== "active") return json(res, 200, { ok: false, reason: "licence_inactive" });
      if (licence.expires_at && new Date() > new Date(licence.expires_at)) return json(res, 200, { ok: false, reason: "licence_expired" });
      if (!isDeviceAllowed(licence, machine_id)) return json(res, 200, { ok: false, reason: "device_removed" });
      const boundDevice = normaliseKnownDevices(licence.known_devices).find((device) => device.machineId === machine_id);
      if (isSecureDevice && hasBrowserMismatch(boundDevice, browserInfo)) return json(res, 200, { ok: false, reason: "browser_mismatch" });
      if (isSecureDevice && requiresSignalSession(browserInfo)) {
        const signalSession = verifyActiveSignalSession(body.signal_session, decoded.license_key, machine_id, licence.signal_sessions);
        if (!signalSession.ok) return json(res, 200, { ok: false, reason: signalSession.reason });
      }

      const now = new Date();

      const sessions = Array.isArray(licence.sessions) ? licence.sessions : [];
      for (const session of sessions) {
        const lastPingAt = Date.parse(session?.lastPingAt || "");
        if (!session?.endedAt && (!Number.isFinite(lastPingAt) || now - lastPingAt > SESSION_GAP)) {
          session.endedAt = session?.lastPingAt || now.toISOString();
        }
      }

      const profileSessionIds = normaliseProfileSessionIds(body.profile_sessions);
      const signalProfileCount = normaliseSignalProfileCount(body.signal_profile_count);
      // Old extension versions omit profile_sessions and keep their original
      // one-session-per-device behaviour until they are updated.
      const sessionIds = profileSessionIds.length ? profileSessionIds : [""];
      for (const profileSessionId of sessionIds) {
        const activeSession = sessions.find((session) => (
          session?.machineId === machine_id &&
          String(session?.profileSessionId || "") === profileSessionId &&
          !session?.endedAt &&
          Number.isFinite(Date.parse(session?.lastPingAt || "")) &&
          now - Date.parse(session.lastPingAt) <= SESSION_GAP
        ));

        if (activeSession) {
          activeSession.lastPingAt = now.toISOString();
          activeSession.ip = ip;
        } else {
          sessions.unshift({
            id: uuidv4(),
            startedAt: now.toISOString(),
            lastPingAt: now.toISOString(),
            endedAt: null,
            ip: ip,
            machineId: machine_id,
            profileSessionId: profileSessionId || null,
          });
        }
      }
      if (sessions.length > 200) sessions.length = 200;

      const hbHistory = licence.heartbeat_history || [];
      hbHistory.unshift({
        id: uuidv4(),
        createdAt: now.toISOString(),
        ip: ip,
        version: version,
        machineId: machine_id,
        signalProfileCount,
      });
      if (hbHistory.length > 50) hbHistory.length = 50;

      await pool.query(
        `UPDATE licences SET
          last_seen = $1,
          last_ip = $2,
          current_version = $3,
          sessions = $4,
          heartbeat_history = $5
         WHERE license_key = $6`,
        [now, ip, version, JSON.stringify(sessions), JSON.stringify(hbHistory), decoded.license_key]
      );

      return json(res, 200, { ok: true, expiresAt: licence.expires_at });
    } catch {
      return json(res, 200, { ok: false, reason: "invalid_token" });
    }
  }

  // ── POST /booking-events ─────────────────────────────────────────────────
  // The extension reports only a confirmed result: payment-link extracted or
  // waitlist confirmed. The timestamp and client IP are assigned server-side;
  // no payment URL, applicant, passport, or VFS token is stored.
  if (req.method === "POST" && url === "/booking-events") {
    const body = await readBody(req);
    const token = String(body.token || "").trim();
    const eventType = String(body.eventType || "").trim();
    const clean = (value, max = 120) => String(value || "").trim().slice(0, max);
    const mission = clean(body.mission, 40);
    const city = clean(body.city);
    const subcategory = clean(body.subcategory);
    const slotDate = clean(body.slotDate, 32) || null;

    if (!token) return json(res, 401, { ok: false, reason: "missing_token" });
    if (!['payment_link', 'waitlist', 'booking'].includes(eventType) || !mission || !subcategory) {
      return json(res, 400, { ok: false, reason: "invalid_booking_event" });
    }

    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      const { rows } = await pool.query(
        `SELECT status, expires_at, deactivated, blocked, active, machine_id, known_devices, max_devices, booking_events FROM licences WHERE license_key = $1`,
        [decoded.license_key]
      );
      const licence = rows[0];
      if (!licence || licence.deactivated || licence.blocked || licence.status !== "active" ||
          (licence.expires_at && new Date() > new Date(licence.expires_at))) {
        return json(res, 403, { ok: false, reason: "licence_inactive" });
      }
      if (!isDeviceAllowed(licence, decoded.machine_id)) return json(res, 403, { ok: false, reason: "device_removed" });

      const events = Array.isArray(licence.booking_events) ? licence.booking_events : [];
      const event = {
        id: uuidv4(),
        createdAt: new Date().toISOString(),
        success: true,
        eventType,
        mission,
        city: city || null,
        subcategory,
        slotDate,
        reason: null,
        machineId: decoded.machine_id || null,
        ip: getClientIp(req),
      };
      events.unshift(event);
      if (events.length > 200) events.length = 200;
      await pool.query(`UPDATE licences SET booking_events = $1 WHERE license_key = $2`, [JSON.stringify(events), decoded.license_key]);
      return json(res, 201, { ok: true, event });
    } catch {
      return json(res, 401, { ok: false, reason: "invalid_token" });
    }
  }

  // ── POST /v1/signals/vps ─────────────────────────────────────────────────
  // Trusted VPS ingress. Requests are HMAC-signed over the exact raw JSON body,
  // timestamp-bound, rate-limited, destination-allowlisted and deduplicated.
  if (req.method === "POST" && url === "/v1/signals/vps") {
    if (!VPS_SIGNAL_ENABLED) {
      // Keep an unconfigured private ingress undiscoverable.
      return json(res, 404, { ok: false, error: "Not found" });
    }

    let rawBody;
    try {
      rawBody = await readRawBody(req);
    } catch (error) {
      return json(res, error?.code === "PAYLOAD_TOO_LARGE" ? 413 : 400, {
        ok: false,
        error: "invalid_payload",
      });
    }

    const issuer = verifiedVpsIssuer(req, rawBody);
    if (!issuer) return json(res, 401, { ok: false, error: "invalid_signature" });

    let body;
    try {
      body = JSON.parse(rawBody.toString("utf8"));
    } catch {
      return json(res, 400, { ok: false, error: "invalid_payload" });
    }

    const event = normalizeVpsSignal(body);
    if (!event) return json(res, 400, { ok: false, error: "invalid_signal" });
    if (!checkVpsSignalRateLimit(issuer)) {
      return json(res, 429, { ok: false, error: "rate_limited" });
    }
    if (!TELEGRAM_ENABLED) {
      return json(res, 503, { ok: false, error: "telegram_disabled" });
    }

    try {
      const claim = await pool.query(
        `INSERT INTO vps_signal_events (event_id) VALUES ($1)
         ON CONFLICT DO NOTHING
         RETURNING event_id`,
        [event.eventId]
      );
      if (claim.rowCount === 0) {
        return json(res, 200, { ok: true, duplicate: true });
      }
    } catch (error) {
      console.error("[VPS SIGNAL] event claim failed:", error.message);
      return json(res, 503, { ok: false, error: "storage_unavailable" });
    }

    const message = buildSlotAlertMessage({
      missionName: event.missionName,
      city: event.city,
      subcategory: event.subcategory,
    });

    let telegramResult;
    if (TELEGRAM_PRO_CHAT_ID) {
      telegramResult = await sendTelegramToChat(TELEGRAM_PRO_CHAT_ID, message, "VPS-PRO");
      if (telegramResult.ok) scheduleLegacyTelegramSend(message, "vps");
    } else if (TELEGRAM_CHAT_ID) {
      telegramResult = await sendTelegramToChat(TELEGRAM_CHAT_ID, message, "VPS-LEGACY-IMMEDIATE");
    } else {
      telegramResult = { ok: false, error: "no_channels_configured" };
    }

    if (!telegramResult.ok) {
      // A failed delivery is retryable with the same event id.
      await pool.query(`DELETE FROM vps_signal_events WHERE event_id = $1`, [event.eventId])
        .catch((error) => console.error("[VPS SIGNAL] event release failed:", error.message));
      return json(res, 502, { ok: false, error: "telegram_error" });
    }

    // Only a successfully posted Telegram notification may wake extensions.
    const signalResult = broadcastServerSlotFound(event);
    console.log(`[VPS SIGNAL] accepted ${event.mission}/${event.city}/${event.subcategory}; recipients=${signalResult.recipients}`);

    return json(res, 200, {
      ok: true,
      duplicate: false,
      telegramSent: true,
      signalRecipients: signalResult.recipients,
    });
  }

  // ── POST /alert/telegram ──────────────────────────────────────────────────
  // Extension calls this instead of api.telegram.org directly, so the bot
  // token stays server-side. JWT-authenticated, licence-status-checked,
  // rate-limited (20/min per licence).
  //
  // Request body: { token: "<JWT>", alert: { missionKey, missionName, cityCode, subcategory } }
  // The `earliestDate` field is intentionally NOT accepted here — if the
  // extension ever sends it, we strip it before building the message.
  if (req.method === "POST" && url === "/alert/telegram") {
    if (!TELEGRAM_ENABLED) {
      return json(res, 503, { ok: false, reason: "telegram_disabled" });
    }

    const body  = await readBody(req);
    const token = (body.token || "").trim();
    const alert = body.alert || {};

    if (!token) return json(res, 401, { ok: false, reason: "missing_token" });
    if (!alert.missionName || !alert.subcategory) {
      return json(res, 400, { ok: false, reason: "missing_alert_data" });
    }

    // 1. Verify JWT
    let decoded;
    try { decoded = jwt.verify(token, JWT_SECRET); }
    catch { return json(res, 401, { ok: false, reason: "invalid_token" }); }

    const licenceKey = decoded.license_key;
    if (!licenceKey) return json(res, 401, { ok: false, reason: "invalid_token" });

    // 2. Check licence status (same rules as /heartbeat)
    try {
      const { rows } = await pool.query(
        `SELECT status, expires_at, deactivated, blocked, active, machine_id, known_devices, max_devices, username, signal_sessions FROM licences WHERE license_key = $1`,
        [licenceKey]
      );
      if (!rows.length) return json(res, 403, { ok: false, reason: "invalid_licence" });
      const l = rows[0];
      if (l.deactivated || l.status === "revoked" || l.status === "deactivated") {
        return json(res, 403, { ok: false, reason: "revoked" });
      }
      if (l.blocked) return json(res, 403, { ok: false, reason: "machine_blocked" });
      if (l.status !== "active") return json(res, 403, { ok: false, reason: "licence_inactive" });
      if (l.expires_at && new Date() > new Date(l.expires_at)) {
        return json(res, 403, { ok: false, reason: "licence_expired" });
      }
      if (!isDeviceAllowed(l, decoded.machine_id)) return json(res, 403, { ok: false, reason: "device_removed" });
    } catch (err) {
      console.error("[ALERT] DB error:", err.message);
      return json(res, 500, { ok: false, reason: "db_error" });
    }

    // 3. Rate limit
    if (!checkAlertRateLimit(licenceKey)) {
      console.log(`[ALERT] Rate limit hit for ${licenceKey}`);
      return json(res, 429, { ok: false, reason: "rate_limited" });
    }

    // 4. Build message.
    // Only country, category, city ship out. Date is deliberately omitted.
    const message = buildSlotAlertMessage({
      missionName: String(alert.missionName || ""),
      city:        String(alert.city || ""),
      subcategory: String(alert.subcategory || ""),
    });

    // The Telegram alert is now also the canonical source for the Tourism
    // Global Signal. This happens server-side so all subscribed profiles
    // receive the same event, not separate client-originated broadcasts.
    const signalResult = alert.signal === false
      ? { sent: false, recipients: 0 }
      : broadcastServerSlotFound({
          mission: alert.missionKey,
          city: alert.cityCode || alert.city,
          subcategory: alert.subcategory,
        });

    // 5. Send to the Pro channel immediately. This is the request the
    //    extension is waiting on — its success/failure is what we return.
    //    The Legacy channel is scheduled separately (see step 6) and its
    //    outcome doesn't affect this response (Q3 = B: one alert = one
    //    rate-limit unit even though we mirror to two channels).
    if (TELEGRAM_PRO_CHAT_ID) {
      const proResult = await sendTelegramToChat(TELEGRAM_PRO_CHAT_ID, message, "PRO");
      if (!proResult.ok) {
        // Even when Pro fails, still schedule the Legacy send so
        // subscribers on the delayed channel don't lose the alert
        // just because Pro had a hiccup.
        scheduleLegacyTelegramSend(message, licenceKey);
        return json(res, 502, { ok: false, reason: "telegram_error", detail: proResult.error, signalSent: signalResult.sent });
      }
      console.log(`[ALERT] Pro sent for ${licenceKey}: ${alert.missionName}/${alert.subcategory}/${alert.city}`);
    } else if (TELEGRAM_CHAT_ID) {
      // No Pro channel configured — fall back to sending the Legacy
      // channel immediately with no delay. Preserves behaviour for
      // deployments that haven't set TELEGRAM_PRO_CHAT_ID yet.
      const legacyResult = await sendTelegramToChat(TELEGRAM_CHAT_ID, message, "LEGACY-IMMEDIATE");
      if (!legacyResult.ok) {
        return json(res, 502, { ok: false, reason: "telegram_error", detail: legacyResult.error, signalSent: signalResult.sent });
      }
      console.log(`[ALERT] Legacy immediate sent for ${licenceKey} (no Pro configured): ${alert.missionName}/${alert.subcategory}/${alert.city}`);
      return json(res, 200, { ok: true, signalSent: signalResult.sent });
    } else {
      // Neither channel configured — shouldn't happen given the
      // TELEGRAM_ENABLED guard above, but bail cleanly if it does.
      return json(res, 503, { ok: false, reason: "no_channels_configured" });
    }

    // 6. Schedule the Legacy mirror. Fire-and-forget; the extension's
    //    Pro-channel confirmation has already been sent.
    scheduleLegacyTelegramSend(message, licenceKey);

    return json(res, 200, { ok: true, signalSent: signalResult.sent });
  }

  return json(res, 404, { ok: false, error: "Not found" });
});

// ── WSS /signal ──────────────────────────────────────────────────────
// The normal HTTP server owns upgrades so Render exposes API and signal
// relay through the same public service/domain.
const signalWss = new WebSocketServer({
  noServer: true,
  maxPayload: 4096,
  perMessageDeflate: false,
});

server.on("upgrade", (req, socket, head) => {
  const pathname = new URL(req.url, "http://localhost").pathname;
  if (pathname !== "/signal") {
    socket.destroy();
    return;
  }
  signalWss.handleUpgrade(req, socket, head, (ws) => {
    signalWss.emit("connection", ws, req);
  });
});

signalWss.on("connection", (ws) => {
  ws.signalAuthorised = false;
  ws.signalChannel = "";
  ws.signalLicenceKey = "";
  ws.signalMachineId = "";

  const authTimer = setTimeout(() => {
    if (!ws.signalAuthorised) ws.close(4001, "auth_timeout");
  }, SIGNAL_AUTH_TIMEOUT_MS);

  ws.on("message", async (raw) => {
    let message;
    try { message = JSON.parse(String(raw)); }
    catch { ws.close(4002, "invalid_json"); return; }

    if (!ws.signalAuthorised) {
      if (message?.type !== "auth") {
        ws.close(4003, "auth_required");
        return;
      }
      const identity = await authenticateSignalToken(message.token);
      const channel = signalChannel(message.mission, message.city, message.subcategory);
      if (!identity || !channel) {
        ws.close(4004, "unauthorized");
        return;
      }
      clearTimeout(authTimer);
      ws.signalAuthorised = true;
      ws.signalLicenceKey = identity.licenceKey;
      ws.signalMachineId = identity.machineId;
      ws.signalChannel = channel;
      if (!signalRooms.has(channel)) signalRooms.set(channel, new Set());
      signalRooms.get(channel).add(ws);
      ws.send(JSON.stringify({ type: "ready", channel }));
      return;
    }

    if (message?.type === "subscribe") {
      const channel = signalChannel(message.mission, message.city, message.subcategory);
      if (!channel) { ws.send(JSON.stringify({ type: "error", reason: "invalid_channel" })); return; }
      leaveSignalRoom(ws);
      ws.signalChannel = channel;
      if (!signalRooms.has(channel)) signalRooms.set(channel, new Set());
      signalRooms.get(channel).add(ws);
      ws.send(JSON.stringify({ type: "ready", channel }));
      return;
    }

    if (message?.type !== "slot_found") return;
    const channel = signalChannel(message.mission, message.city, message.subcategory);
    if (!channel || channel !== ws.signalChannel || typeof message.eventId !== "string" || message.eventId.length < 8 || message.eventId.length > 128) {
      ws.send(JSON.stringify({ type: "error", reason: "invalid_signal" }));
      return;
    }
    if (!checkSignalRateLimit(ws.signalLicenceKey)) {
      ws.send(JSON.stringify({ type: "error", reason: "rate_limited" }));
      return;
    }

    const payload = JSON.stringify({
      type: "slot_found",
      eventId: message.eventId,
      mission: String(message.mission).trim(),
      city: String(message.city).trim(),
      subcategory: String(message.subcategory).trim(),
      sentAt: new Date().toISOString(),
    });
    for (const peer of signalRooms.get(channel) || []) {
      if (peer.readyState === 1) peer.send(payload);
    }
  });

  ws.on("close", () => {
    clearTimeout(authTimer);
    leaveSignalRoom(ws);
  });
  ws.on("error", () => {});
});

async function cleanupVpsSignalEvents() {
  try {
    await pool.query(`DELETE FROM vps_signal_events WHERE received_at < NOW() - INTERVAL '24 hours'`);
  } catch (error) {
    console.error("[VPS SIGNAL] event cleanup failed:", error.message);
  }
}

initDB().then(() => {
  setInterval(() => { void cleanupVpsSignalEvents(); }, 60 * 60_000).unref?.();
  server.listen(PORT, "0.0.0.0", () => {
    console.log(`SlotHawk API -> port ${PORT}`);
  });
}).catch(err => {
  console.error("[DB] Init failed:", err.message);
  process.exit(1);
});
