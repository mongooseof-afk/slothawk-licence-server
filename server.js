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

const PORT        = parseInt(process.env.PORT) || 8765;
const JWT_SECRET  = process.env.JWT_SECRET;
const JWT_EXPIRES = process.env.JWT_EXPIRES_IN || "7d";
const SESSION_GAP = 10 * 60 * 1000;

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

// Periodic cleanup so the Map doesn't grow unbounded over the process
// lifetime. Runs every 5 minutes, drops entries with no recent hits.
setInterval(() => {
  const now = Date.now();
  for (const [key, arr] of alertRateMap.entries()) {
    const filtered = arr.filter(t => now - t < ALERT_RATE_WINDOW_MS);
    if (filtered.length === 0) alertRateMap.delete(key);
    else alertRateMap.set(key, filtered);
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
      booking_events     JSONB NOT NULL DEFAULT '[]'
    )
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

function json(res, statusCode, body) {
  res.writeHead(statusCode, {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, PATCH, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
  });
  res.end(JSON.stringify(body));
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
    knownDevices: r.known_devices || [], known_devices: r.known_devices || [],
    heartbeatHistory: r.heartbeat_history || [], heartbeat_history: r.heartbeat_history || [],
    activationHistory: r.activation_history || [], activation_history: r.activation_history || [],
    sessions: r.sessions || [],
    bookingEvents: r.booking_events || [], booking_events: r.booking_events || [],
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

const MISSION_FLAGS = { Malta: "🇲🇹", Austria: "🇦🇹" };
const CITY_NAMES = {
  MLMCS: "Casablanca", MLMRBT: "Rabat", MLMTGR: "Tangier",
  ASCA: "Casablanca", ASRB: "Rabat", TVC: "Tangier",
};

function buildSlotAlertMessage({ missionName, city, subcategory }) {
  const flag     = MISSION_FLAGS[missionName] || "🌍";
  const cityName = CITY_NAMES[city] || city || "Unknown";
  const time     = formatMoroccoTimestamp(new Date());

  return [
    "🦅 *SLOTHAWK SPOTTED A SLOT* 🦅",
    "▬▬▬▬▬▬▬▬▬▬▬▬▬▬",
    `PAYS: ${escapeMarkdownV2(missionName)} ${flag}`,
    `TYPE: ${escapeMarkdownV2(subcategory)}`,
    `📍 ${escapeMarkdownV2(cityName)}`,
    "",
    `Spotted at ${escapeMarkdownV2(time)}`,
    "",
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
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
    });
    return res.end();
  }

  const url = req.url.split("?")[0];

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
    const key      = generateLicenceKey();
    const id       = uuidv4();
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + duration);
    try {
      const { rows } = await pool.query(
        `INSERT INTO licences (id, license_key, username, plan, status, duration, expires_at) VALUES ($1, $2, $3, $4, 'pending', $5, $6) RETURNING *`,
        [id, key, username, plan, duration, expiresAt]
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

  // ── PATCH /admin/licences/:id/revoke ──────────────────────────────────────
  if (req.method === "PATCH" && url.includes("/revoke")) {
    const id = extractIdFromUrl(url);
    try {
      const result = await pool.query(`UPDATE licences SET status = 'revoked', active = FALSE WHERE id = $1 OR license_key = $1`, [id]);
      console.log(`[REVOKE] id=${id} rows=${result.rowCount}`);
      return json(res, 200, { ok: true });
    } catch (err) { return json(res, 500, { ok: false, error: err.message }); }
  }

  // ── PATCH /admin/licences/:id/reset-machine ───────────────────────────────
  if (req.method === "PATCH" && url.includes("/reset-machine")) {
    const id = extractIdFromUrl(url);
    try {
      const result = await pool.query(`UPDATE licences SET machine_id = NULL, status = 'pending', blocked = FALSE, suspicious = FALSE, suspicious_reason = NULL, known_devices = '[]' WHERE id = $1 OR license_key = $1`, [id]);
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
      const result = await pool.query(`UPDATE licences SET status = 'deactivated', deactivated = TRUE, machine_id = NULL WHERE id = $1 OR license_key = $1`, [id]);
      console.log(`[DEACTIVATE] id=${id} rows=${result.rowCount}`);
      return json(res, 200, { ok: true });
    } catch (err) { return json(res, 500, { ok: false, error: err.message }); }
  }

  // ── PATCH /admin/licences/:id/clear-block ─────────────────────────────────
  if (req.method === "PATCH" && url.includes("/clear-block")) {
    const id = extractIdFromUrl(url);
    try {
      const result = await pool.query(`UPDATE licences SET blocked = FALSE, suspicious = FALSE, suspicious_reason = NULL WHERE id = $1 OR license_key = $1`, [id]);
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
    const body     = await readBody(req);
    const duration = parseInt(body.duration_days) || 30;
    const key      = generateLicenceKey();
    const id       = uuidv4();
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + duration);
    try {
      await pool.query(
        `INSERT INTO licences (id, license_key, status, duration, expires_at) VALUES ($1, $2, 'pending', $3, $4)`,
        [id, key, duration, expiresAt]
      );
      return json(res, 200, { ok: true, key, duration_days: duration });
    } catch (err) {
      return json(res, 500, { ok: false, error: err.message });
    }
  }

  // ── POST /activate-licence ────────────────────────────────────────────────
  if (req.method === "POST" && url === "/activate-licence") {
    const body       = await readBody(req);
    const key        = (body.key || "").trim().toUpperCase();
    const machine_id = (body.machine_id || "").trim();
    const ip         = getClientIp(req);

    if (!key) return json(res, 400, { ok: false, error: "Missing key" });

    try {
      const { rows } = await pool.query(`SELECT * FROM licences WHERE license_key = $1`, [key]);
      if (!rows.length) return json(res, 200, { ok: false, reason: "invalid" });

      const licence = rows[0];

      if (licence.deactivated || licence.status === "revoked" || licence.status === "deactivated")
        return json(res, 200, { ok: false, reason: "revoked" });
      if (licence.blocked)
        return json(res, 200, { ok: false, reason: "machine_blocked" });
      if (licence.expires_at && new Date() > new Date(licence.expires_at))
        return json(res, 200, { ok: false, reason: "expired" });

      // ── DUPLICATE MACHINE → AUTO-REVOKE ALL ───────────────────────
      if (licence.machine_id && machine_id && licence.machine_id !== machine_id) {
        await pool.query(
          `UPDATE licences SET
            status = 'revoked', active = FALSE, blocked = TRUE,
            suspicious = TRUE, suspicious_reason = $1
           WHERE license_key = $2`,
          [`Auto-revoked: duplicate machine attempt. Original: ${licence.machine_id}, Attacker: ${machine_id}, IP: ${ip}`, key]
        );
        console.log(`[AUTO-REVOKE] key=${key} original=${licence.machine_id} attacker=${machine_id} ip=${ip}`);
        return json(res, 200, { ok: false, reason: "revoked" });
      }

      const now = new Date();
      const expiresAt = licence.expires_at || (() => { const d = new Date(now); d.setDate(d.getDate() + licence.duration); return d; })();

      const devices = licence.known_devices || [];
      const alreadyKnown = devices.some(d => d.machineId === machine_id && d.ip === ip);
      if (!alreadyKnown && machine_id) {
        devices.push({ machineId: machine_id, ip: ip, firstSeenAt: now.toISOString() });
      }

      const actHistory = licence.activation_history || [];
      actHistory.unshift({
        id: uuidv4(),
        machineId: machine_id,
        ip: ip,
        version: (body.browser_info || {}).extension_version || '',
        createdAt: now.toISOString(),
      });
      if (actHistory.length > 20) actHistory.length = 20;

      await pool.query(
        `UPDATE licences SET
          status = 'active',
          machine_id = COALESCE(machine_id, $1),
          activated_at = COALESCE(activated_at, $2),
          expires_at = COALESCE(expires_at, $3),
          last_seen = $4,
          first_ip = COALESCE(first_ip, $5),
          last_ip = $5,
          known_devices = $6,
          activation_history = $7
         WHERE license_key = $8`,
        [machine_id || null, now, expiresAt, now, ip, JSON.stringify(devices), JSON.stringify(actHistory), key]
      );

      const token = jwt.sign(
        { license_key: key, machine_id, expires_at: expiresAt instanceof Date ? expiresAt.toISOString() : expiresAt },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRES }
      );

      console.log(`[ACTIVATE] OK key=${key} machine=${machine_id}`);
      return json(res, 200, { ok: true, token, expiresAt: expiresAt instanceof Date ? expiresAt.toISOString() : expiresAt });

    } catch (err) {
      console.error("[ACTIVATE] error:", err.message);
      return json(res, 500, { ok: false, error: "DB error" });
    }
  }

  // ── POST /validate-licence ────────────────────────────────────────────────
  if (req.method === "POST" && url === "/validate-licence") {
    const body  = await readBody(req);
    const token = (body.token || "").trim();
    const key   = (body.key   || "").trim().toUpperCase();

    if (!token) return json(res, 200, { ok: false, reason: "missing_token" });

    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      if (key && decoded.license_key !== key)
        return json(res, 200, { ok: false, reason: "key_mismatch" });

      const { rows } = await pool.query(
        `SELECT status, expires_at, deactivated, blocked FROM licences WHERE license_key = $1`,
        [decoded.license_key]
      );

      if (!rows.length) return json(res, 200, { ok: false, reason: "invalid_session" });
      const l = rows[0];
      if (l.deactivated || l.status === "revoked" || l.status === "deactivated") return json(res, 200, { ok: false, reason: "revoked" });
      if (l.blocked) return json(res, 200, { ok: false, reason: "machine_blocked" });
      if (l.status !== "active") return json(res, 200, { ok: false, reason: "licence_inactive" });
      if (l.expires_at && new Date() > new Date(l.expires_at)) return json(res, 200, { ok: false, reason: "licence_expired" });

      return json(res, 200, { ok: true, expiresAt: l.expires_at });
    } catch {
      return json(res, 200, { ok: false, reason: "invalid_token" });
    }
  }

  // ── POST /refresh-token ───────────────────────────────────────────────────
  if (req.method === "POST" && url === "/refresh-token") {
    const body       = await readBody(req);
    const token      = (body.token      || "").trim();
    const machine_id = (body.machine_id || "").trim();

    if (!token || !machine_id) return json(res, 400, { ok: false, error: "Missing params" });

    try {
      let decoded;
      try { decoded = jwt.verify(token, JWT_SECRET, { ignoreExpiration: true }); }
      catch { return json(res, 200, { ok: false, reason: "invalid_token" }); }

      if (decoded.machine_id !== machine_id) return json(res, 200, { ok: false, reason: "machine_blocked" });

      const { rows } = await pool.query(
        `SELECT status, expires_at, deactivated, blocked FROM licences WHERE license_key = $1`,
        [decoded.license_key]
      );

      if (!rows.length) return json(res, 200, { ok: false, reason: "not_found" });
      const l = rows[0];
      if (l.deactivated || l.status === "revoked" || l.status === "deactivated") return json(res, 200, { ok: false, reason: "revoked" });
      if (l.status !== "active") return json(res, 200, { ok: false, reason: "licence_inactive" });
      if (l.expires_at && new Date() > new Date(l.expires_at)) return json(res, 200, { ok: false, reason: "licence_expired" });

      const newToken = jwt.sign(
        { license_key: decoded.license_key, machine_id, expires_at: l.expires_at },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRES }
      );

      await pool.query(`UPDATE licences SET last_seen = NOW() WHERE license_key = $1`, [decoded.license_key]);
      return json(res, 200, { ok: true, token: newToken });
    } catch (err) {
      return json(res, 500, { ok: false, error: "DB error" });
    }
  }

  // ── POST /revoke-licence ──────────────────────────────────────────────────
  if (req.method === "POST" && url === "/revoke-licence") {
    const body = await readBody(req);
    const key  = (body.key || "").trim().toUpperCase();
    if (!key) return json(res, 400, { ok: false, error: "Missing key" });
    try {
      await pool.query(`UPDATE licences SET status = 'revoked', active = FALSE WHERE license_key = $1`, [key]);
      return json(res, 200, { ok: true });
    } catch (err) { return json(res, 500, { ok: false, error: "DB error" }); }
  }

  // ── POST /heartbeat ───────────────────────────────────────────────────────
  if (req.method === "POST" && url === "/heartbeat") {
    const body       = await readBody(req);
    const token      = (body.token      || "").trim();
    const machine_id = (body.machine_id || "").trim();
    const version    = body.extension_version || "";
    const ip         = getClientIp(req);

    if (!token) return json(res, 200, { ok: false, reason: "missing_token" });

    try {
      const decoded = jwt.verify(token, JWT_SECRET);

      if (decoded.machine_id && machine_id && decoded.machine_id !== machine_id)
        return json(res, 200, { ok: false, reason: "machine_blocked" });

      const { rows } = await pool.query(`SELECT * FROM licences WHERE license_key = $1`, [decoded.license_key]);

      if (!rows.length) return json(res, 200, { ok: false, reason: "invalid" });
      const licence = rows[0];
      if (licence.deactivated || licence.status === "revoked" || licence.status === "deactivated") return json(res, 200, { ok: false, reason: "revoked" });
      if (licence.blocked) return json(res, 200, { ok: false, reason: "machine_blocked" });
      if (licence.status !== "active") return json(res, 200, { ok: false, reason: "licence_inactive" });
      if (licence.expires_at && new Date() > new Date(licence.expires_at)) return json(res, 200, { ok: false, reason: "licence_expired" });

      const now = new Date();

      const sessions = licence.sessions || [];
      const lastSession = sessions[0];
      const gap = lastSession ? (now - new Date(lastSession.lastPingAt)) : Infinity;

      if (gap > SESSION_GAP) {
        sessions.unshift({
          id: uuidv4(),
          startedAt: now.toISOString(),
          lastPingAt: now.toISOString(),
          endedAt: null,
          ip: ip,
          machineId: machine_id,
        });
        if (sessions.length > 50) sessions.length = 50;
      } else {
        sessions[0].lastPingAt = now.toISOString();
      }

      const hbHistory = licence.heartbeat_history || [];
      hbHistory.unshift({
        id: uuidv4(),
        createdAt: now.toISOString(),
        ip: ip,
        version: version,
        machineId: machine_id,
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

  // ── POST /alert/telegram ──────────────────────────────────────────────────
  // Extension calls this instead of api.telegram.org directly, so the bot
  // token stays server-side. JWT-authenticated, licence-status-checked,
  // rate-limited (20/min per licence).
  //
  // Request body: { token: "<JWT>", alert: { missionName, city, subcategory } }
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
        `SELECT status, expires_at, deactivated, blocked FROM licences WHERE license_key = $1`,
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
        return json(res, 502, { ok: false, reason: "telegram_error", detail: proResult.error });
      }
      console.log(`[ALERT] Pro sent for ${licenceKey}: ${alert.missionName}/${alert.subcategory}/${alert.city}`);
    } else if (TELEGRAM_CHAT_ID) {
      // No Pro channel configured — fall back to sending the Legacy
      // channel immediately with no delay. Preserves behaviour for
      // deployments that haven't set TELEGRAM_PRO_CHAT_ID yet.
      const legacyResult = await sendTelegramToChat(TELEGRAM_CHAT_ID, message, "LEGACY-IMMEDIATE");
      if (!legacyResult.ok) {
        return json(res, 502, { ok: false, reason: "telegram_error", detail: legacyResult.error });
      }
      console.log(`[ALERT] Legacy immediate sent for ${licenceKey} (no Pro configured): ${alert.missionName}/${alert.subcategory}/${alert.city}`);
      return json(res, 200, { ok: true });
    } else {
      // Neither channel configured — shouldn't happen given the
      // TELEGRAM_ENABLED guard above, but bail cleanly if it does.
      return json(res, 503, { ok: false, reason: "no_channels_configured" });
    }

    // 6. Schedule the Legacy mirror. Fire-and-forget; the extension's
    //    Pro-channel confirmation has already been sent.
    scheduleLegacyTelegramSend(message, licenceKey);

    return json(res, 200, { ok: true });
  }

  return json(res, 404, { ok: false, error: "Not found" });
});

initDB().then(() => {
  server.listen(PORT, "0.0.0.0", () => {
    console.log(`SlotHawk API -> port ${PORT}`);
  });
}).catch(err => {
  console.error("[DB] Init failed:", err.message);
  process.exit(1);
});
