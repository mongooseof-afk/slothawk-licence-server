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
