/**
 * SlotHawk Licence Server v7
 * Compatible with migrate_v7.sql schema
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
    return json(res, 200, { status: "ok", version: "7.0.0", requiredExtensionVersion: process.env.REQUIRED_VERSION || "0.2.10" });
  }

  if (req.method === "GET" && url === "/version") {
    return json(res, 200, { required: process.env.REQUIRED_VERSION || "0.2.10" });
  }

  if (req.method === "GET" && url === "/status") {
    return json(res, 200, { ok: true, counts: { mlt: 0, aut: 0 } });
  }

  // ── POST /admin/licences/generate OR /api/admin/licences/generate ────────────
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
      await pool.query(
        `INSERT INTO licences (id, license_key, username, plan, status, duration, expires_at) VALUES ($1, $2, $3, $4, 'pending', $5, $6)`,
        [id, key, username, plan, duration, expiresAt]
      );
      console.log(`[GENERATE] key=${key}`);
      const licenceObj = { id, license_key: key, username, plan, status: "pending", duration, expires_at: expiresAt };
      return json(res, 200, { ok: true, key, license_key: key, id, duration_days: duration, licences: [licenceObj] });
    } catch (err) {
      console.error("[GENERATE] error:", err.message);
      return json(res, 500, { ok: false, error: err.message });
    }
  }

  // ── GET /api/admin/licences ───────────────────────────────────────────────────
  if (req.method === "GET" && (url === "/api/admin/licences" || url === "/admin/licences")) {
    try {
      const { rows } = await pool.query(`SELECT * FROM licences ORDER BY created_at DESC LIMIT 100`);
      const total = rows.length;
      return json(res, 200, { data: rows, licences: rows, total, page: 1, limit: 100, totalPages: 1 });
    } catch (err) {
      return json(res, 500, { ok: false, error: err.message });
    }
  }

  // ── PATCH /api/admin/licences/:id/revoke ─────────────────────────────────────
  if (req.method === "PATCH" && url.includes("/revoke")) {
    const id = url.split("/")[4];
    try {
      await pool.query(`UPDATE licences SET status = 'revoked' WHERE id = $1 OR license_key = $1`, [id]);
      return json(res, 200, { ok: true });
    } catch (err) { return json(res, 500, { ok: false, error: err.message }); }
  }

  // ── PATCH /api/admin/licences/:id/reset-machine ──────────────────────────────
  if (req.method === "PATCH" && url.includes("/reset-machine")) {
    const id = url.split("/")[4];
    try {
      await pool.query(`UPDATE licences SET machine_id = NULL WHERE id = $1 OR license_key = $1`, [id]);
      return json(res, 200, { ok: true });
    } catch (err) { return json(res, 500, { ok: false, error: err.message }); }
  }

  // ── PATCH /api/admin/licences/:id/reactivate ─────────────────────────────────
  if (req.method === "PATCH" && url.includes("/reactivate")) {
    const id = url.split("/")[4];
    try {
      await pool.query(`UPDATE licences SET status = 'active', deactivated = FALSE WHERE id = $1 OR license_key = $1`, [id]);
      return json(res, 200, { ok: true });
    } catch (err) { return json(res, 500, { ok: false, error: err.message }); }
  }

  // ── PATCH /api/admin/licences/:id/deactivate ─────────────────────────────────
  if (req.method === "PATCH" && url.includes("/deactivate")) {
    const id = url.split("/")[4];
    try {
      await pool.query(`UPDATE licences SET status = 'inactive', deactivated = TRUE WHERE id = $1 OR license_key = $1`, [id]);
      return json(res, 200, { ok: true });
    } catch (err) { return json(res, 500, { ok: false, error: err.message }); }
  }

  // ── DELETE /api/admin/licences/:id ───────────────────────────────────────────
  if (req.method === "DELETE" && (url.startsWith("/api/admin/licences/") || url.startsWith("/admin/licences/"))) {
    const id = url.split("/")[4];
    try {
      await pool.query(`DELETE FROM licences WHERE id = $1 OR license_key = $1`, [id]);
      return json(res, 200, { ok: true });
    } catch (err) { return json(res, 500, { ok: false, error: err.message }); }
  }

  // ── POST /generate-licence (legacy) ──────────────────────────────────────────
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

  // ── POST /activate-licence ────────────────────────────────────────────────────
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

      if (licence.deactivated || licence.status === "revoked")
        return json(res, 200, { ok: false, reason: "revoked" });

      if (licence.blocked)
        return json(res, 200, { ok: false, reason: "machine_blocked" });

      if (licence.expires_at && new Date() > new Date(licence.expires_at))
        return json(res, 200, { ok: false, reason: "expired" });

      if (licence.machine_id && machine_id && licence.machine_id !== machine_id)
        return json(res, 200, { ok: false, reason: "machine_blocked" });

      const now = new Date();
      const expiresAt = licence.expires_at || (() => { const d = new Date(now); d.setDate(d.getDate() + licence.duration); return d; })();
      const activationEntry = { machine_id, ip, activated_at: now.toISOString() };

      await pool.query(
        `UPDATE licences SET
          status = 'active',
          machine_id = COALESCE(machine_id, $1),
          activated_at = COALESCE(activated_at, $2),
          expires_at = COALESCE(expires_at, $3),
          last_seen = $4,
          first_ip = COALESCE(first_ip, $5),
          last_ip = $5,
          activation_history = activation_history || $6::jsonb
         WHERE license_key = $7`,
        [machine_id || null, now, expiresAt, now, ip, JSON.stringify([activationEntry]), key]
      );

      const token = jwt.sign(
        { license_key: key, machine_id, expires_at: expiresAt instanceof Date ? expiresAt.toISOString() : expiresAt },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRES }
      );

      console.log(`[ACTIVATE] OK key=${key}`);
      return json(res, 200, { ok: true, token, expiresAt: expiresAt instanceof Date ? expiresAt.toISOString() : expiresAt });

    } catch (err) {
      console.error("[ACTIVATE] error:", err.message);
      return json(res, 500, { ok: false, error: "DB error" });
    }
  }

  // ── POST /validate-licence ────────────────────────────────────────────────────
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
      if (l.deactivated || l.status === "revoked") return json(res, 200, { ok: false, reason: "revoked" });
      if (l.blocked) return json(res, 200, { ok: false, reason: "machine_blocked" });
      if (l.status !== "active") return json(res, 200, { ok: false, reason: "licence_inactive" });
      if (l.expires_at && new Date() > new Date(l.expires_at)) return json(res, 200, { ok: false, reason: "licence_expired" });

      return json(res, 200, { ok: true });
    } catch {
      return json(res, 200, { ok: false, reason: "invalid_token" });
    }
  }

  // ── POST /refresh-token ───────────────────────────────────────────────────────
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
      if (l.deactivated || l.status === "revoked") return json(res, 200, { ok: false, reason: "revoked" });
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

  // ── POST /revoke-licence ──────────────────────────────────────────────────────
  if (req.method === "POST" && url === "/revoke-licence") {
    const body = await readBody(req);
    const key  = (body.key || "").trim().toUpperCase();
    if (!key) return json(res, 400, { ok: false, error: "Missing key" });
    try {
      await pool.query(`UPDATE licences SET status = 'revoked' WHERE license_key = $1`, [key]);
      return json(res, 200, { ok: true });
    } catch (err) { return json(res, 500, { ok: false, error: "DB error" }); }
  }

  // ── POST /heartbeat ───────────────────────────────────────────────────────────
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

      const { rows } = await pool.query(
        `SELECT status, expires_at, deactivated, blocked FROM licences WHERE license_key = $1`,
        [decoded.license_key]
      );

      if (!rows.length) return json(res, 200, { ok: false, reason: "invalid" });
      const l = rows[0];
      if (l.deactivated || l.status === "revoked") return json(res, 200, { ok: false, reason: "revoked" });
      if (l.blocked) return json(res, 200, { ok: false, reason: "machine_blocked" });
      if (l.status !== "active") return json(res, 200, { ok: false, reason: "licence_inactive" });
      if (l.expires_at && new Date() > new Date(l.expires_at)) return json(res, 200, { ok: false, reason: "licence_expired" });

      const hbEntry = { ts: new Date().toISOString(), ip, version };

      await pool.query(
        `UPDATE licences SET
          last_seen = NOW(),
          last_ip = $1,
          current_version = $2,
          heartbeat_history = (
            SELECT jsonb_agg(val) FROM (
              SELECT val FROM jsonb_array_elements(heartbeat_history || $3::jsonb) val
              ORDER BY (val->>'ts') DESC LIMIT 50
            ) sub
          )
         WHERE license_key = $4`,
        [ip, version, JSON.stringify([hbEntry]), decoded.license_key]
      );

      return json(res, 200, { ok: true });
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
