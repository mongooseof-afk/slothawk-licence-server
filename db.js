// db.js — PostgreSQL backend (replaces the JSON file store)
// All data is now persistent across Render restarts/deploys.

import pg from 'pg';
import crypto from 'crypto';

const { Pool } = pg;

// Use DATABASE_URL env var on Render, fall back to nothing (will throw)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes('render.com')
    ? { rejectUnauthorized: false }
    : false,
  max: 10,
  idleTimeoutMillis: 30000,
});

// ── Helpers ───────────────────────────────────────────────────────────────────

export function normalizeIp(ip) {
  if (!ip) return null;
  if (ip === '::1') return '127.0.0.1';
  return ip.replace(/^::ffff:/, '');
}

export function generateKey() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  const group = () =>
    Array.from({ length: 5 }, () =>
      chars[Math.floor(Math.random() * chars.length)]
    ).join('');
  return [group(), group(), group(), group(), group()].join('-');
}

// Map a DB row (snake_case) → JS object (camelCase) the rest of server.js expects
function rowToLicence(r) {
  if (!r) return null;
  return {
    id:                r.id,
    licenseKey:        r.license_key,
    key:               r.license_key,
    username:          r.username        ?? '',
    machineId:         r.machine_id      ?? null,
    status:            r.status,
    active:            r.active,
    plan:              r.plan,
    notes:             r.notes           ?? '',
    duration:          r.duration,
    expiresAt:         r.expires_at      ?? null,
    createdAt:         r.created_at,
    activatedAt:       r.activated_at    ?? null,
    lastSeen:          r.last_seen       ?? null,
    firstIp:           r.first_ip        ?? null,
    lastIp:            r.last_ip         ?? null,
    currentVersion:    r.current_version ?? null,
    browserInfo:       r.browser_info    ?? null,
    deactivated:       r.deactivated     ?? false,
    blocked:           r.blocked         ?? false,
    suspicious:        r.suspicious      ?? false,
    suspiciousReason:  r.suspicious_reason ?? null,
    knownDevices:      r.known_devices      ?? [],
    heartbeatHistory:  r.heartbeat_history  ?? [],
    activationHistory: r.activation_history ?? [],
    sessions:          r.sessions           ?? [],
    bookingEvents:     r.booking_events     ?? [],
  };
}

// ── Read ──────────────────────────────────────────────────────────────────────

export async function getLicense(licenseKey) {
  const { rows } = await pool.query(
    'SELECT * FROM licences WHERE license_key = $1',
    [licenseKey]
  );
  return rowToLicence(rows[0]);
}

export async function getLicenseById(id) {
  const { rows } = await pool.query(
    'SELECT * FROM licences WHERE id = $1',
    [id]
  );
  return rowToLicence(rows[0]);
}

export async function listLicenses({ search = '', status = 'all', sortBy = 'created_at', sortOrder = 'desc', page = 1, limit = 25 } = {}) {
  const allowed = ['created_at','activated_at','expires_at','last_seen','status'];
  const col = allowed.includes(sortBy) ? sortBy : 'created_at';
  const dir = sortOrder === 'asc' ? 'ASC' : 'DESC';

  const conditions = [];
  const params = [];

  if (status !== 'all') {
    params.push(status);
    conditions.push(`status = $${params.length}`);
  }
  if (search) {
    params.push(`%${search.toLowerCase()}%`);
    const n = params.length;
    conditions.push(`(LOWER(license_key) LIKE $${n} OR LOWER(username) LIKE $${n} OR LOWER(COALESCE(machine_id,'')) LIKE $${n} OR LOWER(COALESCE(last_ip,'')) LIKE $${n})`);
  }

  const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

  const countRes = await pool.query(`SELECT COUNT(*) FROM licences ${where}`, params);
  const total = parseInt(countRes.rows[0].count, 10);

  const offset = (page - 1) * limit;
  params.push(limit, offset);
  const { rows } = await pool.query(
    `SELECT * FROM licences ${where} ORDER BY ${col} ${dir} LIMIT $${params.length - 1} OFFSET $${params.length}`,
    params
  );

  return { data: rows.map(rowToLicence), total, page, limit, totalPages: Math.ceil(total / limit) || 1 };
}

// ── Create ────────────────────────────────────────────────────────────────────

export async function createLicense({ licenseKey, duration = 30, plan = 'standard', notes = '', username = '' }) {
  const key = licenseKey || generateKey();
  const id  = crypto.randomUUID();
  const expiresAt = new Date(Date.now() + duration * 86400000);

  const { rows } = await pool.query(`
    INSERT INTO licences (id, license_key, username, duration, expires_at, plan, notes)
    VALUES ($1, $2, $3, $4, $5, $6, $7)
    RETURNING *`,
    [id, key, username, duration, expiresAt, plan, notes]
  );
  return rowToLicence(rows[0]);
}

// ── Bind machine ──────────────────────────────────────────────────────────────

export async function bindMachine(licenseKey, machineId, ip = null) {
  const cleanIp = normalizeIp(ip);
  const lic = await getLicense(licenseKey);
  if (!lic) return null;
  const now = new Date();

  // Update known_devices
  const devices = lic.knownDevices || [];
  const known = devices.some(d => d.machineId === machineId && d.ip === cleanIp);
  if (!known) devices.push({ machineId, ip: cleanIp, firstSeenAt: now.toISOString() });

  // Activation history
  const actHistory = lic.activationHistory || [];
  actHistory.unshift({ id: crypto.randomUUID(), createdAt: now.toISOString(), ip: cleanIp, machineId });
  if (actHistory.length > 20) actHistory.length = 20;

  const { rows } = await pool.query(`
    UPDATE licences SET
      machine_id = $1, status = 'active', deactivated = FALSE,
      activated_at = COALESCE(activated_at, $2), last_seen = $2,
      first_ip = COALESCE(first_ip, $3), last_ip = $3,
      known_devices = $4, activation_history = $5
    WHERE license_key = $6 RETURNING *`,
    [machineId, now, cleanIp, JSON.stringify(devices), JSON.stringify(actHistory), licenseKey]
  );
  return rowToLicence(rows[0]);
}

// ── Heartbeat ────────────────────────────────────────────────────────────────

const SESSION_GAP_MS = 10 * 60 * 1000;

export async function updateHeartbeat(licenseKey, machineId = null, version = null, ip = null) {
  const cleanIp = normalizeIp(ip);
  const lic = await getLicense(licenseKey);
  if (!lic) return null;
  const now = new Date();

  // Sessions
  const sessions = lic.sessions || [];
  const last = sessions[0];
  const gap = last ? (now - new Date(last.lastPingAt)) : Infinity;
  if (gap > SESSION_GAP_MS) {
    sessions.unshift({ id: crypto.randomUUID(), startedAt: now.toISOString(), lastPingAt: now.toISOString(), endedAt: null, ip: cleanIp, machineId });
    if (sessions.length > 50) sessions.length = 50;
  } else {
    sessions[0].lastPingAt = now.toISOString();
  }

  // Heartbeat history
  const hbHistory = lic.heartbeatHistory || [];
  hbHistory.unshift({ id: crypto.randomUUID(), createdAt: now.toISOString(), ip: cleanIp, version, machineId });
  if (hbHistory.length > 100) hbHistory.length = 100;

  const { rows } = await pool.query(`
    UPDATE licences SET
      last_seen = $1,
      machine_id = COALESCE($2, machine_id),
      current_version = COALESCE($3, current_version),
      first_ip = COALESCE(first_ip, $4), last_ip = COALESCE($4, last_ip),
      sessions = $5, heartbeat_history = $6
    WHERE license_key = $7 RETURNING *`,
    [now, machineId, version, cleanIp, JSON.stringify(sessions), JSON.stringify(hbHistory), licenseKey]
  );
  return rowToLicence(rows[0]);
}

// ── Booking event ─────────────────────────────────────────────────────────────

export async function addBookingEvent(licenseKey, { success, mission, slotDate, reason, machineId, ip }) {
  const lic = await getLicense(licenseKey);
  if (!lic) return null;
  const events = lic.bookingEvents || [];
  events.unshift({ id: crypto.randomUUID(), createdAt: new Date().toISOString(), success: !!success, mission, slotDate, reason, machineId, ip: normalizeIp(ip) });
  if (events.length > 200) events.length = 200;
  const { rows } = await pool.query(
    `UPDATE licences SET booking_events = $1 WHERE license_key = $2 RETURNING *`,
    [JSON.stringify(events), licenseKey]
  );
  return rowToLicence(rows[0]);
}

// ── Admin actions ─────────────────────────────────────────────────────────────

export async function revokeLicense(licenseKey) {
  const { rows } = await pool.query(
    `UPDATE licences SET active = FALSE, status = 'revoked' WHERE license_key = $1 RETURNING *`,
    [licenseKey]
  );
  return rowToLicence(rows[0]);
}

export async function reactivateLicense(licenseKey) {
  const { rows } = await pool.query(
    `UPDATE licences SET active = TRUE, deactivated = FALSE, status = CASE WHEN machine_id IS NOT NULL THEN 'active' ELSE 'pending' END WHERE license_key = $1 RETURNING *`,
    [licenseKey]
  );
  return rowToLicence(rows[0]);
}

export async function deactivateLicense(licenseKey) {
  const { rows } = await pool.query(
    `UPDATE licences SET machine_id = NULL, status = 'pending', deactivated = TRUE, activated_at = NULL WHERE license_key = $1 RETURNING *`,
    [licenseKey]
  );
  return rowToLicence(rows[0]);
}

export async function resetMachine(licenseKey) {
  const { rows } = await pool.query(
    `UPDATE licences SET machine_id = NULL, status = CASE WHEN active THEN 'pending' ELSE status END,
     deactivated = FALSE, blocked = FALSE, suspicious = FALSE, suspicious_reason = NULL, known_devices = '[]'
     WHERE license_key = $1 RETURNING *`,
    [licenseKey]
  );
  return rowToLicence(rows[0]);
}

export async function extendLicense(licenseKey, days) {
  const { rows } = await pool.query(
    `UPDATE licences SET
      expires_at = GREATEST(expires_at, NOW()) + ($1 || ' days')::INTERVAL,
      duration = duration + $1
     WHERE license_key = $2 RETURNING *`,
    [days, licenseKey]
  );
  return rowToLicence(rows[0]);
}

export async function flagSuspicious(licenseKey, machineId, ip) {
  const reason = `Blocked: new device — machine ${machineId.slice(0, 8)}… from IP ${ip || 'unknown'}`;
  const { rows } = await pool.query(
    `UPDATE licences SET blocked = TRUE, suspicious = TRUE, suspicious_reason = $1 WHERE license_key = $2 RETURNING *`,
    [reason, licenseKey]
  );
  return rowToLicence(rows[0]);
}

export async function clearBlock(licenseKey) {
  const { rows } = await pool.query(
    `UPDATE licences SET blocked = FALSE, suspicious = FALSE, suspicious_reason = NULL WHERE license_key = $1 RETURNING *`,
    [licenseKey]
  );
  return rowToLicence(rows[0]);
}

export async function deleteLicense(licenseKey) {
  const { rowCount } = await pool.query(
    `DELETE FROM licences WHERE license_key = $1`,
    [licenseKey]
  );
  return rowCount > 0;
}
