import express from "express";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import {
  getLicense, getLicenseById, createLicense, bindMachine,
  extendLicense, revokeLicense, reactivateLicense, deactivateLicense, resetMachine,
  deleteLicense, listLicenses, generateKey, updateHeartbeat,
  normalizeIp, flagSuspicious, clearBlock, addBookingEvent,
} from "./db.js";

const PORT = process.env.PORT || 8766;
const MIN_EXTENSION_VERSION = process.env.MIN_VERSION || "0.1.58";
let JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(48).toString("hex");
const JWT_EXPIRY = "7d";

const app = express();
app.set("trust proxy", true);
app.use(express.json());

app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, x-api-key");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

function isExpired(expiresAt) {
  return expiresAt && new Date(expiresAt).getTime() < Date.now();
}

async function findLicense(keyOrId) {
  return (await getLicense(keyOrId)) || (await getLicenseById(keyOrId)) || null;
}

function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRY });
}

function verifyToken(token) {
  try { return jwt.verify(token, JWT_SECRET); }
  catch { return null; }
}

// ── Machine ID ────────────────────────────────────────────────────────────────
app.get("/machine", (req, res) => {
  // On Render, machine_id comes from the DB (per licence), not from a local file.
  // This endpoint is only used by the local sync server — on Render it is not
  // needed but we return a stable ID for backward compatibility.
  res.json({ ok: true, machine_id: "render-server" });
});

// ── Health ────────────────────────────────────────────────────────────────────
app.get("/health", (req, res) => {
  res.json({ status: "ok", version: "5.0.0", requiredExtensionVersion: MIN_EXTENSION_VERSION });
});

app.get("/version", (req, res) => {
  res.json({ required: MIN_EXTENSION_VERSION });
});

// ── Extension: activate ───────────────────────────────────────────────────────
app.post("/activate-licence", async (req, res) => {
  try {
    const { key, machine_id, browser_info } = req.body || {};
    if (!key || !machine_id) return res.json({ ok: false, reason: "missing_fields" });

    const lic = await getLicense(key);
    if (!lic)                        return res.json({ ok: false, reason: "invalid_key" });
    if (!lic.active || lic.status === "revoked") return res.json({ ok: false, reason: "revoked" });
    if (lic.deactivated)             return res.json({ ok: false, reason: "deactivated" });
    if (isExpired(lic.expiresAt))    return res.json({ ok: false, reason: "expired" });
    if (lic.machineId && lic.machineId !== machine_id) return res.json({ ok: false, reason: "machine_blocked" });
    if (lic.blocked)                 return res.json({ ok: false, reason: "blocked_new_device" });

    const knownDevices = lic.knownDevices || [];
    const isNewMachine = knownDevices.length > 0 && !knownDevices.some(d => d.machineId === machine_id);
    if (isNewMachine && !lic.machineId) {
      await flagSuspicious(key, machine_id, normalizeIp(req.ip));
      return res.json({ ok: false, reason: "blocked_new_device" });
    }

    await bindMachine(key, machine_id, req.ip);
    await updateHeartbeat(key, machine_id, browser_info?.extension_version || null, req.ip);
    const token = signToken({ key, machine_id });
    res.json({ ok: true, token, expiresAt: (await getLicense(key))?.expiresAt || null });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// ── Extension: validate ───────────────────────────────────────────────────────
app.post("/validate-licence", async (req, res) => {
  try {
    const { token, key } = req.body || {};
    if (!token) return res.json({ ok: false, reason: "no_token" });
    const payload = verifyToken(token);
    if (!payload) return res.json({ ok: false, reason: "invalid_token" });
    if (key && payload.key !== key) return res.json({ ok: false, reason: "key_mismatch" });
    const lic = await getLicense(payload.key);
    if (!lic || !lic.active || lic.status === "revoked" || lic.deactivated)
      return res.json({ ok: false, reason: !lic ? "invalid_key" : lic.deactivated ? "deactivated" : "revoked" });
    if (isExpired(lic.expiresAt)) return res.json({ ok: false, reason: "expired" });
    if (lic.machineId !== payload.machine_id) return res.json({ ok: false, reason: "machine_reset" });
    res.json({ ok: true, expiresAt: lic.expiresAt });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// ── Extension: heartbeat ──────────────────────────────────────────────────────
app.post("/heartbeat", async (req, res) => {
  try {
    const { token, machine_id, extension_version } = req.body || {};
    if (!token) return res.json({ ok: false, reason: "no_token" });
    const payload = verifyToken(token);
    if (!payload) return res.json({ ok: false, reason: "invalid_token" });
    const lic = await getLicense(payload.key);
    if (!lic || !lic.active || lic.status === "revoked" || lic.deactivated)
      return res.json({ ok: false, reason: !lic ? "invalid_key" : lic.deactivated ? "deactivated" : "revoked" });
    if (isExpired(lic.expiresAt)) return res.json({ ok: false, reason: "expired" });
    if (lic.machineId !== payload.machine_id) return res.json({ ok: false, reason: "machine_reset" });
    await updateHeartbeat(payload.key, machine_id, extension_version, req.ip);
    res.json({ ok: true, expiresAt: lic.expiresAt });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// ── Extension: refresh token ──────────────────────────────────────────────────
app.post("/refresh-token", async (req, res) => {
  try {
    const { token, machine_id } = req.body || {};
    if (!token) return res.json({ ok: false, reason: "no_token" });
    const payload = verifyToken(token);
    if (!payload) return res.json({ ok: false, reason: "invalid_token" });
    const lic = await getLicense(payload.key);
    if (!lic || !lic.active || lic.status === "revoked" || lic.deactivated)
      return res.json({ ok: false, reason: !lic ? "invalid_key" : lic.deactivated ? "deactivated" : "revoked" });
    if (isExpired(lic.expiresAt)) return res.json({ ok: false, reason: "expired" });
    if (lic.machineId !== payload.machine_id) return res.json({ ok: false, reason: "machine_reset" });
    const newToken = signToken({ key: payload.key, machine_id: machine_id || payload.machine_id });
    res.json({ ok: true, token: newToken });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// ── Extension: booking event ──────────────────────────────────────────────────
app.post("/booking-event", async (req, res) => {
  try {
    const { token, success, mission, slot_date, reason } = req.body || {};
    if (!token) return res.json({ ok: false, reason: "no_token" });
    const payload = verifyToken(token);
    if (!payload) return res.json({ ok: false, reason: "invalid_token" });
    await addBookingEvent(payload.key, { success, mission, slotDate: slot_date, reason, machineId: payload.machine_id, ip: req.ip });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// ── Admin: list ───────────────────────────────────────────────────────────────
app.get("/admin/licences", async (req, res) => {
  try {
    const { search = "", status = "all", page = "1", limit = "25", sortBy = "created_at", sortOrder = "desc" } = req.query;
    const result = await listLicenses({
      search: String(search), status: String(status),
      sortBy: String(sortBy), sortOrder: String(sortOrder),
      page: Math.max(1, parseInt(String(page))),
      limit: Math.min(100, Math.max(1, parseInt(String(limit)))),
    });
    res.json(result);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Admin: get one ────────────────────────────────────────────────────────────
app.get("/admin/licences/:key", async (req, res) => {
  try {
    const lic = await findLicense(req.params.key);
    if (!lic) return res.status(404).json({ error: "Licence not found." });
    res.json(lic);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Admin: generate ───────────────────────────────────────────────────────────
app.post("/admin/licences/generate", async (req, res) => {
  try {
    const { duration = 30, quantity = 1, username = "" } = req.body || {};
    if (quantity < 1 || quantity > 100) return res.status(400).json({ error: "quantity must be 1-100" });
    if (duration < 1 || duration > 3650) return res.status(400).json({ error: "duration must be 1-3650 days" });
    const licences = [];
    for (let i = 0; i < quantity; i++) {
      const lic = await createLicense({ duration, username });
      licences.push({ key: lic.key, username: lic.username });
    }
    res.status(201).json({ licences });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Admin: extend ─────────────────────────────────────────────────────────────
app.patch("/admin/licences/:key/extend", async (req, res) => {
  try {
    const { days } = req.body || {};
    if (!days || days < 1) return res.status(400).json({ error: "days must be >= 1" });
    const lic = await findLicense(req.params.key);
    if (!lic) return res.status(404).json({ error: "Licence not found." });
    res.json({ ok: true, licence: await extendLicense(lic.licenseKey, days) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Admin: revoke ─────────────────────────────────────────────────────────────
app.patch("/admin/licences/:key/revoke", async (req, res) => {
  try {
    const lic = await findLicense(req.params.key);
    if (!lic) return res.status(404).json({ error: "Licence not found." });
    res.json({ ok: true, licence: await revokeLicense(lic.licenseKey) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post("/admin/licences/:key/revoke", async (req, res) => {
  try {
    const lic = await findLicense(req.params.key);
    if (!lic) return res.status(404).json({ error: "Licence not found." });
    res.json({ ok: true, licence: await revokeLicense(lic.licenseKey) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Admin: reactivate ─────────────────────────────────────────────────────────
app.patch("/admin/licences/:key/reactivate", async (req, res) => {
  try {
    const lic = await findLicense(req.params.key);
    if (!lic) return res.status(404).json({ error: "Licence not found." });
    res.json({ ok: true, licence: await reactivateLicense(lic.licenseKey) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Admin: reset machine ──────────────────────────────────────────────────────
app.patch("/admin/licences/:key/reset-machine", async (req, res) => {
  try {
    const lic = await findLicense(req.params.key);
    if (!lic) return res.status(404).json({ error: "Licence not found." });
    res.json({ ok: true, licence: await resetMachine(lic.licenseKey) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Admin: deactivate ─────────────────────────────────────────────────────────
app.patch("/admin/licences/:key/deactivate", async (req, res) => {
  try {
    const lic = await findLicense(req.params.key);
    if (!lic) return res.status(404).json({ error: "Licence not found." });
    res.json({ ok: true, licence: await deactivateLicense(lic.licenseKey) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Admin: clear block ────────────────────────────────────────────────────────
app.patch("/admin/licences/:key/clear-block", async (req, res) => {
  try {
    const lic = await findLicense(req.params.key);
    if (!lic) return res.status(404).json({ error: "Licence not found." });
    res.json({ ok: true, licence: await clearBlock(lic.licenseKey) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Admin: delete ─────────────────────────────────────────────────────────────
app.delete("/admin/licences/:key", async (req, res) => {
  try {
    const lic = await findLicense(req.params.key);
    if (!lic) return res.status(404).json({ error: "Licence not found." });
    await deleteLicense(lic.licenseKey);
    res.json({ ok: true, message: "Licence deleted." });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Admin: create (curl helper) ───────────────────────────────────────────────
app.post("/admin/licences", async (req, res) => {
  try {
    const { licenseKey, duration, plan, notes, username } = req.body || {};
    const lic = await createLicense({ licenseKey, duration, plan, notes, username });
    res.json({ ok: true, licence: lic });
  } catch (e) { res.status(e.message?.includes("already exists") ? 409 : 500).json({ ok: false, error: e.message }); }
});

app.get("/", (req, res) => {
  res.json({ ok: true, service: "SlotHawk License Server", version: "5.0.0" });
});

app.listen(PORT, () => {
  console.log(`SlotHawk License Server v5 listening on port ${PORT}`);
});
