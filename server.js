const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const { Pool } = require("pg");

const app = express();
app.use(cors());
app.use(express.json({ limit: "100kb" }));

const PORT = process.env.PORT || 4000;
const DATABASE_URL = process.env.DATABASE_URL;
const ADMIN_API_KEY = process.env.ADMIN_API_KEY;

if (!DATABASE_URL) {
  console.error("Missing DATABASE_URL environment variable.");
  process.exit(1);
}
if (!ADMIN_API_KEY) {
  console.error("Missing ADMIN_API_KEY environment variable.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.PGSSLMODE === "disable" ? false : { rejectUnauthorized: false }
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS pots (
      pot_id TEXT PRIMARY KEY,
      soil_type TEXT NOT NULL,
      experiment_group TEXT NOT NULL CHECK (experiment_group IN ('control', 'treatment')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS devices (
      device_id TEXT PRIMARY KEY,
      device_name TEXT NOT NULL,
      token_hash TEXT NOT NULL UNIQUE,
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS sensor_readings (
      id BIGSERIAL PRIMARY KEY,
      device_id TEXT NOT NULL REFERENCES devices(device_id),
      pot_id TEXT NOT NULL REFERENCES pots(pot_id),
      moisture_percent NUMERIC(5,2) NOT NULL CHECK (moisture_percent >= 0 AND moisture_percent <= 100),
      raw_adc INTEGER,
      recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      sequence_number BIGINT,
      data_source TEXT NOT NULL DEFAULT 'device' CHECK (data_source IN ('device', 'test'))
    );
    CREATE INDEX IF NOT EXISTS idx_readings_pot_recorded ON sensor_readings(pot_id, recorded_at DESC);
    CREATE INDEX IF NOT EXISTS idx_readings_received ON sensor_readings(received_at DESC);
  `);

  const pots = [
    ["P1", "Black Soil", "control"],
    ["P2", "Black Soil", "treatment"],
    ["P3", "Red Soil", "control"],
    ["P4", "Red Soil", "treatment"],
    ["P5", "Sandy Soil", "control"],
    ["P6", "Sandy Soil", "treatment"]
  ];
  for (const p of pots) {
    await pool.query(
      `INSERT INTO pots (pot_id, soil_type, experiment_group)
       VALUES ($1, $2, $3) ON CONFLICT (pot_id) DO NOTHING`,
      p
    );
  }
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function requireAdmin(req, res, next) {
  const supplied = req.get("x-admin-key");
  if (!supplied || !crypto.timingSafeEqual(
    Buffer.from(sha256(supplied), "hex"),
    Buffer.from(sha256(ADMIN_API_KEY), "hex")
  )) {
    return res.status(401).json({ error: "Unauthorized admin request" });
  }
  next();
}

async function requireDevice(req, res, next) {
  try {
    const auth = req.get("authorization") || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
    if (!token) return res.status(401).json({ error: "Missing Bearer device token" });

    const result = await pool.query(
      "SELECT device_id FROM devices WHERE token_hash = $1 AND active = TRUE",
      [sha256(token)]
    );
    if (!result.rowCount) return res.status(401).json({ error: "Invalid or inactive device token" });
    req.deviceId = result.rows[0].device_id;
    next();
  } catch (err) {
    next(err);
  }
}

app.get("/api/health", async (_req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ status: "ok", database: "connected", service: "ecohydra-backend" });
  } catch (_err) {
    res.status(503).json({ status: "error", database: "unavailable" });
  }
});

app.get("/api/pots", async (_req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT p.pot_id, p.soil_type, p.experiment_group,
        (SELECT COUNT(*) FROM sensor_readings r WHERE r.pot_id = p.pot_id AND r.data_source = 'device') AS real_reading_count,
        (SELECT moisture_percent FROM sensor_readings r WHERE r.pot_id = p.pot_id AND r.data_source = 'device' ORDER BY recorded_at DESC LIMIT 1) AS latest_moisture_percent,
        (SELECT recorded_at FROM sensor_readings r WHERE r.pot_id = p.pot_id AND r.data_source = 'device' ORDER BY recorded_at DESC LIMIT 1) AS latest_recorded_at
       FROM pots p ORDER BY p.pot_id`
    );
    res.json({ pots: result.rows });
  } catch (err) { next(err); }
});

app.get("/api/sensor-readings", async (req, res, next) => {
  try {
    const limit = Math.min(Math.max(parseInt(req.query.limit || "100", 10) || 100, 1), 1000);
    const potId = req.query.pot_id;
    const source = req.query.source || "all";
    if (!["all", "device", "test"].includes(source)) {
      return res.status(400).json({ error: "source must be all, device, or test" });
    }
    const clauses = [];
    const values = [];
    if (potId) { values.push(potId); clauses.push(`pot_id = $${values.length}`); }
    if (source !== "all") { values.push(source); clauses.push(`data_source = $${values.length}`); }
    values.push(limit);
    const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
    const result = await pool.query(
      `SELECT id, device_id, pot_id, moisture_percent, raw_adc, recorded_at, received_at, sequence_number, data_source
       FROM sensor_readings ${where} ORDER BY recorded_at DESC LIMIT $${values.length}`,
      values
    );
    res.json({ readings: result.rows });
  } catch (err) { next(err); }
});

// Admin-only: create a device and return its one-time token. Save the token securely.
app.post("/api/devices", requireAdmin, async (req, res, next) => {
  try {
    const { device_id, device_name } = req.body || {};
    if (typeof device_id !== "string" || !/^[A-Za-z0-9_-]{2,64}$/.test(device_id)) {
      return res.status(400).json({ error: "device_id must be 2-64 letters, numbers, _ or -" });
    }
    if (typeof device_name !== "string" || device_name.trim().length < 2 || device_name.trim().length > 100) {
      return res.status(400).json({ error: "device_name must be 2-100 characters" });
    }
    const token = crypto.randomBytes(32).toString("hex");
    await pool.query(
      "INSERT INTO devices (device_id, device_name, token_hash) VALUES ($1, $2, $3)",
      [device_id, device_name.trim(), sha256(token)]
    );
    res.status(201).json({
      device_id,
      device_name: device_name.trim(),
      device_token: token,
      warning: "This token is shown only once. Store it securely."
    });
  } catch (err) {
    if (err.code === "23505") return res.status(409).json({ error: "device_id already exists" });
    next(err);
  }
});

app.post("/api/sensor-readings", requireDevice, async (req, res, next) => {
  try {
    const body = req.body || {};
    const { pot_id, moisture_percent, raw_adc, recorded_at, sequence_number } = body;

    if (typeof pot_id !== "string" || !/^P[1-6]$/.test(pot_id)) {
      return res.status(400).json({ error: "pot_id must be P1 through P6" });
    }
    const moisture = Number(moisture_percent);
    if (!Number.isFinite(moisture) || moisture < 0 || moisture > 100) {
      return res.status(400).json({ error: "moisture_percent must be a number from 0 to 100" });
    }
    let raw = null;
    if (raw_adc !== undefined && raw_adc !== null) {
      raw = Number(raw_adc);
      if (!Number.isInteger(raw) || raw < 0 || raw > 65535) {
        return res.status(400).json({ error: "raw_adc must be an integer from 0 to 65535" });
      }
    }
    let timestamp = new Date();
    if (recorded_at !== undefined) {
      timestamp = new Date(recorded_at);
      if (Number.isNaN(timestamp.getTime())) return res.status(400).json({ error: "recorded_at must be a valid date/time" });
      const now = Date.now();
      if (timestamp.getTime() > now + 5 * 60 * 1000) return res.status(400).json({ error: "recorded_at cannot be more than 5 minutes in the future" });
    }
    let seq = null;
    if (sequence_number !== undefined && sequence_number !== null) {
      seq = Number(sequence_number);
      if (!Number.isSafeInteger(seq) || seq < 0) return res.status(400).json({ error: "sequence_number must be a non-negative integer" });
    }

    const result = await pool.query(
      `INSERT INTO sensor_readings
       (device_id, pot_id, moisture_percent, raw_adc, recorded_at, sequence_number, data_source)
       VALUES ($1, $2, $3, $4, $5, $6, 'device')
       RETURNING id, device_id, pot_id, moisture_percent, raw_adc, recorded_at, received_at, sequence_number, data_source`,
      [req.deviceId, pot_id, moisture, raw, timestamp.toISOString(), seq]
    );
    res.status(201).json({ message: "Reading stored", reading: result.rows[0] });
  } catch (err) { next(err); }
});

// Admin-only test endpoint. These records are marked test and are not real experiment data.
app.post("/api/test-readings", requireAdmin, async (req, res, next) => {
  try {
    const { pot_id, moisture_percent } = req.body || {};
    if (typeof pot_id !== "string" || !/^P[1-6]$/.test(pot_id)) {
      return res.status(400).json({ error: "pot_id must be P1 through P6" });
    }
    const moisture = Number(moisture_percent);
    if (!Number.isFinite(moisture) || moisture < 0 || moisture > 100) {
      return res.status(400).json({ error: "moisture_percent must be a number from 0 to 100" });
    }
    const result = await pool.query(
      `INSERT INTO sensor_readings (device_id, pot_id, moisture_percent, data_source)
       VALUES ('TEST', $1, $2, 'test')
       RETURNING id, device_id, pot_id, moisture_percent, recorded_at, received_at, data_source`,
      [pot_id, moisture]
    );
    res.status(201).json({ message: "Test reading stored; not real experiment data", reading: result.rows[0] });
  } catch (err) { next(err); }
});

app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: "Internal server error" });
});

initDb()
  .then(() => app.listen(PORT, "0.0.0.0", () => {
    console.log(`EcoHydra API listening on port ${PORT}`);
  }))
  .catch((err) => {
    console.error("Database initialization failed:", err.message);
    process.exit(1);
  });
