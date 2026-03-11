"use strict";
const swaggerUi = require("swagger-ui-express");
const swaggerJsdoc = require("swagger-jsdoc");
const express = require("express");
const cors = require("cors");
const { exec } = require("child_process");
const fs = require("fs");
const path = require("path");
const { Client } = require("pg"); // ADDED PG CLIENT
const PROD_LOG_DIR = "G:\\bank of uganda\\logs";
const DEV_LOG_DIR = "G:\\bank of uganda\\logs\\dev logs";
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const NodeCache = require("node-cache");
const jwt = require("jsonwebtoken"); // ADDED JWT
const tokenCache = new NodeCache({ stdTTL: 300 }); // 5 minutes cache

const app = express();
app.set('trust proxy', 1); // Enable trusting X-Forwarded-For from IIS Proxy
app.use(helmet());
app.use(cors());
app.use(express.json());

const limiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 500, // limit each IP to 50 requests per windowMs
  message: { error: "Too many requests from this IP, please try again later." },
  keyGenerator: (req) => {
    return req.ip ? req.ip.replace(/:\d+[^:]*$/, '') : 'unknown';
  }
});
app.use(limiter);

const axios = require("axios");

// --- CONFIGURATION ---
const CONFIG = {
  PORT: 3000,
  STRAPI_BASE_URL: "https://bouweb-test.bou.or.ug",
  SYSTEM_SETTING_ENDPOINT: "/api/system-setting",
  USERS_ME_ENDPOINT: "/admin/users/me",
  AUDIT_LOG_ENDPOINT: "/api/audit-logs",
  NSSM_PATH: "C:\\nssm\\nssm.exe", // change if different
  STRAPI_PROJECT_PATH: "G:\\bank of uganda\\bank of uganda\\backend\\backend", // change to your real path
  STRAPI_API_TOKEN: "55b564dc5c9ad792170318288473e17dc0bb17fb1a7423374ab023a54126cde0a1bc2139f8127207c58a3f2b0d4a31aeaa69d4f570400c176dfcd556ed250427afdbdea0e49369998db965550e426e03db0cb54f35a588d61b2523886a3905f93b89684b4d64a68bcd077635fa2b4195dcedcac02d4f80c78221ee4a0679df0d", // Strapi API Token
  DB_HOST: "127.0.0.1",
  DB_PORT: 5432,
  DB_NAME: "bou",
  DB_USER: "postgres",
  DB_PASS: "BankOfUgandaWebSite@2026",
  BACKUP_EMAIL: "infraadmin@bou.or.ug",
  BACKUP_PASSWORD: "EmergencyPassword2026!",
  JWT_SECRET: "s3cr3t_em3rg3ncy_k3y_b0u",
  PG_DUMP_PATH: "C:\\Program Files\\PostgreSQL\\17\\bin\\pg_dump.exe",
  BACKUP_DIR: "G:\\bou-backups\\dbdumps"
};

const LOG_DIR = path.join(__dirname, "logs");
const LOG_FILE = path.join(LOG_DIR, "control.log");
if (!fs.existsSync(LOG_DIR)) {
  fs.mkdirSync(LOG_DIR, { recursive: true });
}

// Database Connection
const pgClient = new Client({
  host: CONFIG.DB_HOST,
  port: CONFIG.DB_PORT,
  database: CONFIG.DB_NAME,
  user: CONFIG.DB_USER,
  password: CONFIG.DB_PASS,
});

pgClient.connect()
  .then(() => writeLog("Connected to PostgreSQL Database for status tracking."))
  .catch(err => writeLog(`ERROR: Failed to connect to PostgreSQL: ${err.message}`));


async function verifyToken(req, res, next) {
  // Allow swagger docs, status, login and logs endpoints without auth
  if (req.path.startsWith("/docs") || req.path === "/status" || req.path === "/api/login" || req.path.startsWith("/logs")) return next();


  let token = req.headers.authorization?.split(" ")[1];

  // For SSE, allow token via query string
  if (!token && req.query.token) {
    token = req.query.token;
  }

  if (!token) {
    return res.status(401).json({ error: "Unauthorized: No token provided" });
  }

  const cachedUser = tokenCache.get(token);
  if (cachedUser) {
    req.user = cachedUser; // Attach user data to request
    if (cachedUser.isInfraAdmin) return next();
    return res.status(403).json({ error: "Forbidden: Infra Admin role required" });
  }

  // 1. Try decoding as local backup JWT first
  try {
    const decoded = jwt.verify(token, CONFIG.JWT_SECRET);
    if (decoded && decoded.isInfraAdmin) {
      req.user = decoded;
      return next();
    }
  } catch (err) {
    // If it fails, we fall through and try as a Strapi token
  }

  // 2. Try validating as Strapi token
  try {
    const meRes = await axios.get(`${CONFIG.STRAPI_BASE_URL}${CONFIG.USERS_ME_ENDPOINT}`, {
      headers: { Authorization: `Bearer ${token}` }
    });

    const roles = meRes.data.data.roles || [];
    const isInfraAdmin = roles.some(r => r.name === "Infra Admin");
    const userEmail = meRes.data.data.email || "Unknown User";
    const userId = meRes.data.data.id || null;

    // Cache the validation result
    const userData = { isInfraAdmin, email: userEmail, id: userId };
    tokenCache.set(token, userData);
    req.user = userData; // Attach user data to request

    if (!isInfraAdmin) {
      return res.status(403).json({ error: "Forbidden: Infra Admin role required" });
    }

    next();
  } catch (error) {
    if (error.response && error.response.status >= 500) {
      // If Strapi is restarting, it might return 502 for a moment.
      // We shouldn't kick the user out or say "invalid token" if Strapi is just down.
      return res.status(503).json({ error: "Service Unavailable: Strapi backend is currently restarting." });
    }
    return res.status(401).json({ error: "Unauthorized: Invalid or expired token" });
  }
}

app.use(verifyToken);

function writeLog(message) {
  const time = new Date().toISOString();
  const log = `[${time}] ${message}\n`;
  fs.appendFileSync(LOG_FILE, log);
}

async function logAuditToStrapi(action, userEmail, userId) {
  try {
    const payload = {
      data: {
        action: action,
        contentType: "Server Configuration",
        newData: {
          info: `Triggered by ${userEmail}`
        },
        actionTime: new Date().toISOString(),
        user: userId
      }
    };
    await axios.post(`${CONFIG.STRAPI_BASE_URL}${CONFIG.AUDIT_LOG_ENDPOINT}`, payload, {
      headers: {
        Authorization: `Bearer ${CONFIG.STRAPI_API_TOKEN}`,
      },
    });
    writeLog(`Audit log sent to Strapi: ${action} by ${userEmail}`);
  } catch (error) {
    writeLog(`ERROR: Failed to send audit log to Strapi: ${error.message}`);
  }
}

// Helper to update DB Status
async function updateDbStatus(updates) {
  try {
    const keys = Object.keys(updates);
    if (keys.length === 0) return;

    // Always append updated_at
    updates.updated_at = new Date().toISOString();

    const setQuery = keys.map((key, index) => `${key} = $${index + 1}`).join(", ");
    const values = keys.map(key => updates[key]);

    await pgClient.query(`UPDATE infrastructure_status SET ${setQuery} WHERE id = 1`, values);
  } catch (err) {
    writeLog(`ERROR: Failed to update DB status: ${err.message}`);
  }
}

// Helper to backup database
async function backupDatabase() {
  return new Promise((resolve, reject) => {
    try {
      if (!fs.existsSync(CONFIG.BACKUP_DIR)) {
        fs.mkdirSync(CONFIG.BACKUP_DIR, { recursive: true });
      }

      const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
      const backupFile = path.join(CONFIG.BACKUP_DIR, `bou_backup_${timestamp}.sql`);
      
      writeLog(`Starting Database Backup to: ${backupFile}`);

      process.env.PGPASSWORD = CONFIG.DB_PASS;
      const command = `"${CONFIG.PG_DUMP_PATH}" -h ${CONFIG.DB_HOST} -p ${CONFIG.DB_PORT} -U ${CONFIG.DB_USER} -d ${CONFIG.DB_NAME} -f "${backupFile}"`;

      exec(command, (err, stdout, stderr) => {
        delete process.env.PGPASSWORD;
        if (err) {
          writeLog(`DATABASE BACKUP ERROR: ${err.message}`);
          return reject(err);
        }
        writeLog(`Database Backup Completed Successfully: ${backupFile}`);
        resolve(backupFile);
      });
    } catch (err) {
      writeLog(`DATABASE BACKUP EXCEPTION: ${err.message}`);
      reject(err);
    }
  });
}

app.post("/audit/login", async (req, res) => {
  try {
    const userEmail = req.user?.email || "Unknown User";
    const userId = req.user?.id || null;
    await logAuditToStrapi("Logged into Control Panel", userEmail, userId);
    res.json({ message: "Login audited successfully" });
  } catch (err) {
    writeLog(`ERROR: Failed to audit login: ${err.message}`);
    res.status(500).json({ error: err.message });
  }
});

// Primary Login Endpoint (Proxy to Strapi with Local Backup)
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }

  try {
    // 1. Try hitting Strapi first
    const loginRes = await axios.post(`${CONFIG.STRAPI_BASE_URL}/admin/login`, {
      email,
      password,
    });
    
    // Strapi Login Success
    return res.json(loginRes.data);
  } catch (error) {
    // 2. If Strapi fails, check WHY it failed
    const status = error.response ? error.response.status : null;
    
    // If explicit invalid credentials (400, 401), we do NOT fallback to backup unless it matches exactly.
    // Instead of completely failing, let's check the local backup in ALL error cases where Strapi doesn't work.
    // (A 502 Bad Gateway means the proxy is up but Strapi is restarting)

    if (email === CONFIG.BACKUP_EMAIL && password === CONFIG.BACKUP_PASSWORD) {
      writeLog(`Authentication fallback triggered. Backup access granted for ${email}`);
      const fallbackToken = jwt.sign(
        { email: CONFIG.BACKUP_EMAIL, isInfraAdmin: true, id: null },
        CONFIG.JWT_SECRET,
        { expiresIn: "1h" }
      );
      
      return res.json({
        data: {
          token: fallbackToken,
          user: { email: CONFIG.BACKUP_EMAIL }
        }
      });
    }

    // If backup credentials do not match, we throw the original error back to the client
    if (status === 401 || status === 400) {
      return res.status(401).json({ error: "Invalid email or password." });
    }

    return res.status(503).json({ error: "Service Unavailable: Authentication backend is down." });
  }
});

// Add a status endpoint
app.get("/status", async (req, res) => {
  try {
    const dbRes = await pgClient.query('SELECT * FROM infrastructure_status WHERE id = 1');
    if (dbRes.rows.length === 0) {
      return res.json({ currentMode: "prod", isProcessing: false }); // Fallback
    }

    const row = dbRes.rows[0];
    const isProcessing = row.switch_status !== 'idle';

    res.json({
      currentMode: isProcessing ? "transitioning" : (row.current_environment === 'development' ? 'dev' : 'prod'),
      isProcessing: isProcessing,
      targetMode: row.target_environment,
      progressMessage: row.progress_message
    });
  } catch (err) {
    writeLog(`Status Endpoint WARNING: DB Error (${err.message}). Defaulting to fallback.`);
    res.json({ currentMode: "transitioning", isProcessing: true });
  }
});

// Helper for waiting
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

async function updateStrapiSettingsWithRetry(payload, maxRetries = 360, retryDelay = 10000) {
  for (let i = 0; i < maxRetries; i++) {
    try {
      if (i % 6 === 0) { // Log every minute (6 * 10s) instead of every single attempt to keep logs clean
        writeLog(`Checking if Strapi is online to update settings...`);
      }
      await axios.put(`${CONFIG.STRAPI_BASE_URL}${CONFIG.SYSTEM_SETTING_ENDPOINT}`, payload);
      writeLog("Successfully updated Strapi settings.");
      return true;
    } catch (err) {
      writeLog(`Failed to update Strapi settings (${err.message}). Retrying in ${retryDelay / 1000}s...`);
      await delay(retryDelay);
    }
  }
  writeLog("ERROR: Could not update Strapi settings after maximum retries.");
  return false;
}

function run(command, fallbackCommand = null) {
  return new Promise((resolve, reject) => {
    exec(command, (err, stdout, stderr) => {
      if (err) {
        // NSSM often outputs UTF-16 with null bytes, so we aggressively clean it up
        const cleanMsg = err.message.replace(/[^a-zA-Z0-9]/g, '').toLowerCase();
        if (cleanMsg.includes("alreadyrunning") || cleanMsg.includes("servicealreadyrunning")) {
          writeLog(`Notice: Process already running for command: ${command}`);
          
          if (fallbackCommand) {
            writeLog(`Executing fallback command: ${fallbackCommand}`);
            return resolve(run(fallbackCommand)); // Recursively run the fallback
          }
          return resolve(stdout || err.message);
        }
        writeLog("ERROR: " + err.message);
        return reject(err);
      }

      if (stdout) writeLog(stdout);
      if (stderr) writeLog(stderr);

      resolve(stdout);
    });
  });
}

async function stopProd() {
  writeLog("Stopping Production Service...");
  return run(`"${CONFIG.NSSM_PATH}" stop StrapiService`);
}

async function startProd() {
  writeLog("Starting Production Service...");
  return run(
      `"${CONFIG.NSSM_PATH}" start StrapiService`,
      `"${CONFIG.NSSM_PATH}" restart StrapiService` // Fallback if already running
  );
}

async function stopDev() {
  writeLog("Stopping Dev Service...");
  return run(`"${CONFIG.NSSM_PATH}" stop StrapiDevService`);
}

async function startDev() {
  writeLog("Starting Dev Service...");
  return run(
      `"${CONFIG.NSSM_PATH}" start StrapiDevService`,
      `"${CONFIG.NSSM_PATH}" restart StrapiDevService` // Fallback if already running
  );
}

async function buildProject() {
  writeLog("Starting Project Build...");

  return new Promise((resolve, reject) => {
    const buildProcess = exec("npm run build", {
      cwd: CONFIG.STRAPI_PROJECT_PATH,
    });

    const buildLogPath = path.join(LOG_DIR, "build.log");

    buildProcess.stdout.on("data", (data) => {
      fs.appendFileSync(buildLogPath, data);
      writeLog(data);
    });

    buildProcess.stderr.on("data", (data) => {
      fs.appendFileSync(buildLogPath, data);
      writeLog("BUILD" + data);
    });

    buildProcess.on("close", (code) => {
      if (code === 0) {
        writeLog("Build Completed Successfully");
        resolve();
      } else {
        reject(new Error("Build failed"));
      }
    });
  });
}

/**
 * @swagger
 * /switch/emergency-dev:
 *   post:
 *     summary: Force Switch to Development Mode (Backup)
 *     description: Stops production service and starts development service forcefully, ignoring current lock states.
 *     responses:
 *       200:
 *         description: Successfully forced dev mode
 *       500:
 *         description: Internal server error
 */
app.post("/switch/emergency-dev", async (req, res) => {
  try {
    const dbRes = await pgClient.query('SELECT current_environment FROM infrastructure_status WHERE id = 1');
    if (dbRes.rows[0]?.current_environment === 'development') {
      return res.status(409).json({ error: "System is already operating in Development mode." });
    }

    writeLog(`[EMERGENCY AUDIT] Force Switching to DEV mode - Requested by: ${req.user?.email || 'Backup Admin'}`);

    // Try to backup DB, but don't let it block if it fails in emergency
    backupDatabase().catch(e => writeLog(`Emergency: backupDatabase error (ignored): ${e.message}`));

    // Update DB to reflect the forced override
    await updateDbStatus({
      switch_status: 'in_progress',
      target_environment: 'development',
      progress_message: 'EMERGENCY OVERRIDE: Forcing switch to Development Mode...',
      triggered_by: req.user?.email || 'Backup Admin',
      started_at: new Date().toISOString()
    });

    // Try to log to Strapi, but it might be down so ignore errors
    logAuditToStrapi("EMERGENCY Force Switch to Development Mode", req.user?.email || 'Backup Admin', req.user?.id).catch(() => {});

    // 1. Force Stop Production (ignoring errors if it's already crashed)
    try { await stopProd(); } catch (e) { writeLog(`Emergency: stopProd error (ignored): ${e.message}`); }

    // 2. WIPE THE DEV LOG FILE
    const outputFile = path.join(DEV_LOG_DIR, "strapi-output.log");
    if (fs.existsSync(outputFile)) {
      try { fs.writeFileSync(outputFile, ""); } catch(e) {}
    }

    // 3. Start Development Service
    await startDev();

    // 4. Update Strapi Settings in the background (will succeed once it boots)
    updateStrapiSettingsWithRetry({
      data: {
        maintenanceMode: true,
        devModeActive: true
      }
    });

    await updateDbStatus({
      switch_status: 'idle',
      current_environment: 'development',
      target_environment: null,
      progress_message: 'System operating in Development mode (Emergency Started)',
      completed_at: new Date().toISOString()
    });

    res.json({ message: "Emergency Development start signal sent" });
  } catch (err) {
    writeLog(`EMERGENCY SWITCH FAILED: ${err.message}`);
    await updateDbStatus({
      switch_status: 'failed',
      progress_message: `Emergency Switch failed: ${err.message}`
    });
    res.status(500).json({ error: err.message });
  }
});

/**
 * @swagger
 * /switch/dev:
 *   post:
 *     summary: Switch to Development Mode
 *     description: Stops production service and starts development service.
 *     responses:
 *       200:
 *         description: Successfully switched to development mode
 *       500:
 *         description: Internal server error
 */
app.post("/switch/dev", async (req, res) => {
  try {
    const dbRes = await pgClient.query('SELECT switch_status FROM infrastructure_status WHERE id = 1');
    if (dbRes.rows[0]?.switch_status !== 'idle') {
      return res.status(409).json({ error: "A process is already running." });
    }

    writeLog(`[AUDIT] Switching to DEV mode - Requested by: ${req.user?.email}`);

    await updateDbStatus({
      switch_status: 'in_progress',
      target_environment: 'development',
      progress_message: 'Initiating switch to Development Mode...',
      triggered_by: req.user?.email,
      started_at: new Date().toISOString()
    });

    // Save Audit event immediately to Strapi
    await logAuditToStrapi("Switch to Development Mode", req.user?.email, req.user?.id);

    // 0. Backup Database
    try {
      await backupDatabase();
    } catch (err) {
      writeLog(`Switch Warning: Database backup failed, but proceeding: ${err.message}`);
    }

    // 1. Stop Production first
    await stopProd();

    // 2. WIPE THE DEV LOG FILE (Clear the notebook)
    const outputFile = path.join(DEV_LOG_DIR, "strapi-output.log");
    if (fs.existsSync(outputFile)) {
      fs.writeFileSync(outputFile, ""); // Make it empty
    }

    // 3. Start Development Service
    await startDev();

    // 4. Update Strapi Settings via API in the background with retry
    // We send res.json() immediately, so the UI doesn't hang waiting for Strapi to boot.
    updateStrapiSettingsWithRetry({
      data: {
        maintenanceMode: true,
        devModeActive: true
      }
    });

    await updateDbStatus({
      switch_status: 'idle',
      current_environment: 'development',
      target_environment: null,
      progress_message: 'System operating in Development mode',
      completed_at: new Date().toISOString()
    });

    res.json({ message: "Development start signal sent" });
  } catch (err) {
    await updateDbStatus({
      switch_status: 'failed',
      progress_message: `Switch failed: ${err.message}`
    });
    res.status(500).json({ error: err.message });
  }
});

/**
 * @swagger
 * /switch/prod:
 *   post:
 *     summary: Switch to Production Mode
 *     description: Stops development service, builds project, and starts production.
 *     responses:
 *       200:
 *         description: Successfully switched to production mode
 *       500:
 *         description: Internal server error
 */
app.post("/switch/prod", async (req, res) => {
  try {
    const dbRes = await pgClient.query('SELECT switch_status FROM infrastructure_status WHERE id = 1');
    if (dbRes.rows[0]?.switch_status !== 'idle') {
      return res.status(409).json({ error: "A process is already running." });
    }

    writeLog("Switching to PROD mode...");

    await updateDbStatus({
      switch_status: 'in_progress',
      target_environment: 'production',
      progress_message: 'Initiating switch to Production Mode...',
      triggered_by: req.user?.email,
      started_at: new Date().toISOString()
    });

    // Save Audit event immediately to Strapi
    await logAuditToStrapi("Switch to Production Mode", req.user?.email, req.user?.id);

    await stopDev();

    // 1. WIPE THE LOG FILE (The "Fresh Notebook")
    const outputFile = path.join(PROD_LOG_DIR, "strapi-output.log");
    if (fs.existsSync(outputFile)) {
      fs.writeFileSync(outputFile, ""); // This makes the file empty
    }

    // Since this endpoint is taking 30 minutes, we should respond IMMEDIATELY 
    // to the frontend, and run the intensive build in the background.

    res.json({ message: "Production build started in background" });

    // BACKGROUND PROCESS
    (async () => {
      try {
        await updateDbStatus({ progress_message: 'Building Project (This will take a while)...' });
        await buildProject();

        await updateDbStatus({ progress_message: 'Starting Production Service...' });
        await startProd();

        // Wait till Strapi is up, then update its settings to disable dev mode
        await updateStrapiSettingsWithRetry({
          data: {
            maintenanceMode: false,
            devModeActive: false
          }
        });

        await updateDbStatus({
          switch_status: 'idle',
          current_environment: 'production',
          target_environment: null,
          progress_message: 'System operating in Production mode',
          completed_at: new Date().toISOString()
        });

      } catch (e) {
        writeLog("Background PROD sequence failed: " + e.message);
        await updateDbStatus({
          switch_status: 'failed',
          progress_message: `Switch failed during build/start: ${e.message}`
        });
      }
    })();

  } catch (err) {
    await updateDbStatus({
      switch_status: 'failed',
      progress_message: `Switch failed: ${err.message}`
    });
    res.status(500).json({ error: err.message });
  }
});

app.get("/logs", (req, res) => {
  if (!fs.existsSync(LOG_FILE)) {
    return res.json({ logs: "" });
  }

  const logs = fs.readFileSync(LOG_FILE, "utf-8")
    .split("\n")
    .slice(-200)
    .join("\n");

  res.json({ logs });
});

/**
 * @swagger
 * /logs/stream/{mode}:
 *   get:
 *     summary: Stream Live Logs
 *     description: Streams live logs for dev or prod mode.
 *     parameters:
 *       - in: path
 *         name: mode
 *         required: true
 *         schema:
 *           type: string
 *           enum: [dev, prod]
 *         description: Mode to stream logs from
 *     responses:
 *       200:
 *         description: Streaming logs
 */
app.get("/logs/stream/:mode", (req, res) => {
  const mode = req.params.mode; // dev or prod

  let outputFile;
  let errorFile;

  if (mode === "dev") {
    outputFile = path.join(DEV_LOG_DIR, "strapi-output.log");
    errorFile = path.join(DEV_LOG_DIR, "strapi-error.log");
  } else if (mode === "prod") {
    outputFile = path.join(PROD_LOG_DIR, "strapi-output.log");
    errorFile = path.join(PROD_LOG_DIR, "strapi-error.log");
  } else if (mode === "control") {
    outputFile = LOG_FILE;
    errorFile = null;
  } else {
    return res.status(400).json({ error: "Invalid mode" });
  }

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");

  const sendLogs = () => {
    let logs = "";

    try {
      if (fs.existsSync(outputFile)) {
        logs += fs.readFileSync(outputFile, "utf8");
      }

      if (fs.existsSync(errorFile)) {
        logs += "\n\n----- ERRORS -----\n\n";
        logs += fs.readFileSync(errorFile, "utf8");
      }
      if (errorFile && fs.existsSync(errorFile)) {
        logs += "\n\n----- ERRORS -----\n\n";
        logs += fs.readFileSync(errorFile, "utf8");
      }

      if (!logs.trim()) {
        logs = "No logs yet...";
      }

      logs = logs.split("\n").slice(-200).join("\n");

      res.write(`data: ${JSON.stringify(logs)}\n\n`);

    } catch (err) {
      res.write(`data: ${JSON.stringify("Log read error: " + err.message)}\n\n`);
    }
  };

  sendLogs();

  const interval = setInterval(sendLogs, 2000);

  req.on("close", () => {
    clearInterval(interval);
  });
});

const options = {
  definition: {
    openapi: "3.0.0",
    info: {
      title: "Strapi Control API",
      version: "1.0.0",
      description: "API for switching between Dev and Production modes",
    },
    servers: [
      {
        url: "http://localhost:3000",
      },
    ],
  },
  apis: ["./index.js"],
};

const swaggerSpec = swaggerJsdoc(options);

app.use("/docs", swaggerUi.serve, swaggerUi.setup(swaggerSpec));

app.listen(CONFIG.PORT, () => {
  console.log(`Control Server running on port ${CONFIG.PORT}`);
});