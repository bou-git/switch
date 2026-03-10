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
const tokenCache = new NodeCache({ stdTTL: 300 }); // 5 minutes cache

const app = express();
app.set('trust proxy', 1); // Enable trusting X-Forwarded-For from IIS Proxy
app.use(helmet());
app.use(cors());
app.use(express.json());

const limiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 50, // limit each IP to 50 requests per windowMs
  message: { error: "Too many requests from this IP, please try again later." }
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
  STRAPI_PROJECT_PATH: "G:\\bank of uganda\\bou-backend\\backend\\backend", // change to your real path
  STRAPI_API_TOKEN: "55b564dc5c9ad792170318288473e17dc0bb17fb1a7423374ab023a54126cde0a1bc2139f8127207c58a3f2b0d4a31aeaa69d4f570400c176dfcd556ed250427afdbdea0e49369998db965550e426e03db0cb54f35a588d61b2523886a3905f93b89684b4d64a68bcd077635fa2b4195dcedcac02d4f80c78221ee4a0679df0d", // Strapi API Token
  DB_HOST: "127.0.0.1",
  DB_PORT: 5432,
  DB_NAME: "bou",
  DB_USER: "postgres",
  DB_PASS: "BankOfUgandaWebSite@2026"
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
  // Allow swagger docs without auth
  if (req.path.startsWith("/docs")) return next();

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

// Add an audit login endpoint
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

// Add a status endpoint
app.get("/status", verifyToken, async (req, res) => {
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
      writeLog(`Failed to update Strapi settings (${err.message}). Retrying in ${retryDelay/1000}s...`);
      await delay(retryDelay);
    }
  }
  writeLog("ERROR: Could not update Strapi settings after maximum retries.");
  return false;
}

function run(command) {
  return new Promise((resolve, reject) => {
    exec(command, (err, stdout, stderr) => {
      if (err) {
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
  return run(`"${CONFIG.NSSM_PATH}" start StrapiService`);
}

async function stopDev() {
  writeLog("Stopping Dev Service...");
  return run(`"${CONFIG.NSSM_PATH}" stop StrapiDevService`);
}

async function startDev() {
  writeLog("Starting Dev Service...");
  return run(`"${CONFIG.NSSM_PATH}" start StrapiDevService`);
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
      writeLog("BUILD ERROR: " + data);
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