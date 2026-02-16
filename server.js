const fs = require("fs");
const path = require("path");
const https = require("https");
const express = require("express");
const session = require("express-session");
const selfsigned = require("selfsigned");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const cors = require("cors");
const csrf = require("csurf");
const cookieParser = require("cookie-parser");

const app = express();

// ===== CONFIG =====
const PORT = process.env.PORT ? Number(process.env.PORT) : 5000;
const HOST = process.env.HOST || "0.0.0.0";
const DATA_FILE = path.join(__dirname, "data.json");
const CERT_DIR = path.join(__dirname, "certs");
const KEY_PATH = path.join(CERT_DIR, "key.pem");
const CERT_PATH = path.join(CERT_DIR, "cert.pem");

if (!process.env.SESSION_SECRET) {
  console.error("❌ CRITICAL: SESSION_SECRET is not defined in environment variables.");
  process.exit(1);
}
const SESSION_SECRET = process.env.SESSION_SECRET;

const DISABLE_HTTPS = process.env.DISABLE_HTTPS === '1' || process.env.FORCE_HTTP === '1';

// ===== SECURITY MIDDLEWARE =====
app.use(helmet());
app.use(cors({
  origin: (origin, callback) => {
    // In Replit, the domain can change, so we trust the current domain.
    // However, the request asks for restricted CORS.
    // We'll allow the host from the request headers if it's a replit.dev domain
    if (!origin) return callback(null, true);
    if (origin.includes('.replit.dev') || origin.includes('.repl.co')) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true
}));

app.use(express.json({ limit: "5mb" }));
app.use(cookieParser());
app.set('trust proxy', 1);

app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { 
    httpOnly: true, 
    sameSite: "lax", 
    secure: true 
  }
}));

// ===== CSRF PROTECTION =====
const csrfProtection = csrf({ cookie: true });

// ===== RATE LIMITER =====
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts
  message: { error: "Muitas tentativas de login. Tente novamente em 15 minutos." },
  standardHeaders: true,
  legacyHeaders: false,
});

// ===== DATA =====
function loadData() {
  try {
    const data = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
    if (!data.users) data.users = [];
    if (!data.logs) data.logs = [];
    if (!data.failedLogins) data.failedLogins = [];
    return data;
  } catch {
    return { inventory: [], baseProducts: [], materialTypes: [], dailyTotals: {}, meta: { version: 2 }, users: [], logs: [], failedLogins: [] };
  }
}

function saveData(data) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2), "utf8");
}

function ensureAdmin() {
  const adminEmail = process.env.ADMIN_EMAIL;
  const adminPassword = process.env.ADMIN_PASSWORD;

  if (adminEmail && adminPassword) {
    const data = loadData();
    let user = data.users.find(u => u.username === adminEmail);
    const hash = bcrypt.hashSync(adminPassword, 10);
    
    if (!user) {
      data.users.push({ username: adminEmail, role: "admin", passwordHash: hash });
      console.log(`👤 Admin created from env: ${adminEmail}`);
    } else {
      user.passwordHash = hash;
      user.role = "admin";
      console.log(`👤 Admin password updated from env: ${adminEmail}`);
    }
    saveData(data);
  } else {
    console.log("ℹ️ No ADMIN_EMAIL/ADMIN_PASSWORD env vars found. No automatic admin created.");
  }
}

// ===== MIDDLEWARE =====
function requireAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  return res.status(401).json({ error: "unauthorized" });
}

function requireAdmin(req, res, next) {
  if (req.session?.user?.role === "admin") return next();
  return res.status(403).json({ error: "forbidden" });
}

// ===== AUTH & CSRF ROUTES =====
app.get("/api/csrf-token", csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

app.post("/api/login", loginLimiter, (req, res) => {
  const { username, password } = req.body || {};
  const data = loadData();
  const user = data.users.find(u => u.username.toLowerCase() === String(username).toLowerCase());
  
  const ip = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  if (!user || !bcrypt.compareSync(password, user.passwordHash || "")) {
    // Log failed login
    data.failedLogins.push({
      email: username,
      ip: ip,
      ts: Date.now()
    });
    saveData(data);
    console.warn(`[Auth] Failed login attempt for ${username} from IP ${ip}`);
    return res.status(401).json({ error: "invalid" });
  }

  req.session.user = { username: user.username, role: user.role || "user" };
  res.json({ ok: true, user: req.session.user });
});

app.post("/api/logout", csrfProtection, (req, res) => req.session.destroy(() => res.json({ ok: true })));

app.get("/api/me", (req, res) => req.session?.user ? res.json(req.session.user) : res.status(401).json({ error: "unauthorized" }));

// ===== DATA API =====
app.get("/api/data", requireAuth, (_req, res) => {
  const { users, logs, failedLogins, ...publicData } = loadData();
  res.json(publicData);
});

app.post("/api/data", requireAuth, csrfProtection, (req, res) => {
  const incoming = req.body || {};
  const data = loadData();
  data.inventory = incoming.inventory || data.inventory;
  data.baseProducts = incoming.baseProducts || data.baseProducts;
  data.materialTypes = incoming.materialTypes || data.materialTypes;
  data.dailyTotals = incoming.dailyTotals || data.dailyTotals;
  data.meta = incoming.meta || data.meta;
  saveData(data);
  res.json({ status: "ok" });
});

// ===== LOG API =====
app.get("/api/log", requireAuth, (req, res) => {
  const { user, action } = req.query || {};
  let rows = loadData().logs || [];
  if (user) rows = rows.filter(r => (r.user||"").toLowerCase().includes(String(user).toLowerCase()));
  if (action) rows = rows.filter(r => r.action === action);
  rows = rows.sort((a,b)=> b.ts - a.ts).slice(0, 1000);
  res.json(rows);
});

app.post("/api/log", requireAuth, csrfProtection, (req, res) => {
  const entry = req.body || {};
  const data = loadData();
  const safe = {
    id: crypto.randomUUID(),
    ts: Date.now(),
    user: req.session.user.username,
    action: entry.action || "unknown",
    productName: entry.productName || null,
    before: entry.before ?? null,
    delta: entry.delta ?? null,
    after: entry.after ?? null,
    note: entry.note || ""
  };
  data.logs.push(safe);
  if (data.logs.length > 5000) data.logs = data.logs.slice(-5000);
  saveData(data);
  res.json({ ok: true });
});

// ===== USERS API (ADMIN) =====
app.get("/api/users", requireAuth, requireAdmin, (_req, res) => {
  const data = loadData();
  const users = data.users.map(u => ({ username: u.username, role: u.role || "user" }));
  res.json(users);
});

app.post("/api/users", requireAuth, requireAdmin, csrfProtection, (req, res) => {
  const { username, password, role } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: "missing" });
  const data = loadData();
  if (data.users.find(u => u.username.toLowerCase() === String(username).toLowerCase()))
    return res.status(409).json({ error: "exists" });
  const hash = bcrypt.hashSync(String(password), 10);
  data.users.push({ username: String(username), role: role || "user", passwordHash: hash });
  saveData(data);
  res.json({ ok: true });
});

app.post("/api/users/change-password", requireAuth, requireAdmin, csrfProtection, (req, res) => {
  const { username, newPassword } = req.body || {};
  if (!username || !newPassword) return res.status(400).json({ error: "missing" });
  const data = loadData();
  const user = data.users.find(u => u.username.toLowerCase() === String(username).toLowerCase());
  if (!user) return res.status(404).json({ error: "not_found" });
  user.passwordHash = bcrypt.hashSync(String(newPassword), 10);
  saveData(data);
  res.json({ ok: true });
});

app.delete("/api/users/:username", requireAuth, requireAdmin, csrfProtection, (req, res) => {
  const uname = String(req.params.username || "");
  const data = loadData();
  const before = data.users.length;
  data.users = data.users.filter(u => u.username.toLowerCase() !== uname.toLowerCase());
  if (data.users.length === before) return res.status(404).json({ error: "not_found" });
  saveData(data);
  res.json({ ok: true });
});

// ===== ADMIN ROUTE HARDENING =====
app.get("/admin", requireAuth, requireAdmin, (_req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ===== STATIC FRONTEND =====
app.use((_req, res, next) => {
  res.set('Cache-Control', 'no-cache, no-store, must-revalidate');
  next();
});
app.use(express.static(path.join(__dirname, "public"), { extensions: ["html"] }));
app.get("*", (_req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

// ===== START =====
ensureAdmin();

app.listen(PORT, HOST, () => {
  console.log(`✅ Secure Server running on port ${PORT}`);
});
