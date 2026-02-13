const fs = require("fs");
const path = require("path");
const https = require("https");
const express = require("express");
const session = require("express-session");
const selfsigned = require("selfsigned");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");

const app = express();

// ===== CONFIG =====
const HTTPS_PORT = process.env.PORT ? Number(process.env.PORT) : 3443;
const HOST = process.env.HOST || "0.0.0.0";
const DATA_FILE = path.join(__dirname, "data.json");
const CERT_DIR = path.join(__dirname, "certs");
const KEY_PATH = path.join(CERT_DIR, "key.pem");
const CERT_PATH = path.join(CERT_DIR, "cert.pem");
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");
const DISABLE_HTTPS = process.env.DISABLE_HTTPS === '1' || process.env.FORCE_HTTP === '1';
const TRUST_PROXY = process.env.TRUST_PROXY === '1' || process.env.NODE_ENV === 'production';

// ===== CERTS =====
function ensureCerts() {
  if (!fs.existsSync(CERT_DIR)) fs.mkdirSync(CERT_DIR, { recursive: true });
  const missing = !fs.existsSync(KEY_PATH) || !fs.existsSync(CERT_PATH);
  if (missing) {
    console.log("[certs] Gerando certificado autoassinado...");
    const attrs = [{ name: "commonName", value: "inventario-local" }];
    const pems = selfsigned.generate(attrs, { days: 365, keySize: 2048 });
    fs.writeFileSync(KEY_PATH, pems.private, "utf8");
    fs.writeFileSync(CERT_PATH, pems.cert, "utf8");
  }
}

// ===== DATA =====
function loadData() {
  try {
    const data = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
    if (!data.users) data.users = [];
    if (!data.logs) data.logs = [];
    return data;
  } catch {
    return { inventory: [], baseProducts: [], materialTypes: [], dailyTotals: {}, meta: { version: 2 }, users: [], logs: [] };
  }
}
function saveData(data) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2), "utf8");
}
function ensureDefaultAdmin() {
  const data = loadData();
  const user = data.users.find(u => u.username === "admin@3f.local");
  if (!user) {
    const hash = bcrypt.hashSync("senha123", 10);
    data.users.push({ username: "admin@3f.local", role: "admin", passwordHash: hash });
    saveData(data);
    console.log("👤 Usuário padrão criado: admin@3f.local / senha123");
  } else if (!user.passwordHash) {
    user.passwordHash = bcrypt.hashSync("senha123", 10);
    saveData(data);
    console.log("🔑 Hash do admin estava vazio — senha padrão definida: senha123");
  }
}

// ===== MIDDLEWARE =====
app.use(express.json({ limit: "5mb" }));
app.set('trust proxy', TRUST_PROXY ? 1 : 0);
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "lax", secure: !DISABLE_HTTPS }
}));

function requireAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  return res.status(401).json({ error: "unauthorized" });
}
function requireAdmin(req, res, next) {
  if (req.session?.user?.role === "admin") return next();
  return res.status(403).json({ error: "forbidden" });
}

// ===== AUTH =====
app.post("/api/login", (req, res) => {
  const { username, password } = req.body || {};
  const data = loadData();
  const user = data.users.find(u => u.username.toLowerCase() === String(username).toLowerCase());
  if (!user) return res.status(401).json({ error: "invalid" });
  if (!bcrypt.compareSync(password, user.passwordHash || "")) return res.status(401).json({ error: "invalid" });
  req.session.user = { username: user.username, role: user.role || "user" };
  res.json({ ok: true, user: req.session.user });
});
app.post("/api/logout", (req, res) => req.session.destroy(() => res.json({ ok: true })));
app.get("/api/me", (req, res) => req.session?.user ? res.json(req.session.user) : res.status(401).json({ error: "unauthorized" }));

// ===== DATA API =====
app.get("/api/data", requireAuth, (_req, res) => {
  const { users, logs, ...publicData } = loadData();
  res.json(publicData);
});
app.post("/api/data", requireAuth, (req, res) => {
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
app.post("/api/log", requireAuth, (req, res) => {
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
// Lista usuários (sem hash)
app.get("/api/users", requireAuth, requireAdmin, (_req, res) => {
  const data = loadData();
  const users = data.users.map(u => ({ username: u.username, role: u.role || "user" }));
  res.json(users);
});
// Cria usuário
app.post("/api/users", requireAuth, requireAdmin, (req, res) => {
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
// Troca senha
app.post("/api/users/change-password", requireAuth, requireAdmin, (req, res) => {
  const { username, newPassword } = req.body || {};
  if (!username || !newPassword) return res.status(400).json({ error: "missing" });
  const data = loadData();
  const user = data.users.find(u => u.username.toLowerCase() === String(username).toLowerCase());
  if (!user) return res.status(404).json({ error: "not_found" });
  user.passwordHash = bcrypt.hashSync(String(newPassword), 10);
  saveData(data);
  res.json({ ok: true });
});
// Remove usuário (protege admin padrão)
app.delete("/api/users/:username", requireAuth, requireAdmin, (req, res) => {
  const uname = String(req.params.username || "");
  if (uname.toLowerCase() === "admin@3f.local") return res.status(400).json({ error: "cannot_delete_default_admin" });
  const data = loadData();
  const before = data.users.length;
  data.users = data.users.filter(u => u.username.toLowerCase() !== uname.toLowerCase());
  if (data.users.length === before) return res.status(404).json({ error: "not_found" });
  saveData(data);
  res.json({ ok: true });
});

// ===== STATIC FRONTEND =====
app.use(express.static(path.join(__dirname, "public"), { extensions: ["html"] }));
app.get("*", (_req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

// ===== START =====
ensureDefaultAdmin();

if (DISABLE_HTTPS) {
  // Start plain HTTP (useful for many free hosts that provide TLS/termination)
  const PORT = process.env.PORT ? Number(process.env.PORT) : 3000;
  app.listen(PORT, HOST, () => {
    console.log(`✅ HTTP em http://${HOST}:${PORT}`);
    console.log("👤 Login padrão: admin@3f.local / senha123");
  });
} else {
  // Local HTTPS with selfsigned certs
  ensureCerts();
  const options = { key: fs.readFileSync(KEY_PATH), cert: fs.readFileSync(CERT_PATH) };
  https.createServer(options, app).listen(HTTPS_PORT, HOST, () => {
    console.log(`✅ HTTPS em https://localhost:${HTTPS_PORT}`);
    console.log("👤 Login padrão: admin@3f.local / senha123");
  });
}
