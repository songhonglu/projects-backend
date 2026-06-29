/**
 * Projects Portal Backend - Node.js (Express)
 * 
 * 启动方式：node server.js
 * 默认端口：9877
 * 
 * 需要配置：
 * 环境变量: ADMIN_SECRET (随便设一个长随机字符串)
 * 数据存储: 本地 JSON 文件 (data/db.json)
 */

const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 9877;
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'local-dev-secret-change-me';
const SESSION_EXPIRY_DAYS = 30;

// 数据存储路径
const DATA_DIR = path.join(require('os').homedir(), 'projects-backend', 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');

// ═══════════════════════════════════════════════════════
// Password Hashing
// ═══════════════════════════════════════════════════════
function hashPassword(username, password) {
  const data = `${username}:${password}`;
  return crypto.createHash('sha256').update(data).digest('hex');
}

// ═══════════════════════════════════════════════════════
// JWT
// ═══════════════════════════════════════════════════════
function createJWT(payload, secret) {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const expiresAt = Date.now() + SESSION_EXPIRY_DAYS * 24 * 60 * 60 * 1000;
  const body = Buffer.from(JSON.stringify({ ...payload, exp: expiresAt })).toString('base64url');
  const signatureInput = `${header}.${body}`;
  const signature = crypto.createHmac('sha256', secret).update(signatureInput).digest('base64url');
  return `${header}.${body}.${signature}`;
}

function verifyJWT(token, secret) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return { payload: {}, valid: false };
    const [header, body, signature] = parts;
    const signatureInput = `${header}.${body}`;
    const expectedSig = crypto.createHmac('sha256', secret).update(signatureInput).digest('base64url');
    if (expectedSig !== signature) return { payload: {}, valid: false };
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (payload.exp && payload.exp < Date.now()) return { payload: {}, valid: false };
    return { payload, valid: true };
  } catch {
    return { payload: {}, valid: false };
  }
}

// ═══════════════════════════════════════════════════════
// DB (File-based)
// ═══════════════════════════════════════════════════════
const DEFAULT_DB = {
  users: [
    { id: 'user_admin', username: 'songhw', displayName: '宋老师', role: 'admin', projectPerms: null, avatar: '#2563eb', email: '', phone: '' },
    { id: 'user_chenpt', username: 'chenpt', displayName: '陈鹏涛', role: 'user', projectPerms: [], avatar: '#16a34a', email: '', phone: '' },
  ],
  authCtrl: { contractmap: true, 'huarongdao-game': false, amberk: true, 'number-huarongdao': false, 'daily-signin': false },
  theme: 'dark',
};

function loadDB() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
  if (!fs.existsSync(DB_FILE)) {
    const adminHash = hashPassword('songhw', 'Seeyon@135246');
    const chenptHash = hashPassword('chenpt', '123456');
    const db = {
      ...DEFAULT_DB,
      users: DEFAULT_DB.users.map((u, i) => ({ ...u, passwordHash: i === 0 ? adminHash : chenptHash })),
    };
    fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
    return db;
  }
  return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
}

function saveDB(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

function safeUser(u) {
  const { passwordHash, ...safe } = u;
  return safe;
}

// ═══════════════════════════════════════════════════════
// Auth middleware
// ═══════════════════════════════════════════════════════
function getAuth(req) {
  const authHeader = req.headers.authorization || '';
  if (!authHeader.startsWith('Bearer ')) return { payload: {}, valid: false };
  return verifyJWT(authHeader.slice(7), ADMIN_SECRET);
}

function requireAdmin(req, res, next) {
  const auth = getAuth(req);
  if (!auth.valid || auth.payload?.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  req.auth = auth;
  next();
}

// ═══════════════════════════════════════════════════════
// CORS
// ═══════════════════════════════════════════════════════
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(204).end();
  next();
});

// ═══════════════════════════════════════════════════════
// Routes
// ═══════════════════════════════════════════════════════
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Missing username or password' });
  
  const db = loadDB();
  const user = db.users.find(u => u.username === username);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  
  const expectedHash = hashPassword(username, password);
  if (user.passwordHash !== expectedHash) return res.status(401).json({ error: 'Invalid credentials' });
  
  const token = createJWT({ userId: user.id, username: user.username, role: user.role }, ADMIN_SECRET);
  res.json({ success: true, token, user: safeUser(user) });
});

app.post('/api/auth/change-pass', requireAdmin, (req, res) => {
  const { oldPassword, newPassword } = req.body || {};
  if (!oldPassword || !newPassword) return res.status(400).json({ error: 'Missing password fields' });
  if (newPassword.length < 6) return res.status(400).json({ error: 'Password too short (min 6 chars)' });
  
  const db = loadDB();
  const user = db.users.find(u => u.id === req.auth.payload.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  
  const oldHash = hashPassword(user.username, oldPassword);
  if (oldHash !== user.passwordHash) return res.status(401).json({ error: 'Old password incorrect' });
  
  user.passwordHash = hashPassword(user.username, newPassword);
  saveDB(db);
  res.json({ success: true, message: 'Password changed successfully' });
});

app.get('/api/users', requireAdmin, (req, res) => {
  const db = loadDB();
  res.json({ users: db.users.map(safeUser) });
});

app.put('/api/users/:id', requireAdmin, (req, res) => {
  const db = loadDB();
  const user = db.users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  
  const updates = req.body || {};
  if (updates.displayName) user.displayName = updates.displayName;
  if (updates.email) user.email = updates.email;
  if (updates.phone) user.phone = updates.phone;
  if (updates.projectPerms !== undefined) user.projectPerms = updates.projectPerms;
  if (updates.role && user.role !== 'admin') user.role = updates.role;
  
  saveDB(db);
  res.json({ success: true, user: safeUser(user) });
});

app.delete('/api/users/:id', requireAdmin, (req, res) => {
  const db = loadDB();
  const idx = db.users.findIndex(u => u.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'User not found' });
  db.users.splice(idx, 1);
  saveDB(db);
  res.json({ success: true, deleted: req.params.id });
});

app.post('/api/data/read', requireAdmin, (req, res) => {
  const { projectId } = req.body || {};
  if (!projectId) return res.status(400).json({ error: 'Missing projectId' });
  res.json({ success: true, projectId, data: null });
});

app.post('/api/data/write', requireAdmin, (req, res) => {
  const { projectId, data } = req.body || {};
  if (!projectId || !data) return res.status(400).json({ error: 'Missing projectId or data' });
  res.json({ success: true, projectId });
});

// ═══════════════════════════════════════════════════════
// Signin API
// ═══════════════════════════════════════════════════════
function getSigninKey(userId) {
  return 'signin_' + userId;
}

app.post('/api/signin/check', requireAdmin, (req, res) => {
  const db = loadDB();
  const userId = req.auth.payload.userId;
  const key = getSigninKey(userId);
  const today = new Date().toISOString().slice(0, 10);
  const record = db.signins && db.signins[key] && db.signins[key][today];
  res.json({ success: true, alreadySignedIn: !!record, today });
});

app.post('/api/signin/do', requireAdmin, (req, res) => {
  const db = loadDB();
  const userId = req.auth.payload.userId;
  const key = getSigninKey(userId);
  const today = new Date().toISOString().slice(0, 10);
  
  if (!db.signins) db.signins = {};
  if (!db.signins[key]) db.signins[key] = {};
  if (db.signins[key][today]) {
    return res.status(400).json({ error: 'Already signed in today' });
  }
  
  const now = new Date();
  db.signins[key][today] = {
    date: today,
    time: now.toTimeString().slice(0, 8),
    reward: 20,
    dayOfWeek: ['Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday'][now.getDay()],
  };
  saveDB(db);
  res.json({ success: true, record: db.signins[key][today] });
});

app.get('/api/signin/history', requireAdmin, (req, res) => {
  const db = loadDB();
  const userId = req.auth.payload.userId;
  const key = getSigninKey(userId);
  const records = db.signins && db.signins[key] ? Object.values(db.signins[key]) : [];
  records.sort((a, b) => b.date.localeCompare(a.date));
  res.json({ success: true, records });
});

// ═══════════════════════════════════════════════════════
// Start
// ═══════════════════════════════════════════════════════
app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n🚀 Projects Portal Backend running at http://localhost:${PORT}`);
  console.log(`   Admin Secret: ${ADMIN_SECRET.substring(0, 8)}...`);
  console.log(`   Health check: http://localhost:${PORT}/api/health\n`);
});
