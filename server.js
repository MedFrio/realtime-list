
require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const http = require('http');
const { WebSocketServer } = require('ws');
const { db, init } = require('./db');

init();

const app = express();
app.use(express.json({ limit: '256kb' }));
app.use(express.urlencoded({ extended: false }));
app.use(express.static('public'));

const PORT = process.env.PORT || 3000;
const WS_PING_INTERVAL_MS = 10000;
const SESSION_TTL_MS = 1000 * 60 * 60 * 8; // 8h
const SECRET = process.env.APP_SECRET || 'dev-secret-only-local';

// Préparations SQL
const stmtUserByName = db.prepare('SELECT * FROM users WHERE username = ?');
const stmtInsertUser = db.prepare('INSERT INTO users (username, pass_hash, pass_salt, created_at) VALUES (?, ?, ?, ?)');
const stmtInsertSession = db.prepare('INSERT INTO sessions (user_id, token, issued_at, expires_at) VALUES (?, ?, ?, ?)');
const stmtGetSession = db.prepare(`SELECT sessions.*, users.username FROM sessions JOIN users ON users.id = sessions.user_id WHERE token = ?`);
const stmtDeleteExpiredSessions = db.prepare('DELETE FROM sessions WHERE expires_at < ?');
const stmtDeleteSessionByToken = db.prepare('DELETE FROM sessions WHERE token = ?');

const stmtInsertItem = db.prepare('INSERT INTO items (content, owner_id, created_at, updated_at, deleted) VALUES (?, ?, ?, ?, 0)');
const stmtUpdateItem = db.prepare('UPDATE items SET content = ?, updated_at = ? WHERE id = ? AND owner_id = ? AND deleted = 0');
const stmtSoftDelete = db.prepare('UPDATE items SET deleted = 1, updated_at = ? WHERE id = ? AND owner_id = ? AND deleted = 0');
const stmtAllItems = db.prepare('SELECT id, content, owner_id, created_at, updated_at, deleted FROM items WHERE deleted = 0 ORDER BY id ASC');

function now() { return Date.now(); }

// Hachage mot de passe (scrypt)
function hashPassword(password, salt = crypto.randomBytes(16)) {
  const hash = crypto.scryptSync(password, salt, 64, { N: 16384, r: 8, p: 1 });
  return { salt, hash };
}

// Token de session signé HMAC
function signToken(payloadObj) {
  const payload = Buffer.from(JSON.stringify(payloadObj)).toString('base64url');
  const sig = crypto.createHmac('sha256', SECRET).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}
function verifyToken(token) {
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [payload, sig] = parts;
  const expected = crypto.createHmac('sha256', SECRET).update(payload).digest('base64url');
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  try { return JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')); }
  catch { return null; }
}

// Anti-spam simple par connexion: 6 actions/3s
function makeRateLimiter(max = 6, windowMs = 3000) {
  let count = 0;
  let windowStart = now();
  return () => {
    const t = now();
    if (t - windowStart > windowMs) { windowStart = t; count = 0; }
    count++;
    return count <= max;
  };
}

// Sanitisation basique du contenu
function sanitizeContent(s) {
  if (typeof s !== 'string') return '';
  s = s.replace(/<[^>]*>/g, '');
  s = s.replace(/\s+/g, ' ').trim();
  if (s.length > 280) s = s.slice(0, 280);
  return s;
}

// API d'auth
app.post('/api/register', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username et password requis' });
  if (!/^[a-zA-Z0-9_\-]{3,20}$/.test(username)) return res.status(400).json({ error: 'username invalide' });
  if (password.length < 4) return res.status(400).json({ error: 'mot de passe trop court' });

  if (stmtUserByName.get(username)) return res.status(409).json({ error: 'username déjà pris' });
  const { salt, hash } = hashPassword(password);
  const created = now();
  stmtInsertUser.run(username, hash, salt, created);

  const user = stmtUserByName.get(username);
  const issued = now();
  const expires = issued + SESSION_TTL_MS;
  const tokenPayload = { uid: user.id, iat: issued, exp: expires };
  const token = signToken(tokenPayload);
  stmtInsertSession.run(user.id, token, issued, expires);

  res.json({ token, username });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username et password requis' });
  const user = stmtUserByName.get(username);
  if (!user) return res.status(401).json({ error: 'identifiants invalides' });
  const derived = crypto.scryptSync(password, user.pass_salt, 64, { N: 16384, r: 8, p: 1 });
  if (!crypto.timingSafeEqual(derived, user.pass_hash)) return res.status(401).json({ error: 'identifiants invalides' });

  const issued = now();
  const expires = issued + SESSION_TTL_MS;
  const tokenPayload = { uid: user.id, iat: issued, exp: expires };
  const token = signToken(tokenPayload);
  stmtInsertSession.run(user.id, token, issued, expires);
  res.json({ token, username });
});

// Déconnexion: invalide la session liée au token
app.post('/api/logout', (req, res) => {
  const { token } = req.body || {};
  if (!token) return res.status(400).json({ error: 'token requis' });

  // on regarde si le token existe bien
  const s = stmtGetSession.get(token);
  if (!s) return res.status(200).json({ ok: true, removed: 0 }); // idempotent

  const ch = stmtDeleteSessionByToken.run(token).changes;
  return res.json({ ok: true, removed: ch || 0 });
});

// Nettoyage périodique sessions expirées
app.post('/api/housekeeping', (_req, res) => {
  const n = stmtDeleteExpiredSessions.run(now()).changes;
  res.json({ removed: n });
});

// HTTP server + WS
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

let activeConnections = 0;

// Liste des clients par user_id pour présence
const presence = new Map(); // userId -> Set(ws)

function broadcast(obj, exceptWs = null) {
  const data = JSON.stringify(obj);
  wss.clients.forEach(c => {
    if (c.readyState === 1 && c !== exceptWs) c.send(data);
  });
}

function send(ws, obj) {
  ws.send(JSON.stringify(obj));
}

function authFromToken(token) {
  if (!token) return null;
  const payload = verifyToken(token);
  if (!payload) return null;
  if (payload.exp < now()) return null;
  const row = stmtGetSession.get(token);
  if (!row) return null;
  return { userId: row.user_id, username: row.username };
}

wss.on('connection', (ws) => {
  activeConnections++;
  ws.isAlive = true;
  ws.rateOK = makeRateLimiter();
  ws.user = null;

  ws.on('pong', () => { ws.isAlive = true; });

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }

    // Auth handshake
    if (msg.type === 'auth') {
      const auth = authFromToken(msg.token);
      if (!auth) return send(ws, { type: 'error', error: 'auth_failed' });
      ws.user = auth;
      // présence
      if (!presence.has(auth.userId)) presence.set(auth.userId, new Set());
      presence.get(auth.userId).add(ws);

      // snapshot initial + présence actuelle
      const rows = stmtAllItems.all();
      send(ws, { type: 'snapshot', items: rows });
      send(ws, { type: 'hello', username: auth.username, userId: auth.userId, activeConnections });
      // broadcast présence
      broadcast({ type: 'presence', users: Array.from(presence.keys()) });

      return;
    }

    // Refuse actions sans auth
    if (!ws.user) return send(ws, { type: 'error', error: 'not_authenticated' });

    // Anti-spam
    if (!ws.rateOK()) {
      return send(ws, { type: 'error', error: 'rate_limited' });
    }

    // Routing actions
    if (msg.type === 'add') {
      const content = sanitizeContent(msg.content);
      if (!content) return send(ws, { type: 'error', error: 'content_invalid' });
      const ts = now();
      const info = stmtInsertItem.run(content, ws.user.userId, ts, ts);
      const item = { id: info.lastInsertRowid, content, owner_id: ws.user.userId, created_at: ts, updated_at: ts, deleted: 0 };
      broadcast({ type: 'added', item });
    }
    else if (msg.type === 'edit') {
      const id = Number(msg.id);
      if (!Number.isInteger(id)) return send(ws, { type: 'error', error: 'id_invalid' });
      const content = sanitizeContent(msg.content);
      if (!content) return send(ws, { type: 'error', error: 'content_invalid' });
      const ts = now();
      const ch = stmtUpdateItem.run(content, ts, id, ws.user.userId).changes;
      if (!ch) return send(ws, { type: 'error', error: 'not_found_or_forbidden' });
      broadcast({ type: 'edited', id, content, updated_at: ts, owner_id: ws.user.userId });
    }
    else if (msg.type === 'delete') {
      const id = Number(msg.id);
      if (!Number.isInteger(id)) return send(ws, { type: 'error', error: 'id_invalid' });
      const ts = now();
      const ch = stmtSoftDelete.run(ts, id, ws.user.userId).changes;
      if (!ch) return send(ws, { type: 'error', error: 'not_found_or_forbidden' });
      broadcast({ type: 'deleted', id, updated_at: ts, owner_id: ws.user.userId });
    }
    else if (msg.type === 'ping') {
      send(ws, { type: 'pong', t: msg.t || now() });
    }
  });

  ws.on('close', () => {
    activeConnections--;
    if (ws.user && presence.has(ws.user.userId)) {
      presence.get(ws.user.userId).delete(ws);
      if (presence.get(ws.user.userId).size === 0) presence.delete(ws.user.userId);
      broadcast({ type: 'presence', users: Array.from(presence.keys()) });
    }
  });
}); 
// Keepalive et nettoyage WS global
setInterval(() => {
  wss.clients.forEach((ws) => {
    if (ws.isAlive === false) return ws.terminate();
    ws.isAlive = false;
    try { ws.ping(); } catch {}
  });
}, WS_PING_INTERVAL_MS);

// Démarrage du serveur
server.listen(PORT, () => {
  console.log(`HTTP+WS sur http://localhost:${PORT}`);
});