const express = require('express');
const session = require('express-session');
const bcrypt  = require('bcryptjs');
const cors    = require('cors');
const path    = require('path');
const db      = require('./db');

const app  = express();
const PORT = process.env.PORT || 3000;

// Init DB
db.initDB().catch(err => { console.error('DB init error:', err); process.exit(1); });

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
    secret: process.env.SESSION_SECRET || 'auct-secret-key-2024',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 }
}));

// ─── Middleware Admin Auth ───
function requireAdmin(req, res, next) {
    if (req.session && req.session.isAdmin) return next();
    return res.status(401).json({ success: false, message: 'Tidak terautentikasi.' });
}

// ─── PUBLIC ROUTES ───

app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) return res.status(400).json({ success: false, message: 'Username dan password wajib diisi.' });
        const user = await db.findUserByUsername(username);
        if (!user) return res.status(401).json({ success: false, message: 'Username atau password salah.' });
        const valid = await bcrypt.compare(password, user.password_hash);
        if (!valid) return res.status(401).json({ success: false, message: 'Username atau password salah.' });
        req.session.isAdmin = true;
        req.session.adminUser = user.username;
        res.json({ success: true, message: 'Login berhasil.' });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

app.get('/api/session', (req, res) => {
    res.json({ isAdmin: !!(req.session && req.session.isAdmin), user: req.session.adminUser || null });
});

app.post('/api/verify', async (req, res) => {
    try {
        const { key, hwid } = req.body;
        if (!key) return res.status(400).json({ valid: false, message: 'Serial Key Lisensi wajib diisi!' });
        const result = await db.verifyKeyStatus(key, hwid || null);
        res.json(result);
    } catch (e) { res.status(500).json({ valid: false, message: e.message }); }
});

app.post('/api/redeem', async (req, res) => {
    try {
        const { key, identifier, hwid } = req.body;
        if (!key) return res.status(400).json({ success: false, message: 'Serial Key Lisensi wajib diisi!' });
        const clientInfo = { identifier: identifier || 'User', ip: req.ip || req.connection.remoteAddress, hwid: hwid || null };
        const result = await db.redeemKey(key, clientInfo);
        if (!result.success) return res.status(400).json(result);
        res.json(result);
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// ─── ADMIN ROUTES ───

app.get('/api/admin/stats', requireAdmin, async (req, res) => {
    try { res.json(await db.getStats()); }
    catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.get('/api/admin/keys', requireAdmin, async (req, res) => {
    try { res.json({ success: true, keys: await db.getAllKeys() }); }
    catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/admin/keys/generate', requireAdmin, async (req, res) => {
    try {
        const { durationType, durationDays, count, note, prefix } = req.body;
        const result = await db.generateKeys({ durationType, durationDays: parseInt(durationDays) || 0, count: parseInt(count) || 1, note: note || '', prefix: prefix || 'KEY' });
        res.json(result);
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.delete('/api/admin/keys/:id', requireAdmin, async (req, res) => {
    try { res.json(await db.deleteKey(req.params.id)); }
    catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/admin/keys/ban', requireAdmin, async (req, res) => {
    try { res.json(await db.banKey(req.body.id, req.body.reason || '')); }
    catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/admin/keys/unban', requireAdmin, async (req, res) => {
    try { res.json(await db.unbanKey(req.body.id)); }
    catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/admin/keys/pause', requireAdmin, async (req, res) => {
    try { res.json(await db.pauseKey(req.body.id, req.body.reason || '')); }
    catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/admin/keys/resume', requireAdmin, async (req, res) => {
    try { res.json(await db.resumeKey(req.body.id)); }
    catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/admin/keys/add-time', requireAdmin, async (req, res) => {
    try {
        const { id, amount, unit } = req.body;
        res.json(await db.addTimeKey(id, parseInt(amount) || 1, unit || 'days'));
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/admin/keys/add-time-all', requireAdmin, async (req, res) => {
    try {
        const { amount, unit, target } = req.body;
        res.json(await db.addTimeToAllKeys(parseInt(amount) || 1, unit || 'days', target || 'active'));
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/admin/keys/reset-device', requireAdmin, async (req, res) => {
    try { res.json(await db.resetKeyDevice(req.body.id)); }
    catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/admin/global-pause', requireAdmin, async (req, res) => {
    try {
        const { enabled, reason } = req.body;
        res.json(await db.setGlobalPause(!!enabled, reason || ''));
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.get('/api/admin/logs', requireAdmin, async (req, res) => {
    try { res.json({ success: true, logs: await db.getLogs() }); }
    catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// ─── PAGE ROUTES ───
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, () => {
    console.log('');
    console.log('================================================');
    console.log(`  Key Auth System berjalan pada port ${PORT}`);
    console.log(`  URL: http://localhost:${PORT}`);
    console.log('  DB : PostgreSQL (Railway)');
    console.log('================================================');
    console.log('');
});