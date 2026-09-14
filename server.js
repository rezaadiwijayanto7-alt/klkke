const express = require('express');
const session = require('express-session');
const bcrypt  = require('bcryptjs');
const cors    = require('cors');
const path    = require('path');
const db      = require('./db');

const app  = express();
const PORT = process.env.PORT || 3000;

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

function requireAdmin(req, res, next) {
    if (req.session && req.session.isAdmin) return next();
    return res.status(401).json({ success: false, message: 'Tidak terautentikasi.' });
}

app.post('/api/login', async function(req, res) {
    try {
        var username = req.body.username;
        var password = req.body.password;
        if (!username || !password) return res.status(400).json({ success: false, message: 'Username dan password wajib diisi.' });
        var user = await db.findUserByUsername(username);
        if (!user) return res.status(401).json({ success: false, message: 'Username atau password salah.' });
        var valid = await bcrypt.compare(password, user.password_hash);
        if (!valid) return res.status(401).json({ success: false, message: 'Username atau password salah.' });
        req.session.isAdmin = true;
        req.session.adminUser = user.username;
        res.json({ success: true, message: 'Login berhasil! Selamat datang kembali.' });
    } catch (e) { console.error(e); res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/logout', function(req, res) {
    req.session.destroy();
    res.json({ success: true });
});

app.get('/api/session', function(req, res) {
    res.json({ isAdmin: !!(req.session && req.session.isAdmin), user: req.session ? req.session.adminUser : null });
});

app.post('/api/verify', async function(req, res) {
    try {
        var key = req.body.key;
        var hwid = req.body.hwid;
        if (!key) return res.status(400).json({ valid: false, message: 'Serial Key Lisensi wajib diisi!' });
        var result = await db.verifyKeyStatus(key, hwid || null);
        res.json(result);
    } catch (e) { console.error(e); res.status(500).json({ valid: false, message: e.message }); }
});

app.post('/api/redeem', async function(req, res) {
    try {
        var key = req.body.key;
        var identifier = req.body.identifier;
        var hwid = req.body.hwid;
        if (!key) return res.status(400).json({ success: false, message: 'Serial Key Lisensi wajib diisi!' });
        var clientInfo = { identifier: identifier || 'User', ip: req.ip || req.connection.remoteAddress, hwid: hwid || null };
        var result = await db.redeemKey(key, clientInfo);
        if (!result.success) return res.status(400).json(result);
        res.json(result);
    } catch (e) { console.error(e); res.status(500).json({ success: false, message: e.message }); }
});

app.get('/api/admin/stats', requireAdmin, async function(req, res) {
    try { res.json(await db.getStats()); }
    catch (e) { console.error(e); res.status(500).json({ success: false, message: e.message }); }
});

app.get('/api/admin/keys', requireAdmin, async function(req, res) {
    try { res.json({ success: true, keys: await db.getAllKeys() }); }
    catch (e) { console.error(e); res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/admin/keys/generate', requireAdmin, async function(req, res) {
    try {
        var result = await db.generateKeys({
            durationType: req.body.durationType,
            durationDays: parseInt(req.body.durationDays) || 0,
            count: parseInt(req.body.count) || 1,
            note: req.body.note || '',
            prefix: req.body.prefix || 'KEY'
        });
        res.json(result);
    } catch (e) { console.error(e); res.status(500).json({ success: false, message: e.message }); }
});

app.delete('/api/admin/keys/:id', requireAdmin, async function(req, res) {
    try { res.json(await db.deleteKey(req.params.id)); }
    catch (e) { console.error(e); res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/admin/keys/ban', requireAdmin, async function(req, res) {
    try { res.json(await db.banKey(req.body.id, req.body.reason || '')); }
    catch (e) { console.error(e); res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/admin/keys/unban', requireAdmin, async function(req, res) {
    try { res.json(await db.unbanKey(req.body.id)); }
    catch (e) { console.error(e); res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/admin/keys/pause', requireAdmin, async function(req, res) {
    try { res.json(await db.pauseKey(req.body.id, req.body.reason || '')); }
    catch (e) { console.error(e); res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/admin/keys/resume', requireAdmin, async function(req, res) {
    try { res.json(await db.resumeKey(req.body.id)); }
    catch (e) { console.error(e); res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/admin/keys/add-time', requireAdmin, async function(req, res) {
    try {
        res.json(await db.addTimeKey(req.body.id, parseInt(req.body.amount) || 1, req.body.unit || 'days'));
    } catch (e) { console.error(e); res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/admin/keys/add-time-all', requireAdmin, async function(req, res) {
    try {
        res.json(await db.addTimeToAllKeys(parseInt(req.body.amount) || 1, req.body.unit || 'days', req.body.target || 'active'));
    } catch (e) { console.error(e); res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/admin/keys/reset-device', requireAdmin, async function(req, res) {
    try { res.json(await db.resetKeyDevice(req.body.id)); }
    catch (e) { console.error(e); res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/admin/global-pause', requireAdmin, async function(req, res) {
    try {
        res.json(await db.setGlobalPause(!!req.body.enabled, req.body.reason || ''));
    } catch (e) { console.error(e); res.status(500).json({ success: false, message: e.message }); }
});

app.get('/api/admin/logs', requireAdmin, async function(req, res) {
    try { res.json({ success: true, logs: await db.getLogs() }); }
    catch (e) { console.error(e); res.status(500).json({ success: false, message: e.message }); }
});

app.get('/', function(req, res) { res.redirect('/login'); });
app.get('/login', function(req, res) { res.sendFile(path.join(__dirname, 'public', 'login.html')); });
app.get('/dashboard', function(req, res) { res.sendFile(path.join(__dirname, 'public', 'dashboard.html')); });
app.get('*', function(req, res) { res.redirect('/login'); });

// Start server, then init DB
app.listen(PORT, function() {
    console.log('Server berjalan pada port ' + PORT);
    db.initDB().then(function() {
        console.log('Database siap!');
    }).catch(function(err) {
        console.error('DB init error:', err.message);
    });
});