const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const path = require('path');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;

// Inisialisasi DB
db.initDB();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: 'secret-key-auct-super-secure-12345-human-ui',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 24 * 60 * 60 * 1000 } // 24 jam
}));

// Middleware Auth untuk Admin
function requireAdmin(req, res, next) {
    if (req.session && req.session.user && req.session.user.role === 'admin') {
        return next();
    }
    return res.status(401).json({ success: false, message: 'Akses ditolak. Silakan login terlebih dahulu.' });
}

// Serve Static Files dari folder public
app.use(express.static(path.join(__dirname, 'public')));

// ----------------------------------------------------
// AUTH ROUTES
// ----------------------------------------------------
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ success: false, message: 'Username dan Password wajib diisi.' });
    }

    const user = db.findUserByUsername(username);
    if (!user) {
        return res.status(401).json({ success: false, message: 'Username atau Password salah!' });
    }

    const isMatch = bcrypt.compareSync(password, user.passwordHash);
    if (!isMatch) {
        return res.status(401).json({ success: false, message: 'Username atau Password salah!' });
    }

    // Set Session
    req.session.user = {
        id: user.id,
        username: user.username,
        role: user.role
    };

    res.json({
        success: true,
        message: 'Login berhasil! Selamat datang kembali.',
        user: req.session.user
    });
});

app.post('/api/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) return res.status(500).json({ success: false, message: 'Gagal logout.' });
        res.clearCookie('connect.sid');
        res.json({ success: true, message: 'Logout berhasil.' });
    });
});

app.get('/api/me', (req, res) => {
    if (req.session && req.session.user) {
        return res.json({ authenticated: true, user: req.session.user });
    }
    res.json({ authenticated: false });
});

// ----------------------------------------------------
// PUBLIC API: VERIFY & REDEEM LISENSI
// ----------------------------------------------------

// Cek status key tanpa klaim
app.post('/api/verify', (req, res) => {
    const { key, hwid } = req.body;
    if (!key) {
        return res.status(400).json({ valid: false, message: 'Serial Key Lisensi wajib diisi!' });
    }

    const result = db.verifyKeyStatus(key, hwid || null);
    res.json(result);
});

// Klaim Lisensi (Redeem / Activate)
app.post('/api/redeem', (req, res) => {
    const { key, identifier, hwid } = req.body;
    if (!key) {
        return res.status(400).json({ success: false, message: 'Serial Key Lisensi wajib diisi!' });
    }

    const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
    const result = db.redeemKey(key, {
        identifier: identifier || 'Web Client / User',
        ip: clientIp,
        hwid: hwid || null
    });

    if (!result.success) {
        return res.status(400).json(result);
    }
    res.json(result);
});

// ----------------------------------------------------
// ADMIN ROUTES (PROTECTED)
// ----------------------------------------------------

// Ambil Stats Dashboard
app.get('/api/admin/stats', requireAdmin, (req, res) => {
    const stats = db.getStats();
    res.json({ success: true, stats });
});

// Ambil semua lisensi key
app.get('/api/admin/keys', requireAdmin, (req, res) => {
    const keys = db.getAllKeys();
    res.json({ success: true, keys });
});

// Generate Lisensi Key Baru (Single, Durasi, Lifetime)
app.post('/api/admin/keys/generate', requireAdmin, (req, res) => {
    const { count, note, prefix, durationType, durationDays } = req.body;
    const amount = parseInt(count, 10) || 1;
    
    if (amount < 1 || amount > 100) {
        return res.status(400).json({ success: false, message: 'Jumlah key yang dibuat antara 1 - 100.' });
    }

    const generated = db.generateKeys({
        count: amount,
        note: note || '',
        prefix: prefix || 'KEY',
        durationType: durationType || 'single',
        durationDays: parseInt(durationDays, 10) || 0
    });

    res.json({
        success: true,
        message: `Berhasil membuat ${generated.length} lisensi key baru!`,
        keys: generated
    });
});

// Hapus Key
app.delete('/api/admin/keys/:id', requireAdmin, (req, res) => {
    const { id } = req.params;
    const success = db.deleteKey(id);
    if (!success) {
        return res.status(404).json({ success: false, message: 'Key tidak ditemukan.' });
    }
    res.json({ success: true, message: 'Key berhasil dihapus.' });
});

// Ban Key
app.post('/api/admin/keys/ban', requireAdmin, (req, res) => {
    const { id, reason } = req.body;
    if (!id) return res.status(400).json({ success: false, message: 'ID atau Key wajib disertakan.' });

    const result = db.banKey(id, reason || 'Pelanggaran ketentuan penggunaan');
    if (!result.success) return res.status(400).json(result);
    res.json(result);
});

// Unban Key
app.post('/api/admin/keys/unban', requireAdmin, (req, res) => {
    const { id } = req.body;
    if (!id) return res.status(400).json({ success: false, message: 'ID atau Key wajib disertakan.' });

    const result = db.unbanKey(id);
    if (!result.success) return res.status(400).json(result);
    res.json(result);
});

// Jeda (Pause) Lisensi Tertentu
app.post('/api/admin/keys/pause', requireAdmin, (req, res) => {
    const { id, reason } = req.body;
    if (!id) return res.status(400).json({ success: false, message: 'ID atau Key wajib disertakan.' });

    const result = db.pauseKey(id, reason || 'Lisensi dijeda oleh admin');
    if (!result.success) return res.status(400).json(result);
    res.json(result);
});

// Lanjutkan (Resume) Lisensi Tertentu
app.post('/api/admin/keys/resume', requireAdmin, (req, res) => {
    const { id } = req.body;
    if (!id) return res.status(400).json({ success: false, message: 'ID atau Key wajib disertakan.' });

    const result = db.resumeKey(id);
    if (!result.success) return res.status(400).json(result);
    res.json(result);
});

// Tambah Waktu Lisensi Tertentu
app.post('/api/admin/keys/add-time', requireAdmin, (req, res) => {
    const { id, amount, unit } = req.body;
    if (!id) return res.status(400).json({ success: false, message: 'ID atau Key wajib disertakan.' });

    const result = db.addTimeKey(id, amount, unit || 'days');
    if (!result.success) return res.status(400).json(result);
    res.json(result);
});

// Tambah Waktu Lisensi ke SEMUA User (Bulk Compensation / Bonus)
app.post('/api/admin/keys/add-time-all', requireAdmin, (req, res) => {
    const { amount, unit, target } = req.body;
    const num = parseInt(amount, 10) || 0;
    if (num <= 0) {
        return res.status(400).json({ success: false, message: 'Jumlah waktu harus lebih besar dari 0!' });
    }

    const result = db.addTimeToAllKeys(num, unit || 'days', target || 'all');
    res.json(result);
});

// Mode Jeda Global (Global Maintenance / Pause All)
app.post('/api/admin/global-pause', requireAdmin, (req, res) => {
    const { enable, reason } = req.body;
    const result = db.setGlobalPause(!!enable, reason || '');
    res.json(result);
});

// Reset Perangkat / HWID Key
app.post('/api/admin/keys/reset-device', requireAdmin, (req, res) => {
    const { id } = req.body;
    if (!id) return res.status(400).json({ success: false, message: 'ID atau Key wajib disertakan.' });

    const result = db.resetKeyDevice(id);
    if (!result.success) return res.status(400).json(result);
    res.json(result);
});

// Ambil Audit Logs
app.get('/api/admin/logs', requireAdmin, (req, res) => {
    const logs = db.getLogs();
    res.json({ success: true, logs });
});

// Fallback Route untuk SPA / Direct Access
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Start Server
app.listen(PORT, () => {
    console.log(`================================================`);
    console.log(`🚀 Key Auth System berjalan pada port ${PORT}`);
    console.log(`🌐 Server URL   : http://localhost:${PORT}`);
    console.log(`🔑 Default Admin: admin / admin123`);
    console.log(`================================================`);
});
