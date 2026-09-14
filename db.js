'use strict';
const { Pool } = require('pg');

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

function newId() {
    return require('crypto').randomUUID();
}

async function initDB() {
    const client = await pool.connect();
    try {
        await client.query(`
            CREATE TABLE IF NOT EXISTS config (
                key   VARCHAR(100) PRIMARY KEY,
                value TEXT
            );
            CREATE TABLE IF NOT EXISTS users (
                id            VARCHAR(100) PRIMARY KEY,
                username      VARCHAR(100) UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role          VARCHAR(50) DEFAULT 'admin',
                created_at    TIMESTAMPTZ DEFAULT NOW()
            );
            CREATE TABLE IF NOT EXISTS license_keys (
                id                VARCHAR(100) PRIMARY KEY,
                key_code          VARCHAR(100) UNIQUE NOT NULL,
                duration_type     VARCHAR(50)  DEFAULT 'single',
                duration_days     INTEGER      DEFAULT 0,
                status            VARCHAR(50)  DEFAULT 'active',
                is_used           BOOLEAN      DEFAULT FALSE,
                note              TEXT         DEFAULT '',
                created_at        TIMESTAMPTZ  DEFAULT NOW(),
                activated_at      TIMESTAMPTZ,
                expires_at        TIMESTAMPTZ,
                paused_at         TIMESTAMPTZ,
                pause_reason      TEXT         DEFAULT '',
                remaining_time_ms BIGINT,
                banned_at         TIMESTAMPTZ,
                ban_reason        TEXT         DEFAULT '',
                used_at           TIMESTAMPTZ,
                used_by           TEXT         DEFAULT '',
                ip_address        TEXT         DEFAULT '',
                hwid              TEXT
            );
            CREATE TABLE IF NOT EXISTS logs (
                id        VARCHAR(100) PRIMARY KEY,
                timestamp TIMESTAMPTZ DEFAULT NOW(),
                action    VARCHAR(100),
                details   TEXT
            );
        `);

        const bcrypt = require('bcryptjs');
        const ex = await client.query(`SELECT id FROM users WHERE username = 'admin'`);
        if (ex.rows.length === 0) {
            const hash = await bcrypt.hash('admin123', 10);
            await client.query(`INSERT INTO users (id, username, password_hash, role) VALUES ($1, 'admin', $2, 'admin')`, [newId(), hash]);
        }
        await client.query(`INSERT INTO config (key, value) VALUES ('globalPause','false') ON CONFLICT (key) DO NOTHING`);
        await client.query(`INSERT INTO config (key, value) VALUES ('globalPauseReason','') ON CONFLICT (key) DO NOTHING`);
        console.log('Database PostgreSQL siap.');
    } finally { client.release(); }
}

async function addLog(action, details) {
    try { await pool.query(`INSERT INTO logs (id, action, details) VALUES ($1,$2,$3)`, [newId(), action, details]); } catch(_) {}
}

function evaluateKeyStatus(key, isGlobalPaused) {
    if (key.status === 'banned') return { isUsable: false, status: 'banned', label: 'Banned', reason: 'Lisensi di-BAN. Alasan: ' + (key.ban_reason || '-') };
    if (isGlobalPaused) return { isUsable: false, status: 'paused', label: 'Global Jeda', reason: 'Semua layanan sedang dijeda oleh admin.' };
    if (key.status === 'paused') return { isUsable: false, status: 'paused', label: 'Dijeda', reason: 'Lisensi dijeda. Alasan: ' + (key.pause_reason || '-') };
    if (key.duration_type === 'single') {
        if (key.is_used) return { isUsable: false, status: 'used', label: 'Sudah Dipakai', reason: 'Lisensi 1x pakai sudah digunakan.' };
        return { isUsable: true, status: 'active', label: 'Aktif (1x Pakai)' };
    }
    if (key.duration_type === 'lifetime') return { isUsable: true, status: 'active', label: 'Aktif (Lifetime)' };
    if (!key.activated_at) return { isUsable: true, status: 'active', label: 'Belum Diaktifkan' };
    if (key.expires_at && new Date() > new Date(key.expires_at)) return { isUsable: false, status: 'expired', label: 'Kadaluarsa', reason: 'Masa aktif lisensi telah habis.' };
    return { isUsable: true, status: 'active', label: 'Aktif' };
}

async function createUniqueKeyCode(prefix) {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    let code, exists = true;
    while (exists) {
        const seg = () => Array.from({ length: 4 }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
        code = `${prefix}-${seg()}-${seg()}-${seg()}`;
        const r = await pool.query(`SELECT id FROM license_keys WHERE key_code = $1`, [code]);
        exists = r.rows.length > 0;
    }
    return code;
}

async function findUserByUsername(username) {
    const r = await pool.query(`SELECT * FROM users WHERE username = $1`, [username]);
    return r.rows[0] || null;
}

async function getConfig() {
    const r = await pool.query(`SELECT key, value FROM config`);
    const cfg = {};
    r.rows.forEach(row => { cfg[row.key] = row.value; });
    return { globalPause: cfg.globalPause === 'true', globalPauseReason: cfg.globalPauseReason || '' };
}

async function setGlobalPause(enabled, reason = '') {
    await pool.query(`INSERT INTO config (key,value) VALUES ('globalPause',$1) ON CONFLICT (key) DO UPDATE SET value=$1`, [enabled ? 'true' : 'false']);
    await pool.query(`INSERT INTO config (key,value) VALUES ('globalPauseReason',$1) ON CONFLICT (key) DO UPDATE SET value=$1`, [reason]);
    await addLog('GLOBAL_PAUSE', `Global pause ${enabled ? 'ON' : 'OFF'}. Alasan: ${reason}`);
    return { success: true, message: `Global pause ${enabled ? 'diaktifkan' : 'dinonaktifkan'}.` };
}

async function generateKeys(options = {}) {
    const { durationType = 'single', durationDays = 0, count = 1, note = '', prefix = 'KEY' } = options;
    const generated = [];
    for (let i = 0; i < Math.min(count, 100); i++) {
        const keyCode = await createUniqueKeyCode(prefix);
        const id = newId();
        await pool.query(`INSERT INTO license_keys (id,key_code,duration_type,duration_days,note) VALUES ($1,$2,$3,$4,$5)`, [id, keyCode, durationType, durationDays, note]);
        generated.push({ id, keyCode, durationType, durationDays, note, status: 'active' });
    }
    await addLog('GENERATE_KEYS', `${count} key dibuat (tipe: ${durationType})`);
    return { success: true, message: `${generated.length} key berhasil dibuat.`, keys: generated };
}

async function getAllKeys() {
    const cfg = await getConfig();
    const r = await pool.query(`SELECT * FROM license_keys ORDER BY created_at DESC`);
    return r.rows.map(key => {
        const ev = evaluateKeyStatus(key, cfg.globalPause);
        return { id: key.id, keyCode: key.key_code, durationType: key.duration_type, durationDays: key.duration_days,
            status: ev.status, statusLabel: ev.label, note: key.note, createdAt: key.created_at,
            activatedAt: key.activated_at, expiresAt: key.expires_at, pausedAt: key.paused_at,
            pauseReason: key.pause_reason, remainingTimeMs: key.remaining_time_ms,
            bannedAt: key.banned_at, banReason: key.ban_reason, usedBy: key.used_by,
            ipAddress: key.ip_address, hwid: key.hwid, isUsed: key.is_used };
    });
}

async function deleteKey(id) {
    const r = await pool.query(`DELETE FROM license_keys WHERE id=$1 RETURNING key_code`, [id]);
    if (!r.rows.length) return { success: false, message: 'Key tidak ditemukan.' };
    await addLog('DELETE_KEY', `Key ${r.rows[0].key_code} dihapus.`);
    return { success: true, message: 'Key berhasil dihapus.' };
}

async function banKey(id, reason = '') {
    const r = await pool.query(`UPDATE license_keys SET status='banned', ban_reason=$1, banned_at=NOW() WHERE id=$2 RETURNING key_code`, [reason, id]);
    if (!r.rows.length) return { success: false, message: 'Key tidak ditemukan.' };
    await addLog('BAN_KEY', `Key ${r.rows[0].key_code} di-BAN. Alasan: ${reason}`);
    return { success: true, message: 'Key berhasil di-BAN.' };
}

async function unbanKey(id) {
    const r = await pool.query(`UPDATE license_keys SET status='active', ban_reason='', banned_at=NULL WHERE id=$1 RETURNING key_code`, [id]);
    if (!r.rows.length) return { success: false, message: 'Key tidak ditemukan.' };
    await addLog('UNBAN_KEY', `Key ${r.rows[0].key_code} di-UNBAN.`);
    return { success: true, message: 'Key berhasil di-UNBAN.' };
}

async function pauseKey(id, reason = '') {
    const r = await pool.query(`SELECT * FROM license_keys WHERE id=$1`, [id]);
    if (!r.rows.length) return { success: false, message: 'Key tidak ditemukan.' };
    const key = r.rows[0];
    if (key.status === 'paused') return { success: false, message: 'Key sudah dijeda.' };
    const remainingMs = key.expires_at ? Math.max(0, new Date(key.expires_at) - new Date()) : null;
    await pool.query(`UPDATE license_keys SET status='paused', pause_reason=$1, paused_at=NOW(), remaining_time_ms=$2, expires_at=NULL WHERE id=$3`, [reason, remainingMs, id]);
    await addLog('PAUSE_KEY', `Key ${key.key_code} dijeda.`);
    return { success: true, message: 'Key berhasil dijeda.' };
}

async function resumeKey(id) {
    const r = await pool.query(`SELECT * FROM license_keys WHERE id=$1`, [id]);
    if (!r.rows.length) return { success: false, message: 'Key tidak ditemukan.' };
    const key = r.rows[0];
    if (key.status !== 'paused') return { success: false, message: 'Key tidak sedang dijeda.' };
    const newExp = (key.remaining_time_ms && key.duration_type !== 'lifetime' && key.duration_type !== 'single')
        ? new Date(Date.now() + parseInt(key.remaining_time_ms)) : null;
    await pool.query(`UPDATE license_keys SET status='active', pause_reason='', paused_at=NULL, remaining_time_ms=NULL, expires_at=$1 WHERE id=$2`, [newExp, id]);
    await addLog('RESUME_KEY', `Key ${key.key_code} dilanjutkan.`);
    return { success: true, message: 'Key berhasil dilanjutkan.' };
}

async function addTimeKey(id, amount, unit = 'days') {
    const r = await pool.query(`SELECT * FROM license_keys WHERE id=$1`, [id]);
    if (!r.rows.length) return { success: false, message: 'Key tidak ditemukan.' };
    const key = r.rows[0];
    const ms = unit === 'hours' ? amount * 3600000 : amount * 86400000;
    if (key.status === 'paused' && key.remaining_time_ms) {
        await pool.query(`UPDATE license_keys SET remaining_time_ms=remaining_time_ms+$1 WHERE id=$2`, [ms, id]);
    } else if (key.expires_at) {
        await pool.query(`UPDATE license_keys SET expires_at=expires_at+make_interval(secs=>$1) WHERE id=$2`, [ms / 1000, id]);
    }
    await addLog('ADD_TIME', `+${amount} ${unit} ke key ${key.key_code}`);
    return { success: true, message: `+${amount} ${unit} berhasil ditambahkan.` };
}

async function addTimeToAllKeys(amount, unit = 'days', target = 'active') {
    const ms = unit === 'hours' ? amount * 3600000 : amount * 86400000;
    const secs = ms / 1000;
    const where = target === 'all' ? `duration_type NOT IN ('single','lifetime')` : `status='active' AND duration_type NOT IN ('single','lifetime')`;
    await pool.query(`UPDATE license_keys SET expires_at=expires_at+make_interval(secs=>$1) WHERE ${where} AND expires_at IS NOT NULL`, [secs]);
    await pool.query(`UPDATE license_keys SET remaining_time_ms=remaining_time_ms+$1 WHERE status='paused' AND remaining_time_ms IS NOT NULL`, [ms]);
    await addLog('ADD_TIME_ALL', `+${amount} ${unit} ke semua key.`);
    return { success: true, message: `+${amount} ${unit} ditambahkan ke semua key.` };
}

async function verifyKeyStatus(keyCode, hwid = null) {
    if (!keyCode) return { valid: false, message: 'Lisensi Key tidak boleh kosong!' };
    const cfg = await getConfig();
    const r = await pool.query(`SELECT * FROM license_keys WHERE UPPER(key_code)=UPPER($1)`, [keyCode.trim()]);
    if (!r.rows.length) return { valid: false, message: 'Lisensi Key tidak ditemukan / kode salah!' };
    const key = r.rows[0];
    const ev = evaluateKeyStatus(key, cfg.globalPause);
    if (!ev.isUsable) return { valid: false, status: ev.status, message: ev.reason || ev.label, key: { keyCode: key.key_code, status: ev.status, statusLabel: ev.label, note: key.note } };
    if (key.hwid && hwid && key.hwid.trim() !== hwid.trim()) {
        return { valid: false, status: 'hwid_mismatch', message: 'Akses ditolak: Lisensi terikat ke perangkat lain. Hubungi admin untuk reset perangkat.',
            key: { keyCode: key.key_code, status: 'hwid_mismatch', statusLabel: 'Perangkat Tidak Dikenal' } };
    }
    return { valid: true, status: ev.status, message: 'Lisensi Key Valid & Siap Digunakan!',
        key: { keyCode: key.key_code, status: ev.status, statusLabel: ev.label, note: key.note,
            durationType: key.duration_type, durationDays: key.duration_days, activatedAt: key.activated_at, expiresAt: key.expires_at, usedBy: key.used_by } };
}

async function redeemKey(keyCode, clientInfo = {}) {
    if (!keyCode) return { success: false, message: 'Lisensi Key tidak boleh kosong!' };
    const cfg = await getConfig();
    const r = await pool.query(`SELECT * FROM license_keys WHERE UPPER(key_code)=UPPER($1)`, [keyCode.trim()]);
    if (!r.rows.length) return { success: false, message: 'Lisensi Key tidak ditemukan / kode salah!' };
    const key = r.rows[0];
    const ev = evaluateKeyStatus(key, cfg.globalPause);
    if (!ev.isUsable) return { success: false, status: ev.status, message: ev.reason || ev.label };
    const identifier = (clientInfo.identifier || 'User').trim();
    const ip = clientInfo.ip || '127.0.0.1';
    const hwid = clientInfo.hwid || null;
    if (key.hwid && hwid && key.hwid.trim() !== hwid.trim()) {
        await addLog('HWID_MISMATCH', `Ditolak [${key.key_code}] HWID tidak cocok. IP: ${ip}`);
        return { success: false, status: 'hwid_mismatch', message: 'Aktivasi ditolak: Lisensi terikat ke perangkat lain. Hubungi admin untuk reset perangkat.' };
    }
    const now = new Date();
    if (key.duration_type === 'single') {
        await pool.query(`UPDATE license_keys SET is_used=TRUE, activated_at=$1, used_by=$2, ip_address=$3, hwid=COALESCE(hwid,$4), used_at=$1 WHERE id=$5`, [now, identifier, ip, hwid, key.id]);
        await addLog('REDEEM_SINGLE', `Key ${key.key_code} dipakai oleh ${identifier}`);
        return { success: true, message: 'Lisensi 1x pakai berhasil digunakan!', keyInfo: { keyCode: key.key_code, durationType: 'single', usedBy: identifier } };
    }
    if (key.duration_type === 'lifetime') {
        await pool.query(`UPDATE license_keys SET activated_at=COALESCE(activated_at,$1), used_by=$2, ip_address=$3, hwid=COALESCE(hwid,$4) WHERE id=$5`, [now, identifier, ip, hwid, key.id]);
        await addLog('REDEEM_LIFETIME', `Key ${key.key_code} lifetime aktif oleh ${identifier}`);
        return { success: true, message: 'Lisensi Lifetime BERHASIL diaktifkan!', keyInfo: { keyCode: key.key_code, durationType: 'lifetime', expiresAt: null, usedBy: identifier } };
    }
    const expiresAt = key.expires_at || new Date(now.getTime() + (key.duration_days || 1) * 86400000);
    await pool.query(`UPDATE license_keys SET activated_at=COALESCE(activated_at,$1), expires_at=COALESCE(expires_at,$2), used_by=$3, ip_address=$4, hwid=COALESCE(hwid,$5) WHERE id=$6`, [now, expiresAt, identifier, ip, hwid, key.id]);
    await addLog('REDEEM', `Key ${key.key_code} aktif oleh ${identifier}, exp: ${expiresAt}`);
    return { success: true, message: 'Lisensi BERHASIL diaktifkan!', keyInfo: { keyCode: key.key_code, durationType: key.duration_type, activatedAt: now, expiresAt, usedBy: identifier } };
}

async function resetKeyDevice(id) {
    const r = await pool.query(`UPDATE license_keys SET hwid=NULL, ip_address='', used_by='' WHERE id=$1 RETURNING key_code`, [id]);
    if (!r.rows.length) return { success: false, message: 'Key tidak ditemukan.' };
    await addLog('RESET_DEVICE', `Device reset untuk key ${r.rows[0].key_code}`);
    return { success: true, message: 'Perangkat berhasil direset.' };
}

async function getStats() {
    const cfg = await getConfig();
    const r = await pool.query(`SELECT * FROM license_keys`);
    let active = 0, expired = 0, banned = 0, paused = 0, used = 0;
    r.rows.forEach(k => {
        const s = evaluateKeyStatus(k, cfg.globalPause).status;
        if (s === 'active') active++;
        else if (s === 'expired') expired++;
        else if (s === 'banned') banned++;
        else if (s === 'paused') paused++;
        else if (s === 'used') used++;
    });
    return { total: r.rows.length, active, expired, banned, paused, used, globalPause: cfg.globalPause };
}

async function getLogs() {
    const r = await pool.query(`SELECT * FROM logs ORDER BY timestamp DESC LIMIT 200`);
    return r.rows;
}

module.exports = { initDB, findUserByUsername, getConfig, setGlobalPause, generateKeys, getAllKeys, deleteKey, banKey, unbanKey, pauseKey, resumeKey, addTimeKey, addTimeToAllKeys, verifyKeyStatus, redeemKey, resetKeyDevice, getStats, getLogs };