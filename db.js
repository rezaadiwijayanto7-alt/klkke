const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const DB_PATH = path.join(__dirname, 'data', 'db.json');

// Pastikan folder data ada
if (!fs.existsSync(path.join(__dirname, 'data'))) {
    fs.mkdirSync(path.join(__dirname, 'data'), { recursive: true });
}

// Inisialisasi Database JSON jika belum ada
function initDB() {
    if (!fs.existsSync(DB_PATH)) {
        const defaultPasswordHash = bcrypt.hashSync('admin123', 10);
        const initialData = {
            config: {
                globalPause: false,
                globalPauseReason: '',
                globalPausedAt: null
            },
            users: [
                {
                    id: 'admin-1',
                    username: 'admin',
                    passwordHash: defaultPasswordHash,
                    role: 'admin',
                    createdAt: new Date().toISOString()
                }
            ],
            keys: [],
            logs: []
        };
        fs.writeFileSync(DB_PATH, JSON.stringify(initialData, null, 2), 'utf-8');
    }
}

function readDB() {
    initDB();
    try {
        const raw = fs.readFileSync(DB_PATH, 'utf-8');
        const parsed = JSON.parse(raw);
        if (!parsed.config) {
            parsed.config = {
                globalPause: false,
                globalPauseReason: '',
                globalPausedAt: null
            };
        }
        if (!Array.isArray(parsed.users)) parsed.users = [];
        if (!Array.isArray(parsed.keys)) parsed.keys = [];
        if (!Array.isArray(parsed.logs)) parsed.logs = [];
        return parsed;
    } catch (e) {
        console.error('Error reading DB:', e);
        return {
            config: { globalPause: false, globalPauseReason: '', globalPausedAt: null },
            users: [],
            keys: [],
            logs: []
        };
    }
}

function writeDB(data) {
    fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2), 'utf-8');
}

// Format Key Generator (Contoh: AUTH-A1B2-C3D4-E5F6)
function createUniqueKeyCode(prefix = 'KEY') {
    const cleanPrefix = (prefix || 'KEY').trim().toUpperCase().replace(/[^A-Z0-9]/g, '') || 'KEY';
    const part1 = crypto.randomBytes(2).toString('hex').toUpperCase();
    const part2 = crypto.randomBytes(2).toString('hex').toUpperCase();
    const part3 = crypto.randomBytes(2).toString('hex').toUpperCase();
    return `${cleanPrefix}-${part1}-${part2}-${part3}`;
}

// Log aktivitas
function addLog(action, details) {
    const db = readDB();
    db.logs.unshift({
        id: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        action,
        details
    });
    // Batasi log maksimal 150 entri
    if (db.logs.length > 150) {
        db.logs = db.logs.slice(0, 150);
    }
    writeDB(db);
}

// Helper untuk menghitung status aktual key
function evaluateKeyStatus(key, globalPause = false) {
    if (key.status === 'banned') {
        return {
            status: 'banned',
            isUsable: false,
            label: 'Diblokir (Banned)',
            reason: key.banReason || 'Pelanggaran ketentuan lisensi'
        };
    }

    if (globalPause) {
        return {
            status: 'paused',
            isUsable: false,
            label: 'Dijeda Sistem (Global Maintenance)',
            reason: 'Sistem sedang dalam masa jeda/pemeliharaan'
        };
    }

    if (key.status === 'paused') {
        return {
            status: 'paused',
            isUsable: false,
            label: 'Dijeda (Paused / Frozen)',
            reason: key.pauseReason || 'Lisensi sedang dijeda oleh administrator'
        };
    }

    // Jika tipe 1x pakai (single use)
    if (key.durationType === 'single') {
        if (key.isUsed) {
            return {
                status: 'used',
                isUsable: false,
                label: 'Sudah Digunakan (1x Pakai)',
                reason: 'Lisensi 1x pakai telah diklaim sebelumnya'
            };
        }
        return {
            status: 'active',
            isUsable: true,
            label: 'Aktif (Siap Klaim 1x Pakai)',
            reason: ''
        };
    }

    // Jika tipe lifetime
    if (key.durationType === 'lifetime') {
        return {
            status: 'active',
            isUsable: true,
            label: 'Aktif Selamanya (Lifetime)',
            reason: ''
        };
    }

    // Jika belum diaktivasi/diredeem pertama kali
    if (!key.activatedAt) {
        return {
            status: 'active',
            isUsable: true,
            label: 'Aktif (Belum Diaktivasi)',
            reason: ''
        };
    }

    // Sudah diaktivasi, cek masa berlaku expiresAt
    if (key.expiresAt) {
        const now = Date.now();
        const expiryTime = new Date(key.expiresAt).getTime();
        if (now > expiryTime) {
            return {
                status: 'expired',
                isUsable: false,
                label: 'Kedaluwarsa (Expired)',
                reason: 'Masa aktif lisensi telah habis'
            };
        }
        return {
            status: 'active',
            isUsable: true,
            label: 'Aktif (Berlangganan)',
            reason: ''
        };
    }

    return {
        status: 'active',
        isUsable: true,
        label: 'Aktif',
        reason: ''
    };
}

module.exports = {
    initDB,

    // Authentication
    findUserByUsername(username) {
        if (!username) return null;
        const db = readDB();
        return db.users.find(u => u.username.toLowerCase() === username.trim().toLowerCase());
    },

    // Config Global
    getConfig() {
        const db = readDB();
        return db.config || { globalPause: false, globalPauseReason: '', globalPausedAt: null };
    },

    setGlobalPause(enabled, reason = '') {
        const db = readDB();
        db.config.globalPause = !!enabled;
        db.config.globalPauseReason = reason || (enabled ? 'Pemeliharaan server berkala' : '');
        db.config.globalPausedAt = enabled ? new Date().toISOString() : null;

        writeDB(db);
        const actionLabel = enabled ? 'GLOBAL_PAUSE_ON' : 'GLOBAL_PAUSE_OFF';
        const msg = enabled 
            ? `Mode Jeda Global DIAKTIFKAN: "${db.config.globalPauseReason}"` 
            : 'Mode Jeda Global DINONAKTIFKAN (Sistem kembali aktif normal)';
        addLog(actionLabel, msg);

        return { success: true, config: db.config, message: msg };
    },

    // Key Operations
    generateKeys(options = {}) {
        let count = 1;
        let note = '';
        let prefix = 'KEY';
        let durationType = 'single';
        let durationDays = 0;

        if (typeof options === 'object' && options !== null) {
            count = options.count || 1;
            note = options.note || '';
            prefix = options.prefix || 'KEY';
            durationType = options.durationType || 'single';
            durationDays = options.durationDays || 0;
        }

        const db = readDB();
        const createdKeys = [];
        const safeCount = Math.min(Math.max(parseInt(count, 10) || 1, 1), 100);

        let days = 0;
        if (durationType === '1_day') days = 1;
        else if (durationType === '7_days') days = 7;
        else if (durationType === '30_days') days = 30;
        else if (durationType === '90_days') days = 90;
        else if (durationType === '365_days') days = 365;
        else if (durationType === 'custom') days = Math.max(parseInt(durationDays, 10) || 1, 1);
        else if (durationType === 'lifetime') days = 0;
        else days = 0; // single-use

        for (let i = 0; i < safeCount; i++) {
            const keyObj = {
                id: crypto.randomUUID(),
                keyCode: createUniqueKeyCode(prefix),
                durationType,
                durationDays: days,
                status: 'active',
                isUsed: false,
                note: note || (durationType === 'single' ? 'Lisensi 1x Pakai' : (durationType === 'lifetime' ? 'Lisensi Lifetime' : `Lisensi Durasi ${days} Hari`)),
                createdAt: new Date().toISOString(),
                activatedAt: null,
                expiresAt: null,
                pausedAt: null,
                pauseReason: '',
                remainingTimeMs: null,
                bannedAt: null,
                banReason: '',
                usedAt: null,
                usedBy: null,
                ipAddress: null,
                hwid: null
            };
            db.keys.unshift(keyObj);
            createdKeys.push(keyObj);
        }

        writeDB(db);
        addLog('GENERATE_KEYS', `Membuat ${safeCount} lisensi (${durationType.toUpperCase()}, Prefix: ${prefix})`);
        return createdKeys;
    },

    getAllKeys() {
        const db = readDB();
        const isGlobalPaused = !!db.config.globalPause;
        return db.keys.map(k => {
            const evalStat = evaluateKeyStatus(k, isGlobalPaused);
            return {
                ...k,
                currentStatus: evalStat.status,
                statusLabel: evalStat.label,
                statusReason: evalStat.reason,
                isUsable: evalStat.isUsable
            };
        });
    },

    getKeyById(id) {
        const db = readDB();
        return db.keys.find(k => k.id === id);
    },

    deleteKey(id) {
        const db = readDB();
        const index = db.keys.findIndex(k => k.id === id);
        if (index !== -1) {
            const removed = db.keys.splice(index, 1)[0];
            writeDB(db);
            addLog('DELETE_KEY', `Menghapus key ${removed.keyCode}`);
            return true;
        }
        return false;
    },

    // BAN / UNBAN LISENSI
    banKey(id, reason = 'Pelanggaran ketentuan penggunaan') {
        const db = readDB();
        const key = db.keys.find(k => k.id === id || k.keyCode.trim().toUpperCase() === id.trim().toUpperCase());
        if (!key) return { success: false, message: 'Lisensi Key tidak ditemukan!' };

        key.status = 'banned';
        key.bannedAt = new Date().toISOString();
        key.banReason = reason;

        writeDB(db);
        addLog('BAN_KEY', `Lisensi ${key.keyCode} DIBLOKIR / BANNED. Alasan: "${reason}"`);
        return { success: true, message: `Lisensi ${key.keyCode} berhasil diblokir/ban!`, key };
    },

    unbanKey(id) {
        const db = readDB();
        const key = db.keys.find(k => k.id === id || k.keyCode.trim().toUpperCase() === id.trim().toUpperCase());
        if (!key) return { success: false, message: 'Lisensi Key tidak ditemukan!' };

        if (key.status !== 'banned') {
            return { success: false, message: 'Lisensi Key ini tidak dalam status banned.' };
        }

        key.status = 'active';
        key.bannedAt = null;
        key.banReason = '';

        writeDB(db);
        addLog('UNBAN_KEY', `Blokir dicabut untuk lisensi ${key.keyCode}`);
        return { success: true, message: `Lisensi ${key.keyCode} berhasil di-unban (kembali aktif)!`, key };
    },

    // JEDA (PAUSE) / LANJUTKAN (RESUME) LISENSI
    pauseKey(id, reason = 'Dijeda oleh admin') {
        const db = readDB();
        const key = db.keys.find(k => k.id === id || k.keyCode.trim().toUpperCase() === id.trim().toUpperCase());
        if (!key) return { success: false, message: 'Lisensi Key tidak ditemukan!' };

        if (key.status === 'banned') {
            return { success: false, message: 'Lisensi dalam status banned, tidak bisa dijeda.' };
        }
        if (key.status === 'paused') {
            return { success: false, message: 'Lisensi sudah dalam keadaan dijeda.' };
        }

        const now = Date.now();

        // Jika memiliki expiresAt (lisensi berbasis durasi yang sudah aktif)
        if (key.expiresAt) {
            const expiryTime = new Date(key.expiresAt).getTime();
            const remaining = Math.max(0, expiryTime - now);
            key.remainingTimeMs = remaining;
        }

        key.status = 'paused';
        key.pausedAt = new Date().toISOString();
        key.pauseReason = reason;

        writeDB(db);
        addLog('PAUSE_KEY', `Lisensi ${key.keyCode} DIJEDA (Waktu sisa dibekukan). Alasan: "${reason}"`);
        return { success: true, message: `Lisensi ${key.keyCode} berhasil dijeda! Waktu sisa dibekukan.`, key };
    },

    resumeKey(id) {
        const db = readDB();
        const key = db.keys.find(k => k.id === id || k.keyCode.trim().toUpperCase() === id.trim().toUpperCase());
        if (!key) return { success: false, message: 'Lisensi Key tidak ditemukan!' };

        if (key.status !== 'paused') {
            return { success: false, message: 'Lisensi tidak dalam status dijeda.' };
        }

        // Kembalikan sisa waktu jika ada
        if (key.remainingTimeMs && key.remainingTimeMs > 0) {
            const newExpiry = new Date(Date.now() + key.remainingTimeMs).toISOString();
            key.expiresAt = newExpiry;
            key.remainingTimeMs = null;
        }

        key.status = 'active';
        key.pausedAt = null;
        key.pauseReason = '';

        writeDB(db);
        addLog('RESUME_KEY', `Lisensi ${key.keyCode} DILANJUTKAN kembali (Hitungan waktu berjalan)`);
        return { success: true, message: `Lisensi ${key.keyCode} berhasil diaktifkan kembali!`, key };
    },

    // TAMBAH WAKTU LISENSI SPESIFIK
    addTimeKey(id, amount = 1, unit = 'days') {
        const db = readDB();
        const key = db.keys.find(k => k.id === id || k.keyCode.trim().toUpperCase() === id.trim().toUpperCase());
        if (!key) return { success: false, message: 'Lisensi Key tidak ditemukan!' };

        const num = parseInt(amount, 10) || 0;
        if (num <= 0) return { success: false, message: 'Jumlah waktu harus lebih besar dari 0!' };

        let addedMs = 0;
        if (unit === 'hours') addedMs = num * 60 * 60 * 1000;
        else if (unit === 'minutes') addedMs = num * 60 * 1000;
        else addedMs = num * 24 * 60 * 60 * 1000; // default days

        if (!key.activatedAt) {
            if (unit === 'days') key.durationDays = (key.durationDays || 0) + num;
            else key.durationDays = (key.durationDays || 0) + Math.ceil(num / 24);
        } else if (key.status === 'paused') {
            key.remainingTimeMs = (key.remainingTimeMs || 0) + addedMs;
        } else if (key.expiresAt) {
            const currentExpiry = new Date(key.expiresAt).getTime();
            const baseTime = currentExpiry > Date.now() ? currentExpiry : Date.now();
            key.expiresAt = new Date(baseTime + addedMs).toISOString();
        } else if (key.durationType !== 'lifetime' && key.durationType !== 'single') {
            key.expiresAt = new Date(Date.now() + addedMs).toISOString();
        }

        writeDB(db);
        const unitName = unit === 'hours' ? 'Jam' : (unit === 'minutes' ? 'Menit' : 'Hari');
        addLog('ADD_TIME_KEY', `Menambahkan +${num} ${unitName} ke lisensi ${key.keyCode}`);
        return { success: true, message: `Berhasil menambahkan +${num} ${unitName} ke lisensi ${key.keyCode}!`, key };
    },

    // TAMBAH WAKTU LISENSI KE SEMUA USER SECARA MASSAL (BULK COMPENSATE / BONUS)
    addTimeToAllKeys(amount = 1, unit = 'days', target = 'all') {
        const db = readDB();
        const num = parseInt(amount, 10) || 0;
        if (num <= 0) return { success: false, message: 'Jumlah waktu harus lebih besar dari 0!' };

        let addedMs = 0;
        if (unit === 'hours') addedMs = num * 60 * 60 * 1000;
        else if (unit === 'minutes') addedMs = num * 60 * 1000;
        else addedMs = num * 24 * 60 * 60 * 1000; // default days

        let affectedCount = 0;
        const now = Date.now();

        db.keys.forEach(key => {
            if (key.status === 'banned') return;

            if (target === 'active_only' && key.status !== 'active') return;
            if (target === 'paused_only' && key.status !== 'paused') return;

            if (key.status === 'paused') {
                key.remainingTimeMs = (key.remainingTimeMs || 0) + addedMs;
                affectedCount++;
            } else if (key.expiresAt) {
                const currentExpiry = new Date(key.expiresAt).getTime();
                const baseTime = currentExpiry > now ? currentExpiry : now;
                key.expiresAt = new Date(baseTime + addedMs).toISOString();
                affectedCount++;
            } else if (!key.activatedAt && key.durationType !== 'single' && key.durationType !== 'lifetime') {
                if (unit === 'days') key.durationDays = (key.durationDays || 0) + num;
                else key.durationDays = (key.durationDays || 0) + Math.ceil(num / 24);
                affectedCount++;
            }
        });

        writeDB(db);
        const unitName = unit === 'hours' ? 'Jam' : (unit === 'minutes' ? 'Menit' : 'Hari');
        const msg = `Berhasil menambahkan +${num} ${unitName} ke ${affectedCount} lisensi user!`;
        addLog('BULK_ADD_TIME', msg);

        return {
            success: true,
            message: msg,
            affectedCount
        };
    },

    // VERIFIKASI LISENSI
    verifyKeyStatus(keyCode, hwid = null) {
        if (!keyCode || typeof keyCode !== 'string') {
            return { valid: false, message: 'Lisensi Key tidak boleh kosong!' };
        }

        const db = readDB();
        const isGlobalPaused = !!db.config.globalPause;
        const key = db.keys.find(k => k.keyCode.trim().toUpperCase() === keyCode.trim().toUpperCase());

        if (!key) {
            return { valid: false, message: 'Lisensi Key tidak ditemukan / kode salah!' };
        }

        const evalStat = evaluateKeyStatus(key, isGlobalPaused);

        if (!evalStat.isUsable) {
            return {
                valid: false,
                status: evalStat.status,
                message: evalStat.reason || evalStat.label,
                key: {
                    keyCode: key.keyCode,
                    status: evalStat.status,
                    statusLabel: evalStat.label,
                    note: key.note,
                    durationType: key.durationType,
                    expiresAt: key.expiresAt,
                    banReason: key.banReason,
                    pauseReason: key.pauseReason
                }
            };
        }

        // ─── HWID ENFORCEMENT ───
        // Jika key sudah terikat ke device dan client mengirim hwid,
        // tolak jika hwid berbeda (beda device → harus reset dulu).
        if (key.hwid && hwid && key.hwid.trim() !== hwid.trim()) {
            return {
                valid: false,
                status: 'hwid_mismatch',
                message: 'Akses ditolak: Lisensi ini sudah terikat ke perangkat lain. Hubungi admin untuk reset perangkat.',
                key: {
                    keyCode: key.keyCode,
                    status: 'hwid_mismatch',
                    statusLabel: 'Perangkat Tidak Dikenal',
                    note: key.note
                }
            };
        }

        return {
            valid: true,
            status: evalStat.status,
            message: 'Lisensi Key Valid & Siap Digunakan!',
            key: {
                keyCode: key.keyCode,
                status: evalStat.status,
                statusLabel: evalStat.label,
                note: key.note,
                durationType: key.durationType,
                durationDays: key.durationDays,
                activatedAt: key.activatedAt,
                expiresAt: key.expiresAt,
                usedBy: key.usedBy
            }
        };
    },

    // REDEEM / KLAIM / AKTIVASI LISENSI
    redeemKey(keyCode, clientInfo = {}) {
        if (!keyCode || typeof keyCode !== 'string') {
            return { success: false, message: 'Lisensi Key tidak boleh kosong!' };
        }

        const db = readDB();
        const isGlobalPaused = !!db.config.globalPause;

        if (isGlobalPaused) {
            return {
                success: false,
                message: `Aktivasi ditolak: Sistem sedang dijeda / Maintenance (${db.config.globalPauseReason || 'Harap coba beberapa saat lagi'}).`
            };
        }

        const keyIndex = db.keys.findIndex(k => k.keyCode.trim().toUpperCase() === keyCode.trim().toUpperCase());

        if (keyIndex === -1) {
            return { success: false, message: 'Lisensi Key tidak ditemukan atau kode salah!' };
        }

        const key = db.keys[keyIndex];
        const evalStat = evaluateKeyStatus(key, false);

        if (!evalStat.isUsable) {
            return {
                success: false,
                message: `Gagal aktivasi: ${evalStat.reason || evalStat.label}`,
                status: evalStat.status
            };
        }

        const now = new Date();
        const clientIdentifier = (clientInfo.identifier || 'User Web Client').trim();
        const clientIp = clientInfo.ip || '127.0.0.1';
        const clientHwid = clientInfo.hwid || null;

        // ─── HWID ENFORCEMENT ───
        // Jika key sudah terikat ke device lain, tolak aktivasi.
        if (key.hwid && clientHwid && key.hwid.trim() !== clientHwid.trim()) {
            addLog('HWID_MISMATCH', `Percobaan aktivasi ditolak untuk [${key.keyCode}] — HWID tidak cocok. (IP: ${clientIp})`);
            return {
                success: false,
                status: 'hwid_mismatch',
                message: 'Aktivasi ditolak: Lisensi ini sudah terikat ke perangkat lain. Hubungi admin untuk melakukan reset perangkat terlebih dahulu.'
            };
        }

        // Tipe 1x Pakai
        if (key.durationType === 'single') {
            key.isUsed = true;
            key.status = 'used';
            key.usedAt = now.toISOString();
            key.usedBy = clientIdentifier;
            key.ipAddress = clientIp;
            key.hwid = clientHwid;

            db.keys[keyIndex] = key;
            writeDB(db);

            addLog('REDEEM_KEY', `Key 1x Pakai [${key.keyCode}] berhasil diklaim oleh ${key.usedBy} (IP: ${key.ipAddress})`);

            return {
                success: true,
                message: 'Lisensi 1x Pakai BERHASIL diklaim & diaktifkan!',
                keyInfo: {
                    keyCode: key.keyCode,
                    status: 'used',
                    durationType: 'single',
                    usedAt: key.usedAt,
                    usedBy: key.usedBy,
                    note: key.note
                }
            };
        }

        // Tipe Berbasis Durasi Waktu / Lifetime
        if (!key.activatedAt) {
            key.activatedAt = now.toISOString();
            if (key.durationType === 'lifetime') {
                key.expiresAt = null;
            } else if (key.durationDays > 0) {
                const expiry = new Date(now.getTime() + (key.durationDays * 24 * 60 * 60 * 1000));
                key.expiresAt = expiry.toISOString();
            }
        }

        key.isUsed = true;
        key.usedBy = clientIdentifier;
        key.ipAddress = clientIp;
        if (clientHwid) key.hwid = clientHwid;

        db.keys[keyIndex] = key;
        writeDB(db);

        addLog('ACTIVATE_KEY', `Lisensi [${key.keyCode}] diaktifkan oleh ${key.usedBy}. Berlaku hingga: ${key.expiresAt ? new Date(key.expiresAt).toLocaleString('id-ID') : 'Lifetime'}`);

        return {
            success: true,
            message: 'Lisensi BERHASIL diaktifkan!',
            keyInfo: {
                keyCode: key.keyCode,
                status: 'active',
                durationType: key.durationType,
                activatedAt: key.activatedAt,
                expiresAt: key.expiresAt,
                usedBy: key.usedBy,
                note: key.note
            }
        };
    },

    // Reset HWID / Device Bound Key
    resetKeyDevice(id) {
        const db = readDB();
        const key = db.keys.find(k => k.id === id || k.keyCode.trim().toUpperCase() === id.trim().toUpperCase());
        if (!key) return { success: false, message: 'Lisensi Key tidak ditemukan!' };

        key.hwid = null;
        key.ipAddress = null;
        key.usedBy = null;

        writeDB(db);
        addLog('RESET_DEVICE', `Reset binding perangkat / user untuk key ${key.keyCode}`);
        return { success: true, message: `Binding perangkat untuk key ${key.keyCode} berhasil direset!` };
    },

    getLogs() {
        const db = readDB();
        return db.logs;
    },

    getStats() {
        const db = readDB();
        const isGlobalPaused = !!db.config.globalPause;
        let active = 0;
        let paused = 0;
        let banned = 0;
        let expired = 0;
        let used = 0;

        db.keys.forEach(k => {
            const ev = evaluateKeyStatus(k, isGlobalPaused);
            if (ev.status === 'active') active++;
            else if (ev.status === 'paused') paused++;
            else if (ev.status === 'banned') banned++;
            else if (ev.status === 'expired') expired++;
            else if (ev.status === 'used') used++;
        });

        return {
            total: db.keys.length,
            active,
            paused,
            banned,
            expired,
            used,
            globalPause: isGlobalPaused,
            globalPauseReason: db.config.globalPauseReason
        };
    }
};
