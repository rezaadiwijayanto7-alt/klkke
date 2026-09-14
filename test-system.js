const db = require('./db');

console.log("=== UNIT TEST KEY AUTH SYSTEM ===");

// 1. Inisialisasi DB
db.initDB();
console.log("✔ DB Inisialisasi Berhasil");

// 2. Cek User Admin
const admin = db.findUserByUsername('admin');
console.log("✔ User Admin ditemukan:", admin ? admin.username : 'TIDAK DA');

// 3. Generate 1x Pakai Key
const generatedKeys = db.generateKeys(1, 'Test Key Single Use', 'TEST');
const testKeyObj = generatedKeys[0];
console.log("✔ Key Berhasil Dibuat:", testKeyObj.keyCode);

// 4. Verifikasi Key Sebelum Redeem (Harus Valid & Belum Terpakai)
const status1 = db.verifyKeyStatus(testKeyObj.keyCode);
console.log("✔ Verify Sebelum Redeem:", status1.valid ? "VALID (OK)" : "INVALID");
if (!status1.valid) throw new Error("Key harusnya valid sebelum diredeem!");

// 5. Redeem Pertama (Harus BERHASIL & Burn Key)
const redeem1 = db.redeemKey(testKeyObj.keyCode, { identifier: 'ClientTest1', ip: '127.0.0.1' });
console.log("✔ Redeem Ke-1 (1x Pakai):", redeem1.success ? "SUKSES (OK)" : "GAGAL");
if (!redeem1.success) throw new Error("Redeem 1 gagal!");

// 6. Redeem Kedua (Harus GAGAL karena sudah terpakai)
const redeem2 = db.redeemKey(testKeyObj.keyCode, { identifier: 'ClientTest2', ip: '127.0.0.1' });
console.log("✔ Redeem Ke-2 (Cek Hangus):", !redeem2.success ? `BERHASIL DITOLAK (OK - Message: "${redeem2.message}")` : "ERROR: Harusnya gagal!");
if (redeem2.success) throw new Error("Key 1x pakai berhasil diklaim 2 kali!");

// 7. Verify Setelah Redeem (Harus Invalid/Used)
const status2 = db.verifyKeyStatus(testKeyObj.keyCode);
console.log("✔ Verify Setelah Redeem:", !status2.valid ? "INVALID/USED (OK)" : "ERROR");

console.log("==========================================");
console.log("🎉 SEMUA TEST LISENSI 1X PAKAI LULUS (PASSED)!");
console.log("==========================================");
