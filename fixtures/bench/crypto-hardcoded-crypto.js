const crypto = require('crypto');

// 硬编码固定 IV（真实常见坑）
const KEY = Buffer.from('k3y_m4st3r_s3cr3t_harden1ng2028', 'utf8'); // L5 KEY
function encrypt1(plain) {
  const iv = Buffer.from('0123456789abcdef', 'utf8'); // L6 硬编码 IV
  const c = crypto.createCipheriv('aes-256-cbc', KEY, iv);
  return c.update(plain);
}

// 安全：随机 iv
function encrypt2(plain, key) {
  const iv = crypto.randomBytes(16); // L13 随机 IV
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  return { ct: c.update(plain), iv };
}
