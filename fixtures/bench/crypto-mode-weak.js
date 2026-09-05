const crypto = require('crypto');

function encryptECB(plain, key) {
  const c = crypto.createCipheriv('aes-128-ecb', key, null); // L5 命中 ECB
  return Buffer.concat([c.update(plain), c.final()]).toString('hex');
}

function encryptCBC(plain, key) {
  const c = crypto.createCipheriv('aes-256-cbc', key, prevIv); // L10 命中 CBC
  return c.update(plain, 'utf8', 'base64');
}

// 安全：GCM 认证加密
function encryptGCM(plain, key, iv) {
  const c = crypto.createCipheriv('aes-256-gcm', key, iv); // L15 不命中
  return Buffer.concat([c.update(plain), c.final()]).toString('base64');
}
