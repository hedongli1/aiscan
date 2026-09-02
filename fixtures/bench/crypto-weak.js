// 真实性基准：弱加密
const crypto = require('crypto');

crypto.createHash('md5').update(pwd).digest('hex'); // 行 4 应命中

function legacyEncrypt(data, key) {
  return crypto.createCipheriv('des-cbc', key, iv); // 行 9 应命中 DES
}

// see ECB documentation for details —— 注释裸词不应误报
function strong(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}
