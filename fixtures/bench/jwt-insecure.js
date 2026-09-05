const jwt = require('jsonwebtoken');

// 硬编码 JWT secret（真实最常见）
function makeToken(user) {
  return jwt.sign({ sub: user.id, role: 'admin' }, 'shh_do_not_leak', { expiresIn: '1d' }); // L6 命中
}

// alg:none 篡改校验逻辑
function verifyTokenAny(token) {
  const payload = jwt.verify(token, null, { algorithms: ['none'] }); // L11 命中 alg none
  return payload;
}

// 安全：签名用环境变量，验证限定算法
function signSafe(user) {
  return jwt.sign({ sub: user.id }, process.env.JWT_SECRET, { expiresIn: '1d' }); // L16 不命中
}
