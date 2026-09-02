// 真实性基准：TLS 不安全
const https = require('https');

const agent = new https.Agent({
  rejectUnauthorized: false, // 行 5 应命中
});
