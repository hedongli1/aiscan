// 真实性基准：路径穿越
const fs = require('fs');

function readUserFile(req) {
  fs.readFile(req.query.path); // 行 5 应命中
}
