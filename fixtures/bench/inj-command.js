// 真实性基准：命令注入
const { exec, spawn } = require('child_process');

exec('tar -xzf ' + filename); // 行 4 应命中

function build(userCmd) {
  spawn('npm run ' + userCmd); // 行 9 应命中
}

// 不应误报：正则字面量的 .exec() 方法（v0.4.1 修复）
const m = /^(\d+)$/v.exec(input); // 行 14 不应命中
