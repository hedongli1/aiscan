// demo.js — 故意包含多种安全漏洞的示例文件（用于演示 / 测试 aiscan）
// ⚠️ 仅供安全研究与测试，请勿在真实项目中使用这些写法。

// 1) 硬编码 AWS 密钥
const awsKey = 'AKIAIOSFODNN7EXAMPLE123456'; // 典型 AWS Access Key 格式

// 2) 硬编码高熵 Token
const apiToken = 'ghp_xK9mQ2vL8nR4tW7zB1cE5hJ3fG6sD8aP2qW4eR6tY9uI';

// 3) 私钥内容
const privateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA7qVQfZvXJqB8m4wQySdLq3cF0b1vK7zZ3HhQ7uYk2xS8oD2a
-----END RSA PRIVATE KEY-----`;

// 4) SQL 注入：字符串拼接查询
function getUser(id) {
  const query = `SELECT * FROM users WHERE id = ${id}`;
  return db.query(query);
}

// 5) 命令注入
const { exec } = require('child_process');
function runCmd(userInput) {
  exec('ls -la ' + userInput); // 危险
}

// 6) DOM XSS
function render(data) {
  document.getElementById('output').innerHTML = data.userInput;
}

// 7) 弱加密
const crypto = require('crypto');
const hash = crypto.createHash('md5').update(password).digest('hex');

// 8) 关闭 TLS 校验
const https = require('https');
https.request(url, { rejectUnauthorized: false });

// 9) 路径穿越
const fs = require('fs');
function readFile(filename) {
  return fs.readFileSync('/data/' + filename); // filename 来自用户，可 ../ 逃逸
}

// 10) 连接串明文口令
const mongoUrl = 'mongodb://admin:Passw0rd123@db.example.com:27017/prod';
