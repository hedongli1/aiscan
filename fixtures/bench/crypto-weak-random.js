// Math.random 生成 token —— 可预测，真实 CVE 源
export function resetToken(userId) {
  const token = Math.random().toString(36).slice(2); // L4 命中弱随机 token
  return token;
}

function genKey() {
  return Math.random().toString(36) + Math.random().toString(36); // L9 命中弱随机 key
}

// 安全：crypto 强随机
import { randomBytes } from 'crypto';
export function strongToken() {
  return randomBytes(32).toString('hex'); // L15 不命中
}
