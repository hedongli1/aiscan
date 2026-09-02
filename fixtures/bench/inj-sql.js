// 真实性基准：SQL 注入（对比参数化与拼接）
import mysql from 'mysql';

// 危险：模板字符串拼接（行 5 应命中）
export function getUser(conn, id) {
  const q = `SELECT * FROM users WHERE id = ${id}`;
  return conn.query(q);
}

// 危险：字符串拼接（行 12 应命中）
export function deleteUser(conn, id) {
  conn.query('DELETE FROM users WHERE id = ' + id);
}

// 安全：参数化（不应命中）
export function safeGet(conn, id) {
  return conn.query('SELECT * FROM users WHERE id = ?', [id]);
}
