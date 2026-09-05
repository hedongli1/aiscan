const { sequelize } = require('./db');
const knex = require('knex');

// Sequelize 原生查询拼接（L4）
export async function searchUsers(name) {
  const rows = await sequelize.query(
    `SELECT * FROM users WHERE name LIKE '%${name}%'`
  );
  return rows;
}

// knex.raw 拼接（L11）
export async function getByRole(role) {
  return knex.raw(`SELECT id FROM roles WHERE role = '${role}'`);
}

// 安全：参数化占位符
export async function safeSearch(name) {
  return sequelize.query('SELECT * FROM users WHERE name = ?', { replacements: [name] }); // L18 不命中
}
