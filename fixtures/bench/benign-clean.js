// 真实性基准：干净代码，不应产生 high+ 发现
export function add(a, b) {
  return a + b;
}

export async function fetchUser(id) {
  const res = await fetch(`/api/users/${encodeURIComponent(id)}`);
  return res.json();
}

const MODE = process.env.NODE_ENV || 'production';
