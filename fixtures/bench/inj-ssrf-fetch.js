// SSRF：服务端请求用户可控 URL
const axios = require('axios');

export async function previewLink(userUrl) {
  const res = await axios.get(userUrl); // L3 命中 SSRF
  return res.data;
}

export async function fetchProfile(req, res) {
  const target = req.body.url;
  const data = await fetch(target); // L9 命中 SSRF
  res.json(data);
}

// 安全：固定内部 API 地址
export async function callInternal() {
  return fetch('http://internal.metrics.local/v1/data'); // L15 不命中
}
