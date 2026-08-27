// aiscan · 香农熵计算（用于高熵令牌检测）
// 密码学安全凭证的字符分布近似均匀 → 熵高；普通英文/代码 → 熵低。
// 用香农熵 + 长度作为"疑似机密"的启发式信号，模拟 AI 判断 Token 是否为密钥。

// 香农熵（bit/字符）
export function shannonEntropy(str) {
  if (!str || str.length === 0) return 0;
  const freq = new Map();
  for (const ch of str) {
    freq.set(ch, (freq.get(ch) || 0) + 1);
  }
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / str.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// 从一段文本中提取所有"疑似令牌"候选（长度 ≥ minLen 的连续非空白片段）
export function extractTokenCandidates(text, minLen = 16) {
  const candidates = [];
  // 匹配不含空格/引号/括号/等号/分号的连续片段，但保留字母数字 + 部分符号
  const re = /[A-Za-z0-9_\-\.\/+=]{16,}/g;
  let m;
  while ((m = re.exec(text)) !== null) {
    const token = m[0];
    // 过滤纯数字 / 纯日期 / 过长路径（非令牌特征）
    if (/^\d+$/.test(token)) continue;
    if (/^\d{4}[-/]\d{1,2}[-/]\d{1,2}$/.test(token)) continue;
    if (token.includes('/') && !/[A-Z0-9]{8,}/.test(token)) continue; // 可能是路径
    // 过滤完整性哈希前缀（sha512-/sha384-/sha256-/sha1-）：高熵但不是密钥
    if (/^sha(512|384|256|1)-/i.test(token)) continue;
    // 过滤常见十六进制摘要形态（长度 32/40/64 的纯 hex，如 md5/sha 摘要、git hash）
    if (/^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$/i.test(token)) continue;
    candidates.push({ token, start: m.index });
  }
  return candidates;
}

// 判断是否为"疑似机密"：长度与熵双阈值
export function isLikelySecret(token, { minLength = 20, minEntropy = 4.2 } = {}) {
  if (!token || token.length < minLength) return false;
  const entropy = shannonEntropy(token);
  return entropy >= minEntropy;
}

// 为令牌生成 AI 风格置信度评分（0~100）
export function secretConfidence(token) {
  if (!token || token.length < 16) return 0;
  const entropy = shannonEntropy(token);
  const len = token.length;
  let score = 0;
  // 熵贡献（最大约 55 分）：熵 3.5 起 10 分，每 +0.3 加 10 分，封顶 55
  score += Math.max(0, Math.min(55, (entropy - 3.5) / 0.3 * 10));
  // 长度贡献（最大约 25 分）：24 字符以上给满
  score += Math.max(0, Math.min(25, (len - 16) / 8 * 25));
  // 特征字符贡献（最大 20 分）：含大小写混合/数字/特殊符号各加分
  if (/[A-Z]/.test(token) && /[a-z]/.test(token)) score += 8;
  if (/\d/.test(token)) score += 6;
  if (/[^A-Za-z0-9]/.test(token)) score += 6;
  return Math.round(Math.min(100, score));
}
