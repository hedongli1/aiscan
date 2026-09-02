// aiscan · 核心扫描引擎
// 遍历文件 → 逐行逐段匹配规则 → 熵启发式补充 → 汇总统计。
// 纯静态文本分析，绝不执行被测代码。

import { promises as fs } from 'node:fs';
import path from 'node:path';
import { ALL_RULES } from './rules/index.js';
import { extractTokenCandidates, isLikelySecret, secretConfidence } from './entropy.js';

// 跳过二进制 / 巨型 / 生成物 / 依赖目录
const SKIP_DIRS = new Set(['node_modules', '.git', '.next', 'dist', 'build', 'coverage', '.cache', 'vendor', 'target']);
// lockfile 是依赖清单：内容是包名/版本号/sha512 完整性哈希，不是密钥，扫了全是误报
const SKIP_FILES = new Set(['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', 'composer.lock', 'poetry.lock', 'Cargo.lock', 'go.sum', 'Gemfile.lock']);
const SKIP_EXTS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.svg',
  '.woff', '.woff2', '.ttf', '.eot', '.pdf', '.zip', '.gz', '.tar',
  '.db', '.sqlite', '.class', '.jar', '.min.js', '.min.css', '.map',
  '.lock', // 二进制锁文件
]);
const MAX_FILE_BYTES = 1 * 1024 * 1024; // 1MB 以上跳过（避免拖慢）

// 读取 .aiscanignore（类似 .gitignore，每行一个 glob / 目录前缀）
// 解析优先级：显式 --ignore-file > 扫描目标根目录 > 当前工作目录。
// （扫描目标根优先于 cwd：patrol 克隆到临时目录后扫描，ignore 应随目标仓库走）
async function loadIgnoreList(ignoreFilePath, scanRoot) {
  const ignore = new Set();
  const tryPaths = [];
  if (ignoreFilePath) tryPaths.push(ignoreFilePath);
  if (scanRoot) tryPaths.push(path.join(scanRoot, '.aiscanignore'));
  tryPaths.push(path.join(process.cwd(), '.aiscanignore'));

  let text = null;
  for (const p of tryPaths) {
    try {
      text = await fs.readFile(p, 'utf8');
      break;
    } catch {
      // 尝试下一个位置
    }
  }
  if (text === null) return ignore; // 无 .aiscanignore 属正常

  for (const line of text.split('\n')) {
    const l = line.trim();
    if (!l || l.startsWith('#')) continue;
    ignore.add(l);
  }
  return ignore;
}

function isIgnored(relPath, ignoreList) {
  if (ignoreList.size === 0) return false;
  const norm = relPath.replace(/\\/g, '/');
  for (const raw of ignoreList) {
    // 允许目录写法带尾斜杠（tools/ 等价 tools）
    const p = raw.replace(/\\/g, '/').replace(/^\.\//, '').replace(/\/+$/, '');
    if (!p) continue;
    const basename = p.split('/').pop();
    // 完全匹配
    if (norm === p) return true;
    // 以目录为前缀
    if (norm.startsWith(p + '/')) return true;
    // 以「/dir/file」结尾
    if (norm.endsWith('/' + p)) return true;
    // basename 直接相等（允许 lib/rules/index.js 匹配任意 depth 的 rules/index.js）
    if (norm === basename) return true;
    if (norm.endsWith('/' + basename)) return true;
  }
  return false;
}

async function isBinary(buf) {
  // 前 8000 字节含 NUL 视为二进制
  const sample = buf.subarray(0, Math.min(8000, buf.length));
  return sample.includes(0);
}

async function walk(dir, fileList = []) {
  let stat;
  try {
    stat = await fs.stat(dir);
  } catch {
    return fileList;
  }
  // 参数是单个文件时直接加入列表
  if (stat.isFile()) {
    fileList.push(dir);
    return fileList;
  }
  let entries;
  try {
    entries = await fs.readdir(dir, { withFileTypes: true });
  } catch {
    return fileList;
  }
  for (const e of entries) {
    if (SKIP_DIRS.has(e.name)) continue;
    const full = path.join(dir, e.name);
    if (e.isDirectory()) {
      await walk(full, fileList);
    } else if (e.isFile()) {
      fileList.push(full);
    }
  }
  return fileList;
}

function lineAndCol(text, index) {
  const before = text.slice(0, index);
  const line = (before.match(/\n/g) || []).length + 1;
  const col = index - before.lastIndexOf('\n');
  return { line, col };
}

function excerptAround(text, start, maxLen = 120) {
  const s = Math.max(0, start - 20);
  const e = Math.min(text.length, start + maxLen);
  let snippet = text.slice(s, e).replace(/\s+/g, ' ').trim();
  // 脱敏：密钥类候选（长随机串）打码，防止安全工具自己把密钥写进报告/SARIF 造成二次泄漏
  snippet = snippet.replace(/[A-Za-z0-9_\-\/+=]{12,}/g, (m) => {
    if (m.length < 16) return m; // 太短不脱敏
    return m.slice(0, 4) + '…' + m.slice(-2) + `（已脱敏，原文 ${m.length} 字符）`;
  });
  return snippet;
}

// 测试目录降权：第三方仓库的 test/tests/__tests__/spec/fixtures 里的"密钥"多为测试 fixture，
// secret 类发现降为 low（仍报告但不淹没真实信号）。
const TEST_DIR_RE = /(^|\/)(tests?|__tests__|spec|fixtures?|example[^/]*|\.github\/workflows|docs?|documentation|benchmarks?|demo[^/]*|e2e)\//i;

// 常见 HTTP header 名黑名单：generic-api-key 等"关键词+赋值"规则会把
// set-cookie / transfer-encoding / keep-alive 等 header 名字符串误判为 API Key。
// 捕获值命中这些已知无敏感性的 header 名时跳过（它们只是请求头枚举，不是密钥）。
const HTTP_HEADER_NAMES = new Set([
  'accept', 'accept-encoding', 'accept-language', 'authorization', 'cache-control',
  'connection', 'content-encoding', 'content-length', 'content-type', 'cookie', 'cookie2',
  'host', 'keep-alive', 'origin', 'pragma', 'proxy-authorization', 'proxy-connection',
  'referer', 'set-cookie', 'te', 'trailer', 'transfer-encoding', 'upgrade', 'user-agent',
  'via', 'www-authenticate', 'x-api-key', 'x-forwarded-for', 'x-requested-with',
]);

export async function scanDirectory(rootDir, options = {}) {
  const files = await walk(rootDir);
  const findings = [];
  const ignoreList = await loadIgnoreList(options.ignoreFile, rootDir);

  // rootDir 类型只需判定一次（原实现每个文件重复 stat，浪费且语义含糊）
  const absRoot = path.resolve(rootDir);
  let rootIsFile = false;
  try {
    rootIsFile = (await fs.stat(absRoot)).isFile();
  } catch {
    // 路径不存在时 walk 已返回空列表，走不到这里
  }

  for (const file of files) {
    const ext = path.extname(file).toLowerCase();
    // 跳过压缩产物（path.extname 不识别 .min.js 这类双后缀，需额外判断）
    if (SKIP_EXTS.has(ext) || /\.min\.(js|css)$/i.test(file)) continue;
    // 跳过依赖锁文件（内容为版本与完整性哈希，非密钥）
    if (SKIP_FILES.has(path.basename(file))) continue;

    // 单文件输入时 relPath 用文件名，目录输入时用相对路径
    const relPath = rootIsFile ? path.basename(absRoot) : path.relative(absRoot, path.resolve(file));
    if (isIgnored(relPath, ignoreList)) continue;

    let buf;
    let text;
    try {
      const stat = await fs.stat(file);
      if (stat.size > MAX_FILE_BYTES) continue;
      buf = await fs.readFile(file);
      if (await isBinary(buf)) continue;
      text = buf.toString('utf8');
    } catch {
      continue; // 权限 / 并发删除等，跳过
    }

    // 1) 正则规则匹配（gitleaks 规则带 keywords 时先做快速预筛，避免 220+ 正则全量跑）
    const textLower = text.length > 4096 ? null : text.toLowerCase();
    for (const rule of ALL_RULES) {
      if (!rule.regex) continue;
      // keywords 预筛：小文件用小写全文缓存快速判断，大文件直接 indexOf
      if (rule.keywords && rule.keywords.length) {
        const hit = rule.keywords.some((kw) =>
          textLower !== null ? textLower.includes(kw) : text.toLowerCase().includes(kw)
        );
        if (!hit) continue; // 关键词都没有 → 该规则跳过
      }
      const re = new RegExp(rule.regex.source, rule.regex.flags.includes('g') ? rule.regex.flags : rule.regex.flags + 'g');
      let m;
      while ((m = re.exec(text)) !== null) {
        // gitleaks 规则的 entropy 门槛：对捕获组（无捕获组则对整体命中）算香农熵，
        // 低于阈值视为误报（如变量名 key/secret、普通单词）——gitleaks 原版语义
        if (rule.entropy != null) {
          const captured = m[1] || m[0];
          if (shannonOf(captured) < rule.entropy) continue;
        }
        // HTTP header 名黑名单：捕获值若为已知 header 名（set-cookie 等），跳过
        if (rule.category === 'secret' && m[1]) {
          const capturedNorm = m[1].toLowerCase().replace(/['"`]/g, '');
          if (HTTP_HEADER_NAMES.has(capturedNorm)) continue;
        }
        const { line, col } = lineAndCol(text, m.index);
        // 测试目录降权：test/tests/__tests__/spec/fixtures 里的 secret 类发现多为 fixture，
        // 降为 low 避免淹没真实信号（非 secret 类如注入/XSS 保持原级）
        const inTestDir = TEST_DIR_RE.test(relPath);
        const isDowngraded = inTestDir && (rule.category === 'secret' || rule.id === 'TLS-INSECURE');
        const severity = isDowngraded ? 'low' : rule.severity;
        findings.push({
          ruleId: rule.id,
          severity,
          category: rule.category,
          title: rule.title,
          message: isDowngraded ? `${rule.message}（测试目录，已降权）` : rule.message,
          file: relPath,
          line,
          col,
          snippet: excerptAround(text, m.index),
          confidence: 92 + (rule.severity === 'critical' ? 5 : 0),
          heuristic: false,
        });
      }
    }

    // 2) 熵启发式（仅文本类文件，控制噪音）
    const extWhitelist = new Set(['.js', '.jsx', '.ts', '.tsx', '.py', '.rb', '.go', '.java', '.php', '.json', '.yml', '.yaml', '.env', '.sh', '.conf', '.ini', '.toml', '.vue', '.html']);
    if (extWhitelist.has(ext)) {
      // 测试目录降权（同正则分支语义）：测试 fixture 中的高熵令牌降为 low
      const inTestDir = TEST_DIR_RE.test(relPath);
      for (const { token, start } of extractTokenCandidates(text)) {
        if (isLikelySecret(token)) {
          const confidence = secretConfidence(token);
          if (confidence < 65) continue; // 低置信过滤
          const { line, col } = lineAndCol(text, start);
          // 去重：该行已被任何规则（正则）命中过则跳过，避免同一问题报两遍
          const dup = findings.some((f) => f.file === relPath && f.line === line && !f.heuristic);
          if (dup) continue;
          findings.push({
            ruleId: 'SECRET-GENERIC-TOKEN',
            severity: inTestDir ? 'low' : confidence >= 80 ? 'high' : 'medium',
            category: 'secret',
            title: '疑似高熵 Token / 密钥',
            message: `检测到高熵令牌（熵 ${shannonOf(token)}，置信度 ${confidence}%）${inTestDir ? '（测试目录，已降权）' : ''}`,
            file: relPath,
            line,
            col,
            snippet: excerptAround(text, start, 80),
            confidence,
            heuristic: true,
          });
        }
      }
    }
  }

  return { findings, summary: summarize(findings) };
}

function shannonOf(token) {
  // 轻量复用：避免循环 import 的样式问题
  const freq = new Map();
  for (const ch of token) freq.set(ch, (freq.get(ch) || 0) + 1);
  let ent = 0;
  for (const c of freq.values()) {
    const p = c / token.length;
    ent -= p * Math.log2(p);
  }
  return Number(ent.toFixed(2)); // 数值类型（阈值比较需要）
}

export function summarize(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const byCategory = {};
  for (const f of findings) {
    counts[f.severity] = (counts[f.severity] || 0) + 1;
    byCategory[f.category] = (byCategory[f.category] || 0) + 1;
  }
  const total = findings.length;
  const score = Math.max(0, Math.round(100 - total * 4 - (counts.critical || 0) * 12 - (counts.high || 0) * 6));
  return {
    total,
    counts,
    byCategory,
    securityScore: score,
    grade: score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F',
  };
}
