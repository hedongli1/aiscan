// tools/convert-gitleaks.js — 把 gitleaks.toml 规则转换为 aiscan JS 规则数组
// 零依赖：内置一个只覆盖 gitleaks 所用 TOML 子集的解析器。
// 用法: node tools/convert-gitleaks.js > lib/rules/gitleaks.js
// 来源: https://github.com/gitleaks/gitleaks (MIT License)

import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SRC = path.join(__dirname, 'gitleaks-source.toml');

// ── 轻量 TOML 子集解析（仅支持 gitleaks config 用到的语法）──────
// 支持: [[rules]] 数组表、key = value、'''多行字符串'''、普通字符串、
//       数字、[a, b] 数组。忽略注释与顶层非 rules 表。
function parseTomlSubset(text) {
  const rules = [];
  let current = null;
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    let line = lines[i];
    // 去注释（保守：只在行外字符串无关处去 # 注释）
    const commentIdx = findComment(line);
    if (commentIdx >= 0) line = line.slice(0, commentIdx);
    line = line.trim();
    if (!line) continue;

    if (line === '[[rules]]') {
      current = {};
      rules.push(current);
      continue;
    }
    // 跳过非 rules 的表头（如 [allowlist]）
    if (line.startsWith('[')) {
      current = null;
      continue;
    }
    if (!current) continue; // 顶层或 allowlist 里的字段，忽略

    const eq = line.indexOf('=');
    if (eq === -1) continue;
    const key = line.slice(0, eq).trim();
    let value = line.slice(eq + 1).trim();

    // 多行字符串 '''...'''
    if (value.startsWith("'''")) {
      const buf = [];
      let rest = value.slice(3);
      // 单行闭合 '''regex'''
      if (rest.endsWith("'''") && rest.indexOf("'''", 0) <= rest.length - 3) {
        current[key] = rest.slice(0, -3);
        continue;
      }
      buf.push(rest);
      i++;
      while (i < lines.length) {
        const l = lines[i];
        const close = l.indexOf("'''");
        if (close >= 0) {
          buf.push(l.slice(0, close));
          break;
        }
        buf.push(l);
        i++;
      }
      current[key] = buf.join('\n');
      continue;
    }
    // 普通字符串
    if (value.startsWith('"') && value.endsWith('"') && value.length >= 2) {
      current[key] = value.slice(1, -1);
      continue;
    }
    // 数组
    if (value.startsWith('[') && value.endsWith(']')) {
      current[key] = value
        .slice(1, -1)
        .split(',')
        .map((s) => s.trim().replace(/^["']|["']$/g, ''))
        .filter(Boolean);
      continue;
    }
    // 数字
    const num = Number(value);
    if (!Number.isNaN(num) && /^[\d.]+$/.test(value)) {
      current[key] = num;
      continue;
    }
    // 布尔
    if (value === 'true' || value === 'false') {
      current[key] = value === 'true';
      continue;
    }
    current[key] = value;
  }
  return rules;
}

// 找行内注释位置（避开引号内的 #）
function findComment(line) {
  let inStr = false;
  let quote = '';
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (inStr) {
      if (ch === quote) inStr = false;
    } else if (ch === '"' || ch === "'") {
      inStr = true;
      quote = ch;
    } else if (ch === '#') {
      return i;
    }
  }
  return -1;
}

// ── gitleaks → aiscan 规则映射 ─────────────────────────
// Go RE2 → JS RegExp 语法适配：
//  - (?i) 内联忽略大小写 → 移除并给正则加 'i' flag
//  - (?P<name>...) 命名组 → (?:...) 非捕获（JS 不支持 (?P)）
//  - (?s) 单行模式 → JS 默认语义近似，直接移除
function adaptRegex(src) {
  let flags = '';
  let out = src;
  if (out.includes('(?i)')) {
    flags += 'i';
    out = out.replace(/\(\?i\)/g, '');
  }
  // Go 局部大小写控制 → JS 等价（近似）：
  //   (?i:xxx)  → 内联化为整体 i flag 的分组（简化：保留分组内容）
  //   (?-i:xxx) → 大小写敏感分组：因整条规则可能已带 i，改写为字符类近似不可行，
  //               保守做法是把整条规则降为不带 i 的精确匹配（语义偏严不偏松）
  out = out.replace(/\(\?i:([^()]*(?:\([^()]*\)[^()]*)*)\)/g, '$1');
  if (/\(\?-i:/.test(out)) {
    // 去掉 (?-i: 分组标记本身；若整条规则靠 (?i) 起大小写不敏感，此时撤销全局 i
    out = out.replace(/\(\?-i:([^()]*(?:\([^()]*\)[^()]*)*)\)/g, '$1');
    flags = flags.replace('i', '');
  }
  // POSIX 字符类 → JS 等价
  out = out
    .replace(/\[\[:alnum:\]\]/g, '[A-Za-z0-9]')
    .replace(/\[\[:digit:\]\]/g, '[0-9]')
    .replace(/\[\[:alpha:\]\]/g, '[A-Za-z]')
    .replace(/\[\[:upper:\]\]/g, '[A-Z]')
    .replace(/\[\[:lower:\]\]/g, '[a-z]')
    .replace(/\[\[:xdigit:\]\]/g, '[0-9A-Fa-f]');
  out = out.replace(/\(\?P<[^>]+>/g, '(?:');
  out = out.replace(/\(\?s\)/g, '');
  return { source: out, flags };
}

// 严重级映射：gitleaks 无级别，按服务危害度分级
function severityFor(id) {
  // 云厂商主凭证 = critical
  const criticalIds = /^(aws|gcp|google|azure|github|gitlab|stripe|private-key|openai|anthropic|slack-webhook|telegram-bot-api)/;
  if (criticalIds.test(id)) return 'critical';
  return 'high';
}

function titleFor(rule) {
  const desc = rule.description || rule.id;
  // 描述已是完整句，转成简短标题
  return `疑似泄漏：${rule.id}`;
}

function convert(rules) {
  const out = [];
  const seen = new Set();
  for (const r of rules) {
    if (!r.id || !r.regex) continue; // 无正则的规则（如纯 entropy 组合）跳过
    if (seen.has(r.id)) continue; // 重复 id 跳过
    seen.add(r.id);
    // Go RE2 → JS 语法适配 + 合法性校验
    const { source, flags } = adaptRegex(r.regex);
    let re;
    try {
      re = new RegExp(source, flags);
    } catch {
      continue; // 仍不兼容的跳过
    }
    out.push({
      id: `GL-${r.id}`,
      severity: severityFor(r.id),
      category: 'secret',
      title: titleFor(r),
      description: r.description || '',
      regex: re,
      // 适配后的 flags 也要保留（生成 JS 时用 source+flags）
      _source: source,
      _flags: flags,
      // gitleaks 的 entropy 阈值（对捕获组算熵，这里记下来由 scanner 按需使用）
      entropy: r.entropy ?? null,
      // keywords 快速预筛：文本不含关键词时直接跳过正则（性能优化）
      keywords: Array.isArray(r.keywords) ? r.keywords : null,
      message: r.description ? r.description.slice(0, 120) : `检测到疑似 ${r.id} 格式的密钥`,
      recommendation: '立即轮换该凭证，改用环境变量/密钥管理服务注入；用 git filter-repo 清理历史',
      cwe: 'CWE-798',
      source: 'gitleaks',
    });
  }
  return out;
}

// ── 主流程：解析 → 转换 → 生成 JS 模块 ────────────────
// 源 toml 不入库（其中的 gitleaks 官方 allowlist 测试样本会触发 GitHub secret scanning 误报），
// 本地缺失时自动从 gitleaks 官方仓库下载。
import { writeFileSync as _wf, existsSync } from 'node:fs';
let toml;
if (existsSync(SRC)) {
  toml = readFileSync(SRC, 'utf8');
} else {
  console.log('本地无 gitleaks-source.toml，从官方仓库下载…');
  const res = await fetch(
    'https://raw.githubusercontent.com/gitleaks/gitleaks/main/config/gitleaks.toml'
  ).catch(() => null);
  if (!res || !res.ok) {
    // raw 不可达时走 GitHub API 通道
    const api = await fetch('https://api.github.com/repos/gitleaks/gitleaks/contents/config/gitleaks.toml', {
      headers: { Accept: 'application/vnd.github.raw+json' },
    }).catch(() => null);
    if (!api || !api.ok) {
      console.error('无法获取 gitleaks 规则源（raw 与 API 通道均失败）');
      process.exit(1);
    }
    toml = await api.text();
  } else {
    toml = await res.text();
  }
  writeFileSync(SRC, toml, 'utf8'); // 缓存到本地（已被 .gitignore 排除，不会入库）
  console.log(`已下载并缓存（${toml.length} 字节）`);
}
const parsed = parseTomlSubset(toml);
const converted = convert(parsed);

// 生成 lib/rules/gitleaks.js（正则以字符串字面量保留，运行时编译）
const lines = [
  '// ⚠️ 本文件由 tools/convert-gitleaks.js 自动生成，请勿手改',
  '// 规则来源: gitleaks (https://github.com/gitleaks/gitleaks) — MIT License',
  '// 二次创作: aiscan 移植版（保留原 regex/entropy/keywords 语义）',
  `// 生成时间: ${new Date().toISOString().slice(0, 10)} · 共 ${converted.length} 条`,
  '',
  '// 每条规则的 regex 为字符串，由 RULES 加载时编译（避免模块加载即全量编译）',
  'export const GITLEAKS_RULES = [',
];
for (const r of converted) {
  const re = String(r._source).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
  const flags = r._flags || '';
  const kw = r.keywords ? JSON.stringify(r.keywords) : 'null';
  const ent = r.entropy ?? 'null';
  const desc = String(r.description).replace(/\\/g, '\\\\').replace(/'/g, "\\'").slice(0, 200);
  const msg = String(r.message).replace(/\\/g, '\\\\').replace(/'/g, "\\'").slice(0, 150);
  lines.push(`  { id: '${r.id}', severity: '${r.severity}', category: 'secret', title: ${JSON.stringify(r.title)}, description: '${desc}', regex: '${re}', flags: '${flags}', entropy: ${ent}, keywords: ${kw}, message: '${msg}', recommendation: '立即轮换该凭证，改用环境变量/密钥管理服务注入；用 git filter-repo 清理历史', cwe: 'CWE-798', source: 'gitleaks' },`);
}
lines.push('];');
lines.push('');

const outFile = path.join(__dirname, '..', 'lib', 'rules', 'gitleaks.js');
writeFileSync(outFile, lines.join('\n'), 'utf8');
console.error(`✅ 转换完成: ${parsed.length} 条原始规则 → ${converted.length} 条 JS 规则（跳过 ${parsed.length - converted.length} 条无正则/不兼容）`);
console.error(`输出: lib/rules/gitleaks.js`);
