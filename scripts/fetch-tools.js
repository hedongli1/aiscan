#!/usr/bin/env node
/**
 * aiscan 工具发现库 · 数据刷新脚本
 *
 * 作用：通过 GitHub Search API 按「方向 × 多组关键词（OR 组合）」检索高星开源安全工具，
 *      生成 docs/data/tools.json，供 docs/index.html 渲染「方向 Tab + 卡片列表」。
 *
 * 关键设计：
 *   1. 抓取扩容：每个方向配置多组 OR 组合关键词（每组最多 4 个词，符合 GitHub 查询算子限制），
 *      单次请求 100 条 + 按需翻页，按 full_name 去重后按 Star 降序取 Top PER_CAT（默认 40，上限 1000）。
 *   2. 增量保留：已收录工具的人工中文解读（summary）与标签（tags）按 full_name 增量保留，
 *      人工解读过的条目优先占位，每日刷新不会把精选项目与中文说明冲掉。
 *   3. 字段补全：卡片需要的 license / archived / topics / language / pushed_at 全部落库，
 *      前端无需二次请求即可完整渲染。
 *   4. 限流容错：403 / 429 依据 x-ratelimit-reset 退避重试；单个关键词失败不影响整体。
 *
 * 运行：GITHUB_TOKEN=xxx node scripts/fetch-tools.js
 * 可选环境变量：
 *   PER_CAT        每方向收录上限（默认 40，最大 1000）
 *   PER_QUERY      单次请求条数（默认 100）
 *   MAX_PAGES      单关键词最多翻页数（默认 2）
 *   REQUEST_DELAY  请求间隔毫秒（默认：带 token 2200，无 token 7000）
 */
const fs = require('node:fs');
const path = require('node:path');

const TOKEN = process.env.GITHUB_TOKEN || process.env.GH_TOKEN || '';
const PER_CAT = Math.min(1000, Math.max(1, Number(process.env.PER_CAT || 40)));
const PER_QUERY = Math.min(100, Math.max(1, Number(process.env.PER_QUERY || 100)));
const MAX_PAGES = Math.max(1, Number(process.env.MAX_PAGES || 2));
const REQUEST_DELAY = Number(process.env.REQUEST_DELAY || (TOKEN ? 2200 : 7000));

const ROOT = path.join(__dirname, '..');
const OUT_FILE = path.join(ROOT, 'docs', 'data', 'tools.json');

const CATS = [
  {
    id: 'ai-security', name: 'AI/ML 安全', color: '#a78bfa',
    queries: [
      'ai security OR llm security OR genai security',
      'prompt injection OR llm guardrails OR jailbreak detection',
      'ai red teaming OR llm pentesting OR ai vulnerability scanner',
      'ai agent security OR mcp security OR agent security scanner',
    ],
  },
  {
    id: 'redteam', name: '红队 / 渗透', color: '#f87171',
    queries: [
      'red team OR red teaming OR adversary simulation',
      'penetration testing OR pentest OR offensive security',
      'c2 framework OR command and control OR post exploitation',
      'attack surface management OR bug bounty automation OR exploitation framework',
    ],
  },
  {
    id: 'ics-iot', name: '工控 / IoT 安全', color: '#fbbf24',
    queries: [
      'ics security OR industrial control system security OR ot security',
      'scada security OR modbus security OR industrial protocol',
      'plc exploitation OR plc security OR industrial exploitation',
      'iot security OR embedded security OR firmware analysis',
    ],
  },
  {
    id: 'hunting-dfir', name: '威胁狩猎 / DFIR', color: '#34d399',
    queries: [
      'threat hunting OR dfir OR threat detection',
      'incident response OR digital forensics OR forensic analysis',
      'edr OR endpoint detection OR siem OR log analysis',
      'malware analysis OR memory forensics OR yara',
    ],
  },
  {
    id: 'cloud-container', name: '云 / 容器安全', color: '#38bdf8',
    queries: [
      'kubernetes security OR k8s security OR cluster security',
      'cloud security OR cloud native security OR cspm',
      'container security OR docker security OR image scanning',
      'devsecops OR infrastructure security OR zero trust',
    ],
  },
  {
    id: 'code-audit', name: '代码审计 / 密钥检测', color: '#f472b6',
    queries: [
      'sast OR static code analysis OR code scanning',
      'secret scanning OR credential scanning OR hardcoded secrets',
      'code audit OR vulnerability scanner OR dependency scanning',
      'supply chain security OR sbom OR software composition analysis',
    ],
  },
];

const sleep = ms => new Promise(r => setTimeout(r, ms));

function headers() {
  const h = { 'Accept': 'application/vnd.github+json', 'User-Agent': 'aiscan-tools-radar' };
  if (TOKEN) h['Authorization'] = 'Bearer ' + TOKEN;
  return h;
}

/** 单次请求，带限流退避；返回 items 数组（失败返回空数组） */
async function request(url, label) {
  for (let attempt = 1; attempt <= 4; attempt++) {
    try {
      const res = await fetch(url, { headers: headers() });
      if (res.status === 403 || res.status === 429) {
        const remain = res.headers.get('x-ratelimit-remaining');
        const reset = Number(res.headers.get('x-ratelimit-reset') || 0);
        let wait = attempt * 5000;
        if (remain === '0' && reset > 0) wait = Math.max(wait, reset * 1000 - Date.now() + 2500);
        wait = Math.min(wait, 75000);
        console.log('  · 限流(' + res.status + ')，等待 ' + Math.round(wait / 1000) + 's 后重试：' + label);
        await sleep(wait);
        continue;
      }
      if (!res.ok) { console.log('  · 请求失败 ' + res.status + '：' + label); return []; }
      const j = await res.json();
      return j.items || [];
    } catch (e) {
      console.log('  · 异常：' + e.message + '（' + label + '）');
      await sleep(3000 * attempt);
    }
  }
  console.log('  · 放弃：' + label);
  return [];
}

/** 多页检索：按 Star 降序取够 need 条或翻到 MAX_PAGES */
async function search(q, need) {
  const out = [];
  for (let page = 1; page <= MAX_PAGES; page++) {
    const url = 'https://api.github.com/search/repositories?q=' + encodeURIComponent(q)
      + '&sort=stars&order=desc&per_page=' + PER_QUERY + '&page=' + page;
    const items = await request(url, q + ' #p' + page);
    if (!items.length) break;
    out.push(...items);
    if (out.length >= need || items.length < PER_QUERY) break;
    await sleep(REQUEST_DELAY);
  }
  return out;
}

function cleanLicense(it) {
  const lic = it.license || null;
  if (!lic) return null;
  const id = lic.spdx_id || lic.key || null;
  if (!id || id === 'NOASSERTION') return null;
  return id;
}

function norm(it) {
  const [owner, name] = String(it.full_name || '').split('/');
  return {
    full_name: it.full_name,
    name: name || it.full_name,
    owner: owner || '',
    url: it.html_url,
    stars: it.stargazers_count || 0,
    forks: it.forks_count || 0,
    language: it.language || null,
    pushed_at: (it.pushed_at || '').slice(0, 10),
    desc: String(it.description || '').replace(/\s+/g, ' ').trim(),
    topics: (it.topics || []).slice(0, 8),
    license: cleanLicense(it),
    archived: !!it.archived,
  };
}

/** 读取上一版数据：用于保留人工中文解读与精选条目 */
function loadPrev() {
  const notes = {};
  const byCat = {};
  try {
    const old = JSON.parse(fs.readFileSync(OUT_FILE, 'utf8'));
    (old.categories || []).forEach(c => {
      byCat[c.id] = c.tools || [];
      (c.tools || []).forEach(t => {
        if (t.summary) notes[t.full_name] = { summary: t.summary, tags: t.tags || [] };
      });
    });
  } catch (e) { /* 首次运行无旧数据 */ }
  return { notes, byCat };
}

(async () => {
  console.log('aiscan 工具发现库 · 开始刷新（token=' + (TOKEN ? '已配置' : '未配置')
    + '，每方向上限 ' + PER_CAT + '，单关键词 ' + PER_QUERY + ' 条 × 最多 ' + MAX_PAGES + ' 页）');

  const { notes, byCat } = loadPrev();
  const categories = [];

  for (const c of CATS) {
    const pool = new Map();
    const need = PER_CAT * 2;
    for (const q of c.queries) {
      const items = await search(q, need);
      console.log('[' + c.name + '] ' + q + ' → ' + items.length);
      items.forEach(it => {
        if (!it || !it.full_name) return;
        const t = norm(it);
        const ex = pool.get(t.full_name);
        if (!ex || t.stars > ex.stars) pool.set(t.full_name, t);
      });
      await sleep(REQUEST_DELAY);
    }

    const tools = [];
    const seen = new Set();

    // 1) 人工解读过的条目优先保留（若本次仍检索到，则用最新元数据刷新，仅保留人工 summary/tags）
    (byCat[c.id] || []).forEach(old => {
      if (!old.summary || seen.has(old.full_name)) return;
      const fresh = pool.get(old.full_name);
      const [o, n] = String(old.full_name || '').split('/');
      // 未在本次检索命中的历史条目：按 norm() 的字段口径补全，保证卡片字段完整
      const base = fresh || {
        full_name: old.full_name, name: old.name || n || old.full_name, owner: old.owner || o || '',
        url: old.url, stars: old.stars || 0, forks: old.forks || 0,
        language: old.language || null, pushed_at: old.pushed_at || '', desc: old.desc || '',
        topics: old.topics || [], license: old.license || null, archived: !!old.archived,
      };
      tools.push(Object.assign({}, base, {
        summary: old.summary,
        tags: (old.tags && old.tags.length) ? old.tags : (base.topics || []),
      }));
      seen.add(old.full_name);
    });
    const curatedCount = tools.length;

    // 2) 新抓取按 Star 降序补齐至 PER_CAT，并回填历史中文解读
    const fresh = [...pool.values()]
      .filter(t => !seen.has(t.full_name))
      .sort((a, b) => b.stars - a.stars)
      .slice(0, Math.max(0, PER_CAT - tools.length));
    fresh.forEach(t => {
      const n = notes[t.full_name];
      tools.push(Object.assign({}, t, {
        summary: (n && n.summary) || '',
        tags: (n && n.tags && n.tags.length) ? n.tags : (t.topics || []).slice(0, 4),
      }));
      seen.add(t.full_name);
    });

    // 3) 全量按 Star 降序，保证卡片默认排序即最优
    tools.sort((a, b) => (b.stars || 0) - (a.stars || 0));

    categories.push({ id: c.id, name: c.name, color: c.color, queries: c.queries, tools });
    console.log('  == ' + c.name + '：收录 ' + tools.length + ' 个（人工解读保留 ' + curatedCount
      + '，新抓取 ' + fresh.length + '，候选池 ' + pool.size + '）');
  }

  const total = categories.reduce((n, c) => n + c.tools.length, 0);
  const data = {
    meta: {
      source: 'GitHub Search API',
      updated_at: new Date().toISOString().slice(0, 10),
      total,
      per_cat: PER_CAT,
      directions: categories.map(c => c.id),
      note: '由 scripts/fetch-tools.js 每日定时刷新；已收录工具的人工中文解读按 full_name 增量保留',
    },
    categories,
  };

  fs.mkdirSync(path.dirname(OUT_FILE), { recursive: true });
  fs.writeFileSync(OUT_FILE, JSON.stringify(data, null, 1) + '\n', 'utf8');
  console.log('已写入 ' + OUT_FILE + '（共 ' + total + ' 个工具）');
})().catch(e => { console.error(e); process.exit(1); });
