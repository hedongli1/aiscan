#!/usr/bin/env node
/**
 * aiscan 工具发现库 · 数据刷新脚本
 *
 * 作用：通过 GitHub Search API 按「方向 × 关键词」检索高星开源安全工具，
 *      生成 docs/data/tools.json，供 docs/index.html 读取渲染。
 *
 * 关键设计：
 *   1. 已收录工具的中文解读（summary）与标签（tags）按 full_name 增量保留 —— 自动刷新不会冲掉人工撰写的中文说明；
 *      新出现的工具先以英文原始描述展示，后续可人工补中文解读。
 *   2. 每个方向取 Star 降序 Top N（默认 12，可用环境变量 PER_CAT 调整）。
 *   3. 检索限流容错：403/429 退避重试，单个关键词失败不影响整体。
 *
 * 运行：GITHUB_TOKEN=xxx node scripts/fetch-tools.js
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const TOKEN = process.env.GITHUB_TOKEN || '';
const PER_CAT = Number(process.env.PER_CAT || 12);
const PER_QUERY = Number(process.env.PER_QUERY || 20);
const OUT_FILE = path.join(__dirname, '..', 'docs', 'data', 'tools.json');

const CATS = [
  { id: 'ai-security', name: 'AI/ML 安全', color: '#a78bfa',
    queries: ['ai security', 'llm security', 'llm guardrails', 'prompt injection', 'ai red teaming'] },
  { id: 'redteam', name: '红队 / 渗透', color: '#f87171',
    queries: ['red team', 'penetration testing', 'pentest agent'] },
  { id: 'ics-iot', name: '工控 / IoT 安全', color: '#fbbf24',
    queries: ['ics security', 'scada', 'plc exploitation', 'modbus security'] },
  { id: 'hunting-dfir', name: '威胁狩猎 / DFIR', color: '#34d399',
    queries: ['threat hunting', 'dfir'] },
  { id: 'cloud-container', name: '云 / 容器安全', color: '#38bdf8',
    queries: ['kubernetes security', 'cloud security'] },
  { id: 'code-audit', name: '代码审计 / 密钥检测', color: '#f472b6',
    queries: ['sast', 'secret scanning'] },
];

const sleep = ms => new Promise(r => setTimeout(r, ms));

function headers() {
  const h = { 'Accept': 'application/vnd.github+json', 'User-Agent': 'aiscan-tools-radar' };
  if (TOKEN) h['Authorization'] = 'Bearer ' + TOKEN;
  return h;
}

async function search(q) {
  const url = 'https://api.github.com/search/repositories?q=' + encodeURIComponent(q)
    + '&sort=stars&order=desc&per_page=' + PER_QUERY;
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      const res = await fetch(url, { headers: headers() });
      if (res.status === 403 || res.status === 429) {
        console.log('  · 触发限流(' + res.status + ')，退避 ' + attempt * 5 + 's 重试');
        await sleep(attempt * 5000);
        continue;
      }
      if (!res.ok) { console.log('  · 请求失败 ' + res.status + '：' + q); return []; }
      const j = await res.json();
      return j.items || [];
    } catch (e) {
      console.log('  · 异常：' + e.message);
      await sleep(3000);
    }
  }
  return [];
}

function norm(it) {
  const [owner, name] = String(it.full_name).split('/');
  return {
    full_name: it.full_name,
    name, owner,
    url: it.html_url,
    stars: it.stargazers_count,
    language: it.language || null,
    pushed_at: (it.pushed_at || '').slice(0, 10),
    desc: (it.description || '').trim(),
    topics: (it.topics || []).slice(0, 6),
  };
}

/** 读取上一版数据：既用于保留中文解读，也用于保留人工精选条目 */
function loadPrev() {
  const notes = {}, byCat = {};
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
  console.log('aiscan 工具发现库 · 开始刷新（token=' + (TOKEN ? '已配置' : '未配置') + '，每方向 Top ' + PER_CAT + '）');
  const { notes, byCat } = loadPrev();
  const categories = [];

  for (const c of CATS) {
    const pool = new Map();
    for (const q of c.queries) {
      const items = await search(q);
      console.log('[' + c.name + '] ' + q + ' → ' + items.length);
      items.forEach(it => { if (!pool.has(it.full_name)) pool.set(it.full_name, norm(it)); });
      await sleep(2200);
    }

    // 人工解读过的条目优先保留（避免每日刷新把精选项目冲掉），剩余名额由新抓取的高星项目补齐
    const curated = (byCat[c.id] || []).filter(t => t.summary);
    const curatedNames = new Set(curated.map(t => t.full_name));
    const fresh = [...pool.values()]
      .filter(t => !curatedNames.has(t.full_name))
      .sort((a, b) => b.stars - a.stars)
      .slice(0, Math.max(0, PER_CAT - curated.length))
      .map(t => Object.assign({}, t, { summary: '', tags: t.topics || [] }));

    const tools = curated.concat(fresh).slice(0, PER_CAT).map(t => {
      const n = notes[t.full_name];
      const tags = (t.tags && t.tags.length) ? t.tags : (n && n.tags ? n.tags : []);
      return Object.assign({}, t, { summary: t.summary || (n ? n.summary : ''), tags });
    });
    categories.push({ id: c.id, name: c.name, color: c.color, queries: c.queries, tools });
    console.log('  == ' + c.name + '：收录 ' + tools.length + ' 个（精选保留 ' + curated.length
      + '，新抓取 ' + fresh.length + '，候选 ' + pool.size + '）');
  }

  const total = categories.reduce((n, c) => n + c.tools.length, 0);
  const data = {
    meta: {
      source: 'GitHub Search API',
      updated_at: new Date().toISOString().slice(0, 10),
      total,
      note: '由 scripts/fetch-tools.js 定时刷新；已收录工具的中文解读在刷新时增量保留',
    },
    categories,
  };

  fs.mkdirSync(path.dirname(OUT_FILE), { recursive: true });
  fs.writeFileSync(OUT_FILE, JSON.stringify(data, null, 1) + '\n', 'utf8');
  console.log('已写入 ' + OUT_FILE + '（共 ' + total + ' 个工具）');
})().catch(e => { console.error(e); process.exit(1); });
