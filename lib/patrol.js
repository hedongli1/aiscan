// aiscan · 自动巡检（patrol）
// 在 GitHub Actions 定时运行：列出账号全部仓库 → 逐个浅克隆 → 扫描 → 发现高危自动开 Issue。
// 纯 Node 内置模块（fetch 是 Node 18+ 内置），零依赖。

import { promises as fs } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execFileSync } from 'node:child_process';
import { scanDirectory } from './scanner.js';

const GITHUB_API = 'https://api.github.com';

// ── GitHub API 薄封装 ──────────────────────────────────
async function gh(apiPath, token, init = {}) {
  const res = await fetch(`${GITHUB_API}${apiPath}`, {
    ...init,
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      ...(init.headers || {}),
    },
  });
  if (!res.ok) {
    throw new Error(`GitHub API ${apiPath} → HTTP ${res.status}: ${(await res.text()).slice(0, 200)}`);
  }
  return res.json();
}

// 列出账号下全部仓库（owner 名下，含 private，随 token 权限）
export async function listRepos(token) {
  const repos = [];
  let page = 1;
  while (true) {
    const batch = await gh(
      `/user/repos?per_page=100&page=${page}&affiliation=owner&sort=full_name`,
      token
    );
    if (!batch.length) break;
    repos.push(...batch);
    if (batch.length < 100) break;
    page += 1;
  }
  // 排除 fork 与空仓库，只巡检自己拥有的源码仓库
  return repos.filter((r) => !r.fork && r.size > 0);
}

// 浅克隆一个仓库到临时目录
function shallowClone(cloneUrl, token, dest) {
  // token 内嵌 URL 认证（仅存在于本进程内存，不落盘）
  const authed = cloneUrl.replace('https://', `https://x-access-token:${token}@`);
  execFileSync('git', ['clone', '--depth', '1', authed, dest], {
    stdio: ['ignore', 'ignore', 'ignore'], // 静默，避免 token 出现在 stderr
  });
}

// 查 issueRepo 中是否已有某被巡检仓库的未关闭 patrol Issue（按标题判重，防重复轰炸）
async function hasOpenPatrolIssue(issueRepo, token, watchedRepo) {
  const issues = await gh(
    `/repos/${issueRepo}/issues?state=open&labels=aiscan-patrol&per_page=50`,
    token
  );
  return issues.find((i) => i.title.includes(watchedRepo)) || null;
}

// 在 issueRepo 开巡检 Issue（汇总 watchedRepo 的发现；snippet 已由 scanner 层脱敏）
async function openPatrolIssue(issueRepo, watchedRepo, findings, token) {
  const crit = findings.filter((f) => f.severity === 'critical').length;
  const high = findings.filter((f) => f.severity === 'high').length;
  const title = `[aiscan-patrol] ${watchedRepo} 发现 ${crit} critical / ${high} high`;
  const lines = [
    '🛡️ **aiscan 自动巡检发现安全问题**',
    '',
    `仓库：${watchedRepo}`,
    `严重级分布：🔴 critical=${crit}  🟠 high=${high}`,
    '',
    '| 严重级 | 规则 | 位置 | 摘要 |',
    '| --- | --- | --- | --- |',
    ...findings
      .filter((f) => f.severity === 'critical' || f.severity === 'high')
      .map((f) => `| ${f.severity} | ${f.ruleId} | \`${f.file}:${f.line}\` | ${f.snippet.slice(0, 60)} |`),
    '',
    '> 由 aiscan-patrol 定时任务自动扫描生成。snippet 已脱敏。处理后可关闭本 Issue；若为已知误报，请在对应仓库添加 `.aiscanignore`。',
    '',
    '*完整报告见 workflow run 摘要。*',
  ];
  return gh(`/repos/${issueRepo}/issues`, token, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ title, body: lines.join('\n'), labels: ['aiscan-patrol', 'security'] }),
  });
}

// 列出指定用户/组织的全部公开仓库（第三方巡检用，非本人账号）
export async function listPublicRepos(owner, token) {
  const repos = [];
  let page = 1;
  while (true) {
    const batch = await gh(
      `/users/${owner}/repos?per_page=100&page=${page}&sort=full_name&type=owner`,
      token
    );
    if (!batch.length) break;
    repos.push(...batch);
    if (batch.length < 100) break;
    page += 1;
  }
  return repos.filter((r) => !r.fork && r.size > 0);
}

// 获取单个仓库元数据（第三方单仓库模式）
async function getRepo(fullName, token) {
  return gh(`/repos/${fullName}`, token);
}

// ── 自动发现开源目标 ───────────────────────────────────
// GitHub Search API：按 star 排序的近期活跃 JS 仓库，剔除 fork 与超大仓库。
// seed 用于每日轮换（同一天结果稳定，不同天扫不同仓库，逐步扩大覆盖）。
export async function discoverRepos(token, { count = 20, seed = '', maxKb = 50000 } = {}) {
  const monthAgo = new Date(Date.now() - 30 * 24 * 3600 * 1000).toISOString().slice(0, 10);
  const q = `language:javascript pushed:>${monthAgo} size:<${maxKb}`;
  // seed 换页：不同天翻不同页，天然轮换（每天最多扫 count 个）
  const pageBase = seedToNum(seed) % 5; // 前 5 页（star 最高的活跃区）
  const candidates = [];
  for (let p = 0; p < 2; p++) {
    const page = pageBase + p + 1;
    const res = await gh(
      `/search/repositories?q=${encodeURIComponent(q)}&sort=stars&order=desc&per_page=50&page=${page}`,
      token
    );
    if (Array.isArray(res.items)) candidates.push(...res.items);
    if (candidates.length >= count * 4) break; // 多取一些备筛选
  }
  // 过滤：非 fork、非自己账号（自扫保护在主流程还有一层）、去重
  const seen = new Set();
  return candidates.filter((r) => {
    if (r.fork || r.size <= 0) return false;
    if (seen.has(r.full_name)) return false;
    seen.add(r.full_name);
    return true;
  }).slice(0, count);
}

// 日期字符串 → 小整数（做页码种子；不用 Math.random 保持同一天稳定可复现）
function seedToNum(seed) {
  let h = 0;
  for (const ch of String(seed)) h = (h * 31 + ch.charCodeAt(0)) >>> 0;
  return h;
}

// ── 巡检主流程 ─────────────────────────────────────────
// options.minSeverity:   报 Issue 的最低严重级（默认 high）
// options.issueRepo:     Issue 开在哪个仓库（默认 aiscan 自己——因为 GITHUB_TOKEN 只有本仓库写权限）
// options.specificRepo:  'owner/repo' 形式，巡检单个指定仓库（第三方）
// options.targetOwners:  ['owner1','owner2'] 形式，巡检这些用户的全部公开仓库（第三方）
// 第三方边界：只读扫描（匿名克隆公开仓库），绝不开 Issue（那是滥用）。
export async function patrol({
  token,
  minSeverity = 'high',
  dryRun = false,
  issueRepo = null,
  specificRepos = null,
  targetOwners = null,
  targetsFile = null,
  maxPerDay = null,
  autoDiscover = false,
  seed = null,
} = {}) {
  if (!token) throw new Error('patrol 需要 GITHUB_TOKEN');
  const order = { low: 0, medium: 1, high: 2, critical: 3 };
  const threshold = order[minSeverity] ?? 2;

  // targetsFile 模式：从 patrol-targets.json 读配置（定时巡检默认走这里，不扫自己账号）
  // 支持 { autoDiscover, maxPerDay, repos } 三项：autoDiscover=true 时忽略 repos 用自动发现
  if (!specificRepos && !targetOwners && targetsFile) {
    try {
      const cfg = JSON.parse(await fs.readFile(targetsFile, 'utf8'));
      if (typeof cfg.maxPerDay === 'number' && maxPerDay == null) maxPerDay = cfg.maxPerDay;
      if (cfg.autoDiscover) {
        autoDiscover = true;
      } else {
        specificRepos = Array.isArray(cfg.repos) ? cfg.repos.filter(Boolean) : null;
      }
    } catch (err) {
      throw new Error(`读取目标清单失败（${targetsFile}）: ${err.message}`);
    }
  }

  // 目标模式：自动发现 / 多仓库 / 多 owner 公开仓库 / 默认自己账号
  let repos = [];
  let thirdParty = false;
  if (autoDiscover) {
    const day = seed || new Date().toISOString().slice(0, 10); // 以日期为种子：同天稳定、隔天轮换
    repos = await discoverRepos(token, { count: maxPerDay ?? 5, seed: day });
    thirdParty = true;
    console.log(`  ↳ [自动发现] 以 ${day} 为种子，从 GitHub Search 选出 ${repos.length} 个活跃开源仓库`);
  } else if (specificRepos && specificRepos.length) {
    for (const r of specificRepos) repos.push(await getRepo(r, token));
    thirdParty = true;
  } else if (targetOwners && targetOwners.length) {
    for (const owner of targetOwners) {
      repos.push(...(await listPublicRepos(owner, token)));
    }
    thirdParty = true;
  } else {
    repos = await listRepos(token);
  }

  // 硬保护：第三方模式若混入 token 所属用户自己的仓库，直接剔除（用户明确要求永不扫自己）
  if (thirdParty) {
    let myLogin = null;
    try {
      myLogin = (await gh('/user', token)).login;
    } catch {
      // token 无 user 读权限时跳过此保护（匿名场景不会走到这里）
    }
    if (myLogin) {
      const before = repos.length;
      repos = repos.filter((r) => !r.full_name.startsWith(myLogin + '/'));
      const skipped = before - repos.length;
      if (skipped > 0) console.log(`  ↳ [保护] 已剔除 ${skipped} 个属于你自己（${myLogin}）的仓库`);
    }
  }

  // 每日限额：maxPerDay 限制了实际扫描数（发现/列表可以更长，扫够即停）
  if (maxPerDay != null && repos.length > maxPerDay) {
    console.log(`  ↳ [限额] 每日上限 ${maxPerDay} 个，超出 ${repos.length - maxPerDay} 个留到以后轮换`);
    repos = repos.slice(0, maxPerDay);
  }

  console.log(`aiscan-patrol: 待巡检 ${repos.length} 个仓库${thirdParty ? '（第三方只读模式，不开 Issue）' : ''}${maxPerDay != null ? `（每日限额 ${maxPerDay}）` : ''}`);

  const report = { scanned: repos.length, cleanRepos: 0, flaggedRepos: [], issuesOpened: 0, errors: [], thirdParty };
  // Issue 目标仓库：第三方模式绝不向他人仓库开 Issue（滥用），结果仅报告
  const issueTarget = thirdParty
    ? null
    : issueRepo || (await gh('/user', token)).login + '/aiscan';

  for (const repo of repos) {
    const fullName = repo.full_name;
    let tmp = null;
    try {
      tmp = await fs.mkdtemp(path.join(os.tmpdir(), `aiscan-patrol-`));
      // 第三方公开仓库走匿名克隆（只读、无需也不该用用户 token）
      if (thirdParty) {
        execFileSync('git', ['clone', '--depth', '1', repo.clone_url, tmp], {
          stdio: ['ignore', 'ignore', 'ignore'],
        });
      } else {
        shallowClone(repo.clone_url, token, tmp);
      }
      // 仓库根若有 .aiscanignore 会被 scanner 自动读取（cwd 即克隆目录）
      const { findings, summary } = await scanDirectory(tmp);

      const serious = findings.filter((f) => order[f.severity] >= threshold);
      if (serious.length === 0) {
        report.cleanRepos += 1;
        console.log(`  ✅ ${fullName}: ${findings.length} 个低级发现 / 评分 ${summary.securityScore}（${summary.grade}）→ 干净`);
        continue;
      }

      console.log(`  🚨 ${fullName}: ${serious.length} 个 ≥ ${minSeverity} 发现`);
      report.flaggedRepos.push({ repo: fullName, findings: serious.length, summary, detail: serious });

      if (thirdParty) {
        // 第三方仓库：只报告，绝不开 Issue（向他人仓库开 Issue 是滥用）
        console.log(`     ↳ [第三方只读] 结果仅入报告，不开 Issue`);
      } else if (!dryRun) {
        const existing = await hasOpenPatrolIssue(issueTarget, token, fullName);
        if (existing) {
          console.log(`     ↳ 已有未关闭 patrol Issue #${existing.number}，跳过（防重复轰炸）`);
        } else {
          const issue = await openPatrolIssue(issueTarget, fullName, serious, token);
          report.issuesOpened += 1;
          console.log(`     ↳ 已开 Issue #${issue.number} 于 ${issueTarget}`);
        }
      } else {
        console.log(`     ↳ [dry-run] 本应开 Issue（标题: [aiscan-patrol] ${fullName} ...）`);
      }
    } catch (err) {
      report.errors.push({ repo: fullName, error: err.message });
      console.error(`  ❌ ${fullName}: ${err.message}`);
    } finally {
      if (tmp) await fs.rm(tmp, { recursive: true, force: true }).catch(() => {});
    }
  }

  return report;
}