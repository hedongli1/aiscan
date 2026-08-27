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

// ── 巡检主流程 ─────────────────────────────────────────
// options.minSeverity: 报 Issue 的最低严重级（默认 high）
// options.issueRepo:   Issue 开在哪个仓库（默认 aiscan 自己——因为 GITHUB_TOKEN 只有本仓库写权限；
//                      跨仓库开 Issue 需在 workflow 里配 PATROL_TOKEN secret 并传 issueRepo 之外的仓库）
export async function patrol({ token, minSeverity = 'high', dryRun = false, issueRepo = null } = {}) {
  if (!token) throw new Error('patrol 需要 GITHUB_TOKEN');
  const order = { low: 0, medium: 1, high: 2, critical: 3 };
  const threshold = order[minSeverity] ?? 2;

  const repos = await listRepos(token);
  console.log(`aiscan-patrol: 待巡检 ${repos.length} 个仓库`);

  const report = { scanned: repos.length, cleanRepos: 0, flaggedRepos: [], issuesOpened: 0, errors: [] };
  // Issue 目标仓库：默认开在巡检发起仓库（token 通常只有该仓库写权限）
  const issueTarget = issueRepo || (await gh('/user', token)).login + '/aiscan';

  for (const repo of repos) {
    const fullName = repo.full_name;
    let tmp = null;
    try {
      tmp = await fs.mkdtemp(path.join(os.tmpdir(), `aiscan-patrol-`));
      shallowClone(repo.clone_url, token, tmp);
      // 仓库根若有 .aiscanignore 会被 scanner 自动读取（cwd 即克隆目录）
      const { findings, summary } = await scanDirectory(tmp);

      const serious = findings.filter((f) => order[f.severity] >= threshold);
      if (serious.length === 0) {
        report.cleanRepos += 1;
        console.log(`  ✅ ${fullName}: ${findings.length} 个低级发现 / 评分 ${summary.securityScore}（${summary.grade}）→ 干净`);
        continue;
      }

      console.log(`  🚨 ${fullName}: ${serious.length} 个 ≥ ${minSeverity} 发现`);
      report.flaggedRepos.push({ repo: fullName, findings: serious.length, summary });

      if (!dryRun) {
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