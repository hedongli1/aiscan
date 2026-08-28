#!/usr/bin/env node
// aiscan CLI · 入口
import { scanDirectory, summarize } from '../lib/scanner.js';
import { patrol } from '../lib/patrol.js';
import { RULES } from '../lib/rules/index.js';

const VERSION = '0.4.0';

function usage() {
  console.log(`aiscan — AI 辅助代码安全审计（零依赖）v${VERSION}

用法:
  aiscan [路径...] [--json] [--sarif] [--report html] [--severity=high] [--quiet]

选项:
  --version       输出版本号
  --json          输出 JSON 结果
  --sarif         输出 SARIF 2.1.0（GitHub Security 原生支持）
  --report html   生成 HTML 报告（security-report.html）
  --severity=X    只显示 ≥ X 的发现（critical|high|medium|low）
  --fail-on=X     发现 ≥ X 级别问题时以退出码 1 结束（供 CI 门禁）
  --ignore-file=P  指定 .aiscanignore 文件路径（默认从当前目录查找）
  --quiet         仅输出摘要
  --patrol        自动巡检模式：扫描 GitHub 账号下全部仓库，发现 ≥ 指定级别问题自动开 Issue
  --patrol-repo=R 扫描指定第三方仓库（owner/repo，可多次传；只读报告，不开 Issue）
  --patrol-targets=O1,O2  扫描指定用户/组织的全部公开仓库（只读报告，不开 Issue）
  --patrol-sev=X  巡检报 Issue 的最低级别（默认 high；patrol 模式下生效）
  --dry-run       patrol 只报告不实际开 Issue
  --rules         列出全部检测规则
  -h, --help      帮助

退出码: 0 = 通过（或无门禁）；1 = 存在 ≥ fail-on 级别的发现；2 = 运行出错
`);
}

async function main() {
  const args = process.argv.slice(2);
  if (args.includes('-h') || args.includes('--help')) {
    usage();
    return;
  }
  if (args.includes('--version') || args.includes('-v')) {
    console.log(VERSION);
    return;
  }
  if (args.includes('--rules')) {
    console.log(`aiscan · ${RULES.length} 条检测规则\n`);
    for (const r of RULES) {
      console.log(`  [${r.severity.toUpperCase().padEnd(8)}] ${r.id.padEnd(28)} ${r.title}`);
    }
    return;
  }

  const targets = args.filter((a) => !a.startsWith('--'));
  const root = targets.length ? targets : ['.'];

  // ── 巡检模式（patrol）：扫全账号仓库 + 自动开 Issue ──
  // 第三方模式：--patrol-repo=owner/repo（单仓库）/ --patrol-targets=o1,o2（多用户全部公开仓库）
  const patrolRepos = args.filter((a) => a.startsWith('--patrol-repo=')).map((a) => a.split('=').slice(1).join('='));
  const patrolTargets = args.find((a) => a.startsWith('--patrol-targets='))?.split('=')[1]?.split(',').filter(Boolean) || null;
  if (args.includes("--patrol") || patrolRepos.length || patrolTargets || args.some((a) => a.startsWith("--patrol-file="))) {
    const token = process.env.GITHUB_TOKEN || process.env.PATROL_TOKEN;
    if (!token) {
      console.error('patrol 模式需要 GITHUB_TOKEN 环境变量');
      process.exit(2);
    }
    const patrolSev = args.find((a) => a.startsWith('--patrol-sev='))?.split('=')[1] || 'high';
    const dryRun = args.includes('--dry-run');
    const isJsonOut = args.includes('--json');
    // --patrol-file：从 JSON 配置读第三方目标清单（定时巡检默认；不扫自己账号）
    const patrolFile = args.find((a) => a.startsWith('--patrol-file='))?.split('=').slice(1).join('=') || null;
    const report = await patrol({
      token,
      minSeverity: patrolSev,
      dryRun,
      specificRepos: patrolRepos.length ? patrolRepos : null,
      targetOwners: patrolTargets,
      targetsFile: patrolFile,
    });
    if (isJsonOut) {
      console.log(JSON.stringify(report, null, 2));
    } else {
      console.log(`\n📊 巡检汇总: 扫描 ${report.scanned} 个仓库 | 干净 ${report.cleanRepos} | 告警 ${report.flaggedRepos.length}${report.thirdParty ? '（第三方只读，不开 Issue）' : ` | 开 Issue ${report.issuesOpened}`}`);
      for (const f of report.flaggedRepos) {
        console.log(`   🚨 ${f.repo}: ${f.findings} 个 ≥ ${patrolSev}`);
      }
    }
    if (report.errors.length) {
      console.log(`⚠️ 出错仓库: ${report.errors.map((e) => e.repo).join(', ')}`);
      process.exit(2);
    }
    process.exit(report.flaggedRepos.length ? 1 : 0);
  }

  const isJson = args.includes('--json');
  const isSarif = args.includes('--sarif');
  const isHtml = args.includes('--report') && args.includes('html');
  const isQuiet = args.includes('--quiet');
  const severityMin = args.find((a) => a.startsWith('--severity='))?.split('=')[1] || 'low';
  const failOn = args.find((a) => a.startsWith('--fail-on='))?.split('=')[1] || null;
  const ignoreFile = args.find((a) => a.startsWith('--ignore-file='))?.split('=').slice(1).join('=') || null;
  const order = { low: 0, medium: 1, high: 2, critical: 3 };
  const minLevel = order[severityMin] ?? 0;

  const all = [];
  for (const t of root) {
    const res = await scanDirectory(t, { ignoreFile });
    all.push(...res.findings);
  }
  const filtered = all.filter((f) => order[f.severity] >= minLevel);
  const summary = summarize(filtered);

  // CI 门禁：fail-on 级别以上存在发现 → 退出码 1
  let failExit = 0;
  if (failOn && order[failOn] !== undefined) {
    const threshold = order[failOn];
    failExit = filtered.some((f) => order[f.severity] >= threshold) ? 1 : 0;
  }

  if (isSarif) {
    console.log(buildSarif(filtered, root));
    process.exit(failExit);
  }
  if (isJson) {
    console.log(JSON.stringify({ version: VERSION, summary, findings: filtered }, null, 2));
    process.exit(failExit);
  }
  if (isHtml) {
    const html = buildHtml(filtered, summary);
    await import('node:fs').then(async ({ promises: fs }) => {
      await fs.writeFile('security-report.html', html, 'utf8');
    });
    console.log(`已生成 security-report.html（${filtered.length} 个发现，安全评分 ${summary.securityScore} / 等级 ${summary.grade}）`);
    process.exit(failExit);
  }
  if (isQuiet) {
    console.log(
      `aiscan: ${summary.total} 个发现 | critical=${summary.counts.critical} high=${summary.counts.high} medium=${summary.counts.medium} | 安全评分 ${summary.securityScore} (${summary.grade})`
    );
    process.exit(failExit);
  }

  // 默认人类可读输出
  console.log(`\n🔍 aiscan — AI 辅助代码安全审计 v${VERSION}\n`);
  for (const f of filtered) {
    const icon = { critical: '🔴', high: '🟠', medium: '🟡', low: '⚪' }[f.severity] || '⚪';
    console.log(`${icon} [${f.severity.toUpperCase()}] ${f.title}`);
    console.log(`   ${f.file}:${f.line}:${f.col}`);
    console.log(`   ${f.message}`);
    if (f.recommendation) console.log(`   💡 ${f.recommendation}`);
    if (f.heuristic) console.log(`   🧠 AI 启发式，置信度 ${f.confidence}%`);
    console.log(`   ── ${f.snippet}\n`);
  }
  console.log(
    `📊 汇总：${summary.total} 个发现 | 🔴critical=${summary.counts.critical} 🟠high=${summary.counts.high} 🟡medium=${summary.counts.medium} ⚪low=${summary.counts.low}`
  );
  console.log(`🏆 安全评分：${summary.securityScore}/100（等级 ${summary.grade}）\n`);
  process.exit(failExit);
}

function buildSarif(findings, roots) {
  const rules = {};
  const results = findings.map((f) => {
    if (!rules[f.ruleId]) {
      const rule = RULES.find((r) => r.id === f.ruleId) || {};
      rules[f.ruleId] = {
        id: f.ruleId,
        shortDescription: { text: f.title },
        fullDescription: { text: f.message },
        help: { text: rule.recommendation || '' },
        defaultConfiguration: { level: f.severity === 'critical' || f.severity === 'high' ? 'error' : f.severity === 'medium' ? 'warning' : 'note' },
        properties: { tags: [f.category], cwe: rule.cwe || 'CWE-710' },
      };
    }
    return {
      ruleId: f.ruleId,
      message: { text: f.message },
      level: f.severity === 'critical' || f.severity === 'high' ? 'error' : f.severity === 'medium' ? 'warning' : 'note',
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: f.file },
            region: { startLine: f.line, startColumn: f.col },
          },
        },
      ],
      properties: { confidence: f.confidence, heuristic: f.heuristic },
    };
  });
  const sarif = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: { name: 'aiscan', version: VERSION, informationUri: 'https://github.com/hedongli1/aiscan', rules: Object.values(rules) },
        },
        results,
      },
    ],
  };
  return JSON.stringify(sarif, null, 2);
}

function buildHtml(findings, summary) {
  const rows = findings
    .map(
      (f) => `<tr>
        <td><span class="sev s-${f.severity}">${f.severity.toUpperCase()}</span></td>
        <td><strong>${f.title}</strong><br><code>${f.file}:${f.line}</code></td>
        <td><code>${escapeHtml(f.snippet)}</code></td>
        <td>${f.confidence}%</td>
      </tr>`
    )
    .join('\n');
  return `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>aiscan 安全审计报告</title>
<style>
  body{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:0;background:#0f1117;color:#e6edf3}
  .wrap{max-width:960px;margin:0 auto;padding:40px 20px}
  h1{font-size:26px}
  .card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:20px;margin:16px 0}
  .score{font-size:48px;font-weight:700;color:#3fb950}
  .sev{display:inline-block;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:600}
  .s-critical{background:#f8514944;color:#ff7b72}.s-high{background:#ffa65744;color:#ffa657}
  .s-medium{background:#d2992244;color:#d29922}.s-low{background:#8b949e44;color:#8b949e}
  table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:10px;border-bottom:1px solid #21262d;vertical-align:top}
  code{background:#21262d;padding:1px 5px;border-radius:4px;font-size:12px;word-break:break-all}
  .grade{font-size:20px;color:#8b949e}
</style></head><body><div class="wrap">
  <h1>🔍 aiscan 安全审计报告</h1>
  <div class="card"><div style="display:flex;gap:40px;align-items:center">
    <div><div class="score">${summary.securityScore}<span style="font-size:16px;color:#8b949e">/100</span></div><div class="grade">安全等级 ${summary.grade}</div></div>
    <div>发现 ${summary.total} 项<br>critical ${summary.counts.critical} · high ${summary.counts.high} · medium ${summary.counts.medium} · low ${summary.counts.low}</div>
  </div></div>
  <div class="card"><h2 style="margin-top:0">检测结果</h2><table><thead><tr><th>级别</th><th>问题</th><th>代码片段</th><th>置信度</th></tr></thead>
  <tbody>${rows || '<tr><td colspan="4">未发现安全问题 ✅</td></tr>'}</tbody></table></div>
  <p style="color:#8b949e;font-size:13px">由 <a href="https://github.com/hedongli1/aiscan" style="color:#58a6ff">aiscan</a> 生成 · AI 辅助静态安全审计</p>
</div></body></html>`;
}

function escapeHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

main().catch((err) => {
  console.error('aiscan 运行出错:', err.message);
  process.exit(2); // 2 = 工具自身错误（区别于"发现问题"的 1）
});
