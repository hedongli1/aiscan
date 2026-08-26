#!/usr/bin/env node
// aiscan CLI · 入口
import { scanDirectory, summarize } from '../lib/scanner.js';
import { RULES } from '../lib/rules/index.js';

function usage() {
  console.log(`aiscan — AI 辅助代码安全审计（零依赖）

用法:
  aiscan [路径...] [--json] [--sarif] [--report html] [--severity=high] [--quiet]

选项:
  --json          输出 JSON 结果
  --sarif         输出 SARIF 2.1.0（GitHub Security 原生支持）
  --report html   生成 HTML 报告（security-report.html）
  --severity=X    只显示 ≥ X 的发现（critical|high|medium|low）
  --quiet         仅输出摘要
  --rules         列出全部检测规则
  -h, --help      帮助
`);
}

async function main() {
  const args = process.argv.slice(2);
  if (args.includes('-h') || args.includes('--help')) {
    usage();
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
  const isJson = args.includes('--json');
  const isSarif = args.includes('--sarif');
  const isHtml = args.includes('--report') && args.includes('html');
  const isQuiet = args.includes('--quiet');
  const severityMin = args.find((a) => a.startsWith('--severity='))?.split('=')[1] || 'low';
  const order = { low: 0, medium: 1, high: 2, critical: 3 };
  const minLevel = order[severityMin] ?? 0;

  const all = [];
  for (const t of root) {
    const res = await scanDirectory(t);
    all.push(...res.findings);
  }
  const filtered = all.filter((f) => order[f.severity] >= minLevel);
  const summary = summarize(filtered);

  if (isSarif) {
    console.log(buildSarif(filtered, root));
    return;
  }
  if (isJson) {
    console.log(JSON.stringify({ version: '0.1.0', summary, findings: filtered }, null, 2));
    return;
  }
  if (isHtml) {
    const html = buildHtml(filtered, summary);
    await import('node:fs').then(async ({ promises: fs }) => {
      await fs.writeFile('security-report.html', html, 'utf8');
    });
    console.log(`已生成 security-report.html（${filtered.length} 个发现，安全评分 ${summary.securityScore} / 等级 ${summary.grade}）`);
    return;
  }
  if (isQuiet) {
    console.log(
      `aiscan: ${summary.total} 个发现 | critical=${summary.counts.critical} high=${summary.counts.high} medium=${summary.counts.medium} | 安全评分 ${summary.securityScore} (${summary.grade})`
    );
    return;
  }

  // 默认人类可读输出
  console.log(`\n🔍 aiscan — AI 辅助代码安全审计\n`);
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
          driver: { name: 'aiscan', version: '0.1.0', informationUri: 'https://github.com/hedongli1/aiscan', rules: Object.values(rules) },
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
  process.exit(1);
});
