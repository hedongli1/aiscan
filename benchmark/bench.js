#!/usr/bin/env node
// aiscan 真实性基准测量：扫描 fixtures/bench/，对照 manifest 计算 precision/recall/F1
// 用法：node benchmark/bench.js [--verdict]   --verdict=仅输出 JSON（供 CI 断言）
// 退出码：0 = 分数达标；2 = 有 FN/FP 或分数未达标
import { readFileSync, readdirSync } from 'node:fs';
import { scanDirectory } from '../lib/scanner.js';

const manifest = JSON.parse(readFileSync(new URL('./manifest.json', import.meta.url), 'utf8'));
const benchDir = new URL('../fixtures/bench/', import.meta.url).pathname;
const files = readdirSync(benchDir);

let TP = 0, FP = 0, FN = 0;
const details = [];

for (const fx of manifest.fixtures) {
  const { findings } = await scanDirectory(`${benchDir}${fx.file}`);
  const hits = findings.map((f) => ({ line: f.line, ruleId: f.ruleId, severity: f.severity, message: f.message }));
  const hitKeys = new Set(hits.map((h) => `${h.line}:${h.ruleId}`));

  // TP: 期望命中且命中
  for (const exp of fx.expected) {
    const k = `${exp.line}:${exp.ruleId}`;
    if (hitKeys.has(k)) {
      TP++;
      details.push({ file: fx.file, kind: 'TP', line: exp.line, ruleId: exp.ruleId, reason: exp.reason || '' });
    } else {
      FN++;
      details.push({ file: fx.file, kind: 'FN', line: exp.line, ruleId: exp.ruleId, reason: exp.reason || '', actual: hits.filter((h) => h.line === exp.line).map((h) => h.ruleId) });
    }
  }
  // FP: 不应命中却命中
  for (const bad of fx.shouldNotFind) {
    const k = `${bad.line}:${bad.ruleId}`;
    if (hitKeys.has(k)) {
      FP++;
      details.push({ file: fx.file, kind: 'FP', line: bad.line, ruleId: bad.ruleId, reason: bad.reason || '' });
    }
  }
  // benign 文件：任何 high+ 都算 FP
  if (fx.category === 'benign') {
    for (const h of hits) {
      if (h.severity === 'critical' || h.severity === 'high') {
        FP++;
        details.push({ file: fx.file, kind: 'FP(benign)', line: h.line, ruleId: h.ruleId });
      }
    }
  }
}

const precision = TP / (TP + FP) || 0;
const recall = TP / (TP + FN) || 0;
const f1 = precision + recall > 0 ? 2 * ((precision * recall) / (precision + recall)) : 0;
const th = manifest.tolerances.gradeThresholds;
const grade = f1 >= th.excellent ? 'excellent' : f1 >= th.good ? 'good' : f1 >= th.fair ? 'fair' : 'poor';

const report = {
  version: '0.6.0',
  date: '2026-09-02',
  metric: { TP, FP, FN, precision: Number(precision.toFixed(4)), recall: Number(recall.toFixed(4)), f1: Number(f1.toFixed(4)), grade },
  details,
};

if (process.argv.includes('--verdict')) {
  console.log(JSON.stringify(report));
} else {
  console.log(`\n🔬 aiscan 真实性基准 (v${report.version})\n`);
  console.log(`  真正例(TP): ${TP}  假阳性(FP): ${FP}  漏报(FN): ${FN}`);
  console.log(`  precision(检出可信度): ${(precision * 100).toFixed(1)}%`);
  console.log(`  recall(检出覆盖度):    ${(recall * 100).toFixed(1)}%`);
  console.log(`  F1: ${(f1 * 100).toFixed(1)}%  → 等级: ${grade.toUpperCase()}`);
  console.log(`\n  ── 明细 ──`);
  for (const d of details) {
    const icon = d.kind === 'TP' ? '✅' : d.kind.startsWith('FP') ? '🔴' : '🟡';
    console.log(`  ${icon} [${d.kind}] ${d.file}:${d.line} ${d.ruleId} ${d.reason || ''}`);
    if (d.kind === 'FN' && d.actual?.length) console.log(`      实际命中: ${d.actual.join(', ')}`);
  }
  console.log('');
  process.exit(FP || FN ? 2 : 0);
}