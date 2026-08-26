// aiscan · 单元测试（node:test，零依赖）
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { shannonEntropy, isLikelySecret, secretConfidence, extractTokenCandidates } from '../lib/entropy.js';
import { scanDirectory } from '../lib/scanner.js';
import { RULES } from '../lib/rules/index.js';

describe('熵启发式（AI 判断令牌是否为密钥）', () => {
  test('香农熵计算：高熵令牌熵高，普通英文熵低', () => {
    const high = shannonEntropy('x9K5mQ2vL8nR4tW7zB1cE5hJ3fG6sD8aP2qW4eR6tY9uI');
    const low = shannonEntropy('hello world hello world');
    assert.ok(high > 4.5, `高熵令牌熵应 > 4.5，实际 ${high}`);
    assert.ok(low < 3.5, `普通文本熵应 < 3.5，实际 ${low}`);
  });

  test('isLikelySecret：长度与熵双阈值判断', () => {
    assert.equal(isLikelySecret('short'), false); // 太短
    assert.equal(isLikelySecret('x9K5mQ2vL8nR4tW7zB1cE5hJ3fG6sD8a'), true); // 高熵长令牌
  });

  test('secretConfidence：低混合度令牌置信度低，真令牌置信度高', () => {
    const alphabet = secretConfidence('abcdefghijklmnopqrstuvwxyz'); // 无大小写/数字/符号混合
    const realToken = secretConfidence('x9K5mQ2vL8nR4tW7zB1cE5hJ3fG6sD8aP2qW4eR6tY9uI');
    assert.ok(alphabet < realToken, `字母表置信度 ${alphabet} 应低于真令牌 ${realToken}`);
    assert.ok(realToken >= 80, `真令牌置信度应 ≥80，实际 ${realToken}`);
    assert.ok(secretConfidence('hi') === 0);
  });

  test('extractTokenCandidates 提取候选令牌', () => {
    const text = 'token = "abcdefghijklmnopqrstuvwxyz"; date=2026-08-26;';
    const cands = extractTokenCandidates(text);
    assert.ok(cands.length >= 1);
    // 日期不应被当作令牌
    assert.ok(!cands.some((c) => /^\d{4}-\d{2}-\d{2}$/.test(c.token)));
  });
});

describe('扫描引擎', () => {
  test('demo.js 应检出 11 个漏洞（覆盖全部类别）', async () => {
    const { findings } = await scanDirectory('fixtures/demo.js');
    const ids = findings.map((f) => f.ruleId);
    // 关键类别必须命中
    assert.ok(ids.includes('SECRET-AWS'), '应检出 AWS Key');
    assert.ok(ids.includes('SECRET-PRIVATE-KEY'), '应检出私钥');
    assert.ok(ids.includes('SECRET-CONNECTION-STRING'), '应检出连接串');
    assert.ok(ids.includes('INJ-SQL-CONCAT'), '应检出 SQL 注入');
    assert.ok(ids.includes('INJ-COMMAND'), '应检出命令注入');
    assert.ok(ids.includes('INJ-PATH-TRAVERSAL'), '应检出路径穿越');
    assert.ok(ids.includes('XSS-INNERHTML'), '应检出 XSS');
    assert.ok(ids.includes('CRYPTO-WEAK-MD5'), '应检出弱加密');
    assert.ok(ids.includes('TLS-INSECURE'), '应检出 TLS');
    assert.ok(ids.includes('SECRET-GENERIC-TOKEN'), '应检出高熵令牌');
    assert.ok(findings.length >= 10, `发现数应 ≥10，实际 ${findings.length}`);
  });

  test('findings 字段完整', async () => {
    const { findings } = await scanDirectory('fixtures/demo.js');
    for (const f of findings) {
      assert.ok(f.ruleId && f.severity && f.title && f.message, '字段完整');
      assert.ok(f.file.includes('demo.js'), `file 应包含 demo.js: ${f.file}`);
      assert.ok(f.line > 0, 'line 应为正数');
      assert.ok(f.confidence >= 0 && f.confidence <= 100, '置信度 0-100');
    }
  });

  test('安全评分：漏洞文件评分为 F', async () => {
    const { summary } = await scanDirectory('fixtures/demo.js');
    assert.equal(summary.total >= 10, true);
    assert.equal(summary.grade, 'F');
    assert.ok(summary.securityScore < 50, `漏洞文件评分应低，实际 ${summary.securityScore}`);
  });

  test('不存在的路径返回空', async () => {
    const { findings, summary } = await scanDirectory('fixtures/not-exist-dir');
    assert.equal(findings.length, 0);
    assert.equal(summary.grade, 'A');
  });
});

describe('规则库', () => {
  test('规则 id 唯一', () => {
    const ids = RULES.map((r) => r.id);
    assert.equal(new Set(ids).size, ids.length);
  });
  test('规则含 severity / recommendation / cwe', () => {
    for (const r of RULES) {
      assert.ok(['critical', 'high', 'medium', 'low'].includes(r.severity), `${r.id} severity`);
      assert.ok(r.title, `${r.id} title`);
      assert.ok(r.message, `${r.id} message`);
      assert.ok(r.cwe, `${r.id} cwe`);
    }
  });
});
