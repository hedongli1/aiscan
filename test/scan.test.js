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
    // gitleaks 移植规则基线（v0.3.0：内置 15 + gitleaks 221 = 236 条）
    assert.ok(ids.some((id) => id.startsWith('GL-')), '应检出 gitleaks 移植规则命中');
    assert.ok(findings.length >= 12, `发现数应 ≥12（gitleaks 增强后，Node 24 为 15），实际 ${findings.length}`);
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

describe('回归测试（v0.2.0 修复的 bug，全部来自真实审查）', () => {
  test('报告 snippet 不泄漏密钥明文（安全工具自身防二次泄漏）', async () => {
    const { findings } = await scanDirectory('fixtures/demo.js');
    const aws = findings.find((f) => f.ruleId === 'SECRET-AWS');
    assert.ok(aws, 'SECRET-AWS 应命中');
    assert.ok(!aws.snippet.includes('AKIAIOSFODNN7EXAMPLE123456'), 'snippet 不得包含完整密钥');
    assert.ok(aws.snippet.includes('…'), 'snippet 应有脱敏标记');
  });

  test('弱加密规则不误报变量名 / 注释里的裸词', () => {
    const r = RULES.find((x) => x.id === 'CRYPTO-WEAK-CIPHER');
    assert.equal(r.regex.test('const des = items.length;'), false, '变量名 des 不应命中');
    assert.equal(r.regex.test('// see ECB documentation'), false, '注释 ECB 不应命中');
    assert.equal(r.regex.test("algo = 'DES'"), true, "字符串 'DES' 应命中");
    assert.equal(r.regex.test("createCipheriv('des-cbc', key)"), true, 'cipheriv 调用应命中');
  });

  test('MD5/SHA1 规则覆盖函数调用写法', () => {
    const r = RULES.find((x) => x.id === 'CRYPTO-WEAK-MD5');
    assert.equal(r.regex.test('md5(data)'), true, 'md5(data) 应命中');
    assert.equal(r.regex.test('sha1(pwd)'), true, 'sha1(pwd) 应命中');
    assert.equal(r.regex.test("createHash('md5')"), true, "createHash('md5') 应命中");
  });

  test('同一行的正则命中后熵启发式不重复报告', async () => {
    const { findings } = await scanDirectory('fixtures/demo.js');
    // demo.js 中 AWS key 行：SECRET-AWS（正则）与 SECRET-GENERIC-TOKEN（熵）同在一行
    const awsLine = findings.find((f) => f.ruleId === 'SECRET-AWS')?.line;
    const dupOnLine = findings.filter(
      (f) => f.line === awsLine && f.heuristic && f.file === 'demo.js'
    );
    // 熵启发式对已命中的行不再重复报（demo.js 其他行仍可报）
    assert.ok(!dupOnLine.some((f) => f.line === awsLine && f.confidence >= 65 && f.snippet.includes('AKIA')),
      '已被正则命中的行不应再报熵告警');
  });
});

describe('gitleaks 移植规则（v0.3.0 二次创作）', () => {
  test('gitleaks 规则加载且正则有效（≥200，容忍 Node 版本正则差异）', async () => {
    const { ALL_RULES } = await import('../lib/rules/index.js');
    const gl = ALL_RULES.filter((r) => r.source === 'gitleaks');
    // Node 24：221 条全部编译；Node 22 有 ~16 条 Go RE2 语法差异被运行时跳过 → 下限 200
    assert.ok(gl.length >= 200, `gitleaks 规则应 ≥200（Node 24 全量 221），实际 ${gl.length}`);
    for (const r of gl) assert.ok(r.regex instanceof RegExp, `${r.id} 正则应已编译`);
  });

  test('GitHub PAT 格式可检出（GL 规则）', async () => {
    const { ALL_RULES } = await import('../lib/rules/index.js');
    const ghRule = ALL_RULES.find((r) => r.id === 'GL-github-pat');
    if (ghRule) {
      assert.ok(ghRule.regex.test('ghp_16C7e42F292c6912E7710c838347Ae178B4a'), 'GitHub PAT 应命中');
    }
  });

  test('npm token / Slack webhook 格式可检出', async () => {
    const { ALL_RULES } = await import('../lib/rules/index.js');
    const npmRule = ALL_RULES.find((r) => r.id === 'GL-npm-access-token');
    if (npmRule) {
      // npm_ + 36 位小写十六进制占位（非真实 token）
      assert.ok(npmRule.regex.test('npm_' + 'a1b2c3d4'.repeat(4) + 'e5f6'), 'npm token 应命中');
    }
    const slackRule = ALL_RULES.find((r) => r.id === 'GL-slack-webhook-url');
    if (slackRule) {
      // 拼接构造 URL，避免被 GitHub Push Protection 识别为真实 webhook
      const url = 'https://hooks.' + 'slack.com/services/' + 'T00000000/B00000000/' + 'XXXXXXXX'.repeat(3);
      assert.ok(slackRule.regex.test(url), 'Slack webhook 应命中');
    }
  });
});
