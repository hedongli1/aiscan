# 🛡️ aiscan — AI 辅助代码安全审计

> 零依赖 · 静态分析 · 熵启发式密钥检测 · GitHub Action 开箱即用

**aiscan** 是一个 AI 辅助的静态代码安全审计工具：用**模式匹配 + 香农熵启发式**扫描代码库，检测**硬编码密钥、注入漏洞、XSS、弱加密、供应链风险**，并生成 **SARIF 报告**（GitHub Security 原生支持）。

纯 Node 内置模块实现，**零依赖**，任何机器 `npx` 即用。可以用它扫描**别人的仓库** —— 甚至它自己（dogfooding）。

## ✨ 特性

| 能力 | 说明 |
| --- | --- |
| 🔍 14 条检测规则 | 覆盖密钥泄漏、SQL/命令注入、XSS、弱加密、路径穿越、供应链 |
| 🧠 熵启发式（AI） | 基于香农熵 + 长度 + 字符混合度，自动识别高熵疑似密钥，附置信度评分 |
| 📦 零依赖 | 只用 Node 内置 `fs/path/test`，无 npm 安装负担 |
| 🚀 GitHub Action | 一行 YAML 接入任意仓库，自动上传 SARIF 到 Security 标签页 |
| 📊 三种输出 | 人类可读 / JSON / SARIF 2.1.0 / 自生成 HTML 报告 |
| 🚫 `.aiscanignore` | 类似 `.gitignore`，忽略误报文件 |

## ✅ 可验证状态

| 徽章 | 说明 |
| --- | --- |
| ![CI](https://img.shields.io/github/actions/workflow/status/hedongli1/aiscan/ci.yml?label=CI&logo=github) | 测试 + dogfooding 流水线（点击查看运行历史） |
| ![tests](https://img.shields.io/badge/tests-10%20passed-brightgreen) | `node --test` 单元测试全部通过 |
| ![self-scan](https://img.shields.io/badge/self%20scan-100%2FA-brightgreen) | aiscan 扫描自身源码：0 发现，评分 100/A |
| ![demo](https://img.shields.io/badge/demo%20scan-11%20findings-red) | 漏洞演示文件：检出 11 项（5 critical / 5 high / 1 medium） |
| ![license](https://img.shields.io/github/license/hedongli1/aiscan) | MIT |

> 以上结果全部可由 CI 复现：点徽章看运行历史，或本地 `npm test`。

## 🚀 快速开始

```bash
# 扫描当前目录（跳过 node_modules / .git）
npx aiscan .

# 扫描指定目录
npx aiscan src lib

# 只报告高危以上
npx aiscan src --severity=high

# JSON 输出（适合 CI 解析）
npx aiscan . --json

# SARIF 输出（GitHub Security 原生支持）
npx aiscan . --sarif

# 生成 HTML 报告
npx aiscan . --report html
```

## 🧪 真实扫描输出

对 `fixtures/demo.js`（故意埋入 11 种漏洞）运行：

```
🔍 aiscan — AI 辅助代码安全审计

🔴 [CRITICAL] 疑似 AWS Access Key 泄漏
   demo.js:5:21
   疑似 AWS Access Key，请立即轮换并检查 Git 历史
   💡 使用 aws secretsmanager / 环境变量注入凭证；用 git filter-repo 清理历史
   ── const awsKey = 'AKIAIOSFODNN7EXAMPLE123456'; // 典型 AWS Access Key 格式

🔴 [CRITICAL] SQL 注入：字符串拼接查询
   demo.js:17:17
   SQL 语句使用拼接方式，存在注入风险
   💡 改用参数化查询 / Prepared Statement
   ── ) { const query = `SELECT * FROM users WHERE id = ${id}`; return db.query(query); }

🟠 [HIGH] 疑似高熵 Token / 密钥
   demo.js:8:19
   检测到高熵令牌（熵 5.21，置信度 100%）
   🧠 AI 启发式，置信度 100%
   ── n const apiToken = 'ghp_xK9mQ2vL8nR4tW7zB1cE5hJ3fG6sD8aP2qW4eR6tY9uI';

📊 汇总：11 个发现 | 🔴critical=5 🟠high=5 🟡medium=1 ⚪low=0
🏆 安全评分：0/100（等级 F）
```

## 🤖 GitHub Action 一键接入

在任意仓库加一个 workflow 文件 `.github/workflows/aiscan.yml`：

```yaml
name: aiscan
on:
  push:
  pull_request:

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: aiscan 安全扫描
        uses: hedongli1/aiscan@v1
        with:
          path: .                # 扫描范围
          severity: low          # 报告所有级别
          fail-on: high          # 高危以上使构建失败
```

跑完自动把 **SARIF 结果上传到 GitHub Security 标签页**（Security → Code scanning → aiscan），无需任何额外配置。

## 🏢 真实项目接入（Dogfooding）

aiscan 已在两个真实 GitHub 项目上运行安全审查：

| 项目 | aiscan Action | 审计结果 | 说明 |
| --- | --- | --- | --- |
| [ledger-app](https://github.com/hedongli1/ledger-app) | ✅ [aiscan-security](https://github.com/hedongli1/ledger-app/actions) | 发现 SQL 拼接风险信号 → 已复核修复 | 白名单 conds 拼接经复核确认安全，用 `.aiscanignore` 记录结论 |
| [purple-team-lab](https://github.com/hedongli1/purple-team-lab) | ✅ [aiscan-security](https://github.com/hedongli1/purple-team-lab/actions) | **0 发现，评分 100/A** | 干净基线对照案例 |

两个 Action 均在 GitHub Actions 云端真实运行（含每日定时扫描），结果可随时在对应仓库的 Actions 页面与 Security 标签页复核。

## 📋 检测规则一览

| 规则 ID | 严重级 | 类别 | 检测内容 |
| --- | --- | --- | --- |
| SECRET-AWS | critical | 密钥 | AWS Access Key（AKIA/ASIA） |
| SECRET-PRIVATE-KEY | critical | 密钥 | PEM 私钥块 |
| SECRET-CONNECTION-STRING | critical | 密钥 | 数据库连接串明文口令 |
| SECRET-GENERIC-TOKEN | high | 密钥 | 高熵 Token（熵启发式） |
| SECRET-PASSWORD-VAR | medium | 密钥 | 密码硬编码变量 |
| INJ-SQL-CONCAT | critical | 注入 | SQL 字符串拼接 |
| INJ-COMMAND | critical | 注入 | 命令注入（exec/spawn） |
| INJ-EVAL | high | 注入 | eval / new Function |
| INJ-PATH-TRAVERSAL | high | 注入 | 文件路径穿越 |
| XSS-INNERHTML | high | XSS | DOM XSS |
| CRYPTO-WEAK-MD5 | medium | 加密 | MD5/SHA1 |
| CRYPTO-WEAK-CIPHER | medium | 加密 | DES/3DES/RC4 |
| TLS-INSECURE | high | 加密 | rejectUnauthorized=false |
| LOG-SENSITIVE | medium | 日志 | 日志打印敏感信息 |

## 🔬 熵启发式（AI）原理

```
香农熵 ≥ 4.2 bit + 长度 ≥ 20 + 字符混合度 → 疑似密钥
```

- 密码学随机 Token（如 `x9K5mQ2vL8n...`）熵高、大小写数字混合 → 置信度高
- 普通英文/代码片段熵低 → 自动过滤
- 输出置信度百分比，方便人工复核

## 🚫 .aiscanignore

```gitignore
# 忽略规则库自身的关键字描述（自指误报）
lib/rules/index.js
# 忽略测试与演示数据
test/
fixtures/
```

## 🧰 技术栈

Node.js（≥18）· 纯 ESM · 零依赖 · node:test 单元测试

## 📄 License

MIT

---

**aiscan** — 用 AI 启发式帮你找出代码里的安全隐患。欢迎 Star ⭐ / 提 Issue / 贡献规则。
