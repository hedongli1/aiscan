# 安全策略 · Security Policy

## 报告漏洞 · Reporting a Vulnerability

aiscan 的安全承诺：本工具用于**发现**代码中的安全风险，因此它自身的正确性至关重要——如果一个漏洞检测工具自身有漏洞，会误导所有使用者。

如果你发现 aiscan 的安全问题（包括但不限于）：

- **误报导致漏报**：某条规则可能被绕过，导致真实漏洞未被检出
- **扫描器自身漏洞**：aiscan 源码中被检测出的任何高危问题
- **依赖 / 供应链风险**：发布物（npm 包 / GitHub Action）被篡改或投毒
- **性能滥用**：恶意输入导致 CPU 峰值 / 内存耗尽（DoS）

### 📮 报告方式

**请不要公开披露。** 请通过以下方式之一私密报告：

1. **GitHub Security Advisory**（推荐）：仓库首页 → Security → Report a vulnerability
2. **邮件**：在 GitHub 仓库通过 Issue 的 "Security" 标签讨论前先私信

报告时请附带：

- 影响的 aiscan 版本（`npx aiscan --version` 或 package.json）
- 触发场景 / 最小复现代码
- 影响说明与可能的利用方式
- （如有）建议的修复方向

### ⏱ 响应时间表

| 严重级 | 首次响应 | 修复目标 |
| --- | --- | --- |
| Critical / High | 48 小时内 | 7 天内 |
| Medium / Low | 7 天内 | 30 天内 |

### 📌 定向加固说明

aiscan 自带 dogfooding 机制：本仓库 CI 会**用 aiscan 扫描 aiscan 自身源码**（`npm run scan:self`），确保自检持续。该机制也是检测规则正确性的持续验证。

## 安全使用建议

- 扫描结果中标注 `severity: high/critical` 的发现，建议在合并代码前处理或显式记录人工复核结论（`.aiscanignore`）
- CI 中建议使用 `fail-on: high` 作为门禁，拦截高危问题进入主干
- 在 `npm install` 时校验 aiscan 的完整性（lockfile 固定版本）