# Contributing · 贡献指南

感谢你对 aiscan 感兴趣！aiscan 是零依赖的 AI 辅助安全扫描器，代码量小、结构清晰，非常适合作为你理解静态分析 / 安全扫描器内部实现的第一个项目。

## 如何贡献

### 🐛 报告问题

- 在 [Issues](https://github.com/hedongli1/aiscan/issues) 新建 issue
- 模板自动生成，请补全：复现步骤、预期行为、实际行为、环境（Node 版本）

### 🧩 新增检测规则（最常见贡献）

aiscan 的规则都在 `lib/rules/index.js`，每个规则是一个对象：

```js
{
  id: 'SECRET-MY-TOKEN',        // 唯一 ID
  severity: 'high',             // critical | high | medium | low
  category: 'secret',           // secret | injection | crypto | xss | path | tls | logging | supply-chain
  title: '密钥泄漏：自定义 Token',
  regex: /\b(mytoken|my_secret)\s*=\s*["'][A-Za-z0-9_\-]{16,}["']/i,
  message: '检测到疑似自定义密钥',
  recommendation: '使用环境变量并通过密钥管理服务注入',
  cwe: 'CWE-798',
}
```

新增规则请遵循：

1. **先写测试**：在 `test/scan.test.js` 加用例，用故意埋入的样本验证能命中、用正常代码验证不误报
2. **避免过度检测**：正则要有上下文（`=`/`:`/`(`, `)`），不要裸匹配任意长字符串
3. **给出补救建议**：`recommendation` 必须可操作

### 🧠 改进熵启发式

`lib/entropy.js` 实现了香农熵密钥检测。如果你有更好的启发式（如更精确的令牌窗口、上下文评分、语义置信度），欢迎 PR。

### 📦 打包 / 发布

- 保持**零依赖**：所有功能只用 Node 内置模块（`fs/path/process`）
- `package.json` 保持精简；新增 CLI 参数需补充 `--help` 文档
- 发版遵循语义化版本（SemVer）

## 开发流程

```bash
# 1. clone
git clone https://github.com/hedongli1/aiscan.git && cd aiscan
# 2. 测试
npm test                 # node:test 零框架
# 3. 自检（dogfooding）
npm run scan:self        # aiscan 扫自己，应 0 发现
# 4. 提交 PR
```

每次 push / PR 都会触发 CI：单元测试 + dogfooding 自扫 + demo 漏洞基线扫描。

## 提交规范

- 提交信息用中文或英文均可，风格：`<type>: <summary>`（feat / fix / docs / ci / test / perf）
- 一个 PR 只解决一个问题，尽量小
- 新增规则必须附测试

## Code of Conduct

保持友善。这是一个学习与分享安全的项目，不接受攻击性或歧视性言论。