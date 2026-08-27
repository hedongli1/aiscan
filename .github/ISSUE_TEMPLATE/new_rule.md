---
name: 新增检测规则
about: 提议一个 aiscan 尚未覆盖的检测规则
title: "[rule] "
labels: enhancement
assignees: ''
---

**规则目标**
要检测哪种安全问题？结合真实案例说明（不要虚构）。

**样本（必填）**
贴一个会被此规则检测的**伪代码样本**（不要用真实密钥），以及期望的严重级。

```js
// 示例：
const api = { token: "high-entropy-secret-like-92k3mfbav0Qa8zK1xL5nR7tW" };
```

**对照样本**
贴一段**不应触发**的正常代码（防误报）。

**检测思路**
- 正则 / 启发式 / 组合逻辑？
- 归属类别：secret / injection / crypto / xss / path / tls / logging / supply-chain

**CWE 参考**
如覆盖 CWE-798（硬编码凭据）等。

**验收标准**
- [ ] 在 `test/scan.test.js` 有测试用例
- [ ] 通过 demo 扫描不会破坏现有基线（11 个发现）