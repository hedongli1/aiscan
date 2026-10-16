# GitHub 安全工具发现库（aiscan/docs）

从「固定巡检面板」升级为「按方向检索 GitHub 安全工具」的可视化发现库，纯静态单页，
随 GitHub Pages 自动发布：https://hedongli1.github.io/aiscan/

## 线上能力

| 能力 | 说明 |
| --- | --- |
| 关键词搜索 | 支持名称 / 描述 / 标签 / 方向名，多关键词空格与匹配 |
| 多维度筛选 | 6 大安全方向 + 编程语言 |
| 排序 | Star 数 / 最近更新 / 名称 |
| 工具卡 | Star、Fork、语言、更新时间、中文一句话解读、适用标签、直达仓库 |
| 巡检状态区 | 读取 docs/data/patrol-index.json，展示近 7 日巡检统计与告警趋势 |
| 数据兜底 | 内联兜底数据，tools.json 未加载成功时页面仍可浏览 |

## 目录结构

```
docs/index.html                 # 单文件界面（纯静态，无外部依赖）
docs/data/tools.json            # 工具库数据（6 方向 × 12 个）
docs/data/patrol-index.json     # 巡检索引（由 patrol.yml 巡检后生成）
docs/history/YYYY-MM-DD.json    # 每日巡检原始报告（保留最近 30 天）
scripts/fetch-tools.js          # 按方向×关键词检索 GitHub，刷新技术栈数据
.github/workflows/tools-radar.yml   # 每日 UTC 21:40 自动刷新 tools.json 并提交
.github/workflows/patrol.yml        # 每日 UTC 17:00 仓库巡检，附带生成巡检索引
```

## 数据刷新

- 自动：`tools-radar` 每日 UTC 21:40（北京 05:40）抓取并提交，与 trending-radar、patrol 错峰。
- 手动：Actions → tools-radar → Run workflow（可自定义每方向收录数 per_cat）。
- 保护机制：人工解读过的条目优先保留，刷新只补位、不冲掉精选；中文解读按仓库名增量继承。

## 维护提示

新增方向：在 `scripts/fetch-tools.js` 的 `CATS` 中增加一组 `{id, name, color, queries}`，
并在界面数据中同步方向定义即可，界面会自动渲染对应筛选标签。
