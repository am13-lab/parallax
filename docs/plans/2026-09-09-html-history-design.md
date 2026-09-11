# HTML 历史测试记录展示 — 设计

日期：2026-09-09
分支：`feat/spec-pipeline`
基线：worktree 中已有的 `report/html.go` WIP（`RunPayload` / `WriteHTMLRuns` 已就位）

## 目标

`analyze -html` 生成的单文件 HTML 支持查看本地历史测试记录：一个 History 列表展示本地跑过哪些 run，选择某条即可切换整页展示；不再是"只有当前这一次"。

## 约束

- HTML 保持自包含单文件（无外部资源、无网络依赖，file:// 直接打开）。
- file:// 下页面不能动态读磁盘 → 历史数据必须在生成时内嵌。
- findings 由 Go 侧（`BuildFindings` + `ApplyAllowlist`）计算，JS 无此逻辑 → 每份内嵌 run 必须随附预计算的 findings。

## 数据流

```
run 结束 ──写 report.json──┬──> 归档副本到 ~/.parallax/history/<UTC时间戳>-seed<seed>.json
                           └──> 正常输出
analyze -html ──扫 ~/.parallax/history/（EndedAt 倒序）──┬──> 最近 N=20 份：完整内嵌（report + findings）
                                                        ├──> 更早的：仅内嵌摘要行（RunMeta）
                                                        └──> 当前 analyze 的 report 置顶标记 current
```

## 组件

### 1. 归档（runner / cmd run 侧）

- run 写完 `report.json` 后，自动拷贝一份到 `~/.parallax/history/`，目录不存在则创建。
- 文件名：`<UTC时间戳>-seed<seed>.json`，如 `20260909T083000Z-seed12345.json`。
- 归档失败仅告警，不影响 run 结果。

### 2. 生成（report + cmd analyze 侧）

- `RunMeta` 补齐：`Stamp`（归档文件名中的时间戳）、client 组成（由 `Endpoints[].ClientType` 聚合，如 `geth×2 + erigon×1`）、沿用已有 `StartedAt` / `Command` / `Summary`。
- 新增：扫历史目录 → `[]RunPayload`（最近 20 份完整，`BuildFindings` 预计算；历史 run 的 findings 不做 allowlist 分诊——CLI 只对当前 run 应用 allowlist，后续如需一致可把 allowlist 传入 `CollectRuns`）；更早的仅 `RunMeta` 摘要，`Report`/`Findings` 为空。
- 目录不存在或为空 → 退化为现状（单 run 页面）。
- 当前 report 构造的 payload 恒为 `current` 且置顶。

### 3. 页面（HTML/JS）

- payload 结构（已有）：`{runs: [{meta, report, findings}], current}`。
- **修复渲染层**：页面数据源从顶层 `report/findings` 改为 `runs[current]`，所有现有视图（Summary/Findings/Clients/Divergence）按选中 run 重渲染。
- 新增独立 **History** tab：卡片列表（时间倒序），每行 = `时间 · client 组成 · passed/total, divergent · seed · 命令摘要`。
  - 内嵌完整数据的条目：点击切换 `current` 并整页重渲染。
  - 仅摘要的条目：点击弹文件选择器（`<input type="file">`）加载对应 report JSON；该次无 findings，Findings 视图降级提示。
- 切换 run 时同步更新 tab 内所有计数与矩阵。

### 4. 测试

`report` 包扩展 `html_test.go`：

- 归档文件名格式与目录创建。
- `RunMeta` 摘要字段（client 组成聚合、stamp）。
- N=20 截断边界（19/20/21 份历史）。
- current 置顶与越界回退（已有部分覆盖）。
- HTML 内嵌 payload 含 runs 数组且可反序列化（已有，扩展多 run 场景）。

## 错误处理

- 历史目录不可读 / 单份历史 JSON 损坏：跳过该份并在 stdout 告警，不阻塞生成。
- 归档写失败：告警，run 照常成功。
- 文件选择器导入的 JSON 解析失败：页面 toast，不影响已选 run。

## 非目标（YAGNI）

- 趋势图 / run 间 diff / 单 test 历史轨迹。
- `-history-dir` CLI 参数（内部函数留目录参数供测试，CLI 固定用 `~/.parallax/history/`）。
- 历史清理/容量策略。
