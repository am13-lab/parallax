# HTML History Run Selector Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** `analyze -html` 生成的历史选择器：run 自动归档到 `~/.parallax/history/`，HTML 内嵌最近 N=20 份完整 run + 更早的摘要，History tab 点击切换整页展示。

**Architecture:** Go 侧新增 `report/history.go`（归档 + 扫描 + 摘要），`WriteHTMLRuns` 已存在（WIP）；JS 侧把启动时一次性派生的 header/数据改为 `applyRun(i)` 可重入，新增 History tab。CLI 在 `cmd/parallax/app.go` 接线。

**Tech Stack:** Go 1.x 标准库、`html/template`（既有单文件模板）、原生 JS。

**注意（执行者必读）：**
- 工作树里有**无关的未提交改动**（`cases/`、`client/client.go`、`probe/` 等）。每次提交只 `git add` 本任务明确列出的文件，**禁止 `git add -A` / `git add .`**。
- 分支 `feat/spec-pipeline`（worktree `~/Desktop/parallax`），不碰 main。
- 测试命令统一在 worktree 根目录执行：`go test ./report/ -count=1`。

---

### Task 1: RunMeta 补齐 Clients / Seed / Stamp

**Files:**
- Modify: `report/html.go:14-19`（RunMeta）、`report/html.go:65-84`（runPayload）
- Test: `report/html_test.go`

**Step 1: 写失败测试**

在 `report/html_test.go` 追加：

```go
func TestRunPayloadMetaFields(t *testing.T) {
	rep := &runner.Report{
		SchemaVersion: 1,
		StartedAt:     time.Date(2026, 9, 9, 8, 30, 0, 0, time.UTC),
		Seed:          77,
		Command:       "go run ./cmd/parallax run ...",
		Endpoints: []runner.EndpointFingerprint{
			{Name: "cl-1-a", ClientType: "geth"},
			{Name: "cl-1-b", ClientType: "geth"},
			{Name: "cl-2-a", ClientType: "erigon"},
		},
		Summary: runner.Summary{Total: 3, Passed: 3},
	}
	p := runPayload(rep, nil)
	if p.Meta.Stamp != "20260909T083000Z" {
		t.Fatalf("stamp = %q", p.Meta.Stamp)
	}
	if p.Meta.Seed != 77 {
		t.Fatalf("seed = %d", p.Meta.Seed)
	}
	if p.Meta.Clients != "geth×2 + erigon×1" {
		t.Fatalf("clients = %q", p.Meta.Clients)
	}
}
```

**Step 2: 跑测试确认失败**

Run: `go test ./report/ -run TestRunPayloadMetaFields -count=1`
Expected: FAIL（字段不存在 / 零值）

**Step 3: 最小实现**

`report/html.go` RunMeta 增加字段并在 runPayload 填充：

```go
type RunMeta struct {
	Stamp     string         `json:"stamp"`
	StartedAt string         `json:"started_at"`
	Seed      int64          `json:"seed,omitempty"`
	Clients   string         `json:"clients,omitempty"`
	Command   string         `json:"command,omitempty"`
	Summary   runner.Summary `json:"summary"`
}
```

```go
// clientMix aggregates endpoint client types, e.g. "geth×2 + erigon×1".
func clientMix(eps []runner.EndpointFingerprint) string {
	order := []string{}
	count := map[string]int{}
	for _, e := range eps {
		if e.ClientType == "" {
			continue
		}
		if count[e.ClientType] == 0 {
			order = append(order, e.ClientType)
		}
		count[e.ClientType]++
	}
	parts := make([]string, 0, len(order))
	for _, k := range order {
		parts = append(parts, fmt.Sprintf("%s×%d", k, count[k]))
	}
	return strings.Join(parts, " + ")
}
```

runPayload 的 Meta 增加：

```go
Stamp:   rep.StartedAt.UTC().Format("20060102T150405Z"),
Seed:    rep.Seed,
Clients: clientMix(rep.Endpoints),
```

（`strings` 加入 import；`fmt` 已在 WIP 中引入。）

**Step 4: 跑测试确认通过**

Run: `go test ./report/ -run TestRunPayloadMetaFields -count=1`
Expected: PASS

**Step 5: 提交**

```bash
git add report/html.go report/html_test.go
git commit -m "report: run meta gains stamp, seed and client mix for history list"
```

---

### Task 2: 历史归档（run 侧）

**Files:**
- Create: `report/history.go`
- Test: `report/history_test.go`
- Modify: `cmd/parallax/app.go:202-220`（writeOutputs 调归档，仅告警）

**Step 1: 写失败测试** `report/history_test.go`：

```go
func TestArchiveRunFilenameAndContent(t *testing.T) {
	dir := t.TempDir()
	rep := &runner.Report{
		StartedAt: time.Date(2026, 9, 9, 8, 30, 0, 0, time.UTC),
		EndedAt:   time.Date(2026, 9, 9, 8, 31, 0, 0, time.UTC),
		Seed:      42,
	}
	if err := ArchiveRunTo(dir, rep); err != nil {
		t.Fatal(err)
	}
	name := "20260909T083000Z-seed42.json"
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("archive file missing: %v", err)
	}
	var back runner.Report
	if err := json.Unmarshal(data, &back); err != nil || back.Seed != 42 {
		t.Fatalf("archive does not decode: %v", err)
	}
}
```

**Step 2: 跑测试确认失败**

Run: `go test ./report/ -run TestArchiveRun -count=1`
Expected: FAIL（ArchiveRunTo undefined）

**Step 3: 最小实现** `report/history.go`：

```go
package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"parallax/runner"
)

// HistoryDir is the global archive root: ~/.parallax/history.
func HistoryDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".parallax", "history"), nil
}

func archiveName(rep *runner.Report) string {
	return rep.StartedAt.UTC().Format("20060102T150405Z") + "-seed" + fmt.Sprint(rep.Seed) + ".json"
}

// ArchiveRunTo writes one archival copy of rep into dir (created as needed).
func ArchiveRunTo(dir string, rep *runner.Report) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data, err := WriteJSON(rep)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, archiveName(rep)), data, 0o644)
}

// ArchiveRun archives into the global history dir; failures are the caller's
// to warn about.
func ArchiveRun(rep *runner.Report) error {
	dir, err := HistoryDir()
	if err != nil {
		return err
	}
	return ArchiveRunTo(dir, rep)
}
```

（`time` 若未直接用到则去掉 import。）

**Step 4: 跑测试确认通过**

Run: `go test ./report/ -run TestArchiveRun -count=1`
Expected: PASS

**Step 5: 接线 writeOutputs**（`cmd/parallax/app.go` 的 `writeOutputs` 末尾 return 前）：

```go
if err := report.ArchiveRun(rep); err != nil {
	fmt.Fprintf(os.Stderr, "warn: archive run: %v\n", err)
}
```

**Step 6: 全量测试 + 提交**

Run: `go test ./report/ ./cmd/... -count=1`
Expected: PASS

```bash
git add report/history.go report/history_test.go cmd/parallax/app.go
git commit -m "report: archive each run report to ~/.parallax/history"
```

---

### Task 3: 历史扫描 + 内嵌收集（analyze 侧）

**Files:**
- Modify: `report/history.go`
- Test: `report/history_test.go`

**Step 1: 写失败测试**

```go
func TestLoadHistoryNewestFirstAndCap(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 23; i++ {
		rep := &runner.Report{
			StartedAt: time.Date(2026, 9, 1, 0, i, 0, 0, time.UTC),
			EndedAt:   time.Date(2026, 9, 1, 0, i, 30, 0, time.UTC),
			Seed:      int64(i),
		}
		if err := ArchiveRunTo(dir, rep); err != nil {
			t.Fatal(err)
		}
	}
	// 一份损坏文件应被跳过
	if err := os.WriteFile(filepath.Join(dir, "broken.json"), []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	full, summaries, err := LoadHistory(dir, 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(full) != 20 {
		t.Fatalf("full = %d", len(full))
	}
	if len(summaries) != 3 {
		t.Fatalf("summaries = %d", len(summaries))
	}
	if full[0].Meta.Seed != 22 {
		t.Fatalf("newest first violated: %d", full[0].Meta.Seed)
	}
	for _, s := range summaries {
		if s.Report != nil || s.Findings != nil {
			t.Fatal("summary carries payload")
		}
	}
}
```

**Step 2: 跑测试确认失败**

Run: `go test ./report/ -run TestLoadHistory -count=1`
Expected: FAIL（LoadHistory undefined）

**Step 3: 最小实现**（追加到 `report/history.go`）：

```go
// LoadHistory reads dir and returns up to keep newest runs as full payloads;
// older runs degrade to meta-only summaries. Unreadable files are skipped.
// Sort is newest first by StartedAt.
func LoadHistory(dir string, keep int) ([]RunPayload, []RunMeta, error) {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	type item struct {
		meta RunMeta
		path string
	}
	var items []item
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var rep runner.Report
		if err := json.Unmarshal(data, &rep); err != nil {
			continue // corrupt file: skip
		}
		items = append(items, item{meta: metaOf(&rep), path: filepath.Join(dir, e.Name())})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].meta.StartedAt > items[j].meta.StartedAt })
	var full []RunPayload
	var summaries []RunMeta
	for i, it := range items {
		if i < keep {
			data, err := os.ReadFile(it.path)
			if err != nil {
				continue
			}
			var rep runner.Report
			if err := json.Unmarshal(data, &rep); err != nil {
				continue
			}
			full = append(full, runPayload(&rep, BuildFindings(&rep, false)))
		} else {
			summaries = append(summaries, it.meta)
		}
	}
	return full, summaries, nil
}

func metaOf(rep *runner.Report) RunMeta {
	return RunMeta{
		Stamp:     rep.StartedAt.UTC().Format("20060102T150405Z"),
		StartedAt: rep.StartedAt.Format(time.RFC3339),
		Seed:      rep.Seed,
		Clients:   clientMix(rep.Endpoints),
		Command:   rep.Command,
		Summary:   rep.Summary,
	}
}
```

同时重构 runPayload 复用 metaOf（行为不变）。

**Step 4: 跑测试确认通过**

Run: `go test ./report/ -run TestLoadHistory -count=1`
Expected: PASS

**Step 5: 提交**

```bash
git add report/history.go report/history_test.go
git commit -m "report: load history dir as full payloads plus older summaries"
```

---

### Task 4: CLI 接线（analyze 组装 runs + current 置顶）

**Files:**
- Modify: `cmd/parallax/app.go:241-300`（runAnalyze 的 HTML 分支）
- Test: `cmd/parallax/app_test.go`（若已有该文件则追加；无则新建，仅测组装函数）

**Step 1: 写失败测试**

为可测性，组装逻辑抽为 `buildHistoryRuns(rep *runner.Report, findings []report.Finding, dir string) ([]report.RunPayload, error)`（当前 run 在 index 0，历史取 keep=19 份完整 + 其余摘要，去重：当前 report 的 StartedAt 与历史最新一致时跳过该份）。测试：TempDir 里归档 2 份历史，断言返回 len==3 且 index 0 为当前 run。

**Step 2: 跑测试确认失败**

Run: `go test ./cmd/parallax/ -run TestBuildHistoryRuns -count=1`
Expected: FAIL

**Step 3: 最小实现**

runAnalyze 的 `if cfg.HTML` 分支改为：

```go
runs, err := buildHistoryRuns(&rep, findings, historyDirOrEmpty())
if err != nil {
	return fmt.Errorf("collect history: %w", err)
}
htmlData, err := report.WriteHTMLRuns(runs, 0)
```

（`WriteHTML` 单 run 路径保留，内部已委托 `WriteHTMLRuns`。）

**Step 4: 跑测试确认通过 + 提交**

Run: `go test ./cmd/parallax/ ./report/ -count=1`
Expected: PASS

```bash
git add cmd/parallax/app.go cmd/parallax/app_test.go
git commit -m "cli: analyze embeds history runs into html report with current pinned first"
```

---

### Task 5: 页面侧 applyRun + History tab

**Files:**
- Modify: `report/html.go`（JS：254-267 数据入口、268-303 header 派生、944-991 tab/渲染入口；HTML 骨架加 tab 与 view）

**Step 1: 数据入口改多 run（JS）**

```js
const raw = JSON.parse(document.getElementById("parallax-report").textContent);
const runs = raw.runs && raw.runs.length ? raw.runs : [{ meta: {}, report: raw.report || {}, findings: raw.findings || [] }];
let currentRun = typeof raw.current === "number" ? raw.current : 0;
let rep = {}, findings = [], results = [];
```

原 `const rep / const findings / const results / const clientNames / const knownIds` 全部改 `let`；header 派生段（268-303 行）包进 `function applyRun(i)`：

```js
function applyRun(i) {
  currentRun = Math.max(0, Math.min(i, runs.length - 1));
  const r = runs[currentRun] || {};
  rep = r.report || {};
  findings = r.findings || [];
  results = rep.results || [];
  // 清空 header 容器后重建 badges/meta/gen/knownIds/clientNames
  document.getElementById("badges").textContent = "";
  ...（原 268-303 段逻辑移入，runCmd/knownIds/clientNames 均为函数内派生并赋回外层 let）
  currentClient = ""; clientView = "";   // 重置 client 焦点
  document.getElementById("q-find").value = "";
  renderSummary(); renderFindings(); renderHistory();
  tab(currentTab);                        // 保持当前 tab
}
```

文件尾部 `renderSummary(); renderFindings();` 替换为 `applyRun(currentRun);`。

**Step 2: History tab（HTML 骨架 + JS）**

topbar `.tabs` 内加 `<button class="tab sub" id="tab-history">History</button>`，主区加 `<section id="view-history" class="wrap" style="display:none"></section>`；`tab(name)` 函数补 history 分支（参照现有 summary/findings 写法）。

```js
function renderHistory() {
  const out = document.getElementById("view-history");
  out.textContent = "";
  runs.forEach((r, i) => {
    const m = r.meta || {};
    const card = el("div", "card click" + (i === currentRun ? " active" : ""));
    const head = el("div", "fhead");
    head.append(el("span", "fid", (m.started_at || "?").replace("T", " ").slice(0, 16)));
    head.append(chip(i === currentRun ? "st-pass" : "", i === currentRun ? "current" : "load"));
    if (m.clients) head.append(chip("", m.clients));
    const s = m.summary || {};
    head.append(chip("st-pass", (s.passed || 0) + "/" + (s.total || 0) + " passed"));
    if (s.divergent) head.append(chip("st-divergent", s.divergent + " div"));
    if (m.seed != null) head.append(chip("", "seed " + m.seed));
    card.append(head);
    if (m.command) card.append(el("div", "rules", m.command));
    card.addEventListener("click", () => {
      if (r.report) { applyRun(i); return; }
      loadRunFromFile();   // 摘要条目：文件选择器兜底
    });
    out.append(card);
  });
}

function loadRunFromFile() {
  let inp = document.getElementById("hist-file");
  if (!inp) {
    inp = el("input"); inp.type = "file"; inp.accept = ".json,application/json";
    inp.id = "hist-file"; inp.style.display = "none";
    document.body.append(inp);
    inp.addEventListener("change", () => {
      const f = inp.files[0]; if (!f) return;
      f.text().then(txt => {
        const rep2 = JSON.parse(txt);           // 失败 → catch 提示
        runs = runs.concat([{ meta: {}, report: rep2, findings: [] }]);
        applyRun(runs.length - 1);
      }).catch(() => alert("invalid report json"));
      inp.value = "";
    });
  }
  inp.click();
}
```

（卡片 `.card.active` 样式：`border-color:var(--blue)`，加入 CSS。）

**Step 3: 验证**

- `go test ./report/ -count=1`（payload 结构测试仍过）
- 手工冒烟：用任一历史 report.json 跑 `go run ./cmd/parallax analyze <report>.json -html`，浏览器打开生成的 HTML：History tab 可见、current 卡片高亮、点击其他内嵌 run 整页切换、摘要卡片弹文件选择器。

**Step 4: 提交**

```bash
git add report/html.go
git commit -m "report: history tab with per-run switching and file-picker fallback"
```

---

### Task 6: 收尾验证

**Step 1:** `go build ./... && go test ./... -count=1`
**Step 2:** 端到端冒烟：跑一次 `run`（或复用现有 report）→ 确认 `~/.parallax/history/` 出现归档文件 → `analyze -html` → 打开页面验证 History tab。
**Step 3:** 若一切通过，按用户指示决定是否推送 `feat/spec-pipeline`。
