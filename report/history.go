package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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

// CollectRuns assembles the runs array for one HTML report: the current run
// pinned first, then up to keep-1 newest archived runs embedded in full,
// then older archived runs as meta-only summaries. Archived copies that are
// the same run as current (same stamp and seed) are dropped as duplicates.
func CollectRuns(rep *runner.Report, findings []Finding, dir string, keep int) ([]RunPayload, error) {
	if keep < 1 {
		keep = 1
	}
	cur, err := runPayload(rep, findings)
	if err != nil {
		return nil, err
	}
	historyFull, historySummaries, err := LoadHistory(dir, keep)
	if err != nil {
		// History is best-effort: an unreadable dir degrades to a
		// single-run page rather than failing the report.
		historyFull, historySummaries = nil, nil
	}
	runs := make([]RunPayload, 0, 1+len(historyFull)+len(historySummaries))
	runs = append(runs, cur)
	for _, h := range historyFull {
		if h.Meta.Stamp == cur.Meta.Stamp && h.Meta.Seed == cur.Meta.Seed {
			continue
		}
		if len(runs) >= keep {
			runs = append(runs, RunPayload{Meta: h.Meta})
			continue
		}
		runs = append(runs, h)
	}
	for _, m := range historySummaries {
		if m.Stamp == cur.Meta.Stamp && m.Seed == cur.Meta.Seed {
			continue
		}
		runs = append(runs, RunPayload{Meta: m})
	}
	return runs, nil
}

// metaOf extracts the history-list summary of one report.
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

// LoadHistory reads dir and returns up to keep newest runs as full payloads
// (with freshly computed findings); older runs degrade to meta-only
// summaries. Corrupt or unreadable files are skipped. A missing dir is not
// an error: it yields no runs. Sort is newest first.
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
		at   time.Time
		path string
	}
	var items []item
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		path := filepath.Join(dir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var rep runner.Report
		if err := json.Unmarshal(data, &rep); err != nil {
			continue
		}
		items = append(items, item{meta: metaOf(&rep), at: rep.StartedAt, path: path})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].at.After(items[j].at) })
	var full []RunPayload
	var summaries []RunMeta
	for i, it := range items {
		if i >= keep {
			summaries = append(summaries, it.meta)
			continue
		}
		data, err := os.ReadFile(it.path)
		if err != nil {
			continue
		}
		var rep runner.Report
		if err := json.Unmarshal(data, &rep); err != nil {
			continue
		}
		run, err := runPayload(&rep, BuildFindings(&rep, false))
		if err != nil {
			continue
		}
		full = append(full, run)
	}
	return full, summaries, nil
}
