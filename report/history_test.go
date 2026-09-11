package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"parallax/runner"
)

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
	if err := os.WriteFile(filepath.Join(dir, "broken.json"), []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	full, summaries, err := LoadHistory(dir, 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(full) != 20 {
		t.Fatalf("full = %d, want 20", len(full))
	}
	if len(summaries) != 3 {
		t.Fatalf("summaries = %d, want 3", len(summaries))
	}
	if full[0].Meta.Seed != 22 {
		t.Fatalf("newest first violated: seed %d", full[0].Meta.Seed)
	}
	for _, s := range summaries {
		if s.Stamp == "" || s.StartedAt == "" {
			t.Fatal("summary missing meta identity")
		}
	}
	if full[0].Findings == nil {
		t.Fatal("full run missing findings")
	}
}

func TestLoadHistoryMissingDir(t *testing.T) {
	full, summaries, err := LoadHistory(filepath.Join(t.TempDir(), "nope"), 20)
	if err != nil {
		t.Fatalf("missing dir should degrade: %v", err)
	}
	if full != nil || summaries != nil {
		t.Fatal("missing dir should return nil runs")
	}
}

func TestCollectRunsPinsCurrentAndDedupes(t *testing.T) {
	dir := t.TempDir()
	cur := &runner.Report{
		StartedAt: time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC),
		EndedAt:   time.Date(2026, 9, 2, 0, 1, 0, 0, time.UTC),
		Seed:      9,
	}
	if err := ArchiveRunTo(dir, cur); err != nil { // run already archived its own copy
		t.Fatal(err)
	}
	for i := 1; i <= 3; i++ {
		if err := ArchiveRunTo(dir, &runner.Report{
			StartedAt: time.Date(2026, 9, 1, 0, i, 0, 0, time.UTC),
			EndedAt:   time.Date(2026, 9, 1, 0, i, 30, 0, time.UTC),
			Seed:      int64(i),
		}); err != nil {
			t.Fatal(err)
		}
	}
	runs, err := CollectRuns(cur, nil, dir, 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 4 {
		t.Fatalf("runs = %d, want 4 (current + 3 history, duplicate dropped)", len(runs))
	}
	if runs[0].Meta.Seed != 9 {
		t.Fatalf("current not pinned first: seed %d", runs[0].Meta.Seed)
	}
	count := 0
	for _, r := range runs {
		if r.Meta.Seed == 9 {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("current duplicated %d times", count)
	}

	// cap: keep=2 → current + 1 full history, the rest degrade to summaries
	runs, err = CollectRuns(cur, nil, dir, 2)
	if err != nil {
		t.Fatal(err)
	}
	fullCount, sumCount := 0, 0
	for _, r := range runs {
		if r.Report != nil {
			fullCount++
		} else {
			sumCount++
		}
	}
	if fullCount != 2 || sumCount != 2 {
		t.Fatalf("cap violated: full=%d summaries=%d", fullCount, sumCount)
	}
}

func TestCollectRunsKeepsAllWhenCurrentNotArchived(t *testing.T) {
	dir := t.TempDir()
	for i := 1; i <= 5; i++ {
		if err := ArchiveRunTo(dir, &runner.Report{
			StartedAt: time.Date(2026, 9, 1, 0, i, 0, 0, time.UTC),
			EndedAt:   time.Date(2026, 9, 1, 0, i, 30, 0, time.UTC),
			Seed:      int64(i),
		}); err != nil {
			t.Fatal(err)
		}
	}
	cur := &runner.Report{ // never archived
		StartedAt: time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC),
		EndedAt:   time.Date(2026, 9, 9, 0, 1, 0, 0, time.UTC),
		Seed:      99,
	}
	runs, err := CollectRuns(cur, nil, dir, 4)
	if err != nil {
		t.Fatal(err)
	}
	full, summaries := 0, 0
	seen := map[int64]bool{}
	for _, r := range runs {
		if r.Report != nil {
			full++
		} else {
			summaries++
		}
		seen[r.Meta.Seed] = true
	}
	if full != 4 || summaries != 2 {
		t.Fatalf("runs = %d (full=%d summaries=%d), want 6 (full=4 summaries=2)", len(runs), full, summaries)
	}
	for seed := int64(1); seed <= 5; seed++ {
		if !seen[seed] {
			t.Fatalf("history seed %d silently dropped", seed)
		}
	}
}

func TestCollectRunsUnreadableDirDegrades(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "locked")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := ArchiveRunTo(dir, &runner.Report{
		StartedAt: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
		EndedAt:   time.Date(2026, 9, 1, 0, 1, 0, 0, time.UTC),
		Seed:      1,
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Skipf("cannot lock dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	cur := &runner.Report{
		StartedAt: time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC),
		EndedAt:   time.Date(2026, 9, 2, 0, 1, 0, 0, time.UTC),
		Seed:      2,
	}
	runs, err := CollectRuns(cur, nil, dir, 20)
	if err != nil {
		t.Fatalf("unreadable history dir must degrade, not fail: %v", err)
	}
	if len(runs) != 1 || runs[0].Meta.Seed != 2 {
		t.Fatalf("expected current-only runs, got %+v", runs)
	}
}
