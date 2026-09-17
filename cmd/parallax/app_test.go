package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"parallax/env"
	"parallax/report"
	"parallax/runner"
	"parallax/testnode"
)

func TestRunList(t *testing.T) {
	var buf bytes.Buffer
	if err := runList(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "reqresp.ping.empty_body") || !strings.Contains(out, "gossip.block.malformed") {
		t.Fatalf("list output: %s", out)
	}
	if !strings.Contains(out, "reqresp") || !strings.Contains(out, "transport") {
		t.Fatalf("categories missing: %s", out)
	}
}

func TestParseRunArgsDefaults(t *testing.T) {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	var cfg RunConfig
	if err := parseRunArgs(fs, &cfg, nil); err != nil {
		t.Fatal(err)
	}
	if cfg.Env != "static" || cfg.Seed != 42 || cfg.Preset != "mainnet" {
		t.Fatalf("defaults: %+v", cfg)
	}
	// Simplified-run defaults: hive is one flag away from a full run.
	if cfg.Enclave != "parallax" {
		t.Fatalf("enclave default: %q", cfg.Enclave)
	}
	if cfg.SpecsDir != "" {
		t.Fatalf("specs-dir default must be empty (auto-resolved), got %q", cfg.SpecsDir)
	}
	wantClients := "lighthouse,teku,prysm,nimbus,lodestar,grandine"
	if cfg.HiveClientList != wantClients {
		t.Fatalf("hive-clients default: %q", cfg.HiveClientList)
	}

	fs = flag.NewFlagSet("run", flag.ContinueOnError)
	cfg = RunConfig{}
	err := parseRunArgs(fs, &cfg, []string{"-env", "kurtosis", "-enclave", "e1", "-test", "a.b, c.d", "-category", "reqresp"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Enclave != "e1" || len(cfg.TestIDs) != 2 || cfg.TestIDs[1] != "c.d" || cfg.Categories[0] != "reqresp" {
		t.Fatalf("parsed: %+v", cfg)
	}
}

func TestAnalyzeWithAllowlistAndLegacy(t *testing.T) {
	dir := t.TempDir()
	rep := &runner.Report{
		SchemaVersion: 1,
		Seed:          1,
		Results: []runner.TestResult{
			{TestID: "known.one", Category: "reqresp", Status: runner.StatusDivergent,
				Divergences: []runner.Divergence{
					{TestID: "known.one", Type: runner.DivOperational, OutlierClients: []string{"nimbus"}},
				}},
		},
		Summary: runner.Summary{Total: 1, Divergent: 1, Executed: 1},
	}
	data, err := report.WriteJSON(rep)
	if err != nil {
		t.Fatal(err)
	}
	reportPath := filepath.Join(dir, "report.json")
	if err := os.WriteFile(reportPath, data, 0o644); err != nil {
		t.Fatal(err)
	}
	alPath := filepath.Join(dir, "allowlist.json")
	if err := os.WriteFile(alPath, []byte(`{"entries":[{"test_pattern":"known.*","client":"nimbus","action":"suppress","reason":"known"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	err = runAnalyze(AnalyzeConfig{ReportPath: reportPath, AllowlistPath: alPath, Legacy: true}, &buf)
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "suppressed") || !strings.Contains(out, "known") {
		t.Fatalf("analyze output: %s", out)
	}
	if _, err := os.Stat(strings.TrimSuffix(reportPath, ".json") + ".legacy.json"); err != nil {
		t.Fatalf("legacy file: %v", err)
	}
}

// runRun smoke: static env against two live testnodes with a single
// convergent case.
// recordingEnv observes whether teardownEnv releases the environment.
// ctxLive/ctxHasDeadline snapshot the ctx state at teardown time, since
// the teardown-scoped ctx is cancelled when teardownEnv returns.
type recordingEnv struct {
	torndown       bool
	err            error
	ctxLive        bool
	ctxHasDeadline bool
}

func (f *recordingEnv) Endpoints() []env.Endpoint { return nil }
func (f *recordingEnv) Logs(ctx context.Context, ep env.Endpoint, since time.Time) (io.ReadCloser, error) {
	return nil, env.ErrLogsUnsupported
}
func (f *recordingEnv) Info() map[string]string { return nil }
func (f *recordingEnv) Teardown(ctx context.Context) error {
	f.torndown = true
	f.ctxLive = ctx.Err() == nil
	_, f.ctxHasDeadline = ctx.Deadline()
	return f.err
}

// A finished run must release provisioned environments (containers,
// volumes). Attached environments are not owned by the run and survive it.
func TestTeardownEnvAfterRun(t *testing.T) {
	t.Run("provisioned env is torn down", func(t *testing.T) {
		e := &recordingEnv{}
		var buf bytes.Buffer
		teardownEnv(e, RunConfig{Env: "kurtosis", Stdout: &buf})
		if !e.torndown {
			t.Fatal("provisioned env must be torn down after the run")
		}
	})
	t.Run("attached env survives the run", func(t *testing.T) {
		e := &recordingEnv{}
		var buf bytes.Buffer
		teardownEnv(e, RunConfig{Env: "kurtosis", Attach: true, Stdout: &buf})
		if e.torndown {
			t.Fatal("attached env must not be destroyed by the run")
		}
	})
	t.Run("hive env is torn down", func(t *testing.T) {
		e := &recordingEnv{}
		var buf bytes.Buffer
		teardownEnv(e, RunConfig{Env: "hive", Stdout: &buf})
		if !e.torndown {
			t.Fatal("hive env must be torn down after the run")
		}
	})
	t.Run("teardown error is reported without aborting", func(t *testing.T) {
		e := &recordingEnv{err: errors.New("boom")}
		var buf bytes.Buffer
		teardownEnv(e, RunConfig{Env: "hive", Stdout: &buf})
		if !strings.Contains(buf.String(), "boom") {
			t.Fatalf("teardown error must be reported, got: %s", buf.String())
		}
	})
	t.Run("teardown survives a cancelled run context", func(t *testing.T) {
		// An interrupted run (Ctrl-C, deadline) must still be able to
		// release the environment: teardown must run on its own live,
		// timeout-bounded context instead of the run's dead one.
		e := &recordingEnv{}
		var buf bytes.Buffer
		teardownEnv(e, RunConfig{Env: "kurtosis", Stdout: &buf})
		if !e.torndown {
			t.Fatal("teardown must run even when the run ctx is cancelled")
		}
		if !e.ctxLive {
			t.Fatal("teardown ctx must be live at teardown time")
		}
		if !e.ctxHasDeadline {
			t.Fatal("teardown ctx must carry a timeout")
		}
	})
}

func TestRunRunSmoke(t *testing.T) {
	ping := "/eth2/beacon_chain/req/ping/1/ssz_snappy"
	mkNode := func(behavior testnode.Behavior) *testnode.Node {
		n, err := testnode.Start(&testnode.Config{
			Protocols: map[string]*testnode.Script{ping: {Behavior: behavior, Chunks: [][]byte{{0x01}}}},
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(n.Close)
		return n
	}
	n1 := mkNode(testnode.Success)
	n2 := mkNode(testnode.Success)

	dir := t.TempDir()
	configPath := filepath.Join(dir, "clients.yaml")
	content := "clients:\n" +
		"  - name: a\n    client_type: fake\n    multiaddr: " + n1.Multiaddr() + "\n" +
		"  - name: b\n    client_type: fake\n    multiaddr: " + n2.Multiaddr() + "\n"
	if err := os.WriteFile(configPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	err := runRun(context.Background(), RunConfig{
		Env:            "static",
		ConfigPath:     configPath,
		TestIDs:        []string{"reqresp.ping.empty_body"},
		Seed:           1,
		PerTestTimeout: 30 * time.Second,
		OutputDir:      filepath.Join(dir, "results"),
		Preset:         "mainnet",
		Stdout:         &buf,
	})
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "pass=1") {
		t.Fatalf("smoke summary: %s", out)
	}
	if _, err := os.Stat(filepath.Join(dir, "results", "report.json")); err != nil {
		t.Fatalf("report missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "results", "junit.xml")); err != nil {
		t.Fatalf("junit missing: %v", err)
	}
}

func TestConsensusSpecsURLPlainView(t *testing.T) {
	u := consensusSpecsURL("consensus-specs/specs/fulu/p2p-interface.md", 835)
	want := "https://github.com/ethereum/consensus-specs/blob/master/specs/fulu/p2p-interface.md?plain=1#L835"
	if u != want {
		t.Fatalf("got %q, want %q (GitHub renders .md by default and drops #L anchors; ?plain=1 forces the line-numbered source view)", u, want)
	}
	if !strings.Contains(u, "?plain=1#L") {
		t.Fatal("markdown spec links must force the plain (line-numbered) view")
	}
}
