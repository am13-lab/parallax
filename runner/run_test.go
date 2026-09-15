package runner_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"parallax/env"
	"parallax/runner"
)

// ---- fakes ----

type fakeClient struct {
	name       string
	healthy    bool
	poison     *atomic.Bool // when non-nil and true, Health fails
	rotations  int
	reqErr     error
	mu         sync.Mutex
	healthErrs map[string]error // client name -> error to return from Health
}

func newFakeClient(name string) *fakeClient {
	return &fakeClient{name: name, healthy: true}
}

func (f *fakeClient) Name() string { return f.name }
func (f *fakeClient) Type() string { return "fake" }
func (f *fakeClient) ReqResp(ctx context.Context, protocol string, body []byte, timeout time.Duration) (*runner.ReqRespResult, error) {
	if f.reqErr != nil {
		return nil, f.reqErr
	}
	return &runner.ReqRespResult{RawBytes: []byte{0x00}}, nil
}
func (f *fakeClient) SendOnly(ctx context.Context, protocol string, body []byte) error {
	return nil
}
func (f *fakeClient) OpenStream(ctx context.Context, protocol string) (runner.IRStream, error) {
	return nil, nil
}
func (f *fakeClient) SendSlowly(ctx context.Context, protocol string, body []byte, perByte, timeout time.Duration) ([]byte, error) {
	return nil, nil
}
func (f *fakeClient) PublishGossip(ctx context.Context, topic string, data []byte) error {
	return nil
}
func (f *fakeClient) PrepareGossipTopic(ctx context.Context, topic string) error {
	return nil
}
func (f *fakeClient) ObserveGossip(ctx context.Context, topic string, data []byte, wait time.Duration) (runner.GossipVerdict, error) {
	return runner.VerdictUnknown, nil
}
func (f *fakeClient) Connect(ctx context.Context, mode runner.ConnectMode) error { return nil }
func (f *fakeClient) RotateIdentity(ctx context.Context) error {
	f.mu.Lock()
	f.rotations++
	f.mu.Unlock()
	return nil
}
func (f *fakeClient) Health(ctx context.Context) error {
	if f.healthErrs != nil {
		if err := f.healthErrs[f.name]; err != nil {
			return err
		}
	}
	if f.poison != nil && f.poison.Load() {
		return errors.New("poisoned")
	}
	if !f.healthy {
		return errors.New("dead")
	}
	return nil
}
func (f *fakeClient) State(ctx context.Context) (*runner.NodeState, error) {
	return nil, runner.ErrNoBeaconAPI
}
func (f *fakeClient) Metadata(ctx context.Context) (*runner.NodeMetadata, error) {
	return nil, runner.ErrNoBeaconAPI
}
func (f *fakeClient) Snapshot(ctx context.Context) (*runner.ResourceSnapshot, error) {
	return &runner.ResourceSnapshot{}, nil
}
func (f *fakeClient) Close() error { return nil }

type fakeEnv struct{ endpoints []env.Endpoint }

func (f *fakeEnv) Endpoints() []env.Endpoint { return f.endpoints }
func (f *fakeEnv) Logs(ctx context.Context, ep env.Endpoint, since time.Time) (io.ReadCloser, error) {
	return nil, env.ErrLogsUnsupported
}
func (f *fakeEnv) Info() map[string]string            { return map[string]string{"provider": "fake"} }
func (f *fakeEnv) Teardown(ctx context.Context) error { return nil }

func fe0() *fakeEnv { return &fakeEnv{} }

// compile-time: fakeClient implements runner.Client
var _ runner.Client = (*fakeClient)(nil)

func spec(id string, run func(ctx context.Context, te runner.TestEnv) []runner.Divergence) runner.Spec {
	return runner.Spec{ID: id, Category: "reqresp", Run: run}
}

func div(id, outlier string) runner.Divergence {
	return runner.Divergence{
		Type:           runner.DivAcceptReject,
		Severity:       runner.SeverityHigh,
		Description:    "test divergence",
		OutlierClients: []string{outlier},
	}
}

// ---- selection ----

func TestSelectionDeterministicBySeed(t *testing.T) {
	var specs []runner.Spec
	for i := 0; i < 10; i++ {
		specs = append(specs, spec(fmt.Sprintf("t.%02d", i), nil))
	}
	a := runner.SelectSpecs(specs, runner.Options{Seed: 7})
	b := runner.SelectSpecs(specs, runner.Options{Seed: 7})
	if len(a) != 10 || len(b) != 10 {
		t.Fatal("selection must not drop specs")
	}
	for i := range a {
		if a[i].ID != b[i].ID {
			t.Fatalf("same seed must give same order: %d %s vs %s", i, a[i].ID, b[i].ID)
		}
	}
}

func TestSelectionFiltersRunClassAndCategory(t *testing.T) {
	specs := []runner.Spec{
		{ID: "a", Category: "reqresp", Run: nil},
		{ID: "h", Category: "reqresp", Metadata: runner.Metadata{RunClass: runner.RunClassHeavy}},
		{ID: "g", Category: "gossip", Run: nil},
	}
	got := runner.SelectSpecs(specs, runner.Options{})
	if len(got) != 2 {
		t.Fatalf("heavy must be excluded by default, got %v", ids(got))
	}
	got = runner.SelectSpecs(specs, runner.Options{IncludeHeavy: true})
	if len(got) != 3 {
		t.Fatalf("IncludeHeavy must include heavy, got %v", ids(got))
	}
	got = runner.SelectSpecs(specs, runner.Options{Categories: []string{"gossip"}})
	if len(got) != 1 || got[0].ID != "g" {
		t.Fatalf("category filter: got %v", ids(got))
	}
	// Exact TestIDs bypass run-class filtering.
	got = runner.SelectSpecs(specs, runner.Options{TestIDs: []string{"h"}})
	if len(got) != 1 || got[0].ID != "h" {
		t.Fatalf("TestIDs must bypass run class: got %v", ids(got))
	}
}

func ids(specs []runner.Spec) []string {
	out := make([]string, len(specs))
	for i, s := range specs {
		out[i] = s.ID
	}
	return out
}

// ---- run ----

func TestRunPassAndReport(t *testing.T) {
	cs := []runner.Client{newFakeClient("a"), newFakeClient("b")}
	fe := &fakeEnv{}
	var progressed []string
	rep := runner.Run(context.Background(),
		[]runner.Spec{spec("t.ok", func(ctx context.Context, te runner.TestEnv) []runner.Divergence { return nil })},
		cs, fe, runner.ChainConfig{Preset: "mainnet"},
		runner.Options{Seed: 1, Progress: func(r runner.TestResult) { progressed = append(progressed, r.TestID) }},
	)
	if rep.Summary.Passed != 1 || rep.Summary.Total != 1 {
		t.Fatalf("summary: %+v", rep.Summary)
	}
	if rep.Results[0].Status != runner.StatusPass {
		t.Fatalf("status: %v", rep.Results[0].Status)
	}
	if len(progressed) != 1 || progressed[0] != "t.ok" {
		t.Fatalf("progress: %v", progressed)
	}
	if rep.Environment["provider"] != "fake" {
		t.Fatalf("environment info: %v", rep.Environment)
	}
	if rep.SchemaVersion != 1 {
		t.Fatalf("schema version: %d", rep.SchemaVersion)
	}
}

func TestRunNormalizesDivergence(t *testing.T) {
	cs := []runner.Client{newFakeClient("a"), newFakeClient("b")}
	rep := runner.Run(context.Background(),
		[]runner.Spec{spec("t.div", func(ctx context.Context, te runner.TestEnv) []runner.Divergence {
			return []runner.Divergence{div("t.div", "b")}
		})},
		cs, fe0(), runner.ChainConfig{}, runner.Options{Seed: 1},
	)
	r := rep.Results[0]
	if r.Status != runner.StatusDivergent {
		t.Fatalf("status: %v", r.Status)
	}
	d := r.Divergences[0]
	if d.TestID != "t.div" || d.Category != "reqresp" {
		t.Fatalf("runner must fill test id and category: %+v", d)
	}
	if d.RunClass != runner.RunClassStandard {
		t.Fatalf("run class must be normalized: %v", d.RunClass)
	}
}

func TestRunSkipsBelowMinClients(t *testing.T) {
	cs := []runner.Client{&fakeClient{name: "a"}}
	rep := runner.Run(context.Background(),
		[]runner.Spec{spec("t.solo", func(ctx context.Context, te runner.TestEnv) []runner.Divergence {
			return []runner.Divergence{div("x", "b")}
		})},
		cs, fe0(), runner.ChainConfig{}, runner.Options{Seed: 1},
	)
	if rep.Results[0].Status != runner.StatusSkipped {
		t.Fatalf("default min clients is 2, must skip: %+v", rep.Results[0])
	}

	rep = runner.Run(context.Background(),
		[]runner.Spec{runner.Spec{ID: "t.solo", Category: "reqresp", Metadata: runner.Metadata{MinClients: 1},
			Run: func(ctx context.Context, te runner.TestEnv) []runner.Divergence { return nil }}},
		cs, fe0(), runner.ChainConfig{}, runner.Options{Seed: 1},
	)
	if rep.Results[0].Status != runner.StatusPass {
		t.Fatalf("MinClients=1 must run with one client: %+v", rep.Results[0])
	}
}

func TestRunPreflightSkip(t *testing.T) {
	cs := []runner.Client{newFakeClient("a"), newFakeClient("b")}
	s := runner.Spec{ID: "t.pre", Category: "reqresp",
		Preflight: func(ctx context.Context, chain runner.ChainConfig, cs []runner.Client) runner.PreflightResult {
			return runner.PreflightResult{Runnable: false, Reason: "no data sidecars"}
		},
		Run: func(ctx context.Context, te runner.TestEnv) []runner.Divergence { return nil },
	}
	rep := runner.Run(context.Background(), []runner.Spec{s}, cs, fe0(), runner.ChainConfig{}, runner.Options{Seed: 1})
	if rep.Results[0].Status != runner.StatusSkipped || rep.Results[0].SkipReason != "no data sidecars" {
		t.Fatalf("preflight skip: %+v", rep.Results[0])
	}
}

func TestBanExclusion(t *testing.T) {
	a := newFakeClient("a")
	poison := &atomic.Bool{}
	a.poison = poison
	cs := []runner.Client{a, newFakeClient("b")}

	specs := []runner.Spec{
		spec("t.poison", func(ctx context.Context, te runner.TestEnv) []runner.Divergence {
			poison.Store(true)
			return nil
		}),
		spec("t.after", func(ctx context.Context, te runner.TestEnv) []runner.Divergence { return nil }),
	}
	rep := runner.Run(context.Background(), specs, cs, fe0(), runner.ChainConfig{},
		runner.Options{Seed: 1, BanThreshold: 1}) // seed 1: poison then after

	after := rep.Results[1]
	if after.TestID != "t.after" || after.Status != runner.StatusSkipped {
		t.Fatalf("t.after must skip with one usable client: %+v", after)
	}
	if len(after.ExcludedClients) != 1 || after.ExcludedClients[0] != "a" {
		t.Fatalf("excluded clients must be recorded: %v", after.ExcludedClients)
	}
}

func TestBanRecovery(t *testing.T) {
	a := newFakeClient("a")
	poison := &atomic.Bool{}
	a.poison = poison
	b := newFakeClient("b")
	cs := []runner.Client{a, b}

	seenCounts := map[string]int{}
	var mu sync.Mutex

	// Exact TestIDs bypass run-class filtering but keep the specs-slice
	// order: poison, heal, after, recovered. t.poison bans a; t.heal
	// (single-client) restores a's health; the recovery probe must then
	// reinstate a before t.after and t.recovered.
	specs := []runner.Spec{
		spec("t.poison", func(ctx context.Context, te runner.TestEnv) []runner.Divergence {
			poison.Store(true)
			return nil
		}),
		{ID: "t.heal", Category: "reqresp", Metadata: runner.Metadata{MinClients: 1},
			Run: func(ctx context.Context, te runner.TestEnv) []runner.Divergence {
				poison.Store(false)
				return nil
			}},
		spec("t.after", func(ctx context.Context, te runner.TestEnv) []runner.Divergence { return nil }),
		spec("t.recovered", func(ctx context.Context, te runner.TestEnv) []runner.Divergence {
			mu.Lock()
			seenCounts["recovered"] = len(te.Clients)
			mu.Unlock()
			return nil
		}),
	}
	rep := runner.Run(context.Background(), specs, cs, fe0(), runner.ChainConfig{},
		runner.Options{TestIDs: []string{"t.poison", "t.after", "t.heal", "t.recovered"},
			BanThreshold: 1, RecoveryCooldown: time.Microsecond})

	byID := map[string]runner.TestResult{}
	for _, r := range rep.Results {
		byID[r.TestID] = r
	}
	for _, id := range []string{"t.poison", "t.heal", "t.after", "t.recovered"} {
		if byID[id].Status != runner.StatusPass {
			t.Fatalf("%s must pass after recovery: %+v", id, byID[id])
		}
	}
	mu.Lock()
	n := seenCounts["recovered"]
	mu.Unlock()
	if n != 2 {
		t.Fatalf("reinstated client must participate, saw %d clients", n)
	}
}

// TestBanRecoveryZeroDisables pins the other half of the §5.4 contract:
// with RecoveryCooldown == 0 a banned client is never re-probed and stays
// excluded for the rest of the run.
func TestBanRecoveryZeroDisables(t *testing.T) {
	a := newFakeClient("a")
	poison := &atomic.Bool{}
	a.poison = poison
	b := newFakeClient("b")
	cs := []runner.Client{a, b}

	specs := []runner.Spec{
		spec("t.poison", func(ctx context.Context, te runner.TestEnv) []runner.Divergence {
			poison.Store(true)
			return nil
		}),
		{ID: "t.heal", Category: "reqresp", Metadata: runner.Metadata{MinClients: 1},
			Run: func(ctx context.Context, te runner.TestEnv) []runner.Divergence {
				poison.Store(false)
				return nil
			}},
		spec("t.recovered", nil),
	}
	rep := runner.Run(context.Background(), specs, cs, fe0(), runner.ChainConfig{},
		runner.Options{TestIDs: []string{"t.poison", "t.heal", "t.recovered"},
			BanThreshold: 1, RecoveryCooldown: 0})

	// With recovery disabled, "a" stays banned: only "b" remains usable,
	// below the default MinClients floor, so t.recovered must skip and
	// record the exclusion.
	byID := map[string]runner.TestResult{}
	for _, r := range rep.Results {
		byID[r.TestID] = r
	}
	r := byID["t.recovered"]
	if r.Status != runner.StatusSkipped {
		t.Fatalf("cooldown 0 must disable recovery: t.recovered must skip with one usable client: %+v", r)
	}
	if len(r.ExcludedClients) != 1 || r.ExcludedClients[0] != "a" {
		t.Fatalf("excluded clients must record the banned client: %v", r.ExcludedClients)
	}
}

func TestMaxDurationStopsScheduling(t *testing.T) {
	cs := []runner.Client{newFakeClient("a"), newFakeClient("b")}
	var specs []runner.Spec
	for i := 0; i < 5; i++ {
		specs = append(specs, spec(fmt.Sprintf("t.%d", i), nil))
	}
	rep := runner.Run(context.Background(), specs, cs, fe0(), runner.ChainConfig{},
		runner.Options{Seed: 1, InterTestDelay: 100 * time.Millisecond, MaxDuration: 150 * time.Millisecond},
	)
	if rep.Summary.Executed >= 5 {
		t.Fatalf("deadline must stop the run: %+v", rep.Summary)
	}
	if rep.Summary.StopReason != "deadline" {
		t.Fatalf("stop reason: %q", rep.Summary.StopReason)
	}
}

func TestRotateEvery(t *testing.T) {
	cs := []runner.Client{newFakeClient("a"), newFakeClient("b")}
	specs := []runner.Spec{spec("t.1", nil), spec("t.2", nil)}
	runner.Run(context.Background(), specs, cs, fe0(), runner.ChainConfig{},
		runner.Options{Seed: 1, RotateEvery: 1},
	)
	for _, c := range cs {
		fc := c.(*fakeClient)
		fc.mu.Lock()
		r := fc.rotations
		fc.mu.Unlock()
		if r == 0 {
			t.Fatalf("client %s must have rotated", fc.name)
		}
	}
}

func TestPerTestTimeout(t *testing.T) {
	cs := []runner.Client{newFakeClient("a"), newFakeClient("b")}
	s := spec("t.slow", func(ctx context.Context, te runner.TestEnv) []runner.Divergence {
		<-ctx.Done()
		return nil
	})
	rep := runner.Run(context.Background(), []runner.Spec{s}, cs, fe0(), runner.ChainConfig{},
		runner.Options{Seed: 1, PerTestTimeout: 100 * time.Millisecond},
	)
	if rep.Results[0].Status != runner.StatusPass {
		t.Fatalf("cancelled test still completes: %+v", rep.Results[0])
	}
	if rep.Results[0].ElapsedDuration > 2*time.Second {
		t.Fatalf("timeout must bound the test: %v", rep.Results[0].Elapsed)
	}
}

func TestPanicBecomesError(t *testing.T) {
	cs := []runner.Client{newFakeClient("a"), newFakeClient("b")}
	s := spec("t.boom", func(ctx context.Context, te runner.TestEnv) []runner.Divergence {
		panic("boom")
	})
	rep := runner.Run(context.Background(), []runner.Spec{s}, cs, fe0(), runner.ChainConfig{}, runner.Options{Seed: 1})
	if rep.Results[0].Status != runner.StatusError {
		t.Fatalf("panic must become StatusError: %+v", rep.Results[0])
	}
	if rep.Summary.Errors != 1 {
		t.Fatalf("summary errors: %+v", rep.Summary)
	}
}

func TestSystemicHealthFailureDoesNotBan(t *testing.T) {
	// When EVERY client fails the post-test health check, the failure is
	// environmental (host stall): no client may be banned.
	a := newFakeClient("a")
	b := newFakeClient("b")
	poison := &atomic.Bool{}
	a.poison, b.poison = poison, poison
	cs := []runner.Client{a, b}

	seen := map[string]int{}
	var mu sync.Mutex
	specs := []runner.Spec{
		spec("t.first", func(ctx context.Context, te runner.TestEnv) []runner.Divergence {
			poison.Store(true) // everything dies during this test
			return nil
		}),
		spec("t.second", func(ctx context.Context, te runner.TestEnv) []runner.Divergence {
			mu.Lock()
			seen["clients"] = len(te.Clients)
			mu.Unlock()
			return nil
		}),
	}
	rep := runner.Run(context.Background(), specs, cs, fe0(), runner.ChainConfig{},
		runner.Options{Seed: 1, BanThreshold: 1})

	mu.Lock()
	n := seen["clients"]
	mu.Unlock()
	if n != 2 {
		t.Fatalf("systemic failure must not ban: t.second saw %d clients (excluded=%v)", n, rep.Results[1].ExcludedClients)
	}
}
