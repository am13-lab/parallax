package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/hive/hivesim"

	"libp2p-difftest/env"
	"libp2p-difftest/runner"
)

// fakeRunnerClient satisfies runner.Client without any network.
type fakeRunnerClient struct{ name string }

func (f *fakeRunnerClient) Name() string { return f.name }
func (f *fakeRunnerClient) Type() string { return "fake" }
func (f *fakeRunnerClient) ReqResp(ctx context.Context, protocol string, body []byte, timeout time.Duration) (*runner.ReqRespResult, error) {
	return &runner.ReqRespResult{}, nil
}
func (f *fakeRunnerClient) SendOnly(ctx context.Context, protocol string, body []byte) error {
	return nil
}
func (f *fakeRunnerClient) SendSlowly(ctx context.Context, protocol string, body []byte, perByte, timeout time.Duration) ([]byte, error) {
	return nil, nil
}
func (f *fakeRunnerClient) PublishGossip(ctx context.Context, topic string, data []byte) error {
	return nil
}
func (f *fakeRunnerClient) PrepareGossipTopic(ctx context.Context, topic string) error {
	return nil
}
func (f *fakeRunnerClient) ObserveGossip(ctx context.Context, topic string, data []byte, wait time.Duration) (runner.GossipVerdict, error) {
	return runner.VerdictUnknown, nil
}
func (f *fakeRunnerClient) Connect(ctx context.Context, mode runner.ConnectMode) error { return nil }
func (f *fakeRunnerClient) RotateIdentity(ctx context.Context) error                   { return nil }
func (f *fakeRunnerClient) Health(ctx context.Context) error                           { return nil }
func (f *fakeRunnerClient) State(ctx context.Context) (*runner.NodeState, error) {
	return nil, runner.ErrNoBeaconAPI
}
func (f *fakeRunnerClient) Metadata(ctx context.Context) (*runner.NodeMetadata, error) {
	return nil, runner.ErrNoBeaconAPI
}
func (f *fakeRunnerClient) Snapshot(ctx context.Context) (*runner.ResourceSnapshot, error) {
	return &runner.ResourceSnapshot{}, nil
}
func (f *fakeRunnerClient) Close() error { return nil }

// fakeHive implements the subset of the hive simulation API that hivesim
// uses: suite/test creation and completion, client start, client listing.
type fakeHive struct {
	mu        sync.Mutex
	nextID    int
	suites    map[int]bool
	tests     map[int]bool
	ended     map[int]bool
	nodes     int
	testNames map[int]string
	failures  []string // test names ended with pass=false
	beaconURL string   // fake client beacon API base
}

func newFakeHive(beaconURL string) *fakeHive {
	return &fakeHive{
		suites:    map[int]bool{},
		tests:     map[int]bool{},
		ended:     map[int]bool{},
		testNames: map[int]string{},
		beaconURL: beaconURL,
	}
}

func (f *fakeHive) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	path := r.URL.Path

	switch {
	case path == "/testsuite" && r.Method == http.MethodPost:
		f.nextID++
		f.suites[f.nextID] = true
		fmt.Fprintf(w, "%d", f.nextID)

	case strings.HasPrefix(path, "/testsuite/") && strings.HasSuffix(path, "/test") && r.Method == http.MethodPost:
		var body struct {
			Name string `json:"name"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		f.nextID++
		f.tests[f.nextID] = true
		f.testNames[f.nextID] = body.Name
		fmt.Fprintf(w, "%d", f.nextID)

	case strings.HasPrefix(path, "/testsuite/") && strings.Contains(path, "/node") && r.Method == http.MethodPost:
		// Multipart node start: respond with id + IP. The fake client's
		// IP is 127.0.0.1, with the beacon port handled by the config.
		f.nodes++
		w.Write([]byte(fmt.Sprintf(`{"id":"container-%d","ip":"127.0.0.1"}`, f.nodes)))

	case strings.HasSuffix(path, "/test") && r.Method == http.MethodPost:
		// handled above

	case strings.Count(path, "/") >= 3 && strings.Contains(path, "/test/") && r.Method == http.MethodPost:
		// end test: /testsuite/{suite}/test/{test}; body {"pass":bool}.
		// (fmt.Sscanf cannot suppress verbs with %*, so split the path.)
		var body struct {
			Pass bool `json:"pass"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		parts := strings.Split(path, "/")
		var id int
		fmt.Sscanf(parts[len(parts)-1], "%d", &id)
		f.ended[id] = true
		if !body.Pass {
			f.failures = append(f.failures, f.testNames[id])
		}
		w.WriteHeader(http.StatusOK)

	case strings.HasPrefix(path, "/testsuite/") && r.Method == http.MethodDelete:
		w.WriteHeader(http.StatusOK)

	case path == "/clients" && r.Method == http.MethodGet:
		w.Write([]byte(`[]`))

	default:
		// test creation also matches "/testsuite/{id}/test" exactly;
		// anything else is fine to accept silently.
		w.WriteHeader(http.StatusOK)
	}
}

// fake beacon API serving a fixed identity.
func fakeBeacon(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/eth/v1/node/identity", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"peer_id": "16Uiu2HAmPDunVHhEmpkswudvcraieeesLQVZrg7RMVgcrotboWqf",
				"enr":     "",
			},
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestHiveSuiteRun(t *testing.T) {
	beacon := fakeBeacon(t)
	fake := newFakeHive(beacon.URL)
	simServer := httptest.NewServer(fake)
	t.Cleanup(simServer.Close)

	specsRun := map[string]int{}
	fakeClients := func(ctx context.Context, ep env.Endpoint) (runner.Client, error) {
		return &fakeRunnerClient{name: ep.Name}, nil
	}
	cfg := Config{
		ClientTypes:   []string{"prysm", "lighthouse"},
		Categories:    []string{"reqresp", "transport"},
		ClientFactory: fakeClients,
		HTTPPort: func(string) int {
			_, port, _ := net.SplitHostPort(strings.TrimPrefix(beacon.URL, "http://"))
			var p int
			fmt.Sscanf(port, "%d", &p)
			return p
		},
		P2PPort: 9000,
		SpecsFor: func(category string) []runner.Spec {
			return []runner.Spec{{
				ID:       category + ".fake",
				Category: category,
				Run: func(ctx context.Context, te runner.TestEnv) []runner.Divergence {
					specsRun[category] = len(te.Clients)
					return nil
				},
			}}
		},
		Chain:     runner.ChainConfig{Preset: "mainnet"},
		WaitReady: 5 * time.Second,
	}

	sim := hivesim.NewAt(simServer.URL)
	if err := hivesim.RunSuite(sim, BuildSuite(cfg)); err != nil {
		t.Fatalf("run suite: %v", err)
	}

	if fake.nodes != 4 { // 2 clients x 2 categories
		t.Fatalf("node starts: %d", fake.nodes)
	}
	if specsRun["reqresp"] != 2 || specsRun["transport"] != 2 {
		t.Fatalf("specs must see both clients: %v", specsRun)
	}
	if len(fake.failures) != 0 {
		t.Fatalf("convergent fake specs must pass: %v", fake.failures)
	}
}

func TestHiveSuiteFailureMapping(t *testing.T) {
	beacon := fakeBeacon(t)
	fake := newFakeHive(beacon.URL)
	simServer := httptest.NewServer(fake)
	t.Cleanup(simServer.Close)

	cfg := Config{
		ClientTypes: []string{"prysm"},
		Categories:  []string{"reqresp"},
		ClientFactory: func(ctx context.Context, ep env.Endpoint) (runner.Client, error) {
			return &fakeRunnerClient{name: ep.Name}, nil
		},
		HTTPPort: func(string) int { return 3500 },
		P2PPort:  9000,
		SpecsFor: func(category string) []runner.Spec {
			return []runner.Spec{{
				ID:       "reqresp.divergent",
				Category: category,
				Run: func(ctx context.Context, te runner.TestEnv) []runner.Divergence {
					return []runner.Divergence{{
						TestID:        "reqresp.divergent",
						Category:      category,
						Type:          runner.DivAcceptReject,
						Severity:      runner.SeverityHigh,
						Description:   "fake divergence",
						ClientResults: map[string]string{"prysm": "accept"},
					}}
				},
			}}
		},
		Chain:     runner.ChainConfig{},
		WaitReady: 5 * time.Second,
	}

	sim := hivesim.NewAt(simServer.URL)
	if err := hivesim.RunSuite(sim, BuildSuite(cfg)); err != nil {
		t.Fatalf("run suite: %v", err)
	}
	if len(fake.failures) != 1 {
		t.Fatalf("divergent spec must fail the hive test: %v", fake.failures)
	}
	if fake.failures[0] != "p2p-reqresp" {
		t.Fatalf("failure must record the real test name, got %q", fake.failures[0])
	}
}
