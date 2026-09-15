package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/ethereum/hive/hivesim"

	"parallax/client"
	"parallax/cases"
	"parallax/enr"
	"parallax/env"
	"parallax/runner"
)

// Config configures the simulator.
type Config struct {
	ClientTypes []string
	Categories  []string
	// HTTPPort maps a client type to its beacon API port inside the hive
	// network. Defaults differ per client; adjust when the hive fork's
	// client definitions differ.
	HTTPPort func(clientType string) int
	// P2PPort is the clients' libp2p TCP port (9000 in all hive CL defs).
	P2PPort int
	// SpecsFor returns the runner specs for one category. Injectable for
	// tests; the default pulls from the cases registry.
	SpecsFor func(category string) []runner.Spec
	// ClientFactory constructs a runner.Client for an endpoint. Nil selects
	// the default libp2p client; tests inject fakes.
	ClientFactory func(ctx context.Context, ep env.Endpoint) (runner.Client, error)
	// Chain is the chain config the network was launched with.
	Chain runner.ChainConfig
	// WaitReady bounds per-client beacon API readiness.
	WaitReady time.Duration
}

// DefaultHTTPPort lists beacon API ports used by hive CL client definitions.
func DefaultHTTPPort(clientType string) int {
	switch clientType {
	case "nimbus":
		return 5052
	case "lodestar":
		return 9596
	case "teku", "grandine":
		return 4008
	default: // prysm, lighthouse
		return 3500
	}
}

// BuildSuite builds one hive test case per difftest category.
func BuildSuite(cfg Config) hivesim.Suite {
	suite := hivesim.Suite{
		Name:        "beacon-p2p",
		Description: "Differential libp2p testing of consensus clients",
	}
	categories := cfg.Categories
	if len(categories) == 0 {
		categories = []string{"reqresp", "gossip", "discovery", "transport"}
	}
	for _, cat := range categories {
		category := cat
		suite.Add(hivesim.TestSpec{
			Name:        "p2p-" + category,
			DisplayName: "P2P differential: " + category,
			Description: "Runs the " + category + " differential case set against all configured clients on a shared chain.",
			Run: func(t *hivesim.T) {
				runCategory(t, cfg, category)
			},
		})
	}
	return suite
}

// runCategory launches one node per client type on the shared network,
// waits for their beacon APIs, runs the category's specs, and reports
// divergences as a hive test failure.
func runCategory(t *hivesim.T, cfg Config, category string) {
	specsFor := cfg.SpecsFor
	if specsFor == nil {
		// Production default: pull from the cases registry, matching the
		// contract's "production paths use the cases registry" (§11).
		specsFor = cases.ByCategory
	}
	specs := specsFor(category)
	if len(specs) == 0 {
		t.Logf("no specs for category %s, skipping", category)
		return
	}

	var eps []env.Endpoint
	for _, ct := range cfg.ClientTypes {
		c := t.StartClient(ct)
		ep := env.Endpoint{
			Name:       ct,
			ClientType: ct,
			Service:    c.Container,
			Multiaddr:  fmt.Sprintf("/ip4/%s/tcp/%d/p2p/", c.IP, cfg.P2PPort),
			BeaconAPI:  fmt.Sprintf("http://%s:%d", c.IP, cfg.HTTPPort(ct)),
		}
		if err := waitIdentity(ep.BeaconAPI, cfg.WaitReady); err != nil {
			t.Errorf("client %s not ready: %v", ct, err)
			return
		}
		peerID, digest, err := fetchIdentity(ep.BeaconAPI)
		if err != nil {
			t.Errorf("client %s identity: %v", ct, err)
			return
		}
		ep.Multiaddr += peerID
		eps = append(eps, ep)
		t.Logf("client %s ready: peer=%s fork_digest=%x", ct, peerID, digest)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	factory := cfg.ClientFactory
	if factory == nil {
		factory = func(ctx context.Context, ep env.Endpoint) (runner.Client, error) {
			return client.New(ctx, &client.Config{
				Name:       ep.Name,
				ClientType: ep.ClientType,
				Multiaddr:  ep.Multiaddr,
				BeaconAPI:  ep.BeaconAPI,
			})
		}
	}
	var clients []runner.Client
	for _, ep := range eps {
		c, err := factory(ctx, ep)
		if err != nil {
			t.Errorf("connect to %s: %v", ep.Name, err)
			return
		}
		defer c.Close()
		clients = append(clients, c)
	}

	rep := runner.Run(ctx, specs, clients, &hiveEnv{endpoints: eps}, cfg.Chain, runner.Options{
		Seed:           time.Now().UnixNano(),
		PerTestTimeout: 2 * time.Minute,
		Progress: func(r runner.TestResult) {
			t.Logf("%-45s %s", r.TestID, r.Status)
		},
	})

	out, _ := json.MarshalIndent(rep, "", "  ")
	t.Logf("report:\n%s", out)

	if rep.Summary.Divergent > 0 || rep.Summary.Errors > 0 {
		for _, r := range rep.Results {
			for _, d := range r.Divergences {
				t.Errorf("%s: %s (results: %v)", r.TestID, d.Description, d.ClientResults)
			}
		}
	}
}

// waitIdentity polls the beacon API identity endpoint until ready.
func waitIdentity(base string, wait time.Duration) error {
	deadline := time.Now().Add(wait)
	if wait <= 0 {
		wait = 2 * time.Minute
		deadline = time.Now().Add(wait)
	}
	for time.Now().Before(deadline) {
		if _, _, err := fetchIdentity(base); err == nil {
			return nil
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("not ready within %v", wait)
}

func fetchIdentity(base string) (peerID string, digest [4]byte, err error) {
	resp, err := http.Get(base + "/eth/v1/node/identity")
	if err != nil {
		return "", digest, err
	}
	defer resp.Body.Close()
	var body struct {
		Data struct {
			PeerID string `json:"peer_id"`
			ENR    string `json:"enr"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", digest, err
	}
	if body.Data.PeerID == "" {
		return "", digest, fmt.Errorf("empty peer id")
	}
	if rec, derr := enr.DecodeENR(body.Data.ENR); derr == nil {
		if fid, ferr := rec.GetEth2(); ferr == nil {
			digest = fid.ForkDigest
		}
	}
	return body.Data.PeerID, digest, nil
}

// hiveEnv adapts the started clients into the runner's Environment.
type hiveEnv struct{ endpoints []env.Endpoint }

func (h *hiveEnv) Endpoints() []env.Endpoint { return h.endpoints }

func (h *hiveEnv) Logs(ctx context.Context, ep env.Endpoint, since time.Time) (io.ReadCloser, error) {
	return nil, env.ErrLogsUnsupported
}

func (h *hiveEnv) Info() map[string]string {
	return map[string]string{"provider": "hive"}
}

func (h *hiveEnv) Teardown(ctx context.Context) error { return nil }
