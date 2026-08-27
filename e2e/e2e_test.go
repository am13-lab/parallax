package e2e_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"libp2p-difftest/client"
	"libp2p-difftest/env/staticenv"
	"libp2p-difftest/report"
	"libp2p-difftest/runner"
	"libp2p-difftest/testnode"
	"libp2p-difftest/wire"
)

const pingProto = "/eth2/beacon_chain/req/ping/1/ssz_snappy"

// TestEndToEndMiniSuite exercises the whole engine against fake nodes:
// two testnodes, a static environment, real clients, three specs (pass,
// divergent, skipped), JSON and JUnit output.
func TestEndToEndMiniSuite(t *testing.T) {
	// Node A accepts pings; node B resets them, producing a divergence.
	nodeA, err := testnode.Start(&testnode.Config{
		Protocols: map[string]*testnode.Script{
			pingProto: {Behavior: testnode.Success, Chunks: [][]byte{{0x01}}, ReadRequest: true},
		},
		Beacon: &testnode.BeaconConfig{ENR: "", HeadSlot: 32},
	})
	if err != nil {
		t.Fatalf("nodeA: %v", err)
	}
	t.Cleanup(nodeA.Close)
	nodeB, err := testnode.Start(&testnode.Config{
		Protocols: map[string]*testnode.Script{
			pingProto: {Behavior: testnode.Reset},
		},
		Beacon: &testnode.BeaconConfig{ENR: "", HeadSlot: 32},
	})
	if err != nil {
		t.Fatalf("nodeB: %v", err)
	}
	t.Cleanup(nodeB.Close)

	envCfg := &staticenv.Config{Clients: []staticenv.ClientEntry{
		{Name: "a", ClientType: "fake-a", Multiaddr: nodeA.Multiaddr(), BeaconAPI: nodeA.BeaconURL()},
		{Name: "b", ClientType: "fake-b", Multiaddr: nodeB.Multiaddr(), BeaconAPI: nodeB.BeaconURL()},
	}}
	e, err := staticenv.New(envCfg)
	if err != nil {
		t.Fatalf("env: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	var clients []runner.Client
	for _, ep := range e.Endpoints() {
		c, err := client.New(ctx, &client.Config{
			Name:       ep.Name,
			ClientType: ep.ClientType,
			Multiaddr:  ep.Multiaddr,
			BeaconAPI:  ep.BeaconAPI,
		})
		if err != nil {
			t.Fatalf("client %s: %v", ep.Name, err)
		}
		clients = append(clients, c)
		t.Cleanup(func() { c.Close() })
	}

	specs := []runner.Spec{
		{ID: "e2e.ping.ok", Category: "reqresp",
			Run: func(ctx context.Context, te runner.TestEnv) []runner.Divergence { return nil }},
		{ID: "e2e.ping.divergent", Category: "reqresp",
			Run: func(ctx context.Context, te runner.TestEnv) []runner.Divergence {
				var divs []runner.Divergence
				results := map[string]string{}
				for _, c := range te.Clients {
					res, err := c.ReqResp(ctx, pingProto, wire.BuildSSZSnappy([]byte{0x00}), 3*time.Second)
					if err != nil {
						results[c.Name()] = "error: " + err.Error()
						continue
					}
					if res.StreamReset {
						results[c.Name()] = "reset"
					} else {
						results[c.Name()] = "respond"
					}
				}
				verdicts := map[string]bool{}
				for _, v := range results {
					verdicts[v] = true
				}
				if len(verdicts) > 1 {
					for name, v := range results {
						if v == "reset" {
							divs = append(divs, runner.Divergence{
								Type:          runner.DivAcceptReject,
								Severity:      runner.SeverityHigh,
								Description:   "e2e.ping.divergent: responses differ",
								ClientResults: results,
								OutlierClients: []string{name},
							})
						}
					}
				}
				return divs
			}},
		{ID: "e2e.needs.three", Category: "reqresp", Metadata: runner.Metadata{MinClients: 3},
			Run: func(ctx context.Context, te runner.TestEnv) []runner.Divergence { return nil }},
	}

	rep := runner.Run(ctx, specs, clients, e, runner.ChainConfig{Preset: "mainnet"},
		runner.Options{Seed: 42})

	if rep.Summary.Total != 3 {
		t.Fatalf("summary: %+v", rep.Summary)
	}
	if rep.Summary.Passed != 1 || rep.Summary.Divergent != 1 || rep.Summary.Skipped != 1 {
		t.Fatalf("counts wrong: %+v", rep.Summary)
	}
	var divResult runner.TestResult
	for _, r := range rep.Results {
		if r.TestID == "e2e.ping.divergent" {
			divResult = r
		}
	}
	if divResult.Status != runner.StatusDivergent || len(divResult.Divergences) != 1 {
		t.Fatalf("divergence expected in e2e.ping.divergent: %+v", divResult)
	}
	div := divResult.Divergences[0]
	if len(div.ClientResults) != 2 || div.OutlierClients[0] != "b" {
		t.Fatalf("divergence payload: %+v", div)
	}

	// Reports must be consumable.
	dir := t.TempDir()
	jsonData, err := report.WriteJSON(rep)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "report.json"), jsonData, 0o644); err != nil {
		t.Fatal(err)
	}
	junit, err := report.WriteJUnit(rep)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(junit), `<testsuite name="reqresp"`) {
		t.Fatalf("junit shape: %s", junit)
	}
	findings := report.BuildFindings(rep, false)
	if len(findings) != 1 || findings[0].EvidenceCount != 1 {
		t.Fatalf("findings: %+v", findings)
	}
}
