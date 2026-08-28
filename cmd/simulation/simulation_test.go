package main

import (
	"os"
	"path/filepath"
	"testing"

	"libp2p-difftest/runner"
)

func TestRunSimulationProducesDivergences(t *testing.T) {
	dir := t.TempDir()
	rep, err := runSimulation(SimConfig{Out: dir})
	if err != nil {
		t.Fatalf("simulation: %v", err)
	}

	if rep.Summary.Total != 39 {
		t.Fatalf("seed set size: %d", rep.Summary.Total)
	}
	// The deviant node rejects all pings (the script cannot branch on the
	// body), so both ping cases diverge; plus unknown protocol, gossip
	// verdict, and fork digest.
	// teku-c rejects all pings, so the ported still-connected check also
	// flags it on every Status exchange: 5 protocol divergences + 6 status.
	if rep.Summary.Divergent != 11 {
		t.Fatalf("expected 11 divergences from the scripted deviant node: %+v", rep.Summary)
	}

	byID := map[string]runner.TestResult{}
	for _, r := range rep.Results {
		byID[r.TestID] = r
	}
	wantDivergent := []string{
		"reqresp.ping.empty_body",
		"reqresp.ping.extra_bytes",
		"reqresp.status.boundary.head_slot_max_uint64",
		"reqresp.status.boundary.finalized_epoch_max_uint64",
		"reqresp.status.boundary.earliest_slot_max_uint64",
		"reqresp.status.boundary.all_slots_max_uint64",
		"reqresp.status.finalized_mismatch",
		"reqresp.status.fork_mismatch",
		"reqresp.unknown_protocol",
		"gossip.block.malformed",
		"discovery.fork_digest",
	}
	for _, id := range wantDivergent {
		r, ok := byID[id]
		if !ok {
			t.Fatalf("missing result for %s", id)
		}
		if r.Status != runner.StatusDivergent {
			t.Fatalf("%s must diverge: %+v", id, r)
		}
		if len(r.Divergences[0].OutlierClients) == 0 || r.Divergences[0].OutlierClients[0] != "teku-c" {
			t.Fatalf("%s outlier must be the deviant node teku-c: %+v", id, r.Divergences[0])
		}
	}

	// Artifacts must exist on disk.
	if _, err := os.Stat(filepath.Join(dir, "report.json")); err != nil {
		t.Fatalf("report.json: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "junit.xml")); err != nil {
		t.Fatalf("junit.xml: %v", err)
	}
}
