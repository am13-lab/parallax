package main

import (
	"os"
	"path/filepath"
	"testing"

	"parallax/runner"
)

func TestRunSimulationProducesDivergences(t *testing.T) {
	dir := t.TempDir()
	rep, err := runSimulation(SimConfig{Out: dir})
	if err != nil {
		t.Fatalf("simulation: %v", err)
	}

	if rep.Summary.Total != 215 {
		t.Fatalf("standard-class selection size: %d", rep.Summary.Total)
	}
	// The deviant node rejects all pings (the script cannot branch on the
	// body), so both ping cases diverge; plus unknown protocol, gossip
	// verdict, and fork digest.
	// teku-c rejects all pings, so every ping-based case diverges on it
	// (protocol families, status still-connected checks, the cryptomsg
	// ping sweep, statemachine sequences containing ping steps, and the
	// semantic single-client checks applied per client).
	if rep.Summary.Divergent != 93 {
		t.Fatalf("expected 92 divergences from the scripted deviant node: %+v", rep.Summary)
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
		"reqresp.malformed.ping.truncate_one",
		"reqresp.length_bomb.ping.varint_max_uint64",
		"reqresp.trailing_bytes.ping.extra_snappy_chunk",
		"cryptomsg.ping.truncate_one.tiny",
		"cryptomsg.varint.ping.128",
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
