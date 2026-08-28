package cases_test

import (
	"context"
	"testing"

	"libp2p-difftest/cases"
	"libp2p-difftest/internal/testutil"
	"libp2p-difftest/runner"
	"libp2p-difftest/testnode"
)

// statusScripts keeps both nodes serving status v1/v2 and pings so the
// handshake and still-connected checks succeed.
func statusScripts(deviant bool) map[string][]*testnode.Script {
	b := &testnode.Script{Behavior: testnode.Reset, ReadRequest: true}
	if !deviant {
		b = &testnode.Script{Behavior: testnode.Success, Chunks: [][]byte{make([]byte, 92)}, ReadRequest: true}
	}
	ok := &testnode.Script{Behavior: testnode.Success, Chunks: [][]byte{{0x01}}, ReadRequest: true}
	return map[string][]*testnode.Script{
		"/eth2/beacon_chain/req/status/2/ssz_snappy": {ok, b},
		"/eth2/beacon_chain/req/status/1/ssz_snappy": {ok, ok},
		pingProto: {ok, ok},
	}
}

func runCase(t *testing.T, h *harness, id string) []runner.Divergence {
	t.Helper()
	spec, ok := cases.ByID(id)
	if !ok {
		t.Fatalf("case %s not registered", id)
	}
	return spec.Run(context.Background(), h.env())
}

func TestStatusFamilyConvergent(t *testing.T) {
	enrs := digestENRs([4]byte{0xde, 0xad, 0xbe, 0xef})
	h := start(t, 2, statusScripts(false), nil, enrs)
	for _, id := range []string{
		"reqresp.status.boundary.head_slot_max_uint64",
		"reqresp.status.boundary.finalized_epoch_max_uint64",
		"reqresp.status.boundary.earliest_slot_max_uint64",
		"reqresp.status.boundary.all_slots_max_uint64",
		"reqresp.status.finalized_mismatch",
		"reqresp.status.fork_mismatch",
	} {
		if divs := runCase(t, h, id); len(divs) != 0 {
			t.Fatalf("%s must converge when nodes behave identically: %+v", id, divs)
		}
	}
}

func TestStatusFamilyDivergent(t *testing.T) {
	enrs := digestENRs([4]byte{0xde, 0xad, 0xbe, 0xef})
	h := start(t, 2, statusScripts(true), nil, enrs)
	for _, id := range []string{
		"reqresp.status.boundary.head_slot_max_uint64",
		"reqresp.status.finalized_mismatch",
		"reqresp.status.fork_mismatch",
	} {
		divs := runCase(t, h, id)
		if len(divs) != 1 {
			t.Fatalf("%s must diverge with a deviant node: %+v", id, divs)
		}
		if len(divs[0].OutlierClients) != 1 || divs[0].OutlierClients[0] != "B" {
			t.Fatalf("%s outlier must be B: %+v", id, divs[0])
		}
	}
}

// digestENRs wraps one fork digest into identical ENRs for both nodes.
func digestENRs(digest [4]byte) [][]byte {
	eth2 := make([]byte, 16)
	copy(eth2[0:4], digest[:])
	return [][]byte{eth2, eth2}
}

// compliantENR builds a fully spec-compliant ENR with every field the
// structure cases inspect.
func compliantENR(digest [4]byte, nextVersion [4]byte, nextEpoch uint64) string {
	eth2 := make([]byte, 16)
	copy(eth2[0:4], digest[:])
	copy(eth2[4:8], nextVersion[:])
	for i := 8; i < 16; i++ {
		eth2[i] = byte(nextEpoch >> (8 * (15 - i))) // big-endian epoch in last 8 bytes
	}
	return testutil.BuildTestENRFields(map[string][]byte{
		"eth2":     eth2,
		"attnets":  []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		"syncnets": {0x0f},
		"cgc":      {8},
		"nfd":      {0xaa, 0xbb, 0xcc, 0xdd},
		"ip":       {127, 0, 0, 1},
		"tcp":      {0x23, 0x28},
	})
}

// compliantBeacons returns two identical fully compliant beacon configs.
func compliantBeacons(digest [4]byte) []*testnode.BeaconConfig {
	mk := func() *testnode.BeaconConfig {
		return &testnode.BeaconConfig{
			ENR:           compliantENR(digest, [4]byte{0x05, 0, 0, 0}, 269568),
			HeadSlot:      64,
			MetaSeqNumber: 7,
			MetaAttnets:   "0xffffffffffffffff",
			MetaSyncnets:  "0x0f",
			MetaCGC:       "4",
		}
	}
	return []*testnode.BeaconConfig{mk(), mk()}
}

func TestENRFamiliesConvergent(t *testing.T) {
	var digest [4]byte = [4]byte{0xde, 0xad, 0xbe, 0xef}
	h := startBeacons(t, 2, map[string][]*testnode.Script{
		"/eth2/beacon_chain/req/status/1/ssz_snappy": {{Behavior: testnode.Success, Chunks: [][]byte{make([]byte, 84)}, ReadRequest: true}},
		pingProto: {{Behavior: testnode.Success, Chunks: [][]byte{{0x01}}, ReadRequest: true}},
	}, nil, compliantBeacons(digest))
	h.chain.CustodyRequirement = 4

	for _, id := range []string{
		"discovery.enr.eth2_field_present",
		"discovery.enr.eth2_field_size",
		"discovery.enr.secp256k1_present",
		"discovery.enr.attnets_size",
		"discovery.enr.syncnets_size",
		"discovery.enr.cgc_encoding",
		"discovery.enr.nfd_size",
		"discovery.enr.ip_field_valid",
		"discovery.enr.has_transport",
		"discovery.enr.seq_number_nonzero",
		"discovery.consistency.next_fork_version",
		"discovery.consistency.next_fork_epoch",
		"discovery.consistency.nfd_value",
		"discovery.consistency.cgc_minimum",
		"discovery.metadata.attnets_match_enr",
		"discovery.metadata.syncnets_match_enr",
		"discovery.metadata.seq_number_positive",
		"discovery.metadata.custody_group_count",
	} {
		if divs := runCase(t, h, id); len(divs) != 0 {
			t.Fatalf("%s must converge on compliant nodes: %+v", id, divs[0].Description)
		}
	}
}

func TestENRStructureDivergent(t *testing.T) {
	var digest [4]byte = [4]byte{0xde, 0xad, 0xbe, 0xef}
	beacons := compliantBeacons(digest)
	// Deviant node B: ENR without the eth2 key.
	eth2less := testutil.BuildTestENRFields(map[string][]byte{
		"attnets": []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		"tcp":     {0x23, 0x28},
	})
	beacons[1].ENR = eth2less

	h := startBeacons(t, 2, map[string][]*testnode.Script{}, nil, beacons)
	divs := runCase(t, h, "discovery.enr.eth2_field_present")
	if len(divs) != 1 || len(divs[0].OutlierClients) != 1 || divs[0].OutlierClients[0] != "B" {
		t.Fatalf("missing eth2 must diverge with B as outlier: %+v", divs)
	}
}

func TestConsistencyDivergent(t *testing.T) {
	var digest [4]byte = [4]byte{0xde, 0xad, 0xbe, 0xef}
	beacons := compliantBeacons(digest)
	// Node B advertises a different next fork version.
	beacons[1].ENR = compliantENR(digest, [4]byte{0x06, 0, 0, 0}, 269568)

	h := startBeacons(t, 2, map[string][]*testnode.Script{}, nil, beacons)
	divs := runCase(t, h, "discovery.consistency.next_fork_version")
	if len(divs) != 1 || divs[0].Type != runner.DivConsensusValue {
		t.Fatalf("next fork version mismatch must be a consensus value divergence: %+v", divs)
	}
}

func TestMetadataMismatchDivergent(t *testing.T) {
	var digest [4]byte = [4]byte{0xde, 0xad, 0xbe, 0xef}
	beacons := compliantBeacons(digest)
	// Node B's metadata attnets disagree with its ENR.
	beacons[1].MetaAttnets = "0x00000000000000ff"

	h := startBeacons(t, 2, map[string][]*testnode.Script{}, nil, beacons)
	divs := runCase(t, h, "discovery.metadata.attnets_match_enr")
	if len(divs) != 1 {
		t.Fatalf("attnets mismatch must diverge: %+v", divs)
	}
}
