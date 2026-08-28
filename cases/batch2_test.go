package cases_test

import (
	"testing"

	"libp2p-difftest/testnode"
)

// batch2 scripts: nodes serve every protocol the families touch. The
// deviant variant resets everything except the seed protocols.
func batch2Scripts(deviant bool) map[string][]*testnode.Script {
	ok := func() *testnode.Script {
		return &testnode.Script{Behavior: testnode.Success, Chunks: [][]byte{{0x01}}, ReadRequest: true}
	}
	bad := func() *testnode.Script {
		return &testnode.Script{Behavior: testnode.Reset, ReadRequest: true}
	}
	pick := func() *testnode.Script {
		if deviant {
			return bad()
		}
		return ok()
	}
	return map[string][]*testnode.Script{
		pingProto:    {ok(), pick()},
		statusV2Spec: {ok(), pick()},
		"/eth2/beacon_chain/req/beacon_blocks_by_range/2/ssz_snappy":        {ok(), pick()},
		"/eth2/beacon_chain/req/blob_sidecars_by_range/1/ssz_snappy":        {ok(), pick()},
		"/eth2/beacon_chain/req/data_column_sidecars_by_range/1/ssz_snappy": {ok(), pick()},
		"/eth2/beacon_chain/req/data_column_sidecars_by_root/1/ssz_snappy":  {ok(), pick()},
		"/eth2/beacon_chain/req/goodbye/1/ssz_snappy":                       {ok(), pick()},
		"/eth2/beacon_chain/req/metadata/2/ssz_snappy":                      {ok(), pick()},
	}
}

func TestBatch2FamiliesConvergent(t *testing.T) {
	h := start(t, 2, batch2Scripts(false), nil, nil)
	for _, id := range []string{
		"reqresp.boundary.blocks_by_range.start_max_uint64",
		"reqresp.boundary.blocks_by_range.both_max",
		"reqresp.boundary.blobs_by_range.count_zero",
		"reqresp.boundary.data_columns_by_range.start_max_uint64",
		"reqresp.boundary.ping.varint_max_payload_boundary",
		"reqresp.malformed.ping.truncate_one",
		"reqresp.malformed.ping.break_snappy_crc",
		"reqresp.malformed.ping.random_bytes",
		"reqresp.malformed.ping.varint_zero",
		"reqresp.malformed.ping.varint_over_max_payload",
		"reqresp.malformed.wrong_method_body",
		"reqresp.trailing_bytes.blocks_by_range.32",
		"reqresp.trailing_bytes.data_columns_by_root.32",
		"reqresp.trailing_bytes.goodbye.32",
		"reqresp.trailing_bytes.metadata.32",
		"reqresp.trailing_bytes.ping.extra_snappy_chunk",
		"reqresp.length_bomb.ping.varint_max_uint64",
		"reqresp.length_bomb.status.varint_max_uint64",
		"reqresp.length_bomb.blocks_by_range.snappy_size_bomb",
		"reqresp.length_bomb.ping.varint_max_payload_exact",
	} {
		if divs := runCase(t, h, id); len(divs) != 0 {
			t.Fatalf("%s must converge when nodes behave identically: %+v", id, divs)
		}
	}
}

func TestBatch2FamiliesDivergent(t *testing.T) {
	h := start(t, 2, batch2Scripts(true), nil, nil)
	for _, id := range []string{
		"reqresp.boundary.blocks_by_range.start_max_uint64",
		"reqresp.malformed.ping.truncate_one",
		"reqresp.malformed.status.append_garbage",
		"reqresp.malformed.ping.varint_zero",
		"reqresp.malformed.wrong_method_body",
		"reqresp.trailing_bytes.blobs_by_range.32",
		"reqresp.trailing_bytes.metadata.32",
		"reqresp.length_bomb.ping.varint_max_uint64",
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

func TestBatch2GoodbyeTrailingNormalizes(t *testing.T) {
	// A goodbye that resets is compliant: the deviant node must NOT be
	// flagged on the goodbye trailing-bytes case.
	h := start(t, 2, batch2Scripts(true), nil, nil)
	if divs := runCase(t, h, "reqresp.trailing_bytes.goodbye.32"); len(divs) != 0 {
		t.Fatalf("goodbye reset normalization must prevent divergence: %+v", divs)
	}
}
