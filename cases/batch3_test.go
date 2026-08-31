package cases_test

import (
	"testing"

	"parallax/testnode"
)

// batch3 scripts: transport/exhaustion abuse goes to ping; gossip topics
// are subscribed by both nodes; the Gloas protocols are served by default.
func batch3Scripts(deviant bool) map[string][]*testnode.Script {
	ok := func() *testnode.Script {
		return &testnode.Script{Behavior: testnode.Success, Chunks: [][]byte{{0x01}}, ReadRequest: true}
	}
	pick := func() *testnode.Script {
		if deviant {
			return &testnode.Script{Behavior: testnode.Reset, ReadRequest: true}
		}
		return ok()
	}
	return map[string][]*testnode.Script{
		pingProto:    {ok(), pick()},
		statusV2Spec: {ok(), pick()},
	}
}

func TestBatch3TransportExhaustion(t *testing.T) {
	h := start(t, 2, batch3Scripts(false), nil, nil)
	for _, id := range []string{
		"transporttest.handshake.stalled_single",
		"transporttest.handshake.stalled_no_stream",
		"reqresp.exhaustion.slow_request",
		"reqresp.exhaustion.half_open_stream",
		"reqresp.exhaustion.never_read_response",
	} {
		if divs := runCase(t, h, id); len(divs) != 0 {
			t.Fatalf("%s must converge on identical nodes: %+v", id, divs)
		}
	}
}

func TestBatch3TransportDivergent(t *testing.T) {
	h := start(t, 2, batch3Scripts(true), nil, nil)
	for _, id := range []string{
		"transporttest.corrupted.random_bytes",
		"transporttest.corrupted.post_valid_garbage",
		"reqresp.exhaustion.slow_request",
	} {
		divs := runCase(t, h, id)
		if len(divs) != 1 {
			t.Fatalf("%s must diverge with a deviant node: %+v", id, divs)
		}
	}
}

func TestBatch3GossipFamilies(t *testing.T) {
	relayOn := []bool{true, true}
	att0 := "/eth2/deadbeef/beacon_attestation_0/ssz_snappy"
	h := startBeacons(t, 2, map[string][]*testnode.Script{}, relayOn,
		[]string{gossipTopic, att0}, nil)
	for _, id := range []string{
		"gossipsub.malformed.truncated_ssz",
		"gossipsub.malformed.zero_length",
		"gossipsub.attestation_stale.offset_0",
	} {
		// Against relay-everything testnodes, garbage payloads are relayed:
		// convergent accept. The divergent direction is proven by the
		// reject-mode relay node.
		if divs := runCase(t, h, id); len(divs) != 0 {
			t.Fatalf("%s must converge with relay-all nodes: %+v", id, divs)
		}
	}
}

func TestBatch3GossipDivergent(t *testing.T) {
	relayMixed := []bool{true, false}
	att64 := "/eth2/deadbeef/beacon_attestation_64/ssz_snappy"
	h := startBeacons(t, 2, map[string][]*testnode.Script{}, relayMixed,
		[]string{gossipTopic, att64}, nil)
	for _, id := range []string{
		"gossipsub.malformed.broken_snappy",
		"gossipsub.attestation_subnet_oob.64",
	} {
		divs := runCase(t, h, id)
		if len(divs) != 1 {
			t.Fatalf("%s must diverge with a rejecting node: %+v", id, divs)
		}
	}
}

func TestBatch3UnknownTopicTimesOut(t *testing.T) {
	// Nobody subscribes to the unknown topic: both clients reject (weak
	// negative) and the case converges.
	h := start(t, 1, map[string][]*testnode.Script{}, nil, nil)
	if divs := runCase(t, h, "gossipsub.unknown_topic"); len(divs) != 0 {
		t.Fatalf("uniform timeout must converge: %+v", divs)
	}
}

func TestBatch3ProtocolFamilies(t *testing.T) {
	h := start(t, 2, batch3Scripts(false), nil, nil)
	for _, id := range []string{
		"reqresp.data_columns_by_range.columns_oob",
		"reqresp.data_columns_by_range.zero_columns",
	} {
		if divs := runCase(t, h, id); len(divs) != 0 {
			t.Fatalf("%s must converge on identical nodes: %+v", id, divs)
		}
	}
}
