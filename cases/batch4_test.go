package cases_test

import (
	"testing"

	"libp2p-difftest/cases"
	"libp2p-difftest/testnode"
)

func TestBatch4GeneratorsDeterministic(t *testing.T) {
	// Generator output must be stable: same IDs in the same order across
	// calls, since seeds and reproducibility depend on it.
	a := registryIDs()
	b := registryIDs()
	if len(a) == 0 {
		t.Fatal("generators produced no cases")
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("generator output unstable at %d: %s vs %s", i, a[i], b[i])
		}
	}
}

func TestBatch4CryptomsgConvergentAndDivergent(t *testing.T) {
	h := start(t, 2, batch3Scripts(false), nil, nil)
	for _, id := range []string{
		"cryptomsg.ping.truncate_one.tiny",
		"cryptomsg.status.break_crc.large",
		"cryptomsg.varint.ping.128",
	} {
		if divs := runCase(t, h, id); len(divs) != 0 {
			t.Fatalf("%s must converge on identical nodes: %+v", id, divs)
		}
	}
	h2 := start(t, 2, batch3Scripts(true), nil, nil)
	divs := runCase(t, h2, "cryptomsg.ping.truncate_one.tiny")
	if len(divs) != 1 {
		t.Fatalf("deviant node must diverge: %+v", divs)
	}
}

func TestBatch4StatemachineSequence(t *testing.T) {
	h := start(t, 2, batch3Scripts(false), nil, nil)
	// Any generated sequence must converge on identical nodes: run the
	// first registered statemachine case (generators are deterministic).
	var seqID string
	for _, s := range cases.All() {
		if s.Category == "statemachine" {
			seqID = s.ID
			break
		}
	}
	if seqID == "" {
		t.Fatal("no statemachine cases registered")
	}
	divs := runCase(t, h, seqID)
	if len(divs) != 0 {
		t.Fatalf("identical nodes must produce identical step vectors: %+v", divs)
	}
}

// strictScripts serve requests but reject invalid frames like a
// spec-conformant client.
func strictScripts() map[string][]*testnode.Script {
	ok := func() *testnode.Script {
		return &testnode.Script{Behavior: testnode.Success, Chunks: [][]byte{{0x01}},
			ReadRequest: true, StrictRequest: true}
	}
	return map[string][]*testnode.Script{
		pingProto:    {ok(), ok()},
		statusV2Spec: {ok(), ok()},
		"/eth2/beacon_chain/req/metadata/2/ssz_snappy":               {ok(), ok()},
		"/eth2/beacon_chain/req/beacon_blocks_by_range/2/ssz_snappy": {ok(), ok()},
	}
}

func TestBatch4SemanticValidSingleClient(t *testing.T) {
	h := startBeacons(t, 2, strictScripts(), nil, nil, nil)
	// The fake nodes validate framing only, so SSZ-level expectations
	// (zero counts and friends) are exercised against real clients in live
	// runs, not here.
	for _, id := range []string{
		"semantic_valid.ping_valid_accepts",
		"semantic_valid.ping_truncated_rejects",
	} {
		if divs := runCase(t, h, id); len(divs) != 0 {
			t.Fatalf("%s: compliant fake nodes must satisfy the checks: %+v", id, divs)
		}
	}
}
