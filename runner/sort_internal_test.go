package runner

import (
	"reflect"
	"testing"
)

// TestSortPollutingLast verifies the batch ordering: families that send
// deliberately invalid input (and thus trigger client peer-scoring bans)
// execute last, and within each group the shuffled order is preserved.
func TestSortPollutingLast(t *testing.T) {
	in := []Spec{
		{ID: "cryptomsg.ping.a", Category: "cryptomsg"},
		{ID: "reqresp.ping.empty_body", Category: "reqresp"},
		{ID: "reqresp.malformed.ping.x", Category: "reqresp"},
		{ID: "gossip.block.malformed", Category: "gossip"},
		{ID: "discovery.fork_digest", Category: "discovery"},
		{ID: "gossipsub.replay.dup", Category: "gossipsub"},
		{ID: "transporttest.corrupted.x", Category: "transport"},
		{ID: "reqresp.status.valid", Category: "reqresp"},
		{ID: "reqresp.length_bomb.ping.y", Category: "reqresp"},
	}
	want := []string{
		"reqresp.ping.empty_body",
		"discovery.fork_digest",
		"reqresp.status.valid",
		"cryptomsg.ping.a",
		"reqresp.malformed.ping.x",
		"gossip.block.malformed",
		"gossipsub.replay.dup",
		"transporttest.corrupted.x",
		"reqresp.length_bomb.ping.y",
	}

	sortPollutingLast(in)
	got := make([]string, 0, len(in))
	for _, s := range in {
		got = append(got, s.ID)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("order mismatch:\n got %v\nwant %v", got, want)
	}
}

// TestIsPolluting pins the classification.
func TestIsPolluting(t *testing.T) {
	polluting := []Spec{
		{ID: "cryptomsg.varint.ping.1", Category: "cryptomsg"},
		{ID: "cryptomsg.ping.truncate_half.small", Category: "reqresp"},
		{ID: "gossip.block.malformed", Category: "gossip"},
		{ID: "gossipsub.invalid_flood", Category: "gossipsub"},
		{ID: "transporttest.corrupted.random_bytes", Category: "transport"},
		{ID: "reqresp.malformed.status.truncate", Category: "reqresp"},
		{ID: "reqresp.length_bomb.ping.z", Category: "reqresp"},
		{ID: "reqresp.trailing_bytes.ping.extra", Category: "reqresp"},
		{ID: "reqresp.exhaustion.slow_request", Category: "reqresp"},
		// statemachine sequences embed garbage-status steps; lighthouse
		// penalizes those too (measured: re-ban by case ~43 in the batch).
		{ID: "statemachine.seq.04.status_valid.ping_truncated.status_garbage", Category: "statemachine"},
		{ID: "statemachine.seq.28.status_garbage.status_valid.ping_valid", Category: "statemachine"},
		// boundary-value requests are format-legal but penalized as
		// imperfect by lighthouse/grandine.
		{ID: "reqresp.status.boundary.head_slot_max_uint64", Category: "reqresp"},
		{ID: "reqresp.boundary.ping.varint_max_payload_boundary", Category: "reqresp"},
	}
	for _, s := range polluting {
		if !isPolluting(s) {
			t.Errorf("isPolluting(%s) = false, want true", s.ID)
		}
	}
	clean := []Spec{
		{ID: "reqresp.ping.empty_body", Category: "reqresp"},
		{ID: "reqresp.status.valid", Category: "reqresp"},
		{ID: "discovery.fork_digest", Category: "discovery"},
		{ID: "semantic_valid.ping_valid_accepts", Category: "semantic_valid"},
		{ID: "reqresp.unknown_protocol", Category: "reqresp"},
	}
	for _, s := range clean {
		if isPolluting(s) {
			t.Errorf("isPolluting(%s) = true, want false", s.ID)
		}
	}
}
