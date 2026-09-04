package cases

import (
	"context"
	"encoding/binary"
	"fmt"
	"time"

	"parallax/runner"
	"parallax/wire"
)

const statusV2 = "/eth2/beacon_chain/req/status/2/ssz_snappy"

// statusBoundarySpec builds one Status boundary case: valid chain state with
// selected numeric fields replaced by MaxUint64, probing arithmetic safety
// in peer classification. After the exchange a Ping verifies the peer did
// not disconnect us.
func statusBoundarySpec(label string, setHead, setFinalized, setEarliest bool) runner.Spec {
	var what string
	switch {
	case setHead && setFinalized && setEarliest:
		what = "head slot, finalized epoch and earliest available slot"
	case setHead:
		what = "head slot"
	case setFinalized:
		what = "finalized epoch"
	default:
		what = "earliest available slot"
	}
	return runner.Spec{
		ID:       fmt.Sprintf("reqresp.status.boundary.%s", label),
		Category: "reqresp",
		What:     "Sends Status/2 with " + what + " = MaxUint64 (otherwise valid live state); the client must process the boundary without crashing or dropping the connection.",
		Metadata: runner.Metadata{
			SpecRules:    []string{"reqresp:status", "reqresp:ssz-decoding"},
			KnowledgeIDs: []string{"SHERLOCK-1140-status-boundary"},
		},
		Preflight: requireChainState,
		Run: func(ctx context.Context, te runner.TestEnv) []runner.Divergence {
			results := map[string]string{}
			for _, c := range te.Clients {
				state, err := c.State(ctx)
				if err != nil || state == nil || !state.Valid {
					results[c.Name()] = "other:no state"
					continue
				}
				ssz := buildStatusV2(state)
				if setHead {
					binary.LittleEndian.PutUint64(ssz[76:84], ^uint64(0))
				}
				if setFinalized {
					binary.LittleEndian.PutUint64(ssz[36:44], ^uint64(0))
				}
				if setEarliest {
					binary.LittleEndian.PutUint64(ssz[84:92], ^uint64(0))
				}
				res, err := c.ReqResp(ctx, statusV2, wire.BuildSSZSnappy(ssz), reqTimeout)
				out := outcome(res, err)
				if !stillConnected(ctx, c) {
					out = "reject" // peer dropped us after the boundary values
				}
				results[c.Name()] = out
			}
			return diverge(fmt.Sprintf("reqresp.status.boundary.%s", label), "reqresp", te.Meta, results)
		},
	}
}

// buildStatusV2 renders the 92-byte Status/2 container from node state.
func buildStatusV2(state *runner.NodeState) []byte {
	ssz := make([]byte, 92)
	copy(ssz[0:4], state.ForkDigest[:])
	copy(ssz[4:36], state.FinalizedRoot[:])
	binary.LittleEndian.PutUint64(ssz[36:44], state.FinalizedEpoch)
	copy(ssz[44:76], state.HeadRoot[:])
	binary.LittleEndian.PutUint64(ssz[76:84], state.HeadSlot)
	binary.LittleEndian.PutUint64(ssz[84:92], state.EarliestAvailableSlot)
	return ssz
}

// stillConnected probes the peer with a Ping; a failed exchange after a
// Status means the peer dropped the connection.
func stillConnected(ctx context.Context, c runner.Client) bool {
	res, err := c.ReqResp(ctx, pingV1, wire.BuildSSZSnappy(wire.Uint64ToSSZ(1)), 3*time.Second)
	return err == nil && res != nil && !res.StreamReset
}

// statusMismatchSpec builds a Status mismatch case. The mutator returns a
// 92-byte body derived from the node state with exactly one property wrong.
func statusMismatchSpec(id, description string, mutator func(ssz []byte, state *runner.NodeState)) runner.Spec {
	return runner.Spec{
		ID:       id,
		Category: "reqresp",
		What:     "Sends Status/2 with " + description + "; the client must reject the mismatched Status.",
		Metadata: runner.Metadata{
			SpecRules:    []string{"reqresp:status", "reqresp:status-handshake-required"},
			KnowledgeIDs: []string{"PROSE-SHOULD-d2397b37"},
		},
		Preflight: requireChainState,
		Run: func(ctx context.Context, te runner.TestEnv) []runner.Divergence {
			results := map[string]string{}
			for _, c := range te.Clients {
				state, err := c.State(ctx)
				if err != nil || state == nil || !state.Valid {
					results[c.Name()] = "other:no state"
					continue
				}
				ssz := buildStatusV2(state)
				mutator(ssz, state)
				res, err := c.ReqResp(ctx, statusV2, wire.BuildSSZSnappy(ssz), reqTimeout)
				out := outcome(res, err)
				if !stillConnected(ctx, c) {
					out = "reject" // disconnected after mismatch
				}
				results[c.Name()] = out
			}
			return diverge(id, "reqresp", te.Meta, results)
		},
	}
}

// statusSpecs returns the Status family cases (beyond the seed's valid case).
func statusSpecs() []runner.Spec {
	return []runner.Spec{
		statusBoundarySpec("head_slot_max_uint64", true, false, false),
		statusBoundarySpec("finalized_epoch_max_uint64", false, true, false),
		statusBoundarySpec("earliest_slot_max_uint64", false, false, true),
		statusBoundarySpec("all_slots_max_uint64", true, true, true),
		statusMismatchSpec(
			"reqresp.status.finalized_mismatch",
			"correct fork digest, garbage finalized root, impossible finalized epoch",
			func(ssz []byte, _ *runner.NodeState) {
				for i := 4; i < 36; i++ {
					ssz[i] = 0xFF
				}
				binary.LittleEndian.PutUint64(ssz[36:44], 999999)
			},
		),
		statusMismatchSpec(
			"reqresp.status.fork_mismatch",
			"wrong fork digest, otherwise valid state",
			func(ssz []byte, _ *runner.NodeState) {
				copy(ssz[0:4], []byte{0xDE, 0xAD, 0xBE, 0xEF})
			},
		),
	}
}
