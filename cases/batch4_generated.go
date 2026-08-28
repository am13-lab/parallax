package cases

import (
	"context"
	"fmt"

	"libp2p-difftest/runner"
	"libp2p-difftest/wire"
)

// Batch 4: the generative subsystems, ported as deterministic generators
// that produce Spec values (not hand-written cases). The old repo's
// statemachine engine (745 generated sequences), cryptomsg sweep (90) and
// semantic_valid rules (31) are trimmed to representative generators with
// stable, seeded output; the generator pattern is the migration path for
// the rest.

// generatedCryptomsgSpecs sweeps malformations and varint claims across
// protocols and payload size classes, the old cryptomsg category's core.
func generatedCryptomsgSpecs() []runner.Spec {
	protocols := []struct {
		name  string
		id    string
		valid func(size int) []byte
	}{
		{"ping", pingV1, func(size int) []byte { return pad(wire.Uint64ToSSZ(1), size) }},
		{"status", statusV2, func(size int) []byte { return pad(make([]byte, 92), size) }},
		{"blocks_by_range", blocksByRangeV2, func(size int) []byte { return pad(rangeRequest(0, 1, true), size) }},
	}
	sizes := []struct {
		label string
		n     int
	}{
		{"tiny", 1},
		{"small", 128},
		{"large", 65536},
	}
	malformations := []struct {
		label string
		mt    wire.MalformationType
	}{
		{"truncate_one", wire.MalformTruncateOne},
		{"truncate_half", wire.MalformTruncateHalf},
		{"truncate_all", wire.MalformTruncateAll},
		{"random_bytes", wire.MalformRandomBytes},
		{"break_stream_id", wire.MalformBreakSnappyStreamID},
		{"break_crc", wire.MalformBreakSnappyCRC},
		{"append_garbage", wire.MalformAppendGarbage},
	}

	var specs []runner.Spec
	for _, p := range protocols {
		for _, m := range malformations {
			for _, sz := range sizes {
				proto, mt, size := p, m.mt, sz.n
				id := fmt.Sprintf("cryptomsg.%s.%s.%s", proto.name, m.label, sz.label)
				specs = append(specs, exchangeSpec(id, proto.id,
					func(te runner.TestEnv) []byte {
						return wire.BuildMalformedSSZSnappy(proto.valid(size), mt, te.RNG)
					}, nil))
			}
		}
	}

	// Varint claim sweep: values around varint encoding boundaries.
	claims := []uint64{0, 1, 127, 128, 4096, ^uint64(0)}
	for _, p := range protocols {
		for _, c := range claims {
			claim := c
			id := fmt.Sprintf("cryptomsg.varint.%s.%d", protoShort(p.name), claim)
			specs = append(specs, exchangeSpec(id, p.id,
				func(te runner.TestEnv) []byte {
					return wire.BuildVarintLengthMismatch(wire.Uint64ToSSZ(1), claim)
				}, nil))
		}
	}
	return specs
}

func pad(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	extra := make([]byte, size-len(b))
	return append(b, extra...)
}

func protoShort(name string) string {
	out := make([]byte, 0, len(name))
	for i := 0; i < len(name); i++ {
		if name[i] == '_' {
			continue
		}
		out = append(out, name[i])
	}
	return string(out)
}

// step is one action inside a generated statemachine sequence.
type step struct {
	label    string
	protocol string
	body     func(te runner.TestEnv) []byte
}

// statemachineSteps is the alphabet the sequence generator draws from:
// valid, malformed, boundary and degenerate requests on two protocols.
func statemachineSteps() []step {
	return []step{
		{"ping_valid", pingV1, func(te runner.TestEnv) []byte { return wire.BuildSSZSnappy(wire.Uint64ToSSZ(1)) }},
		{"ping_empty", pingV1, func(te runner.TestEnv) []byte { return wire.BuildSSZSnappy(nil) }},
		{"ping_truncated", pingV1, func(te runner.TestEnv) []byte {
			framed := wire.SnappyEncode(wire.Uint64ToSSZ(1))
			return wire.BuildVarintPlusRawBytes(8, framed[:len(framed)-2])
		}},
		{"status_valid", statusV2, func(te runner.TestEnv) []byte { return wire.BuildSSZSnappy(make([]byte, 92)) }},
		{"status_garbage", statusV2, func(te runner.TestEnv) []byte {
			g := make([]byte, 48)
			te.RNG.Read(g)
			return wire.BuildSSZSnappy(g)
		}},
	}
}

// generatedStatemachineSpecs produces seeded request sequences and compares
// the per-step verdict vectors across clients; the sequence ID encodes the
// step plan so a divergence is immediately reproducible.
func generatedStatemachineSpecs() []runner.Spec {
	const sequenceCount = 30
	steps := statemachineSteps()
	rng := seqRand(77)

	var specs []runner.Spec
	for n := 0; n < sequenceCount; n++ {
		length := 2 + n%3 // 2..4 steps
		var plan []step
		var id string
		for i := 0; i < length; i++ {
			st := steps[rng.Intn(len(steps))]
			plan = append(plan, st)
			id += st.label + "."
		}
		fullID := fmt.Sprintf("statemachine.seq.%02d.%s", n, id[:len(id)-1])
		specs = append(specs, runner.Spec{
			ID:       fullID,
			Category: "statemachine",
			Metadata: runner.Metadata{SpecRules: []string{"reqresp:sequence-semantics"}},
			Run: func(ctx context.Context, te runner.TestEnv) []runner.Divergence {
				results := map[string]string{}
				for _, c := range te.Clients {
					vector := ""
					for _, st := range plan {
						res, err := c.ReqResp(ctx, st.protocol, st.body(te), reqTimeout)
						out := outcome(res, err)
						vector += string(classOf(out)[0])
					}
					results[c.Name()] = vector
				}
				return divergeValues(fullID, te, runner.DivAcceptReject, runner.SeverityHigh, results)
			},
		})
	}
	return specs
}

// generatedSemanticSpecs produces single-client conformance checks: each
// client must individually satisfy the expectation, regardless of peers.
func generatedSemanticSpecs() []runner.Spec {
	type check struct {
		label      string
		protocol   string
		body       func(te runner.TestEnv) []byte
		wantAccept bool
	}
	checks := []check{
		{"ping_valid_accepts", pingV1, func(te runner.TestEnv) []byte { return wire.BuildSSZSnappy(wire.Uint64ToSSZ(1)) }, true},
		{"ping_empty_accepts", pingV1, func(te runner.TestEnv) []byte { return wire.BuildSSZSnappy(nil) }, true},
		{"ping_truncated_rejects", pingV1, func(te runner.TestEnv) []byte {
			framed := wire.SnappyEncode(wire.Uint64ToSSZ(1))
			return wire.BuildVarintPlusRawBytes(8, framed[:len(framed)-2])
		}, false},
		{"status_zero_accepts", statusV2, func(te runner.TestEnv) []byte { return wire.BuildSSZSnappy(make([]byte, 92)) }, true},
		{"status_truncate_all_rejects", statusV2, func(te runner.TestEnv) []byte {
			return wire.BuildMalformedSSZSnappy(make([]byte, 92), wire.MalformTruncateAll, nil)
		}, false},
		{"metadata_no_body_accepts", metadataV2, func(te runner.TestEnv) []byte { return wire.BuildSSZSnappy(nil) }, true},
		{"blocks_by_range_zero_count", blocksByRangeV2, func(te runner.TestEnv) []byte {
			return wire.BuildSSZSnappy(rangeRequest(0, 0, true))
		}, false},
		{"blocks_by_range_valid", blocksByRangeV2, func(te runner.TestEnv) []byte {
			return wire.BuildSSZSnappy(rangeRequest(0, 1, true))
		}, true},
	}

	var specs []runner.Spec
	for _, chk := range checks {
		chk := chk
		id := "semantic_valid." + chk.label
		specs = append(specs, runner.Spec{
			ID:       id,
			Category: "semantic_valid",
			Metadata: runner.Metadata{
				SpecRules:  []string{"reqresp:conformance"},
				MinClients: 1,
			},
			Run: func(ctx context.Context, te runner.TestEnv) []runner.Divergence {
				var divs []runner.Divergence
				for _, c := range te.Clients {
					res, err := c.ReqResp(ctx, chk.protocol, chk.body(te), reqTimeout)
					out := classOf(outcome(res, err))
					got := out == "accept"
					if got != chk.wantAccept {
						divs = append(divs, runner.Divergence{
							TestID:         id,
							Category:       "semantic_valid",
							SpecRuleIDs:    te.Meta.SpecRules,
							Type:           runner.DivAcceptReject,
							Severity:       runner.SeverityMedium,
							Description:    fmt.Sprintf("%s: %s violates expected verdict (want accept=%v)", id, c.Name(), chk.wantAccept),
							ClientResults:  map[string]string{c.Name(): outcome(res, err)},
							OutlierClients: []string{c.Name()},
						})
					}
				}
				return divs
			},
		})
	}
	return specs
}

// seqRand is a tiny deterministic PRNG so generated sequences are stable
// without importing math/rand here.
func seqRand(seed int64) *seqRng {
	return &seqRng{state: uint64(seed)*6364136223846793005 + 1442695040888963407}
}

type seqRng struct{ state uint64 }

func (r *seqRng) Intn(n int) int {
	r.state = r.state*6364136223846793005 + 1442695040888963407
	return int((r.state >> 33) % uint64(n))
}
