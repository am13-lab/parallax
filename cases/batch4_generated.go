package cases

import (
	"context"
	"fmt"
	"strings"

	"parallax/runner"
	"parallax/wire"
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

// protocolShortName renders a full protocol path as name/version, e.g.
// "/eth2/beacon_chain/req/ping/1/ssz_snappy" → "ping/1".
func protocolShortName(p string) string {
	parts := strings.Split(p, "/")
	if len(parts) >= 3 {
		return parts[len(parts)-3] + "/" + parts[len(parts)-2]
	}
	return p
}

// stepBodyDesc returns a human-readable description of the body a
// statemachine step sends, keyed by the step label.
func stepBodyDesc(label string) string {
	switch label {
	case "ping_valid":
		return "uint64(1)"
	case "ping_empty":
		return "empty"
	case "ping_truncated":
		return "uint64 truncated by 2B"
	case "status_valid":
		return "zeroed 92-byte status"
	case "status_garbage":
		return "48 random bytes"
	case "blocks_by_range_valid":
		return "range start=0 count=1"
	}
	return ""
}

// stepWant returns the DESIGNED expected verdict for a statemachine step:
// malformed or degenerate requests must be rejected, valid ones accepted.
func stepWant(label string) string {
	switch label {
	case "ping_valid", "status_valid", "blocks_by_range_valid":
		return "accept"
	default:
		return "reject"
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
			What:     "Drives a seeded multi-step req/resp sequence through every client and compares the per-step verdict vector; conformant clients must agree on every step's outcome.",
			Metadata: runner.Metadata{SpecRules: []string{"reqresp:sequence-semantics"}},
			Run: func(ctx context.Context, te runner.TestEnv) []runner.Divergence {
				input := "sequence:"
				var steps []runner.StepOutcome
				var wantVector []string
				for i, st := range plan {
					if i > 0 {
						input += " →"
					}
					bodyDesc := stepBodyDesc(st.label)
					input += " " + protocolShortName(st.protocol) + " (" + bodyDesc + ")"
					wantVector = append(wantVector, stepWant(st.label))
					steps = append(steps, runner.StepOutcome{
						Index:         i + 1,
						Label:         st.label,
						Input:         protocolShortName(st.protocol) + " · " + bodyDesc,
						Expected:      stepWant(st.label),
						ClientResults: map[string]string{},
					})
				}
				results := map[string]string{}
				for _, c := range te.Clients {
					verdicts := make([]string, 0, len(plan))
					for i, st := range plan {
						res, err := c.ReqResp(ctx, st.protocol, st.body(te), reqTimeout)
						out := outcome(res, err)
						verdicts = append(verdicts, classOf(out))
						steps[i].ClientResults[c.Name()] = out
					}
					results[c.Name()] = strings.Join(verdicts, "/")
				}
				divs := divergeValues(fullID, "statemachine", te, runner.DivAcceptReject, runner.SeverityHigh, results)
				if len(divs) > 0 {
					divs[0].Input = input
					divs[0].Expected = strings.Join(wantVector, "/")
					divs[0].Steps = steps
					divs[0].Description = fmt.Sprintf("%s: %d of %d clients deviated from the expected step outcomes",
						fullID, len(divs[0].OutlierClients), len(results))
				}
				return divs
			},
		})
	}
	return specs
}

// bodyHex renders the exact request payload for reproducibility, truncated
// for display.
func bodyHex(b []byte) string {
	const max = 12
	if len(b) > max {
		return fmt.Sprintf("body %dB: 0x%x…", len(b), b[:max])
	}
	return fmt.Sprintf("body %dB: 0x%x", len(b), b)
}

// wantWord renders the expected verdict as a verb for intent sentences.
func wantWord(wantAccept bool) string {
	if wantAccept {
		return "accept"
	}
	return "reject"
}

// generatedSemanticSpecs produces single-client conformance checks: each
// client must individually satisfy the expectation, regardless of peers.
func generatedSemanticSpecs() []runner.Spec {
	type check struct {
		label      string
		protocol   string
		body       func(te runner.TestEnv) []byte
		input      string
		wantAccept bool
	}
	checks := []check{
		{"ping_valid_accepts", pingV1, func(te runner.TestEnv) []byte { return wire.BuildSSZSnappy(wire.Uint64ToSSZ(1)) },
			"ping/1 · uint64(1)", true},
		{"ping_empty_accepts", pingV1, func(te runner.TestEnv) []byte { return wire.BuildSSZSnappy(nil) },
			"ping/1 · empty body", true},
		{"ping_truncated_rejects", pingV1, func(te runner.TestEnv) []byte {
			framed := wire.SnappyEncode(wire.Uint64ToSSZ(1))
			return wire.BuildVarintPlusRawBytes(8, framed[:len(framed)-2])
		}, "ping/1 · uint64(1) truncated by 2B", false},
		{"status_zero_accepts", statusV2, func(te runner.TestEnv) []byte { return wire.BuildSSZSnappy(make([]byte, 92)) },
			"status/2 · zeroed 92-byte status", true},
		{"status_truncate_all_rejects", statusV2, func(te runner.TestEnv) []byte {
			return wire.BuildMalformedSSZSnappy(make([]byte, 92), wire.MalformTruncateAll, nil)
		}, "status/2 · 92-byte status truncated to 0B", false},
		{"metadata_no_body_accepts", metadataV2, func(te runner.TestEnv) []byte { return wire.BuildSSZSnappy(nil) },
			"metadata/2 · empty body", true},
		{"blocks_by_range_zero_count", blocksByRangeV2, func(te runner.TestEnv) []byte {
			return wire.BuildSSZSnappy(rangeRequest(0, 0, true))
		}, "beacon_blocks_by_range/2 · start=0 count=0 step=1", false},
		{"blocks_by_range_valid", blocksByRangeV2, func(te runner.TestEnv) []byte {
			return wire.BuildSSZSnappy(rangeRequest(0, 1, true))
		}, "beacon_blocks_by_range/2 · start=0 count=1 step=1", true},
	}

	var specs []runner.Spec
	for _, chk := range checks {
		chk := chk
		id := "semantic_valid." + chk.label
		specs = append(specs, runner.Spec{
			ID:       id,
			Category: "semantic_valid",
			What:     "Sends " + chk.input + " to every client; each client must " + wantWord(chk.wantAccept) + " the request.",
			Metadata: runner.Metadata{
				SpecRules:  []string{"reqresp:conformance"},
				MinClients: 1,
			},
			Run: func(ctx context.Context, te runner.TestEnv) []runner.Divergence {
				want := "reject"
				if chk.wantAccept {
					want = "accept"
				}
				body := chk.body(te)
				outcomes := map[string]string{}
				details := map[string]string{}
				for _, c := range te.Clients {
					res, err := c.ReqResp(ctx, chk.protocol, body, reqTimeout)
					outcomes[c.Name()] = outcome(res, err)
					details[c.Name()] = detail(res, err)
				}
				var divs []runner.Divergence
				for _, c := range te.Clients {
					got := classOf(outcomes[c.Name()]) == "accept"
					if got == chk.wantAccept {
						continue
					}
					divs = append(divs, runner.Divergence{
						TestID:         id,
						Category:       "semantic_valid",
						SpecRuleIDs:    te.Meta.SpecRules,
						Type:           runner.DivAcceptReject,
						Severity:       runner.SeverityMedium,
						Description:    fmt.Sprintf("%s: %s violates expected verdict (want accept=%v)", id, c.Name(), chk.wantAccept),
						Input:          chk.input + " · " + bodyHex(body),
						Expected:       want,
						ClientResults:  outcomes,
						ClientDetails:  details,
						OutlierClients: []string{c.Name()},
					})
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
