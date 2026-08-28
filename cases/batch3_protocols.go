package cases

import (
	"context"
	"encoding/binary"
	"fmt"

	"libp2p-difftest/runner"
	"libp2p-difftest/wire"
)

// Batch 3d/3e: Gloas execution-payload protocols, data column validation,
// and custody derivation. The Gloas families are config class: they are
// only meaningful when every client runs at the Gloas fork, which the
// preflight enforces via the node state fork name.

const (
	execPayloadByRangeV1 = "/eth2/beacon_chain/req/execution_payload_envelopes_by_range/1/ssz_snappy"
	execPayloadByRootV1  = "/eth2/beacon_chain/req/execution_payload_envelopes_by_root/1/ssz_snappy"
)

// requireGloas preflights that every client reports the Gloas fork active.
func requireGloas(ctx context.Context, chain runner.ChainConfig, cs []runner.Client) runner.PreflightResult {
	for _, c := range cs {
		state, err := c.State(ctx)
		if err != nil || state == nil || state.Fork != "gloas" {
			return runner.PreflightResult{
				Runnable: false,
				Reason:   fmt.Sprintf("client %s not at Gloas fork", c.Name()),
			}
		}
	}
	return runner.PreflightResult{Runnable: true}
}

func protocolSpecs3() []runner.Spec {
	var specs []runner.Spec

	// Gloas execution payload envelopes: boundary counts. Config class so
	// they only run on Gloas devnets.
	payloadRange := []struct {
		label string
		count uint64
	}{
		{"valid_1", 1},
		{"zero_count", 0},
		{"over_max", 128 + 1},
	}
	for _, p := range payloadRange {
		count := p.count
		specs = append(specs, runner.Spec{
			ID:       fmt.Sprintf("reqresp.execution_payload_by_range.%s", p.label),
			Category: "reqresp",
			Metadata: runner.Metadata{
				SpecRules:    []string{"gloas:execution-payload-by-range"},
				KnowledgeIDs: []string{"SHERLOCK-1140-004", "SHERLOCK-1140-378"},
				RunClass:     runner.RunClassConfig,
			},
			Preflight: requireGloas,
			Run: func(ctx context.Context, te runner.TestEnv) []runner.Divergence {
				buf := make([]byte, 16)
				binary.LittleEndian.PutUint64(buf[0:8], 0)
				binary.LittleEndian.PutUint64(buf[8:16], count)
				results := map[string]string{}
				for _, c := range te.Clients {
					res, err := c.ReqResp(ctx, execPayloadByRangeV1, wire.BuildSSZSnappy(buf), reqTimeout)
					results[c.Name()] = outcome(res, err)
				}
				return diverge(fmt.Sprintf("reqresp.execution_payload_by_range.%s", p.label), "reqresp", te.Meta, results)
			},
		})
	}
	payloadRoot := []struct {
		label string
		roots int
	}{
		{"single", 1},
		{"empty", 0},
		{"over_max", 128 + 1},
	}
	for _, p := range payloadRoot {
		roots := p.roots
		specs = append(specs, runner.Spec{
			ID:       fmt.Sprintf("reqresp.execution_payload_by_root.%s", p.label),
			Category: "reqresp",
			Metadata: runner.Metadata{
				SpecRules: []string{"gloas:execution-payload-by-root"},
				RunClass:  runner.RunClassConfig,
			},
			Preflight: requireGloas,
			Run: func(ctx context.Context, te runner.TestEnv) []runner.Divergence {
				buf := make([]byte, roots*32)
				for i := 0; i < roots; i++ {
					buf[i*32] = byte(i)
				}
				results := map[string]string{}
				for _, c := range te.Clients {
					res, err := c.ReqResp(ctx, execPayloadByRootV1, wire.BuildSSZSnappy(buf), reqTimeout)
					results[c.Name()] = outcome(res, err)
				}
				return diverge(fmt.Sprintf("reqresp.execution_payload_by_root.%s", p.label), "reqresp", te.Meta, results)
			},
		})
	}

	// Data column validation: nonsense column indices must be rejected.
	specs = append(specs,
		runner.Spec{
			ID:       "reqresp.data_columns_by_range.columns_oob",
			Category: "reqresp",
			Metadata: runner.Metadata{SpecRules: []string{"fulu:data-columns-by-range"}},
			Run: func(ctx context.Context, te runner.TestEnv) []runner.Divergence {
				body := dataColumnsByRangeRequest(0, 1, []uint64{999999})
				results := map[string]string{}
				for _, c := range te.Clients {
					res, err := c.ReqResp(ctx, dataColsByRangeV1, body, reqTimeout)
					results[c.Name()] = outcome(res, err)
				}
				return diverge("reqresp.data_columns_by_range.columns_oob", "reqresp", te.Meta, results)
			},
		},
		runner.Spec{
			ID:       "reqresp.data_columns_by_range.zero_columns",
			Category: "reqresp",
			Metadata: runner.Metadata{SpecRules: []string{"fulu:data-columns-by-range"}},
			Run: func(ctx context.Context, te runner.TestEnv) []runner.Divergence {
				body := dataColumnsByRangeRequest(0, 1, nil)
				results := map[string]string{}
				for _, c := range te.Clients {
					res, err := c.ReqResp(ctx, dataColsByRangeV1, body, reqTimeout)
					results[c.Name()] = outcome(res, err)
				}
				return diverge("reqresp.data_columns_by_range.zero_columns", "reqresp", te.Meta, results)
			},
		},
	)

	// Custody derivation: the advertised cgc must match the requirement.
	specs = append(specs, runner.Spec{
		ID:       "discovery.custody.advertised_matches_requirement",
		Category: "discovery",
		Metadata: runner.Metadata{
			SpecRules:    []string{"fulu:custody-enr"},
			KnowledgeIDs: []string{"SHERLOCK-1140-058", "SHERLOCK-1140-071"},
		},
		Preflight: requireCustodyRequirement,
		Run: func(ctx context.Context, te runner.TestEnv) []runner.Divergence {
			results := map[string]string{}
			for _, c := range te.Clients {
				rec, out := enrOf(ctx, c)
				if out != "" {
					results[c.Name()] = out
					continue
				}
				val, _, present := rec.GetCGC()
				if !present {
					// Pre-Fulu nodes have no cgc: compliant absence.
					results[c.Name()] = "accept"
					continue
				}
				results[c.Name()] = verdict(val == te.Chain.CustodyRequirement)
			}
			return diverge("discovery.custody.advertised_matches_requirement", "discovery", te.Meta, results)
		},
	})

	// Rate limit errors: burst a protocol and classify the response code.
	// Heavy class: the burst is designed to trip protection mechanisms.
	rateLimitTargets := []struct {
		id, protocol string
		burst        int
	}{
		{"reqresp.rate_limit_error.ping_burst", pingV1, 40},
		{"reqresp.rate_limit_error.metadata_burst", metadataV2, 40},
	}
	for _, t := range rateLimitTargets {
		target := t
		specs = append(specs, runner.Spec{
			ID:       target.id,
			Category: "reqresp",
			Metadata: runner.Metadata{
				SpecRules: []string{"reqresp:rate-limiting"},
				RunClass:  runner.RunClassHeavy,
			},
			Run: func(ctx context.Context, te runner.TestEnv) []runner.Divergence {
				body := wire.BuildSSZSnappy(nil)
				results := map[string]string{}
				for _, c := range te.Clients {
					sawLimited := false
					for i := 0; i < target.burst; i++ {
						res, err := c.ReqResp(ctx, target.protocol, body, reqTimeout)
						out := outcome(res, err)
						if res != nil && len(res.ResponseChunks) > 0 &&
							(res.ResponseChunks[0].ResultCode == 0x02 || res.ResponseChunks[0].ResultCode == 0x03) {
							sawLimited = true
							break
						}
						_ = out
					}
					results[c.Name()] = verdict(sawLimited)
				}
				return diverge(target.id, "reqresp", te.Meta, results)
			},
		})
	}
	return specs
}
