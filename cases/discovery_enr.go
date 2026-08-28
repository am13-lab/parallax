package cases

import (
	"context"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"libp2p-difftest/enr"
	"libp2p-difftest/runner"
)

const farFutureEpoch = ^uint64(0)

// enrOf parses a client's advertised ENR, mapping failures to outcome-class
// strings ("other:...").
func enrOf(ctx context.Context, c runner.Client) (*enr.ENRRecord, string) {
	state, err := c.State(ctx)
	if err != nil || state == nil || !state.Valid {
		return nil, "other:no state"
	}
	if strings.TrimSpace(state.ENR) == "" {
		return nil, "other:no ENR advertised"
	}
	rec, perr := enr.DecodeENR(state.ENR)
	if perr != nil {
		return nil, "other:ENR unparseable"
	}
	return rec, ""
}

// divergeValues compares raw values across clients: agreement passes, more
// than one distinct value yields a divergence whose outliers are the
// minority value groups.
func divergeValues(id string, te runner.TestEnv, divType runner.DivergenceType,
	severity runner.Severity, results map[string]string) []runner.Divergence {

	byValue := map[string][]string{}
	for _, name := range sortedClientNames(results) {
		byValue[results[name]] = append(byValue[results[name]], name)
	}
	if len(byValue) <= 1 {
		return nil
	}
	majority := 0
	for _, ns := range byValue {
		if len(ns) > majority {
			majority = len(ns)
		}
	}
	var outliers []string
	var lines []string
	for _, value := range sortedValueKeys(byValue) {
		ns := byValue[value]
		lines = append(lines, fmt.Sprintf("%s: %v", value, ns))
		if len(ns) < majority {
			outliers = append(outliers, ns...)
		}
	}
	return []runner.Divergence{{
		TestID:         id,
		Category:       "discovery",
		SpecRuleIDs:    te.Meta.SpecRules,
		Type:           divType,
		Severity:       severity,
		Description:    id + ": " + strings.Join(lines, "; "),
		ClientResults:  results,
		OutlierClients: outliers,
	}}
}

func sortedValueKeys(m map[string][]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func verdict(ok bool) string {
	if ok {
		return "accept"
	}
	return "reject"
}

// enrSpecs returns the discovery ENR structure, sequence, consistency and
// metadata families. Property checks classify each client compliant
// ("accept") or violating ("reject"); value checks compare raw values.
func enrSpecs() []runner.Spec {
	// structure: one spec per ENR property rule.
	prop := func(id, rule string, check func(*enr.ENRRecord) bool) runner.Spec {
		return runner.Spec{
			ID:       id,
			Category: "discovery",
			Metadata: runner.Metadata{SpecRules: []string{rule}},
			Run: func(ctx context.Context, te runner.TestEnv) []runner.Divergence {
				results := map[string]string{}
				for _, c := range te.Clients {
					rec, out := enrOf(ctx, c)
					if out != "" {
						results[c.Name()] = out
						continue
					}
					results[c.Name()] = verdict(check(rec))
				}
				return diverge(id, "discovery", te.Meta, results)
			},
		}
	}

	value := func(id, rule string, divType runner.DivergenceType, sev runner.Severity,
		get func(ctx context.Context, te runner.TestEnv, c runner.Client) string) runner.Spec {
		return runner.Spec{
			ID:       id,
			Category: "discovery",
			Metadata: runner.Metadata{SpecRules: []string{rule}},
			Run: func(ctx context.Context, te runner.TestEnv) []runner.Divergence {
				results := map[string]string{}
				for _, c := range te.Clients {
					results[c.Name()] = get(ctx, te, c)
				}
				return divergeValues(id, te, divType, sev, results)
			},
		}
	}

	specs := []runner.Spec{
		prop("discovery.enr.eth2_field_present", "enr:eth2-present",
			func(rec *enr.ENRRecord) bool { return rec.HasKey("eth2") }),
		prop("discovery.enr.eth2_field_size", "enr:eth2-size",
			func(rec *enr.ENRRecord) bool { return rec.KeySize("eth2") == 16 }),
		prop("discovery.enr.secp256k1_present", "enr:secp256k1-present",
			func(rec *enr.ENRRecord) bool { return rec.HasKey("secp256k1") }),
		prop("discovery.enr.attnets_size", "enr:attnets-size",
			func(rec *enr.ENRRecord) bool { return rec.KeySize("attnets") == 8 }),
		prop("discovery.enr.syncnets_size", "enr:syncnets-size",
			func(rec *enr.ENRRecord) bool {
				size := rec.KeySize("syncnets")
				return size == -1 || size == 1
			}),
		prop("discovery.enr.cgc_encoding", "enr:cgc-encoding",
			func(rec *enr.ENRRecord) bool {
				_, raw, present := rec.GetCGC()
				if !present {
					return true
				}
				return len(raw) == 0 || raw[0] != 0x00
			}),
		prop("discovery.enr.nfd_size", "enr:nfd-size",
			func(rec *enr.ENRRecord) bool {
				nfd := rec.GetNFD()
				return nfd == nil || len(nfd) == 4
			}),
		prop("discovery.enr.ip_field_valid", "enr:ip-field",
			func(rec *enr.ENRRecord) bool {
				if size := rec.KeySize("ip"); size != -1 && size != 4 {
					return false
				}
				if size := rec.KeySize("ip6"); size != -1 && size != 16 {
					return false
				}
				return true
			}),
		prop("discovery.enr.has_transport", "enr:transport",
			func(rec *enr.ENRRecord) bool {
				for _, key := range []string{"tcp", "tcp6", "quic", "quic6"} {
					if rec.HasKey(key) {
						return true
					}
				}
				return false
			}),
		prop("discovery.enr.seq_number_nonzero", "enr:seq-nonzero",
			func(rec *enr.ENRRecord) bool { return rec.Seq > 0 }),

		value("discovery.enr.seq_number_value", "enr:seq-value",
			runner.DivValueDiff, runner.SeverityLow,
			func(ctx context.Context, te runner.TestEnv, c runner.Client) string {
				rec, out := enrOf(ctx, c)
				if out != "" {
					return out
				}
				return fmt.Sprintf("seq=%d", rec.Seq)
			}),
		value("discovery.consistency.next_fork_version", "enr:eth2-next-fork-version",
			runner.DivConsensusValue, runner.SeverityHigh,
			func(ctx context.Context, te runner.TestEnv, c runner.Client) string {
				rec, out := enrOf(ctx, c)
				if out != "" {
					return out
				}
				fid, err := rec.GetEth2()
				if err != nil {
					return "other:" + err.Error()
				}
				return hex.EncodeToString(fid.NextForkVersion[:])
			}),
		value("discovery.consistency.next_fork_epoch", "enr:eth2-next-fork-epoch",
			runner.DivConsensusValue, runner.SeverityHigh,
			func(ctx context.Context, te runner.TestEnv, c runner.Client) string {
				rec, out := enrOf(ctx, c)
				if out != "" {
					return out
				}
				fid, err := rec.GetEth2()
				if err != nil {
					return "other:" + err.Error()
				}
				if fid.NextForkEpoch == farFutureEpoch {
					return "FAR_FUTURE"
				}
				return fmt.Sprintf("%d", fid.NextForkEpoch)
			}),
		value("discovery.consistency.nfd_value", "enr:nfd-value",
			runner.DivConsensusValue, runner.SeverityHigh,
			func(ctx context.Context, te runner.TestEnv, c runner.Client) string {
				rec, out := enrOf(ctx, c)
				if out != "" {
					return out
				}
				nfd := rec.GetNFD()
				if nfd == nil {
					return "absent"
				}
				return hex.EncodeToString(nfd)
			}),
		value("discovery.consistency.cgc_minimum", "enr:cgc-minimum",
			runner.DivConsensusValue, runner.SeverityHigh,
			func(ctx context.Context, te runner.TestEnv, c runner.Client) string {
				rec, out := enrOf(ctx, c)
				if out != "" {
					return out
				}
				val, _, present := rec.GetCGC()
				if !present {
					return "accept"
				}
				return verdict(val >= te.Chain.CustodyRequirement)
			}),

		value("discovery.metadata.attnets_match_enr", "metadata:attnets-match-enr",
			runner.DivConsensusValue, runner.SeverityHigh,
			func(ctx context.Context, te runner.TestEnv, c runner.Client) string {
				rec, out := enrOf(ctx, c)
				if out != "" {
					return out
				}
				md, merr := c.Metadata(ctx)
				if merr != nil {
					return "other:no metadata"
				}
				if !rec.HasKey("attnets") {
					return "other:no ENR attnets"
				}
				enrHex := hex.EncodeToString(rec.GetAttnets())
				mdHex := strings.TrimPrefix(md.Attnets, "0x")
				if enrHex == mdHex {
					return "accept"
				}
				return fmt.Sprintf("mismatch enr=%s metadata=%s", enrHex, mdHex)
			}),
		value("discovery.metadata.syncnets_match_enr", "metadata:syncnets-match-enr",
			runner.DivConsensusValue, runner.SeverityHigh,
			func(ctx context.Context, te runner.TestEnv, c runner.Client) string {
				rec, out := enrOf(ctx, c)
				if out != "" {
					return out
				}
				md, merr := c.Metadata(ctx)
				if merr != nil {
					return "other:no metadata"
				}
				if rec.KeySize("syncnets") == -1 || md.Syncnets == "" {
					return "accept"
				}
				enrHex := hex.EncodeToString(rec.GetSyncnets())
				mdHex := strings.TrimPrefix(md.Syncnets, "0x")
				if enrHex == mdHex {
					return "accept"
				}
				return fmt.Sprintf("mismatch enr=%s metadata=%s", enrHex, mdHex)
			}),
		value("discovery.metadata.seq_number_positive", "metadata:seq-positive",
			runner.DivConsensusValue, runner.SeverityHigh,
			func(ctx context.Context, te runner.TestEnv, c runner.Client) string {
				md, merr := c.Metadata(ctx)
				if merr != nil {
					return "other:no metadata"
				}
				return verdict(md.SeqNumber > 0)
			}),
		value("discovery.metadata.custody_group_count", "metadata:cgc-minimum",
			runner.DivConsensusValue, runner.SeverityHigh,
			func(ctx context.Context, te runner.TestEnv, c runner.Client) string {
				md, merr := c.Metadata(ctx)
				if merr != nil {
					return "other:no metadata"
				}
				if !md.HasCGC {
					return "accept"
				}
				return verdict(md.CustodyGroupCount >= te.Chain.CustodyRequirement)
			}),
	}

	// Metadata and custody cases need extra preconditions.
	for i := range specs {
		switch specs[i].ID {
		case "discovery.consistency.cgc_minimum":
			specs[i].Preflight = requireCustodyRequirement
		case "discovery.metadata.attnets_match_enr",
			"discovery.metadata.syncnets_match_enr",
			"discovery.metadata.seq_number_positive":
			specs[i].Preflight = requireMetadata
		case "discovery.metadata.custody_group_count":
			specs[i].Preflight = requireBoth(requireMetadata, requireCustodyRequirement)
		}
	}
	return specs
}

// requireMetadata preflights that every client exposes beacon metadata.
func requireMetadata(ctx context.Context, chain runner.ChainConfig, cs []runner.Client) runner.PreflightResult {
	for _, c := range cs {
		if _, err := c.Metadata(ctx); err != nil {
			return runner.PreflightResult{
				Runnable: false,
				Reason:   "client " + c.Name() + " lacks beacon metadata",
			}
		}
	}
	return runner.PreflightResult{Runnable: true}
}

// requireCustodyRequirement preflights that the chain config carries a
// custody requirement (preset-dependent, Fulu PeerDAS).
func requireCustodyRequirement(ctx context.Context, chain runner.ChainConfig, cs []runner.Client) runner.PreflightResult {
	_ = ctx
	_ = cs
	if chain.CustodyRequirement == 0 {
		return runner.PreflightResult{Runnable: false, Reason: "chain config has no custody requirement"}
	}
	return runner.PreflightResult{Runnable: true}
}

// requireBoth combines two preflights.
func requireBoth(a, b func(context.Context, runner.ChainConfig, []runner.Client) runner.PreflightResult) func(context.Context, runner.ChainConfig, []runner.Client) runner.PreflightResult {
	return func(ctx context.Context, chain runner.ChainConfig, cs []runner.Client) runner.PreflightResult {
		if r := a(ctx, chain, cs); !r.Runnable {
			return r
		}
		return b(ctx, chain, cs)
	}
}
