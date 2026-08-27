package cases

import (
	"context"
	"fmt"
	"time"

	"libp2p-difftest/runner"
	"libp2p-difftest/wire"
)

const gossipWait = 8 * time.Second

// gossipSpecs returns the gossip seed cases.
func gossipSpecs() []runner.Spec {
	return []runner.Spec{
		{
			ID:       "gossip.block.malformed",
			Category: "gossip",
			Metadata: runner.Metadata{
				SpecRules:    []string{"gossipsub:topics", "gossipsub:block-validation"},
				LogSensitive: false,
			},
			Run: func(ctx context.Context, te runner.TestEnv) []runner.Divergence {
				topic := gossipTopic(te.Chain)
				payload := wire.GossipSnappyEncode([]byte("not a signed beacon block at all"))

				results := map[string]string{}
				for _, c := range te.Clients {
					verdict, err := c.ObserveGossip(ctx, topic, payload, gossipWait)
					if err != nil {
						results[c.Name()] = "other:" + err.Error()
						continue
					}
					switch verdict {
					case runner.VerdictAccept:
						results[c.Name()] = "accept"
					case runner.VerdictReject:
						results[c.Name()] = "reject"
					default:
						results[c.Name()] = "other:unknown verdict"
					}
				}
				return diverge("gossip.block.malformed", "gossip", te.Meta, results)
			},
		},
	}
}

// discoverySpecs returns the discovery seed cases.
func discoverySpecs() []runner.Spec {
	return []runner.Spec{
		{
			ID:       "discovery.fork_digest",
			Category: "discovery",
			Metadata: runner.Metadata{
				SpecRules: []string{"discovery:enr", "enr:eth2-field"},
			},
			Preflight: requireChainState,
			Run: func(ctx context.Context, te runner.TestEnv) []runner.Divergence {
				results := map[string]string{}
				for _, c := range te.Clients {
					state, err := c.State(ctx)
					if err != nil || state == nil || !state.Valid {
						results[c.Name()] = "other:no valid state"
						continue
					}
					results[c.Name()] = "digest:" + fmt.Sprintf("%x", state.ForkDigest)
				}
				// Same chain: all clients must report the same fork digest.
				byDigest := map[string][]string{}
				for _, name := range sortedClientNames(results) {
					byDigest[results[name]] = append(byDigest[results[name]], name)
				}
				if len(byDigest) <= 1 {
					return nil
				}
				// Outliers: everyone not in the largest digest group.
				majorityLen := 0
				for _, ns := range byDigest {
					if len(ns) > majorityLen {
						majorityLen = len(ns)
					}
				}
				var outliers []string
				for _, ns := range byDigest {
					if len(ns) < majorityLen {
						outliers = append(outliers, ns...)
					}
				}
				return []runner.Divergence{{
					TestID:         "discovery.fork_digest",
					Category:       "discovery",
					SpecRuleIDs:    te.Meta.SpecRules,
					Type:           runner.DivConsensusValue,
					Severity:       runner.SeverityHigh,
					Description:    "discovery.fork_digest: clients report different fork digests on the same chain",
					ClientResults:  results,
					OutlierClients: outliers,
				}}
			},
		},
	}
}

// transportSpecs returns the transport seed cases.
func transportSpecs() []runner.Spec {
	return []runner.Spec{
		{
			ID:       "transport.handshake.connect",
			Category: "transport",
			Metadata: runner.Metadata{
				SpecRules: []string{"transport:noise"},
			},
			Run: func(ctx context.Context, te runner.TestEnv) []runner.Divergence {
				results := map[string]string{}
				for _, c := range te.Clients {
					if err := c.Connect(ctx, runner.ConnectWithStatus); err != nil {
						results[c.Name()] = "reject"
						continue
					}
					results[c.Name()] = "accept"
				}
				return diverge("transport.handshake.connect", "transport", te.Meta, results)
			},
		},
		{
			ID:       "transport.handshake.identity_rotation",
			Category: "transport",
			Metadata: runner.Metadata{
				SpecRules: []string{"transport:identity"},
			},
			Run: func(ctx context.Context, te runner.TestEnv) []runner.Divergence {
				results := map[string]string{}
				for _, c := range te.Clients {
					if err := c.RotateIdentity(ctx); err != nil {
						results[c.Name()] = "reject"
						continue
					}
					results[c.Name()] = "accept"
				}
				return diverge("transport.handshake.identity_rotation", "transport", te.Meta, results)
			},
		},
	}
}
