package cases

import (
	"context"
	"fmt"
	"time"

	"parallax/runner"
	"parallax/wire"
)

// gossipWait is the gossip re-propagation confirmation window: how long we
// wait for the target to forward a message before concluding it did not.
// 1500ms matches p2p-testing's statemachine executor window. The
// sandbox overrides it (in-memory test nodes relay within
// milliseconds), see SetGossipWait.
var gossipWait = 1500 * time.Millisecond

// SetGossipWait overrides the propagation window. For in-memory node
// environments (sandbox, tests) only.
func SetGossipWait(d time.Duration) { gossipWait = d }

// gossipSpecs returns the gossip seed cases.
func gossipSpecs() []runner.Spec {
	return []runner.Spec{
		{
			ID:       "gossip.block.malformed",
			Category: "gossip",
			What:     "Publishes a malformed signed block on gossip; honest clients must reject it (never re-propagate), consistently across clients.",
			Metadata: runner.Metadata{
				SpecRules:    []string{"gossipsub:topics", "gossipsub:block-validation"},
				LogSensitive: false,
			},
			Run: func(ctx context.Context, te runner.TestEnv) []runner.Divergence {
				topic := gossipTopic(te.Chain)
				// Unique per run: real block payloads are unique, and a
				// nonce keeps content-id dedup in earlier gossip cases
				// from suppressing this message.
				nonce := make([]byte, 16)
				te.RNG.Read(nonce)
				payload := wire.GossipSnappyEncode(append([]byte("malformed block "), nonce...))

				results, details := map[string]string{}, map[string]string{}
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
				return diverge("gossip.block.malformed", "gossip", te.Meta, results, details)
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
			What:     "Compares the fork digest each client reports through discovery; all clients on the same chain must agree.",
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
				// Same chain: all clients must report the same fork digest;
				// divergeValues applies the shared majority/tie outlier rule.
				return divergeValues("discovery.fork_digest", "discovery", te, runner.DivConsensusValue, runner.SeverityHigh, results)
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
			What:     "Connects to every client over libp2p and completes the status handshake; basic reachability must be uniform.",
			Metadata: runner.Metadata{
				SpecRules: []string{"transport:noise"},
			},
			Run: func(ctx context.Context, te runner.TestEnv) []runner.Divergence {
				results, details := map[string]string{}, map[string]string{}
				for _, c := range te.Clients {
					if err := c.Connect(ctx, runner.ConnectWithStatus); err != nil {
						results[c.Name()] = "reject"
						continue
					}
					results[c.Name()] = "accept"
				}
				return diverge("transport.handshake.connect", "transport", te.Meta, results, details)
			},
		},
		{
			ID:       "transport.handshake.identity_rotation",
			Category: "transport",
			What:     "Rotates the peer identity mid-session; every client must handle the stale peer consistently.",
			Metadata: runner.Metadata{
				SpecRules: []string{"transport:identity"},
			},
			Run: func(ctx context.Context, te runner.TestEnv) []runner.Divergence {
				results, details := map[string]string{}, map[string]string{}
				for _, c := range te.Clients {
					if err := c.RotateIdentity(ctx); err != nil {
						results[c.Name()] = "reject"
						continue
					}
					results[c.Name()] = "accept"
				}
				return diverge("transport.handshake.identity_rotation", "transport", te.Meta, results, details)
			},
		},
	}
}
