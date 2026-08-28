package cases

import (
	"context"
	"fmt"
	"sync"
	"time"

	"libp2p-difftest/runner"
	"libp2p-difftest/wire"
)

// Batch 3a/3b: the old transporttest and exhaustion families. These send
// abusive or degenerate stream-level inputs; they are heavy class because
// they deliberately degrade target state, and the testnode-level proof
// covers both directions like every other family.

// stillConnectedAfter runs a normal ping and reports whether the peer is
// still serving after abusive input.
func stillConnectedAfter(ctx context.Context, c runner.Client) string {
	if stillConnected(ctx, c) {
		return "accept"
	}
	return "reject"
}

func outcomeConn(err error) string {
	if err != nil {
		return "reject"
	}
	return "accept"
}

// transportAbuseSpec builds a case that writes an abusive body via SendOnly
// and then classifies whether the peer is still usable.
func transportAbuseSpec(id string, runClass runner.RunClass, knowledge []string,
	buildBody func(te runner.TestEnv) []byte) runner.Spec {
	return transportAbuseSpecProtocol(id, runClass, knowledge, pingV1, buildBody)
}

func transportAbuseSpecProtocol(id string, runClass runner.RunClass, knowledge []string,
	protocol string, buildBody func(te runner.TestEnv) []byte) runner.Spec {
	return runner.Spec{
		ID:       id,
		Category: "transport",
		Metadata: runner.Metadata{
			SpecRules:    []string{"reqresp:request-framing"},
			KnowledgeIDs: knowledge,
			RunClass:     runClass,
		},
		Run: func(ctx context.Context, te runner.TestEnv) []runner.Divergence {
			results := map[string]string{}
			for _, c := range te.Clients {
				err := c.SendOnly(ctx, protocol, buildBody(te))
				out := outcomeConn(err)
				if out == "accept" {
					out = stillConnectedAfter(ctx, c)
				}
				results[c.Name()] = out
			}
			return diverge(id, "transport", te.Meta, results)
		},
	}
}

// stalledSpec holds fresh unhandshaken connections and classifies how many
// the peer keeps vs reaps.
func stalledSpec(id string, runClass runner.RunClass, knowledge []string, count int) runner.Spec {
	return runner.Spec{
		ID:       id,
		Category: "transport",
		Metadata: runner.Metadata{
			SpecRules:    []string{"transport:handshake-timeout"},
			KnowledgeIDs: knowledge,
			RunClass:     runClass,
		},
		Run: func(ctx context.Context, te runner.TestEnv) []runner.Divergence {
			results := map[string]string{}
			for _, c := range te.Clients {
				survived := 0
				for i := 0; i < count; i++ {
					if err := c.Connect(ctx, runner.ConnectNoStatus); err != nil {
						continue
					}
					time.Sleep(300 * time.Millisecond)
					if c.Health(ctx) == nil {
						survived++
					}
				}
				results[c.Name()] = fmt.Sprintf("survived=%d/%d", survived, count)
			}
			return divergeValues(id, te, runner.DivValueDiff, runner.SeverityLow, results)
		},
	}
}

// transportSpecs3 returns the ported transporttest family.
func transportSpecs3() []runner.Spec {
	return []runner.Spec{
		transportAbuseSpec("transporttest.corrupted.random_bytes", runner.RunClassHeavy,
			[]string{"RETH-25"}, func(te runner.TestEnv) []byte {
				garbage := make([]byte, 1024)
				te.RNG.Read(garbage)
				return garbage
			}),
		transportAbuseSpec("transporttest.corrupted.oversized_frame", runner.RunClassHeavy,
			[]string{"RETH-25"}, func(te runner.TestEnv) []byte {
				return wire.BuildSnappySizeBomb(uint64(maxPayloadSize)+1, []byte{0x01})
			}),
		transportAbuseSpec("transporttest.corrupted.truncated_snappy", runner.RunClassHeavy,
			nil, func(te runner.TestEnv) []byte {
				framed := wire.SnappyEncode(wire.Uint64ToSSZ(1))
				return append(wire.EncodeVarint(8), framed[:len(framed)-3]...)
			}),
		transportAbuseSpec("transporttest.corrupted.post_valid_garbage", runner.RunClassHeavy,
			nil, func(te runner.TestEnv) []byte {
				garbage := make([]byte, 32)
				te.RNG.Read(garbage)
				return append(wire.BuildSSZSnappy(wire.Uint64ToSSZ(1)), garbage...)
			}),
		stalledSpec("transporttest.handshake.stalled_single", runner.RunClassStandard,
			[]string{"CL-2020-01", "CL-2022-06"}, 1),
		stalledSpec("transporttest.handshake.stalled_10", runner.RunClassHeavy,
			[]string{"CL-2020-01", "CL-2022-06"}, 10),
		{
			ID:       "transporttest.handshake.stalled_no_stream",
			Category: "transport",
			Metadata: runner.Metadata{
				SpecRules:    []string{"transport:handshake-timeout"},
				KnowledgeIDs: []string{"CL-2026-02"},
			},
			Run: func(ctx context.Context, te runner.TestEnv) []runner.Divergence {
				results := map[string]string{}
				for _, c := range te.Clients {
					if err := c.Connect(ctx, runner.ConnectNoStatus); err != nil {
						results[c.Name()] = "reject"
						continue
					}
					time.Sleep(500 * time.Millisecond)
					results[c.Name()] = verdict(c.Health(ctx) == nil)
				}
				return diverge("transporttest.handshake.stalled_no_stream", "transport", te.Meta, results)
			},
		},
		transportAbuseSpecProtocol("transporttest.identify.push_malformed", runner.RunClassHeavy,
			nil, "/ipfs/id/1.0.0", func(te runner.TestEnv) []byte {
				garbage := make([]byte, 64)
				te.RNG.Read(garbage)
				return garbage
			}),
		{
			ID:       "transporttest.identify.slow_stream",
			Category: "transport",
			Metadata: runner.Metadata{
				SpecRules: []string{"libp2p:identify"},
				RunClass:  runner.RunClassHeavy,
			},
			Run: func(ctx context.Context, te runner.TestEnv) []runner.Divergence {
				results := map[string]string{}
				for _, c := range te.Clients {
					_, err := c.SendSlowly(ctx, "/ipfs/id/1.0.0", []byte{0x0a, 0x04, 0x01, 0x02, 0x03, 0x04},
						50*time.Millisecond, 10*time.Second)
					results[c.Name()] = outcomeConn(err)
				}
				return diverge("transporttest.identify.slow_stream", "transport", te.Meta, results)
			},
		},
	}
}

// exhaustedSpecs returns the old exhaustion family (heavy: the inputs are
// designed to hold target resources).
func exhaustedSpecs() []runner.Spec {
	return []runner.Spec{
		{
			ID:       "reqresp.exhaustion.slow_request",
			Category: "reqresp",
			Metadata: runner.Metadata{
				SpecRules: []string{"reqresp:request-timeouts"},
				RunClass:  runner.RunClassHeavy,
			},
			Run: func(ctx context.Context, te runner.TestEnv) []runner.Divergence {
				body := wire.BuildSSZSnappy(wire.Uint64ToSSZ(1))
				results := map[string]string{}
				for _, c := range te.Clients {
					_, err := c.SendSlowly(ctx, pingV1, body, 100*time.Millisecond, 10*time.Second)
					results[c.Name()] = outcomeConn(err)
				}
				return diverge("reqresp.exhaustion.slow_request", "reqresp", te.Meta, results)
			},
		},
		{
			ID:       "reqresp.exhaustion.half_open_stream",
			Category: "reqresp",
			Metadata: runner.Metadata{
				SpecRules: []string{"reqresp:request-timeouts"},
				RunClass:  runner.RunClassHeavy,
			},
			Run: func(ctx context.Context, te runner.TestEnv) []runner.Divergence {
				full := wire.BuildSSZSnappy(wire.Uint64ToSSZ(1))
				half := full[:len(full)/2]
				results := map[string]string{}
				for _, c := range te.Clients {
					results[c.Name()] = outcomeConn(c.SendOnly(ctx, pingV1, half))
				}
				return diverge("reqresp.exhaustion.half_open_stream", "reqresp", te.Meta, results)
			},
		},
		{
			ID:       "reqresp.exhaustion.never_read_response",
			Category: "reqresp",
			Metadata: runner.Metadata{
				SpecRules: []string{"reqresp:request-timeouts"},
				RunClass:  runner.RunClassHeavy,
			},
			Run: func(ctx context.Context, te runner.TestEnv) []runner.Divergence {
				results := map[string]string{}
				for _, c := range te.Clients {
					results[c.Name()] = outcomeConn(c.SendOnly(ctx, pingV1, wire.BuildSSZSnappy(wire.Uint64ToSSZ(1))))
				}
				return diverge("reqresp.exhaustion.never_read_response", "reqresp", te.Meta, results)
			},
		},
		{
			ID:       "reqresp.exhaustion.parallel_streams",
			Category: "reqresp",
			Metadata: runner.Metadata{
				SpecRules: []string{"reqresp:stream-limits"},
				RunClass:  runner.RunClassHeavy,
			},
			Run: func(ctx context.Context, te runner.TestEnv) []runner.Divergence {
				body := wire.BuildSSZSnappy(wire.Uint64ToSSZ(1))
				results := map[string]string{}
				for _, c := range te.Clients {
					var wg sync.WaitGroup
					var mu sync.Mutex
					served := 0
					for i := 0; i < 8; i++ {
						wg.Add(1)
						go func() {
							defer wg.Done()
							res, err := c.ReqResp(ctx, pingV1, body, 10*time.Second)
							if err == nil && res != nil && len(res.RawBytes) > 0 {
								mu.Lock()
								served++
								mu.Unlock()
							}
						}()
					}
					wg.Wait()
					results[c.Name()] = fmt.Sprintf("served=%d/8", served)
				}
				return divergeValues("reqresp.exhaustion.parallel_streams", te,
					runner.DivValueDiff, runner.SeverityLow, results)
			},
		},
	}
}
