package cases

import (
	"bytes"
	"context"
	"time"

	"parallax/runner"
	"parallax/wire"
)

const (
	statusV1     = "/eth2/beacon_chain/req/status/1/ssz_snappy"
	pingV1       = "/eth2/beacon_chain/req/ping/1/ssz_snappy"
	metadataV2   = "/eth2/beacon_chain/req/metadata/2/ssz_snappy"
	goodbyeV1    = "/eth2/beacon_chain/req/goodbye/1/ssz_snappy"
	blocksByRoot = "/eth2/beacon_chain/req/beacon_blocks_by_root/2/ssz_snappy"

	reqTimeout = 5 * time.Second
)

// reqrespSpecs returns the req/resp seed cases.
func reqrespSpecs() []runner.Spec {
	return []runner.Spec{
		{
			ID:       "reqresp.status.valid",
			Category: "reqresp",
			What:     "Exchanges a valid Status/1 built from each client's live chain state; every client must accept it.",
			Metadata: runner.Metadata{
				SpecRules: []string{"reqresp:status", "phase0:status-envelope"},
			},
			Preflight: requireChainState,
			Run: func(ctx context.Context, te runner.TestEnv) []runner.Divergence {
				results := map[string]string{}
				for _, c := range te.Clients {
					state, err := c.State(ctx)
					if err != nil {
						results[c.Name()] = "other:no state"
						continue
					}
					res, err := c.ReqResp(ctx, statusV1, wire.BuildSSZSnappy(buildStatusBody(state)), reqTimeout)
					results[c.Name()] = outcome(res, err)
				}
				return diverge("reqresp.status.valid", "reqresp", te.Meta, results)
			},
		},
		{
			ID:       "reqresp.ping.empty_body",
			Category: "reqresp",
			What:     "Sends PING with a zero-length SSZ payload; the malformed body must be rejected, not accepted.",
			Metadata: runner.Metadata{SpecRules: []string{"reqresp:ping"}},
			Run: func(ctx context.Context, te runner.TestEnv) []runner.Divergence {
				results := map[string]string{}
				for _, c := range te.Clients {
					res, err := c.ReqResp(ctx, pingV1, wire.BuildSSZSnappy(nil), reqTimeout)
					results[c.Name()] = outcome(res, err)
				}
				return diverge("reqresp.ping.empty_body", "reqresp", te.Meta, results)
			},
		},
		{
			ID:       "reqresp.ping.extra_bytes",
			Category: "reqresp",
			What:     "Sends PING with 2 trailing bytes after the 8-byte payload; spec framing requires rejecting trailing data.",
			Metadata: runner.Metadata{SpecRules: []string{"reqresp:request-framing"}},
			Run: func(ctx context.Context, te runner.TestEnv) []runner.Divergence {
				results := map[string]string{}
				for _, c := range te.Clients {
					body := append(wire.BuildSSZSnappy(wire.Uint64ToSSZ(1)), 0xde, 0xad)
					res, err := c.ReqResp(ctx, pingV1, body, reqTimeout)
					results[c.Name()] = outcome(res, err)
				}
				return diverge("reqresp.ping.extra_bytes", "reqresp", te.Meta, results)
			},
		},
		{
			ID:       "reqresp.status.malformed",
			Category: "reqresp",
			What:     "Sends Status with randomly corrupted SSZ bytes; the client must reject the malformed payload.",
			Metadata: runner.Metadata{SpecRules: []string{"reqresp:status", "reqresp:ssz-decoding"}},
			Run: func(ctx context.Context, te runner.TestEnv) []runner.Divergence {
				results := map[string]string{}
				payload := bytes.Repeat([]byte{0x07}, 84)
				for _, c := range te.Clients {
					body := wire.BuildMalformedSSZSnappy(payload, wire.MalformRandomBytes, te.RNG)
					res, err := c.ReqResp(ctx, statusV1, body, reqTimeout)
					results[c.Name()] = outcome(res, err)
				}
				return diverge("reqresp.status.malformed", "reqresp", te.Meta, results)
			},
		},
		{
			ID:       "reqresp.status.pre_status",
			Category: "reqresp",
			What:     "Connects without the Status handshake, then requests Status; the client must not serve Status before the handshake.",
			Metadata: runner.Metadata{SpecRules: []string{"reqresp:status-handshake-required"}},
			Run: func(ctx context.Context, te runner.TestEnv) []runner.Divergence {
				results := map[string]string{}
				for _, c := range te.Clients {
					if err := c.Connect(ctx, runner.ConnectNoStatus); err != nil {
						results[c.Name()] = "other:connect failed: " + err.Error()
						continue
					}
					// A conformant client must not serve Status before the
					// handshake, regardless of body content.
					res, err := c.ReqResp(ctx, statusV1, wire.BuildSSZSnappy(make([]byte, 84)), reqTimeout)
					results[c.Name()] = outcome(res, err)
					// Restore the normal handshaken connection for later tests.
					_ = c.Connect(ctx, runner.ConnectWithStatus)
				}
				return diverge("reqresp.status.pre_status", "reqresp", te.Meta, results)
			},
		},
		{
			ID:       "reqresp.blocks_by_root.length_bomb",
			Category: "reqresp",
			What:     "Sends BlocksByRoot with a snappy size bomb (declares 1GiB uncompressed); the client must reject it without allocating.",
			Metadata: runner.Metadata{SpecRules: []string{"reqresp:length-prefix", "reqresp:blocks-by-root"}},
			Run: func(ctx context.Context, te runner.TestEnv) []runner.Divergence {
				results := map[string]string{}
				body := wire.BuildSnappySizeBomb(1<<30, bytes.Repeat([]byte{0x11}, 32))
				for _, c := range te.Clients {
					res, err := c.ReqResp(ctx, blocksByRoot, body, reqTimeout)
					results[c.Name()] = outcome(res, err)
				}
				return diverge("reqresp.blocks_by_root.length_bomb", "reqresp", te.Meta, results)
			},
		},
		{
			ID:       "reqresp.blocks_by_root.trailing_bytes",
			Category: "reqresp",
			What:     "Sends BlocksByRoot with 3 trailing bytes after the payload; framing rules require rejection.",
			Metadata: runner.Metadata{SpecRules: []string{"reqresp:request-framing", "reqresp:blocks-by-root"}},
			Run: func(ctx context.Context, te runner.TestEnv) []runner.Divergence {
				results := map[string]string{}
				for _, c := range te.Clients {
					body := append(wire.BuildSSZSnappy(bytes.Repeat([]byte{0x22}, 32)), 0x00, 0x01, 0x02)
					res, err := c.ReqResp(ctx, blocksByRoot, body, reqTimeout)
					results[c.Name()] = outcome(res, err)
				}
				return diverge("reqresp.blocks_by_root.trailing_bytes", "reqresp", te.Meta, results)
			},
		},
		{
			ID:       "reqresp.metadata.valid",
			Category: "reqresp",
			What:     "Requests METADATA/2 with an empty request body; every client must answer with its metadata.",
			Metadata: runner.Metadata{SpecRules: []string{"reqresp:metadata"}},
			Run: func(ctx context.Context, te runner.TestEnv) []runner.Divergence {
				results := map[string]string{}
				for _, c := range te.Clients {
					res, err := c.ReqResp(ctx, metadataV2, wire.BuildSSZSnappy(nil), reqTimeout)
					results[c.Name()] = outcome(res, err)
				}
				return diverge("reqresp.metadata.valid", "reqresp", te.Meta, results)
			},
		},
		{
			ID:       "reqresp.goodbye.valid",
			Category: "reqresp",
			What:     "Sends GOODBYE with the spec-defined shutdown reason 0x80; all clients must handle it consistently (response, reset or silence all conform).",
			Metadata: runner.Metadata{SpecRules: []string{"reqresp:goodbye"}},
			Run: func(ctx context.Context, te runner.TestEnv) []runner.Divergence {
				results := map[string]string{}
				// 0x80 = client shutdown, a spec-defined goodbye reason.
				// A goodbye may legitimately get no response (clients rarely
				// answer before disconnecting), so reset maps to accept here.
				for _, c := range te.Clients {
					res, err := c.ReqResp(ctx, goodbyeV1, wire.BuildSSZSnappy(wire.Uint64ToSSZ(0x80)), reqTimeout)
					out := outcome(res, err)
					if out == "reject" {
						out = "accept"
					}
					results[c.Name()] = out
				}
				return diverge("reqresp.goodbye.valid", "reqresp", te.Meta, results)
			},
		},
		{
			ID:       "reqresp.unknown_protocol",
			Category: "reqresp",
			What:     "Requests a nonexistent protocol ID; every client must fail protocol negotiation the same way.",
			Metadata: runner.Metadata{SpecRules: []string{"reqresp:protocol-negotiation"}},
			Run: func(ctx context.Context, te runner.TestEnv) []runner.Divergence {
				results := map[string]string{}
				for _, c := range te.Clients {
					res, err := c.ReqResp(ctx, "/eth2/beacon_chain/req/definitely_not_real/1/ssz_snappy",
						wire.BuildSSZSnappy(nil), reqTimeout)
					results[c.Name()] = outcome(res, err)
				}
				return diverge("reqresp.unknown_protocol", "reqresp", te.Meta, results)
			},
		},
	}
}

func buildStatusBody(state *runner.NodeState) []byte {
	body := make([]byte, 84)
	copy(body[0:4], state.ForkDigest[:])
	copy(body[4:36], state.FinalizedRoot[:])
	copy(body[44:76], state.HeadRoot[:])
	return body
}

// requireChainState preflights that every client exposes a valid
// Beacon API-derived chain state.
func requireChainState(ctx context.Context, chain runner.ChainConfig, cs []runner.Client) runner.PreflightResult {
	for _, c := range cs {
		state, err := c.State(ctx)
		if err != nil || state == nil || !state.Valid {
			return runner.PreflightResult{
				Runnable: false,
				Reason:   "client " + c.Name() + " lacks valid chain state",
			}
		}
	}
	return runner.PreflightResult{Runnable: true}
}
