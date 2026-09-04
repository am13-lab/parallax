package main

import "strings"

const (
	protoStatusV2              = "/eth2/beacon_chain/req/status/2/ssz_snappy"
	protoBlocksByRangeV2       = "/eth2/beacon_chain/req/beacon_blocks_by_range/2/ssz_snappy"
	protoBlocksByRootV2        = "/eth2/beacon_chain/req/beacon_blocks_by_root/2/ssz_snappy"
	protoBlocksByHeadV1        = "/eth2/beacon_chain/req/beacon_blocks_by_head/1/ssz_snappy"
	protoBlobSidecarsByRangeV1 = "/eth2/beacon_chain/req/blob_sidecars_by_range/1/ssz_snappy"
	protoBlobSidecarsByRootV1  = "/eth2/beacon_chain/req/blob_sidecars_by_root/1/ssz_snappy"
	protoDataColumnsByRangeV1  = "/eth2/beacon_chain/req/data_column_sidecars_by_range/1/ssz_snappy"
	protoLCFinalityUpdateV1    = "/eth2/beacon_chain/req/light_client_finality_update/1/ssz_snappy"
	protoLCOptimisticUpdateV1  = "/eth2/beacon_chain/req/light_client_optimistic_update/1/ssz_snappy"
)

type fallbackSpec struct {
	action   *irAction
	expected string
	note     string
}

func statefulFallbackSpec(res resolved, knownProto map[string]bool) (fallbackSpec, bool) {
	switch res.domain {
	case domReqResp:
		return reqrespStatefulFallback(res, knownProto)
	case domConn:
		return connStatefulFallback(res, knownProto)
	case domDiscovery:
		return discoveryStatefulFallback(res)
	case domGossip:
		return gossipStatefulFallback(res)
	default:
		return fallbackSpec{}, false
	}
}

func applyFallbackPlanFields(p *executionPlan, fb fallbackSpec) {
	if fb.action == nil {
		return
	}
	p.Action = fb.action.Type
	p.Protocol = fb.action.Protocol
	p.Oracle = fb.expected
	if fb.action.Payload != nil && fb.action.Payload.Name != "" {
		p.Builder = fb.action.Payload.Name
	}
	if fb.action.Mutator != "" {
		p.Mutator = fb.action.Mutator
	}
	if fb.note != "" {
		p.Reason = fb.note
	}
}

func reqrespStatefulFallback(res resolved, knownProto map[string]bool) (fallbackSpec, bool) {
	raw := lowerRule(res)
	protocol := reqrespFallbackProtocol(res, raw, knownProto)
	if protocol == "" {
		return fallbackSpec{}, false
	}

	actionType := "ActSendReqResp"
	switch {
	case containsAny(raw, "close the write side", "until eof", "full request message", "sent immediately"):
		actionType = "ActWriteAndClose"
	case containsAny(raw, "new stream", "before reading the payload", "before processing it", "header must be validated"):
		actionType = "ActOpenStream"
	case containsAny(raw, "response_chunk", "response chunks", "error payload", "read more than", "length-prefix", "encoding-dependent", "read the chunk fully", "read from the stream"):
		actionType = "ActValidateResponseOrder"
	}

	act := &irAction{Type: actionType, Protocol: protocol, TimeoutMs: 10000}
	if actionType == "ActOpenStream" {
		return fallbackSpec{action: act, note: "stateful fallback: open a negotiated Req/Resp stream for stream/header lifecycle coverage"}, true
	}
	payload := reqrespFallbackPayload(protocol)
	if payload != nil {
		act.Payload = payload
	}
	return fallbackSpec{action: act, note: "stateful fallback: executable Req/Resp lifecycle/response probe"}, true
}

func connStatefulFallback(res resolved, knownProto map[string]bool) (fallbackSpec, bool) {
	if !knownProto[protoStatusV2] {
		return fallbackSpec{}, false
	}
	return fallbackSpec{
		action: &irAction{
			Type:      "ActSendStatus",
			Protocol:  protoStatusV2,
			Payload:   builderPayload("buildStatusV2SSZ", "ssz_snappy"),
			TimeoutMs: 5000,
		},
		expected: "SUCCESS",
		note:     "stateful fallback: Status exchange probe for connection/status content rule",
	}, true
}

func discoveryStatefulFallback(res resolved) (fallbackSpec, bool) {
	raw := lowerRule(res)
	switch {
	case strings.Contains(raw, "custody") || strings.Contains(raw, "cgc"):
		return fallbackSpec{action: &irAction{Type: "ActVerifyENRBehavior", Protocol: "cgc"}, note: "stateful fallback: verify custody-related ENR behavior"}, true
	case strings.Contains(raw, "nfd") || strings.Contains(raw, "fork") || strings.Contains(raw, "mismatch"):
		return fallbackSpec{action: &irAction{Type: "ActVerifyENRBehavior", Protocol: "nfd"}, note: "stateful fallback: verify fork-boundary ENR behavior"}, true
	default:
		return fallbackSpec{action: &irAction{Type: "ActQueryENR"}, note: "stateful fallback: query ENR for discovery lifecycle rule"}, true
	}
}

func gossipStatefulFallback(res resolved) (fallbackSpec, bool) {
	raw := lowerRule(res)
	topic := normalizeTopic(res.topic)

	switch {
	case topic == "eth2" || containsAny(raw, "genesis values", "bootnodes", "enr"):
		return fallbackSpec{action: &irAction{Type: "ActQueryENR"}, note: "stateful fallback: query ENR for gossip/discovery gating rule"}, true
	case containsAny(raw, "pre-fork topics", "unsubscribed"):
		return fallbackSpec{action: &irAction{
			Type:     "ActInjectGossip",
			Protocol: "blob_sidecar_0",
			Payload:  builderPayload("buildRandomGossip200", "raw"),
			Mutator:  "gossip_random_bytes",
		}, note: "stateful fallback: probe legacy topic handling after fork boundary"}, true
	case containsAny(raw, "request cells", "partialdatacolumnheader"):
		return fallbackSpec{action: &irAction{Type: "ActRequestCustodyColumns", Protocol: "custody", TimeoutMs: 10000}, note: "stateful fallback: request custody columns after data-availability context"}, true
	case containsAny(raw, "subscribe to gossipsub topics", "begin peer discovery"):
		return fallbackSpec{action: &irAction{Type: "ActSwitchTopic", Protocol: "beacon_block"}, note: "stateful fallback: exercise topic-selection gating"}, true
	case topic == "light_client_finality_update":
		return fallbackSpec{action: &irAction{
			Type:     "ActInjectGossip",
			Protocol: "light_client_finality_update",
			Payload:  builderPayload("buildRandomGossip100", "raw"),
			Mutator:  "gossip_random_bytes",
		}, note: "stateful fallback: light-client finality gossip forwarding probe"}, true
	case topic == "light_client_optimistic_update":
		return fallbackSpec{action: &irAction{
			Type:     "ActInjectGossip",
			Protocol: "light_client_optimistic_update",
			Payload:  builderPayload("buildRandomGossip100", "raw"),
			Mutator:  "gossip_random_bytes",
		}, note: "stateful fallback: light-client optimistic gossip forwarding probe"}, true
	case topic == "partial_data_column_sidecar":
		// Partial messages ride the existing data_column_sidecar_{subnet} topic
		// (fulu/partial-columns/p2p-interface.md), but the payload must be a
		// PartialDataColumnSidecar. Binding a full DataColumnSidecar here cannot
		// satisfy any partial-columns precondition, so an Expected:REJECT oracle
		// fires on every client at once instead of testing the rule.
		builder, expected := partialDataColumnBuilder(res, raw)
		return fallbackSpec{action: &irAction{
			Type:     "ActInjectGossip",
			Protocol: "data_column_sidecar_0",
			Payload:  builderPayload(builder, "raw"),
		}, expected: expected, note: "stateful fallback: partial-data-column sidecar gossip probe"}, true
	case topic == "beacon_block" || strings.Contains(raw, "engine_getblobs"):
		return fallbackSpec{action: &irAction{
			Type:     "ActInjectGossip",
			Protocol: "beacon_block",
			Payload:  builderPayload("buildValidBeaconBlock", "raw"),
		}, note: "stateful fallback: valid beacon-block gossip probe for execution-payload side effect rule"}, true
	case topic != "":
		return fallbackSpec{action: &irAction{
			Type:     "ActInjectGossip",
			Protocol: topic,
			Payload:  builderPayload("buildRandomGossip100", "raw"),
			Mutator:  "gossip_random_bytes",
		}, note: "stateful fallback: generic topic-level gossip probe"}, true
	default:
		return fallbackSpec{action: &irAction{Type: "ActCheckConnected"}, note: "stateful fallback: connection liveness probe for machine-level gossip rule"}, true
	}
}

func reqrespFallbackProtocol(res resolved, raw string, knownProto map[string]bool) string {
	if res.protocolID != "" && knownProto[res.protocolID] {
		return res.protocolID
	}
	candidates := []string{}
	switch {
	case containsAny(raw, "data column", "datacolumn"):
		candidates = append(candidates, protoDataColumnsByRangeV1)
	case strings.Contains(raw, "blob") && strings.Contains(raw, "root"):
		candidates = append(candidates, protoBlobSidecarsByRootV1)
	case strings.Contains(raw, "blob"):
		candidates = append(candidates, protoBlobSidecarsByRangeV1)
	case strings.Contains(raw, "beaconblocksbyhead"):
		candidates = append(candidates, protoBlocksByHeadV1)
	case strings.Contains(raw, "light client finality"):
		candidates = append(candidates, protoLCFinalityUpdateV1)
	case strings.Contains(raw, "light client optimistic"):
		candidates = append(candidates, protoLCOptimisticUpdateV1)
	default:
		candidates = append(candidates, protoBlocksByRangeV2)
	}
	candidates = append(candidates, protoBlocksByRangeV2)
	for _, p := range candidates {
		if knownProto[p] {
			return p
		}
	}
	return ""
}

// partialDataColumnBuilder picks the PartialDataColumnSidecar builder that
// actually triggers a partial-columns gossip rule, and returns the oracle
// expectation only when the chosen payload can reach that outcome.
//
// A REJECT rule whose precondition needs prior state (a previously validated
// header for the same block) cannot be provoked by a single injected message, so
// those get a valid payload and no expectation rather than an assertion that
// would fail on every client.
func partialDataColumnBuilder(res resolved, raw string) (builder, expected string) {
	switch {
	case strings.Contains(raw, "semantically empty"):
		return "buildInvalidPartialDataColumnEmpty", "REJECT"
	case strings.Contains(raw, "kzg_commitments list is non-empty"):
		return "buildInvalidPartialDataColumnHeaderNoCommitments", "REJECT"
	case strings.Contains(raw, "proof"):
		return "buildInvalidPartialDataColumnKzgProof", "REJECT"
	case strings.Contains(raw, "signature"):
		return "buildInvalidPartialDataColumnSigInvalid", "REJECT"
	case strings.Contains(raw, "slot"):
		return "buildInvalidPartialDataColumnSlotFuture", "REJECT"
	case strings.Contains(raw, "cells_present_bitmap"):
		return "buildInvalidPartialDataColumnBitmapLenMismatch", "REJECT"
	case strings.Contains(raw, "must equal"):
		// prior_header dedup: needs a first validated header for the same block
		// root before a conflicting one can be rejected. Single-shot injection
		// cannot set that up, so assert nothing.
		return "buildValidPartialDataColumnSidecar", ""
	case res.rule.Outcome == "REJECT":
		return "buildInvalidPartialDataColumnProofCountMismatch", "REJECT"
	default:
		return "buildValidPartialDataColumnSidecar", ""
	}
}

func reqrespFallbackPayload(protocol string) *irPayload {
	switch protocol {
	case protoDataColumnsByRangeV1:
		return builderPayload("buildDataColumnsOrdering", "raw")
	case protoBlobSidecarsByRootV1:
		return builderPayload("buildBlobIdentifierHeadRoot", "ssz_snappy")
	case protoBlobSidecarsByRangeV1:
		// BlobSidecarsByRange is {start_slot, count}: 16 bytes, no step field.
		return builderPayload("buildBlocksByRangeNearHead", "ssz_snappy")
	case protoBlocksByRootV2:
		return builderPayload("buildRootListHeadRoot", "ssz_snappy")
	case protoBlocksByHeadV1:
		return builderPayload("buildBlocksByHeadHeadRoot", "ssz_snappy")
	case protoLCFinalityUpdateV1, protoLCOptimisticUpdateV1:
		return nil
	default:
		// BeaconBlocksByRange is {start_slot, count, step}: 24 bytes. Using the
		// 16-byte blob-shaped builder here makes the request undecodable, so every
		// client answers with a reset or empty stream and an Expected:SUCCESS oracle
		// reports a violation on all of them at once.
		return builderPayload("buildBeaconBlocksByRangeV2NearHead", "ssz_snappy")
	}
}

func builderPayload(name, wrap string) *irPayload {
	return &irPayload{Kind: "builder", Name: name, Wrap: wrap}
}

func lowerRule(res resolved) string {
	return strings.ToLower(res.rule.RawText + " " + res.rule.Source.Anchor + " " + res.methodName + " " + res.topic)
}

func containsAny(hay string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(hay, n) {
			return true
		}
	}
	return false
}
