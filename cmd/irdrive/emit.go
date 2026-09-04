package main

import (
	"fmt"
	"sort"
	"strings"
)

// emit.go — Layers D1 (state templates) + D2 (rule -> transition). One machine
// per domain, using the existing hand-authored state vocabulary so the output is
// drop-in comparable. Templates are cyclic (a reset edge back to init) so the
// generator can reach its profile MinSteps. A rule becomes a transition ONLY when
// the dictionary yields an executable action AND (reqresp/conn) the protocol is
// known to smgen; otherwise it is recorded as a coverage gap.

// gap is a rule that did not become an executable transition.
type gap struct {
	RuleID  string `json:"rule_id"`
	Domain  string `json:"domain"`
	Class   string `json:"class"` // pending_builder | pending_live_builder | pending_inspector | pending_sequence_template | unsupported | audit_only | pending_future
	Reason  string `json:"reason"`
	RawText string `json:"raw_text"`
}

// derivation is the full output of the deriver.
type derivation struct {
	Machines []irMachine
	Plans    []executionPlan
	Gaps     []gap
	Coverage map[string]*domainCoverage // domain -> counts
	Link     linkStats
}

type domainCoverage struct {
	Mapped                  int `json:"mapped"`
	StatefulSupported       int `json:"stateful_supported,omitempty"`
	StatelessSupported      int `json:"stateless_supported,omitempty"`
	AuditOnly               int `json:"audit_only,omitempty"`
	PendingFuture           int `json:"pending_future,omitempty"`
	PendingBuilder          int `json:"pending_builder,omitempty"`
	PendingLiveBuilder      int `json:"pending_live_builder,omitempty"`
	PendingInspector        int `json:"pending_inspector,omitempty"`
	PendingSequenceTemplate int `json:"pending_sequence_template,omitempty"`
	Unsupported             int `json:"unsupported,omitempty"`
	// RandomInjected counts topic-level random/garbage fuzz transitions (not
	// rule-mapped; the random half of the targeted/random strategy).
	RandomInjected int `json:"random_injected,omitempty"`
}

// shapeTemplate defines a machine's states and the from/to for rule transitions.
type shapeTemplate struct {
	name        string
	constructor string
	init        string
	states      []irState
	ruleFrom    string
	ruleTo      string
	backbone    []irTransition // neutral cycle + terminal path
}

// neutralCheck is a side-effect-free executable action for backbone/reset edges.
func neutralCheck() *irAction { return &irAction{Type: "ActCheckConnected"} }

func gossipTemplate() shapeTemplate {
	return shapeTemplate{
		name: "GossipValidation", constructor: "NewGossipMachine", init: "GossipReady", ruleFrom: "GossipReady", ruleTo: "GossipSent",
		states: []irState{{Name: "GossipReady"}, {Name: "GossipSent"}, {Name: "GossipCompleted", Terminal: true}},
		backbone: []irTransition{
			{From: "GossipReady", To: "GossipSent", Label: "gossip_baseline", Weight: 1, Action: neutralCheck(), Description: "backbone: liveness check"},
			{From: "GossipSent", To: "GossipReady", Label: "gossip_reset", Weight: 1, Action: neutralCheck(), Description: "backbone: cycle back so sequences reach MinSteps"},
			{From: "GossipSent", To: "GossipCompleted", Label: "gossip_finish", Weight: 1, Action: neutralCheck(), Description: "backbone: terminal path"},
		},
	}
}

func cryptoTemplate() shapeTemplate {
	return shapeTemplate{
		name: "CryptoMsg", init: "CryptoReady", ruleFrom: "CryptoReady", ruleTo: "CryptoSent",
		states: []irState{{Name: "CryptoReady"}, {Name: "CryptoSent"}, {Name: "CryptoCompleted", Terminal: true}},
		backbone: []irTransition{
			{From: "CryptoReady", To: "CryptoSent", Label: "cm_baseline", Weight: 1, Action: neutralCheck(), Description: "backbone: liveness check"},
			{From: "CryptoSent", To: "CryptoReady", Label: "cm_reset", Weight: 1, Action: neutralCheck(), Description: "backbone: cycle back"},
			{From: "CryptoSent", To: "CryptoCompleted", Label: "cm_finish", Weight: 1, Action: neutralCheck(), Description: "backbone: terminal path"},
		},
	}
}

func reqrespTemplate() shapeTemplate {
	return shapeTemplate{
		name: "ReqResp", init: "Connected", ruleFrom: "Connected", ruleTo: "Completed",
		states: []irState{{Name: "Connected"}, {Name: "Completed"}, {Name: "Closed", Terminal: true}},
		backbone: []irTransition{
			{From: "Connected", To: "Completed", Label: "rr_baseline", Weight: 1, Action: neutralCheck(), Description: "backbone: liveness check"},
			{From: "Completed", To: "Connected", Label: "rr_reset", Weight: 1, Action: neutralCheck(), Description: "backbone: cycle back"},
			{From: "Completed", To: "Closed", Label: "rr_finish", Weight: 1, Action: neutralCheck(), Description: "backbone: terminal path"},
		},
	}
}

func connTemplate() shapeTemplate {
	return shapeTemplate{
		name: "ConnLifecycle", init: "ConnDial", ruleFrom: "ConnDial", ruleTo: "ConnProbing",
		states: []irState{
			{Name: "ConnDial"},
			{Name: "ConnHandshaked"},
			{Name: "ConnProbing"},
			{Name: "ConnGoodbyeSent"},
			{Name: "ConnDisconnected"},
			{Name: "ConnCompleted", Terminal: true},
		},
		backbone: []irTransition{
			{From: "ConnDial", To: "ConnProbing", Label: "conn_baseline", Weight: 1, Action: neutralCheck(), Description: "backbone: liveness check"},
			{From: "ConnProbing", To: "ConnDial", Label: "conn_reset", Weight: 1, Action: neutralCheck(), Description: "backbone: cycle back"},
			{From: "ConnProbing", To: "ConnCompleted", Label: "conn_finish", Weight: 1, Action: neutralCheck(), Description: "backbone: terminal path"},
			{From: "ConnHandshaked", To: "ConnProbing", Label: "conn_probe_after_handshake", Weight: 1, Action: neutralCheck(), Description: "backbone: enter post-handshake probing"},
			{From: "ConnGoodbyeSent", To: "ConnDisconnected", Label: "goodbye_to_disconnected", Weight: 1, Action: neutralCheck(), Description: "backbone: observe disconnect after goodbye"},
			{From: "ConnDisconnected", To: "ConnDial", Label: "conn_reconnect", Weight: 1, Action: &irAction{Type: "ActReconnect", TimeoutMs: 5000}, Description: "backbone: reconnect after disconnect"},
			{From: "ConnDisconnected", To: "ConnCompleted", Label: "end_after_disconnect", Weight: 1, Action: neutralCheck(), Description: "backbone: terminal path after disconnect"},
		},
	}
}

func discoveryTemplate() shapeTemplate {
	return shapeTemplate{
		name: "Discovery", init: "DiscBaseline", ruleFrom: "DiscBaseline", ruleTo: "DiscProbing",
		states: []irState{{Name: "DiscBaseline"}, {Name: "DiscProbing"}, {Name: "DiscCompleted", Terminal: true}},
		backbone: []irTransition{
			{From: "DiscBaseline", To: "DiscProbing", Label: "disc_baseline", Weight: 1, Action: neutralCheck(), Description: "backbone: liveness check"},
			{From: "DiscProbing", To: "DiscBaseline", Label: "disc_reset", Weight: 1, Action: neutralCheck(), Description: "backbone: cycle back"},
			{From: "DiscProbing", To: "DiscCompleted", Label: "disc_finish", Weight: 1, Action: neutralCheck(), Description: "backbone: terminal path"},
		},
	}
}

var domainTemplate = map[string]func() shapeTemplate{
	domCrypto:    cryptoTemplate,
	domGossip:    gossipTemplate,
	domReqResp:   reqrespTemplate,
	domConn:      connTemplate,
	domDiscovery: discoveryTemplate,
}

var domainPrefix = map[string]string{
	domCrypto: "cm",
	domGossip: "g", domReqResp: "rr", domConn: "conn", domDiscovery: "disc",
}

// derive builds all spec-truth machines from the resolved rules.
func derive(resolveds []resolved, entries []dictEntry, knownProto map[string]bool, edgeIdx map[string][]astEdge, randomRatio float64, link linkStats) derivation {
	_ = randomRatio // stateless/random fuzz is tracked for follow-up, not emitted to SM-IR.
	d := derivation{Coverage: map[string]*domainCoverage{}, Link: link}
	byDomain := map[string][]resolved{}
	for _, res := range resolveds {
		if res.domain == domNone {
			p := classifyResolvedPlan(res, entries, knownProto, edgeIdx)
			d.recordPlan(p)
			continue
		}
		if res.domain == domGossip && isCryptoMsgCandidate(res) {
			byDomain[domCrypto] = append(byDomain[domCrypto], res)
			continue
		}
		byDomain[res.domain] = append(byDomain[res.domain], res)
	}

	for _, dom := range []string{domCrypto, domGossip, domReqResp, domConn, domDiscovery} {
		d.Coverage[dom] = &domainCoverage{}
		tmpl := domainTemplate[dom]()
		m := irMachine{Name: tmpl.name, Constructor: tmpl.constructor, InitState: tmpl.init, States: tmpl.states}
		m.Transitions = append(m.Transitions, tmpl.backbone...)

		if dom == domCrypto {
			for _, res := range byDomain[dom] {
				p := classifyCryptoPlan(res)
				d.recordPlan(p)
				if p.EmitTarget == emitSMIR {
					t, g, ok := emitCryptoRule(res, tmpl, edgeIdx)
					if !ok {
						d.Gaps = append(d.Gaps, g)
						d.Coverage[dom].addGap(g.Class)
						continue
					}
					m.Transitions = append(m.Transitions, t)
					d.Coverage[dom].Mapped++
				}
			}
			d.Machines = append(d.Machines, m)
			continue
		}

		for _, res := range byDomain[dom] {
			p := classifyResolvedPlan(res, entries, knownProto, edgeIdx)
			d.recordPlan(p)
			if p.EmitTarget == emitSMIR {
				t, g, ok := emitRule(res, tmpl, entries, knownProto, edgeIdx)
				if !ok {
					d.Gaps = append(d.Gaps, g)
					d.Coverage[dom].addGap(g.Class)
					continue
				}
				m.Transitions = append(m.Transitions, t)
				d.Coverage[dom].Mapped++
			}
		}
		d.Machines = append(d.Machines, m)
	}
	return d
}

func (c *domainCoverage) addGap(class string) {
	switch class {
	case statusPendingBuilder:
		c.PendingBuilder++
	case statusPendingLiveBuilder:
		c.PendingLiveBuilder++
	case statusPendingInspector:
		c.PendingInspector++
	case statusPendingSequenceTemplate:
		c.PendingSequenceTemplate++
	case execPendingFuture:
		c.PendingFuture++
	case execAuditOnly:
		c.AuditOnly++
	default:
		c.Unsupported++
	}
}

func (d *derivation) recordPlan(p executionPlan) {
	d.Plans = append(d.Plans, p)
	if p.Domain != domNone {
		if d.Coverage[p.Domain] == nil {
			d.Coverage[p.Domain] = &domainCoverage{}
		}
		c := d.Coverage[p.Domain]
		switch p.ExecutionKind {
		case execStateful:
			if p.SupportStatus == statusSupported {
				c.StatefulSupported++
			}
		case execStateless:
			if p.SupportStatus == statusSupported {
				c.StatelessSupported++
			}
		case execAuditOnly:
			c.AuditOnly++
		case execPendingFuture:
			c.PendingFuture++
		}
		if p.SupportStatus != statusSupported && p.ExecutionKind != execAuditOnly && p.ExecutionKind != execPendingFuture {
			c.addGap(p.SupportStatus)
		}
	}
	if cls := planGapClass(p); cls != "" {
		d.Gaps = append(d.Gaps, gap{RuleID: p.RuleID, Domain: p.Domain, Class: cls, Reason: p.Reason, RawText: p.RawText})
	}
}

func gapClassForUnmatched(res resolved) string {
	if isFutureRule(res.rule) {
		return execPendingFuture
	}
	if isAuditOnlyRule(res) {
		return execAuditOnly
	}
	if res.domain == domGossip {
		return gossipUnmatchedStatus(res)
	}
	if res.protocolID == "" && res.topic == "" {
		return statusUnsupported
	}
	if res.domain == domReqResp && reqrespNeedsInspector(res.rule.RawText) {
		return statusPendingInspector
	}
	if res.domain == domConn && connNeedsInspector(res.rule.RawText) {
		return statusPendingInspector
	}
	return statusPendingBuilder
}

func gapReasonForUnmatched(res resolved) string {
	if isFutureRule(res.rule) {
		return "future-fork or feature rule is not enabled for the current generated runtime"
	}
	if isAuditOnlyRule(res) {
		return "rule describes capability, deployment, or policy behavior rather than a concrete message-level test"
	}
	if res.domain == domReqResp && reqrespNeedsInspector(res.rule.RawText) {
		return "response inspector required for this Req/Resp rule"
	}
	if res.domain == domConn && connNeedsInspector(res.rule.RawText) {
		return "connection/status response inspector required for this rule"
	}
	if res.domain == domGossip {
		return gossipUnmatchedReason(res)
	}
	return "no dictionary match for this surface/class"
}

func reqrespNeedsInspector(raw string) bool {
	re := strings.ToLower(raw)
	needles := []string{
		"response_chunk", "response chunks", "error payload", "write the response",
		"read exactly", "read more than", "length-prefix", "encoding-dependent",
		"bad server behavior", "utf-8", "close their write side", "rate-limit chunks",
		"withholding each chunk", "above 128", "score", "penalis", "proof",
		"executionproof", "execution proof", "resourceunavailable", "not include",
		"respond with", "response must", "must respond", "should include",
		"must be sent", "consecutive", "single chain", "current fork choice",
		"parent_root", "state transition", "gossip validation", "passes the gossip",
		"where they exist", "if they have", "unable to reply", "empty list",
		"limit the number", "fork choice changes", "valid chain", "weak subjectivity",
		"fulu_fork_epoch", "minimum_request_epoch", "should_not penalize",
	}
	for _, n := range needles {
		if strings.Contains(re, n) {
			return true
		}
	}
	return false
}

func gossipUnmatchedStatus(res resolved) string {
	topic := strings.ToLower(res.topic)
	if strings.Contains(topic, "partial_data_column") {
		return statusPendingBuilder
	}
	if gossipNeedsInspector(res) {
		return statusPendingInspector
	}
	if gossipNeedsSequenceTemplate(res) {
		return statusPendingSequenceTemplate
	}
	if res.protocolID == "" && res.topic == "" {
		return statusUnsupported
	}
	return statusPendingBuilder
}

func gossipUnmatchedReason(res resolved) string {
	switch gossipUnmatchedStatus(res) {
	case statusPendingSequenceTemplate:
		return "gossip rule requires a multi-step forwarding/topic-selection sequence template"
	case statusPendingInspector:
		return "gossip rule depends on receiver state, ENR/discovery state, or response inspection"
	case statusUnsupported:
		return "no concrete gossip topic or protocol surface"
	default:
		if strings.Contains(strings.ToLower(res.topic), "partial_data_column") || strings.Contains(strings.ToLower(res.rule.RawText), "partialdatacolumn") {
			return "typed PartialDataColumnSidecar payload builder is not implemented"
		}
		return "no dictionary match for this surface/class"
	}
}

func gossipNeedsSequenceTemplate(res resolved) bool {
	raw := strings.ToLower(res.rule.RawText)
	topic := strings.ToLower(res.topic)
	if strings.Contains(topic, "partial_data_column") {
		needles := []string{"eagerly push", "request cells", "already sent", "previously sent"}
		for _, n := range needles {
			if strings.Contains(raw, n) {
				return true
			}
		}
	}
	needles := []string{"previously forwarded", "previously validated", "no matching message", "first valid", "already been seen"}
	for _, n := range needles {
		if strings.Contains(raw, n) {
			return true
		}
	}
	return false
}

func gossipNeedsInspector(res resolved) bool {
	raw := strings.ToLower(res.rule.RawText + " " + res.rule.Source.Anchor)
	topic := strings.ToLower(res.topic)
	if topic == "eth2" || strings.Contains(raw, "enr") || strings.Contains(raw, "fork_digest") || strings.Contains(raw, "next_fork") {
		return true
	}
	if topic == "light_client_finality_update" || topic == "light_client_optimistic_update" {
		return true
	}
	if topic == "maximum_gossip_clock_disparity" || topic == "partialdatacolumnpartsmetadata" {
		return true
	}
	if strings.Contains(topic, "partial_data_column") {
		needles := []string{
			"parent", "finalized", "ancestor", "expected proposer", "has been seen",
			"local copy", "matches the partial message's group id",
		}
		for _, n := range needles {
			if strings.Contains(raw, n) {
				return true
			}
		}
	}
	if strings.Contains(raw, "engine_getblobs") || strings.Contains(raw, "local execution") || strings.Contains(raw, "local copy") {
		return true
	}
	return false
}

func connNeedsInspector(raw string) bool {
	re := strings.ToLower(raw)
	needles := []string{
		"response_chunk", "status message", "sync progress", "executionproof",
		"execution proof",
	}
	for _, n := range needles {
		if strings.Contains(re, n) {
			return true
		}
	}
	return false
}

func isFutureFork(fork string) bool {
	switch fork {
	case "gloas", "heze":
		return true
	default:
		return false
	}
}

type cryptoBuilderSpec struct {
	builder  string
	protocol string
}

var cryptoBaselineBuilders = map[string]cryptoBuilderSpec{
	"beacon_block":                          {builder: "buildValidBeaconBlock", protocol: "beacon_block"},
	"beacon_attestation":                    {builder: "buildValidBeaconAttestation", protocol: "beacon_attestation_0"},
	"beacon_aggregate_and_proof":            {builder: "buildValidBeaconAggregateAndProof", protocol: "beacon_aggregate_and_proof"},
	"sync_committee_message":                {builder: "buildValidSyncCommitteeMessage", protocol: "sync_committee_0"},
	"sync_committee_contribution_and_proof": {builder: "buildValidSyncCommitteeContributionAndProof", protocol: "sync_committee_contribution_and_proof"},
	"voluntary_exit":                        {builder: "buildValidVoluntaryExit", protocol: "voluntary_exit"},
	"proposer_slashing":                     {builder: "buildValidProposerSlashing", protocol: "proposer_slashing"},
	"attester_slashing":                     {builder: "buildValidAttesterSlashing", protocol: "attester_slashing"},
	"blob_sidecar":                          {builder: "buildValidBlobSidecar", protocol: "blob_sidecar_0"},
	"data_column_sidecar":                   {builder: "buildValidDataColumnSidecar", protocol: "data_column_sidecar_0"},
	"bls_to_execution_change":               {builder: "buildValidBlsToExecutionChange", protocol: "bls_to_execution_change"},
}

var cryptoInvalidBuilders = map[skelKey]cryptoBuilderSpec{
	{topic: "beacon_block", class: "parent_known_valid"}: {builder: "buildInvalidBeaconBlockParentKnownValid", protocol: "beacon_block"},
	{topic: "beacon_block", class: "sig_invalid"}:        {builder: "buildInvalidBeaconBlockSigInvalid", protocol: "beacon_block"},
	{topic: "beacon_block", class: "slot_future"}:        {builder: "buildInvalidBeaconBlockSlotFuture", protocol: "beacon_block"},
	{topic: "beacon_block", class: "timestamp_correct"}:  {builder: "buildInvalidBeaconBlockTimestampCorrect", protocol: "beacon_block"},
	{topic: "beacon_block", class: "kzg_proof"}:          {builder: "buildInvalidBeaconBlockKzgProof", protocol: "beacon_block"},

	{topic: "beacon_attestation", class: "slot_future"}:            {builder: "buildInvalidBeaconAttestationSlotFuture", protocol: "beacon_attestation_0"},
	{topic: "beacon_attestation", class: "slot_epoch_range"}:       {builder: "buildInvalidBeaconAttestationSlotEpochRange", protocol: "beacon_attestation_0"},
	{topic: "beacon_attestation", class: "index_oob"}:              {builder: "buildInvalidBeaconAttestationIndexOob", protocol: "beacon_attestation_0"},
	{topic: "beacon_attestation", class: "sig_invalid"}:            {builder: "buildInvalidBeaconAttestationSigInvalid", protocol: "beacon_attestation_0"},
	{topic: "beacon_attestation", class: "target_root_consistent"}: {builder: "buildInvalidBeaconAttestationTargetRootConsistent", protocol: "beacon_attestation_0"},
	{topic: "beacon_attestation", class: "finalized_ancestor"}:     {builder: "buildInvalidBeaconAttestationFinalizedAncestor", protocol: "beacon_attestation_0"},

	{topic: "beacon_aggregate_and_proof", class: "slot_future"}:       {builder: "buildInvalidBeaconAggregateAndProofSlotFuture", protocol: "beacon_aggregate_and_proof"},
	{topic: "beacon_aggregate_and_proof", class: "slot_epoch_range"}:  {builder: "buildInvalidBeaconAggregateAndProofSlotEpochRange", protocol: "beacon_aggregate_and_proof"},
	{topic: "beacon_aggregate_and_proof", class: "length_limit"}:      {builder: "buildInvalidBeaconAggregateAndProofNoParticipants", protocol: "beacon_aggregate_and_proof"},
	{topic: "beacon_aggregate_and_proof", class: "unaggregated_bits"}: {builder: "buildInvalidBeaconAggregateAndProofMultipleCommitteeBits", protocol: "beacon_aggregate_and_proof"},

	{topic: "sync_committee_message", class: "sig_invalid"}:      {builder: "buildInvalidSyncCommitteeMessageSigInvalid", protocol: "sync_committee_0"},
	{topic: "sync_committee_message", class: "slot_epoch_range"}: {builder: "buildInvalidSyncCommitteeMessageSlotEpochRange", protocol: "sync_committee_0"},

	{topic: "sync_committee_contribution_and_proof", class: "sig_invalid"}:      {builder: "buildInvalidSyncCommitteeContributionAndProofSigInvalid", protocol: "sync_committee_contribution_and_proof"},
	{topic: "sync_committee_contribution_and_proof", class: "index_oob"}:        {builder: "buildInvalidSyncCommitteeContributionAndProofIndexOob", protocol: "sync_committee_contribution_and_proof"},
	{topic: "sync_committee_contribution_and_proof", class: "slot_epoch_range"}: {builder: "buildInvalidSyncCommitteeContributionAndProofSlotEpochRange", protocol: "sync_committee_contribution_and_proof"},
	{topic: "sync_committee_contribution_and_proof", class: "length_limit"}:     {builder: "buildInvalidSyncCommitteeContributionAndProofLengthLimit", protocol: "sync_committee_contribution_and_proof"},

	{topic: "voluntary_exit", class: "sig_invalid"}: {builder: "buildInvalidVoluntaryExitSigInvalid", protocol: "voluntary_exit"},
	{topic: "voluntary_exit", class: "slot_future"}: {builder: "buildInvalidVoluntaryExitSlotFuture", protocol: "voluntary_exit"},

	{topic: "proposer_slashing", class: "sig_invalid"}:          {builder: "buildInvalidProposerSlashingSigInvalid", protocol: "proposer_slashing"},
	{topic: "proposer_slashing", class: "field_equality"}:       {builder: "buildInvalidProposerSlashingFieldEquality", protocol: "proposer_slashing"},
	{topic: "proposer_slashing", class: "index_oob"}:            {builder: "buildInvalidProposerSlashingIndexOob", protocol: "proposer_slashing"},
	{topic: "proposer_slashing", class: "proposer_index_wrong"}: {builder: "buildInvalidProposerSlashingIndexOob", protocol: "proposer_slashing"},

	{topic: "attester_slashing", class: "sig_invalid"}:    {builder: "buildInvalidAttesterSlashingSigInvalid", protocol: "attester_slashing"},
	{topic: "attester_slashing", class: "field_equality"}: {builder: "buildInvalidAttesterSlashingFieldEquality", protocol: "attester_slashing"},
	{topic: "attester_slashing", class: "index_oob"}:      {builder: "buildInvalidAttesterSlashingIndexOob", protocol: "attester_slashing"},
	{topic: "attester_slashing", class: "length_limit"}:   {builder: "buildInvalidAttesterSlashingLengthLimit", protocol: "attester_slashing"},

	{topic: "blob_sidecar", class: "kzg_proof"}:          {builder: "buildInvalidBlobSidecarKzgProof", protocol: "blob_sidecar_0"},
	{topic: "blob_sidecar", class: "sig_invalid"}:        {builder: "buildInvalidBlobSidecarSigInvalid", protocol: "blob_sidecar_0"},
	{topic: "blob_sidecar", class: "slot_future"}:        {builder: "buildInvalidBlobSidecarSlotFuture", protocol: "blob_sidecar_0"},
	{topic: "blob_sidecar", class: "field_equality"}:     {builder: "buildInvalidBlobSidecarIndexOob", protocol: "blob_sidecar_0"},
	{topic: "data_column_sidecar", class: "kzg_proof"}:   {builder: "buildInvalidDataColumnSidecarKzgProof", protocol: "data_column_sidecar_0"},
	{topic: "data_column_sidecar", class: "sig_invalid"}: {builder: "buildInvalidDataColumnSidecarSigInvalid", protocol: "data_column_sidecar_0"},
	{topic: "data_column_sidecar", class: "slot_future"}: {builder: "buildInvalidDataColumnSidecarSlotFuture", protocol: "data_column_sidecar_0"},

	{topic: "bls_to_execution_change", class: "sig_invalid"}:    {builder: "buildInvalidBlsToExecutionChangeSigInvalid", protocol: "bls_to_execution_change"},
	{topic: "bls_to_execution_change", class: "field_equality"}: {builder: "buildInvalidBlsToExecutionChangeFieldEquality", protocol: "bls_to_execution_change"},
}

var cryptoRuleBuilders = map[string]cryptoBuilderSpec{
	"BEACON_BLOCK-REJECT-4df28963": {builder: "buildInvalidBeaconBlockProposerIndexWrong", protocol: "beacon_block"},

	"BEACON_ATTESTATION-REJECT-02f714ed": {builder: "buildValidBeaconAttestation", protocol: "beacon_attestation_1"},

	"BEACON_AGGREGATE_AND_PROOF-MUST-20b37b69":   {builder: "buildInvalidBeaconAggregateAndProofDataIndexNonZero", protocol: "beacon_aggregate_and_proof"},
	"BEACON_AGGREGATE_AND_PROOF-REJECT-ab7fb155": {builder: "buildInvalidBeaconAggregateAndProofDataIndexNonZero", protocol: "beacon_aggregate_and_proof"},
	"BEACON_AGGREGATE_AND_PROOF-REJECT-14282100": {builder: "buildInvalidBeaconAggregateAndProofAggregateSigInvalid", protocol: "beacon_aggregate_and_proof"},
	"BEACON_AGGREGATE_AND_PROOF-REJECT-2fa7d152": {builder: "buildInvalidBeaconAggregateAndProofSelectionProofSigInvalid", protocol: "beacon_aggregate_and_proof"},
	"BEACON_AGGREGATE_AND_PROOF-REJECT-863359b5": {builder: "buildInvalidBeaconAggregateAndProofSelectionProofSigInvalid", protocol: "beacon_aggregate_and_proof"},
	"BEACON_AGGREGATE_AND_PROOF-REJECT-b10dbef1": {builder: "buildInvalidBeaconAggregateAndProofOuterSigInvalid", protocol: "beacon_aggregate_and_proof"},

	"SYNC_COMMITTEE_MESSAGE-REJECT-3aa5be35": {builder: "buildInvalidSyncCommitteeMessageIndexOob", protocol: "sync_committee_0"},

	"VOLUNTARY_EXIT-REJECT-3aa5be35": {builder: "buildInvalidVoluntaryExitIndexOob", protocol: "voluntary_exit"},

	"PROPOSER_SLASHING-REJECT-bb7fb86d": {builder: "buildInvalidProposerSlashingFieldEquality", protocol: "proposer_slashing"},

	"BLOB_SIDECAR-REJECT-4df28963": {builder: "buildInvalidBlobSidecarProposerIndexWrong", protocol: "blob_sidecar_0"},
	"BLOB_SIDECAR-REJECT-c094c7ea": {builder: "buildValidBlobSidecar", protocol: "blob_sidecar_1"},

	"DATA_COLUMN_SIDECAR-REJECT-4df28963": {builder: "buildInvalidDataColumnSidecarProposerIndexWrong", protocol: "data_column_sidecar_0"},
	"DATA_COLUMN_SIDECAR-REJECT-c094c7ea": {builder: "buildValidDataColumnSidecar", protocol: "data_column_sidecar_1"},

	"ATTESTER_SLASHING-REJECT-6cea922f": {builder: "buildInvalidAttesterSlashingFieldEquality", protocol: "attester_slashing"},

	"BLS_TO_EXECUTION_CHANGE-REJECT-3aa5be35": {builder: "buildInvalidBlsToExecutionChangeIndexOob", protocol: "bls_to_execution_change"},
}

// cryptoDifferentialBuilders maps receiver-state-dependent signed-gossip rules
// (finalized ancestor, parent-known, target/checkpoint consistency, committee
// membership, validator status, fork-epoch gating) to a plausible payload builder.
// These guards fire only under receiver chain/duty state we cannot force on an
// arbitrary devnet, so they are emitted as differential-only probes: inject the
// message, compare client verdicts, and flag cross-client inconsistency rather
// than asserting an absolute REJECT/IGNORE. This makes them executable
// (Go-emittable) as conditional probes instead of pending_inspector gaps.
var cryptoDifferentialBuilders = map[string]cryptoBuilderSpec{
	"BEACON_AGGREGATE_AND_PROOF-IGNORE-19a3a197": {builder: "buildValidBeaconAggregateAndProof", protocol: "beacon_aggregate_and_proof"},
	"BEACON_AGGREGATE_AND_PROOF-IGNORE-dc38af01": {builder: "buildValidBeaconAggregateAndProof", protocol: "beacon_aggregate_and_proof"},
	"BEACON_AGGREGATE_AND_PROOF-REJECT-544ecc21": {builder: "buildValidBeaconAggregateAndProof", protocol: "beacon_aggregate_and_proof"},
	"BEACON_AGGREGATE_AND_PROOF-REJECT-5658ca54": {builder: "buildValidBeaconAggregateAndProof", protocol: "beacon_aggregate_and_proof"},
	"BEACON_AGGREGATE_AND_PROOF-REJECT-9d4a9467": {builder: "buildValidBeaconAggregateAndProof", protocol: "beacon_aggregate_and_proof"},
	"BEACON_AGGREGATE_AND_PROOF-REJECT-f41bc7a4": {builder: "buildInvalidBeaconAggregateAndProofMultipleCommitteeBits", protocol: "beacon_aggregate_and_proof"},
	"BEACON_AGGREGATE_AND_PROOF-REJECT-fc3dd3a9": {builder: "buildValidBeaconAggregateAndProof", protocol: "beacon_aggregate_and_proof"},

	"BEACON_ATTESTATION-REJECT-20aed41d": {builder: "buildValidBeaconAttestation", protocol: "beacon_attestation_0"},
	"BEACON_ATTESTATION-REJECT-551474a5": {builder: "buildValidBeaconAttestation", protocol: "beacon_attestation_0"},
	"BEACON_ATTESTATION-REJECT-f41bc7a4": {builder: "buildValidBeaconAttestation", protocol: "beacon_attestation_0"},

	"BEACON_BLOCK-IGNORE-e183d5a9": {builder: "buildValidBeaconBlock", protocol: "beacon_block"},
	"BEACON_BLOCK-REJECT-a3e807db": {builder: "buildInvalidBeaconBlockProposerIndexWrong", protocol: "beacon_block"},
	"BEACON_BLOCK-REJECT-dbd5e1e1": {builder: "buildValidBeaconBlock", protocol: "beacon_block"},

	"BLOB_SIDECAR-IGNORE-6478f02b": {builder: "buildValidBlobSidecar", protocol: "blob_sidecar_0"},
	"BLOB_SIDECAR-IGNORE-80194614": {builder: "buildValidBlobSidecar", protocol: "blob_sidecar_0"},
	"BLOB_SIDECAR-REJECT-28436443": {builder: "buildInvalidBlobSidecarProposerIndexWrong", protocol: "blob_sidecar_0"},
	"BLOB_SIDECAR-REJECT-5f6c65a0": {builder: "buildValidBlobSidecar", protocol: "blob_sidecar_0"},
	"BLOB_SIDECAR-REJECT-f5bf199b": {builder: "buildValidBlobSidecar", protocol: "blob_sidecar_0"},
	"BLOB_SIDECAR-REJECT-fb4868ac": {builder: "buildValidBlobSidecar", protocol: "blob_sidecar_0"},

	"BLS_TO_EXECUTION_CHANGE-IGNORE-c2adbb4f": {builder: "buildValidBlsToExecutionChange", protocol: "bls_to_execution_change"},

	"DATA_COLUMN_SIDECAR-IGNORE-6478f02b": {builder: "buildValidDataColumnSidecar", protocol: "data_column_sidecar_0"},
	"DATA_COLUMN_SIDECAR-IGNORE-80194614": {builder: "buildValidDataColumnSidecar", protocol: "data_column_sidecar_0"},
	"DATA_COLUMN_SIDECAR-REJECT-28436443": {builder: "buildInvalidDataColumnSidecarProposerIndexWrong", protocol: "data_column_sidecar_0"},
	"DATA_COLUMN_SIDECAR-REJECT-5f6c65a0": {builder: "buildValidDataColumnSidecar", protocol: "data_column_sidecar_0"},
	"DATA_COLUMN_SIDECAR-REJECT-f5bf199b": {builder: "buildValidDataColumnSidecar", protocol: "data_column_sidecar_0"},
	"DATA_COLUMN_SIDECAR-REJECT-fb4868ac": {builder: "buildValidDataColumnSidecar", protocol: "data_column_sidecar_0"},

	"SYNC_COMMITTEE_MESSAGE-REJECT-c428cd4e": {builder: "buildValidSyncCommitteeMessage", protocol: "sync_committee_0"},

	"VOLUNTARY_EXIT-REJECT-15cadc01": {builder: "buildValidVoluntaryExit", protocol: "voluntary_exit"},
	"VOLUNTARY_EXIT-REJECT-e7806012": {builder: "buildValidVoluntaryExit", protocol: "voluntary_exit"},
	"VOLUNTARY_EXIT-REJECT-f5f33715": {builder: "buildValidVoluntaryExit", protocol: "voluntary_exit"},
}

func cryptoDifferentialSpecForRule(res resolved) (cryptoBuilderSpec, bool) {
	spec, ok := cryptoDifferentialBuilders[res.rule.ID]
	return spec, ok
}

func cryptoSpecForRule(res resolved) (cryptoBuilderSpec, bool) {
	if spec, ok := cryptoRuleBuilders[res.rule.ID]; ok {
		return spec, true
	}
	spec, ok := cryptoInvalidBuilders[skelKey{topic: normalizeTopic(res.topic), class: res.class}]
	return spec, ok
}

func isCryptoMsgCandidate(res resolved) bool {
	if res.domain != domGossip || res.class == "" || !isGossipTopic(res.topic) {
		return false
	}
	if _, ok := cryptoBaselineBuilders[normalizeTopic(res.topic)]; ok {
		return true
	}
	_, ok := cryptoSpecForRule(res)
	return ok
}

func normalizeTopic(topic string) string {
	if i := strings.IndexByte(topic, '{'); i >= 0 {
		return strings.TrimRight(topic[:i], "_")
	}
	return topic
}

func emitCryptoBaselines(resolveds []resolved, tmpl shapeTemplate) []irTransition {
	seen := map[string]bool{}
	var topics []string
	for _, res := range resolveds {
		topic := normalizeTopic(res.topic)
		if _, ok := cryptoBaselineBuilders[topic]; ok && !seen[topic] {
			seen[topic] = true
			topics = append(topics, topic)
		}
	}
	sort.Strings(topics)
	var out []irTransition
	for _, topic := range topics {
		spec := cryptoBaselineBuilders[topic]
		out = append(out, irTransition{
			From:        tmpl.ruleFrom,
			To:          tmpl.ruleTo,
			Label:       "cm_valid_" + sanitizeLabel(topic),
			Weight:      2,
			Description: "valid signed " + topic + " baseline",
			Action:      &irAction{Type: "ActInjectGossip", Protocol: spec.protocol, Payload: &irPayload{Kind: "builder", Name: spec.builder, Wrap: "raw"}},
			Oracle:      &irOracle{Differential: true},
		})
	}
	return out
}

func emitCryptoRule(res resolved, tmpl shapeTemplate, edgeIdx map[string][]astEdge) (irTransition, gap, bool) {
	r := res.rule
	mkGap := func(class, reason string) gap {
		return gap{RuleID: r.ID, Domain: domCrypto, Class: class, Reason: reason, RawText: r.RawText}
	}
	if isFutureRule(r) {
		return irTransition{}, mkGap(execPendingFuture, "future-fork signed gossip builder not enabled for this rule"), false
	}
	topic := normalizeTopic(res.topic)
	spec, ok := cryptoSpecForRule(res)
	if !ok {
		if dspec, dok := cryptoDifferentialSpecForRule(res); dok {
			t := irTransition{
				From:        tmpl.ruleFrom,
				To:          tmpl.ruleTo,
				Label:       "cm_diff_" + sanitizeLabel(topic+"_"+res.class) + "_" + hash8(r.ID),
				Weight:      weightForModal(r.Modal),
				Description: r.RawText + descPredicate(r),
				SpecRefs:    []string{r.ID},
				Action:      &irAction{Type: "ActInjectGossip", Protocol: dspec.protocol, Payload: &irPayload{Kind: "builder", Name: dspec.builder, Wrap: "raw"}},
				Guard:       guardFromProvenance(r),
				Oracle:      &irOracle{Differential: true},
			}
			if cd, tags := edgeAnnotations(edgeIdx[r.ID]); cd != "" {
				t.ConditionDesc = cd
				t.Tags = append(t.Tags, tags...)
			}
			return t, gap{}, true
		}
		if cryptoRuleRequiresInspector(res) || cryptoNeedsInspector(res) {
			return irTransition{}, mkGap(statusPendingInspector, "signed-message rule depends on live chain state or receiver history"), false
		}
		if isSequenceClass(res.class) {
			return irTransition{}, mkGap(statusPendingSequenceTemplate, "behavioral rule requires valid-baseline then duplicate/conflict sequence template"), false
		}
		if cryptoNeedsSequenceTemplate(res) {
			return irTransition{}, mkGap(statusPendingSequenceTemplate, "signed-message rule requires a multi-step gossip sequence or topic-selection template"), false
		}
		return irTransition{}, mkGap(statusPendingBuilder, fmt.Sprintf("no signed-message builder registered for topic=%s class=%s", topic, res.class)), false
	}
	t := irTransition{
		From:        tmpl.ruleFrom,
		To:          tmpl.ruleTo,
		Label:       "cm_invalid_" + sanitizeLabel(topic+"_"+res.class) + "_" + hash8(r.ID),
		Weight:      weightForModal(r.Modal),
		Description: r.RawText + descPredicate(r),
		SpecRefs:    []string{r.ID},
		Action:      &irAction{Type: "ActInjectGossip", Protocol: spec.protocol, Payload: &irPayload{Kind: "builder", Name: spec.builder, Wrap: "raw"}},
		Guard:       guardFromProvenance(r),
		Oracle:      synthOracle(r.Modal, "REJECT"),
	}
	if cd, tags := edgeAnnotations(edgeIdx[r.ID]); cd != "" {
		t.ConditionDesc = cd
		t.Tags = append(t.Tags, tags...)
	}
	return t, gap{}, true
}

func cryptoNeedsSequenceTemplate(res resolved) bool {
	raw := strings.ToLower(res.rule.RawText)
	needles := []string{
		"first valid", "already been seen", "has not already been seen",
		"previously forwarded", "previously validated", "no other valid",
		"correct subnet", "expected subnet", "subnet_id is valid",
	}
	for _, n := range needles {
		if strings.Contains(raw, n) {
			return true
		}
	}
	return false
}

func cryptoNeedsInspector(res resolved) bool {
	raw := strings.ToLower(res.rule.RawText)
	needles := []string{
		"expected proposer", "current finalized", "finalized checkpoint",
		"latest finalized",
		"ancestor", "parent has been seen", "parent passes validation",
		"higher slot than",
		"block being voted for", "passes validation", "committee", "member of",
		"validator is active", "initiated exit", "active long enough",
		"withdrawal", "current epoch is at or after", "local copy", "unaggregated",
	}
	for _, n := range needles {
		if strings.Contains(raw, n) {
			return true
		}
	}
	return false
}

// randomGossipBuilders / randomGossipMutators are existing (crypto-free) payload
// generators used for the fuzz half. They are rotated so a topic's fuzz variants
// differ.
var (
	randomGossipBuilders = []string{"buildRandomGossip100", "buildRandomGossip200", "buildRandomGossip300"}
	randomGossipMutators = []string{"gossip_random_bytes", "gossip_append_garbage", "gossip_truncate"}
)

// emitRandomInjections produces per-topic random/garbage fuzz transitions. For a
// topic with N classified rules it emits round(ratio*N) injections (min 1 when
// ratio>0), each an ActInjectGossip of a random payload with a random mutator,
// judged differentially with a crash guard (not tied to a spec rule). Deterministic:
// topics sorted, variants rotated by index.
func emitRandomInjections(gossip []resolved, tmpl shapeTemplate, ratio float64) []irTransition {
	counts := map[string]int{}
	var topics []string
	for _, res := range gossip {
		if !isGossipTopic(res.topic) { // skip spec-extraction noise (constants/types/eth2)
			continue
		}
		if _, ok := counts[res.topic]; !ok {
			topics = append(topics, res.topic)
		}
		counts[res.topic]++
	}
	sort.Strings(topics)

	var out []irTransition
	for _, topic := range topics {
		n := max(int(float64(counts[topic])*ratio+0.5), 1)
		for i := 0; i < n; i++ {
			builder := randomGossipBuilders[i%len(randomGossipBuilders)]
			mutator := randomGossipMutators[i%len(randomGossipMutators)]
			out = append(out, irTransition{
				From:        tmpl.ruleFrom,
				To:          tmpl.ruleTo,
				Label:       fmt.Sprintf("gossip_rand_%s_%d", sanitizeLabel(topic), i),
				Weight:      1,
				Description: "random/garbage gossip injection (fuzz; not rule-specific)",
				Tags:        []string{"random", "fuzz"},
				Action:      &irAction{Type: "ActInjectGossip", Protocol: topic, Payload: &irPayload{Kind: "builder", Name: builder, Wrap: "raw"}, Mutator: mutator},
				Oracle:      synthOracle("", ""), // differential + crash guard
			})
		}
	}
	return out
}

// emitRule converts one resolved rule into a transition, or a gap.
func emitRule(res resolved, tmpl shapeTemplate, entries []dictEntry, knownProto map[string]bool, edgeIdx map[string][]astEdge) (irTransition, gap, bool) {
	r := res.rule
	mkGap := func(class, reason string) gap {
		return gap{RuleID: r.ID, Domain: res.domain, Class: class, Reason: reason, RawText: r.RawText}
	}

	entry := matchEntry(entries, res)
	var act *irAction
	expected := ""
	label := domainPrefix[res.domain] + "_" + labelSurface(res) + "_" + hash8(r.ID)
	from, to := tmpl.ruleFrom, tmpl.ruleTo
	if entry == nil {
		if inferExecutionKind(res, nil, nil, edgeIdx) == execStateful {
			if fb, ok := statefulFallbackSpec(res, knownProto); ok {
				act = fb.action
				expected = fb.expected
				label = domainPrefix[res.domain] + "_stateful_" + labelSurface(res) + "_" + hash8(r.ID)
			}
		}
		if act == nil {
			return irTransition{}, mkGap(gapClassForUnmatched(res), gapReasonForUnmatched(res)), false
		}
	} else {
		act = entry.buildAction(res)
		if act == nil {
			return irTransition{}, mkGap(statusUnsupported, "matched entry but no executable action (missing topic/protocol/payload)"), false
		}
		expected = entry.Emit.Expected
		if entry.Emit.Label != "" {
			label = entry.Emit.Label
		}
		if entry.Emit.From != "" {
			from = entry.Emit.From
		}
		if entry.Emit.To != "" {
			to = entry.Emit.To
		}
	}
	// ReqResp/Conn send actions must target a protocol smgen supports.
	if reqRespProtocolAction(act.Type) && act.Protocol != "" && !knownProto[act.Protocol] {
		return irTransition{}, mkGap(statusUnsupported, fmt.Sprintf("protocol %s not in protocol_model (ahead of runtime support)", act.Protocol)), false
	}

	t := irTransition{
		From:        from,
		To:          to,
		Label:       label,
		Weight:      weightForModal(r.Modal),
		Description: r.RawText + descPredicate(r),
		SpecRefs:    []string{r.ID},
		Action:      act,
		Guard:       guardFromProvenance(r),
		Oracle:      synthOracle(r.Modal, expected),
	}
	// Surface temporal/conditional edge semantics as descriptive metadata. This is
	// context for a human promoting the machine, NOT a live guard — Guard above is
	// left as the fork-only provenance guard.
	if cd, tags := edgeAnnotations(edgeIdx[r.ID]); cd != "" {
		t.ConditionDesc = cd
		t.Tags = append(t.Tags, tags...)
	}
	return t, gap{}, true
}

func reqRespProtocolAction(action string) bool {
	switch action {
	case "ActSendReqResp", "ActSendStatus", "ActValidateResponseOrder", "ActOpenStream":
		return true
	default:
		return false
	}
}

// edgeAnnotations renders a rule's temporal/conditional edges into a human-readable
// condition_desc plus greppable tags. Deterministic: temporal phrases (sorted) precede
// conditional ones, and duplicates are collapsed.
func edgeAnnotations(edges []astEdge) (condDesc string, tags []string) {
	var temporal, conditional []string
	seenTag := map[string]bool{}
	addTag := func(tg string) {
		if !seenTag[tg] {
			seenTag[tg] = true
			tags = append(tags, tg)
		}
	}
	for _, e := range edges {
		switch e.Kind {
		case "temporal":
			if e.ToRef != "" {
				rel := e.Rel
				if rel == "" {
					rel = "after"
				}
				temporal = append(temporal, rel+" «"+e.ToRef+"»")
				addTag("temporal:" + rel)
			}
		case "conditional":
			if e.Guard != "" {
				conditional = append(conditional, "when "+e.Guard)
				addTag("conditional")
			}
		}
	}
	sort.Strings(temporal)
	sort.Strings(conditional)
	phrases := dedupeStrings(append(temporal, conditional...))
	return strings.Join(phrases, "; "), tags
}

// dedupeStrings removes duplicate entries while preserving order.
func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func labelSurface(res resolved) string {
	switch {
	case res.topic != "":
		return sanitizeLabel(res.topic)
	case res.methodName != "":
		return sanitizeLabel(res.methodName)
	}
	return res.domain
}

// descPredicate appends the full AST failure predicate to the description so the
// richer semantics (which the runtime oracle cannot evaluate) are not lost.
func descPredicate(r *astRule) string {
	if r.SourceExpr == "" {
		return ""
	}
	pol := r.ExprPolarity
	if pol == "" {
		pol = "expr"
	}
	return fmt.Sprintf(" [%s: %s]", pol, r.SourceExpr)
}
