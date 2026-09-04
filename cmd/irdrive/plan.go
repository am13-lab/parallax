package main

import "strings"

const (
	execStateful      = "stateful"
	execStateless     = "stateless"
	execAuditOnly     = "audit_only"
	execPendingFuture = "pending_future"

	statusSupported               = "supported"
	statusPendingBuilder          = "pending_builder"
	statusPendingLiveBuilder      = "pending_live_builder"
	statusPendingInspector        = "pending_inspector"
	statusPendingSequenceTemplate = "pending_sequence_template"
	statusUnsupported             = "unsupported"

	emitSMIR              = "sm_ir"
	emitStatelessFollowup = "stateless_followup"
	emitSequenceFollowup  = "sequence_followup"
	emitNone              = "none"

	sourceDictionary = "dictionary"
	sourceHeuristic  = "heuristic"
	sourceHardRule   = "hard_rule"
)

// executionPlan is the classify-first layer between AST rules and any emitted
// artifact. This is intentionally internal to irderive: the durable external
// artifact is the derivation report, not a new workflow file.
type executionPlan struct {
	RuleID               string   `json:"rule_id"`
	Domain               string   `json:"domain"`
	Surface              string   `json:"surface,omitempty"`
	Class                string   `json:"class,omitempty"`
	Fork                 string   `json:"fork,omitempty"`
	ExecutionKind        string   `json:"execution_kind"`
	SupportStatus        string   `json:"support_status"`
	EmitTarget           string   `json:"emit_target"`
	Builder              string   `json:"builder,omitempty"`
	Mutator              string   `json:"mutator,omitempty"`
	Action               string   `json:"action,omitempty"`
	Protocol             string   `json:"protocol,omitempty"`
	Topic                string   `json:"topic,omitempty"`
	Oracle               string   `json:"oracle,omitempty"`
	AuditBucket          string   `json:"audit_bucket,omitempty"`
	Preconditions        []string `json:"preconditions,omitempty"`
	ClassificationSource string   `json:"classification_source"`
	SemanticMachine      string   `json:"semantic_machine,omitempty"`
	SemanticBinding      string   `json:"semantic_binding,omitempty"`
	SemanticStatus       string   `json:"semantic_status,omitempty"`
	Reason               string   `json:"reason,omitempty"`
	RawText              string   `json:"raw_text,omitempty"`
}

func basePlan(res resolved, domain string) executionPlan {
	r := res.rule
	p := executionPlan{
		RuleID:               r.ID,
		Domain:               domain,
		Surface:              planSurface(res),
		Class:                res.class,
		Fork:                 r.ForkIntroduced,
		EmitTarget:           emitNone,
		ClassificationSource: sourceHeuristic,
		RawText:              r.RawText,
	}
	if res.topic != "" {
		p.Topic = res.topic
	}
	if res.protocolID != "" {
		p.Protocol = res.protocolID
	}
	return p
}

func planSurface(res resolved) string {
	switch {
	case res.protocolID != "":
		return res.protocolID
	case res.topic != "":
		return res.topic
	case res.methodName != "":
		return res.methodName
	default:
		return res.domain
	}
}

func classifyResolvedPlan(res resolved, entries []dictEntry, knownProto map[string]bool, edgeIdx map[string][]astEdge) executionPlan {
	p := basePlan(res, res.domain)
	r := res.rule

	if isFutureRule(r) {
		p.ExecutionKind = execPendingFuture
		p.SupportStatus = statusUnsupported
		p.Reason = "future-fork or feature rule is not enabled for the current generated runtime"
		p.ClassificationSource = sourceHardRule
		return p
	}
	if isAuditOnlyRule(res) {
		p.ExecutionKind = execAuditOnly
		p.SupportStatus = statusUnsupported
		p.AuditBucket = auditBucketFor(res)
		p.Reason = "rule describes capability, deployment, or policy behavior rather than a concrete message-level test"
		p.ClassificationSource = sourceHardRule
		return p
	}

	entry := matchEntry(entries, res)
	act := (*irAction)(nil)
	if entry != nil {
		act = entry.buildAction(res)
		applyEntryPlanFields(&p, entry, act)
	}

	p.ExecutionKind = inferExecutionKind(res, entry, act, edgeIdx)
	if entry != nil && entry.Classification.ExecutionKind != "" {
		p.ClassificationSource = sourceDictionary
	} else {
		p.ClassificationSource = sourceHeuristic
	}
	if p.ExecutionKind == execAuditOnly {
		p.SupportStatus = statusUnsupported
		p.EmitTarget = emitNone
		if p.Reason == "" {
			p.Reason = "dictionary classified this rule as audit-only"
		}
		return p
	}
	if p.ExecutionKind == execPendingFuture {
		p.SupportStatus = statusUnsupported
		p.EmitTarget = emitNone
		if p.Reason == "" {
			p.Reason = "dictionary classified this rule as future-pending"
		}
		return p
	}
	if entry == nil && p.ExecutionKind == execStateful {
		if fb, ok := statefulFallbackSpec(res, knownProto); ok {
			applyFallbackPlanFields(&p, fb)
			p.SupportStatus = statusSupported
			p.EmitTarget = emitSMIR
			return p
		}
	}

	if entry == nil {
		p.SupportStatus = supportStatusForUnmatched(res)
		p.Reason = gapReasonForUnmatched(res)
		return p
	}
	if act == nil {
		p.SupportStatus = statusUnsupported
		p.Reason = "matched dictionary entry but no executable action could be built"
		return p
	}
	if reqRespProtocolAction(act.Type) && act.Protocol != "" && !knownProto[act.Protocol] {
		p.SupportStatus = statusUnsupported
		p.Reason = "protocol " + act.Protocol + " not in protocol_model"
		return p
	}

	p.SupportStatus = statusSupported
	switch p.ExecutionKind {
	case execStateful:
		p.EmitTarget = emitSMIR
	case execStateless:
		p.EmitTarget = emitStatelessFollowup
	default:
		p.EmitTarget = emitNone
	}
	return p
}

func classifyCryptoPlan(res resolved) executionPlan {
	p := basePlan(res, domCrypto)
	r := res.rule
	p.Topic = normalizeTopic(res.topic)
	p.Surface = p.Topic

	if isFutureRule(r) {
		p.ExecutionKind = execPendingFuture
		p.SupportStatus = statusUnsupported
		p.Reason = "future-fork signed gossip builder not enabled for this rule"
		p.ClassificationSource = sourceHardRule
		return p
	}

	if spec, ok := cryptoSpecForRule(res); ok {
		p.ExecutionKind = execStateless
		p.ClassificationSource = sourceHeuristic
		p.SupportStatus = statusSupported
		p.EmitTarget = emitStatelessFollowup
		p.Builder = spec.builder
		p.Protocol = spec.protocol
		p.Action = "ActInjectGossip"
		p.Oracle = "REJECT"
		return p
	}

	if spec, ok := cryptoSequenceSpecForRule(res); ok {
		p.ExecutionKind = execStateful
		p.ClassificationSource = sourceHeuristic
		p.SupportStatus = statusSupported
		p.EmitTarget = emitSequenceFollowup
		p.Builder = spec.builder
		p.Protocol = spec.protocol
		p.Action = "ActInjectGossip"
		p.Oracle = "REJECT"
		p.Preconditions = []string{"setup_accepts"}
		return p
	}

	if spec, ok := cryptoDifferentialSpecForRule(res); ok {
		p.ExecutionKind = execStateless
		p.ClassificationSource = sourceHeuristic
		p.SupportStatus = statusSupported
		p.EmitTarget = emitStatelessFollowup
		p.Builder = spec.builder
		p.Protocol = spec.protocol
		p.Action = "ActInjectGossip"
		p.Oracle = "" // differential-only: receiver-state-dependent conditional probe
		return p
	}

	p.ExecutionKind = execStateless
	p.ClassificationSource = sourceHeuristic
	if cryptoRuleRequiresInspector(res) || cryptoNeedsInspector(res) {
		p.SupportStatus = statusPendingInspector
		p.Reason = "signed-message rule depends on live chain state or receiver history"
		return p
	}
	if isSequenceClass(res.class) {
		p.ExecutionKind = execStateful
		p.SupportStatus = statusPendingSequenceTemplate
		p.Reason = "behavioral rule requires valid-baseline then duplicate/conflict sequence template"
		return p
	}
	if cryptoNeedsSequenceTemplate(res) {
		p.ExecutionKind = execStateful
		p.SupportStatus = statusPendingSequenceTemplate
		p.Reason = "signed-message rule requires a multi-step gossip sequence or topic-selection template"
		return p
	}
	p.SupportStatus = statusPendingBuilder
	p.Reason = "no signed-message builder registered for topic=" + p.Topic + " class=" + res.class
	return p
}

func applyEntryPlanFields(p *executionPlan, entry *dictEntry, act *irAction) {
	p.Builder = entry.Emit.Builder
	p.Mutator = entry.Emit.Mutator
	p.Action = entry.Emit.Action
	p.Oracle = entry.Emit.Expected
	if entry.Classification.AuditBucket != "" {
		p.AuditBucket = entry.Classification.AuditBucket
	}
	if entry.Classification.Reason != "" {
		p.Reason = entry.Classification.Reason
	}
	if act != nil {
		p.Action = act.Type
		p.Protocol = act.Protocol
		if act.Payload != nil && act.Payload.Name != "" {
			p.Builder = act.Payload.Name
		}
		if act.Mutator != "" {
			p.Mutator = act.Mutator
		}
	}
}

func inferExecutionKind(res resolved, entry *dictEntry, act *irAction, edgeIdx map[string][]astEdge) string {
	if entry != nil && entry.Classification.ExecutionKind != "" {
		return entry.Classification.ExecutionKind
	}
	if isSequenceClass(res.class) || hasTemporalEdge(edgeIdx[res.rule.ID]) {
		return execStateful
	}
	if res.domain == domConn {
		return execStateful
	}
	if entry != nil && (entry.Emit.From != "" || entry.Emit.To != "" || entry.Emit.RepeatCount > 1) {
		return execStateful
	}
	if act != nil {
		switch act.Type {
		case "ActReconnect", "ActDisconnectPeer", "ActSleep", "ActOpenStream":
			return execStateful
		}
		if act.RepeatCount > 1 {
			return execStateful
		}
	}
	return execStateless
}

func hasTemporalEdge(edges []astEdge) bool {
	for _, e := range edges {
		if e.Kind == "temporal" {
			return true
		}
	}
	return false
}

func isFutureRule(r *astRule) bool {
	return isFutureFork(r.ForkIntroduced) || r.ForkIntroduced == "_features" || strings.Contains(r.RawText, "ExecutionProof")
}

func isAuditOnlyRule(res resolved) bool {
	if res.domain == domNone {
		return true
	}
	raw := strings.ToLower(res.rule.RawText + " " + res.rule.Source.Anchor)
	needles := []string{
		"may support", "must support", "quic", "tcp libp2p transport", "yamux",
		"multiselect", "multistream-select", "behind a nat", "configured to enable inbound",
		"listen only on ipv6", "public listening endpoint", "xx handshake pattern",
		"give priority", "node's custody group count", "reject peers with a value",
	}
	if res.protocolID != "" || res.topic != "" {
		return false
	}
	for _, n := range needles {
		if strings.Contains(raw, n) {
			return true
		}
	}
	return false
}

func auditBucketFor(res resolved) string {
	raw := strings.ToLower(res.rule.RawText + " " + res.rule.Source.Anchor)
	switch {
	case strings.Contains(raw, "quic") || strings.Contains(raw, "tcp") || strings.Contains(raw, "yamux") || strings.Contains(raw, "multiselect") || strings.Contains(raw, "multistream"):
		return "transport_capability"
	case strings.Contains(raw, "nat") || strings.Contains(raw, "listen") || strings.Contains(raw, "public listening endpoint") || strings.Contains(raw, "configured"):
		return "operator_configuration"
	case strings.Contains(raw, "enr") || strings.Contains(raw, "custody group"):
		return "peer_capability"
	default:
		return "unlinked_prose"
	}
}

func supportStatusForUnmatched(res resolved) string {
	if res.domain == domReqResp && reqrespNeedsInspector(res.rule.RawText) {
		return statusPendingInspector
	}
	if res.domain == domConn && connNeedsInspector(res.rule.RawText) {
		return statusPendingInspector
	}
	if res.domain == domGossip {
		return gossipUnmatchedStatus(res)
	}
	if res.protocolID == "" && res.topic == "" {
		return statusUnsupported
	}
	return statusPendingBuilder
}

func planGapClass(p executionPlan) string {
	if p.ExecutionKind == execAuditOnly {
		return execAuditOnly
	}
	if p.ExecutionKind == execPendingFuture {
		return execPendingFuture
	}
	if p.SupportStatus != statusSupported {
		return p.SupportStatus
	}
	return ""
}
