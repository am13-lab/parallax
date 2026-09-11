package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// dictionary.go — Layer D4. Maps a resolved rule to a concrete, executable emit
// spec (action + payload built from existing builders/mutators/fields). Matching
// is most-specific-first (by number of set criteria), then declaration order —
// deterministic. A rule that matches nothing gets NO transition and is reported
// as a typed coverage gap.
//
// Emit specs reference only what codegen executes: mutator names from
// mutators.go, builder names from builders.go (no params), and fields with
// lit/ctx only (never `special`).

type dictMatch struct {
	RuleID          string   `json:"rule_id,omitempty"`         // exact AST rule id pin (highest specificity)
	ViolationClass  string   `json:"violation_class,omitempty"` // matched against the classifier's assigned class
	Domain          string   `json:"domain,omitempty"`
	Method          string   `json:"method,omitempty"` // surface method name (case-insensitive)
	Topic           string   `json:"topic,omitempty"`
	AnchorRegex     string   `json:"anchor_regex,omitempty"`
	RawTextRegex    string   `json:"raw_text_regex,omitempty"`
	SourceExprRegex string   `json:"source_expr_regex,omitempty"`
	Constants       []string `json:"constants,omitempty"` // all must appear in constants_referenced
	Polarity        string   `json:"polarity,omitempty"`
}

type dictEmit struct {
	Action      string           `json:"action"`             // ActInjectGossip | ActSendReqResp
	Protocol    string           `json:"protocol,omitempty"` // override; else topic/protocolID from the rule
	Label       string           `json:"label,omitempty"`    // optional stable transition label override
	From        string           `json:"from,omitempty"`     // optional state override
	To          string           `json:"to,omitempty"`       // optional state override
	Builder     string           `json:"builder,omitempty"`
	Mutator     string           `json:"mutator,omitempty"`
	Fields      map[string]int64 `json:"fields,omitempty"` // lit fields
	Wrap        string           `json:"wrap,omitempty"`
	NoPayload   bool             `json:"no_payload,omitempty"` // request intentionally has no body
	Expected    string           `json:"expected,omitempty"`   // "", REJECT, INVALID_REQUEST, SUCCESS
	TimeoutMs   int              `json:"timeout_ms,omitempty"`
	RepeatCount int              `json:"repeat_count,omitempty"`
}

type dictClassification struct {
	ExecutionKind string `json:"execution_kind,omitempty"` // stateful | stateless | audit_only | pending_future
	AuditBucket   string `json:"audit_bucket,omitempty"`
	Reason        string `json:"reason,omitempty"`
}

type dictEntry struct {
	Match          dictMatch          `json:"match"`
	Emit           dictEmit           `json:"emit"`
	Classification dictClassification `json:"classification,omitempty"`
	Note           string             `json:"note,omitempty"`
}

// loadDictionary reads ir/ir_dictionary.json. A MISSING file falls back to
// the embedded default seed (so the tool/tests are hermetic), but a present-but-
// malformed file is a hard error — silently ignoring a corrupt requested
// dictionary would break the auditable-input guarantee.
func loadDictionary(path string) ([]dictEntry, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return defaultDictionary(), nil
	}
	if err != nil {
		return nil, err
	}
	var entries []dictEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("parse dictionary %s: %w", path, err)
	}
	return entries, nil
}

// specificity counts the set match criteria; higher wins. A RuleID pin dominates
// (exact single-rule match) so a hand-pinned entry always beats a class/topic rule.
func (m dictMatch) specificity() int {
	n := 0
	for _, s := range []string{m.ViolationClass, m.Domain, m.Method, m.Topic, m.AnchorRegex, m.RawTextRegex, m.SourceExprRegex, m.Polarity} {
		if s != "" {
			n++
		}
	}
	if m.RuleID != "" {
		n += 100
	}
	return n + len(m.Constants)
}

func (m dictMatch) matches(res resolved) bool {
	r := res.rule
	if m.RuleID != "" && m.RuleID != r.ID {
		return false
	}
	if m.ViolationClass != "" && m.ViolationClass != res.class {
		return false
	}
	if m.Domain != "" && m.Domain != res.domain {
		return false
	}
	if m.Method != "" && !strings.EqualFold(m.Method, res.methodName) {
		return false
	}
	if m.Topic != "" && m.Topic != res.topic {
		return false
	}
	if m.Polarity != "" && m.Polarity != r.ExprPolarity {
		return false
	}
	if m.AnchorRegex != "" && !regexp.MustCompile(m.AnchorRegex).MatchString(r.Source.Anchor) {
		return false
	}
	if m.RawTextRegex != "" && !regexp.MustCompile(m.RawTextRegex).MatchString(r.RawText) {
		return false
	}
	if m.SourceExprRegex != "" && !regexp.MustCompile(m.SourceExprRegex).MatchString(r.SourceExpr) {
		return false
	}
	for _, c := range m.Constants {
		if !containsStr(r.ConstantsReferenced, c) {
			return false
		}
	}
	return true
}

// matchEntry returns the highest-specificity matching entry, or nil.
func matchEntry(entries []dictEntry, res resolved) *dictEntry {
	best := -1
	var chosen *dictEntry
	for i := range entries {
		e := &entries[i]
		if !e.Match.matches(res) {
			continue
		}
		if s := e.Match.specificity(); s > best {
			best = s
			chosen = e
		}
	}
	return chosen
}

// payloadLessActions are runtime actions that carry no payload: pure queries and
// connection-lifecycle steps. For these the emit spec's Protocol is used verbatim
// (an ENR field name for ActVerifyENRBehavior, empty for ActQueryENR/PeerList) and
// no builder/fields are required.
var payloadLessActions = map[string]bool{
	"ActQueryENR": true, "ActVerifyENRBehavior": true, "ActQueryPeerList": true,
	"ActResolveSubnets": true, "ActCheckConnected": true, "ActConnectRaw": true,
	"ActReconnect": true, "ActDisconnectPeer": true, "ActSleep": true,
}

// buildAction turns a matched emit spec into an irAction, filling protocol/topic
// from the resolved rule. Returns nil when the action cannot be made executable
// (e.g. gossip with no topic, or a payload-bearing action with no payload) — the
// caller records a gap.
func (e dictEntry) buildAction(res resolved) *irAction {
	if payloadLessActions[e.Emit.Action] {
		act := &irAction{Type: e.Emit.Action, Protocol: e.Emit.Protocol}
		if e.Emit.TimeoutMs > 0 {
			act.TimeoutMs = e.Emit.TimeoutMs
		}
		if e.Emit.RepeatCount > 0 {
			act.RepeatCount = e.Emit.RepeatCount
		}
		return act
	}
	protocol := e.Emit.Protocol
	if protocol == "" {
		if res.domain == domGossip {
			protocol = res.topic
		} else {
			protocol = res.protocolID
		}
	}
	if protocol == "" {
		return nil // no target surface -> not executable
	}
	var payload *irPayload
	switch {
	case e.Emit.NoPayload:
		payload = nil
	case e.Emit.Builder != "":
		payload = &irPayload{Kind: "builder", Name: e.Emit.Builder, Wrap: e.Emit.Wrap}
	case len(e.Emit.Fields) > 0:
		fields := map[string]irFieldVal{}
		for k, v := range e.Emit.Fields {
			fields[k] = litVal(v)
		}
		payload = &irPayload{Kind: "fields", Wrap: e.Emit.Wrap, Fields: fields}
	default:
		return nil // no payload -> not executable
	}
	act := &irAction{Type: e.Emit.Action, Protocol: protocol, Payload: payload, Mutator: e.Emit.Mutator}
	if e.Emit.TimeoutMs > 0 {
		act.TimeoutMs = e.Emit.TimeoutMs
	}
	if e.Emit.RepeatCount > 0 {
		act.RepeatCount = e.Emit.RepeatCount
	}
	return act
}

func containsStr(hay []string, needle string) bool {
	for _, s := range hay {
		if s == needle {
			return true
		}
	}
	return false
}

// defaultDictionary is the embedded seed (also written to ir/ir_dictionary.json).
// Every entry references an existing builder/mutator so smgen gate 2 passes.
func defaultDictionary() []dictEntry {
	return []dictEntry{
		{
			// Spec-justified: "In case of an invalid input ... a reader MUST send
			// back InvalidRequest." A truncated (half-open) request is genuinely
			// malformed on any fork; expected REJECT is broad (matches
			// INVALID_REQUEST and STREAM_RESET) so a client that resets instead of
			// replying InvalidRequest is not falsely flagged — only ACCEPT is a bug.
			Note:  "ReqResp: malformed/invalid input MUST NOT be accepted (broad REJECT)",
			Match: dictMatch{Domain: domReqResp, RawTextRegex: `(?i)consider the following cases as invalid input`},
			Emit:  dictEmit{Action: "ActSendReqResp", Protocol: "/eth2/beacon_chain/req/beacon_blocks_by_range/2/ssz_snappy", Builder: "buildBlocksByRangeHalfOpen", Wrap: "raw", Expected: "REJECT", TimeoutMs: 5000},
		},
		{
			Note:  "Gossip: payload exceeds MAX_PAYLOAD_SIZE -> REJECT",
			Match: dictMatch{Domain: domGossip, RawTextRegex: `(?i)MAX_PAYLOAD_SIZE|payload size|uncompressed`},
			Emit:  dictEmit{Action: "ActInjectGossip", Builder: "buildRandomGossip100", Mutator: "gossip_one_over_max_payload", Wrap: "raw", Expected: "REJECT"},
		},
		{
			Note:  "Gossip: invalid full data-column cell/proof data",
			Match: dictMatch{RuleID: "DATA_COLUMN_SIDECAR_SUBNET_ID-MUST-aa0e3ac7"},
			Emit:  dictEmit{Action: "ActInjectGossip", Protocol: "data_column_sidecar_0", Builder: "buildInvalidDataColumnSidecarKzgProof", Wrap: "raw", Expected: "REJECT"},
		},
		{
			Note:  "ReqResp: BeaconBlocksByHead request support probe",
			Match: dictMatch{Domain: domReqResp, Method: "BeaconBlocksByHead", RawTextRegex: `(?i)support requesting blocks|request MUST be encoded as an SSZ-container`},
			Emit:  dictEmit{Action: "ActSendReqResp", Protocol: "/eth2/beacon_chain/req/beacon_blocks_by_head/1/ssz_snappy", Builder: "buildBlocksByHeadHeadRoot", Wrap: "ssz_snappy", TimeoutMs: 10000},
		},
		{
			Note:  "Conn: Status fork_digest mismatch (differential-only; disconnect not directly asserted)",
			Match: dictMatch{Domain: domConn, Method: "Status", RawTextRegex: `(?i)fork_digest`},
			Emit:  dictEmit{Action: "ActSendReqResp", Protocol: "/eth2/beacon_chain/req/status/2/ssz_snappy", Builder: "buildStatusV2ForkFlipped", Wrap: "ssz_snappy", TimeoutMs: 5000},
		},
	}
}
