package main

import (
	"strings"
)

// project.go — Layer 4 (part 1). Derives the spec-truth portion of a flat rule
// from an AST node. Testing/triage fields come from the overlay in join.go.

// flatRule mirrors internal/framework.SpecRule field-for-field (plus fork_removed,
// which the framework struct ignores but the current file carries).
type flatRule struct {
	ID                  string   `json:"id"`
	LegacyIDs           []string `json:"legacy_ids,omitempty"`
	Text                string   `json:"text"`
	Strength            string   `json:"strength"`
	Protocol            string   `json:"protocol"`
	RuleType            string   `json:"rule_type"`
	ObservableInTraffic bool     `json:"observable_in_traffic"`
	Formalized          string   `json:"formalized"`
	TestIDs             []string `json:"test_ids"`
	InvariantIDs        []string `json:"invariant_ids"`
	Testability         string   `json:"testability"`
	CoverageStatus      string   `json:"coverage_status"`
	ForkIntroduced      string   `json:"fork_introduced,omitempty"`
	ForkModified        string   `json:"fork_modified,omitempty"`
	ForkRemoved         string   `json:"fork_removed,omitempty"`
	CurrentStatus       string   `json:"current_status,omitempty"`
	StateMachine        string   `json:"state_machine"`
	Transitions         []string `json:"transitions"`
	KnownBugs           string   `json:"known_bugs,omitempty"`
	FalsePositiveReason string   `json:"false_positive_reason,omitempty"`
}

// specTruth returns the spec-derived fields of a flat rule from an AST node.
// hasTemporal indicates a temporal edge exists for this rule.
func specTruth(r Rule, hasTemporal bool) flatRule {
	strength := strings.ReplaceAll(r.Modal, "_", " ") // MUST_NOT -> "MUST NOT"
	// The flat schema records base strength (MUST/SHOULD/MAY); negation is in text.
	base := strength
	if i := strings.IndexByte(base, ' '); i > 0 {
		base = base[:i]
	}
	if base == "REQUIRED" || base == "RECOMMENDED" {
		if base == "REQUIRED" {
			base = "MUST"
		} else {
			base = "SHOULD"
		}
	}

	forkMod := ""
	if len(r.ForkModified) > 0 {
		forkMod = strings.Join(r.ForkModified, ",")
	}

	return flatRule{
		ID:             r.ID,
		Text:           r.RawText,
		Strength:       base,
		Protocol:       deriveProtocol(r),
		RuleType:       deriveRuleType(r, hasTemporal),
		Formalized:     deriveFormalized(r),
		ForkIntroduced: r.ForkIntroduced,
		ForkModified:   forkMod,
		ForkRemoved:    r.ForkRemoved,
		StateMachine:   deriveStateMachine(r),
		// Overlay defaults for genuinely-new rules (join.go overrides from overlay).
		Testability:    "direct",
		CoverageStatus: "untested",
		CurrentStatus:  "local_candidate",
		TestIDs:        []string{},
		InvariantIDs:   []string{},
		Transitions:    []string{},
	}
}

func deriveProtocol(r Rule) string {
	if strings.HasPrefix(r.BindsTo, "topic:") {
		return strings.TrimPrefix(r.BindsTo, "topic:")
	}
	if strings.HasPrefix(r.BindsTo, "protocol:") {
		return strings.TrimPrefix(r.BindsTo, "protocol:")
	}
	return ""
}

func deriveStateMachine(r Rule) string {
	switch {
	case strings.HasPrefix(r.BindsTo, "topic:"):
		return "gossip"
	case strings.HasPrefix(r.BindsTo, "protocol:"):
		return "reqresp"
	}
	return ""
}

func deriveRuleType(r Rule, hasTemporal bool) string {
	if hasTemporal {
		return "ordering"
	}
	if r.Condition != nil && r.Condition.Antecedent != "" {
		return "conditional"
	}
	hay := strings.ToLower(r.RawText + " " + r.SourceExpr)
	switch {
	case strings.Contains(hay, "timeout") || strings.Contains(hay, "ttfb") ||
		strings.Contains(hay, "seconds") || strings.Contains(hay, " ms"):
		return "timing"
	case strings.Contains(hay, "encod") || strings.Contains(hay, "ssz") ||
		strings.Contains(hay, "size") || strings.Contains(hay, "length") ||
		strings.Contains(hay, "bytes"):
		return "format"
	}
	return "behavioral"
}

// deriveFormalized returns the FAILURE predicate (the oracle condition under
// which the outcome fires), derived conservatively so a validity condition is
// never mistaken for a failure predicate:
//   - failure-polarity source_expr (python `if` guard) is used as-is;
//   - validity-polarity source_expr is negated, but only when it is a complete
//     boolean (has a comparison operator or is a bare predicate call);
//   - otherwise fall back to a prose normalized_expr, or "" — never a guess.
func deriveFormalized(r Rule) string {
	switch r.ExprPolarity {
	case "failure":
		if r.SourceExpr != "" {
			return r.SourceExpr
		}
	case "validity":
		if isCleanBoolean(r.SourceExpr) {
			return "not (" + r.SourceExpr + ")"
		}
		return "" // validity condition we cannot safely invert -> no failure predicate
	}
	return r.NormalizedExpr
}

// isCleanBoolean reports whether expr is a complete boolean expression safe to
// negate: it contains a comparison/relational operator or is a bare predicate
// call like name(args).
func isCleanBoolean(expr string) bool {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return false
	}
	if cleanBoolRe.MatchString(expr) {
		return true
	}
	return predCallRe.MatchString(expr)
}
