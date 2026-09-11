// Command irderive classifies spec-rule AST nodes and derives stateful
// differential-testing SM-IR from the supported stateful subset. Stateless,
// audit-only, future, and pending-builder rules are retained in the derivation
// report for coverage accounting and follow-up testcase generation. It is a pure,
// deterministic function of (AST + semantic dictionary + shape templates): no
// LLM, stable ordering, and every emitted transition traces back to a spec rule
// via spec_refs.
//
// The AST JSON is the contract, so this command mirrors the relevant fields here
// rather than importing cmd/spectrans (which stays untouched).
package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// astSource is the exact spec location a rule was extracted from.
type astSource struct {
	Fork   string `json:"fork"`
	File   string `json:"file"`
	Line   int    `json:"line"`
	Anchor string `json:"anchor"`
}

type astSubject struct {
	Actor     string `json:"actor"`
	Qualifier string `json:"qualifier"`
	Explicit  bool   `json:"explicit"`
}

type astPredicate struct {
	Action string `json:"action"`
	Object string `json:"object"`
}

type astCondition struct {
	Antecedent string `json:"antecedent"`
}

// astRule mirrors a normative rule node in rule_ast.json.
type astRule struct {
	ID                  string        `json:"id"`
	Source              astSource     `json:"source"`
	RawText             string        `json:"raw_text"`
	Subject             astSubject    `json:"subject"`
	Modal               string        `json:"modal"`
	Predicate           astPredicate  `json:"predicate"`
	BindsTo             string        `json:"binds_to"`
	Outcome             string        `json:"outcome"`
	Condition           *astCondition `json:"condition"`
	SourceExpr          string        `json:"source_expr"`
	ExprPolarity        string        `json:"expr_polarity"`
	NormalizedExpr      string        `json:"normalized_expr"`
	Extractor           string        `json:"extractor"`
	Confidence          string        `json:"confidence"`
	ConstantsReferenced []string      `json:"constants_referenced"`
	ForkIntroduced      string        `json:"fork_introduced"`
	ForkModified        []string      `json:"fork_modified"`
	ForkRemoved         string        `json:"fork_removed"`
}

// astSurface mirrors a protocol/topic surface node.
type astSurface struct {
	ID             string `json:"id"`
	Kind           string `json:"kind"` // protocol | topic
	Name           string `json:"name"`
	ProtocolIDNorm string `json:"protocol_id_norm"`
	Version        string `json:"version"`
	Encoding       string `json:"encoding"`
	IntroducedFork string `json:"introduced_fork"`
}

// astEdge mirrors a relation edge (cmd/spectrans/ast.go Edge). Parse-only here.
type astEdge struct {
	Kind       string `json:"kind"` // supersedes | temporal | conditional | provenance
	From       string `json:"from"`
	To         string `json:"to"`
	ToRef      string `json:"to_ref"`
	ToRefKind  string `json:"to_ref_kind"`
	Rel        string `json:"rel"`
	Guard      string `json:"guard"`
	Confidence string `json:"confidence"`
	Score      string `json:"score"`
}

// astDoc is the top-level rule_ast.json document (fields we consume).
type astDoc struct {
	Constants []struct {
		Name  string `json:"name"`
		Value int64  `json:"value"`
	} `json:"constants"`
	Surfaces []astSurface `json:"surfaces"`
	Rules    []astRule    `json:"rules"`
	Edges    []astEdge    `json:"edges"`
}

func loadAST(path string) (*astDoc, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var d astDoc
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, fmt.Errorf("parse AST: %w", err)
	}
	return &d, nil
}

// indexEdgesByFrom buckets edges by their source rule id, keeping only the kinds
// that carry guard-relevant semantics (temporal ordering, conditional antecedents).
// supersedes/provenance edges are provenance, not guard context, so they are skipped.
func indexEdgesByFrom(doc *astDoc) map[string][]astEdge {
	m := map[string][]astEdge{}
	for _, e := range doc.Edges {
		if e.Kind == "temporal" || e.Kind == "conditional" {
			m[e.From] = append(m[e.From], e)
		}
	}
	return m
}

// loadAliases reads spec_rule_aliases.json (AST-node-id -> canonical flat id).
// A missing file yields an empty map; callers fall back to the AST id.
func loadAliases(path string) map[string]string {
	data, err := os.ReadFile(path)
	if err != nil {
		return map[string]string{}
	}
	m := map[string]string{}
	if json.Unmarshal(data, &m) != nil {
		return map[string]string{}
	}
	return m
}

// loadKnownProtocols reads protocol_model.json's availability keys — the set of
// protocol IDs smgen/executor actually support. Rules whose protocol is absent
// become coverage gaps rather than emitted transitions.
func loadKnownProtocols(path string) map[string]bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return map[string]bool{}
	}
	var pm struct {
		Availability map[string]json.RawMessage `json:"availability"`
	}
	if json.Unmarshal(data, &pm) != nil {
		return map[string]bool{}
	}
	out := map[string]bool{}
	for id := range pm.Availability {
		out[id] = true
	}
	return out
}

// canonicalID maps an AST rule id to the canonical id used in spec_refs. It
// falls back to the AST id when no alias exists.
func canonicalID(aliases map[string]string, astID string) string {
	if c, ok := aliases[astID]; ok && c != "" {
		return c
	}
	return astID
}
