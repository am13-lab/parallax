// Command spectrans is a static Spec->Rule translator. It parses the Ethereum
// consensus-layer P2P specs (consensus-specs/specs/**/p2p-interface.md) into a
// faithful, regenerable rule AST (ast/rule_ast.json). Runtime tools consume the
// AST joined with ast/test_overlay.json directly; the flat projection is only a
// debug artifact.
//
// The AST is spec truth only: it mirrors what the spec says and carries no
// testing state. All testing/triage judgments live in ast/test_overlay.json.
package main

// Fork ordering. Earlier forks are parsed before later ones so a reworded rule
// in a later fork can be linked back to the earlier rule it modifies via a
// "supersedes" edge (see buildSupersedes in relations.go); verbatim restatements
// instead merge into one node carrying ForkModified.
var forkOrder = []string{
	"phase0", "altair", "bellatrix", "capella", "deneb",
	"electra", "fulu", "gloas", "heze",
}

// Source is the exact spec location a node was extracted from. Mandatory on
// every node so a rule always traces back to a spec line and regeneration can
// diff cleanly against the previous AST.
type Source struct {
	Fork   string `json:"fork"`
	File   string `json:"file"`
	Line   int    `json:"line"`   // 1-based line of the node's start
	Anchor string `json:"anchor"` // heading section path, " > " joined
}

// Subject is who a normative rule binds. Actor is the resolved role from the
// actor lexicon; Explicit records whether the spec named it or we inferred it
// from section context.
type Subject struct {
	Actor     string `json:"actor"`
	Qualifier string `json:"qualifier,omitempty"`
	Explicit  bool   `json:"explicit"`
}

// Predicate is the (action, object) decomposition of a normative clause.
type Predicate struct {
	Action    string   `json:"action"`
	Object    string   `json:"object"`
	Modifiers []string `json:"modifiers,omitempty"`
}

// Condition is the antecedent guarding a rule (from a python `if`, a bullet
// "if"/"when" clause, or a prose conditional).
type Condition struct {
	Antecedent string `json:"antecedent"`
}

// Constant is a spec-defined constant from a config/constants markdown table.
// Value is the evaluated integer when Expr resolves; Evaluated marks success.
type Constant struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Expr           string `json:"expr"`
	Value          int64  `json:"value"`
	Evaluated      bool   `json:"evaluated"`
	Unit           string `json:"unit,omitempty"`
	Desc           string `json:"desc,omitempty"`
	IntroducedFork string `json:"introduced_fork,omitempty"`
	Source         Source `json:"source"`
}

// Surface is a protocol (Req/Resp method) or gossip topic definition.
type Surface struct {
	ID             string `json:"id"`
	Kind           string `json:"kind"` // "protocol" | "topic"
	Name           string `json:"name"`
	ProtocolIDRaw  string `json:"protocol_id_raw,omitempty"`  // as written in the spec
	ProtocolIDNorm string `json:"protocol_id_norm,omitempty"` // normalized for matching
	Version        string `json:"version,omitempty"`
	Encoding       string `json:"encoding,omitempty"`
	RequestSchema  string `json:"request_schema,omitempty"`
	ResponseSchema string `json:"response_schema,omitempty"`
	IntroducedFork string `json:"introduced_fork,omitempty"`
	Source         Source `json:"source"`
	// Inherit is set when the spec says the schema is "unchanged" from a prior
	// version; a post-pass fills empty schemas from the nearest lower version.
	// Transient (not serialized).
	Inherit bool `json:"-"`
}

// Rule is a single atomic normative statement. Structured extractors (codeblock,
// bullet) fill source_expr with verbatim spec text (spec truth); prose fills
// normalized_expr with an inferred predicate (interpretation, lower confidence).
type Rule struct {
	ID                  string     `json:"id"`
	Source              Source     `json:"source"`
	RawText             string     `json:"raw_text"`
	Subject             Subject    `json:"subject"`
	Modal               string     `json:"modal"` // MUST|MUST_NOT|SHOULD|SHOULD_NOT|MAY|REQUIRED|RECOMMENDED
	Predicate           Predicate  `json:"predicate"`
	BindsTo             string     `json:"binds_to,omitempty"` // "protocol:<id>" | "topic:<name>"
	Outcome             string     `json:"outcome,omitempty"`  // REJECT | IGNORE | ""
	Condition           *Condition `json:"condition,omitempty"`
	SourceExpr          string     `json:"source_expr,omitempty"`
	ExprPolarity        string     `json:"expr_polarity,omitempty"` // failure | validity | ""
	NormalizedExpr      string     `json:"normalized_expr,omitempty"`
	Extractor           string     `json:"extractor"`  // codeblock | bullet | prose
	Confidence          string     `json:"confidence"` // high | medium | low
	ConstantsReferenced []string   `json:"constants_referenced,omitempty"`
	// Provenance (spec truth): the fork that introduced this rule and any forks
	// that modified or removed it, deduped across the fork walk.
	ForkIntroduced string   `json:"fork_introduced,omitempty"`
	ForkModified   []string `json:"fork_modified,omitempty"`
	ForkRemoved    string   `json:"fork_removed,omitempty"`
}

// Edge relates rule nodes or annotates one rule with a resolved referent.
// Invariant: From != "" AND (To != "" OR ToRef != "" OR Guard != "").
// To and ToRef are mutually exclusive: when the referent resolves to a node,
// To is set (and ToRef/ToRefKind stay empty); otherwise ToRef+ToRefKind carry
// the unresolved literal.
type Edge struct {
	Kind       string `json:"kind"`                  // supersedes | temporal | conditional | provenance
	From       string `json:"from"`                  // anchor rule id (the rule the edge is about)
	To         string `json:"to,omitempty"`          // resolved node: "rule:<Rule.ID>" | "surface:<Surface.ID>" | "constant:<Constant.ID>"
	ToRef      string `json:"to_ref,omitempty"`      // literal referent ONLY when it resolves to no node (e.g. an event)
	ToRefKind  string `json:"to_ref_kind,omitempty"` // event | expr (classifies an unresolved ToRef only)
	Rel        string `json:"rel,omitempty"`         // before|after|once|until|upon | modifies
	Guard      string `json:"guard,omitempty"`       // conditional: the condition; provenance: note
	Confidence string `json:"confidence,omitempty"`  // supersedes: high (exact) | medium (fuzzy)
	Score      string `json:"score,omitempty"`       // supersedes fuzzy: Jaccard, e.g. "0.67"
}

// Residual is a modal clause the parser could not confidently decompose. The
// worklist for the scoped LLM/human pass.
type Residual struct {
	Fork    string `json:"fork"`
	File    string `json:"file"`
	Line    int    `json:"line"`
	RawText string `json:"raw_text"`
	Reason  string `json:"reason"`
}

// Meta records generation provenance for the AST file.
type Meta struct {
	Generator   string   `json:"generator"`
	SpecSources []string `json:"spec_sources"`
	Forks       []string `json:"forks"`
}

// RuleAST is the top-level document written to ast/rule_ast.json.
type RuleAST struct {
	Meta      Meta       `json:"meta"`
	Constants []Constant `json:"constants"`
	Surfaces  []Surface  `json:"surfaces"`
	Rules     []Rule     `json:"rules"`
	Edges     []Edge     `json:"edges"`
	Residuals []Residual `json:"residuals"`
}
