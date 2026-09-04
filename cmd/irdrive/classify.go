package main

import (
	"regexp"
	"strings"
)

// classify.go — Layer D3.5. Assigns each gossip-validation rule a VIOLATION CLASS
// (what invariant the rule asserts), so the dictionary can map (topic, class) to a
// builder+mutator that targets that specific violation rather than matching brittle
// free-text. The class is derived from the rule's predicate object / source_expr /
// raw text, matched most-specific-first.
//
// The violation is produced by a dedicated builder variant (buildInvalid<Topic><Class>
// in internal/ethmsg) that constructs an already-corrupted, re-signed message — not a
// mutator. Behavioral classes (marked sequence) can't be a single-shot inject; they
// need a 2-step sequence template instead.

// classSpec is one taxonomy row: a class label, the regex that recognizes it, and
// whether the class is behavioral (needs a sequence template rather than a builder).
type classSpec struct {
	class    string
	re       *regexp.Regexp
	sequence bool // behavioral: inject-valid-then-inject-conflicting; no single builder
}

// violationTaxonomy is ordered most-specific-first: the first match wins, so
// narrower predicates (proposer_index) must precede broader ones (index/slot).
var violationTaxonomy = []classSpec{
	// --- crypto / structural, checked before the words they contain ---
	{"kzg_proof", reC(`kzg|commitment|blob.*proof|inclusion.?proof|cell proof|verify_data_column|verify_.*sidecar`), false},
	{"proposer_index_wrong", reC(`proposer index|expected proposer|proposed by`), false},
	{"sig_invalid", reC(`signature|selection_proof|is valid.*sig|\bsig\b|signed correctly`), false},
	// --- slot / epoch time windows (future before generic slot) ---
	{"slot_future", reC(`future slot|not from a future|from a future slot|current or.*next slot|slot .*greater than.*current|not in the future`), false},
	{"finalized_ancestor", reC(`finaliz|ancestor of the (finaliz|block)|descend|weak subjectivity`), false},
	{"slot_epoch_range", reC(`propagation|target\.epoch|epoch.*matches|within.*epoch|previous epoch|two epochs|slot.*within|too old|stale|current slot|current_slot|fork epoch|for the current`), false},
	// --- indices / subnets (proposer_index already handled above) ---
	{"subnet_mismatch", reC(`correct subnet|expected subnet|subnet.*match|on the.*subnet`), false},
	{"index_oob", reC(`subnet_id|committee index|column index|blob index|data\.index|index.*range|index.*<|index.*valid`), false},
	// --- parent / graph relationships ---
	{"parent_known_valid", reC(`parent`), false},
	{"target_root_consistent", reC(`target root|beacon_block_root|target.*consistent|\bhead\b|ancestor of|lmd`), false},
	// --- payload / execution field checks ---
	{"timestamp_correct", reC(`timestamp`), false},
	{"field_equality", reC(`equals|\bmatch(?:es)?\b|consistent with|same as|corresponds to|block_hash|payment|==|builder_index|execution_requests_root|withdrawal (pubkey|credential)`), false},
	{"length_limit", reC(`length|number of|no more than|at most|MAX_|exceed|\bsize\b|non-empty|at least one|has participants|participants`), false},
	{"type_correct", reC(`correct type|message type|type is`), false},
	{"unaggregated_bits", reC(`aggregation bit|exactly one|unaggregated`), false},
	// --- committee / validator status ---
	{"committee_member", reC(`committee|attester.*in|member of`), false},
	{"validator_status", reC(`validator is active|validator has|initiated exit|withdrawal`), false},
	// --- behavioral (need a 2-step sequence template, not a single builder) ---
	{"dedup_first_seen", reC(`first .*(valid|block|aggregate)|already been|has (not )?been seen|(has )?not seen another|previously (seen|validated)|not.*duplicate`), true},
	{"equivocation_header", reC(`equivocat|two different|conflicting|slashable`), true},
	// --- catch-all: "X is valid" / "passes validation" / "process_* does not
	//     indicate errors" (LC updates, generic validity) -> structural corruption ---
	{"structurally_valid", reC(`passes validation|passes all.*validation|is valid|does not indicate errors|valid as verified`), false},
}

// reC compiles a case-insensitive class regex.
func reC(pat string) *regexp.Regexp { return regexp.MustCompile(`(?i)` + pat) }

// classify returns the violation class for a rule, or "" if none match (bespoke —
// goes on the manual worklist). It reads predicate.object first (the cleanest
// signal), then source_expr, then raw_text.
func classify(r *astRule) string {
	hay := strings.ToLower(strings.Join([]string{r.Predicate.Object, r.SourceExpr, r.RawText}, "  "))
	for _, c := range violationTaxonomy {
		if c.re.MatchString(hay) {
			return c.class
		}
	}
	return ""
}

// isSequenceClass reports whether a class is behavioral — it needs a 2-step
// sequence template rather than a single buildInvalid variant.
func isSequenceClass(class string) bool {
	for _, c := range violationTaxonomy {
		if c.class == class {
			return c.sequence
		}
	}
	return false
}
