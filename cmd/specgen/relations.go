package main

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// relations.go — Layer 2. Dedupes rules across the fork walk (merging fork
// provenance), links reworded rules across forks (supersedes edges), and derives
// temporal/conditional/provenance annotations for each rule.

var (
	temporalRe    = regexp.MustCompile(`(?i)\b(prior to|as soon as|before|after|once|until|upon|following|immediately)\b`)
	conditionalRe = regexp.MustCompile(`(?i)\b(if|when|unless|in case|provided that)\b`)
)

// supersedeThreshold is the minimum Jaccard content-token similarity for a fuzzy
// fork-supersession link (exact canonical matches bypass it). Tune during
// regeneration: lower to catch heavier rewordings, raise to cut false links.
const supersedeThreshold = 0.55

// firstTemporal returns the leftmost genuine temporal-connective match in s, skipping
// adjectival "the following" (list introduction, e.g. "the following cases/validations/
// limits"), which is not an ordering cue. Skipping it lets a real connective later in
// the same sentence still match — e.g. "the following validations MUST pass before
// forwarding X" yields a "before" edge rather than a bogus "after «validations…»".
func firstTemporal(s string) []int {
	for _, loc := range temporalRe.FindAllStringIndex(s, -1) {
		if strings.EqualFold(s[loc[0]:loc[1]], "following") {
			prev := strings.Fields(strings.ToLower(s[:loc[0]]))
			if len(prev) > 0 && prev[len(prev)-1] == "the" {
				continue // "the following <noun>" — list intro, not temporal
			}
		}
		return loc
	}
	return nil
}

// temporalRel canonicalizes a matched connective to an edge rel.
func temporalRel(word string) string {
	switch strings.ToLower(strings.TrimSpace(word)) {
	case "before", "prior to":
		return "before"
	case "after", "following":
		return "after"
	case "once":
		return "once"
	case "until":
		return "until"
	case "upon", "as soon as", "immediately":
		return "upon"
	}
	return "upon"
}

// forkRanker returns a fork-name -> position function (unknown forks sort last).
func forkRanker() func(string) int {
	order := map[string]int{}
	for i, f := range forkOrder {
		order[f] = i
	}
	return func(f string) int {
		if r, ok := order[f]; ok {
			return r
		}
		return len(forkOrder)
	}
}

// buildRelations runs three ordered phases so provenance is never stale:
//  1. dedupe verbatim cross-fork lineages by id;
//  2. link reworded rules across forks (only exact matches mutate ForkModified);
//  3. derive temporal/conditional/provenance annotations from the finalized rules.
func buildRelations(rules []Rule, constants []Constant) ([]Rule, []Edge) {
	rank := forkRanker()

	deduped := dedupeRules(rules, rank)
	deduped, superEdges := buildSupersedes(deduped, rank)

	constIDByName := constIndex(constants)
	var edges []Edge
	for i := range deduped {
		edges = append(edges, deriveEdges(&deduped[i], constIDByName)...)
	}
	edges = append(edges, superEdges...)
	return deduped, edges
}

// dedupeRules merges rules that share an id (identical fork-independent text)
// into one node, recording the earliest fork as ForkIntroduced and later verbatim
// restatements as ForkModified.
func dedupeRules(rules []Rule, rank func(string) int) []Rule {
	type group struct {
		rule  Rule
		forks map[string]bool
		rmvd  string
	}
	groups := map[string]*group{}
	var idOrder []string
	for _, r := range rules {
		g, ok := groups[r.ID]
		if !ok {
			g = &group{rule: r, forks: map[string]bool{}}
			groups[r.ID] = g
			idOrder = append(idOrder, r.ID)
		}
		if r.ForkIntroduced != "" {
			g.forks[r.ForkIntroduced] = true
		}
		if r.ForkRemoved != "" {
			g.rmvd = r.ForkRemoved
		}
		// Prefer the earliest-fork instance as the canonical rule body.
		if rank(r.ForkIntroduced) < rank(g.rule.ForkIntroduced) {
			r.ForkRemoved = g.rule.ForkRemoved
			g.rule = r
		}
	}

	var deduped []Rule
	for _, id := range idOrder {
		g := groups[id]
		var forks []string
		for f := range g.forks {
			forks = append(forks, f)
		}
		sort.Slice(forks, func(i, j int) bool { return rank(forks[i]) < rank(forks[j]) })

		r := g.rule
		if len(forks) > 0 {
			r.ForkIntroduced = forks[0]
			r.ForkModified = nil
			for _, f := range forks[1:] {
				r.ForkModified = append(r.ForkModified, f)
			}
		}
		if g.rmvd != "" {
			r.ForkRemoved = g.rmvd
		}
		deduped = append(deduped, r)
	}
	return deduped
}

// buildSupersedes links a later-fork rule to the earlier-fork rule it reworded.
// Candidates are bucketed by a fork-independent key; within a bucket each later
// rule takes the nearest earlier exact canonical match, or the highest-scoring
// fuzzy match above supersedeThreshold. It also enriches the earlier node's
// ForkModified so provenance edges (derived later) are current.
func buildSupersedes(rules []Rule, rank func(string) int) ([]Rule, []Edge) {
	buckets := map[string][]int{}
	var bucketOrder []string
	for i, r := range rules {
		key := supersedeBucket(r)
		if _, ok := buckets[key]; !ok {
			bucketOrder = append(bucketOrder, key)
		}
		buckets[key] = append(buckets[key], i)
	}
	sort.Strings(bucketOrder)

	var edges []Edge
	for _, key := range bucketOrder {
		members := buckets[key]
		for _, li := range members {
			L := &rules[li]
			lr := rank(L.ForkIntroduced)

			// Earlier-fork candidates, nearest fork first, id-ascending within a fork.
			var cands []int
			for _, mi := range members {
				if rank(rules[mi].ForkIntroduced) < lr {
					cands = append(cands, mi)
				}
			}
			if len(cands) == 0 {
				continue
			}
			sort.Slice(cands, func(a, b int) bool {
				ra, rb := rank(rules[cands[a]].ForkIntroduced), rank(rules[cands[b]].ForkIntroduced)
				if ra != rb {
					return ra > rb // nearer earlier fork first
				}
				return rules[cands[a]].ID < rules[cands[b]].ID
			})

			lc := canonicalRuleText(L.RawText)
			lt := contentTokens(L.RawText)
			bestE, bestScore, exact := -1, 0.0, false

			for _, ei := range cands { // exact tier: nearest wins
				if lc != "" && canonicalRuleText(rules[ei].RawText) == lc {
					bestE, exact = ei, true
					break
				}
			}
			if bestE < 0 { // fuzzy fallback: highest score (nearest on ties)
				for _, ei := range cands {
					s := jaccard(contentTokens(rules[ei].RawText), lt)
					if s >= supersedeThreshold && s > bestScore {
						bestE, bestScore = ei, s
					}
				}
			}
			if bestE < 0 {
				continue
			}

			conf, score := "medium", fmt.Sprintf("%.2f", bestScore)
			if exact {
				conf, score = "high", ""
			}
			edges = append(edges, Edge{
				Kind: "supersedes", From: L.ID, To: "rule:" + rules[bestE].ID,
				Rel: "modifies", Confidence: conf, Score: score,
			})
			// Only exact (verbatim-modulo-provenance) links drive exported spec
			// truth. Fuzzy links are advisory edges — never mutate ForkModified,
			// so a heuristic guess cannot corrupt provenance.
			if exact {
				rules[bestE].ForkModified = addForkSorted(rules[bestE].ForkModified, L.ForkIntroduced, rank)
			}
		}
	}
	return rules, edges
}

// supersedeBucket groups rules that could be rewordings of one another. Bound
// (gossip) rules key on binds_to + outcome/modal — both fork-independent. Unbound
// prose keys on actor + predicate action + modal. The section anchor is
// deliberately excluded: real spec anchors are fork-labelled (e.g. "Phase 0 --
// Networking", "Modifications in Fulu"), so anchoring the bucket would put a rule
// and its later-fork restatement in different buckets and defeat cross-fork
// matching. Breadth is safe here because only exact matches drive provenance
// (see buildSupersedes); fuzzy links are advisory edges.
func supersedeBucket(r Rule) string {
	tag := r.Outcome
	if tag == "" {
		tag = r.Modal
	}
	if r.BindsTo != "" {
		return r.BindsTo + "|" + tag
	}
	return "PROSE|" + r.Subject.Actor + "|" + r.Predicate.Action + "|" + tag
}

var (
	provSuffixRe = regexp.MustCompile(`(?i)\(\[?modified in [a-z0-9]+\]?\)`)
	definedByRe  = regexp.MustCompile(`(?i)\(defined by [^)]*\)`)
)

// canonicalRuleText strips only provenance suffixes ("(Modified in X)") and
// narrow definitional refs ("(defined by ...)"), then normalizes. Semantic
// parentheticals are preserved so they fall to fuzzy matching rather than being
// treated as an exact (high-confidence) match.
func canonicalRuleText(s string) string {
	s = provSuffixRe.ReplaceAllString(s, "")
	s = definedByRe.ReplaceAllString(s, "")
	return normalizeText(stripInlineMarkup(s))
}

var stopwords = map[string]bool{
	"the": true, "a": true, "an": true, "is": true, "are": true, "be": true,
	"been": true, "of": true, "to": true, "in": true, "for": true, "and": true,
	"or": true, "its": true, "it": true, "this": true, "that": true, "with": true,
	"has": true, "have": true, "as": true, "at": true, "by": true, "on": true,
}

// contentTokens returns the significant word set of a rule's text (identifiers
// preserved, stopwords and single chars dropped) for similarity scoring.
func contentTokens(s string) map[string]bool {
	toks := map[string]bool{}
	for _, w := range wordRe.FindAllString(strings.ToLower(stripInlineMarkup(s)), -1) {
		if len(w) < 2 || stopwords[w] {
			continue
		}
		toks[w] = true
	}
	return toks
}

// jaccard is |A∩B| / |A∪B| over two token sets (0 when both empty).
func jaccard(a, b map[string]bool) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 0
	}
	inter := 0
	for t := range a {
		if b[t] {
			inter++
		}
	}
	union := len(a) + len(b) - inter
	if union == 0 {
		return 0
	}
	return float64(inter) / float64(union)
}

// addForkSorted appends f to forks (dedup) and re-sorts by fork rank.
func addForkSorted(forks []string, f string, rank func(string) int) []string {
	if f == "" {
		return forks
	}
	for _, x := range forks {
		if x == f {
			return forks
		}
	}
	forks = append(forks, f)
	sort.Slice(forks, func(i, j int) bool { return rank(forks[i]) < rank(forks[j]) })
	return forks
}

// constIndex maps constant names to node ids for conditional edge resolution.
func constIndex(constants []Constant) map[string]string {
	m := map[string]string{}
	for _, c := range constants {
		if c.Name != "" {
			m[c.Name] = c.ID
		}
	}
	return m
}

// deriveEdges emits temporal/conditional/provenance annotations for one rule.
// It resolves a conditional guard to a constant node when it names exactly one;
// temporal referents stay literal (ToRef) since their targets are events, not
// nodes. Surface targets are deliberately not resolved: surface names collide
// across versions (Status v1/v2) and match incidental code identifiers
// (voluntary_exit.epoch), so a resolved surface To would assert a dependency
// that is not real. It sets rule.Condition from a detected conditional when the
// structured extractor did not.
func deriveEdges(r *Rule, constIDByName map[string]string) []Edge {
	var edges []Edge
	hay := r.RawText

	// Temporal: anchor + the event phrase the connective points at.
	if loc := firstTemporal(hay); loc != nil {
		if ref := referentPhrase(hay[loc[1]:]); ref != "" {
			edges = append(edges, Edge{
				Kind: "temporal", From: r.ID, Rel: temporalRel(hay[loc[0]:loc[1]]),
				ToRef: ref, ToRefKind: "event",
			})
		}
	}

	// Conditional: anchor + guard, resolving a single referenced constant.
	guard := ""
	if r.Condition != nil && r.Condition.Antecedent != "" {
		guard = r.Condition.Antecedent
	} else if conditionalRe.MatchString(hay) {
		if g := extractConditional(hay); g != "" {
			r.Condition = &Condition{Antecedent: g}
			guard = g
		}
	}
	if guard != "" {
		e := Edge{Kind: "conditional", From: r.ID, Guard: guard}
		if cid := resolveSingleConstant(guard, constIDByName); cid != "" {
			e.To = "constant:" + cid
		}
		edges = append(edges, e)
	}

	// Provenance annotation (emitted after supersession so the note is current).
	if len(r.ForkModified) > 0 || r.ForkRemoved != "" {
		edges = append(edges, Edge{Kind: "provenance", From: r.ID, Guard: provenanceNote(r)})
	}
	return edges
}

// referentPhrase returns the phrase a temporal connective points at: the text up
// to the first clause boundary, with markup stripped. It protects decimals (2.0)
// and only treats a period as a boundary when followed by whitespace/end, so
// abbreviations and version numbers are not mangled. Returns "" when the phrase
// carries no content word, so callers emit no dangling referent.
func referentPhrase(s string) string {
	s = strings.TrimSpace(strings.TrimLeft(strings.TrimSpace(s), "-—"))
	end := len(s)
loop:
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ')', ';', ':', ',':
			end = i
			break loop
		case '.':
			prevDigit := i > 0 && s[i-1] >= '0' && s[i-1] <= '9'
			nextDigit := i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '9'
			if prevDigit && nextDigit {
				continue // decimal, e.g. "2.0"
			}
			if i+1 >= len(s) || s[i+1] == ' ' {
				end = i
				break loop
			}
		}
	}
	ref := strings.TrimSpace(stripInlineMarkup(s[:end]))
	if len(contentTokens(ref)) == 0 {
		return "" // only stopwords/fragments — not a meaningful referent
	}
	return ref
}

// resolveSingleConstant returns the constant id when exactly one distinct known
// constant appears in text (constant names are case-sensitive UPPER_SNAKE).
func resolveSingleConstant(text string, constIDByName map[string]string) string {
	found, seen := "", map[string]bool{}
	for _, w := range wordRe.FindAllString(text, -1) {
		if id, ok := constIDByName[w]; ok && !seen[w] {
			seen[w] = true
			if found != "" {
				return ""
			}
			found = id
		}
	}
	return found
}

// extractConditional returns the antecedent phrase following if/when/unless.
func extractConditional(text string) string {
	loc := conditionalRe.FindStringIndex(text)
	if loc == nil {
		return ""
	}
	rest := strings.TrimSpace(text[loc[1]:])
	// Cut at a clause boundary (comma or "then").
	for _, sep := range []string{", then ", ", ", " then "} {
		if i := strings.Index(strings.ToLower(rest), strings.TrimSpace(sep)); i > 0 {
			return strings.TrimSpace(rest[:i])
		}
	}
	return rest
}

func provenanceNote(r *Rule) string {
	var b strings.Builder
	if len(r.ForkModified) > 0 {
		b.WriteString("modified_in=" + strings.Join(r.ForkModified, ","))
	}
	if r.ForkRemoved != "" {
		if b.Len() > 0 {
			b.WriteString(" ")
		}
		b.WriteString("removed_in=" + r.ForkRemoved)
	}
	return b.String()
}
