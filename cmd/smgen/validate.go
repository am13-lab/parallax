package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

// Issue is a single validation finding, tagged with the gate that produced it.
type Issue struct {
	Gate string // e.g. "gate1", "gate2", "gate4"
	Path string // location, e.g. transitions[3].action.mutator
	Msg  string
}

// Result is the outcome of validating one machine file.
type Result struct {
	File     string
	Issues   []Issue
	Warnings []Issue  // non-fatal advisories; do not affect OK()
	Skipped  []string // gates that were not run, with reason
	// Judgment coverage metrics (populated by gate6).
	SingleClientJudged int // transitions with an expected/must_not/spec_predicate/resource/invariant oracle
	DifferentialOnly   int // transitions judged only by cross-client comparison
	JudgedByNothing    int // transitions that opt out of differential yet declare no single-client judgment
}

// OK reports whether the machine passed all run gates. Warnings do not fail.
func (r *Result) OK() bool { return len(r.Issues) == 0 }

func (r *Result) add(gate, path, format string, args ...any) {
	r.Issues = append(r.Issues, Issue{Gate: gate, Path: path, Msg: fmt.Sprintf(format, args...)})
}

func (r *Result) addWarn(gate, path, format string, args ...any) {
	r.Warnings = append(r.Warnings, Issue{Gate: gate, Path: path, Msg: fmt.Sprintf(format, args...)})
}

// refIndex holds the external reference sets used by Gate 2.
type refIndex struct {
	specRules     map[string]bool   // canonical AST rule IDs
	specStrength  map[string]string // canonical AST rule ID -> strength (MUST/SHOULD/MAY)
	invariants    map[string]bool   // INV-* IDs, nil if invariant_rules.json absent
	protocolModel *ProtocolModel    // nil if protocol_model.json absent
}

type ruleIndexPaths struct {
	ruleAST   string
	overlay   string
	legacyMap string
}

// loadRefIndex loads spec rule and invariant IDs for reference resolution.
// Inlined from framework.LoadRuleIndex: the validator only consumes canonical
// AST rule IDs and strengths (overlay/legacy do not affect either).
func loadRefIndex(paths ruleIndexPaths, invariantsPath string) (refIndex, error) {
	data, err := os.ReadFile(paths.ruleAST)
	if err != nil {
		return refIndex{}, fmt.Errorf("read rule AST: %w", err)
	}
	var ast struct {
		Rules []struct {
			ID       string `json:"id"`
			Strength string `json:"strength"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(data, &ast); err != nil {
		return refIndex{}, fmt.Errorf("parse rule AST: %w", err)
	}
	if len(ast.Rules) == 0 {
		return refIndex{}, fmt.Errorf("rule AST has no rules")
	}
	specRules := make(map[string]bool, len(ast.Rules))
	specStrength := make(map[string]string, len(ast.Rules))
	for _, rule := range ast.Rules {
		if rule.ID == "" {
			return refIndex{}, fmt.Errorf("rule AST contains an empty rule id")
		}
		if specRules[rule.ID] {
			return refIndex{}, fmt.Errorf("rule_ast: duplicate rule id %q", rule.ID)
		}
		specRules[rule.ID] = true
		specStrength[rule.ID] = rule.Strength
	}
	return refIndex{
		specRules:    specRules,
		specStrength: specStrength,
		invariants:   loadIDSet(invariantsPath, "invariants"),
	}, nil
}

// strengthRank orders strengths so the strongest among a transition's spec_refs
// wins when deriving an oracle's strength. Unknown -> 0.
func strengthRank(s string) int {
	switch s {
	case "MUST":
		return 3
	case "SHOULD":
		return 2
	case "MAY":
		return 1
	default:
		return 0
	}
}

// applyDerivedStrength fills each oracle's Strength from the transition's
// spec_refs when the oracle omits an explicit strength. The strongest strength
// among the referenced rules wins (a transition encoding any MUST rule is judged
// at MUST severity). Explicit oracle.strength is never overwritten.
func applyDerivedStrength(m *Machine, strengths map[string]string) {
	if strengths == nil {
		return
	}
	for i := range m.Transitions {
		t := &m.Transitions[i]
		if t.Oracle == nil || t.Oracle.Strength != "" || len(t.SpecRefs) == 0 {
			continue
		}
		best := ""
		for _, ref := range t.SpecRefs {
			if s, ok := strengths[ref]; ok && strengthRank(s) > strengthRank(best) {
				best = s
			}
		}
		t.Oracle.Strength = best
	}
}

func loadIDSet(path, arrayKey string) map[string]bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var file map[string]json.RawMessage
	if err := json.Unmarshal(data, &file); err != nil {
		return nil
	}
	raw, ok := file[arrayKey]
	if !ok {
		return nil
	}
	var entries []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil
	}
	set := map[string]bool{}
	for _, e := range entries {
		if e.ID != "" {
			set[e.ID] = true
		}
	}
	return set
}

// validateMachine runs all feasible gates on a loaded machine.
func validateMachine(m *Machine, refs refIndex) *Result {
	r := &Result{}
	gate1Structural(m, r)
	gate2References(m, r, refs)
	gate3Payload(m, r, refs.protocolModel)
	gate4WellFormed(m, r)
	r.Skipped = append(r.Skipped, "gate5: skipped (differential cross-check requires a generated machine pair)")
	gate6Judgment(m, r)
	gate7ForkAvailability(m, r, refs.protocolModel)
	gate8Reachability(m, r)
	sortIssues(r)
	return r
}

// --- Gate 7: fork availability coverage ---

// gate7ForkAvailability checks the Protocol Model's fork-availability metadata
// against the IR. Errors: an availability entry naming an unknown fork, or an
// introduced/deprecated pair out of order. Warning: a Req/Resp protocol used by
// a transition that has no availability entry (so fork-window reasoning is not
// yet possible for it). Skipped when the Protocol Model is absent.
func gate7ForkAvailability(m *Machine, r *Result, pm *ProtocolModel) {
	if pm == nil {
		r.Skipped = append(r.Skipped, "gate7: fork-availability check skipped (protocol_model.json not found)")
		return
	}
	// Validate the availability table's fork names (independent of this machine).
	for proto, av := range pm.Availability {
		if !knownFork(av.IntroducedFork) {
			r.add("gate7", "availability["+proto+"].introduced_fork", "unknown fork %q", av.IntroducedFork)
		}
		if av.DeprecatedFork != "" {
			if !knownFork(av.DeprecatedFork) {
				r.add("gate7", "availability["+proto+"].deprecated_fork", "unknown fork %q", av.DeprecatedFork)
			} else if knownFork(av.IntroducedFork) && forkRank[av.DeprecatedFork] <= forkRank[av.IntroducedFork] {
				r.add("gate7", "availability["+proto+"]", "deprecated_fork %q not after introduced_fork %q", av.DeprecatedFork, av.IntroducedFork)
			}
		}
	}
	// Warn for Req/Resp protocols used by this machine with no availability entry.
	seen := map[string]bool{}
	for i := range m.Transitions {
		a := m.Transitions[i].Action
		if !reqRespProtocolActions[a.Type] || a.Protocol == "" || seen[a.Protocol] {
			continue
		}
		seen[a.Protocol] = true
		if _, ok := pm.availabilityFor(a.Protocol); !ok {
			r.addWarn("gate7", fmt.Sprintf("transitions[%d].action.protocol", i),
				"protocol %q has no fork-availability metadata in protocol_model.json", a.Protocol)
		}
	}
}

// --- Gate 6: oracle judgment coverage (warnings + metrics) ---

// gate6Judgment classifies how each transition is judged and warns about
// transitions that are judged by nothing. A step is included in cross-client
// differential comparison unless it carries an oracle that opts out
// (Oracle != nil && !Oracle.Differential); see statemachine.DifferentialSummary.
// So a transition is "judged by nothing" only when it opts out of differential
// yet declares no single-client verdict (expected/must_not/spec_predicate),
// resource bound, or invariant — that step is masked AND has no other oracle.
// Transitions with no oracle at all are differentially judged by default and
// are not flagged here; the DifferentialOnly count surfaces the population gap
// (how many transitions lack any single-client verdict) for paper metrics.
func gate6Judgment(m *Machine, r *Result) {
	for i := range m.Transitions {
		t := &m.Transitions[i]
		single := hasSingleClientJudgment(t.Oracle)
		differential := t.Oracle == nil || t.Oracle.Differential
		switch {
		case single:
			r.SingleClientJudged++
		case differential:
			r.DifferentialOnly++
		default:
			r.JudgedByNothing++
			r.addWarn("gate6", fmt.Sprintf("transitions[%d].oracle", i),
				"transition %q opts out of differential but declares no single-client judgment (expected/must_not/spec_predicate/resource_bounds/invariant_refs) — judged by nothing",
				t.Label)
		}
	}
}

// hasSingleClientJudgment reports whether an oracle declares any per-client
// verdict mechanism (independent of cross-client differential comparison).
func hasSingleClientJudgment(o *Oracle) bool {
	if o == nil {
		return false
	}
	return o.Expected != "" || len(o.MustNot) > 0 || o.SpecPredicate != "" ||
		o.ResourceBounds != nil || o.ResourceTrend != nil || len(o.InvariantRefs) > 0
}

// --- Gate 1: structural / schema conformance ---

func gate1Structural(m *Machine, r *Result) {
	if m.Name == "" {
		r.add("gate1", "name", "machine name is required")
	}
	if m.InitState == "" {
		r.add("gate1", "init_state", "init_state is required")
	}
	if len(m.States) == 0 {
		r.add("gate1", "states", "at least one state is required")
	}
	for i, s := range m.States {
		if s.Name == "" {
			r.add("gate1", fmt.Sprintf("states[%d].name", i), "state name is required")
		}
	}
	if len(m.Transitions) == 0 {
		r.add("gate1", "transitions", "at least one transition is required")
	}
	for i, t := range m.Transitions {
		base := fmt.Sprintf("transitions[%d]", i)
		if t.From == "" {
			r.add("gate1", base+".from", "from is required")
		}
		if t.To == "" {
			r.add("gate1", base+".to", "to is required")
		}
		if t.Label == "" {
			r.add("gate1", base+".label", "label is required")
		}
		if t.Weight < 0 {
			r.add("gate1", base+".weight", "weight must be >= 0")
		}
		gate1Action(t.Action, base+".action", r)
		if t.Guard != nil {
			gate1Guard(t.Guard, base+".guard", r)
		}
		if t.Oracle != nil {
			gate1Oracle(t.Oracle, base+".oracle", r)
			// A trend oracle judges a time series captured across a burst; without
			// a repeat_count there is no burst and the series is empty.
			if t.Oracle.ResourceTrend != nil && t.Action.RepeatCount <= 1 {
				r.addWarn("gate1", base+".oracle.resource_trend", "resource_trend set but action.repeat_count <= 1; no burst means no series to judge")
			}
		}
	}
}

func gate1Action(a Action, path string, r *Result) {
	if a.Type == "" {
		r.add("gate1", path+".type", "action type is required")
		return
	}
	if _, ok := actionTypeNames[a.Type]; !ok {
		r.add("gate1", path+".type", "unknown action type %q", a.Type)
	}
	if a.TimeoutMs < 0 {
		r.add("gate1", path+".timeout_ms", "timeout_ms must be >= 0")
	}
	if a.TimeoutNs < 0 {
		r.add("gate1", path+".timeout_ns", "timeout_ns must be >= 0")
	}
	if a.TimeoutMs > 0 && a.TimeoutNs > 0 {
		r.add("gate1", path, "set only one of timeout_ms/timeout_ns")
	}
	if a.RepeatCount < 0 {
		r.add("gate1", path+".repeat_count", "repeat_count must be >= 0")
	}
	if a.TargetStream < 0 {
		r.add("gate1", path+".target_stream", "target_stream must be >= 0")
	}
	if a.PoolDelta && a.Type != "ActInjectGossip" {
		r.add("gate1", path+".pool_delta", "pool_delta is only valid for ActInjectGossip")
	}
	if a.Payload != nil {
		gate1Payload(a.Payload, path+".payload", r)
	}
}

func gate1Payload(p *Payload, path string, r *Result) {
	if p.CacheStore != "" && p.CacheLoad != "" {
		r.add("gate1", path, "set only one of cache_store/cache_load")
	}
	if !payloadKinds[p.Kind] {
		r.add("gate1", path+".kind", "invalid payload kind %q (want literal|fields|builder)", p.Kind)
	}
	if !wrapModes[p.Wrap] {
		r.add("gate1", path+".wrap", "invalid wrap %q (want ssz_snappy|raw|none)", p.Wrap)
	}
	switch p.Kind {
	case "literal":
		set := 0
		if p.Bytes != "" {
			set++
		}
		if p.Size != nil {
			set++
		}
		if p.Null {
			set++
		}
		if set != 1 {
			r.add("gate1", path, "literal payload must set exactly one of bytes|size|null")
		}
	case "fields":
		if len(p.Fields) == 0 {
			r.add("gate1", path+".fields", "fields payload requires a non-empty fields map")
		}
	case "builder":
		if p.Name == "" {
			r.add("gate1", path+".name", "builder payload requires a name")
		}
	}
}

func gate1Guard(g *Guard, path string, r *Result) {
	set := guardKeysSet(g)
	if set != 1 {
		r.add("gate1", path, "guard must set exactly one key, found %d", set)
		// Still recurse where possible to surface deeper issues.
	}
	if g.Count != nil {
		gate1Compare(g.Count, path+".count", r)
	}
	if g.Len != nil {
		gate1Compare(g.Len, path+".len", r)
	}
	for i := range g.And {
		gate1Guard(&g.And[i], fmt.Sprintf("%s.and[%d]", path, i), r)
	}
	for i := range g.Or {
		gate1Guard(&g.Or[i], fmt.Sprintf("%s.or[%d]", path, i), r)
	}
	if g.Not != nil {
		gate1Guard(g.Not, path+".not", r)
	}
}

func guardKeysSet(g *Guard) int {
	n := 0
	if g.And != nil {
		n++
	}
	if g.Or != nil {
		n++
	}
	if g.Not != nil {
		n++
	}
	if g.GeneratingMode != nil {
		n++
	}
	if g.Flag != "" {
		n++
	}
	if g.Present != "" {
		n++
	}
	if g.Count != nil {
		n++
	}
	if g.Len != nil {
		n++
	}
	if g.LastResultIn != nil {
		n++
	}
	if g.HasVisited != "" {
		n++
	}
	if g.ForkGte != "" {
		n++
	}
	if g.ForkIn != nil {
		n++
	}
	return n
}

func gate1Compare(c *Compare, path string, r *Result) {
	if c.Field == "" {
		r.add("gate1", path+".field", "compare field is required")
	}
	if !compareOps[c.Op] {
		r.add("gate1", path+".op", "invalid op %q", c.Op)
	}
}

func gate1Oracle(o *Oracle, path string, r *Result) {
	if o.Expected != "" && !oracleVerdicts[o.Expected] {
		r.add("gate1", path+".expected", "unknown verdict %q", o.Expected)
	}
	for i, v := range o.MustNot {
		if !oracleVerdicts[v] {
			r.add("gate1", fmt.Sprintf("%s.must_not[%d]", path, i), "unknown verdict %q", v)
		}
	}
	if o.SpecPredicate != "" {
		if err := validatePredicate(o.SpecPredicate, SpecPredicateVars); err != nil {
			r.add("gate1", path+".spec_predicate", "invalid predicate: %v", err)
		}
	}
	if o.Strength != "" && !ruleStrengths[o.Strength] {
		r.add("gate1", path+".strength", "unknown strength %q (want MUST|SHOULD|MAY)", o.Strength)
	}
	if o.ResourceTrend != nil {
		tr := o.ResourceTrend
		if tr.MinSamples != 0 && tr.MinSamples < 2 {
			r.add("gate1", path+".resource_trend.min_samples", "min_samples must be >= 2")
		}
		if tr.MaxTotalMemGrowthMB == nil && tr.MaxCPURatePerSec == nil && tr.MaxAmplificationRatio == nil {
			r.add("gate1", path+".resource_trend", "resource_trend must set at least one bound (mem growth, cpu rate, or amplification)")
		}
	}
}

// ruleStrengths is the set of valid oracle strength tokens.
var ruleStrengths = map[string]bool{"MUST": true, "SHOULD": true, "MAY": true}

// --- Gate 2: reference resolution ---

func gate2References(m *Machine, r *Result, refs refIndex) {
	states := map[string]bool{}
	for _, s := range m.States {
		states[s.Name] = true
	}
	if refs.invariants == nil {
		r.Skipped = append(r.Skipped, "gate2: invariant_refs resolution skipped (invariant_rules.json not found)")
	}
	for i, t := range m.Transitions {
		base := fmt.Sprintf("transitions[%d]", i)
		if t.From != "" && !states[t.From] {
			r.add("gate2", base+".from", "undefined state %q", t.From)
		}
		if t.To != "" && !states[t.To] {
			r.add("gate2", base+".to", "undefined state %q", t.To)
		}
		gate2Action(t.Action, base+".action", r)
		if t.Guard != nil {
			gate2Guard(t.Guard, base+".guard", r)
		}
		if refs.specRules != nil {
			for j, ref := range t.SpecRefs {
				if !refs.specRules[ref] {
					r.add("gate2", fmt.Sprintf("%s.spec_refs[%d]", base, j), "unresolved spec rule %q", ref)
				}
			}
		}
		if t.Oracle != nil && refs.invariants != nil {
			for j, ref := range t.Oracle.InvariantRefs {
				if !refs.invariants[ref] {
					r.add("gate2", fmt.Sprintf("%s.oracle.invariant_refs[%d]", base, j), "unresolved invariant %q", ref)
				}
			}
		}
	}
}

func gate2Action(a Action, path string, r *Result) {
	if a.Mutator != "" && !mutatorNames[a.Mutator] {
		r.add("gate2", path+".mutator", "unknown mutator %q", a.Mutator)
	}
	switch {
	case reqRespProtocolActions[a.Type]:
		if a.Protocol == "" {
			r.add("gate2", path+".protocol", "action %s requires a protocol ID", a.Type)
		} else if !protocolIDSet[a.Protocol] {
			r.add("gate2", path+".protocol", "unknown protocol ID %q", a.Protocol)
		}
	case noProtocolActions[a.Type]:
		if a.Protocol != "" {
			r.add("gate2", path+".protocol", "action %s must not set protocol", a.Type)
		}
	default:
		// gossip topic / ENR selector actions: protocol is free-form but, if a
		// gossip/topic action sets one, it must be non-empty (caught by emptiness
		// only where required). No registry check.
	}
	if a.Payload != nil && a.Payload.Kind == "builder" && a.Payload.Name != "" {
		if !builderNames[a.Payload.Name] {
			r.add("gate2", path+".payload.name", "unknown builder %q", a.Payload.Name)
		}
	}
}

func gate2Guard(g *Guard, path string, r *Result) {
	if g.Flag != "" && !guardFlagFields[g.Flag] {
		r.add("gate2", path+".flag", "unknown flag %q", g.Flag)
	}
	if g.Present != "" && !guardPresentNames[g.Present] {
		r.add("gate2", path+".present", "unknown presence predicate %q", g.Present)
	}
	if g.Count != nil && g.Count.Field != "" && !guardCounterFields[g.Count.Field] {
		r.add("gate2", path+".count.field", "unknown counter field %q", g.Count.Field)
	}
	if g.Len != nil && g.Len.Field != "" && !guardLenFields[g.Len.Field] {
		r.add("gate2", path+".len.field", "unknown length field %q", g.Len.Field)
	}
	for i, code := range g.LastResultIn {
		if _, ok := resultCodeNames[code]; !ok {
			r.add("gate2", fmt.Sprintf("%s.last_result_in[%d]", path, i), "unknown result code %q", code)
		}
	}
	if g.ForkGte != "" && !knownFork(g.ForkGte) {
		r.add("gate2", path+".fork_gte", "unknown fork %q", g.ForkGte)
	}
	for i, f := range g.ForkIn {
		if !knownFork(f) {
			r.add("gate2", fmt.Sprintf("%s.fork_in[%d]", path, i), "unknown fork %q", f)
		}
	}
	for i := range g.And {
		gate2Guard(&g.And[i], fmt.Sprintf("%s.and[%d]", path, i), r)
	}
	for i := range g.Or {
		// Fork atoms inside or/not cannot be extracted into a ForkConstraint.
		if g.Or[i].isForkAtom() {
			r.add("gate2", fmt.Sprintf("%s.or[%d]", path, i), "fork atom not allowed inside 'or'; use it standalone or in a top-level 'and'")
		}
		gate2Guard(&g.Or[i], fmt.Sprintf("%s.or[%d]", path, i), r)
	}
	if g.Not != nil {
		if g.Not.isForkAtom() {
			r.add("gate2", path+".not", "fork atom not allowed inside 'not'; use it standalone or in a top-level 'and'")
		}
		gate2Guard(g.Not, path+".not", r)
	}
}

// --- Gate 3: payload type-check vs Protocol Model ---

func gate3Payload(m *Machine, r *Result, pm *ProtocolModel) {
	if pm == nil {
		r.Skipped = append(r.Skipped, "gate3: payload type-check vs Protocol Model skipped (protocol_model.json not found)")
	}
	for i, t := range m.Transitions {
		p := t.Action.Payload
		if p == nil || p.Kind != "fields" {
			continue
		}
		base := fmt.Sprintf("transitions[%d].action.payload", i)

		// Structural sanity, independent of the Protocol Model: each field value
		// must declare exactly one source.
		for name, fv := range p.Fields {
			if fieldValueSources(fv) != 1 {
				r.add("gate3", fmt.Sprintf("%s.fields[%s]", base, name),
					"field value must set exactly one of lit|ctx|special")
			}
		}

		if pm == nil {
			continue
		}

		// Resolve the method serving this protocol and type-check against it.
		method, ok := pm.method(t.Action.Protocol)
		if !ok {
			r.add("gate3", base, "no Protocol Model entry for protocol %q; cannot type-check fields payload", t.Action.Protocol)
			continue
		}
		switch method.Request.Container {
		case "none":
			r.add("gate3", base, "method %s takes no request body; fields payload is invalid", method.Name)
			continue
		case "variable":
			r.add("gate3", base, "method %s has a variable-length request; use a builder payload, not fields", method.Name)
			continue
		case "fixed":
			// fall through to field checks
		default:
			r.add("gate3", base, "method %s has unknown request container %q", method.Name, method.Request.Container)
			continue
		}

		// Every IR field must exist; type must be compatible with its source.
		for name, fv := range p.Fields {
			f, _, found := method.Request.field(name)
			if !found {
				r.add("gate3", fmt.Sprintf("%s.fields[%s]", base, name),
					"unknown field for method %s", method.Name)
				continue
			}
			if fv.Lit != nil && f.Type != "uint64" {
				r.add("gate3", fmt.Sprintf("%s.fields[%s]", base, name),
					"literal int not valid for %s field (type %s); use ctx or a builder", name, f.Type)
			}
		}
		// Every schema field must be provided (a fixed container needs all fields).
		for _, f := range method.Request.Fields {
			if _, present := p.Fields[f.Name]; !present {
				r.add("gate3", base, "missing field %q required by method %s", f.Name, method.Name)
			}
		}
	}
}

func fieldValueSources(fv FieldValue) int {
	set := 0
	if fv.Lit != nil {
		set++
	}
	if fv.Ctx != "" {
		set++
	}
	if fv.Special != "" {
		set++
	}
	return set
}

// --- Gate 4: well-formedness ---

func gate4WellFormed(m *Machine, r *Result) {
	states := map[string]bool{}
	terminal := map[string]bool{}
	for _, s := range m.States {
		states[s.Name] = true
		if s.Terminal {
			terminal[s.Name] = true
		}
	}
	if m.InitState != "" && !states[m.InitState] {
		r.add("gate4", "init_state", "init_state %q is not a defined state", m.InitState)
	}

	// Duplicate transition labels.
	seenLabel := map[string]int{}
	for i, t := range m.Transitions {
		if t.Label == "" {
			continue
		}
		if prev, ok := seenLabel[t.Label]; ok {
			r.add("gate4", fmt.Sprintf("transitions[%d].label", i),
				"duplicate label %q (first at transitions[%d])", t.Label, prev)
		} else {
			seenLabel[t.Label] = i
		}
	}

	// Terminal states must have no outgoing transitions.
	for i, t := range m.Transitions {
		if terminal[t.From] {
			r.add("gate4", fmt.Sprintf("transitions[%d]", i),
				"transition leaves terminal state %q", t.From)
		}
	}

	// Reachability from init_state (BFS over transitions).
	adj := map[string][]string{}
	for _, t := range m.Transitions {
		adj[t.From] = append(adj[t.From], t.To)
	}
	reached := map[string]bool{}
	if states[m.InitState] {
		queue := []string{m.InitState}
		reached[m.InitState] = true
		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			for _, next := range adj[cur] {
				if states[next] && !reached[next] {
					reached[next] = true
					queue = append(queue, next)
				}
			}
		}
	}
	var unreached []string
	for _, s := range m.States {
		if !reached[s.Name] {
			unreached = append(unreached, s.Name)
		}
	}
	sort.Strings(unreached)
	for _, s := range unreached {
		r.add("gate4", "states", "state %q is unreachable from init_state %q", s, m.InitState)
	}
}

func sortIssues(r *Result) {
	sort.SliceStable(r.Issues, func(i, j int) bool {
		if r.Issues[i].Gate != r.Issues[j].Gate {
			return r.Issues[i].Gate < r.Issues[j].Gate
		}
		return r.Issues[i].Path < r.Issues[j].Path
	})
}
