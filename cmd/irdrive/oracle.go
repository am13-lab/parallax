package main

// oracle.go — Layer D3. Deterministic oracle synthesis from a rule's modal +
// the emitter-chosen expected verdict. The full AST failure predicate is carried
// in the transition description (set by the emitter); spec_predicate here is the
// down-projection onto the runtime's observable env.

// strengthOf maps an RFC-2119 modal to the oracle strength enum.
func strengthOf(modal string) string {
	switch modal {
	case "MUST", "MUST_NOT", "REQUIRED":
		return "MUST"
	case "SHOULD", "SHOULD_NOT", "RECOMMENDED":
		return "SHOULD"
	case "MAY", "MAY_NOT":
		return "MAY"
	}
	return "MUST"
}

// synthOracle builds the oracle for a rule-derived transition. `expected` is the
// spec-mandated verdict the emitter chose (e.g. "REJECT", "INVALID_REQUEST",
// "SUCCESS", or "" for advisory). A hard expected is only asserted for MUST-class
// rules; SHOULD/MAY become differential-only advisories. CRASH is always in
// must_not.
func synthOracle(modal, expected string) *irOracle {
	strength := strengthOf(modal)
	o := &irOracle{Differential: true, Strength: strength, MustNot: []string{"CRASH"}}
	if strength != "MUST" || expected == "" {
		return o // advisory: cross-client differential + crash guard only
	}
	o.Expected = expected
	switch expected {
	case "REJECT", "INVALID_REQUEST":
		o.MustNot = append(o.MustNot, "ACCEPT")
		o.SpecPredicate = "accepted == 0"
	case "SUCCESS":
		// backbone/positive path; crash guard suffices.
	}
	return o
}

// backboneOracle is the oracle for a structural positive-path transition (send a
// valid message). Not tied to a single rule; judged differentially + crash-guarded.
func backboneOracle() *irOracle {
	return &irOracle{Differential: true, Expected: "SUCCESS", MustNot: []string{"CRASH"}}
}
