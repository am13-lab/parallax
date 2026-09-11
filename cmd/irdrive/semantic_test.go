package main

import (
	"reflect"
	"testing"
)

func semTestMachine() semanticMachineTemplate {
	return semanticMachineTemplate{
		Name: "GossipValidation",
		Transitions: []irTransition{
			{Label: "probe_a", Action: &irAction{}},
			{Label: "rule_a", SpecRefs: []string{"PROSE-SHOULD-bb"}},
			{Label: "rule_b", SpecRefs: []string{"ETH2-SHOULD-aa", "PROSE-SHOULD-bb"}},
		},
	}
}

// TestSemanticTransitionInheritsMachineRuleSet verifies that probe
// transitions without a rule binding inherit the machine's full rule set:
// they exercise the composition of the rules the machine covers, so the
// report anchors them to that rule group instead of showing no spec match.
func TestSemanticTransitionInheritsMachineRuleSet(t *testing.T) {
	mt := semTestMachine()
	b := semanticBindingTemplate{From: "A", To: "B", LabelPrefix: "sem_gossip"}
	base := mt.Transitions[0] // probe with no SpecRefs
	p := executionPlan{RuleID: ""}

	tr := semanticTransitionFromPlan(mt, b, base, p, "")

	want := []string{"ETH2-SHOULD-aa", "PROSE-SHOULD-bb"}
	if !reflect.DeepEqual(tr.SpecRefs, want) {
		t.Fatalf("SpecRefs = %v, want %v", tr.SpecRefs, want)
	}
}

// TestSemanticTransitionKeepsBoundRule verifies a plan bound to a concrete
// rule keeps exactly that rule.
func TestSemanticTransitionKeepsBoundRule(t *testing.T) {
	mt := semTestMachine()
	b := semanticBindingTemplate{From: "A", To: "B", LabelPrefix: "sem_gossip"}
	base := mt.Transitions[0]
	p := executionPlan{RuleID: "PROSE-SHOULD-cc"}

	tr := semanticTransitionFromPlan(mt, b, base, p, "")

	if !reflect.DeepEqual(tr.SpecRefs, []string{"PROSE-SHOULD-cc"}) {
		t.Fatalf("SpecRefs = %v, want [PROSE-SHOULD-cc]", tr.SpecRefs)
	}
}
