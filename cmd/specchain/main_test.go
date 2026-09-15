package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestStageArtsComplete pins the drift-review fix: every stage must track
// ALL artifacts it produces (and those artifacts must exist in the repo),
// otherwise `specchain status` reports freshness while being blind to
// files that silently went stale.
func TestStageArtsComplete(t *testing.T) {
	root, err := filepath.Abs("../..") // test CWD is the package dir
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		"spec": {
			"knowledge/spec/rule_ast.json",
			"knowledge/spec/spec_rules_generated.json",
			"knowledge/spec/protocol_model.json",
		},
		"ir": {
			"knowledge/ir/ir_coverage_gaps.json",
			"knowledge/ir/stateless_tests_generated.json",
			"knowledge/ir/sequence_tests_generated.json",
			"knowledge/ir/sm_ir_generated",
		},
		"cases": {
			"cases/spec_ir_generated.go",
			"cases/spec_ir_machines_generated.go",
			"cases/spec_ir_stateless_generated.go",
			"cases/spec_ir_sequences_generated.go",
		},
	}
	for stage, arts := range want {
		have := stageArts[stage]
		if len(have) == 0 {
			t.Fatalf("stage %q has no tracked artifacts", stage)
		}
		for _, a := range arts {
			if _, err := os.Stat(filepath.Join(root, a)); err != nil {
				t.Fatalf("stage %q artifact %q does not exist: %v", stage, a, err)
			}
			found := false
			for _, h := range have {
				if h == a {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("stage %q is blind to artifact %q (missing from stageArts)", stage, a)
			}
		}
	}
}
