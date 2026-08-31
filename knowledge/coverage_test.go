package knowledge_test

import (
	"testing"

	"parallax/cases"
	"parallax/knowledge"
)

// TestCaseAnchorsResolve fails on any dangling KnowledgeID: every anchor a
// case declares must resolve against the knowledge base, so traceability
// never degenerates into decorative strings.
func TestCaseAnchorsResolve(t *testing.T) {
	kb, err := knowledge.Load("../knowledge")
	if err != nil {
		t.Fatalf("load knowledge base: %v", err)
	}
	for _, s := range cases.All() {
		for _, id := range s.Metadata.KnowledgeIDs {
			if _, ok := kb.Resolve(id); !ok {
				t.Errorf("case %s: dangling knowledge anchor %q", s.ID, id)
			}
		}
	}
}

// TestSpecCatalogCoversTrafficObservableRules pins the catalog's shape so a
// corrupted migration fails loudly.
func TestSpecCatalogCoversTrafficObservableRules(t *testing.T) {
	kb, err := knowledge.Load("../knowledge")
	if err != nil {
		t.Fatalf("load knowledge base: %v", err)
	}
	observable := 0
	protocols := map[string]bool{}
	for _, e := range kb.SpecRules() {
		if e.ObservableInTraffic {
			observable++
		}
		if e.Protocol != "" {
			protocols[e.Protocol] = true
		}
	}
	if observable == 0 || len(protocols) < 5 {
		t.Fatalf("spec catalog suspiciously small: %d observable rules across %d protocols",
			observable, len(protocols))
	}
}
