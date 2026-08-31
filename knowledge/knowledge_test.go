package knowledge_test

import (
	"testing"

	"parallax/knowledge"
)

func TestLoadSpecRules(t *testing.T) {
	kb, err := knowledge.Load("../knowledge")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := len(kb.SpecRules()); got < 500 {
		t.Fatalf("expected the 534-rule spec catalog, got %d", got)
	}

	e, ok := kb.ResolveSpec("ATTESTER_SLASHING-IGNORE-647ecfb9")
	if !ok {
		t.Fatal("catalog entry must resolve")
	}
	if e.Text == "" || e.Strength == "" {
		t.Fatalf("entry must carry text and strength: %+v", e)
	}

	// Legacy SPEC-* IDs resolve through the legacy map.
	if _, ok := kb.ResolveSpec("SPEC-AGG-001"); !ok {
		t.Fatal("legacy SPEC-* IDs must resolve")
	}
}

func TestResolveExternalAnchors(t *testing.T) {
	kb, err := knowledge.Load("../knowledge")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	for _, id := range []string{
		"SHERLOCK-1140-004",
		"RETH-25",
		"CL-2020-01",
		"PROSE-SHOULD-d2397b37",
		"GSR-06",
	} {
		e, ok := kb.Resolve(id)
		if !ok {
			t.Fatalf("anchor %s must resolve", id)
		}
		if e.Title == "" || e.Path == "" {
			t.Fatalf("anchor %s must carry title and path: %+v", id, e)
		}
	}
}

func TestUnresolvedAnchorPrefix(t *testing.T) {
	kb, err := knowledge.Load("../knowledge")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if _, ok := kb.Resolve("NOT-A-SOURCE-1"); ok {
		t.Fatal("unknown anchor prefix must not resolve")
	}
}
