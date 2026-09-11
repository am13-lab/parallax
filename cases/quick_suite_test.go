package cases

import "testing"

// TestQuickSuite verifies the quick-suite manifest: every listed ID must
// exist in the registry, and the list must cover the main families
// without duplicates.
func TestQuickSuite(t *testing.T) {
	ids := QuickSuite()
	if len(ids) == 0 {
		t.Fatal("quick suite is empty")
	}
	all := map[string]bool{}
	for _, s := range All() {
		all[s.ID] = true
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			t.Errorf("duplicate quick-suite id: %s", id)
		}
		seen[id] = true
		if !all[id] {
			t.Errorf("quick-suite id %q not in registry", id)
		}
	}
	// coverage: the suite must touch each major family at least once
	families := map[string]bool{
		"reqresp.": false, "cryptomsg.": false, "gossip": false,
		"discovery": false, "transport": false, "semantic_valid": false,
		"statemachine": false,
	}
	for _, id := range ids {
		for fam := range families {
			if len(id) >= len(fam) && id[:len(fam)] == fam {
				families[fam] = true
			}
		}
	}
	for fam, covered := range families {
		if !covered {
			t.Errorf("quick suite does not cover family %q", fam)
		}
	}
}
