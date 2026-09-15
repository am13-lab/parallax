package cases

import (
	"strings"
	"testing"
)

// TestCryptomsgCasesOwnTheirCategory pins the drift-review fix: the 81
// cryptomsg.* cases were built via exchangeSpec and silently inherited its
// hardcoded "reqresp" category, so -category reqresp pulled in the whole
// polluting sweep and -category cryptomsg matched nothing. They must own
// the "cryptomsg" category (already listed in pollutingCategories).
func TestCryptomsgCasesOwnTheirCategory(t *testing.T) {
	specs := generatedCryptomsgSpecs()
	if len(specs) == 0 {
		t.Fatal("no cryptomsg specs generated")
	}
	for _, s := range specs {
		if s.Category != "cryptomsg" {
			t.Fatalf("%s: category %q, want %q (exchangeSpec default leaked)", s.ID, s.Category, "cryptomsg")
		}
	}
	// The smgen-generated corpus already uses Category "cryptomsg" for
	// ir_stateless.cryptomsg.* / ir_seq.cryptomsg.*; every hand-written
	// cryptomsg.* case must agree.
	for _, s := range All() {
		if strings.HasPrefix(s.ID, "cryptomsg.") && s.Category != "cryptomsg" {
			t.Fatalf("%s: category %q, want %q", s.ID, s.Category, "cryptomsg")
		}
	}
}
