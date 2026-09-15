package runner

import (
	"testing"
	"time"
)

// TestCanRecoverZeroDisables pins the §5.4 contract: RecoveryCooldown == 0
// disables recovery entirely; a positive cooldown allows exactly one probe
// per cooldown window once the ban age exceeds the cooldown.
func TestCanRecoverZeroDisables(t *testing.T) {
	b := &banState{
		consecutive:     map[string]int{},
		bannedAt:        map[string]time.Time{},
		lastRecoveryTry: map[string]time.Time{},
	}
	b.bannedAt["a"] = time.Now().Add(-2 * time.Hour)

	if b.canRecover("a", 0) {
		t.Fatal("cooldown 0 must disable recovery (DESIGN §5.4)")
	}
	if !b.canRecover("a", time.Hour) {
		t.Fatal("positive cooldown past the ban age must allow one probe")
	}
	if b.canRecover("a", time.Hour) {
		t.Fatal("second probe within the cooldown must be throttled")
	}
}
