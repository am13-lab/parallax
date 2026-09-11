package main

import "testing"

// TestApplySuite verifies the tier-to-selection translation.
func TestApplySuite(t *testing.T) {
	t.Run("quick uses the manifest", func(t *testing.T) {
		rc := RunConfig{}
		applySuite("quick", &rc)
		if len(rc.TestIDs) == 0 {
			t.Fatal("quick must set TestIDs to the manifest")
		}
	})

	t.Run("standard excludes IR", func(t *testing.T) {
		rc := RunConfig{}
		applySuite("standard", &rc)
		found := false
		for _, p := range rc.ExcludePrefixes {
			if p == "ir." {
				found = true
			}
		}
		if !found {
			t.Fatalf("standard must exclude IR prefixes, got %v", rc.ExcludePrefixes)
		}
	})

	t.Run("standard preserves explicit exclusions", func(t *testing.T) {
		rc := RunConfig{ExcludePrefixes: []string{"statemachine"}}
		applySuite("standard", &rc)
		hasIR, hasSM := false, false
		for _, p := range rc.ExcludePrefixes {
			if p == "ir." {
				hasIR = true
			}
			if p == "statemachine" {
				hasSM = true
			}
		}
		if !hasIR || !hasSM {
			t.Fatalf("explicit exclusions must be preserved: %v", rc.ExcludePrefixes)
		}
	})

	t.Run("full excludes nothing", func(t *testing.T) {
		rc := RunConfig{}
		applySuite("full", &rc)
		if len(rc.ExcludePrefixes) != 0 || len(rc.TestIDs) != 0 {
			t.Fatalf("full must not filter, got prefixes=%v testIDs=%v", rc.ExcludePrefixes, rc.TestIDs)
		}
	})
}
