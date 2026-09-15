package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

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

// TestResolveSpecsDirOrder pins the lookup order of the consensus-specs
// checkout: explicit -specs-dir > $PARALLAX_SPECS > ./consensus-specs/specs
// > ../consensus-specs/specs; empty when nothing exists.
func TestResolveSpecsDirOrder(t *testing.T) {
	t.Setenv("PARALLAX_SPECS", "")
	root := t.TempDir()
	t.Chdir(root)

	if got := resolveSpecsDir(""); got != "" {
		t.Fatalf("no candidates: got %q, want empty", got)
	}
	if got := resolveSpecsDir("/explicit"); got != "/explicit" {
		t.Fatalf("explicit must win: got %q", got)
	}

	local := filepath.Join("consensus-specs", "specs")
	if err := os.MkdirAll(filepath.Join(root, local), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := resolveSpecsDir(""); got != local {
		t.Fatalf("./: got %q, want %q", got, local)
	}

	envDir := filepath.Join(root, "envspecs")
	if err := os.MkdirAll(envDir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PARALLAX_SPECS", envDir)
	if got := resolveSpecsDir(""); got != envDir {
		t.Fatalf("$PARALLAX_SPECS: got %q, want %q", got, envDir)
	}

	// cwd without ./consensus-specs falls back to the sibling checkout.
	os.Setenv("PARALLAX_SPECS", "")
	sub := filepath.Join(root, "elsewhere")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(sub)
	if got := resolveSpecsDir(""); got != filepath.Join("..", "consensus-specs", "specs") {
		t.Fatalf("../: got %q", got)
	}
}

// TestCasesStale pins the auto-regen trigger: generated case files missing,
// or older than the newest knowledge/spec artifact, mean stale.
func TestCasesStale(t *testing.T) {
	root := t.TempDir()
	mk := func(rel string, mod time.Time) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, mod, mod); err != nil {
			t.Fatal(err)
		}
	}

	if !casesStale(root) {
		t.Fatal("missing generated files must be stale")
	}

	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)
	mk("knowledge/spec/rule_ast.json", past)
	mk("cases/spec_ir_generated.go", past)
	mk("cases/spec_ir_stateless_generated.go", past)
	mk("cases/spec_ir_sequences_generated.go", past)
	if casesStale(root) {
		t.Fatal("generated files newer than knowledge must be fresh")
	}

	mk("knowledge/spec/rule_ast.json", future)
	if !casesStale(root) {
		t.Fatal("knowledge newer than generated files must be stale")
	}
}
