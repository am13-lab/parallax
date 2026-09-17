package triage

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAuthEnvFallback(t *testing.T) {
	t.Setenv("GLM_API_KEY", "env-glm-key")
	auth, err := LoadAuth(filepath.Join(t.TempDir(), "auth.json"))
	if err != nil {
		t.Fatal(err)
	}
	if auth == nil {
		t.Fatal("auth must resolve when an env key is set")
	}
	if auth.Default != GLM || auth.Providers[GLM].APIKey != "env-glm-key" {
		t.Fatalf("unexpected auth: %+v", auth)
	}
	if auth.Providers[GLM].Model != DefaultModels[GLM] {
		t.Fatalf("model must default, got %q", auth.Providers[GLM].Model)
	}
}

func TestLoadAuthNone(t *testing.T) {
	for _, env := range EnvVars {
		os.Unsetenv(env)
	}
	auth, err := LoadAuth(filepath.Join(t.TempDir(), "auth.json"))
	if err != nil {
		t.Fatal(err)
	}
	if auth != nil {
		t.Fatalf("no keys must yield nil auth, got %+v", auth)
	}
}

func TestLoadAuthEnvOverridesFile(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "env-openai")
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.json")
	body := `{"default":"glm","providers":{"openai":{"api_key":"file-openai"},"glm":{"api_key":"file-glm","model":"glm-4.6"}}}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	auth, err := LoadAuth(path)
	if err != nil {
		t.Fatal(err)
	}
	if auth.Default != "glm" {
		t.Fatalf("default = %q, want glm", auth.Default)
	}
	// env wins over the persisted file (12-factor convention).
	if auth.Providers[OpenAI].APIKey != "env-openai" {
		t.Fatalf("env key must win over file, got %q", auth.Providers[OpenAI].APIKey)
	}
	if auth.Providers[GLM].APIKey != "file-glm" {
		t.Fatalf("file-only key must survive, got %q", auth.Providers[GLM].APIKey)
	}
}

func TestParseVerdictFenced(t *testing.T) {
	raw := "```json\n{\"verdict\":\"FALSE_POSITIVE\",\"confidence\":0.9,\"filterable\":true,\"reason\":\"harness\",\"spec_anchor\":\"\",\"suggested_action\":\"filter\"}\n```"
	v, err := parseVerdict(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !v.Filterable || v.Verdict != VerdictFalsePositive {
		t.Fatalf("unexpected verdict: %+v", v)
	}
}

func TestParseVerdictProse(t *testing.T) {
	raw := "Sure! Here is my analysis:\n{\"verdict\":\"NEEDS_HUMAN\",\"confidence\":0.4,\"filterable\":false,\"reason\":\"thin evidence\"}\nHope that helps."
	v, err := parseVerdict(raw)
	if err != nil {
		t.Fatal(err)
	}
	if v.Verdict != VerdictNeedsHuman || v.Filterable {
		t.Fatalf("unexpected verdict: %+v", v)
	}
}

func TestSummarize(t *testing.T) {
	results := []Result{
		{Verdict: VerdictRealIssue},
		{Verdict: VerdictFalsePositive, Filterable: true},
		{Verdict: VerdictNeedsHuman},
		{Unavailable: true},
	}
	s := Summarize(results)
	if s.Total != 4 || s.RealIssues != 1 || s.Filterable != 1 || s.NeedsHuman != 1 || s.Unavailable != 1 {
		t.Fatalf("unexpected summary: %+v", s)
	}
}
