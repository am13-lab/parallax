package triage

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAuthEnvFallback(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("GEMINI_API_KEY", "env-gemini-key")
	auth, err := LoadAuth(filepath.Join(t.TempDir(), "auth.json"))
	if err != nil {
		t.Fatal(err)
	}
	if auth == nil {
		t.Fatal("auth must resolve when an env key is set")
	}
	if auth.Default != Gemini || auth.Providers[Gemini].APIKey != "env-gemini-key" {
		t.Fatalf("unexpected auth: %+v", auth)
	}
	if auth.Providers[Gemini].Model != DefaultModels[Gemini] {
		t.Fatalf("model must default, got %q", auth.Providers[Gemini].Model)
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

func TestLoadAuthFileKeyWinsOverEnv(t *testing.T) {
	// A key saved from the UI is the user's latest intent: it must win
	// over a stale env var on the same machine.
	t.Setenv("OPENAI_API_KEY", "stale-env-key")
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.json")
	body := `{"default":"claude","providers":{"openai":{"api_key":"file-openai"},"claude":{"api_key":"file-claude","model":"claude-sonnet-4-5"}}}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	auth, err := LoadAuth(path)
	if err != nil {
		t.Fatal(err)
	}
	if auth.Default != "claude" {
		t.Fatalf("default = %q, want claude", auth.Default)
	}
	if auth.Providers[OpenAI].APIKey != "file-openai" {
		t.Fatalf("file key must win over env, got %q", auth.Providers[OpenAI].APIKey)
	}
	if auth.Providers[Claude].APIKey != "file-claude" {
		t.Fatalf("file-only key must survive, got %q", auth.Providers[Claude].APIKey)
	}
	// env still fills in providers the file knows nothing about.
	t.Setenv("GEMINI_API_KEY", "env-gemini")
	auth2, err := LoadAuth(filepath.Join(t.TempDir(), "auth2.json"))
	if err != nil {
		t.Fatal(err)
	}
	if auth2.Providers[Gemini].APIKey != "env-gemini" {
		t.Fatalf("env must fill providers missing from the file, got %+v", auth2.Providers)
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
