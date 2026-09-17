// Package triage runs LLM-based triage over differential findings: given
// API credentials it classifies each finding as a real issue or as
// filterable noise, so the final report can say what needs human attention
// and what does not. Without credentials the package is inert and the
// report is produced exactly as before.
package triage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Provider names for the supported model vendors.
const (
	OpenAI = "openai"
	Claude = "claude"
	Gemini = "gemini"
)

// EnvVars maps provider name -> conventional API key environment variable.
var EnvVars = map[string]string{
	OpenAI: "OPENAI_API_KEY",
	Claude: "ANTHROPIC_API_KEY",
	Gemini: "GEMINI_API_KEY",
}

// DefaultModels is the fallback model per provider when auth.json does not
// pin one.
var DefaultModels = map[string]string{
	OpenAI: "gpt-4o-mini",
	Claude: "claude-sonnet-4-5",
	Gemini: "gemini-2.0-flash",
}

// baseURLs for OpenAI-compatible endpoints (Claude uses the native
// Messages API and has its own client path).
const (
	openAIBase    = "https://api.openai.com/v1"
	geminiBase    = "https://generativelanguage.googleapis.com/v1beta/openai"
	anthropicBase = "https://api.anthropic.com/v1"
)

// ProviderAuth is one provider's resolved credential set. Endpoint is an
// optional base-URL override for relay/proxy services; empty selects the
// provider's well-known endpoint.
type ProviderAuth struct {
	APIKey   string `json:"api_key"`
	Model    string `json:"model,omitempty"`
	Endpoint string `json:"endpoint,omitempty"`
}

// effectiveBase returns the endpoint to call: the credential's explicit
// override (relay services) when set, the well-known default otherwise.
func effectiveBase(pa ProviderAuth, def string) string {
	if b := strings.TrimSpace(pa.Endpoint); b != "" {
		return strings.TrimRight(b, "/")
	}
	return def
}

// Auth is the persisted credential file (auth.json). Keys may also come
// from environment variables; the file wins so a checked-in default can be
// overridden per machine.
type Auth struct {
	Default   string                  `json:"default,omitempty"`
	Providers map[string]ProviderAuth `json:"providers"`
}

// LoadAuth resolves triage credentials: env vars first (by provider), then
// authPath (auth.json). Returns nil when no provider has a key — triage is
// skipped entirely in that case, which is the no-credential default.
func LoadAuth(authPath string) (*Auth, error) {
	auth := &Auth{Providers: map[string]ProviderAuth{}}
	if b, err := os.ReadFile(authPath); err == nil {
		if err := json.Unmarshal(b, auth); err != nil {
			return nil, fmt.Errorf("parse %s: %w", authPath, err)
		}
	}
	// A key saved to the file is the user's latest intent and wins over
	// the environment; env vars only fill providers the file is missing.
	for name, env := range EnvVars {
		if v := strings.TrimSpace(os.Getenv(env)); v != "" {
			pa := auth.Providers[name]
			if pa.APIKey == "" {
				pa.APIKey = v
			}
			if pa.Model == "" {
				pa.Model = DefaultModels[name]
			}
			auth.Providers[name] = pa
		}
	}
	for name, pa := range auth.Providers {
		if pa.Model == "" {
			pa.Model = DefaultModels[name]
		}
		auth.Providers[name] = pa
	}
	if len(auth.Providers) == 0 {
		return nil, nil
	}
	if auth.Default == "" || auth.Providers[auth.Default].APIKey == "" {
		auth.Default = firstWithKey(auth.Providers, []string{OpenAI, Claude, Gemini})
	}
	if auth.Default == "" {
		return nil, nil
	}
	return auth, nil
}

func firstWithKey(m map[string]ProviderAuth, order []string) string {
	for _, name := range order {
		if m[name].APIKey != "" {
			return name
		}
	}
	for _, name := range sortedProviderNames(m) {
		if m[name].APIKey != "" {
			return name
		}
	}
	return ""
}

func sortedProviderNames(m map[string]ProviderAuth) []string {
	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k)
	}
	for i := 1; i < len(names); i++ {
		for j := i; j > 0 && names[j] < names[j-1]; j-- {
			names[j], names[j-1] = names[j-1], names[j]
		}
	}
	return names
}

// SaveAuth writes auth.json with 0600 permissions next to the given path.
func SaveAuth(authPath string, auth *Auth) error {
	if dir := filepath.Dir(authPath); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	b, err := json.MarshalIndent(auth, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(authPath, append(b, '\n'), 0o600)
}
