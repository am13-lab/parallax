package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// serveReport writes a minimal report.json (zero findings: triage has
// nothing to classify, so the handler exercises provider routing only,
// never the provider HTTP calls).
func serveReport(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// postJSON is a small helper posting a JSON body (nil = empty body).
func postJSON(t *testing.T, mux *http.ServeMux, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var rd *bytes.Reader
	if body == nil {
		rd = bytes.NewReader(nil)
	} else {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rd = bytes.NewReader(b)
	}
	req := httptest.NewRequest(http.MethodPost, path, rd)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// The triage endpoint always runs against the default provider: the one
// configured last. There is no per-run provider selection.
func TestTriageEndpointUsesDefault(t *testing.T) {
	cfg := ServeConfig{ReportPath: serveReport(t), AuthPath: filepath.Join(t.TempDir(), "auth.json")}
	mux, err := newServeMux(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// configure glm, then openai: the last configured one is the default
	if rec := postJSON(t, mux, "/api/auth", map[string]any{
		"default":   "glm",
		"providers": map[string]any{"glm": map[string]string{"api_key": "fake-glm"}},
	}); rec.Code != http.StatusOK {
		t.Fatalf("save glm: %d %s", rec.Code, rec.Body.String())
	}
	if rec := postJSON(t, mux, "/api/auth", map[string]any{
		"default":   "openai",
		"providers": map[string]any{"openai": map[string]string{"api_key": "fake-openai"}},
	}); rec.Code != http.StatusOK {
		t.Fatalf("save openai: %d %s", rec.Code, rec.Body.String())
	}

	t.Run("triage runs the last configured provider", func(t *testing.T) {
		rec := postJSON(t, mux, "/api/triage", nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
		}
		var info map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &info); err != nil {
			t.Fatal(err)
		}
		if info["provider"] != "openai" {
			t.Fatalf("want last configured provider openai, got %v", info["provider"])
		}
	})

	t.Run("no providers at all runs nothing without error", func(t *testing.T) {
		// Fresh auth file and no env keys: nothing configured anywhere.
		for _, e := range []string{"OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY", "DEEPSEEK_API_KEY", "GLM_API_KEY"} {
			t.Setenv(e, "")
		}
		empty := ServeConfig{ReportPath: serveReport(t), AuthPath: filepath.Join(t.TempDir(), "auth.json")}
		emptyMux, err := newServeMux(empty)
		if err != nil {
			t.Fatal(err)
		}
		rec := postJSON(t, emptyMux, "/api/triage", nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
		}
		var info map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &info); err != nil {
			t.Fatal(err)
		}
		// results is null or [] — either way nothing ran.
		if rs, ok := info["results"].([]any); ok && len(rs) != 0 {
			t.Fatalf("triage must not run without any provider: %v", info["results"])
		}
	})
}
