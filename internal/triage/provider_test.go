package triage

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Authentication failures must surface as a single English hint: the
// upstream response body (which may be localized) must not leak into
// per-finding error strings.
func TestPostJSONAuthErrorSanitized(t *testing.T) {
	for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
			_, _ = w.Write([]byte(`{"error":{"code":"401","message":"令牌已过期或验证不正确"}}`))
		}))
		_, err := postJSON(context.Background(), srv.URL, "bad-key", []byte(`{}`), false)
		srv.Close()
		if err == nil {
			t.Fatalf("HTTP %d: want error", code)
		}
		if !strings.Contains(err.Error(), "authentication failed") {
			t.Fatalf("HTTP %d: error must be the sanitized English hint, got %q", code, err)
		}
		if strings.Contains(err.Error(), "令牌") {
			t.Fatalf("HTTP %d: upstream body must not leak: %q", code, err)
		}
	}
}

// Other non-200 responses keep the truncated upstream body for diagnosis.
func TestPostJSONOtherErrorKeepsBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`upstream exploded`))
	}))
	defer srv.Close()
	_, err := postJSON(context.Background(), srv.URL, "k", []byte(`{}`), false)
	if err == nil || !strings.Contains(err.Error(), "upstream exploded") {
		t.Fatalf("non-auth error must keep the body, got %v", err)
	}
}

// ListModels returns the provider's model ids sorted, speaking each
// provider's auth dialect (Bearer for OpenAI, x-api-key for Claude), and
// honors the credential's base URL override (relay endpoints).
func TestListModels(t *testing.T) {
	var gotAuth, gotPath, gotAccept, gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		gotAccept = r.Header.Get("Accept")
		gotUA = r.Header.Get("User-Agent")
		if r.Header.Get("x-api-key") != "" {
			gotAuth = "x-api-key:" + r.Header.Get("x-api-key")
		}
		w.Write([]byte(`{"data":[{"id":"gpt-4o-mini"},{"id":"gpt-4o"},{"id":"o3"}]}`))
	}))
	defer srv.Close()

	tests := []struct {
		provider string
		wantAuth string
	}{
		{"openai", "Bearer k-openai"},
		{"claude", "x-api-key:k-claude"},
	}
	for _, tc := range tests {
		t.Run(tc.provider, func(t *testing.T) {
			models, err := ListModels(context.Background(), tc.provider, ProviderAuth{
				APIKey:   "k-" + tc.provider,
				Endpoint: srv.URL,
			})
			if err != nil {
				t.Fatal(err)
			}
			if gotPath != "/models" {
				t.Fatalf("request path: %s", gotPath)
			}
			if gotAuth != tc.wantAuth {
				t.Fatalf("auth header: got %q want %q", gotAuth, tc.wantAuth)
			}
			if gotAccept != "application/json" {
				t.Fatalf("Accept header must be application/json, got %q", gotAccept)
			}
			if gotUA != "parallax-triage/1.0" {
				t.Fatalf("UA must identify the client (some relays reject the Go default), got %q", gotUA)
			}
			want := []string{"gpt-4o", "gpt-4o-mini", "o3"} // sorted
			if len(models) != len(want) || models[0] != want[0] || models[2] != want[2] {
				t.Fatalf("models: got %v want %v", models, want)
			}
		})
	}
}

func TestListModelsAuthErrorSanitized(t *testing.T) {
	_, err := ListModels(context.Background(), "openai", ProviderAuth{
		APIKey:   "bad",
		Endpoint: cheapServer(t, http.StatusUnauthorized, `{"error":{"message":"令牌已过期"}}`),
	})
	if err == nil || !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("want sanitized auth error, got %v", err)
	}
	if strings.Contains(err.Error(), "令牌") {
		t.Fatalf("upstream body must not leak: %v", err)
	}
}

func TestListModelsUnsupportedProvider(t *testing.T) {
	if _, err := ListModels(context.Background(), "glm", ProviderAuth{}); err == nil {
		t.Fatal("unsupported provider must error")
	}
}

// A 404/405 from a relay that does not implement the models path must
// surface as a clean English hint, not the upstream error body.
func TestListModelsNotFoundHint(t *testing.T) {
	for _, code := range []int{http.StatusNotFound, http.StatusMethodNotAllowed} {
		_, err := ListModels(context.Background(), "claude", ProviderAuth{
			APIKey:   "k",
			Endpoint: cheapServer(t, code, `{"error":{"message":"Method Not Allowed"}}`),
		})
		if err == nil || !strings.Contains(err.Error(), "model listing not supported") {
			t.Fatalf("HTTP %d: want clean hint, got %v", code, err)
		}
		if strings.Contains(err.Error(), "Method Not Allowed") {
			t.Fatalf("HTTP %d: upstream body must not leak: %v", code, err)
		}
	}
}

func cheapServer(t *testing.T, code int, body string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(code)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}
