package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"

	"parallax/internal/triage"
	"parallax/report"
	"parallax/runner"
)

// ServeConfig carries the `serve` subcommand options.
type ServeConfig struct {
	ReportPath string
	AuthPath   string
	Addr       string
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cfg := ServeConfig{}
	fs.StringVar(&cfg.ReportPath, "report", "", "path to report.json (required)")
	fs.StringVar(&cfg.AuthPath, "auth", "auth.json", "path to the persisted auth.json")
	fs.StringVar(&cfg.Addr, "addr", "127.0.0.1:8080", "listen address (local only)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if cfg.ReportPath == "" {
		return fmt.Errorf("-report is required")
	}
	mux, err := newServeMux(cfg)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "serving %s on http://%s (local only)\n", cfg.ReportPath, cfg.Addr)
	return http.ListenAndServe(cfg.Addr, mux)
}

// newServeMux builds the serve endpoints: the report page, auth
// persistence and the triage runner.
func newServeMux(cfg ServeConfig) (*http.ServeMux, error) {
	data, err := os.ReadFile(cfg.ReportPath)
	if err != nil {
		return nil, fmt.Errorf("read report: %w", err)
	}
	var rep runner.Report
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, fmt.Errorf("parse report: %w", err)
	}
	findings := report.BuildFindings(&rep, false)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		historyDir, dirErr := report.HistoryDir()
		if dirErr != nil {
			historyDir = ""
		}
		runs, err := report.CollectRuns(&rep, findings, historyDir, 20)
		if err != nil {
			http.Error(w, "render: "+err.Error(), http.StatusInternalServerError)
			return
		}
		ruleTexts, ruleLinks := loadRuleInfo(&rep, runs)
		htmlData, err := report.WriteHTMLRuns(runs, 0, ruleTexts, ruleLinks)
		if err != nil {
			http.Error(w, "render: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(htmlData)
	})
	mux.HandleFunc("GET /api/auth", func(w http.ResponseWriter, r *http.Request) {
		auth, err := triage.LoadAuth(cfg.AuthPath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		masked := map[string]any{"providers": map[string]any{}}
		if auth != nil {
			masked["default"] = auth.Default
			provs := masked["providers"].(map[string]any)
			for name, pa := range auth.Providers {
				if pa.APIKey == "" {
					continue
				}
				k := pa.APIKey
				shown := k
				if len(k) > 10 {
					shown = k[:6] + "..." + k[len(k)-4:]
				}
				provs[name] = map[string]string{"api_key": shown, "model": pa.Model, "endpoint": pa.Endpoint}
			}
		}
		writeJSON(w, masked)
	})
	mux.HandleFunc("POST /api/auth", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Default   string `json:"default"`
			Providers map[string]struct {
				APIKey   string `json:"api_key"`
				Model    string `json:"model"`
				Endpoint string `json:"endpoint"`
			} `json:"providers"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad body: "+err.Error(), http.StatusBadRequest)
			return
		}
		// Merge into the persisted auth so saving one provider does not
		// wipe previously saved ones. A provider entry with an empty key
		// still updates model/endpoint — the model picker saves that way —
		// and never clobbers the stored key.
		auth, _ := triage.LoadAuth(cfg.AuthPath)
		if auth == nil {
			auth = &triage.Auth{Providers: map[string]triage.ProviderAuth{}}
		}
		updated := 0
		for name, pa := range body.Providers {
			cur := auth.Providers[name]
			changed := false
			if v := strings.TrimSpace(pa.APIKey); v != "" {
				cur.APIKey = v
				changed = true
			}
			if v := strings.TrimSpace(pa.Model); v != "" && v != cur.Model {
				cur.Model = v
				changed = true
			}
			if v := strings.TrimSpace(pa.Endpoint); v != "" && v != cur.Endpoint {
				cur.Endpoint = v
				changed = true
			}
			if changed {
				auth.Providers[name] = cur
				updated++
			}
		}
		if updated == 0 {
			http.Error(w, "nothing to save: provide an api key, model or endpoint", http.StatusBadRequest)
			return
		}
		if body.Default != "" {
			auth.Default = body.Default
		}
		if auth.Default == "" {
			for _, order := range []string{triage.OpenAI, triage.Claude, triage.Gemini} {
				if auth.Providers[order].APIKey != "" {
					auth.Default = order
					break
				}
			}
		}
		if err := triage.SaveAuth(cfg.AuthPath, auth); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{"saved": cfg.AuthPath, "default": auth.Default})
	})
	mux.HandleFunc("GET /api/models", func(w http.ResponseWriter, r *http.Request) {
		provider := r.URL.Query().Get("provider")
		if provider == "" {
			http.Error(w, "provider query parameter is required", http.StatusBadRequest)
			return
		}
		auth, err := triage.LoadAuth(cfg.AuthPath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		pa, ok := auth.Providers[provider]
		if !ok || pa.APIKey == "" {
			http.Error(w, fmt.Sprintf("provider %q has no api key configured; save one first", provider), http.StatusBadRequest)
			return
		}
		models, err := triage.ListModels(r.Context(), provider, pa)
		if err != nil {
			writeJSON(w, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, map[string]any{"provider": provider, "models": models})
	})
	mux.HandleFunc("POST /api/triage", func(w http.ResponseWriter, r *http.Request) {
		auth, err := triage.LoadAuth(cfg.AuthPath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if auth == nil {
			// No provider configured anywhere: no triage, no error.
			writeJSON(w, triage.Info("", "", nil))
			return
		}
		provider := auth.Default
		inputs := make([]triage.Input, 0, len(findings))
		for _, f := range findings {
			if f.Suppressed {
				continue
			}
			in := triage.Input{
				ID:             f.ID,
				RootCause:      f.RootCause,
				Type:           string(f.Type),
				Severity:       string(f.Severity),
				OutlierClients: f.OutlierClients,
			}
			for _, ev := range f.Evidence {
				in.TestIDs = append(in.TestIDs, ev.TestID)
				in.Details = append(in.Details, ev.Description)
				if len(in.Details) >= maxEvidenceForTriage {
					break
				}
			}
			inputs = append(inputs, in)
		}
		results := triage.Triage(r.Context(), auth, provider, inputs)
		info := triage.Info(provider, auth.Providers[provider].Model, results)
		blob, err := json.Marshal(info)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		rep.Triage = blob
		if err := persistReportTriage(cfg.ReportPath, blob); err != nil {
			fmt.Fprintf(os.Stderr, "warn: persist triage: %v\n", err)
		}
		writeJSON(w, info)
	})
	return mux, nil
}

// persistReportTriage merges the triage section into the saved report.json
// so the analysis survives page reloads without re-running tests.
func persistReportTriage(reportPath string, triageBlob json.RawMessage) error {
	data, err := os.ReadFile(reportPath)
	if err != nil {
		return err
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	m["triage"] = triageBlob
	out, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return os.WriteFile(reportPath, out, 0o644)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
