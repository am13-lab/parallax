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
	data, err := os.ReadFile(cfg.ReportPath)
	if err != nil {
		return fmt.Errorf("read report: %w", err)
	}
	var rep runner.Report
	if err := json.Unmarshal(data, &rep); err != nil {
		return fmt.Errorf("parse report: %w", err)
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
				provs[name] = map[string]string{"api_key": shown, "model": pa.Model}
			}
		}
		writeJSON(w, masked)
	})
	mux.HandleFunc("POST /api/auth", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Default   string `json:"default"`
			Providers map[string]struct {
				APIKey string `json:"api_key"`
				Model  string `json:"model"`
			} `json:"providers"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad body: "+err.Error(), http.StatusBadRequest)
			return
		}
		// Merge into the persisted auth so saving one provider does not
		// wipe previously saved ones.
		auth, _ := triage.LoadAuth(cfg.AuthPath)
		if auth == nil {
			auth = &triage.Auth{Providers: map[string]triage.ProviderAuth{}}
		}
		for name, pa := range body.Providers {
			if strings.TrimSpace(pa.APIKey) == "" {
				continue
			}
			auth.Providers[name] = triage.ProviderAuth{APIKey: pa.APIKey, Model: pa.Model}
		}
		if len(auth.Providers) == 0 {
			http.Error(w, "no api key in body", http.StatusBadRequest)
			return
		}
		if body.Default != "" {
			auth.Default = body.Default
		}
		if auth.Default == "" {
			for _, order := range []string{triage.GLM, triage.DeepSeek, triage.OpenAI, triage.Claude, triage.Gemini} {
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
	mux.HandleFunc("POST /api/triage", func(w http.ResponseWriter, r *http.Request) {
		auth, err := triage.LoadAuth(cfg.AuthPath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if auth == nil {
			http.Error(w, "no api key configured: set env vars or save auth first", http.StatusBadRequest)
			return
		}
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
		provider := auth.Default
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
	fmt.Fprintf(os.Stdout, "serving %s on http://%s (local only)\n", cfg.ReportPath, cfg.Addr)
	return http.ListenAndServe(cfg.Addr, mux)
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
