// Package report serializes run reports: canonical JSON, JUnit XML for CI,
// findings dedup with allowlist suppression, and a legacy-shape adapter.
package report

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"path/filepath"
	"sort"
	"time"

	"libp2p-difftest/runner"
)

// Finding groups divergences that share the same root cause.
type Finding struct {
	ID             string             `json:"id"`
	RootCause      string             `json:"root_cause"`
	OutlierClients []string           `json:"outlier_clients"`
	Type           runner.DivergenceType `json:"type"`
	Severity       runner.Severity    `json:"severity"`
	EvidenceCount  int                `json:"evidence_count"`
	Evidence       []runner.Divergence `json:"evidence"`
	Suppressed     bool               `json:"suppressed,omitempty"`
	SuppressReason string             `json:"suppress_reason,omitempty"`
}

const maxEvidencePerFinding = 5

// WriteJSON renders the canonical report.
func WriteJSON(rep *runner.Report) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(rep); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ---- JUnit ----

type junitSuites struct {
	XMLName xml.Name      `xml:"testsuites"`
	Suites  []junitSuite  `xml:"testsuite"`
}

type junitSuite struct {
	Name     string       `xml:"name,attr"`
	Tests    int          `xml:"tests,attr"`
	Failures int          `xml:"failures,attr"`
	Skipped  int          `xml:"skipped,attr"`
	Cases    []junitCase  `xml:"testcase"`
}

type junitCase struct {
	Name      string        `xml:"name,attr"`
	ClassName string        `xml:"classname,attr"`
	Time      string        `xml:"time,attr"`
	Failure   *junitFailure `xml:"failure,omitempty"`
	Skipped   *junitSkipped `xml:"skipped,omitempty"`
}

type junitFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Body    string `xml:",chardata"`
}

type junitSkipped struct {
	Message string `xml:"message,attr"`
}

// WriteJUnit renders the report as JUnit XML: one testsuite per category,
// one testcase per result. Divergent results become failures; error results
// become typed failures; skipped results become skipped.
func WriteJUnit(rep *runner.Report) ([]byte, error) {
	byCat := map[string][]runner.TestResult{}
	var order []string
	for _, r := range rep.Results {
		if _, ok := byCat[r.Category]; !ok {
			order = append(order, r.Category)
		}
		byCat[r.Category] = append(byCat[r.Category], r)
	}
	sort.Slice(order, func(i, j int) bool { return order[i] < order[j] })

	var suites []junitSuite
	for _, cat := range order {
		rs := byCat[cat]
		suite := junitSuite{Name: cat, Tests: len(rs)}
		for _, r := range rs {
			tc := junitCase{
				Name:      r.TestID,
				ClassName: cat,
				Time:      r.Elapsed,
			}
			switch r.Status {
			case runner.StatusDivergent:
				suite.Failures++
				var msgs []string
				for _, d := range r.Divergences {
					msgs = append(msgs, fmt.Sprintf("[%s/%s] %s | results: %v",
						d.Type, d.Severity, d.Description, d.ClientResults))
				}
				tc.Failure = &junitFailure{
					Message: fmt.Sprintf("%d divergence(s)", len(r.Divergences)),
					Type:    "divergence",
					Body:    joinLines(msgs),
				}
			case runner.StatusSkipped:
				suite.Skipped++
				tc.Skipped = &junitSkipped{Message: r.SkipReason}
			case runner.StatusError:
				suite.Failures++
				tc.Failure = &junitFailure{Message: "test execution error", Type: "error", Body: r.SkipReason}
			}
			suite.Cases = append(suite.Cases, tc)
		}
		suites = append(suites, suite)
	}

	out, err := xml.MarshalIndent(junitSuites{Suites: suites}, "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header+"\n"), out...), nil
}

func joinLines(lines []string) string {
	var buf bytes.Buffer
	for _, l := range lines {
		buf.WriteString(l)
		buf.WriteString("\n")
	}
	return buf.String()
}

// ---- Findings dedup ----

// BuildFindings groups a report's divergences into findings by root cause
// (divergence type plus description) and majority/minority client set.
func BuildFindings(rep *runner.Report, aggressive bool) []Finding {
	type key struct {
		typ      runner.DivergenceType
		cause    string
		outliers string
	}
	groups := map[key]*Finding{}
	var order []key

	for _, r := range rep.Results {
		for _, d := range r.Divergences {
			outliers := append([]string{}, d.OutlierClients...)
			sort.Strings(outliers)
			k := key{typ: d.Type, cause: d.Description, outliers: fmt.Sprint(outliers)}
			if aggressive {
				k.outliers = ""
			}
			f, ok := groups[k]
			if !ok {
				f = &Finding{
					ID:             fmt.Sprintf("F-%s-%d", k.typ, len(groups)+1),
					RootCause:      d.Description,
					OutlierClients: outliers,
					Type:           d.Type,
					Severity:       d.Severity,
				}
				groups[k] = f
				order = append(order, k)
			}
			f.EvidenceCount++
			if len(f.Evidence) < maxEvidencePerFinding {
				f.Evidence = append(f.Evidence, d)
			}
		}
	}

	findings := make([]Finding, 0, len(order))
	for _, k := range order {
		findings = append(findings, *groups[k])
	}
	return findings
}

// ---- Allowlist ----

// AllowlistEntry mirrors the previous tool's known-divergences format.
type AllowlistEntry struct {
	Transition  string `json:"transition,omitempty"`
	TestPattern string `json:"test_pattern,omitempty"`
	Client      string `json:"client,omitempty"`
	Action      string `json:"action"` // "suppress" or "downgrade"
	Reason      string `json:"reason"`
	SpecRuleID  string `json:"spec_rule_id,omitempty"`
}

// Allowlist is a set of known divergences.
type Allowlist struct {
	Entries []AllowlistEntry `json:"entries"`
}

// ApplyAllowlist marks findings matching a known-divergence entry. Matching
// considers the test pattern of any evidence item and the outlier client.
func ApplyAllowlist(findings []Finding, al *Allowlist) {
	if al == nil {
		return
	}
	for i := range findings {
		f := &findings[i]
		for _, e := range al.Entries {
			if !entryMatches(e, f) {
				continue
			}
			if e.Action == "downgrade" {
				f.Severity = runner.SeverityInfo
				f.SuppressReason = e.Reason
			} else {
				f.Suppressed = true
				f.SuppressReason = e.Reason
			}
			break
		}
	}
}

func entryMatches(e AllowlistEntry, f *Finding) bool {
	if e.TestPattern == "" && e.Transition == "" {
		return false
	}
	var targetOK bool
	if e.TestPattern != "" {
		for _, ev := range f.Evidence {
			if ok, _ := filepath.Match(e.TestPattern, ev.TestID); ok {
				targetOK = true
				break
			}
		}
	}
	if !targetOK && e.Transition != "" && e.Transition == f.RootCause {
		targetOK = true
	}
	if !targetOK {
		return false
	}
	if e.Client == "" {
		return true
	}
	for _, oc := range f.OutlierClients {
		if oc == e.Client {
			return true
		}
	}
	return false
}

// ---- Legacy shape ----

// legacyRunSummary mirrors the previous tool's run_summary object.
type legacyRunSummary struct {
	Seed        int64  `json:"seed"`
	StopReason  string `json:"stop_reason,omitempty"`
	ExecutedTests int  `json:"executed_tests"`
	TotalTests  int    `json:"total_tests"`
}

// LegacyShape renders a v1 report in the previous tool's top-level shape
// ({timestamp, divergences, findings, run_summary}) so existing triage
// scripts keep working. Use it via `analyze --legacy`.
func LegacyShape(rep *runner.Report) ([]byte, error) {
	var divergences []runner.Divergence
	for _, r := range rep.Results {
		divergences = append(divergences, r.Divergences...)
	}
	findings := BuildFindings(rep, false)

	legacy := map[string]any{
		"timestamp":   rep.StartedAt.Format(time.RFC3339),
		"divergences": divergences,
		"findings":    findings,
		"run_summary": legacyRunSummary{
			Seed:          rep.Seed,
			StopReason:    rep.Summary.StopReason,
			ExecutedTests: rep.Summary.Executed,
			TotalTests:    rep.Summary.Total,
		},
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(legacy); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
