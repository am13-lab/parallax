package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"parallax/runner"
)

func htmlTestReport() *runner.Report {
	return &runner.Report{
		SchemaVersion: 1,
		Seed:          42,
		ChainPreset:   "mainnet",
		Summary:       runner.Summary{Total: 2, Passed: 1, Divergent: 1, Executed: 2},
		Endpoints: []runner.EndpointFingerprint{
			{Name: "a", ClientType: "fake-a"},
			{Name: "b", ClientType: "fake-b"},
		},
		Results: []runner.TestResult{
			{TestID: "t.pass", Category: "reqresp", Status: runner.StatusPass, Elapsed: "1s"},
			{TestID: "t.div", Category: "reqresp", Status: runner.StatusDivergent, Elapsed: "2s",
				Divergences: []runner.Divergence{{
					TestID:         "t.div",
					Category:       "reqresp",
					Type:           runner.DivAcceptReject,
					Severity:       runner.SeverityHigh,
					Description:    `</script><b>breakout</b>`,
					ClientResults:  map[string]string{"a": "accept", "b": "reject"},
					OutlierClients: []string{"b"},
					SpecRuleIDs:    []string{"reqresp:ping"},
				}}},
		},
	}
}

func TestWriteHTMLSingleFile(t *testing.T) {
	out, err := WriteHTML(htmlTestReport(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.HasPrefix(s, "<!doctype html>") {
		t.Fatal("missing doctype prefix")
	}
	for _, want := range []string{
		`id="parallax-report"`,
		`"schema_version":1`,
		`"test_id":"t.div"`,
		`"root_cause"`,
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("output missing %q", want)
		}
	}
}

func TestWriteHTMLEscapesScriptBreakout(t *testing.T) {
	out, err := WriteHTML(htmlTestReport(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, `\u003c/script\u003e`) {
		t.Fatal("description was not HTML-escaped inside the embedded JSON")
	}
	if strings.Contains(s, "</script><b>breakout") {
		t.Fatal("raw breakout sequence leaked into the page")
	}
	// Exactly two script close tags: the data element and the page script.
	if got := strings.Count(s, "</script>"); got != 2 {
		t.Fatalf("want 2 script closes, got %d", got)
	}
}

func TestWriteHTMLIncludesFindings(t *testing.T) {
	rep := htmlTestReport()
	findings := BuildFindings(rep, false)
	if len(findings) != 1 {
		t.Fatalf("findings: %+v", findings)
	}
	out, err := WriteHTML(rep, findings, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"outlier_clients":["b"]`) {
		t.Fatal("findings outliers missing from embedded payload")
	}
}

func TestWriteHTMLOutputIsParseableJSON(t *testing.T) {
	out, err := WriteHTML(htmlTestReport(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	const marker = `id="parallax-report">`
	i := strings.Index(string(out), marker)
	if i < 0 {
		t.Fatal("data element not found")
	}
	start := i + len(marker)
	end := strings.Index(string(out[start:]), "</script>")
	if end < 0 {
		t.Fatal("data element not terminated")
	}
	var doc struct {
		Runs []struct {
			Report   json.RawMessage `json:"report"`
			Findings []Finding       `json:"findings"`
		} `json:"runs"`
		Current int `json:"current"`
	}
	if err := json.Unmarshal([]byte(string(out[start:start+end])), &doc); err != nil {
		t.Fatalf("embedded payload is not valid JSON: %v", err)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("embedded runs wrong: %d", len(doc.Runs))
	}
	var back runner.Report
	if err := json.Unmarshal(doc.Runs[0].Report, &back); err != nil {
		t.Fatalf("embedded report does not decode: %v", err)
	}
	if len(doc.Runs[0].Findings) != 1 || doc.Runs[0].Findings[0].OutlierClients[0] != "b" {
		t.Fatalf("embedded findings wrong: %+v", doc.Runs[0].Findings)
	}
}

func TestWriteHTMLNilFindingsComputesFromReport(t *testing.T) {
	out, err := WriteHTML(htmlTestReport(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out, []byte(`"evidence_count":1`)) {
		t.Fatal("computed findings not embedded")
	}
}

func TestWriteHTMLRejectReasonVerdicts(t *testing.T) {
	rep := htmlTestReport()
	rep.Results[1].Divergences[0].ClientResults = map[string]string{"a": "accept", "b": "reject:reset"}
	out, err := WriteHTML(rep, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, `indexOf("reject") === 0`) {
		t.Fatal("verdictOf must classify reject:<reason> values as reject")
	}
	if !strings.Contains(s, `"reject:reset"`) {
		t.Fatal("client result with normalized reason missing from payload")
	}
}

func TestWriteHTMLSummaryMatrixUsesFixedLayout(t *testing.T) {
	out, err := WriteHTML(htmlTestReport(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{
		`el("table", "matrix matrix-sum")`,
		`table.matrix-sum{table-layout:fixed}`,
		`table.matrix-sum thead th:first-child`,
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("output missing %q", want)
		}
	}
}

func TestRunPayloadMetaFields(t *testing.T) {
	rep := &runner.Report{
		SchemaVersion: 1,
		StartedAt:     time.Date(2026, 9, 9, 8, 30, 0, 0, time.UTC),
		Seed:          77,
		Command:       "go run ./cmd/parallax run ...",
		Endpoints: []runner.EndpointFingerprint{
			{Name: "cl-1-a", ClientType: "geth"},
			{Name: "cl-1-b", ClientType: "geth"},
			{Name: "cl-2-a", ClientType: "erigon"},
		},
		Summary: runner.Summary{Total: 3, Passed: 3},
	}
	p, err := runPayload(rep, nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.Meta.Stamp != "20260909T083000Z" {
		t.Fatalf("stamp = %q", p.Meta.Stamp)
	}
	if p.Meta.Seed != 77 {
		t.Fatalf("seed = %d", p.Meta.Seed)
	}
	if p.Meta.Clients != "geth×2 + erigon×1" {
		t.Fatalf("clients = %q", p.Meta.Clients)
	}
}

func TestWriteHTMLEmbedsTriage(t *testing.T) {
	rep := htmlTestReport()
	rep.Triage = []byte(`{"provider":"glm","model":"glm-4.6","generated_at":"2026-01-01T00:00:00Z","summary":{"total":1,"real_issues":1},"results":[{"finding_id":"F-1","verdict":"REAL_ISSUE","confidence":0.9,"filterable":false,"reason":"violates MUST"}]}`)
	out, err := WriteHTML(rep, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"LLM Triage Summary", "REAL_ISSUE", "violates MUST", "Generate auth.json"} {
		if !strings.Contains(string(out), want) {
			t.Fatalf("html missing %q", want)
		}
	}
}
