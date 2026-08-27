package report_test

import (
	"encoding/json"
	"strings"
	"testing"

	"libp2p-difftest/runner"
	"libp2p-difftest/report"
)

func sampleReport() *runner.Report {
	return &runner.Report{
		SchemaVersion: 1,
		Seed:          42,
		Environment:   map[string]string{"provider": "fake"},
		ChainPreset:   "mainnet",
		Results: []runner.TestResult{
			{TestID: "t.pass", Category: "reqresp", Status: runner.StatusPass, Elapsed: "1ms"},
			{TestID: "t.div", Category: "reqresp", Status: runner.StatusDivergent, Elapsed: "2ms",
				Divergences: []runner.Divergence{
					{TestID: "t.div", Category: "reqresp", Type: runner.DivAcceptReject,
						Severity: runner.SeverityHigh, Description: "a accepted, b rejected",
						ClientResults: map[string]string{"a": "accept", "b": "reject"},
						OutlierClients: []string{"b"}},
				}},
			{TestID: "t.skip", Category: "gossip", Status: runner.StatusSkipped, SkipReason: "insufficient clients"},
		},
		Summary: runner.Summary{Total: 3, Passed: 1, Divergent: 1, Skipped: 1, Executed: 2},
	}
}

func TestJSONRoundTrip(t *testing.T) {
	rep := sampleReport()
	data, err := report.WriteJSON(rep)
	if err != nil {
		t.Fatalf("write json: %v", err)
	}
	var back runner.Report
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("round trip: %v", err)
	}
	if back.SchemaVersion != 1 || back.Seed != 42 {
		t.Fatalf("fields lost: %+v", back)
	}
	if len(back.Results) != 3 || back.Results[1].Divergences[0].TestID != "t.div" {
		t.Fatalf("results lost: %+v", back.Results)
	}
	if !strings.Contains(string(data), `"schema_version": 1`) {
		t.Fatal("schema_version key missing")
	}
}

func TestJUnitMapping(t *testing.T) {
	rep := sampleReport()
	xml, err := report.WriteJUnit(rep)
	if err != nil {
		t.Fatalf("write junit: %v", err)
	}
	out := string(xml)
	// One testsuite per category, one testcase per result.
	if !strings.Contains(out, `<testsuite name="reqresp"`) || !strings.Contains(out, `<testsuite name="gossip"`) {
		t.Fatalf("category suites missing: %s", out)
	}
	if strings.Count(out, "<testcase ") != 3 {
		t.Fatalf("want 3 testcases: %s", out)
	}
	// Divergent becomes failure, skipped stays skipped, pass plain.
	if !strings.Contains(out, "<failure") {
		t.Fatalf("divergent must map to failure: %s", out)
	}
	if !strings.Contains(out, "<skipped") {
		t.Fatalf("skipped must be present: %s", out)
	}
	if !strings.Contains(out, `name="t.div"`) {
		t.Fatal("test id must appear")
	}
}

func TestFindingsDedup(t *testing.T) {
	rep := &runner.Report{
		SchemaVersion: 1,
		Results: []runner.TestResult{
			{TestID: "a.1", Category: "reqresp", Status: runner.StatusDivergent,
				Divergences: []runner.Divergence{
					{TestID: "a.1", Type: runner.DivAcceptReject, Description: "root X", OutlierClients: []string{"b"}},
				}},
			{TestID: "a.2", Category: "reqresp", Status: runner.StatusDivergent,
				Divergences: []runner.Divergence{
					{TestID: "a.2", Type: runner.DivAcceptReject, Description: "root X", OutlierClients: []string{"b"}},
				}},
			{TestID: "b.1", Category: "reqresp", Status: runner.StatusDivergent,
				Divergences: []runner.Divergence{
					{TestID: "b.1", Type: runner.DivTimeout, Description: "root Y", OutlierClients: []string{"a"}},
				}},
		},
	}
	findings := report.BuildFindings(rep, false)
	if len(findings) != 2 {
		t.Fatalf("same root cause must group: got %d findings", len(findings))
	}
	for _, f := range findings {
		if f.RootCause == "root X" && f.EvidenceCount != 2 {
			t.Fatalf("root X must have 2 evidence: %+v", f)
		}
	}
}

func TestAllowlistSuppression(t *testing.T) {
	rep := &runner.Report{
		SchemaVersion: 1,
		Results: []runner.TestResult{
			{TestID: "known.test", Category: "reqresp", Status: runner.StatusDivergent,
				Divergences: []runner.Divergence{
					{TestID: "known.test", Type: runner.DivOperational, OutlierClients: []string{"nimbus"}},
				}},
			{TestID: "new.test", Category: "reqresp", Status: runner.StatusDivergent,
				Divergences: []runner.Divergence{
					{TestID: "new.test", Type: runner.DivCrash, OutlierClients: []string{"prysm"}},
				}},
		},
	}
	al := &report.Allowlist{
		Entries: []report.AllowlistEntry{
			{TestPattern: "known.*", Client: "nimbus", Action: "suppress", Reason: "known issue"},
		},
	}
	findings := report.BuildFindings(rep, false)
	report.ApplyAllowlist(findings, al)

	var suppressed, active int
	for _, f := range findings {
		if f.Suppressed {
			suppressed++
			if f.SuppressReason != "known issue" {
				t.Fatalf("reason must carry over: %+v", f)
			}
		} else {
			active++
		}
	}
	if suppressed != 1 || active != 1 {
		t.Fatalf("suppressed=%d active=%d", suppressed, active)
	}
}

func TestLegacyAdapter(t *testing.T) {
	rep := sampleReport()
	legacy, err := report.LegacyShape(rep)
	if err != nil {
		t.Fatalf("legacy: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(legacy, &m); err != nil {
		t.Fatalf("legacy json: %v", err)
	}
	for _, key := range []string{"divergences", "findings", "run_summary"} {
		if _, ok := m[key]; !ok {
			t.Fatalf("legacy shape missing %q: %v", key, m)
		}
	}
}
