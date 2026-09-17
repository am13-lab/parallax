package triage

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Verdict values produced by the LLM for each finding.
const (
	VerdictRealIssue     = "REAL_ISSUE"
	VerdictFalsePositive = "FALSE_POSITIVE"
	VerdictKnownNoise    = "KNOWN_NOISE"
	VerdictNeedsHuman    = "NEEDS_HUMAN"
)

// Input is one finding handed to the model. It carries only what the
// prompt needs; the report package maps its Finding type onto this.
type Input struct {
	ID             string            `json:"id"`
	RootCause      string            `json:"root_cause"`
	Type           string            `json:"type"`
	Severity       string            `json:"severity"`
	OutlierClients []string          `json:"outlier_clients"`
	TestIDs        []string          `json:"test_ids"`
	ClientResults  map[string]string `json:"client_results,omitempty"`
	Details        []string          `json:"details,omitempty"` // up to 5 short evidence strings
}

// Result is the model's classification of one finding.
type Result struct {
	ID          string  `json:"finding_id"`
	Verdict     string  `json:"verdict"`
	Confidence  float64 `json:"confidence"`
	Filterable  bool    `json:"filterable"`
	Reason      string  `json:"reason"`
	SpecAnchor  string  `json:"spec_anchor,omitempty"`
	Suggested   string  `json:"suggested_action,omitempty"`
	Unavailable bool    `json:"unavailable,omitempty"` // triage itself failed for this finding
	Error       string  `json:"error,omitempty"`
}

// triageSystemPrompt distills the p2p-testing triage methodology: harness
// artifacts first, spec over majority, conservative verdicts, strict JSON.
const triageSystemPrompt = `You are a triage judge for differential testing of Ethereum consensus-layer (CL) P2P clients.
A differential harness sends identical protocol requests to several client
implementations and records where one client deviates from the others.

For the single finding below decide whether it is a REAL issue that must be
reported upstream, or noise that should be filtered from the report.

Apply these rules in order:
1. HARNESS ARTIFACT: if the probing harness itself plausibly produced the
   anomaly (malformed input by design, own timeout/reset policy, identity
   rotation side effects, resource exhaustion by the test), the finding is
   FALSE_POSITIVE.
2. SPEC DECIDES, NOT MAJORITY: the Ethereum specification — not the number
   of clients agreeing — decides who is correct. A behavior shared by every
   client can still be a bug; a lone dissenter can be the only compliant
   one. Only cite the spec, never the majority.
3. NO MAJORITY BASIS: if you cannot determine the governing spec rule and
   the verdict would rest on vote counting, answer NEEDS_HUMAN.
4. ENVIRONMENTAL: transient timeouts/resets under load with no protocol
   violation evidenced are KNOWN_NOISE (confidence >= 0.6) or NEEDS_HUMAN.
5. CONSERVATIVE: when evidence is thin, prefer NEEDS_HUMAN over a confident
   verdict. Never invent spec clauses; if you cite one, keep it short and
   real (you may reference the testing spec area, e.g. "reqresp: status
   envelope must be 84/92 bytes").

Verdicts:
- REAL_ISSUE: a protocol deviation worth reporting (filterable=false)
- FALSE_POSITIVE: harness artifact (filterable=true)
- KNOWN_NOISE: environmental/transient, not protocol-relevant (filterable=true)
- NEEDS_HUMAN: cannot be decided from the evidence (filterable=false)

Respond ONLY with valid JSON (no markdown fencing):
{"verdict":"REAL_ISSUE|FALSE_POSITIVE|KNOWN_NOISE|NEEDS_HUMAN",
 "confidence":<float 0.0-1.0>,
 "filterable":<bool>,
 "reason":"<2-3 sentences>",
 "spec_anchor":"<short spec area citation or empty>",
 "suggested_action":"report|filter|downgrade|investigate"}`

// Triage classifies each input finding with the configured provider.
// Findings are processed independently; a per-finding failure marks that
// result Unavailable and never aborts the batch.
func Triage(ctx context.Context, auth *Auth, provider string, inputs []Input) []Result {
	results := make([]Result, 0, len(inputs))
	for _, in := range inputs {
		res := triageOne(ctx, auth, provider, in)
		results = append(results, res)
	}
	return results
}

func triageOne(ctx context.Context, auth *Auth, provider string, in Input) Result {
	res := Result{ID: in.ID}
	prompt := buildPrompt(in)
	raw, err := complete(ctx, auth, provider, prompt)
	if err != nil {
		res.Unavailable = true
		res.Error = err.Error()
		return res
	}
	verdict, perr := parseVerdict(raw)
	if perr != nil {
		res.Unavailable = true
		res.Error = fmt.Sprintf("unparseable response: %v (raw: %s)", perr, truncate(raw, 200))
		return res
	}
	res.Verdict = verdict.Verdict
	res.Confidence = verdict.Confidence
	res.Filterable = verdict.Filterable
	res.Reason = verdict.Reason
	res.SpecAnchor = verdict.SpecAnchor
	res.Suggested = verdict.Suggested
	if res.Verdict == "" {
		res.Unavailable = true
		res.Error = "empty verdict"
	}
	return res
}

// verdictJSON mirrors the strict response schema requested in the prompt.
type verdictJSON struct {
	Verdict    string  `json:"verdict"`
	Confidence float64 `json:"confidence"`
	Filterable bool    `json:"filterable"`
	Reason     string  `json:"reason"`
	SpecAnchor string  `json:"spec_anchor"`
	Suggested  string  `json:"suggested_action"`
}

func parseVerdict(raw string) (verdictJSON, error) {
	var v verdictJSON
	cleaned := strings.TrimSpace(raw)
	cleaned = strings.TrimPrefix(cleaned, "```json")
	cleaned = strings.TrimPrefix(cleaned, "```")
	cleaned = strings.TrimSuffix(cleaned, "```")
	cleaned = strings.TrimSpace(cleaned)
	if err := json.Unmarshal([]byte(cleaned), &v); err != nil {
		// tolerate prose around the object: take the outermost {...}
		if i := strings.Index(cleaned, "{"); i >= 0 {
			if j := strings.LastIndex(cleaned, "}"); j > i {
				if err2 := json.Unmarshal([]byte(cleaned[i:j+1]), &v); err2 == nil {
					return v, nil
				}
			}
		}
		return v, err
	}
	return v, nil
}

func buildPrompt(in Input) string {
	var b strings.Builder
	b.WriteString(triageSystemPrompt)
	b.WriteString("\n\nFINDING (JSON):\n")
	blob, _ := json.MarshalIndent(in, "", "  ")
	b.Write(blob)
	return b.String()
}

// TriageInfo is the triage section embedded into the report (JSON) and
// rendered in the HTML page.
type TriageInfo struct {
	Provider    string   `json:"provider"`
	Model       string   `json:"model"`
	GeneratedAt string   `json:"generated_at"`
	Summary     Summary  `json:"summary"`
	Results     []Result `json:"results"`
}

// Summary aggregates verdict counts for the report header.
type Summary struct {
	Total       int `json:"total"`
	RealIssues  int `json:"real_issues"`
	Filterable  int `json:"filterable"`
	NeedsHuman  int `json:"needs_human"`
	Unavailable int `json:"unavailable"`
}

// Summarize builds the counts block from a result set.
func Summarize(results []Result) Summary {
	s := Summary{Total: len(results)}
	for _, r := range results {
		switch {
		case r.Unavailable:
			s.Unavailable++
		case r.Verdict == VerdictRealIssue:
			s.RealIssues++
		case r.Filterable:
			s.Filterable++
		case r.Verdict == VerdictNeedsHuman:
			s.NeedsHuman++
		}
	}
	return s
}

// Info assembles the embeddable triage section.
func Info(provider, model string, results []Result) TriageInfo {
	return TriageInfo{
		Provider:    provider,
		Model:       model,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Summary:     Summarize(results),
		Results:     results,
	}
}
