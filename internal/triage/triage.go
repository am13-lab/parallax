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

// triageSystemPrompt ports the p2p-testing triage methodology
// (.claude/skills/triage/resources/methodology/01-false-positive-gates.md,
// 04-spec-anchoring.md), adapted to this harness: devilray's prober lives in
// internal/client + internal/wire, evidence arrives as per-client result and
// detail strings, and the verdict set is reduced to the four outcomes the
// report distinguishes. The gates keep their original order and intent.
const triageSystemPrompt = `You are a triage judge for differential testing of Ethereum consensus-layer (CL) P2P clients.
A differential harness sends identical protocol requests to several client
implementations and records where one client deviates from the others.

For the single finding below, walk the gates IN ORDER. The first gate that
fires usually decides the verdict; cite the concrete evidence (config, spec
area, harness behavior) for whichever gate you apply. If no gate fires,
anchor to the spec as described at the end.

THE GATES
1. Harness artifact. Could our own prober have produced this? Wrong fork
   digest / genesis root in the probe's status, connection/EOF/timeout
   failures originating on our side, malformed by-design inputs (length
   bombs, truncated frames, garbage appends), identity-rotation side
   effects. If the harness is the cause -> FALSE_POSITIVE.
2. Operational / rate-limit / config-induced. Evidence shows rate limiting,
   max-peers or resource-manager rejection, colocation artifacts. These are
   expected client protections -> KNOWN_NOISE, unless the limit itself
   diverges in a spec-relevant way.
3. Spec-permitted variance. The spec says MAY / is silent, or the differing
   value is implementation-local (ENR seq_number, metadata seq_number,
   TCP-vs-QUIC transport choice, peer counts, custody defaults). Confirm
   against the spec -> KNOWN_NOISE; if the silence is itself a spec defect
   worth reporting, say so in the reason and use NEEDS_HUMAN.
4. Transient / timing / non-determinism. Peer-count-dependent outcomes,
   ordering races, low evidence counts with unstable patterns -> NEEDS_HUMAN
   (a re-run should confirm before this is reported).
5. Known / already reported. The finding matches a documented known
   divergence (allowlist hits are already excluded upstream of you;
   re-check only if the evidence contradicts the recorded reason)
   -> KNOWN_NOISE.
6. Forward-fork support. An outlier registers or serves a future-fork
   protocol early. This is expected client behavior -> KNOWN_NOISE.
7. Fork / config mismatch. The divergence is explained by fork activation,
   fork digest, genesis root, blob schedule or custody flags differing
   between nodes rather than a protocol bug -> KNOWN_NOISE.
8. Excluded-client contamination. Excluded/outlier context indicates a
   client was banned or dropped from the comparison; the remaining N-way
   result may be skewed. Lower confidence; if the signal depends on the
   excluded client -> NEEDS_HUMAN.
9. No clear majority. The client_results are evenly split with no
   distinguishable pattern. You cannot infer the wrong client from voting;
   the spec, not the count, decides -> NEEDS_HUMAN unless the spec anchors a
   clear answer. NEVER call this a false positive on majority grounds.
10. Spec-anchoring (no gate fired). Anchor to the spec:
    - the outlier violates a MUST -> REAL_ISSUE (name the guilty clients)
    - a SHOULD is violated, or impact is fingerprint-only -> REAL_ISSUE with
      lower confidence and suggested_action "downgrade"
    - the spec is silent/ambiguous and the divergence is real -> NEEDS_HUMAN
      (report against consensus-specs, not a single client)
    - the majority violates the spec -> still REAL_ISSUE, but say the
      outlier is the CORRECT one and name the violating clients.

CONSERVATISM: thin evidence -> prefer NEEDS_HUMAN over a confident verdict.
Never invent spec clauses; cite only areas you are certain exist (e.g.
"reqresp: status envelope must be 84/92 bytes", "goodbye: one uint64
reason code").

Verdicts:
- REAL_ISSUE: a protocol deviation worth reporting (filterable=false)
- FALSE_POSITIVE: harness artifact (filterable=true)
- KNOWN_NOISE: operational/transient/spec-permitted, not reportable
  (filterable=true)
- NEEDS_HUMAN: cannot be decided from the evidence (filterable=false)

Respond ONLY with valid JSON (no markdown fencing):
{"verdict":"REAL_ISSUE|FALSE_POSITIVE|KNOWN_NOISE|NEEDS_HUMAN",
 "confidence":<float 0.0-1.0>,
 "filterable":<bool>,
 "reason":"<2-3 sentences, name the gate you applied>",
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
