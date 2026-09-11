package main

import (
	"encoding/json"
	"os"
	"sort"
)

// join.go — Layer 4 (part 2). Joins AST-derived spec-truth with the curated
// overlay to produce a flat debug projection. The AST rule id
// is always the canonical flat id. Legacy SPEC-* ids survive only as metadata on
// the mapped AST rule.

// overlayEntry holds the curated, non-spec fields keyed by rule id.
type overlayEntry struct {
	TestIDs             []string `json:"test_ids"`
	InvariantIDs        []string `json:"invariant_ids"`
	Testability         string   `json:"testability"`
	CoverageStatus      string   `json:"coverage_status"`
	CurrentStatus       string   `json:"current_status,omitempty"`
	StateMachine        string   `json:"state_machine"`
	ObservableInTraffic bool     `json:"observable_in_traffic"`
	Transitions         []string `json:"transitions"`
	KnownBugs           string   `json:"known_bugs,omitempty"`
	FalsePositiveReason string   `json:"false_positive_reason,omitempty"`
}

type specRulesDoc struct {
	Description string     `json:"description"`
	Source      string     `json:"source"`
	Rules       []flatRule `json:"rules"`
}

// legacyMapEntry records the migration path for one pre-AST SPEC-* id.
type legacyMapEntry struct {
	ASTIDs  []string `json:"ast_ids,omitempty"`
	Retired bool     `json:"retired,omitempty"`
	Reason  string   `json:"reason,omitempty"`
	Text    string   `json:"text,omitempty"`
}

// driftReport summarizes the difference between the AST and the existing catalog.
type driftReport struct {
	ExistingRules     int      `json:"existing_rules"`
	ASTRules          int      `json:"ast_rules"`
	MatchedExisting   int      `json:"matched_existing"`
	NewRules          int      `json:"new_rules"`
	UnmatchedExisting int      `json:"unmatched_existing"`
	StaleOverlay      int      `json:"stale_overlay"`
	NewSamples        []string `json:"new_samples"`
	UnmatchedSamples  []string `json:"unmatched_samples"`
	StaleOverlayIDs   []string `json:"stale_overlay_ids"`
}

// loadOverlay reads test_overlay.json (id -> curated fields). A missing file
// yields an empty map (overlay application then a no-op).
func loadOverlay(path string) map[string]overlayEntry {
	data, err := os.ReadFile(path)
	if err != nil {
		return map[string]overlayEntry{}
	}
	m := map[string]overlayEntry{}
	if json.Unmarshal(data, &m) != nil {
		return map[string]overlayEntry{}
	}
	return m
}

// loadLegacyMap reads the old SPEC-* -> AST-id compatibility map. Missing maps
// are tolerated so a from-scratch AST catalog can still be generated.
func loadLegacyMap(path string) (map[string]legacyMapEntry, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return map[string]legacyMapEntry{}, nil
	}
	if err != nil {
		return nil, err
	}
	m := map[string]legacyMapEntry{}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// applyOverlay fills a flat rule's curated fields from the overlay entry.
func applyOverlay(fr *flatRule, e overlayEntry) {
	fr.TestIDs = orEmpty(e.TestIDs)
	fr.InvariantIDs = orEmpty(e.InvariantIDs)
	fr.Transitions = orEmpty(e.Transitions)
	fr.Testability = e.Testability
	fr.CoverageStatus = e.CoverageStatus
	fr.CurrentStatus = e.CurrentStatus
	fr.StateMachine = e.StateMachine
	fr.ObservableInTraffic = e.ObservableInTraffic
	fr.KnownBugs = e.KnownBugs
	fr.FalsePositiveReason = e.FalsePositiveReason
}

// joinFlat produces the flat rule list and a drift report. Existing rules are
// preserved; new AST rules (no normalized-text match) are appended. The curated
// overlay is applied by id over every output rule, so edits to test_overlay.json
// take effect on regeneration. Overlay entries whose id is absent from the output
// are reported as stale bindings.
func joinFlat(ast *RuleAST, existing specRulesDoc, overlay map[string]overlayEntry, legacy map[string]legacyMapEntry) ([]flatRule, map[string]string, driftReport) {
	hasTemporal := map[string]bool{}
	for _, e := range ast.Edges {
		if e.Kind == "temporal" {
			hasTemporal[e.From] = true
		}
	}

	existingByID := map[string]bool{}
	for _, r := range existing.Rules {
		existingByID[r.ID] = true
	}

	legacyByAST := map[string][]string{}
	for oldID, entry := range legacy {
		if entry.Retired {
			continue
		}
		for _, astID := range entry.ASTIDs {
			if astID == "" {
				continue
			}
			legacyByAST[astID] = append(legacyByAST[astID], oldID)
		}
	}

	aliases := map[string]string{} // AST node id -> canonical flat id (itself)
	var out []flatRule
	var drift driftReport
	drift.ExistingRules = len(existing.Rules)
	drift.ASTRules = len(ast.Rules)

	for _, r := range ast.Rules {
		fr := specTruth(r, hasTemporal[r.ID])
		fr.LegacyIDs = dedupeSorted(legacyByAST[r.ID])
		aliases[r.ID] = r.ID
		if existingByID[r.ID] {
			drift.MatchedExisting++
		} else {
			drift.NewRules++
			if len(drift.NewSamples) < 15 {
				drift.NewSamples = append(drift.NewSamples, fr.ID+": "+truncate(fr.Text, 90))
			}
		}
		out = append(out, fr)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })

	for _, r := range existing.Rules {
		if _, ok := aliases[r.ID]; !ok && r.ID != "" {
			drift.UnmatchedExisting++
			if len(drift.UnmatchedSamples) < 15 {
				drift.UnmatchedSamples = append(drift.UnmatchedSamples, r.ID+": "+truncate(r.Text, 90))
			}
		}
	}

	// Apply the curated overlay by id, and report overlay entries whose id no
	// longer appears in the catalog (stale bindings the curator should prune).
	presentIDs := map[string]bool{}
	for i := range out {
		if e, ok := overlay[out[i].ID]; ok {
			applyOverlay(&out[i], e)
		}
		presentIDs[out[i].ID] = true
	}
	for id := range overlay {
		if !presentIDs[id] {
			drift.StaleOverlay++
			if len(drift.StaleOverlayIDs) < 15 {
				drift.StaleOverlayIDs = append(drift.StaleOverlayIDs, id)
			}
		}
	}
	sort.Strings(drift.StaleOverlayIDs)
	return out, aliases, drift
}

func dedupeSorted(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// writeJSON marshals v with indentation and a trailing newline.
func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}
