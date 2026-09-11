package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

const statelessArtifactVersion = 1

type statelessArtifact struct {
	Version    int             `json:"version"`
	Source     string          `json:"source"`
	TotalRules int             `json:"total_rules"`
	Cases      []statelessCase `json:"cases"`
}

type statelessCase struct {
	ID         string     `json:"id"`
	Category   string     `json:"category"`
	Domain     string     `json:"domain"`
	Surface    string     `json:"surface"`
	Probe      string     `json:"probe"`
	RuleIDs    []string   `json:"rule_ids"`
	Transition Transition `json:"transition"`
}

func loadStatelessArtifact(path string) (*statelessArtifact, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var doc statelessArtifact
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("strict decode: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("unexpected trailing JSON")
	}
	return &doc, nil
}

func validateStatelessArtifact(doc *statelessArtifact, refs refIndex) *Result {
	r := &Result{}
	if doc.Version != statelessArtifactVersion {
		r.add("gate1", "version", "version = %d, want %d", doc.Version, statelessArtifactVersion)
	}
	if doc.Source == "" {
		r.add("gate1", "source", "source is required")
	}
	seenIDs := map[string]int{}
	totalRules := 0
	for i := range doc.Cases {
		c := &doc.Cases[i]
		base := fmt.Sprintf("cases[%d]", i)
		if c.ID == "" {
			r.add("gate1", base+".id", "id is required")
		} else if prev, ok := seenIDs[c.ID]; ok {
			r.add("gate4", base+".id", "duplicate test id %q (first at cases[%d])", c.ID, prev)
		} else {
			seenIDs[c.ID] = i
		}
		if !statelessCategories[c.Category] {
			r.add("gate1", base+".category", "unknown category %q", c.Category)
		}
		if c.Category != "" && c.ID != "" && !strings.HasPrefix(c.ID, c.Category+".generated.") {
			r.add("gate1", base+".id", "id %q must start with %q", c.ID, c.Category+".generated.")
		}
		if c.Surface == "" {
			r.add("gate1", base+".surface", "surface is required")
		}
		if c.Probe == "" {
			r.add("gate1", base+".probe", "probe is required")
		}
		if len(c.RuleIDs) == 0 {
			r.add("gate1", base+".rule_ids", "at least one rule id is required")
		}
		totalRules += len(c.RuleIDs)

		for j, rid := range c.RuleIDs {
			if rid == "" {
				r.add("gate1", fmt.Sprintf("%s.rule_ids[%d]", base, j), "rule id is empty")
			}
		}
		if !sameStringSet(c.RuleIDs, c.Transition.SpecRefs) {
			r.add("gate2", base+".transition.spec_refs", "transition spec_refs must match rule_ids")
		}
		if c.Transition.From == "" {
			r.add("gate1", base+".transition.from", "from is required")
		}
		if c.Transition.To == "" {
			r.add("gate1", base+".transition.to", "to is required")
		}

		m := statelessValidationMachine(*c)
		applyDerivedStrength(m, refs.specStrength)
		cr := validateMachine(m, refs)
		for _, is := range cr.Issues {
			r.Issues = append(r.Issues, Issue{
				Gate: is.Gate,
				Path: base + "." + is.Path,
				Msg:  is.Msg,
			})
		}
		for _, w := range cr.Warnings {
			r.Warnings = append(r.Warnings, Issue{
				Gate: w.Gate,
				Path: base + "." + w.Path,
				Msg:  w.Msg,
			})
		}
		r.SingleClientJudged += cr.SingleClientJudged
		r.DifferentialOnly += cr.DifferentialOnly
		r.JudgedByNothing += cr.JudgedByNothing
	}
	if doc.TotalRules != totalRules {
		r.add("gate1", "total_rules", "total_rules = %d, want %d from cases", doc.TotalRules, totalRules)
	}
	sortIssues(r)
	return r
}

func statelessValidationMachine(c statelessCase) *Machine {
	tr := c.Transition
	from := tr.From
	if from == "" {
		from = "GeneratedStart"
	}
	to := tr.To
	if to == "" || to == from {
		to = "GeneratedDone"
	}
	tr.From = from
	tr.To = to
	return &Machine{
		Name:      "GeneratedStateless",
		InitState: from,
		States:    []State{{Name: from}, {Name: to, Terminal: true}},
		Transitions: []Transition{
			tr,
		},
	}
}

func runValidateStateless(path string, refs refIndex) int {
	doc, err := loadStatelessArtifact(path)
	if err != nil {
		fmt.Printf("FAIL %s\n  [gate1] %v\n", path, err)
		return 1
	}
	r := validateStatelessArtifact(doc, refs)
	if r.OK() {
		fmt.Printf("PASS %s (%d generated tests, %d rule links)\n", path, len(doc.Cases), doc.TotalRules)
	} else {
		fmt.Printf("FAIL %s\n", path)
		for _, is := range r.Issues {
			fmt.Printf("  [%s] %s: %s\n", is.Gate, is.Path, is.Msg)
		}
	}
	for _, w := range r.Warnings {
		fmt.Printf("  WARN [%s] %s: %s\n", w.Gate, w.Path, w.Msg)
	}
	fmt.Printf("  judgment: %d single-client, %d differential-only, %d judged-by-nothing\n",
		r.SingleClientJudged, r.DifferentialOnly, r.JudgedByNothing)
	if !r.OK() {
		return 1
	}
	return 0
}

var statelessCategories = map[string]bool{
	"reqresp":   true,
	"discovery": true,
	"gossipsub": true,
	"cryptomsg": true,
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	aa := append([]string(nil), a...)
	bb := append([]string(nil), b...)
	sort.Strings(aa)
	sort.Strings(bb)
	for i := range aa {
		if aa[i] != bb[i] {
			return false
		}
	}
	return true
}
