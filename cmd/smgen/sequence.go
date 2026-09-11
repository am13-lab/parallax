package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

const sequenceArtifactVersion = 1

type sequenceArtifact struct {
	Version    int            `json:"version"`
	Source     string         `json:"source"`
	TotalRules int            `json:"total_rules"`
	Cases      []sequenceCase `json:"cases"`
}

type sequenceCase struct {
	ID       string         `json:"id"`
	Category string         `json:"category"`
	Domain   string         `json:"domain"`
	Surface  string         `json:"surface"`
	Template string         `json:"template"`
	RuleIDs  []string       `json:"rule_ids"`
	Steps    []sequenceStep `json:"steps"`
}

type sequenceStep struct {
	Role       string     `json:"role"`
	Transition Transition `json:"transition"`
}

func loadSequenceArtifact(path string) (*sequenceArtifact, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var doc sequenceArtifact
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("strict decode: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("unexpected trailing JSON")
	}
	return &doc, nil
}

func validateSequenceArtifact(doc *sequenceArtifact, refs refIndex) *Result {
	r := &Result{}
	if doc.Version != sequenceArtifactVersion {
		r.add("gate1", "version", "version = %d, want %d", doc.Version, sequenceArtifactVersion)
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
		if c.Category != "" && c.ID != "" && !strings.HasPrefix(c.ID, c.Category+".generated_sequence.") {
			r.add("gate1", base+".id", "id %q must start with %q", c.ID, c.Category+".generated_sequence.")
		}
		if c.Surface == "" {
			r.add("gate1", base+".surface", "surface is required")
		}
		if c.Template == "" {
			r.add("gate1", base+".template", "template is required")
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
		if len(c.Steps) < 2 {
			r.add("gate1", base+".steps", "sequence test requires at least setup and probe steps")
		}
		probes := 0
		var refsFromSteps []string
		for j := range c.Steps {
			s := &c.Steps[j]
			sbase := fmt.Sprintf("%s.steps[%d]", base, j)
			switch s.Role {
			case "setup", "probe":
			default:
				r.add("gate1", sbase+".role", "unknown role %q", s.Role)
			}
			if s.Role == "probe" {
				probes++
			}
			refsFromSteps = append(refsFromSteps, s.Transition.SpecRefs...)
			if s.Transition.From == "" {
				r.add("gate1", sbase+".transition.from", "from is required")
			}
			if s.Transition.To == "" {
				r.add("gate1", sbase+".transition.to", "to is required")
			}
		}
		if probes != 1 {
			r.add("gate1", base+".steps", "sequence test must contain exactly one probe step, found %d", probes)
		}
		if !sameStringSet(c.RuleIDs, refsFromSteps) {
			r.add("gate2", base+".steps", "union of transition spec_refs must match rule_ids")
		}

		m := sequenceValidationMachine(*c)
		applyDerivedStrength(m, refs.specStrength)
		cr := validateMachine(m, refs)
		for _, is := range cr.Issues {
			r.Issues = append(r.Issues, Issue{Gate: is.Gate, Path: base + "." + is.Path, Msg: is.Msg})
		}
		for _, w := range cr.Warnings {
			r.Warnings = append(r.Warnings, Issue{Gate: w.Gate, Path: base + "." + w.Path, Msg: w.Msg})
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

func sequenceValidationMachine(c sequenceCase) *Machine {
	statesByName := map[string]bool{}
	var states []State
	addState := func(name string) {
		if name == "" || statesByName[name] {
			return
		}
		statesByName[name] = true
		states = append(states, State{Name: name})
	}
	var transitions []Transition
	for _, step := range c.Steps {
		addState(step.Transition.From)
		addState(step.Transition.To)
		transitions = append(transitions, step.Transition)
	}
	if len(states) > 0 && len(c.Steps) > 0 {
		last := c.Steps[len(c.Steps)-1].Transition.To
		for i := range states {
			if states[i].Name == last {
				states[i].Terminal = true
			}
		}
	}
	init := "GeneratedSequenceStart"
	if len(c.Steps) > 0 && c.Steps[0].Transition.From != "" {
		init = c.Steps[0].Transition.From
	}
	return &Machine{Name: "GeneratedSequence", InitState: init, States: states, Transitions: transitions}
}

func runValidateSequences(path string, refs refIndex) int {
	doc, err := loadSequenceArtifact(path)
	if err != nil {
		fmt.Printf("FAIL %s\n  [gate1] %v\n", path, err)
		return 1
	}
	r := validateSequenceArtifact(doc, refs)
	if r.OK() {
		fmt.Printf("PASS %s (%d generated sequence tests, %d rule links)\n", path, len(doc.Cases), doc.TotalRules)
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
