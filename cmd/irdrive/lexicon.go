package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// lexicon.go — the curated phrase->state lexicon used to derive a rule's FROM state
// from its temporal edge (upon/once/after «to_ref»). Maps a spec event phrase to a
// semantic state per machine. Matching is deterministic and word-boundary aware
// (contiguous token run), so "connection" does not match inside "disconnection".

type lexiconEntry struct {
	state string
	words []string // normalized match tokens
}

type stateLexicon struct {
	byMachine map[string][]lexiconEntry
}

type lexiconDoc struct {
	Version  int    `json:"version"`
	Source   string `json:"source"`
	Note     string `json:"note"`
	Machines map[string][]struct {
		Match string `json:"match"`
		State string `json:"state"`
	} `json:"machines"`
}

func lexTokens(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9')
	}) {
		out = append(out, f)
	}
	return out
}

func loadStateLexicon(path string) (*stateLexicon, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc lexiconDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse state lexicon %s: %w", path, err)
	}
	if doc.Version != 1 {
		return nil, fmt.Errorf("state lexicon version = %d, want 1", doc.Version)
	}
	lex := &stateLexicon{byMachine: map[string][]lexiconEntry{}}
	for machine, entries := range doc.Machines {
		for _, e := range entries {
			toks := lexTokens(e.Match)
			if len(toks) == 0 || e.State == "" {
				return nil, fmt.Errorf("state lexicon %s: machine %q has an entry with empty match/state", path, machine)
			}
			lex.byMachine[machine] = append(lex.byMachine[machine], lexiconEntry{state: e.State, words: toks})
		}
	}
	return lex, nil
}

// containsRun reports whether needle appears as a contiguous run in hay.
func containsRun(hay, needle []string) bool {
	if len(needle) == 0 || len(needle) > len(hay) {
		return false
	}
	for i := 0; i+len(needle) <= len(hay); i++ {
		match := true
		for j := range needle {
			if hay[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// resolve returns the state for the longest lexicon phrase that appears as a
// contiguous token run in toRef, or "" when none matches. Ties (equal length) keep
// the earliest declared entry — deterministic.
func (l *stateLexicon) resolve(machine, toRef string) string {
	entries := l.byMachine[machine]
	if len(entries) == 0 {
		return ""
	}
	hay := lexTokens(toRef)
	best := ""
	bestLen := 0
	for _, e := range entries {
		if len(e.words) > bestLen && containsRun(hay, e.words) {
			best = e.state
			bestLen = len(e.words)
		}
	}
	return best
}

// validateStates asserts every lexicon state exists (non-empty) in its named
// machine's template states; a typo fails generation rather than mis-routing.
func (l *stateLexicon) validateStates(tmpl *semanticTemplateDoc) error {
	stateSet := map[string]map[string]bool{}
	for _, m := range tmpl.Machines {
		s := map[string]bool{}
		for _, st := range m.States {
			s[st.Name] = true
		}
		stateSet[m.Name] = s
	}
	for machine, entries := range l.byMachine {
		states, ok := stateSet[machine]
		if !ok {
			return fmt.Errorf("state lexicon: machine %q not defined in template", machine)
		}
		for _, e := range entries {
			if !states[e.state] {
				return fmt.Errorf("state lexicon: machine %q state %q not defined in template", machine, e.state)
			}
		}
	}
	return nil
}
