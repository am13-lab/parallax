package main

import (
	"encoding/json"
	"os"
	"sort"
)

type protocolModel struct {
	Description  string                      `json:"description"`
	Source       string                      `json:"source"`
	Forks        []string                    `json:"forks,omitempty"`
	Availability map[string]availabilityItem `json:"availability"`
	Methods      []json.RawMessage           `json:"methods"`
}

type availabilityItem struct {
	IntroducedFork string `json:"introduced_fork"`
}

func updateProtocolModel(path string, ast *RuleAST) error {
	model := loadProtocolModel(path)
	if model.Availability == nil {
		model.Availability = map[string]availabilityItem{}
	}
	seen := map[string]bool{}
	forks := map[string]bool{}
	for _, f := range forkOrder {
		forks[f] = true
	}
	for i := range ast.Rules {
		forks[ast.Rules[i].Source.Fork] = true
	}
	for _, surface := range ast.Surfaces {
		forks[surface.IntroducedFork] = true
		if surface.Kind != "protocol" || surface.ProtocolIDNorm == "" {
			continue
		}
		seen[surface.ProtocolIDNorm] = true
		model.Availability[surface.ProtocolIDNorm] = availabilityItem{IntroducedFork: surface.IntroducedFork}
	}
	// Prune only availability entries whose introduced_fork is unknown (e.g.
	// the literal "_features" or truncated parse artifacts like "ln").
	// Entries naming valid forks are cumulative metadata and are kept even
	// when the current scan did not re-observe the protocol definition.
	for k, av := range model.Availability {
		if !forks[av.IntroducedFork] {
			delete(model.Availability, k)
		}
	}
	model.Forks = nil
	for f := range forks {
		model.Forks = append(model.Forks, f)
	}
	sort.Strings(model.Forks)
	if model.Description == "" {
		model.Description = "Protocol model generated from consensus P2P spec surfaces"
	}
	if model.Source == "" {
		model.Source = "consensus-specs/specs/**/p2p-interface.md"
	}
	return writeJSON(path, model)
}

func loadProtocolModel(path string) protocolModel {
	data, err := os.ReadFile(path)
	if err != nil {
		return protocolModel{}
	}
	var model protocolModel
	if json.Unmarshal(data, &model) != nil {
		return protocolModel{}
	}
	return model
}
