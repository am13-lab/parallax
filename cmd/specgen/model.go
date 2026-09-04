package main

import (
	"encoding/json"
	"os"
)

type protocolModel struct {
	Description  string                      `json:"description"`
	Source       string                      `json:"source"`
	Availability map[string]availabilityItem `json:"availability"`
	Methods      []json.RawMessage           `json:"methods"`
}

type availabilityItem struct {
	IntroducedFork string `json:"introduced_fork"`
}

func updateProtocolModel(path string, surfaces []Surface) error {
	model := loadProtocolModel(path)
	if model.Availability == nil {
		model.Availability = map[string]availabilityItem{}
	}
	for _, surface := range surfaces {
		if surface.Kind != "protocol" || surface.ProtocolIDNorm == "" {
			continue
		}
		model.Availability[surface.ProtocolIDNorm] = availabilityItem{IntroducedFork: surface.IntroducedFork}
	}
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
