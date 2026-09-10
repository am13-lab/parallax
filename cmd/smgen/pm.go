package main

import (
	"encoding/json"
	"os"
)

// ProtocolModel is SM-IR Layer 0: the typed inventory of Req/Resp methods used
// by gate 3 (payload type-check) and by fields-kind payload codegen.
type ProtocolModel struct {
	Methods []PMMethod `json:"methods"`
	// Forks lists every fork the spec scan observed, including feature forks
	// (specs/_features/<feature>, named by feature). gate7 accepts forks from
	// this list in addition to the hardcoded forkRank ordering.
	Forks []string `json:"forks,omitempty"`
	// Availability maps a protocol ID to its fork window. It lets gate 7 check
	// that every protocol used by the IR has known fork availability and that
	// the named forks are valid.
	Availability map[string]PMAvailability `json:"availability,omitempty"`

	byProto map[string]*PMMethod // protocol ID -> method (built on load)
	forkSet map[string]bool      // forks listed in Forks (built on load)
}

// PMAvailability is the fork window in which a protocol ID is valid.
// DeprecatedFork is empty when the protocol is still current.
type PMAvailability struct {
	IntroducedFork string `json:"introduced_fork"`
	DeprecatedFork string `json:"deprecated_fork,omitempty"`
}

// PMMethod is one Req/Resp method and its request schema.
type PMMethod struct {
	Name        string    `json:"name"`
	ProtocolIDs []string  `json:"protocol_ids"`
	Request     PMRequest `json:"request"`
}

// PMRequest describes the request body shape.
//   - container "fixed":    all-fixed-size SSZ fields; fields-codegen supported.
//   - container "variable": offset-encoded SSZ; must use a named builder.
//   - container "none":     no request body.
type PMRequest struct {
	Container string    `json:"container"`
	Fields    []PMField `json:"fields,omitempty"`
	Note      string    `json:"note,omitempty"`
}

// PMField is one fixed-size SSZ field. Type is "uint64" or "bytes"; Size is the
// serialized byte width.
type PMField struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Size int    `json:"size"`
}

// loadProtocolModel reads protocol_model.json and indexes it by protocol ID.
// A missing file yields (nil, nil) so callers can treat the model as optional
// (gate 3 then reports a skip rather than failing).
func loadProtocolModel(path string) (*ProtocolModel, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var pm ProtocolModel
	if err := json.Unmarshal(data, &pm); err != nil {
		return nil, err
	}
	pm.byProto = map[string]*PMMethod{}
	pm.forkSet = map[string]bool{}
	for _, f := range pm.Forks {
		pm.forkSet[f] = true
	}
	for i := range pm.Methods {
		for _, id := range pm.Methods[i].ProtocolIDs {
			pm.byProto[id] = &pm.Methods[i]
		}
	}
	return &pm, nil
}

// knownModelFork reports whether name is a fork the protocol model declares
// (hardcoded forkRank ordering plus feature forks from the spec scan).
func (pm *ProtocolModel) knownModelFork(name string) bool {
	if knownFork(name) {
		return true
	}
	return pm.forkSet[name]
}

// method returns the method serving the given protocol ID.
func (pm *ProtocolModel) method(protocolID string) (*PMMethod, bool) {
	m, ok := pm.byProto[protocolID]
	return m, ok
}

// availabilityFor returns the fork window declared for a protocol ID.
func (pm *ProtocolModel) availabilityFor(protocolID string) (PMAvailability, bool) {
	a, ok := pm.Availability[protocolID]
	return a, ok
}

// forkRank orders the consensus-spec forks (CLAUDE.md fork order). A fork not in
// this list has rank -1 (unknown). Used to validate availability fork names and,
// later, to compare against a machine's target fork.
var forkRank = map[string]int{
	"phase0": 0, "altair": 1, "bellatrix": 2, "capella": 3, "deneb": 4,
	"electra": 5, "fulu": 6, "gloas": 7, "heze": 8,
}

func knownFork(name string) bool { _, ok := forkRank[name]; return ok }

// field returns the named field of a request schema and its index in field order.
func (r *PMRequest) field(name string) (*PMField, int, bool) {
	for i := range r.Fields {
		if r.Fields[i].Name == name {
			return &r.Fields[i], i, true
		}
	}
	return nil, -1, false
}
