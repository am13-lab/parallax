// Package knowledge resolves Parallax test traceability anchors against the
// knowledge base: the 534-rule consensus-spec P2P catalog (spec/) plus
// external audit and advisory anchors (references/index.json).
package knowledge

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SpecEntry is one rule from the consensus-spec P2P catalog.
type SpecEntry struct {
	ID                  string   `json:"id"`
	LegacyIDs           []string `json:"legacy_ids,omitempty"`
	Text                string   `json:"text"`
	Strength            string   `json:"strength,omitempty"`
	Protocol            string   `json:"protocol,omitempty"`
	RuleType            string   `json:"rule_type,omitempty"`
	ObservableInTraffic bool     `json:"observable_in_traffic,omitempty"`
}

// ExternalEntry is one external knowledge anchor (audit, advisory, prose
// hash family) and the reference document that backs it.
type ExternalEntry struct {
	Title string `json:"title"`
	Kind  string `json:"kind"`
	Path  string `json:"path"`
}

// Entry is what Resolve returns: whichever kind matched, with the resolved
// title and backing path.
type Entry struct {
	ID    string
	Title string
	Kind  string
	Path  string
}

// KB is the loaded knowledge base.
type KB struct {
	spec      map[string]SpecEntry // by ID and legacy ID
	external  map[string]ExternalEntry
	specDir   string
	loadedDir string
}

// Load reads the knowledge base from the given directory.
func Load(dir string) (*KB, error) {
	kb := &KB{
		spec:      map[string]SpecEntry{},
		external:  map[string]ExternalEntry{},
		specDir:   filepath.Join(dir, "spec"),
		loadedDir: dir,
	}

	catalogPath := filepath.Join(kb.specDir, "spec_rules_generated.json")
	raw, err := os.ReadFile(catalogPath)
	if err != nil {
		return nil, fmt.Errorf("read spec catalog: %w", err)
	}
	var catalog struct {
		Rules []SpecEntry `json:"rules"`
	}
	if err := json.Unmarshal(raw, &catalog); err != nil {
		return nil, fmt.Errorf("parse spec catalog: %w", err)
	}
	for _, r := range catalog.Rules {
		kb.spec[r.ID] = r
		for _, legacy := range r.LegacyIDs {
			kb.spec[legacy] = r
		}
	}

	// Legacy IDs that live only in the legacy map (catalog entries without
	// a legacy_ids field still resolve through it).
	legacyPath := filepath.Join(kb.specDir, "spec_rule_legacy_map.json")
	if raw, err := os.ReadFile(legacyPath); err == nil {
		var legacy map[string]struct {
			Text   string   `json:"text"`
			ASTIDs []string `json:"ast_ids"`
		}
		if err := json.Unmarshal(raw, &legacy); err == nil {
			for id, e := range legacy {
				if _, ok := kb.spec[id]; !ok {
					kb.spec[id] = SpecEntry{ID: id, Text: e.Text, LegacyIDs: e.ASTIDs}
				}
			}
		}
	}

	indexPath := filepath.Join(dir, "references", "index.json")
	raw, err = os.ReadFile(indexPath)
	if err != nil {
		return nil, fmt.Errorf("read references index: %w", err)
	}
	var index struct {
		Entries map[string]ExternalEntry `json:"entries"`
	}
	if err := json.Unmarshal(raw, &index); err != nil {
		return nil, fmt.Errorf("parse references index: %w", err)
	}
	kb.external = index.Entries
	return kb, nil
}

// ResolveSpec resolves a spec rule by catalog ID or legacy ID.
func (k *KB) ResolveSpec(id string) (SpecEntry, bool) {
	e, ok := k.spec[id]
	return e, ok
}

// Resolve resolves any anchor: exact spec rule IDs first, then external
// anchors matched by prefix (SHERLOCK-1140-004 resolves the SHERLOCK-1140
// entry). Spec-rule-strength anchors (PROSE-*, ETH2-SHOULD) resolve as
// external prose anchors.
func (k *KB) Resolve(id string) (Entry, bool) {
	if e, ok := k.spec[id]; ok {
		return Entry{ID: e.ID, Title: e.Text, Kind: "spec-rule", Path: "spec/spec_rules_generated.json"}, true
	}
	for prefix, ext := range k.external {
		if id == prefix || strings.HasPrefix(id, prefix+"-") {
			return Entry{
				ID:    id,
				Title: ext.Title,
				Kind:  ext.Kind,
				Path:  filepath.Join("references", ext.Path),
			}, true
		}
	}
	return Entry{}, false
}

// SpecRules returns every cataloged spec rule.
func (k *KB) SpecRules() []SpecEntry {
	out := make([]SpecEntry, 0, len(k.spec))
	seen := map[string]bool{}
	for _, e := range k.spec {
		if seen[e.ID] {
			continue
		}
		seen[e.ID] = true
		out = append(out, e)
	}
	return out
}
