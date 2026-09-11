package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	semanticStatusEmitted         = "emitted"
	semanticStatusPendingTemplate = "pending_template"
	semanticStatusPendingAction   = "pending_action"
)

type semanticTemplateDoc struct {
	Version  int                       `json:"version"`
	Machines []semanticMachineTemplate `json:"machines"`
}

type semanticMachineTemplate struct {
	Name        string                    `json:"name"`
	File        string                    `json:"file"`
	Constructor string                    `json:"constructor,omitempty"`
	InitState   string                    `json:"init_state"`
	States      []irState                 `json:"states"`
	Transitions []irTransition            `json:"transitions"`
	Bindings    []semanticBindingTemplate `json:"bindings,omitempty"`
}

type semanticBindingTemplate struct {
	ID                string        `json:"id"`
	Match             semanticMatch `json:"match"`
	From              string        `json:"from"`
	To                string        `json:"to"`
	LabelPrefix       string        `json:"label_prefix,omitempty"`
	DescriptionPrefix string        `json:"description_prefix,omitempty"`
	Tags              []string      `json:"tags,omitempty"`
	Weight            int           `json:"weight,omitempty"`
	Action            *irAction     `json:"action,omitempty"`
	Oracle            *irOracle     `json:"oracle,omitempty"`
}

type semanticMatch struct {
	RuleID           string `json:"rule_id,omitempty"`
	Domain           string `json:"domain,omitempty"`
	Surface          string `json:"surface,omitempty"`
	SurfaceContains  string `json:"surface_contains,omitempty"`
	Class            string `json:"class,omitempty"`
	ExecutionKind    string `json:"execution_kind,omitempty"`
	SupportStatus    string `json:"support_status,omitempty"`
	Action           string `json:"action,omitempty"`
	Protocol         string `json:"protocol,omitempty"`
	ProtocolContains string `json:"protocol_contains,omitempty"`
	Builder          string `json:"builder,omitempty"`
	RawTextRegex     string `json:"raw_text_regex,omitempty"`
}

type semanticDerivation struct {
	Machines []irMachine
	Files    map[string]string
	Report   semanticReport
}

type semanticReport struct {
	Template          string                           `json:"template,omitempty"`
	TotalMachines     int                              `json:"total_machines"`
	TotalTransitions  int                              `json:"total_transitions"`
	StaticTransitions int                              `json:"static_transitions"`
	BoundRules        int                              `json:"bound_rules"`
	PendingTemplate   int                              `json:"pending_template"`
	PendingAction     int                              `json:"pending_action"`
	ByMachine         map[string]semanticMachineReport `json:"by_machine,omitempty"`
}

type semanticMachineReport struct {
	File              string `json:"file"`
	States            int    `json:"states"`
	StaticTransitions int    `json:"static_transitions"`
	BoundTransitions  int    `json:"bound_transitions"`
	TotalTransitions  int    `json:"total_transitions"`
}

func deriveSemantic(path string, d *derivation, edgeIdx map[string][]astEdge, lex *stateLexicon) (semanticDerivation, error) {
	tmpl, err := loadSemanticTemplate(path)
	if err != nil {
		return semanticDerivation{}, err
	}
	if err := validateSemanticTemplate(tmpl); err != nil {
		return semanticDerivation{}, err
	}
	if lex != nil {
		if err := lex.validateStates(tmpl); err != nil {
			return semanticDerivation{}, err
		}
	}

	out := semanticDerivation{
		Files: map[string]string{},
		Report: semanticReport{
			Template:  path,
			ByMachine: map[string]semanticMachineReport{},
		},
	}
	actionByRule := semanticActionIndex(d.Machines)
	bound := map[string]bool{}

	for _, mt := range tmpl.Machines {
		m := irMachine{
			Name:        mt.Name,
			Constructor: mt.Constructor,
			InitState:   mt.InitState,
			States:      append([]irState(nil), mt.States...),
		}
		m.Transitions = append(m.Transitions, mt.Transitions...)
		staticCount := len(mt.Transitions)
		boundCount := 0

		for _, b := range mt.Bindings {
			for i := range d.Plans {
				p := &d.Plans[i]
				if bound[p.RuleID] || !b.Match.matches(*p) {
					continue
				}
				base, ok := actionByRule[p.RuleID]
				if !ok {
					p.SemanticStatus = semanticStatusPendingAction
					out.Report.PendingAction++
					bound[p.RuleID] = true
					continue
				}
				overrideFrom := resolveTemporalFrom(mt, b, edgeIdx[p.RuleID], lex)
				tr := semanticTransitionFromPlan(mt, b, base, *p, overrideFrom)
				m.Transitions = append(m.Transitions, tr)
				p.SemanticMachine = mt.Name
				p.SemanticBinding = b.ID
				p.SemanticStatus = semanticStatusEmitted
				bound[p.RuleID] = true
				boundCount++
				out.Report.BoundRules++
			}
		}

		out.Machines = append(out.Machines, m)
		out.Files[m.Name] = mt.File
		out.Report.ByMachine[m.Name] = semanticMachineReport{
			File:              mt.File,
			States:            len(m.States),
			StaticTransitions: staticCount,
			BoundTransitions:  boundCount,
			TotalTransitions:  len(m.Transitions),
		}
		out.Report.TotalMachines++
		out.Report.StaticTransitions += staticCount
		out.Report.TotalTransitions += len(m.Transitions)
	}

	for i := range d.Plans {
		p := &d.Plans[i]
		if p.ExecutionKind != execStateful {
			continue
		}
		if p.EmitTarget == emitSequenceFollowup {
			p.SemanticStatus = emitSequenceFollowup
			continue
		}
		if p.SupportStatus != statusSupported {
			if p.SemanticStatus == "" {
				p.SemanticStatus = p.SupportStatus
			}
			continue
		}
		if p.SemanticStatus == "" {
			if _, ok := actionByRule[p.RuleID]; ok {
				p.SemanticStatus = semanticStatusPendingTemplate
				out.Report.PendingTemplate++
			} else {
				p.SemanticStatus = semanticStatusPendingAction
				out.Report.PendingAction++
			}
		}
	}
	return out, nil
}

func loadSemanticTemplate(path string) (*semanticTemplateDoc, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var doc semanticTemplateDoc
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("parse semantic template %s: %w", path, err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("parse semantic template %s: unexpected trailing JSON", path)
	}
	return &doc, nil
}

func validateSemanticTemplate(doc *semanticTemplateDoc) error {
	if doc.Version != 1 {
		return fmt.Errorf("semantic template version = %d, want 1", doc.Version)
	}
	if len(doc.Machines) == 0 {
		return fmt.Errorf("semantic template must define at least one machine")
	}
	machineNames := map[string]bool{}
	files := map[string]bool{}
	for mi, m := range doc.Machines {
		base := fmt.Sprintf("machines[%d]", mi)
		if m.Name == "" {
			return fmt.Errorf("%s.name is required", base)
		}
		if machineNames[m.Name] {
			return fmt.Errorf("%s.name duplicates machine %q", base, m.Name)
		}
		machineNames[m.Name] = true
		if m.File == "" {
			return fmt.Errorf("%s.file is required", base)
		}
		if files[m.File] {
			return fmt.Errorf("%s.file duplicates output file %q", base, m.File)
		}
		files[m.File] = true
		states := map[string]bool{}
		terminal := map[string]bool{}
		for si, s := range m.States {
			if s.Name == "" {
				return fmt.Errorf("%s.states[%d].name is required", base, si)
			}
			if states[s.Name] {
				return fmt.Errorf("%s.states[%d].name duplicates state %q", base, si, s.Name)
			}
			states[s.Name] = true
			if s.Terminal {
				terminal[s.Name] = true
			}
		}
		if !states[m.InitState] {
			return fmt.Errorf("%s.init_state %q is not defined", base, m.InitState)
		}
		labels := map[string]bool{}
		for ti, tr := range m.Transitions {
			if err := validateSemanticTransition(base, ti, tr, states, terminal, labels); err != nil {
				return err
			}
		}
		bindingIDs := map[string]bool{}
		for bi, b := range m.Bindings {
			bbase := fmt.Sprintf("%s.bindings[%d]", base, bi)
			if b.ID == "" {
				return fmt.Errorf("%s.id is required", bbase)
			}
			if bindingIDs[b.ID] {
				return fmt.Errorf("%s.id duplicates binding %q", bbase, b.ID)
			}
			bindingIDs[b.ID] = true
			if b.Match.empty() {
				return fmt.Errorf("%s.match must set at least one matcher", bbase)
			}
			if b.Match.RawTextRegex != "" {
				if _, err := regexp.Compile(b.Match.RawTextRegex); err != nil {
					return fmt.Errorf("%s.match.raw_text_regex: %w", bbase, err)
				}
			}
			if !states[b.From] {
				return fmt.Errorf("%s.from references undefined state %q", bbase, b.From)
			}
			if !states[b.To] {
				return fmt.Errorf("%s.to references undefined state %q", bbase, b.To)
			}
			if terminal[b.From] {
				return fmt.Errorf("%s.from leaves terminal state %q", bbase, b.From)
			}
			if b.Action != nil {
				if err := validateSemanticAction(b.Action, bbase+".action"); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func validateSemanticTransition(base string, idx int, tr irTransition, states, terminal, labels map[string]bool) error {
	tbase := fmt.Sprintf("%s.transitions[%d]", base, idx)
	if !states[tr.From] {
		return fmt.Errorf("%s.from references undefined state %q", tbase, tr.From)
	}
	if !states[tr.To] {
		return fmt.Errorf("%s.to references undefined state %q", tbase, tr.To)
	}
	if terminal[tr.From] {
		return fmt.Errorf("%s leaves terminal state %q", tbase, tr.From)
	}
	if tr.Label == "" {
		return fmt.Errorf("%s.label is required", tbase)
	}
	if labels[tr.Label] {
		return fmt.Errorf("%s.label duplicates %q", tbase, tr.Label)
	}
	labels[tr.Label] = true
	if tr.Action == nil {
		return fmt.Errorf("%s.action is required", tbase)
	}
	return validateSemanticAction(tr.Action, tbase+".action")
}

func validateSemanticAction(a *irAction, path string) error {
	if a.Type == "" {
		return fmt.Errorf("%s.type is required", path)
	}
	if !semanticActionNames[a.Type] {
		return fmt.Errorf("%s.type unknown action %q", path, a.Type)
	}
	if a.Payload != nil {
		switch a.Payload.Kind {
		case "literal":
			set := 0
			if a.Payload.Bytes != "" {
				set++
			}
			if a.Payload.Size != nil {
				set++
			}
			if a.Payload.Null {
				set++
			}
			if set != 1 {
				return fmt.Errorf("%s.payload literal must set exactly one of bytes|size|null", path)
			}
		case "fields":
			if len(a.Payload.Fields) == 0 {
				return fmt.Errorf("%s.payload fields must be non-empty", path)
			}
		case "builder":
			if a.Payload.Name == "" {
				return fmt.Errorf("%s.payload builder requires name", path)
			}
		default:
			return fmt.Errorf("%s.payload.kind unknown %q", path, a.Payload.Kind)
		}
	}
	return nil
}

var semanticActionNames = map[string]bool{
	"ActSendReqResp": true, "ActOpenStream": true, "ActWritePartial": true,
	"ActWriteAndClose": true, "ActReadResponse": true, "ActSleep": true,
	"ActReconnect": true, "ActInjectGossip": true, "ActCheckConnected": true,
	"ActSwitchTopic": true, "ActConnectRaw": true, "ActSendStatus": true,
	"ActDisconnectPeer": true, "ActRequestCustodyColumns": true, "ActQueryENR": true,
	"ActQueryPeerList": true, "ActVerifyENRBehavior": true, "ActResolveSubnets": true,
	"ActValidateResponseOrder": true,
}

func semanticActionIndex(machines []irMachine) map[string]irTransition {
	out := map[string]irTransition{}
	for _, m := range machines {
		for _, tr := range m.Transitions {
			for _, ref := range tr.SpecRefs {
				if ref == "" {
					continue
				}
				if _, ok := out[ref]; !ok {
					out[ref] = tr
				}
			}
		}
	}
	return out
}

// resolveTemporalFrom returns a spec-derived FROM state for a rule's temporal edge,
// or "" when nothing applies. It anchors upon/once/after edges to the lexicon-resolved
// state, but only when that state is real, non-terminal, and neither the binding's from
// nor to (the latter would be a self-loop). before/until edges stay cosmetic.
func resolveTemporalFrom(mt semanticMachineTemplate, b semanticBindingTemplate, edges []astEdge, lex *stateLexicon) string {
	if lex == nil {
		return ""
	}
	stateOK := map[string]bool{}
	term := map[string]bool{}
	for _, s := range mt.States {
		stateOK[s.Name] = true
		if s.Terminal {
			term[s.Name] = true
		}
	}
	for _, e := range edges {
		if e.Kind != "temporal" {
			continue
		}
		switch e.Rel {
		case "upon", "once", "after":
		default:
			continue
		}
		s := lex.resolve(mt.Name, e.ToRef)
		if s == "" || !stateOK[s] || term[s] || s == b.From || s == b.To {
			continue
		}
		return s
	}
	return ""
}

func semanticTransitionFromPlan(mt semanticMachineTemplate, b semanticBindingTemplate, base irTransition, p executionPlan, overrideFrom string) irTransition {
	tr := base
	tr.From = b.From
	if overrideFrom != "" {
		tr.From = overrideFrom
	}
	tr.To = b.To
	tr.Label = semanticLabel(b, p)
	if b.Weight > 0 {
		tr.Weight = b.Weight
	}
	if b.DescriptionPrefix != "" {
		tr.Description = b.DescriptionPrefix + ": " + tr.Description
	}
	if len(tr.SpecRefs) == 0 {
		tr.SpecRefs = []string{p.RuleID}
	} else {
		tr.SpecRefs = append([]string(nil), tr.SpecRefs...)
	}
	tr.Tags = append(append([]string(nil), tr.Tags...), "semantic:"+mt.Name, "binding:"+b.ID)
	tr.Tags = append(tr.Tags, b.Tags...)
	if overrideFrom != "" {
		tr.Tags = append(tr.Tags, "temporal_derived", "spec_from:"+overrideFrom)
	}
	if b.Action != nil {
		tr.Action = b.Action
	}
	if b.Oracle != nil {
		tr.Oracle = b.Oracle
	}
	return tr
}

func semanticLabel(b semanticBindingTemplate, p executionPlan) string {
	prefix := b.LabelPrefix
	if prefix == "" {
		prefix = "sem_" + sanitizeLabel(b.ID)
	}
	surface := p.Surface
	if surface == "" {
		surface = p.Domain
	}
	if p.Class != "" {
		surface += "_" + p.Class
	}
	return prefix + "_" + sanitizeLabel(surface) + "_" + hash8(p.RuleID)
}

func (m semanticMatch) empty() bool {
	return m.RuleID == "" && m.Domain == "" && m.Surface == "" && m.SurfaceContains == "" &&
		m.Class == "" && m.ExecutionKind == "" && m.SupportStatus == "" && m.Action == "" &&
		m.Protocol == "" && m.ProtocolContains == "" && m.Builder == "" && m.RawTextRegex == ""
}

func (m semanticMatch) matches(p executionPlan) bool {
	if m.RuleID != "" && m.RuleID != p.RuleID {
		return false
	}
	if m.Domain != "" && m.Domain != p.Domain {
		return false
	}
	if m.Surface != "" && m.Surface != p.Surface {
		return false
	}
	if m.SurfaceContains != "" && !strings.Contains(strings.ToLower(p.Surface), strings.ToLower(m.SurfaceContains)) {
		return false
	}
	if m.Class != "" && m.Class != p.Class {
		return false
	}
	if m.ExecutionKind != "" && m.ExecutionKind != p.ExecutionKind {
		return false
	}
	if m.SupportStatus != "" && m.SupportStatus != p.SupportStatus {
		return false
	}
	if m.Action != "" && m.Action != p.Action {
		return false
	}
	if m.Protocol != "" && m.Protocol != p.Protocol {
		return false
	}
	if m.ProtocolContains != "" && !strings.Contains(strings.ToLower(p.Protocol), strings.ToLower(m.ProtocolContains)) {
		return false
	}
	if m.Builder != "" && m.Builder != p.Builder {
		return false
	}
	if m.RawTextRegex != "" && !regexp.MustCompile(m.RawTextRegex).MatchString(p.RawText) {
		return false
	}
	return true
}

func staleSemanticMachines(s semanticDerivation, outDir string) []string {
	expected := semanticFileSet(s)
	stale := staleMachineList(s.Machines, outDir, func(m irMachine) string {
		if f := s.Files[m.Name]; f != "" {
			return f
		}
		return strings.ToLower(sanitizeLabel(m.Name)) + ".json"
	})
	files, err := filepath.Glob(filepath.Join(outDir, "*.json"))
	if err != nil {
		stale = append(stale, "glob:"+err.Error())
		sort.Strings(stale)
		return stale
	}
	for _, path := range files {
		name := filepath.Base(path)
		if !expected[name] {
			stale = append(stale, "extra:"+name)
		}
	}
	sort.Strings(stale)
	return stale
}

func semanticFileSet(s semanticDerivation) map[string]bool {
	expected := map[string]bool{}
	for _, m := range s.Machines {
		if f := s.Files[m.Name]; f != "" {
			expected[f] = true
		}
	}
	return expected
}
