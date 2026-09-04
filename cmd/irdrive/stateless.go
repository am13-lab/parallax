package main

import (
	"encoding/json"
	"sort"
	"strings"
)

const statelessArtifactVersion = 1

type statelessTestArtifact struct {
	Version    int                 `json:"version"`
	Source     string              `json:"source"`
	TotalRules int                 `json:"total_rules"`
	Cases      []statelessTestCase `json:"cases"`
}

type statelessTestCase struct {
	ID         string       `json:"id"`
	Category   string       `json:"category"`
	Domain     string       `json:"domain"`
	Surface    string       `json:"surface"`
	Probe      string       `json:"probe"`
	RuleIDs    []string     `json:"rule_ids"`
	Transition irTransition `json:"transition"`
}

type statelessGroup struct {
	category   string
	domain     string
	surface    string
	probe      string
	signature  string
	transition irTransition
	ruleIDs    []string
}

func deriveStatelessTests(resolveds []resolved, entries []dictEntry, knownProto map[string]bool, edgeIdx map[string][]astEdge) statelessTestArtifact {
	groupsBySig := map[string]*statelessGroup{}

	for _, res := range resolveds {
		tr, p, ok := statelessTransitionForResolved(res, entries, knownProto, edgeIdx)
		if !ok {
			continue
		}
		category := statelessCategory(p.Domain)
		if category == "" {
			continue
		}
		surface := p.Surface
		if surface == "" {
			surface = category
		}
		probe := statelessProbeName(tr.Action)
		sig := statelessSignature(category, surface, tr)
		if groupsBySig[sig] == nil {
			groupsBySig[sig] = &statelessGroup{
				category:   category,
				domain:     p.Domain,
				surface:    surface,
				probe:      probe,
				signature:  sig,
				transition: tr,
			}
		}
		groupsBySig[sig].ruleIDs = append(groupsBySig[sig].ruleIDs, p.RuleID)
	}

	groups := make([]*statelessGroup, 0, len(groupsBySig))
	totalRules := 0
	for _, g := range groupsBySig {
		sort.Strings(g.ruleIDs)
		g.ruleIDs = uniqueStrings(g.ruleIDs)
		totalRules += len(g.ruleIDs)
		hash := hash8(g.signature)
		g.transition.Label = statelessTransitionLabel(g.surface, g.probe, hash)
		g.transition.SpecRefs = append([]string(nil), g.ruleIDs...)
		g.transition.Description = "generated stateless probe for " + strings.Join(g.ruleIDs, ", ")
		groups = append(groups, g)
	}
	sort.Slice(groups, func(i, j int) bool {
		li := statelessCaseID(groups[i])
		lj := statelessCaseID(groups[j])
		if li != lj {
			return li < lj
		}
		return groups[i].signature < groups[j].signature
	})

	cases := make([]statelessTestCase, 0, len(groups))
	for _, g := range groups {
		cases = append(cases, statelessTestCase{
			ID:         statelessCaseID(g),
			Category:   g.category,
			Domain:     g.domain,
			Surface:    g.surface,
			Probe:      g.probe,
			RuleIDs:    append([]string(nil), g.ruleIDs...),
			Transition: g.transition,
		})
	}

	return statelessTestArtifact{
		Version:    statelessArtifactVersion,
		Source:     "cmd/irderive",
		TotalRules: totalRules,
		Cases:      cases,
	}
}

func statelessTransitionForResolved(res resolved, entries []dictEntry, knownProto map[string]bool, edgeIdx map[string][]astEdge) (irTransition, executionPlan, bool) {
	if res.domain == domNone {
		return irTransition{}, executionPlan{}, false
	}
	if res.domain == domGossip && isCryptoMsgCandidate(res) {
		p := classifyCryptoPlan(res)
		if !isSupportedStatelessPlan(p) {
			return irTransition{}, p, false
		}
		tr, _, ok := emitCryptoRule(res, cryptoTemplate(), edgeIdx)
		return tr, p, ok
	}

	p := classifyResolvedPlan(res, entries, knownProto, edgeIdx)
	if !isSupportedStatelessPlan(p) {
		return irTransition{}, p, false
	}
	tmplFn := domainTemplate[p.Domain]
	if tmplFn == nil {
		return irTransition{}, p, false
	}
	tr, _, ok := emitRule(res, tmplFn(), entries, knownProto, edgeIdx)
	return tr, p, ok
}

func isSupportedStatelessPlan(p executionPlan) bool {
	return p.ExecutionKind == execStateless &&
		p.SupportStatus == statusSupported &&
		p.EmitTarget == emitStatelessFollowup
}

func statelessCategory(domain string) string {
	switch domain {
	case domReqResp:
		return "reqresp"
	case domDiscovery:
		return "discovery"
	case domGossip:
		return "gossipsub"
	case domCrypto:
		return "cryptomsg"
	default:
		return ""
	}
}

func statelessSignature(category, surface string, tr irTransition) string {
	sig := struct {
		Category string    `json:"category"`
		Surface  string    `json:"surface"`
		Action   *irAction `json:"action"`
		Guard    *irGuard  `json:"guard,omitempty"`
		Oracle   *irOracle `json:"oracle,omitempty"`
	}{
		Category: category,
		Surface:  surface,
		Action:   tr.Action,
		Guard:    tr.Guard,
		Oracle:   tr.Oracle,
	}
	data, _ := json.Marshal(sig)
	return string(data)
}

func statelessProbeName(action *irAction) string {
	if action == nil {
		return "probe"
	}
	parts := []string{action.Type}
	if action.Payload != nil {
		switch action.Payload.Kind {
		case "builder":
			parts = append(parts, action.Payload.Name)
		case "fields":
			parts = append(parts, "fields")
		case "literal":
			parts = append(parts, "literal")
		}
	}
	if action.Mutator != "" {
		parts = append(parts, action.Mutator)
	}
	if len(parts) == 1 && action.Protocol != "" {
		parts = append(parts, action.Protocol)
	}
	return sanitizeLabel(strings.Join(parts, "_"))
}

func statelessTransitionLabel(surface, probe, hash string) string {
	label := sanitizeLabel(surface + "_" + probe)
	if label == "" {
		label = "probe"
	}
	return "stateless_" + label + "_" + hash
}

func statelessCaseID(g *statelessGroup) string {
	return g.category + ".generated." + slugOrDefault(g.surface, g.category) + "." + slugOrDefault(g.probe, "probe") + "." + hash8(g.signature)
}

func slugOrDefault(value, fallback string) string {
	if s := sanitizeLabel(value); s != "" {
		return s
	}
	return sanitizeLabel(fallback)
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := values[:0]
	prev := ""
	for i, v := range values {
		if i == 0 || v != prev {
			out = append(out, v)
			prev = v
		}
	}
	return out
}
