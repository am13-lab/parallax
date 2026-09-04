package main

import (
	"encoding/json"
	"sort"
	"strings"
)

const sequenceArtifactVersion = 1

type sequenceTestArtifact struct {
	Version    int                `json:"version"`
	Source     string             `json:"source"`
	TotalRules int                `json:"total_rules"`
	Cases      []sequenceTestCase `json:"cases"`
}

type sequenceTestCase struct {
	ID       string             `json:"id"`
	Category string             `json:"category"`
	Domain   string             `json:"domain"`
	Surface  string             `json:"surface"`
	Template string             `json:"template"`
	RuleIDs  []string           `json:"rule_ids"`
	Steps    []sequenceTestStep `json:"steps"`
}

type sequenceTestStep struct {
	Role       string       `json:"role"`
	Transition irTransition `json:"transition"`
}

type cryptoSequenceSpec struct {
	template  string
	builder   string
	protocol  string
	poolDelta bool
}

var cryptoSequenceRuleSpecs = map[string]cryptoSequenceSpec{
	"BEACON_AGGREGATE_AND_PROOF-IGNORE-7c1a7594": {
		template: "duplicate_first_seen", builder: "buildLiveValidBeaconAggregateAndProof", protocol: "beacon_aggregate_and_proof",
	},
	"BLOB_SIDECAR-IGNORE-ed3428e1": {
		template: "duplicate_first_seen", builder: "buildLiveValidBlobSidecar", protocol: "blob_sidecar_0",
	},
	"BLS_TO_EXECUTION_CHANGE-IGNORE-b226c668": {
		template: "duplicate_first_seen", builder: "buildLiveValidBlsToExecutionChange", protocol: "bls_to_execution_change", poolDelta: true,
	},
	"DATA_COLUMN_SIDECAR-IGNORE-869c65a5": {
		template: "duplicate_first_seen", builder: "buildLiveValidDataColumnSidecar", protocol: "data_column_sidecar_0",
	},
	"SYNC_COMMITTEE_MESSAGE-IGNORE-7708bbcf": {
		template: "duplicate_first_seen", builder: "buildLiveValidSyncCommitteeMessage", protocol: "sync_committee_0",
	},
	"VOLUNTARY_EXIT-IGNORE-c9db1ebe": {
		template: "duplicate_first_seen", builder: "buildLiveValidVoluntaryExit", protocol: "voluntary_exit", poolDelta: true,
	},
}

func cryptoSequenceSpecForRule(res resolved) (cryptoSequenceSpec, bool) {
	spec, ok := cryptoSequenceRuleSpecs[res.rule.ID]
	return spec, ok
}

func cryptoRuleRequiresInspector(res resolved) bool {
	switch res.rule.ID {
	case "SYNC_COMMITTEE_MESSAGE-REJECT-c428cd4e":
		return true
	default:
		return false
	}
}

type sequenceGroup struct {
	category  string
	domain    string
	surface   string
	template  string
	signature string
	steps     []sequenceTestStep
	ruleIDs   []string
}

func deriveSequenceTests(resolveds []resolved) sequenceTestArtifact {
	groupsBySig := map[string]*sequenceGroup{}

	for _, res := range resolveds {
		if res.domain != domGossip || !isCryptoMsgCandidate(res) {
			continue
		}
		p := classifyCryptoPlan(res)
		if p.EmitTarget != emitSequenceFollowup || p.SupportStatus != statusSupported {
			continue
		}
		spec, ok := cryptoSequenceSpecForRule(res)
		if !ok {
			continue
		}
		g := sequenceGroupForRule(res, p, spec)
		if g == nil {
			continue
		}
		if groupsBySig[g.signature] == nil {
			groupsBySig[g.signature] = g
		}
		groupsBySig[g.signature].ruleIDs = append(groupsBySig[g.signature].ruleIDs, p.RuleID)
	}

	groups := make([]*sequenceGroup, 0, len(groupsBySig))
	totalRules := 0
	for _, g := range groupsBySig {
		sort.Strings(g.ruleIDs)
		g.ruleIDs = uniqueStrings(g.ruleIDs)
		totalRules += len(g.ruleIDs)
		hash := hash8(g.signature)
		for i := range g.steps {
			tr := &g.steps[i].Transition
			tr.Label = sequenceStepLabel(g.surface, g.template, g.steps[i].Role, hash)
			if g.steps[i].Role == "probe" {
				tr.SpecRefs = append([]string(nil), g.ruleIDs...)
				tr.Description = "generated sequence probe for " + strings.Join(g.ruleIDs, ", ")
			}
		}
		groups = append(groups, g)
	}
	sort.Slice(groups, func(i, j int) bool {
		li := sequenceCaseID(groups[i])
		lj := sequenceCaseID(groups[j])
		if li != lj {
			return li < lj
		}
		return groups[i].signature < groups[j].signature
	})

	cases := make([]sequenceTestCase, 0, len(groups))
	for _, g := range groups {
		cases = append(cases, sequenceTestCase{
			ID:       sequenceCaseID(g),
			Category: g.category,
			Domain:   g.domain,
			Surface:  g.surface,
			Template: g.template,
			RuleIDs:  append([]string(nil), g.ruleIDs...),
			Steps:    append([]sequenceTestStep(nil), g.steps...),
		})
	}

	return sequenceTestArtifact{
		Version:    sequenceArtifactVersion,
		Source:     "cmd/irderive",
		TotalRules: totalRules,
		Cases:      cases,
	}
}

func sequenceGroupForRule(res resolved, p executionPlan, spec cryptoSequenceSpec) *sequenceGroup {
	category := statelessCategory(p.Domain)
	if category == "" {
		return nil
	}
	surface := p.Surface
	if surface == "" {
		surface = p.Topic
	}
	cacheKey := "seq_" + sanitizeLabel(surface+"_"+spec.template)
	setup := irTransition{
		From:        "CryptoReady",
		To:          "CryptoPrimed",
		Description: "sequence setup: valid signed " + surface + " baseline",
		Action: &irAction{
			Type:     "ActInjectGossip",
			Protocol: spec.protocol,
			Payload:  &irPayload{Kind: "builder", Name: spec.builder, Wrap: "raw", CacheStore: cacheKey},
		},
		Guard:  guardFromProvenance(res.rule),
		Oracle: &irOracle{Differential: true},
	}
	probe := irTransition{
		From:        "CryptoPrimed",
		To:          "CryptoDone",
		Weight:      weightForModal(res.rule.Modal),
		Description: res.rule.RawText + descPredicate(res.rule),
		SpecRefs:    []string{res.rule.ID},
		Action: &irAction{
			Type:      "ActInjectGossip",
			Protocol:  spec.protocol,
			Payload:   &irPayload{Kind: "builder", Name: spec.builder, Wrap: "raw", CacheLoad: cacheKey},
			PoolDelta: spec.poolDelta,
		},
		Guard:  guardFromProvenance(res.rule),
		Oracle: synthOracle(res.rule.Modal, "REJECT"),
	}
	steps := []sequenceTestStep{
		{Role: "setup", Transition: setup},
		{Role: "probe", Transition: probe},
	}
	sig := sequenceSignature(category, surface, spec.template, steps)
	return &sequenceGroup{
		category:  category,
		domain:    p.Domain,
		surface:   surface,
		template:  spec.template,
		signature: sig,
		steps:     steps,
	}
}

func sequenceSignature(category, surface, template string, steps []sequenceTestStep) string {
	sig := struct {
		Category string             `json:"category"`
		Surface  string             `json:"surface"`
		Template string             `json:"template"`
		Steps    []sequenceTestStep `json:"steps"`
	}{
		Category: category,
		Surface:  surface,
		Template: template,
		Steps:    steps,
	}
	data, _ := json.Marshal(sig)
	return string(data)
}

func sequenceStepLabel(surface, template, role, hash string) string {
	label := sanitizeLabel(surface + "_" + template + "_" + role)
	if label == "" {
		label = role
	}
	return "cm_sequence_" + label + "_" + hash
}

func sequenceCaseID(g *sequenceGroup) string {
	return g.category + ".generated_sequence." + slugOrDefault(g.surface, g.category) + "." + slugOrDefault(g.template, "sequence") + "." + hash8(g.signature)
}
