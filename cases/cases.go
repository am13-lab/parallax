// Package cases contains the v1 seed test set: explicit spec values, no
// init registration. Cases receive chain-dependent values through
// runner.TestEnv.Chain and never hardcode them.
package cases

import (
	"fmt"
	"sort"

	"libp2p-difftest/runner"
)

// All returns every registered seed case.
func All() []runner.Spec {
	var all []runner.Spec
	all = append(all, reqrespSpecs()...)
	all = append(all, statusSpecs()...)
	all = append(all, batch2Specs()...)
	all = append(all, transportSpecs3()...)
	all = append(all, exhaustedSpecs()...)
	all = append(all, gossipSpecs3()...)
	all = append(all, protocolSpecs3()...)
	all = append(all, generatedCryptomsgSpecs()...)
	all = append(all, generatedStatemachineSpecs()...)
	all = append(all, generatedSemanticSpecs()...)
	all = append(all, gossipSpecs()...)
	all = append(all, discoverySpecs()...)
	all = append(all, enrSpecs()...)
	all = append(all, transportSpecs()...)
	return all
}

// ByID returns one case by stable ID.
func ByID(id string) (runner.Spec, bool) {
	for _, s := range All() {
		if s.ID == id {
			return s, true
		}
	}
	return runner.Spec{}, false
}

// ByCategory returns all cases in one category, preserving registration order.
func ByCategory(cat string) []runner.Spec {
	var out []runner.Spec
	for _, s := range All() {
		if s.Category == cat {
			out = append(out, s)
		}
	}
	return out
}

// outcome classifies a req/resp exchange into a comparable class:
// "accept" (success chunk), "reject" (reset, protocol error codes, failed
// exchange), or "other:<detail>" for anything unclassifiable.
func outcome(res *runner.ReqRespResult, err error) string {
	if err != nil {
		return "other:" + err.Error()
	}
	if res == nil {
		return "other:nil result"
	}
	if res.StreamReset {
		return "reject"
	}
	if res.Error != "" && len(res.RawBytes) == 0 {
		return "reject"
	}
	if len(res.ResponseChunks) == 0 {
		return "other:empty response"
	}
	switch res.ResponseChunks[0].ResultCode {
	case 0x00:
		return "accept"
	case 0x01, 0x02, 0x03:
		return "reject"
	default:
		return fmt.Sprintf("other:unknown result code %d", res.ResponseChunks[0].ResultCode)
	}
}

// diverge compares per-client outcome classes and returns one divergence
// when more than one class is observed. The outlier clients are the
// minority side of the split.
func diverge(id, category string, meta runner.Metadata, results map[string]string) []runner.Divergence {
	classes := map[string][]string{} // class -> client names
	names := make([]string, 0, len(results))
	for name := range results {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		cls := classOf(results[name])
		classes[cls] = append(classes[cls], name)
	}
	if len(classes) <= 1 {
		return nil
	}

	// Minority side becomes the outliers; on a tie (e.g. one acceptor vs
	// one rejector) the rejecting side is treated as the deviation.
	var minority []string
	for _, cls := range sortedKeys(classes) {
		ns := classes[cls]
		if minority == nil || len(ns) < len(minority) || (len(ns) == len(minority) && cls == "reject") {
			minority = ns
		}
	}

	var lines []string
	for _, cls := range sortedKeys(classes) {
		lines = append(lines, fmt.Sprintf("%s: %v", cls, classes[cls]))
	}
	desc := id + ": divergent verdicts (" + joinLines(lines, "; ") + ")"

	severity := runner.SeverityHigh
	if _, ok := classes["other"]; ok {
		severity = runner.SeverityLow
	}

	return []runner.Divergence{{
		TestID:         id,
		Category:       category,
		KnowledgeIDs:   meta.KnowledgeIDs,
		SpecRuleIDs:    meta.SpecRules,
		Type:           runner.DivAcceptReject,
		Severity:       severity,
		Description:    desc,
		ClientResults:  results,
		OutlierClients: minority,
	}}
}

func classOf(outcome string) string {
	switch outcome {
	case "accept":
		return "accept"
	case "reject":
		return "reject"
	default:
		return "other"
	}
}

func sortedClientNames(m map[string]string) []string {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func sortedKeys(m map[string][]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func joinLines(parts []string, sep string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += sep
		}
		out += p
	}
	return out
}

// gossipTopic builds the beacon_block gossip topic for the chain under test.
func gossipTopic(chain runner.ChainConfig) string {
	return fmt.Sprintf("/eth2/%x/beacon_block/ssz_snappy", chain.ForkDigest)
}
