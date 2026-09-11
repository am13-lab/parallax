package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	astPath := flag.String("ast", "knowledge/spec/rule_ast.json", "Input rule AST")
	outDir := flag.String("out", "knowledge/ir/sm_ir_generated", "Output dir for semantic generated SM-IR machines")
	stateMachineTemplate := flag.String("state-machine-template", "knowledge/ir/sm_ir_templates/statemachine_template.json", "State-machine template JSON")
	flag.StringVar(stateMachineTemplate, "semantic-template", "knowledge/ir/sm_ir_templates/statemachine_template.json", "Deprecated alias for -state-machine-template")
	dictPath := flag.String("dict", "knowledge/ir/ir_dictionary.json", "Semantic dictionary (falls back to embedded seed)")
	aliasesPath := flag.String("aliases", "knowledge/spec/spec_rule_aliases.json", "Deprecated compatibility input; spec_refs are emitted as AST ids")
	protocolModel := flag.String("protocol-model", "knowledge/spec/protocol_model.json", "Known-protocol set (availability keys)")
	gapsPath := flag.String("gaps", "knowledge/ir/ir_coverage_gaps.json", "Coverage-gap + report output")
	statelessTestsPath := flag.String("stateless-tests", "knowledge/ir/stateless_tests_generated.json", "Generated stateless testcase seed artifact")
	sequenceTestsPath := flag.String("sequence-tests", "knowledge/ir/sequence_tests_generated.json", "Generated multi-step sequence testcase seed artifact")
	lexiconPath := flag.String("state-lexicon", "knowledge/ir/state_lexicon.json", "Phrase->state lexicon for spec-deriving temporal from-states")
	doGenerate := flag.Bool("generate", false, "Write machines + gaps (default action when -check is not set)")
	doCheck := flag.Bool("check", false, "Read-only: report coverage and flag stale on-disk machines; writes nothing")
	doSkeleton := flag.Bool("emit-dict-skeleton", false, "Read-only: print an ir_dictionary.json skeleton (topic x violation_class grid) to stdout; writes nothing")
	randomRatio := flag.Float64("random-ratio", 0.5, "Reserved for future stateless/fuzz generation; stateful SM-IR emission ignores random gossip injections")
	flag.Parse()
	_ = *doGenerate // generate is the default; the flag exists for explicit/CI use

	doc, err := loadAST(*astPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "irderive: %v\n", err)
		os.Exit(1)
	}

	if *doSkeleton {
		if err := emitDictSkeleton(doc); err != nil {
			fmt.Fprintf(os.Stderr, "irderive: %v\n", err)
			os.Exit(1)
		}
		return
	}
	_ = loadAliases(*aliasesPath)
	knownProto := loadKnownProtocols(*protocolModel)
	entries, err := loadDictionary(*dictPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "irderive: %v\n", err)
		os.Exit(1)
	}

	si := newSurfaceIndex(doc.Surfaces)
	resolveds, link := resolveAll(doc, si)
	edgeIdx := indexEdgesByFrom(doc)
	lex, err := loadStateLexicon(*lexiconPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "irderive: state lexicon: %v\n", err)
		os.Exit(1)
	}
	d := derive(resolveds, entries, knownProto, edgeIdx, *randomRatio, link)
	semantic, err := deriveSemantic(*stateMachineTemplate, &d, edgeIdx, lex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "irderive: semantic: %v\n", err)
		os.Exit(1)
	}
	stateless := deriveStatelessTests(resolveds, entries, knownProto, edgeIdx)
	sequences := deriveSequenceTests(resolveds)

	printReport(d)
	printSemanticReport(semantic.Report)
	printStatelessReport(stateless)
	printSequenceReport(sequences)

	// -check is read-only: report coverage + staleness vs the committed machines,
	// write nothing, exit non-zero if the on-disk machines are stale.
	if *doCheck {
		if stale := staleSemanticMachines(semantic, *outDir); len(stale) > 0 {
			fmt.Fprintf(os.Stderr, "check: %d generated semantic machine artifact(s) stale (re-run -generate): %v\n", len(stale), stale)
			os.Exit(1)
		}
		if !jsonArtifactMatches(*statelessTestsPath, stateless) {
			fmt.Fprintf(os.Stderr, "check: generated stateless testcase artifact stale (re-run -generate): %s\n", *statelessTestsPath)
			os.Exit(1)
		}
		if !jsonArtifactMatches(*sequenceTestsPath, sequences) {
			fmt.Fprintf(os.Stderr, "check: generated sequence testcase artifact stale (re-run -generate): %s\n", *sequenceTestsPath)
			os.Exit(1)
		}
		fmt.Println("check: OK (semantic generated machines, stateless tests, and sequence tests match on-disk)")
		return
	}

	if err := writeJSON(*gapsPath, buildReport(d, semantic.Report)); err != nil {
		fmt.Fprintf(os.Stderr, "irderive: write gaps: %v\n", err)
		os.Exit(1)
	}
	if err := writeJSON(*statelessTestsPath, stateless); err != nil {
		fmt.Fprintf(os.Stderr, "irderive: write stateless tests: %v\n", err)
		os.Exit(1)
	}
	if err := writeJSON(*sequenceTestsPath, sequences); err != nil {
		fmt.Fprintf(os.Stderr, "irderive: write sequence tests: %v\n", err)
		os.Exit(1)
	}
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "irderive: mkdir: %v\n", err)
		os.Exit(1)
	}
	if err := pruneGeneratedJSON(*outDir, semanticFileSet(semantic)); err != nil {
		fmt.Fprintf(os.Stderr, "irderive: prune %s: %v\n", *outDir, err)
		os.Exit(1)
	}
	for _, m := range semantic.Machines {
		path := filepath.Join(*outDir, semantic.Files[m.Name])
		if err := writeJSON(path, m); err != nil {
			fmt.Fprintf(os.Stderr, "irderive: write %s: %v\n", path, err)
			os.Exit(1)
		}
	}
	fmt.Printf("wrote %d generated state machines -> %s (template %s; ir/sm_ir is reference-only)\n", len(semantic.Machines), *outDir, *stateMachineTemplate)
	fmt.Printf("wrote %d generated stateless tests covering %d rules -> %s\n", len(stateless.Cases), stateless.TotalRules, *statelessTestsPath)
	fmt.Printf("wrote %d generated sequence tests covering %d rules -> %s\n", len(sequences.Cases), sequences.TotalRules, *sequenceTestsPath)
}

type gapsReport struct {
	Coverage map[string]*domainCoverage `json:"coverage"`
	Link     struct {
		ResolvedByDomain map[string]int `json:"resolved_by_domain"`
		Unresolved       int            `json:"unresolved"`
	} `json:"link"`
	TotalMapped                  int             `json:"total_mapped"`
	TotalStatefulSupported       int             `json:"total_stateful_supported"`
	TotalStatelessSupported      int             `json:"total_stateless_supported"`
	TotalAuditOnly               int             `json:"total_audit_only"`
	TotalPendingFuture           int             `json:"total_pending_future"`
	TotalPendingBuilder          int             `json:"total_pending_builder"`
	TotalPendingLiveBuilder      int             `json:"total_pending_live_builder"`
	TotalPendingInspector        int             `json:"total_pending_inspector"`
	TotalPendingSequenceTemplate int             `json:"total_pending_sequence_template"`
	TotalUnsupported             int             `json:"total_unsupported"`
	Semantic                     semanticReport  `json:"semantic"`
	ClassifiedRules              []executionPlan `json:"classified_rules"`
	Gaps                         []gap           `json:"gaps"`
}

func buildReport(d derivation, semantic semanticReport) gapsReport {
	r := gapsReport{Coverage: d.Coverage, Semantic: semantic, ClassifiedRules: d.Plans, Gaps: d.Gaps}
	r.Link.ResolvedByDomain = d.Link.byDomain
	r.Link.Unresolved = d.Link.gaps
	for _, c := range d.Coverage {
		r.TotalMapped += c.Mapped
		r.TotalStatefulSupported += c.StatefulSupported
		r.TotalStatelessSupported += c.StatelessSupported
		r.TotalAuditOnly += c.AuditOnly
		r.TotalPendingFuture += c.PendingFuture
		r.TotalPendingBuilder += c.PendingBuilder
		r.TotalPendingLiveBuilder += c.PendingLiveBuilder
		r.TotalPendingInspector += c.PendingInspector
		r.TotalPendingSequenceTemplate += c.PendingSequenceTemplate
		r.TotalUnsupported += c.Unsupported
	}
	// Domain-less audit/prose rules are not in a per-domain coverage bucket.
	for _, g := range d.Gaps {
		switch g.Class {
		case execAuditOnly:
			if g.Domain == domNone {
				r.TotalAuditOnly++
			}
		case execPendingFuture:
			if g.Domain == domNone {
				r.TotalPendingFuture++
			}
		case statusPendingLiveBuilder:
			if g.Domain == domNone {
				r.TotalPendingLiveBuilder++
			}
		case statusUnsupported:
			if g.Domain == domNone {
				r.TotalUnsupported++
			}
		}
	}
	return r
}

func staleMachineList(machines []irMachine, outDir string, fileFor func(irMachine) string) []string {
	var stale []string
	for _, m := range machines {
		path := filepath.Join(outDir, fileFor(m))
		want, err := json.MarshalIndent(m, "", "  ")
		if err != nil {
			stale = append(stale, m.Name)
			continue
		}
		want = append(want, '\n')
		got, err := os.ReadFile(path)
		if err != nil || !bytesEqual(got, want) {
			stale = append(stale, m.Name)
		}
	}
	return stale
}

func pruneGeneratedJSON(outDir string, expected map[string]bool) error {
	files, err := filepath.Glob(filepath.Join(outDir, "*.json"))
	if err != nil {
		return err
	}
	for _, path := range files {
		if expected[filepath.Base(path)] {
			continue
		}
		if err := os.Remove(path); err != nil {
			return err
		}
	}
	return nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func jsonArtifactMatches(path string, v any) bool {
	want, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return false
	}
	want = append(want, '\n')
	got, err := os.ReadFile(path)
	return err == nil && bytesEqual(got, want)
}

func printReport(d derivation) {
	fmt.Printf("link: resolved=%v unresolved=%d\n", d.Link.byDomain, d.Link.gaps)
	for _, dom := range []string{domCrypto, domGossip, domReqResp, domConn, domDiscovery} {
		c := d.Coverage[dom]
		fmt.Printf("  %-9s sm_ir=%d stateful_supported=%d stateless_supported=%d audit_only=%d pending_future=%d pending_builder=%d pending_live_builder=%d pending_inspector=%d pending_sequence_template=%d unsupported=%d\n",
			dom, c.Mapped, c.StatefulSupported, c.StatelessSupported, c.AuditOnly, c.PendingFuture, c.PendingBuilder, c.PendingLiveBuilder, c.PendingInspector, c.PendingSequenceTemplate, c.Unsupported)
	}
}

func printSemanticReport(r semanticReport) {
	fmt.Printf("semantic: machines=%d transitions=%d static=%d bound_rules=%d pending_template=%d pending_action=%d\n",
		r.TotalMachines, r.TotalTransitions, r.StaticTransitions, r.BoundRules, r.PendingTemplate, r.PendingAction)
}

func printStatelessReport(a statelessTestArtifact) {
	fmt.Printf("stateless-tests: cases=%d rules=%d grouped=%d\n", len(a.Cases), a.TotalRules, a.TotalRules-len(a.Cases))
}

func printSequenceReport(a sequenceTestArtifact) {
	fmt.Printf("sequence-tests: cases=%d rules=%d grouped=%d\n", len(a.Cases), a.TotalRules, a.TotalRules-len(a.Cases))
}

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}
