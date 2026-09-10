// Command smgen is the SM-IR toolchain. The `-validate` mode checks SM-IR files
// such as ir/sm_ir_generated/*.json against the schema and reference/well-
// formedness gates. The `-generate` mode compiles validated IR into Go state
// machine constructors.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func main() {
	validatePath := flag.String("validate", "", "Validate an SM-IR file or a directory of *.json files")
	generatePath := flag.String("generate", "", "Generate runner.Spec cases from an SM-IR file or directory")
	validateStatelessPath := flag.String("validate-stateless", "", "Validate a generated stateless testcase artifact")
	generateStatelessPath := flag.String("generate-stateless", "", "Generate runner.Spec stateless cases from a stateless testcase artifact")
	validateSequencesPath := flag.String("validate-sequences", "", "Validate a generated sequence testcase artifact")
	generateSequencesPath := flag.String("generate-sequences", "", "Generate runner.Spec sequence cases from a sequence testcase artifact")
	outDir := flag.String("out", "cases", "Output directory for generated Go (with -generate)")
	pkg := flag.String("pkg", "cases", "Package name for generated Go (with -generate)")
	ruleAST := flag.String("rule-ast", "knowledge/spec/rule_ast.json", "Path to canonical rule_ast.json for spec_refs resolution")
	overlay := flag.String("overlay", "knowledge/spec/test_overlay.json", "Path to test_overlay.json for rule metadata")
	legacyMap := flag.String("legacy-map", "knowledge/spec/spec_rule_legacy_map.json", "Path to legacy SPEC-* ID map for normalization")
	invariants := flag.String("invariants", "knowledge/spec/invariant_rules.json", "Path to invariant_rules.json for invariant_refs resolution")
	protocolModel := flag.String("protocol-model", "knowledge/spec/protocol_model.json", "Path to protocol_model.json for payload type-check (gate 3)")
	flag.Parse()

	refs, err := loadRefIndex(ruleIndexPaths{
		ruleAST:   *ruleAST,
		overlay:   *overlay,
		legacyMap: *legacyMap,
	}, *invariants)
	if err != nil {
		fmt.Fprintf(os.Stderr, "smgen: load rule index: %v\n", err)
		os.Exit(2)
	}
	pm, err := loadProtocolModel(*protocolModel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "smgen: load protocol model: %v\n", err)
		os.Exit(2)
	}
	refs.protocolModel = pm

	if *generatePath != "" {
		os.Exit(runGenerate(*generatePath, *outDir, *pkg, refs))
	}
	if *generateStatelessPath != "" {
		os.Exit(runGenerateStateless(*generateStatelessPath, *outDir, *pkg, refs))
	}
	if *generateSequencesPath != "" {
		os.Exit(runGenerateSequences(*generateSequencesPath, *outDir, *pkg, refs))
	}
	if *validateStatelessPath != "" {
		os.Exit(runValidateStateless(*validateStatelessPath, refs))
	}
	if *validateSequencesPath != "" {
		os.Exit(runValidateSequences(*validateSequencesPath, refs))
	}

	if *validatePath == "" {
		fmt.Fprintln(os.Stderr, "smgen: nothing to do; pass -validate <file|dir>, -generate <file>, -validate-stateless <file>, -generate-stateless <file>, -validate-sequences <file>, or -generate-sequences <file>")
		flag.Usage()
		os.Exit(2)
	}

	files, err := collectIRFiles(*validatePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "smgen: %v\n", err)
		os.Exit(2)
	}
	if len(files) == 0 {
		fmt.Fprintf(os.Stderr, "smgen: no SM-IR files found at %q\n", *validatePath)
		os.Exit(2)
	}

	failed := 0
	for _, f := range files {
		ok := validateFile(f, refs)
		if !ok {
			failed++
		}
	}

	fmt.Printf("\n%d file(s) validated, %d failed.\n", len(files), failed)
	if failed > 0 {
		os.Exit(1)
	}
}

// dropUnresolvedSpecRefs removes SpecRefs that no longer resolve in the rule
// catalog (e.g. rules from skipped _features forks) so stale references do
// not block generation. Each drop is printed as a note.
func dropUnresolvedSpecRefs(f string, m *Machine, refs refIndex) {
	if refs.specRules == nil {
		return
	}
	for i := range m.Transitions {
		t := &m.Transitions[i]
		kept := make([]string, 0, len(t.SpecRefs))
		for _, ref := range t.SpecRefs {
			if refs.specRules[ref] {
				kept = append(kept, ref)
				continue
			}
			fmt.Printf("  note %s (machine %q): dropped unresolved spec rule %q\n", f, m.Name, ref)
		}
		t.SpecRefs = kept
	}
}

// runGenerate validates SM-IR files and, if they pass, compiles each eligible
// transition into a runner.Spec case. irPath may be a file or a directory; the
// output is a single Go file defining irMachineSpecs() []runner.Spec. Returns
// the process exit code.
func runGenerate(irPath, outDir, pkg string, refs refIndex) int {
	files, err := collectIRFiles(irPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "smgen: %v\n", err)
		return 1
	}
	var machines []*Machine
	for _, f := range files {
		m, err := loadMachine(f)
		if err != nil {
			fmt.Printf("FAIL %s\n  [gate1] %v\n", f, err)
			return 1
		}
		dropUnresolvedSpecRefs(f, m, refs)
		r := validateMachine(m, refs)
		if !r.OK() {
			fmt.Printf("FAIL %s (machine %q): refusing to generate from invalid IR\n", f, m.Name)
			for _, is := range r.Issues {
				fmt.Printf("  [%s] %s: %s\n", is.Gate, is.Path, is.Msg)
			}
			return 1
		}
		applyDerivedStrength(m, refs.specStrength)
		machines = append(machines, m)
	}

	src, err := renderMachineCasesFile(machines, pkg, irPath, refs.protocolModel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "smgen: generate: %v\n", err)
		return 1
	}
	outPath := filepath.Join(outDir, "spec_ir_generated.go")
	if err := os.WriteFile(outPath, []byte(src), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "smgen: write %s: %v\n", outPath, err)
		return 1
	}
	defSrc, err := renderMachineDefsFile(machines, pkg, irPath, refs.protocolModel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "smgen: generate machine defs: %v\n", err)
		return 1
	}
	defPath := filepath.Join(outDir, "spec_ir_machines_generated.go")
	if err := os.WriteFile(defPath, []byte(defSrc), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "smgen: write %s: %v\n", defPath, err)
		return 1
	}
	total := 0
	for _, m := range machines {
		total += len(m.Transitions)
	}
	fmt.Printf("generated %s (%d machines, %d transitions)\n", outPath, len(machines), total)
	return 0
}

// runGenerateStateless renders the stateless testcase artifact into
// spec_ir_stateless_generated.go defining irStatelessSpecs().
func runGenerateStateless(irPath, outDir, pkg string, refs refIndex) int {
	doc, err := loadStatelessArtifact(irPath)
	if err != nil {
		fmt.Printf("FAIL %s\n  [gate1] %v\n", irPath, err)
		return 1
	}
	if r := validateStatelessArtifact(doc, refs); !r.OK() {
		fmt.Printf("FAIL %s: refusing to generate from invalid artifact\n", irPath)
		for _, is := range r.Issues {
			fmt.Printf("  [%s] %s: %s\n", is.Gate, is.Path, is.Msg)
		}
		return 1
	}
	src, err := renderStatelessCasesFile(doc, refs.protocolModel, pkg, irPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "smgen: generate-stateless: %v\n", err)
		return 1
	}
	outPath := filepath.Join(outDir, "spec_ir_stateless_generated.go")
	if err := os.WriteFile(outPath, []byte(src), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "smgen: write %s: %v\n", outPath, err)
		return 1
	}
	fmt.Printf("generated %s (%d stateless cases)\n", outPath, len(doc.Cases))
	return 0
}

// runGenerateSequences renders the sequence testcase artifact into
// spec_ir_sequences_generated.go defining irSequenceSpecs().
func runGenerateSequences(irPath, outDir, pkg string, refs refIndex) int {
	doc, err := loadSequenceArtifact(irPath)
	if err != nil {
		fmt.Printf("FAIL %s\n  [gate1] %v\n", irPath, err)
		return 1
	}
	if r := validateSequenceArtifact(doc, refs); !r.OK() {
		fmt.Printf("FAIL %s: refusing to generate from invalid artifact\n", irPath)
		for _, is := range r.Issues {
			fmt.Printf("  [%s] %s: %s\n", is.Gate, is.Path, is.Msg)
		}
		return 1
	}
	src, err := renderSequenceCasesFile(doc, refs.protocolModel, pkg, irPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "smgen: generate-sequences: %v\n", err)
		return 1
	}
	outPath := filepath.Join(outDir, "spec_ir_sequences_generated.go")
	if err := os.WriteFile(outPath, []byte(src), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "smgen: write %s: %v\n", outPath, err)
		return 1
	}
	fmt.Printf("generated %s (%d sequence cases)\n", outPath, len(doc.Cases))
	return 0
}

// validateFile validates a single SM-IR file and prints a report. Returns true
// on PASS.
func validateFile(path string, refs refIndex) bool {
	m, err := loadMachine(path)
	if err != nil {
		// A load/decode failure is a Gate 1 (structural) failure.
		fmt.Printf("FAIL %s\n", path)
		fmt.Printf("  [gate1] %v\n", err)
		return false
	}
	r := validateMachine(m, refs)
	r.File = path

	if r.OK() {
		fmt.Printf("PASS %s (machine %q: %d states, %d transitions)\n",
			path, m.Name, len(m.States), len(m.Transitions))
	} else {
		fmt.Printf("FAIL %s (machine %q)\n", path, m.Name)
		for _, is := range r.Issues {
			fmt.Printf("  [%s] %s: %s\n", is.Gate, is.Path, is.Msg)
		}
	}
	for _, w := range r.Warnings {
		fmt.Printf("  WARN [%s] %s: %s\n", w.Gate, w.Path, w.Msg)
	}
	fmt.Printf("  judgment: %d single-client, %d differential-only, %d judged-by-nothing\n",
		r.SingleClientJudged, r.DifferentialOnly, r.JudgedByNothing)
	sort.Strings(r.Skipped)
	for _, s := range r.Skipped {
		fmt.Printf("  - %s\n", s)
	}
	return r.OK()
}

// collectIRFiles returns the list of SM-IR JSON files to validate. For a
// directory it returns all *.json except schema.json. For a file it returns it
// as-is.
func collectIRFiles(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return []string{path}, nil
	}
	var files []string
	err = filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".json") || name == "schema.json" {
			return nil
		}
		files = append(files, p)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	return files, nil
}
