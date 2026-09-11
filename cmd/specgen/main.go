// Command specgen regenerates the three spec knowledge artifacts used by parallax.
package main

import (
	"flag"
	"fmt"
	"os"
)

type paths struct {
	specs, ast, rules, model, overlay, legacy string
}

func main() {
	p := paths{}
	flag.StringVar(&p.specs, "specs", "consensus-specs/specs", "consensus-specs root")
	flag.StringVar(&p.ast, "rule-ast", "knowledge/spec/rule_ast.json", "rule AST output")
	flag.StringVar(&p.rules, "spec-rules", "knowledge/spec/spec_rules_generated.json", "flat rules output")
	flag.StringVar(&p.model, "protocol-model", "knowledge/spec/protocol_model.json", "protocol model output")
	flag.StringVar(&p.overlay, "overlay", "knowledge/spec/test_overlay.json", "test overlay")
	flag.StringVar(&p.legacy, "legacy-map", "knowledge/spec/spec_rule_legacy_map.json", "legacy rule map")
	generate := flag.Bool("generate", false, "regenerate spec artifacts")
	flag.Parse()
	if !*generate {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(p); err != nil {
		fmt.Fprintf(os.Stderr, "specgen: %v\n", err)
		os.Exit(1)
	}
}

func run(p paths) error {
	ast, err := buildAST(p.specs)
	if err != nil {
		return err
	}
	if err := writeJSON(p.ast, ast); err != nil {
		return fmt.Errorf("write rule AST: %w", err)
	}
	rules, err := buildFlatRules(ast, p.overlay, p.legacy)
	if err != nil {
		return err
	}
	if err := writeJSON(p.rules, specRulesDoc{
		Description: "Derived debug projection of AST rules joined with test_overlay.json",
		Source:      "knowledge/spec/rule_ast.json + knowledge/spec/test_overlay.json",
		Rules:       rules,
	}); err != nil {
		return fmt.Errorf("write spec rules: %w", err)
	}
	if err := updateProtocolModel(p.model, ast); err != nil {
		return fmt.Errorf("write protocol model: %w", err)
	}
	fmt.Printf("generated %d rules, %d surfaces\n", len(ast.Rules), len(ast.Surfaces))
	return nil
}

func buildFlatRules(ast *RuleAST, overlayPath, legacyPath string) ([]flatRule, error) {
	overlay := loadOverlay(overlayPath)
	legacy, err := loadLegacyMap(legacyPath)
	if err != nil {
		return nil, fmt.Errorf("load legacy map: %w", err)
	}
	flat, _, _ := joinFlat(ast, specRulesDoc{}, overlay, legacy)
	return flat, nil
}
