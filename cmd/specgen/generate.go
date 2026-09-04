package main

import (
	"fmt"
	"sort"
)

// generate.go — orchestrates Layers 0-2 into a RuleAST.

// buildAST parses every spec file under specsRoot and assembles the rule AST.
func buildAST(specsRoot string) (*RuleAST, error) {
	files, err := discoverSpecFiles(specsRoot)
	if err != nil {
		return nil, fmt.Errorf("discover spec files: %w", err)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no p2p-interface.md files under %s", specsRoot)
	}

	ast := &RuleAST{
		Meta:      Meta{Generator: "spectrans", SpecSources: files},
		Constants: []Constant{},
		Surfaces:  []Surface{},
		Rules:     []Rule{},
		Edges:     []Edge{},
		Residuals: []Residual{},
	}
	forksSeen := map[string]bool{}
	var rawRules []Rule

	for _, f := range files {
		doc, err := parseDoc(f)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", f, err)
		}
		forksSeen[doc.Fork] = true

		ast.Constants = append(ast.Constants, extractConstants(doc)...)
		ast.Surfaces = append(ast.Surfaces, extractSurfaces(doc)...)
		rawRules = append(rawRules, extractValidation(doc)...)

		proseRules, residuals := extractProse(doc)
		rawRules = append(rawRules, proseRules...)
		ast.Residuals = append(ast.Residuals, residuals...)
	}

	// Dedupe constants and surfaces by id (identical across forks share ids),
	// keeping the earliest-fork instance. Done before buildRelations so edge-target
	// resolution indexes over the canonical node set.
	ast.Constants = dedupeConstants(ast.Constants)
	ast.Surfaces = dedupeSurfaces(ast.Surfaces)

	// Fill "unchanged" method schemas from the nearest lower version (post-dedupe
	// so cross-fork versions of the same method are all present).
	inheritSchemas(ast.Surfaces)

	// Dedupe rules across forks, link rewordings, and derive edges (surfaces and
	// constants supply the name->id indexes for temporal/conditional targets).
	ast.Rules, ast.Edges = buildRelations(rawRules, ast.Constants)

	// Resolve constant references mentioned in rule text/source_expr.
	syms := symbolTable(ast.Constants)
	for i := range ast.Rules {
		ast.Rules[i].ConstantsReferenced = referencedConstants(ast.Rules[i], syms)
	}

	for f := range forksSeen {
		ast.Meta.Forks = append(ast.Meta.Forks, f)
	}
	sort.Strings(ast.Meta.Forks)
	return ast, nil
}

// referencedConstants returns the names of known constants appearing in a rule.
func referencedConstants(r Rule, syms map[string]int64) []string {
	hay := r.RawText + " " + r.SourceExpr + " " + r.NormalizedExpr
	var found []string
	seen := map[string]bool{}
	for _, w := range wordRe.FindAllString(hay, -1) {
		if _, ok := syms[w]; ok && !seen[w] {
			seen[w] = true
			found = append(found, w)
		}
	}
	sort.Strings(found)
	return found
}

func dedupeConstants(in []Constant) []Constant {
	seen := map[string]bool{}
	var out []Constant
	for _, c := range in {
		if seen[c.ID] {
			continue
		}
		seen[c.ID] = true
		out = append(out, c)
	}
	return out
}

func dedupeSurfaces(in []Surface) []Surface {
	seen := map[string]bool{}
	var out []Surface
	for _, s := range in {
		if seen[s.ID] {
			continue
		}
		seen[s.ID] = true
		out = append(out, s)
	}
	return out
}
