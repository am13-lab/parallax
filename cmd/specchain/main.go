// Command specchain drives the spec-to-cases pipeline. It can run the
// whole chain in one shot or step by step, so each intermediate artifact
// (knowledge JSONs, SM-IR plans, Go case files) can be inspected between
// stages.
//
//	specchain -specs DIR        run every stage in order
//	specchain spec -specs DIR   stage 1: consensus specs -> knowledge JSONs
//	specchain ir                stage 2: knowledge JSONs -> SM-IR plans
//	specchain cases             stage 3: SM-IR plans -> Go case files
//	specchain status            show which stage artifacts exist and when
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type step struct {
	name string
	args []string
}

func steps(specs string) []step {
	return []step{
		{"specgen (knowledge JSONs)", []string{"run", "./cmd/specgen", "-generate", "-specs", specs}},
		{"irdrive (SM-IR plans)", []string{"run", "./cmd/irdrive"}},
		{"smgen (machine cases)", []string{"run", "./cmd/smgen", "-generate", "knowledge/ir/sm_ir_generated"}},
		{"smgen (stateless cases)", []string{"run", "./cmd/smgen", "-generate-stateless", "knowledge/ir/stateless_tests_generated.json"}},
		{"smgen (sequence cases)", []string{"run", "./cmd/smgen", "-generate-sequences", "knowledge/ir/sequence_tests_generated.json"}},
	}
}

// stageArts maps a stage name to the artifacts it produces (used by the
// status subcommand).
var stageArts = map[string][]string{
	"spec":  {"knowledge/spec/rule_ast.json", "knowledge/spec/spec_rules_generated.json", "knowledge/spec/protocol_model.json"},
	"ir":    {"knowledge/ir/ir_coverage_gaps.json", "knowledge/ir/stateless_tests_generated.json"},
	"cases": {"cases/spec_ir_generated.go", "cases/spec_ir_stateless_generated.go", "cases/spec_ir_sequences_generated.go"},
}

func runStep(s step) error {
	cmd := exec.Command("go", s.args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func runAll(specs string) {
	ss := steps(specs)
	for i, s := range ss {
		fmt.Printf("==> [%d/%d] %s\n", i+1, len(ss), s.name)
		if err := runStep(s); err != nil {
			fmt.Fprintf(os.Stderr, "specchain: step %q failed: %v\n", s.name, err)
			os.Exit(1)
		}
	}
	fmt.Println("specchain: complete")
}

func printStatus() {
	for _, stage := range []string{"spec", "ir", "cases"} {
		fmt.Printf("%-6s", stage)
		arts := stageArts[stage]
		if len(arts) == 0 {
			fmt.Println(" (no tracked artifacts)")
			continue
		}
		missing := 0
		var newest time.Time
		for _, a := range arts {
			info, err := os.Stat(a)
			if err != nil {
				missing++
				continue
			}
			if info.ModTime().After(newest) {
				newest = info.ModTime()
			}
		}
		if missing > 0 {
			fmt.Printf(" MISSING %d/%d artifacts\n", missing, len(arts))
			continue
		}
		fmt.Printf(" ok, newest artifact %s (%s)\n", newest.Format("2006-01-02 15:04"), time.Since(newest).Round(time.Minute))
	}
	fmt.Println("\nstage commands: specchain spec -specs DIR | specchain ir | specchain cases")
}

func usage() {
	fmt.Fprintln(os.Stderr, strings.TrimSpace(`
usage:
  specchain [-specs DIR]          run the full pipeline
  specchain spec  [-specs DIR]    stage 1: specs -> knowledge JSONs
  specchain ir                    stage 2: knowledge JSONs -> SM-IR plans
  specchain cases                 stage 3: SM-IR plans -> Go case files
  specchain all [-specs DIR]      same as the full pipeline
  specchain status                artifact presence and freshness`))
	os.Exit(2)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "spec":
		fs := flag.NewFlagSet("spec", flag.ExitOnError)
		specs := fs.String("specs", filepath.Join("consensus-specs", "specs"), "consensus-specs root passed to specgen")
		fs.Parse(os.Args[2:])
		if err := runStep(steps(*specs)[0]); err != nil {
			fail("spec", err)
		}
	case "ir":
		if err := runStep(steps("")[1]); err != nil {
			fail("ir", err)
		}
	case "cases":
		for _, s := range steps("")[2:] {
			if err := runStep(s); err != nil {
				fail("cases", err)
			}
		}
	case "all":
		fs := flag.NewFlagSet("all", flag.ExitOnError)
		specs := fs.String("specs", filepath.Join("consensus-specs", "specs"), "consensus-specs root passed to specgen")
		fs.Parse(os.Args[2:])
		runAll(*specs)
	case "status":
		printStatus()
	default:
		// legacy form: specchain -specs DIR (full pipeline)
		fs := flag.NewFlagSet("specchain", flag.ExitOnError)
		specs := fs.String("specs", filepath.Join("consensus-specs", "specs"), "consensus-specs root passed to specgen")
		fs.Parse(os.Args[1:])
		runAll(*specs)
	}
}

func fail(stage string, err error) {
	fmt.Fprintf(os.Stderr, "specchain: %s failed: %v\n", stage, err)
	os.Exit(1)
}
