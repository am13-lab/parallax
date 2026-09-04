// Command specchain runs the full spec-to-cases pipeline in one shot:
// specgen (knowledge JSONs) -> irdrive (SM-IR plans) -> smgen (runner.Spec
// cases). Each step streams its output and the chain stops on the first
// failure. The individual commands remain available for partial runs.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
)

type step struct {
	name string
	args []string
}

func main() {
	specs := flag.String("specs", "consensus-specs/specs", "consensus-specs root passed to specgen")
	flag.Parse()

	steps := []step{
		{"specgen (knowledge JSONs)", []string{"run", "./cmd/specgen", "-generate", "-specs", *specs}},
		{"irdrive (SM-IR plans)", []string{"run", "./cmd/irdrive"}},
		{"smgen (machine cases)", []string{"run", "./cmd/smgen", "-generate", "knowledge/ir/sm_ir_generated"}},
		{"smgen (stateless cases)", []string{"run", "./cmd/smgen", "-generate-stateless", "knowledge/ir/stateless_tests_generated.json"}},
		{"smgen (sequence cases)", []string{"run", "./cmd/smgen", "-generate-sequences", "knowledge/ir/sequence_tests_generated.json"}},
	}

	for i, s := range steps {
		fmt.Printf("==> [%d/%d] %s\n", i+1, len(steps), s.name)
		cmd := exec.Command("go", s.args...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "specchain: step %q failed: %v\n", s.name, err)
			os.Exit(1)
		}
	}
	fmt.Println("specchain: complete")
}
