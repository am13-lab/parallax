package main

import (
	"context"
	"flag"
	"fmt"
	"os"
)

func main() {
	out := flag.String("out", "results/demo", "output directory for report.json and junit.xml")
	flag.Parse()

	rep, err := runSimulation(SimConfig{Out: *out, Stdout: os.Stdout})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	fmt.Printf("\nsummary: total=%d pass=%d divergent=%d skipped=%d errors=%d\n",
		rep.Summary.Total, rep.Summary.Passed, rep.Summary.Divergent,
		rep.Summary.Skipped, rep.Summary.Errors)
	fmt.Printf("artifacts: %s/report.json %s/junit.xml\n", *out, *out)
	_ = context.Background
}
