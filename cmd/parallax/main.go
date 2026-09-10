// Command difftest runs differential libp2p tests against consensus layer
// clients: list the case registry, run cases against an environment, and
// analyze saved reports.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch os.Args[1] {
	case "list":
		err = runList(os.Stdout)
	case "run":
		err = cmdRun(ctx, os.Args[2:])
	case "analyze":
		err = cmdAnalyze(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage: difftest <command> [flags]

commands:
  list               print the test case registry
  run [flags]        run cases against an environment
                     -env static|kurtosis     environment backend (static)
                     -config clients.yaml     static: endpoint list
                     -enclave NAME            kurtosis: enclave
                     -args-file FILE          kurtosis: ethereum-package args
                     -attach                  kurtosis: attach, skip provisioning
                     -test ID1,ID2            exact case IDs
                     -category CAT1,CAT2      case categories
                     -seed N                  shuffle seed (42)
                     -out DIR                 output directory (results)
  analyze [flags]    analyze a saved report
                     -report FILE             report.json to process
                     -allowlist FILE          known divergences JSON
                     -legacy                  also emit legacy-shape JSON
                     -html                    also emit a standalone HTML report
                     -junit-out FILE          also emit JUnit XML to this path
`)
}

func cmdRun(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	var cfg RunConfig
	if err := parseRunArgs(fs, &cfg, args); err != nil {
		return err
	}
	cfg.Stdout = os.Stdout
	return runRun(ctx, cfg)
}

func cmdAnalyze(args []string) error {
	fs := flag.NewFlagSet("analyze", flag.ExitOnError)
	var cfg AnalyzeConfig
	fs.StringVar(&cfg.ReportPath, "report", "", "path to report.json")
	fs.StringVar(&cfg.AllowlistPath, "allowlist", "knowledge/known_divergences.json", "path to known divergences JSON")
	fs.BoolVar(&cfg.Legacy, "legacy", false, "emit legacy-shape JSON next to the report")
	fs.StringVar(&cfg.JUnitOut, "junit-out", "", "also emit JUnit XML to this path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if cfg.ReportPath == "" {
		return fmt.Errorf("-report is required")
	}
	return runAnalyze(cfg, os.Stdout)
}
