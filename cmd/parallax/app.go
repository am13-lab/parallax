package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"parallax/cases"
	"parallax/client"
	"parallax/env"
	"parallax/env/hiveenv"
	"parallax/env/kurtosisenv"
	"parallax/env/staticenv"
	"parallax/knowledge"
	"parallax/report"
	"parallax/runner"
)

// RunConfig carries the `run` subcommand options.
type RunConfig struct {
	// environment
	Env        string // static | kurtosis
	ConfigPath string // static: clients.yaml
	Enclave    string
	ArgsFile   string
	Attach     bool
	// Clients is a comma-separated filter on client name substrings
	// (empty = all).
	Clients string

	// one-shot regeneration: run the spec pipeline, rebuild this binary,
	// then exec the fresh binary for the actual run
	Regen    bool
	SpecsDir string

	// hive provider
	HiveGenDir     string
	HiveClientList string
	HiveClients    []string
	HivegenBin     string

	// selection
	Suite             string
	TestIDList        string
	CategoryList      string
	ExcludePrefixList string
	TestIDs           []string
	Categories        []string
	ExcludePrefixes   []string
	IncludeHeavy      bool

	// scheduling
	Seed             int64
	InterTestDelay   time.Duration
	MaxDuration      time.Duration
	BanThreshold     int
	RecoveryCooldown time.Duration
	RotateEvery      int
	PerTestTimeout   time.Duration
	Preset           string

	// output
	OutputDir string
	Progress  func(runner.TestResult)
	Stdout    io.Writer
}

// resolveSpecsDir locates the consensus-specs checkout: an explicit
// -specs-dir wins, then $PARALLAX_SPECS, then ./consensus-specs/specs, then
// the sibling ../consensus-specs/specs. Empty when nothing exists.
func resolveSpecsDir(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if v := os.Getenv("PARALLAX_SPECS"); v != "" && dirOK(v) {
		return v
	}
	for _, c := range []string{
		filepath.Join("consensus-specs", "specs"),
		filepath.Join("..", "consensus-specs", "specs"),
	} {
		if dirOK(c) {
			return c
		}
	}
	return ""
}

func dirOK(dir string) bool {
	info, err := os.Stat(dir)
	return err == nil && info.IsDir()
}

// casesStale reports whether the generated case files are missing or older
// than the newest knowledge/spec artifact, i.e. whether the spec pipeline
// should run before the case registry is trusted.
func casesStale(root string) bool {
	newest := func(rel string) time.Time {
		var out time.Time
		entries, err := os.ReadDir(filepath.Join(root, rel))
		if err != nil {
			return out
		}
		for _, e := range entries {
			if info, err := e.Info(); err == nil && info.ModTime().After(out) {
				out = info.ModTime()
			}
		}
		return out
	}
	var genNewest time.Time
	for _, g := range []string{
		"spec_ir_generated.go",
		"spec_ir_stateless_generated.go",
		"spec_ir_sequences_generated.go",
	} {
		info, err := os.Stat(filepath.Join(root, "cases", g))
		if err != nil {
			return true // missing generated file: definitely stale
		}
		if info.ModTime().After(genNewest) {
			genNewest = info.ModTime()
		}
	}
	return genNewest.Before(newest(filepath.Join("knowledge", "spec")))
}

// regenAndExec runs the spec pipeline, rebuilds the binary and hands the
// run over to the fresh build via exec.
func regenAndExec(cfg RunConfig, specs string) error {
	fmt.Fprintln(cfg.Stdout, "==> regenerating spec-derived cases")
	chain := exec.Command("go", "run", "./cmd/specchain", "all", "-specs", specs)
	chain.Stdout = cfg.Stdout
	chain.Stderr = os.Stderr
	if err := chain.Run(); err != nil {
		return fmt.Errorf("specchain: %w", err)
	}
	fmt.Fprintln(cfg.Stdout, "==> rebuilding binary")
	build := exec.Command("go", "build", "-o", "dist/parallax-final", "./cmd/parallax")
	build.Stdout = cfg.Stdout
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		return fmt.Errorf("rebuild: %w", err)
	}
	args := make([]string, 0, len(os.Args))
	for _, a := range os.Args {
		if a == "-regen" || a == "-regen=true" {
			continue
		}
		args = append(args, a)
	}
	fmt.Fprintln(cfg.Stdout, "==> handing over to fresh binary")
	return syscall.Exec("dist/parallax-final", args, os.Environ())
}

// runRun executes the `run` subcommand.
func runRun(ctx context.Context, cfg RunConfig) error {
	if cfg.Stdout == nil {
		cfg.Stdout = os.Stdout
	}
	if cfg.Regen {
		// Forced one-shot bootstrap. Requires running from the source tree
		// with the go toolchain available.
		specs := resolveSpecsDir(cfg.SpecsDir)
		if specs == "" {
			return fmt.Errorf("-regen needs a consensus-specs checkout (set -specs-dir or $PARALLAX_SPECS)")
		}
		return regenAndExec(cfg, specs)
	}
	if casesStale(".") {
		if specs := resolveSpecsDir(cfg.SpecsDir); specs != "" {
			fmt.Fprintf(cfg.Stdout, "==> generated cases are stale; auto-regenerating from %s\n", specs)
			return regenAndExec(cfg, specs)
		}
		fmt.Fprintln(cfg.Stdout, "==> generated cases are stale but no consensus-specs checkout found; continuing with the committed cases (set PARALLAX_SPECS to enable auto-regen)")
	}
	envr, endpoints, err := setupEnv(ctx, cfg)
	if err != nil {
		return err
	}
	endpoints = filterEndpoints(endpoints, cfg.Clients)

	var clients []runner.Client
	for _, ep := range endpoints {
		c, err := client.New(ctx, &client.Config{
			Name:       ep.Name,
			ClientType: ep.ClientType,
			Multiaddr:  ep.Multiaddr,
			BeaconAPI:  ep.BeaconAPI,
			Proxies:    ep.Proxies,
		})
		if err != nil {
			return fmt.Errorf("connect to %s: %w", ep.Name, err)
		}
		clients = append(clients, c)
		defer c.Close()
	}
	if len(clients) < 1 {
		return fmt.Errorf("no usable clients in the environment")
	}

	chain := deriveChain(ctx, clients, cfg.Preset)
	fmt.Fprintf(cfg.Stdout, "chain: preset=%s fork_digest=%x clients=%d\n",
		chain.Preset, chain.ForkDigest, len(clients))

	// Per-test progress lines: one line per finished test, so a run is never
	// silent about whether it is advancing.
	cfg.Progress = func(r runner.TestResult) {
		fmt.Fprintf(cfg.Stdout, "[test] %-58s %-10s %s\n", r.TestID, r.Status, r.Elapsed)
	}

	specs := cases.All()
	applySuite(cfg.Suite, &cfg)
	if len(cfg.ExcludePrefixes) > 0 {
		specs = excludeSpecPrefixes(specs, cfg.ExcludePrefixes)
	}
	rep := runner.Run(ctx, specs, clients, envr, chain, runner.Options{
		Seed:             cfg.Seed,
		TestIDs:          cfg.TestIDs,
		Categories:       cfg.Categories,
		IncludeHeavy:     cfg.IncludeHeavy,
		InterTestDelay:   cfg.InterTestDelay,
		MaxDuration:      cfg.MaxDuration,
		BanThreshold:     cfg.BanThreshold,
		RecoveryCooldown: cfg.RecoveryCooldown,
		RotateEvery:      cfg.RotateEvery,
		PerTestTimeout:   cfg.PerTestTimeout,
		Progress:         cfg.Progress,
	})

	rep.Command = strings.Join(os.Args, " ")
	if err := writeOutputs(cfg.OutputDir, rep); err != nil {
		return err
	}
	printSummary(cfg.Stdout, rep)
	return nil
}

// applySuite adjusts the selection inputs for the named test tier:
// quick (representative manifest), standard (hand-written families,
// IR excluded) or full (everything). Explicit -exclude-prefix values
// are preserved and merged with the tier's own exclusions.
func applySuite(suite string, cfg *RunConfig) {
	switch suite {
	case "quick":
		cfg.TestIDs = cases.QuickSuite()
	case "full":
		// no exclusions
	default: // standard
		cfg.ExcludePrefixes = appendUnion(cfg.ExcludePrefixes, "ir.", "ir_")
	}
}

func appendUnion(list []string, vals ...string) []string {
	for _, v := range vals {
		found := false
		for _, e := range list {
			if e == v {
				found = true
				break
			}
		}
		if !found {
			list = append(list, v)
		}
	}
	return list
}

// excludeSpecPrefixes drops specs whose ID starts with any of the given
// prefixes (e.g. the IR-generated families: "ir.", "ir_").
func excludeSpecPrefixes(specs []runner.Spec, prefixes []string) []runner.Spec {
	out := specs[:0]
	for _, s := range specs {
		excluded := false
		for _, p := range prefixes {
			if strings.HasPrefix(s.ID, p) {
				excluded = true
				break
			}
		}
		if !excluded {
			out = append(out, s)
		}
	}
	return out
}

// filterEndpoints keeps only endpoints whose Name contains one of the
// comma-separated substrings in pattern (empty pattern keeps all).
func filterEndpoints(eps []env.Endpoint, pattern string) []env.Endpoint {
	if strings.TrimSpace(pattern) == "" {
		return eps
	}
	var out []env.Endpoint
	for _, ep := range eps {
		for _, want := range strings.Split(pattern, ",") {
			if want = strings.TrimSpace(want); want != "" && strings.Contains(ep.Name, want) {
				out = append(out, ep)
				break
			}
		}
	}
	return out
}

func splitComma(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// hiveGenFresh reports whether the hivegen output dir carries a complete
// provisioning set whose genesis is recent enough for CL clients to boot:
// lighthouse rejects genesis states outside the weak subjectivity period,
// which for a small validator set is a matter of hours.
func hiveGenFresh(dir string) bool {
	for _, f := range []string{"genesis.json", "genesis.ssz", "config.yaml"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			return false
		}
	}
	data, err := os.ReadFile(filepath.Join(dir, "genesis.json"))
	if err != nil {
		return false
	}
	var g struct {
		Timestamp string `json:"timestamp"`
	}
	if json.Unmarshal(data, &g) != nil {
		return false
	}
	var ts int64
	if _, err := fmt.Sscanf(g.Timestamp, "0x%x", &ts); err != nil {
		_, _ = fmt.Sscanf(g.Timestamp, "%d", &ts)
	}
	return ts > 0 && time.Since(time.Unix(ts, 0)) < time.Hour
}

func setupEnv(ctx context.Context, cfg RunConfig) (env.Environment, []env.Endpoint, error) {
	switch cfg.Env {
	case "static":
		sc, err := staticenv.Load(cfg.ConfigPath)
		if err != nil {
			return nil, nil, err
		}
		envr, err := staticenv.New(sc)
		if err != nil {
			return nil, nil, err
		}
		return envr, envr.Endpoints(), nil
	case "kurtosis":
		api, err := kurtosisenv.NewRealClient()
		if err != nil {
			return nil, nil, err
		}
		prov := kurtosisenv.Provider{API: api}
		envr, err := prov.Setup(ctx, kurtosisenv.Config{
			Enclave:  cfg.Enclave,
			ArgsFile: cfg.ArgsFile,
			Attach:   cfg.Attach,
		})
		if err != nil {
			return nil, nil, err
		}
		return envr, envr.Endpoints(), nil
	case "hive":
		genDir := cfg.HiveGenDir
		if genDir == "" {
			// Default: keep the provisioning files inside the batch
			// output dir so they are archived with the report.
			genDir = filepath.Join(cfg.OutputDir, "gen")
		}
		if !hiveGenFresh(genDir) {
			bin := cfg.HivegenBin
			if bin == "" {
				bin = "dist/hivegen"
			}
			cmd := exec.Command(bin, "-out", genDir, "-genesis-delay", "90s")
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err := cmd.Run(); err != nil {
				return nil, nil, fmt.Errorf("hivegen (%s): %w", bin, err)
			}
		}
		prov := hiveenv.Provider{}
		envr, err := prov.Setup(ctx, hiveenv.Config{
			Enclave:     cfg.Enclave,
			GenDir:      genDir,
			ClientTypes: cfg.HiveClients,
		})
		if err != nil {
			return nil, nil, err
		}
		return envr, envr.Endpoints(), nil
	default:
		return nil, nil, fmt.Errorf("unknown env %q (want static, kurtosis or hive)", cfg.Env)
	}
}

// deriveChain builds the chain config from the preset plus the first client
// that exposes a valid fork digest.
func deriveChain(ctx context.Context, clients []runner.Client, preset string) runner.ChainConfig {
	chain := runner.ChainConfig{
		Preset:        preset,
		GossipMaxSize: 10485760, // mainnet defaults; refined by state below
		MaxChunkSize:  1048576,
	}
	for _, c := range clients {
		state, err := c.State(ctx)
		if err != nil || state == nil || !state.Valid {
			continue
		}
		chain.ForkDigest = state.ForkDigest
		chain.GenesisValidatorsRoot = state.GenesisValidatorRoot
		chain.GenesisForkVersion = state.GenesisForkVersion
		return chain
	}
	return chain
}

func writeOutputs(outputDir string, rep *runner.Report) error {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return err
	}
	jsonData, err := report.WriteJSON(rep)
	if err != nil {
		return err
	}
	if err := os.WriteFile(outputDir+"/report.json", jsonData, 0o644); err != nil {
		return err
	}
	junit, err := report.WriteJUnit(rep)
	if err != nil {
		return err
	}
	if err := os.WriteFile(outputDir+"/junit.xml", junit, 0o644); err != nil {
		return err
	}
	if err := report.ArchiveRun(rep); err != nil {
		fmt.Fprintf(os.Stderr, "warn: archive run: %v\n", err)
	}
	return nil
}

func printSummary(w io.Writer, rep *runner.Report) {
	fmt.Fprintf(w, "\nsummary: total=%d pass=%d divergent=%d skipped=%d errors=%d\n",
		rep.Summary.Total, rep.Summary.Passed, rep.Summary.Divergent,
		rep.Summary.Skipped, rep.Summary.Errors)
	findings := report.BuildFindings(rep, false)
	for _, f := range findings {
		fmt.Fprintf(w, "finding %s: [%s/%s] %s (outliers: %v, evidence: %d)\n",
			f.ID, f.Type, f.Severity, f.RootCause, f.OutlierClients, f.EvidenceCount)
	}
}

// loadRuleTexts resolves every spec rule id referenced by the report or the
// embedded history runs to its catalog text. Unknown ids (e.g. family tags
// like "reqresp:sequence-semantics") are absent and render as plain ids.
func loadRuleInfo(rep *runner.Report, runs []report.RunPayload) (map[string]string, map[string]string) {
	ids := map[string]bool{}
	collect := func(list []string) {
		for _, id := range list {
			ids[id] = true
		}
	}
	for _, r := range rep.Results {
		collect(r.SpecRuleIDs)
		for _, d := range r.Divergences {
			collect(d.SpecRuleIDs)
		}
	}
	for _, run := range runs {
		var hist runner.Report
		if len(run.Report) == 0 || json.Unmarshal(run.Report, &hist) != nil {
			continue
		}
		for _, r := range hist.Results {
			collect(r.SpecRuleIDs)
			for _, d := range r.Divergences {
				collect(d.SpecRuleIDs)
			}
		}
	}
	if len(ids) == 0 {
		return nil, nil
	}
	kb, err := knowledge.Load("knowledge")
	if err != nil {
		return nil, nil
	}
	raw, rawErr := kb.RawRules()
	out := map[string]string{}
	links := map[string]string{}
	for id := range ids {
		if rawErr == nil {
			if rr, ok := raw[id]; ok {
				txt := rr.RawText
				src := rr.Source.Fork
				if rr.Source.File != "" {
					src += " · " + filepath.Base(rr.Source.File) + ":" + fmt.Sprint(rr.Source.Line)
				}
				if txt != "" {
					txt += "\n"
				}
				txt += "source: " + src
				out[id] = txt
				if u := consensusSpecsURL(rr.Source.File, rr.Source.Line); u != "" {
					links[id] = u
				}
				continue
			}
		}
		for _, e := range kb.SpecRules() {
			if e.ID == id {
				out[id] = e.Text
				break
			}
		}
	}
	return out, links
}

// consensusSpecsURL maps a checked-out consensus-specs file path back to its
// GitHub source location, so reports can link the original spec text.
func consensusSpecsURL(file string, line int) string {
	i := strings.Index(file, "consensus-specs/")
	if i < 0 {
		return ""
	}
	return "https://github.com/ethereum/consensus-specs/blob/master/" +
		file[i+len("consensus-specs/"):] + "?plain=1#L" + strconv.Itoa(line)
}

// AnalyzeConfig carries the `analyze` subcommand options.
type AnalyzeConfig struct {
	ReportPath    string
	AllowlistPath string
	Legacy        bool
	HTML          bool
	JUnitOut      string
}

// runAnalyze executes the `analyze` subcommand.
func runAnalyze(cfg AnalyzeConfig, stdout io.Writer) error {
	data, err := os.ReadFile(cfg.ReportPath)
	if err != nil {
		return fmt.Errorf("read report: %w", err)
	}
	var rep runner.Report
	if err := json.Unmarshal(data, &rep); err != nil {
		return fmt.Errorf("parse report: %w", err)
	}

	findings := report.BuildFindings(&rep, false)
	if cfg.AllowlistPath != "" {
		alData, err := os.ReadFile(cfg.AllowlistPath)
		if err != nil {
			return fmt.Errorf("read allowlist: %w", err)
		}
		var al report.Allowlist
		if err := json.Unmarshal(alData, &al); err != nil {
			return fmt.Errorf("parse allowlist: %w", err)
		}
		report.ApplyAllowlist(findings, &al)
	}

	active := 0
	for _, f := range findings {
		if f.Suppressed {
			fmt.Fprintf(stdout, "suppressed %s: %s (%s)\n", f.ID, f.RootCause, f.SuppressReason)
			continue
		}
		active++
		fmt.Fprintf(stdout, "finding %s: [%s/%s] %s (outliers: %v, evidence: %d)\n",
			f.ID, f.Type, f.Severity, f.RootCause, f.OutlierClients, f.EvidenceCount)
	}
	fmt.Fprintf(stdout, "\n%d finding(s), %d suppressed\n", len(findings), len(findings)-active)

	if cfg.JUnitOut != "" {
		junit, err := report.WriteJUnit(&rep)
		if err != nil {
			return fmt.Errorf("render junit: %w", err)
		}
		if err := os.WriteFile(cfg.JUnitOut, junit, 0o644); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "junit report: %s\n", cfg.JUnitOut)
	}

	if cfg.HTML {
		historyDir, err := report.HistoryDir()
		if err != nil {
			historyDir = ""
		}
		runs, err := report.CollectRuns(&rep, findings, historyDir, 20)
		if err != nil {
			return fmt.Errorf("collect history: %w", err)
		}
		ruleTexts, ruleLinks := loadRuleInfo(&rep, runs)
		htmlData, err := report.WriteHTMLRuns(runs, 0, ruleTexts, ruleLinks)
		if err != nil {
			return fmt.Errorf("render html: %w", err)
		}
		htmlPath := strings.TrimSuffix(cfg.ReportPath, ".json") + ".html"
		if err := os.WriteFile(htmlPath, htmlData, 0o644); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "html report: %s (%d runs)\n", htmlPath, len(runs))
	}

	if cfg.Legacy {
		legacy, err := report.LegacyShape(&rep)
		if err != nil {
			return err
		}
		return os.WriteFile(strings.TrimSuffix(cfg.ReportPath, ".json")+".legacy.json", legacy, 0o644)
	}
	return nil
}

// runList prints the case registry.
func runList(stdout io.Writer) error {
	for _, s := range cases.All() {
		rc := s.Metadata.RunClass
		if rc == "" {
			rc = runner.RunClassStandard
		}
		fmt.Fprintf(stdout, "%-50s %-10s %s\n", s.ID, s.Category, rc)
	}
	return nil
}

// ---- flag parsing ----

func parseRunArgs(fs *flag.FlagSet, cfg *RunConfig, args []string) error {
	fs.StringVar(&cfg.Env, "env", "static", "environment backend: static | kurtosis | hive")
	fs.StringVar(&cfg.ConfigPath, "config", "clients.yaml", "static: path to clients.yaml")
	fs.StringVar(&cfg.Enclave, "enclave", "parallax", "kurtosis/hive: enclave name")
	fs.StringVar(&cfg.ArgsFile, "args-file", "", "kurtosis: ethereum-package args file")
	fs.BoolVar(&cfg.Attach, "attach", false, "kurtosis: attach to existing enclave instead of provisioning")
	fs.StringVar(&cfg.TestIDList, "test", "", "comma-separated exact test IDs (bypasses run-class filter)")
	fs.StringVar(&cfg.CategoryList, "category", "", "comma-separated categories")
	fs.BoolVar(&cfg.Regen, "regen", false, "regenerate spec cases, rebuild, then run (source tree + go toolchain required)")
	fs.StringVar(&cfg.SpecsDir, "specs-dir", "", "consensus-specs root for -regen (default: $PARALLAX_SPECS, ./ or ../ consensus-specs/specs)")
	fs.StringVar(&cfg.Suite, "suite", "quick", "test tier: quick | standard | full (default quick)")
	fs.StringVar(&cfg.ExcludePrefixList, "exclude-prefix", "", "comma-separated test-ID prefixes to exclude (e.g. \"ir.,ir_\")")
	fs.BoolVar(&cfg.IncludeHeavy, "include-heavy", false, "include heavy tests")
	fs.Int64Var(&cfg.Seed, "seed", 42, "random seed")
	fs.DurationVar(&cfg.InterTestDelay, "delay", time.Second, "delay between tests")
	fs.DurationVar(&cfg.MaxDuration, "max-duration", 0, "stop after this duration")
	fs.IntVar(&cfg.BanThreshold, "ban-threshold", 3, "consecutive health failures before exclusion")
	fs.DurationVar(&cfg.RecoveryCooldown, "recovery-cooldown", 2*time.Minute, "min interval between recovery probes of banned clients (0 disables recovery)")
	fs.IntVar(&cfg.RotateEvery, "rotate-every", 10, "rotate probe identities every N tests (0 disables)")
	fs.DurationVar(&cfg.PerTestTimeout, "test-timeout", 2*time.Minute, "per-test timeout")
	fs.StringVar(&cfg.Preset, "preset", "mainnet", "chain preset label")
	fs.StringVar(&cfg.Clients, "clients", "", "comma-separated client name substrings to include (empty = all)")
	fs.StringVar(&cfg.HiveGenDir, "hive-gen", "", "hive env: hivegen output dir (default <out>/gen, generated on demand)")
	fs.StringVar(&cfg.HivegenBin, "hivegen-bin", "dist/hivegen", "hive env: path to the hivegen binary for on-demand provisioning")
	fs.StringVar(&cfg.HiveClientList, "hive-clients", "lighthouse,teku,prysm,nimbus,lodestar,grandine", "hive env: comma-separated CL client types")
	fs.StringVar(&cfg.OutputDir, "out", "results", "output directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg.TestIDs = splitComma(cfg.TestIDList)
	cfg.Categories = splitComma(cfg.CategoryList)
	cfg.ExcludePrefixes = splitComma(cfg.ExcludePrefixList)
	cfg.HiveClients = splitComma(cfg.HiveClientList)
	return nil
}
