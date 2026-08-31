package runner

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand"
	"runtime/debug"
	"sync"
	"time"

	"parallax/env"
)

// Status is the outcome of one executed test.
type Status string

const (
	StatusPass      Status = "pass"
	StatusDivergent Status = "divergent"
	StatusSkipped   Status = "skipped"
	StatusError     Status = "error"
)

// TestResult is the outcome of one spec.
type TestResult struct {
	TestID          string       `json:"test_id"`
	Category        string       `json:"category"`
	Status          Status       `json:"status"`
	SkipReason      string       `json:"skip_reason,omitempty"`
	ExcludedClients []string     `json:"excluded_clients,omitempty"`
	Divergences     []Divergence `json:"divergences,omitempty"`
	Elapsed         string       `json:"elapsed"`
	// ElapsedDuration is the parsed form of Elapsed for programmatic use.
	ElapsedDuration time.Duration `json:"-"`
}

// Summary aggregates a run.
type Summary struct {
	Total      int    `json:"total"`
	Passed     int    `json:"passed"`
	Divergent  int    `json:"divergent"`
	Skipped    int    `json:"skipped"`
	Errors     int    `json:"errors"`
	Executed   int    `json:"executed"`
	StopReason string `json:"stop_reason,omitempty"`
}

// EndpointFingerprint identifies the exact target in a report.
type EndpointFingerprint struct {
	Name       string `json:"name"`
	ClientType string `json:"client_type"`
	Multiaddr  string `json:"multiaddr,omitempty"`
	Image      string `json:"image,omitempty"`
	Version    string `json:"version,omitempty"`
}

// Report is the full result of one run. Schema version 1.
type Report struct {
	SchemaVersion int                   `json:"schema_version"`
	StartedAt     time.Time             `json:"started_at"`
	EndedAt       time.Time             `json:"ended_at"`
	Seed          int64                 `json:"seed"`
	Environment   map[string]string     `json:"environment"`
	Endpoints     []EndpointFingerprint `json:"endpoints"`
	Chain         ChainConfig           `json:"-"`
	ChainPreset   string                `json:"chain_preset,omitempty"`
	Results       []TestResult          `json:"results"`
	Summary       Summary               `json:"summary"`
}

// Options configures a run.
type Options struct {
	Seed             int64
	TestIDs          []string
	Categories       []string
	IncludeHeavy     bool
	IncludeConfig    bool
	InterTestDelay   time.Duration
	MaxDuration      time.Duration
	BanThreshold     int
	RecoveryCooldown time.Duration
	RotateEvery      int
	PerTestTimeout   time.Duration
	Progress         func(TestResult)
}

// SelectSpecs applies the selection rules: exact TestIDs bypass all
// filtering; otherwise categories and run-class filters apply, and the
// result is shuffled deterministically by the seed.
func SelectSpecs(specs []Spec, opts Options) []Spec {
	if len(opts.TestIDs) > 0 {
		want := make(map[string]bool, len(opts.TestIDs))
		for _, id := range opts.TestIDs {
			want[id] = true
		}
		var out []Spec
		for _, s := range specs {
			if want[s.ID] {
				out = append(out, s)
			}
		}
		return out
	}

	cats := make(map[string]bool, len(opts.Categories))
	for _, c := range opts.Categories {
		cats[c] = true
	}
	var out []Spec
	for _, s := range specs {
		if len(cats) > 0 && !cats[s.Category] {
			continue
		}
		rc := s.Metadata.RunClass
		if rc == RunClassHeavy && !opts.IncludeHeavy {
			continue
		}
		if rc == RunClassConfig && !opts.IncludeConfig {
			continue
		}
		out = append(out, s)
	}

	rng := rand.New(rand.NewSource(opts.Seed))
	rng.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

type banState struct {
	mu              sync.Mutex
	consecutive     map[string]int
	bannedAt        map[string]time.Time
	lastRecoveryTry map[string]time.Time
}

func (b *banState) isBanned(name string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, ok := b.bannedAt[name]
	return ok
}

// recordFailure bumps the failure count and returns true when the client
// crossed the ban threshold.
func (b *banState) recordFailure(name string, threshold int) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.consecutive[name]++
	if threshold > 0 && b.consecutive[name] >= threshold {
		b.bannedAt[name] = time.Now()
		return true
	}
	return false
}

func (b *banState) reset(name string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.consecutive, name)
	delete(b.bannedAt, name)
}

func (b *banState) bannedNames() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]string, 0, len(b.bannedAt))
	for name := range b.bannedAt {
		out = append(out, name)
	}
	return out
}

func (b *banState) canRecover(name string, cooldown time.Duration) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	at, ok := b.bannedAt[name]
	if !ok {
		return false
	}
	if cooldown > 0 && time.Since(at) < cooldown {
		return false
	}
	if last, seen := b.lastRecoveryTry[name]; seen && cooldown > 0 && time.Since(last) < cooldown {
		return false
	}
	b.lastRecoveryTry[name] = time.Now()
	return true
}

// Run executes the specs sequentially against the clients and returns the
// assembled report.
func Run(ctx context.Context, specs []Spec, clients []Client, environment env.Environment,
	chain ChainConfig, opts Options) *Report {

	started := time.Now()
	rep := &Report{
		SchemaVersion: 1,
		StartedAt:     started,
		Seed:          opts.Seed,
		Environment:   map[string]string{},
		Chain:         chain,
		ChainPreset:   chain.Preset,
	}
	if environment != nil {
		for k, v := range environment.Info() {
			rep.Environment[k] = v
		}
		for _, ep := range environment.Endpoints() {
			rep.Endpoints = append(rep.Endpoints, EndpointFingerprint{
				Name: ep.Name, ClientType: ep.ClientType, Multiaddr: ep.Multiaddr,
				Image: ep.Image, Version: ep.Version,
			})
		}
	}

	selected := SelectSpecs(specs, opts)
	bans := &banState{
		consecutive:     map[string]int{},
		bannedAt:        map[string]time.Time{},
		lastRecoveryTry: map[string]time.Time{},
	}
	var deadline *time.Time
	if opts.MaxDuration > 0 {
		d := started.Add(opts.MaxDuration)
		deadline = &d
	}

	for i, s := range selected {
		if ctx.Err() != nil {
			rep.Summary.StopReason = "context cancelled"
			break
		}
		if deadline != nil && time.Now().After(*deadline) {
			rep.Summary.StopReason = "deadline"
			break
		}

		// Recover banned clients whose cooldown elapsed.
		for _, name := range bans.bannedNames() {
			if !bans.canRecover(name, opts.RecoveryCooldown) {
				continue
			}
			for _, c := range clients {
				if c.Name() != name {
					continue
				}
				rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
				err := c.Health(rctx)
				cancel()
				if err == nil {
					bans.reset(name)
				}
			}
		}

		// Usable clients: not banned.
		var usable []Client
		for _, c := range clients {
			if !bans.isBanned(c.Name()) {
				usable = append(usable, c)
			}
		}

		result := TestResult{TestID: s.ID, Category: s.Category}
		for _, name := range bans.bannedNames() {
			result.ExcludedClients = append(result.ExcludedClients, name)
		}

		floor := s.Metadata.MinClients
		if floor <= 0 {
			floor = 2
		}
		switch {
		case len(usable) < floor:
			result.Status = StatusSkipped
			result.SkipReason = fmt.Sprintf("insufficient usable clients: have %d, need %d", len(usable), floor)
		case s.Preflight != nil:
			pf := s.Preflight(ctx, chain, usable)
			if !pf.Runnable {
				result.Status = StatusSkipped
				result.SkipReason = pf.Reason
			}
		}

		if result.Status == "" {
			// Identity rotation cadence.
			if opts.RotateEvery > 0 && i > 0 && i%opts.RotateEvery == 0 {
				for _, c := range usable {
					rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
					if err := c.RotateIdentity(rctx); err != nil {
						if banned := bans.recordFailure(c.Name(), opts.BanThreshold); banned {
							slog.Warn("client banned after rotation failure", "client", c.Name())
						}
					}
					cancel()
				}
			}

			runCtx := ctx
			cancel := func() {}
			if opts.PerTestTimeout > 0 {
				runCtx, cancel = context.WithTimeout(ctx, opts.PerTestTimeout)
			}
			te := TestEnv{
				Clients: usable,
				Env:     environment,
				Chain:   chain,
				Meta:    s.Metadata,
				RNG:     rand.New(rand.NewSource(opts.Seed + int64(i))),
				Log:     slog.Default(),
			}
			testStart := time.Now()
			divs, runErr := runSpecSafe(runCtx, s, te)
			cancel()

			result.ElapsedDuration = time.Since(testStart)
			result.Elapsed = result.ElapsedDuration.String()
			if runErr != nil {
				result.Status = StatusError
			}
			for j := range divs {
				if divs[j].TestID == "" {
					divs[j].TestID = s.ID
				}
				if divs[j].Category == "" {
					divs[j].Category = s.Category
				}
				if divs[j].RunClass == "" {
					divs[j].RunClass = normalizeRunClass(s.Metadata.RunClass)
				}
				divs[j].ExcludedClients = result.ExcludedClients
				if divs[j].Severity == "" {
					divs[j].Severity = SeverityMedium
				}
			}
			if result.Status != StatusError {
				result.Divergences = divs
				switch {
				case len(divs) > 0:
					result.Status = StatusDivergent
				default:
					result.Status = StatusPass
				}
			}
		}

		// Post-test health check feeds the ban logic. A failure hitting
		// EVERY usable client at once is environmental (host stall, VM
		// pressure) and must not ban anyone.
		healthFailures := 0
		for _, c := range usable {
			hctx, cancel := context.WithTimeout(ctx, 8*time.Second)
			err := c.Health(hctx)
			cancel()
			if err != nil {
				healthFailures++
			}
		}
		if len(usable) > 0 && healthFailures == len(usable) {
			slog.Warn("all clients failed post-test health check; treating as environmental, no bans",
				"test", s.ID, "clients", len(usable))
		} else {
			for _, c := range usable {
				hctx, cancel := context.WithTimeout(ctx, 8*time.Second)
				err := c.Health(hctx)
				cancel()
				if err != nil {
					wasBanned := bans.recordFailure(c.Name(), opts.BanThreshold)
					if wasBanned {
						slog.Warn("client banned after repeated health failures", "client", c.Name(), "test", s.ID)
					}
				} else {
					bans.reset(c.Name())
				}
			}
		}

		rep.Results = append(rep.Results, result)
		rep.Summary.Total++
		switch result.Status {
		case StatusPass:
			rep.Summary.Passed++
		case StatusDivergent:
			rep.Summary.Divergent++
		case StatusSkipped:
			rep.Summary.Skipped++
		case StatusError:
			rep.Summary.Errors++
		}
		if result.Status != StatusSkipped {
			rep.Summary.Executed++
		}
		if opts.Progress != nil {
			opts.Progress(result)
		}

		// Inter-test delay.
		if opts.InterTestDelay > 0 && i < len(selected)-1 {
			if !sleepRespecting(ctx, deadline, opts.InterTestDelay) {
				rep.Summary.StopReason = stopReasonFor(ctx, deadline)
				break
			}
		}
	}

	rep.EndedAt = time.Now()
	if rep.Summary.StopReason == "" && ctx.Err() != nil {
		rep.Summary.StopReason = "context cancelled"
	}
	return rep
}

func runSpecSafe(ctx context.Context, s Spec, te TestEnv) (divs []Divergence, err error) {
	defer func() {
		if r := recover(); r != nil {
			divs = nil
			err = fmt.Errorf("panic: %v", r)
			slog.Error("test panicked", "test", s.ID, "panic", r, "stack", string(debug.Stack()))
		}
	}()
	if s.Run == nil {
		return nil, nil
	}
	return s.Run(ctx, te), nil
}

func normalizeRunClass(rc RunClass) RunClass {
	if rc == "" {
		return RunClassStandard
	}
	return rc
}

func sleepRespecting(ctx context.Context, deadline *time.Time, d time.Duration) bool {
	if deadline != nil {
		if remaining := time.Until(*deadline); remaining < d {
			d = remaining
		}
		if d <= 0 {
			return false
		}
	}
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

func stopReasonFor(ctx context.Context, deadline *time.Time) string {
	if deadline != nil && time.Now().After(*deadline) {
		return "deadline"
	}
	return "context cancelled"
}
