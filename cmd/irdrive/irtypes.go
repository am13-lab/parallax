package main

// irtypes.go — SM-IR output structs mirroring ir/sm_ir/schema.json. The
// schema is additionalProperties:false, so every field here maps to a schema key
// and optionals use omitempty. cmd/smgen consumes this JSON.

type irMachine struct {
	Name        string         `json:"name"`
	Constructor string         `json:"constructor,omitempty"`
	InitState   string         `json:"init_state"`
	States      []irState      `json:"states"`
	Transitions []irTransition `json:"transitions"`
}

type irState struct {
	Name     string `json:"name"`
	Terminal bool   `json:"terminal,omitempty"`
}

type irTransition struct {
	From          string    `json:"from"`
	To            string    `json:"to"`
	Label         string    `json:"label"`
	Weight        int       `json:"weight,omitempty"`
	Description   string    `json:"description,omitempty"`
	ConditionDesc string    `json:"condition_desc,omitempty"`
	Tags          []string  `json:"tags,omitempty"`
	SpecRefs      []string  `json:"spec_refs,omitempty"`
	Action        *irAction `json:"action"`
	Guard         *irGuard  `json:"guard,omitempty"`
	Oracle        *irOracle `json:"oracle,omitempty"`
}

type irAction struct {
	Type          string     `json:"type"`
	Protocol      string     `json:"protocol,omitempty"`
	Payload       *irPayload `json:"payload,omitempty"`
	TimeoutMs     int        `json:"timeout_ms,omitempty"`
	TimeoutNs     int        `json:"timeout_ns,omitempty"`
	Mutator       string     `json:"mutator,omitempty"`
	TargetStream  *int       `json:"target_stream,omitempty"`
	RepeatCount   int        `json:"repeat_count,omitempty"`
	KeepWriteOpen bool       `json:"keep_write_open,omitempty"`
	PoolDelta     bool       `json:"pool_delta,omitempty"`
}

type irPayload struct {
	Kind       string                `json:"kind"` // literal | fields | builder
	Wrap       string                `json:"wrap,omitempty"`
	Bytes      string                `json:"bytes,omitempty"`
	Size       *int                  `json:"size,omitempty"`
	Null       bool                  `json:"null,omitempty"`
	Fields     map[string]irFieldVal `json:"fields,omitempty"`
	Name       string                `json:"name,omitempty"`
	Params     []any                 `json:"params,omitempty"`
	CacheStore string                `json:"cache_store,omitempty"`
	CacheLoad  string                `json:"cache_load,omitempty"`
}

// irFieldVal is exactly one of lit/ctx (we never emit special — no codegen path).
type irFieldVal struct {
	Lit *int64 `json:"lit,omitempty"`
	Ctx string `json:"ctx,omitempty"`
}

// irGuard mirrors the guard schema; we only emit fork constraints and simple
// flag/has_visited guards derived from AST conditional/provenance edges.
type irGuard struct {
	And            []irGuard  `json:"and,omitempty"`
	Or             []irGuard  `json:"or,omitempty"`
	Not            *irGuard   `json:"not,omitempty"`
	GeneratingMode *bool      `json:"generating_mode,omitempty"`
	Flag           string     `json:"flag,omitempty"`
	Present        string     `json:"present,omitempty"`
	Count          *irCompare `json:"count,omitempty"`
	Len            *irCompare `json:"len,omitempty"`
	LastResultIn   []string   `json:"last_result_in,omitempty"`
	HasVisited     string     `json:"has_visited,omitempty"`
	ForkGte        string     `json:"fork_gte,omitempty"`
	ForkIn         []string   `json:"fork_in,omitempty"`
}

type irCompare struct {
	Field string `json:"field"`
	Op    string `json:"op"`
	Value int    `json:"value"`
}

type irOracle struct {
	Differential   bool              `json:"differential,omitempty"`
	Expected       string            `json:"expected,omitempty"`
	MustNot        []string          `json:"must_not,omitempty"`
	SpecPredicate  string            `json:"spec_predicate,omitempty"`
	ResourceBounds *irResourceBounds `json:"resource_bounds,omitempty"`
	ResourceTrend  *irResourceTrend  `json:"resource_trend,omitempty"`
	InvariantRefs  []string          `json:"invariant_refs,omitempty"`
	Strength       string            `json:"strength,omitempty"`
}

type irResourceBounds struct {
	MaxStreamDelta    *int `json:"max_stream_delta,omitempty"`
	MaxMemDeltaMB     *int `json:"max_mem_delta_mb,omitempty"`
	MaxGoroutineDelta *int `json:"max_goroutine_delta,omitempty"`
	MaxFDDelta        *int `json:"max_fd_delta,omitempty"`
}

type irResourceTrend struct {
	MinSamples            int      `json:"min_samples,omitempty"`
	MaxTotalMemGrowthMB   *int     `json:"max_total_mem_growth_mb,omitempty"`
	RequireMonotonic      bool     `json:"require_monotonic,omitempty"`
	MaxCPURatePerSec      *float64 `json:"max_cpu_rate_per_sec,omitempty"`
	MaxAmplificationRatio *float64 `json:"max_amplification_ratio,omitempty"`
}

func litVal(v int64) irFieldVal { return irFieldVal{Lit: &v} }
