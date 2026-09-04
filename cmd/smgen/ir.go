package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
)

// The structs below mirror ir/sm_ir/schema.json. They are the in-memory model
// shared by the validator and Go compiler.

// Machine is a single state machine in SM-IR form.
type Machine struct {
	Name string `json:"name"`
	// Constructor overrides the generated Go constructor function name. When
	// empty, the generator emits New<sanitize(Name)>Machine. Used where the
	// machine Name differs from the established constructor name (e.g. machine
	// "GossipValidation" with constructor NewGossipMachine).
	Constructor string       `json:"constructor,omitempty"`
	InitState   string       `json:"init_state"`
	States      []State      `json:"states"`
	Transitions []Transition `json:"transitions"`
}

// State is a named protocol state.
type State struct {
	Name     string `json:"name"`
	Terminal bool   `json:"terminal,omitempty"`
}

// Transition connects two states via an action, optionally guarded, with an
// oracle binding and spec provenance.
type Transition struct {
	From          string   `json:"from"`
	To            string   `json:"to"`
	Label         string   `json:"label"`
	Weight        int      `json:"weight,omitempty"`
	Description   string   `json:"description,omitempty"`
	ConditionDesc string   `json:"condition_desc,omitempty"`
	Tags          []string `json:"tags,omitempty"`
	SpecRefs      []string `json:"spec_refs,omitempty"`
	Action        Action   `json:"action"`
	Guard         *Guard   `json:"guard,omitempty"`
	Oracle        *Oracle  `json:"oracle,omitempty"`
}

// Action describes what to do when the transition is taken.
type Action struct {
	Type      string   `json:"type"`
	Protocol  string   `json:"protocol,omitempty"`
	Payload   *Payload `json:"payload,omitempty"`
	TimeoutMs int      `json:"timeout_ms,omitempty"`
	// TimeoutNs sets Action.Timeout to a raw nanosecond count. Used for the few
	// transitions that overload Timeout as a small integer (e.g. gossip burst
	// counts). Mutually exclusive with TimeoutMs.
	TimeoutNs    int    `json:"timeout_ns,omitempty"`
	Mutator      string `json:"mutator,omitempty"`
	TargetStream int    `json:"target_stream,omitempty"`
	RepeatCount  int    `json:"repeat_count,omitempty"`
	// KeepWriteOpen (ActReadResponse only) leaves the target stream's write side
	// open before reading, for the intentional requester-MUST-close violation test.
	// Default (false) half-closes first so the responder replies deterministically.
	KeepWriteOpen bool `json:"keep_write_open,omitempty"`
	// PoolDelta makes ActInjectGossip on operation-pool topics judge acceptance by
	// whether the injected operation creates a new pool entry.
	PoolDelta bool `json:"pool_delta,omitempty"`
}

// Payload is the hybrid payload IR: declarative literal/fields or a named builder.
type Payload struct {
	Kind       string                `json:"kind"`
	Wrap       string                `json:"wrap,omitempty"`
	Bytes      string                `json:"bytes,omitempty"`
	Size       *int                  `json:"size,omitempty"`
	Null       bool                  `json:"null,omitempty"`
	Fields     map[string]FieldValue `json:"fields,omitempty"`
	Name       string                `json:"name,omitempty"`
	Params     []any                 `json:"params,omitempty"`
	CacheStore string                `json:"cache_store,omitempty"`
	CacheLoad  string                `json:"cache_load,omitempty"`
}

// FieldValue is one SSZ field's value source (exactly one of lit/ctx/special).
// Lit is uint64 so it can represent the full range of SSZ uint64 fields
// (e.g. seq_number = MAX_UINT64), which exceeds Go's int on 64-bit platforms.
type FieldValue struct {
	Lit     *uint64 `json:"lit,omitempty"`
	Ctx     string  `json:"ctx,omitempty"`
	Special string  `json:"special,omitempty"`
}

// Guard is a boolean expression over SeqContext. Exactly one field is set.
type Guard struct {
	And            []Guard  `json:"and,omitempty"`
	Or             []Guard  `json:"or,omitempty"`
	Not            *Guard   `json:"not,omitempty"`
	GeneratingMode *bool    `json:"generating_mode,omitempty"`
	Flag           string   `json:"flag,omitempty"`
	Present        string   `json:"present,omitempty"`
	Count          *Compare `json:"count,omitempty"`
	Len            *Compare `json:"len,omitempty"`
	LastResultIn   []string `json:"last_result_in,omitempty"`
	HasVisited     string   `json:"has_visited,omitempty"`
	// ForkGte / ForkIn are fork-availability atoms. The compiler extracts them
	// into the transition's ForkConstraint (not the runtime Condition); they may
	// appear only as a standalone guard or as direct children of a top-level
	// "and".
	ForkGte string   `json:"fork_gte,omitempty"`
	ForkIn  []string `json:"fork_in,omitempty"`
}

// isForkAtom reports whether the guard is a single fork_gte / fork_in atom.
func (g *Guard) isForkAtom() bool {
	return g != nil && (g.ForkGte != "" || len(g.ForkIn) > 0)
}

// Compare is an integer comparison used by count/len guards.
type Compare struct {
	Field string `json:"field"`
	Op    string `json:"op"`
	Value int    `json:"value"`
}

// Oracle binds a transition to the oracles that judge its response.
type Oracle struct {
	Differential   bool            `json:"differential,omitempty"`
	Expected       string          `json:"expected,omitempty"`
	MustNot        []string        `json:"must_not,omitempty"`
	SpecPredicate  string          `json:"spec_predicate,omitempty"`
	ResourceBounds *ResourceBounds `json:"resource_bounds,omitempty"`
	ResourceTrend  *ResourceTrend  `json:"resource_trend,omitempty"`
	InvariantRefs  []string        `json:"invariant_refs,omitempty"`
	// Strength is the spec strength (MUST/SHOULD/MAY) of the rule this oracle
	// enforces. It drives single-client oracle violation severity (MUST->High,
	// SHOULD->Low advisory, MAY->Info). When empty, smgen derives it from the
	// transition's spec_refs at generate time; an unresolved/absent strength
	// defaults to MUST-equivalent severity so judgments are never silently
	// weakened.
	Strength string `json:"strength,omitempty"`
}

// ResourceBounds expresses the resource-usage oracle's per-step limits.
type ResourceBounds struct {
	MaxStreamDelta    *int `json:"max_stream_delta,omitempty"`
	MaxMemDeltaMB     *int `json:"max_mem_delta_mb,omitempty"`
	MaxGoroutineDelta *int `json:"max_goroutine_delta,omitempty"`
	MaxFdDelta        *int `json:"max_fd_delta,omitempty"`
}

// ResourceTrend expresses the resource-trend oracle's limits over a sustained-load
// window (a burst of repeated actions). See framework.ResourceTrend.
type ResourceTrend struct {
	MinSamples            int      `json:"min_samples,omitempty"`
	MaxTotalMemGrowthMB   *int     `json:"max_total_mem_growth_mb,omitempty"`
	RequireMonotonic      bool     `json:"require_monotonic,omitempty"`
	MaxCPURatePerSec      *float64 `json:"max_cpu_rate_per_sec,omitempty"`
	MaxAmplificationRatio *float64 `json:"max_amplification_ratio,omitempty"`
}

// loadMachine reads and strictly unmarshals an SM-IR file. Unknown fields are
// rejected (Gate 1: structural conformance). A decode error is returned so the
// caller can record it as a Gate-1 issue.
func loadMachine(path string) (*Machine, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var m Machine
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("strict decode: %w", err)
	}
	// Reject trailing content after the JSON object.
	if dec.More() {
		return nil, fmt.Errorf("unexpected trailing data after JSON object")
	}
	return &m, nil
}
