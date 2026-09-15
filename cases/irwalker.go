package cases

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"time"

	"parallax/runner"
)

// irwalker.go — a minimal state machine walker for the smgen-generated IR
// machines. The generated spec_ir_machines file supplies machine data; this
// file plans a seeded path through the graph, executes the same path on every
// client, and compares the joint per-step verdict vectors.
//
// Simplifications versus the p2p-testing engine: the path is planned once
// (structurally) so every client executes the same transitions; guards are
// evaluated against a planning context where generating_mode is false and
// LastResultCode is unknown (no real guard uses it); unmapped or destructive
// actions yield a "skipped" step verdict.

const irWalkStepBudget = 12

var irWalkSeeds = []int64{1, 2, 3}

// irMachine is the simplified machine definition emitted by smgen.
type irMachine struct {
	Name        string
	InitState   string
	Transitions []irTransition
}

// irTransition is one machine edge with its action and simplified oracle.
type irTransition struct {
	From          string
	To            string
	Label         string
	Weight        int
	ForkGte       string
	ForkIn        []string
	Guard         func(*irContext) bool // compiled non-fork guard; nil = none
	SpecRefs      []string
	ActionType    string // IR action type string
	Protocol      string
	TimeoutMs     int
	Payload       func(*irContext) []byte
	Mutator       string // applied after Payload; "" = none
	RepeatCount   int    // burst send count for req/resp; <=1 = single
	KeepWriteOpen bool   // ReadResponse: skip the half-close when true
}

// irPlan is one planned path through a machine.
type irPlan struct {
	Transitions []*irTransition
}

// irPlanPath walks the graph structurally with a seeded RNG: guards evaluate
// against a planning context with zeroed counters, so runtime-only guards
// resolve to their zero-state truth.
func irPlanPath(m *irMachine, seed int64) irPlan {
	rng := rand.New(rand.NewSource(seed))
	plan := irPlan{}
	state := m.InitState
	ictx := &irContext{Rng: rng, OpenStreams: map[string]struct{}{}}
	for step := 0; step < irWalkStepBudget; step++ {
		var candidates []*irTransition
		totalWeight := 0
		for i := range m.Transitions {
			t := &m.Transitions[i]
			if t.From != state {
				continue
			}
			if !irForkAllows(ictx.Fork, t) {
				continue
			}
			if t.Guard != nil && !t.Guard(ictx) {
				continue
			}
			w := t.Weight
			if w <= 0 {
				w = 1
			}
			candidates = append(candidates, t)
			totalWeight += w
		}
		if len(candidates) == 0 {
			break
		}
		pick := rng.Intn(totalWeight)
		var chosen *irTransition
		for _, t := range candidates {
			w := t.Weight
			if w <= 0 {
				w = 1
			}
			if pick < w {
				chosen = t
				break
			}
			pick -= w
		}
		plan.Transitions = append(plan.Transitions, chosen)
		irAdvancePlanningContext(ictx, chosen)
		state = chosen.To
	}
	return plan
}

// irForkAllows reports whether the fork constraint holds for fork name
// (empty = unknown = allowed).
func irForkAllows(fork string, t *irTransition) bool {
	if t.ForkGte == "" && len(t.ForkIn) == 0 {
		return true
	}
	if fork == "" {
		return true
	}
	if len(t.ForkIn) > 0 {
		for _, f := range t.ForkIn {
			if f == fork {
				return true
			}
		}
		return false
	}
	rank, want := irForkRank(fork), irForkRank(t.ForkGte)
	return want < 0 || rank >= want
}

// irAdvancePlanningContext applies the structural side effects of a transition
// so later guards see the same counter evolution the walk produces.
func irAdvancePlanningContext(ictx *irContext, t *irTransition) {
	switch t.ActionType {
	case "ActOpenStream":
		ictx.OpenStreams[fmt.Sprintf("plan_stream_%d", len(ictx.OpenStreams))] = struct{}{}
	case "ActSendReqResp", "ActSendStatus":
		ictx.MessagesSent++
	case "ActInjectGossip":
		if t.Protocol != "" && ictx.CurrentTopic == "" {
			ictx.CurrentTopic = t.Protocol
		}
	case "ActReconnect", "ActConnectRaw":
		ictx.ConnectionCount++
	}
	// Transitions hop states; the planning context tracks nothing else.
	_ = t.To
}

// irWalkSpecs converts machine definitions into seeded walk Specs.
func irWalkSpecs() []runner.Spec {
	var specs []runner.Spec
	for _, m := range irMachineDefs() {
		for _, seed := range irWalkSeeds {
			specs = append(specs, irWalkSpec(m, seed))
		}
	}
	return specs
}

func irWalkSpec(m *irMachine, seed int64) runner.Spec {
	id := fmt.Sprintf("ir.walk.%s.s%d", m.Name, seed)
	plan := irPlanPath(m, seed)
	var labels []string
	for _, t := range plan.Transitions {
		labels = append(labels, t.Label)
	}
	what := fmt.Sprintf("Seeded walk of machine %q (seed %d): %d steps (%s); every client must agree on each step's outcome.",
		m.Name, seed, len(plan.Transitions), strings.Join(labels, " -> "))
	return runner.Spec{
		ID:       id,
		Category: "ir_walk",
		What:     what,
		Metadata: runner.Metadata{
			SpecRules:  irWalkSpecRefs(plan),
			MinClients: 2,
		},
		Run: func(ctx context.Context, te runner.TestEnv) []runner.Divergence {
			results := map[string]string{}
			var firstSteps []runner.StepOutcome
			for _, c := range te.Clients {
				verdicts, steps := irExecuteWalk(ctx, c, te, plan, seed)
				results[c.Name()] = strings.Join(verdicts, "/")
				if firstSteps == nil {
					firstSteps = steps
				}
			}
			divs := divergeValues(id, "ir_walk", te, runner.DivAcceptReject, runner.SeverityHigh, results)
			if len(divs) > 0 && firstSteps != nil {
				divs[0].Steps = firstSteps
			}
			return divs
		},
	}
}

func irWalkSpecRefs(plan irPlan) []string {
	var refs []string
	seen := map[string]bool{}
	for _, t := range plan.Transitions {
		for _, r := range t.SpecRefs {
			if !seen[r] {
				seen[r] = true
				refs = append(refs, r)
			}
		}
	}
	return refs
}

// irExecuteWalk runs the planned transitions against one client, returning the
// per-step verdict classes and detailed step outcomes.
func irExecuteWalk(ctx context.Context, c runner.Client, te runner.TestEnv, plan irPlan, seed int64) ([]string, []runner.StepOutcome) {
	ictx := irNewContext(te)
	ictx.Rng = rand.New(rand.NewSource(seed * 1000))
	if src, ok := c.(interface {
		LiveBeaconAPI() string
		LivePoolContains(topic string, index uint64) (contains, observable bool)
	}); ok {
		ictx.LiveBuilder = newLiveBuilderContext(src)
	}
	w := &irWalkExecution{
		client:  c,
		ictx:    ictx,
		streams: map[string]runner.IRStream{},
	}
	var verdicts []string
	var steps []runner.StepOutcome
	for i, t := range plan.Transitions {
		verdict, detail := w.execAction(ctx, i+1, t)
		verdicts = append(verdicts, verdict)
		steps = append(steps, runner.StepOutcome{
			Index:         i + 1,
			Label:         t.Label,
			Input:         detail,
			Expected:      "",
			ClientResults: map[string]string{c.Name(): verdict},
		})
	}
	return verdicts, steps
}

// irWalkExecution carries per-client walk state.
type irWalkExecution struct {
	client     runner.Client
	ictx       *irContext
	streams    map[string]runner.IRStream // key: stream_<n>
	lastStream string
}

func (w *irWalkExecution) findStream(target int) runner.IRStream {
	if target > 0 {
		return w.streams[fmt.Sprintf("stream_%d", target)]
	}
	return w.streams[w.lastStream]
}

const irSlowLorisCap = 2 * time.Second

// execAction executes one planned transition and returns a comparable verdict
// class plus a short input description.
func (w *irWalkExecution) execAction(ctx context.Context, index int, t *irTransition) (verdict, detail string) {
	a := t
	ictx := w.ictx
	stepKey := fmt.Sprintf("stream_%d", index)
	switch a.ActionType {
	case "ActSendReqResp", "ActSendStatus":
		body := irPayload(a, ictx)
		timeout := irTimeout(a.TimeoutMs)
		repeat := a.RepeatCount
		if repeat <= 1 {
			repeat = 1
		}
		var res *runner.ReqRespResult
		var err error
		for i := 0; i < repeat; i++ {
			res, err = w.client.ReqResp(ctx, a.Protocol, body, timeout)
			ictx.MessagesSent++
			if err != nil || res == nil || (res.Error != "" && len(res.RawBytes) == 0) || res.StreamReset {
				break // server is rejecting further requests
			}
			if len(res.RawBytes) > 0 {
				ictx.LastResultCode = res.RawBytes[0]
			}
		}
		if res != nil && len(res.RawBytes) > 0 {
			ictx.LastResultCode = res.RawBytes[0]
		}
		return classOf(outcome(res, err)), shortInput(a.Protocol, body)
	case "ActOpenStream":
		s, err := w.client.OpenStream(ctx, a.Protocol)
		if err != nil {
			return "other:open_failed", shortInput(a.Protocol, nil)
		}
		if p := irPayload(a, ictx); len(p) > 0 {
			if err := s.WriteChunk(p, false); err != nil {
				_ = s.Close()
				return "other:write_failed", shortInput(a.Protocol, p)
			}
		}
		w.streams[stepKey] = s
		w.lastStream = stepKey
		ictx.OpenStreams[stepKey] = struct{}{}
		return "opened", shortInput(a.Protocol, nil)
	case "ActWritePartial":
		s := w.findStream(int(0)) // TargetStream simplification: latest
		if s == nil {
			return "other:no_open_stream", shortInput(a.Protocol, nil)
		}
		p := irPayload(a, ictx)
		if err := s.WriteChunk(p, false); err != nil {
			return "other:write_failed", shortInput(a.Protocol, p)
		}
		if a.TimeoutMs > 0 {
			d := time.Duration(a.TimeoutMs) * time.Millisecond
			if d > irSlowLorisCap {
				d = irSlowLorisCap
			}
			time.Sleep(d)
		}
		return "written", shortInput(a.Protocol, p)
	case "ActWriteAndClose":
		s := w.findStream(0)
		if s == nil {
			return "other:no_open_stream", shortInput(a.Protocol, nil)
		}
		p := irPayload(a, ictx)
		if err := s.WriteChunk(p, true); err != nil {
			return "other:write_failed", shortInput(a.Protocol, p)
		}
		return "sent", shortInput(a.Protocol, p)
	case "ActReadResponse":
		s := w.findStream(0)
		if s == nil {
			return "other:no_open_stream", shortInput(a.Protocol, nil)
		}
		if !a.KeepWriteOpen {
			// Half-close so the responder sees a complete request (EOF).
			_ = s.WriteChunk(nil, true)
		}
		resp, err := s.ReadResponse(irTimeout(a.TimeoutMs))
		for k, v := range w.streams {
			if v == s {
				delete(w.streams, k)
				delete(ictx.OpenStreams, k)
			}
		}
		if err != nil {
			return "stream_reset", shortInput(a.Protocol, resp)
		}
		if len(resp) > 0 {
			ictx.LastResultCode = resp[0]
		}
		if len(resp) > 0 && resp[0] == 0x00 {
			return "accept", shortInput(a.Protocol, resp)
		}
		if len(resp) == 0 {
			return "other:empty_response", shortInput(a.Protocol, resp)
		}
		return "reject", shortInput(a.Protocol, resp)
	case "ActInjectGossip":
		p := irPayload(a, ictx)
		if ictx.SetupInapplicableReason != "" {
			return "inapplicable", ictx.SetupInapplicableReason
		}
		topic := a.Protocol
		if ictx.GossipTopicOverride != "" {
			topic = ictx.GossipTopicOverride
		}
		if topic == "" {
			topic = ictx.CurrentTopic
		}
		full := irFullGossipTopic(ictx, topic)
		v, err := w.client.ObserveGossip(ctx, full, p, gossipWait)
		return gossipOutcome(v, err), "gossip " + full
	case "ActCheckConnected":
		if err := w.client.Health(ctx); err != nil {
			return "not_connected", "health"
		}
		return "connected", "health"
	case "ActReconnect", "ActConnectRaw":
		if err := w.client.Connect(ctx, runner.ConnectNoStatus); err != nil {
			return "reconnect_failed", "connect"
		}
		return "reconnected", "connect"
	case "ActSwitchTopic":
		ictx.CurrentTopic = a.Protocol
		return "topic_set", "topic " + a.Protocol
	case "ActValidateResponseOrder":
		body := irPayload(a, ictx)
		v := irOrderCheck(ctx, w.client, a.Protocol, t.Label, body, a.TimeoutMs)
		if len(body) > 0 {
			ictx.LastResultCode = 0x00
		}
		return v, shortInput(a.Protocol, body)
	case "ActDisconnectPeer":
		v := irDisconnectAndRestore(ctx, w.client)
		ictx.StatusDone = false
		ictx.ConnectionCount++
		return v, "disconnect"
	case "ActRequestCustodyColumns":
		v := irCustodyRequest(ctx, w.client, ictx, a.Protocol)
		return v, "custody " + a.Protocol
	case "ActQueryENR", "ActVerifyENRBehavior":
		if _, err := w.client.State(ctx); err != nil {
			return "state_unavailable", "state"
		}
		return "state_available", "state"
	default:
		return "skipped", "action " + a.ActionType
	}
}

func irPayload(a *irTransition, ictx *irContext) []byte {
	var payload []byte
	if a.Payload != nil {
		payload = a.Payload(ictx)
	}
	if a.Mutator != "" {
		payload = irApplyMutator(a.Mutator, payload, ictx.Rng)
	}
	return payload
}

// irTimeScale scales the walker's internal waits/timeouts (default 1.0).
// Set PARALLAX_TIME_SCALE (e.g. 0.2) to shorten response waits overall for
// quick verification rounds; verdicts are unchanged as long as clients
// respond in time, only the no-response wait ceiling shrinks.
var irTimeScale = func() float64 {
	if v := os.Getenv("PARALLAX_TIME_SCALE"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 {
			return f
		}
	}
	return 1.0
}()

func irTimeout(ms int) time.Duration {
	if ms <= 0 {
		return time.Duration(15*irTimeScale) * time.Second
	}
	return time.Duration(float64(ms)*irTimeScale) * time.Millisecond
}

func shortInput(protocol string, body []byte) string {
	const max = 12
	b := ""
	if len(body) > max {
		b = fmt.Sprintf("body %dB: 0x%x…", len(body), body[:max])
	} else if len(body) > 0 {
		b = fmt.Sprintf("body %dB: 0x%x", len(body), body)
	}
	if b == "" {
		return protocol
	}
	return protocol + " · " + b
}
