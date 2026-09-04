package main

import (
	"fmt"
	"sort"
)

// triBool is a three-valued logic result for static guard evaluation. A guard
// is triFalse only when it is provably unsatisfiable; client-derived and
// plan-time atoms collapse to triUnknown so the analyzer never raises a false
// alarm on state it cannot decide statically.
type triBool int

const (
	triFalse triBool = iota
	triUnknown
	triTrue
)

// evalGuard statically evaluates a guard expression. A nil guard (unconditional
// transition) is triTrue. Leaf atoms that depend on runtime/client state
// (generating_mode, flag, present, last_result_in, has_visited, fork_gte,
// fork_in) are triUnknown. Only count/len comparisons that admit no value over
// the nonnegative-integer domain, and combinators that propagate a provable
// False/True, yield a decisive result.
func evalGuard(g *Guard) triBool {
	if g == nil {
		return triTrue
	}
	switch {
	case g.And != nil:
		res := triTrue
		for i := range g.And {
			switch evalGuard(&g.And[i]) {
			case triFalse:
				return triFalse
			case triUnknown:
				res = triUnknown
			}
		}
		return res
	case g.Or != nil:
		res := triFalse
		for i := range g.Or {
			switch evalGuard(&g.Or[i]) {
			case triTrue:
				return triTrue
			case triUnknown:
				res = triUnknown
			}
		}
		return res
	case g.Not != nil:
		switch evalGuard(g.Not) {
		case triTrue:
			return triFalse
		case triFalse:
			return triTrue
		default:
			return triUnknown
		}
	case g.Count != nil:
		return evalCompare(g.Count)
	case g.Len != nil:
		return evalCompare(g.Len)
	default:
		// generating_mode, flag, present, last_result_in, has_visited,
		// fork_gte, fork_in: undecidable statically.
		return triUnknown
	}
}

// evalCompare reports triFalse when a count/len comparison can be satisfied by
// no value in the nonnegative-integer domain that counters and collection
// lengths inhabit; otherwise triUnknown (the counter may or may not reach the
// value at runtime).
func evalCompare(c *Compare) triBool {
	switch c.Op {
	case "<":
		if c.Value <= 0 { // no nonneg int is < a nonpositive bound
			return triFalse
		}
	case "<=":
		if c.Value < 0 {
			return triFalse
		}
	case "==":
		if c.Value < 0 {
			return triFalse
		}
	}
	return triUnknown
}

// collectHasVisited returns every has_visited label referenced anywhere in a
// guard tree.
func collectHasVisited(g *Guard) []string {
	if g == nil {
		return nil
	}
	var out []string
	if g.HasVisited != "" {
		out = append(out, g.HasVisited)
	}
	for i := range g.And {
		out = append(out, collectHasVisited(&g.And[i])...)
	}
	for i := range g.Or {
		out = append(out, collectHasVisited(&g.Or[i])...)
	}
	if g.Not != nil {
		out = append(out, collectHasVisited(g.Not)...)
	}
	return out
}

// gate8Reachability checks that the machine is logically sound as a graph,
// accounting for guards. It complements gate4 (which does guard-unaware forward
// reachability) by adding: dead-transition detection (provably-false guards),
// has_visited label resolution, structural deadlock (a reachable non-terminal
// state with no satisfiable outgoing edge), and a liveness check that every
// reachable non-terminal state can still reach a terminal state.
//
// An edge is "live" when its guard is not provably false. Reachability and
// deadlock analysis run over live edges only, so the gate never flags a state
// the machine could legitimately enter at runtime.
func gate8Reachability(m *Machine, r *Result) {
	states := map[string]bool{}
	terminal := map[string]bool{}
	for _, s := range m.States {
		states[s.Name] = true
		if s.Terminal {
			terminal[s.Name] = true
		}
	}
	labels := map[string]bool{}
	for _, t := range m.Transitions {
		if t.Label != "" {
			labels[t.Label] = true
		}
	}

	// Live adjacency, dead-guard detection, and has_visited resolution.
	live := map[string][]string{}
	hasLiveOut := map[string]bool{}
	for i, t := range m.Transitions {
		for _, hv := range collectHasVisited(t.Guard) {
			if !labels[hv] {
				r.add("gate8", fmt.Sprintf("transitions[%d].guard", i),
					"has_visited references undefined label %q", hv)
			}
		}
		if evalGuard(t.Guard) == triFalse {
			r.add("gate8", fmt.Sprintf("transitions[%d].guard", i),
				"guard is unsatisfiable; transition %q is dead", t.Label)
			continue
		}
		if states[t.From] {
			hasLiveOut[t.From] = true
			if states[t.To] {
				live[t.From] = append(live[t.From], t.To)
			}
		}
	}

	// Forward reachability from init over live edges.
	reachable := map[string]bool{}
	if states[m.InitState] {
		queue := []string{m.InitState}
		reachable[m.InitState] = true
		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			for _, nx := range live[cur] {
				if !reachable[nx] {
					reachable[nx] = true
					queue = append(queue, nx)
				}
			}
		}
	}

	// Structural deadlock: a reachable non-terminal state with no live outgoing
	// edge traps the executor.
	var dead []string
	for _, s := range m.States {
		if reachable[s.Name] && !terminal[s.Name] && !hasLiveOut[s.Name] {
			dead = append(dead, s.Name)
		}
	}
	sort.Strings(dead)
	for _, s := range dead {
		r.add("gate8", "states",
			"non-terminal state %q has no satisfiable outgoing transition (deadlock)", s)
	}

	// Liveness. Open-ended machines with no terminal state get a single notice;
	// per-state trap analysis would be redundant noise there.
	if len(terminal) == 0 {
		r.addWarn("gate8", "states", "machine declares no terminal state")
		return
	}
	rev := map[string][]string{}
	for from, tos := range live {
		for _, to := range tos {
			rev[to] = append(rev[to], from)
		}
	}
	canReachTerminal := map[string]bool{}
	var queue []string
	for t := range terminal {
		if states[t] {
			canReachTerminal[t] = true
			queue = append(queue, t)
		}
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, p := range rev[cur] {
			if !canReachTerminal[p] {
				canReachTerminal[p] = true
				queue = append(queue, p)
			}
		}
	}
	var trapped []string
	for _, s := range m.States {
		if reachable[s.Name] && !terminal[s.Name] && !canReachTerminal[s.Name] {
			trapped = append(trapped, s.Name)
		}
	}
	sort.Strings(trapped)
	for _, s := range trapped {
		r.addWarn("gate8", "states", "state %q cannot reach any terminal state", s)
	}
}
