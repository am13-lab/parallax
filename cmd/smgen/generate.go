package main

import (
	"fmt"
	"strconv"
	"strings"
)

// generate.go — shared helpers for the case renderer (render_cases.go).
// The engine-style machine compiler that previously lived here was removed;
// parallax renders SM-IR into self-contained runner.Spec cases instead.

// splitForkGuard separates fork atoms (fork_gte / fork_in) from the rest of a
// guard. Fork atoms AND-combine, so they may appear standalone or anywhere
// within and-nesting; gate2 rejects them under or/not. Returns the combined
// fork constraint (gte, in) and the residual non-fork guard (nil if none), which
// the caller compiles into the runtime Condition.
func splitForkGuard(g *Guard) (gte string, in []string, residual *Guard, err error) {
	if g == nil {
		return "", nil, nil, nil
	}
	if g.isForkAtom() {
		return g.ForkGte, g.ForkIn, nil, nil
	}
	if g.And != nil {
		var residuals []Guard
		for i := range g.And {
			cg, ci, cr, cerr := splitForkGuard(&g.And[i])
			if cerr != nil {
				return "", nil, nil, cerr
			}
			if cg != "" {
				if gte != "" {
					return "", nil, nil, fmt.Errorf("multiple fork_gte atoms in one guard")
				}
				gte = cg
			}
			if len(ci) > 0 {
				if len(in) > 0 {
					return "", nil, nil, fmt.Errorf("multiple fork_in atoms in one guard")
				}
				in = ci
			}
			if cr != nil {
				residuals = append(residuals, *cr)
			}
		}
		switch len(residuals) {
		case 0:
			residual = nil
		case 1:
			residual = &residuals[0]
		default:
			residual = &Guard{And: residuals}
		}
		return gte, in, residual, nil
	}
	// Non-fork, non-and node (flag/count/or/not/...): entirely residual.
	return "", nil, g, nil
}

func goStringSlice(ss []string) string {
	quoted := make([]string, len(ss))
	for i, s := range ss {
		quoted[i] = strconv.Quote(s)
	}
	return "[]string{" + strings.Join(quoted, ", ") + "}"
}

func hexToGoBytes(hexStr string) (string, error) {
	hexStr = strings.TrimSpace(hexStr)
	if len(hexStr)%2 != 0 {
		return "", fmt.Errorf("literal bytes hex must have even length, got %d", len(hexStr))
	}
	var parts []string
	for i := 0; i < len(hexStr); i += 2 {
		v, err := strconv.ParseUint(hexStr[i:i+2], 16, 8)
		if err != nil {
			return "", fmt.Errorf("invalid hex in literal bytes: %w", err)
		}
		parts = append(parts, fmt.Sprintf("0x%02x", v))
	}
	return "[]byte{" + strings.Join(parts, ", ") + "}", nil
}

func sanitizeIdent(name string) string {
	var b strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}
