package main

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

func hash8(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:8]
}

var nonLabelRe = regexp.MustCompile(`[^a-z0-9]+`)

// sanitizeLabel lowercases and reduces to [a-z0-9_], for readable stable labels.
func sanitizeLabel(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = nonLabelRe.ReplaceAllString(s, "_")
	return strings.Trim(s, "_")
}

// weightForModal biases selection by spec strength.
func weightForModal(modal string) int {
	switch strengthOf(modal) {
	case "MUST":
		return 10
	case "SHOULD":
		return 5
	default:
		return 2
	}
}

// guardFromProvenance emits a fork constraint when a rule was introduced after
// phase0, so a transition only fires on clients running that fork or later.
func guardFromProvenance(r *astRule) *irGuard {
	if r.ForkIntroduced != "" && r.ForkIntroduced != "phase0" {
		return &irGuard{ForkGte: r.ForkIntroduced}
	}
	return nil
}
