package main

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

// normalizeText collapses whitespace and lowercases for stable hashing and
// cross-fork dedupe. It is not shown to users; only used as a matching key.
func normalizeText(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.Join(strings.Fields(s), " ")
}

// hash8 returns the first 8 hex chars of the SHA-256 of the normalized text.
func hash8(s string) string {
	sum := sha256.Sum256([]byte(normalizeText(s)))
	return hex.EncodeToString(sum[:])[:8]
}

// mintID builds a deterministic AST node id: <SURFACE>-<TAG>-<hash8>.
// SURFACE/TAG are upper-cased and sanitized to [A-Z0-9_].
func mintID(surface, tag, text string) string {
	parts := []string{}
	for _, p := range []string{surface, tag} {
		if s := sanitizeIDPart(p); s != "" {
			parts = append(parts, s)
		}
	}
	parts = append(parts, hash8(text))
	return strings.Join(parts, "-")
}

var idPartRe = regexp.MustCompile(`[^A-Z0-9]+`)

func sanitizeIDPart(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	s = idPartRe.ReplaceAllString(s, "_")
	return strings.Trim(s, "_")
}

// firstBacktick returns the first `...`-quoted span in s, or "".
func firstBacktick(s string) string {
	i := strings.IndexByte(s, '`')
	if i < 0 {
		return ""
	}
	j := strings.IndexByte(s[i+1:], '`')
	if j < 0 {
		return ""
	}
	return s[i+1 : i+1+j]
}

// stripInlineMarkup removes markdown backticks and asterisk emphasis for a
// readable raw_text. It deliberately leaves underscores intact so identifiers
// like MAX_REQUEST_LIGHT_CLIENT_UPDATES survive.
func stripInlineMarkup(s string) string {
	repl := strings.NewReplacer("`", "", "**", "", "*", "")
	return strings.TrimSpace(repl.Replace(s))
}

// topicFromSection derives a gossip topic name from the heading stack by taking
// the innermost heading and extracting its backticked token when present
// (e.g. "Modified `beacon_block`" -> "beacon_block").
func topicFromSection(path []string) string {
	for i := len(path) - 1; i >= 0; i-- {
		h := path[i]
		if h == "" {
			continue
		}
		if bt := firstBacktick(h); bt != "" {
			return bt
		}
		// Bare topic headings (rare) — accept a single lowercase token.
		if isTopicToken(h) {
			return h
		}
	}
	return ""
}

func isTopicToken(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z') && r != '_' && !(r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}
