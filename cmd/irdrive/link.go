package main

import (
	"regexp"
	"sort"
	"strings"
)

// link.go — Layer D0.5. Resolves each AST rule to a (domain, surface). Today the
// AST has 0 protocol-bound rules (topic-bound + unbound only), so without this
// pass ReqResp/ConnLifecycle would be empty. The resolver is pure and table-
// driven: anchor keywords -> domain, then a method/topic-name match -> surface.

var methodSegRe = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9]*)\s+v(\d+)$`)

// linkStats reports resolution outcomes so the gossip-only fallback is explicit.
type linkStats struct {
	byDomain map[string]int
	gaps     int
}

// resolveAll binds every rule to a domain/surface. Rules that resolve to nothing
// are returned with domain domNone (the caller records them as gaps).
func resolveAll(doc *astDoc, si *surfaceIndex) ([]resolved, linkStats) {
	// Deterministic order: by rule id.
	rules := make([]*astRule, len(doc.Rules))
	for i := range doc.Rules {
		rules[i] = &doc.Rules[i]
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })

	stats := linkStats{byDomain: map[string]int{}}
	out := make([]resolved, 0, len(rules))
	for _, r := range rules {
		res := resolveRule(r, si)
		out = append(out, res)
		if res.domain == domNone {
			stats.gaps++
		} else {
			stats.byDomain[res.domain]++
		}
	}
	return out, stats
}

func resolveRule(r *astRule, si *surfaceIndex) resolved {
	if bound, ok := classifyBound(r); ok {
		return bound
	}

	anchorLC := strings.ToLower(r.Source.Anchor)
	domain := domainFromAnchor(anchorLC)

	// Try to pin a specific Req/Resp method from the anchor segments, then
	// raw_text. A method match can override the domain (Status -> conn).
	if name, pid := methodMatch(r, si); name != "" {
		d := domainOfMethod(name)
		if domain == domNone || domain == domReqResp || domain == domConn {
			return resolved{rule: r, domain: d, protocolID: pid, methodName: name}
		}
	}

	// Gossip: pin a topic from the anchor/raw_text if present.
	if domain == domGossip {
		if topic := topicMatch(r, si); topic != "" {
			return resolved{rule: r, domain: domGossip, topic: topic}
		}
		return resolved{rule: r, domain: domGossip} // machine-level gossip rule
	}

	if domain != domNone {
		return resolved{rule: r, domain: domain} // machine-level rule for its domain
	}
	return resolved{rule: r, domain: domNone}
}

// domainFromAnchor picks a domain from anchor keywords (most specific first).
func domainFromAnchor(anchorLC string) string {
	switch {
	case strings.Contains(anchorLC, "discovery") || strings.Contains(anchorLC, "discv5"):
		return domDiscovery
	case strings.Contains(anchorLC, "req/resp") || strings.Contains(anchorLC, "req-resp"):
		return domReqResp
	case strings.Contains(anchorLC, "gossip"):
		return domGossip
	}
	return domNone
}

// methodMatch looks for a "<Name> v<N>" segment in the anchor, or a bare surface
// Name in the anchor/raw_text, returning the method name and normalized protocol id.
func methodMatch(r *astRule, si *surfaceIndex) (string, string) {
	for _, seg := range strings.Split(r.Source.Anchor, " > ") {
		seg = strings.TrimSpace(seg)
		if m := methodSegRe.FindStringSubmatch(seg); m != nil {
			if s, ok := lookupSurface(si, m[1], m[2]); ok {
				return s.Name, s.ProtocolIDNorm
			}
		}
	}
	// Bare-name match against known protocol surfaces (longest name first so
	// "BeaconBlocksByRange" wins over "Status").
	names := make([]astSurface, len(si.protocols))
	copy(names, si.protocols)
	sort.Slice(names, func(i, j int) bool { return len(names[i].Name) > len(names[j].Name) })
	hay := r.Source.Anchor + " " + r.RawText
	for _, s := range names {
		if containsWord(hay, s.Name) {
			return s.Name, s.ProtocolIDNorm
		}
	}
	return "", ""
}

func lookupSurface(si *surfaceIndex, name, ver string) (astSurface, bool) {
	for _, s := range si.protocols {
		if strings.EqualFold(s.Name, name) && s.Version == ver {
			return s, true
		}
	}
	s, ok := si.byName[strings.ToLower(name)]
	return s, ok
}

// topicMatch finds a known gossip topic name in the anchor/raw_text.
func topicMatch(r *astRule, si *surfaceIndex) string {
	hay := r.Source.Anchor + " " + r.RawText
	// Longest topic first to prefer specific names.
	topics := make([]string, 0, len(si.topics))
	for t := range si.topics {
		topics = append(topics, t)
	}
	sort.Slice(topics, func(i, j int) bool { return len(topics[i]) > len(topics[j]) })
	for _, t := range topics {
		if containsWord(hay, t) {
			return t
		}
	}
	return ""
}

// containsWord reports whether needle appears in haystack on token boundaries
// (case-insensitive), avoiding accidental substring hits.
func containsWord(haystack, needle string) bool {
	if needle == "" {
		return false
	}
	re := regexp.MustCompile(`(?i)(^|[^A-Za-z0-9_])` + regexp.QuoteMeta(needle) + `([^A-Za-z0-9_]|$)`)
	return re.MatchString(haystack)
}
