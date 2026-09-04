package main

import (
	"regexp"
	"sort"
	"strings"
)

// protocol.go — Layer 1c. Extracts Req/Resp methods and gossip topics as
// Surface nodes. Protocol IDs are preserved verbatim (ProtocolIDRaw) and also
// normalized (ProtocolIDNorm, with an ssz_snappy encoding suffix) for matching.
// A level-5 heading is treated as a method either when it is "Name vN" or when a
// Protocol ID line follows it (covers light-client methods like
// GetLightClientBootstrap that carry no version in the heading).

var (
	methodVersionRe = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9]*)\s+v(\d+)$`)
	methodBareRe    = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9]*)$`)
	protocolIDRe    = regexp.MustCompile("`(/eth2/[^`]+)`")
	protocolIDLabel = regexp.MustCompile(`(?i)protocol id`)
	reqLabelRe      = regexp.MustCompile(`(?i)request .*content|request content`)
	respLabelRe     = regexp.MustCompile(`(?i)response .*content|response content`)
	// combinedLabelRe matches "Request, Response Content", "Request/Response
	// Content", "Request and Response Content" — one schema block for both sides.
	combinedLabelRe = regexp.MustCompile(`(?i)request\s*[,/&]?\s*(?:and\s+)?response\s+content`)
	// unchangedRe marks a method whose schema is inherited from a prior version.
	unchangedRe = regexp.MustCompile(`(?i)(?:remain|remains)\s+unchanged|unchanged from`)
)

// extractSurfaces returns protocol and topic surfaces defined in the doc.
func extractSurfaces(doc *Doc) []Surface {
	var out []Surface
	blocks := doc.Blocks
	for i, blk := range blocks {
		if blk.Kind != BlockHeading {
			continue
		}
		switch {
		case blk.HeadingLevel == 5:
			s, ok := parseMethodHeading(doc, blocks, i)
			if ok {
				out = append(out, s)
			}
		case blk.HeadingLevel == 6:
			name := firstBacktick(blk.HeadingText)
			if name == "" || !isTopicToken(name) {
				continue
			}
			s := Surface{
				Kind:           "topic",
				Name:           name,
				IntroducedFork: doc.Fork,
				Source:         Source{Fork: doc.Fork, File: doc.File, Line: blk.Line, Anchor: anchor(blk.SectionPath)},
			}
			s.ID = surfaceID("TOPIC", name, name)
			out = append(out, s)
		}
	}
	return out
}

// parseMethodHeading builds a protocol Surface from a level-5 heading. Bare-name
// headings are accepted only when a Protocol ID follows (so non-method level-5
// headings are not misclassified).
func parseMethodHeading(doc *Doc, blocks []Block, i int) (Surface, bool) {
	blk := blocks[i]
	name, version := "", ""
	if m := methodVersionRe.FindStringSubmatch(blk.HeadingText); m != nil {
		name, version = m[1], m[2]
	} else if m := methodBareRe.FindStringSubmatch(blk.HeadingText); m != nil {
		name = m[1]
	} else {
		return Surface{}, false
	}

	raw := findProtocolID(blocks, i+1)
	if version == "" && raw == "" {
		return Surface{}, false // bare name with no protocol id -> not a method
	}
	if version == "" {
		version = versionFromProtocolID(raw)
	}

	s := Surface{
		Kind:           "protocol",
		Name:           name,
		Version:        version,
		ProtocolIDRaw:  raw,
		ProtocolIDNorm: normalizeProtocolID(raw),
		IntroducedFork: doc.Fork,
		Source:         Source{Fork: doc.Fork, File: doc.File, Line: blk.Line, Anchor: anchor(blk.SectionPath)},
	}
	if enc := encodingOf(s.ProtocolIDNorm); enc != "" {
		s.Encoding = enc
	}
	s.RequestSchema, s.ResponseSchema, s.Inherit = findSchemas(blocks, i+1)
	s.ID = surfaceID("PROTO", s.Name+"_v"+s.Version, s.ProtocolIDNorm)
	return s, true
}

// findProtocolID scans forward from a method heading for the "Protocol ID:" line
// and returns the first `/eth2/...` id.
func findProtocolID(blocks []Block, start int) string {
	for i := start; i < len(blocks) && i < start+8; i++ {
		b := blocks[i]
		if b.Kind == BlockHeading {
			break
		}
		if b.Kind != BlockParagraph && b.Kind != BlockList {
			continue
		}
		text := b.paragraphText()
		if !protocolIDLabel.MatchString(text) && !strings.Contains(text, "/eth2/") {
			continue
		}
		if m := protocolIDRe.FindStringSubmatch(text); m != nil {
			return m[1]
		}
	}
	return ""
}

// findSchemas captures the request/response SSZ schema code blocks that follow a
// method heading, keyed by the content label that precedes each code block. It
// handles the separate "Request Content:" / "Response Content:" labels, the
// combined "Request, Response Content:" (one block for both), and reports an
// inherit flag when the method says its schema is "unchanged" from a prior
// version. Best-effort: returns "" for a schema that is not found.
func findSchemas(blocks []Block, start int) (req, resp string, inherit bool) {
	pending := ""
	for i := start; i < len(blocks); i++ {
		b := blocks[i]
		if b.Kind == BlockHeading {
			break
		}
		if b.Kind == BlockParagraph {
			t := b.paragraphText()
			switch {
			case unchangedRe.MatchString(t):
				inherit = true
			case combinedLabelRe.MatchString(t):
				pending = "both"
			case reqLabelRe.MatchString(t):
				pending = "req"
			case respLabelRe.MatchString(t):
				pending = "resp"
			}
			continue
		}
		if b.Kind == BlockCode && pending != "" {
			schema := codeText(b)
			switch pending {
			case "both":
				if req == "" {
					req = schema
				}
				if resp == "" {
					resp = schema
				}
			case "req":
				if req == "" {
					req = schema
				}
			case "resp":
				if resp == "" {
					resp = schema
				}
			}
			pending = ""
		}
	}
	return req, resp, inherit
}

// inheritSchemas fills empty schemas on surfaces marked Inherit from the nearest
// lower version of the same method Name. Runs as a global post-pass so it works
// across forks (e.g. Altair v2 inheriting from Phase0 v1).
func inheritSchemas(surfaces []Surface) {
	byName := map[string][]int{}
	for i := range surfaces {
		if surfaces[i].Kind == "protocol" {
			byName[surfaces[i].Name] = append(byName[surfaces[i].Name], i)
		}
	}
	for _, idxs := range byName {
		sort.Slice(idxs, func(a, b int) bool {
			return verNum(surfaces[idxs[a]].Version) < verNum(surfaces[idxs[b]].Version)
		})
		for pos, idx := range idxs {
			if !surfaces[idx].Inherit {
				continue
			}
			if surfaces[idx].RequestSchema == "" {
				surfaces[idx].RequestSchema = nearestSchema(surfaces, idxs, pos, true)
			}
			if surfaces[idx].ResponseSchema == "" {
				surfaces[idx].ResponseSchema = nearestSchema(surfaces, idxs, pos, false)
			}
		}
	}
}

// nearestSchema returns the request (or response) schema of the nearest lower
// version in idxs before pos, or "".
func nearestSchema(surfaces []Surface, idxs []int, pos int, request bool) string {
	for p := pos - 1; p >= 0; p-- {
		s := surfaces[idxs[p]]
		if request && s.RequestSchema != "" {
			return s.RequestSchema
		}
		if !request && s.ResponseSchema != "" {
			return s.ResponseSchema
		}
	}
	return ""
}

func verNum(v string) int {
	n := 0
	for _, r := range v {
		if r < '0' || r > '9' {
			return n
		}
		n = n*10 + int(r-'0')
	}
	return n
}

func codeText(b Block) string {
	parts := make([]string, len(b.CodeLines))
	for i, l := range b.CodeLines {
		parts[i] = l.Text
	}
	return strings.TrimSpace(strings.Join(parts, "\n"))
}

// normalizeProtocolID trims a trailing slash and appends the ssz_snappy encoding
// when the spec omitted it, so ids match protocol_model.json / spec.go form.
func normalizeProtocolID(raw string) string {
	if raw == "" {
		return ""
	}
	s := strings.TrimSuffix(strings.TrimSpace(raw), "/")
	parts := strings.Split(s, "/")
	last := parts[len(parts)-1]
	if last != "ssz_snappy" && last != "ssz" {
		s += "/ssz_snappy"
	}
	return s
}

func encodingOf(norm string) string {
	parts := strings.Split(norm, "/")
	if len(parts) == 0 {
		return ""
	}
	last := parts[len(parts)-1]
	if last == "ssz_snappy" || last == "ssz" {
		return last
	}
	return ""
}

// versionFromProtocolID extracts the version segment from a protocol id path
// like /eth2/beacon_chain/req/<name>/<version>/<encoding>.
func versionFromProtocolID(raw string) string {
	parts := strings.Split(strings.Trim(raw, "/"), "/")
	for i := len(parts) - 1; i >= 0; i-- {
		p := parts[i]
		if p == "" || p == "ssz_snappy" || p == "ssz" {
			continue
		}
		if isAllDigits(p) {
			return p
		}
	}
	return ""
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func surfaceID(prefix, name, key string) string {
	return mintID(prefix, name, key)
}
