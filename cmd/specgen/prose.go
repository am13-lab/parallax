package main

import (
	"regexp"
	"strings"
)

// prose.go — Layer 1d. Parses free-prose normative sentences into atomic
// {subject, modal, action, object} rules. Multi-modal sentences are split into
// one rule per modal. Clauses that cannot be decomposed become residuals.
//
// Prose rules are interpretation, not verbatim spec truth: they carry no
// source_expr and a medium/low confidence, so downstream never mistakes an
// inferred predicate for the spec's own words.

// modalRe matches RFC-2119 keywords, longest-first so "MUST NOT" wins over "MUST".
var modalRe = regexp.MustCompile(`\b(MUST NOT|MUST|SHOULD NOT|SHOULD|MAY NOT|MAY|REQUIRED|RECOMMENDED)\b`)

// actorLexicon maps spec role words (lowercased) to a canonical actor.
var actorLexicon = map[string]string{
	"client": "client", "clients": "client",
	"implementation": "implementation", "implementations": "implementation",
	"node": "node", "nodes": "node",
	"peer": "peer", "peers": "peer",
	"requester": "requester", "responder": "responder",
	"sender": "sender", "receiver": "receiver",
	"validator": "validator", "validators": "validator",
	"server": "responder", "dialer": "requester",
}

var wordRe = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*`)

// extractProse returns prose-derived rules and the residual worklist.
func extractProse(doc *Doc) ([]Rule, []Residual) {
	var rules []Rule
	var residuals []Residual

	for i, blk := range doc.Blocks {
		if blk.Kind != BlockParagraph && blk.Kind != BlockList {
			continue
		}
		for _, unit := range sentenceUnits(blk) {
			if !modalRe.MatchString(unit.text) {
				continue
			}
			// Skip validation bullets already captured by Layer 1a.
			if bulletRe.MatchString(unit.raw) {
				continue
			}
			r, res := parseModalSentence(doc, blk, unit)
			rules = append(rules, r...)
			residuals = append(residuals, res...)
			if blk.Kind == BlockParagraph {
				if intro, ok := parseModalListIntro(doc, blk, unit); ok && i+1 < len(doc.Blocks) && doc.Blocks[i+1].Kind == BlockList {
					rules = append(rules, parseModalListItems(doc, doc.Blocks[i+1], intro)...)
				}
			}
		}
	}
	return rules, residuals
}

// sentenceUnit is a sentence-sized chunk plus its raw source line for provenance.
type sentenceUnit struct {
	text string
	raw  string
	line int
}

// sentenceUnits breaks a block into sentence-sized units. List items are one
// unit each; paragraphs are split on sentence boundaries.
func sentenceUnits(blk Block) []sentenceUnit {
	var out []sentenceUnit
	if blk.Kind == BlockList {
		for _, item := range groupBulletItems(blk.Lines) {
			txt := stripListMarker(item.text)
			if txt != "" {
				out = append(out, sentenceUnit{text: txt, raw: item.first, line: item.line})
			}
		}
		return out
	}
	// Paragraph: attribute each sentence to the block's start line (fine-grained
	// line attribution within a joined paragraph is not reliable).
	for _, s := range splitSentences(blk.paragraphText()) {
		out = append(out, sentenceUnit{text: s, raw: s, line: blk.Line})
	}
	return out
}

var sentenceBoundaryRe = regexp.MustCompile(`\.\s+`)

// splitSentences splits on ". " while protecting common abbreviations.
func splitSentences(text string) []string {
	protected := text
	for _, abbr := range []string{"e.g.", "i.e.", "etc.", "vs.", "cf."} {
		protected = strings.ReplaceAll(protected, abbr, strings.ReplaceAll(abbr, ".", "\x00"))
	}
	parts := sentenceBoundaryRe.Split(protected, -1)
	var out []string
	for _, p := range parts {
		p = strings.ReplaceAll(p, "\x00", ".")
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// parseModalSentence decomposes one sentence into one rule per modal keyword.
func parseModalSentence(doc *Doc, blk Block, unit sentenceUnit) ([]Rule, []Residual) {
	locs := modalRe.FindAllStringSubmatchIndex(unit.text, -1)
	if len(locs) == 0 {
		return nil, nil
	}
	subjectText := strings.TrimSpace(unit.text[:locs[0][0]])
	subject := resolveSubject(subjectText, blk.SectionPath)
	topic := topicFromSection(blk.SectionPath)
	bindsTo := ""
	if topic != "" {
		bindsTo = "topic:" + topic
	}

	var rules []Rule
	var residuals []Residual
	for i, loc := range locs {
		modalRaw := unit.text[loc[2]:loc[3]]
		clauseStart := loc[3]
		clauseEnd := len(unit.text)
		if i+1 < len(locs) {
			clauseEnd = locs[i+1][0]
		}
		clause := trimConnector(strings.TrimSpace(unit.text[clauseStart:clauseEnd]))
		if isModalListIntroClause(clause) {
			continue
		}
		action, object, ok := splitActionObject(clause)
		if !ok {
			residuals = append(residuals, Residual{
				Fork: doc.Fork, File: doc.File, Line: unit.line,
				RawText: unit.text, Reason: "modal clause has no parseable action",
			})
			continue
		}
		conf := "medium"
		if !subject.Explicit {
			conf = "low"
		}
		rawText := strings.TrimSpace(stripInlineMarkup(subjectText) + " " + normalizeModal(modalRaw) + " " + stripInlineMarkup(clause))
		r := Rule{
			ID:             mintID(subjectSurface(topic), normalizeModal(modalRaw), rawText),
			Source:         Source{Fork: doc.Fork, File: doc.File, Line: unit.line, Anchor: anchor(blk.SectionPath)},
			RawText:        strings.TrimSpace(rawText),
			Subject:        subject,
			Modal:          normalizeModal(modalRaw),
			Predicate:      Predicate{Action: action, Object: object},
			BindsTo:        bindsTo,
			NormalizedExpr: normalizedPredicate(subject, action, object),
			Extractor:      "prose",
			Confidence:     conf,
			ForkIntroduced: doc.Fork,
		}
		rules = append(rules, r)
	}
	return rules, residuals
}

type modalListIntro struct {
	modal      string
	subject    Subject
	subjectRaw string
	condition  string
}

// parseModalListIntro recognizes prose of the form "Clients MUST:" followed by
// a list. The modal is propagated to each child item by parseModalListItems.
func parseModalListIntro(doc *Doc, blk Block, unit sentenceUnit) (modalListIntro, bool) {
	locs := modalRe.FindAllStringSubmatchIndex(unit.text, -1)
	if len(locs) == 0 {
		return modalListIntro{}, false
	}
	last := locs[len(locs)-1]
	if !isModalListIntroClause(unit.text[last[3]:]) {
		return modalListIntro{}, false
	}
	prefix := strings.TrimSpace(unit.text[:last[0]])
	if prefix == "" {
		return modalListIntro{}, false
	}
	subjectRaw := introSubjectText(prefix)
	subject := resolveSubject(subjectRaw, blk.SectionPath)
	if !subject.Explicit {
		// "In particular they MUST:" often refers back to "clients" in the same
		// paragraph. Resolve against the full prefix before falling back to section
		// context so the subject does not degrade to a generic receiver/client.
		subject = resolveSubject(prefix, blk.SectionPath)
	}
	return modalListIntro{
		modal:      normalizeModal(unit.text[last[2]:last[3]]),
		subject:    subject,
		subjectRaw: stripInlineMarkup(subjectRaw),
		condition:  introCondition(prefix),
	}, true
}

// parseModalListItems turns a modal-introduced list into one prose rule per
// item. The child items are imperatives; the parent supplies the modal/subject.
func parseModalListItems(doc *Doc, blk Block, intro modalListIntro) []Rule {
	var rules []Rule
	topic := topicFromSection(blk.SectionPath)
	bindsTo := ""
	if topic != "" {
		bindsTo = "topic:" + topic
	}
	for _, item := range groupBulletItems(blk.Lines) {
		text := stripListMarker(item.text)
		clause, cond := imperativeClause(text)
		action, object, ok := splitActionObject(clause)
		if !ok {
			continue
		}
		guard := combineConditions(intro.condition, cond)
		rawText := strings.TrimSpace(intro.subjectRaw + " " + intro.modal + " " + stripInlineMarkup(clause))
		r := Rule{
			ID:             mintID(subjectSurface(topic), intro.modal, rawText),
			Source:         Source{Fork: doc.Fork, File: doc.File, Line: item.line, Anchor: anchor(blk.SectionPath)},
			RawText:        rawText,
			Subject:        intro.subject,
			Modal:          intro.modal,
			Predicate:      Predicate{Action: action, Object: object},
			BindsTo:        bindsTo,
			NormalizedExpr: normalizedPredicate(intro.subject, action, object),
			Extractor:      "prose",
			Confidence:     "medium",
			ForkIntroduced: doc.Fork,
		}
		if guard != "" {
			r.Condition = &Condition{Antecedent: guard}
		}
		rules = append(rules, r)
	}
	return rules
}

func normalizeModal(m string) string {
	return strings.ReplaceAll(strings.ToUpper(strings.TrimSpace(m)), " ", "_")
}

// resolveSubject picks an actor from the subject text, falling back to section
// context. Explicit is true only when the actor was named in the sentence.
func resolveSubject(subjectText string, section []string) Subject {
	for _, w := range wordRe.FindAllString(strings.ToLower(subjectText), -1) {
		if actor, ok := actorLexicon[w]; ok {
			return Subject{Actor: actor, Qualifier: subjectQualifier(subjectText), Explicit: true}
		}
	}
	// Infer from section context.
	sec := strings.ToLower(strings.Join(section, " "))
	switch {
	case strings.Contains(sec, "req/resp") || strings.Contains(sec, "req/resp domain"):
		return Subject{Actor: "client", Explicit: false}
	case strings.Contains(sec, "gossip"):
		return Subject{Actor: "receiver", Explicit: false}
	case strings.Contains(sec, "discovery"):
		return Subject{Actor: "node", Explicit: false}
	}
	return Subject{Actor: "client", Explicit: false}
}

// subjectQualifier surfaces a leading adjective like "dialing" / "requesting".
func subjectQualifier(subjectText string) string {
	for _, q := range []string{"dialing", "requesting", "responding", "receiving", "sending"} {
		if strings.Contains(strings.ToLower(subjectText), q) {
			return q
		}
	}
	return ""
}

// splitActionObject takes the text after a modal and splits it into a leading
// verb (action) and the remainder (object). Returns ok=false when there is no
// alphabetic action word.
func splitActionObject(clause string) (action, object string, ok bool) {
	clause = strings.TrimSpace(clause)
	if clause == "" {
		return "", "", false
	}
	fields := strings.Fields(clause)
	first := strings.ToLower(strings.Trim(fields[0], "`*_,."))
	if !isActionWord(first) {
		return "", "", false
	}
	object = strings.TrimSpace(strings.TrimPrefix(clause, fields[0]))
	object = stripInlineMarkup(object)
	return first, object, true
}

func isActionWord(s string) bool {
	if s == "" {
		return false
	}
	letter := false
	lastHyphen := false
	for _, r := range s {
		if r == '-' {
			if !letter || lastHyphen {
				return false
			}
			lastHyphen = true
			continue
		}
		if !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') {
			return false
		}
		letter = true
		lastHyphen = false
	}
	return letter && !lastHyphen
}

// trimConnector drops a leading "and"/"or"/"," left over from clause splitting.
func trimConnector(s string) string {
	s = strings.TrimLeft(s, ", ")
	for _, c := range []string{"and ", "or ", "but "} {
		if strings.HasPrefix(strings.ToLower(s), c) {
			s = s[len(c):]
		}
	}
	return strings.TrimSpace(s)
}

func isModalListIntroClause(clause string) bool {
	clause = strings.TrimSpace(clause)
	return clause == "" || clause == ":"
}

func stripListMarker(text string) string {
	t := strings.TrimSpace(text)
	switch {
	case strings.HasPrefix(t, "- ") || strings.HasPrefix(t, "* "):
		return strings.TrimSpace(t[2:])
	}
	if dot := strings.IndexByte(t, '.'); dot > 0 && dot+1 < len(t) && t[dot+1] == ' ' {
		allDigits := true
		for _, r := range t[:dot] {
			if r < '0' || r > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			return strings.TrimSpace(t[dot+2:])
		}
	}
	return t
}

func introSubjectText(prefix string) string {
	prefix = strings.TrimSpace(prefix)
	for _, sep := range []string{". ", "; "} {
		if i := strings.LastIndex(prefix, sep); i >= 0 && i+len(sep) < len(prefix) {
			return strings.TrimSpace(prefix[i+len(sep):])
		}
	}
	return prefix
}

func introCondition(prefix string) string {
	if g := extractConditional(prefix); g != "" {
		return g
	}
	return ""
}

var (
	colonContextRe    = regexp.MustCompile(`^([^:]{1,80}):\s*(.+)$`)
	leadingIfClauseRe = regexp.MustCompile(`(?i)^(if|when|unless|in case)\b(.+?),\s*(.+)$`)
	leadingSubjectRe  = regexp.MustCompile(`(?i)^(it|they|the node|the client|the clients|the responder|the requester|the reader|clients|nodes)\s+(.+)$`)
	leadingAuxModalRe = regexp.MustCompile(`(?i)^(must|should|may)\s+(.+)$`)
)

func imperativeClause(text string) (clause, condition string) {
	text = stripTrailingPeriod(strings.TrimSpace(text))
	if m := colonContextRe.FindStringSubmatch(text); m != nil {
		condition = strings.TrimSpace(stripInlineMarkup(m[1]))
		text = strings.TrimSpace(m[2])
	}
	if m := leadingIfClauseRe.FindStringSubmatch(text); m != nil {
		lead := cleanConditionText(m[1] + " " + m[2])
		condition = combineConditions(condition, lead)
		text = strings.TrimSpace(m[3])
	}
	text = stripLeadingSubjectAndAux(text)
	return text, condition
}

func stripLeadingSubjectAndAux(text string) string {
	text = strings.TrimSpace(text)
	if m := leadingSubjectRe.FindStringSubmatch(text); m != nil {
		text = strings.TrimSpace(m[2])
	}
	if m := leadingAuxModalRe.FindStringSubmatch(text); m != nil {
		text = strings.TrimSpace(m[2])
	}
	return text
}

func combineConditions(a, b string) string {
	a = cleanConditionText(a)
	b = cleanConditionText(b)
	switch {
	case a == "":
		return b
	case b == "":
		return a
	default:
		return a + " and " + b
	}
}

func cleanConditionText(s string) string {
	return strings.Join(strings.Fields(stripInlineMarkup(s)), " ")
}

func normalizedPredicate(sub Subject, action, object string) string {
	obj := strings.Join(strings.Fields(object), " ")
	if len(obj) > 80 {
		obj = obj[:80]
	}
	return strings.TrimSpace(sub.Actor + "." + action + "(" + obj + ")")
}

func subjectSurface(topic string) string {
	if topic != "" {
		return topic
	}
	return "PROSE"
}
