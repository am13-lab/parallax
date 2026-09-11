package main

import (
	"regexp"
	"strings"
)

// validation.go — Layer 1a. Extracts gossip validation rules from the two
// structured forms the spec uses:
//
//	(a) Python validate_* functions: "# [REJECT] <desc>" (+ "# (...)" continuation)
//	    near a "raise GossipReject/GossipIgnore(...)". Rules are paired by raise:
//	    the controlling condition is the conjunction of the enclosing `if` guards,
//	    and the description comes from the nearest preceding annotation comment.
//	(b) Markdown bullets: "- _[REJECT]_ <desc>" / "- [IGNORE] <desc>", where a
//	    bullet may span continuation lines. source_expr is set only when the bullet
//	    is a clean code expression (a lone `expr` or an "i.e. `expr`" tail).
//
// These run before prose parsing so structured rules never fall through to the
// residual worklist.

var (
	pyAnnotRe   = regexp.MustCompile(`^#\s*\[(REJECT|IGNORE)\]\s*(.*)$`)
	pyIfStartRe = regexp.MustCompile(`^(?:if|elif)\b`)
	pyIfLeadRe  = regexp.MustCompile(`^(?:if|elif)\b\s*`)
	pyRaiseRe   = regexp.MustCompile(`^raise\s+Gossip(Reject|Ignore)\s*\(`)
	bulletRe    = regexp.MustCompile(`^\s*-\s*_?\[(REJECT|IGNORE)\]_?\s*(.*)$`)
	condLeadRe  = regexp.MustCompile(`^\s*-\s*(If|When|Otherwise|otherwise)\b(.*)$`)
	fnDefTopic  = regexp.MustCompile(`^def\s+validate_([a-z0-9_]+)_gossip\b`)
	provAddedRe = regexp.MustCompile(`(?i)validations?\s+are\s+(added|removed|set in place)`)
	// ieRe matches an "i.e." / "-- i.e." restatement introducing a formal expression.
	ieRe = regexp.MustCompile(`(?i)\bi\.e\.?\b`)
	// cleanBoolRe recognizes a comparison/relational operator, marking an
	// expression as a complete boolean (safe to negate into a failure predicate).
	cleanBoolRe = regexp.MustCompile(`(==|!=|<=|>=|<|>| in | not in )`)
	// predCallRe recognizes a bare predicate call like name(args) with nothing
	// trailing — also treated as a complete boolean.
	predCallRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.]*\([^)]*\)$`)
)

// extractValidation walks a parsed doc and returns validation rules. It tracks
// the current topic (from headings and validate_* function names) and a
// provenance mode from preceding paragraphs ("removed" -> ForkRemoved).
func extractValidation(doc *Doc) []Rule {
	var out []Rule
	mode := "" // "", "added", "removed", "set in place"

	for _, blk := range doc.Blocks {
		switch blk.Kind {
		case BlockParagraph:
			if m := provAddedRe.FindStringSubmatch(blk.paragraphText()); m != nil {
				mode = strings.ToLower(m[1])
			}
		case BlockCode:
			if blk.CodeLang == "python" || blk.CodeLang == "py" || blk.CodeLang == "" {
				out = append(out, parsePythonValidation(doc, blk)...)
			}
		case BlockList:
			out = append(out, parseBulletValidation(doc, blk, mode)...)
		case BlockHeading:
			mode = "" // a new heading resets the added/removed context
		}
	}
	return out
}

// ifFrame is an open `if` branch: its indentation and condition text.
type ifFrame struct {
	indent int
	cond   string
}

// annot is a pending validation annotation awaiting its raise.
type annot struct {
	outcome string
	desc    string
	line    int
}

// parsePythonValidation pairs each "raise GossipReject/Ignore" with the nearest
// preceding annotation and the conjunction of its enclosing `if` conditions.
func parsePythonValidation(doc *Doc, blk Block) []Rule {
	var out []Rule
	topic := topicFromSection(blk.SectionPath)
	var stack []ifFrame
	var pending *annot

	lines := blk.CodeLines
	for i := 0; i < len(lines); i++ {
		raw := lines[i].Text
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		indent := indentOf(raw)

		// Comments: capture annotations and their continuation context.
		if strings.HasPrefix(trimmed, "#") {
			if m := pyAnnotRe.FindStringSubmatch(trimmed); m != nil {
				pending = &annot{outcome: m[1], desc: strings.TrimSpace(m[2]), line: lines[i].Num}
			} else if pending != nil {
				extra := strings.Trim(strings.TrimSpace(strings.TrimLeft(trimmed, "#")), "()")
				if extra != "" {
					pending.desc = strings.TrimSpace(pending.desc + " (" + extra + ")")
				}
			}
			continue
		}

		if fm := fnDefTopic.FindStringSubmatch(trimmed); fm != nil {
			topic = fm[1]
			continue
		}

		// Dedent: close branches we've exited. A same-indent `elif` also lands
		// here — its sibling `if` frame is at the same indent and gets popped,
		// so `elif` then opens a fresh frame like a plain `if`.
		for len(stack) > 0 && stack[len(stack)-1].indent >= indent {
			stack = stack[:len(stack)-1]
		}

		if pyIfStartRe.MatchString(trimmed) {
			cond, next := gatherCondition(lines, i)
			stack = append(stack, ifFrame{indent: indent, cond: cond})
			i = next
			continue
		}

		if rm := pyRaiseRe.FindStringSubmatch(trimmed); rm != nil {
			outcome := strings.ToUpper(rm[1]) // REJECT | IGNORE
			desc, line := "", lines[i].Num
			if pending != nil {
				desc = pending.desc
				if pending.outcome != "" {
					outcome = pending.outcome // annotation is authoritative for desc/outcome
				}
				line = pending.line
			}
			cond := conjoinConds(stack)
			polarity := ""
			if cond != "" {
				polarity = "failure" // a python `if` guard is the FAILURE condition
			}
			out = append(out, newValidationRule(doc, blk, topic, outcome, desc, cond, polarity, line, "codeblock", ""))
			pending = nil
		}
	}
	return out
}

// gatherCondition reads a possibly-multiline `if`/`elif` header starting at
// lines[i], accumulating continuation lines until the statement's trailing ":".
// It returns the condition text (keyword and trailing colon stripped, whitespace
// collapsed) and the index of the last line consumed.
func gatherCondition(lines []Line, i int) (string, int) {
	acc := strings.TrimSpace(lines[i].Text)
	for !strings.HasSuffix(strings.TrimSpace(acc), ":") && i+1 < len(lines) {
		i++
		acc += " " + strings.TrimSpace(lines[i].Text)
	}
	cond := pyIfLeadRe.ReplaceAllString(strings.TrimSpace(acc), "")
	cond = strings.TrimSuffix(strings.TrimSpace(cond), ":")
	return strings.Join(strings.Fields(cond), " "), i
}

// conjoinConds joins the currently-open `if` conditions with " and ": a raise
// fires only when every enclosing branch condition holds.
func conjoinConds(stack []ifFrame) string {
	if len(stack) == 0 {
		return ""
	}
	parts := make([]string, len(stack))
	for i, f := range stack {
		parts[i] = f.cond
	}
	return strings.Join(parts, " and ")
}

// parseBulletValidation groups multiline bullets, then extracts [REJECT]/[IGNORE]
// rules. Continuation lines are joined before the description/condition are read.
func parseBulletValidation(doc *Doc, blk Block, mode string) []Rule {
	var out []Rule
	topic := topicFromSection(blk.SectionPath)
	condContext := "" // most recent "- If ...:" / "- otherwise:" antecedent

	for _, item := range groupBulletItems(blk.Lines) {
		if cm := condLeadRe.FindStringSubmatch(item.first); cm != nil {
			condContext = strings.TrimRight(strings.TrimSpace(cm[1]+" "+cm[2]), ":")
			continue
		}
		m := bulletRe.FindStringSubmatch(item.text)
		if m == nil {
			continue
		}
		outcome := m[1]
		body := strings.TrimSpace(m[2])
		desc := stripTrailingPeriod(body)
		cond := bulletSourceExpr(body)
		polarity := ""
		if cond != "" {
			polarity = "validity" // a gossip bullet states the condition that must HOLD
		}
		ctx := ""
		if isIndented(item.first) {
			ctx = condContext
		}
		r := newValidationRule(doc, blk, topic, outcome, desc, cond, polarity, item.line, "bullet", ctx)
		if mode == "removed" {
			r.ForkRemoved = doc.Fork
		}
		out = append(out, r)
	}
	return out
}

// bulletItem is one list item: its first (marker) line, the joined full text,
// and the source line number.
type bulletItem struct {
	first string
	text  string
	line  int
}

// groupBulletItems folds continuation lines into their preceding list item so a
// bullet's condition/description that spills onto the next line is not truncated.
func groupBulletItems(lines []Line) []bulletItem {
	var items []bulletItem
	cur := -1
	for _, l := range lines {
		if isListItem(l.Text) {
			items = append(items, bulletItem{first: l.Text, text: strings.TrimSpace(l.Text), line: l.Num})
			cur = len(items) - 1
		} else if cur >= 0 && strings.TrimSpace(l.Text) != "" {
			items[cur].text += " " + strings.TrimSpace(l.Text)
		}
	}
	return items
}

// bulletSourceExpr returns the verbatim validity expression a bullet states, or
// "" when the bullet is prose with only incidental inline code. It accepts two
// shapes: (a) the whole body is a single backticked expression, or (b) an
// "i.e. `expr`" restatement whose tail is a single backticked expression (with an
// optional "returns True"/"holds"/"is True" suffix). Anything else — a bullet
// with prose around several inline-code spans (e.g. "validate that `bid.slot` is
// greater than …") — yields "" rather than a misleading fragment.
func bulletSourceExpr(body string) string {
	if loc := ieRe.FindStringIndex(body); loc != nil {
		if e := loneBacktickExpr(body[loc[1]:]); e != "" {
			return e
		}
		return ""
	}
	return loneBacktickExpr(body)
}

// loneBacktickExpr returns the single backticked expression that constitutes the
// entire segment, or "" if the segment is more than one backticked expression
// plus at most a bare affirmation ("returns True"/"holds"/...). Everything the
// affirmation-set does not cover — prose joining multiple inline-code spans, e.g.
// "validate that `bid.slot` is greater than …" — yields "".
func loneBacktickExpr(seg string) string {
	seg = strings.TrimSpace(seg)
	i := strings.IndexByte(seg, '`')
	if i < 0 {
		return ""
	}
	j := strings.IndexByte(seg[i+1:], '`')
	if j < 0 {
		return ""
	}
	bt := strings.TrimSpace(seg[i+1 : i+1+j])
	// Whatever surrounds the first backticked span must be empty or a bare
	// affirmation for the span to stand as the whole expression.
	tail := seg[:i] + seg[i+1+j+1:]
	tail = strings.Trim(strings.ToLower(strings.ReplaceAll(tail, "`", "")), ". \t")
	switch strings.TrimSpace(tail) {
	case "", "returns true", "is true", "holds", "is set", "evaluates to true", "must hold":
		return bt
	}
	return ""
}

// newValidationRule assembles a Rule from an extracted validation annotation.
// line is the annotation/bullet line (provenance points at the rule text).
// polarity records whether cond is the FAILURE condition (python) or the
// VALIDITY condition (bullet).
func newValidationRule(doc *Doc, blk Block, topic, outcome, desc, cond, polarity string, line int, extractor, condContext string) Rule {
	bindsTo := ""
	if topic != "" {
		bindsTo = "topic:" + topic
	}
	surface := topic
	if surface == "" {
		surface = "GOSSIP"
	}
	rawText := "[" + outcome + "] " + desc
	r := Rule{
		ID: mintID(surface, outcome, rawText),
		Source: Source{
			Fork: doc.Fork, File: doc.File, Line: line, Anchor: anchor(blk.SectionPath),
		},
		RawText:        rawText,
		Subject:        Subject{Actor: "receiver", Explicit: false},
		Modal:          "MUST",
		Predicate:      Predicate{Action: strings.ToLower(outcome), Object: desc},
		BindsTo:        bindsTo,
		Outcome:        outcome,
		SourceExpr:     cond,
		ExprPolarity:   polarity,
		Extractor:      extractor,
		Confidence:     "high",
		ForkIntroduced: doc.Fork,
	}
	if cond != "" {
		r.Condition = &Condition{Antecedent: cond}
	} else if condContext != "" {
		r.Condition = &Condition{Antecedent: condContext}
	}
	return r
}

func indentOf(raw string) int {
	n := 0
	for _, c := range raw {
		if c == ' ' {
			n++
		} else if c == '\t' {
			n += 4
		} else {
			break
		}
	}
	return n
}

func stripTrailingPeriod(s string) string {
	return strings.TrimRight(strings.TrimSpace(s), ".")
}
