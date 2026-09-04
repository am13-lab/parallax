package main

import (
	"strconv"
	"strings"
)

// constants.go — Layer 1b. Parses config/constant markdown tables into Constant
// nodes and a symbol table used to resolve constant references elsewhere.

// extractConstants returns constants defined in the doc's markdown tables.
func extractConstants(doc *Doc) []Constant {
	var out []Constant
	for _, blk := range doc.Blocks {
		if blk.Kind != BlockTable || !isConstantTable(blk.TableHeader) {
			continue
		}
		nameCol, valCol, descCol := constantColumns(blk.TableHeader)
		for _, row := range blk.TableRows {
			if nameCol >= len(row) || valCol >= len(row) {
				continue
			}
			name := firstBacktick(row[nameCol])
			if name == "" {
				name = strings.TrimSpace(row[nameCol])
			}
			if !looksLikeConstName(name) {
				continue
			}
			expr := constantExpr(row[valCol])
			val, ok := evalIntExpr(expr)
			desc := ""
			if descCol >= 0 && descCol < len(row) {
				desc = strings.TrimSpace(row[descCol])
			}
			out = append(out, Constant{
				ID:             mintID("CONST", name, name),
				Name:           name,
				Expr:           expr,
				Value:          val,
				Evaluated:      ok,
				Desc:           desc,
				IntroducedFork: doc.Fork,
				Source:         Source{Fork: doc.Fork, File: doc.File, Line: blk.Line, Anchor: anchor(blk.SectionPath)},
			})
		}
	}
	return out
}

func isConstantTable(header []string) bool {
	hasName, hasValue := false, false
	for _, h := range header {
		switch strings.ToLower(strings.TrimSpace(h)) {
		case "name":
			hasName = true
		case "value":
			hasValue = true
		}
	}
	return hasName && hasValue
}

func constantColumns(header []string) (nameCol, valCol, descCol int) {
	nameCol, valCol, descCol = 0, 1, -1
	for i, h := range header {
		switch strings.ToLower(strings.TrimSpace(h)) {
		case "name":
			nameCol = i
		case "value":
			valCol = i
		case "description", "unit":
			if descCol < 0 {
				descCol = i
			}
		}
	}
	return
}

func looksLikeConstName(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	for _, r := range s {
		if !(r >= 'A' && r <= 'Z') && r != '_' && !(r >= '0' && r <= '9') {
			return false
		}
	}
	// Require at least one letter to avoid pure-number cells.
	return strings.IndexFunc(s, func(r rune) bool { return r >= 'A' && r <= 'Z' }) >= 0
}

// constantExpr pulls the machine expression out of a value cell. The spec writes
// e.g. "`10 * 2**20` (= 10,485,760, 10 MiB)" or a bare "`32`" or "`500`".
func constantExpr(cell string) string {
	if bt := firstBacktick(cell); bt != "" {
		return strings.TrimSpace(bt)
	}
	// Fallback: take the text before a "(" annotation.
	if i := strings.IndexByte(cell, '('); i >= 0 {
		return strings.TrimSpace(cell[:i])
	}
	return strings.TrimSpace(cell)
}

// evalIntExpr evaluates a small arithmetic subset: integer literals (with commas
// or underscores), + - * and ** (power), and parentheses. Returns ok=false when
// the expression uses anything outside that grammar (e.g. references another
// constant), which the caller records as unevaluated.
func evalIntExpr(expr string) (int64, bool) {
	toks, ok := tokenizeExpr(expr)
	if !ok {
		return 0, false
	}
	p := &exprParser{toks: toks}
	v, ok := p.parseAddSub()
	if !ok || p.pos != len(p.toks) {
		return 0, false
	}
	return v, true
}

type exprParser struct {
	toks []string
	pos  int
}

func (p *exprParser) peek() string {
	if p.pos < len(p.toks) {
		return p.toks[p.pos]
	}
	return ""
}

func (p *exprParser) parseAddSub() (int64, bool) {
	v, ok := p.parseMul()
	if !ok {
		return 0, false
	}
	for p.peek() == "+" || p.peek() == "-" {
		op := p.toks[p.pos]
		p.pos++
		r, ok := p.parseMul()
		if !ok {
			return 0, false
		}
		if op == "+" {
			v += r
		} else {
			v -= r
		}
	}
	return v, true
}

func (p *exprParser) parseMul() (int64, bool) {
	v, ok := p.parsePow()
	if !ok {
		return 0, false
	}
	for p.peek() == "*" {
		p.pos++
		r, ok := p.parsePow()
		if !ok {
			return 0, false
		}
		v *= r
	}
	return v, true
}

func (p *exprParser) parsePow() (int64, bool) {
	base, ok := p.parseAtom()
	if !ok {
		return 0, false
	}
	if p.peek() == "**" {
		p.pos++
		exp, ok := p.parsePow() // right-associative
		if !ok || exp < 0 {
			return 0, false
		}
		result := int64(1)
		for i := int64(0); i < exp; i++ {
			result *= base
		}
		return result, true
	}
	return base, true
}

func (p *exprParser) parseAtom() (int64, bool) {
	t := p.peek()
	if t == "(" {
		p.pos++
		v, ok := p.parseAddSub()
		if !ok || p.peek() != ")" {
			return 0, false
		}
		p.pos++
		return v, true
	}
	if t == "-" {
		p.pos++
		v, ok := p.parseAtom()
		return -v, ok
	}
	n, err := strconv.ParseInt(t, 10, 64)
	if err != nil {
		return 0, false
	}
	p.pos++
	return n, true
}

// tokenizeExpr splits an expression into number/operator/paren tokens. Commas
// and underscores inside numbers are stripped. Any other character fails.
func tokenizeExpr(expr string) ([]string, bool) {
	var toks []string
	i := 0
	s := expr
	for i < len(s) {
		c := s[i]
		switch {
		case c == ' ' || c == '\t':
			i++
		case c == '(' || c == ')' || c == '+' || c == '-':
			toks = append(toks, string(c))
			i++
		case c == '*':
			if i+1 < len(s) && s[i+1] == '*' {
				toks = append(toks, "**")
				i += 2
			} else {
				toks = append(toks, "*")
				i++
			}
		case c >= '0' && c <= '9':
			j := i
			var num strings.Builder
			for j < len(s) && (s[j] >= '0' && s[j] <= '9' || s[j] == ',' || s[j] == '_') {
				if s[j] != ',' && s[j] != '_' {
					num.WriteByte(s[j])
				}
				j++
			}
			toks = append(toks, num.String())
			i = j
		default:
			return nil, false // letter, reference, etc. — not evaluable
		}
	}
	return toks, len(toks) > 0
}

// symbolTable maps constant name -> evaluated value for resolved constants.
func symbolTable(consts []Constant) map[string]int64 {
	m := map[string]int64{}
	for _, c := range consts {
		if c.Evaluated {
			m[c.Name] = c.Value
		}
	}
	return m
}
