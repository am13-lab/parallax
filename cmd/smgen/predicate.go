package main

import (
	"fmt"
	"strconv"
)

// SpecPredicateVars is the set of observable variables a spec_predicate may
// reference. They are derived per step from the client's StepResult by the
// caller (see statemachine.EvaluateSequenceOracles). Booleans are 0/1.
var SpecPredicateVars = map[string]bool{
	"result_code":     true, // raw response status byte (req/resp: 0=ok,1=invalid,2=err,3=unavailable)
	"response_bytes":  true, // length of the response body
	"stream_reset":    true, // 1 if the peer reset the stream
	"burst_completed": true, // requests completed in a burst (0 = not a burst)
	"accepted":        true, // 1 if the verdict is SUCCESS/ACCEPT
	"rejected":        true, // 1 if the verdict is a rejection
	"crashed":         true, // 1 if the peer crashed/became unreachable
	"timed_out":       true, // 1 if the step timed out
}

// EvalPredicate evaluates a boolean spec predicate against an environment of
// integer-valued observables. Grammar:
//
//	expr   := or
//	or     := and ('||' and)*
//	and    := unary ('&&' unary)*
//	unary  := '!' unary | atom
//	atom   := '(' expr ')' | comparison
//	cmp    := operand cmpop operand | operand 'in' '{' intlist '}'
//	operand:= int | ident
//	cmpop  := == | != | < | <= | > | >=
func EvalPredicate(expr string, env map[string]int64) (bool, error) {
	resolve := func(name string) (int64, error) {
		v, ok := env[name]
		if !ok {
			return 0, fmt.Errorf("unknown variable %q", name)
		}
		return v, nil
	}
	return parsePredicate(expr, resolve)
}

// ValidatePredicate parses expr and checks it references only known variables,
// without needing values. Used by the IR validator so malformed predicates are
// rejected at build time rather than silently skipped at run time.
func validatePredicate(expr string, known map[string]bool) error {
	resolve := func(name string) (int64, error) {
		if !known[name] {
			return 0, fmt.Errorf("unknown variable %q", name)
		}
		return 0, nil
	}
	_, err := parsePredicate(expr, resolve)
	return err
}

func parsePredicate(expr string, resolve func(string) (int64, error)) (bool, error) {
	toks, err := lexPredicate(expr)
	if err != nil {
		return false, err
	}
	p := &predParser{toks: toks, resolve: resolve}
	v, err := p.parseOr()
	if err != nil {
		return false, err
	}
	if p.pos != len(p.toks) {
		return false, fmt.Errorf("unexpected trailing token %q", p.toks[p.pos].text)
	}
	return v, nil
}

type predToken struct {
	kind string // int, ident, op, and, or, not, lparen, rparen, lbrace, rbrace, comma, in
	text string
}

func lexPredicate(s string) ([]predToken, error) {
	var toks []predToken
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n':
			i++
		case c == '(':
			toks = append(toks, predToken{"lparen", "("})
			i++
		case c == ')':
			toks = append(toks, predToken{"rparen", ")"})
			i++
		case c == '{':
			toks = append(toks, predToken{"lbrace", "{"})
			i++
		case c == '}':
			toks = append(toks, predToken{"rbrace", "}"})
			i++
		case c == ',':
			toks = append(toks, predToken{"comma", ","})
			i++
		case c == '&':
			if i+1 < len(s) && s[i+1] == '&' {
				toks = append(toks, predToken{"and", "&&"})
				i += 2
			} else {
				return nil, fmt.Errorf("unexpected '&' at %d", i)
			}
		case c == '|':
			if i+1 < len(s) && s[i+1] == '|' {
				toks = append(toks, predToken{"or", "||"})
				i += 2
			} else {
				return nil, fmt.Errorf("unexpected '|' at %d", i)
			}
		case c == '!':
			if i+1 < len(s) && s[i+1] == '=' {
				toks = append(toks, predToken{"op", "!="})
				i += 2
			} else {
				toks = append(toks, predToken{"not", "!"})
				i++
			}
		case c == '=':
			if i+1 < len(s) && s[i+1] == '=' {
				toks = append(toks, predToken{"op", "=="})
				i += 2
			} else {
				return nil, fmt.Errorf("unexpected '=' at %d (use '==')", i)
			}
		case c == '<' || c == '>':
			if i+1 < len(s) && s[i+1] == '=' {
				toks = append(toks, predToken{"op", string(c) + "="})
				i += 2
			} else {
				toks = append(toks, predToken{"op", string(c)})
				i++
			}
		case c >= '0' && c <= '9':
			j := i
			for j < len(s) && s[j] >= '0' && s[j] <= '9' {
				j++
			}
			toks = append(toks, predToken{"int", s[i:j]})
			i = j
		case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_':
			j := i
			for j < len(s) && ((s[j] >= 'a' && s[j] <= 'z') || (s[j] >= 'A' && s[j] <= 'Z') || (s[j] >= '0' && s[j] <= '9') || s[j] == '_') {
				j++
			}
			word := s[i:j]
			if word == "in" {
				toks = append(toks, predToken{"in", word})
			} else {
				toks = append(toks, predToken{"ident", word})
			}
			i = j
		default:
			return nil, fmt.Errorf("unexpected character %q at %d", string(c), i)
		}
	}
	return toks, nil
}

type predParser struct {
	toks    []predToken
	pos     int
	resolve func(string) (int64, error)
}

func (p *predParser) peek() *predToken {
	if p.pos < len(p.toks) {
		return &p.toks[p.pos]
	}
	return nil
}

func (p *predParser) parseOr() (bool, error) {
	v, err := p.parseAnd()
	if err != nil {
		return false, err
	}
	for t := p.peek(); t != nil && t.kind == "or"; t = p.peek() {
		p.pos++
		r, err := p.parseAnd()
		if err != nil {
			return false, err
		}
		v = v || r
	}
	return v, nil
}

func (p *predParser) parseAnd() (bool, error) {
	v, err := p.parseUnary()
	if err != nil {
		return false, err
	}
	for t := p.peek(); t != nil && t.kind == "and"; t = p.peek() {
		p.pos++
		r, err := p.parseUnary()
		if err != nil {
			return false, err
		}
		v = v && r
	}
	return v, nil
}

func (p *predParser) parseUnary() (bool, error) {
	if t := p.peek(); t != nil && t.kind == "not" {
		p.pos++
		v, err := p.parseUnary()
		if err != nil {
			return false, err
		}
		return !v, nil
	}
	return p.parseAtom()
}

func (p *predParser) parseAtom() (bool, error) {
	t := p.peek()
	if t == nil {
		return false, fmt.Errorf("unexpected end of predicate")
	}
	if t.kind == "lparen" {
		p.pos++
		v, err := p.parseOr()
		if err != nil {
			return false, err
		}
		if c := p.peek(); c == nil || c.kind != "rparen" {
			return false, fmt.Errorf("expected ')'")
		}
		p.pos++
		return v, nil
	}
	return p.parseComparison()
}

func (p *predParser) parseComparison() (bool, error) {
	left, err := p.parseOperand()
	if err != nil {
		return false, err
	}
	t := p.peek()
	if t == nil {
		return false, fmt.Errorf("expected comparison operator after operand")
	}
	if t.kind == "in" {
		p.pos++
		return p.parseInSet(left)
	}
	if t.kind != "op" {
		return false, fmt.Errorf("expected comparison operator, got %q", t.text)
	}
	op := t.text
	p.pos++
	right, err := p.parseOperand()
	if err != nil {
		return false, err
	}
	return compareInts(left, op, right)
}

func (p *predParser) parseInSet(left int64) (bool, error) {
	if c := p.peek(); c == nil || c.kind != "lbrace" {
		return false, fmt.Errorf("expected '{' after 'in'")
	}
	p.pos++
	found := false
	for {
		t := p.peek()
		if t == nil {
			return false, fmt.Errorf("unterminated set literal")
		}
		if t.kind == "rbrace" {
			p.pos++
			break
		}
		if t.kind == "comma" {
			p.pos++
			continue
		}
		if t.kind != "int" {
			return false, fmt.Errorf("set literal expects integers, got %q", t.text)
		}
		n, _ := strconv.ParseInt(t.text, 10, 64)
		if n == left {
			found = true
		}
		p.pos++
	}
	return found, nil
}

func (p *predParser) parseOperand() (int64, error) {
	t := p.peek()
	if t == nil {
		return 0, fmt.Errorf("expected operand")
	}
	switch t.kind {
	case "int":
		p.pos++
		return strconv.ParseInt(t.text, 10, 64)
	case "ident":
		p.pos++
		return p.resolve(t.text)
	default:
		return 0, fmt.Errorf("expected integer or variable, got %q", t.text)
	}
}

func compareInts(l int64, op string, r int64) (bool, error) {
	switch op {
	case "==":
		return l == r, nil
	case "!=":
		return l != r, nil
	case "<":
		return l < r, nil
	case "<=":
		return l <= r, nil
	case ">":
		return l > r, nil
	case ">=":
		return l >= r, nil
	default:
		return false, fmt.Errorf("unknown operator %q", op)
	}
}
