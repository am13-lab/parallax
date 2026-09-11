package main

import (
	"os"
	"path/filepath"
	"strings"
)

// BlockKind classifies a parsed markdown block.
type BlockKind int

const (
	BlockHeading BlockKind = iota
	BlockCode
	BlockTable
	BlockParagraph
	BlockList
)

// Line is a raw source line with its 1-based number.
type Line struct {
	Num  int
	Text string
}

// Block is one parsed markdown block, tagged with the fork/file it came from
// and the heading stack (SectionPath) in effect at its start.
type Block struct {
	Kind        BlockKind
	Fork        string
	File        string
	Line        int      // 1-based start line
	SectionPath []string // heading titles, top-most first

	// Heading
	HeadingLevel int
	HeadingText  string

	// Code
	CodeLang  string
	CodeLines []Line

	// Table
	TableHeader []string
	TableRows   [][]string

	// Paragraph / List: raw lines preserved (with numbers) so downstream
	// extractors can slice conditions and report exact provenance.
	Lines []Line
}

// Doc is a parsed p2p-interface.md file.
type Doc struct {
	Fork   string
	File   string
	Blocks []Block
}

// Anchor renders a section path as a single " > " joined string.
func anchor(path []string) string { return strings.Join(path, " > ") }

// discoverSpecFiles returns every p2p-interface.md under specsRoot, ordered by
// fork (forkOrder) and then path so nested feature files follow their fork.
// Feature forks live under specs/_features/<feature>/; forkOf maps them to the
// feature name so their protocols and rules stay in the catalog under a
// stable, named fork instead of leaking the literal "_features" segment.
func discoverSpecFiles(specsRoot string) ([]string, error) {
	var all []string
	err := filepath.WalkDir(specsRoot, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && d.Name() == "p2p-interface.md" {
			all = append(all, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	// Rank by fork position (unknown forks sort last), then lexicographically.
	rank := func(path string) int {
		f := forkOf(path)
		for i, name := range forkOrder {
			if name == f {
				return i
			}
		}
		return len(forkOrder)
	}
	// Simple stable insertion sort keyed by (forkRank, path).
	for i := 1; i < len(all); i++ {
		for j := i; j > 0; j-- {
			a, b := all[j-1], all[j]
			if rank(a) > rank(b) || (rank(a) == rank(b) && a > b) {
				all[j-1], all[j] = b, a
			} else {
				break
			}
		}
	}
	return all, nil
}

// forkOf extracts the fork name from a spec path like
// ".../specs/<fork>/p2p-interface.md" or ".../specs/<fork>/<feature>/p2p-interface.md".
// Feature forks are stored under specs/_features/<feature>/ and are named by
// their feature (e.g. "eip8025") so downstream tools see a real fork name.
func forkOf(path string) string {
	parts := strings.Split(filepath.ToSlash(path), "/")
	for i, p := range parts {
		if p == "specs" && i+1 < len(parts) {
			if parts[i+1] == "_features" && i+2 < len(parts) {
				return parts[i+2]
			}
			return parts[i+1]
		}
	}
	return ""
}

// parseDoc reads and blocks-parses a single p2p-interface.md file.
func parseDoc(path string) (*Doc, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw := strings.Split(string(data), "\n")
	lines := make([]Line, len(raw))
	for i, t := range raw {
		lines[i] = Line{Num: i + 1, Text: t}
	}

	doc := &Doc{Fork: forkOf(path), File: path}
	var section []string // current heading stack

	i := 0
	for i < len(lines) {
		ln := lines[i]
		trimmed := strings.TrimSpace(ln.Text)

		switch {
		case trimmed == "":
			i++

		case strings.HasPrefix(trimmed, "#"):
			level := headingLevel(trimmed)
			text := strings.TrimSpace(strings.TrimLeft(trimmed, "#"))
			section = pushHeading(section, level, text)
			doc.Blocks = append(doc.Blocks, Block{
				Kind: BlockHeading, Fork: doc.Fork, File: path, Line: ln.Num,
				SectionPath: clone(section), HeadingLevel: level, HeadingText: text,
			})
			i++

		case strings.HasPrefix(trimmed, "```"):
			blk, next := readCodeBlock(lines, i)
			blk.Fork, blk.File, blk.SectionPath = doc.Fork, path, clone(section)
			doc.Blocks = append(doc.Blocks, blk)
			i = next

		case isTableRow(trimmed):
			blk, next := readTable(lines, i)
			blk.Fork, blk.File, blk.SectionPath = doc.Fork, path, clone(section)
			doc.Blocks = append(doc.Blocks, blk)
			i = next

		case isListItem(ln.Text):
			blk, next := readList(lines, i)
			blk.Fork, blk.File, blk.SectionPath = doc.Fork, path, clone(section)
			doc.Blocks = append(doc.Blocks, blk)
			i = next

		default:
			blk, next := readParagraph(lines, i)
			blk.Fork, blk.File, blk.SectionPath = doc.Fork, path, clone(section)
			doc.Blocks = append(doc.Blocks, blk)
			i = next
		}
	}
	return doc, nil
}

func headingLevel(s string) int {
	n := 0
	for _, r := range s {
		if r == '#' {
			n++
		} else {
			break
		}
	}
	return n
}

// pushHeading updates the heading stack: a level-N heading replaces everything
// at depth >= N and appends itself at depth N.
func pushHeading(stack []string, level int, text string) []string {
	if level < 1 {
		level = 1
	}
	out := clone(stack)
	for len(out) >= level {
		out = out[:len(out)-1]
	}
	for len(out) < level-1 {
		out = append(out, "") // pad missing intermediate levels
	}
	return append(out, text)
}

func readCodeBlock(lines []Line, start int) (Block, int) {
	fence := strings.TrimSpace(lines[start].Text)
	lang := strings.TrimSpace(strings.TrimPrefix(fence, "```"))
	blk := Block{Kind: BlockCode, Line: lines[start].Num, CodeLang: lang}
	i := start + 1
	for i < len(lines) {
		if strings.HasPrefix(strings.TrimSpace(lines[i].Text), "```") {
			i++ // consume closing fence
			break
		}
		blk.CodeLines = append(blk.CodeLines, lines[i])
		i++
	}
	return blk, i
}

func isTableRow(trimmed string) bool {
	return strings.HasPrefix(trimmed, "|") && strings.Contains(trimmed[1:], "|")
}

// isTableSeparator matches the |---|:--:| divider row.
func isTableSeparator(trimmed string) bool {
	if !strings.HasPrefix(trimmed, "|") {
		return false
	}
	for _, r := range trimmed {
		switch r {
		case '|', '-', ':', ' ':
		default:
			return false
		}
	}
	return strings.Contains(trimmed, "-")
}

func readTable(lines []Line, start int) (Block, int) {
	blk := Block{Kind: BlockTable, Line: lines[start].Num}
	blk.TableHeader = splitTableRow(lines[start].Text)
	i := start + 1
	// optional separator row
	if i < len(lines) && isTableSeparator(strings.TrimSpace(lines[i].Text)) {
		i++
	}
	for i < len(lines) && isTableRow(strings.TrimSpace(lines[i].Text)) {
		blk.TableRows = append(blk.TableRows, splitTableRow(lines[i].Text))
		i++
	}
	return blk, i
}

func splitTableRow(s string) []string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "|")
	s = strings.TrimSuffix(s, "|")
	parts := strings.Split(s, "|")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

// isListItem reports whether a raw line begins a bullet or numbered item,
// allowing leading indentation (nested bullets).
func isListItem(raw string) bool {
	t := strings.TrimLeft(raw, " \t")
	if strings.HasPrefix(t, "- ") || strings.HasPrefix(t, "* ") {
		return true
	}
	// numbered: "1. " / "12. "
	dot := strings.IndexByte(t, '.')
	if dot > 0 {
		allDigits := true
		for _, r := range t[:dot] {
			if r < '0' || r > '9' {
				allDigits = false
				break
			}
		}
		if allDigits && dot+1 < len(t) && t[dot+1] == ' ' {
			return true
		}
	}
	return false
}

// readList consumes a contiguous list: item lines plus their indented
// continuation lines, stopping at a blank line or a heading/code/table.
func readList(lines []Line, start int) (Block, int) {
	blk := Block{Kind: BlockList, Line: lines[start].Num}
	i := start
	for i < len(lines) {
		raw := lines[i].Text
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			break
		}
		if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "```") {
			break
		}
		if isListItem(raw) || isIndented(raw) {
			blk.Lines = append(blk.Lines, lines[i])
			i++
			continue
		}
		break
	}
	return blk, i
}

func isIndented(raw string) bool {
	return len(raw) > 0 && (raw[0] == ' ' || raw[0] == '\t')
}

// readParagraph consumes consecutive non-blank prose lines until a blank line
// or the start of another block kind.
func readParagraph(lines []Line, start int) (Block, int) {
	blk := Block{Kind: BlockParagraph, Line: lines[start].Num}
	i := start
	for i < len(lines) {
		raw := lines[i].Text
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") ||
			strings.HasPrefix(trimmed, "```") || isTableRow(trimmed) || isListItem(raw) {
			break
		}
		blk.Lines = append(blk.Lines, lines[i])
		i++
	}
	if len(blk.Lines) == 0 { // safety: never stall
		blk.Lines = append(blk.Lines, lines[start])
		i = start + 1
	}
	return blk, i
}

// paragraphText joins a paragraph/list block's raw lines into one string.
func (b Block) paragraphText() string {
	parts := make([]string, len(b.Lines))
	for i, l := range b.Lines {
		parts[i] = strings.TrimSpace(l.Text)
	}
	return strings.Join(parts, " ")
}

func clone(s []string) []string {
	out := make([]string, len(s))
	copy(out, s)
	return out
}
