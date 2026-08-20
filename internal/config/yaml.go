// Package config loads threatdiff configuration and rule packs.
//
// Rule packs are YAML, because that is what security engineers expect to write.
// threatdiff has no third-party dependencies, so this file implements the
// subset of YAML that a declarative rule file actually needs:
//
//	block mappings, block sequences, flow mappings/sequences,
//	plain / single-quoted / double-quoted scalars, literal (|) and
//	folded (>) block scalars, comments, and the --- document marker.
//
// Everything else - anchors, aliases, tags, multi-document streams, complex
// keys, multi-line plain scalars - is rejected with a line-numbered error
// instead of being silently misparsed. For a security tool, "I do not
// understand this rule file" is a much better outcome than "I guessed".
package config

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// UnmarshalYAML parses YAML into out, which must be a pointer. Unknown fields
// are rejected so a typo in a rule file fails loudly instead of disabling a
// check by accident.
func UnmarshalYAML(data []byte, out any) error {
	tree, err := parseYAML(string(data))
	if err != nil {
		return err
	}
	return bind(tree, out)
}

// UnmarshalJSON parses JSON into out with the same strictness as
// UnmarshalYAML, so .json and .yaml rule packs behave identically.
func UnmarshalJSON(data []byte, out any) error {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("invalid json: %w", err)
	}
	return nil
}

// bind round-trips the generic tree through encoding/json so struct tags,
// type conversion and unknown-field detection are handled by the stdlib.
func bind(tree any, out any) error {
	raw, err := json.Marshal(tree)
	if err != nil {
		return fmt.Errorf("internal: re-encoding parsed yaml: %w", err)
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// line scanning
// ---------------------------------------------------------------------------

type yline struct {
	num    int    // 1-based line number, for error messages
	indent int    // count of leading spaces
	text   string // content with indentation and trailing comment removed
	blank  bool
}

func scanLines(src string) ([]yline, error) {
	raw := strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n")
	out := make([]yline, 0, len(raw))
	for i, r := range raw {
		num := i + 1
		if strings.ContainsRune(r, '\t') && strings.TrimSpace(r) != "" {
			if lead := r[:len(r)-len(strings.TrimLeft(r, " \t"))]; strings.ContainsRune(lead, '\t') {
				return nil, fmt.Errorf("line %d: tab used for indentation; YAML requires spaces", num)
			}
		}
		indent := len(r) - len(strings.TrimLeft(r, " "))
		body := r[indent:]
		out = append(out, yline{num: num, indent: indent, text: body, blank: strings.TrimSpace(body) == ""})
	}
	return out, nil
}

// stripComment removes a trailing `#` comment, honouring quoting.
func stripComment(s string) string {
	var inSingle, inDouble bool
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inDouble && c == '\\':
			i++
		case c == '\'' && !inDouble:
			inSingle = !inSingle
		case c == '"' && !inSingle:
			inDouble = !inDouble
		case c == '#' && !inSingle && !inDouble:
			if i == 0 || s[i-1] == ' ' || s[i-1] == '\t' {
				return strings.TrimRight(s[:i], " \t")
			}
		}
	}
	return strings.TrimRight(s, " \t")
}

// ---------------------------------------------------------------------------
// parser
// ---------------------------------------------------------------------------

type yparser struct {
	lines []yline
	i     int
}

func parseYAML(src string) (any, error) {
	lines, err := scanLines(src)
	if err != nil {
		return nil, err
	}
	p := &yparser{lines: lines}

	p.skipIgnorable()
	// Optional document start marker.
	if p.cur() != nil && strings.TrimSpace(p.cur().text) == "---" {
		p.i++
		p.skipIgnorable()
	}
	if p.cur() == nil {
		return map[string]any{}, nil
	}
	node, err := p.parseBlock(p.cur().indent)
	if err != nil {
		return nil, err
	}
	p.skipIgnorable()
	if l := p.cur(); l != nil {
		if strings.TrimSpace(l.text) == "---" || strings.TrimSpace(l.text) == "..." {
			return nil, fmt.Errorf("line %d: multi-document YAML streams are not supported", l.num)
		}
		return nil, fmt.Errorf("line %d: unexpected content %q (check indentation)", l.num, strings.TrimSpace(l.text))
	}
	return node, nil
}

func (p *yparser) cur() *yline {
	if p.i >= len(p.lines) {
		return nil
	}
	return &p.lines[p.i]
}

// skipIgnorable advances past blank lines and whole-line comments.
func (p *yparser) skipIgnorable() {
	for p.i < len(p.lines) {
		l := p.lines[p.i]
		if l.blank || strings.HasPrefix(strings.TrimSpace(l.text), "#") {
			p.i++
			continue
		}
		return
	}
}

// parseBlock dispatches to a sequence or mapping parser based on the first
// significant line at the given indentation.
func (p *yparser) parseBlock(indent int) (any, error) {
	p.skipIgnorable()
	l := p.cur()
	if l == nil {
		return nil, nil
	}
	if isSeqEntry(l.text) {
		return p.parseSeq(indent)
	}
	return p.parseMap(indent)
}

func isSeqEntry(text string) bool {
	t := stripComment(text)
	return t == "-" || strings.HasPrefix(t, "- ")
}

func (p *yparser) parseSeq(indent int) (any, error) {
	out := []any{}
	for {
		p.skipIgnorable()
		l := p.cur()
		if l == nil || l.indent != indent || !isSeqEntry(l.text) {
			if l != nil && l.indent > indent && len(out) > 0 {
				return nil, fmt.Errorf("line %d: unexpected indentation inside a list", l.num)
			}
			return out, nil
		}
		body := stripComment(l.text)
		afterDash := body[1:]
		gap := len(afterDash) - len(strings.TrimLeft(afterDash, " "))
		rest := strings.TrimSpace(afterDash)
		// Column at which the item's own content begins: "- " => indent+2.
		itemIndent := indent + 1 + gap

		if rest == "" {
			p.i++
			p.skipIgnorable()
			next := p.cur()
			if next == nil || next.indent <= indent {
				out = append(out, nil)
				continue
			}
			v, err := p.parseBlock(next.indent)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
			continue
		}

		if key, _, ok := splitMapEntry(rest); ok && key != "" {
			// Inline start of a mapping: rewrite the line so the mapping parser
			// sees the first entry at the item's own indentation.
			p.lines[p.i].indent = itemIndent
			p.lines[p.i].text = rest
			v, err := p.parseMap(itemIndent)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
			continue
		}

		v, err := p.scalarOrBlock(rest, indent)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
}

func (p *yparser) parseMap(indent int) (any, error) {
	out := map[string]any{}
	for {
		p.skipIgnorable()
		l := p.cur()
		if l == nil {
			return out, nil
		}
		if l.indent < indent {
			return out, nil
		}
		if l.indent > indent {
			return nil, fmt.Errorf("line %d: unexpected indentation (expected %d spaces, got %d)", l.num, indent, l.indent)
		}
		if isSeqEntry(l.text) {
			return out, nil
		}
		body := stripComment(l.text)
		if body == "---" || body == "..." {
			return out, nil
		}
		key, rest, ok := splitMapEntry(body)
		if !ok {
			return nil, fmt.Errorf("line %d: expected `key: value`, got %q", l.num, strings.TrimSpace(l.text))
		}
		if err := rejectUnsupported(l.num, rest); err != nil {
			return nil, err
		}
		if _, dup := out[key]; dup {
			return nil, fmt.Errorf("line %d: duplicate key %q", l.num, key)
		}

		if rest == "" {
			p.i++
			p.skipIgnorable()
			next := p.cur()
			switch {
			case next == nil:
				out[key] = nil
			case next.indent > indent:
				v, err := p.parseBlock(next.indent)
				if err != nil {
					return nil, err
				}
				out[key] = v
			case next.indent == indent && isSeqEntry(next.text):
				// A list may sit at the same indentation as its key.
				v, err := p.parseSeq(indent)
				if err != nil {
					return nil, err
				}
				out[key] = v
			default:
				// Sibling key or dedent: the key has an empty value.
				out[key] = nil
			}
			continue
		}

		v, err := p.scalarOrBlock(rest, indent)
		if err != nil {
			return nil, err
		}
		out[key] = v
	}
}

// scalarOrBlock resolves a value that appeared on the same line as its key or
// list marker; `|` and `>` pull in the following indented block.
func (p *yparser) scalarOrBlock(rest string, parentIndent int) (any, error) {
	if strings.HasPrefix(rest, "|") || strings.HasPrefix(rest, ">") {
		return p.readBlockScalar(rest, parentIndent)
	}
	p.i++
	return parseScalar(rest)
}

func (p *yparser) readBlockScalar(header string, parentIndent int) (any, error) {
	folded := header[0] == '>'
	mods := header[1:]
	chomp := byte(0) // 0 = clip, '-' = strip, '+' = keep
	explicitIndent := 0
	for i := 0; i < len(mods); i++ {
		switch {
		case mods[i] == '-' || mods[i] == '+':
			chomp = mods[i]
		case mods[i] >= '1' && mods[i] <= '9':
			explicitIndent = int(mods[i] - '0')
		case mods[i] == ' ':
			// trailing comment already stripped
		default:
			return nil, fmt.Errorf("line %d: unsupported block scalar header %q", p.cur().num, header)
		}
	}
	p.i++

	var body []string
	contentIndent := parentIndent + explicitIndent
	determined := explicitIndent > 0
	for p.i < len(p.lines) {
		l := p.lines[p.i]
		if l.blank {
			body = append(body, "")
			p.i++
			continue
		}
		if l.indent <= parentIndent {
			break
		}
		if !determined {
			contentIndent = l.indent
			determined = true
		}
		if l.indent < contentIndent {
			break
		}
		body = append(body, strings.Repeat(" ", l.indent-contentIndent)+l.text)
		p.i++
	}
	// Drop trailing blank lines, remembering whether any existed.
	trailing := 0
	for len(body) > 0 && body[len(body)-1] == "" {
		body = body[:len(body)-1]
		trailing++
	}

	var text string
	if folded {
		var b strings.Builder
		for i, ln := range body {
			if i > 0 {
				if ln == "" || body[i-1] == "" {
					b.WriteString("\n")
				} else {
					b.WriteString(" ")
				}
			}
			b.WriteString(ln)
		}
		text = b.String()
	} else {
		text = strings.Join(body, "\n")
	}

	switch chomp {
	case '-':
		// strip: no trailing newline
	case '+':
		text += strings.Repeat("\n", trailing+1)
	default:
		if len(body) > 0 {
			text += "\n"
		}
	}
	return text, nil
}

// rejectUnsupported catches YAML features this parser deliberately does not
// implement, so a rule file using them fails instead of misbehaving.
func rejectUnsupported(lineNum int, rest string) error {
	t := strings.TrimSpace(rest)
	if t == "" {
		return nil
	}
	switch t[0] {
	case '&':
		return fmt.Errorf("line %d: YAML anchors are not supported", lineNum)
	case '*':
		return fmt.Errorf("line %d: YAML aliases are not supported", lineNum)
	case '!':
		return fmt.Errorf("line %d: YAML tags are not supported", lineNum)
	}
	return nil
}

// splitMapEntry finds the `: ` separating a key from its value, ignoring
// colons inside quotes and flow collections.
func splitMapEntry(s string) (key, rest string, ok bool) {
	var inSingle, inDouble bool
	depth := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inDouble && c == '\\':
			i++
		case c == '\'' && !inDouble:
			inSingle = !inSingle
		case c == '"' && !inSingle:
			inDouble = !inDouble
		case inSingle || inDouble:
			// skip
		case c == '[' || c == '{':
			depth++
		case c == ']' || c == '}':
			depth--
		case c == ':' && depth == 0:
			if i+1 == len(s) || s[i+1] == ' ' {
				k := strings.TrimSpace(s[:i])
				k = unquoteScalar(k)
				return k, strings.TrimSpace(s[i+1:]), true
			}
		}
	}
	return "", "", false
}

// ---------------------------------------------------------------------------
// scalars and flow collections
// ---------------------------------------------------------------------------

func parseScalar(s string) (any, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	switch s[0] {
	case '[':
		return parseFlowSeq(s)
	case '{':
		return parseFlowMap(s)
	case '"', '\'':
		return unquoteScalar(s), nil
	}
	switch strings.ToLower(s) {
	case "null", "~":
		return nil, nil
	case "true", "yes", "on":
		return true, nil
	case "false", "no", "off":
		return false, nil
	}
	if i, err := strconv.ParseInt(s, 10, 64); err == nil {
		return i, nil
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return f, nil
	}
	return s, nil
}

func unquoteScalar(s string) string {
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		return strings.ReplaceAll(s[1:len(s)-1], "''", "'")
	}
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		if out, err := strconv.Unquote(s); err == nil {
			return out
		}
		body := s[1 : len(s)-1]
		r := strings.NewReplacer(`\"`, `"`, `\\`, `\`, `\n`, "\n", `\t`, "\t", `\r`, "\r", `\/`, "/")
		return r.Replace(body)
	}
	return s
}

// splitFlow splits the inside of a flow collection on top-level commas.
func splitFlow(body string) ([]string, error) {
	var parts []string
	var b strings.Builder
	var inSingle, inDouble bool
	depth := 0
	for i := 0; i < len(body); i++ {
		c := body[i]
		switch {
		case inDouble && c == '\\':
			b.WriteByte(c)
			if i+1 < len(body) {
				i++
				b.WriteByte(body[i])
			}
			continue
		case c == '\'' && !inDouble:
			inSingle = !inSingle
		case c == '"' && !inSingle:
			inDouble = !inDouble
		case inSingle || inDouble:
			// literal
		case c == '[' || c == '{':
			depth++
		case c == ']' || c == '}':
			depth--
			if depth < 0 {
				return nil, fmt.Errorf("unbalanced %q in flow collection", string(c))
			}
		case c == ',' && depth == 0:
			parts = append(parts, strings.TrimSpace(b.String()))
			b.Reset()
			continue
		}
		b.WriteByte(c)
	}
	if inSingle || inDouble {
		return nil, fmt.Errorf("unterminated quote in flow collection")
	}
	if depth != 0 {
		return nil, fmt.Errorf("unbalanced brackets in flow collection")
	}
	if strings.TrimSpace(b.String()) != "" {
		parts = append(parts, strings.TrimSpace(b.String()))
	}
	return parts, nil
}

func parseFlowSeq(s string) (any, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "[") || !strings.HasSuffix(s, "]") {
		return nil, fmt.Errorf("malformed flow sequence %q", s)
	}
	parts, err := splitFlow(s[1 : len(s)-1])
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(parts))
	for _, p := range parts {
		v, err := parseScalar(p)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func parseFlowMap(s string) (any, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "{") || !strings.HasSuffix(s, "}") {
		return nil, fmt.Errorf("malformed flow mapping %q", s)
	}
	parts, err := splitFlow(s[1 : len(s)-1])
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	for _, p := range parts {
		k, rest, ok := splitMapEntry(p)
		if !ok {
			return nil, fmt.Errorf("malformed entry %q in flow mapping", p)
		}
		v, err := parseScalar(rest)
		if err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, nil
}
