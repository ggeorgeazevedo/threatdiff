// Package diff implements a unified-diff parser tailored for security review.
//
// Unlike a generic patch applier, this parser keeps information that matters
// when you are reasoning about *risk* rather than about content:
//
//   - both the old and the new line number for every line, so a finding can be
//     anchored precisely in the pull request;
//   - the hunk "section heading" that git emits after the @@ marker (usually the
//     enclosing function), which is what lets us say "inside handleLogin()";
//   - removed lines as first-class citizens, because a deleted authorization
//     check is a stronger signal than almost anything that was added.
package diff

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"path"
	"strconv"
	"strings"
)

// Kind classifies a single line inside a hunk.
type Kind uint8

const (
	// Context is an unchanged line included for surrounding context.
	Context Kind = iota
	// Added is a line introduced by the patch.
	Added
	// Removed is a line deleted by the patch.
	Removed
)

func (k Kind) String() string {
	switch k {
	case Added:
		return "added"
	case Removed:
		return "removed"
	default:
		return "context"
	}
}

// Status describes what happened to a file as a whole.
type Status uint8

const (
	// Modified means the file existed before and after.
	Modified Status = iota
	// Created means the file is new in this change.
	Created
	// Deleted means the file was removed by this change.
	Deleted
	// Renamed means the file moved (possibly with edits).
	Renamed
)

func (s Status) String() string {
	switch s {
	case Created:
		return "created"
	case Deleted:
		return "deleted"
	case Renamed:
		return "renamed"
	default:
		return "modified"
	}
}

// Line is a single line of a hunk.
type Line struct {
	Kind Kind
	// Text is the line content with the leading +/-/space marker stripped.
	Text string
	// OldLine is the 1-based line number in the pre-image, or 0 for added lines.
	OldLine int
	// NewLine is the 1-based line number in the post-image, or 0 for removed lines.
	NewLine int
}

// Hunk is a contiguous region of change.
type Hunk struct {
	OldStart int
	OldCount int
	NewStart int
	NewCount int
	// Section is the text git appends after the closing @@, normally the
	// enclosing function or class signature.
	Section string
	Lines   []Line
}

// File aggregates every hunk that touches one path.
type File struct {
	// Path is the post-image path, or the pre-image path for deletions.
	Path string
	// OldPath is set for renames and deletions.
	OldPath string
	Status  Status
	// Binary is true when git reported a binary patch; Hunks will be empty.
	Binary    bool
	OldMode   string
	NewMode   string
	Hunks     []Hunk
	Additions int
	Deletions int
}

// Ext returns the lowercase file extension including the dot ("" if none).
func (f *File) Ext() string { return strings.ToLower(path.Ext(f.Path)) }

// Base returns the file name without directories.
func (f *File) Base() string { return path.Base(f.Path) }

// Lines iterates every line of every hunk, in order.
func (f *File) Lines(fn func(h *Hunk, l Line) bool) {
	for i := range f.Hunks {
		h := &f.Hunks[i]
		for _, l := range h.Lines {
			if !fn(h, l) {
				return
			}
		}
	}
}

// Diff is a parsed patch.
type Diff struct {
	Files []File
}

// Totals returns the number of files, added lines and removed lines.
func (d *Diff) Totals() (files, additions, deletions int) {
	files = len(d.Files)
	for i := range d.Files {
		additions += d.Files[i].Additions
		deletions += d.Files[i].Deletions
	}
	return
}

// ErrEmpty is returned when the input contained no recognizable patch data.
var ErrEmpty = errors.New("diff: no file changes found in input")

const maxLineBytes = 1 << 20 // 1 MiB; minified bundles routinely exceed bufio's default.

// Parse reads a unified diff (typically `git diff -U3`) and returns its
// structured form. Input that contains no patch data yields ErrEmpty.
func Parse(r io.Reader) (*Diff, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), maxLineBytes)

	p := &parser{}
	for sc.Scan() {
		p.feed(sc.Text())
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("diff: reading input: %w", err)
	}
	p.flushFile()

	if len(p.out.Files) == 0 {
		return nil, ErrEmpty
	}
	return &p.out, nil
}

// ParseString is a convenience wrapper around Parse.
func ParseString(s string) (*Diff, error) { return Parse(strings.NewReader(s)) }

type parser struct {
	out Diff

	cur     *File
	hunk    *Hunk
	oldLine int
	newLine int

	// headerPath* hold what the `diff --git` line claimed, used only when the
	// ---/+++ lines are absent (pure rename or mode change).
	headerOld string
	headerNew string
}

func (p *parser) feed(line string) {
	switch {
	case strings.HasPrefix(line, "diff --git "):
		p.flushFile()
		p.startFile(line)

	case p.cur == nil:
		// Support bare unified diffs that lack a `diff --git` header.
		if strings.HasPrefix(line, "--- ") {
			p.flushFile()
			p.startBare()
			p.applyOldPath(line)
		}

	case strings.HasPrefix(line, "old mode "):
		p.cur.OldMode = strings.TrimSpace(line[len("old mode "):])
	case strings.HasPrefix(line, "new mode "):
		p.cur.NewMode = strings.TrimSpace(line[len("new mode "):])
	case strings.HasPrefix(line, "new file mode "):
		p.cur.Status = Created
		p.cur.NewMode = strings.TrimSpace(line[len("new file mode "):])
	case strings.HasPrefix(line, "deleted file mode "):
		p.cur.Status = Deleted
		p.cur.OldMode = strings.TrimSpace(line[len("deleted file mode "):])

	case strings.HasPrefix(line, "rename from "):
		p.cur.Status = Renamed
		p.cur.OldPath = unquotePath(strings.TrimSpace(line[len("rename from "):]))
	case strings.HasPrefix(line, "rename to "):
		p.cur.Status = Renamed
		p.cur.Path = unquotePath(strings.TrimSpace(line[len("rename to "):]))
	case strings.HasPrefix(line, "copy from "):
		p.cur.OldPath = unquotePath(strings.TrimSpace(line[len("copy from "):]))
	case strings.HasPrefix(line, "copy to "):
		p.cur.Path = unquotePath(strings.TrimSpace(line[len("copy to "):]))

	case strings.HasPrefix(line, "Binary files "), strings.HasPrefix(line, "GIT binary patch"):
		p.cur.Binary = true
		p.hunk = nil

	case strings.HasPrefix(line, "--- "):
		p.applyOldPath(line)
	case strings.HasPrefix(line, "+++ "):
		p.applyNewPath(line)

	case strings.HasPrefix(line, "@@"):
		p.startHunk(line)

	case p.hunk != nil:
		p.hunkLine(line)
	}
}

func (p *parser) startFile(header string) {
	p.cur = &File{Status: Modified}
	p.hunk = nil
	p.headerOld, p.headerNew = splitGitHeader(header)
	p.cur.OldPath = p.headerOld
	p.cur.Path = p.headerNew
}

func (p *parser) startBare() {
	p.cur = &File{Status: Modified}
	p.hunk = nil
	p.headerOld, p.headerNew = "", ""
}

func (p *parser) applyOldPath(line string) {
	raw := strings.TrimSpace(line[len("--- "):])
	raw = stripTimestamp(raw)
	if raw == "/dev/null" {
		p.cur.Status = Created
		return
	}
	if pth := stripPrefix(unquotePath(raw)); pth != "" {
		p.cur.OldPath = pth
	}
}

func (p *parser) applyNewPath(line string) {
	raw := strings.TrimSpace(line[len("+++ "):])
	raw = stripTimestamp(raw)
	if raw == "/dev/null" {
		p.cur.Status = Deleted
		if p.cur.Path == "" || p.cur.Path == "/dev/null" {
			p.cur.Path = p.cur.OldPath
		}
		return
	}
	if pth := stripPrefix(unquotePath(raw)); pth != "" {
		p.cur.Path = pth
	}
}

func (p *parser) startHunk(line string) {
	h, ok := parseHunkHeader(line)
	if !ok {
		return
	}
	p.cur.Hunks = append(p.cur.Hunks, h)
	p.hunk = &p.cur.Hunks[len(p.cur.Hunks)-1]
	p.oldLine = h.OldStart
	p.newLine = h.NewStart
}

func (p *parser) hunkLine(line string) {
	if line == "" {
		// git emits a bare empty line for an unchanged empty line when
		// trailing whitespace is stripped somewhere in transit.
		p.hunk.Lines = append(p.hunk.Lines, Line{
			Kind: Context, Text: "", OldLine: p.oldLine, NewLine: p.newLine,
		})
		p.oldLine++
		p.newLine++
		return
	}
	switch line[0] {
	case '+':
		p.hunk.Lines = append(p.hunk.Lines, Line{
			Kind: Added, Text: line[1:], NewLine: p.newLine,
		})
		p.newLine++
		p.cur.Additions++
	case '-':
		p.hunk.Lines = append(p.hunk.Lines, Line{
			Kind: Removed, Text: line[1:], OldLine: p.oldLine,
		})
		p.oldLine++
		p.cur.Deletions++
	case ' ':
		p.hunk.Lines = append(p.hunk.Lines, Line{
			Kind: Context, Text: line[1:], OldLine: p.oldLine, NewLine: p.newLine,
		})
		p.oldLine++
		p.newLine++
	case '\\':
		// "\ No newline at end of file" - carries no line number.
	default:
		// Anything else ends the hunk (e.g. the start of trailing commit text).
		p.hunk = nil
	}
}

func (p *parser) flushFile() {
	if p.cur == nil {
		return
	}
	f := *p.cur
	p.cur, p.hunk = nil, nil

	if f.Path == "" {
		f.Path = f.OldPath
	}
	if f.Path == "" {
		return
	}
	if f.Status == Modified && f.OldPath != "" && f.OldPath != f.Path {
		f.Status = Renamed
	}
	if f.Status != Renamed && f.OldPath == f.Path {
		f.OldPath = ""
	}
	p.out.Files = append(p.out.Files, f)
}

// parseHunkHeader understands "@@ -12,7 +12,9 @@ func handleLogin(w, r) {".
// Counts are optional and default to 1, matching the unified diff spec.
func parseHunkHeader(line string) (Hunk, bool) {
	if !strings.HasPrefix(line, "@@") {
		return Hunk{}, false
	}
	end := strings.Index(line[2:], "@@")
	if end < 0 {
		return Hunk{}, false
	}
	ranges := strings.TrimSpace(line[2 : 2+end])
	section := strings.TrimSpace(line[2+end+2:])

	fields := strings.Fields(ranges)
	if len(fields) < 2 {
		return Hunk{}, false
	}
	oldStart, oldCount, ok := parseRange(fields[0], '-')
	if !ok {
		return Hunk{}, false
	}
	newStart, newCount, ok := parseRange(fields[1], '+')
	if !ok {
		return Hunk{}, false
	}
	return Hunk{
		OldStart: oldStart, OldCount: oldCount,
		NewStart: newStart, NewCount: newCount,
		Section: section,
	}, true
}

func parseRange(s string, sign byte) (start, count int, ok bool) {
	if len(s) == 0 || s[0] != sign {
		return 0, 0, false
	}
	s = s[1:]
	count = 1
	if i := strings.IndexByte(s, ','); i >= 0 {
		c, err := strconv.Atoi(s[i+1:])
		if err != nil {
			return 0, 0, false
		}
		count = c
		s = s[:i]
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, 0, false
	}
	// A zero-length range means "before line n"; git reports start as n, and the
	// first real line is n+1 only when count == 0. Normalize to 1 minimum.
	if n == 0 {
		n = 1
	}
	return n, count, true
}

// splitGitHeader extracts the two paths from a `diff --git a/x b/y` line.
// Paths containing spaces make this ambiguous, so we take the conservative
// route: if either side is quoted we unquote it, otherwise we split on the
// midpoint that yields matching a/ and b/ prefixes.
func splitGitHeader(line string) (oldPath, newPath string) {
	rest := strings.TrimPrefix(line, "diff --git ")
	if strings.HasPrefix(rest, `"`) {
		// At least one side is quoted; scan for the closing quote.
		if end := findClosingQuote(rest); end > 0 {
			oldPath = stripPrefix(unquotePath(rest[:end+1]))
			newPath = stripPrefix(unquotePath(strings.TrimSpace(rest[end+1:])))
			return oldPath, newPath
		}
	}
	fields := strings.Fields(rest)
	if len(fields) == 2 {
		return stripPrefix(fields[0]), stripPrefix(fields[1])
	}
	// Space-containing unquoted paths: find a split point where the right half
	// starts with "b/" and both halves have equal word counts.
	for i := 1; i < len(fields); i++ {
		right := strings.Join(fields[i:], " ")
		if strings.HasPrefix(right, "b/") {
			left := strings.Join(fields[:i], " ")
			if strings.HasPrefix(left, "a/") {
				return stripPrefix(left), stripPrefix(right)
			}
		}
	}
	if len(fields) > 0 {
		return stripPrefix(fields[0]), stripPrefix(fields[len(fields)-1])
	}
	return "", ""
}

func findClosingQuote(s string) int {
	for i := 1; i < len(s); i++ {
		if s[i] == '\\' {
			i++
			continue
		}
		if s[i] == '"' {
			return i
		}
	}
	return -1
}

// stripPrefix removes git's a/ and b/ path prefixes.
func stripPrefix(p string) string {
	switch {
	case p == "/dev/null":
		return ""
	case strings.HasPrefix(p, "a/"), strings.HasPrefix(p, "b/"):
		return p[2:]
	case strings.HasPrefix(p, "i/"), strings.HasPrefix(p, "w/"),
		strings.HasPrefix(p, "c/"), strings.HasPrefix(p, "o/"):
		return p[2:]
	default:
		return p
	}
}

// stripTimestamp removes the tab-separated timestamp that plain `diff -u`
// appends to the ---/+++ lines.
func stripTimestamp(s string) string {
	if i := strings.IndexByte(s, '\t'); i >= 0 {
		return s[:i]
	}
	return s
}

// unquotePath reverses git's C-style quoting of paths with unusual bytes.
func unquotePath(p string) string {
	if len(p) < 2 || p[0] != '"' || p[len(p)-1] != '"' {
		return p
	}
	if out, err := strconv.Unquote(p); err == nil {
		return out
	}
	// strconv.Unquote rejects git's octal escapes for raw bytes; fall back to a
	// manual pass that preserves them as-is.
	var b strings.Builder
	body := p[1 : len(p)-1]
	for i := 0; i < len(body); i++ {
		if body[i] != '\\' || i+1 >= len(body) {
			b.WriteByte(body[i])
			continue
		}
		i++
		switch body[i] {
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		case 'r':
			b.WriteByte('\r')
		case '\\', '"':
			b.WriteByte(body[i])
		default:
			if i+2 < len(body) && isOctal(body[i]) && isOctal(body[i+1]) && isOctal(body[i+2]) {
				if v, err := strconv.ParseUint(body[i:i+3], 8, 8); err == nil {
					b.WriteByte(byte(v))
					i += 2
					continue
				}
			}
			b.WriteByte(body[i])
		}
	}
	return b.String()
}

func isOctal(c byte) bool { return c >= '0' && c <= '7' }
