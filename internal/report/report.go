// Package report renders an analysis in the four shapes a pull request
// workflow actually needs: a terminal view for the author, a Markdown comment
// for the reviewer, SARIF for the code-scanning UI, and JSON for whatever the
// platform team builds next.
package report

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/ggeorgeazevedo/threatdiff/internal/analyze"
	"github.com/ggeorgeazevedo/threatdiff/internal/owners"
	"github.com/ggeorgeazevedo/threatdiff/internal/rules"
	"github.com/ggeorgeazevedo/threatdiff/internal/score"
)

// Meta describes the run itself.
type Meta struct {
	Tool        string `json:"tool"`
	Version     string `json:"version"`
	GeneratedAt string `json:"generated_at"`
	Repository  string `json:"repository,omitempty"`
	Base        string `json:"base,omitempty"`
	Head        string `json:"head,omitempty"`
	ConfigFile  string `json:"config_file,omitempty"`
	RulePacks   int    `json:"rule_packs,omitempty"`
}

// NewMeta builds run metadata with the timestamp filled in.
func NewMeta(version string) Meta {
	return Meta{
		Tool:        "threatdiff",
		Version:     version,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}
}

// Report bundles everything a renderer needs.
type Report struct {
	Meta    Meta            `json:"meta"`
	Result  *analyze.Result `json:"result"`
	Score   score.Result    `json:"score"`
	Verdict score.Verdict   `json:"-"`
	Router  *owners.Router  `json:"-"`
}

// Format identifies an output renderer.
type Format string

// Supported formats.
const (
	FormatPretty   Format = "pretty"
	FormatMarkdown Format = "markdown"
	FormatSARIF    Format = "sarif"
	FormatJSON     Format = "json"
)

// Formats lists every supported output format.
func Formats() []string {
	return []string{string(FormatPretty), string(FormatMarkdown), string(FormatSARIF), string(FormatJSON)}
}

// Render dispatches to the requested renderer.
func Render(w io.Writer, f Format, r *Report, color bool) error {
	switch f {
	case FormatPretty, "":
		return Pretty(w, r, color)
	case FormatMarkdown, "md":
		return Markdown(w, r)
	case FormatSARIF:
		return SARIF(w, r)
	case FormatJSON:
		return JSON(w, r)
	default:
		return fmt.Errorf("unknown format %q (want one of %s)", f, strings.Join(Formats(), ", "))
	}
}

// ---------------------------------------------------------------------------
// shared helpers
// ---------------------------------------------------------------------------

// byCategory groups live findings into STRIDE buckets, ordered by category
// score so the most important threat is discussed first.
func byCategory(r *Report) []categoryGroup {
	m := map[rules.Category][]*analyze.Finding{}
	for _, f := range r.Result.Findings {
		m[f.Category] = append(m[f.Category], f)
	}
	order := map[rules.Category]float64{}
	for _, c := range r.Score.Categories {
		order[c.Category] = c.Score
	}
	out := make([]categoryGroup, 0, len(m))
	for c, fs := range m {
		out = append(out, categoryGroup{Category: c, Findings: fs, Score: order[c]})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].Category < out[j].Category
	})
	return out
}

type categoryGroup struct {
	Category rules.Category
	Findings []*analyze.Finding
	Score    float64
}

// severityOrder is the display order for severity summaries.
var severityOrder = []rules.Severity{
	rules.Critical, rules.High, rules.Medium, rules.Low, rules.Info,
}

func pluralize(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

// bar renders a proportional bar for terminal and Markdown summaries.
func bar(value, max float64, width int) string {
	if max <= 0 {
		return strings.Repeat("·", width)
	}
	filled := int((value/max)*float64(width) + 0.5)
	if filled > width {
		filled = width
	}
	if filled < 0 {
		filled = 0
	}
	return strings.Repeat("█", filled) + strings.Repeat("·", width-filled)
}

// occurrenceNote summarises repeats of the same rule inside one file.
func occurrenceNote(f *analyze.Finding) string {
	if f.Occurrences <= 1 {
		return ""
	}
	note := fmt.Sprintf("%d occurrences", f.Occurrences)
	if len(f.OtherLines) > 0 {
		parts := make([]string, 0, len(f.OtherLines))
		for _, l := range f.OtherLines {
			parts = append(parts, fmt.Sprintf("%d", l))
		}
		note += " (also at " + strings.Join(parts, ", ")
		if f.Occurrences-1 > len(f.OtherLines) {
			note += fmt.Sprintf(" and %d more", f.Occurrences-1-len(f.OtherLines))
		}
		note += ")"
	}
	return note
}

// firstLine collapses a multi-line question into one line for compact output.
func firstLine(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Join(strings.Fields(s), " ")
	return s
}

// wrap breaks text at word boundaries to the given width, indenting
// continuation lines.
func wrap(s string, width int, indent string) []string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return nil
	}
	var lines []string
	cur := words[0]
	for _, w := range words[1:] {
		if len(cur)+1+len(w) > width {
			lines = append(lines, cur)
			cur = w
			continue
		}
		cur += " " + w
	}
	lines = append(lines, cur)
	for i := 1; i < len(lines); i++ {
		lines[i] = indent + lines[i]
	}
	return lines
}
