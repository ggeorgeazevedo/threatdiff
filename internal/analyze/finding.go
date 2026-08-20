// Package analyze matches rules against a parsed diff and produces findings.
//
// A finding is not an assertion that something is broken. It is a question with
// a location attached: "this line changed, here is the threat it belongs to,
// here is what a reviewer should verify". That framing is deliberate - a PR
// gate that claims certainty it does not have gets muted within a week.
package analyze

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	"github.com/ggeorgeazevedo/threatdiff/internal/diff"
	"github.com/ggeorgeazevedo/threatdiff/internal/rules"
)

// Finding is one rule match anchored in the diff.
type Finding struct {
	RuleID     string           `json:"rule_id"`
	Title      string           `json:"title"`
	Category   rules.Category   `json:"category"`
	Severity   rules.Severity   `json:"severity"`
	Confidence rules.Confidence `json:"confidence"`
	Trigger    rules.Trigger    `json:"trigger"`

	File    string `json:"file"`
	Line    int    `json:"line"`
	OldLine int    `json:"old_line,omitempty"`
	// Section is the enclosing function or class, as reported by git in the
	// hunk header.
	Section string `json:"section,omitempty"`
	// Snippet is the changed line, redacted and truncated for display.
	Snippet string `json:"snippet,omitempty"`
	// Match is the substring that triggered the rule, redacted when needed.
	Match string `json:"match,omitempty"`

	Question string   `json:"question"`
	Guidance string   `json:"guidance,omitempty"`
	CWE      []string `json:"cwe,omitempty"`
	OWASP    []string `json:"owasp,omitempty"`
	Refs     []string `json:"references,omitempty"`
	Tags     []string `json:"tags,omitempty"`

	// Occurrences counts how many times this rule matched in this file. Repeats
	// are folded into the first hit rather than repeated: four adjacent lines
	// turning off four halves of the same S3 public-access block is one
	// decision, and reporting it four times trains people to skim.
	Occurrences int   `json:"occurrences,omitempty"`
	OtherLines  []int `json:"other_lines,omitempty"`
	// RelatedFingerprints holds the fingerprints of the folded repeats. The
	// baseline needs every one of them: if only the leader were recorded, the
	// next run would suppress the leader, promote a repeat to leader, and
	// report it as new.
	RelatedFingerprints []string `json:"related_fingerprints,omitempty"`

	// Fingerprint is stable across line moves: it hashes the rule, the path and
	// the normalised matched text, not the line number.
	Fingerprint string `json:"fingerprint"`

	// Score is the finding's contribution to the overall risk score.
	Score float64 `json:"score"`

	// Suppressed is set when an inline comment or the baseline silenced this
	// finding. Suppressed findings are reported separately, never dropped
	// silently: an invisible suppression is how a gate rots.
	Suppressed bool   `json:"suppressed,omitempty"`
	SuppressBy string `json:"suppressed_by,omitempty"`
	Reason     string `json:"suppression_reason,omitempty"`

	// Reviewers is filled in by the routing step.
	Reviewers []string `json:"reviewers,omitempty"`
}

// Location renders "path:line" for terminal output.
func (f *Finding) Location() string {
	if f.Line > 0 {
		return f.File + ":" + itoa(f.Line)
	}
	return f.File
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func fingerprint(ruleID, path, text string) string {
	h := sha256.New()
	h.Write([]byte(ruleID))
	h.Write([]byte{0})
	h.Write([]byte(path))
	h.Write([]byte{0})
	h.Write([]byte(normalize(text)))
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// normalize collapses whitespace so that reindentation does not invalidate a
// baseline entry.
func normalize(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// Stats summarises the shape of the change itself, independent of findings.
type Stats struct {
	FilesChanged   int            `json:"files_changed"`
	Additions      int            `json:"additions"`
	Deletions      int            `json:"deletions"`
	BinaryFiles    int            `json:"binary_files,omitempty"`
	Languages      map[string]int `json:"languages,omitempty"`
	RulesEvaluated int            `json:"rules_evaluated"`
	FilesSkipped   int            `json:"files_skipped,omitempty"`
}

// Result is the complete output of an analysis run.
type Result struct {
	Findings   []*Finding `json:"findings"`
	Suppressed []*Finding `json:"suppressed,omitempty"`
	Stats      Stats      `json:"stats"`
}

// CountBySeverity returns the number of live findings at each severity.
func (r *Result) CountBySeverity() map[rules.Severity]int {
	out := map[rules.Severity]int{}
	for _, f := range r.Findings {
		out[f.Severity]++
	}
	return out
}

// CountByCategory returns the number of live findings in each STRIDE category.
func (r *Result) CountByCategory() map[rules.Category]int {
	out := map[rules.Category]int{}
	for _, f := range r.Findings {
		out[f.Category]++
	}
	return out
}

// Highest returns the worst severity present, or "" when there are no findings.
func (r *Result) Highest() rules.Severity {
	var worst rules.Severity
	for _, f := range r.Findings {
		if f.Severity.Rank() > worst.Rank() {
			worst = f.Severity
		}
	}
	return worst
}

// ByFile groups findings by path, preserving severity order within each file.
func (r *Result) ByFile() ([]string, map[string][]*Finding) {
	m := map[string][]*Finding{}
	for _, f := range r.Findings {
		m[f.File] = append(m[f.File], f)
	}
	paths := make([]string, 0, len(m))
	for p := range m {
		paths = append(paths, p)
	}
	sort.Slice(paths, func(i, j int) bool {
		a, b := worstIn(m[paths[i]]), worstIn(m[paths[j]])
		if a != b {
			return a > b
		}
		return paths[i] < paths[j]
	})
	return paths, m
}

func worstIn(fs []*Finding) int {
	worst := 0
	for _, f := range fs {
		if r := f.Severity.Rank(); r > worst {
			worst = r
		}
	}
	return worst
}

// sortFindings orders findings by severity, then confidence, then location, so
// the output is deterministic and the worst thing is always first.
func sortFindings(fs []*Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if x, y := a.Severity.Rank(), b.Severity.Rank(); x != y {
			return x > y
		}
		if x, y := a.Confidence.Weight(), b.Confidence.Weight(); x != y {
			return x > y
		}
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.RuleID < b.RuleID
	})
}

// languageCounts tallies languages across the changed files.
func languageCounts(d *diff.Diff) map[string]int {
	out := map[string]int{}
	for i := range d.Files {
		out[rules.LanguageOf(d.Files[i].Path)]++
	}
	return out
}
