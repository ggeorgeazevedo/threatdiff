package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/ggeorgeazevedo/threatdiff/internal/analyze"
	"github.com/ggeorgeazevedo/threatdiff/internal/rules"
	"github.com/ggeorgeazevedo/threatdiff/internal/score"
)

// ANSI helpers. Everything routes through a palette so --no-color is a single
// switch rather than a hundred conditionals.
type palette struct{ on bool }

func (p palette) wrap(code, s string) string {
	if !p.on {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func (p palette) bold(s string) string   { return p.wrap("1", s) }
func (p palette) dim(s string) string    { return p.wrap("2", s) }
func (p palette) red(s string) string    { return p.wrap("31;1", s) }
func (p palette) yellow(s string) string { return p.wrap("33;1", s) }
func (p palette) blue(s string) string   { return p.wrap("34;1", s) }
func (p palette) green(s string) string  { return p.wrap("32;1", s) }
func (p palette) cyan(s string) string   { return p.wrap("36", s) }

func (p palette) severity(s rules.Severity) string {
	label := strings.ToUpper(string(s))
	switch s {
	case rules.Critical:
		return p.wrap("41;97;1", " "+label+" ")
	case rules.High:
		return p.red(label)
	case rules.Medium:
		return p.yellow(label)
	case rules.Low:
		return p.blue(label)
	default:
		return p.dim(label)
	}
}

func (p palette) band(b score.Band) string {
	label := strings.ToUpper(string(b))
	switch b {
	case score.BandCritical:
		return p.wrap("41;97;1", " "+label+" ")
	case score.BandHigh:
		return p.red(label)
	case score.BandMedium:
		return p.yellow(label)
	case score.BandLow:
		return p.blue(label)
	default:
		return p.green(label)
	}
}

// Pretty writes the terminal report.
func Pretty(w io.Writer, r *Report, color bool) error {
	p := palette{on: color}
	res := r.Result

	fmt.Fprintf(w, "\n%s  %s  %s\n",
		p.bold("threatdiff"),
		p.dim("risk"),
		p.bold(fmt.Sprintf("%.0f/100", r.Score.Total))+"  "+p.band(r.Score.Band),
	)

	fmt.Fprintf(w, "%s\n", p.dim(fmt.Sprintf(
		"  %s across %s   %s   %s",
		pluralize(len(res.Findings), "finding", "findings"),
		pluralize(countFiles(res), "file", "files"),
		fmt.Sprintf("+%d/-%d lines in %d changed files", res.Stats.Additions, res.Stats.Deletions, res.Stats.FilesChanged),
		fmt.Sprintf("%d rules", res.Stats.RulesEvaluated),
	)))

	if len(res.Findings) == 0 {
		fmt.Fprintf(w, "\n  %s  No security-relevant changes matched. %s\n\n",
			p.green("clean"),
			p.dim("That is a statement about the rules, not a guarantee about the code."))
		printSuppressed(w, p, r)
		return nil
	}

	// Severity summary line.
	counts := res.CountBySeverity()
	var parts []string
	for _, s := range severityOrder {
		if counts[s] > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", p.severity(s), counts[s]))
		}
	}
	fmt.Fprintf(w, "  %s\n", strings.Join(parts, p.dim("  ·  ")))

	// Category breakdown.
	if len(r.Score.Categories) > 0 {
		fmt.Fprintf(w, "\n%s\n", p.bold("  Threat categories"))
		max := r.Score.Categories[0].Score
		for _, c := range r.Score.Categories {
			fmt.Fprintf(w, "    %-24s %s %s\n",
				c.Category.Title(),
				p.cyan(bar(c.Score, max, 18)),
				p.dim(fmt.Sprintf("%5.1f  %s", c.Score, pluralize(c.Count, "finding", "findings"))),
			)
		}
	}

	// Findings, grouped by file.
	paths, grouped := res.ByFile()
	for _, path := range paths {
		fmt.Fprintf(w, "\n%s\n", p.bold("  "+path))
		for _, f := range grouped[path] {
			printFinding(w, p, f)
		}
	}

	// Reviewer routing.
	if r.Router != nil {
		names, index := r.Router.Apply(res)
		if len(names) > 0 {
			fmt.Fprintf(w, "\n%s\n", p.bold("  Suggested reviewers"))
			for _, n := range names {
				fmt.Fprintf(w, "    %-28s %s\n", p.cyan(n),
					p.dim(pluralize(len(index[n]), "finding", "findings")))
			}
		}
	}

	printSuppressed(w, p, r)

	// Verdict.
	fmt.Fprintln(w)
	if r.Verdict.Failed {
		fmt.Fprintf(w, "  %s %s\n", p.red("FAIL"), r.Verdict.Reason)
	} else {
		fmt.Fprintf(w, "  %s %s\n", p.green("PASS"), p.dim("no gate threshold reached"))
	}
	fmt.Fprintf(w, "  %s\n\n", p.dim("suppress a finding in place with:  // "+analyze.Marker+"[rule.id] why it is fine"))
	return nil
}

func printFinding(w io.Writer, p palette, f *analyze.Finding) {
	loc := fmt.Sprintf("%d", f.Line)
	if f.Line == 0 {
		loc = "-"
	}
	head := fmt.Sprintf("    %s  %s", p.severity(f.Severity), p.bold(f.Title))
	fmt.Fprintln(w, head)

	if f.Trigger == rules.OnRemoved && f.OldLine > 0 {
		loc = fmt.Sprintf("%s (removed from old line %d)", loc, f.OldLine)
	}
	meta := fmt.Sprintf("line %s · %s · %s confidence · %+.1f", loc, f.RuleID, f.Confidence, f.Score)
	if f.Occurrences > 1 {
		meta += " · " + occurrenceNote(f)
	}
	if f.Section != "" {
		meta += " · in " + f.Section
	}
	fmt.Fprintf(w, "      %s\n", p.dim(meta))

	if f.Snippet != "" {
		marker := "+"
		if f.Trigger == rules.OnRemoved {
			marker = "-"
		} else if f.Trigger == rules.OnFile {
			marker = " "
		}
		snippet := truncateLine(f.Snippet, 96)
		if marker == "-" {
			fmt.Fprintf(w, "      %s %s\n", p.red(marker), p.dim(snippet))
		} else {
			fmt.Fprintf(w, "      %s %s\n", p.green(marker), p.dim(snippet))
		}
	}

	for i, line := range wrap(firstLine(f.Question), 88, "        ") {
		if i == 0 {
			fmt.Fprintf(w, "      %s %s\n", p.yellow("?"), line)
		} else {
			fmt.Fprintln(w, line)
		}
	}
	if len(f.Reviewers) > 0 {
		fmt.Fprintf(w, "      %s %s\n", p.dim("→"), p.cyan(strings.Join(f.Reviewers, " ")))
	}
}

func printSuppressed(w io.Writer, p palette, r *Report) {
	if len(r.Result.Suppressed) == 0 {
		return
	}
	fmt.Fprintf(w, "\n%s %s\n", p.bold("  Suppressed"),
		p.dim(fmt.Sprintf("(%d, not counted in the score)", len(r.Result.Suppressed))))
	for _, f := range r.Result.Suppressed {
		reason := f.Reason
		if reason == "" {
			reason = p.yellow("no reason given")
		}
		fmt.Fprintf(w, "    %s %s  %s\n",
			p.dim(strings.ToLower(string(f.Severity))),
			f.RuleID,
			p.dim(fmt.Sprintf("%s · %s · %s", f.Location(), f.SuppressBy, reason)))
	}
}

func countFiles(res *analyze.Result) int {
	seen := map[string]bool{}
	for _, f := range res.Findings {
		seen[f.File] = true
	}
	return len(seen)
}

func truncateLine(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}
