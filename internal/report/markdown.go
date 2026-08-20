package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/ggeorgeazevedo/threatdiff/internal/analyze"
	"github.com/ggeorgeazevedo/threatdiff/internal/rules"
)

// CommentMarker lets CI find and update its previous comment instead of adding
// a new one on every push. A bot that appends is a bot that gets muted.
const CommentMarker = "<!-- threatdiff:report -->"

// Markdown writes the pull request comment.
//
// The shape of this document is the whole point of the tool. It is not a list
// of alerts; it is a review checklist, grouped the way a threat model is
// grouped, where each item is a question with the code already quoted next to
// it. A reviewer who works through it top to bottom has done a threat model of
// the change without having been asked to do one.
func Markdown(w io.Writer, r *Report) error {
	res := r.Result

	fmt.Fprintln(w, CommentMarker)
	fmt.Fprintf(w, "## threatdiff — risk **%.0f / 100** · `%s`\n\n",
		r.Score.Total, strings.ToUpper(string(r.Score.Band)))

	fmt.Fprintf(w, "%s across %s · `+%d / -%d` lines in %s · %d rules evaluated\n\n",
		bold(pluralize(len(res.Findings), "finding", "findings")),
		pluralize(countFiles(res), "file", "files"),
		res.Stats.Additions, res.Stats.Deletions,
		pluralize(res.Stats.FilesChanged, "changed file", "changed files"),
		res.Stats.RulesEvaluated,
	)

	if len(res.Findings) == 0 {
		fmt.Fprintln(w, "No security-relevant changes matched the active rules.")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "> That is a statement about the rules, not a guarantee about the code. "+
			"Rules only see patterns somebody thought to write down.")
		writeSuppressed(w, r)
		writeFooter(w, r)
		return nil
	}

	writeSummaryTable(w, r)
	writeChecklist(w, r)
	writeReviewers(w, r)
	writeSuppressed(w, r)
	writeFooter(w, r)
	return nil
}

func writeSummaryTable(w io.Writer, r *Report) {
	if len(r.Score.Categories) == 0 {
		return
	}
	fmt.Fprintln(w, "| Threat category | Weight | Findings | Worst |")
	fmt.Fprintln(w, "| --- | ---: | ---: | --- |")
	max := r.Score.Categories[0].Score
	for _, c := range r.Score.Categories {
		fmt.Fprintf(w, "| %s | `%s` %.1f | %d | %s |\n",
			c.Category.Title(), bar(c.Score, max, 10), c.Score, c.Count, severityBadge(c.Worst))
	}
	fmt.Fprintf(w, "\n<sub>Score = %.1f from findings (saturating) + %.1f from blast radius. "+
		"Raw signal total before saturation: %.1f.</sub>\n\n",
		r.Score.Signals, r.Score.BlastRadius, r.Score.Raw)
}

func writeChecklist(w io.Writer, r *Report) {
	fmt.Fprintln(w, "### Review checklist")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Each item is a question, not a verdict. Answer it in the thread, or tick it "+
		"and move on. Grouped by the STRIDE category the change touches.")
	fmt.Fprintln(w)

	mention := r.Router != nil && r.Router.Mention()

	for _, g := range byCategory(r) {
		open := ""
		if g.Findings[0].Severity.Rank() >= rules.High.Rank() {
			open = " open"
		}
		fmt.Fprintf(w, "<details%s>\n<summary><b>%s</b> — %s</summary>\n\n",
			open, g.Category.Title(), pluralize(len(g.Findings), "finding", "findings"))

		for _, f := range g.Findings {
			writeFinding(w, f, mention)
		}
		fmt.Fprintln(w, "</details>")
		fmt.Fprintln(w)
	}
}

func writeFinding(w io.Writer, f *analyze.Finding, mention bool) {
	loc := f.File
	if f.Line > 0 {
		loc = fmt.Sprintf("%s:%d", f.File, f.Line)
	}

	fmt.Fprintf(w, "- [ ] **%s** — `%s`  %s\n", escape(f.Title), loc, severityBadge(f.Severity))
	fmt.Fprintln(w)

	if f.Snippet != "" {
		marker := "+ "
		if f.Trigger == rules.OnRemoved {
			marker = "- "
		} else if f.Trigger == rules.OnFile {
			marker = "  "
		}
		fmt.Fprintf(w, "  ```diff\n  %s%s\n  ```\n\n", marker, oneLine(f.Snippet))
	}

	fmt.Fprintf(w, "  **Ask:** %s\n\n", firstLine(f.Question))

	if f.Guidance != "" {
		fmt.Fprintln(w, "  <details><summary>How to answer it</summary>")
		fmt.Fprintln(w)
		for _, line := range strings.Split(f.Guidance, "\n") {
			fmt.Fprintf(w, "  %s\n", line)
		}
		fmt.Fprintln(w)
		fmt.Fprintln(w, "  </details>")
		fmt.Fprintln(w)
	}

	var tags []string
	tags = append(tags, "rule `"+f.RuleID+"`")
	tags = append(tags, string(f.Confidence)+" confidence")
	if n := occurrenceNote(f); n != "" {
		tags = append(tags, n)
	}
	if f.Trigger == rules.OnRemoved && f.OldLine > 0 {
		tags = append(tags, fmt.Sprintf("removed from old line %d", f.OldLine))
	}
	if f.Section != "" {
		tags = append(tags, "in `"+escape(f.Section)+"`")
	}
	tags = append(tags, f.CWE...)
	tags = append(tags, f.OWASP...)
	if mention && len(f.Reviewers) > 0 {
		tags = append(tags, strings.Join(f.Reviewers, " "))
	}
	fmt.Fprintf(w, "  <sub>%s</sub>\n\n", strings.Join(tags, " · "))
}

func writeReviewers(w io.Writer, r *Report) {
	if r.Router == nil {
		return
	}
	names, index := r.Router.Apply(r.Result)
	if len(names) == 0 {
		return
	}
	fmt.Fprintln(w, "### Suggested reviewers")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "| Reviewer | Findings | Why |")
	fmt.Fprintln(w, "| --- | ---: | --- |")
	for _, n := range names {
		cats := map[rules.Category]bool{}
		for _, f := range index[n] {
			cats[f.Category] = true
		}
		var why []string
		for c := range cats {
			why = append(why, c.Title())
		}
		fmt.Fprintf(w, "| %s | %d | %s |\n", n, len(index[n]), strings.Join(why, ", "))
	}
	fmt.Fprintln(w)
}

func writeSuppressed(w io.Writer, r *Report) {
	sup := r.Result.Suppressed
	if len(sup) == 0 {
		return
	}
	noReason := 0
	for _, f := range sup {
		if strings.TrimSpace(f.Reason) == "" {
			noReason++
		}
	}
	fmt.Fprintf(w, "<details>\n<summary>Suppressed: %d (not counted in the score)</summary>\n\n",
		len(sup))
	fmt.Fprintln(w, "| Finding | Location | Suppressed by | Reason |")
	fmt.Fprintln(w, "| --- | --- | --- | --- |")
	for _, f := range sup {
		reason := strings.TrimSpace(f.Reason)
		if reason == "" {
			reason = "_no reason given_"
		}
		fmt.Fprintf(w, "| `%s` | `%s` | %s | %s |\n",
			f.RuleID, f.Location(), f.SuppressBy, escape(reason))
	}
	fmt.Fprintln(w)
	if noReason > 0 {
		fmt.Fprintf(w, "> %s suppressed without a stated reason. "+
			"A suppression with no reason is indistinguishable from a mistake six months from now.\n\n",
			pluralize(noReason, "finding is", "findings are"))
	}
	fmt.Fprintln(w, "</details>")
	fmt.Fprintln(w)
}

func writeFooter(w io.Writer, r *Report) {
	if r.Verdict.Failed {
		fmt.Fprintf(w, "> **Gate failed:** %s\n\n", r.Verdict.Reason)
	}
	fmt.Fprintf(w, "<sub>Suppress a finding in place with `// %s[rule.id] why it is fine` "+
		"on the line or the line above. Generated by threatdiff %s.</sub>\n",
		analyze.Marker, r.Meta.Version)
}

func severityBadge(s rules.Severity) string {
	if s == "" {
		return ""
	}
	return "`" + strings.ToUpper(string(s)) + "`"
}

func bold(s string) string { return "**" + s + "**" }

// escape neutralises the characters that would break a Markdown table cell or
// start an unintended construct. Findings quote code the author controls, and a
// PR comment is a place where injected Markdown can mislead a reviewer.
func escape(s string) string {
	r := strings.NewReplacer(
		"|", "\\|",
		"<", "&lt;",
		">", "&gt;",
		"\n", " ",
		"\r", " ",
	)
	return r.Replace(s)
}

// oneLine flattens a snippet and neutralises fence-breaking sequences so a
// crafted line cannot escape the code block it is quoted in.
func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "```", "` ` `")
	return s
}
