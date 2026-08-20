package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/ggeorgeazevedo/threatdiff/internal/rules"
)

const rulesUsage = `threatdiff rules - inspect the active rule set

USAGE
  threatdiff rules list [--category C] [--severity S] [--json]
  threatdiff rules show <rule-id>
  threatdiff rules validate <path>
  threatdiff rules docs                 write a Markdown reference of every rule
  threatdiff rules languages            list language identifiers usable in rules
  threatdiff rules categories           list STRIDE categories
`

func cmdRules(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stdout, rulesUsage)
		return exitOK
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "list":
		return rulesList(rest)
	case "show":
		return rulesShow(rest)
	case "validate":
		return rulesValidate(rest)
	case "docs":
		return rulesDocs(rest)
	case "languages":
		for _, l := range rules.Languages() {
			fmt.Println(l)
		}
		return exitOK
	case "categories":
		for _, c := range rules.Categories() {
			fmt.Printf("%-24s %s\n", c, c.Title())
		}
		return exitOK
	case "-h", "--help", "help":
		fmt.Fprint(os.Stdout, rulesUsage)
		return exitOK
	default:
		fmt.Fprintf(os.Stderr, "threatdiff rules: unknown subcommand %q\n\n%s", sub, rulesUsage)
		return exitError
	}
}

func loadSet(extra []string) (*rules.Set, int) {
	set, err := rules.Default(extra...)
	if err != nil {
		return nil, fail("%v", err)
	}
	return set, exitOK
}

func rulesList(args []string) int {
	var extra stringList
	fs := flag.NewFlagSet("rules list", flag.ContinueOnError)
	category := fs.String("category", "", "filter by STRIDE category")
	severity := fs.String("severity", "", "filter by severity")
	asJSON := fs.Bool("json", false, "emit JSON")
	fs.Var(&extra, "rules", "additional rule pack file or directory (repeatable)")
	if err := fs.Parse(args); err != nil {
		return exitError
	}

	set, code := loadSet(extra)
	if set == nil {
		return code
	}

	var selected []*rules.Compiled
	for _, r := range set.Rules {
		if *category != "" && string(r.Category) != *category {
			continue
		}
		if *severity != "" && string(r.Severity) != *severity {
			continue
		}
		selected = append(selected, r)
	}

	if *asJSON {
		out := make([]*rules.Rule, 0, len(selected))
		for _, r := range selected {
			out = append(out, r.Rule)
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			return fail("%v", err)
		}
		return exitOK
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "SEVERITY\tCONF\tON\tCATEGORY\tID\tTITLE")
	for _, r := range selected {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			r.Severity, r.Conf(), r.On(), r.Category, r.ID, r.Title)
	}
	if err := tw.Flush(); err != nil {
		return fail("%v", err)
	}
	fmt.Printf("\n%d of %d rules shown, from %d packs: %s\n",
		len(selected), set.Len(), len(set.Origin), strings.Join(set.Origin, ", "))
	return exitOK
}

func rulesShow(args []string) int {
	var extra stringList
	fs := flag.NewFlagSet("rules show", flag.ContinueOnError)
	fs.Var(&extra, "rules", "additional rule pack file or directory (repeatable)")
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	if fs.NArg() != 1 {
		return fail("usage: threatdiff rules show <rule-id>")
	}
	set, code := loadSet(extra)
	if set == nil {
		return code
	}
	id := fs.Arg(0)
	r, ok := set.ByID(id)
	if !ok {
		suggestions := similarIDs(set, id)
		if len(suggestions) > 0 {
			return fail("no rule %q. Did you mean: %s", id, strings.Join(suggestions, ", "))
		}
		return fail("no rule %q (see `threatdiff rules list`)", id)
	}

	fmt.Printf("%s\n%s\n\n", r.ID, strings.Repeat("=", len(r.ID)))
	fmt.Printf("%s\n\n", r.Title)
	fmt.Printf("  category    %s (%s)\n", r.Category, r.Category.Title())
	fmt.Printf("  severity    %s\n", r.Severity)
	fmt.Printf("  confidence  %s\n", r.Conf())
	fmt.Printf("  triggers    on %s lines\n", r.On())
	if len(r.Languages) > 0 {
		fmt.Printf("  languages   %s\n", strings.Join(r.Languages, ", "))
	}
	if len(r.Paths) > 0 {
		fmt.Printf("  paths       %s\n", strings.Join(r.Paths, ", "))
	}
	if len(r.ExcludePaths) > 0 {
		fmt.Printf("  excludes    %s\n", strings.Join(r.ExcludePaths, ", "))
	}
	if r.Redact {
		fmt.Printf("  redaction   matched text is masked in all output\n")
	}
	fmt.Printf("\nQuestion asked of the reviewer\n  %s\n", wrapText(r.Question, 76, "  "))
	if r.Guidance != "" {
		fmt.Printf("\nGuidance\n")
		for _, line := range strings.Split(strings.TrimRight(r.Guidance, "\n"), "\n") {
			fmt.Printf("  %s\n", line)
		}
	}
	if len(r.Patterns) > 0 {
		fmt.Printf("\nPatterns\n")
		for _, p := range r.Patterns {
			fmt.Printf("  %s\n", p)
		}
	}
	if r.Near != nil {
		fmt.Printf("\nProximity constraint (window %d lines, scope %s)\n", nearWindow(r), nearScope(r))
		for _, p := range r.Near.Present {
			fmt.Printf("  require nearby: %s\n", p)
		}
		for _, p := range r.Near.Absent {
			fmt.Printf("  require absent: %s\n", p)
		}
	}
	if len(r.CWE) > 0 || len(r.OWASP) > 0 || len(r.References) > 0 {
		fmt.Printf("\nReferences\n")
		for _, v := range append(append([]string{}, r.CWE...), r.OWASP...) {
			fmt.Printf("  %s\n", v)
		}
		for _, v := range r.References {
			fmt.Printf("  %s\n", v)
		}
	}
	fmt.Printf("\nSuppress in code with\n  // threatdiff:ignore[%s] reason\n", r.ID)
	return exitOK
}

func nearWindow(r *rules.Compiled) int {
	if r.Near != nil && r.Near.Window > 0 {
		return r.Near.Window
	}
	return 5
}

func nearScope(r *rules.Compiled) string {
	if r.Near != nil && r.Near.Scope != "" {
		return r.Near.Scope
	}
	return "hunk"
}

func rulesValidate(args []string) int {
	if len(args) == 0 {
		return fail("usage: threatdiff rules validate <path>")
	}
	total := 0
	for _, p := range args {
		packs, err := rules.LoadPath(p)
		if err != nil {
			return fail("%v", err)
		}
		set, err := rules.Compile(packs...)
		if err != nil {
			return fail("%v", err)
		}
		for _, pk := range packs {
			fmt.Printf("ok  %-40s %d rules\n", pk.Name, len(pk.Rules))
		}
		total += set.Len()
	}
	// Compiling against the builtin set too catches ID collisions, which are
	// silent overrides rather than errors at runtime.
	builtin, err := rules.Default()
	if err != nil {
		return fail("%v", err)
	}
	for _, p := range args {
		packs, _ := rules.LoadPath(p)
		for _, pk := range packs {
			for _, r := range pk.Rules {
				if _, exists := builtin.ByID(r.ID); exists {
					fmt.Printf("note %-40s overrides builtin rule %s\n", pk.Name, r.ID)
				}
			}
		}
	}
	fmt.Printf("\n%d rules validated\n", total)
	return exitOK
}

func rulesDocs(args []string) int {
	var extra stringList
	fs := flag.NewFlagSet("rules docs", flag.ContinueOnError)
	out := fs.String("out", "", "write to this file instead of stdout")
	fs.Var(&extra, "rules", "additional rule pack file or directory (repeatable)")
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	set, code := loadSet(extra)
	if set == nil {
		return code
	}

	var b strings.Builder
	b.WriteString("# Rule reference\n\n")
	b.WriteString("Generated by `threatdiff rules docs`. ")
	fmt.Fprintf(&b, "%d rules across %d packs.\n\n", set.Len(), len(set.Origin))

	byCat := map[rules.Category][]*rules.Compiled{}
	for _, r := range set.Rules {
		byCat[r.Category] = append(byCat[r.Category], r)
	}
	for _, c := range rules.Categories() {
		list := byCat[c]
		if len(list) == 0 {
			continue
		}
		sort.Slice(list, func(i, j int) bool {
			if list[i].Severity.Rank() != list[j].Severity.Rank() {
				return list[i].Severity.Rank() > list[j].Severity.Rank()
			}
			return list[i].ID < list[j].ID
		})
		fmt.Fprintf(&b, "## %s\n\n", c.Title())
		b.WriteString("| Rule | Severity | Confidence | Triggers on | Question |\n")
		b.WriteString("| --- | --- | --- | --- | --- |\n")
		for _, r := range list {
			fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s |\n",
				r.ID, r.Severity, r.Conf(), r.On(),
				strings.ReplaceAll(oneLine(r.Question), "|", "\\|"))
		}
		b.WriteString("\n")
	}

	if *out == "" {
		fmt.Print(b.String())
		return exitOK
	}
	if err := os.WriteFile(*out, []byte(b.String()), 0o644); err != nil {
		return fail("%v", err)
	}
	fmt.Fprintf(os.Stderr, "threatdiff: wrote %s\n", *out)
	return exitOK
}

func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

func wrapText(s string, width int, indent string) string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return ""
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
	return strings.Join(lines, "\n"+indent)
}

func similarIDs(set *rules.Set, id string) []string {
	var out []string
	prefix := id
	if i := strings.Index(id, "."); i > 0 {
		prefix = id[:i]
	}
	for _, candidate := range set.IDs() {
		if strings.HasPrefix(candidate, prefix) || strings.Contains(candidate, id) {
			out = append(out, candidate)
		}
	}
	if len(out) > 5 {
		out = out[:5]
	}
	return out
}
