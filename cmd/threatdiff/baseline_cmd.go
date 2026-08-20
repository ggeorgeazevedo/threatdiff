package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/ggeorgeazevedo/threatdiff/internal/analyze"
)

const baselineUsage = `threatdiff baseline - accept the findings that already exist

Adopting a PR gate in an established repository fails if day one is a wall of
findings about code nobody is touching. A baseline records what is there today
so the gate only speaks up about what changes from now on.

Entries are keyed by a fingerprint of the rule, the path and the normalised
line - not the line number - so reformatting does not quietly re-open or
re-suppress anything. Every entry is dated, because a baseline is a debt
register and debts should be reviewed.

USAGE
  threatdiff baseline write [flags]

EXAMPLE
  # accept everything currently in the default branch
  threatdiff baseline write --base "$(git rev-list --max-parents=0 HEAD)" \
      --out .threatdiff-baseline.json --reason "pre-existing at adoption"
`

func cmdBaseline(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stdout, baselineUsage)
		return exitOK
	}
	if args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprint(os.Stdout, baselineUsage)
		return exitOK
	}
	if args[0] != "write" {
		fmt.Fprintf(os.Stderr, "threatdiff baseline: unknown subcommand %q\n\n%s", args[0], baselineUsage)
		return exitError
	}

	var f scanFlags
	fs := flag.NewFlagSet("baseline write", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.StringVar(&f.repo, "repo", ".", "repository directory")
	fs.StringVar(&f.base, "base", "", "base ref")
	fs.StringVar(&f.head, "head", "", "head ref")
	fs.StringVar(&f.patch, "diff", "", "read a unified diff from this file, or - for stdin")
	fs.IntVar(&f.context, "context", 5, "context lines to request from git")
	fs.StringVar(&f.configPath, "config", "", "config file")
	fs.Var(&f.rulePaths, "rules", "additional rule pack file or directory (repeatable)")
	out := fs.String("out", ".threatdiff-baseline.json", "baseline file to write")
	reason := fs.String("reason", "", "reason recorded against every new entry")

	if err := fs.Parse(args[1:]); err != nil {
		return exitError
	}

	// Deliberately ignore any configured baseline while generating one:
	// otherwise entries already accepted would be filtered out of the run and
	// silently dropped from the regenerated file.
	f.baseline = ""

	rep, err := runAnalysis(&f)
	if err != nil {
		return fail("%v", err)
	}

	added, err := analyze.WriteBaseline(*out, rep.Result, *reason)
	if err != nil {
		return fail("%v", err)
	}

	total := len(rep.Result.Findings) + len(rep.Result.Suppressed)
	fmt.Fprintf(os.Stderr, "threatdiff: %s (%d new, %d findings seen)\n", *out, added, total)
	if added > 0 && *reason == "" {
		fmt.Fprintln(os.Stderr,
			"threatdiff: no --reason given; the entries say nothing about why they are accepted")
	}
	return exitOK
}
