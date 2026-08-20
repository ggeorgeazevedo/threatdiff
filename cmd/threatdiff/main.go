// Command threatdiff turns a pull request diff into a threat model: what
// changed, which threat it belongs to, and the question a reviewer should
// answer before approving.
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/ggeorgeazevedo/threatdiff/internal/version"
)

// Exit codes. These are part of the interface: CI depends on them.
const (
	exitOK       = 0 // ran, gate not triggered
	exitFindings = 1 // ran, gate triggered
	exitError    = 2 // could not run
)

const usage = `threatdiff - threat modelling for pull request diffs

USAGE
  threatdiff <command> [flags]

COMMANDS
  scan        Analyse a diff and report the threats it introduces (default)
  rules       Inspect, validate and document the active rule set
  baseline    Record current findings as accepted, to adopt threatdiff gradually
  init        Write a starter .threatdiff.yaml
  version     Print build information

Run "threatdiff <command> -h" for the flags of a command.

QUICK START
  threatdiff scan                          # working tree against the default branch
  threatdiff scan --base main --head HEAD  # an explicit range
  git diff main... | threatdiff scan --diff -
  threatdiff scan --format markdown --out review.md
  threatdiff scan --fail-on high           # exit 1 when a high finding appears

EXIT CODES
  0  analysis completed, gate not triggered
  1  analysis completed, gate triggered
  2  could not run (bad flags, unreadable rules, git failure)
`

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stdout, usage)
		return exitOK
	}

	cmd := args[0]
	rest := args[1:]

	// Allow bare flags to mean `scan`, so `threatdiff --base main` works.
	if strings.HasPrefix(cmd, "-") {
		switch cmd {
		case "-h", "--help", "-help":
			fmt.Fprint(os.Stdout, usage)
			return exitOK
		case "-v", "--version":
			fmt.Fprintln(os.Stdout, version.Full())
			return exitOK
		}
		cmd, rest = "scan", args
	}

	switch cmd {
	case "scan":
		return cmdScan(rest)
	case "rules":
		return cmdRules(rest)
	case "baseline":
		return cmdBaseline(rest)
	case "init":
		return cmdInit(rest)
	case "version":
		fmt.Fprintln(os.Stdout, version.Full())
		return exitOK
	case "help":
		fmt.Fprint(os.Stdout, usage)
		return exitOK
	default:
		fmt.Fprintf(os.Stderr, "threatdiff: unknown command %q\n\n%s", cmd, usage)
		return exitError
	}
}

func fail(format string, a ...any) int {
	fmt.Fprintf(os.Stderr, "threatdiff: "+format+"\n", a...)
	return exitError
}
