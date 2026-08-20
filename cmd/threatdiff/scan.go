package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ggeorgeazevedo/threatdiff/internal/analyze"
	"github.com/ggeorgeazevedo/threatdiff/internal/config"
	"github.com/ggeorgeazevedo/threatdiff/internal/diff"
	"github.com/ggeorgeazevedo/threatdiff/internal/owners"
	"github.com/ggeorgeazevedo/threatdiff/internal/report"
	"github.com/ggeorgeazevedo/threatdiff/internal/rules"
	"github.com/ggeorgeazevedo/threatdiff/internal/score"
	"github.com/ggeorgeazevedo/threatdiff/internal/version"
)

// stringList collects a repeatable flag.
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

type scanFlags struct {
	repo    string
	base    string
	head    string
	staged  bool
	patch   string
	context int

	configPath string
	rulePaths  stringList
	baseline   string

	format  string
	out     string
	sarifTo string
	mdTo    string
	jsonTo  string

	failOn        string
	failScore     float64
	minConfidence string
	only          stringList
	disable       stringList

	noColor bool
	quiet   bool

	githubOutput string
}

func cmdScan(args []string) int {
	var f scanFlags
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	fs.StringVar(&f.repo, "repo", ".", "repository directory")
	fs.StringVar(&f.base, "base", "", "base ref (default: CI base branch, then origin/HEAD, then HEAD~1)")
	fs.StringVar(&f.head, "head", "", "head ref (default: working tree)")
	fs.BoolVar(&f.staged, "staged", false, "analyse the staged changes instead of the working tree")
	fs.StringVar(&f.patch, "diff", "", "read a unified diff from this file, or - for stdin")
	fs.IntVar(&f.context, "context", 5, "context lines to request from git (affects `near` accuracy)")

	fs.StringVar(&f.configPath, "config", "", "config file (default: .threatdiff.yaml if present)")
	fs.Var(&f.rulePaths, "rules", "additional rule pack file or directory (repeatable)")
	fs.StringVar(&f.baseline, "baseline", "", "baseline file of accepted findings")

	fs.StringVar(&f.format, "format", "pretty", "stdout format: "+strings.Join(report.Formats(), "|"))
	fs.StringVar(&f.out, "out", "", "write the stdout format to this file instead")
	fs.StringVar(&f.sarifTo, "sarif-out", "", "additionally write SARIF to this file")
	fs.StringVar(&f.mdTo, "markdown-out", "", "additionally write the Markdown comment to this file")
	fs.StringVar(&f.jsonTo, "json-out", "", "additionally write JSON to this file")

	fs.StringVar(&f.failOn, "fail-on", "", "exit 1 when a finding at this severity or worse appears")
	fs.Float64Var(&f.failScore, "fail-score", 0, "exit 1 when the risk score reaches this value")
	fs.StringVar(&f.minConfidence, "min-confidence", "", "drop findings below this confidence (high|medium|low)")
	fs.Var(&f.only, "only", "run only this rule id (repeatable)")
	fs.Var(&f.disable, "disable", "disable this rule id (repeatable)")

	fs.BoolVar(&f.noColor, "no-color", false, "disable ANSI colour")
	fs.BoolVar(&f.quiet, "quiet", false, "suppress progress notes on stderr")
	fs.StringVar(&f.githubOutput, "github-output", "", "append score/band/findings/failed as key=value to this file (use $GITHUB_OUTPUT)")

	fs.Usage = func() {
		fmt.Fprint(os.Stderr, "threatdiff scan - analyse a diff for security-relevant change\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitError
	}

	rep, err := runAnalysis(&f)
	if err != nil {
		return fail("%v", err)
	}

	color := useColor(f.noColor, f.out)
	if err := writeMain(rep, &f, color); err != nil {
		return fail("%v", err)
	}
	for _, extra := range []struct {
		path   string
		format report.Format
	}{
		{f.sarifTo, report.FormatSARIF},
		{f.mdTo, report.FormatMarkdown},
		{f.jsonTo, report.FormatJSON},
	} {
		if extra.path == "" {
			continue
		}
		if err := writeFile(extra.path, extra.format, rep); err != nil {
			return fail("%v", err)
		}
		if !f.quiet {
			fmt.Fprintf(os.Stderr, "threatdiff: wrote %s\n", extra.path)
		}
	}

	if f.githubOutput != "" {
		if err := writeGitHubOutput(f.githubOutput, rep); err != nil {
			return fail("%v", err)
		}
	}

	if rep.Verdict.Failed {
		return exitFindings
	}
	return exitOK
}

// writeGitHubOutput appends the machine-readable summary that a workflow step
// consumes. Doing it here rather than in shell keeps the Action free of a jq or
// python dependency, which matters on self-hosted runners.
func writeGitHubOutput(path string, rep *report.Report) error {
	fh, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("opening %s: %w", path, err)
	}
	defer fh.Close()

	failed := "false"
	if rep.Verdict.Failed {
		failed = "true"
	}
	counts := rep.Result.CountBySeverity()
	_, err = fmt.Fprintf(fh,
		"score=%.1f\nband=%s\nfindings=%d\nsuppressed=%d\ncritical=%d\nhigh=%d\nmedium=%d\nlow=%d\nfailed=%s\n",
		rep.Score.Total, rep.Score.Band,
		len(rep.Result.Findings), len(rep.Result.Suppressed),
		counts[rules.Critical], counts[rules.High], counts[rules.Medium], counts[rules.Low],
		failed,
	)
	return err
}

// runAnalysis does everything except deciding where the output goes, so that
// `scan` and `baseline` cannot drift apart in how they interpret the diff.
func runAnalysis(f *scanFlags) (*report.Report, error) {
	// ---- configuration ----------------------------------------------------
	root := f.repo
	if r, err := diff.RepoRoot(f.repo); err == nil && r != "" {
		root = r
	}

	cfg, cfgPath, err := config.Load(root, f.configPath)
	if err != nil {
		return nil, err
	}
	applyFlagOverrides(cfg, f)

	set, err := rules.Default(append(cfg.RulePaths, f.rulePaths...)...)
	if err != nil {
		return nil, err
	}
	if set.Len() == 0 {
		return nil, fmt.Errorf("no rules are enabled; check `rules.only` and `rules.disable` in %s", cfgPath)
	}

	baseline, err := analyze.LoadBaseline(cfg.Baseline)
	if err != nil {
		return nil, err
	}

	engine, err := analyze.New(set, cfg, baseline)
	if err != nil {
		return nil, err
	}

	// ---- input ------------------------------------------------------------
	d, meta, err := loadDiff(f, root)
	if err != nil {
		if !errors.Is(err, diff.ErrEmpty) {
			return nil, err
		}
		d = &diff.Diff{}
	}

	// ---- analysis ---------------------------------------------------------
	res := engine.Analyze(d)
	sc := score.Compute(res, cfg.Scoring)

	router, err := owners.New(cfg.Review)
	if err != nil {
		return nil, err
	}
	if co, err := owners.FindCodeowners(root); err == nil && co != nil {
		router = router.WithCodeowners(co)
	}
	router.Apply(res)

	gate := score.Gate{FailScore: cfg.FailScore}
	if cfg.FailOn != "" {
		sev, err := rules.ParseSeverity(cfg.FailOn)
		if err != nil {
			return nil, fmt.Errorf("fail-on: %w", err)
		}
		gate.FailOn = sev
	}

	meta.Version = version.Short()
	meta.ConfigFile = cfgPath
	meta.RulePacks = len(set.Origin)

	return &report.Report{
		Meta:    meta,
		Result:  res,
		Score:   sc,
		Verdict: gate.Apply(res, sc),
		Router:  router,
	}, nil
}

func applyFlagOverrides(cfg *config.Config, f *scanFlags) {
	if f.failOn != "" {
		cfg.FailOn = f.failOn
	}
	if f.failScore > 0 {
		cfg.FailScore = f.failScore
	}
	if f.minConfidence != "" {
		cfg.MinConfidence = f.minConfidence
	}
	if f.baseline != "" {
		cfg.Baseline = f.baseline
	}
	cfg.Rules.Only = append(cfg.Rules.Only, f.only...)
	cfg.Rules.Disable = append(cfg.Rules.Disable, f.disable...)
}

func loadDiff(f *scanFlags, root string) (*diff.Diff, report.Meta, error) {
	meta := report.NewMeta(version.Short())

	if f.patch != "" {
		var r io.Reader
		if f.patch == "-" {
			r = os.Stdin
			meta.Base = "stdin"
		} else {
			fh, err := os.Open(f.patch)
			if err != nil {
				return nil, meta, fmt.Errorf("opening patch %s: %w", f.patch, err)
			}
			defer fh.Close()
			r = fh
			meta.Base = filepath.Base(f.patch)
		}
		d, err := diff.Parse(r)
		return d, meta, err
	}

	src := diff.Source{Repo: root, Base: f.base, Head: f.head, Staged: f.staged, Context: f.context}
	if src.Base == "" && !src.Staged {
		src.Base = diff.ResolveBase(root)
	}
	meta.Base = diff.Describe(root, src.Base)
	if src.Head != "" {
		meta.Head = diff.Describe(root, src.Head)
	} else if src.Staged {
		meta.Head = "index"
	} else {
		meta.Head = "working tree"
	}
	meta.Repository = filepath.Base(root)

	d, err := diff.FromGit(src)
	return d, meta, err
}

func writeMain(rep *report.Report, f *scanFlags, color bool) error {
	format := report.Format(f.format)
	if f.out == "" {
		return report.Render(os.Stdout, format, rep, color)
	}
	return writeFile(f.out, format, rep)
}

func writeFile(path string, format report.Format, rep *report.Report) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("creating %s: %w", dir, err)
		}
	}
	fh, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating %s: %w", path, err)
	}
	defer fh.Close()
	return report.Render(fh, format, rep, false)
}

// useColor decides whether to emit ANSI escapes. NO_COLOR is honoured because
// it is the convention; FORCE_COLOR because CI logs render colour but are not
// terminals.
func useColor(noColor bool, out string) bool {
	if noColor || out != "" {
		return false
	}
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if os.Getenv("FORCE_COLOR") != "" {
		return true
	}
	info, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
