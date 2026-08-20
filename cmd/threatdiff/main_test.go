package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	examplePatch = "../../examples/pull-request.patch"
	// Tests must not inherit this repository's own .threatdiff.yaml.
	emptyConfig = "testdata/config-empty.yaml"
)

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return string(b)
}

func TestScanExamplePatchEndToEnd(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "report.json")
	sarif := filepath.Join(dir, "report.sarif")
	md := filepath.Join(dir, "report.md")
	ghOut := filepath.Join(dir, "gh-output")

	code := run([]string{
		"scan",
		"--config", emptyConfig,
		"--diff", examplePatch,
		"--format", "json", "--out", out,
		"--sarif-out", sarif,
		"--markdown-out", md,
		"--github-output", ghOut,
		"--fail-on", "critical",
		"--quiet", "--no-color",
	})
	if code != exitFindings {
		t.Fatalf("exit code = %d, want %d (the example patch is deliberately awful)", code, exitFindings)
	}

	var report struct {
		Score struct {
			Total float64 `json:"total"`
			Band  string  `json:"band"`
		} `json:"score"`
		Gate struct {
			Failed bool `json:"failed"`
		} `json:"gate"`
		Summary struct {
			Total      int            `json:"total"`
			BySeverity map[string]int `json:"by_severity"`
		} `json:"summary"`
		Findings []struct {
			RuleID string `json:"rule_id"`
			File   string `json:"file"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(readFile(t, out)), &report); err != nil {
		t.Fatalf("json report: %v", err)
	}
	if !report.Gate.Failed {
		t.Error("gate should have failed")
	}
	if report.Score.Band != "critical" {
		t.Errorf("band = %q, want critical", report.Score.Band)
	}
	if report.Summary.BySeverity["critical"] == 0 {
		t.Error("the example patch should contain critical findings")
	}

	// The findings this example is built to demonstrate. If a refactor breaks
	// one of these, the tool has quietly stopped doing its job.
	wantRules := []string{
		"control.authz-annotation-removed",
		"injection.unsafe-deserialization",
		"ci.pull-request-target-with-head-checkout",
		"iac.storage-made-public",
		"authn.session-cookie-flags-weakened",
		"supplychain.dependency-from-vcs-or-url",
	}
	seen := map[string]bool{}
	for _, f := range report.Findings {
		seen[f.RuleID] = true
	}
	for _, want := range wantRules {
		if !seen[want] {
			t.Errorf("expected rule %s to fire on the example patch", want)
		}
	}

	// Every extra output must exist and be usable.
	if !strings.Contains(readFile(t, md), "### Review checklist") {
		t.Error("markdown output is missing the checklist")
	}
	var sarifDoc map[string]any
	if err := json.Unmarshal([]byte(readFile(t, sarif)), &sarifDoc); err != nil {
		t.Errorf("sarif output is not valid JSON: %v", err)
	}

	gh := readFile(t, ghOut)
	for _, want := range []string{"score=", "band=critical", "findings=", "failed=true"} {
		if !strings.Contains(gh, want) {
			t.Errorf("github output is missing %q:\n%s", want, gh)
		}
	}
}

func TestScanIsDeterministic(t *testing.T) {
	// A gate whose output reorders between runs produces noisy comment diffs
	// and destroys trust in the tool.
	dir := t.TempDir()
	first := filepath.Join(dir, "a.json")
	second := filepath.Join(dir, "b.json")
	for _, out := range []string{first, second} {
		if code := run([]string{"scan", "--config", emptyConfig, "--diff", examplePatch, "--format", "json",
			"--out", out, "--quiet"}); code != exitOK {
			t.Fatalf("exit code = %d", code)
		}
	}
	a, b := readFile(t, first), readFile(t, second)
	// The generated timestamp is expected to differ; nothing else may.
	a = stripTimestamps(a)
	b = stripTimestamps(b)
	if a != b {
		t.Error("two runs over the same patch produced different reports")
	}
}

func stripTimestamps(s string) string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if strings.Contains(line, `"generated_at"`) {
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

func TestGateIsOffByDefault(t *testing.T) {
	dir := t.TempDir()
	code := run([]string{"scan", "--config", emptyConfig, "--diff", examplePatch, "--format", "json",
		"--out", filepath.Join(dir, "r.json"), "--quiet"})
	if code != exitOK {
		t.Errorf("without --fail-on the exit code must be 0, got %d", code)
	}
}

func TestMinConfidenceReducesFindings(t *testing.T) {
	dir := t.TempDir()
	count := func(args ...string) int {
		out := filepath.Join(dir, strings.Join(args, "")+".json")
		base := []string{"scan", "--config", emptyConfig, "--diff", examplePatch, "--format", "json", "--out", out, "--quiet"}
		if code := run(append(base, args...)); code > exitFindings {
			t.Fatalf("exit code = %d", code)
		}
		var r struct {
			Summary struct {
				Total int `json:"total"`
			} `json:"summary"`
		}
		if err := json.Unmarshal([]byte(readFile(t, out)), &r); err != nil {
			t.Fatal(err)
		}
		return r.Summary.Total
	}
	all := count()
	strict := count("--min-confidence", "high")
	if strict >= all {
		t.Errorf("min-confidence=high gave %d findings, all gave %d", strict, all)
	}
	if strict == 0 {
		t.Error("high-confidence rules should still fire on the example patch")
	}
}

func TestOnlyAndDisableFlags(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "only.json")
	code := run([]string{"scan", "--config", emptyConfig, "--diff", examplePatch, "--format", "json", "--out", out,
		"--only", "injection.unsafe-deserialization", "--quiet"})
	if code != exitOK {
		t.Fatalf("exit code = %d", code)
	}
	var r struct {
		Findings []struct {
			RuleID string `json:"rule_id"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(readFile(t, out)), &r); err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) == 0 {
		t.Fatal("expected the selected rule to fire")
	}
	for _, f := range r.Findings {
		if f.RuleID != "injection.unsafe-deserialization" {
			t.Errorf("--only leaked rule %s", f.RuleID)
		}
	}
}

func TestBaselineRoundTripSilencesEverything(t *testing.T) {
	dir := t.TempDir()
	baseline := filepath.Join(dir, "baseline.json")

	if code := run([]string{"baseline", "write", "--config", emptyConfig, "--diff", examplePatch,
		"--out", baseline, "--reason", "pre-existing at adoption"}); code != exitOK {
		t.Fatalf("baseline write exit code = %d", code)
	}

	out := filepath.Join(dir, "r.json")
	code := run([]string{"scan", "--config", emptyConfig, "--diff", examplePatch, "--format", "json", "--out", out,
		"--baseline", baseline, "--fail-on", "critical", "--quiet"})
	if code != exitOK {
		t.Errorf("a fully baselined run must pass the gate, exit code = %d", code)
	}

	var r struct {
		Summary struct {
			Total      int `json:"total"`
			Suppressed int `json:"suppressed"`
		} `json:"summary"`
	}
	if err := json.Unmarshal([]byte(readFile(t, out)), &r); err != nil {
		t.Fatal(err)
	}
	if r.Summary.Total != 0 {
		t.Errorf("%d findings survived the baseline", r.Summary.Total)
	}
	if r.Summary.Suppressed == 0 {
		t.Error("baselined findings must still be reported as suppressed, not dropped")
	}
}

func TestInitWritesUsableConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, ".threatdiff.yaml")
	if code := cmdInit([]string{"--out", cfg}); code != exitOK {
		t.Fatalf("init exit code = %d", code)
	}
	// Refuses to clobber.
	if code := cmdInit([]string{"--out", cfg}); code == exitOK {
		t.Error("init should refuse to overwrite without --force")
	}
	if code := cmdInit([]string{"--out", cfg, "--force"}); code != exitOK {
		t.Error("init --force should overwrite")
	}

	// And the generated config must actually load and run.
	out := filepath.Join(dir, "r.json")
	if code := run([]string{"scan", "--diff", examplePatch, "--config", cfg,
		"--format", "json", "--out", out, "--quiet"}); code > exitFindings {
		t.Fatalf("the generated config does not work: exit code %d", code)
	}
}

func TestRulesSubcommands(t *testing.T) {
	if code := cmdRules([]string{"list"}); code != exitOK {
		t.Errorf("rules list exit code = %d", code)
	}
	if code := cmdRules([]string{"show", "injection.unsafe-deserialization"}); code != exitOK {
		t.Errorf("rules show exit code = %d", code)
	}
	if code := cmdRules([]string{"show", "no.such.rule"}); code == exitOK {
		t.Error("rules show should fail for an unknown id")
	}
	if code := cmdRules([]string{"languages"}); code != exitOK {
		t.Errorf("rules languages exit code = %d", code)
	}
	if code := cmdRules([]string{"categories"}); code != exitOK {
		t.Errorf("rules categories exit code = %d", code)
	}
	dir := t.TempDir()
	if code := cmdRules([]string{"docs", "--out", filepath.Join(dir, "rules.md")}); code != exitOK {
		t.Errorf("rules docs exit code = %d", code)
	}
	if !strings.Contains(readFile(t, filepath.Join(dir, "rules.md")), "# Rule reference") {
		t.Error("generated rule reference looks wrong")
	}
}

func TestCustomRulePackOverridesBuiltin(t *testing.T) {
	dir := t.TempDir()
	pack := filepath.Join(dir, "custom.yaml")
	// Reusing a builtin id is the documented way to retune a rule without
	// forking the pack.
	err := os.WriteFile(pack, []byte(`version: 1
name: house-rules
rules:
  - id: crypto.weak-hash-for-security
    title: MD5 is banned outright here
    category: tampering
    severity: critical
    confidence: high
    on: added
    patterns:
      - '(?i)\bmd5\b'
    question: Why is MD5 present at all?
    guidance: We do not allow it, even for cache keys.
`), 0o644)
	if err != nil {
		t.Fatal(err)
	}

	if code := cmdRules([]string{"validate", pack}); code != exitOK {
		t.Fatalf("the custom pack does not validate")
	}

	out := filepath.Join(dir, "r.json")
	if code := run([]string{"scan", "--config", emptyConfig, "--diff", examplePatch, "--rules", pack,
		"--format", "json", "--out", out, "--quiet",
		"--only", "crypto.weak-hash-for-security"}); code > exitFindings {
		t.Fatalf("exit code = %d", code)
	}
	var r struct {
		Findings []struct {
			Title    string `json:"title"`
			Severity string `json:"severity"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(readFile(t, out)), &r); err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) == 0 {
		t.Fatal("the overriding rule did not fire")
	}
	if r.Findings[0].Title != "MD5 is banned outright here" || r.Findings[0].Severity != "critical" {
		t.Errorf("override did not take effect: %+v", r.Findings[0])
	}
}

func TestBadInputsExitWithTwo(t *testing.T) {
	cases := [][]string{
		{"scan", "--diff", "/nonexistent/patch.diff"},
		{"scan", "--rules", "/nonexistent/rules"},
		{"scan", "--diff", examplePatch, "--fail-on", "apocalyptic"},
		{"scan", "--diff", examplePatch, "--min-confidence", "certain"},
		{"nonsense-command"},
	}
	for _, args := range cases {
		if code := run(args); code != exitError {
			t.Errorf("%v: exit code = %d, want %d", args, code, exitError)
		}
	}
}

func TestEmptyDiffIsCleanNotAnError(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.patch")
	if err := os.WriteFile(empty, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "r.json")
	if code := run([]string{"scan", "--config", emptyConfig, "--diff", empty, "--format", "json",
		"--out", out, "--fail-on", "low", "--quiet"}); code != exitOK {
		t.Errorf("an empty diff should be a clean pass, got exit code %d", code)
	}
}

func TestVersionAndHelp(t *testing.T) {
	for _, args := range [][]string{{"version"}, {"--version"}, {"help"}, {"--help"}, {}} {
		if code := run(args); code != exitOK {
			t.Errorf("%v: exit code = %d", args, code)
		}
	}
}
