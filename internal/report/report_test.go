package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ggeorgeazevedo/threatdiff/internal/analyze"
	"github.com/ggeorgeazevedo/threatdiff/internal/config"
	"github.com/ggeorgeazevedo/threatdiff/internal/owners"
	"github.com/ggeorgeazevedo/threatdiff/internal/rules"
	"github.com/ggeorgeazevedo/threatdiff/internal/score"
)

func sampleReport(t *testing.T) *Report {
	t.Helper()
	res := &analyze.Result{
		Findings: []*analyze.Finding{
			{
				RuleID:   "authz.tenant-scope-dropped-from-query",
				Title:    "Query filter on tenant, account or owner removed",
				Category: rules.ElevationOfPrivilege, Severity: rules.Critical,
				Confidence: rules.ConfLow, Trigger: rules.OnRemoved,
				File: "api/invoices.go", Line: 88, OldLine: 91,
				Section:     "func (s *Server) List(w, r)",
				Snippet:     `.Where("tenant_id = ?", tenantID)`,
				Question:    "Does this query still return only rows belonging to the caller's tenant?",
				Guidance:    "Cross-tenant leaks look exactly like this in a diff.",
				CWE:         []string{"CWE-639"},
				OWASP:       []string{"A01:2021 Broken Access Control"},
				Fingerprint: "abc123def4567890",
				Occurrences: 2, OtherLines: []int{97},
			},
			{
				RuleID:   "crypto.weak-hash-for-security",
				Title:    "Weak hash function used",
				Category: rules.Tampering, Severity: rules.Medium,
				Confidence: rules.ConfMedium, Trigger: rules.OnAdded,
				File: "lib/hash.go", Line: 12,
				Snippet:     "h := md5.Sum(body)",
				Question:    "Is this hash used for a security decision?",
				Fingerprint: "0123456789abcdef",
				Occurrences: 1,
			},
		},
		Suppressed: []*analyze.Finding{
			{
				RuleID:   "secret.generic-credential-assignment",
				Title:    "Credential-shaped value assigned to a variable",
				Category: rules.SecretsExposure, Severity: rules.High,
				Confidence: rules.ConfLow, Trigger: rules.OnAdded,
				File: "docs/example.py", Line: 3,
				Snippet:     `api_key = "exa[redacted 20 chars]"`,
				Question:    "Is this a real credential?",
				Fingerprint: "fedcba9876543210",
				Suppressed:  true, SuppressBy: "inline", Reason: "documentation placeholder",
				Occurrences: 1,
			},
		},
		Stats: analyze.Stats{
			FilesChanged: 6, Additions: 59, Deletions: 25, RulesEvaluated: 88,
			Languages: map[string]int{"go": 4, "terraform": 2},
		},
	}
	sc := score.Compute(res, config.ScoringConfig{})
	router, err := owners.New(config.ReviewConfig{
		Routes: []config.Route{
			{Categories: []string{"elevation-of-privilege"}, Reviewers: []string{"@org/authz"}},
		},
		Default: []string{"@org/appsec"},
	})
	if err != nil {
		t.Fatal(err)
	}
	router.Apply(res)

	return &Report{
		Meta:    Meta{Tool: "threatdiff", Version: "test", GeneratedAt: "2026-01-01T00:00:00Z"},
		Result:  res,
		Score:   sc,
		Verdict: score.Verdict{Failed: true, Reason: "1 critical finding (gate: --fail-on critical)"},
		Router:  router,
	}
}

func render(t *testing.T, f Format, r *Report) string {
	t.Helper()
	var buf bytes.Buffer
	if err := Render(&buf, f, r, false); err != nil {
		t.Fatalf("render %s: %v", f, err)
	}
	return buf.String()
}

func TestPrettyContainsTheEssentials(t *testing.T) {
	out := render(t, FormatPretty, sampleReport(t))
	for _, want := range []string{
		"threatdiff",
		"api/invoices.go",
		"Query filter on tenant",
		"Does this query still return only rows",
		"authz.tenant-scope-dropped-from-query",
		"2 occurrences",
		"removed from old line 91",
		"Suggested reviewers",
		"@org/authz",
		"Suppressed",
		"documentation placeholder",
		"FAIL",
		"threatdiff:ignore",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("pretty output is missing %q", want)
		}
	}
}

func TestPrettyHasNoAnsiWhenColourIsOff(t *testing.T) {
	out := render(t, FormatPretty, sampleReport(t))
	if strings.Contains(out, "\x1b[") {
		t.Error("colour disabled but ANSI escapes were emitted")
	}
}

func TestPrettyWithColourEmitsAnsi(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, FormatPretty, sampleReport(t), true); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "\x1b[") {
		t.Error("colour enabled but no ANSI escapes were emitted")
	}
}

func TestMarkdownStructure(t *testing.T) {
	out := render(t, FormatMarkdown, sampleReport(t))

	if !strings.HasPrefix(out, CommentMarker) {
		t.Error("the comment must start with the marker so CI can update it in place")
	}
	for _, want := range []string{
		"## threatdiff",
		"| Threat category |",
		"### Review checklist",
		"- [ ] **Query filter on tenant",
		"**Ask:**",
		"<details><summary>How to answer it</summary>",
		"### Suggested reviewers",
		"@org/authz",
		"Suppressed: 1",
		"**Gate failed:**",
		"CWE-639",
		"```diff",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown is missing %q", want)
		}
	}
	// Removed lines must be rendered as removals, or the reviewer reads the
	// finding backwards.
	if !strings.Contains(out, `- .Where("tenant_id = ?", tenantID)`) {
		t.Error("removed snippet should be prefixed with -")
	}
}

func TestMarkdownEscapesTableBreakingText(t *testing.T) {
	r := sampleReport(t)
	r.Result.Suppressed[0].Reason = "pipe | inside <b>and html</b>"
	out := render(t, FormatMarkdown, r)
	if strings.Contains(out, "| pipe | inside") {
		t.Error("an unescaped pipe would break the table")
	}
	if strings.Contains(out, "<b>and html</b>") {
		t.Error("html in a reason should be escaped")
	}
}

func TestMarkdownCannotEscapeItsCodeFence(t *testing.T) {
	// A snippet is attacker-influenced text quoted into a comment a reviewer
	// reads. It must not be able to close its own fence and inject Markdown.
	r := sampleReport(t)
	r.Result.Findings[1].Snippet = "x := 1\n```\n# Approved by security\n"
	out := render(t, FormatMarkdown, r)
	if strings.Contains(out, "\n```\n# Approved by security") {
		t.Error("a snippet escaped its code fence")
	}
}

func TestMarkdownCleanRun(t *testing.T) {
	res := &analyze.Result{Stats: analyze.Stats{FilesChanged: 2, RulesEvaluated: 88}}
	r := &Report{
		Meta:   Meta{Version: "test"},
		Result: res,
		Score:  score.Compute(res, config.ScoringConfig{}),
	}
	out := render(t, FormatMarkdown, r)
	if !strings.Contains(out, "No security-relevant changes matched") {
		t.Error("a clean run should say so")
	}
	// Honesty about what a clean result means is part of the deliverable.
	if !strings.Contains(out, "not a guarantee about the code") {
		t.Error("a clean run should not overclaim")
	}
}

func TestSARIFIsWellFormed(t *testing.T) {
	out := render(t, FormatSARIF, sampleReport(t))

	var log struct {
		Schema  string `json:"$schema"`
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID                   string                 `json:"id"`
						ShortDescription     struct{ Text string }  `json:"shortDescription"`
						DefaultConfiguration struct{ Level string } `json:"defaultConfiguration"`
						Properties           struct {
							SecuritySeverity string   `json:"security-severity"`
							Precision        string   `json:"precision"`
							Tags             []string `json:"tags"`
						} `json:"properties"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				RuleIndex int    `json:"ruleIndex"`
				Level     string `json:"level"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct{ URI string }    `json:"artifactLocation"`
						Region           struct{ StartLine int } `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
				PartialFingerprints map[string]string `json:"partialFingerprints"`
				Suppressions        []struct {
					Kind          string `json:"kind"`
					Justification string `json:"justification"`
				} `json:"suppressions"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(out), &log); err != nil {
		t.Fatalf("SARIF is not valid JSON: %v", err)
	}
	if log.Version != "2.1.0" || !strings.Contains(log.Schema, "sarif") {
		t.Errorf("version/schema = %q / %q", log.Version, log.Schema)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("want 1 run, got %d", len(log.Runs))
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != "threatdiff" {
		t.Errorf("driver name = %q", run.Tool.Driver.Name)
	}
	// Two live findings plus one suppressed one: suppressed results are
	// reported with a suppression, not dropped.
	if len(run.Results) != 3 {
		t.Fatalf("want 3 results, got %d", len(run.Results))
	}
	if len(run.Tool.Driver.Rules) != 3 {
		t.Fatalf("want 3 rule definitions, got %d", len(run.Tool.Driver.Rules))
	}

	for i, res := range run.Results {
		if res.RuleIndex < 0 || res.RuleIndex >= len(run.Tool.Driver.Rules) {
			t.Fatalf("result %d has out-of-range ruleIndex %d", i, res.RuleIndex)
		}
		if run.Tool.Driver.Rules[res.RuleIndex].ID != res.RuleID {
			t.Errorf("result %d: ruleIndex points at %q, not %q",
				i, run.Tool.Driver.Rules[res.RuleIndex].ID, res.RuleID)
		}
		if res.PartialFingerprints["threatdiff/v1"] == "" {
			t.Errorf("result %d has no fingerprint, so code scanning cannot track it", i)
		}
		if len(res.Locations) == 0 || res.Locations[0].PhysicalLocation.ArtifactLocation.URI == "" {
			t.Errorf("result %d has no location", i)
		}
		if res.Locations[0].PhysicalLocation.Region.StartLine <= 0 {
			t.Errorf("result %d has a non-positive start line", i)
		}
	}

	if run.Results[0].Level != "error" {
		t.Errorf("a critical finding should be level error, got %q", run.Results[0].Level)
	}

	var suppressedSeen bool
	for _, res := range run.Results {
		if len(res.Suppressions) > 0 {
			suppressedSeen = true
			if res.Suppressions[0].Justification == "" {
				t.Error("a suppression should carry its justification")
			}
		}
	}
	if !suppressedSeen {
		t.Error("the suppressed finding did not reach SARIF")
	}

	for _, r := range run.Tool.Driver.Rules {
		if r.Properties.SecuritySeverity == "" {
			t.Errorf("rule %s has no security-severity; GitHub needs it to rank the alert", r.ID)
		}
		if r.Properties.Precision == "" {
			t.Errorf("rule %s has no precision", r.ID)
		}
		if len(r.Properties.Tags) == 0 {
			t.Errorf("rule %s has no tags", r.ID)
		}
	}
}

func TestSARIFEmptyRunIsStillValid(t *testing.T) {
	res := &analyze.Result{}
	r := &Report{Meta: Meta{Version: "t"}, Result: res, Score: score.Compute(res, config.ScoringConfig{})}
	out := render(t, FormatSARIF, r)
	if !strings.Contains(out, `"results": []`) {
		t.Errorf("an empty run must emit an empty array, not null:\n%s", out)
	}
	var any map[string]any
	if err := json.Unmarshal([]byte(out), &any); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
}

func TestJSONContract(t *testing.T) {
	out := render(t, FormatJSON, sampleReport(t))
	var got struct {
		Meta struct {
			Tool    string `json:"tool"`
			Version string `json:"version"`
		} `json:"meta"`
		Score struct {
			Total float64 `json:"total"`
			Band  string  `json:"band"`
		} `json:"score"`
		Gate struct {
			Failed bool   `json:"failed"`
			Reason string `json:"reason"`
		} `json:"gate"`
		Summary struct {
			Total      int            `json:"total"`
			Suppressed int            `json:"suppressed"`
			BySeverity map[string]int `json:"by_severity"`
			ByCategory map[string]int `json:"by_category"`
			Reviewers  map[string]int `json:"reviewers"`
		} `json:"summary"`
		Findings []struct {
			RuleID      string `json:"rule_id"`
			Fingerprint string `json:"fingerprint"`
			File        string `json:"file"`
			Line        int    `json:"line"`
		} `json:"findings"`
		Suppressed []struct {
			RuleID string `json:"rule_id"`
		} `json:"suppressed"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if got.Meta.Tool != "threatdiff" {
		t.Errorf("meta.tool = %q", got.Meta.Tool)
	}
	if got.Score.Total <= 0 || got.Score.Band == "" {
		t.Errorf("score = %+v", got.Score)
	}
	if !got.Gate.Failed || got.Gate.Reason == "" {
		t.Errorf("gate = %+v", got.Gate)
	}
	if got.Summary.Total != 2 || got.Summary.Suppressed != 1 {
		t.Errorf("summary counts = %+v", got.Summary)
	}
	if got.Summary.BySeverity["critical"] != 1 || got.Summary.ByCategory["tampering"] != 1 {
		t.Errorf("summary breakdown = %+v", got.Summary)
	}
	if got.Summary.Reviewers["@org/authz"] != 1 {
		t.Errorf("reviewers = %+v", got.Summary.Reviewers)
	}
	if len(got.Findings) != 2 || got.Findings[0].Fingerprint == "" {
		t.Errorf("findings = %+v", got.Findings)
	}
	if len(got.Suppressed) != 1 {
		t.Errorf("suppressed = %+v", got.Suppressed)
	}
}

func TestJSONEmptyArraysNotNull(t *testing.T) {
	res := &analyze.Result{}
	r := &Report{Meta: Meta{Version: "t"}, Result: res, Score: score.Compute(res, config.ScoringConfig{})}
	out := render(t, FormatJSON, r)
	if strings.Contains(out, `"findings": null`) || strings.Contains(out, `"suppressed": null`) {
		t.Errorf("consumers should not have to handle null:\n%s", out)
	}
}

func TestUnknownFormatIsAnError(t *testing.T) {
	var buf bytes.Buffer
	err := Render(&buf, Format("yaml"), sampleReport(t), false)
	if err == nil || !strings.Contains(err.Error(), "unknown format") {
		t.Errorf("want an unknown-format error, got %v", err)
	}
}

func TestRedactedSnippetsSurviveEveryRenderer(t *testing.T) {
	const secret = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	r := sampleReport(t)
	// Simulate what the engine would have produced: already masked.
	r.Result.Findings[1].Snippet = analyze.Mask(secret)
	r.Result.Findings[1].Match = analyze.Mask(secret)

	for _, f := range []Format{FormatPretty, FormatMarkdown, FormatSARIF, FormatJSON} {
		out := render(t, f, r)
		if strings.Contains(out, secret) {
			t.Errorf("%s renderer leaked the secret", f)
		}
	}
}

func TestBarRendering(t *testing.T) {
	if got := bar(10, 10, 4); got != "████" {
		t.Errorf("full bar = %q", got)
	}
	if got := bar(0, 10, 4); got != "····" {
		t.Errorf("empty bar = %q", got)
	}
	if got := bar(5, 0, 3); got != "···" {
		t.Errorf("zero max should not divide by zero, got %q", got)
	}
	if got := bar(20, 10, 4); got != "████" {
		t.Errorf("overflow should clamp, got %q", got)
	}
}

func TestOccurrenceNote(t *testing.T) {
	if got := occurrenceNote(&analyze.Finding{Occurrences: 1}); got != "" {
		t.Errorf("a single occurrence needs no note, got %q", got)
	}
	got := occurrenceNote(&analyze.Finding{Occurrences: 12, OtherLines: []int{2, 3}})
	if !strings.Contains(got, "12 occurrences") || !strings.Contains(got, "and 9 more") {
		t.Errorf("note = %q", got)
	}
}
