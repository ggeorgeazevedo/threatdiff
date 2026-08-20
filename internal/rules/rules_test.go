package rules

import (
	"strings"
	"testing"
)

func TestBuiltinPacksCompile(t *testing.T) {
	set, err := Default()
	if err != nil {
		t.Fatalf("compiling builtin packs: %v", err)
	}
	if set.Len() < 50 {
		t.Fatalf("expected a substantial builtin set, got %d rules", set.Len())
	}

	seen := map[string]bool{}
	for _, r := range set.Rules {
		if seen[r.ID] {
			t.Errorf("duplicate rule id %s", r.ID)
		}
		seen[r.ID] = true

		// A rule that cannot tell a reviewer what to check is noise, so the
		// question is mandatory and is checked at compile time. Guidance is not
		// mandatory, but a rule without it is much less useful, so hold the
		// builtin pack to a higher bar than the schema does.
		if strings.TrimSpace(r.Question) == "" {
			t.Errorf("%s: empty question", r.ID)
		}
		if strings.TrimSpace(r.Guidance) == "" {
			t.Errorf("%s: builtin rules must carry guidance", r.ID)
		}
		if len(r.CWE) == 0 && r.Category != SupplyChain {
			t.Logf("note: %s has no CWE mapping", r.ID)
		}
	}
}

func TestBuiltinCoversEveryCategory(t *testing.T) {
	set, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	present := map[Category]int{}
	for _, r := range set.Rules {
		present[r.Category]++
	}
	for _, c := range Categories() {
		if present[c] == 0 {
			t.Errorf("no builtin rule covers category %s", c)
		}
	}
}

func TestCompileRejectsInvalidRules(t *testing.T) {
	base := func() *Rule {
		return &Rule{
			ID: "test.rule", Title: "T", Category: Tampering,
			Severity: High, Patterns: []string{"x"}, Question: "Q?",
		}
	}
	cases := []struct {
		name   string
		mutate func(*Rule)
		want   string
	}{
		{"no id", func(r *Rule) { r.ID = "" }, "missing `id`"},
		{"bad id", func(r *Rule) { r.ID = "Test_Rule" }, "lowercase"},
		{"no title", func(r *Rule) { r.Title = "" }, "missing `title`"},
		{"bad severity", func(r *Rule) { r.Severity = "urgent" }, "invalid severity"},
		{"bad category", func(r *Rule) { r.Category = "confusion" }, "invalid category"},
		{"bad confidence", func(r *Rule) { r.Confidence = "certain" }, "invalid confidence"},
		{"bad trigger", func(r *Rule) { r.Trigger = "sideways" }, "invalid `on:"},
		{"no question", func(r *Rule) { r.Question = "" }, "missing `question`"},
		{"no selector", func(r *Rule) { r.Patterns = nil }, "at least one of"},
		{"bad regex", func(r *Rule) { r.Patterns = []string{"("} }, "patterns"},
		{"lookahead", func(r *Rule) { r.Patterns = []string{"(?=x)"} }, "lookaround"},
		{"bad language", func(r *Rule) { r.Languages = []string{"cobol"} }, "unknown language"},
		{"bad event", func(r *Rule) { r.FileEvents = []string{"touched"} }, "unknown file event"},
		{"empty near", func(r *Rule) { r.Near = &Near{} }, "`near` needs"},
		{"bad near scope", func(r *Rule) {
			r.Near = &Near{Absent: []string{"x"}, Scope: "galaxy"}
		}, "near.scope"},
		{"negated glob", func(r *Rule) { r.Paths = []string{"!x"} }, "negated globs"},
	}

	for _, c := range cases {
		r := base()
		c.mutate(r)
		_, err := Compile(&Pack{Version: 1, Name: "t", Rules: []*Rule{r}})
		if err == nil {
			t.Errorf("%s: expected an error", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %q does not mention %q", c.name, err, c.want)
		}
	}
}

func TestLaterPackOverridesEarlier(t *testing.T) {
	a := &Pack{Version: 1, Name: "a", Rules: []*Rule{{
		ID: "x.y", Title: "original", Category: Tampering, Severity: Low,
		Patterns: []string{"a"}, Question: "Q?",
	}}}
	b := &Pack{Version: 1, Name: "b", Rules: []*Rule{{
		ID: "x.y", Title: "override", Category: Tampering, Severity: Critical,
		Patterns: []string{"b"}, Question: "Q?",
	}}}
	set, err := Compile(a, b)
	if err != nil {
		t.Fatal(err)
	}
	if set.Len() != 1 {
		t.Fatalf("want 1 rule, got %d", set.Len())
	}
	r, _ := set.ByID("x.y")
	if r.Title != "override" || r.Severity != Critical {
		t.Errorf("override did not win: %+v", r.Rule)
	}
}

func TestDisabledRulesAreExcluded(t *testing.T) {
	off := false
	set, err := Compile(&Pack{Version: 1, Name: "p", Rules: []*Rule{
		{ID: "a.b", Title: "on", Category: Tampering, Severity: Low,
			Patterns: []string{"x"}, Question: "Q?"},
		{ID: "c.d", Title: "off", Category: Tampering, Severity: Low,
			Patterns: []string{"x"}, Question: "Q?", Enabled: &off},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if set.Len() != 1 {
		t.Fatalf("want 1 enabled rule, got %d", set.Len())
	}
	// A disabled rule is still addressable, so `rules show` can explain it.
	if _, ok := set.ByID("c.d"); !ok {
		t.Error("disabled rule should still be resolvable by id")
	}
}

func TestUnsupportedPackVersion(t *testing.T) {
	_, err := Compile(&Pack{Version: 99, Name: "future"})
	if err == nil || !strings.Contains(err.Error(), "version") {
		t.Errorf("want a version error, got %v", err)
	}
}

func TestGlobToRegexp(t *testing.T) {
	cases := []struct {
		glob, path string
		want       bool
	}{
		{"**/*_test.go", "pkg/api/handler_test.go", true},
		{"**/*_test.go", "handler_test.go", true},
		{"**/*_test.go", "handler.go", false},
		{"*.tf", "infra/modules/net.tf", true},    // bare name matches at any depth
		{"infra/*.tf", "infra/net.tf", true},      // anchored
		{"infra/*.tf", "infra/sub/net.tf", false}, // * does not cross /
		{"infra/**/*.tf", "infra/a/b/net.tf", true},
		{".github/workflows/**", ".github/workflows/ci.yml", true},
		{".github/workflows/**", ".github/dependabot.yml", false},
		{"**/*.{yaml,yml}", "k8s/deploy.yml", true},
		{"**/*.{yaml,yml}", "k8s/deploy.json", false},
		{"Dockerfile", "services/api/Dockerfile", true},
		{"**/test/**", "src/test/fixtures/x.go", true},
		{"src/?.go", "src/a.go", true},
		{"src/?.go", "src/ab.go", false},
	}
	for _, c := range cases {
		got, err := MatchGlob(c.glob, c.path)
		if err != nil {
			t.Errorf("%s: %v", c.glob, err)
			continue
		}
		if got != c.want {
			t.Errorf("MatchGlob(%q, %q) = %v, want %v", c.glob, c.path, got, c.want)
		}
	}
}

func TestGlobRejectsUnbalancedBraces(t *testing.T) {
	if _, err := GlobToRegexp("a/{b,c"); err == nil {
		t.Error("expected an error for an unbalanced brace")
	}
	if _, err := GlobToRegexp("a/b}"); err == nil {
		t.Error("expected an error for an unbalanced brace")
	}
}

func TestLanguageOf(t *testing.T) {
	cases := map[string]string{
		"main.go":                       "go",
		"app/views.py":                  "python",
		"web/src/App.tsx":               "typescript",
		"infra/main.tf":                 "terraform",
		"Dockerfile":                    "dockerfile",
		"services/api/Dockerfile.prod":  "dockerfile",
		".github/workflows/release.yml": "ci",
		"k8s/deploy.yml":                "yaml",
		"package.json":                  "node-deps",
		"yarn.lock":                     "lockfile",
		".env.production":               "dotenv",
		"docker-compose.yaml":           "compose",
		"README":                        "unknown",
	}
	for path, want := range cases {
		if got := LanguageOf(path); got != want {
			t.Errorf("LanguageOf(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestMatchesPath(t *testing.T) {
	set, err := Compile(&Pack{Version: 1, Name: "p", Rules: []*Rule{{
		ID: "a.b", Title: "T", Category: Tampering, Severity: Low,
		Languages: []string{"go"}, Paths: []string{"api/**"},
		ExcludePaths: []string{"**/*_test.go"},
		Patterns:     []string{"x"}, Question: "Q?",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	r := set.Rules[0]
	if !r.MatchesPath("api/handler.go", "go") {
		t.Error("should match api/handler.go")
	}
	if r.MatchesPath("api/handler_test.go", "go") {
		t.Error("exclude_paths should win over paths")
	}
	if r.MatchesPath("web/handler.go", "go") {
		t.Error("should not match outside api/")
	}
	if r.MatchesPath("api/handler.py", "python") {
		t.Error("language filter should exclude python")
	}
}

func TestSeverityAndConfidenceParsing(t *testing.T) {
	if s, err := ParseSeverity(" HIGH "); err != nil || s != High {
		t.Errorf("ParseSeverity = %v, %v", s, err)
	}
	if _, err := ParseSeverity("spicy"); err == nil {
		t.Error("expected an error")
	}
	if c, err := ParseConfidence("Low"); err != nil || c != ConfLow {
		t.Errorf("ParseConfidence = %v, %v", c, err)
	}
	if Critical.Rank() <= High.Rank() || High.Rank() <= Medium.Rank() {
		t.Error("severity ranks are not ordered")
	}
	if ConfHigh.Weight() <= ConfLow.Weight() {
		t.Error("confidence weights are not ordered")
	}
}

func TestDefaultTriggerInference(t *testing.T) {
	withPatterns := &Rule{Patterns: []string{"x"}}
	if withPatterns.On() != OnAdded {
		t.Errorf("a pattern rule should default to `added`, got %s", withPatterns.On())
	}
	pathOnly := &Rule{Paths: []string{"**"}}
	if pathOnly.On() != OnFile {
		t.Errorf("a path-only rule should default to `file`, got %s", pathOnly.On())
	}
}
