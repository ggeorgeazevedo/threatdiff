package analyze

import (
	"strings"
	"testing"

	"github.com/ggeorgeazevedo/threatdiff/internal/config"
	"github.com/ggeorgeazevedo/threatdiff/internal/diff"
	"github.com/ggeorgeazevedo/threatdiff/internal/rules"
)

func newEngine(t *testing.T, cfg *config.Config, rs ...*rules.Rule) *Engine {
	t.Helper()
	set, err := rules.Compile(&rules.Pack{Version: 1, Name: "test", Rules: rs})
	if err != nil {
		t.Fatalf("compiling test rules: %v", err)
	}
	e, err := New(set, cfg, nil)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	return e
}

func analyzePatch(t *testing.T, e *Engine, patch string) *Result {
	t.Helper()
	d, err := diff.ParseString(patch)
	if err != nil {
		t.Fatalf("parsing patch: %v", err)
	}
	return e.Analyze(d)
}

// entropyOff keeps the statistical detector out of tests that are about rule
// matching, so an unrelated tuning change cannot break them.
func entropyOff() *config.Config {
	no := false
	return &config.Config{Entropy: config.EntropyConfig{Enabled: &no}}
}

const addedPatch = `diff --git a/app/views.py b/app/views.py
--- a/app/views.py
+++ b/app/views.py
@@ -5,6 +5,8 @@ def index(request):
 	ctx = {}
-	verify_signature(request)
+	os.system("echo " + request.GET["name"])
+	DEBUG = True
 	return render(ctx)
`

func TestMatchesAddedLines(t *testing.T) {
	e := newEngine(t, entropyOff(), &rules.Rule{
		ID: "t.command", Title: "Command execution", Category: rules.Tampering,
		Severity: rules.Critical, Confidence: rules.ConfHigh,
		Patterns: []string{`os\.system\s*\(`}, Question: "Q?",
	})
	res := analyzePatch(t, e, addedPatch)
	if len(res.Findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(res.Findings))
	}
	f := res.Findings[0]
	if f.File != "app/views.py" || f.Line != 6 {
		t.Errorf("location = %s", f.Location())
	}
	if f.Section != "def index(request):" {
		t.Errorf("section = %q", f.Section)
	}
	if !strings.Contains(f.Snippet, "os.system") {
		t.Errorf("snippet = %q", f.Snippet)
	}
}

func TestMatchesRemovedLinesAndAnchorsToSurvivingLine(t *testing.T) {
	// The whole point of the removed-line trigger: a deleted control is
	// invisible to a scanner that only reads the resulting file.
	e := newEngine(t, entropyOff(), &rules.Rule{
		ID: "t.control-removed", Title: "Verification removed", Category: rules.Tampering,
		Severity: rules.Critical, Confidence: rules.ConfHigh, Trigger: rules.OnRemoved,
		Patterns: []string{`verify_signature`}, Question: "Q?",
	})
	res := analyzePatch(t, e, addedPatch)
	if len(res.Findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(res.Findings))
	}
	f := res.Findings[0]
	if f.Trigger != rules.OnRemoved {
		t.Errorf("trigger = %s", f.Trigger)
	}
	if f.OldLine != 6 {
		t.Errorf("old line = %d, want 6", f.OldLine)
	}
	// The deleted line has no line number in the new file, so it must be
	// anchored to the nearest line that still exists or no review UI can show it.
	if f.Line != 5 {
		t.Errorf("anchor line = %d, want 5 (the context line above)", f.Line)
	}
}

func TestNearAbsentSuppressesMatch(t *testing.T) {
	rule := &rules.Rule{
		ID: "t.route-no-auth", Title: "Route without auth", Category: rules.ElevationOfPrivilege,
		Severity: rules.High, Confidence: rules.ConfLow,
		Patterns: []string{`@app\.route`},
		Near:     &rules.Near{Absent: []string{`login_required`}, Window: 3},
		Question: "Q?",
	}

	guarded := `--- a/a.py
+++ b/a.py
@@ -1,2 +1,4 @@
+@login_required
+@app.route("/admin")
+def admin():
+    pass
`
	unguarded := `--- a/b.py
+++ b/b.py
@@ -1,2 +1,3 @@
+@app.route("/admin")
+def admin():
+    pass
`
	e := newEngine(t, entropyOff(), rule)
	if got := analyzePatch(t, e, guarded); len(got.Findings) != 0 {
		t.Errorf("guarded route should not fire, got %d findings", len(got.Findings))
	}
	if got := analyzePatch(t, e, unguarded); len(got.Findings) != 1 {
		t.Errorf("unguarded route should fire, got %d findings", len(got.Findings))
	}
}

func TestNearPresentRequiresContext(t *testing.T) {
	rule := &rules.Rule{
		ID: "t.random-secret", Title: "Weak random for a secret", Category: rules.Spoofing,
		Severity: rules.High, Patterns: []string{`random\.randint`},
		Near:     &rules.Near{Present: []string{`token|secret`}, Window: 2},
		Question: "Q?",
	}
	e := newEngine(t, entropyOff(), rule)

	relevant := "--- a/a.py\n+++ b/a.py\n@@ -1 +1,2 @@\n+token = random.randint(0, 9999)\n"
	irrelevant := "--- a/b.py\n+++ b/b.py\n@@ -1 +1,2 @@\n+dice = random.randint(1, 6)\n"

	if got := analyzePatch(t, e, relevant); len(got.Findings) != 1 {
		t.Errorf("want 1 finding for the token case, got %d", len(got.Findings))
	}
	if got := analyzePatch(t, e, irrelevant); len(got.Findings) != 0 {
		t.Errorf("want 0 findings for the dice case, got %d", len(got.Findings))
	}
}

func TestExcludePatternWins(t *testing.T) {
	e := newEngine(t, entropyOff(), &rules.Rule{
		ID: "t.md5", Title: "MD5", Category: rules.Tampering, Severity: rules.High,
		Patterns: []string{`md5`}, ExcludePatterns: []string{`cache_key`},
		Question: "Q?",
	})
	patch := "--- a/a.go\n+++ b/a.go\n@@ -1 +1,3 @@\n+h := md5.Sum(pw)\n+cache_key := md5.Sum(url)\n"
	res := analyzePatch(t, e, patch)
	if len(res.Findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(res.Findings))
	}
	if !strings.Contains(res.Findings[0].Snippet, "pw") {
		t.Errorf("wrong line matched: %q", res.Findings[0].Snippet)
	}
}

func TestFileRuleFiresOnFileEvent(t *testing.T) {
	e := newEngine(t, entropyOff(), &rules.Rule{
		ID: "t.lockfile-gone", Title: "Lockfile deleted", Category: rules.SupplyChain,
		Severity: rules.High, Trigger: rules.OnFile, FileEvents: []string{"deleted"},
		Paths: []string{"**/yarn.lock"}, Question: "Q?",
	})

	deleted := `diff --git a/yarn.lock b/yarn.lock
deleted file mode 100644
--- a/yarn.lock
+++ /dev/null
@@ -1,2 +0,0 @@
-a
-b
`
	modified := `diff --git a/yarn.lock b/yarn.lock
--- a/yarn.lock
+++ b/yarn.lock
@@ -1 +1 @@
-a
+b
`
	if got := analyzePatch(t, e, deleted); len(got.Findings) != 1 {
		t.Errorf("deletion should fire, got %d", len(got.Findings))
	}
	if got := analyzePatch(t, e, modified); len(got.Findings) != 0 {
		t.Errorf("modification should not fire, got %d", len(got.Findings))
	}
}

func TestRepeatsAreFoldedIntoOneFinding(t *testing.T) {
	e := newEngine(t, entropyOff(), &rules.Rule{
		ID: "t.public", Title: "Public", Category: rules.InformationDisclosure,
		Severity: rules.Critical, Patterns: []string{`= false`}, Question: "Q?",
	})
	patch := `--- a/main.tf
+++ b/main.tf
@@ -1,4 +1,5 @@
+  block_public_acls       = false
+  block_public_policy     = false
+  ignore_public_acls      = false
+  restrict_public_buckets = false
`
	res := analyzePatch(t, e, patch)
	if len(res.Findings) != 1 {
		t.Fatalf("four adjacent hits of one rule should collapse to one finding, got %d", len(res.Findings))
	}
	f := res.Findings[0]
	if f.Occurrences != 4 {
		t.Errorf("occurrences = %d, want 4", f.Occurrences)
	}
	if len(f.OtherLines) != 3 {
		t.Errorf("other lines = %v, want 3 entries", f.OtherLines)
	}
}

func TestInlineSuppression(t *testing.T) {
	rule := &rules.Rule{
		ID: "t.md5", Title: "MD5", Category: rules.Tampering, Severity: rules.High,
		Patterns: []string{`md5`}, Question: "Q?",
	}
	e := newEngine(t, entropyOff(), rule)

	cases := []struct {
		name       string
		patch      string
		suppressed bool
		reason     string
	}{
		{
			name:       "bare marker on the line",
			patch:      "--- a/a.go\n+++ b/a.go\n@@ -1 +1,2 @@\n+h := md5.Sum(x) // threatdiff:ignore -- etag only\n",
			suppressed: true, reason: "etag only",
		},
		{
			name:       "bracketed rule id",
			patch:      "--- a/a.go\n+++ b/a.go\n@@ -1 +1,2 @@\n+h := md5.Sum(x) # threatdiff:ignore[t.md5] not security\n",
			suppressed: true, reason: "not security",
		},
		{
			name:       "marker on the previous line",
			patch:      "--- a/a.go\n+++ b/a.go\n@@ -1 +1,3 @@\n+// threatdiff:ignore t.md5 -- legacy\n+h := md5.Sum(x)\n",
			suppressed: true, reason: "legacy",
		},
		{
			name:       "different rule id does not suppress",
			patch:      "--- a/a.go\n+++ b/a.go\n@@ -1 +1,2 @@\n+h := md5.Sum(x) // threatdiff:ignore[t.other] nope\n",
			suppressed: false,
		},
		{
			name: "html comment closer is not part of the reason",
			patch: "--- a/a.md\n+++ b/a.md\n@@ -1 +1,3 @@\n" +
				"+<!-- threatdiff:ignore[t.md5] documentation example -->\n+h := md5.Sum(x)\n",
			suppressed: true, reason: "documentation example",
		},
		{
			name:       "wildcard family suppression",
			patch:      "--- a/a.go\n+++ b/a.go\n@@ -1 +1,2 @@\n+h := md5.Sum(x) // threatdiff:ignore[t.*] whole family\n",
			suppressed: true, reason: "whole family",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := analyzePatch(t, e, c.patch)
			if c.suppressed {
				if len(res.Findings) != 0 || len(res.Suppressed) != 1 {
					t.Fatalf("want it suppressed, got %d live / %d suppressed",
						len(res.Findings), len(res.Suppressed))
				}
				if res.Suppressed[0].Reason != c.reason {
					t.Errorf("reason = %q, want %q", res.Suppressed[0].Reason, c.reason)
				}
			} else if len(res.Findings) != 1 {
				t.Fatalf("want it live, got %d live / %d suppressed",
					len(res.Findings), len(res.Suppressed))
			}
		})
	}
}

func TestBaselineSuppresses(t *testing.T) {
	rule := &rules.Rule{
		ID: "t.md5", Title: "MD5", Category: rules.Tampering, Severity: rules.High,
		Patterns: []string{`md5`}, Question: "Q?",
	}
	set, err := rules.Compile(&rules.Pack{Version: 1, Name: "t", Rules: []*rules.Rule{rule}})
	if err != nil {
		t.Fatal(err)
	}
	patch := "--- a/a.go\n+++ b/a.go\n@@ -1 +1,2 @@\n+h := md5.Sum(x)\n"

	e, _ := New(set, entropyOff(), nil)
	res := analyzePatch(t, e, patch)
	if len(res.Findings) != 1 {
		t.Fatalf("setup: want 1 finding")
	}
	fp := res.Findings[0].Fingerprint

	e2, _ := New(set, entropyOff(), map[string]string{fp: "accepted at adoption"})
	res2 := analyzePatch(t, e2, patch)
	if len(res2.Findings) != 0 || len(res2.Suppressed) != 1 {
		t.Fatalf("baseline should suppress: %d live, %d suppressed",
			len(res2.Findings), len(res2.Suppressed))
	}
	if res2.Suppressed[0].SuppressBy != "baseline" {
		t.Errorf("suppressed by %q", res2.Suppressed[0].SuppressBy)
	}
}

func TestFingerprintIgnoresLineNumberButNotContent(t *testing.T) {
	a := fingerprint("r.id", "a.go", "  x := md5.Sum(v)")
	b := fingerprint("r.id", "a.go", "\tx := md5.Sum(v)  ") // reindented
	c := fingerprint("r.id", "a.go", "x := sha256.Sum(v)")
	d := fingerprint("r.id", "b.go", "x := md5.Sum(v)")
	if a != b {
		t.Error("reindentation should not change the fingerprint")
	}
	if a == c {
		t.Error("different content should change the fingerprint")
	}
	if a == d {
		t.Error("different path should change the fingerprint")
	}
}

func TestMinConfidenceFilter(t *testing.T) {
	rs := []*rules.Rule{
		{ID: "t.high", Title: "H", Category: rules.Tampering, Severity: rules.High,
			Confidence: rules.ConfHigh, Patterns: []string{`x`}, Question: "Q?"},
		{ID: "t.low", Title: "L", Category: rules.Tampering, Severity: rules.High,
			Confidence: rules.ConfLow, Patterns: []string{`x`}, Question: "Q?"},
	}
	cfg := entropyOff()
	cfg.MinConfidence = "high"
	e := newEngine(t, cfg, rs...)
	res := analyzePatch(t, e, "--- a/a.go\n+++ b/a.go\n@@ -1 +1,2 @@\n+x\n")
	if len(res.Findings) != 1 || res.Findings[0].RuleID != "t.high" {
		t.Fatalf("min_confidence not applied: %+v", res.Findings)
	}
}

func TestSeverityOverrideAndDisable(t *testing.T) {
	rs := []*rules.Rule{
		{ID: "t.a", Title: "A", Category: rules.Tampering, Severity: rules.Critical,
			Patterns: []string{`x`}, Question: "Q?"},
		{ID: "t.b", Title: "B", Category: rules.Tampering, Severity: rules.Critical,
			Patterns: []string{`x`}, Question: "Q?"},
	}
	cfg := entropyOff()
	cfg.Rules.Severity = map[string]string{"t.a": "low"}
	cfg.Rules.Disable = []string{"t.b"}

	e := newEngine(t, cfg, rs...)
	res := analyzePatch(t, e, "--- a/a.go\n+++ b/a.go\n@@ -1 +1,2 @@\n+x\n")
	if len(res.Findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(res.Findings))
	}
	if res.Findings[0].RuleID != "t.a" || res.Findings[0].Severity != rules.Low {
		t.Errorf("got %s at %s", res.Findings[0].RuleID, res.Findings[0].Severity)
	}
}

func TestExcludePathsSkipFiles(t *testing.T) {
	cfg := entropyOff()
	cfg.ExcludePaths = []string{"vendor/**"}
	e := newEngine(t, cfg, &rules.Rule{
		ID: "t.a", Title: "A", Category: rules.Tampering, Severity: rules.High,
		Patterns: []string{`x`}, Question: "Q?",
	})
	patch := "--- a/vendor/lib.go\n+++ b/vendor/lib.go\n@@ -1 +1,2 @@\n+x\n"
	res := analyzePatch(t, e, patch)
	if len(res.Findings) != 0 {
		t.Errorf("excluded path still produced findings")
	}
	if res.Stats.FilesSkipped != 1 {
		t.Errorf("files skipped = %d", res.Stats.FilesSkipped)
	}
}

func TestRedactionNeverEchoesTheSecret(t *testing.T) {
	const secret = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	e := newEngine(t, entropyOff(), &rules.Rule{
		ID: "t.token", Title: "Token", Category: rules.SecretsExposure,
		Severity: rules.Critical, Redact: true,
		Patterns: []string{`ghp_[A-Za-z0-9]{36}`}, Question: "Q?",
	})
	patch := "--- a/a.go\n+++ b/a.go\n@@ -1 +1,2 @@\n+const tok = \"" + secret + "\"\n"
	res := analyzePatch(t, e, patch)
	if len(res.Findings) != 1 {
		t.Fatalf("want 1 finding")
	}
	f := res.Findings[0]
	if strings.Contains(f.Snippet, secret) || strings.Contains(f.Match, secret) {
		t.Fatalf("the secret leaked into the finding: %q / %q", f.Snippet, f.Match)
	}
	if !strings.Contains(f.Snippet, "redacted") {
		t.Errorf("snippet should show a redaction marker, got %q", f.Snippet)
	}
}

func TestEntropyDetector(t *testing.T) {
	set, err := rules.Compile(&rules.Pack{Version: 1, Name: "empty", Rules: []*rules.Rule{{
		ID: "t.noop", Title: "N", Category: rules.Tampering, Severity: rules.Info,
		Patterns: []string{`\x00never`}, Question: "Q?",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	e, err := New(set, &config.Config{}, nil)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		line string
		want bool
	}{
		{"random api key", `API_KEY = "hV3kPq82ZmXbT4rLdWy9NsAeCu6Gf1Jo"`, true},
		{"env placeholder", `API_KEY = "${API_KEY}"`, false},
		{"os.environ", `api_key = os.environ["API_KEY"]`, false},
		{"non credential name", `banner_text = "hV3kPq82ZmXbT4rLdWy9NsAeCu6Gf1Jo"`, false},
		{"too short", `api_key = "abc123"`, false},
		{"low entropy", `api_key = "aaaaaaaaaaaaaaaaaaaaaaaaaa"`, false},
		{"a url", `webhook_url = "https://example.com/hooks/abcdefghijklmno"`, false},
		{"obvious placeholder", `secret = "changeme-changeme-changeme"`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			patch := "--- a/a.py\n+++ b/a.py\n@@ -1 +1,2 @@\n+" + c.line + "\n"
			res := analyzePatch(t, e, patch)
			got := len(res.Findings) > 0
			if got != c.want {
				t.Errorf("detector fired = %v, want %v (findings: %+v)", got, c.want, res.Findings)
			}
			for _, f := range res.Findings {
				if strings.Contains(f.Snippet, "hV3kPq82ZmXbT4rLdWy9NsAeCu6Gf1Jo") {
					t.Error("entropy findings must be redacted")
				}
			}
		})
	}
}

func TestEntropySkipsNoisyPaths(t *testing.T) {
	set, _ := rules.Compile(&rules.Pack{Version: 1, Name: "empty", Rules: []*rules.Rule{{
		ID: "t.noop", Title: "N", Category: rules.Tampering, Severity: rules.Info,
		Patterns: []string{`\x00never`}, Question: "Q?",
	}}})
	e, _ := New(set, &config.Config{}, nil)
	patch := "--- a/yarn.lock\n+++ b/yarn.lock\n@@ -1 +1,2 @@\n+  integrity_key \"hV3kPq82ZmXbT4rLdWy9NsAeCu6Gf1Jo\"\n"
	if res := analyzePatch(t, e, patch); len(res.Findings) != 0 {
		t.Errorf("lockfiles should be skipped by the entropy detector, got %+v", res.Findings)
	}
}

func TestShannonEntropy(t *testing.T) {
	if ShannonEntropy("") != 0 {
		t.Error("empty string should have zero entropy")
	}
	if ShannonEntropy("aaaaaaaa") != 0 {
		t.Error("a single repeated character should have zero entropy")
	}
	random := ShannonEntropy("hV3kPq82ZmXbT4rLdWy9NsAeCu6Gf1Jo")
	repeated := ShannonEntropy("abababababababab")
	if random <= repeated {
		t.Errorf("random (%.2f) should exceed repetitive (%.2f)", random, repeated)
	}
}

func TestMask(t *testing.T) {
	if got := Mask("abc"); got != "[redacted]" {
		t.Errorf("short value = %q", got)
	}
	long := Mask("AKIAIOSFODNN7EXAMPLE")
	if !strings.HasPrefix(long, "AKIA") || strings.Contains(long, "EXAMPLE") {
		t.Errorf("mask should keep a short prefix only, got %q", long)
	}
}

func TestStatsAreReported(t *testing.T) {
	e := newEngine(t, entropyOff(), &rules.Rule{
		ID: "t.a", Title: "A", Category: rules.Tampering, Severity: rules.Low,
		Patterns: []string{`never-matches-this`}, Question: "Q?",
	})
	res := analyzePatch(t, e, addedPatch)
	if res.Stats.FilesChanged != 1 || res.Stats.Additions != 2 || res.Stats.Deletions != 1 {
		t.Errorf("stats = %+v", res.Stats)
	}
	if res.Stats.Languages["python"] != 1 {
		t.Errorf("languages = %+v", res.Stats.Languages)
	}
	if res.Stats.RulesEvaluated != 1 {
		t.Errorf("rules evaluated = %d", res.Stats.RulesEvaluated)
	}
}

func TestFindingsAreSortedWorstFirst(t *testing.T) {
	rs := []*rules.Rule{
		{ID: "t.low", Title: "L", Category: rules.Tampering, Severity: rules.Low,
			Patterns: []string{`x`}, Question: "Q?"},
		{ID: "t.crit", Title: "C", Category: rules.Tampering, Severity: rules.Critical,
			Patterns: []string{`x`}, Question: "Q?"},
		{ID: "t.med", Title: "M", Category: rules.Tampering, Severity: rules.Medium,
			Patterns: []string{`x`}, Question: "Q?"},
	}
	e := newEngine(t, entropyOff(), rs...)
	res := analyzePatch(t, e, "--- a/a.go\n+++ b/a.go\n@@ -1 +1,2 @@\n+x\n")
	if len(res.Findings) != 3 {
		t.Fatalf("want 3 findings, got %d", len(res.Findings))
	}
	want := []rules.Severity{rules.Critical, rules.Medium, rules.Low}
	for i, s := range want {
		if res.Findings[i].Severity != s {
			t.Errorf("finding %d is %s, want %s", i, res.Findings[i].Severity, s)
		}
	}
	if res.Highest() != rules.Critical {
		t.Errorf("Highest() = %s", res.Highest())
	}
}
