package owners

import (
	"reflect"
	"strings"
	"testing"

	"github.com/ggeorgeazevedo/threatdiff/internal/analyze"
	"github.com/ggeorgeazevedo/threatdiff/internal/config"
	"github.com/ggeorgeazevedo/threatdiff/internal/rules"
)

func f(rule string, cat rules.Category, sev rules.Severity, file string) *analyze.Finding {
	return &analyze.Finding{RuleID: rule, Category: cat, Severity: sev, File: file}
}

func TestRouteByCategory(t *testing.T) {
	r, err := New(config.ReviewConfig{
		Default: []string{"@org/appsec"},
		Routes: []config.Route{
			{Name: "authz", Categories: []string{"elevation-of-privilege"}, Reviewers: []string{"@org/authz"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := r.Route(f("authz.x", rules.ElevationOfPrivilege, rules.High, "api/a.go"))
	if !reflect.DeepEqual(got, []string{"@org/authz"}) {
		t.Errorf("got %v", got)
	}
	fallback := r.Route(f("dos.x", rules.DenialOfService, rules.Low, "api/a.go"))
	if !reflect.DeepEqual(fallback, []string{"@org/appsec"}) {
		t.Errorf("fallback = %v", fallback)
	}
}

func TestRouteByPathAndRulePrefix(t *testing.T) {
	r, err := New(config.ReviewConfig{
		Routes: []config.Route{
			{Name: "infra", Paths: []string{"**/*.tf", ".github/workflows/**"}, Reviewers: []string{"@org/cloud"}},
			{Name: "crypto", Rules: []string{"crypto.*"}, Reviewers: []string{"@org/crypto"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := r.Route(f("iac.x", rules.Tampering, rules.High, "infra/main.tf")); !reflect.DeepEqual(got, []string{"@org/cloud"}) {
		t.Errorf("terraform route = %v", got)
	}
	if got := r.Route(f("ci.x", rules.Tampering, rules.High, ".github/workflows/ci.yml")); !reflect.DeepEqual(got, []string{"@org/cloud"}) {
		t.Errorf("workflow route = %v", got)
	}
	if got := r.Route(f("crypto.weak", rules.Tampering, rules.High, "lib/hash.go")); !reflect.DeepEqual(got, []string{"@org/crypto"}) {
		t.Errorf("crypto route = %v", got)
	}
}

func TestRoutesAreAdditiveAndDeduplicated(t *testing.T) {
	r, err := New(config.ReviewConfig{
		Routes: []config.Route{
			{Categories: []string{"tampering"}, Reviewers: []string{"@a", "@shared"}},
			{Paths: []string{"**/*.tf"}, Reviewers: []string{"@b", "@shared"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := r.Route(f("x.y", rules.Tampering, rules.High, "infra/main.tf"))
	want := []string{"@a", "@shared", "@b"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestMinSeverityGatesRouting(t *testing.T) {
	r, err := New(config.ReviewConfig{
		Routes: []config.Route{
			{Categories: []string{"tampering"}, MinSeverity: "high", Reviewers: []string{"@org/sec"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := r.Route(f("x.y", rules.Tampering, rules.Low, "a.go")); len(got) != 0 {
		t.Errorf("low severity should not route, got %v", got)
	}
	if got := r.Route(f("x.y", rules.Tampering, rules.Critical, "a.go")); len(got) != 1 {
		t.Errorf("critical should route, got %v", got)
	}
}

func TestRouteWithoutReviewersIsRejected(t *testing.T) {
	_, err := New(config.ReviewConfig{Routes: []config.Route{{Name: "empty"}}})
	if err == nil || !strings.Contains(err.Error(), "no reviewers") {
		t.Errorf("want an error about missing reviewers, got %v", err)
	}
}

func TestApplyBuildsReviewerIndex(t *testing.T) {
	r, err := New(config.ReviewConfig{
		Routes: []config.Route{
			{Categories: []string{"tampering"}, Reviewers: []string{"@a"}},
			{Categories: []string{"spoofing"}, Reviewers: []string{"@b"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	res := &analyze.Result{Findings: []*analyze.Finding{
		f("x.1", rules.Tampering, rules.High, "a.go"),
		f("x.2", rules.Tampering, rules.High, "b.go"),
		f("x.3", rules.Spoofing, rules.High, "c.go"),
	}}
	names, index := r.Apply(res)
	if len(names) != 2 || names[0] != "@a" {
		t.Fatalf("names = %v (busiest reviewer should sort first)", names)
	}
	if len(index["@a"]) != 2 || len(index["@b"]) != 1 {
		t.Errorf("index = %v", index)
	}
	if len(res.Findings[0].Reviewers) != 1 {
		t.Error("Apply should annotate the findings themselves")
	}
}

const codeownersFile = `# comment line

*                       @org/everyone
/infra/                 @org/cloud
*.tf                    @org/terraform
docs/**/*.md            @org/docs
/api/billing/           @org/payments @alice
`

func TestCodeownersLastMatchWins(t *testing.T) {
	co, err := ParseCodeowners(strings.NewReader(codeownersFile))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]string{
		"README.md":               {"@org/everyone"},
		"infra/main.tf":           {"@org/terraform"}, // *.tf comes after /infra/
		"infra/README.md":         {"@org/cloud"},
		"docs/guides/setup.md":    {"@org/docs"},
		"api/billing/invoices.go": {"@org/payments", "@alice"},
		"api/users/handler.go":    {"@org/everyone"},
	}
	for path, want := range cases {
		got := co.Owners(path)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("Owners(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestCodeownersUsedAsFallback(t *testing.T) {
	co, err := ParseCodeowners(strings.NewReader(codeownersFile))
	if err != nil {
		t.Fatal(err)
	}
	r, err := New(config.ReviewConfig{
		Default: []string{"@org/appsec"},
		Routes: []config.Route{
			{Categories: []string{"secrets"}, Reviewers: []string{"@org/secrets"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	r = r.WithCodeowners(co)

	// An explicit route still wins.
	if got := r.Route(f("secret.x", rules.SecretsExposure, rules.High, "infra/main.tf")); !reflect.DeepEqual(got, []string{"@org/secrets"}) {
		t.Errorf("explicit route should win, got %v", got)
	}
	// Otherwise CODEOWNERS answers, so a repository gets useful routing with no
	// threatdiff configuration at all.
	if got := r.Route(f("dos.x", rules.DenialOfService, rules.Low, "infra/main.tf")); !reflect.DeepEqual(got, []string{"@org/terraform"}) {
		t.Errorf("codeowners fallback = %v", got)
	}
	// And the configured default is the last resort.
	if got := r.Route(f("dos.x", rules.DenialOfService, rules.Low, "nothing/here.xyz")); !reflect.DeepEqual(got, []string{"@org/everyone"}) {
		t.Errorf("wildcard codeowners entry should still match, got %v", got)
	}
}

func TestNilCodeownersIsSafe(t *testing.T) {
	var co *Codeowners
	if got := co.Owners("a.go"); got != nil {
		t.Errorf("nil Codeowners should return nil, got %v", got)
	}
}

func TestMentionDefaultsOn(t *testing.T) {
	r, _ := New(config.ReviewConfig{})
	if !r.Mention() {
		t.Error("mentions should default to on")
	}
	off := false
	r2, _ := New(config.ReviewConfig{Mention: &off})
	if r2.Mention() {
		t.Error("mentions should be disableable")
	}
}
