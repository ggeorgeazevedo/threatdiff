package score

import (
	"math"
	"testing"

	"github.com/ggeorgeazevedo/threatdiff/internal/analyze"
	"github.com/ggeorgeazevedo/threatdiff/internal/config"
	"github.com/ggeorgeazevedo/threatdiff/internal/rules"
)

func finding(sev rules.Severity, conf rules.Confidence, cat rules.Category, trig rules.Trigger) *analyze.Finding {
	return &analyze.Finding{
		RuleID: "t." + string(sev), Severity: sev, Confidence: conf,
		Category: cat, Trigger: trig,
	}
}

func result(fs ...*analyze.Finding) *analyze.Result {
	return &analyze.Result{Findings: fs}
}

func TestOneCriticalOutranksManyMediums(t *testing.T) {
	// This is the property the whole model exists to protect. If it ever
	// inverts, a large refactor outranks a targeted change to authentication
	// and the gate starts teaching people to write bigger pull requests.
	crit := Compute(result(finding(rules.Critical, rules.ConfHigh, rules.ElevationOfPrivilege, rules.OnAdded)),
		config.ScoringConfig{})

	var mediums []*analyze.Finding
	for i := 0; i < 8; i++ {
		mediums = append(mediums, finding(rules.Medium, rules.ConfMedium, rules.Tampering, rules.OnAdded))
		mediums[i].RuleID = "t.medium" + string(rune('a'+i))
	}
	many := Compute(result(mediums...), config.ScoringConfig{})

	if crit.Total <= many.Total {
		t.Errorf("one critical scored %.1f, eight mediums scored %.1f", crit.Total, many.Total)
	}
}

func TestSaturation(t *testing.T) {
	// Doubling the number of identical findings must add less than double the
	// score, otherwise the number is just a line count.
	one := Compute(result(finding(rules.High, rules.ConfHigh, rules.Tampering, rules.OnAdded)),
		config.ScoringConfig{})

	var ten []*analyze.Finding
	for i := 0; i < 10; i++ {
		f := finding(rules.High, rules.ConfHigh, rules.Tampering, rules.OnAdded)
		f.RuleID = "t.high" + string(rune('a'+i))
		ten = append(ten, f)
	}
	tenRes := Compute(result(ten...), config.ScoringConfig{})

	if tenRes.Total <= one.Total {
		t.Fatal("more findings should score higher")
	}
	if tenRes.Total >= one.Total*10 {
		t.Errorf("score is not saturating: 1 finding = %.1f, 10 findings = %.1f",
			one.Total, tenRes.Total)
	}
	if tenRes.Total > 100 {
		t.Errorf("score exceeded 100: %.1f", tenRes.Total)
	}
}

func TestRemovedControlsWeighMore(t *testing.T) {
	added := Compute(result(finding(rules.High, rules.ConfHigh, rules.Tampering, rules.OnAdded)),
		config.ScoringConfig{})
	removed := Compute(result(finding(rules.High, rules.ConfHigh, rules.Tampering, rules.OnRemoved)),
		config.ScoringConfig{})
	if removed.Raw <= added.Raw {
		t.Errorf("removal raw %.1f should exceed addition raw %.1f", removed.Raw, added.Raw)
	}
}

func TestConfidenceScalesContribution(t *testing.T) {
	high := Compute(result(finding(rules.High, rules.ConfHigh, rules.Tampering, rules.OnAdded)),
		config.ScoringConfig{})
	low := Compute(result(finding(rules.High, rules.ConfLow, rules.Tampering, rules.OnAdded)),
		config.ScoringConfig{})
	if low.Raw >= high.Raw {
		t.Errorf("low confidence raw %.1f should be under high %.1f", low.Raw, high.Raw)
	}
}

func TestBlastRadiusContributesAndSaturates(t *testing.T) {
	small := Compute(&analyze.Result{Stats: analyze.Stats{FilesChanged: 1, Additions: 10}},
		config.ScoringConfig{})
	big := Compute(&analyze.Result{Stats: analyze.Stats{FilesChanged: 60, Additions: 4000}},
		config.ScoringConfig{})
	huge := Compute(&analyze.Result{Stats: analyze.Stats{FilesChanged: 600, Additions: 40000}},
		config.ScoringConfig{})

	if small.BlastRadius >= big.BlastRadius {
		t.Error("a bigger change should carry more blast radius")
	}
	if big.BlastRadius > DefaultBlastRadiusWeight || huge.BlastRadius > DefaultBlastRadiusWeight {
		t.Errorf("blast radius exceeded its ceiling: %.1f / %.1f", big.BlastRadius, huge.BlastRadius)
	}
	if math.Abs(huge.BlastRadius-big.BlastRadius) > 1.5 {
		t.Errorf("blast radius is not saturating: %.1f vs %.1f", big.BlastRadius, huge.BlastRadius)
	}
}

func TestEmptyResultScoresZero(t *testing.T) {
	got := Compute(&analyze.Result{}, config.ScoringConfig{})
	if got.Total != 0 || got.Band != BandMinimal {
		t.Errorf("empty result scored %.1f (%s)", got.Total, got.Band)
	}
}

func TestBands(t *testing.T) {
	cases := []struct {
		total float64
		want  Band
	}{
		{0, BandMinimal}, {4, BandMinimal}, {5, BandLow}, {19, BandLow},
		{20, BandMedium}, {44, BandMedium}, {45, BandHigh}, {74, BandHigh},
		{75, BandCritical}, {100, BandCritical},
	}
	for _, c := range cases {
		if got := bandFor(c.total, config.ScoringConfig{}); got != c.want {
			t.Errorf("bandFor(%.0f) = %s, want %s", c.total, got, c.want)
		}
	}
}

func TestCategoriesAreRankedAndCounted(t *testing.T) {
	res := result(
		finding(rules.Critical, rules.ConfHigh, rules.ElevationOfPrivilege, rules.OnAdded),
		finding(rules.Low, rules.ConfLow, rules.Tampering, rules.OnAdded),
		finding(rules.Medium, rules.ConfHigh, rules.Tampering, rules.OnAdded),
	)
	got := Compute(res, config.ScoringConfig{})
	if len(got.Categories) != 2 {
		t.Fatalf("want 2 categories, got %d", len(got.Categories))
	}
	if got.Categories[0].Category != rules.ElevationOfPrivilege {
		t.Errorf("highest category = %s", got.Categories[0].Category)
	}
	if got.Categories[1].Count != 2 || got.Categories[1].Worst != rules.Medium {
		t.Errorf("tampering aggregate = %+v", got.Categories[1])
	}
}

func TestFindingScoresAreAssigned(t *testing.T) {
	f := finding(rules.Critical, rules.ConfHigh, rules.Tampering, rules.OnAdded)
	sup := finding(rules.High, rules.ConfHigh, rules.Tampering, rules.OnAdded)
	res := &analyze.Result{Findings: []*analyze.Finding{f}, Suppressed: []*analyze.Finding{sup}}
	Compute(res, config.ScoringConfig{})
	if f.Score <= 0 {
		t.Error("live findings must carry their contribution")
	}
	// Suppressed findings are scored so a report can say what the score would
	// have been, but they do not move the total.
	if sup.Score <= 0 {
		t.Error("suppressed findings should still be scored for reporting")
	}
	withSup := Compute(res, config.ScoringConfig{})
	withoutSup := Compute(&analyze.Result{Findings: []*analyze.Finding{f}}, config.ScoringConfig{})
	if withSup.Total != withoutSup.Total {
		t.Errorf("suppressed findings changed the total: %.1f vs %.1f",
			withSup.Total, withoutSup.Total)
	}
}

func TestTopDrivers(t *testing.T) {
	res := result(
		finding(rules.Low, rules.ConfLow, rules.Tampering, rules.OnAdded),
		finding(rules.Critical, rules.ConfHigh, rules.Spoofing, rules.OnAdded),
		finding(rules.Medium, rules.ConfHigh, rules.Tampering, rules.OnAdded),
		finding(rules.High, rules.ConfHigh, rules.Tampering, rules.OnAdded),
	)
	got := Compute(res, config.ScoringConfig{})
	if len(got.TopDrivers) != 3 {
		t.Fatalf("want 3 drivers, got %d", len(got.TopDrivers))
	}
	if got.TopDrivers[0].Severity != rules.Critical {
		t.Errorf("first driver = %s", got.TopDrivers[0].Severity)
	}
}

func TestConfigurableWeights(t *testing.T) {
	cfg := config.ScoringConfig{
		Base:              map[string]float64{"low": 100},
		RemovalMultiplier: 1,
		Saturation:        1000,
	}
	got := Compute(result(finding(rules.Low, rules.ConfHigh, rules.Tampering, rules.OnAdded)), cfg)
	if got.Raw != 100 {
		t.Errorf("raw = %.1f, want the configured 100", got.Raw)
	}
}

func TestGateOnSeverity(t *testing.T) {
	res := result(finding(rules.High, rules.ConfHigh, rules.Tampering, rules.OnAdded))
	sc := Compute(res, config.ScoringConfig{})

	if v := (Gate{FailOn: rules.Critical}).Apply(res, sc); v.Failed {
		t.Error("a high finding should not trip a critical gate")
	}
	v := (Gate{FailOn: rules.High}).Apply(res, sc)
	if !v.Failed {
		t.Fatal("a high finding should trip a high gate")
	}
	if v.Reason == "" {
		t.Error("a failing gate must explain itself")
	}
	if v := (Gate{FailOn: rules.Medium}).Apply(res, sc); !v.Failed {
		t.Error("a high finding should trip a medium gate")
	}
}

func TestGateOnScore(t *testing.T) {
	res := result(finding(rules.Critical, rules.ConfHigh, rules.Tampering, rules.OnAdded))
	sc := Compute(res, config.ScoringConfig{})
	if v := (Gate{FailScore: 100}).Apply(res, sc); v.Failed {
		t.Error("should not trip a threshold above the score")
	}
	if v := (Gate{FailScore: 5}).Apply(res, sc); !v.Failed {
		t.Error("should trip a threshold below the score")
	}
}

func TestGateDisabledByDefault(t *testing.T) {
	res := result(finding(rules.Critical, rules.ConfHigh, rules.Tampering, rules.OnAdded))
	sc := Compute(res, config.ScoringConfig{})
	if v := (Gate{}).Apply(res, sc); v.Failed {
		t.Error("an unconfigured gate must never fail a build")
	}
}
