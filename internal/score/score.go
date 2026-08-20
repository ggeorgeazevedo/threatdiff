// Package score turns a set of findings into a single number a pull request can
// be gated on, and - more importantly - into an explanation of that number.
//
// The model has three properties that were chosen deliberately:
//
//  1. The worst finding sets a floor; everything else fills the headroom above
//     it, with diminishing returns. Concretely: the single largest contribution
//     is mapped through 1-exp(-x/k) to a floor, and the sum of the remaining
//     findings can only close the gap between that floor and the ceiling, again
//     through 1-exp(-x/k).
//
//     This is what stops a handful of mediums from outranking one critical. A
//     plain sum would mean a large refactor scores higher than a targeted change
//     to authentication, and a gate that behaves that way teaches people to
//     write bigger pull requests. A genuinely large pile of mediums still gets
//     there - thirty of them really is a high-risk change - it just takes
//     thirty, not eight.
//
//  2. Removed controls weigh more than added risk. A deleted authorization
//     check is a regression in a property the system already had; new risky
//     code at least arrives with a reviewer's attention on it.
//
//  3. Every number is explainable. Each finding carries the arithmetic that
//     produced its contribution, because a gate nobody can argue with is a gate
//     that gets bypassed rather than fixed.
package score

import (
	"math"
	"sort"

	"github.com/ggeorgeazevedo/threatdiff/internal/analyze"
	"github.com/ggeorgeazevedo/threatdiff/internal/config"
	"github.com/ggeorgeazevedo/threatdiff/internal/rules"
)

// Band is a coarse risk label derived from the score.
type Band string

// Bands, worst first.
const (
	BandCritical Band = "critical"
	BandHigh     Band = "high"
	BandMedium   Band = "medium"
	BandLow      Band = "low"
	BandMinimal  Band = "minimal"
)

// Rank orders bands, higher is worse.
func (b Band) Rank() int {
	switch b {
	case BandCritical:
		return 5
	case BandHigh:
		return 4
	case BandMedium:
		return 3
	case BandLow:
		return 2
	case BandMinimal:
		return 1
	}
	return 0
}

// Defaults for the model. Every one of them is overridable in config.
const (
	DefaultSaturation        = 70.0
	DefaultRemovalMultiplier = 1.3
	DefaultBlastRadiusWeight = 15.0
	// DefaultLeadScale tunes the floor set by the single worst finding. At 38,
	// one critical high-confidence finding (40 points) lands at roughly 55,
	// which is inside the "high" band on its own.
	DefaultLeadScale = 38.0
	signalCeiling    = 85.0
)

var defaultBase = map[rules.Severity]float64{
	rules.Critical: 40,
	rules.High:     24,
	rules.Medium:   10,
	rules.Low:      4,
	rules.Info:     1,
}

var defaultBands = map[Band]float64{
	BandCritical: 75,
	BandHigh:     45,
	BandMedium:   20,
	BandLow:      5,
}

// CategoryScore aggregates findings within one STRIDE category.
type CategoryScore struct {
	Category rules.Category `json:"category"`
	Score    float64        `json:"score"`
	Count    int            `json:"count"`
	Worst    rules.Severity `json:"worst"`
}

// Result is the computed risk picture for a change.
type Result struct {
	// Total is 0-100.
	Total float64 `json:"total"`
	Band  Band    `json:"band"`
	// Signals is the contribution from findings, after saturation (0-85).
	Signals float64 `json:"signals"`
	// BlastRadius is the contribution from the size and spread of the change
	// (0-15). A change that touches nothing sensitive still gets a floor from
	// here, which is correct: bigger diffs are reviewed worse.
	BlastRadius float64 `json:"blast_radius"`
	// Raw is the pre-saturation sum, useful when tuning.
	Raw        float64         `json:"raw"`
	Categories []CategoryScore `json:"categories"`
	// TopDrivers lists the findings that moved the number the most.
	TopDrivers []*analyze.Finding `json:"-"`
}

// Compute scores a result and, as a side effect, fills in Finding.Score.
func Compute(res *analyze.Result, cfg config.ScoringConfig) Result {
	base := baseWeights(cfg)
	removal := cfg.RemovalMultiplier
	if removal <= 0 {
		removal = DefaultRemovalMultiplier
	}
	saturation := cfg.Saturation
	if saturation <= 0 {
		saturation = DefaultSaturation
	}
	brWeight := cfg.BlastRadiusWeight
	if brWeight <= 0 {
		brWeight = DefaultBlastRadiusWeight
	}

	leadScale := cfg.LeadScale
	if leadScale <= 0 {
		leadScale = DefaultLeadScale
	}

	catScore := map[rules.Category]float64{}
	catCount := map[rules.Category]int{}
	catWorst := map[rules.Category]rules.Severity{}

	var raw, lead float64
	for _, f := range res.Findings {
		v := base[f.Severity] * f.Confidence.Weight()
		if f.Trigger == rules.OnRemoved {
			v *= removal
		}
		v = round1(v)
		f.Score = v
		raw += v
		if v > lead {
			lead = v
		}

		catScore[f.Category] += v
		catCount[f.Category]++
		if f.Severity.Rank() > catWorst[f.Category].Rank() {
			catWorst[f.Category] = f.Severity
		}
	}
	// Suppressed findings are scored too, so the report can say what the score
	// would have been - but they do not contribute to the total.
	for _, f := range res.Suppressed {
		v := base[f.Severity] * f.Confidence.Weight()
		if f.Trigger == rules.OnRemoved {
			v *= removal
		}
		f.Score = round1(v)
	}

	// Floor from the worst single finding, then headroom from the rest.
	floor := signalCeiling * (1 - math.Exp(-lead/leadScale))
	rest := raw - lead
	signals := floor + (signalCeiling-floor)*(1-math.Exp(-rest/saturation))
	br := blastRadius(res.Stats, brWeight)

	total := math.Min(100, signals+br)

	out := Result{
		Total:       round1(total),
		Signals:     round1(signals),
		BlastRadius: round1(br),
		Raw:         round1(raw),
		Band:        bandFor(total, cfg),
	}

	for c, s := range catScore {
		out.Categories = append(out.Categories, CategoryScore{
			Category: c, Score: round1(s), Count: catCount[c], Worst: catWorst[c],
		})
	}
	sort.Slice(out.Categories, func(i, j int) bool {
		if out.Categories[i].Score != out.Categories[j].Score {
			return out.Categories[i].Score > out.Categories[j].Score
		}
		return out.Categories[i].Category < out.Categories[j].Category
	})

	drivers := append([]*analyze.Finding(nil), res.Findings...)
	sort.SliceStable(drivers, func(i, j int) bool { return drivers[i].Score > drivers[j].Score })
	if len(drivers) > 3 {
		drivers = drivers[:3]
	}
	out.TopDrivers = drivers

	return out
}

// blastRadius maps the size of the change onto 0..weight. It saturates, so the
// difference between a 40-file and a 400-file change is small - both are past
// the point where a human reviews every line.
func blastRadius(s analyze.Stats, weight float64) float64 {
	files := float64(s.FilesChanged)
	lines := float64(s.Additions + s.Deletions)
	x := files/25.0 + lines/800.0
	return weight * (1 - math.Exp(-x))
}

func baseWeights(cfg config.ScoringConfig) map[rules.Severity]float64 {
	out := map[rules.Severity]float64{}
	for k, v := range defaultBase {
		out[k] = v
	}
	for k, v := range cfg.Base {
		if sev, err := rules.ParseSeverity(k); err == nil {
			out[sev] = v
		}
	}
	return out
}

func bandFor(total float64, cfg config.ScoringConfig) Band {
	thresholds := map[Band]float64{}
	for k, v := range defaultBands {
		thresholds[k] = v
	}
	for k, v := range cfg.Bands {
		thresholds[Band(k)] = v
	}
	switch {
	case total >= thresholds[BandCritical]:
		return BandCritical
	case total >= thresholds[BandHigh]:
		return BandHigh
	case total >= thresholds[BandMedium]:
		return BandMedium
	case total >= thresholds[BandLow]:
		return BandLow
	}
	return BandMinimal
}

func round1(f float64) float64 { return math.Round(f*10) / 10 }

// Gate decides the process exit status.
type Gate struct {
	// FailOn is the minimum severity that fails the run ("" disables).
	FailOn rules.Severity
	// FailScore fails the run when the total score reaches it (0 disables).
	FailScore float64
}

// Verdict is the outcome of applying a gate.
type Verdict struct {
	Failed bool
	Reason string
}

// Apply evaluates the gate against a result.
func (g Gate) Apply(res *analyze.Result, sc Result) Verdict {
	if g.FailOn != "" {
		worst := res.Highest()
		if worst.Rank() >= g.FailOn.Rank() && worst.Rank() > 0 {
			n := res.CountBySeverity()[worst]
			return Verdict{
				Failed: true,
				Reason: plural(n, string(worst)+" finding", string(worst)+" findings") +
					" (gate: --fail-on " + string(g.FailOn) + ")",
			}
		}
	}
	if g.FailScore > 0 && sc.Total >= g.FailScore {
		return Verdict{
			Failed: true,
			Reason: "risk score " + trimFloat(sc.Total) + " reached the configured threshold " + trimFloat(g.FailScore),
		}
	}
	return Verdict{}
}

func plural(n int, one, many string) string {
	s := itoa(n) + " "
	if n == 1 {
		return s + one
	}
	return s + many
}

func trimFloat(f float64) string {
	i := int(math.Round(f))
	return itoa(i)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
