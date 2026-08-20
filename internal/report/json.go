package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/ggeorgeazevedo/threatdiff/internal/analyze"
	"github.com/ggeorgeazevedo/threatdiff/internal/rules"
	"github.com/ggeorgeazevedo/threatdiff/internal/score"
)

// jsonOutput is the stable machine-readable contract. It is a separate type
// from the internal Report on purpose: internal refactors should not silently
// change what other people's automation parses.
type jsonOutput struct {
	Meta     Meta               `json:"meta"`
	Score    jsonScore          `json:"score"`
	Gate     jsonGate           `json:"gate"`
	Stats    analyze.Stats      `json:"stats"`
	Summary  jsonSummary        `json:"summary"`
	Findings []*analyze.Finding `json:"findings"`
	Ignored  []*analyze.Finding `json:"suppressed"`
}

type jsonScore struct {
	Total       float64               `json:"total"`
	Band        score.Band            `json:"band"`
	Signals     float64               `json:"signals"`
	BlastRadius float64               `json:"blast_radius"`
	Raw         float64               `json:"raw"`
	Categories  []score.CategoryScore `json:"categories"`
}

type jsonGate struct {
	Failed bool   `json:"failed"`
	Reason string `json:"reason,omitempty"`
}

type jsonSummary struct {
	Total      int            `json:"total"`
	Suppressed int            `json:"suppressed"`
	BySeverity map[string]int `json:"by_severity"`
	ByCategory map[string]int `json:"by_category"`
	Reviewers  map[string]int `json:"reviewers,omitempty"`
}

// JSON writes the machine-readable report.
func JSON(w io.Writer, r *Report) error {
	out := jsonOutput{
		Meta: r.Meta,
		Score: jsonScore{
			Total:       r.Score.Total,
			Band:        r.Score.Band,
			Signals:     r.Score.Signals,
			BlastRadius: r.Score.BlastRadius,
			Raw:         r.Score.Raw,
			Categories:  r.Score.Categories,
		},
		Gate:     jsonGate{Failed: r.Verdict.Failed, Reason: r.Verdict.Reason},
		Stats:    r.Result.Stats,
		Findings: nonNil(r.Result.Findings),
		Ignored:  nonNil(r.Result.Suppressed),
		Summary: jsonSummary{
			Total:      len(r.Result.Findings),
			Suppressed: len(r.Result.Suppressed),
			BySeverity: countKeys(r.Result.CountBySeverity()),
			ByCategory: countCategories(r.Result.CountByCategory()),
		},
	}
	if r.Router != nil {
		names, index := r.Router.Apply(r.Result)
		if len(names) > 0 {
			out.Summary.Reviewers = map[string]int{}
			for _, n := range names {
				out.Summary.Reviewers[n] = len(index[n])
			}
		}
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		return fmt.Errorf("writing json: %w", err)
	}
	return nil
}

func nonNil(in []*analyze.Finding) []*analyze.Finding {
	if in == nil {
		return []*analyze.Finding{}
	}
	return in
}

func countKeys(in map[rules.Severity]int) map[string]int {
	out := map[string]int{}
	for k, v := range in {
		out[string(k)] = v
	}
	return out
}

func countCategories(in map[rules.Category]int) map[string]int {
	out := map[string]int{}
	for k, v := range in {
		out[string(k)] = v
	}
	return out
}
