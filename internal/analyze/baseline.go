package analyze

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// A baseline records findings a repository has consciously accepted, so
// threatdiff can be switched on in an existing codebase without a flood on day
// one. Entries are keyed by fingerprint, which is derived from the rule, the
// path and the normalised line - not the line number - so ordinary refactoring
// does not silently un-suppress or re-suppress anything.
//
// Baselines age badly by nature. Each entry carries the date it was added so a
// periodic review can ask whether it is still true.

// BaselineEntry is one accepted finding.
type BaselineEntry struct {
	Fingerprint string `json:"fingerprint"`
	Rule        string `json:"rule"`
	File        string `json:"file"`
	Reason      string `json:"reason,omitempty"`
	AddedAt     string `json:"added_at,omitempty"`
}

// Baseline is the on-disk format.
type Baseline struct {
	Version   int             `json:"version"`
	Generated string          `json:"generated,omitempty"`
	Entries   []BaselineEntry `json:"entries"`
}

// LoadBaseline reads a baseline file into a fingerprint -> reason map. A
// missing file is not an error: it means "no baseline".
func LoadBaseline(path string) (map[string]string, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading baseline %s: %w", path, err)
	}
	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("parsing baseline %s: %w", path, err)
	}
	if b.Version != 0 && b.Version != 1 {
		return nil, fmt.Errorf("baseline %s: unsupported version %d", path, b.Version)
	}
	out := make(map[string]string, len(b.Entries))
	for _, e := range b.Entries {
		reason := e.Reason
		if reason == "" {
			reason = "accepted in baseline"
		}
		out[e.Fingerprint] = reason
	}
	return out, nil
}

// WriteBaseline records every current finding as accepted. Existing entries are
// preserved so a regenerated baseline does not lose the reasons people wrote.
func WriteBaseline(path string, res *Result, reason string) (int, error) {
	existing := map[string]BaselineEntry{}
	if data, err := os.ReadFile(path); err == nil {
		var b Baseline
		if err := json.Unmarshal(data, &b); err == nil {
			for _, e := range b.Entries {
				existing[e.Fingerprint] = e
			}
		}
	}

	today := time.Now().UTC().Format("2006-01-02")
	added := 0
	for _, f := range append(append([]*Finding{}, res.Findings...), res.Suppressed...) {
		r := reason
		if r == "" {
			r = f.Reason
		}
		// Record the folded repeats as well as the leader, so a second run
		// cannot promote a repeat into a "new" finding.
		for _, fp := range append([]string{f.Fingerprint}, f.RelatedFingerprints...) {
			if _, ok := existing[fp]; ok {
				continue
			}
			existing[fp] = BaselineEntry{
				Fingerprint: fp,
				Rule:        f.RuleID,
				File:        f.File,
				Reason:      r,
				AddedAt:     today,
			}
			added++
		}
	}

	out := Baseline{Version: 1, Generated: time.Now().UTC().Format(time.RFC3339)}
	for _, e := range existing {
		out.Entries = append(out.Entries, e)
	}
	sort.Slice(out.Entries, func(i, j int) bool {
		if out.Entries[i].File != out.Entries[j].File {
			return out.Entries[i].File < out.Entries[j].File
		}
		if out.Entries[i].Rule != out.Entries[j].Rule {
			return out.Entries[i].Rule < out.Entries[j].Rule
		}
		return out.Entries[i].Fingerprint < out.Entries[j].Fingerprint
	})

	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return 0, fmt.Errorf("encoding baseline: %w", err)
	}
	data = append(data, '\n')
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return 0, fmt.Errorf("creating %s: %w", dir, err)
		}
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return 0, fmt.Errorf("writing baseline %s: %w", path, err)
	}
	return added, nil
}
