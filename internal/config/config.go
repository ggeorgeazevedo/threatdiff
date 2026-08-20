package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DefaultFileNames are the locations threatdiff looks in, in order, when no
// --config flag is given.
var DefaultFileNames = []string{
	".threatdiff.yaml",
	".threatdiff.yml",
	".threatdiff/config.yaml",
	".github/threatdiff.yaml",
}

// Config is the repository-level configuration. Every field is optional; the
// zero value is a working configuration.
type Config struct {
	Version int `json:"version,omitempty"`

	// MinConfidence drops findings below this confidence level entirely.
	MinConfidence string `json:"min_confidence,omitempty"`
	// FailOn is the severity at which `threatdiff scan` exits non-zero.
	FailOn string `json:"fail_on,omitempty"`
	// FailScore is an alternative gate on the overall risk score (0-100).
	FailScore float64 `json:"fail_score,omitempty"`

	// ExcludePaths are skipped before any rule runs.
	ExcludePaths []string `json:"exclude_paths,omitempty"`
	// RulePaths point at extra rule packs (files or directories).
	RulePaths []string `json:"rule_paths,omitempty"`
	// Baseline is a path to a fingerprint file of accepted findings.
	Baseline string `json:"baseline,omitempty"`

	Rules   RulesConfig   `json:"rules,omitempty"`
	Entropy EntropyConfig `json:"entropy,omitempty"`
	Scoring ScoringConfig `json:"scoring,omitempty"`
	Review  ReviewConfig  `json:"review,omitempty"`
}

// RulesConfig tunes the active rule set without editing rule packs.
type RulesConfig struct {
	Disable []string `json:"disable,omitempty"`
	Enable  []string `json:"enable,omitempty"`
	// Only, when non-empty, restricts the run to these rule IDs.
	Only []string `json:"only,omitempty"`
	// Severity overrides a rule's severity, e.g. {"crypto.weak-hash": "low"}.
	Severity map[string]string `json:"severity,omitempty"`
}

// EntropyConfig controls the built-in high-entropy string detector, which
// catches credentials that no provider-specific pattern knows about.
type EntropyConfig struct {
	// Enabled defaults to true.
	Enabled *bool `json:"enabled,omitempty"`
	// MinEntropy is the Shannon entropy per character threshold. Default 3.6.
	MinEntropy float64 `json:"min_entropy,omitempty"`
	// MinLength is the shortest candidate considered. Default 20.
	MinLength int `json:"min_length,omitempty"`
	// ExcludePaths are additional paths the detector ignores.
	ExcludePaths []string `json:"exclude_paths,omitempty"`
}

// On reports whether the entropy detector should run.
func (e EntropyConfig) On() bool { return e.Enabled == nil || *e.Enabled }

// Entropy returns the effective entropy threshold.
func (e EntropyConfig) Entropy() float64 {
	if e.MinEntropy > 0 {
		return e.MinEntropy
	}
	return 3.6
}

// Length returns the effective minimum candidate length.
func (e EntropyConfig) Length() int {
	if e.MinLength > 0 {
		return e.MinLength
	}
	return 20
}

// ScoringConfig lets a team re-weight the risk model. The defaults are
// documented in docs/scoring.md; override them only with a reason you can
// explain to the next reviewer.
type ScoringConfig struct {
	// Base is the per-severity point value before multipliers.
	Base map[string]float64 `json:"base,omitempty"`
	// RemovalMultiplier scales findings that come from deleted lines.
	RemovalMultiplier float64 `json:"removal_multiplier,omitempty"`
	// Saturation controls how quickly many findings stop adding score.
	Saturation float64 `json:"saturation,omitempty"`
	// LeadScale controls the floor set by the single worst finding.
	LeadScale float64 `json:"lead_scale,omitempty"`
	// BlastRadiusWeight is the maximum contribution of change size (0-20).
	BlastRadiusWeight float64 `json:"blast_radius_weight,omitempty"`
	// Bands maps a band name to its inclusive lower bound.
	Bands map[string]float64 `json:"bands,omitempty"`
}

// ReviewConfig routes findings to the humans who should look at them.
type ReviewConfig struct {
	// Default reviewers, used when no route matches.
	Default []string `json:"default,omitempty"`
	// Routes are evaluated in order; all matching routes contribute.
	Routes []Route `json:"routes,omitempty"`
	// Mention controls whether reviewers are @-mentioned in the PR comment.
	Mention *bool `json:"mention,omitempty"`
}

// ShouldMention reports whether reviewers should be @-mentioned.
func (r ReviewConfig) ShouldMention() bool { return r.Mention == nil || *r.Mention }

// Route is one reviewer-routing rule.
type Route struct {
	Name string `json:"name,omitempty"`
	// Categories matches STRIDE categories.
	Categories []string `json:"categories,omitempty"`
	// Rules matches rule IDs (exact, or a prefix ending in ".*").
	Rules []string `json:"rules,omitempty"`
	// Paths matches file globs.
	Paths []string `json:"paths,omitempty"`
	// MinSeverity only routes findings at or above this severity.
	MinSeverity string `json:"min_severity,omitempty"`
	// Reviewers are handles or team slugs.
	Reviewers []string `json:"reviewers"`
}

// Load reads a config file. An empty path searches DefaultFileNames relative to
// root and returns the zero Config when none exists.
func Load(root, path string) (*Config, string, error) {
	if path != "" {
		cfg, err := loadFile(path)
		return cfg, path, err
	}
	for _, name := range DefaultFileNames {
		p := filepath.Join(root, name)
		if _, err := os.Stat(p); err == nil {
			cfg, err := loadFile(p)
			return cfg, p, err
		}
	}
	return &Config{}, "", nil
}

func loadFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}
	var c Config
	if strings.HasSuffix(strings.ToLower(path), ".json") {
		err = UnmarshalJSON(data, &c)
	} else {
		err = UnmarshalYAML(data, &c)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if c.Version != 0 && c.Version != 1 {
		return nil, fmt.Errorf("%s: unsupported config version %d", path, c.Version)
	}
	return &c, nil
}
