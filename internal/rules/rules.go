// Package rules defines the declarative rule model that drives threatdiff.
//
// A rule answers one question: "if I see this in a diff, what threat should a
// human think about?" It is deliberately not a vulnerability signature. A rule
// firing is an invitation to review, carrying the STRIDE category, the question
// a reviewer should ask, and the guidance to answer it.
package rules

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Severity ranks how bad the modelled threat is if the reviewer's answer is
// "yes, this is a problem".
type Severity string

// Severity levels, ordered.
const (
	Critical Severity = "critical"
	High     Severity = "high"
	Medium   Severity = "medium"
	Low      Severity = "low"
	Info     Severity = "info"
)

// Rank returns a numeric order where higher is worse. Unknown values rank 0.
func (s Severity) Rank() int {
	switch s {
	case Critical:
		return 5
	case High:
		return 4
	case Medium:
		return 3
	case Low:
		return 2
	case Info:
		return 1
	}
	return 0
}

// Valid reports whether s is a known severity.
func (s Severity) Valid() bool { return s.Rank() > 0 }

// ParseSeverity converts user input into a Severity.
func ParseSeverity(s string) (Severity, error) {
	v := Severity(strings.ToLower(strings.TrimSpace(s)))
	if !v.Valid() {
		return "", fmt.Errorf("unknown severity %q (want critical|high|medium|low|info)", s)
	}
	return v, nil
}

// Confidence expresses how often the rule is right when it fires. It scales the
// contribution to the risk score, so a noisy-but-valuable rule can stay on.
type Confidence string

// Confidence levels.
const (
	ConfHigh   Confidence = "high"
	ConfMedium Confidence = "medium"
	ConfLow    Confidence = "low"
)

// Weight returns the score multiplier for a confidence level.
func (c Confidence) Weight() float64 {
	switch c {
	case ConfHigh:
		return 1.0
	case ConfMedium:
		return 0.7
	case ConfLow:
		return 0.45
	}
	return 0.7
}

// Valid reports whether c is a known confidence level.
func (c Confidence) Valid() bool {
	return c == ConfHigh || c == ConfMedium || c == ConfLow
}

// ParseConfidence converts user input into a Confidence.
func ParseConfidence(s string) (Confidence, error) {
	v := Confidence(strings.ToLower(strings.TrimSpace(s)))
	if !v.Valid() {
		return "", fmt.Errorf("unknown confidence %q (want high|medium|low)", s)
	}
	return v, nil
}

// Trigger selects which side of the diff a rule inspects.
type Trigger string

// Trigger values.
const (
	// OnAdded matches lines introduced by the change.
	OnAdded Trigger = "added"
	// OnRemoved matches lines deleted by the change. This is where control
	// regressions live: a deleted @requires_admin is invisible to a scanner
	// that only looks at the resulting file.
	OnRemoved Trigger = "removed"
	// OnAny matches either side.
	OnAny Trigger = "any"
	// OnFile matches the file itself rather than any line.
	OnFile Trigger = "file"
)

// Category is the STRIDE bucket (plus two practical extras) a rule belongs to.
type Category string

// Categories.
const (
	Spoofing              Category = "spoofing"
	Tampering             Category = "tampering"
	Repudiation           Category = "repudiation"
	InformationDisclosure Category = "information-disclosure"
	DenialOfService       Category = "denial-of-service"
	ElevationOfPrivilege  Category = "elevation-of-privilege"
	SupplyChain           Category = "supply-chain"
	SecretsExposure       Category = "secrets"
)

// Title returns a display name for the category.
func (c Category) Title() string {
	switch c {
	case Spoofing:
		return "Spoofing"
	case Tampering:
		return "Tampering"
	case Repudiation:
		return "Repudiation"
	case InformationDisclosure:
		return "Information disclosure"
	case DenialOfService:
		return "Denial of service"
	case ElevationOfPrivilege:
		return "Elevation of privilege"
	case SupplyChain:
		return "Supply chain"
	case SecretsExposure:
		return "Secrets exposure"
	}
	return string(c)
}

var allCategories = []Category{
	Spoofing, Tampering, Repudiation, InformationDisclosure,
	DenialOfService, ElevationOfPrivilege, SupplyChain, SecretsExposure,
}

// Categories returns every known category in display order.
func Categories() []Category { return append([]Category(nil), allCategories...) }

// Near constrains a match by what surrounds it. It is what turns a naive
// "there is a new route" pattern into the far more useful "there is a new route
// and nothing that looks like an authorization check anywhere near it".
type Near struct {
	// Present requires at least one of these patterns nearby.
	Present []string `json:"present,omitempty"`
	// Absent requires that none of these patterns appear nearby.
	Absent []string `json:"absent,omitempty"`
	// Window is the number of lines to look at on each side. Default 5.
	Window int `json:"window,omitempty"`
	// Scope is "hunk" (default) or "file": how far the window may reach.
	Scope string `json:"scope,omitempty"`
}

// Rule is one declarative check.
type Rule struct {
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	Category Category `json:"category"`

	Severity   Severity   `json:"severity"`
	Confidence Confidence `json:"confidence,omitempty"`
	Trigger    Trigger    `json:"on,omitempty"`

	// Languages restricts the rule to files of these languages (see langs.go).
	Languages []string `json:"languages,omitempty"`
	// Paths restricts the rule to matching paths. A pattern without a "/"
	// matches the file name at any depth.
	Paths        []string `json:"paths,omitempty"`
	ExcludePaths []string `json:"exclude_paths,omitempty"`

	// Patterns are RE2 regexes; any match fires the rule. When empty the rule
	// is path-only and fires once per matching file.
	Patterns        []string `json:"patterns,omitempty"`
	ExcludePatterns []string `json:"exclude_patterns,omitempty"`
	Near            *Near    `json:"near,omitempty"`

	// FileEvents limits a path-only rule to certain file statuses
	// (created|deleted|renamed|modified).
	FileEvents []string `json:"file_events,omitempty"`

	// Question is what the reviewer is asked. This is the product.
	Question string `json:"question"`
	// Guidance tells the reviewer how to answer the question.
	Guidance string `json:"guidance,omitempty"`

	References []string `json:"references,omitempty"`
	CWE        []string `json:"cwe,omitempty"`
	OWASP      []string `json:"owasp,omitempty"`
	Tags       []string `json:"tags,omitempty"`

	// Redact marks a rule whose matched text must never be echoed verbatim
	// (secret detectors). Findings are shown masked.
	Redact bool `json:"redact,omitempty"`

	// Enabled defaults to true; set false to ship a rule in the pack but off.
	Enabled *bool `json:"enabled,omitempty"`
}

// On returns the effective trigger.
func (r *Rule) On() Trigger {
	if r.Trigger == "" {
		if len(r.Patterns) == 0 {
			return OnFile
		}
		return OnAdded
	}
	return r.Trigger
}

// Conf returns the effective confidence.
func (r *Rule) Conf() Confidence {
	if r.Confidence == "" {
		return ConfMedium
	}
	return r.Confidence
}

// IsEnabled reports whether the rule should run.
func (r *Rule) IsEnabled() bool { return r.Enabled == nil || *r.Enabled }

// Pack is a named collection of rules, the unit of distribution.
type Pack struct {
	Version     int     `json:"version"`
	Name        string  `json:"name,omitempty"`
	Description string  `json:"description,omitempty"`
	Rules       []*Rule `json:"rules"`
}

// Compiled is a Rule with its regexes and globs prepared for matching.
type Compiled struct {
	*Rule

	Patterns        []*regexp.Regexp
	ExcludePatterns []*regexp.Regexp
	NearPresent     []*regexp.Regexp
	NearAbsent      []*regexp.Regexp
	NearWindow      int
	NearFileScope   bool

	paths        []*regexp.Regexp
	excludePaths []*regexp.Regexp
	languages    map[string]bool
	fileEvents   map[string]bool
}

// MatchesPath reports whether the rule applies to the given path and language.
func (c *Compiled) MatchesPath(p, lang string) bool {
	for _, ex := range c.excludePaths {
		if ex.MatchString(p) {
			return false
		}
	}
	if len(c.languages) > 0 && !c.languages[lang] {
		return false
	}
	if len(c.paths) == 0 {
		return true
	}
	for _, g := range c.paths {
		if g.MatchString(p) {
			return true
		}
	}
	return false
}

// MatchesEvent reports whether a path-only rule applies to a file status.
func (c *Compiled) MatchesEvent(status string) bool {
	if len(c.fileEvents) == 0 {
		return true
	}
	return c.fileEvents[status]
}

// Set is a validated, compiled collection of rules.
type Set struct {
	Rules  []*Compiled
	byID   map[string]*Compiled
	Origin []string // pack names, for `threatdiff rules list`
}

// Len returns the number of enabled rules.
func (s *Set) Len() int { return len(s.Rules) }

// ByID returns a rule by identifier.
func (s *Set) ByID(id string) (*Compiled, bool) {
	c, ok := s.byID[id]
	return c, ok
}

// IDs returns every rule identifier, sorted.
func (s *Set) IDs() []string {
	out := make([]string, 0, len(s.Rules))
	for _, r := range s.Rules {
		out = append(out, r.ID)
	}
	sort.Strings(out)
	return out
}

var idRe = regexp.MustCompile(`^[a-z0-9]+(?:[.\-][a-z0-9]+)*$`)

// Compile validates and prepares packs for matching. Rules from later packs
// override earlier ones with the same ID, which is how a repository customises
// the builtin pack without forking it.
func Compile(packs ...*Pack) (*Set, error) {
	set := &Set{byID: map[string]*Compiled{}}
	order := []string{}

	for _, pk := range packs {
		if pk == nil {
			continue
		}
		if pk.Version != 0 && pk.Version != 1 {
			return nil, fmt.Errorf("rule pack %q: unsupported version %d (this build understands version 1)", pk.Name, pk.Version)
		}
		if pk.Name != "" {
			set.Origin = append(set.Origin, pk.Name)
		}
		for _, r := range pk.Rules {
			c, err := compileRule(r)
			if err != nil {
				return nil, fmt.Errorf("rule pack %q: %w", pk.Name, err)
			}
			if _, exists := set.byID[c.ID]; !exists {
				order = append(order, c.ID)
			}
			set.byID[c.ID] = c
		}
	}

	for _, id := range order {
		c := set.byID[id]
		if c.IsEnabled() {
			set.Rules = append(set.Rules, c)
		}
	}
	sort.SliceStable(set.Rules, func(i, j int) bool {
		if a, b := set.Rules[i].Severity.Rank(), set.Rules[j].Severity.Rank(); a != b {
			return a > b
		}
		return set.Rules[i].ID < set.Rules[j].ID
	})
	return set, nil
}

// CompileOne validates and prepares a single rule. It exists for detectors
// that are implemented in Go rather than as patterns (see the entropy detector
// in the analyze package) but still need to present themselves as ordinary
// rules to the rest of the pipeline.
func CompileOne(r *Rule) (*Compiled, error) { return compileRule(r) }

func compileRule(r *Rule) (*Compiled, error) {
	if r == nil {
		return nil, fmt.Errorf("empty rule entry")
	}
	if r.ID == "" {
		return nil, fmt.Errorf("rule is missing `id`")
	}
	if !idRe.MatchString(r.ID) {
		return nil, fmt.Errorf("rule %q: id must be lowercase alphanumerics separated by `.` or `-`", r.ID)
	}
	if r.Title == "" {
		return nil, fmt.Errorf("rule %q: missing `title`", r.ID)
	}
	if !r.Severity.Valid() {
		return nil, fmt.Errorf("rule %q: invalid severity %q", r.ID, r.Severity)
	}
	if r.Confidence != "" && !r.Confidence.Valid() {
		return nil, fmt.Errorf("rule %q: invalid confidence %q", r.ID, r.Confidence)
	}
	if !isKnownCategory(r.Category) {
		return nil, fmt.Errorf("rule %q: invalid category %q (want one of %s)", r.ID, r.Category, categoryList())
	}
	switch r.On() {
	case OnAdded, OnRemoved, OnAny, OnFile:
	default:
		return nil, fmt.Errorf("rule %q: invalid `on: %s` (want added|removed|any|file)", r.ID, r.Trigger)
	}
	if r.Question == "" {
		return nil, fmt.Errorf("rule %q: missing `question` - a rule that cannot tell a reviewer what to check is noise", r.ID)
	}
	if len(r.Patterns) == 0 && len(r.Paths) == 0 {
		return nil, fmt.Errorf("rule %q: needs at least one of `patterns` or `paths`", r.ID)
	}
	if len(r.Patterns) == 0 && r.On() != OnFile {
		return nil, fmt.Errorf("rule %q: `on: %s` requires `patterns`", r.ID, r.On())
	}

	c := &Compiled{Rule: r, NearWindow: 5}

	var err error
	if c.Patterns, err = compileAll(r.ID, "patterns", r.Patterns); err != nil {
		return nil, err
	}
	if c.ExcludePatterns, err = compileAll(r.ID, "exclude_patterns", r.ExcludePatterns); err != nil {
		return nil, err
	}
	if r.Near != nil {
		if len(r.Near.Present) == 0 && len(r.Near.Absent) == 0 {
			return nil, fmt.Errorf("rule %q: `near` needs `present` or `absent`", r.ID)
		}
		if c.NearPresent, err = compileAll(r.ID, "near.present", r.Near.Present); err != nil {
			return nil, err
		}
		if c.NearAbsent, err = compileAll(r.ID, "near.absent", r.Near.Absent); err != nil {
			return nil, err
		}
		if r.Near.Window > 0 {
			c.NearWindow = r.Near.Window
		}
		switch r.Near.Scope {
		case "", "hunk":
		case "file":
			c.NearFileScope = true
		default:
			return nil, fmt.Errorf("rule %q: `near.scope` must be hunk or file", r.ID)
		}
	}

	if c.paths, err = compileGlobs(r.ID, "paths", r.Paths); err != nil {
		return nil, err
	}
	if c.excludePaths, err = compileGlobs(r.ID, "exclude_paths", r.ExcludePaths); err != nil {
		return nil, err
	}

	if len(r.Languages) > 0 {
		c.languages = map[string]bool{}
		for _, l := range r.Languages {
			l = strings.ToLower(strings.TrimSpace(l))
			if !KnownLanguage(l) {
				return nil, fmt.Errorf("rule %q: unknown language %q (see `threatdiff rules languages`)", r.ID, l)
			}
			c.languages[l] = true
		}
	}
	if len(r.FileEvents) > 0 {
		c.fileEvents = map[string]bool{}
		for _, e := range r.FileEvents {
			e = strings.ToLower(strings.TrimSpace(e))
			switch e {
			case "created", "deleted", "renamed", "modified":
				c.fileEvents[e] = true
			default:
				return nil, fmt.Errorf("rule %q: unknown file event %q", r.ID, e)
			}
		}
	}
	return c, nil
}

func compileAll(id, field string, pats []string) ([]*regexp.Regexp, error) {
	out := make([]*regexp.Regexp, 0, len(pats))
	for _, p := range pats {
		if strings.TrimSpace(p) == "" {
			return nil, fmt.Errorf("rule %q: empty pattern in `%s`", id, field)
		}
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("rule %q: %s: %w (note: RE2 has no lookaround or backreferences)", id, field, err)
		}
		out = append(out, re)
	}
	return out, nil
}

func isKnownCategory(c Category) bool {
	for _, k := range allCategories {
		if c == k {
			return true
		}
	}
	return false
}

func categoryList() string {
	parts := make([]string, len(allCategories))
	for i, c := range allCategories {
		parts[i] = string(c)
	}
	return strings.Join(parts, "|")
}
