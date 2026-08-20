package analyze

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/ggeorgeazevedo/threatdiff/internal/config"
	"github.com/ggeorgeazevedo/threatdiff/internal/diff"
	"github.com/ggeorgeazevedo/threatdiff/internal/rules"
)

// Engine matches a compiled rule set against diffs.
type Engine struct {
	set *rules.Set
	cfg *config.Config

	exclude     []*regexp.Regexp
	entropyExcl []*regexp.Regexp
	baseline    map[string]string
	sevOverride map[string]rules.Severity
	disabled    map[string]bool
	only        map[string]bool
	minConf     int
}

// New builds an engine. baseline may be nil.
func New(set *rules.Set, cfg *config.Config, baseline map[string]string) (*Engine, error) {
	if cfg == nil {
		cfg = &config.Config{}
	}
	e := &Engine{
		set:         set,
		cfg:         cfg,
		baseline:    baseline,
		sevOverride: map[string]rules.Severity{},
		disabled:    map[string]bool{},
		only:        map[string]bool{},
		minConf:     1,
	}

	var err error
	if e.exclude, err = compileGlobList("exclude_paths", cfg.ExcludePaths); err != nil {
		return nil, err
	}
	if e.entropyExcl, err = compileGlobList("entropy.exclude_paths", cfg.Entropy.ExcludePaths); err != nil {
		return nil, err
	}

	for _, id := range cfg.Rules.Disable {
		e.disabled[id] = true
	}
	for _, id := range cfg.Rules.Enable {
		delete(e.disabled, id)
	}
	for _, id := range cfg.Rules.Only {
		e.only[id] = true
	}
	for id, s := range cfg.Rules.Severity {
		sev, err := rules.ParseSeverity(s)
		if err != nil {
			return nil, fmt.Errorf("rules.severity[%s]: %w", id, err)
		}
		if _, ok := set.ByID(id); !ok {
			return nil, fmt.Errorf("rules.severity[%s]: no such rule", id)
		}
		e.sevOverride[id] = sev
	}
	if cfg.MinConfidence != "" {
		c, err := rules.ParseConfidence(cfg.MinConfidence)
		if err != nil {
			return nil, err
		}
		e.minConf = confRank(c)
	}
	return e, nil
}

func compileGlobList(field string, globs []string) ([]*regexp.Regexp, error) {
	out := make([]*regexp.Regexp, 0, len(globs))
	for _, g := range globs {
		re, err := rules.GlobToRegexp(g)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", field, err)
		}
		out = append(out, re)
	}
	return out, nil
}

func confRank(c rules.Confidence) int {
	switch c {
	case rules.ConfHigh:
		return 3
	case rules.ConfMedium:
		return 2
	default:
		return 1
	}
}

// Analyze runs every enabled rule against the diff.
func (e *Engine) Analyze(d *diff.Diff) *Result {
	files, adds, dels := d.Totals()
	res := &Result{
		Stats: Stats{
			FilesChanged:   files,
			Additions:      adds,
			Deletions:      dels,
			Languages:      languageCounts(d),
			RulesEvaluated: e.set.Len(),
		},
	}

	seen := map[string]bool{}
	groups := map[string]*Finding{}

	for i := range d.Files {
		f := &d.Files[i]
		if f.Binary {
			res.Stats.BinaryFiles++
		}
		if e.excluded(f.Path) {
			res.Stats.FilesSkipped++
			continue
		}
		lang := rules.LanguageOf(f.Path)
		fileText := collectText(f)

		for _, rule := range e.set.Rules {
			if e.skipRule(rule.ID) {
				continue
			}
			if !rule.MatchesPath(f.Path, lang) {
				continue
			}
			if rule.On() == rules.OnFile {
				if !rule.MatchesEvent(f.Status.String()) {
					continue
				}
				e.emit(res, seen, groups, e.fileFinding(rule, f))
				continue
			}
			if f.Binary {
				continue
			}
			e.matchLines(res, seen, groups, rule, f, fileText)
		}

		if !f.Binary && e.cfg.Entropy.On() &&
			!e.skipRule(entropyRule.ID) && !e.entropyExcluded(f.Path) {
			for _, fd := range e.entropyFindings(f) {
				e.emit(res, seen, groups, fd)
			}
		}
	}

	sortFindings(res.Findings)
	sortFindings(res.Suppressed)
	return res
}

func (e *Engine) skipRule(id string) bool {
	if len(e.only) > 0 && !e.only[id] {
		return true
	}
	return e.disabled[id]
}

func (e *Engine) excluded(path string) bool {
	for _, re := range e.exclude {
		if re.MatchString(path) {
			return true
		}
	}
	return false
}

func (e *Engine) entropyExcluded(path string) bool {
	for _, re := range e.entropyExcl {
		if re.MatchString(path) {
			return true
		}
	}
	return false
}

// maxOccurrenceLines caps how many repeat locations are listed before the
// report switches to a count.
const maxOccurrenceLines = 8

// emit applies confidence filtering, deduplication, repeat folding and
// suppression, then files the finding in the right bucket.
func (e *Engine) emit(res *Result, seen map[string]bool, groups map[string]*Finding, f *Finding) {
	if f == nil {
		return
	}
	if sev, ok := e.sevOverride[f.RuleID]; ok {
		f.Severity = sev
	}
	if confRank(f.Confidence) < e.minConf {
		return
	}
	key := f.Fingerprint + ":" + itoa(f.Line)
	if seen[key] {
		return
	}
	seen[key] = true

	if reason, ok := e.baseline[f.Fingerprint]; ok {
		f.Suppressed = true
		f.SuppressBy = "baseline"
		f.Reason = reason
	}

	// Fold repeats of the same rule within the same file into the first hit.
	// Suppressed and live findings are grouped separately so a suppression on
	// one line does not hide an unsuppressed match on another.
	gkey := f.RuleID + "\x00" + f.File
	if f.Suppressed {
		gkey = "suppressed\x00" + gkey
	}
	if first, ok := groups[gkey]; ok {
		first.Occurrences++
		if len(first.OtherLines) < maxOccurrenceLines && f.Line > 0 {
			first.OtherLines = append(first.OtherLines, f.Line)
		}
		first.RelatedFingerprints = append(first.RelatedFingerprints, f.Fingerprint)
		return
	}
	f.Occurrences = 1
	groups[gkey] = f

	if f.Suppressed {
		res.Suppressed = append(res.Suppressed, f)
		return
	}
	res.Findings = append(res.Findings, f)
}

func (e *Engine) fileFinding(rule *rules.Compiled, f *diff.File) *Finding {
	line := 1
	if len(f.Hunks) > 0 {
		line = f.Hunks[0].NewStart
	}
	if f.Status == diff.Deleted {
		line = 0
	}
	fd := newFinding(rule, f.Path, line, 0, "", f.Path, "")
	fd.Snippet = f.Status.String() + " " + f.Path
	if f.OldPath != "" && f.OldPath != f.Path {
		fd.Snippet += " (was " + f.OldPath + ")"
	}
	fd.Match = ""
	return fd
}

func (e *Engine) matchLines(res *Result, seen map[string]bool, groups map[string]*Finding, rule *rules.Compiled, f *diff.File, fileText []string) {
	trig := rule.On()
	for hi := range f.Hunks {
		h := &f.Hunks[hi]
		anchors := anchorLines(h)
		for li := range h.Lines {
			l := h.Lines[li]
			if !triggerMatches(trig, l.Kind) {
				continue
			}
			if strings.TrimSpace(l.Text) == "" {
				continue
			}
			match := firstMatch(rule.Patterns, l.Text)
			if match == "" {
				continue
			}
			if anyMatch(rule.ExcludePatterns, l.Text) {
				continue
			}
			if !e.nearOK(rule, h, li, fileText) {
				continue
			}

			fd := newFinding(rule, f.Path, anchors[li], l.OldLine, h.Section, l.Text, match)
			if reason, by, ok := suppressedAt(h, li, rule.ID); ok {
				fd.Suppressed = true
				fd.SuppressBy = by
				fd.Reason = reason
			}
			e.emit(res, seen, groups, fd)
		}
	}
}

func lineNumber(l diff.Line) int {
	if l.NewLine > 0 {
		return l.NewLine
	}
	return l.OldLine
}

// anchorLines maps every line of a hunk onto a line number that exists in the
// post-image.
//
// Deleted lines have no line in the new file, but a review UI - and SARIF - can
// only annotate lines that still exist. Anchoring a removal to the nearest
// surviving line above it is what puts "you deleted the authorization check"
// next to the place where the check used to be, rather than nowhere.
func anchorLines(h *diff.Hunk) []int {
	out := make([]int, len(h.Lines))
	last := h.NewStart
	if last < 1 {
		last = 1
	}
	for i, l := range h.Lines {
		if l.NewLine > 0 {
			last = l.NewLine
		}
		out[i] = last
	}
	return out
}

func triggerMatches(t rules.Trigger, k diff.Kind) bool {
	switch t {
	case rules.OnAdded:
		return k == diff.Added
	case rules.OnRemoved:
		return k == diff.Removed
	case rules.OnAny:
		return k == diff.Added || k == diff.Removed
	}
	return false
}

func firstMatch(res []*regexp.Regexp, s string) string {
	for _, re := range res {
		if m := re.FindString(s); m != "" {
			return m
		}
		// A pattern can match an empty string (e.g. an optional group only);
		// treat a successful match with no text as the whole line.
		if re.MatchString(s) {
			return s
		}
	}
	return ""
}

func anyMatch(res []*regexp.Regexp, s string) bool {
	for _, re := range res {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

// nearOK evaluates the rule's `near` constraint.
func (e *Engine) nearOK(rule *rules.Compiled, h *diff.Hunk, li int, fileText []string) bool {
	if len(rule.NearPresent) == 0 && len(rule.NearAbsent) == 0 {
		return true
	}
	var window []string
	if rule.NearFileScope {
		window = fileText
	} else {
		lo := li - rule.NearWindow
		if lo < 0 {
			lo = 0
		}
		hi := li + rule.NearWindow + 1
		if hi > len(h.Lines) {
			hi = len(h.Lines)
		}
		window = make([]string, 0, hi-lo)
		for _, l := range h.Lines[lo:hi] {
			window = append(window, l.Text)
		}
		// The hunk section header carries the enclosing function signature,
		// which frequently holds the decorator or guard we are looking for.
		if h.Section != "" {
			window = append(window, h.Section)
		}
	}

	if len(rule.NearAbsent) > 0 {
		for _, re := range rule.NearAbsent {
			for _, t := range window {
				if re.MatchString(t) {
					return false
				}
			}
		}
	}
	if len(rule.NearPresent) > 0 {
		found := false
		for _, re := range rule.NearPresent {
			for _, t := range window {
				if re.MatchString(t) {
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func collectText(f *diff.File) []string {
	var out []string
	for i := range f.Hunks {
		if f.Hunks[i].Section != "" {
			out = append(out, f.Hunks[i].Section)
		}
		for _, l := range f.Hunks[i].Lines {
			out = append(out, l.Text)
		}
	}
	return out
}

func newFinding(rule *rules.Compiled, path string, line, oldLine int, section, text, match string) *Finding {
	fd := &Finding{
		RuleID:      rule.ID,
		Title:       rule.Title,
		Category:    rule.Category,
		Severity:    rule.Severity,
		Confidence:  rule.Conf(),
		Trigger:     rule.On(),
		File:        path,
		Line:        line,
		OldLine:     oldLine,
		Section:     cleanSection(section),
		Question:    strings.TrimSpace(rule.Question),
		Guidance:    strings.TrimRight(rule.Guidance, "\n"),
		CWE:         rule.CWE,
		OWASP:       rule.OWASP,
		Refs:        rule.References,
		Tags:        rule.Tags,
		Fingerprint: fingerprint(rule.ID, path, text),
	}
	fd.Snippet = display(text, rule.Redact, match)
	fd.Match = display(match, rule.Redact, match)
	return fd
}

// cleanSection trims git's section heading to something readable.
func cleanSection(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 80 {
		s = s[:77] + "..."
	}
	return s
}
