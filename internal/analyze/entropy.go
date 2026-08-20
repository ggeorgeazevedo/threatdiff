package analyze

import (
	"math"
	"regexp"
	"strings"

	"github.com/ggeorgeazevedo/threatdiff/internal/diff"
	"github.com/ggeorgeazevedo/threatdiff/internal/rules"
)

// The entropy detector exists because provider-specific patterns only find the
// credentials whose format somebody already wrote a pattern for. Internal
// signing keys, partner API tokens and anything minted by your own service have
// no published prefix, and they leak just as badly.
//
// This is a statistical detector, so it is tuned to be quiet: a candidate must
// be assigned to an identifier that reads like a credential, be long enough to
// be one, mix character classes, and clear a Shannon entropy threshold.

var entropyRuleDef = &rules.Rule{
	ID:         "secret.high-entropy-string",
	Title:      "High-entropy string assigned to a credential-shaped name",
	Category:   rules.SecretsExposure,
	Severity:   rules.High,
	Confidence: rules.ConfLow,
	Trigger:    rules.OnAdded,
	Paths:      []string{"**"},
	Patterns:   []string{"."}, // unused: matching is implemented in Go
	Redact:     true,
	Question: "Is this a real credential? If it is, it must be rotated - " +
		"the value is already in the repository's history.",
	Guidance: `Statistical detection cannot tell a token from a base64-encoded
test fixture, so this finding needs a human answer either way.

If it is a secret: rotate first, then remove it. Deleting the line in a later
commit does not remove the blob from history.

If it is not: suppress it in place with an inline comment naming the reason, so
the next person to touch this file is not asked the same question again.`,
	CWE: []string{"CWE-798"},
}

var entropyRule *rules.Compiled

func init() {
	c, err := rules.CompileOne(entropyRuleDef)
	if err != nil {
		panic("internal: entropy rule does not compile: " + err.Error())
	}
	entropyRule = c
}

// assignRe captures `name = "value"`, `name: "value"`, `NAME="value"` and the
// bare `NAME=value` form used by env files.
var assignRe = regexp.MustCompile(
	`(?i)([A-Za-z_][A-Za-z0-9_.\-]{2,40})\s*[:=]\s*` +
		"(?:\"([^\"\\s]{8,200})\"|'([^'\\s]{8,200})'|`([^`\\s]{8,200})`|([A-Za-z0-9+/=_\\-]{8,200}))")

// nameHint matches identifiers that plausibly hold a credential. Without this
// the detector fires on every base64 asset and hash in the tree.
var nameHint = regexp.MustCompile(`(?i)(secret|token|key|passw|pwd|credential|auth|api|access|private|signature|sign|salt|cert|session|cookie|bearer|client_?id|nonce|seed)`)

// placeholderRe recognises values that are obviously not real.
var placeholderRe = regexp.MustCompile(`(?i)^(\$\{|\{\{|%\(|<%|process\.env|os\.environ|env\[|ENV\[|null|none|true|false|undefined|changeme|placeholder|redacted|example|sample|dummy|your[_\-]|xxx+|test|fake|todo|fixme|\*+|\.\.\.)`)

// structuralRe skips values that are clearly not opaque secrets.
var structuralRe = regexp.MustCompile(`(?i)^(https?://|/|\./|\.\./|[a-z]+\.[a-z]+\.[a-z]+$|#[0-9a-f]{3,8}$|[0-9]+(\.[0-9]+)+$|[0-9]+$)`)

// noisyPaths are files where high-entropy strings are the norm rather than the
// exception. Scanning them produces findings nobody reads.
var noisyPaths = []string{
	"**/*.lock", "**/*.sum", "**/package-lock.json", "**/yarn.lock",
	"**/pnpm-lock.yaml", "**/Gemfile.lock", "**/poetry.lock", "**/composer.lock",
	"**/*.min.js", "**/*.min.css", "**/*.map", "**/*.snap", "**/*.svg",
	"**/*.ipynb", "**/testdata/**", "**/fixtures/**", "**/__snapshots__/**",
	"**/vendor/**", "**/node_modules/**", "**/*.po", "**/*.mo",
}

var noisyPathRes = func() []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(noisyPaths))
	for _, g := range noisyPaths {
		if re, err := rules.GlobToRegexp(g); err == nil {
			out = append(out, re)
		}
	}
	return out
}()

func (e *Engine) entropyFindings(f *diff.File) []*Finding {
	for _, re := range noisyPathRes {
		if re.MatchString(f.Path) {
			return nil
		}
	}
	minEntropy := e.cfg.Entropy.Entropy()
	minLen := e.cfg.Entropy.Length()

	var out []*Finding
	for hi := range f.Hunks {
		h := &f.Hunks[hi]
		for li := range h.Lines {
			l := h.Lines[li]
			if l.Kind != diff.Added {
				continue
			}
			name, value, ok := candidate(l.Text, minLen)
			if !ok {
				continue
			}
			if ShannonEntropy(value) < minEntropy {
				continue
			}
			if !mixedCharClasses(value) {
				continue
			}
			fd := newFinding(entropyRule, f.Path, lineNumber(l), l.OldLine, h.Section, l.Text, value)
			fd.Title = "High-entropy value assigned to `" + name + "`"
			if reason, by, sup := suppressedAt(h, li, entropyRule.ID); sup {
				fd.Suppressed, fd.SuppressBy, fd.Reason = true, by, reason
			}
			out = append(out, fd)
		}
	}
	return out
}

// candidate extracts a (name, value) pair worth scoring from a line.
func candidate(text string, minLen int) (name, value string, ok bool) {
	m := assignRe.FindStringSubmatch(text)
	if m == nil {
		return "", "", false
	}
	name = m[1]
	for _, g := range m[2:] {
		if g != "" {
			value = g
			break
		}
	}
	if value == "" {
		return "", "", false
	}
	if len(value) < minLen {
		return "", "", false
	}
	if !nameHint.MatchString(name) {
		return "", "", false
	}
	if placeholderRe.MatchString(value) || structuralRe.MatchString(value) {
		return "", "", false
	}
	// A value that is mostly separators is a path or a sentence, not a token.
	if strings.Count(value, "/") > 2 || strings.Count(value, " ") > 0 {
		return "", "", false
	}
	return name, value, true
}

// ShannonEntropy returns the per-character Shannon entropy of s, in bits.
// Random base64 lands around 5.5-6.0; English prose around 3.0-4.0; a
// repetitive placeholder well below that.
func ShannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

// mixedCharClasses requires a candidate to draw on at least three of
// {lower, upper, digit, symbol}, or to be long enough that two suffice.
func mixedCharClasses(s string) bool {
	var lower, upper, digit, symbol bool
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
			lower = true
		case c >= 'A' && c <= 'Z':
			upper = true
		case c >= '0' && c <= '9':
			digit = true
		default:
			symbol = true
		}
	}
	classes := 0
	for _, b := range []bool{lower, upper, digit, symbol} {
		if b {
			classes++
		}
	}
	if classes >= 3 {
		return true
	}
	return classes >= 2 && len(s) >= 32
}
