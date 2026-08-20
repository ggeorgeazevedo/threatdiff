// Package owners decides who should look at each finding.
//
// The bottleneck in application security is rarely detection; it is getting the
// right pair of eyes onto the right ten lines. A finding routed to "the security
// team" is a queue. The same finding routed to the two people who own that
// service, with the question already written, is a conversation.
package owners

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/ggeorgeazevedo/threatdiff/internal/analyze"
	"github.com/ggeorgeazevedo/threatdiff/internal/config"
	"github.com/ggeorgeazevedo/threatdiff/internal/rules"
)

// Router assigns reviewers to findings.
type Router struct {
	routes     []compiledRoute
	fallback   []string
	codeowners *Codeowners
	mention    bool
}

type compiledRoute struct {
	name        string
	categories  map[rules.Category]bool
	rulePrefix  []string
	ruleExact   map[string]bool
	paths       []*regexp.Regexp
	minSeverity rules.Severity
	reviewers   []string
}

// New compiles a review configuration.
func New(cfg config.ReviewConfig) (*Router, error) {
	r := &Router{fallback: cfg.Default, mention: cfg.ShouldMention()}
	for i, route := range cfg.Routes {
		cr := compiledRoute{
			name:      route.Name,
			reviewers: route.Reviewers,
			ruleExact: map[string]bool{},
		}
		if len(route.Reviewers) == 0 {
			return nil, fmt.Errorf("review.routes[%d]: no reviewers listed", i)
		}
		if len(route.Categories) > 0 {
			cr.categories = map[rules.Category]bool{}
			for _, c := range route.Categories {
				cr.categories[rules.Category(strings.ToLower(strings.TrimSpace(c)))] = true
			}
		}
		for _, id := range route.Rules {
			if strings.HasSuffix(id, "*") {
				cr.rulePrefix = append(cr.rulePrefix, strings.TrimSuffix(id, "*"))
			} else {
				cr.ruleExact[id] = true
			}
		}
		for _, g := range route.Paths {
			re, err := rules.GlobToRegexp(g)
			if err != nil {
				return nil, fmt.Errorf("review.routes[%d].paths: %w", i, err)
			}
			cr.paths = append(cr.paths, re)
		}
		if route.MinSeverity != "" {
			sev, err := rules.ParseSeverity(route.MinSeverity)
			if err != nil {
				return nil, fmt.Errorf("review.routes[%d]: %w", i, err)
			}
			cr.minSeverity = sev
		}
		r.routes = append(r.routes, cr)
	}
	return r, nil
}

// WithCodeowners attaches a parsed CODEOWNERS file, used when no explicit route
// matches. This means a repository gets useful routing with no threatdiff
// configuration at all.
func (r *Router) WithCodeowners(co *Codeowners) *Router {
	r.codeowners = co
	return r
}

// Mention reports whether reviewers should be @-mentioned in output.
func (r *Router) Mention() bool { return r.mention }

// Route returns the reviewers for one finding.
func (r *Router) Route(f *analyze.Finding) []string {
	var out []string
	for _, route := range r.routes {
		if route.matches(f) {
			out = append(out, route.reviewers...)
		}
	}
	if len(out) == 0 && r.codeowners != nil {
		out = append(out, r.codeowners.Owners(f.File)...)
	}
	if len(out) == 0 {
		out = append(out, r.fallback...)
	}
	return dedupe(out)
}

func (c compiledRoute) matches(f *analyze.Finding) bool {
	if c.minSeverity != "" && f.Severity.Rank() < c.minSeverity.Rank() {
		return false
	}
	// An empty route (no selectors) matches everything at or above minSeverity.
	selectors := 0
	if c.categories != nil {
		selectors++
		if !c.categories[f.Category] {
			return false
		}
	}
	if len(c.ruleExact) > 0 || len(c.rulePrefix) > 0 {
		selectors++
		hit := c.ruleExact[f.RuleID]
		if !hit {
			for _, p := range c.rulePrefix {
				if strings.HasPrefix(f.RuleID, p) {
					hit = true
					break
				}
			}
		}
		if !hit {
			return false
		}
	}
	if len(c.paths) > 0 {
		selectors++
		hit := false
		for _, re := range c.paths {
			if re.MatchString(f.File) {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	if selectors == 0 && c.minSeverity == "" {
		return false
	}
	return true
}

// Apply annotates every finding with its reviewers and returns the inverse
// index, reviewer -> findings, sorted for stable output.
func (r *Router) Apply(res *analyze.Result) ([]string, map[string][]*analyze.Finding) {
	index := map[string][]*analyze.Finding{}
	for _, f := range res.Findings {
		f.Reviewers = r.Route(f)
		for _, rev := range f.Reviewers {
			index[rev] = append(index[rev], f)
		}
	}
	names := make([]string, 0, len(index))
	for k := range index {
		names = append(names, k)
	}
	sort.Slice(names, func(i, j int) bool {
		if len(index[names[i]]) != len(index[names[j]]) {
			return len(index[names[i]]) > len(index[names[j]])
		}
		return names[i] < names[j]
	})
	return names, index
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := in[:0:0]
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// ---------------------------------------------------------------------------
// CODEOWNERS
// ---------------------------------------------------------------------------

// Codeowners is a parsed CODEOWNERS file. GitHub semantics: the last matching
// pattern wins, and a pattern with no owners clears ownership.
type Codeowners struct {
	Path  string
	rules []coRule
}

type coRule struct {
	re     *regexp.Regexp
	owners []string
}

// CodeownersLocations are the paths GitHub itself checks, in order.
var CodeownersLocations = []string{
	".github/CODEOWNERS",
	"CODEOWNERS",
	"docs/CODEOWNERS",
}

// FindCodeowners looks for a CODEOWNERS file under root. A missing file is not
// an error; it returns (nil, nil).
func FindCodeowners(root string) (*Codeowners, error) {
	for _, name := range CodeownersLocations {
		p := filepath.Join(root, name)
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		defer f.Close()
		co, err := parseCodeowners(f)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		co.Path = p
		return co, nil
	}
	return nil, nil
}

// ParseCodeowners reads CODEOWNERS content.
func ParseCodeowners(r io.Reader) (*Codeowners, error) { return parseCodeowners(r) }

func parseCodeowners(r io.Reader) (*Codeowners, error) {
	co := &Codeowners{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		pattern := fields[0]
		re, err := codeownersGlob(pattern)
		if err != nil {
			// A pattern we cannot compile is skipped rather than fatal: a
			// CODEOWNERS file is not threatdiff's to validate.
			continue
		}
		co.rules = append(co.rules, coRule{re: re, owners: fields[1:]})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return co, nil
}

// Owners returns the owners of a path, or nil.
func (c *Codeowners) Owners(path string) []string {
	if c == nil {
		return nil
	}
	var owners []string
	for _, r := range c.rules {
		if r.re.MatchString(path) {
			owners = r.owners // last match wins
		}
	}
	return owners
}

// codeownersGlob translates CODEOWNERS pattern syntax, which is gitignore-like:
// a leading "/" anchors to the repository root, a trailing "/" matches a
// directory and everything under it, and a bare name matches at any depth.
func codeownersGlob(p string) (*regexp.Regexp, error) {
	anchored := strings.HasPrefix(p, "/")
	dirOnly := strings.HasSuffix(p, "/")
	trimmed := strings.Trim(p, "/")
	if trimmed == "" || trimmed == "*" {
		return regexp.Compile(`^.*$`)
	}

	var b strings.Builder
	b.WriteString("^")
	if !anchored && !strings.Contains(trimmed, "/") {
		b.WriteString("(?:.*/)?")
	}
	for i := 0; i < len(trimmed); i++ {
		switch c := trimmed[i]; c {
		case '*':
			if i+1 < len(trimmed) && trimmed[i+1] == '*' {
				i++
				b.WriteString(".*")
			} else {
				b.WriteString("[^/]*")
			}
		case '?':
			b.WriteString("[^/]")
		case '/':
			b.WriteString("/")
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	if dirOnly || !strings.Contains(trimmed, ".") {
		// Directory patterns cover everything beneath them.
		b.WriteString("(?:/.*)?")
	}
	b.WriteString("$")
	return regexp.Compile(b.String())
}
