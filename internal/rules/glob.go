package rules

import (
	"fmt"
	"regexp"
	"strings"
)

// compileGlobs turns path globs into anchored regexes.
//
// Supported syntax:
//
//	**      any number of path segments
//	*       any characters except "/"
//	?       one character except "/"
//	{a,b}   alternation
//	!prefix negation is NOT supported; use exclude_paths instead
//
// A pattern containing no "/" is matched against the file's base name at any
// depth, which is what people mean when they write `*.tf` or `Dockerfile`.
func compileGlobs(ruleID, field string, globs []string) ([]*regexp.Regexp, error) {
	out := make([]*regexp.Regexp, 0, len(globs))
	for _, g := range globs {
		g = strings.TrimSpace(g)
		if g == "" {
			return nil, fmt.Errorf("rule %q: empty glob in `%s`", ruleID, field)
		}
		if strings.HasPrefix(g, "!") {
			return nil, fmt.Errorf("rule %q: `%s`: negated globs are not supported, use exclude_paths", ruleID, field)
		}
		re, err := GlobToRegexp(g)
		if err != nil {
			return nil, fmt.Errorf("rule %q: `%s`: %w", ruleID, field, err)
		}
		out = append(out, re)
	}
	return out, nil
}

// GlobToRegexp converts a path glob into an anchored, case-insensitive regexp.
func GlobToRegexp(g string) (*regexp.Regexp, error) {
	g = strings.TrimPrefix(g, "./")
	anchorBase := !strings.Contains(g, "/")

	var b strings.Builder
	b.WriteString("(?i)^")
	if anchorBase {
		// Match the file name at any depth.
		b.WriteString("(?:.*/)?")
	}

	depth := 0
	for i := 0; i < len(g); i++ {
		c := g[i]
		switch c {
		case '*':
			if i+1 < len(g) && g[i+1] == '*' {
				i++
				// "**/" collapses to "zero or more segments".
				if i+1 < len(g) && g[i+1] == '/' {
					i++
					b.WriteString("(?:[^/]+/)*")
				} else {
					b.WriteString(".*")
				}
			} else {
				b.WriteString("[^/]*")
			}
		case '?':
			b.WriteString("[^/]")
		case '{':
			depth++
			b.WriteString("(?:")
		case '}':
			if depth == 0 {
				return nil, fmt.Errorf("unbalanced `}` in glob %q", g)
			}
			depth--
			b.WriteString(")")
		case ',':
			if depth > 0 {
				b.WriteString("|")
			} else {
				b.WriteString(",")
			}
		case '/':
			b.WriteString("/")
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	if depth != 0 {
		return nil, fmt.Errorf("unbalanced `{` in glob %q", g)
	}
	b.WriteString("$")
	return regexp.Compile(b.String())
}

// MatchGlob is a convenience helper for one-off matching.
func MatchGlob(glob, path string) (bool, error) {
	re, err := GlobToRegexp(glob)
	if err != nil {
		return false, err
	}
	return re.MatchString(path), nil
}
