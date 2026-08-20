package analyze

import (
	"strings"

	"github.com/ggeorgeazevedo/threatdiff/internal/diff"
)

// Marker is the inline suppression keyword.
const Marker = "threatdiff:ignore"

// Suppression syntax, accepted on the matched line or the line directly above:
//
//	// threatdiff:ignore -- placeholder value used in the example config
//	# threatdiff:ignore[crypto.weak-hash-for-security] etag only, not security
//	// threatdiff:ignore secret.generic-credential-assignment -- public sandbox key
//
// A bare marker with no rule id suppresses every rule on that line. A reason is
// not syntactically required, but the reporters call out suppressions that lack
// one: "ignored, no reason given" is exactly the thing a reviewer should see.
func suppressedAt(h *diff.Hunk, li int, ruleID string) (reason, by string, ok bool) {
	if r, y, found := parseSuppression(h.Lines[li].Text, ruleID); found {
		return r, y, true
	}
	if li > 0 {
		if r, y, found := parseSuppression(h.Lines[li-1].Text, ruleID); found {
			return r, y, true
		}
	}
	return "", "", false
}

func parseSuppression(text, ruleID string) (reason, by string, ok bool) {
	idx := strings.Index(text, Marker)
	if idx < 0 {
		return "", "", false
	}
	rest := strings.TrimSpace(text[idx+len(Marker):])

	var idPart string
	switch {
	case strings.HasPrefix(rest, "["):
		end := strings.Index(rest, "]")
		if end < 0 {
			return "", "", false
		}
		idPart = rest[1:end]
		rest = strings.TrimSpace(rest[end+1:])
	default:
		// Everything up to "--" (or the first word, if there is no "--") is
		// treated as the rule list when it looks like a rule id.
		head, tail, hasSep := strings.Cut(rest, "--")
		head = strings.TrimSpace(head)
		if hasSep {
			idPart = head
			rest = strings.TrimSpace(tail)
		} else if first, remainder, _ := strings.Cut(head, " "); looksLikeRuleID(first) {
			idPart = first
			rest = strings.TrimSpace(remainder)
		} else {
			rest = head
		}
	}

	reason = strings.TrimSpace(strings.TrimLeft(rest, ":-"))
	// Strip whatever closes the host language's comment, so the reason reads as
	// a sentence rather than trailing punctuation from the syntax around it.
	for _, closer := range []string{"*/", "-->", "#}", "--}}", "}}", "]]"} {
		if strings.HasSuffix(reason, closer) {
			reason = strings.TrimSpace(strings.TrimSuffix(reason, closer))
			break
		}
	}

	if idPart == "" {
		return reason, "inline", true
	}
	for _, id := range strings.FieldsFunc(idPart, func(r rune) bool { return r == ',' || r == ' ' }) {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if id == ruleID {
			return reason, "inline", true
		}
		// Prefix form: "crypto.*" suppresses the whole family.
		if strings.HasSuffix(id, "*") && strings.HasPrefix(ruleID, strings.TrimSuffix(id, "*")) {
			return reason, "inline", true
		}
	}
	return "", "", false
}

func looksLikeRuleID(s string) bool {
	if s == "" || !strings.ContainsAny(s, ".-") {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-', r == '_', r == '*', r == ',':
		default:
			return false
		}
	}
	return true
}
