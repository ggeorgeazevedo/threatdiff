package analyze

import "strings"

// maxSnippet caps how much of a changed line is echoed back. PR comments and
// terminal output both become unreadable past this, and a long line is usually
// minified output that nobody wants to read anyway.
const maxSnippet = 200

// display prepares text for output: trimmed, redacted when the rule handles
// credentials, and truncated.
//
// Redaction matters more than it looks. A findings comment on a public pull
// request is world-readable, and a tool that quotes the secret it just found
// has published it a second time - this time somewhere indexed.
func display(text string, redact bool, secret string) string {
	s := strings.TrimSpace(text)
	if s == "" {
		return ""
	}
	if redact {
		s = redactSecret(s, secret)
	}
	return truncate(s, maxSnippet)
}

func redactSecret(line, secret string) string {
	secret = strings.TrimSpace(secret)
	if secret == "" || len(secret) < 4 {
		return Mask(line)
	}
	if !strings.Contains(line, secret) {
		return Mask(line)
	}
	return strings.ReplaceAll(line, secret, Mask(secret))
}

// Mask replaces a value with a fixed-shape placeholder that keeps just enough
// of a prefix to recognise the provider (AKIA..., ghp_..., -----BEGIN...)
// without disclosing anything usable.
func Mask(s string) string {
	s = strings.TrimSpace(s)
	switch {
	case len(s) <= 6:
		return "[redacted]"
	case len(s) <= 16:
		return s[:3] + "[redacted]"
	default:
		return s[:4] + "[redacted " + itoa(len(s)-4) + " chars]"
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	// Cut on a rune boundary.
	cut := n - 3
	for cut > 0 && !isRuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "..."
}

func isRuneStart(b byte) bool { return b&0xC0 != 0x80 }
