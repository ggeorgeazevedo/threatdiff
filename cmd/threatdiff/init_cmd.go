package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

const starterConfig = `# threatdiff configuration
# Docs: https://github.com/ggeorgeazevedo/threatdiff/blob/main/docs/configuration.md
version: 1

# Exit non-zero when a finding at this severity or worse appears.
# Start at "critical" and tighten once the noise level is known.
fail_on: critical

# Drop findings below this confidence. The low-confidence rules are the ones
# that ask good questions and are often wrong - keep them on while the team is
# still calibrating, turn them down if the checklist gets ignored.
min_confidence: low

# Paths no rule should look at. Vendored and generated code produces findings
# nobody can act on.
exclude_paths:
  - "vendor/**"
  - "node_modules/**"
  - "**/*.generated.*"
  - "**/*_pb2.py"
  - "**/dist/**"
  - "**/build/**"

# Accept what already exists so the gate only speaks about new change.
# Generate with: threatdiff baseline write
# baseline: .threatdiff-baseline.json

# Your own rules live here and can override builtin ones by reusing their id.
# rule_paths:
#   - .threatdiff/rules

rules:
  # disable:
  #   - dos.retry-without-backoff
  # severity:
  #   crypto.weak-hash-for-security: low

# Route findings to the people who can answer them. Falls back to CODEOWNERS
# when no route matches, and to the "default" list when CODEOWNERS has no entry.
# Fill in the handles and uncomment. A route with no reviewers is rejected on
# purpose: a rule that routes to nobody is a rule that routes to nobody.
# review:
#   default: ["@your-org/appsec"]
#   routes:
#     - name: access control
#       categories: [elevation-of-privilege, spoofing]
#       min_severity: high
#       reviewers: ["@your-org/appsec"]
#     - name: infrastructure
#       paths: ["**/*.tf", ".github/workflows/**", "**/Dockerfile*", "**/*.hcl"]
#       reviewers: ["@your-org/platform"]

# The high-entropy secret detector. Statistical, so it is the noisiest thing
# here - but it is also the only thing that finds a credential format nobody
# has written a pattern for yet.
entropy:
  enabled: true
  min_entropy: 3.6
  min_length: 20
`

const initUsage = `threatdiff init - write a starter configuration

USAGE
  threatdiff init [--out .threatdiff.yaml] [--force]
`

func cmdInit(args []string) int {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	out := fs.String("out", ".threatdiff.yaml", "path to write")
	force := fs.Bool("force", false, "overwrite an existing file")
	fs.Usage = func() { fmt.Fprint(os.Stderr, initUsage) }
	if err := fs.Parse(args); err != nil {
		return exitError
	}

	if _, err := os.Stat(*out); err == nil && !*force {
		return fail("%s already exists (use --force to overwrite)", *out)
	}
	if dir := filepath.Dir(*out); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fail("%v", err)
		}
	}
	if err := os.WriteFile(*out, []byte(starterConfig), 0o644); err != nil {
		return fail("%v", err)
	}
	fmt.Fprintf(os.Stderr, "threatdiff: wrote %s\n", *out)
	fmt.Fprintln(os.Stderr, "threatdiff: next, run `threatdiff scan` on a branch you know is risky and see whether the questions are the ones you would have asked")
	return exitOK
}
