# Configuration

threatdiff runs with no configuration at all. Everything here is for tuning it to a specific
repository.

The file is looked for, in order, at:

1. `.threatdiff.yaml`
2. `.threatdiff.yml`
3. `.threatdiff/config.yaml`
4. `.github/threatdiff.yaml`

Or pass `--config path`. `threatdiff init` writes a commented starter.

Command-line flags override the file.

---

## Full reference

```yaml
version: 1

# ── the gate ────────────────────────────────────────────────────────────────
# Empty means the run never fails a build. Start here.
fail_on: critical        # critical | high | medium | low | info
fail_score: 0            # or gate on the 0-100 risk score; 0 disables

# ── filtering ───────────────────────────────────────────────────────────────
min_confidence: low      # high | medium | low - drop anything below

exclude_paths:           # skipped before any rule runs
  - "vendor/**"
  - "node_modules/**"
  - "**/*.generated.*"
  - "**/*_pb2.py"
  - "**/dist/**"

# ── inputs ──────────────────────────────────────────────────────────────────
baseline: .threatdiff-baseline.json
rule_paths:
  - .threatdiff/rules    # a file or a directory, searched recursively

# ── rule set tuning ─────────────────────────────────────────────────────────
rules:
  disable:
    - dos.retry-without-backoff
  enable:                # re-enable something disabled elsewhere
    - crypto.kdf-parameters-lowered
  only:                  # when non-empty, run ONLY these. Mostly for debugging.
    []
  severity:              # retune without writing a rule
    crypto.weak-hash-for-security: low
    authz.new-endpoint-without-auth: critical

# ── the entropy detector ────────────────────────────────────────────────────
entropy:
  enabled: true
  min_entropy: 3.6       # Shannon bits per character
  min_length: 20
  exclude_paths:
    - "docs/**"

# ── the risk model ──────────────────────────────────────────────────────────
scoring:
  base:                  # points per severity, before multipliers
    critical: 40
    high: 24
    medium: 10
    low: 4
    info: 1
  removal_multiplier: 1.3
  lead_scale: 38         # how quickly the worst finding sets its floor
  saturation: 70         # how quickly the remaining findings stop adding
  blast_radius_weight: 15
  bands:
    critical: 75
    high: 45
    medium: 20
    low: 5

# ── reviewer routing ────────────────────────────────────────────────────────
review:
  default: ["@org/appsec"]
  mention: true          # @-mention reviewers in the Markdown comment
  routes:
    - name: access control
      categories: [elevation-of-privilege, spoofing]
      min_severity: high
      reviewers: ["@org/appsec-authz"]
    - name: infrastructure
      paths: ["**/*.tf", ".github/workflows/**", "**/Dockerfile*"]
      reviewers: ["@org/platform-security"]
    - name: crypto family
      rules: ["crypto.*"]
      reviewers: ["@alice"]
```

Unknown fields are rejected with a line number. A typo in a config file should fail loudly
rather than silently disabling something.

---

## Notes on individual settings

### `fail_on` and `fail_score`

Either may be set; either one tripping fails the run. `fail_on` compares against the worst live
severity, so `fail_on: high` also fails on a critical.

The recommended progression is `""` → `critical` → `high`, over weeks, with a baseline written
before the first non-empty value. See [adoption.md](adoption.md).

### `min_confidence`

The quickest lever when the checklist is too long. `min_confidence: medium` removes the
heuristic rules — the ones that ask good questions and are often wrong — and leaves the
specific ones.

Prefer this over disabling rules while you are still calibrating: it is one line to undo.

### `exclude_paths` vs a rule's own `exclude_paths`

The top-level list is checked before any rule runs, so it is also the fastest. Use it for
generated and vendored code. Use a rule's own `exclude_paths` when only that rule is wrong about
a path.

Globs support `**`, `*`, `?` and `{a,b}`. A pattern with no `/` matches the file name at any
depth, so `*.tf` means what you expect rather than "*.tf in the root only".

### `rules.severity`

Retuning severity is usually better than disabling. A rule at `low` still appears in the
checklist, still gets a question asked, and contributes almost nothing to the score. A disabled
rule teaches the team nothing.

### `entropy`

The statistical secret detector: it catches credential formats nobody has written a pattern for.
It is the noisiest thing in the tool by design, and it is tuned to compensate — a candidate must
be assigned to a credential-shaped identifier, be long enough, mix character classes, and clear
the entropy threshold. Lockfiles, minified bundles, snapshots, fixtures and vendored code are
skipped automatically.

Raising `min_entropy` to `4.2` makes it much quieter. Turning it off entirely is a real option if
you already run a dedicated secret scanner — but check that the other scanner also looks at the
diff of every pull request, not just at the default branch on a schedule.

### `scoring`

Change these when your team's sense of severity differs from the defaults, and write down why.
The two that matter most:

- **`removal_multiplier`** — how much more a deleted control weighs than added risk. Lower it if
  your codebase does a lot of legitimate refactoring of security helpers.
- **`saturation`** — how quickly extra findings stop adding score. Lower means a long list
  reaches the ceiling sooner; higher means only genuinely large piles do.

### `review`

Routes are additive: a finding matching two routes gets both sets of reviewers. When no route
matches, threatdiff reads `CODEOWNERS` (`.github/CODEOWNERS`, `CODEOWNERS`, `docs/CODEOWNERS`,
with GitHub's last-match-wins semantics), and only then falls back to `default`.

A route with no `reviewers` is a configuration error, not a no-op: a rule that routes to nobody
is a rule that routes to nobody.

Set `mention: false` if you want the routing shown in the table but not as an `@`-mention — some
teams find the notifications more annoying than useful in the first weeks.

---

## Environment

| Variable | Effect |
| --- | --- |
| `NO_COLOR` | Disables ANSI output. |
| `FORCE_COLOR` | Enables ANSI output even when stdout is not a terminal (CI logs). |
| `GITHUB_BASE_REF`, `CI_MERGE_REQUEST_TARGET_BRANCH_NAME`, `CHANGE_TARGET` | Auto-detected base branch. |

Colour is off automatically when output is redirected to a file.
