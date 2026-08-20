# threatdiff

**Threat modelling for pull request diffs.** threatdiff reads a `git diff`, works out which
threats the change touches, and hands the reviewer a checklist of questions with the code
already quoted next to each one.

It is not another vulnerability scanner. A scanner reads the file that *results* from a change
and tells you what is wrong with it. threatdiff reads the *change itself* and tells you what to
ask about it — including the things a scanner structurally cannot see, like a deleted
authorization decorator, a dropped tenant filter, or a CSRF exemption that was added last week.

```
threatdiff  risk  89/100   CRITICAL
  22 findings across 6 files   +59/-25 lines in 6 changed files   88 rules

  Threat categories
    Elevation of privilege   ██████████████████ 173.6  6 findings
    Tampering                █████████·········  88.8  4 findings
    Information disclosure   █████████·········  85.8  4 findings
    Supply chain             ██████············  62.0  4 findings
    Spoofing                 █████·············  52.0  2 findings
    Secrets exposure         ███···············  27.6  2 findings

  api/invoices.py
     CRITICAL   Authorization annotation or decorator removed
      line 15 (removed from old line 8) · control.authz-annotation-removed · +52.0
      - @login_required
      ? Which endpoints or handlers stop requiring authorization because of this
        change, and is that intentional?
      → @org/appsec-authz
```

- **Zero dependencies.** Pure Go standard library. An AppSec tool that runs in your pipeline
  should not be the largest supply-chain surface in it.
- **Runs anywhere.** One static binary, or a composite GitHub Action, or a pre-commit hook.
- **Four outputs.** Terminal for the author, a sticky Markdown comment for the reviewer,
  SARIF for GitHub code scanning, JSON for whatever your platform team builds next.
- **88 built-in rules**, every one of them carrying the question a reviewer should answer and
  the guidance to answer it. Add your own in YAML.

---

## Table of contents

- [Why this exists](#why-this-exists)
- [Install](#install)
- [Quick start](#quick-start)
- [In CI](#in-ci)
- [What a finding looks like](#what-a-finding-looks-like)
- [The risk score](#the-risk-score)
- [Suppressions and baselines](#suppressions-and-baselines)
- [Writing your own rules](#writing-your-own-rules)
- [Reviewer routing](#reviewer-routing)
- [Configuration](#configuration)
- [Command reference](#command-reference)
- [How it works](#how-it-works)
- [What it deliberately does not do](#what-it-deliberately-does-not-do)
- [Contributing](#contributing)

---

## Why this exists

Three observations, from the ordinary practice of application security:

**1. The interesting security signal in a change is often a deletion.**

```diff
-@login_required
 @bp.route("/invoices/<invoice_id>")
 def get_invoice(invoice_id):
-    return Invoice.query.filter_by(id=invoice_id, tenant_id=current_user.tenant_id).first()
+    return Invoice.query.filter_by(id=invoice_id).first()
```

Every SAST tool in the world analyses the resulting file. In the resulting file there is no
missing decorator and no missing tenant filter — there is just a route handler that does a
lookup. The finding is in the diff, and only in the diff.

**2. Nobody threat models a pull request.** Threat modelling happens at design time, on a
whiteboard, for a system that then changes 400 times before it ships. The change is where the
risk enters, and the change is exactly where nobody has the time to do the exercise.

**3. Findings without questions get muted.** "Potential SQL injection at line 42" invites a
reviewer to guess whether the tool is right. "Is every value in this statement bound as a
parameter, or is any of it concatenated from caller-controlled input?" invites them to answer.
The second one is what a security engineer would actually have asked, and it is answerable in
thirty seconds by the person who wrote the line.

threatdiff is those three observations turned into a tool. Every rule is a question. Findings
are grouped by STRIDE category, so the output reads like a threat model rather than a lint log.
And roughly a third of the rule set fires on *removed* lines, which is the part no other tool in
your pipeline is looking at.

---

## Install

```bash
# Go 1.22+
go install github.com/ggeorgeazevedo/threatdiff/cmd/threatdiff@latest

# or from source
git clone https://github.com/ggeorgeazevedo/threatdiff && cd threatdiff && make build
# -> bin/threatdiff
```

Release binaries for linux/darwin/windows on amd64 and arm64 are attached to each tagged
release, with `checksums.txt`.

There is nothing to configure to get started: the rule packs are embedded in the binary.

---

## Quick start

```bash
# your working tree against the default branch
threatdiff scan

# an explicit range, the way a pull request sees it (three-dot: head vs merge base)
threatdiff scan --base main --head HEAD

# a patch from anywhere
git diff main... | threatdiff scan --diff -
threatdiff scan --diff some.patch

# only what you have staged - useful as a pre-commit hook
threatdiff scan --staged

# gate a build
threatdiff scan --fail-on high     # exit 1 if a high or critical finding appears
threatdiff scan --fail-score 60    # exit 1 if the risk score reaches 60
```

Exit codes are part of the interface:

| Code | Meaning |
| --- | --- |
| `0` | Analysis completed, gate not triggered |
| `1` | Analysis completed, gate triggered |
| `2` | Could not run (bad flags, unreadable rules, git failure) |

A run with no gate configured never fails a build. That is deliberate: a tool that starts
blocking merges on day one gets removed on day two.

### As a pre-commit hook

`.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: threatdiff
        name: threatdiff
        entry: threatdiff scan --staged --fail-on critical
        language: system
        pass_filenames: false
```

---

## In CI

The GitHub Action posts a sticky review comment, writes the job summary, produces SARIF for code
scanning, and optionally fails the job.

```yaml
name: threatdiff
on:
  pull_request:
    types: [opened, synchronize, reopened, ready_for_review]

permissions:
  contents: read
  pull-requests: write   # to post the checklist
  security-events: write # to upload SARIF

jobs:
  threat-model:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0        # the merge base must exist locally

      - id: threatdiff
        uses: ggeorgeazevedo/threatdiff@v0   # pin to a SHA in production
        with:
          fail-on: ""           # start with no gate; tighten later

      - uses: github/codeql-action/upload-sarif@v3
        if: always() && steps.threatdiff.outputs.sarif-file != ''
        with:
          sarif_file: ${{ steps.threatdiff.outputs.sarif-file }}
          category: threatdiff
```

A fuller example, including labelling high-risk pull requests, is in
[`examples/workflow-pull-request.yml`](examples/workflow-pull-request.yml).

**Action inputs:** `version`, `base-ref`, `head-ref`, `config`, `rules`, `baseline`, `fail-on`,
`fail-score`, `min-confidence`, `comment`, `sarif`, `sarif-file`, `working-directory`,
`github-token`.

**Action outputs:** `score`, `band`, `findings`, `failed`, `sarif-file`, `markdown-file`.

Not on GitHub? Everything the Action does is available from the CLI:

```bash
threatdiff scan \
  --base "origin/$CI_MERGE_REQUEST_TARGET_BRANCH_NAME" \
  --format json --out threatdiff.json \
  --markdown-out threatdiff.md \
  --sarif-out threatdiff.sarif \
  --fail-on critical
```

`--base` is auto-detected from `GITHUB_BASE_REF`, `CI_MERGE_REQUEST_TARGET_BRANCH_NAME` or
`CHANGE_TARGET`, then from `origin/HEAD`, then `main`/`master`, then `HEAD~1`.

---

## What a finding looks like

Every finding carries a location, the changed line, a question, guidance, a STRIDE category, a
severity, a confidence level, a CWE mapping, and a stable fingerprint.

In the Markdown comment it renders as a checklist item:

> - [ ] **Query filter on tenant, account or owner removed** — `api/invoices.py:15` `CRITICAL`
>
>   ```diff
>   - Invoice.query.filter_by(id=invoice_id, tenant_id=current_user.tenant_id)
>   ```
>
>   **Ask:** Does this query still return only rows belonging to the caller's tenant?
>
>   <details><summary>How to answer it</summary>
>
>   Cross-tenant data leaks are the most expensive class of bug in a multi-tenant product and
>   they look exactly like this in a diff. If the filter moved into a shared scope, a base
>   repository or a row-level security policy, name it. …
>   </details>
>
>   <sub>rule `authz.tenant-scope-dropped-from-query` · low confidence · CWE-639 · @org/appsec-authz</sub>

**Severity** is how bad it is if the answer is "yes, that is a problem".
**Confidence** is how often the rule is right when it fires. They are separate on purpose: a
low-confidence critical rule is still worth asking about, it just should not dominate the score.

Repeated hits of one rule in one file are folded into a single item with an occurrence count.
Four adjacent lines turning off four halves of the same S3 public-access block is one decision,
and reporting it four times trains people to skim.

Rules that match credentials are marked `redact`, and their matched text is masked everywhere —
terminal, comment, SARIF and JSON. A tool that quotes the secret it just found has published it
a second time, this time somewhere indexed.

---

## The risk score

One number, 0–100, with a band. It exists so a pull request can be gated and so a security team
can see at a glance which changes are worth a human. Three properties, all deliberate:

**The worst finding sets a floor; everything else fills the headroom above it.** The single
largest contribution is mapped through `1-exp(-x/k)` to a floor, and the sum of the rest closes
the gap to the ceiling through the same curve. This is what stops eight mediums from outranking
one critical. A plain sum would mean a large refactor scores higher than a targeted change to
authentication, and a gate that behaves that way teaches people to write bigger pull requests. A
genuinely large pile of mediums still gets there — thirty of them really is a high-risk change —
it just takes thirty, not eight.

**Removed controls weigh 1.3× more than added risk.** A deleted authorization check is a
regression in a property the system already had. New risky code at least arrives with a
reviewer's attention on it.

**Blast radius contributes up to 15 points, saturating.** Bigger diffs get reviewed worse. The
difference between a 40-file and a 400-file change is small, because both are past the point
where anyone reads every line.

| Band | Score |
| --- | --- |
| `critical` | ≥ 75 |
| `high` | ≥ 45 |
| `medium` | ≥ 20 |
| `low` | ≥ 5 |
| `minimal` | < 5 |

Every number is explainable: each finding prints its own contribution, and the report shows the
split between signal and blast radius. A gate nobody can argue with is a gate that gets bypassed
rather than fixed. Every weight is overridable in `scoring:` — see
[docs/configuration.md](docs/configuration.md).

---

## Suppressions and baselines

**Inline**, on the matched line or the line above:

```python
api_key = "example-value-not-real"  # threatdiff:ignore[secret.generic-credential-assignment] docs placeholder
h = hashlib.md5(url).hexdigest()    # threatdiff:ignore -- cache key, not security
resp = requests.get(url)            # threatdiff:ignore[injection.*] whole family, host is a constant
```

**Baseline**, for adopting threatdiff in a repository that already has history:

```bash
threatdiff baseline write \
  --base "$(git rev-list --max-parents=0 HEAD)" \
  --out .threatdiff-baseline.json \
  --reason "pre-existing at adoption"
```

Baseline entries are keyed by a fingerprint of the rule, the path and the *normalised* line — not
the line number — so reformatting does not silently re-open or re-suppress anything. Every entry
is dated, because a baseline is a debt register and debts should be reviewed.

Suppressed findings are always reported, in their own section, with the reason. Findings
suppressed without a reason are called out. An invisible suppression is how a gate rots.

---

## Writing your own rules

Rules are YAML. Reusing a built-in rule's `id` overrides it, which is how you retune the
defaults without forking the pack.

```yaml
version: 1
name: house-rules

rules:
  - id: house.legacy-auth-helper
    title: Deprecated authentication helper used
    category: elevation-of-privilege   # STRIDE, plus supply-chain and secrets
    severity: high                     # critical | high | medium | low | info
    confidence: medium                 # high | medium | low
    on: added                          # added | removed | any | file
    languages: [python, go]
    paths: ["services/**"]
    exclude_paths: ["**/*_test.go"]
    patterns:
      - '(?i)legacy_auth\.(check|verify)\s*\('
    exclude_patterns:
      - '(?i)#\s*migrated'
    near:                              # the constraint that removes the noise
      absent:
        - '(?i)(new_auth|authz_v2)'
      window: 8
      scope: hunk                      # hunk | file
    question: >
      Why is this call still on the old helper, and what does the new one enforce
      that the old one does not?
    guidance: |
      legacy_auth.check() only validates the session; it does not evaluate the
      tenant policy. Anything under services/ needs authz_v2.authorize().
    cwe: ["CWE-863"]
    references:
      - "https://internal.example.com/docs/authz-v2"
```

```bash
threatdiff rules validate .threatdiff/rules      # errors are line-numbered
threatdiff scan --rules .threatdiff/rules
threatdiff rules show house.legacy-auth-helper
threatdiff rules docs --out docs/rules.md        # generate a reference table
```

Two things the schema enforces, both on purpose:

- **`question` is mandatory.** A rule that cannot tell a reviewer what to check is noise.
- **Unknown fields are rejected**, with a line number. A typo in a rule file should fail loudly,
  not silently disable a check.

Patterns are Go RE2: no lookaround, no backreferences, linear time. That last property matters
here — a rule pack is user input, and a backtracking engine would make a rule file into a denial
of service vector against your own CI.

The `near` constraint is what separates a useful rule from a noisy one. `authz.new-endpoint-without-auth`
fires on a new route handler *only when nothing resembling an authorization check appears within
ten lines*. That single condition is the difference between a rule you keep and a rule you turn off.

Full reference: [docs/writing-rules.md](docs/writing-rules.md). All 88 built-in rules:
[docs/rules.md](docs/rules.md).

---

## Reviewer routing

Detection is rarely the bottleneck in application security. Getting the right pair of eyes onto
the right ten lines is.

```yaml
review:
  default: ["@org/appsec"]
  routes:
    - name: access control
      categories: [elevation-of-privilege, spoofing]
      min_severity: high
      reviewers: ["@org/appsec-authz"]
    - name: infrastructure
      paths: ["**/*.tf", ".github/workflows/**", "**/Dockerfile*"]
      reviewers: ["@org/platform-security"]
    - name: crypto
      rules: ["crypto.*"]
      reviewers: ["@alice"]
```

Routes are additive — a finding that matches two routes gets both sets of reviewers. When no
route matches, threatdiff falls back to your `CODEOWNERS` file (GitHub semantics: last match
wins), and then to `default`. So a repository with a CODEOWNERS file gets useful routing with no
threatdiff configuration at all.

---

## Configuration

`.threatdiff.yaml` in the repository root. Generate a commented starter with `threatdiff init`.

```yaml
version: 1

fail_on: critical          # severity that fails the run; empty means never
fail_score: 0              # or gate on the score instead
min_confidence: low        # drop findings below this confidence

exclude_paths:
  - "vendor/**"
  - "node_modules/**"
  - "**/*.generated.*"

baseline: .threatdiff-baseline.json
rule_paths: [.threatdiff/rules]

rules:
  disable: [dos.retry-without-backoff]
  severity:
    crypto.weak-hash-for-security: low

entropy:                   # the built-in high-entropy secret detector
  enabled: true
  min_entropy: 3.6
  min_length: 20

scoring:                   # every weight in the model is yours to change
  removal_multiplier: 1.3
  saturation: 70
  blast_radius_weight: 15

review:
  default: ["@org/appsec"]
```

Flags override the file. Full reference: [docs/configuration.md](docs/configuration.md).

---

## Command reference

```
threatdiff scan       Analyse a diff and report the threats it introduces
threatdiff rules      Inspect, validate and document the active rule set
  rules list [--category C] [--severity S] [--json]
  rules show <rule-id>
  rules validate <path>
  rules docs [--out FILE]
  rules languages | rules categories
threatdiff baseline write [--out FILE] [--reason TEXT]
threatdiff init       Write a starter .threatdiff.yaml
threatdiff version
```

Key `scan` flags:

| Flag | Purpose |
| --- | --- |
| `--base`, `--head` | The range. Compared three-dot, like a pull request. |
| `--staged` | Analyse the index instead of the working tree. |
| `--diff FILE\|-` | Read a patch instead of invoking git. |
| `--format` | `pretty` (default), `markdown`, `sarif`, `json`. |
| `--out`, `--sarif-out`, `--markdown-out`, `--json-out` | Write several formats in one run. |
| `--fail-on`, `--fail-score` | The gate. |
| `--min-confidence` | Quieten the statistical rules while you calibrate. |
| `--only`, `--disable` | Run a single rule, or turn one off. |
| `--rules`, `--config`, `--baseline` | Inputs. |
| `--github-output` | Append `score=`/`band=`/`findings=`/`failed=` to `$GITHUB_OUTPUT`. |
| `--context` | Context lines to request from git; more makes `near` more accurate. |

---

## How it works

```
git diff ──▶ diff parser ──▶ rule engine ──▶ scorer ──▶ reporters
                 │                │             │           ├─ pretty
                 │                │             │           ├─ markdown
                 │                │             │           ├─ sarif
                 │                │             │           └─ json
                 │                │             │
       old + new line numbers,    │       floor from the worst
       hunk section headings,     │       finding + saturating
       add / remove / context     │       tail + blast radius
                                  │
                    patterns · path & language filters
                    proximity constraints · entropy detector
                    suppressions · baseline · repeat folding
```

| Package | Responsibility |
| --- | --- |
| `internal/diff` | Unified diff parser that keeps both line numbers and hunk section headings |
| `internal/config` | A YAML subset parser (no dependencies) and the config schema |
| `internal/rules` | The rule model, compiler, globs, language detection, embedded packs |
| `internal/analyze` | Matching, proximity, entropy detection, redaction, suppression, baselines |
| `internal/score` | The risk model and the gate |
| `internal/owners` | Reviewer routing and a CODEOWNERS parser |
| `internal/report` | The four renderers |

Two design notes worth calling out:

**Removed lines get anchored to a surviving line.** A deleted line has no line number in the new
file, but a review UI — and SARIF — can only annotate lines that still exist. threatdiff anchors
a removal to the nearest surviving line above it, and says so in the finding. Without this, the
most valuable half of the rule set would have nowhere to render.

**The YAML parser is deliberately small.** It implements block mappings, block sequences, flow
collections, quoted and block scalars, and comments — and rejects anchors, aliases, tags and
multi-document streams with a line-numbered error. For a security tool, "I do not understand
this rule file" is a much better outcome than "I guessed".

---

## What it deliberately does not do

Being clear about this is part of the tool working.

- **It does not prove anything.** There is no data-flow analysis, no call graph, no type
  information. A finding is a question, and the answer might well be "no, that is fine". The
  output is written to make that answer cheap to give.
- **It does not replace SAST, SCA or secret scanning.** It is the layer none of those cover: the
  delta, and specifically the deletions. Run it alongside them.
- **It does not see whole-repository context.** A rule that fires on a new route cannot know
  about the middleware three files away. `near` with `scope: file` widens the window, and a
  reviewer's "that is handled in router.go" is a perfectly good answer that closes the finding.
- **A clean run is not a guarantee.** It means no rule matched. Rules only see patterns somebody
  thought to write down. threatdiff says this in its own output, every time.

---

## Adoption

Turning this on in an existing repository, in the order that works:

1. **Week 1–2 — no gate.** `fail-on: ""`. The comment appears; nobody is blocked. Watch which
   rules fire and whether the questions are the ones you would have asked.
2. **Then — baseline and calibrate.** `threatdiff baseline write` for the existing code.
   Turn down or disable the rules your codebase makes noisy; raise the ones it makes important.
   `severity:` overrides and a house rule pack both belong here.
3. **Then — gate on critical.** `fail-on: critical`. At this point the gate only fires on things
   the team has already agreed are worth stopping for.
4. **Later — route, then tighten.** Add `review:` routes so findings reach the people who can
   answer them, then move the gate to `high` if the numbers support it.

More detail, including how to run this across many repositories: [docs/adoption.md](docs/adoption.md).

---

## Contributing

New rules are the most valuable contribution, and the bar is specific: a rule must ask a
question a reviewer can answer, and it must be one you would be willing to see fire on your own
pull requests. See [CONTRIBUTING.md](CONTRIBUTING.md).

```bash
make check   # vet + gofmt + tests, the same set CI runs
make demo    # run against the bundled example pull request
make docs    # regenerate docs/rules.md
```

## License

MIT. See [LICENSE](LICENSE).
