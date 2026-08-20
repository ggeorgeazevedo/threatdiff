# Adoption

A security gate fails for social reasons far more often than technical ones. This is the rollout
that survives contact with a real engineering organisation.

---

## The failure mode to avoid

Turn threatdiff on with `fail-on: high` in a repository with ten years of history, and the first
pull request gets forty findings about code the author did not touch. What happens next is
predictable: someone adds `continue-on-error: true`, and the tool is now decoration.

Everything below exists to avoid that specific week.

---

## Week 1–2: no gate, just the comment

```yaml
- uses: ggeorgeazevedo/threatdiff@v0
  with:
    fail-on: ""     # nothing is blocked
```

Nobody is stopped. The checklist appears on every pull request. Your job in this phase is to read
the output yourself, on real changes, and answer one question per rule:

> Is this the question I would have asked?

Keep a note of three things:

- rules that fire constantly on things nobody cares about → candidates for `disable` or a lower
  severity,
- rules that fire and turn out to be right → tell people, this is what buys you the gate later,
- questions that are worded badly for your codebase → override the rule with your own wording.

Two weeks is usually enough. Fewer than about thirty pull requests is not.

---

## Week 3: baseline and calibrate

Record what already exists so the gate only ever speaks about new change:

```bash
threatdiff baseline write \
  --base "$(git rev-list --max-parents=0 HEAD)" \
  --out .threatdiff-baseline.json \
  --reason "pre-existing at threatdiff adoption, $(date +%Y-%m)"
```

Commit it. Then calibrate, in this order of preference:

1. **`min_confidence: medium`** if the checklist is simply too long. One line, easy to undo.
2. **`rules.severity`** overrides for rules that matter less in your context. A rule at `low`
   still asks its question and still appears; it just stops driving the score.
3. **`exclude_paths`** for generated, vendored and migration code.
4. **`rules.disable`** last. Disabling teaches the team nothing.

```yaml
min_confidence: medium
baseline: .threatdiff-baseline.json
exclude_paths: ["vendor/**", "**/*.generated.*", "**/migrations/**"]
rules:
  severity:
    crypto.weak-hash-for-security: low     # we use md5 for cache keys everywhere
    dos.no-timeout-on-outbound-call: low   # handled by our HTTP client wrapper
```

If a rule is wrong in a way that is specific to your codebase, override it rather than deleting
it — see [writing-rules.md](writing-rules.md#overriding-a-built-in-rule).

---

## Week 4: gate on critical

```yaml
fail_on: critical
```

By now the critical rules are ones the team has watched for a month and agreed are worth
stopping for. The number of pull requests actually blocked should be small — if it is not, you
are not calibrated yet, and week 3 is worth repeating.

Announce it before it happens, and say exactly how to unblock: the inline suppression syntax,
and who to ask.

---

## Month 2 onwards: route, then tighten

Routing is what turns the tool from a linter into a workflow. Without it, findings go to the
author, who is the person least able to be objective about them.

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
```

If you already have a `CODEOWNERS` file, routing works without any of this — threatdiff falls
back to it automatically. Explicit routes are for the cases where the right reviewer depends on
the *kind* of finding rather than the path.

Move to `fail_on: high` only when the numbers support it: look at how many high findings the last
hundred pull requests produced and how many were real.

---

## Rolling out across many repositories

**Share the configuration, not the copies.** Put your house rules and config in one repository
and pull them in:

```yaml
- uses: actions/checkout@v4
  with: { fetch-depth: 0 }
- uses: actions/checkout@v4
  with:
    repository: your-org/appsec-policy
    path: .appsec
- uses: ggeorgeazevedo/threatdiff@v0
  with:
    config: .appsec/threatdiff.yaml
    rules: .appsec/rules
```

**Stage by tier, not alphabetically.** Start with the repositories that handle authentication,
payments and customer data. Those are where the rules are most likely to be right and where a
caught regression makes the case for everything else.

**Aggregate the JSON.** Every run can emit `--json-out`, which contains the score, the band and
the per-category breakdown. Collecting that across repositories gives you something more useful
than a vulnerability count: a view of where risky change is concentrated.

```bash
threatdiff scan --format json --out threatdiff.json --quiet
# .score.total, .score.band, .summary.by_category, .summary.by_severity
```

---

## Keeping it healthy

**Review the baseline quarterly.** Every entry is dated. An entry that has been there for a year
is either a real risk nobody owns or a rule that should have been retuned. Both are worth
knowing.

**Watch suppressions.** They are always reported, and ones without a reason are called out. A
rising count of reasonless suppressions is the earliest sign that the tool has become noise. Fix
the rule, not the suppressions.

**Regenerate the rule reference.** `make docs` keeps `docs/rules.md` in sync so people can
actually find out what a rule id means.

**Read the questions occasionally.** The value of this tool is entirely in whether the questions
are good. If they have drifted from what your team cares about, that is a rules problem and it is
fixable in an afternoon.
