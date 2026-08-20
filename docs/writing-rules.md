# Writing rules

A threatdiff rule answers one question: *if I see this in a diff, what threat should a human
think about?* It is not a vulnerability signature. A rule firing is an invitation to review.

That framing drives most of the schema, and it drives the one thing the compiler refuses to
accept: a rule without a `question`.

---

## The shape of a rule

```yaml
version: 1
name: house-rules          # shown in `rules list`; defaults to the file name
description: >
  Optional. What this pack is for and who owns it.

rules:
  - id: house.legacy-auth-helper
    title: Deprecated authentication helper used
    category: elevation-of-privilege
    severity: high
    confidence: medium
    on: added

    languages: [python, go]
    paths: ["services/**"]
    exclude_paths: ["**/*_test.go"]

    patterns:
      - '(?i)legacy_auth\.(check|verify)\s*\('
    exclude_patterns:
      - '(?i)#\s*migrated'

    near:
      absent: ['(?i)(new_auth|authz_v2)']
      window: 8
      scope: hunk

    question: >
      Why is this call still on the old helper, and what does the new one
      enforce that the old one does not?
    guidance: |
      legacy_auth.check() validates the session only; it does not evaluate the
      tenant policy. Anything under services/ needs authz_v2.authorize().

    cwe: ["CWE-863"]
    owasp: ["A01:2021 Broken Access Control"]
    references: ["https://internal.example.com/docs/authz-v2"]
    tags: ["migration"]
    redact: false
    enabled: true
```

## Field reference

| Field | Required | Notes |
| --- | --- | --- |
| `id` | yes | Lowercase alphanumerics separated by `.` or `-`. The prefix is the family: `crypto.*`, `authz.*`. Reusing a built-in id overrides that rule. |
| `title` | yes | One line, in the reviewer's language. It is the heading of the checklist item. |
| `category` | yes | `spoofing`, `tampering`, `repudiation`, `information-disclosure`, `denial-of-service`, `elevation-of-privilege`, plus `supply-chain` and `secrets`. |
| `severity` | yes | `critical`, `high`, `medium`, `low`, `info`. How bad it is *if the answer is yes*. |
| `confidence` | no | `high`, `medium`, `low`. Default `medium`. How often the rule is right when it fires. Scales the score. |
| `on` | no | `added` (default when `patterns` is set), `removed`, `any`, `file` (default when only `paths` is set). |
| `languages` | no | Restrict by detected language. `threatdiff rules languages` lists them. |
| `paths` / `exclude_paths` | no | Globs. A pattern with no `/` matches the file name at any depth. |
| `patterns` | see notes | RE2 regexes; any match fires. Required unless `on: file`. |
| `exclude_patterns` | no | A match on the same line cancels the finding. |
| `near` | no | Proximity constraint. See below. |
| `file_events` | no | For `on: file`: `created`, `deleted`, `renamed`, `modified`. |
| `question` | yes | What the reviewer is asked. This is the product. |
| `guidance` | no | How to answer it. Rendered in a collapsible block. Built-in rules all have one. |
| `cwe`, `owasp`, `references`, `tags` | no | Shown in the finding and mapped into SARIF tags. |
| `redact` | no | Mask matched text everywhere. Set it on anything that can match a credential. |
| `enabled` | no | `false` ships the rule off by default. |

`patterns` or `paths` is required — a rule with neither would match everything.

---

## Severity is not confidence

They are separate axes and conflating them is the most common way to build a noisy rule set.

- **Severity** answers "if the reviewer says yes, how bad is it?"
- **Confidence** answers "how often does this rule fire on something real?"

`authz.tenant-scope-dropped-from-query` is `severity: critical, confidence: low`. Cross-tenant
data exposure is about as bad as it gets, and the regex looking for a removed `tenant_id` filter
is right maybe a third of the time. Both statements are true, and keeping them separate lets the
score treat the rule sensibly while still asking the question.

A `low` confidence rule is not a bad rule. It is a rule that is honest.

---

## `near`: the field that makes rules usable

A pattern alone is almost always too broad. `near` constrains a match by what surrounds it.

```yaml
near:
  absent: ['(?i)(auth|permission|current_user|token)']
  present: ['(?i)(token|secret|password)']
  window: 10          # lines on each side; default 5
  scope: hunk         # hunk (default) or file
```

- **`absent`** — fire only when *none* of these appear nearby. This is how
  `authz.new-endpoint-without-auth` works: a new route handler with no authorization-shaped
  token within ten lines. Without it the rule fires on every route in every diff and gets turned
  off within a week.
- **`present`** — fire only when at least one appears nearby. This is how
  `crypto.insecure-randomness` avoids complaining about `random.randint(1, 6)` while still
  catching `token = random.randint(...)`.
- **`scope: file`** widens the window to every line of the diff for that file. Use it when the
  evidence is structurally elsewhere — `audit.webhook-or-callback-added` uses it, because the
  signature check may be fifty lines from the route definition.

The window includes context lines and the hunk's section heading (the function signature git
prints after `@@`), which is often exactly where the decorator or guard lives. Running with a
larger `--context` makes `near` more accurate.

---

## Rules that fire on removals

This is what threatdiff is for, and it is worth writing more of them.

```yaml
on: removed
patterns:
  - '(?i)\.(use|addmiddleware)\s*\(\s*[a-z0-9_.]*(auth|jwt|session)'
```

Two things to keep in mind:

1. **Removed lines are anchored to a surviving line.** The finding reports the nearest line that
   still exists in the new file, plus the original line number. You get this for free.
2. **Exclude test paths.** Deleting a test that mentions `auth` is a different (and much less
   severe) event than deleting the middleware. `control.security-test-removed` handles that case
   at `medium`; do not let your control rules fire on it too.

---

## Regex constraints

Patterns are compiled with Go's `regexp`, which is RE2:

- No lookahead, lookbehind or backreferences. Use `exclude_patterns` or `near.absent` instead.
- Guaranteed linear time. This is not a limitation to work around, it is the reason a rule pack
  can be untrusted input without becoming a denial of service against your own CI.
- `(?i)` for case insensitivity, `(?s)` for dot-matches-newline (rarely useful here — matching
  is line by line).

Practical advice:

- Anchor with `^\s*` when you mean "at the start of a statement".
- Prefer `\b` boundaries over bare substrings; `md5` matches `md5sum` and `NOTMD5` otherwise.
- Quote patterns in YAML with single quotes so backslashes stay literal. If the pattern contains
  a single quote, double it: `'it''s'`.
- Test both directions. A rule that never fires and a rule that always fires are equally useless,
  and only one of them is obvious in review.

---

## Testing a rule

```bash
# does the pack compile? errors carry file and line numbers
threatdiff rules validate .threatdiff/rules

# run only your rule against a real patch
threatdiff scan --diff some.patch --rules .threatdiff/rules --only house.legacy-auth-helper

# and against a body of history, to see the false-positive rate honestly
for sha in $(git log --format=%H -n 200); do
  git show "$sha" | threatdiff scan --diff - --rules .threatdiff/rules \
    --only house.legacy-auth-helper --format json 2>/dev/null \
    | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["findings"]))'
done | sort | uniq -c
```

That last loop is the one that matters. A rule that fires on 40% of your commits is not a rule,
it is a banner. Either add a `near` constraint, narrow the paths, or lower the confidence so the
score treats it appropriately.

---

## Overriding a built-in rule

Give your rule the same `id`. Later packs win, and built-in packs are always loaded first.

```yaml
version: 1
name: house-overrides
rules:
  - id: crypto.weak-hash-for-security
    title: MD5 is banned outright here
    category: tampering
    severity: critical
    confidence: high
    on: added
    patterns: ['(?i)\bmd5\b']
    question: Why is MD5 present at all?
    guidance: We do not allow it, even for cache keys. Use SHA-256.
```

`threatdiff rules validate` prints a `note` line whenever a pack overrides a built-in id, so an
accidental collision is visible.

For a smaller change — just the severity — use the config instead of a whole rule:

```yaml
rules:
  severity:
    crypto.weak-hash-for-security: low
  disable:
    - dos.retry-without-backoff
```

---

## Contributing a rule upstream

The bar for the built-in packs, in order of importance:

1. **The question is answerable in about thirty seconds** by the person who wrote the line.
2. **The guidance says what to do**, not just what is wrong, and is honest about when the finding
   is a false positive.
3. **Confidence is set truthfully.** If it is a heuristic, say `low`. Nobody is grading you on it,
   and an honest `low` is what keeps the score meaningful.
4. **It has a `near` constraint or narrow paths** unless the pattern is genuinely specific
   <!-- threatdiff:ignore[secret.private-key-block] documentation quoting the header, not a key -->
  (`-----BEGIN PRIVATE KEY-----` needs neither).
5. **A CWE mapping** where one applies.
6. **Test paths are excluded** where the rule would otherwise fire on fixtures.

Run `make check` and `make docs` before opening a pull request — CI verifies that
`docs/rules.md` is in sync with the packs.
