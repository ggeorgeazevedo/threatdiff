# Contributing

Thanks for looking. New rules are the most valuable contribution here, and they have a specific
bar — see below.

## Getting set up

```bash
git clone https://github.com/ggeorgeazevedo/threatdiff && cd threatdiff
make check   # go vet + gofmt + tests. This is exactly what CI runs.
make demo    # run against the bundled example pull request
```

Go 1.22 or newer. There are no other dependencies, and there should never be any: threatdiff is
standard library only. A pull request that adds a module to `go.mod` needs to make the case for
it in the description, and the bar is high — this tool runs inside other people's CI with access
to their diffs.

## Contributing a rule

A rule is a question a reviewer can answer, not a claim that something is broken. The bar, in
order of importance:

1. **The question is answerable in about thirty seconds** by the person who wrote the line.
   "Does this query still return only rows belonging to the caller's tenant?" — yes.
   "Is this secure?" — no.
2. **The guidance says what to do**, and is honest about when the finding is a false positive.
   Read a few existing rules for the register.
3. **Confidence is set truthfully.** If it is a heuristic, say `low`. An honest `low` is what
   keeps the risk score meaningful; an optimistic `high` is what gets the whole tool muted.
4. **It has a `near` constraint or narrow paths**, unless the pattern is genuinely specific.
   <!-- threatdiff:ignore[secret.private-key-block] documentation quoting the header, not a key -->
   `-----BEGIN PRIVATE KEY-----` needs neither; `md5` needs both.
5. **Test and fixture paths are excluded** where the rule would otherwise fire on them.
6. **A CWE mapping** where one applies.

Before opening the pull request, run the rule over real history and look at the hit rate:

```bash
for sha in $(git log --format=%H -n 200); do
  git show "$sha" | ./bin/threatdiff scan --diff - --only your.rule-id --format json 2>/dev/null \
    | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["findings"]))'
done | sort | uniq -c
```

A rule that fires on 40% of commits is a banner, not a rule. Say what you found in the pull
request description — an honest "this fired on 12 of 200 commits, 4 were real" is exactly the
information a reviewer needs.

Then:

```bash
make check
make docs   # regenerate docs/rules.md; CI checks it is in sync
```

Full schema reference: [docs/writing-rules.md](docs/writing-rules.md).

## Contributing code

- **Comments explain why, not what.** The codebase has a house style of explaining the reasoning
  behind a decision where it is not obvious — why removed lines are anchored to a surviving line,
  why the score saturates, why the YAML parser rejects anchors. Match it.
- **Tests are expected**, and the interesting ones are behavioural: "one critical outranks eight
  mediums", "a snippet cannot escape its Markdown code fence", "a baselined run passes the gate".
  Look at the existing tests before writing new ones.
- **Do not break the JSON contract** in `internal/report/json.go` without a note in the pull
  request. People build on it.
- **Exit codes are interface.** `0` clean, `1` gate triggered, `2` could not run.

## Reporting a bug

The most useful bug report contains a minimal patch that reproduces it:

```bash
threatdiff scan --diff repro.patch --format json
```

Attach `repro.patch`, the output, and what you expected. If the patch contains anything real,
please redact it first — and if threatdiff itself printed a secret it should have masked, that is
a security issue rather than a bug: see [SECURITY.md](SECURITY.md).

## What is out of scope

- **Data-flow analysis, call graphs, type resolution.** There are good tools for that and this is
  not trying to be one. threatdiff reads a diff.
- **Auto-fixing.** A tool that rewrites security-relevant code based on a regex match is a worse
  idea than the problem it solves.
- **Language-specific parsers.** The rules are regex over diff lines on purpose: it is what makes
  the tool work identically on a Terraform file, a GitHub workflow and a Kotlin service.

## Code of conduct

Be decent. Assume the other person is trying to do good work. Disagreement about a rule's
confidence level is normal and healthy; making it personal is not.
