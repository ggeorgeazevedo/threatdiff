# Security policy

## Reporting a vulnerability

Please report security issues privately, through GitHub's
[private vulnerability reporting](https://github.com/ggeorgeazevedo/threatdiff/security/advisories/new)
rather than a public issue.

Include what you did, what happened, and what you expected. A minimal patch file that reproduces
the behaviour is the most useful thing you can attach.

You should get an acknowledgement within a few days. If the report is valid, we will agree a
disclosure timeline with you and credit you in the advisory unless you would rather we did not.

## Threat model of threatdiff itself

threatdiff runs inside other people's CI with read access to their diffs, and it writes output
into pull request comments. That gives it three properties worth stating plainly.

**It has no network access and makes no outbound calls.** It reads a diff, applies rules from
disk or from the binary, and writes files. It sends nothing anywhere. If you observe it opening a
socket, that is a vulnerability.

**It has no third-party dependencies.** Standard library only. This is a deliberate constraint,
not an accident of the moment: a security tool that runs in your pipeline should not be the
largest supply-chain surface in it. Pull requests adding dependencies are held to a high bar.

**Its inputs are untrusted.** A diff comes from a pull request, which may come from a fork. Rule
packs may come from anywhere. Both are handled accordingly:

- Patterns compile with Go's RE2, which is linear time and has no backtracking. A crafted rule
  file cannot become a denial of service against the CI job running it.
- The YAML parser implements a deliberately small subset and rejects anchors, aliases, tags and
  multi-document streams with a line-numbered error, rather than guessing.
- Diff lines quoted into Markdown are flattened and have fence sequences neutralised, so a
  crafted source line cannot escape its code block and inject Markdown into a comment a reviewer
  is reading. Table cells escape pipes and HTML.
- Rules that can match a credential are marked `redact`, and their matched text is masked in
  every output format. A tool that echoes the secret it just found has published it a second
  time, this time into a comment that may be world-readable.

Issues in any of those four areas are security issues, not bugs. In particular: **any path by
which a secret reaches an unredacted output** is treated as a vulnerability, whether or not the
rule that matched it was marked `redact`.

## What is not a vulnerability

- **A false negative.** threatdiff is a heuristic tool and says so in its own output. A rule that
  fails to fire is a rule improvement — please open a normal issue or a pull request.
- **A false positive.** Same. Tune it, override it, or suppress it in place.
- **A clean run on vulnerable code.** A clean result means no rule matched. Rules only see
  patterns somebody thought to write down.

## Supported versions

The latest tagged release. Fixes are issued as a new patch release rather than backported.
