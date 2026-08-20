# The risk score

threatdiff produces one number between 0 and 100, plus a band. It exists so a pull request can be
gated automatically and so a security team can see at a glance which changes deserve a human.

Every part of it is overridable, and every part of it is printed alongside the result. A gate
nobody can argue with is a gate that gets bypassed rather than fixed.

---

## The model

### Step 1 — each finding gets a contribution

```
contribution = base[severity] × confidence_weight × removal_multiplier
```

| Severity | Base | | Confidence | Weight |
| --- | ---: | --- | --- | ---: |
| critical | 40 | | high | 1.00 |
| high | 24 | | medium | 0.70 |
| medium | 10 | | low | 0.45 |
| low | 4 | | | |
| info | 1 | | | |

`removal_multiplier` is **1.3** for findings that come from deleted lines, and 1.0 otherwise. A
deleted authorization check is a regression in a property the system already had; new risky code
at least arrives with a reviewer's attention on it.

So a critical, high-confidence finding on a removed line contributes `40 × 1.0 × 1.3 = 52`. A
high-severity, low-confidence finding on an added line contributes `24 × 0.45 = 10.8`.

Each finding prints its own contribution, so this arithmetic is always visible.

### Step 2 — the worst finding sets a floor

```
lead  = the single largest contribution
floor = 85 × (1 - exp(-lead / 38))
```

One critical high-confidence finding (40 points) produces a floor of about 55 — inside the
`high` band on its own, which is correct: that pull request needs a human regardless of what else
is in it.

### Step 3 — everything else fills the headroom

```
rest    = (sum of all contributions) - lead
signals = floor + (85 - floor) × (1 - exp(-rest / 70))
```

The remaining findings can only close the gap between the floor and the 85-point ceiling, and
they do it with diminishing returns.

This two-stage shape is what stops a handful of mediums from outranking one critical. A plain
sum would mean a large refactor scores higher than a targeted change to authentication, and a
gate that behaves that way teaches people to write bigger pull requests.

A genuinely large pile of mediums still gets there. Eight of them score about 50; thirty of them
score about 81. That is the right answer in both cases — thirty medium findings really is a
high-risk change.

### Step 4 — blast radius

```
x            = files / 25 + lines / 800
blast_radius = 15 × (1 - exp(-x))
```

Up to 15 points from the size and spread of the change, saturating. Bigger diffs get reviewed
worse; this is the part of the score that is about human attention rather than about any specific
finding. The difference between a 40-file and a 400-file change is small, because both are past
the point where anyone reads every line.

### Step 5 — total

```
total = min(100, signals + blast_radius)
```

| Band | Score |
| --- | ---: |
| `critical` | ≥ 75 |
| `high` | ≥ 45 |
| `medium` | ≥ 20 |
| `low` | ≥ 5 |
| `minimal` | < 5 |

---

## What is not counted

**Suppressed findings.** Inline suppressions and baseline entries are scored — so a report can
tell you what the score *would* have been — but they do not move the total.

**Folded repeats.** Four adjacent lines matching one rule in one file count once. That is one
decision by one author, and counting it four times would let a formatting choice change the risk
score.

---

## Category scores

The per-category numbers in the report are raw sums, not saturated. They exist to rank the
categories against each other and to answer "what kind of risk is this change?", so a raw sum is
the right thing: it makes the relative weights visible. They are not on the same scale as the
total, and the report says so.

---

## Tuning it

```yaml
scoring:
  base:
    critical: 40
    high: 24
    medium: 10
    low: 4
    info: 1
  removal_multiplier: 1.3
  lead_scale: 38
  saturation: 70
  blast_radius_weight: 15
  bands:
    critical: 75
    high: 45
    medium: 20
    low: 5
```

The two worth touching:

- **`removal_multiplier`** — lower it if your codebase does a lot of legitimate refactoring of
  security helpers and the removal rules are consistently firing on moves rather than deletions.
- **`saturation`** — lower means a long list reaches the ceiling sooner; higher means only
  genuinely large piles do.

Two worth leaving alone unless you have a reason you can write down:

- **`lead_scale`** controls the whole "one critical outranks eight mediums" property. Raising it
  weakens that guarantee.
- **`bands`** are what everyone will quote in meetings. Moving them re-labels history.

---

## Gating on it

```bash
threatdiff scan --fail-score 60     # fail when the score reaches 60
threatdiff scan --fail-on high      # fail when a high or critical finding appears
```

Either may be set; either one tripping fails the run.

**Which to use.** `--fail-on` is more predictable and easier to argue about — it fails on a
specific finding, which is a specific thing to fix. `--fail-score` catches the case `--fail-on`
misses: a change with no single alarming finding but a lot of medium ones across several
categories. Teams that use both usually set `fail_on: critical` and `fail_score: 70`.

Neither is set by default. A run with no gate configured never fails a build.
