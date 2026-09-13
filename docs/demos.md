# The demos: what each one shows, and why there is more than one

Maturity: `experimental` as a set. Eight demos are shipped and one is proposed;
the index below marks which is which, and `tests/test_demos.py` fails if the
index and `demo/` disagree about what exists.

## 1. The problem with one big demo

A single end-to-end run demonstrates that the stages compose and nothing else.
The behaviours worth showing are mostly **distinctions** — `no_match` is not
`missing`, an escalation is not a verdict, a failure is not a `normal` — and a
distinction needs two runs side by side or it is a paragraph, not a
demonstration. So the set is organised by *the situation it puts the pipeline
in*, not by which stage it reaches.

**The long run is one member of the set, not its purpose.** A day of traffic
shows volume, cost and the shape of real context; it does not show a single one
of the distinctions above, because ordinary traffic exercises one path.

## 2. Naming

**`demo/<noun_phrase>.py`, lower snake case, naming what it shows rather than
which stage it reaches.** No number in the filename.

The number lives in the index and nowhere else, which is the opposite of the
convention `sql/migrations/` and `docs/decisions/` use — deliberately. Those are
**records**, ordered by when they happened, and renumbering one would break a
citation. A demo is chosen by topic; inserting *"the one that shows staleness"*
between two others must not rename a file that three documents already link to.
`demo/run-demo` accepts either the number or the name.

An area prefix is not used either. `enrichment_states.py` already sorts beside
`escalation_and_scope.py` and reads as a sentence; `d03_enrichment_states.py`
buys ordering the index already provides and costs the importability
`tests/test_demos.py` relies on.

## 3. The index

`demo/run-demo --list` prints this, and `tests/test_demos.py` holds the two in
agreement.

| # | Script | Tier | What it shows | Data it needs | Runtime |
| --- | --- | --- | --- | --- | --- |
| 1 | `ingest_and_context.py` | foundations | one record's whole journey, at a size where every number checks by eye | `data/ingest/` (committed) | ~1 min |
| 2 | `context_over_a_day.py` | scale | what a context looks like when there is enough traffic for the answer to be interesting | `data/demo/` (**not committed**) | ~20 min |
| 3 | `assess_a_slice.py` | assessment | all six stages, ending in the message a consumer reads, twice — feed as published vs one entry repointed | `data/ingest/` + live feed + model | ~4 min |
| 4 | `enrichment_states.py` | situations | `ok` / `stale` / `missing` / `failed` / `no_match` side by side, and why none of them means "safe" | committed; snapshot timing only | ~2 min |
| 5 | `escalation_and_scope.py` | situations | the same indicator contacted vs only resolved — scope before severity, and the gate's subordination to escalation | committed + `plant_indicators.py` | ~3 min |
| 6 | `failure_paths.py` | situations | quarantine, a schema-invalid model answer, a budget-truncated run, a source outage — four failures that are never a verdict | committed; scripted model | ~3 min |
| 7 | `replay_an_assessment.py` | situations | a stored assessment replayed against the versions **it recorded**, and what a replay refuses | any prior run's store | ~2 min |
| 8 | `backup_and_restore.py` | situations | what survives, what rebuilds, and what a capture replay alone does *not* bring back | any prior run's store | ~3 min |
| 9 | `assess_a_day.py` | **proposed**, scale | the long run: a rebased day, planted, assessed, with cost and gate counts | `data/demo/` + both generators | hours |

### The tiers

**foundations** (1) — one record, every number checkable.
**assessment** (3) — the six stages and the message.
**situations** (4–8) — one distinction each. These are the ones that are missing,
and they are small on purpose: a demo that shows two things shows neither.
**scale** (2, 9) — volume, cost, and what breaks at size.

## 4. Is the data we have enough?

**Mostly yes, and the gap is exactly the one the project already records.**

| Situation | Data it needs | Have it? |
| --- | --- | --- |
| Context building, truncation | a busy host | **yes** — the day has 3 199 hosts and the busiest carries 14 662 flows in three hours, so a rendering that overflows its budget is real traffic rather than a constructed one |
| `no_match` everywhere | ordinary traffic + real feed | **yes** — demo 3 pass A |
| A positive match, escalation, the analyst | traffic intersecting the feed | **yes, generated** — `scripts/plant_indicators.py`, five scenarios |
| `stale` / `missing` / `failed` enrichment | snapshot **timing**, not new traffic | **yes** — `load_threatfox(now=…)` dates a snapshot, a bad URL produces a typed failure, and loading nothing produces `missing` |
| Quarantine | malformed records | **yes, trivially synthesised** — the input contract is `extra="forbid"`, so one unknown key does it |
| A second enrichment source | a second mapping migration | **yes** — `tests/test_end_to_end.py::second_source_migrations` already builds one; a demo would reuse it rather than invent a second |
| Time-correct enrichment over the day | the capture moved to meet a loadable snapshot | **yes, generated** — `scripts/rebase_capture.py` |
| **Genuine malicious or multi-stage activity** | a real incident | **no, and no generator fixes it** |
| **Ground truth for any verdict** | analyst labelling | **no** |

So: **no new *traffic* is needed for demos 1–8.** What the existing capture cannot
supply is the last two rows, and those are not a demo problem — they are
[`evaluation-corpus.md`](evaluation-corpus.md)'s subject and they gate
measurement, not demonstration. Candidate public datasets that *do* carry
genuine multi-stage activity are listed in
[`evaluation-corpus.md`](evaluation-corpus.md) §10, with what adopting one would
cost: they are PCAP and this pipeline ingests flow records, and their age makes
contemporaneous enrichment impossible. A planted indicator makes the escalation path
*run*; it does not make the verdict *right*, and
[`synthetic-corpus.md`](synthetic-corpus.md) §5 is the list of what it cannot
measure.

**One practical caveat that is not about sufficiency.** `data/demo/` is
gitignored and not in this repository, so demos 2 and 9 run only where that
capture exists. Demos 1 and 3–8 run from committed data, which is why the
proposed set deliberately puts every *distinction* on committed inputs and
leaves the uncommitted capture to the two scale demos.

## 5. How 4–8 are built

None of them needed a new capability; each arranges existing parts. They share
`demo/_common.py` — a private schema, a staged capture, ingestion over the wire
and a scripted endpoint — because five demos each opening a schema and crossing
the broker is the same forty lines five times, and forty lines copied five times
is five places for *"how a demo sets up"* to drift.

**Demos 1–3 do not use it.** They predate it, they work, and demo 3 costs live
model calls to re-verify; the duplication between them and `_common.py` is real
and recorded here rather than hidden. Folding them in is a cleanup, not a fix.

**4–7 script the model endpoint** rather than calling the configured one. A demo
about what happens when a model fails its schema cannot wait for a live model to
do it, and a demo about replay needs the same answer twice. Demo 3 is the one
that runs against the live endpoint, which is why it is also the one whose
outcome varies between runs.

- **4** loads the same snapshot three ways (fresh, old enough to be stale, not at
  all) and prints the enriched context each time. The point is that four states
  stay four.
- **5** imports `plant_address` and `plant_resolved_only` from
  `scripts/plant_indicators.py` rather than shelling out to it, so what
  "contacted" and "resolved only" mean as data has one definition and the corpus
  generator and the demo cannot disagree about it. Three hosts in one window, and
  the third is unplanted so the gate has something to clear.
- **6** needs a scripted endpoint (the one `tests/test_assessments.py` already
  has) for the schema-invalid case; the rest is a malformed record, a tightened
  rendering budget and a bad feed URL.
- **7** and **8** wrap `scripts/replay_assessment.py` and `scripts/backup.py`,
  which already exist — these are the cheapest two.
- **9** is 1 + 3 over the output of both generators, and is the only one whose
  cost needs thought: at `[budgets.triage]`'s 8 000 tokens and the gate on, the
  model call count is the number of contexts holding a claim, which the planting
  decides.
