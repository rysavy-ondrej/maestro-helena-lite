# 0041 — Enrichment status: six states, four names, and the two that are derived

Status: accepted — 2026-09-12 (task 55, D9 Governance). **Recorded after the
fact.** The decision was taken across tasks 20–27 and lives in
`sql/migrations/0011`, `0013` and `0015` and in `tests/test_acceptance_enrichment.py`.
This record is where it becomes findable; it adds no rule those files do not
already enforce.

## The question this closes

`concept/08-open-questions.md`, under *blocking — must be answered inside the
stage that needs them*:

> How the enriched context represents enrichment that is missing, stale, in
> flight or failed, so triage cannot read absence of evidence as evidence of
> absence — **this is the stage's central acceptance property**.

## The answer

**1. Two columns, and they are not interchangeable.**

```
status          ok / stale / failed / missing   — what happened to the query
classification  a taxonomy path, `no_match` included — what the source said
```

`classification` (and `taxonomy_version`) is NULL **exactly** when `status` is
`failed` or `missing`: `concept/05` rule 4, a query that did not complete emits a
typed error and no taxonomy object. So a row can never present a source that
could not be asked as a source that answered and found nothing. RisingWave has no
CHECK constraints, so the constraint is enforced in Python at construction and
`tests/test_evidence.py` is what makes it fail.

**2. `no_match` is a classification and never a status.** It is the answer
`status = 'ok'` got. `sql/migrations/0011_enrichment_evidence.sql` says it at the
column.

**3. `ok` is stored; `stale` and `missing` are derived.** Two of the four names
are properties of a row and two are properties of *now*
(`sql/migrations/0013_feed_snapshots.sql`):

| Name | Where it comes from | Why |
| --- | --- | --- |
| `ok` | stored on the claim | it is what happened when the query ran, and that is true forever |
| `stale` | a plain view over `now()` against the source's own `refresh_interval_seconds` | a function of the clock, so a stored value would be wrong the moment time passed |
| `missing` | a LEFT JOIN from the entity finding no snapshot for that source | not a property of any row, because the rows do not exist |
| `failed` | the ledger row in `helena_reference_feed_snapshot` | a load that did not complete wrote no claim to carry it |

**4. A stale snapshot's negative is a real `no_match` with a date on it.** The
row says both — `status = 'stale'` beside `classification = 'no_match'` — and
that combination is deliberate rather than tolerated. A stale snapshot *did*
complete its query; it completed it a while ago. Forbidding the pair would mean
dropping the row (the absent-row failure this whole property exists to prevent)
or relabelling a real negative. What a reader needs is to tell a stale negative
from a fresh one, and `test_a_stale_negative_is_never_mistakable_for_a_fresh_one`
is that. **This is where the suite disagrees with task 25's step 3, on purpose;
`concept/` outranks `prd.json`.**

**5. `in_flight` is not an enrichment status, and that is the interesting part.**
There are **six** states a reader must tell apart and only four names, because
the sixth — a load part-written, claims stored and ledger row not — *has not
finished having an outcome*. `helena_reference_feed_snapshot`'s outcomes are
`loaded`, `unchanged`, `failed`, and there is no `in_flight` among them.

What makes it safe is an **ordering, not a status**:
`helena.enrichment.load_threatfox` writes its claims, `FLUSH`es, and only then
writes the ledger row, so **the ledger row is the commit point**. A snapshot
nothing has committed has no validity interval, so its claims cannot be joined,
and the entity reads `missing` or `failed` with no classification.
`test_a_load_in_flight_is_invisible_until_its_ledger_row_lands` reproduces the
state out of a real load and asserts both halves: no hit, and no `no_match`.

`in_flight` *does* exist one layer up, as one of the agent contract's gap kinds
(`helena.contracts.v1.IN_FLIGHT`, [0022](0022-the-composition-rule.md) §the seven
kinds) and in both frozen prompts. That is not an inconsistency: a gap kind is
what an *agent* reports about a thing it could not see, and an agent can be shown
a rendering while a retrieval it triggered is outstanding. An enrichment claim is
a row, and a row is written or it is not.

## What this does not settle

- **Whether triage actually reads the distinction correctly.** The distinction is
  present in the rendering ([0018](0018-the-triage-rendering.md)) and in both
  prompts, and the prompts tell the model that none of the four means "found
  nothing". Whether a model honours it is a measurement, and it needs the corpus
  (`docs/evaluation-corpus.md`). Unmeasured, and said so.
- **The per-source refresh schedule that `stale` is computed against.**
  `sslbl-ja3` has `refresh_interval_seconds = None` and cannot go stale, because
  it is not being refreshed ([`docs/sources/sslbl-ja3.md`](../sources/sslbl-ja3.md)).
  A source with no schedule and no artifact is a different thing from a fresh one
  and the descriptor is where that lives.
