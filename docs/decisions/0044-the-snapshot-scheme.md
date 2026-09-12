# 0044 — The snapshot scheme: one ledger, intervals, and history that is not deleted

Status: accepted — 2026-09-12 (task 55, D9 Governance). **Recorded after the
fact.** The decision was taken in task 23 and corrected task 22's loader on the
way in; it lives in `sql/migrations/0013_feed_snapshots.sql` and
`sql/migrations/0015_enriched_context.sql`. This record is where it becomes
findable.

## The question this closes

`concept/08-open-questions.md`, blocking, enrichment: **the snapshot and
versioning scheme, and how replay selects the snapshot current at event time.**
`concept/02`: *"Replay joins the snapshot current at event time, not today's."*
`concept/05`: *"write a snapshot version with every load and keep enough history
for replay."*

The reason it is not cosmetic: a context from last Tuesday enriched against
today's feed would be a different assessment every time it was read, and a stored
one could never be reproduced. ThreatFox regenerates every few minutes, so this
is the ordinary case rather than an edge.

## The answer

**1. A snapshot version is the sha256 of the fetched bytes.** NULL on a failure,
because a failed load has no snapshot and a row naming both a snapshot and a
failure reads as neither — `helena.enrichment.FeedSnapshot` refuses it.

**2. One ledger for every feed, not one table per feed.**
`helena_reference_feed_snapshot` is a TABLE, one row per load **attempt** per
source: `attempted_at`, the redacted `source_url`, an `outcome` of `loaded` /
`unchanged` / `failed`, the `snapshot_version`, and a JSONB `counts`.

The counts are JSONB rather than columns because they are not the same across
feeds — ThreatFox counts entries read, claims stored and skipped file hashes, and
a feed with no unmappable indicator type would count two of those. **A column per
feed's idea of a count is how a shared table stops being shared.** What every
feed has in common — when, what came of it, which snapshot — is columns.

**3. History is kept, and task 22's loader was wrong to delete it.** That loader
replaced its claims insert-then-delete, leaving exactly one snapshot. That shape
is right for the Public Suffix List, which holds one snapshot on purpose and
whose derivation `GROUP BY`s `snapshot_version` so a second one fails loudly. For
a *feed* it is wrong: a claim records the snapshot it matched against, and
deleting that snapshot leaves a stored assessment citing a snapshot the store no
longer has — a replay that cannot be validated. **Pruning is now a deliberate
operation against a stated retention, never a side effect of loading.**

**4. The selection is a range predicate, not a "latest" subquery.** Two plain
views turn the ledger into intervals with `lead()`:

| View | Over | Answers |
| --- | --- | --- |
| `helena_reference_feed_snapshot_validity` | successful loads only | which snapshot was current, `valid_from` → `valid_to` (NULL = still current) |
| `helena_reference_feed_attempt_validity` | **every** attempt, failures included | had we tried at that moment, and how did it go |

`helena_analytical_enriched_context` joins both on the context's `window_start`
(`>= valid_from AND (valid_to IS NULL OR < valid_to)`). The first gives the
claim; the second is what tells `failed` from `missing`
([0041](0041-enrichment-status-representation.md)).

**Failed attempts are excluded from the snapshot ordering on purpose**: a failure
left the previous snapshot in place, so it must not end that snapshot's validity.
That is `concept/instruction.md` §6's *"a failed fetch leaving an empty table"*
trap, expressed as a `WHERE`.

**5. Nothing computes a disappearance.** The recent export is a rolling window,
not a cumulative archive, so an indicator present in snapshot N and absent from
N+1 has either **aged out or been retracted, and the export says which by saying
nothing.** `concept/02` settles what may be concluded and it is very little:
*"removal from a feed is not exoneration."* Keeping the old snapshot is what
makes that possible — the claim stands, dated, against the snapshot that carried
it. A view that diffed two snapshots would be asserting a difference the source
does not distinguish.

## What this does not settle

- **The retention of the snapshot history itself.** The scheme makes pruning
  deliberate; it does not say when. A snapshot cited by a stored assessment may
  not be pruned, which is the same *freeze-before-evict* rule
  `concept/07` states for contexts — [`docs/deferred.md`](../deferred.md),
  *retention and freezing*.
- **Whether an identical replay reproduces an identical assessment.** The
  versioned inputs are stored and the replay validates against the recorded
  versions ([0035](0035-assessment-replay.md)); the model is not deterministic,
  and `concept/01` puts *"identical inputs replay identically"* on the
  not-claimable list. Determinism is not replayability.
