# 0040 — Durability: the two halves of the record, and a logical backup of the tables

Status: accepted — 2026-09-12 (task 53, D9 Operations)

## Context

`concept/08-open-questions.md` files one line under *cross-cutting and urgent*:

> Durability and backup for the single store, now that findings and evidence
> exist only there, which is a correctness concern rather than an ops detail.

The sentence is precise about why it is not an ops detail. Everything else in
this project has a second place it could come from — the input is on disk as a
retained capture, the flatten and signal layers are views over a table, the
emitted message is a projection of rows. The feed snapshot an assessment cited,
the evidence, and the assessment itself have no second place. Re-asking the model
produces a different run. Re-fetching a feed produces a *different snapshot*, and
`concept/08` says what that means: *"a later snapshot changes what an identical
context would say."* So losing those rows is not losing a cache; it is losing the
record that a verdict was entitled to cite.

Three things were already settled and constrain any answer:

- **The broker retains nothing that can be relied on** — consume-once,
  restart-volatile, a topic never re-readable (`concept/07`). Retention is not a
  durability mechanism and 5 minutes of it is not 5 minutes of safety.
- **The output topic is egress, not storage** — *"nothing may be recoverable only
  from it"* (`concept/03`).
- **One store.** No second database, no checkpoint store, no file-backed state
  (`concept/instruction.md` §2), and since task 50 that is a test:
  `tests/test_architecture_boundary.py::test_the_package_writes_to_no_file_and_starts_no_process`.

## Decision

**1. The durable record is the retained captures plus the engine's durable
tables, and those two halves recover different things.** Neither substitutes for
the other, and this is measured rather than asserted:
`tests/test_durability.py::test_a_replay_without_a_restore_does_not_bring_back_an_assessment`
replays a capture into an empty migrated schema and the analytical tables stay
empty. `docs/runbook.md` §15 is the table.

**2. The backup is logical, not a copy of `.rwdata/`.** It copies rows out of
every base table through the PostgreSQL wire protocol and puts them back the same
way. Three reasons, in order of weight:

- *It is the form that can be tested.* A physical copy of the store directory can
  only be restored by starting an engine on it, and only one engine runs per
  machine (`docs/runbook.md` §2) — so a physical restore could not be exercised
  by the suite at all, and an untested backup procedure is a belief.
- *It is the form that crosses a version.* A store directory is a RisingWave 3.0.3
  artifact. Typed rows are not.
- *It is the form that reads as data.* A backup whose contents can be inspected,
  diffed and counted is a backup whose restore can be reconciled.

What it costs is the point of the residual-risk list in §15: no read transaction
means no point-in-time snapshot, and a restore holds the file in memory.

**3. Materialized views are not backed up, because they rebuild.** A restore
applies the migrations to the target and inserts the tables' rows; the views
backfill from the tables — measured over the whole schema by
`test_the_materialized_views_rebuilt_without_being_in_the_backup`, extending the
single-view measurement in `docs/runbook.md` §8. Including them would mean
restoring derived state, which is how a store ends up with a view that disagrees
with the table under it.

**4. The migration ledger travels in the header and is compared, never written.**
It is the schema's identity, not its contents. A restore into a schema whose
ledger, relation set or column types differ is refused by name rather than
adapted, because adapting a stored row to a column set it was not written against
is migrating a row forward, which `concept/instruction.md` §2 forbids outright.

**5. The bytes live in `scripts/backup.py`, not in the package.**
`helena.durability` turns a connection into lines of text and lines of text back
into rows and touches no path. A backup file is not a second store — nothing in
the pipeline reads it, nothing falls back to it, and nothing is recoverable only
from it — but keeping the file handling outside the package is what keeps that
distinction structural instead of a claim, and it keeps task 50's boundary test
true.

**6. Four refusals, never collapsed.** `BackupIncomplete` (the file is not
whole), `BackupMoved` (the store changed while it was read), `RestoreRefused`
(the target cannot receive this backup) and — on the other half of the record —
`helena.normalizer.CaptureStoreUnreachable`. The operator does something
different about each.

**7. The capture store has a startup check, and `scan_captures` now fails loud on
an unreachable directory.** `uv run scripts/dev_check.py --captures DIR` verifies
that the directory is reachable and that every capture hashes to its own name.
The hash is not a formality: a capture's sha256 is half of every event id and
every raw-record reference in the store, so a capture that changed under its name
makes every citation pointing into it a citation to different records.

## What this changed on the way in

`scan_captures` returned `{}` for a directory that did not exist, for a path that
was a file, and for a directory that was there and empty. Three states, one
value, and the wrong one was the dangerous one: a mistyped `--captures` read as
*"this deployment retained no captures"*, which `helena.status` would report as a
deployment that had lost every record it ever ingested. `docs/runbook.md` §13.1
already refused to print that zero when the flag was *absent* and could not tell
the two cases apart when it was present. It is now
`CaptureStoreUnreachable`, a subclass of `CaptureError` so every existing handler
still catches it, and *reachable and empty* still returns `{}`.
`concept/instruction.md` §2: absence is not emptiness.

## Alternatives rejected

**`risingwave ctl meta backup-meta` plus a copy of the state store.** The engine
has its own meta-snapshot mechanism. It backs up *metadata*, so it is only
meaningful beside a consistent copy of the Hummock object store under
`.rwdata/state_store`, and restoring the pair means starting an engine on it —
which is the untestable path above. It is also a 3.0.3 artifact end to end. Worth
revisiting if a deployment ever runs more than one engine; recorded here so the
next person does not have to rediscover that it exists.

**Backing up the reference tables by re-loading the feed instead.** Tempting,
because a feed is fetchable. It is wrong for the reason the Context above gives:
the snapshot an assessment cited is not the snapshot a re-fetch returns, and a
restore that re-fetched would silently rewrite what a stored verdict claims to
have seen.

**A backup index or manifest file listing the backups.** That is a second store
with a second copy of a fact. The filename carries its UTC timestamp and
`ls`/`sort` answers the only question anyone asks of a backup directory.

## Consequences

- Durability is now a suite (`tests/test_durability.py`, 25 tests) rather than a
  runbook paragraph, and the backup's relation set is read from the engine's
  catalogue — so a migration that adds a table is in the backup without anyone
  remembering, and a migration that puts an un-encodable column type on a table
  fails a test rather than an operator's backup.
- A restore performed after a context has left the 24-hour retention horizon does
  not bring the *retained* views back, because the horizon is re-evaluated as rows
  arrive. The tables are exact; what is derived from the clock is derived again.
  Recorded as residual risk 3 in §15 and **not measured** — it needs a day to
  pass between the backup and the restore.
- Nothing schedules a backup, rotates one, or copies one off the machine. That is
  deliberate scope: there is no deployment yet, and a scheduler would be a
  timer this repository does not have anywhere else.
- `concept/08-open-questions.md`'s cross-cutting entry is answered for the single
  store and **not** for the two hazards beside it in the same paragraph: the
  record that was silently lost at a catch-up boundary, and replayability as a
  goal rather than a claim. This record does not touch either.
