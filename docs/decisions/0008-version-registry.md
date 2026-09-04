# 0008 — The version registry, and why a revision is never an edit

**Status: accepted.** Task 5 (D0 Foundations).
**Authority:** `concept/07-principles.md` ("Versioning": the nine dimensions
recorded on every assessment, the aggregation constant asserted equal in SQL and
Python, taxonomy and agent schemas frozen once recorded),
`concept/02-concepts-and-taxonomy.md` ("The vocabulary is frozen as a version. A
revision is a new version module, never an edit"), `concept/06-technology.md`
(agent output schemas are Pydantic, historical versions retained as frozen
classes), `concept/instruction.md` §2 (reproducibility) and §3 (editing the
taxonomy is an escalation).

`helena.versions` holds `VersionSet` — the nine dimensions — and
`AGGREGATION_VERSION`. `sql/migrations/0002_aggregation_version.sql` holds the
engine's copy of that one constant. `tests/test_versions.py` asserts the two
equal by asking a real engine.

## Why every dimension is recorded, and why none of them defaults

The failure being prevented is the quiet one: **a hosted endpoint changes
beneath a stable API name**, and a replayed assessment scores against something
other than what ran. So model, prompt, schema, rendering, taxonomy, enrichment
snapshot, normalization snapshot, policy and aggregation are all recorded, and
replay validates a stored
assessment against *the version that assessment recorded* — never against
current code, and never after migrating the row forward, which would make replay
reproduce the migration instead of the original run.

Every dimension is required at construction. There is no default and no
"current" constructor, including for the aggregation version, because the two
uses point in opposite directions: writing a row records what actually produced
it, and reading one back for replay must take what is stored. A set completed
from current constants would look identical to one that was recorded, which is
exactly the class of silent lie the registry exists to prevent.

`model_version` is the identity the model's **response** reported, not the
configured model name — the configured name is the thing that stays stable while
what answers to it changes. The increment that first calls a model owns getting
it; the registry only refuses to record nothing.

**The field names are the column names.** `VersionSet.stamp(row)` returns the
row with the nine version columns added and refuses a row that already carries
one; `VersionSet.from_row(row)` is the replay direction and names any dimension
the row does not record. One set of names, so a written row and a read row
cannot disagree.

## The aggregation version has two homes, and the drift is a failing test

`concept/instruction.md` §2: *two copies of a version constant must be asserted
equal by a test — the SQL and the Python. Two copies that can drift are worse
than none.* The Python copy is `helena.versions.AGGREGATION_VERSION`; the SQL
copy is a **plain view** created by migration 0002:

```sql
CREATE VIEW helena_aggregation_version AS SELECT 'v1' AS aggregation_version;
```

A view rather than a table: there is one constant, one row and no writer, so a
table would be state nobody maintains — and an `UPDATE` to it would rewrite the
version under rows that already recorded one. Not a materialized view: that is
disk for a literal. Not a column `DEFAULT` on an assessment table either, for
two reasons — there is no assessment table yet and inventing one here would be
writing the D3/D4 contract ahead of the increment that needs it, and a default
is a silent fallback for a writer that forgot to record a version, which is the
one thing this registry may not do.

The test does not grep the file. It applies the migrations to a throwaway engine
and runs `SELECT aggregation_version FROM helena_aggregation_version` —
verified by mutation: changing the Python constant alone fails the test.

## A streaming view cannot read it — measured, not assumed

Against RisingWave 3.0.3:

```sql
CREATE MATERIALIZED VIEW m AS
    SELECT l.version, v.aggregation_version
    FROM helena_schema_migrations l CROSS JOIN helena_aggregation_version v;
-- Not supported: streaming nested-loop join
```

The same query written as `JOIN … ON true` and as a scalar subquery is rejected
identically. A batch `SELECT` over the view is fine. So a D2 aggregation view
**carries the literal itself**, and its own test asserts that the rows it
produces equal `AGGREGATION_VERSION` — the same equality, asserted the same way,
one level further down. `tests/test_versions.py` pins the engine behaviour so an
engine version that lifts the restriction is noticed rather than assumed.

## A revision is a new version, never an edit

The rule from `concept/02-concepts-and-taxonomy.md` and
`concept/07-principles.md`, stated once here for everything downstream:

- **The taxonomy** is frozen as a version. A revision is a **new version
  module** — `v2` beside `v1`, with `v1` left importable exactly as it was.
  Editing it in place silently changes what every historical row claims.
  Editing the taxonomy at all is an escalation (`concept/instruction.md` §3).
- **Agent output schemas** are the same: historical versions are retained as
  frozen Pydantic classes, and replay validates against the recorded one. A
  migration that reshapes a stored field is rejected outright.
- **Prompt and rendering** versions follow the same shape: what triage saw is
  pinned by the recorded version, not reconstructed from current code.
- **The aggregation version** is bumped when the aggregation changes what a
  context *means* — not when a view is reformulated with the same meaning. The
  bump is a **new migration** that drops and recreates the view with the new
  value, together with every aggregation view carrying the literal. On the SQL
  side this rule is structural rather than a convention: the migration runner
  refuses an applied file whose checksum changed
  (`docs/decisions/0007-sql-migrations.md`), so editing 0002 is not available.
- **The enrichment snapshot** version is written by the loader with every load;
  a claim cites the snapshot it matched, and replay joins the snapshot that was
  current then.

## Amendment, 2026-09-04 — a ninth dimension

`normalization_snapshot_version` was added, on the operator's decision, after
task 15 found the gap: the Public Suffix List snapshot that decides a registrable
domain had no dimension to record it.

It is **not** `enrichment_snapshot_version`. That one is the feed snapshot an
enrichment join matched against. Normalization runs *before* enrichment and
settles what the join key even is, and the list is revised regularly — its
wildcard and exception rules mean a name can fall under a different registrable
domain under a later snapshot. Without its own dimension, an assessment citing a
registrable domain and replayed later could score against a different scope than
the one that ran, which is the exact failure this registry exists to prevent.

Added now rather than at the increment that needs it because nothing stores
version columns yet, so there are no rows to migrate forward and no frozen schema
to break — the alternative was to add it once assessments existed, when it would
have been a change to stored data rather than to a class nothing has written.

## What was not done

- **No assessment table, and no version columns in SQL.** The columns are named
  by `VERSION_COLUMNS` in Python; the migration that creates the first
  version-carrying table declares them, and a stamped row whose column names do
  not match will fail loudly on the INSERT rather than silently drop a version.
- **No values for the dimensions that do not exist yet.** Prompts,
  renderings, taxonomy modules, feed snapshots and policies arrive in D2–D5, and
  a constant invented here would be a version for nothing.
- **No version table in the engine and no version-set identifier.** Whether a
  stored assessment carries the nine columns inline or cites a version-set row
  is a question for the increment that writes the first assessment; deciding it
  here would be a join table with no rows.
- **No `Version` ordering or comparison.** Nothing compares two versions yet;
  the identifiers are opaque tokens, deliberately permissive because a model
  version is whatever the endpoint calls itself.
