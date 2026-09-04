# 0016 — The view-layering rule and the materialization policy are enforced by declaration and by execution

**Status: accepted.** Task 17 (D2 Context).
**Authority:** `concept/03-architecture.md` (three view layers — flatten →
signal → analytical; an analytical view never reads the flatten layer or the
source; *do not materialize an intermediate that only feeds an aggregate*, at a
measured 42 % more disk), `concept/06-technology.md` (the cost table, and
"`CREATE MATERIALIZED VIEW` is the habit-forming default"), and
`concept/instruction.md` §1 (**plain view by default**, every definition states
which it is and what reads it), §2 (**view layering holds**) and §7.

## What was decided

**Every object a migration creates declares itself**, in a comment block
immediately above its `CREATE`, in four fields:

```
-- Layer:    signal
-- Object:   MATERIALIZED VIEW. <why, in prose>
-- Reads:    helena_signal_entity_observations, helena_signal_host_context
-- Read by:  helena_signal_context_entities_retained, ..., tests/test_context.py
```

`helena.migrations.declarations()` parses them and **refuses** a file that does
not carry them. It refuses six ways: a `CREATE` with no block above it, a block
missing any of the four fields, a `Layer:` that is not one of the six, an
`Object:` that disagrees with the `CREATE` under it, a `Reads:` that is prose
rather than a list of relations, and — the materialization half — **a
`MATERIALIZED VIEW` whose `Read by:` names nobody.**

The layers are `operational`, `source`, `reference`, `flatten`, `signal`,
`analytical`, and `helena.migrations.MAY_READ` says which may read which. The row
the invariant is about is `analytical`, which may read `signal` and `reference`
and **nothing else** — not the flatten layer, not the source.

## Why the declarations can be trusted

A comment is not evidence. `tests/test_view_layering.py` closes that gap before
any layering conclusion is drawn from a comment:
`test_the_declared_reads_are_the_dependencies_the_engine_recorded` asserts the
`Reads:` lines of all thirty objects **equal `rw_catalog.rw_depend` on a running
engine**, expanded the way the engine expands them.

That expansion is itself the measurement the materialization policy rests on.
Measured against RisingWave 3.0.3: **a plain view is inlined into the plan of
whatever reads it**, so the engine records a materialized view over a plain view
over a table as depending on all three, and the expansion stops at a table or a
materialized view because those are *read* rather than inlined. A plain view is
therefore not a cheap object — it is not an object at all at runtime.

`test_the_schema_holds_exactly_what_the_migrations_declare` closes the same gap
for `Object:`, against `information_schema.tables`, in both directions.

## The cost, measured here

`scripts/dev_check.py --storage` (also `make storage`) reports what each relation
of a migrated schema stores, from `rw_catalog.rw_table_stats` — the object's own
rows plus the state of the streaming job behind it, which is where most of a
materialized view's disk goes. It is the engine's own accounting, an estimate
rather than a `du`, and it moves as compaction runs.

Two things it makes observable rather than arguable, both measured on
2026-09-04 against RisingWave 3.0.3:

**A plain view stores nothing.** With records in the store and the whole signal
layer running, the nineteen plain views report **zero bytes** and every byte
reported belongs to a table or a materialized view.
`test_a_plain_view_stores_nothing_and_the_check_says_so` asserts it.

**A materialized intermediate that only feeds an aggregate costs.** Two pipelines
producing the same aggregate, one over `helena_flatten_flows` as it is and one
over a materialized copy of it:

| Input | Aggregate over the plain view | Materialized intermediate + its aggregate | Cost |
| --- | --- | --- | --- |
| the ten-record layer capture | 142 064 bytes | 159 194 bytes | **+12 %** |
| the fixture captures plus `data/ingest/flow-sample.jsonl` — 73 flow rows → 2 contexts | 119 154 bytes | 186 236 bytes | **+56 %** |

`concept/03-architecture.md`'s **42 %** is a third workload's number and this
repository does not reproduce it — **the size of the penalty is the aggregation
factor, not a constant**, so the note's figure should be read as "this cost is
real and this is its order", not as a rate. What is constant is the direction,
and that is what `test_materializing_an_intermediate_that_feeds_an_aggregate
_costs_disk` asserts; the run prints the number it measured.

## What this does not do

- **There is no analytical object yet**, so the row of the rule the invariant is
  actually about is exercised on a synthetic migration
  (`test_an_analytical_view_over_the_flatten_layer_is_a_violation`) rather than
  on this repository's SQL. The rule fires; nothing in the repository has had the
  chance to break it.
- **`Read by:` is checked for completeness of *relations*, not of readers.** Every
  relation that declares `Reads: X` must appear in X's `Read by:`; a module or a
  test named there is checked only for existing on disk. Prose about future
  readers stays prose.
- **A relation is recognised inside `Read by:` prose by the `helena_` prefix.**
  `Reads:` is a strict list and needs no prefix. Renaming the schema's prefix
  would be a naming decision that costs here.
- **Nothing is enforced about the SQL a view is written in** beyond what it reads.

## The consequence that has to be said out loud

Retrofitting declarations meant **editing migration files that had already been
applied**, which changes their checksums. `helena.migrations` refuses to run
against a ledger recording the old ones — measured, and it is the correct
behaviour (`docs/decisions/0007-sql-migrations.md`): *the engine does not hold
what this file says*.

Nothing is deployed, and the suite builds its schema from scratch every run, so
the cost was zero here — and this is the last increment at which it is zero. A
store that has had these migrations applied must be dropped and re-migrated. A
declaration added to a migration **after this point** is the same edit and the
same refusal, so a new object declares itself in the file that creates it.
