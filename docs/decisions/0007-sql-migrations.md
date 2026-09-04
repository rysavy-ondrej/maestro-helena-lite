# 0007 — The engine schema is numbered `.sql` files, applied by a small runner

**Status: accepted.** Task 4 (D0 Foundations).
**Authority:** `concept/06-technology.md` (the engine's view and model
definitions are **project source in their own right**; migrations are **plain
numbered `.sql` files applied in order**, tested by execution against a throwaway
instance; *"why not a SQL transformation framework: it would be a major
dependency in the data path"*), `concept/03-architecture.md` (one store; the
broker is not one), `concept/instruction.md` §1 (no machinery ahead of a
measured need) and §2 (fail loud; never collapse failure kinds).

## What was built

`sql/migrations/NNNN_name.sql`, and `helena.migrations` — discover, decide what
is pending, execute it, record it. `scripts/migrate.py` runs it by hand,
`tests/conftest.py::migrated_engine` runs it for the suite. No framework, no
templating, no DSL, no new dependency: psycopg was already here.

## The ledger is migration 0001, not a constant in Python

`helena_schema_migrations` is created by `0001_schema_migrations.sql` like any
other migration, and the runner treats "the table is not there" as the empty
state. The alternative — bootstrapping the ledger from a `CREATE TABLE IF NOT
EXISTS` string inside the runner — would give the engine's schema two homes, one
of them a Python string that no migration ever describes.

The cost is one honest special case: **0001 has nowhere to record its own
failure**, and `MigrationFailed.recorded_in_ledger` is `False` when that happens
so the error can say so rather than imply a row exists. It is a single
`CREATE TABLE`, so it cannot fail halfway.

## Refusals, and why each one

Everything except executing SQL is a refusal, and all but two fire before the
engine is touched at all:

| Refused | Because |
| --- | --- |
| a `.sql` file not named `NNNN_name.sql` | a file outside the ordering is indistinguishable afterwards from one that was applied |
| two files with one version | "in order" stops being defined |
| versions that are not `1..N` | a gap means a file was lost, or written against a number that already shipped |
| a recorded version with no file | the engine holds something the repository no longer describes |
| a rename or **any edit** to an applied file | the recorded sha256 no longer matches; the engine does not hold what the file says |
| a recorded `failed` | the store is half-migrated |
| a connection not in autocommit | RisingWave DDL in an open transaction is not visible to what follows; it would appear to apply and then not be there |

A checksum over the file's **bytes**, so reformatting an applied migration is a
change like any other. It is meant to be strict: the remedy is always to write
the next migration.

## There is no rollback, and `failed` is a stored state

Measured against RisingWave 3.0.3, not inferred: `CREATE TABLE a; CREATE TABLE a`
sent as one statement leaves `a` behind and then raises. **There is no
transaction around DDL**, so a file that fails partway has already changed the
store.

Rather than pretend otherwise, the failure is *typed, stored and countable*: the
ledger row carries `status = 'failed'` and the engine's error text, the runner
refuses to apply anything further, and `SELECT count(*) FROM
helena_schema_migrations WHERE status = 'failed'` is the count. `applied`,
`failed` and *absent* stay three distinct things, at the ledger and in the
exception type (`MigrationError` = nothing ran; `MigrationFailed` = something
may have). Recovery is manual and deliberate — `docs/runbook.md` §5.

## Migrate before data flows

**Every view a deployment needs must exist before ingestion starts.** The broker
is consume-once and restart-volatile (`concept/03-architecture.md`), so a record
consumed before a view existed is gone: the view starts empty and there is no
backlog to fill it from. The only way back is replaying a retained source
capture through the ingestion path. This is a deployment ordering rule, recorded
in `docs/runbook.md` §5 and in the module docstring, and it is the reason the
schema is a first-class artifact rather than something a stage creates when it
starts.

## The throwaway instance is a schema, not a process

`concept/06-technology.md` asks for migrations tested by execution against a
throwaway instance. Task 3 measured why a *process* per test is not available:
`single_node` binds fixed meta and compute ports, so a second RisingWave cannot
run beside the first. The suite therefore uses the session-scoped in-memory
engine from `tests/conftest.py` and gives each test its own **schema** —
`CREATE SCHEMA` / `search_path` / `DROP SCHEMA … CASCADE`. The engine is
throwaway (in-memory, gone at the end of the run), the store each test sees is
empty, and the migrations really execute. `engine_schema` and `migrated_engine`
are the fixtures.

## What was not done

- **No `down` migrations.** Nothing has needed one, and a reverse script that has
  never run is a claim rather than a capability. A throwaway engine is the
  prototype's undo.
- **No schema qualification in the migration files.** They are unqualified, so
  they land in `search_path` — which is what lets a test isolate them. A
  deployment gets `public`.
- **No domain schema.** `sql/migrations/` holds the ledger and nothing else,
  because at D0 there is no view to create yet: the version registry is task 5,
  quarantine is task 9, the flatten layer is task 12. Each brings its own
  numbered file.
