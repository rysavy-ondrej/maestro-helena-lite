# MAESTRO HELENA

Host-context enrichment and LLM-enhanced network analysis: a prototype that turns
flow telemetry into windowed host contexts, enriches them against static threat
intelligence, and has two agents assess them — read-only, analyst-supporting,
non-blocking.

**Maturity: experimental.** The skeleton exists and is under construction. No
claim is made here about verdict quality: the evaluation corpus does not exist,
and every measurement is gated on it.

## The authoritative source is `concept/`

**`concept/` describes what HELENA is, and it wins over this README, over any
docstring, and over any comment in the code.** If code and a concept note
disagree, the note is right and the code is a defect.

| Note | What it settles |
| --- | --- |
| [`concept/README.md`](concept/README.md) | The index and the six-stage shape |
| [`concept/01-goal-and-scope.md`](concept/01-goal-and-scope.md) | The problem, the scope, and what may not be claimed |
| [`concept/02-concepts-and-taxonomy.md`](concept/02-concepts-and-taxonomy.md) | Vocabulary, taxonomy, scope-before-severity |
| [`concept/03-architecture.md`](concept/03-architecture.md) | Stages, components, the single store, the boundaries |
| [`concept/04-the-two-agents.md`](concept/04-the-two-agents.md) | Triage and Analyst |
| [`concept/05-threat-intelligence.md`](concept/05-threat-intelligence.md) | Sources, tiers, loader and tool rules |
| [`concept/06-technology.md`](concept/06-technology.md) | Python 3.12, uv, RisingWave, Blink, Pydantic |
| [`concept/07-principles.md`](concept/07-principles.md) | The rules an implementation may not break |
| [`concept/08-open-questions.md`](concept/08-open-questions.md) | What is unsettled, and what it blocks |
| [`concept/instruction.md`](concept/instruction.md) | **Binding build rules** and the definition of done |

Decisions this repository has made, with their reasons, are in
[`docs/decisions/`](docs/decisions/).

## Layout

```
src/helena/          one package, one module per architecture component
  normalizer.py        per-format adapters, flow records -> validated events
  context.py           windowed host context, entity extraction, enriched view
  enrichment.py        feed loaders and snapshot-versioned reference tables
  agents.py            the versioned agent contract, Triage and Analyst
  tools.py             approved providers as cache-first tools
  orchestration.py     deterministic routing, budgets, persistence, replay
  sink.py              egress of every assessed context to the output topic
  broker.py            the Kafka wire protocol, both ends, and nothing else
  config.py            the fail-loud environment loader and Secret
  observability.py     the one structured log channel and its redactor
  migrations.py        applies sql/migrations/ and records what it applied
sql/migrations/      the engine's schema: NNNN_name.sql, applied in order
tests/               the one pytest suite, mirroring the package
scripts/             dev-up / dev-down, the pin-and-endpoint check, migrate, replay
docs/decisions/      why each dependency and each layout choice is here
docs/versions.md     the pinned binaries and their checksums
docs/runbook.md      running the engine and broker, and the libpython hazard
bin/                 third-party binaries the project runs, not builds
data/                real samples, for shape decisions and for tests
```

There is one package, one test suite and one environment. A second package, a
second test runner, a monorepo layout or a build step would each be a change to
`concept/instruction.md` §1, not a convenience.

## Working in it

Everything runs through `uv` against the `.venv/` at the project root. Never
`pip`, never a second virtualenv, never a system interpreter.

```bash
uv sync                 # install the locked environment
uv run pytest -q        # the one test suite
make check              # lockfile in sync, sources compile, suite passes
```

`uv.lock` is the reproducibility contract and is committed; the environment is
disposable and rebuilt from it.

The local infrastructure — the broker and the streaming engine — comes up with

```bash
scripts/dev-up          # verify the pins, run both, wait until both answer
scripts/dev-down        # stop them again
```

The suite needs neither: a fixture starts the pinned binary when nothing is
answering. Both are third-party binaries the project *runs*, pinned in
[`docs/versions.md`](docs/versions.md); nothing here downloads one.

RisingWave is dynamically linked against `libpython3.12.so.1.0`, and **putting
another Python minor under that name fails with no symptom at all** — it starts,
serves SQL and reports the right version. [`docs/runbook.md`](docs/runbook.md)
§1 has the measurements and the check that catches it.

## The engine schema

The engine's view and model definitions are project source. They live in
`sql/migrations/` as plain numbered `.sql` files applied in order — no SQL
transformation framework, which would be a major dependency in the data path
ahead of any measured need for one.

```bash
uv run scripts/migrate.py --status   # what is applied, what is pending
uv run scripts/migrate.py            # apply everything pending, in order
```

Applying is idempotent, and everything else the runner does is refusal: a gap
in the numbering, two files with one number, a file recorded as applied that
is no longer on disk, a rename, or **any edit to an already-applied file** —
its sha256 is recorded when it is applied. To change something that shipped,
write the next migration. There is no rollback and there cannot be one:
RisingWave has no transaction around DDL, so a file that fails partway is
recorded as `failed` and blocks the runner until a human has resolved it.

**Migrate before data flows.** The broker is consume-once, so a view created
after ingestion started begins empty and there is no backlog to fill it from
— only a replayed capture.
[`docs/decisions/0007-sql-migrations.md`](docs/decisions/0007-sql-migrations.md)
and [`docs/runbook.md`](docs/runbook.md) §5 have the rest.

## Configuration and credentials

Configuration arrives through the environment, loaded from `.env` in local
development. **`.env` is never committed and no value from it may appear in a
log, a row, a prompt, a trace, a test fixture or a report** — names are fine
everywhere, values nowhere. A missing value is a startup error naming the
variable; it is never a default and never a fallback to another agent's setting.

Copy [`.env.example`](.env.example) to `.env` and fill it in; it lists every
variable the project reads, with an empty value. `helena.config.Settings.load()`
is the only path that reads them — resolution is agent-specific, then general,
then fail, and an empty or whitespace-only value counts as missing. Tokens and
provider keys are `helena.config.Secret`, which renders redacted in `str`,
`repr` and every serialization; `reveal()` is the one deliberate way out, at the
point of use. The variable names and why each is required are in
[`docs/decisions/0004-configuration-variables.md`](docs/decisions/0004-configuration-variables.md).

`helena.observability` is the one log channel: one JSON object per line on
stderr, with a fixed set of top-level keys, carrying the tenant and sensor from
`Settings`. **Observability is local structured logs only** — a hosted tracer
would be a second egress channel for prompts and retrieved text, and a boundary
test keeps every tracing SDK out of the environment as well as out of the
imports. Redaction happens at the emitter rather than at the call site: every
value is swept for configured credentials, `outbound_request` and `exception`
strip the request URL structurally, and the serialized line is swept once more
before it is written. What it covers and what it deliberately does not guess at
are in
[`docs/decisions/0005-structured-logging-and-redaction.md`](docs/decisions/0005-structured-logging-and-redaction.md).

## Versions

Every row an assessment could cite records eight versions — model, prompt,
schema, rendering, taxonomy, enrichment snapshot, policy and aggregation —
because **a hosted endpoint can change beneath a stable API name, and an
unrecorded change silently breaks replay**. `helena.versions.VersionSet` is that
record; its field names are the column names, `stamp(row)` adds them and refuses
a row that already carries one, and `from_row(row)` is the replay direction and
names any dimension the row does not record. Nothing defaults: a stored
assessment is validated against the versions **it** recorded, never against
current code, and a set completed from current constants would be
indistinguishable from one that was really recorded.

The aggregation version is the one constant that exists twice, in
`helena.versions.AGGREGATION_VERSION` and in
[`sql/migrations/0002_aggregation_version.sql`](sql/migrations/0002_aggregation_version.sql).
`tests/test_versions.py` asserts the two equal by applying the migrations to a
throwaway engine and selecting from the view — two copies that can drift apart
are worse than none.

**A revision is a new version, never an edit.** A taxonomy or agent-schema
revision is a new version module beside the old one, which stays importable
exactly as it was; the aggregation version is bumped in a new migration, and the
migration runner's checksum makes editing the applied one impossible.
[`docs/decisions/0008-version-registry.md`](docs/decisions/0008-version-registry.md)
has the rule, what it costs and what was deliberately left out.

## Ingest: the input contract, the captures, and the events

The only input is **one flat JSON object per observed flow**, with inline DNS,
TLS and HTTP observations. `helena.normalizer.FlowRecord` is that record exactly
as a producer supplies it: it validates shape, not meaning, and it carries **no
tenant, no sensor, no schema version and no raw-record reference** — all four are
assigned at ingestion, never read from the record. Unknown fields are refused
rather than coerced, no type is coerced either, and `as_supplied()` round-trips a
parsed record back to the JSON it came from, asserted over all 62 records of
`data/ingest/flow-sample.jsonl` and both capture fixtures.

A **capture** is a retained file of flow records identified by the sha256 of the
file, and the captures are the durable record for replay — the broker is
consume-once and retains nothing you can rely on. `describe_capture` gives a
capture's hash, record count and byte size; `scan_captures` reads a directory
whose files are named by their own digest and refuses one whose name and content
disagree. **There is no capture index and no state file**, because that would be
a second store, and one that disagreed with the files would be worse than none.

The assumption underneath: **a hash identifies a capture only once the file
closes**, so capture identity — and every event id derived from it — is
provisional under live ingestion. Nothing today ingests anything but a closed
file. `tests/test_normalizer.py` demonstrates it by appending a record and
watching the identity change, and
[`docs/decisions/0010-capture-identity.md`](docs/decisions/0010-capture-identity.md)
records the contract, the requiredness assumption behind it, and what live
ingestion has to decide.

The bytes are read by an **adapter**, and that is the boundary a second input
format has to be absorbed by: `parse(line) -> FlowRecord | ParseFailure`, with no
capture, no identity and no configuration, so an adapter cannot stamp a tenant,
decide an event id, or add a field to the event. `INPUT_ADAPTERS` is the
registration point and `HELENA_INPUT_FORMAT` names the one this deployment reads
through, so **adding an input format is an adapter and a configuration change**,
never a contract change. There are two: `flow-json`, the format every real
capture is in, and `flow-envelope`, a synthetic second format whose only job is
to make that claim measurable — the same ten records in two formats, read by two
adapters, produce events with equal observations and the same schema version.

A record an adapter refuses comes back as a typed `ParseFailure` — `malformed_json`,
`not_this_format` or `contract_violation`, three reasons that are never collapsed
— rather than as an exception, so a bad record does not stall the capture and
cannot be dropped silently. `Normalizer.ingest_capture` is what stores one: see
**quarantine** below.
[`docs/decisions/0012-input-format-adapters.md`](docs/decisions/0012-input-format-adapters.md)
has the interface, the failure vocabulary, and what the second adapter does and
does not demonstrate.

A **normalized event** is what the Normalizer produces from a record: an
`identity` block and an `observation` block, kept apart so the boundary between
what arrived and what this deployment decided is structural rather than a naming
convention. The identity is the five fields the input does not carry — tenant,
sensor, schema version, event id and raw-record reference. Tenant and sensor come
from `Settings` and are refused when blank at all three places one could be
(startup, the `Normalizer`, and the identity block itself); the raw-record
reference is the capture's digest plus the record's offset.

The **event id** is a sha256 over the tenant, the sensor and that reference, so
replaying a capture into the same deployment reproduces every id and nothing is
drawn from a clock or a counter — there is no ingestion timestamp on an event for
the same reason. The identity is in the digest as well as the capture reference
because two deployments ingesting the same file would otherwise mint the same
ids in the one store, where an `INSERT` onto an existing key is an upsert that
overwrites without raising.
[`docs/decisions/0011-event-identity-and-the-event-id.md`](docs/decisions/0011-event-identity-and-the-event-id.md)
has the derivation, what is deliberately not in it, and the note that stamping a
tenant is a seam and not yet isolation enforcement.

**Quarantine lives in the engine**, with everything else durable. A record the
adapter refuses is written to `helena_ingest_quarantine`
(`sql/migrations/0003_ingest_quarantine.sql`) with its typed reason, the contract
version that refused it, the raw-record reference and the **payload exactly as
read** — `BYTEA`, because a refused line need not be valid UTF-8, and untruncated
— and `Normalizer.ingest_capture` carries on to the next record. That closes the
open question `concept/08-open-questions.md` records about quarantined records
landing outside the single store: a file, a dead-letter topic or a side table
would each be a second store, and a refused record is evidence, because it is the
only record of which fields this project marked required are not required in the
wild.

The counter is the plain view `helena_ingest_quarantine_counts`, grouped by
identity, capture, format and **reason** — the three reasons stay three numbers.
`Quarantine.counts(capture)` joins it to the capture's own record count, which is
the only denominator that exists while the broker is consume-once, and refuses a
count that does not reconcile.
[`docs/decisions/0013-quarantine-in-the-single-store.md`](docs/decisions/0013-quarantine-in-the-single-store.md)
has the key, why there is no timestamp and no event id on the row, and what this
does not claim.

## Ingest over the wire

**The broker is addressed only through the Kafka wire protocol, on both ends.**
`helena.broker` is the only module in the package that imports a Kafka client,
and `tests/test_broker.py` asserts that structurally — along with the absence of
any HTTP or socket client in it, so the broker's own REST port is unreachable
rather than merely untouched, and the absence of any address literal anywhere in
the package. The address and the topic are `KAFKA_BOOTSTRAP_SERVERS` and
`HELENA_INGEST_TOPIC`, with no defaults.

One flow record per message, **exactly as the producer wrote it**, with the
raw-record reference in two message headers. The record cannot carry that
reference — it carries no tenant, sensor, schema version or raw-record reference
by contract — and an envelope around it would be a change to the input format for
every producer.
[`docs/decisions/0014-the-ingest-topic-message.md`](docs/decisions/0014-the-ingest-topic-message.md)
has the reasoning, including why a message with no reference stops the run
instead of being quarantined, and what that leaves open.

`Normalizer.normalize` (from a capture) and `Normalizer.normalize_message` (from
the topic) end in the same stamping, so a capture published to the topic and
consumed back produces rows identical to the same capture read from disk. That is
what makes replay through the live path a property the suite checks rather than a
diagram.

Accepted records land in `helena_normalized_events`
(`sql/migrations/0004_normalized_events.sql`) with the observation as JSONB — the
record as supplied, so an unobserved layer is an **absent key** and an
observed-but-empty one is an empty array, both measured against the engine over
all 62 real records.

`helena_ingest_counts` makes `normalized` an engine-side count, and
`ingest_counts(...)` reconciles four numbers from four places — the capture file,
the run, and the two counter views — refusing a set that does not add up.
`consumed < records` is reported rather than raised: it means records were lost
between the producer and the store, and because **the broker is not a store**
they are gone. The measurement behind that is in
[`docs/runbook.md`](docs/runbook.md) §3: a drained topic empties a few seconds
later, not instantly, while a topic nobody read keeps its records — so it is
consume-once and not a retention window, and a retry written against "never
re-readable" alone would double-ingest.

### Replay

    uv run scripts/replay_capture.py --captures <dir> <sha256> --ingest

The retained capture is the durable record, and replay is a **producer**: it puts
the capture's records back on the ingest topic in the wire form a sensor uses, and
everything after that is the live path. `--rate` is a floor on records per second;
`--ingest` also runs the ingestion side in this process — nothing else consumes
the topic in this prototype — and prints the four counters at the end.

Replaying a capture twice rewrites the same rows: every assigned field comes from
the capture, the offset and the configured identity, and an INSERT onto an
existing key is an upsert. Publishing twice without draining in between is the
case that fails, and it says so rather than reporting the lost records it
resembles.

[`docs/runbook.md`](docs/runbook.md) §8 is the procedure, including what
backfilling a newly added view actually requires — measured, and narrower than
the concept note assumed: a view over `helena_normalized_events` backfills from
the table, so what needs replaying is records that never reached the store, not
views that were created late.
