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
  versions.py          the nine recorded version dimensions, and stamping
sql/migrations/      the engine's schema: NNNN_name.sql, applied in order
tests/               the one pytest suite, mirroring the package
scripts/             dev-up / dev-down, the pin-and-endpoint check, migrate, replay
demo/                one script that runs ingest and context and prints the result
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

Every row an assessment could cite records nine versions — model, prompt,
schema, rendering, taxonomy, enrichment snapshot, normalization snapshot, policy
and aggregation —
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

The taxonomy is the first of these to exist. [`helena.taxonomy`](src/helena/taxonomy/__init__.py)
holds the machinery and one module per version — `v1.py` is the first — and
`helena.taxonomy.version("v1")` returns the frozen vocabulary that a row
recording `v1` is replayed against. **Emitting a new version means adding a
module**, never editing one: `v2` sits beside `v1`, `v1` keeps validating exactly
what it validated, and a version whose module is absent raises `UnknownVersion`
rather than silently falling back to the current vocabulary — a replay that
cannot be validated is a different thing from one that fails.
`tests/test_package_layout.py` refuses anything but `__init__.py` and `vN.py`
inside such a package, because a shared helper in there is a file every frozen
version imports and therefore a way to edit `v1` through a side door.

**Every source declares what it may say.** [`helena.enrichment`](src/helena/enrichment.py)
holds the registry: a source's **tier** (A–D, describing the *source* and never
the entry — which is what makes "deterministic signals escalate independently" a
testable rule rather than a judgement call), the entity types it is about, and
the taxonomy subset it may emit, versioned. `check_claim` refuses a path outside
that subset, so a mapping drifting from its published declaration is caught where
it happens. ThreatFox is tier B and the SSLBL JA3 list tier C, both as
`concept/05-threat-intelligence.md`'s catalogue rates them, and the JA3 caveat —
under a hundred fingerprints, static since 2021, untested against known-good
traffic by its own publisher — is recorded on the descriptor rather than in prose
a consumer may never open. The Public Suffix List is **deliberately not
registered**: its tier is N/A rather than unassigned, because it makes no claim
about any entity.

`source_diversity` counts how many *independent* sources a set of claims
represents, over retained origins rather than over source names — so one source
making forty claims is one, an aggregator republishing forty rows with no origin
retained is one, and the same origin arriving directly and through an aggregator
is one. That last case is the correlated-source double-count
`concept/02-concepts-and-taxonomy.md` names.

**Two levels, and the vocabulary each one closes over.** The *evidence* level
classifies an indicator — what a source says about an address, domain, URL or
fingerprint — over the roots `no_match`, `normal`, `suspicious`, `malicious` and
`unknown`. The *context* level classifies a host context, and its roots are
closed **per emitter**: triage may emit only `normal` or `suspicious`, because a
context triage could not assess is a typed failure rather than a third label,
while the analyst adds `unknown` and `malicious`. `unknown` has no sub-paths at
all — a child would claim a specificity the run does not have.

**`v1`'s evidence level is roots-only, and that is a decision rather than an
unfinished list.** `concept/02-concepts-and-taxonomy.md` adopts the evidence
level "essentially unchanged from an existing published indicator taxonomy" and
neither names that taxonomy nor reproduces it, so there is nothing in this
repository to adopt sub-paths *from* — and inventing a plausible set is precisely
what the note's own rule forbids ("emit the parent rather than guessing a child").
They arrive with the first feed that needs them, in a `v2`.

## Ingest: the input contract, the captures, and the events

The only input is **one flat JSON object per observed flow**, with inline DNS,
TLS and HTTP observations. `helena.normalizer.FlowRecord` is that record exactly
as a producer supplies it: it validates shape, not meaning, and it carries **no
tenant, no sensor, no schema version and no raw-record reference** — all four are
assigned at ingestion, never read from the record. Unknown fields are refused
rather than coerced, no type is coerced either, and `as_supplied()` round-trips a
parsed record back to the JSON it came from, asserted over all 62 records of
`data/ingest/flow-sample.jsonl`, both capture fixtures, and — when it is present
— all 239 850 records of the day capture `data/demo/20250920`.

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
ingestion has to decide. That assumption has since been tested: a second capture
refused 100 % of its records, requiredness was re-measured over both, and the
ADR's addendum says what moved and what it cost.

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

## Context: the flatten and signal layers

The Context Builder is three layers of views — **flatten → signal → analytical**
— and an analytical view reads the signal layer, never the flatten layer and
never the source (`concept/03-architecture.md`).

That rule and the materialization policy beside it are **enforced, not
conventional**. Every object a migration creates declares itself above its
`CREATE` — layer, view or materialized view, what it reads and what reads it —
and `tests/test_view_layering.py` refuses a missing declaration, refuses a
materialized view nobody reads, and asserts every `Reads:` line equal to
`rw_catalog.rw_depend` on a running engine before it draws any conclusion from a
comment. `make storage` reports what each relation costs, where a plain view
never appears with a number:
[`docs/decisions/0016-view-layering-and-materialization-policy.md`](docs/decisions/0016-view-layering-and-materialization-policy.md)
has what that was measured at.

The bottom layer exists:
`sql/migrations/0005_flatten_layer.sql` creates eight **plain views** over
`helena_normalized_events`, turning the stored JSONB observation into typed
columns once, rather than in every view above that wants a start time or a
domain.

| View | One row per |
| --- | --- |
| `helena_flatten_flows` | normalized event — the flow, typed |
| `helena_flatten_dns` | event that observed DNS: its rcode and its counts |
| `helena_flatten_dns_queries` | question asked |
| `helena_flatten_dns_responses` | resource record answered |
| `helena_flatten_tls` | event that observed TLS: SNI, versions, fingerprints |
| `helena_flatten_http` | observed HTTP layer, per version |
| `helena_flatten_http_requests` | request, HTTP/1 and HTTP/2 together |
| `helena_flatten_http_responses` | response, HTTP/1 and HTTP/2 together |

Every row carries the whole assigned identity — tenant, sensor, capture sha256,
record offset, event id and schema version.

Nothing here is materialized, because nothing queries a flatten row on its own:
`concept/03-architecture.md` measured a materialized intermediate at 42 % more
disk than the same query as a plain view. That is only free if the layer above
can still be a streaming job over it, so it was measured first and the suite
asserts it — a materialized view over these views backfills and returns rows,
including over `jsonb_array_elements(...) WITH ORDINALITY` and a `UNION ALL` of
two such branches, and `TUMBLE(helena_flatten_flows, flow_start, INTERVAL '5
minutes')` is accepted directly off the plain view.

**Absence stays distinct from emptiness**, which is why there is a row per
observed *layer* and not only rows per unpacked element: a set-returning function
turns "the array was empty" and "the layer was never observed" into the same zero
rows. A layer that was observed has a row whose count column may read 0; a layer
that was not observed has no row at all. `tcp.24` observed TLS and negotiated no
protocol (`alpn_count = 0`); `udp.28` observed no application layer and appears
in none of the seven.

[`docs/decisions/0015-the-flatten-layer.md`](docs/decisions/0015-the-flatten-layer.md)
has the rest, including what the layer deliberately does not do — it does not
split a URI into a domain, and it does not sum the two directions.

### The host context

`sql/migrations/0006_host_context.sql` creates the signal layer's first object:
`helena_signal_host_context`, one row per host per five-minute tumbling window,
aggregated off `helena_flatten_flows`. **A flow is assigned by its start time**,
so a long flow is credited entirely to the window it began in
(`concept/02-concepts-and-taxonomy.md`). The host key is the source address, so
a host seen only as a destination gets no context — in the sample that is 16 of
the 17 observed addresses. The four counters stay bidirectional and there is no
total column, and **the context carries no verdict**: no classification, no
confidence, no score.

It is the one object so far that **is** materialized. The measured rule is not
to materialize an intermediate that only feeds an aggregate; this is the
aggregate, it is queried by host and window on its own, and it is the row a
finding will cite by `context_id`.

`context_id` is `sha256` over the length-prefixed tenant, sensor, host, window
start as epoch seconds and aggregation version — the event id's construction,
plus the version. That last part is deliberate and is the difference between the
two ids: an event id says *which record*, a context id says *which computation
over which records*, so a revised aggregation is a new context rather than an
in-place edit of what an existing id means. The aggregation version is stamped
on every row from the SQL literal, because a streaming query cannot read
`helena_aggregation_version`.

What a *late record* does is the other thing, and it is measured rather than
claimed: it revises the context's row in place, changing the counters and
leaving the id alone. `concept/07-principles.md` and
`concept/08-open-questions.md` describe that differently; the migration file
records the disagreement and why the implementation follows the second.
Replaying a capture, by contrast, changes nothing — the source rows are upserts,
and the aggregate follows.

The window choice has a cost — a long flow inflates the window it started in, and
two flows either side of a boundary are never seen together — and **measuring
window coherence needs the evaluation corpus that does not exist**. No sampled
flow crosses a boundary at all, so the suite demonstrates the rule with a real
record whose duration is lengthened past one, and claims nothing about how often
it matters.

### The entity rows

`sql/migrations/0007_context_entities.sql` creates the signal layer's second
output: `helena_signal_context_entities`, **one row per entity per context**,
hanging off the host context by its `context_id`. Entities are what enrichment
is about and what it joins to (`concept/02-concepts-and-taxonomy.md`), and there
are four types, taken from where `concept/05-threat-intelligence.md` says they
come from:

| Entity type | Extracted from |
| --- | --- |
| `address` | flow destinations, and the values of A / AAAA resource records |
| `domain` | DNS query names, DNS response names, TLS SNI, and the **host part** of an HTTP or HTTP/2 URI |
| `fingerprint` | the client's JA3 and JA4 — never the server's `ja3s`/`ja4s` |
| `url` | HTTP and HTTP/2 request URIs, whole |

The rows are per entity because **arrays inside a window cannot be joined to
evidence** (`concept/03-architecture.md`), and each carries
**observation-scoped traffic**: `observed_flow_count` and the four bidirectional
counters, which are *the traffic of the flows in which the entity was observed*
— not traffic to it. An address that only ever appeared as a DNS answer carries
the octets of the lookups that mentioned it. A flow that observed one value
twice contributes its octets once.

Five flags say **which layer observed the value**:
`observed_as_flow_destination`, `observed_in_dns_query`,
`observed_in_dns_response`, `observed_in_tls` and `observed_in_http`. The first
is the distinction the composition rule turns on — an address the host exchanged
bytes with is not an address the host merely resolved, and in the sample 16 of
the 30 resolved addresses are never contacted. The other four are the weaker
substitute `concept/02-concepts-and-taxonomy.md` records for domains, where the
scope test cannot work: a name in a TLS SNI was connected to, where a name seen
only in a DNS query may never have been.

Three things the migration file records rather than glosses. **JA4 has no public
blocklist** — the rows exist and nothing enriches them, which is why
`fingerprint_algorithm` is on the row: a JA4 with no source is `missing`, a JA3
no source matched is `no_match`, and those may not be collapsed. **URL feeds
have narrow reach on this input**, because TLS yields an SNI and not a URL — 36
request URIs against 25 TLS handshakes in the sample. And **the value is the
name as observed**: nothing is lowercased and no registrable domain is derived
here. The registrable domain arrives beside it, from the Public Suffix List —
see below.

`helena_signal_entity_observations` sits underneath as a **plain view** — one
row per (flow, entity) observation, the intermediate the entity rows are
aggregated from, and the one place the window is taken. Nothing reads a single
observation, so it is not materialized; the entity rows above it are, because
they are the join target the enrichment tables and the rendering come to.

### Registrable domains: the Public Suffix List

`sql/migrations/0008_public_suffix_list.sql` adds
`helena_reference_public_suffix` — one snapshot of the published list — and
derives, for every domain entity value, the **public suffix** and the
**registrable domain**.

```bash
uv run scripts/load_public_suffix_list.py            # fetch and load
uv run scripts/load_public_suffix_list.py --status   # what is loaded
```

**This is normalization, not enrichment.** `concept/05-threat-intelligence.md`
puts the list in the catalogue with an empty "Maps to" cell and no tier:
*registrable-domain normalization — needed for scope correctness, not
enrichment*. The table carries no threat type, no confidence and no tier, and a
test asserts by column name that it never will. Nothing here produces a taxonomy
claim, and a name's registrable domain escalates nothing.

It is needed because a scope comparison is unreliable without it in both
directions: `example.co.uk` and `other.co.uk` share two trailing labels and
nothing else, while `a.b.example.com` and `c.example.com` are one registrant.
Where the boundary is cannot be derived from a name — it is published, per
suffix, and it changes.

`entity_value` is untouched. The name as observed is what
[`docs/decisions/0009-netify-application-identification.md`](docs/decisions/0009-netify-application-identification.md)
fixes the one existing feed's join on, and the registrable domain arrives as a
column beside it in `helena_signal_context_domains`, for a different question.

`registrable_domain_status` keeps four states apart, and they are four different
things:

| Status | Means |
| --- | --- |
| `derived` | the name has a registrable domain, and it is on the row |
| `name_is_a_public_suffix` | the name **is** a public suffix (`co.uk`, `com`, an unlisted single-label name). Nothing is missing; there is nothing there |
| `invalid_name` | not a domain name — an empty label, or an address literal. The list was consulted and refused |
| `list_not_loaded` | no rule matched at all, not even the algorithm's default `*`, which means the reference table is empty. `missing`, never `no_match` |

The derivation is a join, not a function: the engine has no UDF this could be,
and a `LIKE` join would be a streaming nested-loop join, which RisingWave
refuses. A name's candidate suffixes — its rightmost 0, 1, 2 … labels — are
equi-joined against the rules, wildcards and exceptions fall out of two integer
columns, and the algorithm's default rule is stored as an actual row so that
*no rule matched* can only mean *the list is not loaded*.

Correctness is not argued here. The suite runs the publisher's own 77
`checkPublicSuffix` vectors — mixed case, leading dots, unlisted TLDs, wildcards
with exceptions, IDN labels in both Unicode and punycode — through the whole
path: a name becomes a DNS query in a capture, the capture becomes events, the
events become an entity row, and the entity row becomes a registrable domain.

A failed fetch leaves the previous snapshot in place and writes a
`failed` row to `helena_reference_public_suffix_load` naming a typed reason.
Nothing schedules the loader; "its own schedule" is whatever runs the script.

### The retention boundary, completeness, and the frozen copy

`sql/migrations/0009_retention_boundary.sql` puts a boundary around the context
views. **Retention is a temporal filter, not a delete**
(`concept/07-principles.md`): `helena_signal_host_context_retained` and
`helena_signal_context_entities_retained` are materialized views holding what is
inside the horizon, and nothing is removed from the aggregates behind them.

**The horizon is one parameter, and it is also the late-record tolerance** — a
record arriving after its window's raw records are gone cannot revise anything.
It is `24 hours`, and it is a **candidate rather than a decision**: the concept
records the horizon as unset and to be chosen by watching the rejection counter.
It has three homes — `helena.context.RETENTION_HORIZON`, the
`helena_retention_horizon` view, and the literal in the retained view's
predicate, which a streaming query cannot read from a view — and the suite reads
the third out of `rw_catalog` and hands it back to the engine to evaluate, so
the three cannot drift.

`helena_signal_host_context_live` is the citable row: a retained context plus
two columns a materialized view cannot carry, because `now()` outside a `WHERE`
clause is refused in a streaming query.

- **`completeness` is `open` or `provisional`, and there is no `final`.** `open`
  is a window that has not closed; `provisional` is one that has, whose records
  are still retained and which a late record can still revise. A context does
  not become final — it leaves the retained view.
- **`context_version` is a digest of the context id and its six statistics.** It
  is the second identity on the row and the two do different jobs: `context_id`
  is stable across revisions (settled, and measured — an incrementally
  maintained view edits in place), while a revision mints a new
  `context_version`. So *a revised context is a new version rather than an edit*
  is true of the thing a citation records.

**A context cited by a finding is copied out, never evicted.**
`helena.context.ContextStore.freeze` copies a live row into
`helena_frozen_context`, keyed by `(tenant, sensor, context_id,
context_version)`: freezing an unrevised context twice writes one row, freezing
after a revision keeps both, and freezing a context that has already left the
boundary is a typed `ContextOutsideRetention` rather than a silent no-op.
Nothing calls it yet — the code that issues a finding does not exist, so what is
demonstrated is that a frozen copy survives a revision, not that one is taken at
the right moment.

**The boundary reports what it drops.** `helena_signal_retention_rejections`
counts contexts and records outside the horizon per identity, reading the
*unbounded* aggregate on purpose — a counter over the retained view could only
report zero. `RetentionRejections.rate` raises rather than returning `0.0` when
nothing was aggregated, because a zero would read as "the boundary dropped
nothing".

Two things were measured against the pinned engine before any of it was written.
A temporal filter in a materialized view **really evicts**: a context 277.6 s
past its window, under a 283-second horizon, was there at creation and gone five
seconds after the horizon passed, while the aggregate behind it kept the row.
And **a late record inside the boundary still revises through the filter** —
`concept/08-open-questions.md` had that as untested and not to be inferred; it
is now measured, and the note says so.

Every fixture in this repository is dated 2024-06-01, so **the retained views
are empty over the fixtures**, and the tests reach the inside of the boundary
with a real record whose `ts` is re-stamped. The same holds for a deployment:
replaying an archived capture produces contexts the boundary does not show.
