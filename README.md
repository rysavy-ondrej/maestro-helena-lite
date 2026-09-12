# MAESTRO HELENA

Host-context enrichment and LLM-enhanced network analysis: a prototype that turns
flow telemetry into windowed host contexts, enriches them against static threat
intelligence, and has two agents assess them — read-only, analyst-supporting,
non-blocking.

**Maturity: experimental.** The skeleton exists and is under construction. No
claim is made here about verdict quality: the evaluation corpus does not exist,
and every measurement is gated on it.
[`docs/evaluation-corpus.md`](docs/evaluation-corpus.md) is what one would have to
be, what an evaluation over it would spend against the provider's quota, and which
research question each missing piece blocks.

What the prototype *does* demonstrate, what it may not be read as, and the test
that executes each of those properties end to end, are in
[`docs/acceptance.md`](docs/acceptance.md) — `make acceptance` runs it.

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
  agents.py            the model client, structured output, and the bounded retry
  contracts/           the agent request/result pair, one frozen module per version
  taxonomy/            the two classification vocabularies, one frozen module per version
  hosts/               triage's closed host attribute set, one frozen module per version
  rendering/           the five-part triage projection, one frozen module per version
  triage/              the triage runner, and its prompt, one frozen module per version
  analyst/             the analyst runner — the budgeted tool loop — and its prompt,
                       one frozen module per version
  tools.py             approved providers as tools: the credential-owning boundary,
                       and the cache-first lookup whose cache is the evidence store
  providers.py         the live adapters behind that boundary — the protocol half,
                       apart so the boundary can be asserted to hold no HTTP client
  disclosure.py        what may be sent to which source, and the record of what was
  orchestration.py     deterministic routing, budgets, persistence, replay
  sink.py              egress of every assessed context to the output topic
  broker.py            the Kafka wire protocol, both ends, and nothing else
  config.py            the fail-loud environment loader and Secret
  observability.py     the one structured log channel and its redactor
  status.py            the metric views read back, and the rates that refuse zero
  migrations.py        applies sql/migrations/ and records what it applied
  versions.py          the nine recorded version dimensions, and stamping
sql/migrations/      the engine's schema: NNNN_name.sql, applied in order
config/hosts.toml    the fixed host attributes, and triage's only source of them
config/rendering.toml the size budget the triage rendering is bounded by
config/agents.toml   how many times one assessment may ask the model, and
                     whether the analyst is shown what triage concluded
config/policy.toml   the confidence thresholds, the budget values, and the send policy
tests/               the one pytest suite, mirroring the package
scripts/             dev-up / dev-down, the pin-and-endpoint check, migrate, replay,
                     emit (drain the assessed contexts to the output topic),
                     status (the pipeline's own numbers, as plain SQL),
                     measure_rendering (what a real capture renders to), and
                     corpus_sizing (what an evaluation would cost in live queries)
demo/                one script that runs ingest and context and prints the result
docs/acceptance.md   what "the prototype works" means, and what it does not
docs/evaluation-corpus.md  what a labelled corpus would have to be, and what
                     measuring against it would cost - the gate on every claim
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

### The conformance gate, and the rule that comes with it

[`concept/07-principles.md`](concept/07-principles.md) ends with a table headed
**"Behaviour that must be impossible"** — twenty rows, each a plausible
implementation that would produce a pipeline which *runs and lies*.
[`tests/test_conformance.py`](tests/test_conformance.py) is that table as an
executable suite: one named test per row, `MNH-01` to `MNH-20` in the note's own
order, so a regression is caught by the suite rather than by a reader.

```bash
make conformance        # the twenty rows alone, ~30 s
make check              # lockfile, compile, and the whole suite including them
```

It is not a second suite. It is collected by `uv run pytest -q` like everything
else, which is what makes it required; the marker exists so that *"do the
guarantees still hold"* is a question you can ask on its own.

**Adding a row to the table means adding a test.** That is enforced rather than
requested — the suite parses the note on every run, and a row with no
`test_mnhNN_…` named for it is a failure, as is a test naming a row the table no
longer holds, as is a reworded row whose test still asserts the old sentence.
Each row also names its in-depth coverage elsewhere in the suite (`COVERED_BY`),
and those names are resolved, so deleting the only thing checking a row fails at
the row. The module docstring is the whole rule.

### The architectural boundary: five rejections, five tests

[`concept/06-technology.md`](concept/06-technology.md)'s table does not only say
what HELENA uses. Five of its rows say what it does not — **graph framework**
(not adopted), **higher-level agent frameworks** (deferred), **workflow engine**
(rejected), **hosted tracing** (local structured logs only), and the **second
store**: relational profile store, vector store, checkpoint store. Each is load
bearing for a rule somewhere else — a graph framework brings a checkpointer, a
workflow engine brings a metadata database, a hosted tracer is a second egress
channel for prompts and retrieved text — and each is one `uv add` from being
reversed by accident rather than by decision.

[`tests/test_architecture_boundary.py`](tests/test_architecture_boundary.py) is
those five as tests. Beyond the declared-and-imported check that
`tests/test_dependency_boundary.py` already makes, it asserts that a second-store
client is not *installed* (a transitive one is an `import` away), that the
**standard library's** stores are unimported — `sqlite3`, `shelve` and `dbm` need
no dependency, so the approved-set test passes them by construction — that the
package writes **no file** and starts no process, that the deployment names
exactly two topics, and that the migrated schema defines **no source, sink,
connection or secret**, which is the persistence target no import scan would
reveal.

**Reversing one takes a decision record, not an incidental dependency** — the
note says so itself for the second store, and
[`docs/decisions/0039-architectural-boundaries.md`](docs/decisions/0039-architectural-boundaries.md)
says it for all five and lists what a reversal has to answer. A test requires
that record to exist and to name every rejection it governs, and two meta-tests
parse the technology table on every run, so adding a rejection to the note means
adding a test and withdrawing one is red until the commit carries all three.

### Secrets hygiene: two exposure profiles, not one rule

The same provider secret is exposed differently depending on where it travels.
The abuse.ch **hunting API** takes the key in an `Auth-Key` *header*, where it
does not reach a proxy log, shell history, an exception carrying the request URL,
or a pasted link. The **v2 export** takes it in a *URL path segment*, where it
reaches all four — and that is not hypothetical: a live key reached a project
conversation inside a pasted link, which is the incident the redaction rule exists
for. `concept/07-principles.md`'s *"a key that travels in a URL path must be
redacted before anything is logged or stored, including the fetch trace a loader
records for provenance"* is therefore narrower than *"redact everything"* and
stronger than *"this provider is fine"*.

[`tests/test_secrets.py`](tests/test_secrets.py) holds the channels that had no
owner: the **path** form of a loader's stored fetch trace and of its stored
failure detail, the wrapper as a property of the package (no model field can hold
a credential without the redacting serializer, and `reveal()` is called in three
declared places), **source control** — every tracked file, fixtures included, read
for every value the local `.env` holds — and the two downstream surfaces a prompt
test cannot reach, a stored evidence row and an emitted message. The log, the
agent-visible tool surface and the prompt bytes are owned by three other modules
and are not restated here; [`docs/runbook.md`](docs/runbook.md) §14 has the table,
the measurements (re-measured 2026-09-12) and what to do if a key does get out —
rotate first, the repository second.

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

### Long runs over SSH

`./implement.sh` runs PRD tasks through fresh Claude Code sessions, one per
task, and a run of several tasks outlives a remote login. Start it detached and
closing the SSH session no longer takes the run with it:

```bash
tmux new -d -s runner './implement.sh -n 5'   # start it detached
tmux attach -t runner                         # watch it; Ctrl-b d leaves again
```

Without tmux, `setsid nohup ./implement.sh -n 5 > ~/runner.log 2>&1 < /dev/null &`
detaches the same way without the live view. The runner drops terminal styling
when stdout is not a terminal, so a redirected log stays readable, and it never
reads stdin.

**Keep that wrapper log outside the tree.** The linear-history gate runs `git
status --porcelain`, which counts untracked files, so a stray log inside the
repository makes the *next* invocation refuse to start (exit 5) before it has
run anything. The runner's own per-session logs under `prds/logs/` are
different: the session that writes one commits it.

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

`helena.status` is the other half of the same decision. **The audit record is the
stored assessment, not a trace UI** — it already carries the retrieval trace, the
disclosure record, cost, latency and versions as typed columns, which is
queryable in a way a trace UI is not. So what must be observable is seven plain
views over rows the pipeline already writes
([`sql/migrations/0021_pipeline_observability.sql`](sql/migrations/0021_pipeline_observability.sql)):
latency, cost, tokens, retries and cache state per model; the typed failures by
reason; the escalation rate and which trigger caused it; each feed's snapshot age
against its own schedule; and the end-to-end record reconciliation, beside the
retention boundary's rejection rate (0009) and the engine-side emission count
(0020).

    uv run scripts/status.py --captures data/ingest     # `helena status`

Every number is a `SELECT` an operator with `psql` can run without any of this
code, which is the point. **No rate is stored and no rate is computed over an
empty denominator**: `0.0` would read as "the boundary dropped nothing", "triage
escalates nothing" or "this model is free" when the truth is that nothing has
run, so each one raises and the report prints the reason where the number would
have been. The reconciliation is two views rather than one because its five terms
live in three view layers and one of them — how many records the capture held —
is not in the engine at all;
[`docs/decisions/0038-pipeline-metrics-and-reconciliation.md`](docs/decisions/0038-pipeline-metrics-and-reconciliation.md)
has that and the rest, and `docs/runbook.md` §13 explains the numbers.

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

[`helena.contracts`](src/helena/contracts/__init__.py) is the second, on the same
terms: `contracts.version("v1")` returns the `AgentRequest`, `AgentResult` and
`AgentFailure` classes a stored assessment recording `schema_version = "v1"` is
replayed against. See [The agent contract](#the-agent-contract) below.
[`helena.hosts`](src/helena/hosts/__init__.py) is the third — the closed host
attribute set triage's part one is built from, read from `config/hosts.toml` and
from nothing else — and [`helena.rendering`](src/helena/rendering/__init__.py) is
the fourth: `rendering.version("v1").render(projection, attributes, budget)`
builds the five-part projection an agent is given, and an assessment records
which version built it. `docs/decisions/0018-the-triage-rendering.md` has the
five parts, the line grammar, the TLS parameter subset and what the rendering
deliberately does not carry.

**The rendering is bounded, and what it dropped is visible twice.** The budget is
a number of characters in `config/rendering.toml` — policy in a file, because
`concept/07` makes budget values policy and not constants in a branch, and
`render` has no default to fall back on. A section that had to drop records opens
with a `truncated kept=N total=N dropped=N` line *and* carries a
`helena.contracts.v1.Truncation`, so the model and the code both see it; the host
section, the connection statistics and every source header line are never
dropped, because they are what says which lookups happened and what became of
them. What is kept is a prefix of the section's neutral order and never the hits
first — a dropped claim is not a lost alert, because deterministic escalation
reads the store rather than the rendering.
`docs/decisions/0019-the-rendering-size-budget.md` has the four rules and the
measurement the number came from; `make rendering-size` re-measures it.

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

**The enriched context is a join, and it is per entity.**
[`sql/migrations/0015_enriched_context.sql`](sql/migrations/0015_enriched_context.sql)
is the first object in the **analytical** layer — until it existed, `MAY_READ`'s
`analytical` row was an invariant the layering tests could describe and not
exercise. It joins a context's entity rows to the claims about them, per entity,
because a host context is one row with arrays inside it and an array inside a
window cannot be joined to evidence.

Three things it does that are easy to get wrong. It joins **the snapshot that was
current at the context's event time**, not the newest one, so an old context does
not silently re-enrich itself every time it is read. It emits a row for every
(entity, source) rather than only for the hits, so an entity with no hit anywhere
is a **`no_match` row and not an absence** — with sparse coverage most entities
have no hit on anything, and triage reading "no hit" as "clean" is the failure
mode the design exists to prevent. And it records **whether the claim's port
matched** what the host actually reached, three-valued and never as a filter: a
C2 claim on a port the host never touched is a weaker claim, not no claim, and
dropping the row would make the composition rule's decision on its behalf.

**It carries no verdict, no severity and no score**, and that absence is the
point. `concept/02`'s composition rule — an evidence-level classification about a
contacted indicator does not become the context verdict — is about what a reader
may conclude from these rows. A verdict column would be that decision taken in
SQL, where none of the traffic correlation the rule turns on has been weighed.

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
the package. The address is `KAFKA_BOOTSTRAP_SERVERS` and the two topics are
`HELENA_INGEST_TOPIC` and `HELENA_OUTPUT_TOPIC`, with no defaults — and startup
refuses a configuration where the two topics are the same name, because a
deployment emitting onto its own input would quarantine every message it produced
and look like a sensor sending malformed traffic.

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

## The agent contract

One versioned typed request/result pair covers **both** agents
(`concept/04-the-two-agents.md`). Agents never exchange free-form
natural-language messages, and nothing crosses an agent boundary except validated
typed fields. [`helena.contracts.v1`](src/helena/contracts/v1.py) is the first
version; [`docs/decisions/0017-the-agent-contract.md`](docs/decisions/0017-the-agent-contract.md)
carries the argument for every shape in it.

**Three fields are deliberately absent**, and they are refused three ways rather
than one: no such field exists, `extra="forbid"` on every model means no caller
can add one at runtime, and `tests/test_contracts.py` asserts the absence by name
over every model *and* over the module's AST.

| Absent | `concept/04`'s reason |
| --- | --- |
| a free-text **task** per invocation | "a varying instruction channel into the model … and [it] gives attacker-influenced content a route into the instruction position" |
| loose **observations** / **relevant context** | they would carry the rendering's content "without the guarantees that make an assessment replayable" |
| **recommended actions** | "has no consumer and invites the remediation channel the concept excludes" |

**There is one result class and the asymmetry is rules on it**, not a second
shape — two classes would be two places every later rule has to be written, and
the first one forgotten is a triage run that quietly returned `malicious`. So a
triage request may not carry a step or live-query budget at all, a triage result
may not carry an evidence package, a retrieval trace, a proposed claim or a cost
reporting any tool use, and the closed root set per emitter is
`helena.taxonomy`'s, already frozen per taxonomy version.

**The citation rule has exactly two exemptions.** A `normal` **triage** decision
returns verdict and confidence only. `unknown` is exempt because a run whose
enrichment entirely failed has no evidence row to point at — and its `gaps` list
is *mandatory* instead, which is what stops the exemption becoming an
unfalsifiable shrug. Everything else, an analyst `normal` included, requires at
least one citation.

**A citation has to resolve to something the run was given.** Every rendered
section lists the stable evidence identifiers it showed, so `check_exchange`
refuses a result citing an id the rendering never showed and the retrieval trace
never produced. It also refuses an outcome that does not echo the request's eight
known version dimensions, and an outcome carrying no `truncated` gap when the
rendering dropped something — silent truncation is a correctness bug, and it has
to stay visible in the record of the run and not only in the input to it.

**The typed failure has nowhere to put a verdict.** `AgentFailure` has no
`classification`, no `root`, no `confidence` and no `citations`, and
`extra="forbid"` means one cannot be added — the same way
`helena.enrichment.QueryFailure` enforces its own rule. Its three reasons are
`schema_invalid`, `model_unavailable` and `timed_out`; **budget exhaustion is not
one of them**, because `concept/07-principles.md` requires a budget-exhausted run
to return a verdict on what it gathered, degraded to `unknown` and never `normal`.

**A request cannot record the model that answered it.** `RequestVersions` carries
the eight version dimensions known before the call plus `model_requested` — what
this deployment asked for — and `completed_by()` produces the nine-dimension
`VersionSet` once a response has said what actually answered. A `model_unavailable`
failure therefore records no model version at all, because nothing answered, and
recording the configured name there would be exactly the substitution the version
registry exists to prevent.

What is demonstrated by the contract alone is that the shapes refuse what the
concept notes say they must refuse. A model has now been called through them —
see below — but no assessment has been stored or emitted, and no result has been
replayed against a recorded `schema_version`.

## Calling a model

[`helena.agents`](src/helena/agents.py) is the model client:
`ModelClient.for_agent(settings, agent)` resolves one agent's endpoint, token and
model **purely from configuration**, and `assess(request, client=…, messages=…,
policy=…)` returns a validated `AgentResult` or a typed `AgentFailure` and never
raises for anything the model or the endpoint did.
[`docs/decisions/0020-the-model-client.md`](docs/decisions/0020-the-model-client.md)
carries the argument for every choice below.

**There is no framework, and that is an open escalation rather than a
preference.** `concept/06-technology.md` names LangChain for this increment and
also settles hosted tracing as rejected; `langchain-openai` resolves to 37
distributions including `langsmith`, a hard dependency of `langchain-core`, which
the dependency boundary test asserts is not even importable. So the endpoint is
reached with `urllib`, the way the feed loaders reach theirs, and the question
returns with the analyst's tool loop — the half of LangChain's justification that
nothing has needed yet.

**The schema the model is given is derived from the contract, never written
twice.** `AgentResult`'s three code-owned fields — `emitter`, `cost` and
`versions`, which are what the run *spent* and what *produced* it — are removed,
and the rest becomes the endpoint's `response_format` schema. What comes back is
validated by constructing that same frozen class. Two things this had to learn by
running rather than by reading: the closed vocabularies the contract enforces in
`model_post_init` are **invisible** to `model_json_schema`, and a live model
filled `stance` with a line of the rendering three attempts running until the
enums were injected from the contract's own constants; and validating in
Pydantic's *JSON* mode is what stops `strict=True` refusing every JSON array
where the contract declares a tuple.

**Schema-invalid output is retried, bounded, with the validation error fed back —
and a repair call is refused by construction.** Each attempt is the *original*
question plus one message saying what was wrong, so the invalid answer is
discarded and never sent anywhere; `test_no_repair_call_path_exists` asserts that
over the bytes the endpoint received, which a repair path could not pass. The
bound is `config/agents.toml`, the retries are spent against the request's token
budget, and `Cost.retries` records what they cost. Exhaustion is an
`AgentFailure`, never a verdict.

**What produced a result is recorded**: the model identity the *response*
reported (never the configured name), and the endpoint host — host and port, with
userinfo, path and query dropped rather than masked, so cross-wiring between two
agents' endpoints is detectable. `helena.agents` never names an agent: a test
parses the module and fails if `"triage"` or `"analyst"` appears as a string
constant, because model choice is a configuration value and never a code path.
The assessment row that should carry the endpoint host does not exist yet, and
until it does the structured log is the only record of it.

## Triage: one rendering in, two labels out

[`helena.triage`](src/helena/triage/__init__.py) is the runner and
`helena.triage.v1` is the prompt, frozen the moment a row records
`prompt_version = "v1"` — the shape
[`docs/decisions/0008-version-registry.md`](docs/decisions/0008-version-registry.md)
promised prompts in the same sentence as renderings. The call is
`triage.run(request, client=…, policy=…, prompt=triage.version("v1"))`, and it
returns a validated `AgentResult` or a typed `AgentFailure`, the same two
terminal outcomes `assess` has.
[`docs/decisions/0021-the-triage-runner.md`](docs/decisions/0021-the-triage-runner.md)
carries the argument for each choice below.

**Two labels, looked up rather than written down.** `concept/02`: *triage emits
`normal` or `suspicious` and nothing else, and a context triage could not assess
is a typed failure, not a third label.* The set comes from
`helena.taxonomy.version(v).emitter_roots["triage"]` — resolved against the
version the request records — and it is injected into the endpoint's schema as an
enum, because a closed vocabulary the contract checks in `model_post_init` is
invisible to `model_json_schema` and a model shown a bare string invents a value
for it. A model that answers `malicious` or `unknown` anyway fails the contract,
is retried with the error fed back, and becomes a typed failure with nowhere on
it to put a verdict.

**The rendering is data, and the frame is structural rather than persuasive.**
Two turns: the frozen instructions, then the rendering alone between two marker
lines. The markers are whole lines because `helena.rendering.v1.token`
percent-encodes the newline, so no value a host chose can start a line of its own
— saying "this is data" in the prompt is necessary and is not what makes it hold.
`messages` refuses a rendering carrying a marker line anyway rather than trusting
the property it depends on.

**Binding no tools is asserted at the call site.** The contract already refuses a
triage request that budgets a step or a live query and a triage result that
reports having spent one; the runner checks the budgets it was handed and the
field set it is about to offer, and a test asserts over the bytes the endpoint
receives that no tool definition is sent.

**Truncation stays visible on the outcome**, and the gap is written by code: what
was dropped is a fact the rendering measured and the model cannot see records
that are not there. The outcome is rebuilt through `model_validate`, not
`model_copy`, so the contract's own rules run again. Then `check_exchange` is
called — and a citation that resolves to nothing the run was given becomes a
typed failure rather than a verdict with an unresolvable citation.

**A triage failure escalates nothing.** `escalates` is the triage half of what
reaches the analyst and returns `False` for every typed failure, by type rather
than by reading a field. `concept/04` says failing closed is safe *because*
deterministic escalation is independent of whether triage ran at all — and that
evaluator is now `helena.policy.v1.escalate`, below, so a context whose model
call failed is still weighed by the evidence. Until task 32 and this one landed,
it was not, and that was the one thing this stage shipped genuinely unsafe.

## The composition rule: scope before severity

[`helena.policy`](src/helena/policy/__init__.py) is the machinery and
`helena.policy.v1` is the rule, frozen the moment an assessment records
`policy_version = "v1"` — the sixth versioned package, and the version dimension
that had no owner until now. `concept/02-concepts-and-taxonomy.md` calls it *the
single most consequential rule in the taxonomy* and says where it has to live:
*"the model classifies, the policy constrains what evidence can support what
verdict. This is where over-alerting will come from if it is wrong."*
[`docs/decisions/0022-the-composition-rule.md`](docs/decisions/0022-the-composition-rule.md)
carries the argument for each choice below.

**It runs after the prompt, on the model's own answer, and does not rewrite it.**
The prompt tells the model how to *read* the rendering; the contract says whether
the answer is well-formed; `check_exchange` says whether it holds against its own
request; and then `constrain` asks whether the cited evidence can support the
verdict. A rule stated in the prompt would be one more sentence in the
instruction position that attacker-influenced data is trying to argue with, and
it would be testable only for its own presence. The `Decision` is a **second**
record beside the `AgentResult`, because an evaluation that could not tell a
model's answer from a policy's correction of it would be measuring the wrong
thing.

**Seven rules, one per sentence of the note**, each a named function and each a
row of the table in `tests/test_policy.py`: a C2 hit on an address the host
contacted with bytes in both directions stands; the same hit with one failed
connection and no bytes returned is `suspicious` at most; a claim scoped to a
port the host never reached is too — which is the decision
`sql/migrations/0015_enriched_context.sql` explicitly deferred here; a contacted
phishing domain reaches `malicious.phishing` and never `malicious.compromised`,
because the user was targeted and the host was not; a malicious indicator on
shared infrastructure transfers nothing without corroboration; `normal` on
contacted indicators never establishes `normal` for the context; and domain-only
support is capped, because **the scope test works on address entities and not on
domain ones**.

**A cap is a bare root and never a path** — *"emit the parent rather than
guessing a child"* — and it is resolved against the taxonomy for the emitter the
result came from, so a policy that capped to something that emitter could not
have said fails rather than inventing a label. What a rule permits is
three-valued: the proposed path, a weaker root, or `None` for *this evidence
establishes nothing*, which is neither `normal` nor `unknown` and is deliberately
not turned into a verdict here.

**The two limitations are outcomes, not footnotes.** `domain_scope_untestable`
is recorded whenever a name is what carried a capped verdict, and
`shared_infrastructure_undetermined` is recorded whenever a `malicious` verdict
**survives** — because a CDN, a cloud tenant and a shared subdomain are external
facts no source in this deployment supplies, and only the resolver case is
observable from the ports the host actually reached. They are the policy's own
gap kinds and not the contract's seven: none of those names a test that does not
apply, and spelling `missing` here would collapse "the lookup did not happen"
into "the rule could not be run".

## Deterministic escalation: what runs the analyst without asking the model

`helena.policy.v1.escalate` is `concept/04`'s **second** independent input, and
the one that matters: *"the enrichment evidence escalates on its own — a Tier A,
or a high-confidence Tier B, malicious classification whose traffic
characteristics support it — regardless of the triage verdict. An LLM returning
`normal` may not bury a high-confidence match."*
[`docs/decisions/0023-deterministic-escalation.md`](docs/decisions/0023-deterministic-escalation.md)
carries the argument.

**It takes no result, and the test is over the signature and the AST.** There is
no parameter a verdict could arrive through, and nothing the rule reaches may
name `AgentResult`, `AgentFailure`, `Decision` or `constrain`. The way this
invariant gets broken is not a rule that reads a verdict on purpose — it is a
later increment passing the triage result in so the evaluator can skip work when
triage already said `normal`, which looks like an optimisation and is the
suppression. Its input comes from `supports_in`, a second read beside
`supports_for`: one asks what the store holds, the other what a model chose to
cite.

**The three clauses are three tests.** The tier (`ESCALATING_TIERS`); the claim's
own `malicious` root; and the traffic, which is **the same composition rule**
above applied to one claim rather than to a citation set — a hit whose traffic
does not support it does not escalate as `malicious`, decided by the same
predicates so that one `policy_version` cannot hold two opinions about one claim.
Every malicious claim becomes a `Candidate` whether or not it escalated, with
every rule that held it back named, because *why did this one not escalate* is
the question a quiet stream raises.

**The thresholds are `config/policy.toml`, and the file carries two versions.**
`policy_version` says which frozen rules the numbers are for — `escalate` refuses
a set written for another — and `thresholds_version` is the file's own, recorded
on every escalation, because `v1.py` is frozen and the file is not. The loader
fails at startup naming a registered Tier B source the file is silent about, and
refuses a threshold for a source no tier reads one for. `concept/08` lists these
thresholds as open and blocking; 0.80 is a measured position in ThreatFox's own
bimodal distribution (0.75 alone carries two thirds of the address side, so a
threshold at or below it admits 94 % of hits) and is **a candidate, not a
decision**.

**An aggregator is never many votes.** `independent_sources` is counted by
`helena.enrichment.source_diversity`, so one source's forty rows about one
address are one. No `v1` rule raises anything on that count — `concept/04`
conditions escalation on tier and confidence and on nothing else — so its job is
prohibitive: it is what stops a below-threshold claim being lifted by the number
of rows behind it.

**Two limits are recorded rather than fixed.** A claim from a superseded snapshot
still escalates and records `freshness_adequacy_untested`, because *removal from
a feed is not exoneration* and how much a delisting should cost is unmeasured.
And **domain hits do not escalate at all**: the scope test works on addresses and
not on names, which `concept/02` calls the place that bites precisely where it
matters most. Both are passing tests over a real capture and a real feed load,
not paragraphs.

## Provider tools: a boundary, not a server

[`helena.tools`](src/helena/tools.py) is the D5 tool layer, and
[`docs/decisions/0024-provider-tools-and-the-mcp-boundary.md`](docs/decisions/0024-provider-tools-and-the-mcp-boundary.md)
carries the argument. `concept/03-architecture.md` asks for "a cache-first MCP
tool" and then says what it means by it — *"the tool layer, deterministic project
code, not the model, owns credentials, tenant scoping, budget enforcement, what
may be sent, disclosure recording and response validation. **The agent sees a
tool, never an HTTP client and never a key**"* — which is a list of properties of
a **boundary**, not of a wire protocol.

**So there is no MCP server and no MCP SDK.** A per-provider wrapper process
would add a dependency, a second surface and a second place a credential lives,
in the increment that first needs none of the three; `mcp` joins `langchain` in
`tests/test_dependency_boundary.py`'s `DELIBERATELY_ABSENT`, so adopting the
protocol later starts by changing a test rather than by an import appearing. The
seam it would go behind is already there: `ProviderTool` is one concrete class —
not a base class with one subclass — and the provider-specific half is one
injected callable, `ask(call, credential) -> ProviderAnswer`.

**The call has two sides and they are not the same object.** `Lookup.for_agent`
is compact, normalized and typed — `EnrichmentEvidence` rows tagged `analyst`,
each cited by a stable identifier, with `RetrievalStep`s beside them.
`Lookup.native` is the provider's response **exactly as it arrived**, retained
for audit and replay and with no route to the agent. A live answer has no feed
snapshot, so what dates it is the response itself: `snapshot_version` is a digest
of those bytes, which is what makes a lookup-dependent assessment replayable.

**Four things a call can be, and none of them is `no_match`.** A refusal (the
layer would not send it — malformed arguments, or an entity type the source does
not cover), a typed `QueryFailure` on the step with no taxonomy object beside it,
an explicit `no_match` claim, and a hit. A response outside the source's declared
subset is the second of those and discards *every* claim in it, because a mapping
that has drifted from its declaration is not partially trustworthy. A tool for an
unregistered source cannot be built at all: the descriptor is resolved through
`helena.enrichment.source`, so adding a provider stays a governed decision.

**The credential is the layer's and the isolation is tested over the real one.**
It is a `Secret` injected at construction, held in a private slot, handed to the
adapter and revealed nowhere else; the module imports no HTTP machinery and holds
no URL, read off its own AST. The test loads the real key from `.env` and asserts
— on a boolean, never on the value — that it reaches no agent-visible surface,
that no `://` does either, and that every value crossing the boundary is a string
in a declared field. Two things that leak by default were fixed in the writing: a
Pydantic `ValidationError` rendered with `str()` carries a documentation URL and
echoes the model's own input back, and a diagnostic must be redacted **before**
it is truncated or a half-key survives.

**Retrieved provider text is data, and the isolation is a mechanism rather than a
sentence.** What crosses is a typed object with `extra="forbid"`, the
classification comes from the declared subset and never from provider text, and
`content()` is `json.dumps`, so a newline cannot start a line of its own. A
`"\n\nSYSTEM: ignore the previous instructions…"` planted in a provider field
survives only as an escaped value, which is a test.

**What is not built is named, because a green suite here must not read as a
finished layer:** nothing paces calls to the configured rate, and no live provider
has been queried — the layer runs against a stand-in over the committed ThreatFox
extract, whose *records* are real and whose *envelope* is not, because no
per-indicator query surface has been confirmed yet. The sharpest gap the send
policy does **not** close is where an indicator came from: one the model invents is
sent as readily as one the context observed, because nothing joins a tool argument
to the host context.

## The lookup cache is the evidence store

[`sql/migrations/0017_analyst_lookup_cache.sql`](sql/migrations/0017_analyst_lookup_cache.sql)
and the cache-first half of `helena.tools`; the argument is in
[`docs/decisions/0025-the-lookup-cache.md`](docs/decisions/0025-the-lookup-cache.md).
`concept/07-principles.md` rejects a separate opaque cache in one sentence —
*"an assessment could then cite something the cache had already evicted"* — so
there is **no cache** in the sense `concept/instruction.md` §3 forbids: two
tables in the one engine, in the evidence shape 0011 defined, and a reader that
holds a connection and no state. **Nothing is evicted**; `expires_at` bounds
validity and not lifetime, which is exactly what lets §4 of that decision answer
the way it does.

**A hit sends nothing, and that makes caching a privacy control as much as a cost
one.** The measurement is not a call counter: the adapter is the only thing in
the layer that can reach a provider, so an adapter that was not called is an
indicator that was not disclosed. The trace says which it was — `cache_hit` or
`live_query` — and a hit's `retrieved_at` is the **underlying record's** time, so
two runs differing only in cache state are distinguishable afterwards and the age
of what was served is visible.

**Two open questions from `concept/08` are now answered, and both are answers
rather than defaults.** *Negative results are cached*, because a `no_match` is an
answer rather than an absence, because most lookups miss and a hits-only cache
would almost never help under a few-hundred-per-day quota, and because not
caching one re-discloses the indicator every run. *An expired entry is served
explicitly `stale` when the live query fails* — the record was never evicted, and
`concept/02` defines `stale` as precisely that: the claim stands and its age is
now part of what it is worth. That answer carries **two** retrieval steps, a
`cache_hit` citing rows that are every one of them `stale` and a `live_query`
carrying the typed failure, so `stale` and `failed` reach the agent as
themselves. A failure beside an `ok` row is still refused.

**A failure is not cached** — an outage is not a record of what a source said —
and a response that arrived and would not map is handled in between: the bytes
are stored under their digest *before* anything is read out of them
(`concept/05` rule 5), no claim is, and the next lookup is still a miss. That
order is what makes a replay read what the provider said rather than what it
would say today.

**Cache-key normalization folds only documented equivalences.** `2001:0DB8::0001`
and `2001:db8::1` are one address; `Example.COM.` and `example.com` are one
domain; a default port and an empty path fold out of a URL. A path's case, a
fragment, and an IDN's two forms do **not** fold, because a fold that is too
eager serves one indicator's evidence for another while one that is too timid
costs a single query. There is no `status` column: `ok` and `stale` are
properties of *now*, derived at read time, which is the decision
`helena.enrichment.feed_status` already made for feeds.

## Budgets: four dimensions, one ledger, charged at the boundary

[`helena.budgets`](src/helena/budgets.py), with the argument in
[`docs/decisions/0026-the-budget-guard.md`](docs/decisions/0026-the-budget-guard.md).
`concept/07-principles.md` gives four dimensions — steps, tokens, wall clock,
live external queries — and one rule about where they are checked: *"budgets are
enforced at the tool boundary, so an agent cannot reason its way around them"*.

**`RunBudget` is one ledger per agent run, not four counters per call.** Both
`helena.agents.assess` and `helena.tools.ProviderTool.lookup` take it,
keyword-only and with no default, and both charge the same object — which is what
makes the wall clock cover *the whole run including provider waits*.
`concept/07`'s own reason: at a few lookups per minute an analyst run checking six
indicators spends over a minute on the rate limit alone, so a per-call clock would
hand the run its full budget again after every lookup. A test drives an injected
clock through a slow adapter and watches the second lookup get refused on the
first one's wait.

**A cache hit answers after the quota is spent, and a miss does not.** The live
query is charged *after* the cache read, so a run out of quota can still read what
it already fetched; a step and the clock are charged before anything, so an
unbounded loop cannot be bought with malformed calls. A spent dimension is a typed
`ToolRefusal` carrying `budget_exhausted` — the same string as the gap kind, not a
second spelling of it — and never a `QueryFailure`, because nothing was queried.
An exhausted quota is also **not** the stale fallback: that exists because the
provider did not answer, and letting a budget decide what the evidence is would
make two runs differing only in budget differ in what they cite.

**Spent is not truncated.** A dimension is exhausted when the run *asked for more
and was refused*, not when a remainder reached zero: a run that spent its last
token on the answer it returned finished, and degrading it would collapse
*unassessable* into *assessed* from the accounting side. What a truncated run
returns is `concept/07`'s rule and `degraded` is the one place code rewrites a
classification — `normal` becomes `unknown` with the exhaustion explicit,
everything else keeps its verdict and gains the gap, and a typed failure stays a
typed failure. It re-validates through the contract rather than copying, so the
"never `normal`" rule is enforced by the same code that would refuse the outcome
built by hand; the test asserts it from both sides. A truncated triage `normal`
raises instead: triage has no `unknown` root, and `assess` already turns that run
into a typed failure carrying the gap.

**The values are policy and the fourth is derived.** `config/policy.toml` gained a
`[budgets]` table beside its thresholds — one sentence of `concept/07` makes both
"policy, not constants in a branch" — and `live_queries` is not a key in it. It is
`floor(retrieval_seconds x slowest rate / 60)`, so the two dimensions
`concept/07` requires to be set against each other are set against each other by
construction, and the loader refuses four ways the pair can contradict itself.
`[rate_limits]` is **the rate the tool layer holds itself to, not a measured
provider limit**, and nothing paces calls to it yet. Every number in those tables
is a candidate, for the same reason nothing else here is calibrated.

**What is not demonstrated:** no analyst tool loop exists yet, so nothing has
driven all four dimensions through one real agent run; nothing stores a `Cost`, so
"budgets consumed are recorded on the assessment" is a ready shape and not a
property that holds; and there is **no monetary figure**, because deriving one
needs a price table this repository does not have — `concept/06` makes the cost
derived rather than capped, and the tokens it would be derived from are measured.

## Disclosure: what may be sent, and the record of what was

[`helena.disclosure`](src/helena/disclosure.py), with the argument in
[`docs/decisions/0027-disclosure-and-the-send-policy.md`](docs/decisions/0027-disclosure-and-the-send-policy.md).
`concept/07-principles.md` turns one sentence into two obligations: *"what may be
sent to which source is governed policy, and what was disclosed is recorded on the
assessment — source, query, cache hit or live, disclosed-to, and when."*

**The send policy is a third table of `config/policy.toml`**, one entry per source
that may be queried live, declaring the host its requests go to, which entity types
this deployment permits being disclosed to it, and which fields of the outbound
request may be populated. An entry is what makes a source queryable at all: a tool
for a source with no entry cannot be constructed, the way a tool for an
unregistered source cannot. `threatfox-api.abuse.ch` is in there because it was
measured — 401 without the `Auth-Key` header, on 2026-09-09, sending no credential
and no indicator — and the query surface *behind* that host is still task 38's to
confirm.

**Enforcement refuses; it never trims.** `send_policy_forbids` is a fourth refusal
reason and deliberately not a variant of `entity_type_not_covered`: one is the
source's capability and the other is this deployment's permission, and they are
fixed in different places. The field half holds structurally rather than by
discipline — the permitted vocabulary *is* the field set of the `ToolCall` the
adapter is handed, so a policy-forbidden field is a request that cannot be
assembled, and the tenant and the sensor are in no vocabulary at all. The check
runs **before the cache read**, so a revoked permission stops the source being
consulted rather than being answered from records fetched while it was in force.

**A cache hit records nothing, and that is the point.** Caching is a privacy
control: the indicator was disclosed once, when the entry was fetched. So the
ledger holds one row per *outbound call*, written before the send — a request that
timed out disclosed the indicator too — and "cache hit or live" is
`RetrievalStep.outcome` on the same assessment. The two reconcile, and the suite
asserts it: provider disclosures equal `RunBudget.live_queries_spent`, with
`cache_hits` counting the calls that told nobody anything.

**Model inference discloses on the same footing**, because inference is hosted and
a prompt is egress. `assess` records one row per attempt — a retry sends the
rendering again — naming the model, the endpoint host, the size of what left and a
digest of it. The prompt itself is not copied into the record: it is the rendering
the request already carries under a recorded version, and a second copy would put
internal addresses somewhere nothing else governs.

**What is not demonstrated:** nothing stores a disclosure row, because nothing
stores an assessment — the ledger is in-process, which is the standing `Cost` has
and until the same increment; and the policy does not ask where an indicator
*came from*, so one the model invented is still sent as readily as one the
context observed.

## The first live provider

[`helena.providers`](src/helena/providers.py) is the adapter behind the boundary,
and [`docs/decisions/0028-the-threatfox-hunting-api.md`](docs/decisions/0028-the-threatfox-hunting-api.md)
is the **source record** it was written from — every shape in it measured against
`POST threatfox-api.abuse.ch/api/v1/` on 2026-09-10, eighteen probes, before a
line of the adapter existed. `concept/05` asks for exactly that and says why: the
last three source records in this project were each wrong because they were
written from a documentation page.

**The surface it confirmed, and the one thing `concept/05` had wrong.** The note
said no per-indicator lookup endpoint appeared in the public documentation.
`search_ioc` is documented and answers; the note now carries a dated correction
rather than an overwrite. Four measurements shape the adapter:

| | |
| --- | --- |
| **HTTP 200 answers every application error** | the status carries nothing; `query_status` does — and `data` is a list on `ok` and a **string** on `no_result` |
| **`exact_match` cannot be used for an address** | ThreatFox has no bare-`ip` indicator type, only `ip:port`, so an exact match on an address is always `no_result` |
| **the wildcard is not a substring search and it crosses entity types** | it returned a `url` record for an address query and 1 386 records for `workers.dev`. A wildcard result is a set of **candidates** |
| **exact match is case-insensitive but rejects a trailing root dot** | so what is sent is the *normalized* indicator, or the layer caches a `no_match` that is wrong |

**A candidate that is about something else is counted, not dropped.** Every claim
carries `records_returned` and `records_out_of_scope`, and a response whose every
record was out of scope answers `no_match` with the counts saying the provider was
not silent. Reporting a URL listing as an address claim would be
scope-before-severity failing in the direction that over-alerts.

**One mapping, not two.** An API record is translated into the bulk export's own
entry shape and pushed through the loader's `split_indicator` and
`classify_threat_type`, so an `ip:port` record is scoped `address:port` by
whichever tier read it. The suite asserts that over every committed export entry.

**The host is policy's and the adapter checks it.** `threatfox_url(permit)` builds
the URL from `[send_policy.threatfox] disclosed_to`, and an adapter pointed
anywhere else refuses to be constructed — which closes what ADR-0027 §6 deferred
until a live adapter existed.

**What is demonstrated:** the surface, the mapping, five typed failure reasons
over a real socket, and one live call in the suite. **What is not:** the
publisher's false-positive list, because *measured 2026-09-10 there is not one* —
neither surface publishes one, and what the publisher does instead is expire IOCs,
which is a deletion. The design for how one would enter is ADR-0028 §8 and stays
`deferred` for absence of the artifact. Nothing paces calls to the configured
rate; no agent has driven a tool loop through this; and the **retrieval confound
is now measured** — for three indicators present in both tiers, every field the
two surfaces share was identical, so a ThreatFox analyst claim corroborating a
ThreatFox enrichment claim is one source agreeing with itself.

## Durability: two halves of one record, and a backup of the half nothing else holds

`concept/08-open-questions.md` files this under *cross-cutting and urgent* —
*"durability and backup for the single store, now that findings and evidence
exist only there, which is a correctness concern rather than an ops detail."*
[`helena.durability`](src/helena/durability.py) is the model,
[`scripts/backup.py`](scripts/backup.py) is the command,
[`docs/runbook.md`](docs/runbook.md) §15 is the procedure and the residual risk,
and [`docs/decisions/0040-durability-and-backup.md`](docs/decisions/0040-durability-and-backup.md)
is the record.

    retained captures on disk    +    the engine's durable tables

**They recover different things, and that is measured rather than argued.** A
capture replayed into an empty migrated schema reconstructs the input and
everything derived from it — normalized events, quarantine rows, the flatten and
signal layers, because a view over a table backfills from the table. It
reconstructs **nothing** the pipeline learned: no feed snapshot, no evidence, no
assessment, no citation. Re-asking the model is a different run and re-fetching a
feed is a *different snapshot*, so those rows are not a cache of something
re-derivable — they are the record.

| Excluded from the backup | Because |
| --- | --- |
| **The broker** | consume-once, restart-volatile, a topic never re-readable. There is nothing to copy, and retention is not durability |
| **The output topic** | egress only; nothing may be recoverable only from it, and every field of a message is a projection of a row that *is* in the backup |
| Materialized views | derived — a restore applies the migrations and the engine rebuilds them from the tables |

```bash
make backup                                          # into .backups/, gitignored
uv run scripts/backup.py --verify .backups/<file>    # is it whole?
uv run scripts/backup.py --restore <file> --schema helena_restore_test
uv run scripts/dev_check.py --captures <dir>         # the other half, at startup
```

The backup is JSON lines — header, one row per line, trailer — and it refuses
four things by name rather than reconciling any of them: a file whose trailer is
missing or does not verify (truncation is visible or it is a bug), a store that
changed while it was being read, a target whose migration ledger or column types
are not the backup's or that already holds rows, and a capture store that is
unreachable rather than empty. The relation set comes from the engine's
catalogue, so a migration that adds a table is in the backup without anyone
remembering to add it.

**Measured 2026-09-12**, warm, against the pinned engine: a 3 375-claim snapshot
backs up in 0.34 s to 2.36 MB and restores in 2.26 s, and applying the schema to
a fresh target takes ~24 s — so recovery is dominated by the migration and not by
the data. What is **not** demonstrated: a restore into a different engine process
or across an engine version (one engine runs per machine), a store larger than a
fixture, and the case where enough time has passed for a context to leave the
24-hour retention horizon, which would change what the *retained* views hold
while leaving every table exact.
