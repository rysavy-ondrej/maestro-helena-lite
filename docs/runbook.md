# Runbook — the local engine and broker

HELENA's automatic pipeline is local end to end. Two third-party binaries carry
it: **RisingWave**, the streaming engine and single store, and **Blink**, the
Kafka-protocol broker. Both are pinned in [`versions.md`](versions.md).

---

## 1. The hazard: a different Python minor under the engine's library name

**Read this before touching `bin/`.** It is first because it is the only failure
in this document that gives you nothing to debug.

`bin/risingwave` is dynamically linked against `libpython3.12.so.1.0`
(`objdump -p bin/risingwave | grep NEEDED`). Distributions that ship a different
Python minor cannot satisfy that from their own repositories — this machine
ships 3.14 — and the obvious fix is to symlink the version you have onto the
name the binary wants. **Do not.** The name matches, the symbols resolve, and
the ABI does not.

### The symptom is that there is no symptom

Measured on 2026-09-03 by pointing `LD_LIBRARY_PATH` at a directory holding
`libpython3.12.so.1.0 -> /usr/lib/x86_64-linux-gnu/libpython3.14.so.1.0`:

| Thing you might check | Correct library | Wrong minor symlinked |
| --- | --- | --- |
| `ldd bin/risingwave` | resolves | resolves — to the wrong file |
| `./bin/risingwave --version` | `risingwave 3.0.3 (ec07f2eb75)` | **identical**, exit 0 |
| `single_node --in-memory` starts | yes | **yes** |
| binds the PostgreSQL port, serves `SELECT version()` | yes | **yes, same string** |
| anything in the engine's log | — | **nothing** |

The engine ran for two minutes under the mismatched library and reported nothing
wrong at any layer reachable over the wire. Compare the *missing* library, which
is loud and immediate:

    ./bin/risingwave: error while loading shared libraries:
    libpython3.12.so.1.0: cannot open shared object file: No such file or directory

So: **a forgotten `source bin/env.sh` tells you. A wrong Python minor does not.**

An attempt to force the mismatch into the open by exercising the one code path
that calls into libpython — embedded Python UDFs, `[udf]
enable_embedded_python_udf = true` — was **inconclusive**: the first `SELECT`
that evaluates such a function kills the whole engine process with no message in
its log, and it does that **with the pinned library too**. That is a RisingWave
3.0.3 bug, not evidence of the ABI. HELENA uses no Python UDFs, and no
conclusion about the ABI can be drawn from that path.

### What to do about it

Because nothing at runtime discriminates, the check has to be structural, and
it is:

    uv run scripts/dev_check.py --binaries-only

It resolves the SONAME through `ldd` in the environment the engine will actually
get, and compares the **sha256 of the resolved file** against the pin in
`docs/versions.md`. `scripts/dev-up` runs it before it starts anything, and
`tests/test_infrastructure.py` runs it as part of the suite — including a test
that builds the bad symlink and asserts the check rejects it.

Related, and the same hazard seen from the Python side: `pyproject.toml` pins
`requires-python = ">=3.12,<3.13"`. The **upper** bound is deliberate. It turns
a Python minor bump into a resolution error instead of a silent runtime failure.

---

## 2. Up and down

    source bin/env.sh          # only needed for a bare ./bin/risingwave; dev-up does it
    scripts/dev-up             # verify the pins, start both, wait until both answer
    scripts/dev-down           # stop both

`dev-up` **does not download anything**. The binaries are third-party artifacts
the project runs, not builds; if `bin/` is empty, `dev-up` says so and points at
`docs/versions.md`.

Addresses come from `RISINGWAVE_DSN` and `KAFKA_BOOTSTRAP_SERVERS` through
`helena.config`, so what `dev-up` binds is exactly what the pipeline connects
to, and a missing variable fails the same way in both.

| | Where |
| --- | --- |
| Logs | `.run/risingwave.log`, `.run/blink.log` |
| Process ids | `.run/risingwave.pid`, `.run/blink.pid` |
| Engine store | `.rwdata/` — `dev-down` leaves it alone |
| Engine working directory | `.run/engine/` — see the `secrets/` note below |

Neither `.run/` nor `.rwdata/` is committed.

### Only one engine per machine

`single_node --listen-addr` moves the **PostgreSQL** port only. The meta and
compute services bind fixed ports (5690, 5688), so a second RisingWave cannot
run alongside the first, whatever `--listen-addr` says. It fails with

    panicked at .../connection.rs: failed to bind `grpc-meta-leader-service`
    to `127.0.0.1:5690`: Address already in use (os error 98)

which is why the test fixtures use an instance that is already answering rather
than always starting a throwaway one. `uv run pytest -q` works whether or not
`dev-up` has been run; it does not work with a *half*-started engine.

### The `secrets/` directory

RisingWave's frontend creates its temp-secret directory at `./secrets` relative
to its **working directory**. A `secrets/` folder appearing at the project root
means the engine was started from there; `dev-up` gives it `.run/engine/` and
the test fixtures give it a pytest temporary directory. `.gitignore` covers the
root one defensively.

### Telemetry is off

RisingWave reports to `telemetry.risingwave.dev` by default. The pipeline is
local end to end and a second outbound channel is a decision rather than a
default, so `scripts/risingwave.toml` sets `[server] telemetry_enabled = false`.
That file holds nothing else.

---

## 3. Blink

### It is configured by environment variables, not by the settings file

`--settings <path>` is required and the file is read, but every setting observed
comes from the environment. **Unknown YAML keys are accepted silently** — a
settings file with a typo in it starts a broker with defaults and says nothing.
`scripts/blink.yaml` is therefore empty (`{}`) on purpose, and `scripts/dev-up`
exports what it needs.

Blink prints the settings it resolved, so `.run/blink.log` is the authority on
what is actually in effect:

| Variable | Default | Note |
| --- | --- | --- |
| `BROKER_PORTS` | `9094`, `9092` | `dev-up` sets one, from `KAFKA_BOOTSTRAP_SERVERS` |
| `KAFKA_HOSTNAME` | `localhost` | what metadata advertises |
| `REST_PORT` | `30004` | not used by HELENA — see below |
| `RETENTION` | `5m` | |
| `KAFKA_CFG_NUM_PARTITIONS` | `1` | |
| `ENABLE_CONSUMER_GROUPS` | `false` | turning it on does not help — see below |

Also present and unused here: `HEAP_MEMORY_FACTOR`, `KAFKA_MEM_HEAP`,
`USE_LAST_ACCESSED_OFFSET`, `CHECK_FOR_SKIPPED_BATCHES`,
`OBLITERATION_WARNING_INTERVAL_MINUTES`.

The REST port is deliberately untouched: `concept/06-technology.md` makes the
Kafka wire protocol the **only** way the broker is addressed, on both ends, so
the health check goes through Kafka metadata even though REST would be easier.

### Consumer groups do not work — consume with `assign()`

Measured against blink 0.2.0 with librdkafka:

- `subscribe()` never receives anything, and **raises no error**.
- The cause is precise: the broker **closes the TCP connection on
  `FindCoordinatorRequest v2`**. Metadata succeeds, the coordinator lookup gets
  a disconnect, and the consumer retries forever in `query-coord`.
- Setting `ENABLE_CONSUMER_GROUPS=true` does not help. Blink starts its consumer
  group background tasks and the disconnect is unchanged.
- `api.version.request=false` with `broker.version.fallback=0.10.0` does not
  help either. The consumer still gets no assignment.
- `AdminClient.list_consumer_groups()` **succeeds** and returns an empty result,
  so it is not a usable probe for this.

The pinned commit is `645c814f`, whose message is *"Restrict the
FindCoordinator version range to supported versions"* — the limitation is where
the pin sits, not an accident of the local build.

**Everything that consumes from the broker must use
`assign(TopicPartition(topic, partition, offset))` and manage its own offsets.**
`tests/test_infrastructure.py` round-trips a record that way.

### Create a topic before producing to it — and ask metadata first

Producing to a topic that does not exist leaves the message in the producer
queue: no error, and `flush()` returns a non-zero outstanding count. Create it
with `AdminClient.create_topics` first. `helena.broker.BrokerProducer.publish`
never returns a silent success — `flush` raises `BrokerError` naming the
outstanding count, and `create_topic` is the step it tells you to take.

**`CreateTopics` for a topic that already exists is not
`TOPIC_ALREADY_EXISTS`.** Measured 2026-09-03: blink answers with a response
librdkafka cannot parse at all —

    _BAD_MSG "CREATETOPICS worker failed to parse response:
              CreateTopics response protocol parse failure"
    PROTOERR  Broker returned topic  that was not included in the original request

— so the "already exists" case is indistinguishable by error code from a broker
that is genuinely misbehaving. `create_topic` therefore asks `Metadata` first and
only creates when the topic is absent; a parse failure that does get through is
reported as an error, not swallowed.

### The broker is not a store, and the reclaim is not instant

`concept/03-architecture.md`: *memory-first, single-node, consume-once and
restart-volatile: a record read once is gone whatever retention says. A topic is
never re-readable.* **Broker retention is not a durability mechanism**, and
nothing in HELENA replays by re-reading a topic — replay publishes the retained
capture again (`docs/decisions/0014-the-ingest-topic-message.md`).

Measured against blink 0.2.0, because the timing matters to anyone writing a
retry:

| What was done | What was observed |
| --- | --- |
| 3 records produced, drained once | all 3 returned |
| drained again **immediately** | can still return all 3 — the reclaim is a background step, not part of the read |
| drained again a few seconds later | empty, watermarks back to `(0, 0)` |
| produced and **never read**, 30 s later | all 3 still there — so this is consume-once, not a short retention window |

So "never re-readable" is true in substance and not instantaneous. A retry
written against the sentence alone will occasionally ingest a capture twice. The
counters are what catch that: `helena.normalizer.IngestCounts` refuses a
`consumed` larger than the capture's record count.

`RETENTION` defaults to 5m and does not enter into any of this. Do not reach for
it: a longer retention would make a topic look like a store for a while, which
is worse than the current behaviour, not better.

---

## 4. Checking without starting anything

    uv run scripts/dev_check.py --binaries-only   # pins only
    uv run scripts/dev_check.py                   # pins, then both endpoints
    uv run scripts/dev_check.py --wait 120        # ... retrying until they answer
    uv run scripts/dev_check.py --storage         # what the migrated schema stores

`scripts/dev_check.py` is the only code that reads the pins, and
`tests/test_infrastructure.py` calls the same functions — so "the endpoint
answers" means one thing in the runbook, in `dev-up` and in the suite.

### What "answers" means, measured

`single_node --in-memory` on this machine:

| | Elapsed from launch |
| --- | --- |
| accepts a PostgreSQL connection | 0.50 s |
| `SELECT version()` | 0.51 s |
| `rw_catalog.rw_worker_nodes` shows 3 running workers | 0.53 s |
| `CREATE TABLE` / `INSERT` / `FLUSH` / `SELECT` / `DROP` | 0.65 s |

So the engine is usable about a second after launch, and `SELECT version()`
becomes true roughly 0.15 s **before** DDL does. The endpoint check is
read-only on purpose — it also runs against the `dev-up` instance, and a health
check should not write to the store — so anything that needs DDL immediately
after startup should retry its DDL rather than treat the smoke check as a
guarantee.

---

## 5. Migrations

The engine's schema is `sql/migrations/NNNN_name.sql` — plain numbered files,
applied in order, no transformation framework
(`docs/decisions/0007-sql-migrations.md`). `helena.migrations` applies them and
records each one in `helena_schema_migrations` in the engine.

    uv run scripts/migrate.py --status   # what is applied, what is pending
    uv run scripts/migrate.py            # apply everything pending, in order

It is idempotent — a second run applies nothing — and it refuses rather than
guesses: a gap in the numbering, two files with one number, a file that is
recorded as applied but is no longer on disk, a rename or **any edit to an
already-applied file** (the checksum is recorded when it is applied). To change
something that has shipped, write the next migration.

### Migrate before data flows

**Every view a deployment needs must exist before anything is ingested** — or,
stated as the thing that actually bites, before the records it needs reach the
store. The broker is consume-once and restart-volatile: a record that has been
consumed is gone whatever retention says, and a restart discards what is queued
(`concept/03-architecture.md`, "What is *not* a store"). A record consumed while
`helena_normalized_events` did not exist is a record that is nowhere.

The step that usually follows this one does **not** hold here, and it is measured
rather than reasoned (2026-09-04, §8): a view added over
`helena_normalized_events` *does* backfill, because normalized events are a table
in the single store rather than a stream the view had to have been listening to.
The empty view to worry about is the one whose **records** never landed, not the
one that was created late.

Either way the answer is the same, and it is why captures are the durable record
and the broker is not: apply the migration, then replay the captures that cover
the window you need — §8. Order the startup `migrate`, then ingest, never the
other way round.

### There is no rollback

RisingWave has no transaction around DDL. Measured, not inferred: sending
`CREATE TABLE a; CREATE TABLE a` in one statement leaves `a` behind and *then*
raises. A migration file that fails partway has therefore already done whatever
ran before the failing statement.

The runner records that version as `failed` in the ledger and refuses to apply
anything else until it is resolved, so a half-migrated store is visible instead
of turning up later as a confusing duplicate-object error. Resolving it is
manual and deliberate:

1. undo by hand whatever the file managed to do;
2. `DELETE FROM helena_schema_migrations WHERE version = <n>` and `FLUSH`;
3. fix the file and run again.

One exception with no way around it: `0001_schema_migrations.sql` *is* the
ledger, so if it fails there is nowhere to record that it failed. The error says
so rather than implying the ledger was written.

### What the schema costs

    make storage        # or: uv run scripts/dev_check.py --storage

One line per relation that stores anything, largest first, then a total. The
numbers are `rw_catalog.rw_table_stats` — the engine's own accounting, an
estimate that moves as compaction runs — and they cover the object's own rows
**plus the state of the streaming job behind it**, which is where most of a
materialized view's disk goes.

```
   2,392,442 bytes  materialized view  helena_signal_context_entities
     361,636 bytes  materialized view  helena_signal_domain_registrable
       ...
   3,235,812 bytes  in total, across 11 tables and materialized views;
                    19 plain views store nothing
```

**A plain view never appears with a number**, and that is the point: a layer
showing up here that should have been plain views is paying disk for rows nothing
reads (`docs/decisions/0016-view-layering-and-materialization-policy.md`, which
carries what it was measured at). Run it after a load, not on an empty store —
an empty schema is refused rather than reported as costing nothing.

### Editing a migration that has already been applied

Don't. The ledger holds each applied file's sha256 and the runner refuses to
touch a store whose files have changed underneath it, **including a change to
comments only** — the checksum is over the bytes. The refusal names the file and
both hashes, and it is correct: the engine does not hold what the file says.

A store that has had the migrations applied before task 17 (which retrofitted the
declaration comments into 0001–0004 and 0008) has to be dropped and re-migrated.
The same holds for a store migrated before `0010_entity_value_null_guard.sql`,
which retrofitted `Superseded by:` into the seven definitions it replaces, in
0007, 0008 and 0009, and for one migrated before `0019_sink.sql`, which
retrofitted `Read by:` into the five definitions the sink view reads — in 0009,
0010, 0015 and 0018 (twice). `0020_emission_counts.sql` adds one more, into 0019
itself, for the same reason: the emission counter reads the sink view, and every
relation that is read has to name its reader.
`0021_pipeline_observability.sql` is the largest of these so far — its seven
views read relations defined in **0003, 0004, 0006, 0013 (twice), 0018 (twice)
and 0020**, and every one of those files had to name its new reader. A store
migrated before 0021 has to be dropped and re-migrated. There is no in-place
repair short of writing the new checksums into the ledger by hand, which is the
same act with the evidence removed.

**`Read by:` is the second standing cost of the same kind, and it has the same
justification as `Superseded by:`.**
`tests/test_view_layering.py::test_every_relation_that_reads_an_object_is_named_in_its_read_by`
fails until a new reader is named in the file that defines what it reads, so
adding a view is an edit to the files above it. That is deliberate: the question
"what would break if I changed this view?" is answered in the file a person
already has open, rather than by a grep that misses the reader written last
week.

**This is the standing cost of `Superseded by:`, and it is deliberate.** A
migration that drops and recreates an object has to go back and mark the
definition it replaced, because the alternative is leaving a `CREATE` in the tree
that the engine never holds with nothing saying so. `helena.migrations` refuses
the migration until the mark is there, so the choice is made when the file is
written rather than discovered by whoever edits the dead definition later.

### Bumping the aggregation version

`0002_aggregation_version.sql` holds the engine's copy of
`helena.versions.AGGREGATION_VERSION`, and `tests/test_versions.py` fails if the
two disagree. Bump it **when the aggregation changes what a context means**, not
when a view is reformulated with the same meaning, and bump it in one commit:

1. write the next migration — `DROP VIEW helena_aggregation_version;` then
   `CREATE VIEW … AS SELECT '<new>' AS aggregation_version;` — never an edit to
   0002, which the checksum refuses anyway;
2. change every aggregation view that carries the literal, in the same file;
3. change `AGGREGATION_VERSION` in `helena/versions.py`;
4. `uv run pytest -q` — the equality tests are what tell you a copy was missed.

Rows already in the store keep the version they recorded. Nothing rewrites them:
replay validates a stored assessment against the version *it* recorded
(`docs/decisions/0008-version-registry.md`).

### A migrated schema costs streaming jobs, and an abandoned one keeps costing them

Measured on the pinned RisingWave 3.0.3, 2026-09-12, against a `single_node` with
`parallelism: 4`: applying `sql/migrations/` into one schema takes the cluster
from **273 actors to about 466** — roughly **190 actors per migrated schema** —
and the engine refuses a new streaming job above `hard limit: 400` **per unit of
parallelism**, so the practical ceiling on this machine is around 1 600 actors:

    Not supported: the number of actors exceeds the limit ...
    DETAILS: - hard limit: 400 ... actor_count: 1606, parallelism: 4

The suite's fixtures create their schemas as `helena_test_…` / `helena_e2e_…` and
drop them in a `finally`, so a run that completes leaves nothing behind. **A run
that is killed cannot**, and each abandoned schema holds its ~190 actors until
somebody drops it. Four of them is a cluster that refuses the next migration, and
the failure arrives as a `MigrationFailed` in whatever test happened to be
migrating — which reads like a broken migration and is not one. To check and to
clear:

```sql
SELECT count(*) FROM rw_catalog.rw_actors;
SELECT name FROM rw_catalog.rw_schemas WHERE name LIKE 'helena\_test\_%'
    OR name LIKE 'helena\_e2e\_%';
DROP SCHEMA <name> CASCADE;    -- one per abandoned run
```

Nothing outside those two prefixes is the suite's. `public` is where
`uv run scripts/migrate.py` puts a deployment's own schema, and dropping that is
dropping the store.

---

## 6. Quarantine: what ingestion refused

A record the configured adapter refuses is not dropped and does not stall the
capture: it is written to `helena_ingest_quarantine` in the engine with its typed
reason, the contract version that refused it, the capture and offset that address
it, and the raw bytes exactly as read. Quarantine lives in the single store like
everything else durable — `docs/decisions/0013-quarantine-in-the-single-store.md`.

Three reasons, and they mean different things:

| `reason` | What it says |
| --- | --- |
| `malformed_json` | The framing broke. Not JSON at all, truncated, or not valid UTF-8 |
| `not_this_format` | The wrong adapter is configured for this input — check `HELENA_INPUT_FORMAT` |
| `contract_violation` | This format's shape, refused by the flow-record contract. **The producer changed** |

Reading the counter by hand, against the configured engine:

```sql
SELECT reason, sum(quarantined) FROM helena_ingest_quarantine_counts
 WHERE tenant = '<tenant>' AND capture_sha256 = '<sha256>' GROUP BY reason;

SELECT record_offset, reason, detail, payload FROM helena_ingest_quarantine
 WHERE capture_sha256 = '<sha256>' ORDER BY record_offset;
```

The denominator is **not** in the engine. The broker is consume-once, so how many
records a capture held is a fact about the retained file;
`helena.normalizer.Quarantine.counts(capture)` brings the two together and
refuses a total that does not reconcile.

**A rising `contract_violation` rate is the number to watch**, and it has already
been collected on once. Field requiredness was measured from one capture of one
host over 130.8 seconds; a second capture — a day of one network — was then
refused **in its entirety**, a rate of 100 %, and requiredness was re-derived
over both (`docs/decisions/0010-capture-identity.md`, addendum). So a producer
that omits a field marked required here is still quarantined rather than
accepted, and the answer to a high rate is still a **new observation of the
input** — `detail` names the field and `payload` is the record — not a field
loosened on a hunch. Loosening one is a contract change and gets its own
increment, which is exactly what that addendum records.

What that episode is worth operationally: a 100 % rate with every row naming the
same handful of fields is a producer the contract has never seen, not a broken
sensor. Read the fields before reading the number.

Re-ingesting a capture rewrites the same rows rather than doubling them: the key
is the ingestion identity plus the capture and offset, and an `INSERT` onto an
existing key in RisingWave is an upsert. So the rate does not drift upward with
every replay.

---

## 7. Ingest: the topic, the events and the counters

Flow records arrive on `HELENA_INGEST_TOPIC` over the Kafka wire protocol. One
record per message, exactly as the producer wrote it, with the raw-record
reference in two message headers — `helena-capture-sha256` and
`helena-record-offset`. `docs/decisions/0014-the-ingest-topic-message.md` is why.

A message with no usable reference in its headers **stops the run** with
`IngestMessageError` naming the header. That is not the same thing as a refused
record: a quarantine row is keyed by the capture and the offset, so a message
carrying neither has no row it could be written to. It means a producer is
publishing to the wrong topic.

Accepted records land in `helena_normalized_events`
(`sql/migrations/0004_normalized_events.sql`) with the identity the deployment
assigned and the observation as JSONB — the record as supplied, so an unobserved
layer is an absent key and an observed-but-empty one is an empty array.

### The four numbers, and where each comes from

    SELECT normalized FROM helena_ingest_counts
     WHERE tenant = '<tenant>' AND capture_sha256 = '<sha256>';

| Number | Source | Why it cannot come from anywhere else |
| --- | --- | --- |
| `records` | the retained capture file | the broker is consume-once; a topic cannot say how many records there were |
| `consumed` | the ingest run | nothing else counts what came off the topic |
| `normalized` | `helena_ingest_counts` | the store holds the rows |
| `quarantined` | `helena_ingest_quarantine_counts` | ditto, with the three reasons kept apart |

`helena.normalizer.ingest_counts(...)` brings them together and **refuses a set
that does not reconcile**: `normalized + quarantined` must equal `consumed`, and
`consumed` may not exceed `records`.

`consumed < records` is reported as `complete is False`, not raised. It means
records went missing between the producer and the store, and because the broker
keeps nothing they are gone — the answer is to replay the capture, which is
still on disk. §8.

---

## 8. Replay: a retained capture, back through the pipeline

    uv run scripts/replay_capture.py --captures <dir> <sha256>
    uv run scripts/replay_capture.py --captures <dir> <sha256> --rate 200 --ingest

The retained capture is the durable record (`concept/07-principles.md`). Replay
publishes its records to `HELENA_INGEST_TOPIC` in exactly the wire form a sensor
uses — §7 — and everything after that is the live path: the same adapter, the
same identity stamping, the same two stores, the same counters. There is no
second normalization path, and `tests/test_normalizer.py` states that as rows
rather than as an intention: the events a replay leaves in the store are compared
against the events the same capture produces read straight off disk.

| Option | What it does |
| --- | --- |
| `--captures DIR` | required. The directory of retained captures. There is no default: replaying the wrong directory publishes another deployment's records under this one's identity |
| `--rate PER_SECOND` | a **floor** on how fast records are published — record *k* goes no earlier than *k / rate* seconds after the first. Unset, they go as fast as the broker accepts them. A broker that cannot keep up makes the run slower and nothing speeds it back up; a pacer that caught up in a burst would replay at a rate nobody asked for |
| `--ingest` | also run the **ingestion** side in this process and print the four counters. Nothing else consumes the topic in this prototype, so this is also how a replay actually reaches the store |
| `--idle-timeout SECONDS` | with `--ingest`, how long the consumer waits before deciding the topic has gone quiet. There is no end-of-stream in the protocol |

Exit status is 0 only when every record was published and, with `--ingest`, every
record is accounted for in the store.

### A capture directory holds files named by their own hash

`<sha256>.jsonl`, and the digest is checked against the bytes on every scan, so a
capture that changed under its name is refused rather than replayed under a
reference that addresses different records. `data/ingest/` is **not** such a
directory — `flow-sample.jsonl` is a sample, not a retained capture, and the
command says so:

    FAILED: data/ingest/flow-sample.jsonl: a capture file is named <sha256>.jsonl

`tests/fixtures/captures/` is one.

### Replaying twice is safe. Publishing twice and draining once is not

Every assigned field is derived from the capture, the offset and the configured
identity, and an INSERT onto an existing key is an upsert (§5), so a second
replay **rewrites the same rows**. Measured 2026-09-04: the ten-record fixture
replayed twice through the command left ten events with identical event ids.

Publishing twice *without* draining in between is the case that fails, and it
fails loud:

    FAILED: the counters do not reconcile: ... 20 message(s) were consumed for a
    capture of 10 records, so at least one record was consumed more than once

That check runs **before** the accounting check on purpose. The upsert means
`normalized` does not grow, so a double-consumed run produces the same three
numbers as a run that lost records; a diagnosis pointing at loss would send you
looking for a broker fault that is not there.

### Backfilling a view added to a running deployment

What actually needs replaying, measured against the pinned engine on 2026-09-04:

- **A view added over `helena_normalized_events` backfills from the table.** With
  ten events in the store, a `CREATE MATERIALIZED VIEW ... AS SELECT ... FROM
  helena_normalized_events GROUP BY ...` reported all ten the moment it was
  created, and picked up a later replay's record incrementally.
- **Replay is needed when the records are not in the store**: consumed before the
  table existed (migrate before data flows — §5), lost between the topic and the
  store (`complete is False` — §7), or never ingested by this deployment.

`concept/06-technology.md` says *the broker is consume-once, so a view added later
starts empty rather than backfilling; adding one to a running deployment requires
replay from the retained captures.* That is right about the broker, and right
about a view over the stream. It is not what happens for a view over the stored
events, because since migration 0004 normalized events are a **table in the single
store**, not a stream a view had to be listening to. The rule underneath it still
holds and is the one to carry: **what never reached the store cannot be recovered
from the broker, only from the capture.**

The procedure:

1. Write the migration for the new view and apply it — `make migrate`, §5.
2. Ask whether the records it needs are in the store:

       SELECT tenant, capture_sha256, normalized FROM helena_ingest_counts;

3. If they are there, the view is already populated — check it and stop.
4. If they are not, replay each capture that covers the period:

       uv run scripts/replay_capture.py --captures <dir> <sha256> --ingest

5. Read the counters it prints. `every record of the capture reached the store` is
   the only line that says so; anything else is a short run, and §7 says which
   number is short.

### Replaying a stored *assessment* is a different command

    uv run scripts/replay_assessment.py <assessment_id>
    uv run scripts/replay_assessment.py <assessment_id> --rerun

The capture replay above puts records back through ingestion. This one puts one
**stored assessment** back through the two agents: it reads the row and its child
rows, validates them against the contract version the row recorded, rebuilds the
request by re-rendering the recorded context version under the recorded rendering
version, and — with `--rerun` — asks the recorded prompt again and prints a diff
across verdict, path, confidence and citations.

| | |
| --- | --- |
| without `--rerun` | **calls nothing.** Reads, validates, reconstructs. This is the check that a stored assessment's inputs still rebuild |
| with `--rerun` | calls the configured **model** endpoint and spends that quota. No provider is queried either way: every lookup resolves from the stored response, and a tool that is not a replay is refused before the model is called |

Three things it will refuse, and each of them is the point rather than a fault:

- the context version the assessment recorded is no longer in the store — there is
  nothing to render, and rendering the current version would assess a different
  snapshot;
- the row records a `schema_version` this tree does not hold — historical schema
  classes are retained frozen and old rows are never migrated forward;
- the evidence the assessment cited is not in the rebuilt rendering, so the inputs
  have moved.

**A difference in the diff is not a failure.** The model is not deterministic; a
re-run is idempotent in its record, not in its verdict. What would be a failure is
a reconstruction that could not be validated, and that stops the command before
anything is called. `docs/decisions/0035-assessment-replay.md` is the long form,
including the four things a replay does not reconstruct.

The identifier is the one `AssessmentStore.store` returns, and it is also

    SELECT assessment_id FROM helena_analytical_assessment
     WHERE context_id = %s AND emitter = %s;

---

## 9. Reference data: the Public Suffix List

The only reference table so far, and it is **normalization, not enrichment** —
`concept/05-threat-intelligence.md` gives it an empty "Maps to" cell and no tier.
It decides where a name's registry-controlled part ends, which is what makes a
scope comparison between a feed's domain and an observed name mean anything. It
maps to nothing in the taxonomy and escalates nothing.

    uv run scripts/load_public_suffix_list.py            # fetch and load
    uv run scripts/load_public_suffix_list.py --status   # what is loaded

Nothing schedules it. "Its own schedule" is cron, a timer, or a hand-run; the
publisher refreshes the list a few times a week and the loader is idempotent —
the same bytes are the same snapshot and are recorded as `unchanged` rather than
rewritten.

### A failed load leaves the previous snapshot in place

Every attempt writes a row to `helena_reference_public_suffix_load`, including
the ones that wrote nothing else:

    SELECT attempted_at, status, snapshot_version, rule_count, failure_reason
    FROM helena_reference_public_suffix_load ORDER BY attempted_at DESC;

`loaded`, `unchanged` and `failed` are three different things, and a `failed` row
names one of `fetch_failed`, `malformed_rule` or `empty_list`. The rules table is
untouched by a failure, so the previous snapshot stays current — which is the
right behaviour and also the one that goes unnoticed, so read the load table
before trusting a registrable domain.

### `list_not_loaded` is not `no_match`

`helena_signal_domain_registrable.registrable_domain_status` has four values and
they are not interchangeable:

| Status | Means |
| --- | --- |
| `derived` | the registrable domain is on the row |
| `name_is_a_public_suffix` | the name **is** a public suffix. Nothing is missing |
| `invalid_name` | not a domain name — an empty label, or an address literal |
| `list_not_loaded` | the reference table is empty. Run the loader |

With a snapshot loaded, every valid name matches at least the algorithm's default
`*` rule, so `list_not_loaded` can only mean nobody loaded the list. A whole
column of `NULL` registrable domains right after a fresh migration is this, not a
bug in the derivation.

---

## 10. When something is wrong

| Symptom | Cause |
| --- | --- |
| `error while loading shared libraries: libpython3.12.so.1.0` | `bin/env.sh` not sourced, or `bin/lib/` missing |
| `dev_check` reports a sha256 mismatch on the resolved libpython | §1. Stop and read it |
| `failed to bind grpc-meta-leader-service to 127.0.0.1:5690` | another RisingWave is running. `scripts/dev-down`, or find it |
| `dev-up` says a component is already running | a stale pidfile in `.run/`, or it really is. `scripts/dev-down` |
| The engine answers but SQL fails on a fresh start | it was still coming up; §4 |
| A consumer subscribes and receives nothing, no error | §3. Use `assign()` |
| `BrokerError: N message(s) were still queued` | the topic was never created. §3 |
| `BrokerError: could not create topic ... parse failure` | §3. Metadata and `CreateTopics` disagree; something created it in between |
| `IngestMessageError: the message carries no [...] header(s)` | a producer is publishing to the wrong topic. §7 |
| An ingest run reports `complete is False` | records were lost between the producer and the store; replay the capture. §7 |
| `flush()` returns a non-zero outstanding count | the topic does not exist; §3 |
| A blink setting has no effect | it is an environment variable, not a YAML key; §3 |
| The integration tests raise `ConfigurationError` | no `.env`. Copy `.env.example` and fill it in; the addresses are read through `helena.config` |
| `scripts/migrate.py` refuses with "has changed since it was applied" | an applied migration was edited. §5 — write the next one instead |
| `MigrationFailed: ... the number of actors exceeds the limit ... hard limit: 400` | abandoned `helena_test_*` / `helena_e2e_*` schemas from killed test runs are still holding streaming jobs. §5, last block |
| A view exists but is empty and the data is old | the records never reached the store, or they are not this capture's. §8 |
| `FAILED: ... a capture file is named <sha256>.jsonl` | `--captures` is not a capture directory. §8 |
| `FAILED: ... holds no assessment <id>` | that identifier is not in this store, or a later pass superseded the run. §8 |
| `FAILED: ... does not hold context ... outside the retention boundary` | the context the assessment scored has left the horizon, so its rendering cannot be rebuilt. §8 |
| `FAILED: no contract version 'vN'` | the assessment records a schema version this tree does not hold. It is not migrated forward; §8 |
| `FAILED: ... holds no capture <sha256>` | that digest is not in that directory — the file was renamed, or its bytes changed |
| `FAILED: ... consumed more than once` | the capture was published to the topic twice and drained once. §8 |
| `INCOMPLETE: N record(s) never came off the topic` | records were lost between the producer and the store. §7, then replay again |
| `helena_ingest_quarantine` is filling up | the producer drifted, or the wrong `HELENA_INPUT_FORMAT` is set. §6 — the `reason` column tells you which |
| `list_not_loaded` on every domain row | the Public Suffix List was never loaded. §9 |
| `load_public_suffix_list.py` prints `failed: ... fetch_failed` | no route to the publisher, or a proxy. The previous snapshot is still in place; §9 |

---

## 11. Egress: what the output topic carries, and what you inherit by forwarding it

`uv run scripts/emit.py` is what emits — see §12 for running it. This section is
about what the bytes contain, because the property it describes is a property of
the **payload** and not of the deployment.

**The message is unredacted and no redaction is planned in the sink.**
`concept/03-architecture.md`, "Trust and egress boundaries", 2.: the sink writes
to the *local* broker, so no gate is crossed — but the payload contains

| Field | What it is |
| --- | --- |
| `host` | an internal address: the monitored host |
| `entities[].entity_value` | addresses contacted, names resolved, URLs, certificate fingerprints |
| `entities[].evidence[].native_evidence` | the publisher's record, verbatim — retrieved external text |
| `disclosures[].query` | which indicators this network told an external provider about, and which model endpoint it prompted |

**Any consumer that forwards a message off-site inherits the redaction,
minimization and disclosure obligations, and the pipeline cannot enforce that.**
Every message carries `helena.sink.MESSAGE_CAVEAT` in its `caveat` field so the
statement travels with the bytes, but a caveat is not a control.

Two operational consequences:

- a SIEM forwarder, a cloud connector or a hosted dashboard on this topic is an
  egress decision, not a configuration detail — `concept/instruction.md` §3 makes
  a second egress channel something to stop and ask about;
- the topic is **egress, not storage**. Nothing in a message is recoverable only
  from it (`tests/test_sink.py` executes that), so a consumer that lost a message
  can read the assessment back out of the engine; and a consumer that retained
  one has made a second copy of internal addresses outside the store.

`docs/decisions/0036-the-output-message.md` §5 has the argument, and §7 the rule
for changing the shape: a change to the field set, a field's meaning or a field's
type bumps `helena.sink.MESSAGE_VERSION` and comes with a decision record.

---

## 12. Emitting: draining the store to the output topic, and counting it

### Running it

```bash
uv run scripts/emit.py --count      # ask the engine; produce nothing
uv run scripts/emit.py              # drain every terminal outcome to the topic
```

There are no flags for the topic or the broker. Both come from configuration —
`HELENA_OUTPUT_TOPIC` and `KAFKA_BOOTSTRAP_SERVERS` — because a topic typed on a
command line is a topic that can differ between two runs of the same deployment.
`HELENA_OUTPUT_TOPIC` **may not be the same name as `HELENA_INGEST_TOPIC`**;
startup refuses that, and §12.3 below says what it would otherwise look like.

The exit status is 0 only when every message the store held reached the broker.

### It is a drain, not a stream, and it repeats

`scripts/emit.py` emits every terminal outcome the store holds and returns.
**It keeps no cursor**, so running it twice puts the same messages on the topic
twice. That is the contract rather than a defect — `concept/03-architecture.md`:
*"delivery is at-least-once, so consumers deduplicate; exactly-once is not
attempted"* — and the consumer discards the repeat by `assessment_id`, which is
identical across runs, in the payload and in the `helena-assessment-id` header.
`docs/decisions/0037-at-least-once-emission.md` §2 is the contract to hand a
consumer.

Two operational consequences:

- **there is no continuous emitter.** Nothing runs on a schedule; a message
  reaches the topic when somebody runs the drain;
- **the topic carries the full context volume.** `normal` verdicts are emitted
  too, by design, and one message over the ten-record layers capture measures
  36 994 bytes. ADR-0037 §4 has the hazard and what would have to be measured
  before changing it.

### 12.1 "The consumer sees nothing"

Ask the engine. The broker is memory-first and consume-once — a topic read once
is empty and a topic nobody read is empty after a restart (§3) — so once the
messages are gone, the engine is the only side that still knows there were any.

```bash
uv run scripts/emit.py --count
```

or the same number in plain SQL, for an operator who is not running the emitter:

```sql
SELECT * FROM helena_analytical_emission_counts;
```

| What it says | What happened |
| --- | --- |
| no row, or `pending = 0` | **Nothing was assessed.** Look upstream — ingest (§7), the context views, the orchestrator. Nothing was ever emitted because there was nothing to emit |
| `pending = N`, N > 0 | **N messages existed.** If none arrived, they were emitted with no consumer attached, or the consumer read them and the broker reclaimed them. They are gone; the assessments are not — they are still rows, and another drain re-emits them |

The count is at **message** grain, one per terminal outcome. `helena_analytical_sink`
itself is one row per (terminal run × entity × source) — 41 rows for one message
over the layers capture — so counting that view directly answers a different
question.

### 12.2 "It emitted fewer than the engine holds"

```
emitted 7 of 9 message(s) to helena.output
2 message(s) were assessed after this run read its list and were not emitted; run it again
```

Ordinary, and it says so: a pass that landed while the drain was in flight is the
next run's message. The drain reads its list first and the count second precisely
so that this case shows up as a shortfall to re-run rather than as an error.

`emitted` larger than `pending` is different and is refused — it would mean one
run produced a message twice, which is the one duplicate at-least-once does not
cover, because a consumer deduplicating across runs is not looking for it.

### 12.3 The failure that looks like something else

If `HELENA_OUTPUT_TOPIC` and `HELENA_INGEST_TOPIC` were ever the same name, the
pipeline would consume every message it emitted back as a flow record, fail to
parse it, and file it in quarantine (§6) — with every counter reconciling. The
symptom would read as *a sensor sending malformed traffic*, which is a real thing
that happens, so the diagnosis would go to the wrong place entirely.
`helena.config` refuses that configuration at startup, naming both variables. If
you see quarantine filling with records that look like assessments, check those
two variables first.


## 13. Status: what the pipeline's own numbers say

```bash
uv run scripts/status.py
uv run scripts/status.py --captures data/ingest
```

This is `helena status`. It prints, for `HELENA_TENANT` / `HELENA_SENSOR`, the
end-to-end reconciliation, what the retention boundary is dropping, each feed's
snapshot age against its schedule, latency / cost / retries / cache state per
model, the typed failures, the escalation rate and the retrieval trace by source.

**It is not a health check.** It prints numbers and does not decide which of them
is bad — there are no thresholds here and none are configured. This section is
where the numbers are explained.

**Every number is a `SELECT`, and none of it needs this command.** The views are
`sql/migrations/0021_pipeline_observability.sql` plus `0009`'s rejection counter
and `0020`'s emission counter, so an operator with `psql` and none of this
project's code gets the same answers:

```sql
SELECT * FROM helena_analytical_pipeline_reconciliation;
SELECT * FROM helena_analytical_run_metrics;
SELECT * FROM helena_reference_feed_staleness;
SELECT * FROM helena_signal_retention_rejections;
```

That is deliberate and it is the reason **no hosted tracer is configured, and
adding one is not a configuration change**: a tracing service is a second egress
channel carrying prompts, rendered context and retrieved provider text
(`concept/07-principles.md`, `concept/instruction.md` §3). See
`docs/decisions/0038-pipeline-metrics-and-reconciliation.md`.

### 13.1 `--captures` and why its absence is not zero

How many records **existed** is a property of the retained capture file and of
nothing else: the broker is consume-once and restart-volatile (§3), so the topic
cannot be asked. Without `--captures` the report prints

```
  capture records   not read (pass --captures DIR)
  unaccounted       — (no capture directory was read, so how many records existed is unknown; ...)
```

rather than a zero, which would report a deployment that had lost every record it
ever ingested.

### 13.2 Reading the PIPELINE block

```
PIPELINE
  capture records   11 in 1 capture(s)
  normalized        10
  quarantined       1
  admitted          11
  unaccounted       0
  context records   10 in 1 context(s)
  unaggregated      0
  assessments       3 over 2 context(s)
  emittable         2 message(s)
```

| Line | What a non-zero means |
| --- | --- |
| `unaccounted` | records that reached **neither** store. The broker keeps nothing, so they are gone; replay the capture (§8) |
| `unaggregated` | normalized events that reached no context. Usually a record with no `ip` layer or an unparseable `ts` — the tumble drops it. A fact about the input, not a fault |
| `assessments` > `emittable` | ordinary: an escalated pass stores two runs and emits one message |
| `admitted` > `capture records` | refused outright. A capture was published to the topic twice and drained once; storing an event again is an upsert, so it looks exactly like loss (§7) |

### 13.3 Reading FEEDS

```
FEEDS
  threatfox                stale    1 attempt(s), 3.000 interval(s) behind
```

`missing`, `stale` and `ok` are three different things and are never collapsed:

| Status | What it is | What to do |
| --- | --- | --- |
| `ok` | the snapshot is younger than the source's own refresh interval, **or** the source declares no schedule (the SSLBL JA3 list is not late, it is finished) | nothing |
| `stale` | there is a snapshot and the publisher has moved past it. The claims still stand — removal from a feed is not exoneration | look at `intervals behind`. One is a late cron; thirty is a loader nobody is running |
| `missing` | **no snapshot at all.** Never `no_match`, which is a source that ran and found nothing | if `attempt(s)` is non-zero and a `last failed attempt` line follows, the loader runs and fails — §10. If it is a source you expected, nobody has loaded it |

### 13.4 Where a rate is a sentence instead of a number

```
    cache    0 hit(s) / 0 live, ratio — (triage's runs ... retrieved nothing, so
             there is no cache-hit ratio; 0.0 would read as 'the cache never
             helped' about runs that never asked)
```

That is the report working. Every rate here refuses an empty denominator and says
why, because `0.0` over nothing reads as good news — "the boundary dropped
nothing", "triage escalates nothing", "this model is free" — when the truth is
that nothing has run.

### 13.5 "The cost says 0.000000"

`config/policy.toml` is deliberately silent about the price of the endpoint this
repository is configured against, so `priced 0/N` and no cost is the **normal**
state and means *not priced*, never *free*. Add a `[model_prices.<model>]` entry
to derive a figure; the revision that derived it is recorded on every assessment
row beside the number.

---

## 14. Credentials: two exposure profiles, and only one needs the URL rule

`concept/07-principles.md` is absolute about the five channels — *"never logged,
in any form: tokens and credentials — in prompts, evidence, logs, traces or
source control"* — and then adds one rule that is narrower than it looks:

    *"a key that travels in a URL path must be redacted before anything is
    logged or stored, including the fetch trace a loader records for
    provenance."*

**That rule is about the exposure channel, not about the provider.** The same
abuse.ch secret has two profiles, and treating them uniformly gets one of them
wrong in each direction: assume the header profile leaks like a path and you
redact provenance you needed; assume the path profile is as contained as a header
and the key reaches four places at once.

| | Header profile | Path profile |
| --- | --- | --- |
| Surface | `POST threatfox-api.abuse.ch/api/v1/`, the hunting API | `GET threatfox-api.abuse.ch/v2/files/exports/<AUTH-KEY>/full.csv.zip`, the v2 export |
| Where the key travels | an `Auth-Key` **request header** | a **URL path segment** |
| Reaches a proxy or access log | no — a header is not in the request line | **yes**, the path is |
| Reaches shell history | no | **yes** (`curl`, a `wget`, a pasted command) |
| Reaches an exception | no | **yes** — `urllib.error.HTTPError.url` carries the full request URL, and `http.client.InvalidURL` quotes the path |
| Reaches a pasted link | no | **yes**, and this is not hypothetical: a live key reached a project conversation exactly this way |
| Used by this repository | yes — `helena.providers`, the analyst's lookup | **no.** Nothing here fetches it |

**The export this repository does fetch needs no credential at all.**
`GET threatfox.abuse.ch/export/json/recent/` — the one
`helena.enrichment.fetch_threatfox` uses — answers `200` with nothing attached.
Measured again on **2026-09-12**, which is the fourth time, because a concept note
said the opposite until 2026-09-03 and the claim had already propagated through
four files by then:

| Request | Result, 2026-09-12 |
| --- | --- |
| `GET threatfox.abuse.ch/export/json/recent/`, no credential | **200**, `application/json` |
| `POST threatfox-api.abuse.ch/api/v1/`, no `Auth-Key` header | **401** |
| `POST threatfox-api.abuse.ch/api/v1/`, `Auth-Key` header | **200** |
| `GET threatfox-api.abuse.ch/v2/files/exports/<a key that is not one>/full.csv.zip` | **401** — so the path segment really is the credential |

**Do not "re-correct" the 2026-09-03 correction.** Until then
`concept/05-threat-intelligence.md` said the *bulk export* carried the key in its
path and that the key had two exposure profiles; the first half was wrong and the
note records the correction rather than overwriting it. What is true is narrower
and is the table above: the two profiles live on **two different endpoints**, the
path one is a v2 export **nothing here fetches**, and the endpoint the loader does
fetch has no credential at all. That claim has already flip-flopped through four
files once.

**Re-measure before trusting any row of that table.** abuse.ch changes its auth on
its own schedule. Probe with **status codes**, never by printing a key — and probe
the path profile with a key that is *not* one, so the probe itself does not put the
live key in a URL. The section head of `helena.enrichment`'s ThreatFox block
carries the same measurements with their dates, and
`concept/05-threat-intelligence.md` carries the history.

### The loader redacts anyway, and that is deliberate

`load_threatfox` and `load_public_suffix_list` both take a required `redactor` and
both put **two** stored columns through it — `source_url` and `failure_detail` —
even though neither endpoint wants a credential today. The reason is the first
paragraph: the rule is about the channel. If abuse.ch moves the bulk export behind
the v2 surface, the loader's provenance column is already safe and nothing has to
be remembered.

`Redactor.url` replaces **registered values** in a path, and deliberately does not
guess: a path segment that merely looks opaque is a file hash in this project, and
redacting one would destroy the provenance the fetch exists to record. The
consequence is stated rather than hidden — *an unregistered credential in a path
is not redacted* — and what closes it is that credentials enter only through
`helena.config`, where every one of them is registered.

### If a key does get out

In this order, and the first step is not the repository:

1. **Rotate the key at the provider.** A key in a pasted link is disclosed from
   the moment it is pasted; everything else is cleanup.
2. Replace the value in `.env`. Nothing else holds it — `git ls-files` does not
   list `.env`, `secrets/` is ignored, and `tests/test_secrets.py` asserts both.
3. Then deal with the copy. `uv run pytest -q tests/test_secrets.py` is the scan:
   it reads every tracked file for every value the local `.env` holds, so a
   committed copy is a named failure. A commit that already happened needs a
   history rewrite, which is an operator decision and not a session's.
4. Do not put the old value in the commit message, the report or the ticket while
   you do it. `***redacted***` is what those say.

### What enforces each channel

No single module owns "no credential anywhere", and that is on purpose — each
channel is tested where it exists:

| Channel | Test |
| --- | --- |
| a log line, and an exception carrying a request URL | `tests/test_observability.py`, against the live key |
| the agent-visible tool surface | `tests/test_tools.py`, against the live key |
| the prompt bytes and the disclosure record | `tests/test_conformance.py`, MNH-15 |
| the loader's stored URL and failure detail, path form | `tests/test_secrets.py` |
| the wrapper, and the three places `reveal()` may be called | `tests/test_secrets.py` |
| source control, including fixtures | `tests/test_secrets.py` |
| a stored evidence row and an emitted message | `tests/test_secrets.py` |

One asymmetry in that table is worth knowing about as an operator: a fetch failure
used to be able to print a key into a terminal with nothing logged at all, because
`http.client.InvalidURL` is a subclass of neither `OSError` nor `ValueError` and so
escaped the loader's typed-failure wrapper. Both fetch functions now build their
own redacted message and raise it with the cause suppressed
(`helena.enrichment._FETCH_FAILURES` has the measurement). A traceback prints a
`__cause__` chain in full, so a redacted message over an unredacted cause is not
redacted.

---

## 15. Durability: what survives, what is backed up, and how long recovery takes

Findings and evidence exist in one place. `concept/08-open-questions.md` files
this under *cross-cutting and urgent* — *"durability and backup for the single
store, now that findings and evidence exist only there, which is a correctness
concern rather than an ops detail"* — and that is why there is a command for it
and a suite behind it (`helena.durability`, `tests/test_durability.py`).

### The durable record is two things

    retained captures on disk    +    the engine's durable tables

They recover two different things and neither substitutes for the other:

| Half | What it brings back | What it does not |
| --- | --- | --- |
| The retained captures | the input, and everything derived from it — normalized events, quarantine rows, the flatten and signal layers, because a view over a table backfills from the table (§8) | anything the pipeline *learned* |
| The engine's durable tables | the feed snapshot an assessment cited, the feed rows, the evidence, the assessments with their citation, gap, pattern, retrieval and disclosure rows | the input, if the capture is gone |

**The tables are not a cache of something re-derivable**, and that is measured
rather than argued: `test_a_replay_without_a_restore_does_not_bring_back_an_assessment`
replays a capture into an empty migrated schema and the analytical tables stay
empty. Re-asking the model is a different run, and re-fetching a feed is a
*different snapshot* — a later snapshot changes what an identical context would
say (`concept/08`), so the snapshot that an assessment cited only exists in the
store that holds it.

### What is excluded, and why it is an exclusion rather than a gap

| Not backed up | Because |
| --- | --- |
| **The broker** | consume-once, restart-volatile, a topic never re-readable (§3). There is nothing to copy, and retention is not a durability mechanism |
| **The output topic** | egress only — *nothing may be recoverable only from it* (`concept/03`). Every field of a message is a projection of a row that is in the backup, and `tests/test_sink.py` executes a recovery query per field group |
| Materialized views | derived. A restore applies the migrations and the engine rebuilds them from the tables |
| In-flight run state | *"an interrupted run is simply re-run"* (`concept/03`). There is no checkpoint to lose |

### The procedure

    uv run scripts/backup.py --out .backups                    # take one
    uv run scripts/backup.py --verify .backups/<file>           # is it whole?
    uv run scripts/backup.py --restore .backups/<file>          # put it back

    uv run scripts/dev_check.py --captures <dir>                # the other half

`.backups/` is not committed and nothing in the package reads it. A backup is
JSON lines — a header, one line per row, a trailer — and the three things it
refuses are worth knowing before you need them:

| Refusal | What it means |
| --- | --- |
| `BackupIncomplete` | the trailer is missing, its digest does not verify, or the row counts in the header, the trailer and the file disagree. This is what a truncated write looks like, and it is refused before any row is restored |
| `BackupMoved` | a relation held a different number of rows when it was read than when it was counted. RisingWave has no multi-statement read transaction, so **a backup taken under live ingestion is not a point-in-time snapshot.** Quiesce and retake it |
| `RestoreRefused` | the target's migration ledger, relation set or column types are not the backup's, or a target relation already holds rows. Every table has a primary key, so restoring onto rows would upsert and leave a store that is neither the backup nor what was there |

### Rehearsing a restore

There is one engine per machine (§2), so the throwaway instance is a **schema**:

    uv run psql -c "CREATE SCHEMA helena_restore_test"          # or any client
    # apply the migrations to it, then:
    uv run scripts/backup.py --restore .backups/<file> --schema helena_restore_test

Drop it again afterwards with `DROP SCHEMA ... CASCADE`, and drop it *promptly*:
an abandoned migrated schema keeps ~190 actors alive and the ceiling is ~1 600
(§5). Use **one connection per schema.** Measured 2026-09-12: a single session
that did `SET search_path` from one migrated schema to a second one had
`information_schema.tables` report the second schema's migration ledger as
existing and then fail to select from it — so the runner saw a ledger that was
not there.

### Recovery time

Measured 2026-09-12 against the pinned engine on this machine, warm:

| Step | 65-row fixture state | 3 375-claim ThreatFox snapshot |
| --- | --- | --- |
| `make migrate` into a fresh schema | 23.3 s | 24.4 s |
| backup | 0.22 s | 0.34 s (2 364 121 bytes) |
| restore | 0.39 s | 2.26 s |
| **recovery total** | **~24 s** | **~27 s** |

**The migration dominates**, and it will keep dominating: applying the schema
starts a streaming job per materialized view and the row count barely moves it.
A capture replay after the restore is the §8 command and costs what it costs
there — the ten-record fixture goes in under a second.

### Residual risk

Recorded rather than resolved, in the order they are likely to bite:

1. **A backup is not a point-in-time snapshot.** There is no read transaction to
   take one under. `BackupMoved` detects the case where a relation changed while
   it was being read; it cannot detect two relations that were each self-
   consistent at different instants. **Quiesce ingestion before a backup you
   intend to restore from.**
2. **A restore reads the whole file into memory before it writes a row.** That is
   deliberate — there is no transaction to roll a half-applied restore back, so
   the only guarantee available is to refuse the file first. The measured cost is
   ~700 bytes of JSON per row (2.36 MB for 3 376 rows), so a million-row store
   wants roughly a gigabyte to restore. Splitting a restore per relation is the
   change to make when that bites, and it costs the all-or-nothing property.
3. **Clock-derived state is derived again, not restored.** The retention horizon,
   the snapshot-currency window and the completeness flag reach `now()`. A
   restore performed *after* a context has left the 24-hour retention horizon
   does not bring the retained views back, because the horizon is re-evaluated as
   the rows arrive. The tables are exact either way — no durable table reads the
   clock, which `tests/test_durability.py` asserts — but
   `helena_signal_host_context_retained` and its readers are not. **Not measured:
   it needs a day to pass between backup and restore.**
4. **A restore into a different engine process is untested.** One engine per
   machine (§2) means every restore this suite has performed went into another
   schema of the same process. The format is logical rather than a copy of
   `.rwdata/`, which is the form that *should* cross a process and a version, and
   the engine version is recorded in every backup's header so that a restore
   elsewhere is a known fact rather than a guess. It is still untested.
5. **Nothing schedules a backup.** There is no timer, no retention policy for the
   backup files and no off-machine copy. A backup that exists only beside the
   store it came from survives the engine and not the disk.
6. **The capture store's identity is provisional under live ingestion.** A
   capture is addressed by the hash of its file, and a file still being written
   has no final digest (`helena.normalizer`, `concept/08`). The startup check
   verifies what is closed; it cannot verify what is open.

### The startup check

    uv run scripts/dev_check.py --captures tests/fixtures/captures
    ok: tests/fixtures/captures: 2 capture(s), 11 record(s), 11,103 bytes, every
        file verified against its own sha256

Three outcomes and they stay three, because the operator does something
different about each:

| Outcome | Means |
| --- | --- |
| `<dir>: N capture(s), …` with N ≥ 1 | reachable, and every file hashes to its own name |
| `<dir>: 0 capture(s), …` | reachable and holding nothing. A real state for a deployment that has retained nothing yet |
| `FAILED: … does not exist` / `is not a directory` | **unreachable.** Until task 53 this returned "no captures" — a glob over a missing directory returns nothing — so a mistyped directory read as a deployment that had lost every record it ever ingested (§13.1). `helena.normalizer.CaptureStoreUnreachable` is now a different failure from a corrupt file |
| `FAILED: … is not the capture its name claims` | a capture changed under its name. A capture's sha256 is half of every event id and every raw-record reference in the store, so every citation pointing into it now points at different records |
