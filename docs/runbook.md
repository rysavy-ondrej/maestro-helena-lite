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

**A rising `contract_violation` rate is the number to watch.** Field requiredness
in this contract was measured from one capture of one host over 130.8 seconds
(`docs/decisions/0010-capture-identity.md`), so a producer that omits a field
marked required here is quarantined rather than accepted. The answer to a high
rate is a **new observation of the input** — `detail` names the field and
`payload` is the record — not a field loosened on a hunch. Loosening one is a
contract change and gets its own increment.

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
| A view exists but is empty and the data is old | the records never reached the store, or they are not this capture's. §8 |
| `FAILED: ... a capture file is named <sha256>.jsonl` | `--captures` is not a capture directory. §8 |
| `FAILED: ... holds no capture <sha256>` | that digest is not in that directory — the file was renamed, or its bytes changed |
| `FAILED: ... consumed more than once` | the capture was published to the topic twice and drained once. §8 |
| `INCOMPLETE: N record(s) never came off the topic` | records were lost between the producer and the store. §7, then replay again |
| `helena_ingest_quarantine` is filling up | the producer drifted, or the wrong `HELENA_INPUT_FORMAT` is set. §6 — the `reason` column tells you which |
| `list_not_loaded` on every domain row | the Public Suffix List was never loaded. §9 |
| `load_public_suffix_list.py` prints `failed: ... fetch_failed` | no route to the publisher, or a proxy. The previous snapshot is still in place; §9 |
