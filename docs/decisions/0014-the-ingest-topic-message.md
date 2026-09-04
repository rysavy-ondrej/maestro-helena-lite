# 0014 — The ingest topic message: the record in the value, its reference in the headers

**Status: accepted.** Task 10 (D1 Ingest).
**Authority:** `concept/03-architecture.md` (the interface table — *ingest
topic(s), in: one flow record per message, over the Kafka wire protocol*; *the
broker is addressed only through the Kafka wire protocol ... that rule holds on
both ends*; the broker is **not a store**), `concept/02-concepts-and-taxonomy.md`
(a flow record *carries no tenant, sensor, schema version or raw-record
reference*), `concept/instruction.md` §2 (one store; the output topic is egress,
not storage) and §6 (*a defaulted tenant*; *catching an exception and
continuing*).

## The problem

Two requirements meet at the ingest topic and neither can be given up.

1. **One flow record per message.** The value on the wire is the producer's
   record, and the flow-record contract has nothing in it that the producer does
   not send. An envelope around the record would be a change to the input format
   for every producer, which is exactly what
   `docs/decisions/0012-input-format-adapters.md` says a second format must not
   require.
2. **Every event records where its raw record is.** `RawRecordReference` — the
   capture's sha256 and the record's zero-based offset in it — is a required
   field of every `NormalizedEvent`, is the primary key of both ingest tables,
   and is what the event id is derived from
   (`docs/decisions/0011-event-identity-and-the-event-id.md`). It is what makes
   a stored row point back at the bytes it came from, and
   `concept/07-principles.md` keeps the retained captures as the durable record
   precisely so that pointer means something.

The record does not carry the reference, by contract. So the reference has to
travel some other way.

## The decision

**The message value is the raw record, byte for byte. The raw-record reference
travels in two Kafka message headers.**

```
value                        the line exactly as the producer wrote it
helena-capture-sha256        the retained capture's digest, UTF-8
helena-record-offset         the record's zero-based offset in it, decimal UTF-8
```

`helena.normalizer.IngestMessage` is both ends of that contract — `headers()`
writes them and `from_headers()` reads them — so a header name or an encoding
cannot be spelled two ways. `helena.broker` carries bytes and header bytes and
knows nothing about what they mean, which is what keeps "replacing the broker is
a configuration change" a property of the code's shape rather than a hope.

Headers are Kafka, not a broker extension: measured against the pinned blink
0.2.0, a message published with headers comes back with the same headers,
byte-identical.

### What this buys

The adapter parses off the wire precisely what it parses off a file, so a
quarantine row holds the bytes the producer actually sent, and
`Normalizer.normalize` (from a capture) and `Normalizer.normalize_message` (from
the topic) end in the same `_stamp` — one stamping path, which is what
`concept/03-architecture.md` means by replay going through the same ingestion
path as live traffic. A capture published to the topic and consumed back
produces rows identical to the same capture read from disk;
`tests/test_normalizer.py` asserts exactly that.

## A message that carries no reference is refused, not quarantined

`IngestMessageError` is raised and the run stops. That is the opposite of what a
refused *record* does, and the difference is structural rather than a policy
choice: **a quarantine row is keyed by the capture and the offset**
(`sql/migrations/0003_ingest_quarantine.sql`), so a message that carries neither
has no row it could be written to. There is nothing to file it against and
nothing to count it in.

It is also a different kind of fault. A record the contract refuses is *producer
drift*, the thing the quarantine rate exists to measure. A message with no
reference is a producer publishing something else to this topic, or publishing to
the wrong one — a configuration fault, not data. Collapsing the two would file a
misconfiguration as this producer's drift, and
`concept/instruction.md` §2 forbids collapsing distinct failures.

**This leaves an open question, and it is not answered here.** If a deployment
ever needed to *keep* wire-level refusals rather than fail on them, they would
need somewhere to live, and that somewhere cannot be the quarantine table as it
is keyed today. Inventing a second table (or worse, a dead-letter topic — the
broker is not a store) to hold a case the prototype has never seen would be
structure ahead of the increment. The failure is loud, it names the header, and
it stops rather than losing anything silently; that is the smallest honest
answer until a real producer produces one.

## What a live producer would have to do

Nothing in this prototype ingests anything but a closed capture file, and this
decision inherits the limitation `docs/decisions/0010-capture-identity.md`
already records: **a hash identifies a capture only once the file closes**, so a
producer streaming from a file still being written has no final digest to put in
the header. Replay — publishing a retained capture, which is the next increment
— is fully served. Live ingestion from an open file is not, and the answer is
not a defaulted or provisional digest: it is a decision about what identifies a
record in flight, and it is still open.

## The counters this makes possible

`sql/migrations/0004_normalized_events.sql` adds `helena_normalized_events` and
the plain view `helena_ingest_counts` over it, so *normalized* becomes an
engine-side count rather than the subtraction `QuarantineCounts.normalized` has
been making. `helena.normalizer.IngestCounts` holds the four numbers and refuses
a set that does not reconcile:

| Number | Comes from | Why not from anywhere else |
| --- | --- | --- |
| `records` | the retained capture file | the broker is consume-once; the topic cannot say how many there were |
| `consumed` | the run | nothing else counts what came off the topic |
| `normalized` | `helena_ingest_counts` | the store is what actually holds the rows |
| `quarantined` | `helena_ingest_quarantine_counts` | ditto, and it keeps the three reasons apart |

`normalized + quarantined` must equal `consumed`, and `consumed` may not exceed
`records`. `consumed < records` is reported as `complete is False` rather than
raised: a partial run is a fact about the run, the missing records are gone
because the broker keeps nothing, and the capture is still on disk to replay.

## The measurement behind "the broker is not a store"

Measured against blink 0.2.0 on 2026-09-03, and it corrects the timing the
concept note implies:

- Three records produced and drained once: the drain returns all three.
- A **second drain immediately afterwards can still return all three.** The
  reclaim is a background step, not part of the read.
- Within a few seconds the topic is empty and its watermarks are back to
  `(0, 0)`.
- A topic produced to and **never read** still holds its records after 30
  seconds, so this is consume-once and not a short retention window.

The substance of `concept/03-architecture.md` holds — a record read once is gone
— but "never re-readable" is not instantaneous, and a retry written against the
note alone would occasionally double-ingest. `tests/test_broker.py` asserts both
halves, including the never-read control. Nothing in the pipeline retries by
re-reading a topic: replay reads the retained capture.

## Configuration

`HELENA_INGEST_TOPIC` joins `KAFKA_BOOTSTRAP_SERVERS` in `helena.config`, with no
default, for the reason nothing there has one: a deployment pointed at a
misspelled topic waits forever on a topic nobody produces to, which is
indistinguishable from a producer that stopped.

**There is no output-topic variable yet.** The egress rule is enforced —
`tests/test_broker.py` asserts that `helena.broker` is the only module in the
package that imports a Kafka client, which covers the sink as much as the
normalizer — but a configuration key nothing reads is a key with one value and
no way to be wrong. It enters with the sink that writes to it.

## Consequences

- The ingest topic's contract is now two header names, and changing either is a
  change every producer sees. They live in one place, `helena.normalizer`.
- `Quarantine.record` takes a `RawRecordReference` rather than a capture and an
  offset, because a consumer holds a reference and has no capture file.
- A wire-level refusal is fatal to a run. If that turns out to be wrong in
  practice, the fix is a decision about where such a record lives, not a
  `try/except` around the loop.
