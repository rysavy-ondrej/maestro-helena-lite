# 0013 — Quarantined records live in the single store

**Status: accepted.** Task 9 (D1 Ingest). **This closes an open question.**
**Authority:** `concept/08-open-questions.md` (*cross-cutting and urgent* —
"where quarantined records live, given they currently land outside the store the
project says holds everything"), `concept/03-architecture.md` (the Normalizer
*quarantines invalid input without stalling the stream*),
`concept/instruction.md` §2 (**one store**; *unknown fields are quarantined, not
coerced*; `stale`/`failed`/`missing`/`no_match`/typed error are never collapsed)
and §6 (*quarantine with a typed reason and the raw input exactly as read, and
keep the stream running*).

## The question, and the answer

`concept/08-open-questions.md` lists three cross-cutting and urgent unknowns.
This decision settles the third of them: **quarantined records live in the
streaming engine, as typed rows, like everything else durable.**

`sql/migrations/0003_ingest_quarantine.sql` creates `helena_ingest_quarantine`
and the plain view `helena_ingest_quarantine_counts` over it.
`helena.normalizer.Quarantine` writes and reads them, and
`Normalizer.ingest_capture` is the ingestion path that routes refusals there and
carries on.

There was never a real alternative that survived the invariant. A quarantine
file, a dead-letter topic and a side table in a second database are each a
second store, and `concept/instruction.md` §2 allows none of them — *no second
database, no vector store, no checkpoint store, no file-backed agent memory, no
cache that is not itself the evidence store*. A dead-letter topic fails a second
rule as well: **the output topic is egress, not storage**, and the broker is
consume-once and restart-volatile, so a refused record that existed only there
would be gone after a restart. What made the question worth asking is that a
quarantined record *looks* like a log line, and a log line is exactly the thing
this project does not treat as evidence.

And it is evidence. A quarantine row is the only record of the one thing the
project most needs to learn about its input: which of the fields it marked
required are not required in the wild.
`docs/decisions/0010-capture-identity.md` says field requiredness was measured
from one capture, one host, 130.8 seconds, and that a producer omitting a field
this contract requires will be **quarantined rather than accepted**. The
quarantine rate is how that surfaces, and the raw payload is how it is
diagnosed. That is durable evidence, not an operational aside.

## What a row holds, and what it deliberately does not

The columns are the ingestion identity (`tenant`, `sensor`), the raw-record
reference (`capture_sha256`, `record_offset`), the contract version in force
(`schema_version`), the typed failure (`input_format`, `reason`, `detail`) and
the bytes (`payload`).

**The primary key is `(tenant, sensor, capture_sha256, record_offset)`.** The
raw-record reference alone would not do, for the reason ADR-0011 gives for
putting tenant and sensor in the event id: a RisingWave INSERT onto an existing
primary key is an upsert that overwrites the row and raises nothing, so two
deployments ingesting the same file into one store would silently overwrite each
other's quarantine rows. The upsert is otherwise a feature — a capture replayed
twice rewrites the same row rather than doubling the count.

**The payload is `BYTEA`, and nothing truncates it.** A refused line is not
necessarily valid UTF-8 — `b'{"id":"\xff"}'` is one of the real
`malformed_json` cases — so a text column would have to refuse the row or decode
it lossily, and a quarantine row that lost the bytes that caused it cannot be
diagnosed. Measured against RisingWave 3.0.3: `BYTEA` round-trips those bytes
unchanged. `concept/instruction.md` §2 requires truncation to be visible; there
is no truncation marker here because there is no truncation.

**There is no event id.** The digest over tenant, sensor, capture and offset
would compute for a refused record, and writing it would assert an event
identity for something that never became an event. `Normalizer.normalize` stamps
no identity on a record that never became an observation, and this is the same
rule on the storage side. The primary key is what addresses the row.

**There is no timestamp**, for the reason ADR-0011 keeps an ingestion timestamp
off the normalized event: a wall clock makes a capture replayed twice produce a
different row from the run it replays, and under the upsert above the stored
value would silently mean "the last time this was refused" rather than "when it
was first seen". When a record arrived is a property of an ingest run, and
nothing records runs yet. The increment that does owns adding it.

**There is no version set.** `helena.versions.VersionSet` requires all eight
dimensions and seven of them do not exist yet (ADR-0008); stamping one here
would mean inventing seven constants for a row no assessment cites. What
determined this row is recorded instead: the contract version that refused it
and the input format that read it. ADR-0012 deferred "an adapter version on
`ParseFailure`" to this increment — the adapter still has no version of its own,
and `input_format` is what a row records about which parser refused it. When
adapters acquire versions, this table is where one belongs.

## The counter

`helena_ingest_quarantine_counts` is a **plain view**, not materialized: an
aggregate over a table holding only refused records, with nothing streaming or
joining from it. It groups by `tenant`, `sensor`, `capture_sha256`,
`input_format` and `reason`.

**The reason is in the GROUP BY rather than summed away.** The three reasons —
`malformed_json`, `not_this_format`, `contract_violation` — mean different
things to whoever reads the number, and `concept/instruction.md` §2 forbids
collapsing them at any layer. A single total would merge "this deployment is
reading the wrong thing" into "the producer changed".
`QuarantineCounts.by_reason` always carries all three keys, zero included, so a
reason that did not occur is a zero rather than a missing key that reads as an
unknown.

**The denominator is not in the engine, and cannot be.** The broker is
consume-once and restart-volatile, so "how many records were there" is a fact
about the retained capture file (`Capture.record_count`).
`Quarantine.counts(capture)` brings the two sides together and **refuses a count
that does not reconcile** — a per-reason total that does not add up, or more
quarantined records than the capture holds, is a validation error rather than a
plausible-looking number.

`QuarantineCounts.normalized` is `records - quarantined`. It is exact, because
`normalize_capture` yields exactly one result per record in file order and every
result is either an event or a quarantine row — but it is a **subtraction, not a
count**, because no table holds a normalized event yet. The increment that
stores events makes it an engine-side count that reconciles against this
subtraction instead of replacing it, and that is where the PRD's "ingest
counters (records consumed, normalized, quarantined)" belong. A rate over a
capture with no records raises rather than reporting `0.0`, which would read as
"nothing was refused".

## What this does not claim

Nothing has been ingested from the broker. The path exercised is
`Normalizer.ingest_capture` over a capture on disk, into a real engine, and the
"without stalling the stream" claim is demonstrated at that scale: a malformed
record in the middle of a capture is stored and the records around it still
normalize. Whether a refused record stalls a *live* consumer is a claim the
increment that wires the broker gets to make.

Writes do not `FLUSH`. A RisingWave row is not readable until a flush, so
flushing per refused record would be correct and would also put a synchronous
round trip in the middle of the stream — the stall this increment exists to
avoid. `Quarantine.stored` and `Quarantine.counts` flush before reading
instead. The consequence is stated rather than hidden: a count taken through
another connection while ingestion is still running may lag.
