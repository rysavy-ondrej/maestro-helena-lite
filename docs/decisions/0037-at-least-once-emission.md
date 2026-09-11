# 0037 — At-least-once emission, and the count that outlives the broker

**Status: accepted.** Task 47 (D7 Emit).
**Authority:** `concept/03-architecture.md` ("The interfaces", the Sink
component, "What stays external"), `concept/instruction.md` §2 (the output topic
is egress; the broker is addressed only through the Kafka wire protocol; a failed
run is emitted), `concept/07-principles.md` (any terminal outcome is emitted,
including typed failures), `concept/08-open-questions.md` (output volume), and
`docs/decisions/0014`, `0033`, `0036`.

This increment adds `helena.sink.emit` and `helena.sink.EmissionCounts`,
`sql/migrations/0020_emission_counts.sql`
(`helena_analytical_emission_counts`, one plain view), `HELENA_OUTPUT_TOPIC` in
`helena.config`, `scripts/emit.py`, eleven tests in `tests/test_sink.py` — eight
of them against the pinned broker as well as the pinned engine — and two in
`tests/test_config.py`. It adds **no runtime dependency, no second store,
no table, no contract field and no egress channel** — the output topic is the
channel `concept/03` already specifies, and this is the first thing to use it.

---

## 1. Emission is a loop in project code, not a `CREATE SINK`

ADR-0036 §2 measured why, and nothing here revisits it: the sink view descends
from `helena_analytical_enriched_context`, which derives `status` from `now()`,
and RisingWave 3.0.3 refuses `now()` outside a `WHERE` clause in a streaming
query — so `CREATE MATERIALIZED VIEW … FROM helena_analytical_sink` cannot be
bound and neither can a sink over it.

What that costs is stated rather than hidden: **emission is a drain, not a
stream.** `emit` reads the terminal runs the store holds, produces them, and
returns. There is no continuous job and no cursor, so a deployment emits by
running the drain — which at prototype scale re-emits the whole store each time
(§4).

What it buys is that `concept/instruction.md` §2's *"the broker is addressed only
through the Kafka wire protocol, on both ends"* stays true with **one** Kafka
client in the repository. `helena.sink` builds bytes and hands them to
`helena.broker`; a `CREATE SINK` would have made the engine a second producer,
configured in SQL, with its own connector and its own failure modes.

## 2. The deduplication contract

`concept/03`: *"Delivery is at-least-once, so consumers deduplicate;
exactly-once is not attempted."* This is what a consumer implements against.

**The key is `assessment_id`**, carried both as a payload field and as the
`helena-assessment-id` header, so a consumer can discard a repeat without parsing
the value.

It is a digest over `(tenant, sensor, context_id, context_version, emitter,
trigger)` (`sql/migrations/0018`). Four properties follow, and all four are what
make deduplicating on it correct rather than lossy:

| Property | Consequence for a consumer |
| --- | --- |
| No outcome and no timestamp in the digest | Two emissions of one terminal run carry one key. The bytes are identical too, asserted in `tests/test_sink.py` |
| `context_version` is in the digest | A window that gained a late record is a **different** context and a different key. Deduplicating does not hide a re-assessment |
| `emitter` is in the digest | It is not a context id. An escalated context emits once, under the analyst's key, and the triage decision rides inside the payload |
| It is not a message id | There is deliberately no sequence number, emission timestamp or delivery id. One would satisfy "at-least-once" and leave a consumer two messages it cannot tell are one |

**The obligations that go with it:**

- **Deduplicate on `assessment_id`, keeping either copy.** They are the same
  bytes.
- **Do not treat a repeat as a new event.** A re-drain is not a re-assessment.
- **Do not infer ordering from arrival.** The topic has one partition and the
  drain emits oldest-first by `assessed_at`, but that is a property of this
  emitter, not a guarantee of the contract. `assessed_at` is in the payload.
- **Expect `normal` and expect typed failures.** A consumer that filters to
  "interesting" verdicts at the edge is re-implementing triage, and a typed
  failure carries `outcome_kind = "typed_failure"` with a null `verdict` rather
  than a verdict of its own (`concept/instruction.md` §2).
- **Check `message_version` before parsing.** `v1` today; §7 of ADR-0036 has the
  rule for changing it.

**What the pipeline does not do:** no delivery receipt, no consumer offset, no
retry of a message the broker accepted. A message the broker *refused* raises
`BrokerError` and takes the run down with it, because the broker keeps nothing
and a producer that carried on would lose it with nothing counting it.

## 3. The count is of what there is to emit, and nothing records what was emitted

`concept/03`: *"Emission must be observable from the engine side — a count of
rows the sink view produced — because the broker discards its queue on restart,
so a message emitted with no consumer attached is simply gone and nothing counts
it. Otherwise 'nothing arrived' cannot be told apart from 'nothing was
assessed'."*

`helena_analytical_emission_counts` is that count: `count(DISTINCT
assessment_id)` over `helena_analytical_sink`, grouped by tenant and sensor. It
is in the engine rather than only in `SinkStore.pending` so that an operator who
is not running the emitter can ask it with plain SQL — which is the whole point,
because the situation it answers is one where the broker has already lost the
evidence.

It counts at **message** grain and not at the view's own. The view is one row per
(terminal run × entity × source): measured over the layers capture, one assessed
context is **41 rows and one message**, and that multiplies by the number of
sources a deployment has loaded. Counting rows would make "one message arrived"
and "nothing arrived" equally consistent with a shortfall of 40, which is the
confusion the count exists to remove.

**Deliberately not built: a ledger of what was emitted.** It was considered and
rejected, for three reasons rather than one:

1. **It would make the sink write.** `concept/03` puts the output topic under
   egress and `concept/instruction.md` §2 says nothing may be recoverable only
   from it; a sink that wrote emission rows back into the store would be the
   first component that both reads the store to emit and writes to it because it
   emitted.
2. **Its only use is suppressing a duplicate the contract says the consumer
   removes.** Delivery is at-least-once by decision, not by accident.
3. **It is the first step toward exactly-once**, which `concept/03` says is not
   attempted. A ledger makes "emit only what is not in the ledger" look like one
   small change away, and that change is wrong: the row would be written after
   the produce, so a crash between them loses the message permanently — trading a
   duplicate the consumer handles for a loss nothing detects.

What replaces it is `EmissionCounts`, two numbers from the two sides of the wire:
`pending` from the engine and `emitted` from what the broker acknowledged. The
list is read before the count so that a pass landing mid-drain raises `pending`
(reported through `complete`) rather than `emitted` (refused as a
double-emission). `emitted > pending` is a `SinkError`, because it is the one
duplicate the at-least-once contract does **not** cover: two copies inside a
single run, which a consumer deduplicating across runs is not looking for.

## 4. The output-volume hazard, recorded rather than solved

`concept/08-open-questions.md` already lists it: *"Emitting `normal` verdicts
means the topic carries the full context volume. Intended at prototype scale; it
would need revisiting at real rates."* This increment is what makes it real, so
here is the arithmetic rather than the adjective.

The topic carries **one message per assessed context per drain**, and every
assessed context is emitted — `normal` included, by
`concept/07-principles.md`'s table. So the message rate is the *context* rate,
not the alert rate, and the two differ by whatever fraction of traffic is
interesting.

**Measured, on 2026-09-11**, rather than described: one message over the
ten-record layers capture — one host, one five-minute window, 41 entities, one
enrichment source — serializes to **36 994 bytes**. That is the smallest
realistic context this repository holds, and it is already 36 KB, because the
payload nests one object per (entity × source) and the version set, the retrieval
trace and the disclosure ledger ride on every message whatever the verdict. A
deployment watching a real network multiplies that by every host in every
five-minute window, and a host that talks to a thousand names produces a message
in the megabytes.

**Two amplifiers on top, both properties of this design:**

- **The drain has no cursor.** `emit` re-emits every terminal outcome the store
  holds, so running it twice puts everything on the topic twice. At prototype
  scale — one operator, one drain per run — that is the at-least-once contract
  doing its job. At real rates it is quadratic in a way nothing bounds.
- **The broker is memory-first and single-node** (`concept/03`). Volume that a
  consumer does not keep up with is not backpressure; it is a broker holding the
  backlog in memory.

**What is deliberately not built:** no filter, no sampling, no compaction, no
retention policy and no cursor. Every one of them is a decision about what the
pipeline may stop saying, and a filter at the edge that dropped `normal` would
re-implement triage in the transport — the failure `concept/07`'s table names as
*a budget-truncated run returning `normal`*, arriving by a different route. The
honest prototype-scale answer is to emit everything and record the bound here;
revisiting it needs a measured message rate against a real capture, which is
`concept/08`'s open question and not this task's.

## 5. `HELENA_OUTPUT_TOPIC`, and why it may not be the ingest topic

The topic is configuration and there is no default, for the reason nothing in
`helena.config` has one. The name is a separate variable from
`HELENA_INGEST_TOPIC` because they are separate decisions, and `Infrastructure`
**refuses a configuration where they are equal**.

That is not tidiness. A deployment emitting onto its own input would consume each
message back as a flow record, fail to parse it, and quarantine it with a typed
reason — and every counter in the pipeline would reconcile. The symptom an
operator would see is a sensor sending malformed traffic, which is a real thing
that happens, so the diagnosis would go to the wrong place entirely. It is one
comparison at startup and it names both variables.

## 6. What this does not claim

- **No consumer outside this repository has read one of these messages.** The
  interface is exercised by `tests/test_sink.py` against the pinned broker and by
  nothing else, and `helena.sink`'s maturity label is `experimental` for that
  reason.
- **"Replacing the broker is a configuration change" is still a property of the
  code's shape**, not a demonstration. Egress has now been run against blink
  0.2.0 and against no other broker, exactly as ingress has.
- **At-least-once is what is implemented; no lower bound on loss is claimed.**
  `flush` raises for a message the broker refused, so a run that returns has had
  every message acknowledged — but a message acknowledged by a memory-first
  single-node broker with no consumer attached is still a message that is gone,
  which is the whole reason the count is on the engine side.
- **`emit` is the only producer to this topic and it is a drain.** Nothing runs
  it on a schedule and nothing in this project consumes it.
