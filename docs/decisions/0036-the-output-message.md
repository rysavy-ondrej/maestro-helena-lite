# 0036 — The sink view and the emitted message

**Status: accepted.** Task 46 (D7 Emit).
**Authority:** `concept/03-architecture.md` (the Sink component, "The
interfaces", "The store", "Trust and egress boundaries"),
`concept/instruction.md` §2 (the output topic is egress; `stale` / `failed` /
`missing` / `no_match` never collapsed; view layering), `concept/07-principles.md`
(versions on a citable row, disclosure), and `docs/decisions/0016`, `0033`,
`0034`, `0035`.

This increment adds `sql/migrations/0019_sink.sql`
(`helena_analytical_sink`, one plain view), the message shape and the read in
`src/helena/sink.py`, `tests/test_sink.py`, and
`tests/fixtures/sink/message-v1.json`. It changes one line of
`helena.migrations.MAY_READ` (§3). It adds **no runtime dependency, no second
store, no egress channel, no table and no contract field.**

It does **not** emit anything. Producing to the output topic, counting what was
delivered and the deduplication contract are task 47.

---

## 1. The grain, and why the message is assembled in Python

`concept/03` asks for two things that are not the same shape:

- *"A sink over a view joining the enriched context, the terminal verdict and the
  cited evidence"* — a join whose natural grain is one row per entity per source;
- *"One JSON message per assessed context"* — one object per terminal run, with
  the entity rows nested inside it.

`helena_analytical_sink` is the first. `helena.sink.SinkStore.project` groups it
into the second and reads the four child tables of `sql/migrations/0018` for the
lists that do not fan out per entity — gaps, patterns, the retrieval trace and
the disclosure ledger. That is the shape `helena.rendering.RenderingStore` already
has, for the reason it gives: a single join of all of it would fan the
per-assessment lists across every entity row, so one gap would arrive once per
source.

An alternative was to aggregate the whole message in SQL — `jsonb_agg` /
`array_agg(row(...))`, both of which the pinned engine supports in a batch query —
and emit the view's rows directly. It was rejected because it would put the
message's field names in SQL *and* the shape in Python, which is two copies of an
interface that can disagree, and the one that goes stale is the one nothing
validates. Pydantic is where the shape is checked.

## 2. Measured: the sink cannot be a `CREATE SINK`

Measured on RisingWave 3.0.3, 2026-09-11, against a migrated schema:

```
CREATE MATERIALIZED VIEW probe AS
SELECT context_id, status FROM helena_analytical_enriched_context;
-- InternalError: Failed to run the query
--   Caused by: Bind error: failed to bind view helena_analytical_enriched_context
```

The enriched context derives `status` from `now()`, and a streaming query rejects
`now()` outside a `WHERE` clause — the same thing `sql/migrations/0009` measured
for `completeness`. Anything downstream of the enriched context is therefore a
**batch** read, and so is the sink view.

Two consequences, both for task 47:

- emission is deterministic project code reading this view and producing over the
  Kafka wire protocol through `helena.broker`, not a RisingWave Kafka sink;
- the engine-side count `concept/03` requires (*"a count of rows the sink view
  produced"*) is a batch `SELECT`, which is `SinkStore.pending`.

What would reverse it: a status column that is a property of the row rather than
of `now()`. `sql/migrations/0017`'s head already argues the other way for the
lookup cache — *"a stored `stale` would be wrong the moment time passed"* — so
this is not a small change and it is not an optimisation; it is a different
answer to when freshness is decided.

## 3. `analytical` may now read `analytical`

`helena.migrations.MAY_READ["analytical"]` was `{signal, reference}` and is now
`{analytical, signal, reference}`.

The invariant is unchanged. `concept/instruction.md` §2 states it as *"View
layering holds: flatten → signal → analytical. An analytical view never reads the
flatten layer or the source directly"*, and `concept/03` the same way. Neither
says anything about a layer reading itself, and `signal` and `reference` have
both been able to since `MAY_READ` existed — `helena_signal_context_entities`
reads `helena_signal_host_context`, `helena_reference_evidence_analyst` reads
`helena_reference_analyst_evidence`. The `analytical` row was narrower because
until `sql/migrations/0018` the layer held one object.

There is nowhere else the join could read from. The assessment rows are
`analytical` (0018 put them there deliberately, because only `analytical` may read
`signal` **and** `reference`, which is what a verdict-and-evidence join needs),
and so is the enriched context. A sink view in any other layer would be a view
that reads upward.

`tests/test_view_layering.py` still executes the case the invariant is about — an
analytical view reaching the flatten layer or the source is still a violation, and
still named as one.

## 4. The four absences, and the fifth

`concept/instruction.md` §2: *"`stale`, `failed`, `missing` and `no_match` are
four different things, and a typed error is a fifth. Never collapse them, at any
layer, for any reason."* The output topic is a layer.

They reach the message as **two independent fields** of `EmittedEvidence`, copied
from the enriched context without merging:

| `status` | `classification` | what happened |
| --- | --- | --- |
| `ok` | a path | the source answered and made a claim |
| `ok` | `no_match` | the source answered and said nothing about this entity |
| `stale` | a path or `no_match` | the same, from a snapshot past its refresh window |
| `failed` | `null` | the load did not complete; there is no claim to have |
| `missing` | `null` | no snapshot exists to consult at this window |

`status` is never `null`: the enriched context's `CASE` is total, and the message
model makes it a required field so that a NULL would be a loud refusal rather
than a sixth meaning nobody declared.

The sixth case is **an entity whose `evidence` tuple is empty** — no source has
ever been asked at all — and it is this view's own, because the enriched context
cannot express it: that view `CROSS JOIN`s the snapshot ledger, so on a
deployment where no feed has loaded it yields no rows whatever. The sink's `LEFT
JOIN` turns that into entity rows with no evidence rather than into a context
with no entities, which matters because *"the host contacted nothing"* is the
single most misleading thing this message could say by accident. `missing` is a
source that was asked for and had nothing to look in at that window; an empty
tuple is nobody to ask.

`context_resolved` is the same kind of distinction one level up: `false` means the
store no longer holds the exact context version that was assessed — the window
gained a late record and `context_version` moved — so the entity list is empty
because of the store rather than because of the traffic. Each of the six rows and
both values of `context_resolved` has a test that executes it.

## 5. Redaction is inherited, and the payload says so

`concept/03`, "Trust and egress boundaries", 2.:

> *"The sink writes to the **local** broker, so no redaction is performed — but
> that is a property of the deployment, not of the message: the payload contains
> internal addresses, hostnames and retrieved external text, and **any consumer
> that forwards it off-site inherits the redaction, minimization and disclosure
> obligations**. The pipeline cannot enforce that."*

What is in the payload, named rather than left to be discovered:

| Field | What it is |
| --- | --- |
| `host` | an internal address, the monitored host |
| `entities[].entity_value` | addresses contacted, names resolved, URLs and certificate fingerprints |
| `entities[].evidence[].native_evidence` | the publisher's own record, verbatim — retrieved external text |
| `disclosures[].query` | which indicators this network told an external provider about, and which model endpoint it prompted |

The fourth is not in `concept/03`'s list and is added here: a disclosure ledger is
itself disclosive, because it says what this network was interested in.

**No redaction is performed and none is planned in the sink.** Redacting here
would make the local consumer's copy differ from the stored rows, which would
break the property §6 is about for no gain against a local broker; the redaction
gate `concept/03` describes belongs to the deferred cloud Investigation Agent,
which has nothing to gate yet. What the sink does instead is carry the obligation
with the bytes: `MESSAGE_CAVEAT` is a field on every message
(`OutputMessage.caveat`), so a consumer that never reads this file still receives
the statement. The pipeline still cannot enforce it, and the message does not
pretend otherwise.

## 6. Nothing is recoverable only from the topic

`concept/instruction.md` §2: *"The output topic is egress, not storage. Nothing
may be recoverable only from it."*

Every field of the message except two is a projection of a row in the single
store, and `tests/test_sink.py::test_every_field_of_the_message_is_recoverable_from_the_engine`
recovers each one with a query written against the **underlying tables** — never
against the sink view the message came out of — and compares. The two exceptions
are `message_version` and `caveat`, which are constants of the emitter rather than
state; `test_only_the_two_self_describing_fields_are_code_owned` refuses a third.

`RECOVERED_FROM` in that file is the map from every dotted field path to the
relation it comes from, and `test_every_field_of_the_message_has_a_declared_recovery_route`
walks the Pydantic models and asserts the two sets equal. A field added without a
route is a failing test rather than an un-auditable message.

That is also the answer to the duplication the task names: the same assessment
exists as rows and as bytes, and the two can disagree. They cannot be
*independently* wrong here, because the message is derived on every read — there
is no second stored copy to go stale. What can go wrong is a careless edit to the
view or to the read, and the recovery test is what catches that class.

## 7. The message shape is an interface version, not a frozen version module

`MESSAGE_VERSION = "v1"` is on every message. It is deliberately **not** a
`helena.sink.v1` module in the sense of `docs/decisions/0008-version-registry.md`,
and the criterion is the one that file gives: a frozen version module exists
because *a stored row records that version and replay validates against it*. No
row records a message version — there is no column for one, and replay reads the
assessment tables, never the topic. A versioned package here would be an interface
with one implementation and a registry nothing resolves from, which
`concept/instruction.md` §1 refuses.

What it is instead is an interface contract with the consumers `concept/03` names
(*"the analyst workflow / SIEM"*), and the rule is:

> **A change to the field set, to a field's meaning or to a field's type is an
> interface change. It bumps `MESSAGE_VERSION` and it comes with a decision
> record.**

`tests/fixtures/sink/message-v1.json` pins the JSON Schema of `OutputMessage`
with every `description` removed — the field set, the types and which fields are
required — compared byte for byte, so a silent edit is a failing test rather than
a consumer discovering it at three in the morning. The prose is deliberately not
pinned: a `description` is a docstring, and pinning docstrings would make every
clarification an interface change, which teaches whoever hits it to regenerate the
fixture — and a pin people regenerate reflexively is not a pin. The fixture's
README says what to do when it fails, and says that regenerating it to make the
test pass is the one wrong answer.

What would reverse the choice: a second consumer that has to negotiate a version,
or a stored row that records which shape was emitted. Either makes the message a
recorded version rather than an interface one, and then it belongs in a frozen
module beside the contract.

## 8. What the triage decision carries, and what it does not

`concept/03`: *"A context that was escalated is emitted **once**, carrying the
analyst's verdict and the triage decision that led to it."*

`OutputMessage.triage` is present exactly where the terminal run is the
analyst's, and it carries eleven fields: the identifier, the trigger, the outcome
kind, the verdict and its path, the confidence, the failure pair, when it
happened, and the model and prompt versions. It does **not** carry triage's
citations, gaps, budgets or cost. Those are in the store under
`triage.assessment_id`, which is in the message, so carrying them would grow the
payload without adding a fact — and the rule §6 states is about recoverability,
not about completeness of the payload.

The split between what is the terminal run's and what is the pass's is one
sentence:

> Everything describing the **verdict** — classification, citations, gaps,
> patterns, narrative — is the terminal run's. Everything describing **what the
> pass did** — the retrieval trace and the disclosure ledger — is the pass's,
> with each entry tagged by the emitter that produced it.

The traces are pass-wide because a triage run calls a hosted model and
`concept/03` makes that egress: a message showing only the analyst's disclosures
would under-report what assessing this context sent off-site. Triage cannot
retrieve at all (`concept/04`), so a triage-tagged retrieval step is a contract
violation a consumer can see.

## 9. What is deferred, and by whom

- **Emission itself**, the deduplication contract and the delivered-side count.
  Task 47. `SinkStore.pending` is the engine-side half only, and a count of rows
  the view produced is not a count of messages that arrived.
- **The escalation record**, unchanged and still unowned since
  `docs/decisions/0033` §7. `Escalation.thresholds_version` reaches no row, so the
  message says an analyst ran on `deterministic_signal` and cannot say which
  thresholds decided that.
- **The composition rule's decision and proposed claims.** Neither is stored
  (there is no findings table, `docs/decisions/0033` and `0035`), so
  `OutputMessage.classification` is what the model said and the message cannot
  carry what the evidence permitted. A field for it would be a field with no row
  behind it, which §6 forbids.
- **Pruning.** The view bounds nothing and neither does the message.
  `concept/08` still lists the retention horizon as open.
- **Any consumer.** Nothing has read one of these messages, so the interface is
  exercised by this project's tests and by nothing else. The maturity label on
  `helena.sink` says `experimental` and says exactly that.
