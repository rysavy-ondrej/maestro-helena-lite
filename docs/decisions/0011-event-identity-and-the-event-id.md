# 0011 — The identity the Normalizer stamps, and how an event id is made

**Status: accepted.** Task 7 (D1 Ingest).
**Authority:** `concept/03-architecture.md` (the Normalizer *assigns tenant,
sensor, schema version, event id and raw-record reference — none of which the
input carries*, and replay goes through the same ingestion path as live
traffic), `concept/02-concepts-and-taxonomy.md` (tenant and sensor are assigned
at ingestion from deployment configuration, **never read from the record**),
`concept/07-principles.md` (a hosted thing can change beneath a stable name, so
what produced a row is recorded on it; a tenant that silently defaults is an
isolation failure that looks like it is working), `concept/instruction.md` §2
and §6.

`helena.normalizer` now holds `NormalizedEvent` — an `identity` block and an
`observation` block — and the `Normalizer` that produces one. Nothing is written
to the engine yet; that is the increment that wires the broker.

## The two blocks, and why they are two

`observation` is a `FlowRecord`: the record exactly as the producer supplied it,
round-tripping to its own JSON. `identity` is the five fields the deployment
assigns. Keeping them apart makes the boundary between *what arrived* and *what
this deployment decided* a structural fact rather than a naming convention — and
it means the absence tests over the input contract (ADR-0010) keep their
meaning, because a field appearing in `identity` is a field that provably did
not come from the record.

Every field of the identity block is required and none has a default. A default
is indistinguishable, on the row and in every view above it, from a configured
value; the only way to prevent a defaulted tenant is to leave nowhere for a
default to live.

## Identity comes from `Settings`, and refuses to be blank

`Normalizer.from_settings(settings)` holds one `IngestionIdentity` and stamps it
on every event. It is held on the instance rather than passed per record,
because a per-call tenant is an argument a caller can get wrong once and be
wrong about silently, per record.

There are three places the identity is refused rather than defaulted, and all
three are tested:

1. `Settings.load` fails at startup naming `HELENA_TENANT` / `HELENA_SENSOR`
   when either is unset, empty or whitespace (ADR-0004).
2. `Normalizer.__post_init__` raises `ConfigurationError` naming the same
   variable when handed an identity assembled some other way — a test, or a
   caller that thought it had one.
3. `EventIdentity` itself refuses a blank or space-padded tenant or sensor, so
   ` acme` and `acme` cannot become two tenants that look like one.

The record cannot influence any of it in either of the two ways it could try. A
record carrying a `tenant` **field** is refused outright by `extra="forbid"` —
not read, and not silently dropped, which is the dangerous half. A record whose
**values** name a tenant (a DNS name, a URI, the producer's own record id)
reaches nothing that reads them: the stamped tenant is the configured one,
character for character, and the values survive into the observation unchanged.

## The event id

```text
event_id = sha256( len-prefixed( tenant, sensor, capture_sha256, record_offset ) )
```

Every part survives a replay, so replaying a capture into the same deployment
reproduces every id exactly. Nothing is drawn from a clock, a counter or a
`uuid4`, and there is deliberately **no ingestion timestamp on the event** — a
wall-clock field would make every replay differ from the run it replays. The
arrival time of a record is a property of a run and belongs to whatever records
runs.

**The tenant and the sensor are in the digest, which is more than the PRD step
asked for** (it said capture reference plus record offset). The reason is the
single store: two deployments ingesting the same capture file would otherwise
mint identical ids, and a RisingWave `INSERT` onto an existing primary key is an
**upsert that overwrites the row and raises nothing** (measured in task 4). That
is a cross-tenant overwrite that looks like it is working — the exact shape of
failure the tenant rules exist to prevent. The cost is stated rather than
hidden: an id is reproducible only under the identity that made it, so
re-ingesting a capture under a renamed tenant produces new ids. That is the
honest answer, because it is a different deployment's observation.

**The schema version is not in the digest.** It versions the shape of the event,
not which record it is; mixing it in would change every id the first time the
shape changed, and the replay guarantee would hold only until the next version
bump.

**The parts are length-prefixed, not joined by a delimiter.** A tenant is an
operator-supplied string, so any separator can occur inside one, and
`tenant="a"/sensor="b:c"` must not hash to the same bytes as
`tenant="a:b"/sensor="c"`. A test asserts those two ids differ; reverting the
encoding to a join makes it fail.

The **raw-record reference** is the capture's sha256 plus the record's
zero-based offset, and never the record's own `id` — that is the producer's
label (`udp.0`, `tcp.17`), unique only within a capture and scoped by protocol.
The one-record capture fixture holds byte-for-byte the same record as offset 8
of the layer capture, and the two get different event ids: that is what
"identified by the hash of the file" costs and buys.

## Two different things are called "schema version"

`EVENT_SCHEMA_VERSION` in `helena.normalizer` versions the **shape of an
ingested event**. `VersionSet.schema_version` in `helena.versions` versions the
**agent output schema** a stored assessment is replayed against. Two concept
notes use the same words for both. Nothing joins them today, and a test pins the
collision so that the increment where an event row first cites a version set
finds it already known rather than discovering it in a column name.

`EVENT_SCHEMA_VERSION` has **one home**. There is no SQL copy to assert it
against because no table holds a normalized event yet; inventing a second copy
now would be inventing the drift the two-copies rule exists to catch. The
increment that creates that table adds the copy and the equality test with it.

## What this rests on, and what to revisit

- **Capture identity is provisional under live ingestion** (ADR-0010): a hash
  identifies a capture only once the file closes, so every event id derived from
  one is provisional in the same way. Nothing today ingests anything but a
  closed file.
- **Ingestion identity comes from deployment configuration, which does not scale
  to multiple sensors sharing one normalizer** (`concept/06-technology.md`,
  `concept/08-open-questions.md`). A second sensor is the trigger, and it
  arrives as a second `Normalizer`, not as a per-record argument.
- **The identity is stamped, not enforced.** `concept/03-architecture.md` is
  explicit that tenant isolation is a seam and not yet enforcement: the tenant is
  on every event and carried onward, and no scoped retrieval or per-tenant policy
  exists. Nothing here should be read as isolation having been implemented.
