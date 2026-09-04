# 0010 — The flow record contract, and what capture identity rests on

**Status: accepted.** Task 6 (D1 Ingest).
**Authority:** `concept/02-concepts-and-taxonomy.md` (flow record, capture,
tenant and sensor assigned at ingestion and never read from the record),
`concept/03-architecture.md` (the Normalizer assigns tenant, sensor, schema
version, event id and raw-record reference; the retained capture is the durable
record for replay), `concept/07-principles.md` (retention and replay),
`concept/08-open-questions.md` (the assumption this record is named for),
`concept/instruction.md` §2 (one store; absence is not emptiness; unknown fields
are quarantined, not coerced).

`helena.normalizer` now holds two things: `FlowRecord`, the input exactly as a
producer supplies it, and the capture registry that reads the files it comes in.

## The contract has no identity block, and that is the point

The input is *one flat JSON object per observed flow, with inline DNS / TLS /
HTTP observations*, and it carries **no tenant, no sensor, no schema version and
no raw-record reference**. All four are assigned by the Normalizer from
deployment configuration and from the capture — never read from the record.

So the contract has no field for any of them, and
`tests/test_normalizer.py::test_no_model_in_the_contract_carries_assigned_identity`
walks all fifteen models in the contract and fails if one appears. A second test
walks the 62 real records from the other side and fails if a producer ever
starts sending one. The failure being prevented is `concept/instruction.md` §6's
**defaulted tenant** — an isolation failure that looks like it is working —
which is one optional field away in a model that has somewhere to put it.

`id` is the one field that looks like an identifier and is not one. It is the
producer's own label (`udp.0`, `tcp.17`), unique within the sampled capture and
scoped by protocol; nothing guarantees it across two captures, so the
raw-record reference is the capture plus the record's offset, which the next
increment assigns.

## No invented fields, demonstrated over a whole capture

"No invented fields" is not checkable by reading a field list, so the test does
not read one. `FlowRecord.as_supplied()` is `model_dump(exclude_unset=True)`,
and the test asserts it equals the parsed JSON for **every one of the 62 real
records and every record of both capture fixtures**, one test per record. A
field the contract invented shows up on the left, a field it dropped or renamed
is missing from it, and a coerced type comes back as a different value.

Three configuration choices carry the invariants, each measured against Pydantic
2.13 rather than assumed:

| Choice | What it enforces |
| --- | --- |
| `extra="forbid"` | *Unknown fields are quarantined, not coerced.* An unrecognised key is a `ValidationError` the quarantine path turns into a typed row |
| `strict=True` | `"1.5"` into a float is refused, `1.0` into an int is refused, `1` into a float is accepted — an integer epoch second is still a time. Same for JSON input as for Python objects |
| `frozen=True` | A parsed record is a fact, not a buffer |

The models deliberately do **not** set `hide_input_in_errors`, which every
settings model in `helena.config` does set. A credential must never reach a
traceback; a rejected flow record has to name the offending value or the
quarantine row it produces cannot be diagnosed — and that row holds the whole
raw record anyway. `data/ingest/README.md` records what a flow record does carry
(device identifiers, GUIDs, user-agent strings) and confirms it carries no
credentials, tokens, cookies or authorization headers.

## Requiredness is measured, and it is the likeliest source of a false quarantine

**This is the open assumption in the contract.** The field set and the
requiredness of every field were derived from `data/ingest/flow-sample.jsonl` —
62 records, one host, 130.8 s — which is the only flow-record corpus that
exists. The rule applied: a key is in the contract only if it was observed; it
is required if it was present in every observation of its kind; it is optional
if the sample shows it absent at least once, **including when the counter-example
comes from the other HTTP version**, because a response's `content_type` is the
same fact over HTTP/1.1 as over HTTP/2.

`data/ingest/README.md` warns that this capture's ratios describe the capture
and not the schema. So a field required here because fifteen observations all
carried it may be optional in reality, and a producer omitting it will be
**quarantined rather than accepted**. That is the intended direction of the
error — drift surfaces, countable, with the raw record kept exactly as read —
but the quarantine rate is the number to watch when a second capture arrives,
and the answer to a high one is a new observation of the input, not a field
loosened on a hunch.

HTTP/1 and HTTP/2 are separate models because their observed key sets differ
structurally: `num` (ordering within the flow) and `content_len` appear on
HTTP/1 observations and on none of the 21 HTTP/2 requests or 47 HTTP/2
responses.

Two things the contract deliberately does **not** enforce, because enforcing
them would be inventing a requirement to make the model look complete:

- **`ip.proto` agreeing with which of `tcp`/`udp` is present.** True on all 62
  records, and a property of this producer rather than of the input. Enforcing
  it would quarantine the first ICMP record ever sent.
- **Anything about the meaning of a value.** `ip.src` is a `str`, not an address
  object; `uri` is the whole URI including the query string, not a host. Parsing
  is normalization and belongs to the increments that do it — and the host-part
  rule (`concept/instruction.md` §6) applies where a domain column is written,
  not where the record is read.

## A capture is the hash of a file, and there is no index

`describe_capture` reads a file and returns its sha256, its record count and its
byte size. `scan_captures` reads a directory whose files are **named by their
own digest** and refuses a `.jsonl` that is not, or one whose name is not its
own hash — the same discipline `helena.migrations` applies to an applied
migration file, for the same reason: the repository must not be able to claim
one thing while holding another.

**There is no capture index and no state file.** A capture is described by
reading it. An index would be a second store of exactly the kind
`concept/instruction.md` §2 forbids, and one that disagreed with the files would
be worse than none — the files *are* the durable record. The count is what
ingest reconciles against, so it is a refusal rather than a best effort: a blank
line inside a capture is a `CaptureError`, because a line silently skipped is a
record that never shows up as missing.

## The assumption: a hash identifies a capture only once the file closes

`concept/08-open-questions.md` carries it as an assumption in force, to be
revisited when live ingestion is built. Stated here because there is now code
resting on it:

> A file still being written has no final digest. **Capture identity under live
> ingestion is provisional** — and since the raw-record reference and the event
> id are derived from the capture reference plus the record offset, so is every
> identity downstream of it.

`tests/test_normalizer.py::test_appending_to_a_capture_changes_its_identity`
demonstrates it by measurement rather than by asserting the prose: a capture is
described, one record is appended, and the hash, the record count and the byte
size all change — while the record already in the file is byte-for-byte the same
record, now unreadable under the identity it was first described with. Nothing
about the record changed and its capture reference did.

Nothing today ingests anything but a closed file, so nothing is blocked. What
the increment that adds live ingestion has to decide, and must not decide by
default:

- what a record's capture reference is while the file it arrives in is open;
- whether a provisional reference is rewritten when the file closes — which
  would mean rewriting identity on stored rows, and `concept/instruction.md` §2
  forbids migrating stored rows forward;
- or whether live ingestion addresses something other than a file hash, in which
  case *a capture is identified by the hash of the file* stops being true and
  `concept/02-concepts-and-taxonomy.md` needs the change, not this file.

## What was not done

- **No adapter, no parse-failure type, no quarantine.** A record that fails
  validation raises a `ValidationError` and nothing catches it yet: the adapter
  protocol is the next increment and quarantine the one after, and a typed
  failure invented here would be a contract written ahead of the code that
  stores it.
- **No identity stamping and no event id.** `FlowRecord` is the input; the
  normalized event with its identity block is the next increment.
- **No schema version for the input contract.** The schema version is one of the
  dimensions in `helena.versions`, and it is stamped on the normalized
  event, not on the raw record — the raw record is what arrived, and it has no
  version because the producer sends none.
- **No versions on a `Capture`.** Nothing an assessment can cite exists yet: a
  capture is a file on disk, not a row in the store. The increment that first
  writes a row referencing a capture stamps that row.
- **No logging.** `helena.observability.logger` needs `Settings` for tenant and
  sensor, and reading a file to count its records does not need an identity.
  The increment that consumes the ingest topic has one already.
