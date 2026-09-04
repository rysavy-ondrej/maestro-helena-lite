# 0012 — Per-format input adapters, and the registration point

**Status: accepted.** Task 8 (D1 Ingest).
**Authority:** `concept/06-technology.md` (compatibility boundaries: *a second
format later means writing an adapter, not changing the contracts — that is the
boundary that must survive*), `concept/07-principles.md` (versioning: *a new
input format is an adapter, not a contract change*),
`concept/03-architecture.md` (the Normalizer is *per-format adapters parsing
flow records into validated events* and *quarantines invalid input without
stalling the stream*), `concept/instruction.md` §1, §2 and §6.

`helena.normalizer` now reads its input through an **adapter**, selected by
`HELENA_INPUT_FORMAT`. There are two: `flow-json`, the format every real capture
is in, and `flow-envelope`, a synthetic second format that exists so the
boundary claim can be measured. Nothing is stored or counted yet — quarantine is
the next increment.

## The interface, and what it deliberately does not have

```python
class InputAdapter(Protocol):
    input_format: str
    def parse(self, line: bytes) -> FlowRecord | ParseFailure: ...
```

One method. Raw line in — undecoded bytes, exactly as `read_capture` yields them
— and either the observation it describes or a typed reason it does not.

**An adapter does not produce a `NormalizedEvent`**, although the task's step
said "validated normalized event out". It produces the *observation*; the
`Normalizer` stamps the identity around it. The difference matters: identity
comes from deployment configuration and is assigned in exactly one place
(ADR-0011), and an adapter that could assemble an identity would be one more
place a tenant could come from — one per format, each able to get it wrong
silently. The composed path still satisfies the step: bytes in, a validated
normalized event or a typed parse failure out, from `Normalizer.normalize`.

Everything else the adapter is not given is the same argument. It has no
capture, so it cannot decide an event id. It has no configuration, so it cannot
be pointed at a different tenant. It has nowhere to put a field of its own on
the event, so a format that needed one would have to change the contract — which
is the conversation this boundary exists to force, rather than something to
accommodate quietly.

## The typed parse failure, and its three reasons

```python
class ParseFailure(Observed):
    input_format: str
    reason: Literal["malformed_json", "not_this_format", "contract_violation"]
    detail: str
```

**Returned, not raised.** A record this project cannot parse is an expected
outcome of reading somebody else's telemetry, not an exceptional one.
`concept/instruction.md` §6 names *catching an exception and continuing* as a
trap and gives the alternative in the same row — *quarantine with a typed reason
and the raw input exactly as read, and keep the stream running*. A typed value
the caller must handle is that refusal, with nowhere for it to be dropped
silently: `normalize_capture` yields one result per record in file order, so a
bad record does not stall the rest of the capture and every record still has
exactly one outcome.

The three reasons are never collapsed, because they mean different things to
whoever reads the counter the next increment adds:

| Reason | What it says | Whose problem |
| --- | --- | --- |
| `malformed_json` | The bytes are not JSON at all | The producer's framing, or something that truncated the line |
| `not_this_format` | JSON, and not this format's shape | This deployment: `HELENA_INPUT_FORMAT` names the wrong adapter |
| `contract_violation` | This format's shape, refused by the flow-record contract | Input drift — the number to watch (ADR-0010) |

**Measured, and not symmetric.** Only a format that declares itself can report
`not_this_format` precisely. `flow-envelope` checks the name in its own
envelope, so a flat line reaching it is refused as the wrong format;
`flow-json` has no envelope, so an envelope line reaching *it* looks exactly
like producer drift and comes back as `contract_violation`. That is a fact about
the formats rather than about the adapters, and a test pins it rather than the
module claiming a precision it does not have.

`detail` names the field and what was wrong with it and **does not copy the
offending value**. The raw record is kept exactly as read by whatever
quarantines it; a second copy of input this module has already refused to trust
is a second place it travels from.

The failure carries no capture reference and no offset. The `Normalizer` is what
addresses a record: a failure comes back from `normalize` for the record it was
given, and `normalize_capture` yields results in file order, so `enumerate`
gives the offset for both outcomes. There is no adapter version on it either —
nothing stores or cites a parse failure yet, and the increment that writes the
quarantine row is where a version belongs, beside the version set it stamps.

## The registration point: `INPUT_ADAPTERS` and `HELENA_INPUT_FORMAT`

```python
INPUT_ADAPTERS: dict[str, InputAdapter] = {
    FLOW_JSON: FlowJsonAdapter(),
    FLOW_ENVELOPE: FlowEnvelopeAdapter(),
}
```

**Adding an input format is two things: an adapter registered here, and a
configuration change.** No contract moves, no view changes, nothing downstream
of `NormalizedEvent` is touched. `helena.config` deliberately does not know
which formats exist — it resolves `HELENA_INPUT_FORMAT` as a string, and
`adapter_for` refuses an unknown one at startup naming the variable and listing
what is registered. Configuration says which format arrives; the normalizer says
which formats exist.

The variable is required and has no default, for the reason nothing in
`helena.config` has one: a deployment reading its traffic through the wrong
parser would quarantine every record and look like a producer problem.

**One adapter per deployment, not per record.** A normalizer that sniffed the
format would make "which parser produced this row" a property of the row rather
than of the configuration, and a record that parsed as two formats would be
resolved by whichever adapter happened to be tried first. For the same reason a
capture directory holds one format.

## Why there is a second adapter at all

`concept/instruction.md` §1 is explicit that an interface with one
implementation should be inlined, and a registry for two things is named as a
speculative abstraction. The second adapter is what stops this from being one:
without it, "a second format is an adapter, not a contract change" is a claim
nothing tests, and the interface is a shape nobody has pushed against.

`flow-envelope` is therefore deliberately trivial and deliberately synthetic —
three scalars renamed, the protocol layers moved under `layers`, the format
naming itself. Its fixture is the ten records of the layer-coverage capture,
transformed mechanically, and the test re-derives the file and compares it byte
for byte.

What that demonstrates, exactly: two captures holding the same ten records in
two formats, read by two adapters selected by configuration alone, produce
events whose observations are equal field for field and whose stamped
`schema_version` is the same one. The event ids differ, and must — two files are
two captures, so two raw-record references (ADR-0011).

What it does **not** demonstrate: that the boundary holds for a format carrying
something this contract has no place for. A format with a field `FlowRecord`
does not model, or one whose records are not one-per-line, would meet the
adapter interface and then have nowhere to put what it carries. That is the
honest limit of this evidence, and the first real second format is what tests
it.

## What the event does not record

The event contract has no field naming a format, an adapter or a parse failure,
and a test asserts it — the counterpart to the equality test above, because a
third format must not be accommodated by quietly adding one. Which adapter read
a record is a property of the deployment's configuration.

The consequence, stated rather than hidden: a stored event does not say which
format it was read from. It does not need to — the observation is the record —
but re-deriving an event from a retained capture requires knowing the format of
that capture, which today is the deployment's configuration and nothing else.
The increment that stores events is where that has to be recorded if it ever
needs to be, and it is a contract change when it happens.
