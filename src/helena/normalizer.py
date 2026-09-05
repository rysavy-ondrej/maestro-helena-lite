"""Normalizer — flow records in, validated events with an assigned identity out.

`concept/02-concepts-and-taxonomy.md` names the two things this module reads:

> **Flow record** — the only input: one flat JSON object per observed flow, with
> inline DNS / TLS / HTTP observations. It carries **no** tenant, sensor, schema
> version or raw-record reference.
>
> **Capture** — a retained file of flow records, identified by the hash of the
> file. The captures are the project's durable record.

and what it produces from them: a `NormalizedEvent`, which is
`concept/03-architecture.md`'s Normalizer row made of two blocks —

> Per-format adapters parsing flow records into validated events; **assigns
> tenant, sensor, schema version, event id and raw-record reference — none of
> which the input carries**; quarantines invalid input without stalling the
> stream.

So `FlowRecord` is the input **exactly as a producer supplies it** and nothing
else, and it has no identity block: all five assigned fields live on the event
instead. Adding one to the input contract would put a field there that no
producer sends, and the first thing that would happen is a defaulted tenant —
the isolation failure that looks like it is working (`concept/instruction.md`
§6). `tests/test_normalizer.py` asserts their absence, recursively, over every
model reachable from `FlowRecord`.

Between the two sits the **adapter**: raw line in, a validated observation or a
typed `ParseFailure` out. A refused record is not dropped and does not stall the
capture: `Normalizer.ingest_capture` writes it to the **quarantine** table in the
engine, with its typed reason and its raw line exactly as read, and carries on to
the next record. `Quarantine` and `QuarantineCounts` are that table and its
counter, and they live in the one store like everything else durable —
`docs/decisions/0013-quarantine-in-the-single-store.md`.

## What the contract validates, and what it deliberately does not

It validates **shape**, not meaning. `ip.src` is a `str` because that is what
arrives; it is not parsed into an address object, a URI is not split into its
host part, and an epoch float is not turned into a timestamp. Those belong to
the flatten layer, and doing them here would mean the stored record is no longer
the record as read — an event's `observation` round-trips to the producer's JSON
for exactly that reason.

Three configuration choices carry the invariants, and each is measured against
Pydantic 2.13 rather than assumed (`tests/test_normalizer.py`):

- **`extra="forbid"`** — *unknown fields are quarantined, not coerced. Input
  drift must surface* (`concept/instruction.md` §2). An unrecognised key is a
  `ValidationError`, which the quarantine path turns into a typed row holding
  the raw record exactly as read.
- **`strict=True`** — no silent coercion either. Measured: `"1.5"` into a float
  field is rejected, `1.0` into an int field is rejected, `1` into a float field
  is accepted (an integer epoch second is still a time), and the same holds for
  JSON input as for Python objects. A producer that starts sending numbers as
  strings surfaces as quarantine rather than as data that quietly changed type.
- **`frozen=True`** — a parsed record is a fact, not a buffer.

The models do **not** set `hide_input_in_errors`, and that is the opposite of
what every settings model in `helena.config` does. The asymmetry is deliberate:
a credential must never be echoed into a traceback, while a rejected flow record
has to name the offending value or a quarantine row cannot be diagnosed — and
the quarantine row holds the whole raw record anyway. `ParseFailure.detail`
takes the second half of that seriously: it names the field and what was wrong
with it and does not copy the value, because the raw record is already kept
exactly as read and a second copy of refused input is a second place it leaks
from. The datasheet in
`data/ingest/README.md` records what a flow record does carry (device
identifiers, GUIDs, user-agent strings) and confirms what it does not (no
credentials, tokens, cookies or authorization headers).

## Which fields are required, and how that was measured

The field set and the requiredness of every field are measured against every
flow-record capture this project holds, by one mechanical rule:

- a key is **present in the contract** only if it was observed (no invented
  fields);
- it is **required** only if it was present in **every** observation of its
  kind, in **every** capture;
- it is **optional** otherwise — including when the counter-example comes from
  the other HTTP version, because an HTTP response's `content_type` is the same
  fact whether it was observed over HTTP/1.1 or HTTP/2.

Two captures have been measured:

| Capture | Records | Sources | Span |
| --- | --- | --- | --- |
| `data/ingest/flow-sample.jsonl` | 62 | 1 host | 130.8 s |
| `data/demo/20250920/` (143 files) | 239 850 | 3 199 addresses | 23.97 h |

**The second refused 100 % of its records against the contract measured from the
first**, which is the outcome the first measurement predicted in as many words.
What those 239 850 quarantined records were made of is worth writing down,
because two different things were wrong and only one of them was drift.

*Observations the earlier producer did not send at all* — `tx` on the flow (all
239 850 records, and on its own enough to refuse every one under
`extra="forbid"`), `udp.dgms` (192 724), `tcp.segs` (47 126) and
`tls.recs[].dir` (23 354). `dgms` and `segs` are per-packet arrays shaped
exactly like the `tls.recs` this contract already carried, so there was a place
to put them. A field with no place here would have been the conversation the
adapter boundary exists to force rather than an addition to this list.

*Requiredness measured too tightly* — `tls.ja4s` was required and this producer
never sends it; the other fourteen TLS handshake keys sit at about 64 % (64.2 to
64.4, depending on the key) because a flow captured mid-connection has records
but no handshake. `dns.rcode`,
`dns.responses`, `dns.queries`, `dns.responses[].ttl`, `http.req`, `http.res`
and `http2.res` are the same error at smaller scale. None of this was drift: it
was 62 records of one host mistaken for the schema.

And one **rename**: `http.req[].num` and `http.res[].num` arrive as `rnum` from
this producer, which also puts `rnum` on HTTP/2, where no ordering field had
been seen before. Both spellings are in the contract and both are optional,
each being absent from one capture. Neither is mapped onto the other — that
would make the stored record no longer the record as read.

**What this cost.** Twenty-eight fields moved from required to optional (and
fifteen new ones arrived; none was removed and none tightened), so a producer
that stops sending one of the twenty-eight is now accepted where it would once
have been quarantined. That is a real loss of drift detection, and it is the price of
the rule above rather than a concession to convenience: requiredness is a claim
about every capture, and a claim two captures contradict was never true. The
direction of a fix is a further observation of the input, never a field
tightened back on a hunch.

HTTP/1 and HTTP/2 remain separate models. Their key sets are no longer disjoint
— `rnum` is on both — but `content_len` still appears only on HTTP/1, and the
two versions stay apart because a reader that merged them would have to invent a
rule for which spelling of the ordering field it meant.

## Absence is not emptiness

`concept/instruction.md` §2: *an unobserved layer is null and stays null; an
observed-but-empty one is an empty array and is sent.* Both halves are in the
contract and both are in the sample, which is why the fixture captures carry
them: a record with no application layer at all leaves `dns`, `tls`, `http` and
`http2` as `None`, while `tcp.24` has `tls.alpn == []` — TLS was observed, ALPN
was not negotiated. Nothing here defaults a missing list to `[]`, and
`FlowRecord.as_supplied()` is the round trip that proves it, field by field,
against all 62 real records.

The day capture adds a third state one level down, and it is the one to be
careful with: `dns` observed but `dns.responses` absent is not `responses == []`
and not a flow without DNS. Optional-and-absent, observed-and-empty, and
layer-not-observed are three different facts, and this contract keeps them
three.

## One adapter per format, and what that boundary is holding back

`concept/06-technology.md` and `concept/07-principles.md` both say it: **a
second input format is an adapter, not a contract change.** The adapter is the
only thing in this module that knows what the bytes look like, and its interface
is one method — `parse(line) -> FlowRecord | ParseFailure`. Everything it is not
given is the point. It has no capture, no identity and no configuration, so it
cannot stamp a tenant, cannot decide an event id, and has nowhere to put a field
of its own on the event; a format that needed one of those would be a change to
the contract, and that is the conversation the boundary is there to force.

`INPUT_ADAPTERS` is the registration point and `HELENA_INPUT_FORMAT` names the
one this deployment reads, so **adding a format is an adapter and a
configuration change**. `flow-envelope` is the second entry, and it exists to
make that claim testable rather than to read anybody's traffic: the events it
produces from the same records carry the same `schema_version` and observations
equal field for field to the flat format's.

A refused record is a **typed value, not an exception**: three reasons
(`malformed_json`, `not_this_format`, `contract_violation`) that mean different
things to whoever reads the counter and are never collapsed into one.

## Two doors, one stamping path

Records reach this module two ways and there is deliberately only one place an
identity is assigned. `normalize` takes a capture and an offset — the retained
file — and `normalize_message` takes an `IngestMessage` off the ingest topic;
both end in `_stamp`, so the same record produces byte-identical rows whichever
door it came in through. `concept/03-architecture.md` requires replay to go
through the same ingestion path as live traffic, and a second stamping
implementation is exactly the parallel path that rule forbids.

The wire form is one flow record per message, unchanged, with the raw-record
reference in the message **headers** — see the ingest-topic section below and
`docs/decisions/0014-the-ingest-topic-message.md`. `helena.broker` carries the
bytes and knows nothing about what they mean.

## The identity the Normalizer assigns, and where it comes from

Tenant and sensor come from `Settings` — from deployment configuration — and are
**never read from the record**, which is a statement with two halves and both
are tested. A record that carries a `tenant` key is refused outright by
`extra="forbid"`, and a record whose *values* happen to name a tenant reaches
nothing that reads them. `Normalizer` holds one `IngestionIdentity` and refuses
to exist without a non-blank tenant and sensor, so the failure is at
construction and names the variable rather than being one blank string on every
row.

The **event id** is a sha256 over the tenant, the sensor and the raw-record
reference — the capture's digest and the record's offset. Every part of it
survives a replay, so replaying a capture into the same deployment reproduces
every id; nothing is drawn from a clock or a counter. `_event_id` has the two
consequences that are easy to get wrong written out: why the identity is in the
digest and not only the capture reference, and why the schema version is not.

## Captures, and the assumption their identity rests on

A capture is identified by the sha256 of its bytes. `describe_capture` is the
only place that computes one, `scan_captures` reads a directory whose files are
**named by their own digest** and refuses one whose name and content disagree —
the same discipline `helena.migrations` applies to an applied migration file,
for the same reason: the repository must not be able to claim one thing while
holding another.

**The open assumption, carried from `concept/08-open-questions.md` and recorded
here because it is code that rests on it:** *a hash identifies a capture only
once the file closes.* A file still being written has no final digest, so
**capture identity under live ingestion is provisional** — and since the event
id is derived from the capture reference plus the record offset, so is every
identity downstream of it. `tests/test_normalizer.py` demonstrates this by
measurement rather than asserting the prose: appending one record to a capture
changes its hash, its record count and its byte size, so the same records under
a still-open file address a capture that will not exist once it closes. Revisit
when live ingestion is built; nothing today ingests anything but a closed file.

There is **no capture index and no state file.** A capture is described by
reading it, because the alternative is a second store of exactly the kind
`concept/instruction.md` §2 forbids — and an index that disagreed with the files
would be worse than no index. The retained files *are* the durable record.

Reads: capture files on disk, deployment identity from `helena.config`, and the
ingest topic through `helena.broker` — over the Kafka wire protocol only, never
a broker-specific API. Writes: normalized events and quarantine rows to the
engine, over the PostgreSQL wire protocol.

Maturity: experimental — the contract, the capture registry, the adapters,
identity stamping, quarantine and the ingest path are exercised by
`tests/test_normalizer.py`, against all 62 real records, the committed capture
fixtures, a real engine and the pinned broker. What has been demonstrated is
captures published to a topic, consumed back, normalized and stored, with the
counters reconciling against the files — at both scales, 62 records and 239 850;
what has not is a live producer, a capture still being written, or any broker but
this one. The field-requiredness claim above now rests on two captures from two
producers, one of them a day of a whole network; it is a much better-supported
claim than it was, and it is still a claim about two captures. The second adapter
demonstrates that the boundary holds for a format that renames and re-nests; it
is not evidence about a format that carries something this contract has no place
for.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, Literal, Protocol, get_args, runtime_checkable

import psycopg
from psycopg.types.json import Jsonb

from pydantic import (
    BaseModel,
    ConfigDict,
    NonNegativeInt,
    StringConstraints,
    ValidationError,
    model_validator,
)

from helena.broker import (
    DEFAULT_IDLE_TIMEOUT_SECONDS,
    BrokerConsumer,
    BrokerProducer,
)
from helena.config import (
    HELENA_INPUT_FORMAT,
    HELENA_SENSOR,
    HELENA_TENANT,
    ConfigurationError,
    IngestionIdentity,
    Settings,
)
from helena.versions import Version

__all__ = [
    "CAPTURE_SUFFIX",
    "EVENT_SCHEMA_VERSION",
    "INGEST_COUNTS_VIEW",
    "INGEST_HEADER_CAPTURE",
    "INGEST_HEADER_OFFSET",
    "NORMALIZED_EVENTS_TABLE",
    "FLOW_ENVELOPE",
    "FLOW_JSON",
    "INPUT_ADAPTERS",
    "PARSE_FAILURE_REASONS",
    "QUARANTINE_COUNTS_VIEW",
    "QUARANTINE_TABLE",
    "Capture",
    "CaptureError",
    "DnsObservation",
    "DnsQuery",
    "DnsResponse",
    "EventStore",
    "FlowRecord",
    "Http2Observation",
    "Http2Request",
    "Http2Response",
    "HttpObservation",
    "HttpRequest",
    "HttpResponse",
    "IpObservation",
    "EventIdentity",
    "FlowEnvelopeAdapter",
    "FlowJsonAdapter",
    "IngestCounts",
    "IngestMessage",
    "IngestMessageError",
    "InputAdapter",
    "NormalizedEvent",
    "Normalizer",
    "ParseFailure",
    "ParseFailureReason",
    "Quarantine",
    "QuarantineCounts",
    "QuarantinedRecord",
    "RawRecordReference",
    "TcpObservation",
    "TcpSegment",
    "TlsObservation",
    "TlsRecord",
    "UdpDatagram",
    "UdpObservation",
    "adapter_for",
    "consume_ingest_topic",
    "describe_capture",
    "ingest_counts",
    "publish_capture",
    "read_capture",
    "scan_captures",
]


class Observed(BaseModel):
    """Shared configuration for every model in this module.

    One place for the three choices the module docstring argues for, so a new
    part of the contract cannot quietly acquire different ones: unknown fields
    are refused rather than coerced, no type is coerced either, and a parsed
    record cannot be edited after the fact.

    The normalized event's identity block takes the same three, for the same
    reasons and one more: an identity that could be edited after it was stamped
    is an identity that could be edited to a different tenant.
    """

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class IpObservation(Observed):
    """The network layer: the pair of addresses and the bidirectional counters.

    `bsent`/`brecv` and `psent`/`precv` are kept as the two directions the input
    supplies — `concept/07-principles.md` requires the traffic statistics to stay
    bidirectional, and summing them here would be the first place that is lost.
    """

    proto: str
    src: str
    dst: str
    bsent: int
    brecv: int
    psent: int
    precv: int


class TcpSegment(Observed):
    """One TCP segment: when it went, which way, how big, and its flags.

    Observed on the day capture only (1 481 439 segments), where every segment
    carries all four keys. `dir` is a string here (`'>'` / `'<'`) while
    `TlsRecord.dir` is a signed integer — two producers' ways of writing the
    same idea, and neither is normalized into the other because this contract
    stores the record as supplied.

    `ts` is a float that arrives as an integer on whole-second segments, which
    strict mode widens (an integer epoch second is still a time).
    """

    ts: float
    dir: str
    len: int
    flags: str


class TcpObservation(Observed):
    """The TCP port pair, and the per-segment detail when the producer sends it.

    The ports were present on all 31 TCP records of `flow-sample.jsonl` and all
    47 126 of the day capture. `segs` is absent from the first and present on
    every record of the second, which is what makes it optional.
    """

    srcport: int
    dstport: int
    segs: list[TcpSegment] | None = None


class UdpDatagram(Observed):
    """One UDP datagram: when it went, which way, and how big.

    The UDP counterpart of `TcpSegment`, minus the flags a datagram does not
    have. Observed on the day capture only (566 182 datagrams), all three keys
    on every one.
    """

    ts: float
    dir: str
    len: int


class UdpObservation(Observed):
    """The UDP port pair, and the per-datagram detail when the producer sends it.

    The ports were present on all 31 UDP records of `flow-sample.jsonl` and all
    192 724 of the day capture; `dgms` only on the second.
    """

    srcport: int
    dstport: int
    dgms: list[UdpDatagram] | None = None


class DnsQuery(Observed):
    """One question in the flow's DNS traffic: the name and the query type."""

    qn: str
    qt: str | None = None


class DnsResponse(Observed):
    """One resource record in the flow's DNS traffic.

    `rr` says which section it came from (`answer` or `authority` in the
    sample). The record is kept flat and whole because the resolved address is
    routinely *not* the first element — the worked example in
    `concept/instruction.md` §6 has it at index 2, and the sample's largest
    chain is 12 records long. Whatever reads this flattens; nothing indexes.
    """

    rr: str
    qn: str
    rt: str
    rv: str
    ttl: int | None = None


class DnsObservation(Observed):
    """The DNS observed inline on the flow.

    There are three states here and they are all different. `responses == []` is
    an answered-with-nothing lookup; `responses is None` is a flow whose DNS was
    observed without an answer section at all (100 records of the day capture);
    and a flow with no `dns` key is one where no DNS was observed. Nothing
    defaults one into another.
    """

    rcode: int | None = None
    responses: list[DnsResponse] | None = None
    queries: list[DnsQuery] | None = None


class TlsRecord(Observed):
    """One TLS record: version, a signed length, and — later — an explicit direction.

    The sign of `len` is the direction (175 of `flow-sample.jsonl`'s 500 records
    are negative), which is why it is an `int` and not a size. The day capture's
    producer also sends `dir` as `+1`/`-1` alongside it, saying the same thing
    twice; both are kept as supplied, because collapsing them here would make
    the stored record no longer the record as read.

    `ct` is absent from 4.0 % of the day capture's 426 566 records, so it is
    optional even though `flow-sample.jsonl` had it on all 500.
    """

    ver: str
    len: int
    ct: int | None = None
    dir: int | None = None


class TlsObservation(Observed):
    """The TLS handshake and record sequence observed inline on the flow.

    The `c*` fields are the client's offer and the `s*` fields the server's
    selection; `ja3`/`ja4` fingerprint the client, `ja3s`/`ja4s` the server.
    Several arrive **observed but empty** — `alpn == []` where no protocol was
    negotiated, `ssvers == []` where the server sent no supported-versions
    extension. Empty is not absent.

    Only `recs` is required, and the reason the other fifteen are not is worth
    keeping apart from ordinary absence. All sixteen keys were present on all 25
    of `flow-sample.jsonl`'s TLS observations; on the day capture's 23 362 they
    run at 64.4 %, because **a flow captured mid-connection carries records but
    no handshake** — there is nothing to fingerprint and no SNI to read. `ja4s`
    is a third case again: this producer never emits it at all. So an absent
    `sni` means "no handshake was seen", not "no name was sent", and a reader
    that treated the two alike would be counting the capture's start time as a
    property of the traffic.
    """

    recs: list[TlsRecord]
    cver: str | None = None
    cciphers: list[str] | None = None
    cexts: list[str] | None = None
    sni: str | None = None
    alpn: list[str] | None = None
    csigs: list[str] | None = None
    csvers: list[str] | None = None
    ja3: str | None = None
    ja4: str | None = None
    sver: str | None = None
    scipher: str | None = None
    sexts: list[str] | None = None
    ssvers: list[str] | None = None
    ja3s: str | None = None
    ja4s: str | None = None


class HttpRequest(Observed):
    """One HTTP/1 request observed on the flow.

    `uri` is the whole URI as supplied, including the query string. It is stored
    whole and split later: `concept/instruction.md` §6 requires the **host part**
    in a domain column, and the sample carries 32 full URIs where a bare domain
    was once assumed.
    """

    method: str
    uri: str | None = None
    agent: str | None = None
    num: int | None = None
    rnum: int | None = None
    content_type: str | None = None
    content_len: str | None = None


class HttpResponse(Observed):
    """One HTTP/1 response observed on the flow.

    `code` and `content_len` are strings because that is how they arrive; strict
    mode means they are not silently turned into integers.
    """

    code: str
    num: int | None = None
    rnum: int | None = None
    content_type: str | None = None
    content_len: str | None = None
    server: str | None = None


class HttpObservation(Observed):
    """The HTTP/1 exchanges observed inline on the flow.

    Both sides are optional: the day capture has 2 flows with responses and no
    requests and 26 with requests and no responses, which is what a flow caught
    part-way through an exchange looks like.
    """

    req: list[HttpRequest] | None = None
    res: list[HttpResponse] | None = None


class Http2Request(Observed):
    """One HTTP/2 request observed on the flow.

    No `content_len`: it was observed on neither capture's HTTP/2 requests, and
    inventing it would be inventing a field. `num` is absent too, but `rnum` —
    the ordering field HTTP/1 spells `num` on one producer and `rnum` on the
    other — is present on all 2 832 of the day capture's HTTP/2 requests and on
    none of `flow-sample.jsonl`'s 21.
    """

    method: str
    uri: str
    agent: str
    rnum: int | None = None


class Http2Response(Observed):
    """One HTTP/2 response observed on the flow."""

    code: str
    rnum: int | None = None
    content_type: str | None = None
    server: str | None = None


class Http2Observation(Observed):
    """The HTTP/2 exchanges observed inline on the flow.

    `res` is absent on 845 of the day capture's 944 HTTP/2 observations — a
    request seen with no response in the same flow — so only `req` is required.
    """

    req: list[Http2Request]
    res: list[Http2Response] | None = None


class FlowRecord(Observed):
    """One observed flow, exactly as a producer supplies it.

    `id` is the producer's own label for the record (`udp.0`, `tcp.17`). It is
    unique within the sampled capture and scoped by protocol, and it is **not**
    the raw-record reference — that is assigned at ingestion from the capture and
    the record's offset, because nothing guarantees this label is unique across
    two captures.

    `ts` is the flow's start as an epoch float and `td` its duration in seconds.
    A flow is credited to the window containing `ts`
    (`concept/02-concepts-and-taxonomy.md`), so the pair is kept as supplied
    rather than turned into an interval here.

    `tx` is a third time the day capture's producer sends and the earlier one
    does not. Measured over that capture: it falls on a strict 60-second grid,
    ten distinct values per ten-minute file, and `tx >= ts + td` on every one of
    the 239 850 records — so it is when the producer exported the flow, never
    earlier than the flow ended, and it is a fact about the *export batch*
    rather than about the traffic. Nothing reads it. It is carried because it
    was observed, and a flow is still windowed on `ts`: windowing on an export
    time would bin flows by when the sensor happened to flush.

    Every application layer is optional and defaults to `None` — unobserved, not
    empty. `tcp` and `udp` are optional for the same reason: the sample has one
    of the two on every record and `ip.proto` agrees with which, but that is a
    property of this producer, not a rule of the input, and enforcing it here
    would quarantine the first ICMP record ever sent.
    """

    id: str
    ts: float
    td: float
    tx: float | None = None
    ip: IpObservation
    tcp: TcpObservation | None = None
    udp: UdpObservation | None = None
    dns: DnsObservation | None = None
    tls: TlsObservation | None = None
    http: HttpObservation | None = None
    http2: Http2Observation | None = None

    def as_supplied(self) -> dict[str, Any]:
        """The record as the producer sent it: only the keys that were set.

        `exclude_unset` rather than `exclude_none`, so this stays a statement
        about what arrived rather than about what happens to be null now. It is
        what the round-trip test compares against the parsed JSON, which is the
        only way to demonstrate "no invented fields" over a whole capture
        instead of over a field list somebody remembered to check.
        """
        return self.model_dump(exclude_unset=True)


# --- Captures -------------------------------------------------------------
#
# A capture is a retained file of flow records identified by the hash of the
# file. There is no index and no registry state: `scan_captures` reads the
# directory, `describe_capture` reads the file. See the module docstring for why
# a stored index would be a second store.

CAPTURE_SUFFIX = ".jsonl"

# What a sha256 looks like written down. One copy, used by the filename regex
# below and by the raw-record reference's own field, so "a capture is addressed
# by its digest" means the same thing in both places.
DIGEST_PATTERN = r"[0-9a-f]{64}"

# A capture file is named by its own digest, so the name and the bytes can be
# checked against each other.
CAPTURE_FILENAME = re.compile(rf"^{DIGEST_PATTERN}{re.escape(CAPTURE_SUFFIX)}$")


class CaptureError(Exception):
    """A capture file is not what a capture file has to be.

    Every case is a refusal to describe the file at all, rather than a
    best-effort count: a record count that quietly skipped something cannot be
    reconciled against what ingestion produced, which is the one thing the count
    exists for.
    """


@dataclass(frozen=True)
class Capture:
    """One retained capture file: what identifies it, and what it holds.

    `sha256` is the identity — two paths holding the same bytes are the same
    capture, and one byte's difference is a different one. `path` is only where
    this description was read from.

    `record_count` and `byte_size` are what ingestion reconciles against: the
    broker is consume-once and restart-volatile, so "did every record arrive"
    can only be answered against the file, never against the topic.
    """

    sha256: str
    record_count: int
    byte_size: int
    path: Path


def _records(data: bytes, path: Path) -> list[bytes]:
    """The records of a JSONL capture: one per line, exactly as written.

    A single trailing newline ends the last record. Any other empty line is a
    `CaptureError` — a blank line silently skipped is a record that never shows
    up as missing.
    """
    if not data:
        return []
    body = data[:-1] if data.endswith(b"\n") else data
    lines = body.split(b"\n")
    for offset, line in enumerate(lines):
        if not line.strip():
            raise CaptureError(f"{path}: line {offset + 1} is blank")
    return lines


def describe_capture(path: Path) -> Capture:
    """Read `path` and describe it: its hash, its record count and its size.

    The hash is over the file's bytes, not over the records — an identity that
    depended on how the records were parsed would change whenever the parser
    did.
    """
    data = path.read_bytes()
    return Capture(
        sha256=hashlib.sha256(data).hexdigest(),
        record_count=len(_records(data, path)),
        byte_size=len(data),
        path=path,
    )


def read_capture(capture: Capture) -> Iterator[tuple[int, bytes]]:
    """Every record of a capture as `(offset, raw line)`, in file order.

    `offset` is the record's zero-based ordinal within the capture. The line is
    handed over as bytes, undecoded and unparsed, because whatever fails to
    parse has to be quarantined **exactly as read**.

    The file is re-read rather than remembered from `describe_capture`, and the
    digest is checked, so a capture that changed underneath its description is a
    `CaptureError` rather than a silently different set of records.
    """
    data = capture.path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != capture.sha256:
        raise CaptureError(
            f"{capture.path}: content changed since it was described "
            f"(described {capture.sha256}, now {digest})"
        )
    return enumerate(_records(data, capture.path))


def scan_captures(directory: Path) -> dict[str, Capture]:
    """Every capture in `directory`, keyed by hash, or a `CaptureError`.

    The files are **named by their own digest**, which is what makes "addressed
    by its file hash" checkable rather than a convention: a `.jsonl` whose name
    is not a sha256, or whose name is not *its* sha256, is an error. Anything
    that is not a `.jsonl` is left alone, so the directory can carry a README
    saying what each digest holds.
    """
    captures: dict[str, Capture] = {}
    for path in sorted(directory.glob(f"*{CAPTURE_SUFFIX}")):
        if not CAPTURE_FILENAME.match(path.name):
            raise CaptureError(
                f"{path}: a capture file is named <sha256>{CAPTURE_SUFFIX}"
            )
        capture = describe_capture(path)
        if capture.sha256 != path.stem:
            raise CaptureError(
                f"{path}: content hashes to {capture.sha256}, "
                f"so the file is not the capture its name claims"
            )
        captures[capture.sha256] = capture
    return captures


# --- Normalized events ----------------------------------------------------
#
# `concept/03-architecture.md`, the Normalizer row: *parses flow records into
# validated events; assigns tenant, sensor, schema version, event id and
# raw-record reference — none of which the input carries.* An event is therefore
# two blocks that never mix: the identity this deployment assigned, and the
# observation exactly as the producer supplied it.

# The version of the normalized-event contract — the `schema version` the
# Normalizer stamps on every event.
#
# It is NOT `VersionSet.schema_version`, which is the agent output schema a
# stored assessment is replayed against (`helena.versions`). Two different
# things called "schema version" by two different concept notes: this one
# versions the shape of an ingested event, that one versions what an agent
# returned. Nothing joins them, and the day an event row cites a version set the
# two names have to be told apart in SQL, so they are told apart here first.
#
# It has one home. There is no SQL copy to assert it against yet — no table
# holds a normalized event until the increment that writes one — and inventing a
# second copy now would be inventing the drift the equality rule exists to catch.
EVENT_SCHEMA_VERSION = "v1"

# Tenant and sensor as they are written onto an event: non-blank, and with no
# leading or trailing whitespace, because ` acme` and `acme` are two tenants
# that look like one. Interior spaces are allowed — a deployment may well be
# called `Acme Corp` — and nothing else about the value is invented here.
Identifier = Annotated[str, StringConstraints(pattern=r"^\S(?:.*\S)?$", max_length=200)]

# A capture's sha256, written down. The same pattern the capture files are named
# with, so a reference cannot address a capture in a form no capture has.
Digest = Annotated[str, StringConstraints(pattern=rf"^{DIGEST_PATTERN}$")]


class RawRecordReference(Observed):
    """Where an event's raw record is: which capture, and where in it.

    A capture reference alone does not address a record and a record's own `id`
    does not either — the producer's label (`udp.0`, `tcp.17`) is unique only
    within a capture and scoped by protocol, and the same bytes appear in two
    captures under two identities. The pair is the reference: the sha256 of the
    retained file, and the record's zero-based offset in it, which is exactly
    what `read_capture` yields.

    This is what makes the raw record retrievable — `concept/07-principles.md`
    keeps the raw records as the durable record, and a quarantine row or a
    citation that could not point back at one would be a claim with nothing
    behind it.
    """

    capture_sha256: Digest
    record_offset: NonNegativeInt


class EventIdentity(Observed):
    """What the deployment assigned to one event. None of it is in the input.

    Every field is required and none has a default. That is the whole of
    `concept/instruction.md` §6's *a defaulted tenant is an isolation failure
    that looks like it is working*: a default here would be indistinguishable,
    on the row and in every view above it, from a tenant that was configured.
    """

    tenant: Identifier
    sensor: Identifier
    # `EVENT_SCHEMA_VERSION`, stamped so a stored event says which contract
    # validated it rather than being read back against whatever the code says
    # today (`concept/07-principles.md`: replay validates against the version the
    # row recorded).
    schema_version: Version
    event_id: Digest
    raw_record: RawRecordReference


class NormalizedEvent(Observed):
    """One validated event: assigned identity, and the record as supplied.

    The two blocks are kept apart rather than flattened together so that the
    boundary between *what arrived* and *what this deployment decided* is a
    structural fact instead of a naming convention. `observation` round-trips to
    the producer's JSON exactly as `FlowRecord` does; nothing in `identity` came
    from it.

    There is deliberately **no ingestion timestamp**. Replaying a capture has to
    reproduce the same rows, and a wall-clock field would make every replay
    differ from the run it replays — the arrival time of a record is a property
    of a run, and belongs to whatever records runs.
    """

    identity: EventIdentity
    observation: FlowRecord


# --- Input adapters -------------------------------------------------------
#
# `concept/06-technology.md`, compatibility boundaries: *a second format later
# means writing an adapter, not changing the contracts. That is the boundary
# that must survive.* `concept/07-principles.md` says the same thing from the
# versioning side: a new input format is *an adapter, not a contract change*.
#
# An adapter is therefore the only thing that knows what the bytes look like.
# It turns one raw line into a `FlowRecord` — the observation — or into a typed
# `ParseFailure` saying why it could not. It does **not** produce a
# `NormalizedEvent`: identity is stamped in exactly one place (the `Normalizer`,
# from configuration), and an adapter that could assemble an identity would be a
# second place a tenant could come from, one per format.

# The format the sample capture and the fixtures are in: one flat JSON object
# per line, the record exactly as `FlowRecord` describes it.
FLOW_JSON = "flow-json"

# A second format, and the only reason it exists: an adapter that has to rename
# and re-nest before the same contract accepts it, so "a second format is an
# adapter, not a contract change" is a thing the suite runs rather than a thing
# this comment claims. It is a synthetic format — no producer sends it — and the
# fixture is derived mechanically from the real capture it mirrors
# (`tests/fixtures/captures-flow-envelope/README.md`).
FLOW_ENVELOPE = "flow-envelope"

# The five keys of a flow-envelope line — three renamed scalars, the layers and
# the name the envelope calls itself by. That tag is `FLOW_ENVELOPE` itself
# rather than a second string, so the name in the file and the name in
# `HELENA_INPUT_FORMAT` cannot drift apart.
ENVELOPE_SCALARS = {"flow_id": "id", "start": "ts", "duration": "td"}
ENVELOPE_KEYS = frozenset({"format", *ENVELOPE_SCALARS, "layers"})

# Why one raw record did not become an event. Three reasons, never collapsed
# into one (`concept/instruction.md` §2), because they mean different things to
# whoever reads the quarantine counter:
#
# - `malformed_json` — the bytes are not JSON at all. The producer's framing
#   broke, or something truncated the line.
# - `not_this_format` — the bytes are JSON, and not this format's shape. Only a
#   format that declares itself can say this precisely: `flow-envelope` checks
#   the name in its own envelope, while `flow-json` has no envelope, so lines
#   from another format reach it as `contract_violation` unless they are not a
#   JSON object at all. Measured and pinned by a test, because the difference is
#   between "the wrong adapter is configured" and "the producer changed".
# - `contract_violation` — this format's shape, refused by the flow-record
#   contract: an unknown key, a missing one, a value of the wrong type. This is
#   input drift, and it is the one whose rate is a fact about the producer.
ParseFailureReason = Literal["malformed_json", "not_this_format", "contract_violation"]


class ParseFailure(Observed):
    """A raw record an adapter refused, and the typed reason it refused it.

    Returned, not raised. A parse failure is an expected outcome of reading
    somebody else's telemetry, and the increment after this one turns it into a
    quarantine row: catching an exception and continuing is the trap
    (`concept/instruction.md` §6), while a typed value the caller has to handle
    is the same refusal with nowhere for it to be dropped silently.

    `detail` names the offending field and what was wrong with it, and
    deliberately does **not** copy the offending value: the raw record is kept
    exactly as read by whatever quarantines it, and one copy of an input this
    module has already refused to trust is enough.

    There is no capture reference and no offset here. The `Normalizer` is what
    addresses a record — a failure comes back from `normalize` for the record it
    was given, and `normalize_capture` yields one result per record in file
    order, so `enumerate` gives the offset for both outcomes.
    """

    input_format: str
    reason: ParseFailureReason
    detail: str


@runtime_checkable
class InputAdapter(Protocol):
    """Raw line in; the observation it describes, or the reason it does not.

    The whole of the boundary that has to survive a second input format. It is
    deliberately this narrow — no capture, no identity, no configuration, no
    state — because everything it does not have is something a second format
    cannot change: an adapter cannot stamp a tenant, cannot decide an event id,
    and cannot add a field to the event contract.
    """

    input_format: str

    def parse(self, line: bytes) -> FlowRecord | ParseFailure:
        """One raw record, undecoded, as `read_capture` yields it."""
        ...


class FlowJsonAdapter:
    """`flow-json`: one flat JSON object per line, as `FlowRecord` describes it.

    The format every capture in `data/ingest/` and `tests/fixtures/captures/` is
    in, and the only one a producer actually sends today.
    """

    input_format = FLOW_JSON

    def parse(self, line: bytes) -> FlowRecord | ParseFailure:
        decoded = _json_object(line, self.input_format)
        if isinstance(decoded, ParseFailure):
            return decoded
        return _flow_record(decoded, self.input_format)


class FlowEnvelopeAdapter:
    """`flow-envelope`: the same record, renamed and wrapped.

    One JSON object per line, carrying `format`, `flow_id`, `start`, `duration`
    and a `layers` object holding the protocol layers unchanged. The adapter
    maps the three scalars back to `id`, `ts` and `td`, lifts the layers to the
    top level, and hands the result to the same `FlowRecord` contract.

    It is trivial on purpose. What it demonstrates is not that HELENA reads two
    formats — nothing sends this one — but that reading a second one took an
    adapter and a configuration value, and changed no contract: the events it
    produces are `NormalizedEvent`s with the same `schema_version` and
    observations equal, field for field, to the ones the flat format produces
    from the same records.

    An envelope whose keys are not exactly the five, whose `format` says
    something else, or whose `layers` would shadow one of the scalars is
    `not_this_format`. The last of those matters: `layers` is merged with the
    mapped scalars, and a key collision resolved by merge order would silently
    replace a record's `id` with one from somewhere else.
    """

    input_format = FLOW_ENVELOPE

    def parse(self, line: bytes) -> FlowRecord | ParseFailure:
        envelope = _json_object(line, self.input_format)
        if isinstance(envelope, ParseFailure):
            return envelope
        if set(envelope) != ENVELOPE_KEYS:
            return self._refuse(
                f"envelope keys are {sorted(envelope)}, "
                f"not {sorted(ENVELOPE_KEYS)}"
            )
        if envelope["format"] != FLOW_ENVELOPE:
            return self._refuse(
                f"envelope declares format {envelope['format']!r}, "
                f"not {FLOW_ENVELOPE!r}"
            )
        layers = envelope["layers"]
        if not isinstance(layers, dict):
            return self._refuse(
                f"`layers` is a JSON {_json_type(layers)}, not an object"
            )
        shadowed = sorted(set(layers) & set(ENVELOPE_SCALARS.values()))
        if shadowed:
            return self._refuse(f"`layers` would shadow the envelope's {shadowed}")
        record = {
            field: envelope[key] for key, field in ENVELOPE_SCALARS.items()
        }
        return _flow_record({**record, **layers}, self.input_format)

    def _refuse(self, detail: str) -> ParseFailure:
        return ParseFailure(
            input_format=self.input_format, reason="not_this_format", detail=detail
        )


# The registration point. A format is a name here and an adapter beside it;
# `HELENA_INPUT_FORMAT` says which one this deployment reads its input through.
# So adding a format is writing an adapter and changing a configuration value —
# never a change to `FlowRecord`, to `NormalizedEvent`, or to anything
# downstream of them.
#
# One adapter per deployment, deliberately. A normalizer that sniffed the format
# per record would make "which parser produced this row" a property of the row
# rather than of the configuration, and a record that parsed as two formats
# would be resolved by whichever adapter was tried first.
INPUT_ADAPTERS: dict[str, InputAdapter] = {
    FLOW_JSON: FlowJsonAdapter(),
    FLOW_ENVELOPE: FlowEnvelopeAdapter(),
}


def adapter_for(input_format: str) -> InputAdapter:
    """The adapter `input_format` names, or a startup failure naming the variable.

    No default and no fallback, for the reason every other value in
    `helena.config` has neither: a deployment reading its traffic through the
    wrong parser quarantines every record and looks like a producer problem.
    """
    adapter = INPUT_ADAPTERS.get(input_format)
    if adapter is None:
        raise ConfigurationError(
            f"{HELENA_INPUT_FORMAT}={input_format!r} names no input adapter. "
            f"Registered formats: {', '.join(sorted(INPUT_ADAPTERS))}. A new "
            f"input format is an adapter registered in helena.normalizer and a "
            f"change to this variable, never a change to a contract."
        )
    return adapter


def _json_type(value: Any) -> str:
    """What JSON calls the type Python decoded it into, for a failure message."""
    return {
        dict: "object",
        list: "array",
        str: "string",
        bool: "boolean",
        int: "number",
        float: "number",
        type(None): "null",
    }[type(value)]


def _json_object(line: bytes, input_format: str) -> dict[str, Any] | ParseFailure:
    """One raw line decoded to a JSON object, or the typed reason it is not one.

    Decoding here rather than through `model_validate_json` is what lets the two
    reasons stay apart: Pydantic reports "not JSON" and "JSON, but not an
    object" as the same kind of validation error, and they are the difference
    between a broken producer and a misconfigured adapter.
    """
    try:
        decoded = json.loads(line)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        return ParseFailure(
            input_format=input_format, reason="malformed_json", detail=str(error)
        )
    if not isinstance(decoded, dict):
        return ParseFailure(
            input_format=input_format,
            reason="not_this_format",
            detail=f"the line is a JSON {_json_type(decoded)}, not an object",
        )
    return decoded


def _flow_record(
    record: dict[str, Any], input_format: str
) -> FlowRecord | ParseFailure:
    """The decoded object as a validated `FlowRecord`, or why the contract refused it.

    Every adapter ends here, which is what makes the contract the one thing two
    formats share.
    """
    try:
        return FlowRecord.model_validate(record)
    except ValidationError as error:
        return ParseFailure(
            input_format=input_format,
            reason="contract_violation",
            detail=_violations(error),
        )


def _violations(error: ValidationError) -> str:
    """A validation error as `field: message [type]`, without the input.

    Pydantic echoes the rejected value into `str(error)`, and this deliberately
    does not: the raw record is kept exactly as read by whatever quarantines it,
    and a second copy of an input the contract has just refused to trust is a
    second place it leaks from. One rendering, used by the contract refusal and
    by the ingest-message one, so the two say the same kind of thing.
    """
    return "; ".join(
        f"{'.'.join(str(part) for part in item['loc']) or '<record>'}: "
        f"{item['msg']} [{item['type']}]"
        for item in error.errors()
    )


# --- The ingest topic ------------------------------------------------------
#
# `concept/03-architecture.md`'s interface table: *ingest topic(s), in — one flow
# record per message, over the Kafka wire protocol.* The value of a message is
# exactly that: the raw line as the producer wrote it, byte for byte, so the
# adapter parses off the wire precisely what it parses off a file and a
# quarantine row holds the bytes that were actually sent.
#
# The **raw-record reference travels in the message headers**, not in the value,
# and that is the one design decision this section carries
# (`docs/decisions/0014-the-ingest-topic-message.md`). Every event must record
# which capture a record came from and where in it
# (`RawRecordReference`) — it is what makes the raw record retrievable and what
# the event id is derived from — and the flow record itself carries none of that,
# by contract. Putting the reference in the value would mean an envelope, which
# is a change to the input format for every producer; putting it in a header
# leaves the record untouched and keeps the reference where it belongs, as
# metadata about a record rather than a field of one.
#
# `helena.broker` knows nothing about any of this. It carries bytes and header
# bytes; this is the only place that knows what the headers mean.

INGEST_HEADER_CAPTURE = "helena-capture-sha256"
INGEST_HEADER_OFFSET = "helena-record-offset"
INGEST_HEADERS = (INGEST_HEADER_CAPTURE, INGEST_HEADER_OFFSET)


class IngestMessageError(Exception):
    """A message on the ingest topic is not an ingest message.

    Raised, and it stops the run — which is the opposite of what a refused
    *record* does, and the difference is worth being explicit about.

    A record the adapter refuses is producer data this deployment can file:
    quarantine holds it under the capture and offset that address it, and
    ingestion carries on. A message with no reference in its headers cannot be
    filed anywhere — a quarantine row is *keyed* by capture and offset, so there
    is no row to write and nothing to count it against. It is not input drift; it
    is a producer publishing something else to this topic, or publishing to the
    wrong one, and continuing past it would drop a message with nothing
    recording that it existed.

    That leaves an open question rather than a settled one: where a wire-level
    refusal would live if the prototype needed to keep them. It is recorded in
    `docs/decisions/0014-the-ingest-topic-message.md` and deliberately not
    answered by inventing a second table.
    """


class IngestMessage(Observed):
    """One flow record on the ingest topic: the raw line and where it came from.

    The wire form of what `Normalizer.normalize` takes as arguments. `payload`
    is the record exactly as produced — unparsed, undecoded — and `raw_record`
    is the reference the producer stated in the headers.

    Nothing here is trusted beyond its shape: the digest must look like a
    sha256 and the offset must be a non-negative integer, and that is all a
    consumer can check. Whether the capture exists and whether it really holds
    that many records is a question about a file, and the consumer does not have
    one — `ingest_counts` is where the reference is reconciled against the
    retained capture, after the run.
    """

    raw_record: RawRecordReference
    payload: bytes

    def headers(self) -> dict[str, bytes]:
        """The reference, as the message headers carry it.

        The producer side of the contract. It is here rather than in whatever
        publishes, so that the two ends of the wire format are one piece of code
        and cannot disagree about a header name or an encoding.
        """
        return {
            INGEST_HEADER_CAPTURE: self.raw_record.capture_sha256.encode("utf-8"),
            INGEST_HEADER_OFFSET: str(self.raw_record.record_offset).encode("utf-8"),
        }

    @classmethod
    def from_headers(
        cls, *, value: bytes, headers: Mapping[str, bytes]
    ) -> IngestMessage:
        """The consumer side: a message's bytes and headers, or a typed refusal.

        Every failure names the header and says what was wrong with it, because
        the thing an operator has to find is a producer, and "the message was
        rejected" does not locate one.
        """
        missing = [name for name in INGEST_HEADERS if name not in headers]
        if missing:
            raise IngestMessageError(
                f"the message carries no {missing} header(s), so there is no "
                f"raw-record reference to stamp on the event. Every message on "
                f"the ingest topic states which capture the record came from "
                f"and its offset in it; a producer that sends none is publishing "
                f"to the wrong topic."
            )
        raw_offset = headers[INGEST_HEADER_OFFSET]
        try:
            offset = int(raw_offset.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as error:
            raise IngestMessageError(
                f"the {INGEST_HEADER_OFFSET} header is not a decimal integer: "
                f"{raw_offset!r}"
            ) from error
        try:
            capture_sha256 = headers[INGEST_HEADER_CAPTURE].decode("utf-8")
        except UnicodeDecodeError as error:
            raise IngestMessageError(
                f"the {INGEST_HEADER_CAPTURE} header is not UTF-8"
            ) from error
        try:
            reference = RawRecordReference(
                capture_sha256=capture_sha256, record_offset=offset
            )
        except ValidationError as error:
            raise IngestMessageError(
                f"the message headers do not address a raw record: "
                f"{_violations(error)}"
            ) from error
        return cls(raw_record=reference, payload=value)


@dataclass(frozen=True)
class Normalizer:
    """Parses records into events, stamping identity from configuration.

    Built from `Settings`, and refusing to exist without a tenant and a sensor.
    `Settings.load` already fails at startup naming the variable, so this is the
    second half of the same rule: an identity assembled some other way — by a
    test, or by a caller that thought it had one — is refused here rather than
    stamped onto every event it touches.

    The identity is held once, on the instance, rather than passed per record.
    A per-call tenant is an argument a caller can get wrong, and the failure
    would be silent and per-record.

    The adapter is held the same way and for a related reason: one deployment
    reads one input format, named by `HELENA_INPUT_FORMAT`, and which parser
    produced a row is a property of the configuration rather than of the row.
    """

    identity: IngestionIdentity
    adapter: InputAdapter

    def __post_init__(self) -> None:
        for variable, value in (
            (HELENA_TENANT, self.identity.tenant),
            (HELENA_SENSOR, self.identity.sensor),
        ):
            if not value.strip():
                raise ConfigurationError(
                    f"{variable} is blank, so there is no ingestion identity to "
                    f"stamp. It is set per deployment and never read from the "
                    f"record; a tenant that silently defaults is an isolation "
                    f"failure that looks like it is working."
                )

    @classmethod
    def from_settings(cls, settings: Settings) -> Normalizer:
        """The normalizer this deployment is configured to be."""
        return cls(
            identity=settings.identity,
            adapter=adapter_for(settings.input_format),
        )

    def normalize(
        self, capture: Capture, offset: int, line: bytes
    ) -> NormalizedEvent | ParseFailure:
        """One record of a capture: validated and stamped, or typed and refused.

        A record the adapter refuses comes back as a `ParseFailure` rather than
        an exception, and nothing here half-normalizes it — no identity is
        stamped on a record that never became an observation. The increment
        after this one turns that value into a quarantine row holding the raw
        line and this same reference; until then the caller has a value it
        cannot mistake for an event, which is the difference between a refusal
        and the swallowed exception `concept/instruction.md` §6 names.

        An offset that addresses no record still raises. That is not input
        drift — the bytes were never read — it is a caller asking for a record
        that does not exist, and quarantining it would file a producer's name
        against this deployment's own bug.
        """
        if not 0 <= offset < capture.record_count:
            raise CaptureError(
                f"offset {offset} does not address a record of capture "
                f"{capture.sha256} ({capture.record_count} records)"
            )
        return self._stamp(
            RawRecordReference(capture_sha256=capture.sha256, record_offset=offset),
            line,
        )

    def normalize_message(
        self, message: IngestMessage
    ) -> NormalizedEvent | ParseFailure:
        """One record off the ingest topic: validated and stamped, or refused.

        The wire equivalent of `normalize`, and deliberately the same stamping:
        both end in `_stamp`, so a record that arrived over the broker and the
        same record read from the retained capture produce byte-identical rows.
        That is the whole of `concept/03-architecture.md`'s *replay goes through
        the same ingestion path as live traffic* on this side of the wire —
        without it, replay would exercise a second implementation of the thing it
        is supposed to be checking.

        There is no record-count bound to check here, because a consumer has no
        capture file. The reference is the producer's claim and it is reconciled
        after the run, against the retained capture, by `ingest_counts`.
        """
        return self._stamp(message.raw_record, message.payload)

    def _stamp(
        self, reference: RawRecordReference, line: bytes
    ) -> NormalizedEvent | ParseFailure:
        """Parse one raw line and stamp this deployment's identity on it.

        The one place an identity is assigned, whichever door the record came
        in through.
        """
        observation = self.adapter.parse(line)
        if isinstance(observation, ParseFailure):
            return observation
        return NormalizedEvent(
            identity=EventIdentity(
                tenant=self.identity.tenant,
                sensor=self.identity.sensor,
                schema_version=EVENT_SCHEMA_VERSION,
                event_id=_event_id(
                    tenant=self.identity.tenant,
                    sensor=self.identity.sensor,
                    reference=reference,
                ),
                raw_record=reference,
            ),
            observation=observation,
        )

    def normalize_capture(
        self, capture: Capture
    ) -> Iterator[NormalizedEvent | ParseFailure]:
        """Every record of a capture, in file order: one result per record.

        The one path from a capture to events, so replay and live ingestion
        cannot drift apart into two implementations of the same stamping
        (`concept/03-architecture.md`: replay goes through the same ingestion
        path as live traffic).

        One result per record and in file order, so `enumerate` over this gives
        each result its offset — which is what a refused record needs and an
        event already carries. A failure is yielded rather than raised, so a
        record that cannot be parsed does not stall the rest of the capture.
        """
        for _, _, result in self._results(capture):
            yield result

    def ingest_capture(
        self, capture: Capture, quarantine: Quarantine
    ) -> Iterator[NormalizedEvent]:
        """Every record of a capture: events out, refusals into quarantine.

        The stream does not stall and nothing is dropped. A record the adapter
        refuses is written to the quarantine table with its typed reason and its
        raw line exactly as read, and the loop continues to the next record —
        `concept/instruction.md` §6's replacement for catching an exception and
        carrying on. A caller that only wants the events gets only the events,
        and the ones that did not become events are countable afterwards through
        `Quarantine.counts`.

        It reads through the same `_results` as `normalize_capture`, so there is
        one loop over a capture and one stamping path rather than an ingestion
        path and a quarantining path that could disagree about what a record is.

        The quarantine's identity must be this normalizer's identity. A
        `Quarantine` built under a different tenant would file this deployment's
        refused records against another producer's name — the same isolation
        failure a defaulted tenant is, arriving through a second door.
        """
        if quarantine.identity != self.identity:
            raise ConfigurationError(
                f"the quarantine is addressed as tenant "
                f"{quarantine.identity.tenant!r} / sensor "
                f"{quarantine.identity.sensor!r} and this normalizer stamps "
                f"{self.identity.tenant!r} / {self.identity.sensor!r}; a "
                f"refused record would be filed under an identity that did not "
                f"read it."
            )
        for offset, line, result in self._results(capture):
            if isinstance(result, ParseFailure):
                quarantine.record(
                    reference=RawRecordReference(
                        capture_sha256=capture.sha256, record_offset=offset
                    ),
                    line=line,
                    failure=result,
                )
                continue
            yield result

    def _results(
        self, capture: Capture
    ) -> Iterator[tuple[int, bytes, NormalizedEvent | ParseFailure]]:
        """One `(offset, raw line, result)` per record, in file order.

        The raw line is carried alongside the result because quarantine needs
        the bytes *exactly as read* and a result cannot supply them: an event
        holds the parsed observation and a `ParseFailure` deliberately holds no
        copy of the input it refused.
        """
        for offset, line in read_capture(capture):
            yield offset, line, self.normalize(capture, offset, line)

    def ingest_messages(
        self,
        messages: Iterable[IngestMessage],
        events: EventStore,
        quarantine: Quarantine,
    ) -> int:
        """Consume the ingest topic into the store. Returns messages consumed.

        The live ingestion path: every message becomes either a row in
        `helena_normalized_events` or a row in `helena_ingest_quarantine`, and
        the return value is the denominator that makes those two counts
        reconcilable — `ingest_counts` is where the three are checked against
        each other and against the retained capture.

        Nothing is dropped and nothing stalls. A record the adapter refuses goes
        to quarantine with its typed reason and its bytes exactly as they were
        produced, and the loop continues. A *message* that is not an ingest
        message at all raises out of `IngestMessage.from_headers` before this
        sees it — see `IngestMessageError` for why that one is not survivable
        the way a refused record is.

        Both stores must be addressed under this normalizer's identity, for the
        reason `ingest_capture` gives: a row filed under an identity that did
        not read the record is the isolation failure a defaulted tenant is,
        arriving through a second door.
        """
        for store, what in ((events, "event store"), (quarantine, "quarantine")):
            if store.identity != self.identity:
                raise ConfigurationError(
                    f"the {what} is addressed as tenant "
                    f"{store.identity.tenant!r} / sensor "
                    f"{store.identity.sensor!r} and this normalizer stamps "
                    f"{self.identity.tenant!r} / {self.identity.sensor!r}; the "
                    f"rows would be filed under an identity that did not read "
                    f"the records."
                )
        consumed = 0
        for message in messages:
            consumed += 1
            result = self.normalize_message(message)
            if isinstance(result, ParseFailure):
                quarantine.record(
                    reference=message.raw_record,
                    line=message.payload,
                    failure=result,
                )
                continue
            events.record(result)
        return consumed


# --- Quarantine ------------------------------------------------------------
#
# `concept/03-architecture.md` gives the Normalizer the job of quarantining
# invalid input *without stalling the stream*, and `concept/instruction.md` §6
# names the trap it replaces: *catching an exception and continuing*. The
# alternative it gives is this — **quarantine with a typed reason and the raw
# input exactly as read, and keep the stream running.**
#
# Where those rows live was an open question. `concept/08-open-questions.md`
# lists it under *cross-cutting and urgent*: "where quarantined records live,
# given they currently land outside the store the project says holds
# everything". They live in the engine, with everything else durable
# (`concept/instruction.md` §2: one store). The table and the counter view are
# `sql/migrations/0003_ingest_quarantine.sql`, and the decision record is
# `docs/decisions/0013-quarantine-in-the-single-store.md`.

# The two names the engine knows this by. One home each, on this side; the
# migration is the other, and `tests/test_normalizer.py` asserts the two agree
# by asking a real engine what it created rather than by reading the .sql file,
# which would find the name in the comment that explains it.
QUARANTINE_TABLE = "helena_ingest_quarantine"
QUARANTINE_COUNTS_VIEW = "helena_ingest_quarantine_counts"

# The three reasons, as a tuple, taken from the type rather than written out a
# second time. A counter that reported only the reasons that happened to occur
# would read a missing key as an unknown; every count carries all three.
PARSE_FAILURE_REASONS: tuple[ParseFailureReason, ...] = get_args(ParseFailureReason)


class QuarantinedRecord(Observed):
    """One refused raw record, as the store holds it.

    Three blocks, and the split is the same one `NormalizedEvent` makes: what
    this deployment assigned (`tenant`, `sensor`, `schema_version`, and the
    `raw_record` reference that says which record this is), why it was refused
    (`failure`, exactly the `ParseFailure` the adapter returned), and the bytes
    themselves (`payload`, exactly as read).

    There is deliberately **no event id**. The digest over tenant, sensor,
    capture and offset would compute perfectly well for a refused record, and
    writing it here would assert an identity for something that never became an
    event — `Normalizer.normalize` stamps no identity on a record that never
    became an observation, and this is the same rule on the storage side. The
    four fields that address the row are its primary key instead.

    There is no timestamp either, for the reason `NormalizedEvent` has none: a
    wall clock would make a replayed capture produce a different row from the
    run it replays.
    """

    tenant: Identifier
    sensor: Identifier
    raw_record: RawRecordReference
    schema_version: Version
    failure: ParseFailure
    payload: bytes


class QuarantineCounts(Observed):
    """The quarantine counter for one capture: numerator, denominator, rate.

    `records` is the denominator and it comes from the retained capture file,
    not from the engine: the broker is consume-once and restart-volatile, so
    "how many records were there" can only be answered against the file
    (`Capture.record_count`). `quarantined` and `by_reason` come from the
    engine, through `QUARANTINE_COUNTS_VIEW`.

    The counts are checked against each other on construction rather than
    trusted — `concept/instruction.md` §7 requires produced-versus-materialised
    counts to reconcile, and a reconciliation that is never evaluated is a
    claim. A per-reason total that does not add up to `quarantined`, or more
    quarantined records than the capture holds, is a `ValidationError` here
    rather than a plausible-looking number.
    """

    records: NonNegativeInt
    quarantined: NonNegativeInt
    by_reason: dict[ParseFailureReason, NonNegativeInt]

    @model_validator(mode="after")
    def _reconciles(self) -> QuarantineCounts:
        if set(self.by_reason) != set(PARSE_FAILURE_REASONS):
            raise ValueError(
                f"by_reason must carry all of {PARSE_FAILURE_REASONS}, and "
                f"carries {tuple(sorted(self.by_reason))}. A reason missing "
                f"from a counter reads as an unknown, and the three reasons are "
                f"never collapsed."
            )
        total = sum(self.by_reason.values())
        if total != self.quarantined:
            raise ValueError(
                f"the per-reason counts total {total} and {self.quarantined} "
                f"records are quarantined; the counter does not reconcile"
            )
        if self.quarantined > self.records:
            raise ValueError(
                f"{self.quarantined} records quarantined out of {self.records} "
                f"in the capture; the counter does not reconcile"
            )
        return self

    @property
    def normalized(self) -> int:
        """How many records became events.

        Derived, and exact: `Normalizer.normalize_capture` yields exactly one
        result per record in file order, and every result is either an event or
        a quarantine row. It is derived rather than counted because no table
        holds a normalized event yet — the increment that writes one makes this
        an engine-side count that reconciles against this subtraction instead of
        replacing it.
        """
        return self.records - self.quarantined

    @property
    def rate(self) -> float:
        """The quarantine rate: refused records over records read.

        The number `docs/decisions/0010-capture-identity.md` says to watch when
        a second capture arrives, because this project's field requiredness was
        measured from one capture of one host and a producer that omits a field
        it marked required is quarantined rather than accepted.

        A capture with no records raises rather than reporting 0.0: no rate is
        defined over nothing, and a zero would read as "nothing was refused".
        """
        if self.records == 0:
            raise ValueError(
                "the capture holds no records, so there is no quarantine rate; "
                "0.0 would read as 'nothing was refused'"
            )
        return self.quarantined / self.records


@dataclass(frozen=True)
class Quarantine:
    """The quarantine table, addressed under one ingestion identity.

    The identity is held on the instance rather than passed per record, for the
    reason `Normalizer` holds one: a per-call tenant is an argument a caller can
    get wrong, and every row it wrote would be filed under the wrong producer.
    `Normalizer.ingest_capture` refuses a `Quarantine` whose identity is not its
    own.

    Writes do **not** `FLUSH`. A RisingWave row is not readable until a flush
    (measured, task 04), so flushing per record would be correct and would also
    make every refused record a synchronous round trip in the middle of the
    stream — which is the stall this whole increment exists to avoid. The reads
    below flush first instead, so "the rows are there when you count them"
    holds without putting a barrier on the write path.
    """

    connection: psycopg.Connection
    identity: IngestionIdentity

    def record(
        self,
        *,
        reference: RawRecordReference,
        line: bytes,
        failure: ParseFailure,
    ) -> QuarantinedRecord:
        """Store one refused record, and return the row as it was written.

        The row is built as a `QuarantinedRecord` first and the columns come
        from that, so the contract is what reaches the engine rather than a
        second, looser description of the same thing assembled at the INSERT.

        It takes the raw-record reference rather than a capture and an offset,
        because a record refused off the ingest topic has a reference and no
        capture file: the consumer holds what the producer stated, not the
        retained bytes it came from. `ingest_capture` builds the same reference
        from the capture it is reading.
        """
        row = QuarantinedRecord(
            tenant=self.identity.tenant,
            sensor=self.identity.sensor,
            raw_record=reference,
            schema_version=EVENT_SCHEMA_VERSION,
            failure=failure,
            payload=line,
        )
        self.connection.execute(
            f"INSERT INTO {QUARANTINE_TABLE} (tenant, sensor, capture_sha256, "
            f"record_offset, schema_version, input_format, reason, detail, "
            f"payload) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (
                row.tenant,
                row.sensor,
                row.raw_record.capture_sha256,
                row.raw_record.record_offset,
                row.schema_version,
                row.failure.input_format,
                row.failure.reason,
                row.failure.detail,
                row.payload,
            ),
        )
        return row

    def stored(self, capture: Capture) -> list[QuarantinedRecord]:
        """Every quarantined record of `capture` under this identity, in order.

        Read back through the same contract that wrote them, so a column that
        stopped meaning what it meant is a `ValidationError` rather than a row
        that still parses.
        """
        self.connection.execute("FLUSH")
        rows = self.connection.execute(
            f"SELECT record_offset, schema_version, input_format, reason, "
            f"detail, payload FROM {QUARANTINE_TABLE} "
            f"WHERE tenant = %s AND sensor = %s AND capture_sha256 = %s "
            f"ORDER BY record_offset",
            (self.identity.tenant, self.identity.sensor, capture.sha256),
        ).fetchall()
        return [
            QuarantinedRecord(
                tenant=self.identity.tenant,
                sensor=self.identity.sensor,
                raw_record=RawRecordReference(
                    capture_sha256=capture.sha256, record_offset=offset
                ),
                schema_version=schema_version,
                failure=ParseFailure(
                    input_format=input_format, reason=reason, detail=detail
                ),
                payload=bytes(payload),
            )
            for offset, schema_version, input_format, reason, detail, payload in rows
        ]

    def counts(self, capture: Capture) -> QuarantineCounts:
        """The quarantine counter for `capture` under this identity.

        The numerator is summed over `input_format`, which the view keeps apart
        for whoever queries it directly: one deployment reads one format, and
        the primary key means a record re-ingested under a different one
        replaces its own row rather than adding a second.
        """
        self.connection.execute("FLUSH")
        rows = self.connection.execute(
            f"SELECT reason, quarantined FROM {QUARANTINE_COUNTS_VIEW} "
            f"WHERE tenant = %s AND sensor = %s AND capture_sha256 = %s",
            (self.identity.tenant, self.identity.sensor, capture.sha256),
        ).fetchall()
        by_reason: dict[str, int] = dict.fromkeys(PARSE_FAILURE_REASONS, 0)
        for reason, quarantined in rows:
            if reason not in by_reason:
                raise ValueError(
                    f"{QUARANTINE_COUNTS_VIEW} reports reason {reason!r}, which "
                    f"is not one of {PARSE_FAILURE_REASONS}"
                )
            by_reason[reason] += quarantined
        return QuarantineCounts(
            records=capture.record_count,
            quarantined=sum(by_reason.values()),
            by_reason=by_reason,
        )


# --- Normalized events in the store ----------------------------------------
#
# The other half of what ingestion produces. A refused record becomes a
# quarantine row; an accepted one becomes a row here, and every record of a
# capture becomes exactly one of the two — which is what makes the counters
# reconcile rather than merely agree.
#
# `sql/migrations/0004_normalized_events.sql` is the table and the counter view,
# and it is the first thing in the store that something downstream reads: the
# flatten layer of `concept/03-architecture.md`'s three is built over it.

# The two names the engine knows this by, and the migration is the other home.
# `tests/test_normalizer.py` asserts the two agree by asking a real engine what
# it created, rather than by reading the .sql file — which would find the name in
# the comment that explains it.
NORMALIZED_EVENTS_TABLE = "helena_normalized_events"
INGEST_COUNTS_VIEW = "helena_ingest_counts"


@dataclass(frozen=True)
class EventStore:
    """The normalized-event table, addressed under one ingestion identity.

    The same shape as `Quarantine` and for the same reasons: the identity is on
    the instance rather than passed per row, and `Normalizer.ingest_messages`
    refuses a store whose identity is not its own.

    Writes do **not** `FLUSH`, and the reads below flush first instead. A
    RisingWave row is unreadable until a flush (measured, task 04), so flushing
    per event would put a synchronous round trip in the middle of the stream —
    the stall ingestion is supposed not to have. The consequence is the one
    `docs/decisions/0013-quarantine-in-the-single-store.md` already states for
    quarantine: a count taken through another connection while a run is in
    flight may lag.
    """

    connection: psycopg.Connection
    identity: IngestionIdentity

    def record(self, event: NormalizedEvent) -> None:
        """Store one normalized event.

        The event must have been stamped by this store's identity. A store that
        wrote another deployment's event would put it under this tenant's key,
        and an INSERT onto an existing key in RisingWave is a silent upsert — so
        the check is not defensive, it is the thing standing between two
        deployments and one overwritten row.
        """
        if (event.identity.tenant, event.identity.sensor) != (
            self.identity.tenant,
            self.identity.sensor,
        ):
            raise ConfigurationError(
                f"the event was stamped {event.identity.tenant!r} / "
                f"{event.identity.sensor!r} and this store is addressed as "
                f"{self.identity.tenant!r} / {self.identity.sensor!r}; storing "
                f"it would file one deployment's observation under another's "
                f"name."
            )
        self.connection.execute(
            f"INSERT INTO {NORMALIZED_EVENTS_TABLE} (tenant, sensor, "
            f"capture_sha256, record_offset, schema_version, event_id, "
            f"observation) VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (
                event.identity.tenant,
                event.identity.sensor,
                event.identity.raw_record.capture_sha256,
                event.identity.raw_record.record_offset,
                event.identity.schema_version,
                event.identity.event_id,
                Jsonb(event.observation.as_supplied()),
            ),
        )

    def stored(self, capture: Capture) -> list[NormalizedEvent]:
        """Every event of `capture` under this identity, in record order.

        Read back through the same contract that wrote them — the observation is
        re-validated as a `FlowRecord` — so a column that stopped meaning what it
        meant is a `ValidationError` rather than a row that still parses. It is
        also what demonstrates that the store round-trips *absence*: an
        unobserved layer comes back missing rather than null, because
        `as_supplied` wrote only the keys that were set and JSONB kept it that
        way.
        """
        self.connection.execute("FLUSH")
        rows = self.connection.execute(
            f"SELECT record_offset, schema_version, event_id, observation "
            f"FROM {NORMALIZED_EVENTS_TABLE} "
            f"WHERE tenant = %s AND sensor = %s AND capture_sha256 = %s "
            f"ORDER BY record_offset",
            (self.identity.tenant, self.identity.sensor, capture.sha256),
        ).fetchall()
        return [
            NormalizedEvent(
                identity=EventIdentity(
                    tenant=self.identity.tenant,
                    sensor=self.identity.sensor,
                    schema_version=schema_version,
                    event_id=event_id,
                    raw_record=RawRecordReference(
                        capture_sha256=capture.sha256, record_offset=offset
                    ),
                ),
                observation=FlowRecord.model_validate(observation),
            )
            for offset, schema_version, event_id, observation in rows
        ]

    def normalized(self, capture: Capture) -> int:
        """How many records of `capture` became events, from the engine.

        The engine-side count `QuarantineCounts.normalized` was a subtraction
        for: the two are asserted against each other in `IngestCounts`, so the
        derived number and the stored one have to agree rather than one
        replacing the other.
        """
        self.connection.execute("FLUSH")
        rows = self.connection.execute(
            f"SELECT normalized FROM {INGEST_COUNTS_VIEW} "
            f"WHERE tenant = %s AND sensor = %s AND capture_sha256 = %s",
            (self.identity.tenant, self.identity.sensor, capture.sha256),
        ).fetchall()
        # The view groups by exactly the three columns this filters on, so it is
        # one row or none — none meaning no record of this capture became an
        # event, which is a real answer and not a missing one.
        return int(rows[0][0]) if rows else 0


class IngestCounts(Observed):
    """One ingest run's counters, reconciled: records, consumed, normalized, refused.

    `concept/instruction.md` §7 requires produced-versus-materialised counts to
    reconcile. The four numbers deliberately come from four different places, and
    that is what makes the check worth running:

    - `records` from the retained capture file. The broker is consume-once and
      restart-volatile — measured against the pinned blink: a topic drained once
      is empty again — so how many records existed can only be a fact about the
      file.
    - `consumed` from the run, counting messages taken off the topic.
    - `normalized` from `helena_ingest_counts` in the engine.
    - `quarantine` from `helena_ingest_quarantine_counts` in the engine, which
      keeps the three refusal reasons apart and reconciles its own total.

    A set that does not add up is a `ValidationError` here rather than a
    plausible-looking number in a report. What it catches is the failure mode the
    whole counter exists for: records that went missing between the topic and the
    store, which is exactly what a broker that is not a store makes possible.

    **Consuming a record twice is checked before that, and reported as its own
    failure**, because the two are indistinguishable by arithmetic alone: storing
    an event a second time is an upsert that rewrites the row rather than adding
    one (measured, task 04), so `normalized` does not grow and a double-consumed
    run looks exactly like a run that lost records. Replay is what makes it
    reachable — a capture published to the topic twice and drained once — and a
    diagnosis pointing at loss would send an operator looking for a broker
    problem that is not there.
    """

    records: NonNegativeInt
    consumed: NonNegativeInt
    normalized: NonNegativeInt
    quarantine: QuarantineCounts

    @model_validator(mode="after")
    def _reconciles(self) -> IngestCounts:
        if self.quarantine.records != self.records:
            raise ValueError(
                f"the quarantine counter is over a capture of "
                f"{self.quarantine.records} records and this run read one of "
                f"{self.records}; the two counters are not about the same "
                f"capture"
            )
        if self.consumed > self.records:
            raise ValueError(
                f"{self.consumed} message(s) were consumed for a capture of "
                f"{self.records} records, so at least one record was consumed "
                f"more than once — the capture was probably published to the "
                f"topic twice and drained once"
            )
        accounted = self.normalized + self.quarantine.quarantined
        if accounted != self.consumed:
            raise ValueError(
                f"{self.consumed} message(s) were consumed and "
                f"{self.normalized} normalized + "
                f"{self.quarantine.quarantined} quarantined = {accounted} are "
                f"accounted for; the difference is records that reached neither "
                f"store, and the broker keeps nothing to recover them from"
            )
        return self

    @property
    def complete(self) -> bool:
        """Whether every record of the capture arrived.

        `consumed < records` is the honest reading of a broker that is not a
        store: the run read fewer messages than the file holds, and the missing
        ones are gone rather than waiting to be re-read. It is reported, not
        raised — a partial run is a fact about the run, and the file is still
        there to replay.
        """
        return self.consumed == self.records


def ingest_counts(
    *,
    capture: Capture,
    consumed: int,
    events: EventStore,
    quarantine: Quarantine,
) -> IngestCounts:
    """The counters for one ingest run of `capture`, reconciled.

    Both stores must be addressed under one identity: counters assembled from
    two would reconcile numerically and describe two different deployments.
    """
    if events.identity != quarantine.identity:
        raise ConfigurationError(
            f"the event store is addressed as tenant "
            f"{events.identity.tenant!r} and the quarantine as "
            f"{quarantine.identity.tenant!r}; one run's counters cannot come "
            f"from two identities"
        )
    return IngestCounts(
        records=capture.record_count,
        consumed=consumed,
        normalized=events.normalized(capture),
        quarantine=quarantine.counts(capture),
    )


# --- Replay: a retained capture, back through the live path -----------------
#
# `concept/07-principles.md`: *the durable record is the retained capture,
# replayed through the same ingestion path as live traffic so replay exercises
# the real pipeline rather than a parallel one.* And `concept/06-technology.md`
# says what it is for: *the broker is consume-once, so a view added later starts
# empty rather than backfilling; adding one to a running deployment requires
# replay from the retained captures.*
#
# So replay is not a second reader of a capture. It is a **producer**: it puts
# the capture's records on the ingest topic in the wire form
# `docs/decisions/0014-the-ingest-topic-message.md` defines, and every step
# after that is the code live traffic already goes through — the same adapter,
# the same `_stamp`, the same two stores, the same counters. Neither function
# below parses a record or stamps an identity, and that is the point: a replay
# path that normalized anything itself would be the parallel pipeline the rule
# exists to prevent, and it would be the one nobody notices has drifted.
#
# `scripts/replay_capture.py` is the command that runs them.


def publish_capture(
    capture: Capture,
    producer: BrokerProducer,
    topic: str,
    *,
    rate: float | None = None,
) -> int:
    """Publish every record of `capture` to `topic`. Returns records published.

    The producer side of replay, and the only thing this project has that
    produces to the ingest topic — in a deployment that is a sensor's job.

    `rate` is records per second, paced against the wall clock: record *k* is
    published no earlier than *k / rate* seconds after the first one, so the
    whole run takes at least `(record_count - 1) / rate`. It is a floor rather
    than a schedule — a broker that cannot keep up makes the run slower and
    nothing here speeds it back up, because a pacer that caught up by publishing
    a burst would replay at a rate nobody asked for. Left unset, the records go
    as fast as the broker accepts them.

    The topic is created first, because producing to a topic that does not exist
    leaves the message queued with no error at all (measured, `docs/runbook.md`
    §3), and flushed at the end, because nothing has reached the broker until it
    is flushed and the return value would otherwise be a count of intentions.

    Records are read from the file rather than from anything remembered: the
    digest is re-checked by `read_capture`, so a capture that changed since it
    was described is a `CaptureError` rather than a replay of different records
    under the same reference.
    """
    if rate is not None and rate <= 0:
        raise ValueError(
            f"a replay rate of {rate} record(s) per second would publish "
            f"nothing; leave the rate unset to publish as fast as the broker "
            f"accepts"
        )
    producer.create_topic(topic)
    started = time.monotonic()
    published = 0
    for offset, line in read_capture(capture):
        if rate is not None:
            delay = started + published / rate - time.monotonic()
            if delay > 0:
                time.sleep(delay)
        message = IngestMessage(
            raw_record=RawRecordReference(
                capture_sha256=capture.sha256, record_offset=offset
            ),
            payload=line,
        )
        producer.publish(topic, message.payload, message.headers())
        published += 1
    producer.flush()
    return published


def consume_ingest_topic(
    consumer: BrokerConsumer,
    topic: str,
    *,
    idle_timeout: float = DEFAULT_IDLE_TIMEOUT_SECONDS,
) -> Iterator[IngestMessage]:
    """Every message on `topic`, as an ingest message, until it goes quiet.

    The consumer side of the wire, and the one place a wire message becomes an
    ingest message. It is a function rather than three lines at each call site
    for the reason the whole of this section exists: replay and live ingestion
    have to decode the headers the same way or they are two pipelines, and the
    second one is the one that is not tested.

    It yields as it goes, so `Normalizer.ingest_messages` writes each record as
    it arrives instead of after the topic is drained — the broker is not a store
    and buffering a whole run in memory would make a crash lose every record
    that had already been read.

    A message that is not an ingest message raises `IngestMessageError` out of
    here and stops the run. See that class for why that one is not survivable
    the way a refused record is.
    """
    for message in consumer.consume(topic, idle_timeout=idle_timeout):
        yield IngestMessage.from_headers(value=message.value, headers=message.headers)


def _event_id(*, tenant: str, sensor: str, reference: RawRecordReference) -> str:
    """The event id: a digest over the identity and the raw-record reference.

    Deterministic, and derived only from things that do not change on a replay —
    the configured tenant and sensor, the capture's hash and the record's offset.
    So replaying a capture into the same deployment reproduces every id exactly,
    which is what makes "a capture replayed twice produces identical rows"
    checkable rather than aspirational.

    **Tenant and sensor are in the digest as well as the capture reference**,
    which is more than the raw-record reference alone. Two deployments ingesting
    the same file would otherwise mint the same ids in the one store, and a
    RisingWave INSERT onto an existing primary key is an upsert that overwrites
    the row and raises nothing — a cross-tenant overwrite that looks like it is
    working. The cost is stated rather than hidden: an id is reproducible only
    under the identity that made it, so re-ingesting a capture under a renamed
    tenant produces new ids, and that is the honest answer, because it is a
    different deployment's observation.

    `EVENT_SCHEMA_VERSION` is deliberately **not** in the digest. It versions the
    shape of the event, not which record it is, and mixing it in would change
    every id the first time the shape changed — the replay guarantee would then
    hold only until the next version bump.

    The parts are length-prefixed rather than joined by a separator: a tenant is
    an operator-supplied string, so any delimiter can appear inside one, and
    `tenant="a"/sensor="b:c"` must not hash to the same bytes as
    `tenant="a:b"/sensor="c"`.
    """
    material = b"".join(
        _length_prefixed(part)
        for part in (
            tenant,
            sensor,
            reference.capture_sha256,
            str(reference.record_offset),
        )
    )
    return hashlib.sha256(material).hexdigest()


def _length_prefixed(value: str) -> bytes:
    """`value` as its UTF-8 length, a colon, then its UTF-8 bytes."""
    encoded = value.encode("utf-8")
    return f"{len(encoded)}:".encode() + encoded
