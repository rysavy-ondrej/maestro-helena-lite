"""Tests for helena.normalizer. Mirrors src/helena/normalizer.py.

Three things are under test: the raw flow record contract, the captures it is
read from, and the identity the Normalizer stamps onto an event. The first two
are exercised against real data — all 62 records of
`data/ingest/flow-sample.jsonl` and the committed capture fixtures — because the
contract is a claim about what a producer actually sends, and a claim like that
tested against a hand-written record only says what the test author remembered.

The identity tests are about the two directions of one rule: nothing in the
record can reach the tenant, and nothing outside the configuration and the
capture can reach the event id.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any
from uuid import uuid4

import psycopg
import pytest
from pydantic import BaseModel, ValidationError

from helena.config import ConfigurationError, IngestionIdentity, Settings
from helena.broker import BrokerConsumer, BrokerProducer
from helena.normalizer import (
    CAPTURE_SUFFIX,
    EVENT_SCHEMA_VERSION,
    FLOW_ENVELOPE,
    FLOW_JSON,
    INGEST_COUNTS_VIEW,
    INGEST_HEADER_CAPTURE,
    INGEST_HEADER_OFFSET,
    INPUT_ADAPTERS,
    NORMALIZED_EVENTS_TABLE,
    PARSE_FAILURE_REASONS,
    QUARANTINE_COUNTS_VIEW,
    QUARANTINE_TABLE,
    Capture,
    CaptureError,
    DnsObservation,
    EventIdentity,
    EventStore,
    FlowEnvelopeAdapter,
    FlowJsonAdapter,
    FlowRecord,
    HttpObservation,
    IngestCounts,
    IngestMessage,
    IngestMessageError,
    InputAdapter,
    NormalizedEvent,
    Normalizer,
    ParseFailure,
    Quarantine,
    QuarantineCounts,
    QuarantinedRecord,
    RawRecordReference,
    TlsObservation,
    adapter_for,
    consume_ingest_topic,
    describe_capture,
    ingest_counts,
    publish_capture,
    read_capture,
    scan_captures,
)
from helena.versions import VersionSet

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SAMPLE = PROJECT_ROOT / "data" / "ingest" / "flow-sample.jsonl"
SAMPLE_DATASHEET = PROJECT_ROOT / "data" / "ingest" / "README.md"
FIXTURE_CAPTURES = Path(__file__).resolve().parent / "fixtures" / "captures"

# The two committed captures, by the digest each file is named with. Named here
# so a test can say which capture it means; `scan_captures` is what proves each
# file still hashes to its name.
LAYERS_CAPTURE = "ace6ca33f7bf8aa949f79124abf33fc115cfd0909e9dea798f4762cf87af8318"
ONE_RECORD_CAPTURE = "6e361f1b99b88a8b3e77aeec4b630abff5e71396087a485eea03db3bb1856e64"

# The second format's fixture, in its own directory because a capture directory
# holds one format — a deployment reads one format (`HELENA_INPUT_FORMAT`), and
# mixing two in a directory would make "which adapter reads this file" a
# property of the file. Its ten records are the layer-coverage capture's ten,
# transformed; `test_the_envelope_fixture_is_the_flat_capture_transformed` pins
# the derivation.
ENVELOPE_CAPTURES = (
    Path(__file__).resolve().parent / "fixtures" / "captures-flow-envelope"
)
ENVELOPE_CAPTURE = "0d6634914060f34869a0258296b45cc1dc9906002184f78f3e363e320bfe2eca"

# The identity the input does not carry (`concept/02-concepts-and-taxonomy.md`,
# `concept/03-architecture.md`): tenant, sensor, schema version and the
# raw-record reference are all assigned by the Normalizer. A field name
# containing any of these fragments would mean the contract had grown a place
# for one of them.
ASSIGNED_IDENTITY = ("tenant", "sensor", "schema", "capture", "raw_record", "event_id")


def sample_lines() -> list[bytes]:
    data = SAMPLE.read_bytes()
    return data[:-1].split(b"\n") if data.endswith(b"\n") else data.split(b"\n")


SAMPLE_LINES = sample_lines()


def fixture_lines() -> list[tuple[str, int, bytes]]:
    """Every record of every committed capture, as `(capture, offset, line)`."""
    return [
        (capture.sha256, offset, line)
        for capture in scan_captures(FIXTURE_CAPTURES).values()
        for offset, line in read_capture(capture)
    ]


FIXTURE_LINES = fixture_lines()


# --- The contract is the input, and nothing else --------------------------


@pytest.mark.parametrize("line", SAMPLE_LINES, ids=lambda line: json.loads(line)["id"])
def test_every_real_record_validates_and_round_trips(line: bytes):
    """The strongest statement available about "no invented fields".

    Not "the field list looks right" but: parse the record, ask it what was
    supplied, and compare against the JSON. A field the contract invented would
    appear on the left; a field it dropped or renamed would be missing from it;
    a coerced type would come back as a different value. All 62 records, one
    test each, so a failure names the record.
    """
    supplied = json.loads(line)
    assert FlowRecord.model_validate_json(line).as_supplied() == supplied


@pytest.mark.parametrize(
    ("capture", "offset", "line"),
    FIXTURE_LINES,
    ids=lambda value: str(value)[:12],
)
def test_every_fixture_record_validates_and_round_trips(
    capture: str, offset: int, line: bytes
):
    assert FlowRecord.model_validate_json(line).as_supplied() == json.loads(line)


def _contract_models(root: type[BaseModel] = FlowRecord) -> set[type[BaseModel]]:
    """Every model reachable from `root`, including the nested ones.

    `FlowRecord` by default, because the absence tests below are about the input
    contract and walking from `NormalizedEvent` would sweep in the identity
    block — which is precisely where those fields are supposed to be.
    """
    found: set[type[BaseModel]] = set()

    def walk(model: type[BaseModel]) -> None:
        if model in found:
            return
        found.add(model)
        for field in model.model_fields.values():
            for annotation in (field.annotation, *getattr(field.annotation, "__args__", ())):
                for candidate in (annotation, *getattr(annotation, "__args__", ())):
                    if isinstance(candidate, type) and issubclass(candidate, BaseModel):
                        walk(candidate)

    walk(root)
    return found


def test_the_contract_reaches_every_nested_model():
    """The absence tests below are only as good as this walk."""
    assert len(_contract_models()) == 15
    assert {DnsObservation, TlsObservation, HttpObservation} <= _contract_models()


@pytest.mark.parametrize("model", sorted(_contract_models(), key=lambda m: m.__name__))
def test_no_model_in_the_contract_carries_assigned_identity(model: type[BaseModel]):
    """Tenant, sensor, schema version and raw-record reference are absent.

    The input carries none of them and the Normalizer assigns all of them. A
    field for one here is where a defaulted tenant comes from — the isolation
    failure that looks like it is working.
    """
    offending = [
        name
        for name in model.model_fields
        for fragment in ASSIGNED_IDENTITY
        if fragment in name
    ]
    assert offending == []
    assert "version" not in model.model_fields


def test_no_real_record_supplies_assigned_identity():
    """The other direction: the producer does not send them either.

    If a capture ever did, this fails and the contract question reopens —
    rather than the field being quietly accepted because a model grew a place
    for it.
    """

    def keys(value: Any) -> set[str]:
        if isinstance(value, dict):
            return set(value) | {k for v in value.values() for k in keys(v)}
        if isinstance(value, list):
            return {k for v in value for k in keys(v)}
        return set()

    supplied = {k for line in SAMPLE_LINES for k in keys(json.loads(line))}
    assert supplied
    offending = sorted(
        name for name in supplied for fragment in ASSIGNED_IDENTITY if fragment in name
    )
    assert offending == []


def test_a_record_carrying_a_tenant_is_refused_not_ignored():
    """`extra="forbid"`: input drift surfaces as a validation error.

    Quarantine — the increment after this one — is what turns that error into a
    typed row. What matters here is that the record cannot be half-accepted:
    the tenant is neither read nor silently dropped.
    """
    record = json.loads(SAMPLE_LINES[0])
    record["tenant"] = "acme"
    with pytest.raises(ValidationError) as raised:
        FlowRecord.model_validate(record)
    assert [error["type"] for error in raised.value.errors()] == ["extra_forbidden"]


def test_an_unknown_field_inside_a_layer_is_refused_too():
    record = json.loads(SAMPLE_LINES[0])
    record["dns"]["edns"] = {"udpsize": 4096}
    with pytest.raises(ValidationError) as raised:
        FlowRecord.model_validate(record)
    error = raised.value.errors()[0]
    assert error["type"] == "extra_forbidden"
    assert error["loc"] == ("dns", "edns")


def test_a_missing_required_field_is_refused():
    record = json.loads(SAMPLE_LINES[0])
    del record["ip"]["bsent"]
    with pytest.raises(ValidationError) as raised:
        FlowRecord.model_validate(record)
    assert raised.value.errors()[0]["loc"] == ("ip", "bsent")


@pytest.mark.parametrize(
    ("field", "value", "accepted"),
    [
        ("ts", 1717277577, True),  # an integer epoch second is still a time
        ("ts", "1717277577.7776", False),  # a number sent as a string is drift
        ("td", "0.018", False),
        ("id", 1, False),
    ],
)
def test_strict_mode_refuses_coercion(field: str, value: Any, accepted: bool):
    """Measured against Pydantic 2.13 rather than assumed.

    `strict=True` still widens int to float, which is what makes an integer
    timestamp acceptable, and refuses everything else. Without this the first
    producer to emit `"77"` instead of `77` would be accepted and the change
    would never be visible anywhere.
    """
    record = json.loads(SAMPLE_LINES[0])
    record[field] = value
    if accepted:
        assert FlowRecord.model_validate(record).as_supplied()[field] == value
        return
    with pytest.raises(ValidationError):
        FlowRecord.model_validate(record)


def test_a_parsed_record_cannot_be_edited():
    record = FlowRecord.model_validate_json(SAMPLE_LINES[0])
    with pytest.raises(ValidationError):
        record.id = "something-else"


# --- Absence is not emptiness ---------------------------------------------


def _fixture_record(capture: str, offset: int) -> FlowRecord:
    lines = dict(
        ((offset, line) for offset, line in read_capture(scan_captures(FIXTURE_CAPTURES)[capture]))
    )
    return FlowRecord.model_validate_json(lines[offset])


def test_an_unobserved_layer_is_null():
    """Offset 8 of the layer capture is SSDP: no DNS, no TLS, no HTTP at all."""
    record = _fixture_record(LAYERS_CAPTURE, 8)
    assert record.id == "udp.28"
    assert (record.dns, record.tls, record.http, record.http2) == (None, None, None, None)
    assert record.udp is not None
    assert record.tcp is None
    assert "dns" not in record.as_supplied()


def test_an_observed_but_empty_array_stays_an_empty_array():
    """Offset 7 is TLS with no ALPN negotiated: `alpn == []`, not `None`.

    The two cases sit one field apart on the same record — `alpn` observed and
    empty, `ssvers` observed and empty, `cciphers` observed and populated — and
    a layer that could not tell them apart could not tell "no TLS traffic" from
    "TLS traffic that negotiated no protocol".
    """
    record = _fixture_record(LAYERS_CAPTURE, 7)
    assert record.id == "tcp.24"
    assert record.tls is not None
    assert record.tls.alpn == []
    assert record.tls.ssvers == []
    assert record.tls.cciphers != []
    assert record.as_supplied()["tls"]["alpn"] == []


def test_a_populated_array_beside_an_empty_one_survives():
    record = _fixture_record(LAYERS_CAPTURE, 9)
    assert record.id == "tcp.30"
    assert record.tls is not None
    assert len(record.tls.csvers) == 3
    assert record.tls.ssvers == []


def test_an_absent_optional_field_is_not_defaulted_to_empty():
    """A missing `content_type` is `None`, and does not come back as `""`."""
    record = _fixture_record(LAYERS_CAPTURE, 2)
    assert record.http is not None
    request = record.http.req[0]
    assert request.content_type is None
    assert "content_type" not in record.as_supplied()["http"]["req"][0]


def test_a_dns_answer_chain_is_kept_whole_and_in_order():
    """The resolved address is at index 2 here, and index 11 elsewhere.

    `concept/instruction.md` §6 lists reading index `[0]` of a nested array as a
    trap that has already cost this project something. The contract's job is to
    keep the chain whole so whatever reads it can flatten.
    """
    record = _fixture_record(LAYERS_CAPTURE, 0)
    assert record.dns is not None
    assert [response.rt for response in record.dns.responses] == ["CNAME", "CNAME", "A"]
    assert record.dns.responses[2].rv == "52.137.106.217"

    longest = _fixture_record(LAYERS_CAPTURE, 3)
    assert longest.dns is not None
    assert len(longest.dns.responses) == 12


def test_a_lookup_that_resolved_nothing_is_not_an_unobserved_lookup():
    """`rcode` 3 with one authority record — observed, and answered nothing."""
    record = _fixture_record(LAYERS_CAPTURE, 6)
    assert record.dns is not None
    assert record.dns.rcode == 3
    assert [response.rr for response in record.dns.responses] == ["authority"]
    assert record.dns.queries[0].qt == "PTR"


# --- Captures --------------------------------------------------------------


def _datasheet_value(label: str) -> str:
    """One row of the datasheet table in `data/ingest/README.md`."""
    match = re.search(rf"^\| {label} \| (.+?) \|$", SAMPLE_DATASHEET.read_text(), re.M)
    assert match, f"{SAMPLE_DATASHEET} has no '{label}' row"
    return match.group(1)


def test_the_sample_capture_matches_its_datasheet():
    """Two copies of the capture's identity, asserted equal by computing one.

    `data/ingest/README.md` records the sha256, the byte size and the record
    count of the sample, and says the checksum *is* the version. This is the
    same rule the project applies to a version constant with two homes: two
    copies that can drift are worse than none. The datasheet is the second copy,
    and it is the one a recorded experiment cites.
    """
    capture = describe_capture(SAMPLE)
    assert capture.sha256 == _datasheet_value("SHA-256").strip("`")
    assert capture.byte_size == int(
        _datasheet_value("Size").removesuffix(" bytes").replace(" ", "")
    )
    assert capture.record_count == int(_datasheet_value("Records").split()[0])
    assert capture.byte_size == SAMPLE.stat().st_size


def test_the_committed_captures_hash_to_the_names_they_are_filed_under():
    captures = scan_captures(FIXTURE_CAPTURES)
    assert set(captures) == {LAYERS_CAPTURE, ONE_RECORD_CAPTURE}
    for sha256, capture in captures.items():
        assert capture.path.name == f"{sha256}{CAPTURE_SUFFIX}"
        assert capture.byte_size == capture.path.stat().st_size
    assert captures[LAYERS_CAPTURE].record_count == 10
    assert captures[ONE_RECORD_CAPTURE].record_count == 1
    assert captures[ONE_RECORD_CAPTURE].byte_size == 206


def test_a_capture_is_identified_by_the_file_and_not_by_its_records():
    """The one-record capture's record is also record 8 of the layer capture.

    Same bytes, two captures, two identities — which is what "identified by the
    hash of the file" means, and why a capture reference has to travel with a
    record offset rather than standing in for one.
    """
    captures = scan_captures(FIXTURE_CAPTURES)
    shared = dict(read_capture(captures[ONE_RECORD_CAPTURE]))[0]
    assert dict(read_capture(captures[LAYERS_CAPTURE]))[8] == shared
    assert LAYERS_CAPTURE != ONE_RECORD_CAPTURE


def test_reading_a_capture_yields_every_record_in_order_undecoded():
    capture = scan_captures(FIXTURE_CAPTURES)[LAYERS_CAPTURE]
    records = list(read_capture(capture))
    assert [offset for offset, _ in records] == list(range(capture.record_count))
    assert all(isinstance(line, bytes) for _, line in records)
    assert [json.loads(line)["id"] for _, line in records] == [
        "udp.0",
        "tcp.0",
        "tcp.1",
        "udp.4",
        "tcp.3",
        "tcp.4",
        "udp.7",
        "tcp.24",
        "udp.28",
        "tcp.30",
    ]


def test_the_readme_beside_the_captures_is_not_mistaken_for_one():
    assert (FIXTURE_CAPTURES / "README.md").exists()
    assert len(scan_captures(FIXTURE_CAPTURES)) == 2


def test_a_capture_file_not_named_by_a_hash_is_refused(tmp_path: Path):
    (tmp_path / "yesterday.jsonl").write_bytes(b"{}\n")
    with pytest.raises(CaptureError, match="named <sha256>"):
        scan_captures(tmp_path)


def test_a_capture_filed_under_the_wrong_hash_is_refused(tmp_path: Path):
    """An edited capture is caught the way an edited migration is."""
    data = b"{}\n"
    wrong = hashlib.sha256(b"something else").hexdigest()
    (tmp_path / f"{wrong}.jsonl").write_bytes(data)
    with pytest.raises(CaptureError, match="not the capture its name claims"):
        scan_captures(tmp_path)


def test_a_capture_that_changed_since_it_was_described_is_refused(tmp_path: Path):
    path = tmp_path / "capture.jsonl"
    path.write_bytes(SAMPLE_LINES[0] + b"\n")
    capture = describe_capture(path)
    path.write_bytes(SAMPLE_LINES[1] + b"\n")
    with pytest.raises(CaptureError, match="content changed"):
        list(read_capture(capture))


def test_a_blank_line_is_a_broken_capture_not_a_skipped_record(tmp_path: Path):
    """A silently skipped line is a record that never shows up as missing.

    Ingest counts are reconciled against `record_count`, so a count that quietly
    disagreed with the file would make the reconciliation say what it was asked
    to say.
    """
    path = tmp_path / "capture.jsonl"
    path.write_bytes(SAMPLE_LINES[0] + b"\n\n" + SAMPLE_LINES[1] + b"\n")
    with pytest.raises(CaptureError, match="line 2 is blank"):
        describe_capture(path)


def test_a_capture_with_no_trailing_newline_still_holds_its_last_record(
    tmp_path: Path,
):
    path = tmp_path / "capture.jsonl"
    path.write_bytes(SAMPLE_LINES[0] + b"\n" + SAMPLE_LINES[1])
    assert describe_capture(path).record_count == 2


def test_an_empty_capture_holds_no_records(tmp_path: Path):
    path = tmp_path / "capture.jsonl"
    path.write_bytes(b"")
    capture = describe_capture(path)
    assert capture.record_count == 0
    assert capture.byte_size == 0
    assert list(read_capture(capture)) == []


# --- The open assumption, demonstrated rather than asserted ---------------


def test_appending_to_a_capture_changes_its_identity(tmp_path: Path):
    """Why capture identity is provisional under live ingestion.

    `concept/08-open-questions.md`: *a capture is identified by the hash of its
    retained file — provisional for live ingestion, where an open file has no
    final digest until it closes.* This is that assumption measured. Every part
    of the description changes when one more record lands, so a file still being
    written addresses a capture that will not exist once it closes — and so does
    every event id derived from it. Nothing today ingests anything but a closed
    file; `docs/decisions/0010-capture-identity.md` records what happens to this
    when something does.
    """
    path = tmp_path / "open.jsonl"
    path.write_bytes(SAMPLE_LINES[0] + b"\n")
    while_open = describe_capture(path)

    with path.open("ab") as handle:
        handle.write(SAMPLE_LINES[1] + b"\n")
    once_closed = describe_capture(path)

    assert once_closed.sha256 != while_open.sha256
    assert once_closed.record_count == while_open.record_count + 1
    assert once_closed.byte_size > while_open.byte_size

    # The record that was already there is byte-for-byte the same record, and
    # it is now unreadable under the identity it was first described with. That
    # is the whole of the problem: nothing about the record changed, and its
    # capture reference did.
    assert dict(read_capture(once_closed))[0] == SAMPLE_LINES[0]
    with pytest.raises(CaptureError, match="content changed"):
        list(read_capture(while_open))


# --- The identity the Normalizer assigns ----------------------------------
#
# `concept/03-architecture.md`: the Normalizer *assigns tenant, sensor, schema
# version, event id and raw-record reference — none of which the input carries*.
# Everything below is about where those five come from, and about the two ways
# they could come from the wrong place: read out of the record, or defaulted.

# A complete environment of values that are obviously not credentials, so a leak
# in a pytest failure message would be a nuisance rather than an incident. The
# identity variables are what these tests vary; the rest are here because
# `Settings.load` resolves all or nothing.
ENVIRONMENT = {
    "LLM_URL": "http://model.invalid/v1",
    "LLM_TOKEN": "token-under-test",
    "LLM_MODEL": "model-under-test",
    "HELENA_TENANT": "tenant-under-test",
    "HELENA_SENSOR": "sensor-under-test",
    "HELENA_INPUT_FORMAT": FLOW_JSON,
    "ABUSECH_AUTH_KEY": "abusech-key-under-test",
    "VIRUSTOTAL_AUTH_KEY": "virustotal-key-under-test",
    "RISINGWAVE_DSN": "postgresql://root@localhost:4566/dev",
    "KAFKA_BOOTSTRAP_SERVERS": "localhost:9092",
    "HELENA_INGEST_TOPIC": "helena.ingest",
}


def settings(**overrides: str) -> Settings:
    """Configuration resolved from an explicit environment, never the machine's."""
    return Settings.load(environ={**ENVIRONMENT, **overrides}, env_file=None)


def normalizer(**overrides: str) -> Normalizer:
    return Normalizer.from_settings(settings(**overrides))


def capture_of(path: Path, lines: list[bytes]) -> Capture:
    """A capture file holding exactly `lines`, described."""
    path.write_bytes(b"".join(line + b"\n" for line in lines))
    return describe_capture(path)


def fixture_capture(sha256: str) -> Capture:
    return scan_captures(FIXTURE_CAPTURES)[sha256]


def test_an_event_is_an_assigned_identity_and_the_record_as_supplied():
    """Both blocks, on one real record, with nothing crossing between them."""
    capture = fixture_capture(ONE_RECORD_CAPTURE)
    line = dict(read_capture(capture))[0]
    event = normalizer().normalize(capture, 0, line)

    assert isinstance(event, NormalizedEvent)
    assert event.identity.tenant == "tenant-under-test"
    assert event.identity.sensor == "sensor-under-test"
    assert event.identity.schema_version == EVENT_SCHEMA_VERSION
    assert event.identity.raw_record.capture_sha256 == ONE_RECORD_CAPTURE
    assert event.identity.raw_record.record_offset == 0
    assert re.fullmatch(r"[0-9a-f]{64}", event.identity.event_id)
    assert event.observation.as_supplied() == json.loads(line)


def test_no_field_of_the_identity_block_has_a_default():
    """A default here is indistinguishable, on the row, from a configured value.

    `concept/instruction.md` §6: a tenant that silently defaults is an isolation
    failure that looks like it is working. The defence is that there is nowhere
    for a default to live — every field is required, so an event that could not
    be given an identity cannot be built at all.
    """
    assert set(EventIdentity.model_fields) == {
        "tenant",
        "sensor",
        "schema_version",
        "event_id",
        "raw_record",
    }
    optional = [
        name
        for name, field in EventIdentity.model_fields.items()
        if not field.is_required()
    ]
    assert optional == []
    with pytest.raises(ValidationError) as raised:
        EventIdentity(sensor="s", schema_version="v1", event_id="0" * 64, raw_record={})
    assert {error["loc"][0] for error in raised.value.errors()} >= {"tenant"}


# --- Nothing in the record can influence the tenant ------------------------


def test_a_record_carrying_a_tenant_cannot_be_normalized_at_all(tmp_path: Path):
    """The first half: a tenant-like *field* is refused, not read and not dropped.

    A half-accepted record is the dangerous outcome — the tenant silently
    ignored, the record stored as if it were clean — so the assertion is that
    no event comes back at all, rather than that the stamped tenant happens to
    be right. The refusal is a typed `ParseFailure` now that an adapter is what
    parses; it is still a refusal, and there is still no event.
    """
    record = json.loads(SAMPLE_LINES[0])
    record["tenant"] = "acme"
    capture = capture_of(tmp_path / "c.jsonl", [json.dumps(record).encode()])

    refused = normalizer().normalize(capture, 0, dict(read_capture(capture))[0])
    assert isinstance(refused, ParseFailure)
    assert refused.reason == "contract_violation"
    assert "tenant" in refused.detail
    assert "extra_forbidden" in refused.detail


def test_a_tenant_like_value_inside_the_record_does_not_reach_the_identity(
    tmp_path: Path,
):
    """The second half: values that *say* a tenant are just data.

    A record cannot carry a tenant field, so the remaining way in is a value —
    a DNS name, a URI, the producer's own record id — that names another tenant
    and gets read by something that thinks it is authoritative. The stamped
    identity is the configured one, character for character, and the record's
    values survive into the observation unchanged.
    """
    record = json.loads(SAMPLE_LINES[0])
    record["id"] = "tenant=acme"
    record["dns"]["queries"][0]["qn"] = "tenant-under-test.evil.example"
    record["ip"]["src"] = "tenant-under-test"
    capture = capture_of(tmp_path / "c.jsonl", [json.dumps(record).encode()])

    event = normalizer(HELENA_TENANT="acme-production").normalize(
        capture, 0, dict(read_capture(capture))[0]
    )
    assert event.identity.tenant == "acme-production"
    assert event.identity.sensor == "sensor-under-test"
    assert event.observation.id == "tenant=acme"
    assert event.observation.ip.src == "tenant-under-test"


def test_the_same_record_under_two_configurations_gets_two_identities(
    tmp_path: Path,
):
    """The identity is the deployment's, so one record yields two events.

    Same bytes, same capture, same offset — everything the record contributes is
    identical, and the two events differ in tenant, sensor and event id. That is
    "assigned from configuration" stated as a measurement rather than as prose.
    """
    capture = capture_of(tmp_path / "c.jsonl", [SAMPLE_LINES[0]])
    line = dict(read_capture(capture))[0]

    first = normalizer(HELENA_TENANT="acme", HELENA_SENSOR="edge-1")
    second = normalizer(HELENA_TENANT="globex", HELENA_SENSOR="edge-1")
    one, two = first.normalize(capture, 0, line), second.normalize(capture, 0, line)

    assert one.observation == two.observation
    assert (one.identity.tenant, two.identity.tenant) == ("acme", "globex")
    assert one.identity.raw_record == two.identity.raw_record
    assert one.identity.event_id != two.identity.event_id


def test_the_normalizer_refuses_a_blank_identity():
    """Refusing to start, at the two places an identity can be blank.

    `Settings.load` fails naming the variable when it is unset or blank, and the
    Normalizer fails the same way when handed an identity assembled some other
    way. Both are startup failures rather than a blank string on every row.
    """
    with pytest.raises(ConfigurationError, match="HELENA_TENANT"):
        settings(HELENA_TENANT="   ")

    with pytest.raises(ConfigurationError, match="HELENA_SENSOR"):
        Normalizer(
            identity=IngestionIdentity(tenant="acme", sensor=" \t "),
            adapter=INPUT_ADAPTERS[FLOW_JSON],
        )


@pytest.mark.parametrize("blank", ["", " ", "\t"])
def test_a_blank_tenant_cannot_be_written_onto_an_event(blank: str):
    """And if one got past both, the identity block itself refuses it."""
    with pytest.raises(ValidationError):
        EventIdentity(
            tenant=blank,
            sensor="edge-1",
            schema_version=EVENT_SCHEMA_VERSION,
            event_id="0" * 64,
            raw_record={"capture_sha256": "a" * 64, "record_offset": 0},
        )


# --- The event id ----------------------------------------------------------


def test_replaying_the_same_capture_twice_produces_identical_event_ids():
    """The replay guarantee, over every record of a real capture.

    Two independent runs — the capture re-described from the file, a fresh
    Normalizer built from a fresh `Settings` — produce equal events field for
    field, ids included. `concept/03-architecture.md` requires replay to go
    through the same ingestion path as live traffic, and an id that came from a
    clock, a counter or a `uuid4` would make every replayed row a new row.
    """
    first = list(normalizer().normalize_capture(describe_capture(SAMPLE)))
    second = list(normalizer().normalize_capture(describe_capture(SAMPLE)))

    assert len(first) == 62
    assert [event.identity.event_id for event in first] == [
        event.identity.event_id for event in second
    ]
    assert first == second


def test_every_record_of_a_capture_gets_a_distinct_event_id():
    events = list(normalizer().normalize_capture(describe_capture(SAMPLE)))
    assert len({event.identity.event_id for event in events}) == len(events)
    assert [event.identity.raw_record.record_offset for event in events] == list(
        range(62)
    )


def test_the_same_record_in_two_captures_gets_two_event_ids():
    """The one-record capture's record is also record 8 of the layer capture.

    Byte-for-byte the same record, and two ids — because a raw-record reference
    is the capture plus the offset, and a record's own `id` is the producer's
    label, unique only within a capture. Anything keyed on the record's own id
    would collapse these two into one.
    """
    one = fixture_capture(ONE_RECORD_CAPTURE)
    layers = fixture_capture(LAYERS_CAPTURE)
    line = dict(read_capture(one))[0]
    assert dict(read_capture(layers))[8] == line

    stamper = normalizer()
    assert stamper.normalize(one, 0, line).identity.event_id != stamper.normalize(
        layers, 8, line
    ).identity.event_id


def test_the_event_id_is_unambiguous_across_the_identity_boundaries(tmp_path: Path):
    """A tenant is an operator-supplied string, so it can contain any separator.

    `tenant="a"/sensor="b:c"` and `tenant="a:b"/sensor="c"` are two deployments.
    Joining the parts with a delimiter would hash both to `a:b:c` and mint one
    id for two tenants — the length-prefixed encoding is what makes that
    impossible, and this is the test that would catch a "simplification" back to
    a join.
    """
    capture = capture_of(tmp_path / "c.jsonl", [SAMPLE_LINES[0]])
    line = dict(read_capture(capture))[0]

    def event_id(tenant: str, sensor: str) -> str:
        stamper = normalizer(HELENA_TENANT=tenant, HELENA_SENSOR=sensor)
        return stamper.normalize(capture, 0, line).identity.event_id

    assert event_id("a", "b:c") != event_id("a:b", "c")


def test_an_offset_that_does_not_address_a_record_is_refused():
    """A reference has to point at a record that exists, or it points at nothing."""
    capture = fixture_capture(ONE_RECORD_CAPTURE)
    line = dict(read_capture(capture))[0]
    for offset in (1, -1):
        with pytest.raises(CaptureError, match="does not address a record"):
            normalizer().normalize(capture, offset, line)


def test_an_event_cannot_be_edited_after_it_is_stamped():
    """An identity that could be edited could be edited to another tenant."""
    capture = fixture_capture(ONE_RECORD_CAPTURE)
    event = normalizer().normalize(capture, 0, dict(read_capture(capture))[0])
    with pytest.raises(ValidationError):
        event.identity.tenant = "someone-else"
    with pytest.raises(ValidationError):
        event.identity = event.identity


def test_the_stamped_schema_version_is_the_contract_version_and_not_the_agent_one():
    """Two different things are called "schema version"; the event gets this one.

    `helena.versions.VersionSet.schema_version` is the agent output schema a
    stored assessment is replayed against. `EVENT_SCHEMA_VERSION` versions the
    shape of an ingested event. Nothing joins them yet, and the day an event row
    cites a version set they have to be told apart in SQL — so the difference is
    pinned here rather than discovered there.
    """
    capture = fixture_capture(ONE_RECORD_CAPTURE)
    event = normalizer().normalize(capture, 0, dict(read_capture(capture))[0])
    assert event.identity.schema_version == EVENT_SCHEMA_VERSION

    # The collision is real and is pinned here rather than discovered later: the
    # two contracts both call a field `schema_version`, and they version
    # different things. A row that ever carries both needs two column names.
    assert "schema_version" in VersionSet.model_fields
    assert "schema_version" in EventIdentity.model_fields


# --- The adapter boundary: a second format, and no contract change ---------
#
# `concept/06-technology.md` and `concept/07-principles.md`: a second input
# format is an adapter, not a contract change. These are the tests that make
# that a measurement — a second format really read, through a second adapter,
# producing observations equal field for field to the first format's.


def envelope_line(record: dict[str, Any]) -> bytes:
    """One flow-json record written as a flow-envelope line.

    The whole of the second format: three scalars renamed, the protocol layers
    moved under `layers`, and the format naming itself. Written here rather than
    in the package because nothing HELENA runs produces this format — it exists
    to be read — and `test_the_envelope_fixture_is_the_flat_capture_transformed`
    is what keeps this transform and the committed fixture the same thing.
    """
    return json.dumps(
        {
            "format": FLOW_ENVELOPE,
            "flow_id": record["id"],
            "start": record["ts"],
            "duration": record["td"],
            "layers": {
                key: value
                for key, value in record.items()
                if key not in {"id", "ts", "td"}
            },
        },
        separators=(",", ":"),
    ).encode()


def envelope_capture() -> Capture:
    return scan_captures(ENVELOPE_CAPTURES)[ENVELOPE_CAPTURE]


def flat_line(offset: int) -> bytes:
    return dict(read_capture(fixture_capture(LAYERS_CAPTURE)))[offset]


def test_the_registry_is_the_registration_point_and_names_its_adapters():
    """A format is a name in `INPUT_ADAPTERS` and the adapter filed under it."""
    assert set(INPUT_ADAPTERS) == {FLOW_JSON, FLOW_ENVELOPE}
    for name, adapter in INPUT_ADAPTERS.items():
        assert isinstance(adapter, InputAdapter)
        assert adapter.input_format == name
        assert adapter_for(name) is adapter


def test_an_unregistered_format_is_refused_naming_the_variable():
    """Configuration resolves, and the adapter lookup is where it fails.

    `helena.config` does not know which formats exist — the names live with the
    adapters — so a wrong value survives `Settings.load` and is refused when the
    normalizer is built, naming `HELENA_INPUT_FORMAT` and listing what is
    registered. It is a startup failure either way, and never a default.
    """
    assert settings(HELENA_INPUT_FORMAT="pcap").input_format == "pcap"

    with pytest.raises(ConfigurationError, match="HELENA_INPUT_FORMAT") as raised:
        normalizer(HELENA_INPUT_FORMAT="pcap")
    assert all(name in str(raised.value) for name in INPUT_ADAPTERS)

    for blank in ("", "   "):
        with pytest.raises(ConfigurationError, match="HELENA_INPUT_FORMAT"):
            settings(HELENA_INPUT_FORMAT=blank)


def test_the_configured_format_is_the_adapter_the_normalizer_reads_through():
    """Adding a format is a configuration change: this is the change."""
    assert normalizer().adapter is INPUT_ADAPTERS[FLOW_JSON]
    assert (
        normalizer(HELENA_INPUT_FORMAT=FLOW_ENVELOPE).adapter
        is INPUT_ADAPTERS[FLOW_ENVELOPE]
    )


@pytest.mark.parametrize("line", SAMPLE_LINES, ids=lambda line: json.loads(line)["id"])
def test_the_flat_adapter_parses_every_real_record_unchanged(line: bytes):
    """The adapter is the contract's reader, over all 62 records.

    It decodes the JSON itself rather than going through `model_validate_json`,
    so that "not JSON" and "JSON, but not an object" can stay two reasons — and
    this asserts the round trip still holds through the extra step.
    """
    record = FlowJsonAdapter().parse(line)
    assert isinstance(record, FlowRecord)
    assert record.as_supplied() == json.loads(line)


def _mangled(**changes: Any) -> bytes:
    record = json.loads(SAMPLE_LINES[0])
    record.update(changes)
    return json.dumps(record).encode()


@pytest.mark.parametrize(
    ("line", "reason"),
    [
        (b"not json at all", "malformed_json"),
        (b'{"id": ', "malformed_json"),
        (b'{"id":"\xff"}', "malformed_json"),
        (b"[1,2]", "not_this_format"),
        (b'"a record"', "not_this_format"),
        (b"null", "not_this_format"),
        (b"{}", "contract_violation"),
        (_mangled(unexpected=1), "contract_violation"),
        (_mangled(ts="1.5"), "contract_violation"),
    ],
    ids=[
        "not-json",
        "truncated",
        "invalid-utf8",
        "json-array",
        "json-string",
        "json-null",
        "empty-object",
        "unknown-key",
        "wrong-type",
    ],
)
def test_a_refused_record_comes_back_typed_and_says_which_kind(
    line: bytes, reason: str
):
    """Three reasons, never collapsed (`concept/instruction.md` §2).

    They mean different things to whoever reads the counter the next increment
    adds: framing broken, wrong adapter configured, producer drifted.
    """
    failure = FlowJsonAdapter().parse(line)
    assert isinstance(failure, ParseFailure)
    assert failure.reason == reason
    assert failure.input_format == FLOW_JSON
    assert failure.detail


def test_a_parse_failure_names_the_field_without_copying_the_value():
    """The raw record is kept exactly as read; the failure does not copy it.

    A second copy of input this module has already refused to trust is a second
    place it travels from, and the quarantine row the next increment writes
    holds the record itself.
    """
    failure = FlowJsonAdapter().parse(_mangled(ts="not-a-number-at-all"))
    assert isinstance(failure, ParseFailure)
    copied = "not-a-number-at-all" in failure.detail
    assert not copied
    assert "ts" in failure.detail


def test_a_refused_record_does_not_stall_the_rest_of_the_capture(tmp_path: Path):
    """The stream keeps running, and every record still has exactly one result.

    Three records, the middle one unparseable: two events and one typed failure,
    in file order. `enumerate` gives each result its offset, which is what makes
    a failure addressable — the events already carry theirs.
    """
    capture = capture_of(
        tmp_path / "c.jsonl",
        [SAMPLE_LINES[0], b"{ this is not a record }", SAMPLE_LINES[1]],
    )
    results = list(normalizer().normalize_capture(capture))

    assert len(results) == capture.record_count == 3
    assert [type(result) for result in results] == [
        NormalizedEvent,
        ParseFailure,
        NormalizedEvent,
    ]
    assert results[1].reason == "malformed_json"
    assert [
        offset
        for offset, result in enumerate(results)
        if isinstance(result, NormalizedEvent)
    ] == [0, 2]
    assert [
        result.identity.raw_record.record_offset
        for result in results
        if isinstance(result, NormalizedEvent)
    ] == [0, 2]


# --- The second format -----------------------------------------------------


def test_the_envelope_fixture_is_the_flat_capture_transformed():
    """The committed fixture is derived, and the derivation is pinned.

    Nothing in the second format is invented data: every line is the
    corresponding record of the layer-coverage capture, renamed and wrapped. Two
    copies of a transform that could drift apart are worth no more here than two
    copies of a version constant, so the test re-derives the file and compares.
    """
    assert set(scan_captures(ENVELOPE_CAPTURES)) == {ENVELOPE_CAPTURE}
    assert (ENVELOPE_CAPTURES / "README.md").exists()

    flat = list(read_capture(fixture_capture(LAYERS_CAPTURE)))
    envelope = list(read_capture(envelope_capture()))

    assert len(envelope) == len(flat) == 10
    for (offset, flat_bytes), (envelope_offset, envelope_bytes) in zip(flat, envelope):
        assert offset == envelope_offset
        assert envelope_bytes == envelope_line(json.loads(flat_bytes))


def test_the_second_format_produces_events_the_same_contract_describes():
    """The whole claim, measured: a second format, and no contract change.

    Two captures holding the same ten records in two formats, read by two
    adapters selected by configuration alone. The observations are equal field
    for field and the stamped schema version is the same one, so the second
    format changed nothing about what an event is. The event ids differ, and
    have to: they are two files, so two captures, so two raw-record references.
    """
    flat_events = list(normalizer().normalize_capture(fixture_capture(LAYERS_CAPTURE)))
    envelope_events = list(
        normalizer(HELENA_INPUT_FORMAT=FLOW_ENVELOPE).normalize_capture(
            envelope_capture()
        )
    )

    assert len(flat_events) == len(envelope_events) == 10
    for flat, envelope in zip(flat_events, envelope_events):
        assert isinstance(flat, NormalizedEvent)
        assert isinstance(envelope, NormalizedEvent)
        assert envelope.observation == flat.observation
        assert envelope.observation.as_supplied() == flat.observation.as_supplied()
        assert envelope.identity.schema_version == flat.identity.schema_version
        assert (envelope.identity.tenant, envelope.identity.sensor) == (
            flat.identity.tenant,
            flat.identity.sensor,
        )
        assert (
            envelope.identity.raw_record.record_offset
            == flat.identity.raw_record.record_offset
        )
        assert envelope.identity.event_id != flat.identity.event_id


def test_the_event_contract_has_no_place_for_the_format_that_produced_it():
    """A second adapter needed no field, and there is nowhere to put one.

    The counterpart to the equality test above: not only did the event contract
    not change, it has no field naming a format, an adapter or a parse failure —
    so a third format cannot be accommodated by quietly adding one either. Which
    adapter read a record is a property of the deployment's configuration, and
    the increment that stores events is where that has to be recorded if a
    stored event ever needs to say it.
    """
    assert set(NormalizedEvent.model_fields) == {"identity", "observation"}
    assert set(EventIdentity.model_fields) == {
        "tenant",
        "sensor",
        "schema_version",
        "event_id",
        "raw_record",
    }

    forbidden = ("format", "adapter", "parse", "failure")
    for model in _contract_models(NormalizedEvent):
        assert model is not ParseFailure
        for name in model.model_fields:
            assert not any(fragment in name.lower() for fragment in forbidden), (
                f"{model.__name__}.{name} names the input format on the event"
            )


def _envelope(**changes: Any) -> bytes:
    """A valid flow-envelope line with the changes applied at the top level."""
    line = json.loads(envelope_line(json.loads(flat_line(1))))
    line.update(changes)
    return json.dumps(line).encode()


def _envelope_layers(**changes: Any) -> bytes:
    """The same, with the changes applied inside `layers`."""
    line = json.loads(envelope_line(json.loads(flat_line(1))))
    line["layers"] = {**line["layers"], **changes}
    return json.dumps(line).encode()


@pytest.mark.parametrize(
    ("line", "reason"),
    [
        (b'{"format":"flow-envelope"}', "not_this_format"),
        (_envelope(format="something-else"), "not_this_format"),
        (_envelope(layers=[]), "not_this_format"),
        (_envelope(extra=1), "not_this_format"),
        (_envelope_layers(id="spoofed"), "not_this_format"),
        (_envelope_layers(unexpected=1), "contract_violation"),
        (_envelope(start="1.5"), "contract_violation"),
        (b"not json at all", "malformed_json"),
    ],
    ids=[
        "missing-keys",
        "another-formats-name",
        "layers-not-an-object",
        "unknown-envelope-key",
        "layers-shadowing-a-scalar",
        "unknown-layer",
        "wrong-scalar-type",
        "not-json",
    ],
)
def test_the_envelope_adapter_refuses_with_the_same_vocabulary(
    line: bytes, reason: str
):
    """Both adapters speak the same three reasons; only the checks differ.

    The envelope's own shape is `not_this_format` and the record inside it is
    `contract_violation`, which is the distinction the counter is for: the first
    says this deployment is reading the wrong thing, the second says the
    producer changed. `layers-shadowing-a-scalar` is the one that would be a
    silent bug rather than a refusal — a merge order that let `layers` win would
    replace the record's own id with one from somewhere else.
    """
    failure = FlowEnvelopeAdapter().parse(line)
    assert isinstance(failure, ParseFailure)
    assert failure.reason == reason
    assert failure.input_format == FLOW_ENVELOPE


def test_a_format_that_declares_itself_can_say_the_adapter_is_wrong():
    """Measured, because the two directions are not symmetric.

    An envelope line read by the flat adapter is `contract_violation` — the flat
    format has no envelope to check, so another format's bytes look exactly like
    producer drift. The reverse direction *can* tell, because the envelope names
    itself. That asymmetry is a fact about the formats rather than about the
    adapters, and it is what the module comment on `not_this_format` says.
    """
    flat = flat_line(1)
    envelope = envelope_line(json.loads(flat))

    misread_flat = FlowEnvelopeAdapter().parse(flat)
    assert isinstance(misread_flat, ParseFailure)
    assert misread_flat.reason == "not_this_format"

    misread_envelope = FlowJsonAdapter().parse(envelope)
    assert isinstance(misread_envelope, ParseFailure)
    assert misread_envelope.reason == "contract_violation"


# --- Quarantine: refused records, in the store, counted -------------------
#
# `concept/03-architecture.md` gives the Normalizer the job of quarantining
# invalid input *without stalling the stream*, and
# `concept/08-open-questions.md` asked where those records live. They live in
# the engine, so these tests execute against one
# (`docs/decisions/0013-quarantine-in-the-single-store.md`).


def quarantine_for(
    connection: psycopg.Connection, **overrides: str
) -> Quarantine:
    return Quarantine(connection=connection, identity=settings(**overrides).identity)


def _drifted(line: bytes, **changes: Any) -> bytes:
    """A real record with something changed, so a refusal is about the change.

    Named apart from `_mangled` above, which mangles a fixed record; this one
    takes the line it drifts, because a quarantine test says which offset of
    which capture the row it expects came from.
    """
    record = json.loads(line)
    record.update(changes)
    return json.dumps(record, separators=(",", ":")).encode()


# Not valid UTF-8, so it is also the case a VARCHAR payload column could not
# hold: `json.loads` raises `UnicodeDecodeError` on it rather than
# `JSONDecodeError`, and the adapter reports `malformed_json`.
NOT_UTF8 = b'{"id":"\xff","ts":1.0}'


@pytest.mark.integration
def test_the_quarantine_constants_name_what_the_migration_creates(
    migrated_engine: psycopg.Connection,
):
    """The two copies of each name, asserted equal by asking the engine.

    Grepping `sql/migrations/0003_ingest_quarantine.sql` would find the names in
    the comments that explain them.
    """
    rows = migrated_engine.execute(
        "SELECT table_name, table_type FROM information_schema.tables "
        "WHERE table_schema = current_schema() AND table_name IN (%s, %s)",
        (QUARANTINE_TABLE, QUARANTINE_COUNTS_VIEW),
    ).fetchall()
    assert sorted(rows) == sorted(
        [(QUARANTINE_TABLE, "BASE TABLE"), (QUARANTINE_COUNTS_VIEW, "VIEW")]
    )


@pytest.mark.integration
def test_a_malformed_record_quarantines_while_its_neighbours_normalize(
    migrated_engine: psycopg.Connection, tmp_path: Path
):
    """The headline claim: one bad record does not stall or shorten the rest.

    Three records, the middle one unparseable. Two events come out, in file
    order and with their real offsets, and the third is a row in the store
    rather than an exception the caller had to catch or a record nobody counted.
    """
    capture = capture_of(
        tmp_path / "mixed.jsonl", [flat_line(0), b"not json at all", flat_line(2)]
    )
    quarantine = quarantine_for(migrated_engine)

    events = list(normalizer().ingest_capture(capture, quarantine))

    assert [event.identity.raw_record.record_offset for event in events] == [0, 2]
    assert [event.observation.id for event in events] == [
        json.loads(flat_line(0))["id"],
        json.loads(flat_line(2))["id"],
    ]

    stored = quarantine.stored(capture)
    assert len(stored) == 1
    assert stored[0].raw_record.record_offset == 1
    assert stored[0].raw_record.capture_sha256 == capture.sha256
    assert stored[0].failure.reason == "malformed_json"
    assert stored[0].failure.input_format == FLOW_JSON
    assert stored[0].payload == b"not json at all"


@pytest.mark.integration
def test_the_quarantined_payload_is_the_raw_line_exactly_as_read(
    migrated_engine: psycopg.Connection, tmp_path: Path
):
    """`concept/instruction.md` §6: the raw input **exactly as read**.

    Including bytes that are not valid UTF-8, which is why the column is BYTEA:
    a text column would have had to refuse the row or decode it lossily, and a
    quarantine row that lost the bytes that caused it cannot be diagnosed.
    Nothing truncates it either — *truncation is visible or it is a bug*.
    """
    capture = capture_of(tmp_path / "bad.jsonl", [NOT_UTF8])
    quarantine = quarantine_for(migrated_engine)

    assert list(normalizer().ingest_capture(capture, quarantine)) == []

    stored = quarantine.stored(capture)
    assert [row.payload for row in stored] == [NOT_UTF8]
    assert stored[0].failure.reason == "malformed_json"


@pytest.mark.integration
def test_the_stored_row_records_the_contract_version_that_refused_it(
    migrated_engine: psycopg.Connection, tmp_path: Path
):
    """A quarantine backlog says which contract refused it, not which is current.

    `concept/07-principles.md`: replay validates against the version the row
    recorded. Re-examining these rows after a contract change has to be able to
    tell a record v1 refused from one v2 refused.
    """
    capture = capture_of(
        tmp_path / "drifted.jsonl", [_drifted(flat_line(0), unexpected=1)]
    )
    quarantine = quarantine_for(migrated_engine)

    assert list(normalizer().ingest_capture(capture, quarantine)) == []

    stored = quarantine.stored(capture)
    assert [row.schema_version for row in stored] == [EVENT_SCHEMA_VERSION]
    assert stored[0].failure.reason == "contract_violation"


def test_a_quarantined_record_carries_no_event_id():
    """A record that never became an event has no event identity.

    `Normalizer.normalize` stamps nothing on a record that never became an
    observation; this is the same rule where the row is written. What addresses
    the row is the ingestion identity plus the raw-record reference — its
    primary key — and an event id here would assert an identity for something
    that does not exist.
    """
    assert "event_id" not in QuarantinedRecord.model_fields
    assert set(QuarantinedRecord.model_fields) == {
        "tenant",
        "sensor",
        "raw_record",
        "schema_version",
        "failure",
        "payload",
    }


@pytest.mark.integration
def test_the_three_reasons_stay_distinct_in_the_store_and_in_the_counter(
    migrated_engine: psycopg.Connection, tmp_path: Path
):
    """`concept/instruction.md` §2: never collapse them, at any layer.

    One record of each reason, read by the envelope adapter because it is the
    one that can report all three — a flat-format line reaches it as
    `not_this_format` (the envelope names itself), a broken envelope record as
    `contract_violation`, and bytes that are not JSON as `malformed_json`.
    The counter reports three separate numbers, and the reasons on the rows are
    the reasons in the view.
    """
    good = dict(read_capture(envelope_capture()))
    capture = capture_of(
        tmp_path / "three.jsonl",
        [good[0], flat_line(0), _envelope_layers(unexpected=1), b"{", good[1]],
    )
    quarantine = quarantine_for(migrated_engine, HELENA_INPUT_FORMAT=FLOW_ENVELOPE)
    reader = normalizer(HELENA_INPUT_FORMAT=FLOW_ENVELOPE)

    events = list(reader.ingest_capture(capture, quarantine))
    assert [event.identity.raw_record.record_offset for event in events] == [0, 4]

    stored = quarantine.stored(capture)
    assert [(row.raw_record.record_offset, row.failure.reason) for row in stored] == [
        (1, "not_this_format"),
        (2, "contract_violation"),
        (3, "malformed_json"),
    ]

    counts = quarantine.counts(capture)
    assert counts.by_reason == {
        "malformed_json": 1,
        "not_this_format": 1,
        "contract_violation": 1,
    }
    assert counts.quarantined == 3


@pytest.mark.integration
def test_the_counter_reconciles_against_the_capture_record_count(
    migrated_engine: psycopg.Connection, tmp_path: Path
):
    """Produced versus materialised, over the one denominator that exists.

    The broker is consume-once, so "how many records were there" is a fact about
    the retained file. `normalized` is a subtraction until something stores an
    event, and this asserts the subtraction equals the events actually produced
    rather than taking it on trust.
    """
    lines = [flat_line(offset) for offset in range(4)] + [b"not json", NOT_UTF8]
    capture = capture_of(tmp_path / "rate.jsonl", lines)
    quarantine = quarantine_for(migrated_engine)

    events = list(normalizer().ingest_capture(capture, quarantine))

    counts = quarantine.counts(capture)
    assert counts.records == capture.record_count == 6
    assert counts.quarantined == 2
    assert counts.normalized == len(events) == 4
    assert counts.rate == pytest.approx(2 / 6)


@pytest.mark.integration
def test_a_capture_that_parses_wholly_quarantines_nothing(
    migrated_engine: psycopg.Connection,
):
    """The committed layer-coverage capture, all ten records, rate zero.

    A zero here is a measured zero over real records — the same capture every
    contract test reads — not the absence of a counter.
    """
    capture = fixture_capture(LAYERS_CAPTURE)
    quarantine = quarantine_for(migrated_engine)

    events = list(normalizer().ingest_capture(capture, quarantine))

    counts = quarantine.counts(capture)
    assert len(events) == capture.record_count
    assert counts.quarantined == 0
    assert counts.rate == 0.0
    assert counts.by_reason == dict.fromkeys(PARSE_FAILURE_REASONS, 0)
    assert quarantine.stored(capture) == []


@pytest.mark.integration
def test_re_ingesting_a_capture_rewrites_the_same_rows_rather_than_doubling(
    migrated_engine: psycopg.Connection, tmp_path: Path
):
    """Replay is idempotent here for the same reason event ids are.

    The key is the ingestion identity plus the raw-record reference, and a
    RisingWave INSERT onto an existing key is an upsert — so a capture replayed
    twice leaves the same one row, and the quarantine rate does not drift upward
    with every replay.
    """
    capture = capture_of(tmp_path / "twice.jsonl", [flat_line(0), b"not json"])
    quarantine = quarantine_for(migrated_engine)

    first = list(normalizer().ingest_capture(capture, quarantine))
    before = quarantine.stored(capture)
    second = list(normalizer().ingest_capture(capture, quarantine))
    after = quarantine.stored(capture)

    assert first == second
    assert before == after
    assert quarantine.counts(capture).quarantined == 1


@pytest.mark.integration
def test_two_tenants_quarantining_one_capture_do_not_overwrite_each_other(
    migrated_engine: psycopg.Connection, tmp_path: Path
):
    """The reason tenant and sensor are in the key as well as the reference.

    An INSERT onto an existing primary key in RisingWave overwrites the row and
    raises nothing, so a key of capture-plus-offset alone would make one
    deployment's quarantine row silently replace another's — a cross-tenant
    overwrite that looks like it is working.
    """
    capture = capture_of(tmp_path / "shared.jsonl", [b"not json"])
    theirs = quarantine_for(migrated_engine, HELENA_TENANT="another-tenant")
    ours = quarantine_for(migrated_engine)

    list(normalizer().ingest_capture(capture, ours))
    list(normalizer(HELENA_TENANT="another-tenant").ingest_capture(capture, theirs))

    assert [row.tenant for row in ours.stored(capture)] == ["tenant-under-test"]
    assert [row.tenant for row in theirs.stored(capture)] == ["another-tenant"]
    assert ours.counts(capture).quarantined == 1
    assert theirs.counts(capture).quarantined == 1


@pytest.mark.integration
def test_quarantining_under_another_identity_is_refused(
    migrated_engine: psycopg.Connection, tmp_path: Path
):
    """A refused record is filed under the identity that read it, or not at all.

    A `Quarantine` built for another tenant would file this deployment's
    refusals against another producer's name — a defaulted tenant arriving
    through a second door.
    """
    capture = capture_of(tmp_path / "wrong.jsonl", [b"not json"])
    theirs = quarantine_for(migrated_engine, HELENA_SENSOR="another-sensor")

    with pytest.raises(ConfigurationError) as refusal:
        list(normalizer().ingest_capture(capture, theirs))
    assert "another-sensor" in str(refusal.value)
    assert theirs.stored(capture) == []


def test_a_counter_that_does_not_reconcile_is_refused():
    """The reconciliation is evaluated, not asserted in a comment.

    `concept/instruction.md` §7 requires produced-versus-materialised counts to
    reconcile; a count object that could hold three numbers that contradict each
    other would make the requirement unfalsifiable.
    """
    whole = dict.fromkeys(PARSE_FAILURE_REASONS, 0)

    with pytest.raises(ValidationError):
        QuarantineCounts(records=10, quarantined=1, by_reason=whole)

    with pytest.raises(ValidationError):
        QuarantineCounts(
            records=10, quarantined=1, by_reason={"malformed_json": 1}
        )

    with pytest.raises(ValidationError):
        QuarantineCounts(
            records=1, quarantined=2, by_reason={**whole, "malformed_json": 2}
        )


def test_no_rate_is_reported_over_a_capture_with_no_records():
    """0.0 would read as "nothing was refused"; nothing was read."""
    empty = QuarantineCounts(
        records=0, quarantined=0, by_reason=dict.fromkeys(PARSE_FAILURE_REASONS, 0)
    )
    assert empty.normalized == 0
    with pytest.raises(ValueError):
        empty.rate


# --- The ingest topic, and the events it produces ---------------------------
#
# `concept/03-architecture.md`: *ingest topic(s), in — one flow record per
# message, over the Kafka wire protocol*, and *the durable record for replay is
# the retained source capture, replayed through the same ingestion path as live
# traffic so that replay exercises the real pipeline rather than a parallel one.*
#
# So these tests publish a real capture to a real topic on the pinned broker,
# consume it back through `helena.broker`, and store what comes out in a real
# engine. A test that handed the normalizer a list of messages would demonstrate
# the loop and none of the things that actually go wrong between two processes:
# a header that did not survive, a byte that changed, a record that never
# arrived.


def event_store_for(
    connection: psycopg.Connection, **overrides: str
) -> EventStore:
    return EventStore(connection=connection, identity=settings(**overrides).identity)


def publish(bootstrap: str, topic: str, capture: Capture) -> int:
    """Publish every record of `capture` to `topic`. Returns records published.

    The producer side of the ingest contract, written out here rather than in
    the package: the replay driver that will own it is the next increment
    (`prds/prd.json` task 11), and a helper in the package with only a test
    calling it would be structure ahead of the increment that needs it.
    """
    with BrokerProducer(bootstrap) as producer:
        producer.create_topic(topic)
        published = 0
        for offset, line in read_capture(capture):
            message = IngestMessage(
                raw_record=RawRecordReference(
                    capture_sha256=capture.sha256, record_offset=offset
                ),
                payload=line,
            )
            producer.publish(topic, message.payload, message.headers())
            published += 1
    return published


def consumed_messages(bootstrap: str, topic: str) -> list[IngestMessage]:
    with BrokerConsumer(bootstrap) as consumer:
        return [
            IngestMessage.from_headers(value=message.value, headers=message.headers)
            for message in consumer.consume(topic, idle_timeout=3.0)
        ]


def ingest_topic_name() -> str:
    """A topic of this test's own. The pinned broker is consume-once.

    A shared topic would make one test's leftovers another test's input, and
    there is no way to reset one — a topic drained once is empty, and a topic
    that was not drained still holds what the last run put there.
    """
    return f"helena-ingest-{uuid4().hex[:12]}"


def test_the_ingest_message_carries_the_reference_in_its_headers():
    """The wire contract: the value is the record, untouched; the headers locate it."""
    line = SAMPLE_LINES[0]
    message = IngestMessage(
        raw_record=RawRecordReference(capture_sha256="a" * 64, record_offset=17),
        payload=line,
    )
    assert message.payload == line, "the record is not repackaged"
    assert message.headers() == {
        INGEST_HEADER_CAPTURE: (b"a" * 64),
        INGEST_HEADER_OFFSET: b"17",
    }
    assert (
        IngestMessage.from_headers(value=line, headers=message.headers()) == message
    )


@pytest.mark.parametrize(
    "headers, expected",
    [
        pytest.param({}, INGEST_HEADER_CAPTURE, id="no headers at all"),
        pytest.param(
            {INGEST_HEADER_CAPTURE: b"a" * 64},
            INGEST_HEADER_OFFSET,
            id="no offset",
        ),
        pytest.param(
            {INGEST_HEADER_CAPTURE: b"a" * 64, INGEST_HEADER_OFFSET: b"twelve"},
            "decimal integer",
            id="offset is not a number",
        ),
        pytest.param(
            {INGEST_HEADER_CAPTURE: b"not-a-digest", INGEST_HEADER_OFFSET: b"0"},
            "do not address a raw record",
            id="capture is not a digest",
        ),
        pytest.param(
            {INGEST_HEADER_CAPTURE: b"a" * 64, INGEST_HEADER_OFFSET: b"-1"},
            "do not address a raw record",
            id="offset is negative",
        ),
    ],
)
def test_a_message_with_no_usable_reference_is_refused_naming_the_header(
    headers: dict[str, bytes], expected: str
):
    """Refused, not guessed — and the message names what an operator must fix.

    This is the one refusal in the ingest path that is not a quarantine row, and
    the reason is structural rather than a policy choice: a quarantine row is
    *keyed* by the capture and offset, so a message that carries neither has no
    row to be written to. See `IngestMessageError`.
    """
    with pytest.raises(IngestMessageError) as refused:
        IngestMessage.from_headers(value=b'{"id":"udp.0"}', headers=headers)
    assert expected in str(refused.value)


def test_a_refused_message_is_not_a_parse_failure():
    """Two refusals that must not be collapsed into one.

    A `ParseFailure` is a statement about a *record* — the producer sent
    something this contract refuses, and it is quarantined and counted. An
    `IngestMessageError` is a statement about a *message* — whatever this is, it
    is not addressed to the ingest topic's contract at all. Collapsing them would
    file a misconfigured producer's traffic as this producer's drift.
    """
    line = b"not json at all"

    # The same bytes, through the two doors. As a record it is a typed value the
    # caller has to handle and the store keeps; as a whole message it is a
    # refusal that stops the run.
    failure = FlowJsonAdapter().parse(line)
    assert isinstance(failure, ParseFailure)
    assert failure.reason == "malformed_json"

    with pytest.raises(IngestMessageError):
        IngestMessage.from_headers(value=line, headers={})

    # And the bytes being unparseable is not what makes a message refused: a
    # message carrying the same unparseable record *with* a reference is
    # accepted at the wire boundary and refused at the contract, as a
    # quarantinable record.
    reference = RawRecordReference(capture_sha256="b" * 64, record_offset=0)
    message = IngestMessage(raw_record=reference, payload=line)
    accepted = IngestMessage.from_headers(
        value=line, headers=message.headers()
    )
    assert accepted == message
    assert isinstance(normalizer().normalize_message(accepted), ParseFailure)


@pytest.mark.integration
def test_the_event_constants_name_what_the_migration_creates(
    migrated_engine: psycopg.Connection,
):
    """The two copies of each name, asserted equal by asking the engine."""
    rows = migrated_engine.execute(
        "SELECT table_name, table_type FROM information_schema.tables "
        "WHERE table_schema = current_schema() AND table_name IN (%s, %s)",
        (NORMALIZED_EVENTS_TABLE, INGEST_COUNTS_VIEW),
    ).fetchall()
    assert sorted(rows) == sorted(
        [(NORMALIZED_EVENTS_TABLE, "BASE TABLE"), (INGEST_COUNTS_VIEW, "VIEW")]
    )


@pytest.mark.integration
def test_a_capture_published_to_the_topic_is_consumed_normalized_and_stored(
    migrated_engine: psycopg.Connection, broker_bootstrap: str
):
    """The whole ingress path over the real wire, on all 62 real records.

    Published to the broker, consumed back, normalized, written to the engine,
    and read out again through the contract that wrote them. What it
    demonstrates that a list of messages could not: the record survives the wire
    byte for byte, the raw-record reference survives in the headers, and the
    observation survives JSONB — including the two halves of *absence is not
    emptiness*, which the last two assertions check on real records.
    """
    capture = describe_capture(SAMPLE)
    topic = ingest_topic_name()
    published = publish(broker_bootstrap, topic, capture)
    assert published == capture.record_count == 62

    events = event_store_for(migrated_engine)
    quarantine = quarantine_for(migrated_engine)
    consumed = normalizer().ingest_messages(
        consumed_messages(broker_bootstrap, topic), events, quarantine
    )

    assert consumed == 62
    stored = events.stored(capture)
    assert len(stored) == 62
    assert [event.identity.raw_record.record_offset for event in stored] == list(
        range(62)
    )

    # The records themselves, compared against the file rather than against
    # what the normalizer happened to produce.
    assert [event.observation.as_supplied() for event in stored] == [
        json.loads(line) for line in SAMPLE_LINES
    ]

    # Absence is not emptiness, both halves, over the store. `tcp.24` observed
    # TLS with no ALPN negotiated; 32 records observed no DNS at all.
    by_id = {event.observation.id: event for event in stored}
    assert by_id["tcp.24"].observation.tls.alpn == []
    assert "alpn" in by_id["tcp.24"].observation.as_supplied()["tls"]
    assert sum(event.observation.dns is None for event in stored) == 32
    without_dns = [
        event for event in stored if event.observation.dns is None
    ]
    assert len(without_dns) == 32
    assert not any(
        "dns" in event.observation.as_supplied() for event in without_dns
    ), "an unobserved layer came back as a null key rather than an absent one"


@pytest.mark.integration
def test_an_event_off_the_wire_is_identical_to_one_read_from_the_file(
    migrated_engine: psycopg.Connection, broker_bootstrap: str
):
    """One stamping path, whichever door the record came in through.

    `concept/03-architecture.md` requires replay to go through the same
    ingestion path as live traffic. If the wire path stamped anything of its own
    — a different id, a different schema version — the replay guarantee would be
    about a path nothing else uses.
    """
    capture = fixture_capture(LAYERS_CAPTURE)
    topic = ingest_topic_name()
    publish(broker_bootstrap, topic, capture)

    events = event_store_for(migrated_engine)
    normalizer().ingest_messages(
        consumed_messages(broker_bootstrap, topic),
        events,
        quarantine_for(migrated_engine),
    )

    from_the_file = list(normalizer().normalize_capture(capture))
    assert events.stored(capture) == from_the_file


@pytest.mark.integration
def test_a_refused_record_off_the_wire_quarantines_and_the_counters_reconcile(
    migrated_engine: psycopg.Connection, broker_bootstrap: str, tmp_path: Path
):
    """The counters, over a capture that produces both kinds of row.

    Four numbers from four places — the file, the run, `helena_ingest_counts`
    and `helena_ingest_quarantine_counts` — and `IngestCounts` refuses a set
    that does not add up. This is `concept/instruction.md` §7's *produced-versus-
    materialised counts reconcile*, evaluated rather than claimed.
    """
    capture = capture_of(
        tmp_path / "mixed.jsonl",
        [flat_line(0), b"not json at all", _drifted(flat_line(2), unexpected=1)],
    )
    topic = ingest_topic_name()
    publish(broker_bootstrap, topic, capture)

    events = event_store_for(migrated_engine)
    quarantine = quarantine_for(migrated_engine)
    consumed = normalizer().ingest_messages(
        consumed_messages(broker_bootstrap, topic), events, quarantine
    )

    counts = ingest_counts(
        capture=capture, consumed=consumed, events=events, quarantine=quarantine
    )
    assert counts.records == 3
    assert counts.consumed == 3
    assert counts.normalized == 1
    assert counts.quarantine.quarantined == 2
    assert counts.quarantine.by_reason == {
        "malformed_json": 1,
        "contract_violation": 1,
        "not_this_format": 0,
    }
    assert counts.complete is True

    # The engine-side count and the subtraction `QuarantineCounts` has been
    # making since task 09 have to agree, not replace each other.
    assert counts.normalized == counts.quarantine.normalized


@pytest.mark.integration
def test_a_run_that_lost_records_between_the_topic_and_the_store_does_not_reconcile(
    migrated_engine: psycopg.Connection, tmp_path: Path
):
    """The failure the counter exists for, made to happen.

    The broker keeps nothing, so a record that was published and never consumed
    is simply gone — and the only thing that can notice is the capture's own
    record count. `complete` is False rather than an exception: a partial run is
    a fact about the run, and the file is still there to replay.
    """
    capture = capture_of(tmp_path / "three.jsonl", [flat_line(i) for i in range(3)])
    events = event_store_for(migrated_engine)
    quarantine = quarantine_for(migrated_engine)

    # Two of the three records reach the store; the third never arrived.
    consumed = normalizer().ingest_messages(
        [
            IngestMessage(
                raw_record=RawRecordReference(
                    capture_sha256=capture.sha256, record_offset=offset
                ),
                payload=line,
            )
            for offset, line in list(read_capture(capture))[:2]
        ],
        events,
        quarantine,
    )
    counts = ingest_counts(
        capture=capture, consumed=consumed, events=events, quarantine=quarantine
    )
    assert counts.consumed == 2
    assert counts.records == 3
    assert counts.complete is False

    # And a set that claims more than it consumed is refused outright.
    with pytest.raises(ValidationError):
        IngestCounts(
            records=3,
            consumed=2,
            normalized=3,
            quarantine=QuarantineCounts(
                records=3,
                quarantined=0,
                by_reason=dict.fromkeys(PARSE_FAILURE_REASONS, 0),
            ),
        )
    with pytest.raises(ValidationError):
        IngestCounts(
            records=3,
            consumed=4,
            normalized=4,
            quarantine=QuarantineCounts(
                records=3,
                quarantined=0,
                by_reason=dict.fromkeys(PARSE_FAILURE_REASONS, 0),
            ),
        )


@pytest.mark.integration
def test_ingesting_the_same_capture_twice_leaves_identical_rows(
    migrated_engine: psycopg.Connection, tmp_path: Path
):
    """Replay is idempotent, on the accepted side as well as the refused one.

    Every assigned field is derived from the capture, the offset and the
    configured identity, so the second run rewrites byte-identical rows. An
    INSERT onto an existing key in RisingWave is an upsert, which is what makes
    that a rewrite rather than a duplicate.
    """
    capture = capture_of(tmp_path / "twice.jsonl", [flat_line(0), flat_line(1)])
    events = event_store_for(migrated_engine)
    quarantine = quarantine_for(migrated_engine)
    messages = [
        IngestMessage(
            raw_record=RawRecordReference(
                capture_sha256=capture.sha256, record_offset=offset
            ),
            payload=line,
        )
        for offset, line in read_capture(capture)
    ]

    normalizer().ingest_messages(messages, events, quarantine)
    first = events.stored(capture)
    normalizer().ingest_messages(messages, events, quarantine)
    second = events.stored(capture)

    assert first == second
    assert len(second) == 2
    assert events.normalized(capture) == 2


@pytest.mark.integration
def test_storing_an_event_under_another_identity_is_refused(
    migrated_engine: psycopg.Connection, tmp_path: Path
):
    """An observation is filed under the identity that read it, or not at all.

    The accepted-side half of the rule `ingest_capture` already applies to
    quarantine. Without it, one deployment's events would land on another's
    primary key and silently overwrite them.
    """
    capture = capture_of(tmp_path / "ours.jsonl", [flat_line(0)])
    theirs = event_store_for(migrated_engine, HELENA_TENANT="another-tenant")
    message = IngestMessage(
        raw_record=RawRecordReference(
            capture_sha256=capture.sha256, record_offset=0
        ),
        payload=flat_line(0),
    )

    with pytest.raises(ConfigurationError) as refusal:
        normalizer().ingest_messages([message], theirs, quarantine_for(migrated_engine))
    assert "another-tenant" in str(refusal.value)
    assert theirs.stored(capture) == []


@pytest.mark.integration
def test_two_deployments_ingesting_one_capture_keep_their_own_events(
    migrated_engine: psycopg.Connection, tmp_path: Path
):
    """The key carries the identity, so neither run overwrites the other."""
    capture = capture_of(tmp_path / "shared.jsonl", [flat_line(0)])
    message = IngestMessage(
        raw_record=RawRecordReference(
            capture_sha256=capture.sha256, record_offset=0
        ),
        payload=flat_line(0),
    )
    ours = event_store_for(migrated_engine)
    theirs = event_store_for(migrated_engine, HELENA_TENANT="another-tenant")

    normalizer().ingest_messages([message], ours, quarantine_for(migrated_engine))
    normalizer(HELENA_TENANT="another-tenant").ingest_messages(
        [message],
        theirs,
        quarantine_for(migrated_engine, HELENA_TENANT="another-tenant"),
    )

    assert [event.identity.tenant for event in ours.stored(capture)] == [
        "tenant-under-test"
    ]
    assert [event.identity.tenant for event in theirs.stored(capture)] == [
        "another-tenant"
    ]
    assert ours.stored(capture)[0].identity.event_id != (
        theirs.stored(capture)[0].identity.event_id
    )


def test_consuming_a_record_twice_is_not_reported_as_a_lost_record():
    """Two failures that look identical in the arithmetic, kept apart by name.

    Storing an event twice is an upsert, so `normalized` does not grow — which
    makes a double-consumed run and a run that lost records produce the same
    three numbers. Replay is what makes the first one reachable, so it is
    checked first and says what it is; an operator sent looking for a lost
    record would be looking for a broker fault that is not there.
    """

    def set_of(**overrides: int) -> dict[str, object]:
        return {
            "records": 3,
            "consumed": 3,
            "normalized": 3,
            "quarantine": QuarantineCounts(
                records=3,
                quarantined=0,
                by_reason=dict.fromkeys(PARSE_FAILURE_REASONS, 0),
            ),
            **overrides,
        }

    with pytest.raises(ValidationError, match="more than once"):
        IngestCounts(**set_of(consumed=6))
    with pytest.raises(ValidationError, match="reached neither store"):
        IngestCounts(**set_of(normalized=2))


# --- Replay: the retained capture, back through the live path ---------------
#
# `concept/07-principles.md`: *the durable record is the retained capture,
# replayed through the same ingestion path as live traffic so replay exercises
# the real pipeline rather than a parallel one.*
#
# Two claims, and they need different tests. That replay *publishes the capture*
# is a fact about the wire, checked by reading the topic back. That it goes
# through *the same path* is a fact about the rows: the events a replay leaves
# in the store are compared against the events the same capture produces read
# straight off disk, so a second normalization path would have to produce
# byte-identical rows to escape notice.


@pytest.mark.parametrize("rate", [0.0, -1.0], ids=["zero", "negative"])
def test_a_replay_rate_that_publishes_nothing_is_refused(rate: float):
    """Refused before the topic is created — which is why `None` is the producer.

    A rate of zero is not "as fast as possible"; it is a run that never
    finishes. Reading it as the unpaced case would be the silent default
    `concept/instruction.md` §6 names, one layer up from configuration.
    """
    with pytest.raises(ValueError, match="publish"):
        publish_capture(
            fixture_capture(LAYERS_CAPTURE), None, "helena-ingest-never", rate=rate
        )


@pytest.mark.integration
def test_replay_publishes_every_record_of_a_capture_in_the_wire_form(
    broker_bootstrap: str,
):
    """Every record, in file order, with the reference the capture addresses it by."""
    capture = fixture_capture(LAYERS_CAPTURE)
    topic = ingest_topic_name()

    with BrokerProducer(broker_bootstrap) as producer:
        published = publish_capture(capture, producer, topic)

    assert published == capture.record_count
    with BrokerConsumer(broker_bootstrap) as consumer:
        messages = list(consume_ingest_topic(consumer, topic, idle_timeout=3.0))
    assert [
        (message.raw_record.record_offset, message.payload) for message in messages
    ] == list(read_capture(capture))
    assert {message.raw_record.capture_sha256 for message in messages} == {
        capture.sha256
    }


@pytest.mark.integration
def test_replay_paces_at_the_configured_rate(broker_bootstrap: str, tmp_path: Path):
    """The rate is a floor on the run, and the unpaced control says it is the rate.

    Without the control this measures nothing: a slow broker would satisfy the
    floor on its own. Both topics are created before the clock starts, so
    neither number includes a `CreateTopics` round trip.
    """
    capture = capture_of(
        tmp_path / "paced.jsonl", [flat_line(offset) for offset in range(5)]
    )
    rate = 2.5
    floor = (capture.record_count - 1) / rate
    paced_topic, control_topic = ingest_topic_name(), ingest_topic_name()

    with BrokerProducer(broker_bootstrap) as producer:
        producer.create_topic(paced_topic)
        producer.create_topic(control_topic)
        started = time.monotonic()
        publish_capture(capture, producer, paced_topic, rate=rate)
        paced = time.monotonic() - started
        started = time.monotonic()
        publish_capture(capture, producer, control_topic)
        unpaced = time.monotonic() - started

    assert paced >= floor, f"{capture.record_count} records at {rate}/s took {paced}s"
    assert unpaced < floor, (
        f"the unpaced control took {unpaced}s, which is longer than the paced "
        f"floor of {floor}s — this comparison says nothing about the pacer"
    )


@pytest.mark.integration
def test_a_capture_replayed_twice_produces_identical_rows(
    migrated_engine: psycopg.Connection, broker_bootstrap: str, tmp_path: Path
):
    """Both stores, over the wire, twice: the same rows and the same counters.

    The capture holds a record the adapter refuses, so the second replay has to
    reproduce the quarantine row as well as the events — every assigned field on
    both sides is derived from the capture, the offset and the configured
    identity, and an INSERT onto an existing key in RisingWave is an upsert, so
    a second run rewrites rather than duplicates.

    Each replay gets its own topic. The broker's reclaim after a drain is
    asynchronous (measured, task 10), so reusing one topic would sometimes hand
    the second run the first run's records.
    """
    capture = capture_of(
        tmp_path / "replayed.jsonl", [flat_line(0), b'{"id":', flat_line(1)]
    )
    events = event_store_for(migrated_engine)
    quarantine = quarantine_for(migrated_engine)

    def replay() -> tuple[list[NormalizedEvent], list[QuarantinedRecord], IngestCounts]:
        topic = ingest_topic_name()
        with BrokerProducer(broker_bootstrap) as producer:
            published = publish_capture(capture, producer, topic)
        with BrokerConsumer(broker_bootstrap) as consumer:
            consumed = normalizer().ingest_messages(
                consume_ingest_topic(consumer, topic, idle_timeout=3.0),
                events,
                quarantine,
            )
        assert published == consumed == capture.record_count
        return (
            events.stored(capture),
            quarantine.stored(capture),
            ingest_counts(
                capture=capture,
                consumed=consumed,
                events=events,
                quarantine=quarantine,
            ),
        )

    first = replay()
    second = replay()

    assert first == second
    stored_events, quarantined, counts = second
    offsets = [event.identity.raw_record.record_offset for event in stored_events]
    assert offsets == [0, 2]
    assert [row.raw_record.record_offset for row in quarantined] == [1]
    assert counts.normalized == 2
    assert counts.quarantine.quarantined == 1
    assert counts.complete


@pytest.mark.integration
def test_a_replayed_capture_produces_the_rows_the_file_path_produces(
    migrated_engine: psycopg.Connection, broker_bootstrap: str, tmp_path: Path
):
    """No parallel code path, stated as rows rather than as an assertion about imports.

    The left side went through a broker, a header decode and a store; the right
    side is the same capture read off disk. One adapter, one `_stamp`, so they
    are the same events or the replay path is a second implementation.
    """
    capture = capture_of(
        tmp_path / "same.jsonl", [flat_line(offset) for offset in range(4)]
    )
    topic = ingest_topic_name()
    events = event_store_for(migrated_engine)

    with BrokerProducer(broker_bootstrap) as producer:
        publish_capture(capture, producer, topic)
    with BrokerConsumer(broker_bootstrap) as consumer:
        normalizer().ingest_messages(
            consume_ingest_topic(consumer, topic, idle_timeout=3.0),
            events,
            quarantine_for(migrated_engine),
        )

    assert events.stored(capture) == list(normalizer().normalize_capture(capture))


@pytest.mark.integration
def test_replay_reports_produced_versus_materialized_counts(
    migrated_engine: psycopg.Connection, broker_bootstrap: str
):
    """The whole real sample, published and then counted out of the store."""
    capture = describe_capture(SAMPLE)
    topic = ingest_topic_name()
    events = event_store_for(migrated_engine)
    quarantine = quarantine_for(migrated_engine)

    with BrokerProducer(broker_bootstrap) as producer:
        published = publish_capture(capture, producer, topic)
    with BrokerConsumer(broker_bootstrap) as consumer:
        consumed = normalizer().ingest_messages(
            consume_ingest_topic(consumer, topic, idle_timeout=3.0),
            events,
            quarantine,
        )
    counts = ingest_counts(
        capture=capture, consumed=consumed, events=events, quarantine=quarantine
    )

    assert published == len(SAMPLE_LINES)
    assert counts.records == counts.consumed == counts.normalized == published
    assert counts.quarantine.quarantined == 0
    assert counts.complete


# --- The command that drives a replay ---------------------------------------
#
# `scripts/replay_capture.py` is run the way an operator runs it — through
# `uv run`, in a subprocess, resolving its configuration from the environment —
# because what a wrapper gets wrong is argument handling and exit status, and
# calling `main()` in-process would test neither.


def replay_command(*arguments: str, **environment: str) -> subprocess.CompletedProcess:
    """`scripts/replay_capture.py` in a subprocess, with an explicit environment.

    The process environment wins over `.env` (`helena.config.Settings.load`), so
    the values here are what the command resolves — a run that fell through to
    the developer's own `.env` would publish to the real ingest topic.
    """
    return subprocess.run(
        ["uv", "run", "scripts/replay_capture.py", *arguments],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        timeout=300,
        env={**os.environ, **ENVIRONMENT, **environment},
    )


def test_the_replay_command_refuses_a_capture_it_cannot_find():
    """Nothing is published, and the message says where it looked."""
    result = replay_command("--captures", str(FIXTURE_CAPTURES), "0" * 64)
    assert result.returncode == 1
    assert "holds no capture" in result.stderr


def test_the_replay_command_refuses_a_rate_that_publishes_nothing():
    result = replay_command(
        "--captures", str(FIXTURE_CAPTURES), "0" * 64, "--rate", "0"
    )
    assert result.returncode == 2
    assert "greater than zero" in result.stderr


@pytest.mark.integration
def test_the_replay_command_publishes_the_capture_it_is_given(broker_bootstrap: str):
    """The command, end to end on the producer side, against the pinned broker."""
    capture = fixture_capture(LAYERS_CAPTURE)
    topic = ingest_topic_name()

    result = replay_command(
        "--captures",
        str(FIXTURE_CAPTURES),
        capture.sha256,
        KAFKA_BOOTSTRAP_SERVERS=broker_bootstrap,
        HELENA_INGEST_TOPIC=topic,
    )

    assert result.returncode == 0, result.stderr
    expected = f"published {capture.record_count} of {capture.record_count}"
    assert expected in result.stdout
    with BrokerConsumer(broker_bootstrap) as consumer:
        messages = list(consume_ingest_topic(consumer, topic, idle_timeout=3.0))
    assert [
        (message.raw_record.record_offset, message.payload) for message in messages
    ] == list(read_capture(capture))
