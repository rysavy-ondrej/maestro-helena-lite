"""Tests for helena.context. Mirrors src/helena/context.py.

The component's source is SQL — `concept/03-architecture.md` makes the engine's
view definitions project source in their own right — so this file tests it the
only way that means anything: by applying the migrations to a throwaway engine,
putting real records through the real ingestion path, and asking the views what
they hold. Reading `sql/migrations/0005_flatten_layer.sql` or
`sql/migrations/0006_host_context.sql` and agreeing with them would find the
comment, not the view.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

import psycopg
import pytest
from pydantic import ValidationError

import helena.context
from helena.config import Settings
from helena.normalizer import (
    EVENT_SCHEMA_VERSION,
    Capture,
    EventStore,
    NormalizedEvent,
    Normalizer,
    describe_capture,
    scan_captures,
)
from helena.context import (
    COMPLETENESS_VALUES,
    FROZEN_CONTEXT_TABLE,
    LIVE_HOST_CONTEXT_VIEW,
    RETAINED_CONTEXT_ENTITIES_VIEW,
    RETAINED_HOST_CONTEXT_VIEW,
    RETENTION_HORIZON,
    RETENTION_HORIZON_VIEW,
    RETENTION_REJECTIONS_VIEW,
    ContextOutsideRetention,
    ContextStore,
    FrozenContext,
    RetentionRejections,
)
from helena.versions import AGGREGATION_VERSION, AGGREGATION_VERSION_VIEW

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SAMPLE = PROJECT_ROOT / "data" / "ingest" / "flow-sample.jsonl"
FIXTURE_CAPTURES = Path(__file__).resolve().parent / "fixtures" / "captures"

# The layer-coverage capture: ten real records holding every layer combination
# the sample contains, including the flow with no application layer at all and
# the TLS observation whose ALPN is observed and empty. See the README beside it.
LAYERS_CAPTURE = "ace6ca33f7bf8aa949f79124abf33fc115cfd0909e9dea798f4762cf87af8318"

# The one-record capture. Its single record is byte-for-byte offset 8 of the
# capture above, under a different capture hash — so ingesting it after the
# layer capture is a second observation of the same traffic, not a replay.
ONE_RECORD_CAPTURE = (
    "6e361f1b99b88a8b3e77aeec4b630abff5e71396087a485eea03db3bb1856e64"
)

# The same environment shape tests/test_normalizer.py uses, and for the same
# reason: values that are obviously not credentials, so a leak into a pytest
# failure message would be a nuisance rather than an incident.
ENVIRONMENT = {
    "LLM_URL": "http://model.invalid/v1",
    "LLM_TOKEN": "token-under-test",
    "LLM_MODEL": "model-under-test",
    "HELENA_TENANT": "tenant-under-test",
    "HELENA_SENSOR": "sensor-under-test",
    "HELENA_INPUT_FORMAT": "flow-json",
    "ABUSECH_AUTH_KEY": "abusech-key-under-test",
    "VIRUSTOTAL_AUTH_KEY": "virustotal-key-under-test",
    "RISINGWAVE_DSN": "postgresql://root@localhost:4566/dev",
    "KAFKA_BOOTSTRAP_SERVERS": "localhost:9092",
    "HELENA_INGEST_TOPIC": "helena.ingest",
}

# The flatten layer, as sql/migrations/0005_flatten_layer.sql declares it: the
# object, and the shape a reader gets. This is the second copy of the layer's
# interface — the file is the first — and `test_every_flatten_object_has_the
# _shape_it_declares` asserts them equal by asking the engine, which is the only
# comparison that can fail.
FLATTEN_IDENTITY = (
    ("tenant", "character varying"),
    ("sensor", "character varying"),
    ("capture_sha256", "character varying"),
    ("record_offset", "bigint"),
    ("event_id", "character varying"),
    ("schema_version", "character varying"),
)

FLATTEN_SHAPES = {
    "helena_flatten_flows": FLATTEN_IDENTITY
    + (
        ("record_id", "character varying"),
        ("flow_start", "timestamp with time zone"),
        ("duration_seconds", "double precision"),
        ("proto", "character varying"),
        ("src_address", "character varying"),
        ("dst_address", "character varying"),
        ("bytes_sent", "bigint"),
        ("bytes_received", "bigint"),
        ("packets_sent", "bigint"),
        ("packets_received", "bigint"),
        ("transport", "character varying"),
        ("src_port", "integer"),
        ("dst_port", "integer"),
    ),
    "helena_flatten_dns": FLATTEN_IDENTITY
    + (
        ("rcode", "integer"),
        ("query_count", "integer"),
        ("response_count", "integer"),
    ),
    "helena_flatten_dns_queries": FLATTEN_IDENTITY
    + (
        ("query_index", "bigint"),
        ("query_name", "character varying"),
        ("query_type", "character varying"),
    ),
    "helena_flatten_dns_responses": FLATTEN_IDENTITY
    + (
        ("response_index", "bigint"),
        ("section", "character varying"),
        ("response_name", "character varying"),
        ("record_type", "character varying"),
        ("ttl_seconds", "bigint"),
        ("record_value", "character varying"),
    ),
    "helena_flatten_tls": FLATTEN_IDENTITY
    + (
        ("server_name", "character varying"),
        ("client_version", "character varying"),
        ("server_version", "character varying"),
        ("server_cipher", "character varying"),
        ("client_ja3", "character varying"),
        ("client_ja4", "character varying"),
        ("server_ja3", "character varying"),
        ("server_ja4", "character varying"),
        ("alpn_count", "integer"),
        ("record_count", "integer"),
    ),
    "helena_flatten_http": FLATTEN_IDENTITY
    + (
        ("protocol", "character varying"),
        ("request_count", "integer"),
        ("response_count", "integer"),
    ),
    "helena_flatten_http_requests": FLATTEN_IDENTITY
    + (
        ("protocol", "character varying"),
        ("request_index", "bigint"),
        ("method", "character varying"),
        ("uri", "character varying"),
        ("user_agent", "character varying"),
        ("exchange_number", "integer"),
        ("content_type", "character varying"),
        ("content_length", "character varying"),
    ),
    "helena_flatten_http_responses": FLATTEN_IDENTITY
    + (
        ("protocol", "character varying"),
        ("response_index", "bigint"),
        ("status_code", "character varying"),
        ("exchange_number", "integer"),
        ("content_type", "character varying"),
        ("content_length", "character varying"),
        ("server", "character varying"),
    ),
}

FLATTEN_OBJECTS = tuple(FLATTEN_SHAPES)

# The signal layer, as sql/migrations/0006_host_context.sql declares it. The
# same deliberate friction as FLATTEN_SHAPES above: this is the second copy of
# the object's interface, and adding a column to the view means editing here
# too. There is no verdict, classification, confidence, severity or score
# column, and `test_the_host_context_carries_no_verdict` is what says so.
HOST_CONTEXT = "helena_signal_host_context"

HOST_CONTEXT_SHAPE = (
    ("context_id", "character varying"),
    ("tenant", "character varying"),
    ("sensor", "character varying"),
    ("host", "character varying"),
    ("window_start", "timestamp with time zone"),
    ("window_end", "timestamp with time zone"),
    ("flow_count", "bigint"),
    ("duration_seconds", "double precision"),
    ("bytes_sent", "bigint"),
    ("bytes_received", "bigint"),
    ("packets_sent", "bigint"),
    ("packets_received", "bigint"),
    ("aggregation_version", "character varying"),
)

# The entity objects, as sql/migrations/0007_context_entities.sql declares them,
# and the shape a reader of the row gets. Third copy of the deliberate friction
# FLATTEN_SHAPES and HOST_CONTEXT_SHAPE already carry: adding a column to the
# view means editing this tuple, and the engine is what the two are compared
# against.
ENTITY_OBSERVATIONS = "helena_signal_entity_observations"
CONTEXT_ENTITIES = "helena_signal_context_entities"

CONTEXT_ENTITIES_SHAPE = (
    ("context_id", "character varying"),
    ("tenant", "character varying"),
    ("sensor", "character varying"),
    ("host", "character varying"),
    ("window_start", "timestamp with time zone"),
    ("window_end", "timestamp with time zone"),
    ("entity_type", "character varying"),
    ("entity_value", "character varying"),
    ("fingerprint_algorithm", "character varying"),
    ("observed_as_flow_destination", "boolean"),
    ("observed_in_dns_query", "boolean"),
    ("observed_in_dns_response", "boolean"),
    ("observed_in_tls", "boolean"),
    ("observed_in_http", "boolean"),
    ("observed_flow_count", "bigint"),
    ("observed_bytes_sent", "bigint"),
    ("observed_bytes_received", "bigint"),
    ("observed_packets_sent", "bigint"),
    ("observed_packets_received", "bigint"),
    ("aggregation_version", "character varying"),
)

# The five layer flags, in the order they sit on the row. `_observations` names
# one of these per extracted value, so what the view OR's together and what the
# expectation below OR's together are the same vocabulary.
ENTITY_FLAGS = (
    "observed_as_flow_destination",
    "observed_in_dns_query",
    "observed_in_dns_response",
    "observed_in_tls",
    "observed_in_http",
)

WINDOW_SECONDS = 300


def test_module_imports():
    assert helena.context.__doc__


# --- Putting real records into a throwaway engine -------------------------


def settings(**overrides: str) -> Settings:
    """Configuration resolved from an explicit environment, never the machine's."""
    return Settings.load(environ={**ENVIRONMENT, **overrides}, env_file=None)


def store_capture(
    connection: psycopg.Connection, capture: Capture, **overrides: str
) -> None:
    """Normalize every record of `capture` and store it, through the real path.

    Not an INSERT of hand-made rows: the flatten layer's whole job is to unpack
    what ingestion actually wrote, so a test that wrote its own JSONB would be
    testing the views against a guess about the table above them.
    """
    configured = settings(**overrides)
    normalizer = Normalizer.from_settings(configured)
    store = EventStore(connection=connection, identity=configured.identity)
    for result in normalizer.normalize_capture(capture):
        assert isinstance(result, NormalizedEvent), result
        store.record(result)
    connection.execute("FLUSH")


def layers_capture() -> Capture:
    return scan_captures(FIXTURE_CAPTURES)[LAYERS_CAPTURE]


def layers_records() -> list[dict]:
    path = FIXTURE_CAPTURES / f"{LAYERS_CAPTURE}.jsonl"
    return [json.loads(line) for line in path.read_bytes().splitlines()]


@pytest.fixture
def flattened(migrated_engine: psycopg.Connection) -> psycopg.Connection:
    """The ten-record layer-coverage capture, ingested and stored."""
    store_capture(migrated_engine, layers_capture())
    return migrated_engine


@pytest.fixture
def contexts(flattened: psycopg.Connection) -> psycopg.Connection:
    """The same ten records, read through the signal layer.

    The layer capture is the right input for this too: its nine flows before
    21:35:00Z and one after it are a single host across a window boundary, which
    is exactly the shape one host context per host per window has to get right.
    """
    return flattened


def _by_window(records: list[dict]) -> list[tuple[datetime, list[dict]]]:
    """`records` grouped by the window their start time falls in, in order.

    The window is computed from the record's own `ts` in Python — the same
    arithmetic `TUMBLE` does, written independently — so the expected values in
    a test come from the file rather than from a number someone wrote down.
    """
    grouped: dict[datetime, list[dict]] = {}
    for record in records:
        start = datetime.fromtimestamp(
            int(record["ts"] // WINDOW_SECONDS) * WINDOW_SECONDS, tz=timezone.utc
        )
        grouped.setdefault(start, []).append(record)
    return sorted(grouped.items())


def _context_id(
    tenant: str, sensor: str, host: str, window_start: datetime, version: str
) -> str:
    """The context id, recomputed from the parts the row carries.

    Written out here rather than imported, because a test that called the
    implementation would agree with it by construction. The parts are
    length-prefixed — `<utf8 byte length>:<bytes>` — which is the event id's
    encoding and for the same reason: an operator-supplied tenant can contain
    any delimiter, so `tenant='a'/sensor='b:c'` must not hash to the same bytes
    as `tenant='a:b'/sensor='c'`.
    """
    parts = (tenant, sensor, host, str(int(window_start.timestamp())), version)
    material = b"".join(
        f"{len(part.encode())}:".encode() + part.encode() for part in parts
    )
    return hashlib.sha256(material).hexdigest()


def rows(connection: psycopg.Connection, sql: str, *args: object) -> list[tuple]:
    # `args or None`: psycopg reads the query for placeholders as soon as any
    # parameter sequence is passed, and a bare `%` in a LIKE pattern is then a
    # malformed placeholder rather than a wildcard.
    return connection.execute(sql, args or None).fetchall()


def one(connection: psycopg.Connection, sql: str, *args: object) -> object:
    result = rows(connection, sql, *args)
    assert len(result) == 1, f"expected one row, got {len(result)}"
    return result[0][0]


# --- What the layer is: eight plain views over the source ------------------


@pytest.mark.integration
def test_every_flatten_object_is_a_plain_view(migrated_engine: psycopg.Connection):
    """The declaration in the migration file, checked against the engine.

    `concept/03-architecture.md`: do not materialize an intermediate that only
    feeds an aggregate. Every object here is that intermediate, so every one of
    them must come back a VIEW — a MATERIALIZED VIEW appearing in this list is
    42 % more disk for rows nothing reads, and it would be invisible without
    this assertion.
    """
    found = dict(
        rows(
            migrated_engine,
            "SELECT table_name, table_type FROM information_schema.tables "
            "WHERE table_schema = current_schema() "
            "AND table_name LIKE 'helena_flatten_%'",
        )
    )
    assert found == {name: "VIEW" for name in FLATTEN_OBJECTS}


@pytest.mark.integration
@pytest.mark.parametrize("view", FLATTEN_OBJECTS)
def test_every_flatten_object_has_the_shape_it_declares(
    migrated_engine: psycopg.Connection, view: str
):
    """Column names and types, in order, as the engine reports them."""
    shape = tuple(
        rows(
            migrated_engine,
            "SELECT column_name, data_type FROM information_schema.columns "
            "WHERE table_schema = current_schema() AND table_name = %s "
            "ORDER BY ordinal_position",
            view,
        )
    )
    assert shape == FLATTEN_SHAPES[view]


@pytest.mark.integration
@pytest.mark.parametrize("view", FLATTEN_OBJECTS)
def test_every_flatten_row_carries_the_whole_identity(
    flattened: psycopg.Connection, view: str
):
    """Tenant, sensor, capture reference, event id and schema version, on every row.

    An entity row that could not name its tenant would end the tenant seam
    (`concept/03-architecture.md`) at ingestion, and a row that could not name
    the capture it came from could not be replayed or cited.
    """
    capture = layers_capture()
    identities = rows(
        flattened,
        f"SELECT DISTINCT tenant, sensor, capture_sha256, schema_version "
        f"FROM {view}",
    )
    assert identities == [
        (
            "tenant-under-test",
            "sensor-under-test",
            capture.sha256,
            EVENT_SCHEMA_VERSION,
        )
    ]
    # The event id is the one the normalizer stamped on the event this row was
    # unpacked from, not a new one — so it agrees with the source table on the
    # record offset, row by row.
    mismatched = one(
        flattened,
        f"SELECT count(*) FROM {view} v JOIN helena_normalized_events e "
        f"ON v.tenant = e.tenant AND v.sensor = e.sensor "
        f"AND v.capture_sha256 = e.capture_sha256 "
        f"AND v.record_offset = e.record_offset "
        f"WHERE v.event_id <> e.event_id",
    )
    assert mismatched == 0


@pytest.mark.integration
def test_two_tenants_ingesting_one_capture_stay_apart_in_the_flatten_layer(
    migrated_engine: psycopg.Connection,
):
    """The identity columns are what separates them, not a filter someone remembers."""
    capture = layers_capture()
    store_capture(migrated_engine, capture)
    store_capture(migrated_engine, capture, HELENA_TENANT="other-tenant")

    per_tenant = rows(
        migrated_engine,
        "SELECT tenant, count(*) FROM helena_flatten_flows GROUP BY tenant "
        "ORDER BY tenant",
    )
    assert per_tenant == [("other-tenant", 10), ("tenant-under-test", 10)]

    names = rows(
        migrated_engine,
        "SELECT DISTINCT tenant FROM helena_flatten_dns_queries "
        "WHERE query_name = %s",
        "settings-win.data.microsoft.com",
    )
    assert sorted(names) == [("other-tenant",), ("tenant-under-test",)]


# --- The flow row is the record, typed --------------------------------------


@pytest.mark.integration
def test_the_flow_row_is_the_record_typed(flattened: psycopg.Connection):
    """Every column of every flow row, against the file it came from.

    Written as a whole-capture comparison rather than a spot check on one row,
    because the failure this catches — a column reading the wrong JSON key — is
    invisible on a record where the two keys happen to hold the same thing.
    """
    got = rows(
        flattened,
        "SELECT record_offset, record_id, flow_start, duration_seconds, proto, "
        "src_address, dst_address, bytes_sent, bytes_received, packets_sent, "
        "packets_received, transport, src_port, dst_port "
        "FROM helena_flatten_flows ORDER BY record_offset",
    )
    expected = []
    for offset, record in enumerate(layers_records()):
        transport = "tcp" if "tcp" in record else "udp" if "udp" in record else None
        ports = record.get("tcp") or record.get("udp") or {}
        expected.append(
            (
                offset,
                record["id"],
                record["ts"],
                record["td"],
                record["ip"]["proto"],
                record["ip"]["src"],
                record["ip"]["dst"],
                record["ip"]["bsent"],
                record["ip"]["brecv"],
                record["ip"]["psent"],
                record["ip"]["precv"],
                transport,
                ports.get("srcport"),
                ports.get("dstport"),
            )
        )
    # The start time is the only column that changed type on the way in, so it
    # is compared as the epoch it was rather than as the string it prints as.
    assert [(row[0], row[2].timestamp(), *row[3:]) for row in got] == [
        (row[0], row[2], *row[3:]) for row in expected
    ]
    assert [row[1] for row in got] == [row[1] for row in expected]


@pytest.mark.integration
def test_the_flow_counters_stay_bidirectional(flattened: psycopg.Connection):
    """No column sums the two directions, and the two differ on real records.

    `concept/07-principles.md` keeps connection statistics bidirectional because
    direction is signal. The first assertion is the structural one — there is no
    total column to read — and the second is what makes it matter.
    """
    columns = {name for name, _ in FLATTEN_SHAPES["helena_flatten_flows"]}
    assert not {column for column in columns if "total" in column}
    asymmetric = one(
        flattened,
        "SELECT count(*) FROM helena_flatten_flows "
        "WHERE bytes_sent <> bytes_received",
    )
    assert asymmetric == 10


@pytest.mark.integration
def test_a_flow_that_observed_both_transports_says_so(
    migrated_engine: psycopg.Connection, tmp_path: Path
):
    """The case no sampled record has, and the view does not resolve it silently.

    `FlowRecord` allows a record to carry both `tcp` and `udp`; no record in the
    sample does, which makes this the one branch of the `transport` expression
    real data cannot reach. The record here is a real one with a real `udp`
    block from another real record added to it — a shape the contract permits —
    put through the normalizer like any other.
    """
    records = layers_records()
    both = dict(records[1])  # tcp.0
    both["udp"] = dict(records[0]["udp"])  # udp.0's ports
    path = tmp_path / "both.jsonl"
    path.write_bytes(json.dumps(both).encode() + b"\n")
    store_capture(migrated_engine, describe_capture(path))

    assert rows(
        migrated_engine,
        "SELECT transport, src_port, dst_port FROM helena_flatten_flows",
    ) == [("tcp+udp", records[1]["tcp"]["srcport"], records[1]["tcp"]["dstport"])]


# --- Absence is not emptiness ----------------------------------------------


@pytest.mark.integration
def test_a_flow_with_no_application_layer_has_no_row_in_any_layer_view(
    flattened: psycopg.Connection,
):
    """`udp.28`: SSDP, no DNS, no TLS, no HTTP. It is a flow and nothing else."""
    offset = 8
    assert layers_records()[offset]["id"] == "udp.28"
    assert one(
        flattened,
        "SELECT count(*) FROM helena_flatten_flows WHERE record_offset = %s",
        offset,
    ) == 1
    for view in FLATTEN_OBJECTS:
        if view == "helena_flatten_flows":
            continue
        assert (
            one(
                flattened,
                f"SELECT count(*) FROM {view} WHERE record_offset = %s",
                offset,
            )
            == 0
        ), f"{view} produced a row for a flow that observed no application layer"


@pytest.mark.integration
def test_tls_observed_with_no_alpn_is_a_row_saying_zero(flattened: psycopg.Connection):
    """The two halves of *absence is not emptiness*, side by side.

    `tcp.24` negotiated no protocol — `alpn` arrived observed and empty — and
    `udp.28` observed no TLS at all. One is a row reading 0; the other is no row.
    """
    assert layers_records()[7]["id"] == "tcp.24"
    assert layers_records()[7]["tls"]["alpn"] == []
    assert rows(
        flattened,
        "SELECT record_offset, alpn_count, record_count FROM helena_flatten_tls "
        "WHERE alpn_count = 0",
    ) == [(7, 0, 16)]
    assert (
        one(
            flattened,
            "SELECT count(*) FROM helena_flatten_tls WHERE record_offset = 8",
        )
        == 0
    )


@pytest.mark.integration
def test_a_lookup_that_resolved_nothing_keeps_its_rcode_and_its_section(
    flattened: psycopg.Connection,
):
    """`udp.7`: NXDOMAIN. One authority record, no answer, and it is not absence."""
    assert layers_records()[6]["id"] == "udp.7"
    assert rows(
        flattened,
        "SELECT rcode, query_count, response_count FROM helena_flatten_dns "
        "WHERE record_offset = 6",
    ) == [(3, 1, 1)]
    assert rows(
        flattened,
        "SELECT section, record_type, record_value FROM helena_flatten_dns_responses "
        "WHERE record_offset = 6",
    ) == [("authority", "SOA", "")]
    answers = one(
        flattened,
        "SELECT count(*) FROM helena_flatten_dns_responses "
        "WHERE record_offset = 6 AND section = 'answer'",
    )
    assert answers == 0


# --- The arrays, unpacked ---------------------------------------------------


@pytest.mark.integration
def test_the_dns_answer_chain_is_flat_and_in_order(flattened: psycopg.Connection):
    """One row per resource record, positions kept, nothing indexed.

    `concept/instruction.md` §6 names reading `[0]` as a trap that has already
    cost this project something: on `udp.0` the resolved address is the third
    record of the chain, and `udp.4`'s chain is twelve records long.
    """
    chain = rows(
        flattened,
        "SELECT response_index, section, response_name, record_type, ttl_seconds, "
        "record_value FROM helena_flatten_dns_responses WHERE record_offset = 0 "
        "ORDER BY response_index",
    )
    expected = layers_records()[0]["dns"]["responses"]
    assert chain == [
        (position, item["rr"], item["qn"], item["rt"], item["ttl"], item["rv"])
        for position, item in enumerate(expected, start=1)
    ]
    addresses = [row for row in chain if row[3] == "A"]
    assert len(addresses) == 1
    assert addresses[0][0] == 3, "the resolved address is not the first record"

    assert (
        one(
            flattened,
            "SELECT count(*) FROM helena_flatten_dns_responses "
            "WHERE record_offset = 3",
        )
        == 12
    )


@pytest.mark.integration
def test_http_requests_carry_the_protocol_they_were_observed_under(
    flattened: psycopg.Connection,
):
    """One view over both versions, and the version is a column rather than a guess.

    `exchange_number` is NULL on every HTTP/2 row because the HTTP/2 observation
    has no such field — measured over the sample, `num` is on all HTTP/1
    requests and none of the HTTP/2 ones — and the `protocol` column is what
    makes that readable rather than mysterious. The expected numbers are counted
    off the fixture records, so the NULLs are compared against what the file
    actually omits rather than against a rule remembered from the sample.
    """
    records = layers_records()

    def observed(layer: str, side: str, field: str) -> tuple[int, int]:
        items = [
            item
            for record in records
            if layer in record
            for item in record[layer][side]
        ]
        return len(items), sum(field in item for item in items)

    assert rows(
        flattened,
        "SELECT protocol, count(*), count(exchange_number) "
        "FROM helena_flatten_http_requests GROUP BY protocol ORDER BY protocol",
    ) == [
        ("http", *observed("http", "req", "num")),
        ("http2", *observed("http2", "req", "num")),
    ]
    assert observed("http2", "req", "num")[1] == 0

    assert rows(
        flattened,
        "SELECT protocol, count(*), count(exchange_number), count(content_length) "
        "FROM helena_flatten_http_responses GROUP BY protocol ORDER BY protocol",
    ) == [
        (
            "http",
            *observed("http", "res", "num"),
            observed("http", "res", "content_len")[1],
        ),
        (
            "http2",
            *observed("http2", "res", "num"),
            observed("http2", "res", "content_len")[1],
        ),
    ]


@pytest.mark.integration
def test_a_uri_is_stored_whole_and_not_split_here(flattened: psycopg.Connection):
    """The host part is entity extraction's job; this layer keeps what arrived.

    `concept/instruction.md` §6 requires the host part in a *domain* column, and
    the flatten layer has no domain column — splitting here would make it decide
    what a domain is, which is a question about the Public Suffix List.
    """
    request = layers_records()[2]["http"]["req"][0]
    assert "?" in request["uri"]
    assert rows(
        flattened,
        "SELECT method, uri, user_agent, exchange_number, content_type, "
        "content_length FROM helena_flatten_http_requests WHERE record_offset = 2",
    ) == [
        (
            request["method"],
            request["uri"],
            request["agent"],
            request["num"],
            None,
            None,
        )
    ]


@pytest.mark.integration
def test_an_optional_field_absent_on_a_real_record_is_null(
    flattened: psycopg.Connection,
):
    """`tcp.1`'s response carries no `server`; `tcp.4`'s does."""
    assert "server" not in layers_records()[2]["http"]["res"][0]
    assert layers_records()[5]["http"]["res"][0]["server"]
    assert rows(
        flattened,
        "SELECT record_offset, response_index, server "
        "FROM helena_flatten_http_responses WHERE record_offset IN (2, 5) "
        "ORDER BY record_offset, response_index",
    ) == [
        (2, 1, None),
        (5, 1, layers_records()[5]["http"]["res"][0]["server"]),
        (5, 2, layers_records()[5]["http"]["res"][1].get("server")),
    ]


@pytest.mark.integration
def test_the_tls_handshake_columns_name_the_side_they_fingerprint(
    flattened: psycopg.Connection,
):
    """`ja3s` is one letter from `ja3`, and which side it fingerprints is the point."""
    record = layers_records()[9]["tls"]
    assert rows(
        flattened,
        "SELECT server_name, client_version, server_version, server_cipher, "
        "client_ja3, client_ja4, server_ja3, server_ja4 "
        "FROM helena_flatten_tls WHERE record_offset = 9",
    ) == [
        (
            record["sni"],
            record["cver"],
            record["sver"],
            record["scipher"],
            record["ja3"],
            record["ja4"],
            record["ja3s"],
            record["ja4s"],
        )
    ]


# --- The counts reconcile ---------------------------------------------------


@pytest.mark.integration
def test_the_layer_counts_reconcile_with_the_rows_unpacked_from_them(
    migrated_engine: psycopg.Connection,
):
    """`concept/instruction.md` §7: produced-versus-materialised counts reconcile.

    Run over the whole 62-record sample rather than the fixture, because the two
    numbers are computed two different ways — `jsonb_array_length` on the layer
    row, `count(*)` over the unpacked rows — and a disagreement is exactly how a
    silently dropped element would show up.
    """
    store_capture(migrated_engine, describe_capture(SAMPLE))
    pairs = (
        ("helena_flatten_dns", "query_count", "helena_flatten_dns_queries"),
        ("helena_flatten_dns", "response_count", "helena_flatten_dns_responses"),
        ("helena_flatten_http", "request_count", "helena_flatten_http_requests"),
        ("helena_flatten_http", "response_count", "helena_flatten_http_responses"),
    )
    for layer, column, unpacked in pairs:
        declared = int(one(migrated_engine, f"SELECT sum({column}) FROM {layer}"))
        materialised = one(migrated_engine, f"SELECT count(*) FROM {unpacked}")
        assert declared == materialised, f"{layer}.{column} vs {unpacked}"


@pytest.mark.integration
def test_the_layer_rows_count_what_their_own_layer_held(
    flattened: psycopg.Connection,
):
    """Per row, per layer, against the fixture — not summed over the capture.

    The sum over the sample cannot see a `request_count` reading the response
    array, because the sample happens to hold fifteen of each. The fixture does
    not: `tcp.0` observed one HTTP/2 request and three responses, and `tcp.4`
    observed two of each.
    """
    records = layers_records()
    assert rows(
        flattened,
        "SELECT record_offset, protocol, request_count, response_count "
        "FROM helena_flatten_http ORDER BY record_offset, protocol",
    ) == sorted(
        (offset, layer, len(record[layer]["req"]), len(record[layer]["res"]))
        for offset, record in enumerate(records)
        for layer in ("http", "http2")
        if layer in record
    )
    assert rows(
        flattened,
        "SELECT record_offset, rcode, query_count, response_count "
        "FROM helena_flatten_dns ORDER BY record_offset",
    ) == [
        (
            offset,
            record["dns"]["rcode"],
            len(record["dns"]["queries"]),
            len(record["dns"]["responses"]),
        )
        for offset, record in enumerate(records)
        if "dns" in record
    ]


@pytest.mark.integration
def test_the_http_request_and_response_counts_are_two_different_columns(
    migrated_engine: psycopg.Connection, tmp_path: Path
):
    """The one thing no real HTTP/1 record in the sample can demonstrate.

    Every HTTP/1 observation in `data/ingest/flow-sample.jsonl` holds as many
    responses as requests — measured, all eleven of them — so a
    `request_count` reading the response array is invisible to every test over
    real HTTP/1 data. HTTP/2 does separate them (`tcp.0` observed one request
    and three responses) and the row above checks that; this closes the other
    branch of the union by shortening a real record's response list, which is a
    shape the contract permits and the producer simply did not emit here.
    """
    record = dict(layers_records()[5])  # tcp.4: two HTTP/1 requests, two responses
    assert len(record["http"]["req"]) == len(record["http"]["res"]) == 2
    record["http"] = {
        "req": record["http"]["req"],
        "res": record["http"]["res"][:1],
    }
    path = tmp_path / "shortened.jsonl"
    path.write_bytes(json.dumps(record).encode() + b"\n")
    store_capture(migrated_engine, describe_capture(path))

    assert rows(
        migrated_engine,
        "SELECT protocol, request_count, response_count FROM helena_flatten_http",
    ) == [("http", 2, 1)]
    assert (
        one(
            migrated_engine,
            "SELECT count(*) FROM helena_flatten_http_responses",
        )
        == 1
    )


@pytest.mark.integration
def test_the_whole_sample_flattens_to_the_shapes_the_file_holds(
    migrated_engine: psycopg.Connection,
):
    """Every row count, against the same count taken from the JSON in Python.

    The expected numbers are computed from the file rather than written down, so
    a change to the sample cannot make this test agree with a stale constant.
    """
    capture = describe_capture(SAMPLE)
    store_capture(migrated_engine, capture)
    records = [json.loads(line) for line in SAMPLE.read_bytes().splitlines()]

    expected = {
        "helena_flatten_flows": len(records),
        "helena_flatten_dns": sum("dns" in record for record in records),
        "helena_flatten_dns_queries": sum(
            len(record["dns"]["queries"]) for record in records if "dns" in record
        ),
        "helena_flatten_dns_responses": sum(
            len(record["dns"]["responses"]) for record in records if "dns" in record
        ),
        "helena_flatten_tls": sum("tls" in record for record in records),
        "helena_flatten_http": sum(
            ("http" in record) + ("http2" in record) for record in records
        ),
        "helena_flatten_http_requests": sum(
            len(record[layer]["req"])
            for record in records
            for layer in ("http", "http2")
            if layer in record
        ),
        "helena_flatten_http_responses": sum(
            len(record[layer]["res"])
            for record in records
            for layer in ("http", "http2")
            if layer in record
        ),
    }
    found = {
        view: one(migrated_engine, f"SELECT count(*) FROM {view}")
        for view in FLATTEN_OBJECTS
    }
    assert found == expected
    assert capture.record_count == len(records) == 62


# --- What the layer above can be built on -----------------------------------


@pytest.mark.integration
def test_a_materialized_view_can_be_built_over_a_flatten_view(
    flattened: psycopg.Connection,
):
    """The measurement the plain-view decision rests on.

    Keeping the flatten layer unmaterialized is only free if the signal layer
    can still be a streaming job over it. Both of the constructions this file
    uses have to survive into a streaming plan: a set-returning function with
    ordinality, and a `UNION ALL` of two of them. Asserted by creating the
    materialized views and reading rows back, because a `CREATE` that is
    accepted and then produces nothing would be the worse failure.
    """
    flattened.execute(
        "CREATE MATERIALIZED VIEW probe_names AS "
        "SELECT tenant, query_name, count(*) AS lookups "
        "FROM helena_flatten_dns_queries GROUP BY tenant, query_name"
    )
    flattened.execute(
        "CREATE MATERIALIZED VIEW probe_requests AS "
        "SELECT protocol, count(*) AS requests "
        "FROM helena_flatten_http_requests GROUP BY protocol"
    )
    try:
        assert (
            one(flattened, "SELECT sum(lookups)::BIGINT FROM probe_names") == 3
        )
        assert rows(
            flattened, "SELECT protocol, requests FROM probe_requests ORDER BY protocol"
        ) == [("http", 5), ("http2", 1)]
    finally:
        flattened.execute("DROP MATERIALIZED VIEW probe_requests")
        flattened.execute("DROP MATERIALIZED VIEW probe_names")


@pytest.mark.integration
def test_the_flow_start_is_a_timestamp_a_window_can_be_taken_over(
    migrated_engine: psycopg.Connection,
):
    """The sample straddles a five-minute boundary, and the column shows it.

    Not the windowed aggregation itself — that is the next increment — but the
    fact it depends on: `TUMBLE` accepts `flow_start` off the plain view, and the
    62 records fall into two windows because the capture is 130.8 s long and
    crosses 21:35:00Z.
    """
    store_capture(migrated_engine, describe_capture(SAMPLE))
    windows = rows(
        migrated_engine,
        "SELECT window_start, count(*) FROM "
        "TUMBLE(helena_flatten_flows, flow_start, INTERVAL '5 minutes') "
        "GROUP BY window_start ORDER BY window_start",
    )
    assert [count for _, count in windows] == [59, 3]
    assert sum(count for _, count in windows) == 62


# --- The signal layer: one host context per host per window -----------------


@pytest.mark.integration
def test_every_signal_object_declares_what_it_is(migrated_engine: psycopg.Connection):
    """The declarations in the migration files, checked against the engine.

    The flatten layer below is plain views because a materialized intermediate
    that only feeds an aggregate costs 42 % more disk for rows nothing reads
    (`concept/03-architecture.md`), and the signal layer has objects on both
    sides of that rule. The host context and the entity rows are aggregates
    queried on their own — the rows a finding will cite and the rows the
    enrichment tables are joined to — so they are materialized, and a plain view
    there would be a citable row that exists only as a query plan. The entity
    observations are the intermediate exactly: nothing reads a single one.

    The query is by prefix rather than by name, so an object added to the layer
    without a declaration fails here instead of going unnoticed.
    """
    assert dict(
        rows(
            migrated_engine,
            "SELECT table_name, table_type FROM information_schema.tables "
            "WHERE table_schema = current_schema() "
            "AND table_name LIKE 'helena_signal_%'",
        )
    ) == {
        HOST_CONTEXT: "MATERIALIZED VIEW",
        ENTITY_OBSERVATIONS: "VIEW",
        CONTEXT_ENTITIES: "MATERIALIZED VIEW",
        # The retention boundary of sql/migrations/0009_retention_boundary.sql.
        # The two retained views are materialized because a temporal filter in a
        # materialized view is what makes the engine drop the state when the
        # horizon passes — a plain view there would hide rows while what is
        # behind them grew forever. The live view and the rejection counter are
        # plain because both read `now()` outside a WHERE clause, which a
        # streaming query refuses outright.
        RETAINED_HOST_CONTEXT_VIEW: "MATERIALIZED VIEW",
        LIVE_HOST_CONTEXT_VIEW: "VIEW",
        RETAINED_CONTEXT_ENTITIES_VIEW: "MATERIALIZED VIEW",
        RETENTION_REJECTIONS_VIEW: "VIEW",
        # The registrable-domain derivation of
        # sql/migrations/0008_public_suffix_list.sql. The two candidate views
        # are intermediates — nothing reads a single candidate — and the
        # derivation is materialized because it is joined from. What they hold
        # is tests/test_enrichment.py's; that they declared themselves is this
        # test's, because the query is by prefix.
        "helena_signal_domain_suffix_candidates": "VIEW",
        "helena_signal_domain_public_suffix": "VIEW",
        "helena_signal_domain_registrable": "MATERIALIZED VIEW",
        "helena_signal_context_domains": "VIEW",
    }


@pytest.mark.integration
def test_the_host_context_has_the_shape_it_declares(
    migrated_engine: psycopg.Connection,
):
    """Column names and types, in order, as the engine reports them."""
    shape = tuple(
        rows(
            migrated_engine,
            "SELECT column_name, data_type FROM information_schema.columns "
            "WHERE table_schema = current_schema() AND table_name = %s "
            "ORDER BY ordinal_position",
            HOST_CONTEXT,
        )
    )
    assert shape == HOST_CONTEXT_SHAPE


@pytest.mark.integration
def test_the_host_context_carries_no_verdict(migrated_engine: psycopg.Connection):
    """`concept/02-concepts-and-taxonomy.md`: a host context carries no verdict.

    A fact and an inference are separate rows — an inference is appended, never
    written onto the fact it is about — so a column here that could hold one is
    the conflation the whole taxonomy note exists to prevent. Checked by name
    rather than by reading the file, because the failure this catches is someone
    adding the column, not someone editing the comment.
    """
    forbidden = ("verdict", "classification", "confidence", "severity", "score")
    columns = [name for name, _ in HOST_CONTEXT_SHAPE]
    assert [name for name in columns if any(word in name for word in forbidden)] == []
    engine_columns = [
        name
        for (name,) in rows(
            migrated_engine,
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_schema = current_schema() AND table_name = %s",
            HOST_CONTEXT,
        )
    ]
    assert sorted(engine_columns) == sorted(columns)


@pytest.mark.integration
def test_one_context_per_host_per_window(contexts: psycopg.Connection):
    """The layer-coverage capture is one host across a window boundary.

    Its ten records are nine flows starting before 21:35:00Z and one (`tcp.30`,
    21:35:08.6Z) after it, all from `10.127.0.100` — so the aggregation must
    produce exactly two rows, and the key must be unique across them.
    """
    assert rows(
        contexts,
        f"SELECT host, window_start, flow_count FROM {HOST_CONTEXT} "
        f"ORDER BY window_start",
    ) == [
        ("10.127.0.100", datetime(2024, 6, 1, 21, 30, tzinfo=timezone.utc), 9),
        ("10.127.0.100", datetime(2024, 6, 1, 21, 35, tzinfo=timezone.utc), 1),
    ]
    assert one(
        contexts,
        f"SELECT count(*) FROM (SELECT DISTINCT tenant, sensor, host, window_start "
        f"FROM {HOST_CONTEXT}) k",
    ) == one(contexts, f"SELECT count(*) FROM {HOST_CONTEXT}")


@pytest.mark.integration
def test_a_flow_is_assigned_to_the_window_containing_its_start(
    migrated_engine: psycopg.Connection,
):
    """Every flow of the whole sample, against the window computed from its own `ts`.

    The expected split is taken from the file in Python rather than written
    down: a record's window is `floor(ts / 300) * 300`, which is what "assigned
    by its start time" means, and the 62 records fall 59/3 across 21:35:00Z.
    """
    store_capture(migrated_engine, describe_capture(SAMPLE))
    records = [json.loads(line) for line in SAMPLE.read_bytes().splitlines()]

    expected = Counter(
        datetime.fromtimestamp(int(record["ts"] // 300) * 300, tz=timezone.utc)
        for record in records
    )
    found = rows(
        migrated_engine,
        f"SELECT window_start, window_end, flow_count FROM {HOST_CONTEXT} "
        f"ORDER BY window_start",
    )
    assert [(start, count) for start, _, count in found] == sorted(expected.items())
    assert [count for _, _, count in found] == [59, 3]
    # The window is five minutes wide and its bounds are the ones the flows were
    # assigned by — an end that is not start + 5 minutes would mean the rows are
    # grouped by one window and labelled with another.
    assert all(end - start == timedelta(minutes=5) for start, end, _ in found)


@pytest.mark.integration
def test_a_long_flow_is_credited_entirely_to_the_window_it_began_in(
    migrated_engine: psycopg.Connection, tmp_path: Path
):
    """The rule the fixtures cannot otherwise reach, and what that costs.

    Measured over all 62 sampled records: the longest flow runs 110.5 s
    (`tcp.7`) and **no sampled flow crosses a window boundary**, so no test over
    the real capture can tell assignment-by-start from assignment-by-overlap.
    The only honest way to show the mechanism is a real record whose duration is
    lengthened past the boundary — `td` is a float the contract accepts any
    value for — which demonstrates the rule and measures nothing at all about
    how often it matters. Window coherence stays blocked on the corpus
    (`concept/08-open-questions.md`).
    """
    record = dict(layers_records()[0])  # udp.0, 21:32:57.8Z, 0.019 s
    assert record["ts"] < 1717277700 <= record["ts"] + 900
    record["td"] = 900.0  # fifteen minutes: three windows, starting in the first
    path = tmp_path / "long.jsonl"
    path.write_bytes(json.dumps(record).encode() + b"\n")
    store_capture(migrated_engine, describe_capture(path))

    assert rows(
        migrated_engine,
        f"SELECT window_start, flow_count, duration_seconds FROM {HOST_CONTEXT}",
    ) == [(datetime(2024, 6, 1, 21, 30, tzinfo=timezone.utc), 1, 900.0)]


@pytest.mark.integration
def test_a_host_seen_only_as_a_destination_gets_no_context(
    migrated_engine: psycopg.Connection,
):
    """The host key is the source address, and the sample makes the cost visible.

    Seventeen addresses are observed in `data/ingest/flow-sample.jsonl`. One is
    a source; the other sixteen are only ever destinations and get no context at
    all — `concept/08-open-questions.md` records that as an assumption in force,
    and this is what it looks like in rows.
    """
    store_capture(migrated_engine, describe_capture(SAMPLE))
    records = [json.loads(line) for line in SAMPLE.read_bytes().splitlines()]
    sources = {record["ip"]["src"] for record in records}
    destinations = {record["ip"]["dst"] for record in records}
    assert len(sources) == 1 and len(destinations - sources) == 16

    hosts = {
        host
        for (host,) in rows(
            migrated_engine, f"SELECT DISTINCT host FROM {HOST_CONTEXT}"
        )
    }
    assert hosts == sources
    assert hosts & destinations == set()


@pytest.mark.integration
def test_the_context_counters_stay_bidirectional(contexts: psycopg.Connection):
    """Four counters, per window, against the same four summed from the JSON.

    `concept/07-principles.md` keeps connection statistics bidirectional because
    direction is signal. The two windows of the layer capture are lopsided in
    opposite proportions — 10 904 sent against 33 096 received in the first —
    so a column reading the other direction's array, or a `bytes_total` quietly
    replacing the pair, cannot pass this.
    """
    expected = []
    for start, group in _by_window(layers_records()):
        expected.append(
            (
                start,
                sum(record["ip"]["bsent"] for record in group),
                sum(record["ip"]["brecv"] for record in group),
                sum(record["ip"]["psent"] for record in group),
                sum(record["ip"]["precv"] for record in group),
            )
        )
    assert rows(
        contexts,
        f"SELECT window_start, bytes_sent, bytes_received, packets_sent, "
        f"packets_received FROM {HOST_CONTEXT} ORDER BY window_start",
    ) == expected
    assert expected[0][1] != expected[0][2] and expected[0][3] != expected[0][4]


@pytest.mark.integration
def test_the_context_durations_are_the_flows_own_durations(
    contexts: psycopg.Connection,
):
    """The duration statistic is the sum of the flows credited to the window.

    Not the span of the window, and not the span from the first flow's start to
    the last flow's end: a host context says how much flow time was credited
    here, and the window bounds are already two columns of their own.
    """
    expected = [
        (start, sum(record["td"] for record in group))
        for start, group in _by_window(layers_records())
    ]
    found = rows(
        contexts,
        f"SELECT window_start, duration_seconds FROM {HOST_CONTEXT} "
        f"ORDER BY window_start",
    )
    assert [start for start, _ in found] == [start for start, _ in expected]
    for (_, got), (_, want) in zip(found, expected):
        assert got == pytest.approx(want)


@pytest.mark.integration
def test_the_context_flow_counts_reconcile_with_the_flatten_layer(
    contexts: psycopg.Connection,
):
    """Every flow is credited to exactly one context, and none is dropped.

    `concept/instruction.md` §7 wants the counts to reconcile rather than to be
    asserted about. The window assignment is a total function over the flows —
    every flow has a start — so the flow counts must sum to the flatten layer's
    row count, and a `WHERE` that quietly excluded a row would show up here as a
    number that does not add up.
    """
    assert one(contexts, f"SELECT sum(flow_count)::BIGINT FROM {HOST_CONTEXT}") == one(
        contexts, "SELECT count(*) FROM helena_flatten_flows"
    )


# --- Identity and the aggregation version -----------------------------------


@pytest.mark.integration
def test_every_context_row_carries_the_aggregation_version(
    contexts: psycopg.Connection,
):
    """The third copy of the constant, asserted against the other two.

    `sql/migrations/0002_aggregation_version.sql` measured why this one has to
    be a literal: a streaming query cannot read `helena_aggregation_version`
    (RisingWave rejects it as a streaming nested-loop join), so the aggregation
    stamps the value itself. Two copies that can drift are worse than none, so
    the rows this view produces are compared against the Python constant *and*
    against the engine's own copy.
    """
    stamped = {
        version
        for (version,) in rows(
            contexts, f"SELECT DISTINCT aggregation_version FROM {HOST_CONTEXT}"
        )
    }
    assert stamped == {AGGREGATION_VERSION}
    assert stamped == {
        one(contexts, f"SELECT aggregation_version FROM {AGGREGATION_VERSION_VIEW}")
    }


@pytest.mark.integration
def test_the_context_id_is_a_digest_of_the_identity_the_window_and_the_version(
    contexts: psycopg.Connection,
):
    """The id recomputed in Python from the row's own columns.

    The construction is the event id's — length-prefixed parts, so a delimiter
    inside an operator-supplied tenant cannot make two identities collide
    (`docs/decisions/0011-event-identity-and-the-event-id.md`) — with the window
    start as epoch seconds and the aggregation version included. Recomputed here
    rather than compared against a stored constant, because what has to hold is
    that the id is a function of exactly those five things and of nothing else.
    """
    found = rows(
        contexts,
        f"SELECT context_id, tenant, sensor, host, window_start, "
        f"aggregation_version FROM {HOST_CONTEXT}",
    )
    assert len(found) == 2
    for context_id, tenant, sensor, host, window_start, version in found:
        assert context_id == _context_id(tenant, sensor, host, window_start, version)
    assert len({context_id for context_id, *_ in found}) == 2


@pytest.mark.integration
def test_the_context_id_changes_with_the_aggregation_version(
    contexts: psycopg.Connection,
):
    """A revised aggregation is a new context, not an edit of an existing one.

    The version is in the digest, which is the opposite of the event id and
    deliberate: an event id says *which record*, a context id says *which
    computation over which records*. So the same host and window under a
    revised aggregation cannot resolve to the id a citation already holds. This
    asserts the digest actually depends on the version rather than merely
    carrying it in a column beside the id.
    """
    (context_id, tenant, sensor, host, window_start, version), *_ = rows(
        contexts,
        f"SELECT context_id, tenant, sensor, host, window_start, "
        f"aggregation_version FROM {HOST_CONTEXT} ORDER BY window_start",
    )
    assert context_id == _context_id(tenant, sensor, host, window_start, version)
    assert context_id != _context_id(tenant, sensor, host, window_start, "v2")


@pytest.mark.integration
def test_two_tenants_ingesting_one_capture_get_two_contexts(
    migrated_engine: psycopg.Connection,
):
    """The same host in the same window under two tenants is two contexts.

    Tenant and sensor are in the digest for the reason the event id has them
    there: one store holds both deployments, and an id that collided across
    tenants would be a cross-tenant overwrite that looks like it is working.
    """
    capture = layers_capture()
    store_capture(migrated_engine, capture)
    store_capture(migrated_engine, capture, HELENA_TENANT="other-tenant")

    found = rows(
        migrated_engine,
        f"SELECT tenant, count(*), sum(flow_count)::BIGINT FROM {HOST_CONTEXT} "
        f"GROUP BY tenant ORDER BY tenant",
    )
    assert found == [("other-tenant", 2, 10), ("tenant-under-test", 2, 10)]
    identifiers = {
        context_id
        for (context_id,) in rows(
            migrated_engine, f"SELECT context_id FROM {HOST_CONTEXT}"
        )
    }
    assert len(identifiers) == 4


# --- What a revision does, measured -----------------------------------------


@pytest.mark.integration
def test_replaying_a_capture_does_not_double_a_context(
    contexts: psycopg.Connection,
):
    """Replay is an upsert at the source, and the aggregate follows it.

    Every field of an event is derived from the capture, the offset and the
    configured identity, so a replayed record rewrites a byte-identical row —
    and a materialized view over it must reflect the update rather than count
    the record twice. Measured rather than assumed: the counts are read, the
    capture is put through the whole path again, and the counts are read again.
    """
    before = rows(
        contexts,
        f"SELECT context_id, flow_count, bytes_sent FROM {HOST_CONTEXT} "
        f"ORDER BY window_start",
    )
    store_capture(contexts, layers_capture())
    assert (
        rows(
            contexts,
            f"SELECT context_id, flow_count, bytes_sent FROM {HOST_CONTEXT} "
            f"ORDER BY window_start",
        )
        == before
    )


@pytest.mark.integration
def test_a_late_record_revises_a_context_in_place(contexts: psycopg.Connection):
    """What "revision" actually is here, recorded rather than claimed away.

    `concept/07-principles.md` says a revised context is a new version and never
    an edit in place; `concept/08-open-questions.md` says context identity is
    stable across revisions, "so a finding may cite an id whose numbers have
    changed". They disagree, and this is the measurement that says which one
    describes the implementation: a record for a window that already has a
    context is folded into that context's row, the counters change and the id
    does not. Freezing a cited context is `concept/07`'s own answer, and it
    belongs to the increment that issues a finding — nothing cites a context
    yet.

    The late record is the one-record capture, whose single record (`udp.28`,
    812 octets sent) is also offset 8 of the layer capture but under a different
    capture hash, so it is a second observation and not a replay of the first.
    """
    before = rows(
        contexts,
        f"SELECT context_id, flow_count, bytes_sent FROM {HOST_CONTEXT} "
        f"ORDER BY window_start",
    )
    assert before[0][1:] == (9, 10904)

    store_capture(contexts, scan_captures(FIXTURE_CAPTURES)[ONE_RECORD_CAPTURE])

    after = rows(
        contexts,
        f"SELECT context_id, flow_count, bytes_sent FROM {HOST_CONTEXT} "
        f"ORDER BY window_start",
    )
    assert [context_id for context_id, *_ in after] == [
        context_id for context_id, *_ in before
    ]
    assert after[0][1:] == (10, 10904 + 812)
    assert after[1] == before[1]


@pytest.mark.integration
def test_two_hosts_in_one_window_are_two_contexts(
    migrated_engine: psycopg.Connection, tmp_path: Path
):
    """The other half of the host key, which no fixture can reach on its own.

    Every one of the 62 sampled flows has the same source address, so every test
    above exercises "one row per host per window" across windows and across
    tenants but never across two hosts in one window — and the group key would
    look correct with the host dropped from it. Two real records, one of them
    with its address pair reversed (the same conversation observed from the
    other side, which is a shape the contract permits and this producer's single
    vantage point simply never emitted), put through the real normalizer.

    Only `src` and `dst` are exchanged. The counters are left as they were: what
    is being asserted is that the host key is read off `ip.src`, and each
    context carries the traffic of the flows keyed to it.
    """
    first, second = (dict(record) for record in layers_records()[:2])
    second["ip"] = {
        **second["ip"],
        "src": second["ip"]["dst"],
        "dst": second["ip"]["src"],
    }
    assert first["ip"]["src"] != second["ip"]["src"]
    path = tmp_path / "two-hosts.jsonl"
    path.write_bytes(
        b"".join(json.dumps(record).encode() + b"\n" for record in (first, second))
    )
    store_capture(migrated_engine, describe_capture(path))

    assert rows(
        migrated_engine,
        f"SELECT host, window_start, flow_count, bytes_sent, bytes_received "
        f"FROM {HOST_CONTEXT} ORDER BY host",
    ) == sorted(
        (
            record["ip"]["src"],
            datetime(2024, 6, 1, 21, 30, tzinfo=timezone.utc),
            1,
            record["ip"]["bsent"],
            record["ip"]["brecv"],
        )
        for record in (first, second)
    )
    assert (
        one(migrated_engine, f"SELECT count(DISTINCT context_id) FROM {HOST_CONTEXT}")
        == 2
    )


# --- The signal layer: the entity rows beside a context ---------------------


def _uri_host(uri: str) -> str | None:
    """The host part of a URI, by an implementation that is not the view's.

    `urlsplit().hostname` drops the scheme, the userinfo, the port, the path,
    the query and the fragment — the whole of what `concept/instruction.md` §6
    means by "the host part" — and it is the standard library rather than a
    transcription of the SQL, so the two agreeing means something. It differs
    from the view in one way: it lowercases. That difference is invisible on
    this input — no DNS name, SNI or URI host in the sample carries an uppercase
    character — and case folding is part of the normalization deferred to prd
    task 15, so no test here introduces one.
    """
    return urlsplit(uri).hostname or None


def _observations(record: dict) -> list[tuple[str, str, str | None, str]]:
    """Every (entity type, value, fingerprint algorithm, flag) one record holds.

    Written from `concept/05-threat-intelligence.md`'s table rather than from
    the view: flow destinations and A/AAAA answers give addresses; DNS query
    names, DNS response names, the TLS SNI and the host part of a URI give
    domains; the client's JA3 and JA4 give fingerprints; a request URI gives a
    url. `ja3s`/`ja4s` are the server's and are deliberately absent.
    """
    found = [("address", record["ip"]["dst"], None, "observed_as_flow_destination")]
    dns = record.get("dns")
    if dns is not None:
        for query in dns["queries"]:
            found.append(("domain", query["qn"], None, "observed_in_dns_query"))
        for response in dns["responses"]:
            found.append(("domain", response["qn"], None, "observed_in_dns_response"))
            if response["rt"] in ("A", "AAAA"):
                found.append(
                    ("address", response["rv"], None, "observed_in_dns_response")
                )
    tls = record.get("tls")
    if tls is not None:
        found.append(("domain", tls["sni"], None, "observed_in_tls"))
        found.append(("fingerprint", tls["ja3"], "ja3", "observed_in_tls"))
        found.append(("fingerprint", tls["ja4"], "ja4", "observed_in_tls"))
    for layer in ("http", "http2"):
        observed = record.get(layer)
        if observed is None:
            continue
        for request in observed["req"]:
            found.append(("url", request["uri"], None, "observed_in_http"))
            host = _uri_host(request["uri"])
            if host is not None:
                found.append(("domain", host, None, "observed_in_http"))
    return found


def _expected_entities(records: list[dict]) -> list[tuple]:
    """The entity rows the records imply: key, flags, and the observed traffic.

    The traffic is summed over the **distinct flows** in which the value was
    observed, which is the definition in `concept/02-concepts-and-taxonomy.md` —
    "the traffic of the flows in which the entity was observed" — and the reason
    a name mentioned twice on one flow may not count that flow's octets twice.
    """
    entities: dict[tuple, tuple[set, dict]] = {}
    for offset, record in enumerate(records):
        window = datetime.fromtimestamp(
            int(record["ts"] // WINDOW_SECONDS) * WINDOW_SECONDS, tz=timezone.utc
        )
        for kind, value, algorithm, flag in _observations(record):
            flags, flows = entities.setdefault(
                (window, kind, value, algorithm), (set(), {})
            )
            flags.add(flag)
            flows[offset] = record["ip"]
    shaped = [
        (
            window,
            kind,
            value,
            algorithm,
            tuple(flag in flags for flag in ENTITY_FLAGS),
            len(flows),
            sum(ip["bsent"] for ip in flows.values()),
            sum(ip["brecv"] for ip in flows.values()),
            sum(ip["psent"] for ip in flows.values()),
            sum(ip["precv"] for ip in flows.values()),
        )
        for (window, kind, value, algorithm), (flags, flows) in entities.items()
    ]
    return sorted(shaped, key=_entity_order)


def _entity_order(row: tuple) -> tuple:
    # `fingerprint_algorithm` is NULL on every type but `fingerprint`, and None
    # does not order against a string.
    return (row[0], row[1], row[2], row[3] or "")


def _entity_rows(connection: psycopg.Connection, **where: str) -> list[tuple]:
    """Every entity row, in the shape `_expected_entities` produces."""
    clause = "".join(f" AND {column} = %s" for column in where)
    found = rows(
        connection,
        f"SELECT window_start, entity_type, entity_value, fingerprint_algorithm, "
        f"{', '.join(ENTITY_FLAGS)}, observed_flow_count, observed_bytes_sent, "
        f"observed_bytes_received, observed_packets_sent, observed_packets_received "
        f"FROM {CONTEXT_ENTITIES} WHERE TRUE{clause}",
        *where.values(),
    )
    end = 4 + len(ENTITY_FLAGS)
    return sorted(
        (row[0], row[1], row[2], row[3], tuple(row[4:end]), *row[end:])
        for row in found
    )


@pytest.fixture
def entities(contexts: psycopg.Connection) -> psycopg.Connection:
    """The ten-record layer-coverage capture, read through the entity rows.

    The same input as the host context, and for the same reason: it holds every
    layer combination the sample contains, so every extraction branch has a real
    record behind it, and it straddles a window boundary, so "one row per entity
    per context" is exercised across two contexts rather than one.
    """
    return contexts


@pytest.mark.integration
def test_the_entity_row_has_the_shape_it_declares(
    migrated_engine: psycopg.Connection,
):
    """Column names and types, in order, as the engine reports them."""
    shape = tuple(
        rows(
            migrated_engine,
            "SELECT column_name, data_type FROM information_schema.columns "
            "WHERE table_schema = current_schema() AND table_name = %s "
            "ORDER BY ordinal_position",
            CONTEXT_ENTITIES,
        )
    )
    assert shape == CONTEXT_ENTITIES_SHAPE


@pytest.mark.integration
def test_the_entity_row_carries_no_verdict(migrated_engine: psycopg.Connection):
    """An entity row is a fact about what was observed, and nothing more.

    The same rule the host context is held to: a fact and an inference are
    separate rows, and enrichment evidence is appended beside an entity rather
    than written onto it. A `classification` column here would be the place the
    join's answer gets stamped onto the observation it was about.
    """
    forbidden = ("verdict", "classification", "confidence", "severity", "score")
    columns = [name for name, _ in CONTEXT_ENTITIES_SHAPE]
    assert [name for name in columns if any(word in name for word in forbidden)] == []
    engine_columns = [
        name
        for (name,) in rows(
            migrated_engine,
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_schema = current_schema() AND table_name = %s",
            CONTEXT_ENTITIES,
        )
    ]
    assert sorted(engine_columns) == sorted(columns)


@pytest.mark.integration
def test_one_row_per_entity_per_context(entities: psycopg.Connection):
    """The grain `concept/03-architecture.md` requires, asserted two ways.

    "Arrays inside a window cannot be joined to evidence", so the row is per
    entity — and the same value observed in several flows, or in several layers
    of one flow, is one row rather than several. The duplicate query is what
    fails if the aggregation loses a group key; the comparison against the file
    is what fails if it gains one.
    """
    duplicated = one(
        entities,
        f"SELECT count(*) FROM (SELECT context_id, entity_type, entity_value "
        f"FROM {CONTEXT_ENTITIES} GROUP BY 1, 2, 3 HAVING count(*) > 1) d",
    )
    assert duplicated == 0

    keys = [row[:4] for row in _entity_rows(entities)]
    assert keys == [row[:4] for row in _expected_entities(layers_records())]
    assert len(keys) == len(set(keys))


@pytest.mark.integration
def test_the_address_entities_are_the_destinations_and_the_a_answers(
    entities: psycopg.Connection,
):
    """`concept/05-threat-intelligence.md`: flow destinations, A / AAAA answers.

    Both sources in one assertion, against the values taken from the file. A
    CNAME's target is a name and not an address, so it is not here; the SOA and
    PTR records in the fixture are not either.
    """
    assert _entity_rows(entities, entity_type="address") == [
        row for row in _expected_entities(layers_records()) if row[1] == "address"
    ]
    records = layers_records()
    resolved = {
        response["rv"]
        for record in records
        if "dns" in record
        for response in record["dns"]["responses"]
        if response["rt"] in ("A", "AAAA")
    }
    cname_targets = {
        response["rv"]
        for record in records
        if "dns" in record
        for response in record["dns"]["responses"]
        if response["rt"] == "CNAME"
    }
    found = {
        value
        for (value,) in rows(
            entities,
            f"SELECT DISTINCT entity_value FROM {CONTEXT_ENTITIES} "
            f"WHERE entity_type = 'address'",
        )
    }
    assert resolved <= found
    assert cname_targets and not (cname_targets & found)


@pytest.mark.integration
def test_an_address_seen_only_as_a_dns_answer_is_flagged_apart_from_a_destination(
    entities: psycopg.Connection,
):
    """The flag `concept/02-concepts-and-taxonomy.md` asks for, by name.

    The composition rule turns on this difference: a C2 hit on an address the
    host exchanged bytes with supports `malicious.c2`, and the same hit on an
    address the host only ever resolved does not. Both cases are in the fixture
    — `40.126.32.138` was resolved and then connected to, and the other six
    answers of that lookup were resolved and never contacted — so the flags are
    read off real records rather than a constructed one.
    """
    found = dict(
        rows(
            entities,
            f"SELECT entity_value, observed_as_flow_destination "
            f"FROM {CONTEXT_ENTITIES} WHERE entity_type = 'address' "
            f"AND observed_in_dns_response",
        )
    )
    records = layers_records()
    destinations = {record["ip"]["dst"] for record in records}
    resolved = {
        response["rv"]
        for record in records
        if "dns" in record
        for response in record["dns"]["responses"]
        if response["rt"] in ("A", "AAAA")
    }
    assert found == {value: value in destinations for value in resolved}
    # Both halves are real, or the flag would be a column with one value.
    assert True in found.values() and False in found.values()


@pytest.mark.integration
def test_the_domain_entities_record_which_layers_observed_them(
    entities: psycopg.Connection,
):
    """The weaker substitute for the scope test, and what it can still say.

    `concept/02-concepts-and-taxonomy.md` records the limitation: a name carries
    the traffic of the flows that *mentioned* it, not of the connection to the
    address it resolved to — "what the rendering can still say is which layers
    observed the name: a name in TLS SNI was connected to, where a name seen
    only in a DNS query may never have been". `login.live.com` is the first case
    in the fixture (asked, answered, offered as an SNI and requested over HTTP)
    and `prdv4a.aadg.msidentity.com` the second (a name in an answer chain and
    nowhere else).
    """
    assert _entity_rows(entities, entity_type="domain") == [
        row for row in _expected_entities(layers_records()) if row[1] == "domain"
    ]
    flags = dict(
        rows(
            entities,
            f"SELECT entity_value, ARRAY[observed_in_dns_query, "
            f"observed_in_dns_response, observed_in_tls, observed_in_http] "
            f"FROM {CONTEXT_ENTITIES} WHERE entity_type = 'domain' "
            f"AND entity_value IN (%s, %s)",
            "login.live.com",
            "prdv4a.aadg.msidentity.com",
        )
    )
    assert flags == {
        "login.live.com": [True, True, True, True],
        "prdv4a.aadg.msidentity.com": [False, True, False, False],
    }


@pytest.mark.integration
def test_the_fingerprints_are_the_clients_and_carry_their_algorithm(
    entities: psycopg.Connection,
):
    """JA3 and JA4, client-side only, and which is which on the row.

    `concept/05-threat-intelligence.md` says "TLS JA3 and JA4, client-side
    only", so `ja3s` and `ja4s` — which fingerprint the server's selection —
    produce no entity, and the fixture's server fingerprints are asserted absent
    rather than assumed. `fingerprint_algorithm` is on the row because the two
    are not enrichable alike: the catalogue holds one JA3 list and **no JA4
    source at all**, so a JA4 with no source is `missing` where a JA3 no source
    matched is `no_match`, and `concept/instruction.md` §2 forbids collapsing
    those two.
    """
    assert _entity_rows(entities, entity_type="fingerprint") == [
        row for row in _expected_entities(layers_records()) if row[1] == "fingerprint"
    ]
    records = [record for record in layers_records() if "tls" in record]
    assert records
    by_algorithm: dict[str, set[str]] = {"ja3": set(), "ja4": set()}
    for record in records:
        by_algorithm["ja3"].add(record["tls"]["ja3"])
        by_algorithm["ja4"].add(record["tls"]["ja4"])
    found: dict[str, set[str]] = {"ja3": set(), "ja4": set()}
    for algorithm, value in rows(
        entities,
        f"SELECT fingerprint_algorithm, entity_value FROM {CONTEXT_ENTITIES} "
        f"WHERE entity_type = 'fingerprint'",
    ):
        found[algorithm].add(value)
    assert found == by_algorithm

    server_side = {record["tls"]["ja3s"] for record in records} | {
        record["tls"]["ja4s"] for record in records
    }
    every_value = {
        value
        for (value,) in rows(entities, f"SELECT entity_value FROM {CONTEXT_ENTITIES}")
    }
    assert server_side and not (server_side & every_value)


@pytest.mark.integration
def test_the_url_entities_are_the_request_uris_whole(entities: psycopg.Connection):
    """The URI exactly as supplied, query string and all — and both versions.

    `concept/05-threat-intelligence.md` takes url entities from "HTTP and
    HTTP/2 URIs", and a URL feed matches at exact-URL scope, so truncating the
    query would be truncating the join key. The fixture carries both versions:
    `tcp.0` requested over HTTP/2 and `tcp.1` over HTTP/1.
    """
    assert _entity_rows(entities, entity_type="url") == [
        row for row in _expected_entities(layers_records()) if row[1] == "url"
    ]
    supplied = {
        request["uri"]
        for record in layers_records()
        for layer in ("http", "http2")
        if layer in record
        for request in record[layer]["req"]
    }
    found = {
        value
        for (value,) in rows(
            entities,
            f"SELECT entity_value FROM {CONTEXT_ENTITIES} WHERE entity_type = 'url'",
        )
    }
    assert found == supplied
    assert any("?" in uri for uri in found)
    assert {uri.split(":", 1)[0] for uri in found} == {"http", "https"}


@pytest.mark.integration
def test_observation_scoped_traffic_is_the_traffic_of_the_flows_that_observed_it(
    entities: psycopg.Connection,
):
    """Every column of every entity row, against the file it came from.

    A whole-capture comparison rather than a spot check, for the reason the
    flow-row test gives: a counter reading the wrong direction is invisible on a
    row where the two happen to agree. The four counters stay bidirectional and
    there is no total, so a swap cannot hide.
    """
    assert _entity_rows(entities) == _expected_entities(layers_records())


@pytest.mark.integration
def test_an_entity_observed_twice_on_one_flow_counts_that_flow_once(
    entities: psycopg.Connection,
):
    """The inner aggregation, on the record that needs it.

    `tcp.4` requests two different URLs from one host, so that host is observed
    twice on one flow. Its octets are the flow's octets, not twice them — and
    the two URLs are still two url rows, because they are two entities.
    """
    (record,) = [
        record
        for record in layers_records()
        if record.get("id") == "tcp.4" and "http" in record
    ]
    uris = [request["uri"] for request in record["http"]["req"]]
    assert len(uris) == 2 and len(set(uris)) == 2
    hosts = {_uri_host(uri) for uri in uris}
    assert len(hosts) == 1
    (host,) = hosts

    assert rows(
        entities,
        f"SELECT observed_flow_count, observed_bytes_sent, observed_bytes_received "
        f"FROM {CONTEXT_ENTITIES} WHERE entity_type = 'domain' AND entity_value = %s",
        host,
    ) == [(1, record["ip"]["bsent"], record["ip"]["brecv"])]
    assert (
        one(
            entities,
            f"SELECT count(*) FROM {CONTEXT_ENTITIES} WHERE entity_type = 'url' "
            f"AND entity_value IN (%s, %s)",
            *uris,
        )
        == 2
    )


@pytest.mark.integration
def test_every_entity_row_belongs_to_the_context_whose_window_it_shares(
    entities: psycopg.Connection,
):
    """The join to the host context, and the second copy of the window interval.

    `INTERVAL '5 minutes'` is written in 0006 and again in 0007 because `TUMBLE`
    takes a named relation and the two views window different ones. Two copies
    that can drift are what `concept/instruction.md` §2 forbids for a version
    constant, so this is the assertion that fails when they do: every entity row
    joins a context, no entity row is lost by the join, and the window ends
    agree as well as the starts.
    """
    produced = one(entities, f"SELECT count(*) FROM {CONTEXT_ENTITIES}")
    joined = one(
        entities,
        f"SELECT count(*) FROM {CONTEXT_ENTITIES} e JOIN {HOST_CONTEXT} h "
        f"ON h.context_id = e.context_id WHERE e.window_start = h.window_start "
        f"AND e.window_end = h.window_end AND e.tenant = h.tenant "
        f"AND e.sensor = h.sensor AND e.host = h.host",
    )
    assert produced == joined > 0
    assert (
        one(entities, f"SELECT count(DISTINCT context_id) FROM {CONTEXT_ENTITIES}") == 2
    )
    for context_id, tenant, sensor, host, window_start, version in rows(
        entities,
        f"SELECT DISTINCT context_id, tenant, sensor, host, window_start, "
        f"aggregation_version FROM {CONTEXT_ENTITIES}",
    ):
        assert context_id == _context_id(tenant, sensor, host, window_start, version)


@pytest.mark.integration
def test_every_entity_row_carries_the_context_aggregation_version(
    entities: psycopg.Connection,
):
    """Read off the context row rather than stamped again.

    The version literal and the id digest exist once, in 0006. An entity row
    that carried its own copy could disagree with the context it hangs off, and
    a citation would then resolve to two versions of one computation.
    """
    stamped = {
        version
        for (version,) in rows(
            entities, f"SELECT DISTINCT aggregation_version FROM {CONTEXT_ENTITIES}"
        )
    }
    assert stamped == {AGGREGATION_VERSION}
    assert stamped == {
        one(entities, f"SELECT aggregation_version FROM {AGGREGATION_VERSION_VIEW}")
    }


@pytest.mark.integration
def test_two_tenants_ingesting_one_capture_keep_their_entities_apart(
    migrated_engine: psycopg.Connection,
):
    """The tenant seam reaches the join target, not only the source table.

    An entity row is what the enrichment join and the rendering read, so a row
    that could not name its tenant would end the seam here — one tenant's
    domains would appear in the other's context.
    """
    capture = layers_capture()
    store_capture(migrated_engine, capture)
    store_capture(migrated_engine, capture, HELENA_TENANT="other-tenant")

    per_tenant = rows(
        migrated_engine,
        f"SELECT tenant, count(*) FROM {CONTEXT_ENTITIES} GROUP BY tenant "
        f"ORDER BY tenant",
    )
    expected = len(_expected_entities(layers_records()))
    assert per_tenant == [("other-tenant", expected), ("tenant-under-test", expected)]
    distinct = f"SELECT count(DISTINCT context_id) FROM {CONTEXT_ENTITIES}"
    assert one(migrated_engine, distinct) == 4


@pytest.mark.integration
def test_the_observation_rows_reconcile_with_what_the_records_hold(
    entities: psycopg.Connection,
):
    """`concept/instruction.md` §7: produced-versus-materialised counts reconcile.

    One observation row per extracted value per flow, counted from the JSON in
    Python. It is the intermediate the entity rows are aggregated from, so a
    branch that silently dropped rows — a join key that does not match, a filter
    that fires on real data — shows up here as a number rather than as a missing
    entity nobody was looking for.
    """
    records = layers_records()
    assert one(entities, f"SELECT count(*) FROM {ENTITY_OBSERVATIONS}") == sum(
        len(_observations(record)) for record in records
    )


@pytest.mark.integration
def test_the_whole_sample_produces_the_entities_the_file_holds(
    migrated_engine: psycopg.Connection,
):
    """All 62 records, every entity row, against the same rows built in Python.

    The layer fixture is ten records chosen for coverage; this is the whole
    sample, so a branch that only misbehaves on a record the fixture does not
    contain — the twelve-record answer chain, the NXDOMAIN lookup, the flow with
    no application layer — has nowhere to hide.
    """
    store_capture(migrated_engine, describe_capture(SAMPLE))
    records = [json.loads(line) for line in SAMPLE.read_bytes().splitlines()]
    assert len(records) == 62
    assert _entity_rows(migrated_engine) == _expected_entities(records)
    per_type = Counter(row[1] for row in _entity_rows(migrated_engine))
    assert set(per_type) == {"address", "domain", "fingerprint", "url"}


@pytest.mark.integration
def test_the_uri_host_part_drops_the_scheme_userinfo_port_path_and_query(
    migrated_engine: psycopg.Connection, tmp_path: Path
):
    """`concept/instruction.md` §6: a URI in a domain column is the trap.

    No sampled URI carries userinfo, a port or a fragment, so those three steps
    of the host expression are unexercised by every test above. The record here
    is a real one whose request URI was replaced — a string the contract permits
    — put through the real normalizer, which is the same technique the window
    and transport branches are demonstrated with. The url entity keeps the URI
    whole; only the domain entity is cut down.
    """
    record = dict(layers_records()[2])  # tcp.1, HTTP/1, one request
    uri = "http://someone@files.example.test:8443/a/b?c=d#e"
    request = {**record["http"]["req"][0], "uri": uri}
    record["http"] = {**record["http"], "req": [request]}
    path = tmp_path / "authority.jsonl"
    path.write_bytes(json.dumps(record).encode() + b"\n")
    store_capture(migrated_engine, describe_capture(path))

    assert rows(
        migrated_engine,
        f"SELECT entity_type, entity_value FROM {CONTEXT_ENTITIES} "
        f"WHERE entity_type IN ('domain', 'url') ORDER BY entity_type",
    ) == [("domain", "files.example.test"), ("url", uri)]
    assert _uri_host(uri) == "files.example.test"


@pytest.mark.integration
def test_a_relative_uri_is_a_url_entity_and_no_domain_entity(
    migrated_engine: psycopg.Connection, tmp_path: Path
):
    """A URI with no authority has no host part, and none is invented.

    All 36 sampled request URIs are absolute, but an HTTP/1 request line
    routinely carries a path with the host in a header the input does not
    supply. The url entity is still produced; the domain entity would have to be
    guessed, so there is not one.
    """
    record = dict(layers_records()[2])  # tcp.1
    uri = "/msdownload/update/v3/static/trustedr/en/disallowedcertstl.cab"
    request = {**record["http"]["req"][0], "uri": uri}
    record["http"] = {**record["http"], "req": [request]}
    path = tmp_path / "relative.jsonl"
    path.write_bytes(json.dumps(record).encode() + b"\n")
    store_capture(migrated_engine, describe_capture(path))

    assert rows(
        migrated_engine,
        f"SELECT entity_type, entity_value FROM {CONTEXT_ENTITIES} "
        f"WHERE entity_type IN ('domain', 'url')",
    ) == [("url", uri)]
    assert _uri_host(uri) is None


# --- The retention boundary, completeness, and the frozen copy --------------
#
# `sql/migrations/0009_retention_boundary.sql` argues the design; these are the
# measurements. Every fixture in this repository is dated 2024-06-01, so a
# horizon a prototype would set puts all of them outside the boundary — which is
# useful (it is the "outside" case, from real records) but cannot show the inside
# of the boundary at all. What shows that is the technique tasks 12–15 used for a
# case the sample cannot reach: a real record put through the real normalizer
# with one contract-permitted field changed, here `ts`.

# The shape of the citable row, as sql/migrations/0009_retention_boundary.sql
# declares it. `context_version` and `completeness` are what the live view adds
# to a retained context, and they lead the row because they are what a citation
# records.
LIVE_HOST_CONTEXT_SHAPE = (
    ("context_id", "character varying"),
    ("context_version", "character varying"),
    ("completeness", "character varying"),
    ("tenant", "character varying"),
    ("sensor", "character varying"),
    ("host", "character varying"),
    ("window_start", "timestamp with time zone"),
    ("window_end", "timestamp with time zone"),
    ("flow_count", "bigint"),
    ("duration_seconds", "double precision"),
    ("bytes_sent", "bigint"),
    ("bytes_received", "bigint"),
    ("packets_sent", "bigint"),
    ("packets_received", "bigint"),
    ("aggregation_version", "character varying"),
)

FROZEN_CONTEXT_SHAPE = (
    ("tenant", "character varying"),
    ("sensor", "character varying"),
    ("context_id", "character varying"),
    ("context_version", "character varying"),
    ("completeness", "character varying"),
    ("host", "character varying"),
    ("window_start", "timestamp with time zone"),
    ("window_end", "timestamp with time zone"),
    ("flow_count", "bigint"),
    ("duration_seconds", "double precision"),
    ("bytes_sent", "bigint"),
    ("bytes_received", "bigint"),
    ("packets_sent", "bigint"),
    ("packets_received", "bigint"),
    ("aggregation_version", "character varying"),
)

RETENTION_REJECTIONS_SHAPE = (
    ("tenant", "character varying"),
    ("sensor", "character varying"),
    ("retention_horizon", "interval"),
    ("contexts", "bigint"),
    ("contexts_outside_boundary", "bigint"),
    ("records", "bigint"),
    ("records_outside_boundary", "bigint"),
)

# The columns whose values the context version is a digest of, in order. The
# second copy of the construction in the live view's SELECT list; the test below
# recomputes the digest from them.
VERSIONED_STATISTICS = (
    "flow_count",
    "duration_seconds",
    "bytes_sent",
    "bytes_received",
    "packets_sent",
    "packets_received",
)


def store_records(
    connection: psycopg.Connection, path: Path, records: list[dict], **overrides: str
) -> None:
    """Write `records` as a capture and put them through the real ingest path.

    The capture identity is the hash of the file, so two calls with different
    records are two captures and a record ingested by the second is a second
    observation rather than a replay of the first.
    """
    path.write_bytes(
        b"".join(json.dumps(record).encode() + b"\n" for record in records)
    )
    store_capture(connection, describe_capture(path), **overrides)


def restamped(record: dict, ts: float) -> dict:
    """A real record with its start time moved. Nothing else is touched.

    `ts` is a field of the input contract and the flatten layer reads it as the
    flow's start, so moving it is a contract-permitted change to a real record —
    the only way to reach the inside of a retention boundary from fixtures dated
    2024-06-01.
    """
    return {**record, "ts": ts}


def current_window() -> float:
    """The start of the window `now` falls in, as epoch seconds."""
    return float(int(time.time() // WINDOW_SECONDS) * WINDOW_SECONDS)


def store(connection: psycopg.Connection, **overrides: str) -> ContextStore:
    configured = settings(**overrides)
    return ContextStore(connection=connection, identity=configured.identity)


@pytest.fixture
def bounded(migrated_engine: psycopg.Connection, tmp_path: Path) -> psycopg.Connection:
    """Four contexts: two outside the boundary, one provisional, one open.

    The ten-record layer capture supplies the two outside — its windows are
    2024-06-01, which no horizon a prototype would set reaches. Two real records
    re-stamped supply the two inside: one an hour ago, whose window has closed
    but whose records are still retained, and one in the window `now` falls in,
    which has not closed.
    """
    store_capture(migrated_engine, layers_capture())
    window = current_window()
    store_records(
        migrated_engine,
        tmp_path / "provisional.jsonl",
        [restamped(layers_records()[0], window - 3600 + 1)],
    )
    store_records(
        migrated_engine,
        tmp_path / "open.jsonl",
        [restamped(layers_records()[1], window + 1)],
    )
    return migrated_engine


@pytest.mark.integration
def test_the_retention_objects_declare_what_they_are(
    migrated_engine: psycopg.Connection,
):
    """The two objects the signal-layer prefix test cannot see.

    `helena_retention_horizon` is reference rather than signal — one constant,
    one row — and `helena_frozen_context` is the one thing here that holds a row
    the engine would otherwise take away, so it is a table. RisingWave reports a
    table as `BASE TABLE`.
    """
    assert dict(
        rows(
            migrated_engine,
            "SELECT table_name, table_type FROM information_schema.tables "
            "WHERE table_schema = current_schema() AND table_name IN (%s, %s)",
            RETENTION_HORIZON_VIEW,
            FROZEN_CONTEXT_TABLE,
        )
    ) == {RETENTION_HORIZON_VIEW: "VIEW", FROZEN_CONTEXT_TABLE: "BASE TABLE"}


@pytest.mark.integration
@pytest.mark.parametrize(
    ("relation", "shape"),
    (
        (LIVE_HOST_CONTEXT_VIEW, LIVE_HOST_CONTEXT_SHAPE),
        (FROZEN_CONTEXT_TABLE, FROZEN_CONTEXT_SHAPE),
        (RETENTION_REJECTIONS_VIEW, RETENTION_REJECTIONS_SHAPE),
    ),
)
def test_the_retention_objects_have_the_shape_they_declare(
    migrated_engine: psycopg.Connection, relation: str, shape: tuple
):
    assert (
        tuple(
            rows(
                migrated_engine,
                "SELECT column_name, data_type FROM information_schema.columns "
                "WHERE table_schema = current_schema() AND table_name = %s "
                "ORDER BY ordinal_position",
                relation,
            )
        )
        == shape
    )


@pytest.mark.integration
def test_the_retained_views_carry_the_shape_of_what_they_bound(
    migrated_engine: psycopg.Connection,
):
    """Retention is a filter, so a retained view is its source minus rows.

    A retained view that dropped, renamed or reordered a column would be a
    second definition of the context, and the boundary would have become a
    transformation.
    """
    for relation, shape in (
        (RETAINED_HOST_CONTEXT_VIEW, HOST_CONTEXT_SHAPE),
        (RETAINED_CONTEXT_ENTITIES_VIEW, CONTEXT_ENTITIES_SHAPE),
    ):
        assert (
            tuple(
                rows(
                    migrated_engine,
                    "SELECT column_name, data_type FROM information_schema.columns "
                    "WHERE table_schema = current_schema() AND table_name = %s "
                    "ORDER BY ordinal_position",
                    relation,
                )
            )
            == shape
        ), relation


@pytest.mark.integration
def test_the_horizon_has_one_value_in_three_places(
    migrated_engine: psycopg.Connection,
):
    """One parameter, and the copies it is forced to have are asserted equal.

    A streaming query cannot read `helena_retention_horizon` — a CROSS JOIN to a
    one-row view is refused as a streaming nested-loop join
    (sql/migrations/0002_aggregation_version.sql) — so the retained view carries
    the interval as a literal and there are three homes for one number: the
    Python constant, the declaring view, and the predicate the engine actually
    runs.

    The third is read out of `rw_catalog` rather than out of the .sql file, and
    then handed back to the engine to evaluate. Grepping the migration would find
    the value in the comment that explains it; the catalogue is what the engine
    received.
    """
    declared = one(migrated_engine, f"SELECT retention_horizon FROM {RETENTION_HORIZON_VIEW}")
    assert declared == RETENTION_HORIZON

    definition = one(
        migrated_engine,
        "SELECT definition FROM rw_catalog.rw_materialized_views "
        "WHERE schema_name = current_schema() AND name = %s",
        RETAINED_HOST_CONTEXT_VIEW,
    )
    intervals = re.findall(r"INTERVAL '([^']+)'", definition)
    assert len(intervals) == 1, definition
    assert one(migrated_engine, f"SELECT INTERVAL '{intervals[0]}'") == RETENTION_HORIZON


@pytest.mark.integration
def test_the_boundary_hides_an_old_context_and_keeps_the_records(
    bounded: psycopg.Connection,
):
    """Retention is a temporal filter, not a delete.

    The layer capture's two 2024 contexts are in the aggregate and not in the
    retained view; the two re-stamped ones are in both. Nothing was deleted —
    which is what makes the rejection counter below able to count what was
    dropped, and what makes an archived capture replayable.
    """
    assert one(bounded, f"SELECT count(*) FROM {HOST_CONTEXT}") == 4
    assert (
        one(
            bounded,
            f"SELECT count(*) FROM {HOST_CONTEXT} WHERE window_start < '2025-01-01'",
        )
        == 2
    )
    retained = rows(
        bounded,
        f"SELECT window_start FROM {RETAINED_HOST_CONTEXT_VIEW} ORDER BY window_start",
    )
    assert len(retained) == 2
    assert all(start.year >= 2026 for (start,) in retained)


@pytest.mark.integration
def test_an_entity_row_is_inside_the_boundary_exactly_when_its_context_is(
    bounded: psycopg.Connection,
):
    """The entity boundary is the context's, by construction rather than by copy.

    `helena_signal_context_entities_retained` joins the retained context instead
    of repeating the temporal predicate, so there is no second copy of the
    horizon to drift — and an entity row cannot outlive the context it belongs
    to, which is what would leave a citation pointing at entities of a context
    nothing can resolve.
    """
    assert one(bounded, f"SELECT count(*) FROM {CONTEXT_ENTITIES}") > 0
    assert rows(
        bounded,
        f"SELECT DISTINCT e.context_id FROM {RETAINED_CONTEXT_ENTITIES_VIEW} e "
        f"ORDER BY e.context_id",
    ) == rows(
        bounded,
        f"SELECT DISTINCT c.context_id FROM {CONTEXT_ENTITIES} c "
        f"JOIN {RETAINED_HOST_CONTEXT_VIEW} r ON c.context_id = r.context_id "
        f"ORDER BY c.context_id",
    )
    assert (
        one(
            bounded,
            f"SELECT count(*) FROM {RETAINED_CONTEXT_ENTITIES_VIEW} e "
            f"WHERE NOT EXISTS (SELECT 1 FROM {RETAINED_HOST_CONTEXT_VIEW} r "
            f"WHERE r.context_id = e.context_id)",
        )
        == 0
    )


@pytest.mark.integration
def test_completeness_is_open_while_the_window_is_and_provisional_after(
    bounded: psycopg.Connection,
):
    """The two values, on two real contexts, and there is no third.

    `open` is a window that has not closed; `provisional` is one that has, whose
    records are still retained and which a late record can still revise. Neither
    is "final" — `concept/02-concepts-and-taxonomy.md` — and a context does not
    become final, it leaves the retained view.
    """
    window = datetime.fromtimestamp(current_window(), tz=timezone.utc)
    assert rows(
        bounded,
        f"SELECT completeness, window_start FROM {LIVE_HOST_CONTEXT_VIEW} "
        f"ORDER BY window_start",
    ) == [
        ("provisional", window - timedelta(hours=1)),
        ("open", window),
    ]


@pytest.mark.integration
def test_completeness_has_no_final_value_anywhere(bounded: psycopg.Connection):
    """The domain is two values, and it is structural on both sides.

    In the engine `completeness` is a two-branch CASE in a view nothing writes
    to, so a third value has nowhere to come from; in Python it is a `Literal`,
    so a frozen row claiming one is a validation error rather than a stored
    claim that a context is finished.
    """
    assert [
        value
        for (value,) in rows(
            bounded, f"SELECT DISTINCT completeness FROM {LIVE_HOST_CONTEXT_VIEW}"
        )
    ] != []
    assert all(
        value in COMPLETENESS_VALUES
        for (value,) in rows(
            bounded, f"SELECT DISTINCT completeness FROM {LIVE_HOST_CONTEXT_VIEW}"
        )
    )
    assert "final" not in COMPLETENESS_VALUES

    live = rows(
        bounded,
        f"SELECT {', '.join(name for name, _ in FROZEN_CONTEXT_SHAPE)} "
        f"FROM {LIVE_HOST_CONTEXT_VIEW} LIMIT 1",
    )[0]
    fields = dict(zip((name for name, _ in FROZEN_CONTEXT_SHAPE), live, strict=True))
    assert FrozenContext(**fields).completeness in COMPLETENESS_VALUES
    with pytest.raises(ValidationError):
        FrozenContext(**{**fields, "completeness": "final"})


@pytest.mark.integration
def test_a_context_leaves_the_retained_view_when_its_window_passes_the_horizon(
    migrated_engine: psycopg.Connection, tmp_path: Path
):
    """The boundary is enforced by the engine as the clock moves, not at read time.

    The shipped horizon is 24 hours, which no test can wait out, so what is
    measured here is the mechanism the shipped view is built from: the same
    temporal filter over the same aggregate, with a horizon computed to expire a
    few seconds from now. The row is there when the view is created and gone
    once the horizon passes, while the aggregate behind it still holds it —
    retention is a filter, not a delete.

    Measured before this migration was written, and this is the test that keeps
    it true: a context whose window_end was 277.6 s old, under a 283-second
    horizon, was present at creation and gone 5 s after the horizon passed.
    """
    store_records(
        migrated_engine,
        tmp_path / "expiring.jsonl",
        [restamped(layers_records()[0], current_window() - 1)],
    )
    window_end = one(migrated_engine, f"SELECT window_end FROM {HOST_CONTEXT}")
    horizon = int(time.time() - window_end.timestamp()) + 6
    migrated_engine.execute(
        f"CREATE MATERIALIZED VIEW probe_retained AS "
        f"SELECT context_id, window_end FROM {HOST_CONTEXT} "
        f"WHERE window_end > now() - INTERVAL '{horizon} seconds'"
    )
    assert one(migrated_engine, "SELECT count(*) FROM probe_retained") == 1

    deadline = time.time() + 60
    while (
        one(migrated_engine, "SELECT count(*) FROM probe_retained") > 0
        and time.time() < deadline
    ):
        time.sleep(0.5)
    assert one(migrated_engine, "SELECT count(*) FROM probe_retained") == 0
    assert one(migrated_engine, f"SELECT count(*) FROM {HOST_CONTEXT}") == 1


@pytest.mark.integration
def test_a_late_record_inside_the_boundary_still_revises_through_the_filter(
    migrated_engine: psycopg.Connection, tmp_path: Path
):
    """`concept/08-open-questions.md` lists this as untested. It is now measured.

    The note says: untested, **and not to be inferred**, whether a late record
    inside the boundary still revises under a temporal filter. A temporal filter
    is a streaming operator between the aggregate and the reader, and "the row
    updates" is not something to assume of it — so a second observation of a
    window that already has a retained context is put through the real path, and
    the retained row is read before and after.

    It revises: the counters change through the filter exactly as they change in
    the aggregate, and the context id does not move.
    """
    window = current_window()
    first, second = layers_records()[0], layers_records()[1]
    store_records(migrated_engine, tmp_path / "first.jsonl", [restamped(first, window + 1)])
    before = rows(
        migrated_engine,
        f"SELECT context_id, flow_count, bytes_sent FROM {RETAINED_HOST_CONTEXT_VIEW}",
    )
    assert before == [(before[0][0], 1, first["ip"]["bsent"])]

    store_records(
        migrated_engine, tmp_path / "second.jsonl", [restamped(second, window + 2)]
    )
    assert rows(
        migrated_engine,
        f"SELECT context_id, flow_count, bytes_sent FROM {RETAINED_HOST_CONTEXT_VIEW}",
    ) == [(before[0][0], 2, first["ip"]["bsent"] + second["ip"]["bsent"])]


@pytest.mark.integration
def test_the_context_version_is_a_digest_of_the_id_and_the_statistics(
    bounded: psycopg.Connection,
):
    """What a citation pins, recomputed outside the view that produces it.

    The parts are length-prefixed, the construction the event id and the context
    id already use. `duration_seconds` goes in as the engine's rendering of a
    DOUBLE PRECISION, so the expectation reads that rendering back from the
    engine rather than formatting a float in Python: what this checks is the
    column set and the composition, not float formatting.
    """
    casts = ", ".join(f"{name}::VARCHAR" for name in VERSIONED_STATISTICS)
    for context_id, version, *statistics in rows(
        bounded,
        f"SELECT context_id, context_version, {casts} FROM {LIVE_HOST_CONTEXT_VIEW}",
    ):
        material = b"".join(
            f"{len(part.encode())}:".encode() + part.encode()
            for part in (context_id, *statistics)
        )
        assert version == hashlib.sha256(material).hexdigest()


@pytest.mark.integration
def test_a_revised_context_mints_a_new_version_and_keeps_its_identity(
    migrated_engine: psycopg.Connection, tmp_path: Path
):
    """The two identities pull apart exactly here.

    `concept/07-principles.md` settled on 2026-09-04 that a revised context keeps
    its `context_id` — an incrementally maintained view edits the counters in
    place, and task 13 measured it. The same note requires a citation to be
    stable rather than merely current. `context_version` is what carries that: a
    revision leaves the id alone and produces a new version of the values, so
    "a revised context is a new version rather than an edit in place" is true of
    the thing a citation records.
    """
    window = current_window()
    store_records(
        migrated_engine,
        tmp_path / "before.jsonl",
        [restamped(layers_records()[0], window + 1)],
    )
    before = rows(
        migrated_engine,
        f"SELECT context_id, context_version FROM {LIVE_HOST_CONTEXT_VIEW}",
    )
    store_records(
        migrated_engine,
        tmp_path / "after.jsonl",
        [restamped(layers_records()[1], window + 2)],
    )
    after = rows(
        migrated_engine,
        f"SELECT context_id, context_version FROM {LIVE_HOST_CONTEXT_VIEW}",
    )
    assert [context_id for context_id, _ in after] == [
        context_id for context_id, _ in before
    ]
    assert after[0][1] != before[0][1]


@pytest.mark.integration
def test_a_frozen_context_survives_the_revision_of_the_context_it_copied(
    migrated_engine: psycopg.Connection, tmp_path: Path
):
    """Freezing before eviction is what makes a citation stable, not merely current.

    The copy is taken, the context is then revised by a second observation, and
    the frozen row still says what the first citation was issued against. A
    second freeze adds the revised version beside it rather than overwriting it:
    two citations, two answers, both resolvable.
    """
    window = current_window()
    first, second = layers_records()[0], layers_records()[1]
    store_records(migrated_engine, tmp_path / "cited.jsonl", [restamped(first, window + 1)])
    contexts = store(migrated_engine)
    context_id = one(migrated_engine, f"SELECT context_id FROM {LIVE_HOST_CONTEXT_VIEW}")

    cited = contexts.freeze(context_id)
    assert cited.flow_count == 1
    assert cited.bytes_sent == first["ip"]["bsent"]
    assert cited.completeness == "open"
    assert cited.aggregation_version == AGGREGATION_VERSION

    store_records(
        migrated_engine, tmp_path / "revision.jsonl", [restamped(second, window + 2)]
    )
    assert (
        one(migrated_engine, f"SELECT flow_count FROM {LIVE_HOST_CONTEXT_VIEW}") == 2
    )
    assert contexts.frozen(context_id) == [cited]

    revised = contexts.freeze(context_id)
    assert revised.context_id == cited.context_id
    assert revised.context_version != cited.context_version
    assert revised.flow_count == 2
    assert sorted(contexts.frozen(context_id), key=lambda row: row.flow_count) == [
        cited,
        revised,
    ]


@pytest.mark.integration
def test_freezing_an_unrevised_context_twice_writes_one_row(
    migrated_engine: psycopg.Connection, tmp_path: Path
):
    """A finding issued twice against the same numbers is one frozen version.

    The key is (identity, context_id, context_version), so the second freeze is
    an upsert of an identical row rather than a second copy.
    """
    store_records(
        migrated_engine,
        tmp_path / "twice.jsonl",
        [restamped(layers_records()[0], current_window() + 1)],
    )
    contexts = store(migrated_engine)
    context_id = one(migrated_engine, f"SELECT context_id FROM {LIVE_HOST_CONTEXT_VIEW}")
    assert contexts.freeze(context_id) == contexts.freeze(context_id)
    assert len(contexts.frozen(context_id)) == 1


@pytest.mark.integration
def test_freezing_a_context_outside_the_boundary_is_a_typed_refusal(
    bounded: psycopg.Connection,
):
    """A copy-out that came too late is not a silent no-op.

    The context is still in the aggregate — nothing was deleted — and it is
    outside the boundary, so there is nothing live to cite. A freeze that wrote
    no row and said nothing would leave a citation resolving to whatever the
    live view happens to say later, which is the failure
    `concept/07-principles.md`'s copy-out rule exists to prevent.
    """
    outside = one(
        bounded,
        f"SELECT context_id FROM {HOST_CONTEXT} WHERE window_start < '2025-01-01' "
        f"ORDER BY window_start LIMIT 1",
    )
    contexts = store(bounded)
    with pytest.raises(ContextOutsideRetention) as refusal:
        contexts.freeze(outside)
    assert outside in str(refusal.value)
    assert contexts.frozen(outside) == []


@pytest.mark.integration
def test_a_store_cannot_freeze_another_deployments_context(
    bounded: psycopg.Connection,
):
    """The identity is on the store, so a context is frozen under its own tenant.

    The same rule `EventStore.record` enforces on the way in: a row written under
    another deployment's key is an isolation failure that looks like it is
    working.
    """
    context_id = one(bounded, f"SELECT context_id FROM {LIVE_HOST_CONTEXT_VIEW} LIMIT 1")
    other = store(bounded, HELENA_TENANT="another-tenant")
    with pytest.raises(ContextOutsideRetention):
        other.freeze(context_id)
    assert store(bounded).freeze(context_id).tenant == settings().identity.tenant


@pytest.mark.integration
def test_the_boundary_reports_what_it_drops(bounded: psycopg.Connection):
    """The rejection counter, against contexts whose numbers the fixture fixes.

    Ten records of the layer capture are outside the boundary and two re-stamped
    ones are inside, so the counter is 2 of 4 contexts and 10 of 12 records. The
    rate is the number `concept/07-principles.md` requires to be observable and
    `concept/08-open-questions.md` says the horizon itself will be chosen by.
    """
    rejections = store(bounded).rejections()
    assert rejections == RetentionRejections(
        tenant=settings().identity.tenant,
        sensor=settings().identity.sensor,
        horizon=RETENTION_HORIZON,
        contexts=4,
        contexts_outside_boundary=2,
        records=12,
        records_outside_boundary=10,
    )
    assert rejections.rate == 10 / 12
    assert (
        one(bounded, f"SELECT sum(flow_count) FROM {HOST_CONTEXT}")
        == rejections.records
    )


@pytest.mark.integration
def test_the_rejection_counter_keeps_two_deployments_apart(
    bounded: psycopg.Connection, tmp_path: Path
):
    """It groups by identity, and a second tenant's records are not this one's."""
    store_records(
        bounded,
        tmp_path / "other-tenant.jsonl",
        [restamped(layers_records()[2], current_window() + 3)],
        HELENA_TENANT="another-tenant",
    )
    assert store(bounded).rejections().records == 12
    other = store(bounded, HELENA_TENANT="another-tenant").rejections()
    assert other.tenant == "another-tenant"
    assert (other.records, other.records_outside_boundary) == (1, 0)
    assert other.rate == 0.0


@pytest.mark.integration
def test_a_store_with_no_contexts_reports_zeros_and_no_rate(
    migrated_engine: psycopg.Connection,
):
    """No rate over nothing.

    0.0 would read as "the boundary dropped nothing" when the truth is "nothing
    was aggregated" — the same refusal `QuarantineCounts.rate` makes, and the
    same reason `stale` and `no_match` are never one value. The horizon still
    comes from the engine, so an empty counter still reports the boundary the
    store was built with.
    """
    rejections = store(migrated_engine).rejections()
    assert (rejections.contexts, rejections.records) == (0, 0)
    assert rejections.horizon == RETENTION_HORIZON
    with pytest.raises(ValueError, match="no rejection rate"):
        rejections.rate


def test_the_rejection_counter_refuses_a_set_that_does_not_reconcile():
    """A counter that has stopped meaning anything fails loudly.

    Unit, not integration: what is checked is the contract, and a number the
    engine cannot currently produce is exactly what a broken view would produce.
    """
    with pytest.raises(ValidationError, match="does not reconcile"):
        RetentionRejections(
            tenant="t",
            sensor="s",
            horizon=RETENTION_HORIZON,
            contexts=1,
            contexts_outside_boundary=2,
            records=1,
            records_outside_boundary=0,
        )
    with pytest.raises(ValidationError, match="does not reconcile"):
        RetentionRejections(
            tenant="t",
            sensor="s",
            horizon=RETENTION_HORIZON,
            contexts=1,
            contexts_outside_boundary=0,
            records=1,
            records_outside_boundary=2,
        )
