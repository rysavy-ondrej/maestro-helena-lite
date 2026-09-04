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
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg
import pytest

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
def test_the_host_context_is_a_materialized_view(migrated_engine: psycopg.Connection):
    """The declaration in the migration file, checked against the engine.

    The flatten layer below is plain views because a materialized intermediate
    that only feeds an aggregate costs 42 % more disk for rows nothing reads
    (`concept/03-architecture.md`). This is the aggregate, it is queried by host
    and window on its own, and it is the row a finding will cite — so it is
    materialized, and a plain view appearing here would be a citable row that
    exists only as a query plan.
    """
    assert rows(
        migrated_engine,
        "SELECT table_name, table_type FROM information_schema.tables "
        "WHERE table_schema = current_schema() "
        "AND table_name LIKE 'helena_signal_%'",
    ) == [(HOST_CONTEXT, "MATERIALIZED VIEW")]


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
