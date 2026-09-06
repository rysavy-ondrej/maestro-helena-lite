"""The enriched context: a join, per entity, against the snapshot that was current.

Every test runs a real capture through the real ingestion path and a real
ThreatFox extract through the real loader, then reads the analytical view. There
is no way to test a join by describing it.

Two of these are the ones the task asks for by name, and both are about absence:
an entity with no hit anywhere yields `no_match` and **not a missing row**,
because an enriched context is mostly negative space; and loading a newer
snapshot does not change what an older window was enriched with, because replay
joins the snapshot current at event time.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path

import psycopg
import pytest

from helena.config import Settings
from helena.enrichment import SOURCES, THREATFOX_SOURCE, load_threatfox
from helena.normalizer import EventStore, Normalizer, read_capture, scan_captures
from helena.observability import Redactor

FIXTURE_CAPTURES = Path(__file__).resolve().parent / "fixtures" / "captures"
LAYERS_CAPTURE = "ace6ca33f7bf8aa949f79124abf33fc115cfd0909e9dea798f4762cf87af8318"
THREATFOX_FIXTURE = (
    Path(__file__).resolve().parent / "fixtures" / "threatfox" / "export.json"
)
RAW = THREATFOX_FIXTURE.read_bytes()
TENANT, SENSOR = "tenant-under-test", "sensor-under-test"
URL = "https://threatfox.invalid/export/json/recent/"

ENVIRONMENT = {
    "LLM_URL": "http://model.invalid/v1",
    "LLM_TOKEN": "token-under-test",
    "LLM_MODEL": "model-under-test",
    "HELENA_TENANT": TENANT,
    "HELENA_SENSOR": SENSOR,
    "HELENA_INPUT_FORMAT": "flow-json",
    "ABUSECH_AUTH_KEY": "abusech-key-under-test",
    "VIRUSTOTAL_AUTH_KEY": "virustotal-key-under-test",
    "RISINGWAVE_DSN": "postgresql://root@localhost:4566/dev",
    "KAFKA_BOOTSTRAP_SERVERS": "localhost:9092",
    "HELENA_INGEST_TOPIC": "helena.ingest",
}
VIEW = "helena_analytical_enriched_context"


def settings() -> Settings:
    return Settings.load(environ=ENVIRONMENT, env_file=None)


def redactor() -> Redactor:
    return Redactor.from_settings(settings())


def store_capture(connection: psycopg.Connection) -> None:
    """Every record of the layer-coverage capture, through the real normalizer."""
    configured = settings()
    normalizer = Normalizer.from_settings(configured)
    events = EventStore(connection=connection, identity=configured.identity)
    capture = scan_captures(FIXTURE_CAPTURES)[LAYERS_CAPTURE]
    for offset, line in read_capture(capture):
        events.record(normalizer.normalize(capture, offset, line))
    connection.execute("FLUSH")


def rows(
    connection: psycopg.Connection, where: str = "", params: tuple = ()
) -> list[dict]:
    cursor = connection.execute(f"SELECT * FROM {VIEW} {where}".strip(), params)
    names = [d.name for d in cursor.description]
    return [dict(zip(names, row)) for row in cursor.fetchall()]


def load(connection: psycopg.Connection, raw: bytes, *, now: datetime | None = None):
    return load_threatfox(
        connection,
        tenant=TENANT,
        sensor=SENSOR,
        source_url=URL,
        redactor=redactor(),
        raw=raw,
        now=now,
    )


def targeted(raw: bytes, entity_value: str, ioc_type: str = "domain") -> bytes:
    """The extract with one entry repointed at an entity the capture has.

    The committed extract names indicators from the real feed and the committed
    capture is one Windows host's routine traffic, so nothing in one appears in
    the other — realistic, and useless for testing a match. One entry is
    repointed so the join has something to join.
    """
    document = json.loads(raw)
    key = sorted(document)[0]
    document[key][0]["ioc_type"] = ioc_type
    document[key][0]["ioc_value"] = entity_value
    return json.dumps(document).encode()


@pytest.fixture
def context(migrated_engine: psycopg.Connection) -> psycopg.Connection:
    """A migrated engine holding one capture's contexts and entities."""
    store_capture(migrated_engine)
    return migrated_engine


def an_entity(connection: psycopg.Connection, entity_type: str = "domain") -> str:
    value = connection.execute(
        "SELECT entity_value FROM helena_signal_context_entities "
        "WHERE entity_type = %s ORDER BY entity_value LIMIT 1",
        (entity_type,),
    ).fetchone()
    assert value, f"the capture produced no {entity_type} entity"
    return value[0]


def first_window(connection: psycopg.Connection) -> datetime:
    return connection.execute(
        "SELECT min(window_start) FROM helena_signal_host_context"
    ).fetchone()[0]


# --- The layer boundary this view is the first to cross ---------------------


def test_the_enriched_context_is_the_first_analytical_object():
    """`MAY_READ`'s `analytical` row was describable and unexercised until now."""
    from helena import migrations

    declared = migrations.declarations()
    analytical = [k for k, v in declared.items() if v.layer == "analytical"]
    assert analytical == [VIEW]
    allowed = {k for k, v in declared.items() if v.layer in ("signal", "reference")}
    assert declared[VIEW].reads <= allowed


# --- Mostly negative space --------------------------------------------------


@pytest.mark.integration
def test_an_entity_with_no_hit_yields_no_match_and_not_an_absent_row(
    context: psycopg.Connection,
):
    """The test the task asks for by name, and the one the design turns on.

    `concept/02`: with sparse blocklist coverage **most entities have no hit on
    anything**, so an enriched context is mostly negative space — and triage
    reading "no hit" as "clean" is the failure mode the whole design exists to
    prevent. An absent row cannot be read as anything; a `no_match` row can be
    read as what it is.
    """
    load(context, RAW, now=first_window(context) - timedelta(hours=1))
    enriched = rows(context)
    assert enriched, "the join produced nothing at all"

    entities = context.execute(
        "SELECT count(*) FROM helena_signal_context_entities"
    ).fetchone()[0]
    # One source has been asked, so every entity gets exactly one row.
    assert len(enriched) == entities

    unmatched = [row for row in enriched if row["evidence_id"] is None]
    assert unmatched, "nothing in this capture was absent from the feed"
    for row in unmatched:
        assert row["classification"] == "no_match"
        assert row["snapshot_version"] is not None


@pytest.mark.integration
def test_no_match_is_a_classification_and_never_a_status(context: psycopg.Connection):
    load(context, RAW, now=first_window(context) - timedelta(hours=1))
    statuses = {row["status"] for row in rows(context)}
    assert "no_match" not in statuses
    assert statuses <= {"ok", "stale", "failed", "missing"}


# --- A hit, and what comes with it ------------------------------------------


@pytest.mark.integration
def test_a_matching_entity_carries_the_claim_and_its_provenance(
    context: psycopg.Connection,
):
    value = an_entity(context)
    loaded = load(
        context, targeted(RAW, value), now=first_window(context) - timedelta(hours=1)
    )
    matched = rows(
        context, "WHERE entity_value = %s AND evidence_id IS NOT NULL", (value,)
    )
    assert matched, f"nothing matched {value}"
    for row in matched:
        assert row["classification"] == "malicious"
        assert row["source_id"] == THREATFOX_SOURCE
        assert row["source_tier"] == SOURCES[THREATFOX_SOURCE].tier.value
        assert row["evidence_tier"] == "enrichment"
        assert row["snapshot_version"] == loaded.snapshot_version
        assert row["taxonomy_version"] == "v1"
        assert 0.0 <= row["confidence"] <= 1.0
        # The scope columns the composition rule reads travel with the claim.
        assert row["observed_flow_count"] >= 1


@pytest.mark.integration
def test_the_claim_does_not_become_a_verdict(context: psycopg.Connection):
    """`concept/02`'s composition rule, as an absence.

    "An evidence-level classification about a contacted indicator does not become
    the context verdict" is the single most consequential rule in the taxonomy,
    and the way this view respects it is by carrying **no verdict column at all**.
    A reader weighs the claim against the traffic beside it; this view weighs
    nothing.
    """
    columns = {
        row[0]
        for row in context.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_name = %s",
            (VIEW,),
        ).fetchall()
    }
    assert not columns & {"verdict", "severity", "score", "risk"}
    assert {"classification", "confidence", "observed_as_flow_destination"} <= columns


# --- The snapshot current at event time -------------------------------------


@pytest.mark.integration
def test_a_newer_snapshot_does_not_change_an_older_window(
    context: psycopg.Connection,
):
    """The second test the task asks for by name.

    `concept/02`: *"Replay joins the snapshot current at event time, not
    today's."* A context enriched against whatever happens to be loaded now would
    be a different assessment every time it was read, and a stored one could
    never be reproduced.
    """
    value = an_entity(context)
    window = first_window(context)

    before = load(context, targeted(RAW, value), now=window - timedelta(hours=1))
    matched = rows(
        context, "WHERE entity_value = %s AND evidence_id IS NOT NULL", (value,)
    )
    assert matched, "the snapshot current at event time did not join"
    assert {row["snapshot_version"] for row in matched} == {before.snapshot_version}

    # A snapshot loaded long after that window must not reach it, even though it
    # is the newest one now.
    after = load(
        context,
        targeted(RAW, value, ioc_type="url"),
        now=window + timedelta(days=30),
    )
    assert after.snapshot_version != before.snapshot_version
    still = rows(
        context, "WHERE entity_value = %s AND evidence_id IS NOT NULL", (value,)
    )
    assert {row["snapshot_version"] for row in still} == {before.snapshot_version}


@pytest.mark.integration
def test_a_window_before_any_snapshot_has_nothing_to_join(
    context: psycopg.Connection,
):
    """Loaded after the fact, so no snapshot covered that window.

    Not `no_match` — there was nothing to look in — and that is the difference
    the four statuses exist to keep.
    """
    load(context, RAW, now=first_window(context) + timedelta(days=30))
    enriched = rows(context)
    assert enriched
    assert {row["status"] for row in enriched} == {"missing"}
    assert {row["classification"] for row in enriched} == {None}


# --- The four statuses, distinguishable on the row --------------------------


@pytest.mark.integration
def test_a_stale_snapshot_says_so_and_keeps_its_claim(context: psycopg.Connection):
    """An aged snapshot is evidence with a date on it, not evidence withdrawn.

    `concept/02`: removal from a feed is not exoneration — and neither is a feed
    going quiet. The claim stands and the row says how old it is.
    """
    value = an_entity(context)
    load(context, targeted(RAW, value), now=first_window(context) - timedelta(hours=1))
    matched = rows(
        context, "WHERE entity_value = %s AND evidence_id IS NOT NULL", (value,)
    )
    assert matched
    for row in matched:
        # The capture is dated 2024-06-01, so a snapshot current at that window
        # is far older than ThreatFox's own refresh interval today.
        assert row["status"] == "stale"
        assert row["classification"] == "malicious"
        assert row["snapshot_loaded_at"] is not None


@pytest.mark.integration
def test_a_failed_attempt_is_told_from_never_having_asked(
    context: psycopg.Connection,
):
    """`failed` and `missing` are both "no data" and are different facts.

    `concept/instruction.md` forbids collapsing them: one is a source that was
    tried and could not answer, the other a source that was never asked.
    """
    load(context, b"{}", now=first_window(context) - timedelta(hours=1))
    enriched = rows(context)
    assert enriched
    assert {row["status"] for row in enriched} == {"failed"}
    assert {row["classification"] for row in enriched} == {None}


@pytest.mark.integration
def test_a_source_never_asked_produces_no_rows_rather_than_missing_ones(
    context: psycopg.Connection,
):
    """Stated in 0015's head rather than hidden.

    The source list is every source that has ever been asked, read off the
    ledger, because a second copy of the registry in SQL is a second copy that
    can disagree. A registered source that has never attempted a load therefore
    has no row here — `helena.enrichment.feed_status` is what reports `missing`
    for it, which is a question about the source and not about any entity.
    """
    assert "sslbl-ja3" in SOURCES
    load(context, RAW, now=first_window(context) - timedelta(hours=1))
    assert {row["source_id"] for row in rows(context)} == {THREATFOX_SOURCE}


# --- Port qualification -----------------------------------------------------


def a_contacted_port(connection: psycopg.Connection) -> tuple[str, int]:
    reached = connection.execute(
        "SELECT entity_value, port FROM helena_signal_context_entity_ports "
        "ORDER BY entity_value, port LIMIT 1"
    ).fetchone()
    assert reached, "the capture produced no contacted port"
    return reached[0], reached[1]


@pytest.mark.integration
def test_a_port_scoped_claim_records_that_the_port_matched(
    context: psycopg.Connection,
):
    """`concept/05`: a C2 on one port matched against a host that contacted
    another is a weaker claim — so the row has to say which case it is.
    """
    address, port = a_contacted_port(context)
    load(
        context,
        targeted(RAW, f"{address}:{port}", ioc_type="ip:port"),
        now=first_window(context) - timedelta(hours=1),
    )
    matched = rows(
        context, "WHERE entity_value = %s AND evidence_id IS NOT NULL", (address,)
    )
    assert matched, f"nothing matched {address}"
    assert any(row["port_matched"] for row in matched)
    for row in matched:
        assert row["scope_type"] == "address:port"
        assert row["scope_value"] == f"{address}:{port}"


@pytest.mark.integration
def test_a_claim_on_a_port_the_host_never_reached_is_kept_and_marked(
    context: psycopg.Connection,
):
    """The weaker claim, still on the row.

    Three-valued and not a filter: dropping it would be the view deciding the
    composition rule's question, and the rule's answer is "suspicious at most",
    which needs the row to exist.
    """
    address, port = a_contacted_port(context)
    elsewhere = 1 if port != 1 else 2
    load(
        context,
        targeted(RAW, f"{address}:{elsewhere}", ioc_type="ip:port"),
        now=first_window(context) - timedelta(hours=1),
    )
    matched = rows(
        context, "WHERE entity_value = %s AND evidence_id IS NOT NULL", (address,)
    )
    assert matched, "the claim on the other port did not join"
    for row in matched:
        assert row["port_matched"] is False
        assert row["classification"] == "malicious"


@pytest.mark.integration
def test_a_claim_that_is_not_port_scoped_leaves_the_question_unasked(
    context: psycopg.Connection,
):
    """NULL, not false: the question does not arise for a domain claim."""
    value = an_entity(context)
    load(context, targeted(RAW, value), now=first_window(context) - timedelta(hours=1))
    matched = rows(
        context, "WHERE entity_value = %s AND evidence_id IS NOT NULL", (value,)
    )
    assert matched
    for row in matched:
        assert row["scope_type"] == "domain"
        assert row["port_matched"] is None
