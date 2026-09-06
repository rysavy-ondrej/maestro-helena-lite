"""The enrichment views: reference tables in, evidence-level claims out.

`concept/03-architecture.md` calls them "SQL mapping and join views turning
reference tables into enrichment evidence and the enriched context. **No runtime
service**." Every test here runs against a real engine, because a mapping view
that was only read is a mapping nobody has seen produce a row.

`tests/test_threatfox.py` covers the other half — what the loader does with the
publisher's format, which is decisions about *this feed*. This file covers what
is the same for every feed: the evidence shape, the identifier, the tiers, and
that a mapped row is a taxonomy path the source declared it could emit.
"""

from __future__ import annotations

from pathlib import Path

import psycopg
import pytest

from helena import taxonomy
from helena.config import Settings
from helena.enrichment import (
    ENRICHMENT_EVIDENCE_VIEW,
    OK,
    SOURCES,
    THREATFOX_REFERENCE_TABLE,
    THREATFOX_SOURCE,
    Claim,
    EnrichmentEvidence,
    Tier,
    check_claim,
    evidence_id,
    load_threatfox,
    threatfox_rows,
)
from helena.observability import Redactor

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "threatfox" / "export.json"
RAW = FIXTURE.read_bytes()
TENANT, SENSOR = "acme", "sensor-1"
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

# The engine's evidence shape, held here as the second copy of the interface —
# the same deliberate friction FLATTEN_SHAPES and REGISTRABLE_SHAPE are.
EVIDENCE_SHAPE = {
    "evidence_id",
    "tenant",
    "sensor",
    "source_id",
    "source_tier",
    "evidence_tier",
    "snapshot_version",
    "entity_type",
    "entity_value",
    "status",
    "classification",
    "taxonomy_version",
    "confidence",
    "scope_type",
    "scope_value",
    "first_seen",
    "last_seen",
    "valid_until",
    "native_evidence",
}


@pytest.fixture
def loaded(migrated_engine: psycopg.Connection) -> psycopg.Connection:
    """A migrated engine holding the committed extract as its ThreatFox snapshot."""
    load_threatfox(
        migrated_engine,
        tenant=TENANT,
        sensor=SENSOR,
        source_url=URL,
        redactor=Redactor.from_settings(
            Settings.load(environ=ENVIRONMENT, env_file=None)
        ),
        raw=RAW,
    )
    return migrated_engine


def claims(connection: psycopg.Connection) -> list[dict]:
    cursor = connection.execute(f"SELECT * FROM {ENRICHMENT_EVIDENCE_VIEW}")
    names = [d.name for d in cursor.description]
    return [dict(zip(names, row)) for row in cursor.fetchall()]


# --- There is a mapping view, and it produces the evidence shape ------------


@pytest.mark.integration
def test_the_view_presents_the_evidence_shape(loaded: psycopg.Connection):
    columns = {
        row[0]
        for row in loaded.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_name = %s",
            (ENRICHMENT_EVIDENCE_VIEW,),
        ).fetchall()
    }
    assert columns == EVIDENCE_SHAPE


@pytest.mark.integration
def test_every_reference_row_becomes_exactly_one_claim(loaded: psycopg.Connection):
    """A projection, not an aggregate: nothing is collapsed on the way through."""
    expected = len(threatfox_rows(RAW).rows)
    stored = loaded.execute(
        f"SELECT count(*) FROM {THREATFOX_REFERENCE_TABLE}"
    ).fetchone()[0]
    assert stored == expected
    assert len(claims(loaded)) == expected


@pytest.mark.integration
def test_a_mapped_row_validates_as_the_python_evidence_model(
    loaded: psycopg.Connection,
):
    """The shape the view produces is the shape `EnrichmentEvidence` describes.

    Read back and re-validated, so a column that stopped meaning what it meant is
    a `ValidationError` here rather than a row that still selects.
    """
    for row in claims(loaded):
        fields = {
            k: v
            for k, v in row.items()
            if k not in ("tenant", "sensor", "evidence_tier")
        }
        # The engine stores the tier's value and the model's field is the enum;
        # converting at the boundary is the reader's job, and strict mode is what
        # makes that a decision rather than a coercion nobody noticed.
        fields["source_tier"] = Tier(fields["source_tier"])
        model = EnrichmentEvidence(**fields)
        assert model.status == OK
        assert model.verdict == model.classification.split(".")[0]


# --- The identifier, in two homes, asserted equal ---------------------------


@pytest.mark.integration
def test_the_engine_and_python_derive_the_same_evidence_id(
    loaded: psycopg.Connection,
):
    """Two homes for one construction, checked by asking the engine.

    `sql/migrations/0014_feed_mapping_views.sql` is what produces the identifier;
    `helena.enrichment.evidence_id` is the same digest in Python. Two copies that
    can drift are worse than none — these cannot, because this asks the engine
    rather than reading the file.
    """
    reference = {
        (row["indicator_id"], row["record_offset"]): row
        for row in _reference_rows(loaded)
    }
    assert reference
    for claim in claims(loaded):
        native = claim["native_evidence"]
        row = reference[(native["indicator_id"], _offset_of(loaded, claim))]
        assert claim["evidence_id"] == evidence_id(
            tenant=TENANT,
            sensor=SENSOR,
            source_id=THREATFOX_SOURCE,
            snapshot_version=claim["snapshot_version"],
            entity_type=claim["entity_type"],
            entity_value=claim["entity_value"],
            classification=claim["classification"],
            scope_type=claim["scope_type"],
            scope_value=claim["scope_value"],
            native_record=f"{row['indicator_id']}:{row['record_offset']}",
        )


def _reference_rows(connection: psycopg.Connection) -> list[dict]:
    cursor = connection.execute(f"SELECT * FROM {THREATFOX_REFERENCE_TABLE}")
    names = [d.name for d in cursor.description]
    return [dict(zip(names, row)) for row in cursor.fetchall()]


def _offset_of(connection: psycopg.Connection, claim: dict) -> int:
    """The record offset behind one claim, from its native evidence."""
    for row in _reference_rows(connection):
        if (
            row["indicator_id"] == claim["native_evidence"]["indicator_id"]
            and row["entity_value"] == claim["entity_value"]
            and row["snapshot_version"] == claim["snapshot_version"]
        ):
            return row["record_offset"]
    raise AssertionError("no reference row behind this claim")


@pytest.mark.integration
def test_the_identifier_is_stable_across_a_reload(loaded: psycopg.Connection):
    """A citation survives replay: the same bytes produce the same identifiers."""
    before = sorted(claim["evidence_id"] for claim in claims(loaded))
    load_threatfox(
        loaded,
        tenant=TENANT,
        sensor=SENSOR,
        source_url=URL,
        redactor=Redactor.from_settings(
            Settings.load(environ=ENVIRONMENT, env_file=None)
        ),
        raw=RAW,
    )
    assert sorted(claim["evidence_id"] for claim in claims(loaded)) == before


@pytest.mark.integration
def test_two_records_under_one_indicator_id_are_two_claims(
    loaded: psycopg.Connection,
):
    """The fixture's constructed id carries two entries — see its README.

    The native record is the publisher's key **and the offset within the list it
    keys**, so two entries under one id are two identifiers rather than one that
    silently keeps the last.
    """
    by_indicator: dict[str, set[str]] = {}
    for claim in claims(loaded):
        by_indicator.setdefault(
            claim["native_evidence"]["indicator_id"], set()
        ).add(claim["evidence_id"])
    multiple = {k: v for k, v in by_indicator.items() if len(v) > 1}
    assert multiple, "the fixture no longer carries an id with two entries"
    for identifiers in multiple.values():
        assert len(identifiers) == len(set(identifiers))


# --- Contradictions are preserved -------------------------------------------


@pytest.mark.integration
def test_nothing_aggregates_or_deduplicates(loaded: psycopg.Connection):
    """`concept/05` rule 6: never collapse disagreement before the agent sees it.

    An entity with several claims keeps several rows. The view is `UNION ALL` and
    a projection — there is no `DISTINCT`, no `GROUP BY` and nothing that could
    pick between two claims.
    """
    rows = claims(loaded)
    per_entity: dict[tuple[str, str], int] = {}
    for row in rows:
        key = (row["entity_type"], row["entity_value"])
        per_entity[key] = per_entity.get(key, 0) + 1
    assert sum(per_entity.values()) == len(rows)
    assert len({row["evidence_id"] for row in rows}) == len(rows)


# --- The tiers, which answer different questions ----------------------------


@pytest.mark.integration
def test_every_row_is_tagged_with_the_enrichment_evidence_tier(
    loaded: psycopg.Connection,
):
    """`concept/05` splits the system's evidence in two.

    The **enrichment tier** is static feeds joined in SQL; the **analyst tier** is
    live providers queried through tools. It is not the A–D source tier, which
    says how strong a source is — these answer different questions about the same
    row, and a live-provider claim will carry `analyst` and the same shape
    otherwise.
    """
    assert {row["evidence_tier"] for row in claims(loaded)} == {"enrichment"}


@pytest.mark.integration
def test_the_source_tier_is_the_registry_s_and_not_the_view_s_invention(
    loaded: psycopg.Connection,
):
    tiers = {row["source_tier"] for row in claims(loaded)}
    assert tiers == {SOURCES[THREATFOX_SOURCE].tier.value}
    assert SOURCES[THREATFOX_SOURCE].tier is Tier.B


# --- Every mapped row is a path the source declared it could emit ------------


@pytest.mark.integration
def test_every_mapped_row_is_a_valid_taxonomy_path(loaded: psycopg.Connection):
    """Step 5, as an execution test rather than a claim about the mapping table.

    The rows came out of the engine, so this is the view's output being checked
    against the vocabulary rather than the Python that fed it.
    """
    for row in claims(loaded):
        resolved = taxonomy.resolve(
            row["classification"],
            level=taxonomy.EVIDENCE,
            version=row["taxonomy_version"],
        )
        assert resolved.path == row["classification"]
        assert not resolved.unused


@pytest.mark.integration
def test_every_mapped_row_is_inside_the_source_s_declared_subset(
    loaded: psycopg.Connection,
):
    """`concept/05` rule 1 requires the declared subset to be tested.

    This is the mapping meeting its own declaration, on rows the engine produced
    — the strongest form of that check available, because it is what a join would
    actually see.
    """
    for row in claims(loaded):
        check_claim(
            Claim(
                source_id=row["source_id"],
                entity_type=row["entity_type"],
                entity_value=row["entity_value"],
                path=row["classification"],
            )
        )


# --- The scope, and what the loader normalized ------------------------------


@pytest.mark.integration
def test_an_ip_port_claim_scopes_to_the_address_and_port(loaded: psycopg.Connection):
    """The entity is the address, because that is what a context row joins on.

    The scope is the address on that port, because that is what the claim is
    about — `concept/05`: a C2 on one port matched against a host that contacted
    another is a weaker claim.
    """
    scoped = [row for row in claims(loaded) if row["scope_type"] == "address:port"]
    assert scoped, "the fixture no longer carries an ip:port indicator"
    for row in scoped:
        assert row["entity_type"] == "address"
        assert ":" not in row["entity_value"]
        port = row["native_evidence"]["port"]
        assert row["scope_value"] == f"{row['entity_value']}:{port}"


@pytest.mark.integration
def test_a_claim_without_a_port_scopes_to_its_entity(loaded: psycopg.Connection):
    for row in claims(loaded):
        if row["scope_type"] != "address:port":
            assert row["scope_type"] == row["entity_type"]
            assert row["scope_value"] == row["entity_value"]


@pytest.mark.integration
def test_the_confidence_reaches_the_claim_as_a_fraction(loaded: psycopg.Connection):
    """0–100 in the reference table, 0.0–1.0 on the claim: a change of unit."""
    levels = {
        row[0]
        for row in loaded.execute(
            f"SELECT DISTINCT confidence_level FROM {THREATFOX_REFERENCE_TABLE}"
        ).fetchall()
    }
    mapped = {row["confidence"] for row in claims(loaded)}
    assert len(mapped) > 1, "the fixture no longer has spread confidence"
    assert {round(value * 100) for value in mapped} == levels


@pytest.mark.integration
def test_the_compromised_flag_reaches_the_claim_as_native_evidence(
    loaded: psycopg.Connection,
):
    """Never the classification — `concept/05`, and the view does not vary on it."""
    rows = claims(loaded)
    compromised = [row for row in rows if row["native_evidence"]["is_compromised"]]
    assert compromised, "the fixture no longer carries a compromised entry"
    assert {row["classification"] for row in rows} == {"malicious"}
