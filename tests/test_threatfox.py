"""The ThreatFox loader: the five properties of the real export that change it.

`concept/05-threat-intelligence.md` names them, and every one is a way a loader
written from a documentation page would be wrong: `ip:port` indicators, a
compromised flag that is common rather than rare, genuinely spread numeric
confidence, a threat-type vocabulary larger than any sample, and frequently
absent references and last-seen dates with tags as a delimited string.

The fixture is a committed extract of a real export; `tests/fixtures/threatfox/README.md`
says what each entry is there for. Ratios come from the whole export and are
recorded in `helena.enrichment`, not inferred from eleven entries.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import psycopg
import pytest

from helena.enrichment import (
    EMPTY_EXPORT,
    ENRICHMENT_EVIDENCE_TABLE,
    FAILED,
    FETCH_FAILED,
    LOADED,
    MALFORMED_EXPORT,
    OK,
    THREATFOX_ENTITY_TYPES,
    THREATFOX_LOAD_TABLE,
    THREATFOX_SOURCE,
    THREATFOX_THREAT_TYPES,
    THREATFOX_UNSEEN_THREAT_TYPE,
    UNCHANGED,
    SOURCES,
    ThreatFoxError,
    ThreatFoxLoad,
    Tier,
    check_claim,
    classify_threat_type,
    load_threatfox,
    parse_threatfox,
    split_indicator,
    threatfox_claims,
)
from helena.config import Settings
from helena.observability import Redactor

# The URL lives in the script, not the package -- see that module's docstring and
# tests/test_broker.py::test_no_module_in_the_package_holds_a_broker_address.
# Imported from there so this test and the loader cannot disagree about it.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
from load_threatfox import THREATFOX_EXPORT_URL  # noqa: E402

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "threatfox" / "export.json"
RAW = FIXTURE.read_bytes()
TENANT, SENSOR = "acme", "sensor-1"

# The same shape `tests/test_enrichment.py` uses: a Settings built from an
# explicit environment rather than the developer's, so a redactor registers
# values a test controls.
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


@pytest.fixture
def redactor() -> Redactor:
    return Redactor.from_settings(
        Settings.load(environ=ENVIRONMENT, env_file=None)
    )


def snapshot():
    return threatfox_claims(RAW, tenant=TENANT, sensor=SENSOR)


# --- Flatten, never index ---------------------------------------------------


def test_the_export_is_flattened_rather_than_indexed():
    """The top level is an object keyed by indicator id whose values are lists.

    Every list in the real snapshot had length one, which is a property of that
    snapshot and not of the format. `concept/instruction.md` §6 lists reading
    `[0]` of a nested array among the traps that have already cost this project
    something, and the fixture carries one id with two entries so that a loader
    which indexed would come up one short here.
    """
    document = json.loads(RAW)
    assert all(isinstance(value, list) for value in document.values())
    assert any(len(value) > 1 for value in document.values()), (
        "the fixture no longer exercises the flatten; see its README"
    )
    entries = parse_threatfox(RAW)
    assert len(entries) == sum(len(value) for value in document.values())
    assert len(entries) > len(document)


def test_a_value_that_is_not_a_list_is_a_format_change_and_is_refused():
    """Refuse rather than skip: a publisher's format change must surface."""
    with pytest.raises(ThreatFoxError, match="the format is a list") as raised:
        parse_threatfox(b'{"1": {"ioc_type": "domain"}}')
    assert raised.value.reason == MALFORMED_EXPORT


def test_a_renamed_field_is_a_format_change_and_is_refused():
    with pytest.raises(ThreatFoxError, match="the publisher's format has changed"):
        parse_threatfox(b'{"1": [{"ioc_type": "domain", "ioc_value": "x.test"}]}')


def test_an_empty_export_leaves_the_previous_snapshot():
    """`concept/instruction.md`: never let a failure empty a table."""
    with pytest.raises(ThreatFoxError) as raised:
        parse_threatfox(b"{}")
    assert raised.value.reason == EMPTY_EXPORT


# --- ip:port, and keeping the port ------------------------------------------


def test_an_ip_port_indicator_splits_and_the_port_survives():
    """`concept/05`: a C2 on one port matched against a host that contacted
    another is a weaker claim.

    The entity is the address, because that is what a context row joins on. The
    port is in the scope and in the native evidence, so the claim still says what
    it is about.
    """
    entry = next(e for e in parse_threatfox(RAW) if e.ioc_type == "ip:port")
    entity_type, entity_value, port = split_indicator(entry)
    assert entity_type == "address"
    assert ":" not in entity_value
    assert port is not None and port > 0
    assert entry.ioc_value == f"{entity_value}:{port}"

    claim = next(c for c in snapshot().claims if c.scope_type == "address:port")
    assert claim.entity_type == "address"
    assert ":" not in claim.entity_value
    assert claim.scope_value == f"{claim.entity_value}:{claim.native_evidence['port']}"


def test_a_malformed_ip_port_is_a_format_change():
    entry = next(e for e in parse_threatfox(RAW) if e.ioc_type == "ip:port")
    broken = type(entry)(**{**entry.__dict__, "ioc_value": "1.2.3.4:not-a-port"})
    with pytest.raises(ThreatFoxError, match="ioc_value"):
        split_indicator(broken)


def test_a_domain_claim_has_no_port_and_scopes_to_itself():
    claim = next(c for c in snapshot().claims if c.entity_type == "domain")
    assert claim.scope_type == "domain"
    assert claim.scope_value == claim.entity_value
    assert "port" not in claim.native_evidence


# --- The compromised flag is evidence, never the classification -------------


def test_the_compromised_flag_is_native_evidence_and_not_the_classification():
    """`concept/05`: "A compromised flag separates victim from owner, and is
    **common, not rare**" — 16.5 % of the real export.

    *"A legitimate site currently hosting phishing is malicious at that URL and
    time even though its owner is a victim. Keep the operational role as the
    classification and the compromised flag as native evidence."* So a
    compromised entry and an uncompromised one with the same threat type carry
    the **same** classification and differ in their evidence.
    """
    claims = snapshot().claims
    compromised = [c for c in claims if c.native_evidence["is_compromised"]]
    assert compromised, "the fixture no longer carries a compromised entry"
    for claim in compromised:
        assert claim.classification == "malicious"
        assert claim.native_evidence["is_compromised"] is True
    # The flag changes nothing about the classification, which is the point.
    assert {c.classification for c in claims} == {"malicious"}


# --- Confidence reaches the claim -------------------------------------------


def test_the_entry_confidence_reaches_the_claim_rather_than_being_flattened():
    """`concept/05`: confidence is "numeric and genuinely spread" and "must reach
    the claim rather than being flattened away".

    0–100 in the export and 0.0–1.0 on the claim, which is a change of unit and
    not of meaning. Measured over the real export the values were 49, 50, 75, 80,
    90, 95 and 100 — a loader that rounded to a flag would discard the only
    per-entry signal there is.
    """
    document = json.loads(RAW)
    raw_levels = {e["confidence_level"] for v in document.values() for e in v}
    claim_levels = {c.confidence for c in snapshot().claims}
    assert len(raw_levels) > 1, "the fixture no longer has spread confidence"
    for claim in snapshot().claims:
        assert 0.0 <= claim.confidence <= 1.0
    assert {round(level * 100) for level in claim_levels} <= raw_levels


def test_confidence_is_confidence_in_the_mapping():
    """Not P(malicious) — which is why a `no_match` at 1.0 is meaningful.

    `tests/test_evidence.py` holds that case; here it is enough that a tier-B
    source's high-confidence entry and its low-confidence one are the same tier.
    """
    claims = snapshot().claims
    assert {c.source_tier for c in claims} == {Tier.B}
    assert len({c.confidence for c in claims}) > 1


# --- The threat-type mapping ------------------------------------------------


def test_every_known_threat_type_maps_deterministically():
    for threat_type, expected in THREATFOX_THREAT_TYPES.items():
        path, seen = classify_threat_type(threat_type)
        assert (path, seen) == (expected, True)
        # Twice, because "deterministic" is the claim.
        assert classify_threat_type(threat_type) == (path, seen)


def test_an_unseen_threat_type_emits_the_parent_and_is_counted():
    """`concept/02`: "a mapping with a threat type it has never seen emits
    `malicious`, not an invented `malicious.something`."

    `concept/05` warns the real vocabulary is larger than any sample, so this is
    the ordinary case rather than the exotic one — and the count is what makes
    the source's vocabulary growing visible instead of silent.
    """
    path, seen = classify_threat_type("some_type_invented_after_this_was_written")
    assert path == THREATFOX_UNSEEN_THREAT_TYPE == "malicious"
    assert seen is False

    document = json.loads(RAW)
    key = next(iter(document))
    document[key][0]["threat_type"] = "brand_new_thing"
    result = threatfox_claims(
        json.dumps(document).encode(), tenant=TENANT, sensor=SENSOR
    )
    assert result.unseen_threat_types == ("brand_new_thing",)
    unseen_claim = next(
        c for c in result.claims if not c.native_evidence["threat_type_seen_by_mapping"]
    )
    assert unseen_claim.classification == "malicious"
    assert unseen_claim.native_evidence["threat_type"] == "brand_new_thing"


def test_the_threat_type_survives_as_native_evidence():
    """Nothing is lost by emitting the root.

    `concept/05` adopts the evidence level from a published taxonomy "so that
    HELENA's evidence stays comparable with other tools' rather than re-deriving a
    vocabulary from the same providers" — so ThreatFox's threat type does not
    become a taxonomy child. It is still on the claim, where an agent can read it.
    """
    for claim in snapshot().claims:
        assert claim.native_evidence["threat_type"]


def test_every_claim_is_inside_the_declared_subset():
    """The source registry's rule, exercised against real mapped claims.

    `concept/05` rule 1 requires the declared subset to be tested; this is the
    mapping meeting its own declaration rather than a descriptor checking itself.
    """
    for claim in snapshot().claims:
        assert claim.classification in SOURCES[THREATFOX_SOURCE].emits
        check_claim(
            __import__("helena.enrichment", fromlist=["Claim"]).Claim(
                source_id=THREATFOX_SOURCE,
                entity_type=claim.entity_type,
                entity_value=claim.entity_value,
                path=claim.classification,
            )
        )


# --- Time, tags, and not inventing precision --------------------------------


def test_an_absent_last_seen_stays_absent():
    """`concept/05`: absent on 19.3 % of the real export, and never invented."""
    document = json.loads(RAW)
    assert any(
        not e.get("last_seen_utc") for v in document.values() for e in v
    ), "the fixture no longer carries an entry without last_seen"
    claims = snapshot().claims
    assert any(c.last_seen is None for c in claims)
    for claim in claims:
        assert claim.first_seen is not None
        assert claim.first_seen.tzinfo is timezone.utc


def test_a_claim_is_dated_by_first_seen_plus_the_snapshot():
    """`concept/05`: "recency cannot be read from last-seen alone"."""
    result = snapshot()
    claim = result.claims[0]
    assert result.snapshot_version in claim.dated_by
    assert claim.first_seen.isoformat() in claim.dated_by


def test_tags_are_split_from_a_delimited_string_and_an_absent_one_is_no_tags():
    """`concept/05`: "tags are a delimited string, not an array"."""
    entries = parse_threatfox(RAW)
    tagged = next(e for e in entries if e.tags)
    assert isinstance(tagged.tags, tuple)
    assert all(tag and "," not in tag for tag in tagged.tags)
    untagged = [e for e in entries if not e.tags]
    assert untagged, "the fixture no longer carries an entry without tags"
    assert untagged[0].tags == ()


# --- What did not become a claim, counted -----------------------------------


def test_file_hashes_are_skipped_and_counted():
    """ThreatFox reports file hashes and HELENA has no entity for one.

    A `fingerprint` here is a TLS JA3/JA4 — a property of a connection — not a
    file digest, so there is nothing in a host context for these to attach to.
    They are counted rather than dropped, because a skip nobody counted is how a
    reconciliation stops being possible (`concept/instruction.md` §7).
    """
    document = json.loads(RAW)
    hashes = [
        e for v in document.values() for e in v if "hash" in e["ioc_type"]
    ]
    assert hashes, "the fixture no longer carries a file hash"
    result = snapshot()
    assert result.skipped_no_entity == len(hashes)
    assert not [c for c in result.claims if "hash" in c.entity_type]
    for ioc_type in {e["ioc_type"] for e in hashes}:
        assert ioc_type not in THREATFOX_ENTITY_TYPES


def test_the_counts_reconcile():
    result = snapshot()
    assert result.entries_read == len(result.claims) + result.skipped_no_entity
    assert result.entries_read == len(parse_threatfox(RAW))


def test_a_load_row_whose_counts_do_not_reconcile_is_refused():
    with pytest.raises(ValueError, match="do not reconcile"):
        ThreatFoxLoad(
            attempted_at=datetime.now(timezone.utc),
            source_url=THREATFOX_EXPORT_URL,
            status=LOADED,
            snapshot_version="a" * 64,
            entries_read=10,
            claims_stored=5,
            skipped_no_entity=2,
            unseen_threat_types=0,
            failure_reason=None,
            failure_detail=None,
        )


def test_a_failed_load_names_no_snapshot_and_a_successful_one_names_no_reason():
    """A row that read as both would be a row nobody could act on."""
    with pytest.raises(ValueError, match="a failed load has no snapshot"):
        ThreatFoxLoad(
            attempted_at=datetime.now(timezone.utc),
            source_url=THREATFOX_EXPORT_URL,
            status=FAILED,
            snapshot_version="a" * 64,
            entries_read=None,
            claims_stored=None,
            skipped_no_entity=None,
            unseen_threat_types=None,
            failure_reason=FETCH_FAILED,
            failure_detail="",
        )
    with pytest.raises(ValueError, match="names failure reason"):
        ThreatFoxLoad(
            attempted_at=datetime.now(timezone.utc),
            source_url=THREATFOX_EXPORT_URL,
            status=LOADED,
            snapshot_version="a" * 64,
            entries_read=1,
            claims_stored=1,
            skipped_no_entity=0,
            unseen_threat_types=0,
            failure_reason=FETCH_FAILED,
            failure_detail="",
        )


# --- The loader against a real engine ---------------------------------------


@pytest.mark.integration
def test_a_load_writes_the_claims_and_a_load_row(
    migrated_engine: psycopg.Connection, redactor: Redactor
):
    load = load_threatfox(
        migrated_engine,
        tenant=TENANT,
        sensor=SENSOR,
        source_url=THREATFOX_EXPORT_URL,
        redactor=redactor,
        raw=RAW,
    )
    assert load.status == LOADED
    assert load.claims_stored == len(snapshot().claims)
    assert load.entries_read == load.claims_stored + load.skipped_no_entity

    stored = migrated_engine.execute(
        f"SELECT count(*), count(DISTINCT snapshot_version) "
        f"FROM {ENRICHMENT_EVIDENCE_TABLE} WHERE source_id = %s",
        (THREATFOX_SOURCE,),
    ).fetchone()
    assert stored == (load.claims_stored, 1)

    rows = migrated_engine.execute(
        f"SELECT status, snapshot_version, claims_stored FROM {THREATFOX_LOAD_TABLE}"
    ).fetchall()
    assert rows == [(LOADED, load.snapshot_version, load.claims_stored)]


@pytest.mark.integration
def test_the_same_bytes_twice_is_one_snapshot(
    migrated_engine: psycopg.Connection, redactor: Redactor
):
    """Two fetches of an unchanged export are one snapshot, not two copies.

    The attempt is still recorded: an operator asking why a snapshot is old needs
    to see that a fetch happened and returned the same bytes.
    """
    first = load_threatfox(
        migrated_engine,
        tenant=TENANT,
        sensor=SENSOR,
        source_url=THREATFOX_EXPORT_URL,
        redactor=redactor,
        raw=RAW
    )
    second = load_threatfox(
        migrated_engine,
        tenant=TENANT,
        sensor=SENSOR,
        source_url=THREATFOX_EXPORT_URL,
        redactor=redactor,
        raw=RAW
    )
    assert first.status == LOADED
    assert second.status == UNCHANGED
    assert second.snapshot_version == first.snapshot_version
    count = migrated_engine.execute(
        f"SELECT count(*) FROM {ENRICHMENT_EVIDENCE_TABLE} WHERE source_id = %s",
        (THREATFOX_SOURCE,),
    ).fetchone()[0]
    assert count == first.claims_stored
    attempts = migrated_engine.execute(
        f"SELECT count(*) FROM {THREATFOX_LOAD_TABLE}"
    ).fetchone()[0]
    assert attempts == 2


@pytest.mark.integration
def test_a_failed_fetch_leaves_the_previous_snapshot_and_records_the_failure(
    migrated_engine: psycopg.Connection, redactor: Redactor
):
    """`concept/instruction.md`: never let a failure empty a table.

    The result is `stale` — the claims are still there and still joinable — never
    a silent empty opinion, which downstream would read as `no_match`.
    """
    good = load_threatfox(
        migrated_engine,
        tenant=TENANT,
        sensor=SENSOR,
        source_url=THREATFOX_EXPORT_URL,
        redactor=redactor,
        raw=RAW
    )
    bad = load_threatfox(
        migrated_engine,
        tenant=TENANT,
        sensor=SENSOR,
        source_url=THREATFOX_EXPORT_URL,
        redactor=redactor,
        raw=b"not json at all",
    )
    assert bad.status == FAILED
    assert bad.failure_reason == MALFORMED_EXPORT
    assert bad.snapshot_version is None

    survived = migrated_engine.execute(
        f"SELECT count(*), max(snapshot_version) FROM {ENRICHMENT_EVIDENCE_TABLE} "
        f"WHERE source_id = %s",
        (THREATFOX_SOURCE,),
    ).fetchone()
    assert survived == (good.claims_stored, good.snapshot_version)


@pytest.mark.integration
def test_a_new_snapshot_replaces_the_old_one(
    migrated_engine: psycopg.Connection, redactor: Redactor
):
    """Insert then delete, so a half-done replacement is a superset.

    0008 argues the order: a superset for a moment is a reader seeing an old
    claim beside a new one, and an empty table for a moment is a reader seeing
    `no_match` where there is a hit.
    """
    first = load_threatfox(
        migrated_engine,
        tenant=TENANT,
        sensor=SENSOR,
        source_url=THREATFOX_EXPORT_URL,
        redactor=redactor,
        raw=RAW
    )
    document = json.loads(RAW)
    document[next(iter(document))][0]["confidence_level"] = 51
    second = load_threatfox(
        migrated_engine,
        tenant=TENANT,
        sensor=SENSOR,
        source_url=THREATFOX_EXPORT_URL,
        redactor=redactor,
        raw=json.dumps(document).encode(),
    )
    assert second.status == LOADED
    assert second.snapshot_version != first.snapshot_version
    held = migrated_engine.execute(
        f"SELECT DISTINCT snapshot_version FROM {ENRICHMENT_EVIDENCE_TABLE} "
        f"WHERE source_id = %s",
        (THREATFOX_SOURCE,),
    ).fetchall()
    assert held == [(second.snapshot_version,)]


@pytest.mark.integration
def test_a_stored_claim_is_a_well_formed_evidence_row(
    migrated_engine: psycopg.Connection, redactor: Redactor
):
    """Status `ok` with a classification, and the four statuses stay apart."""
    load_threatfox(
        migrated_engine,
        tenant=TENANT,
        sensor=SENSOR,
        source_url=THREATFOX_EXPORT_URL,
        redactor=redactor,
        raw=RAW
    )
    statuses = migrated_engine.execute(
        f"SELECT DISTINCT status FROM {ENRICHMENT_EVIDENCE_TABLE} WHERE source_id = %s",
        (THREATFOX_SOURCE,),
    ).fetchall()
    assert statuses == [(OK,)]
    nulls = migrated_engine.execute(
        f"SELECT count(*) FROM {ENRICHMENT_EVIDENCE_TABLE} "
        f"WHERE source_id = %s AND classification IS NULL",
        (THREATFOX_SOURCE,),
    ).fetchone()[0]
    assert nulls == 0


@pytest.mark.integration
def test_the_recorded_url_goes_through_the_redactor(
    migrated_engine: psycopg.Connection, redactor: Redactor
):
    """The rule is about the channel, not about this provider.

    This endpoint needs no credential — measured 2026-09-06, and re-measured
    because the concept note's earlier claim that it did was wrong. The redactor
    is applied anyway: `concept/instruction.md` §6 requires a credential in a URL
    to be redacted before anything is **stored**, and abuse.ch may change its auth
    on its own schedule.
    """
    secret = "supersecretkey"
    load_threatfox(
        migrated_engine,
        tenant=TENANT,
        sensor=SENSOR,
        source_url=f"{THREATFOX_EXPORT_URL}?auth_key={secret}",
        redactor=Redactor([secret]),
        raw=RAW,
    )
    stored = migrated_engine.execute(
        f"SELECT source_url FROM {THREATFOX_LOAD_TABLE}"
    ).fetchall()
    assert stored
    for (url,) in stored:
        assert secret not in url
