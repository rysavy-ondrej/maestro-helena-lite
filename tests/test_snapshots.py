"""Snapshot versioning: history to replay from, and never emptying a table.

`concept/05-threat-intelligence.md`: *"write a snapshot version with every load
and keep enough history for replay"*, and *"never let a failure empty a table — a
fetch failure, a format change or an empty response leaves the previous snapshot
in place and records the failure, so the result is `stale` or `missing`, never a
silent empty opinion."*

Three failure modes, each asserting the same two things: the previous snapshot
survives, and the failure is on the record. Plus the two statuses that are
functions of the clock rather than properties of a row.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg
import pytest

from helena.config import Settings
from helena.enrichment import (
    EMPTY_EXPORT,
    ENRICHMENT_EVIDENCE_VIEW,
    FAILED,
    FEED_SNAPSHOT_CURRENT_VIEW,
    FEED_SNAPSHOT_TABLE,
    FETCH_FAILED,
    LOADED,
    MALFORMED_EXPORT,
    MISSING,
    OK,
    SNAPSHOTS_KEPT,
    SOURCES,
    STALE,
    THREATFOX_SOURCE,
    UNCHANGED,
    FeedSnapshot,
    feed_status,
    load_threatfox,
    prune_snapshots,
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


@pytest.fixture
def redactor() -> Redactor:
    return Redactor.from_settings(Settings.load(environ=ENVIRONMENT, env_file=None))


def load(connection: psycopg.Connection, redactor: Redactor, raw: bytes) -> FeedSnapshot:
    return load_threatfox(
        connection,
        tenant=TENANT,
        sensor=SENSOR,
        source_url=URL,
        redactor=redactor,
        raw=raw,
    )


def claims_held(connection: psycopg.Connection) -> dict[str, int]:
    """Snapshot version -> how many claims of it the evidence table holds."""
    connection.execute("FLUSH")
    return {
        version: count
        for version, count in connection.execute(
            f"SELECT snapshot_version, count(*) FROM {ENRICHMENT_EVIDENCE_VIEW} "
            f"WHERE source_id = %s GROUP BY snapshot_version",
            (THREATFOX_SOURCE,),
        ).fetchall()
    }


def varied(seed: int) -> bytes:
    """The fixture with one confidence changed, so the bytes hash differently."""
    document = json.loads(RAW)
    document[sorted(document)[0]][0]["confidence_level"] = 50 + seed
    return json.dumps(document).encode()


# --- Never empty a table: three failure modes, one guarantee ----------------


@pytest.mark.integration
@pytest.mark.parametrize(
    ("raw", "reason", "what"),
    [
        (b"not json at all", MALFORMED_EXPORT, "a format change"),
        (b"{}", EMPTY_EXPORT, "an empty response"),
        (b'{"1": {"not": "a list"}}', MALFORMED_EXPORT, "a reshaped export"),
    ],
    ids=["malformed", "empty", "reshaped"],
)
def test_a_failed_load_leaves_the_snapshot_and_records_the_failure(
    migrated_engine: psycopg.Connection,
    redactor: Redactor,
    raw: bytes,
    reason: str,
    what: str,
):
    """`concept/instruction.md`: the result is `stale`, never a silent empty opinion.

    An emptied table would read downstream as `no_match` — a source that ran and
    found nothing — which is the failure mode `concept/02` says the whole design
    exists to prevent, arriving through the loader instead of through triage.
    """
    good = load(migrated_engine, redactor, RAW)
    before = claims_held(migrated_engine)
    assert before, "the good load stored nothing"

    bad = load(migrated_engine, redactor, raw)
    assert bad.outcome == FAILED, what
    assert bad.failure_reason == reason
    assert bad.snapshot_version is None
    assert bad.failure_detail

    assert claims_held(migrated_engine) == before
    assert feed_status(
        migrated_engine, tenant=TENANT, sensor=SENSOR, source_id=THREATFOX_SOURCE
    ).snapshot_version == good.snapshot_version


@pytest.mark.integration
def test_a_fetch_failure_is_recorded_the_same_way(
    migrated_engine: psycopg.Connection, redactor: Redactor
):
    """No bytes at all, which from the loader's side is one thing.

    A 404, a DNS failure and a timeout are all `fetch_failed`: the previous
    snapshot stays either way, and which one it was is in the detail.
    """
    good = load(migrated_engine, redactor, RAW)
    bad = load_threatfox(
        migrated_engine,
        tenant=TENANT,
        sensor=SENSOR,
        source_url="http://127.0.0.1:1/does-not-exist",
        redactor=redactor,
    )
    assert bad.outcome == FAILED
    assert bad.failure_reason == FETCH_FAILED
    assert claims_held(migrated_engine) == {
        good.snapshot_version: good.counts["claims_stored"]
    }


@pytest.mark.integration
def test_every_attempt_is_on_the_record_including_the_failures(
    migrated_engine: psycopg.Connection, redactor: Redactor
):
    load(migrated_engine, redactor, RAW)
    load(migrated_engine, redactor, b"{}")
    load(migrated_engine, redactor, RAW)
    outcomes = migrated_engine.execute(
        f"SELECT outcome, count(*) FROM {FEED_SNAPSHOT_TABLE} "
        f"WHERE source_id = %s GROUP BY outcome",
        (THREATFOX_SOURCE,),
    ).fetchall()
    assert dict(outcomes) == {LOADED: 1, FAILED: 1, UNCHANGED: 1}


# --- History, because replay joins the snapshot current at event time -------


@pytest.mark.integration
def test_a_new_snapshot_does_not_delete_the_old_one(
    migrated_engine: psycopg.Connection, redactor: Redactor
):
    """The correction 0013 makes to the loader task 22 shipped.

    `concept/02`: "Replay joins the snapshot current at event time, not today's."
    A claim records the snapshot it matched against, so deleting that snapshot on
    the next load leaves a stored assessment citing something the store no longer
    has — a replay that cannot be validated rather than one that disagrees.
    """
    first = load(migrated_engine, redactor, RAW)
    second = load(migrated_engine, redactor, varied(1))
    assert second.snapshot_version != first.snapshot_version
    held = claims_held(migrated_engine)
    assert set(held) == {first.snapshot_version, second.snapshot_version}


@pytest.mark.integration
def test_pruning_is_deliberate_and_keeps_the_newest(
    migrated_engine: psycopg.Connection, redactor: Redactor
):
    """Not a side effect of loading — which is exactly what went wrong before.

    Pruning has to exist: the recent export is thousands of claims an hour. It is
    a call somebody makes, against a number this repository records as a
    candidate rather than a decision.
    """
    versions = [
        load(migrated_engine, redactor, varied(n)).snapshot_version
        for n in range(SNAPSHOTS_KEPT + 2)
    ]
    assert len(set(claims_held(migrated_engine))) == len(versions)

    dropped = prune_snapshots(
        migrated_engine, tenant=TENANT, sensor=SENSOR, source_id=THREATFOX_SOURCE
    )
    assert dropped == len(versions) - SNAPSHOTS_KEPT
    assert set(claims_held(migrated_engine)) == set(versions[-SNAPSHOTS_KEPT:])


@pytest.mark.integration
def test_pruning_again_drops_nothing(
    migrated_engine: psycopg.Connection, redactor: Redactor
):
    load(migrated_engine, redactor, RAW)
    assert prune_snapshots(
        migrated_engine, tenant=TENANT, sensor=SENSOR, source_id=THREATFOX_SOURCE
    ) == 0


@pytest.mark.integration
def test_an_unchanged_load_is_one_snapshot_and_not_two(
    migrated_engine: psycopg.Connection, redactor: Redactor
):
    """Two attempts, one snapshot: the ledger records both, the claims are one set."""
    load(migrated_engine, redactor, RAW)
    load(migrated_engine, redactor, RAW)
    assert len(claims_held(migrated_engine)) == 1
    attempts = migrated_engine.execute(
        f"SELECT count(*) FROM {FEED_SNAPSHOT_TABLE} WHERE source_id = %s",
        (THREATFOX_SOURCE,),
    ).fetchone()[0]
    assert attempts == 2


# --- ok / stale / missing, which are three different things -----------------


@pytest.mark.integration
def test_a_source_never_loaded_is_missing_and_not_no_match(
    migrated_engine: psycopg.Connection
):
    """The distinction the whole design turns on.

    `no_match` is a source that ran and found nothing. `missing` is a source that
    was never asked, and it is not a value any row carries — the rows do not
    exist. Reading the second as the first is triage reading "no hit" as "clean".
    """
    status = feed_status(
        migrated_engine, tenant=TENANT, sensor=SENSOR, source_id=THREATFOX_SOURCE
    )
    assert status.status == MISSING
    assert status.snapshot_version is None
    assert not status.has_snapshot
    assert status.status != "no_match"


@pytest.mark.integration
def test_a_fresh_snapshot_is_ok(
    migrated_engine: psycopg.Connection, redactor: Redactor
):
    loaded = load(migrated_engine, redactor, RAW)
    status = feed_status(
        migrated_engine, tenant=TENANT, sensor=SENSOR, source_id=THREATFOX_SOURCE
    )
    assert status.status == OK
    assert status.snapshot_version == loaded.snapshot_version
    assert status.refresh_interval_seconds == (
        SOURCES[THREATFOX_SOURCE].refresh_interval_seconds
    )


@pytest.mark.integration
def test_a_snapshot_older_than_the_feeds_schedule_is_stale(
    migrated_engine: psycopg.Connection, redactor: Redactor
):
    """Derived from the clock, which is why it is not stored.

    The load is written with an `attempted_at` in the past rather than by waiting
    an hour — the same technique `tests/test_context.py` uses to reach a window
    the fixtures cannot.
    """
    interval = SOURCES[THREATFOX_SOURCE].refresh_interval_seconds
    stale_at = datetime.now(timezone.utc) - timedelta(seconds=interval * 2)
    load_threatfox(
        migrated_engine,
        tenant=TENANT,
        sensor=SENSOR,
        source_url=URL,
        redactor=redactor,
        raw=RAW,
        now=stale_at,
    )
    status = feed_status(
        migrated_engine, tenant=TENANT, sensor=SENSOR, source_id=THREATFOX_SOURCE
    )
    assert status.status == STALE
    assert status.has_snapshot, "a stale snapshot is still a snapshot"


@pytest.mark.integration
def test_a_stale_snapshot_keeps_its_claims(
    migrated_engine: psycopg.Connection, redactor: Redactor
):
    """`concept/02`: removal from a feed is not exoneration.

    An aged snapshot is evidence with a date on it, not evidence withdrawn, so
    the claims are still there and still joinable. Staleness is what a reader
    weighs them by.
    """
    interval = SOURCES[THREATFOX_SOURCE].refresh_interval_seconds
    loaded = load_threatfox(
        migrated_engine,
        tenant=TENANT,
        sensor=SENSOR,
        source_url=URL,
        redactor=redactor,
        raw=RAW,
        now=datetime.now(timezone.utc) - timedelta(seconds=interval * 2),
    )
    assert claims_held(migrated_engine) == {
        loaded.snapshot_version: loaded.counts["claims_stored"]
    }


@pytest.mark.integration
def test_a_failed_load_does_not_become_the_current_snapshot(
    migrated_engine: psycopg.Connection, redactor: Redactor
):
    """The view reads the newest attempt that produced one, not the newest attempt.

    A failure is in the ledger and is deliberately not current: it left the
    previous snapshot in place, so what is current is still the one before it.
    """
    good = load(migrated_engine, redactor, RAW)
    load(migrated_engine, redactor, b"{}")
    rows = migrated_engine.execute(
        f"SELECT snapshot_version FROM {FEED_SNAPSHOT_CURRENT_VIEW} "
        f"WHERE source_id = %s",
        (THREATFOX_SOURCE,),
    ).fetchall()
    assert rows == [(good.snapshot_version,)]


def test_a_source_with_no_schedule_can_never_be_stale():
    """`concept/05` records the SSLBL JA3 list as **static since 2021**.

    It is not late; it is finished. A refresh interval would make it permanently
    stale and say something false about it — what is wrong with that list is in
    its caveat, not in its age.
    """
    assert SOURCES["sslbl-ja3"].refresh_interval_seconds is None
    assert SOURCES[THREATFOX_SOURCE].refresh_interval_seconds is not None
