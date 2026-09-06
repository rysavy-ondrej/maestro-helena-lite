"""Acceptance: what a reader sees when there is no evidence, and why it is not `no_match`.

This is the named suite `prds/prd.json` task 25 asks for, and it is a **gate**:
`make acceptance` runs it alone, and the triage stage (D4) is not buildable until
it passes. Everything D4 renders to an agent comes out of
`helena_analytical_enriched_context`, so the property tested here is the one that
decides whether triage can tell "nobody knows" from "nothing was found".

`concept/02-concepts-and-taxonomy.md` states it twice, and both halves matter:

    `no_match` — the source **completed its query** and returned no record.
    A lookup outcome, never a statement of safety.

    Enrichment status — `ok` / `stale` / `failed` / `missing`, each **distinct
    from `no_match`**.

    With sparse blocklist coverage, most entities have no hit on anything, so an
    enriched context is mostly negative space. Triage reading "no hit" as "clean"
    is the failure mode the whole design exists to prevent.

So there are six states a reader must be able to tell apart, and this module
builds each of them out of real ingest and the real loader rather than asserting
on hand-written rows:

    fresh hit        a current snapshot holds a claim about this entity
    fresh no_match   a current snapshot was consulted and held nothing
    stale            the snapshot that covered this window is past its refresh
    failed           a load was attempted for this window and did not complete
    missing          no load had been attempted when this window happened
    in flight        a load is part-written: its claims are stored, its ledger
                     row is not

The last one has no name in the vocabulary, and that is the point. There is no
`in_flight` outcome in `helena_reference_feed_snapshot` -- outcomes are `loaded`,
`unchanged`, `failed` -- because a load in flight has not finished having an
outcome. What makes it safe is an ordering rather than a status:
`helena.enrichment.load_threatfox` writes its claims, FLUSHes, and only then
writes the ledger row, so **the ledger row is the commit point**. A snapshot
nothing has committed has no validity interval, so its claims cannot be joined.
`test_a_load_in_flight_is_invisible_until_its_ledger_row_lands` is that property.

### Where this suite disagrees with its own task description

Task 25 step 3 asks for "no path exists by which a **stale** or failed feed can
produce `no_match`". Half of that is `concept/02` and is asserted here: a query
that did not complete -- `failed`, `missing`, in flight -- carries no
classification at all, so it can never read as a clean lookup.

The other half is not, and is deliberately not asserted, because `concept/`
outranks `prd.json` in the authority order (`prds/CONTEXT.md` §1). A stale
snapshot **did** complete its query; it completed it a while ago. A stale
snapshot that held no claim about an entity is therefore a genuine `no_match`
with a date on it, and the row says both -- `status = 'stale'` beside
`classification = 'no_match'`. Forbidding that combination would mean either
dropping the row, which is the absent-row failure mode this suite exists to
prevent, or relabelling a real negative as something else, which loses the fact
that the source answered. What the reader actually needs is to tell a stale
negative from a fresh one, and that is
`test_a_stale_negative_is_never_mistakable_for_a_fresh_one`.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg
import pytest

from helena.config import Settings
from helena.enrichment import THREATFOX_SOURCE, load_threatfox
from helena.normalizer import (
    Capture,
    EventStore,
    NormalizedEvent,
    Normalizer,
    describe_capture,
)
from helena.observability import Redactor

# Every test here needs the engine, and every test here is the gate.
pytestmark = [pytest.mark.acceptance, pytest.mark.integration]

FIXTURES = Path(__file__).resolve().parent / "fixtures"
LAYERS_CAPTURE = "ace6ca33f7bf8aa949f79124abf33fc115cfd0909e9dea798f4762cf87af8318"
RAW = (FIXTURES / "threatfox" / "export.json").read_bytes()

TENANT, SENSOR = "tenant-under-test", "sensor-under-test"
URL = "https://threatfox.invalid/export/json/recent/"
VIEW = "helena_analytical_enriched_context"

# `sql/migrations/0006_host_context.sql` tumbles on INTERVAL '5 minutes'.
WINDOW_SECONDS = 300

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


def settings() -> Settings:
    return Settings.load(environ=ENVIRONMENT, env_file=None)


def redactor() -> Redactor:
    return Redactor.from_settings(settings())


def layers_records() -> list[dict]:
    path = FIXTURES / "captures" / f"{LAYERS_CAPTURE}.jsonl"
    return [json.loads(line) for line in path.read_bytes().splitlines()]


def restamped(record: dict, ts: float) -> dict:
    """A real record with its start time moved, and nothing else touched.

    `ts` is a field of the input contract and the flatten layer reads it as the
    flow's start, so moving it is a contract-permitted change to a real record.
    It is the only way to put a context in a window chosen relative to `now`,
    which every freshness assertion here needs -- the committed captures are
    dated 2024-06-01.
    """
    return {**record, "ts": ts}


def window_containing(moment: float) -> datetime:
    """The start of the tumbling window `moment` falls in."""
    return datetime.fromtimestamp(
        int(moment // WINDOW_SECONDS) * WINDOW_SECONDS, tz=timezone.utc
    )


def store_records(
    connection: psycopg.Connection, path: Path, records: list[dict]
) -> Capture:
    """Write `records` as a capture and put them through the real ingest path.

    Not an INSERT of hand-made rows: the point of reading the analytical view is
    that everything under it ran, so a test that wrote its own rows would be
    testing the view against a guess about the layers below it.
    """
    path.write_bytes(
        b"".join(json.dumps(record).encode() + b"\n" for record in records)
    )
    capture = describe_capture(path)
    configured = settings()
    normalizer = Normalizer.from_settings(configured)
    store = EventStore(connection=connection, identity=configured.identity)
    for result in normalizer.normalize_capture(capture):
        assert isinstance(result, NormalizedEvent), result
        store.record(result)
    connection.execute("FLUSH")
    return capture


def load(connection: psycopg.Connection, raw: bytes, *, now: datetime):
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
    """The committed extract with one entry repointed at an entity we have.

    The extract names indicators from the real feed and the capture is one
    Windows host's routine traffic, so nothing in one appears in the other --
    realistic, and useless for testing a join.
    """
    document = json.loads(raw)
    key = sorted(document)[0]
    document[key][0]["ioc_type"] = ioc_type
    document[key][0]["ioc_value"] = entity_value
    return json.dumps(document).encode()


def rows(
    connection: psycopg.Connection, where: str = "", params: tuple = ()
) -> list[dict]:
    cursor = connection.execute(f"SELECT * FROM {VIEW} {where}".strip(), params)
    names = [d.name for d in cursor.description]
    return [dict(zip(names, row)) for row in cursor.fetchall()]


def entities_in(connection: psycopg.Connection, window: datetime) -> list[str]:
    return [
        value
        for (value,) in connection.execute(
            "SELECT DISTINCT entity_value FROM helena_signal_context_entities "
            "WHERE entity_type = 'domain' AND window_start = %s "
            "ORDER BY entity_value",
            (window,),
        ).fetchall()
    ]


def signature(row: dict) -> tuple:
    """What a reader can tell about this row's enrichment, and nothing else."""
    return (row["status"], row["classification"], row["evidence_id"] is not None)


# --- The six states, each built and each named ------------------------------
#
# Every state below is (window, load history) -- status is a property of the two
# together, never of an entity. The classification is the per-entity half.


@pytest.fixture
def fresh(migrated_engine: psycopg.Connection, tmp_path: Path) -> psycopg.Connection:
    """One context in the window `now` falls in, from a re-stamped real record."""
    window = window_containing(time.time())
    store_records(
        migrated_engine,
        tmp_path / "fresh.jsonl",
        [restamped(layers_records()[0], window.timestamp() + 1)],
    )
    return migrated_engine


def test_a_fresh_hit_is_ok_and_carries_the_claim(fresh: psycopg.Connection):
    """The state everything else is defined against: a source answered, recently."""
    window = window_containing(time.time())
    value = entities_in(fresh, window)[0]
    # Loaded at the window's own start, so the snapshot covers the window and is
    # far inside ThreatFox's 3600s refresh interval.
    load(fresh, targeted(RAW, value), now=window)

    hit = rows(fresh, "WHERE entity_value = %s", (value,))
    assert hit, "the entity produced no row at all"
    assert [signature(row) for row in hit] == [("ok", "malicious", True)]
    assert hit[0]["snapshot_version"] is not None
    assert hit[0]["source_id"] == THREATFOX_SOURCE


def test_a_fresh_lookup_that_found_nothing_is_ok_and_no_match(
    fresh: psycopg.Connection,
):
    """A completed query that returned no record. The commonest row in the store.

    `concept/02`: a lookup outcome, never a statement of safety -- so it is a
    ROW, with a status saying the source really did answer.
    """
    window = window_containing(time.time())
    values = entities_in(fresh, window)
    assert len(values) > 1, "need one entity to target and another to miss"
    load(fresh, targeted(RAW, values[0]), now=window)

    missed = rows(fresh, "WHERE entity_value = %s", (values[1],))
    assert missed, "an entity with no hit produced no row -- absence, not no_match"
    assert [signature(row) for row in missed] == [("ok", "no_match", False)]


def test_a_stale_snapshot_is_stale_and_keeps_its_claim(
    migrated_engine: psycopg.Connection, tmp_path: Path
):
    """Past its refresh interval, so the claim is evidence with a date on it.

    `concept/02`: removal from a feed is not exoneration, and neither is a feed
    going quiet. The claim stands; the row says how old the snapshot is.
    """
    window = window_containing(time.time() - 2 * 3600)
    store_records(
        migrated_engine,
        tmp_path / "stale.jsonl",
        [restamped(layers_records()[0], window.timestamp() + 1)],
    )
    value = entities_in(migrated_engine, window)[0]
    # Two hours before now, against a 3600s refresh interval.
    load(migrated_engine, targeted(RAW, value), now=window)

    aged = rows(migrated_engine, "WHERE entity_value = %s", (value,))
    assert [signature(row) for row in aged] == [("stale", "malicious", True)]
    assert aged[0]["snapshot_loaded_at"] is not None


def test_a_failed_load_is_failed_and_carries_no_classification(
    fresh: psycopg.Connection,
):
    """A query that did not complete emits a typed error and no taxonomy object.

    `concept/02` names the ways this must not go wrong: a timeout, quota
    exhaustion or an auth failure never becomes `no_match`, and never becomes
    `unknown` either.
    """
    window = window_containing(time.time())
    load(fresh, b"{}", now=window)  # parses to nothing -- a failed load

    enriched = rows(fresh)
    assert enriched
    assert {signature(row) for row in enriched} == {("failed", None, False)}


def test_a_window_no_load_had_reached_is_missing(fresh: psycopg.Connection):
    """Never asked at the time, which is not the same as asked and told nothing."""
    window = window_containing(time.time())
    # The only load happens well after the window it is being read for.
    load(fresh, RAW, now=window + timedelta(days=30))

    enriched = rows(fresh)
    assert enriched
    assert {signature(row) for row in enriched} == {("missing", None, False)}


def test_a_load_in_flight_is_invisible_until_its_ledger_row_lands(
    fresh: psycopg.Connection,
):
    """The sixth state, and the only one with no name in the vocabulary.

    `load_threatfox` writes its claims, FLUSHes, and only then writes the ledger
    row, so a load in flight is exactly: claims present, ledger row absent. That
    intermediate state is reproduced here by deleting the ledger row of a real
    completed load -- the claims stay written by the real loader, and only the
    commit point goes.

    The guarantee is that a part-written snapshot is not readable at all. It must
    not produce a hit, because it has not finished landing; and it must not
    produce `no_match`, because nothing has completed a query.
    """
    window = window_containing(time.time())
    value = entities_in(fresh, window)[0]

    # A first load that genuinely covers the window, so there is a hit to lose.
    landed = load(fresh, targeted(RAW, value), now=window)
    assert [signature(row) for row in rows(fresh, "WHERE entity_value = %s", (value,))] \
        == [("ok", "malicious", True)]

    # Now roll the ledger row back to before it was written. The claims stay.
    fresh.execute(
        "DELETE FROM helena_reference_feed_snapshot "
        "WHERE source_id = %s AND attempted_at = %s",
        (THREATFOX_SOURCE, window),
    )
    fresh.execute("FLUSH")
    stored = fresh.execute(
        "SELECT count(*) FROM helena_reference_threatfox WHERE snapshot_version = %s",
        (landed.snapshot_version,),
    ).fetchone()[0]
    assert stored, "the in-flight state needs the claims to still be there"

    in_flight = rows(fresh, "WHERE entity_value = %s", (value,))
    for row in in_flight:
        assert row["evidence_id"] is None, "a part-written snapshot produced a hit"
        assert row["classification"] != "no_match", (
            "a load that has not committed presented as a completed query"
        )
        assert row["classification"] is None
        assert row["status"] in ("failed", "missing")


# --- The properties over the whole space, not one state at a time -----------


def test_the_states_are_distinguishable_in_one_store(
    migrated_engine: psycopg.Connection, tmp_path: Path
):
    """Four windows, one source, one store: every status tells itself apart.

    Statuses are a property of (window, load history) rather than of an entity,
    so telling them apart takes four windows and a load history that puts each
    one in a different position relative to it. This is the acceptance property
    stated whole -- the per-state tests above each assert one row of it.
    """
    now = time.time()
    windows = {
        "missing": window_containing(now - 6 * 3600),
        "failed": window_containing(now - 4 * 3600),
        "stale": window_containing(now - 2 * 3600),
        "ok": window_containing(now),
    }
    for name, window in windows.items():
        store_records(
            migrated_engine,
            tmp_path / f"{name}.jsonl",
            [restamped(layers_records()[0], window.timestamp() + 1)],
        )
    value = entities_in(migrated_engine, windows["ok"])[0]

    # The load history. Each attempt starts a validity interval that runs until
    # the next one, so where a window sits among them decides its status.
    load(migrated_engine, b"{}", now=windows["failed"] - timedelta(seconds=60))
    load(
        migrated_engine,
        targeted(RAW, value),
        now=windows["stale"] - timedelta(seconds=60),
    )
    load(
        migrated_engine,
        targeted(RAW, value, ioc_type="url"),
        now=windows["ok"] - timedelta(seconds=60),
    )

    seen = {}
    for name, window in windows.items():
        found = rows(
            migrated_engine,
            "WHERE entity_value = %s AND window_start = %s",
            (value, window),
        )
        assert found, f"the {name} window produced no row"
        assert len({row["status"] for row in found}) == 1
        seen[name] = found[0]["status"]

    assert seen == {
        "missing": "missing",
        "failed": "failed",
        "stale": "stale",
        "ok": "ok",
    }
    # And the whole point: four statuses, four distinct values, none of them
    # `no_match` and none of them each other.
    assert len(set(seen.values())) == len(seen)


def test_no_query_that_did_not_complete_carries_a_classification(
    migrated_engine: psycopg.Connection, tmp_path: Path
):
    """The half of task 25 step 3 that `concept/02` does require.

    `failed` and `missing` both mean the source did not answer for this window.
    Neither may carry a taxonomy object of any kind -- not `no_match`, not
    `unknown`. Asserted over every row of every state built here rather than on
    a single constructed row, because "no path exists" is a claim about the
    space and not about one example.
    """
    now = time.time()
    windows = [
        window_containing(now - 6 * 3600),
        window_containing(now - 4 * 3600),
        window_containing(now - 2 * 3600),
        window_containing(now),
    ]
    for index, window in enumerate(windows):
        store_records(
            migrated_engine,
            tmp_path / f"w{index}.jsonl",
            [restamped(layers_records()[0], window.timestamp() + 1)],
        )
    value = entities_in(migrated_engine, windows[-1])[0]
    load(migrated_engine, b"{}", now=windows[1] - timedelta(seconds=60))
    load(migrated_engine, targeted(RAW, value), now=windows[2] - timedelta(seconds=60))
    load(
        migrated_engine,
        targeted(RAW, value, ioc_type="url"),
        now=windows[3] - timedelta(seconds=60),
    )

    enriched = rows(migrated_engine)
    assert enriched, "nothing was built to check"
    incomplete = [row for row in enriched if row["status"] in ("failed", "missing")]
    assert incomplete, "no incomplete-query rows were built, so nothing was proven"
    for row in incomplete:
        assert row["classification"] is None, (
            f"status {row['status']!r} carried classification "
            f"{row['classification']!r} -- a query that did not complete "
            f"produced a taxonomy object"
        )
        assert row["evidence_id"] is None
        assert row["snapshot_version"] is None

    # The converse, so this cannot pass by producing no classifications at all:
    # every row that DOES carry one had a snapshot to read it from.
    classified = [row for row in enriched if row["classification"] is not None]
    assert classified, "no classified rows were built, so nothing was proven"
    for row in classified:
        assert row["status"] in ("ok", "stale")
        assert row["snapshot_version"] is not None


def test_a_stale_negative_is_never_mistakable_for_a_fresh_one(
    migrated_engine: psycopg.Connection, tmp_path: Path
):
    """Where this suite resolves task 25 step 3 against `concept/`.

    A stale snapshot completed its query, so a stale `no_match` is a real
    negative rather than a forbidden one -- see the module head. What must hold
    is that a reader can tell it from a fresh negative, and the status column is
    what does that. If these two rows were indistinguishable, an hours-old
    silence would read as a current all-clear.
    """
    now = time.time()
    old, new = window_containing(now - 2 * 3600), window_containing(now)
    for name, window in (("old", old), ("new", new)):
        store_records(
            migrated_engine,
            tmp_path / f"{name}.jsonl",
            [restamped(layers_records()[0], window.timestamp() + 1)],
        )
    # Two loads, neither naming any entity the capture has, so every row is a
    # negative. The only difference between the windows is the snapshot's age.
    load(migrated_engine, RAW, now=old - timedelta(seconds=60))
    load(migrated_engine, RAW, now=new - timedelta(seconds=60))

    negatives = rows(migrated_engine, "WHERE classification = 'no_match'")
    assert negatives, "no negatives were built"
    by_window = {row["window_start"]: row["status"] for row in negatives}
    assert by_window.get(old) == "stale", "an aged negative did not say it was aged"
    assert by_window.get(new) == "ok", "a current negative did not say it was current"
    # Same classification, different status. That is the whole distinction, and
    # it is why `no_match` is not a status.
    assert {row["classification"] for row in negatives} == {"no_match"}
    assert by_window[old] != by_window[new]


def test_the_gate_covers_every_status_the_model_defines(
    migrated_engine: psycopg.Connection, tmp_path: Path
):
    """A suite that silently stopped covering a status would still be green.

    `ENRICHMENT_STATUSES` is the vocabulary; this asserts the suite reaches all
    of it. If a fifth status is ever added, this fails until the gate grows a
    fixture for it, which is the point of wiring the suite as a gate at all.
    """
    from helena.enrichment import ENRICHMENT_STATUSES

    now = time.time()
    windows = [
        window_containing(now - 6 * 3600),
        window_containing(now - 4 * 3600),
        window_containing(now - 2 * 3600),
        window_containing(now),
    ]
    for index, window in enumerate(windows):
        store_records(
            migrated_engine,
            tmp_path / f"w{index}.jsonl",
            [restamped(layers_records()[0], window.timestamp() + 1)],
        )
    value = entities_in(migrated_engine, windows[-1])[0]
    load(migrated_engine, b"{}", now=windows[1] - timedelta(seconds=60))
    load(migrated_engine, targeted(RAW, value), now=windows[2] - timedelta(seconds=60))
    load(
        migrated_engine,
        targeted(RAW, value, ioc_type="url"),
        now=windows[3] - timedelta(seconds=60),
    )

    reached = {row["status"] for row in rows(migrated_engine)}
    assert reached == set(ENRICHMENT_STATUSES), (
        f"the gate reached {sorted(reached)} of {sorted(ENRICHMENT_STATUSES)}"
    )
    assert "no_match" not in reached, "`no_match` is a classification, never a status"
