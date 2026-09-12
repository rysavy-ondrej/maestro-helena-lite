"""Durability: what survives, what a backup carries, and what a replay cannot bring back.

`concept/08-open-questions.md` files this under *cross-cutting and urgent*:
*"Durability and backup for the single store, now that findings and evidence exist
only there, which is a correctness concern rather than an ops detail."* The
correctness claim this module executes is that sentence turned around — the two
halves of the durable record recover two different things, and neither substitutes
for the other:

    the retained captures  ->  the input, and everything derived from it
    the engine's tables    ->  the feed snapshots, the evidence, the assessments

So there is one drill and several readings of it. A full pipeline state is built
in one migrated schema, backed up, and restored into another; the two schemas are
then compared relation by relation. The same capture is replayed onto the restored
schema, and separately onto an empty one. What the empty one does *not* hold
afterwards is the whole point:
`test_a_replay_without_a_restore_does_not_bring_back_an_assessment` is the test
that says the engine's tables are the record rather than a cache of something
re-derivable.

### A schema, not a second engine

`single_node` binds fixed meta and compute ports, so a second RisingWave cannot
run beside the first (`docs/runbook.md` §2, `tests/conftest.py`). The throwaway
instance available on this machine is a migrated schema of its own, which is what
`--schema` on `scripts/backup.py` exists for and what the runbook's rehearsal
procedure uses. What is therefore *not* exercised here is a restore into a
different engine process or across an engine version; `docs/runbook.md` §15
records that as the gap it is.

### The comparison has to allow for the wall clock

A restore happens later than the backup, and some of this schema's definitions
reach `now()` — the retention horizon, the snapshot-currency window, the
completeness flag. `time_derived()` reads the engine's own view definitions and
closes that set over what reads what, rather than trusting a list written here,
and the comparison requires every *other* relation to be identical. That is the
honest shape of "a restore reconstructs the pipeline state": the rows come back
exactly, and what is derived from the clock is derived again.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import psycopg
import pytest

from helena import durability, enrichment, migrations
from helena.broker import BrokerConsumer, BrokerProducer
from helena.config import Settings
from helena.durability import BackupIncomplete, BackupTrailer, RestoreRefused
from helena.normalizer import (
    Capture,
    CaptureError,
    IngestCounts,
    CaptureStoreUnreachable,
    EventStore,
    Normalizer,
    Quarantine,
    consume_ingest_topic,
    describe_capture,
    ingest_counts,
    publish_capture,
    scan_captures,
)

import backup  # noqa: E402 — scripts/ is on the path from tests/conftest.py
from test_end_to_end import (  # noqa: E402 — the harness task 52 built
    Run,
    a_topic,
    environment,
    escalating_script,
    run_pipeline,
)

pytestmark = pytest.mark.integration

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RUNBOOK = PROJECT_ROOT / "docs" / "runbook.md"
DECISION = PROJECT_ROOT / "docs" / "decisions" / "0040-durability-and-backup.md"
FIXTURE_CAPTURES = Path(__file__).resolve().parent / "fixtures" / "captures"

#: Relations a restore is *not* expected to reproduce row for row, named by the
#: property that makes them that way rather than by name — see `time_derived`.
#: A table is never one of them, which is what makes the backup exact.
CLOCK = "now()"

#: What the pipeline *learned*, as opposed to what it read: the feed snapshot an
#: assessment cited, the feed rows the evidence is projected from, the evidence
#: itself, and the assessments with their citation and disclosure rows. Not one
#: of them is derivable from a capture, which is what
#: `test_a_replay_without_a_restore_does_not_bring_back_an_assessment` measures.
#: `helena_reference_evidence` is a view over `helena_reference_threatfox` —
#: migration 0014 dropped the table 0011 created and replaced it with the
#: projection, so the durable row is the feed row and the evidence is the read.
LEARNED = (
    "helena_reference_feed_snapshot",
    "helena_reference_threatfox",
    "helena_reference_evidence",
    "helena_analytical_assessment",
    "helena_analytical_assessment_citation",
    "helena_analytical_assessment_disclosure",
)


# --- The schemas the drill runs in ------------------------------------------


@contextmanager
def migrated(engine_dsn: str) -> Iterator[psycopg.Connection]:
    """A migrated schema of its own, dropped on the way out.

    `tests/conftest.py`'s `_migrated_schema` for one module: autocommit because
    RisingWave DDL inside an open transaction is not visible to what follows it,
    and a schema rather than a process because only one engine runs per machine.
    """
    schema = f"helena_durability_{uuid.uuid4().hex}"
    with psycopg.connect(engine_dsn, autocommit=True, connect_timeout=5) as connection:
        connection.execute(f"CREATE SCHEMA {schema}")
        try:
            connection.execute(f"SET search_path TO {schema}")
            migrations.apply(connection)
            yield connection
        finally:
            connection.execute("SET search_path TO public")
            connection.execute(f"DROP SCHEMA {schema} CASCADE")


@pytest.fixture(scope="module")
def source_engine(engine_dsn: str) -> Iterator[psycopg.Connection]:
    """Where the pipeline runs, and what the backup is taken from."""
    with migrated(engine_dsn) as connection:
        yield connection


@pytest.fixture(scope="module")
def target_engine(engine_dsn: str) -> Iterator[psycopg.Connection]:
    """The restore target: the same migrations, applied separately, holding nothing.

    Module-scoped for the reason `tests/test_end_to_end.py::module_engine` gives —
    applying the migrations starts a streaming job per materialized view, so a
    schema per test would make the suite scale with (views x tests). Nothing
    restores into it twice.
    """
    with migrated(engine_dsn) as connection:
        yield connection


# --- Reading a schema back ---------------------------------------------------


def relations(connection: psycopg.Connection) -> dict[str, str]:
    """Every relation of the current schema and what kind it is, from the catalogue.

    The migration ledger is excluded because it is the schema's identity rather
    than its contents: a restore compares it and never writes it
    (`helena.durability.durable_relations`).
    """
    return {
        name: kind
        for name, kind in connection.execute(
            "SELECT table_name, table_type FROM information_schema.tables "
            "WHERE table_schema = current_schema() ORDER BY table_name"
        ).fetchall()
        if name != migrations.LEDGER_TABLE
    }


def rows_of(connection: psycopg.Connection, relation: str) -> list[str]:
    """One relation's rows as sorted strings, so two schemas can be compared.

    Stringified per value rather than compared as typed tuples: the comparison
    is "did the same rows come back", and a `Decimal('1.0')` that arrives as
    `1.0` is the same row. What the *types* have to survive is asserted where it
    belongs — `helena.durability` encodes by column type, and a value that did
    not survive would come back as a different string here.
    """
    with connection.cursor() as cursor:
        cursor.execute(f"SELECT * FROM {relation}")  # noqa: S608 — a catalogue name
        return sorted(
            json.dumps([str(value) for value in row], sort_keys=True)
            for row in cursor
        )


def contents(connection: psycopg.Connection) -> dict[str, list[str]]:
    """Every relation of the current schema, with its rows."""
    return {name: rows_of(connection, name) for name in relations(connection)}


def definitions(connection: psycopg.Connection) -> dict[str, str]:
    """Every view and materialized view of this schema, as the engine holds it.

    From the engine and not from `sql/migrations/`, for the reason
    `tests/test_view_layering.py` reads it this way: the engine strips comments,
    so what it returns is the definition rather than the prose around it. A
    text search over the files finds the comment arguing for a thing's absence.
    """
    (schema_id,) = connection.execute(
        "SELECT id FROM rw_catalog.rw_schemas WHERE name = current_schema()"
    ).fetchone()
    found: dict[str, str] = {}
    for catalogue in ("rw_views", "rw_materialized_views"):
        for name, definition in connection.execute(
            f"SELECT name, definition FROM rw_catalog.{catalogue} "  # noqa: S608
            f"WHERE schema_id = %s",
            (schema_id,),
        ).fetchall():
            found[name] = definition
    return found


def time_derived(connection: psycopg.Connection) -> set[str]:
    """Relations whose content can depend on the wall clock, transitively.

    A definition that calls `now()` is one; so is anything that reads one, and
    so on. Computed rather than listed because the list is the thing that goes
    stale: a migration that adds a temporal filter to a view has to move every
    reader of it into this set, and nobody would remember to.
    """
    defined = definitions(connection)
    derived = {
        name for name, sql in defined.items() if CLOCK in sql.lower()
    }
    while True:
        grown = {
            name
            for name, sql in defined.items()
            if name not in derived
            and any(re.search(rf"\b{other}\b", sql) for other in derived)
        }
        if not grown:
            return derived
        derived |= grown


# --- The drill ---------------------------------------------------------------


@dataclass(frozen=True)
class Drill:
    """One recovery rehearsal: a pipeline state, a backup, and a restore of it."""

    run: Run
    source: psycopg.Connection
    target: psycopg.Connection
    lines: tuple[str, ...]
    header: durability.BackupHeader
    restored: durability.RestoreResult
    #: The source schema's contents, read before the restore.
    before: dict[str, list[str]]
    #: The target schema's contents, read after it.
    after: dict[str, list[str]]
    #: What the source's clock-dependent relations were, so the comparison can
    #: exclude exactly those and nothing else.
    clock_bound: frozenset[str]
    seconds: float


@pytest.fixture(scope="module")
def drill(
    source_engine: psycopg.Connection,
    target_engine: psycopg.Connection,
    broker_bootstrap: str,
    tmp_path_factory: pytest.TempPathFactory,
) -> Drill:
    """Build a full pipeline state, back it up, restore it into a second schema.

    Module-scoped: it crosses the broker, the engine's own aggregation and two
    scripted model calls, and every test below is a reading of what it produced.
    `seconds` is the wall clock of the backup and the restore together, which is
    the recovery time `docs/runbook.md` §15 records.
    """
    run = run_pipeline(
        source_engine,
        bootstrap=broker_bootstrap,
        tmp_path=tmp_path_factory.mktemp("durability"),
        script=escalating_script,
    )
    before = contents(source_engine)
    clock_bound = frozenset(time_derived(source_engine))
    started = datetime.now(timezone.utc)
    lines = tuple(durability.back_up(source_engine, taken_at=started))
    header = durability.verify(lines)
    restored = durability.restore(target_engine, lines)
    seconds = (datetime.now(timezone.utc) - started).total_seconds()
    return Drill(
        run=run,
        source=source_engine,
        target=target_engine,
        lines=lines,
        header=header,
        restored=restored,
        before=before,
        after=contents(target_engine),
        clock_bound=clock_bound,
        seconds=seconds,
    )


def restamped(lines: list[str]) -> list[str]:
    """`lines` with a trailer that verifies, for testing what comes *after* the digest.

    A backup with an edited header is refused twice over — the digest first and
    then the schema comparison — and a test that only ever saw the first refusal
    would not know the second one works. This puts a correct trailer back on so
    the second refusal is the one being measured.
    """
    body = "".join(f"{line}\n" for line in lines[:-1])
    trailer = BackupTrailer(
        rows=len(lines) - 2, body_sha256=hashlib.sha256(body.encode("utf-8")).hexdigest()
    )
    return [*lines[:-1], trailer.model_dump_json()]


def replay_into(
    connection: psycopg.Connection, capture: Capture, bootstrap: str
) -> IngestCounts:
    """Publish a retained capture to a fresh topic and ingest it into `connection`.

    `docs/runbook.md` §8's replay, in the two calls the shipped path uses: there
    is no second normalization path, so this is the same adapter, the same
    identity stamping and the same counters `scripts/replay_capture.py` drives.
    A topic of its own per replay, because the broker is consume-once and two
    replays sharing one would each consume part of the other's records.
    """
    ingest_topic = a_topic("replay")
    settings = Settings.load(
        environ=environment(
            bootstrap=bootstrap,
            ingest_topic=ingest_topic,
            output_topic=a_topic("unused"),
        ),
        env_file=None,
    )
    events = EventStore(connection=connection, identity=settings.identity)
    quarantine = Quarantine(connection=connection, identity=settings.identity)
    with BrokerProducer.from_settings(settings) as producer:
        published = publish_capture(capture, producer, ingest_topic)
    assert published == capture.record_count
    with BrokerConsumer.from_settings(settings) as consumer:
        consumed = Normalizer.from_settings(settings).ingest_messages(
            consume_ingest_topic(consumer, ingest_topic, idle_timeout=5.0),
            events,
            quarantine,
        )
    connection.execute("FLUSH")
    return ingest_counts(
        capture=capture, consumed=consumed, events=events, quarantine=quarantine
    )


# --- What the backup is of ---------------------------------------------------


def test_the_backup_is_every_durable_table_and_not_the_ledger(
    migrated_engine: psycopg.Connection,
):
    """The relation set comes from the catalogue, so a new table cannot be missed.

    Compared against `helena.migrations.declarations()` — what the migration
    files say the schema holds — rather than against a list here. A migration
    that adds a table and forgets the backup is the failure this prevents, and
    it is the whole reason `durable_relations` reads the catalogue.
    """
    declared = {
        declaration.relation
        for declaration in migrations.declarations().values()
        if declaration.kind == "TABLE"
    } - {migrations.LEDGER_TABLE}
    backed_up = {
        relation.name for relation in durability.durable_relations(migrated_engine)
    }
    assert backed_up == declared
    assert migrations.LEDGER_TABLE not in backed_up, (
        "the ledger is the schema's identity, not its contents: a restore "
        "compares it and never writes it"
    )


def test_every_column_of_every_durable_table_has_an_encoding(
    migrated_engine: psycopg.Connection,
):
    """No table column is of a type the format would have to guess at.

    `durable_relations` raises on one, so this passing is the assertion. It is
    worth its own test because the day a migration puts an `interval` or an
    array on a *table* — both are already in the views — the failure has to
    arrive here rather than in an operator's backup.
    """
    for relation in durability.durable_relations(migrated_engine):
        for column, data_type in relation.columns:
            assert data_type in durability.ENCODED_TYPES, f"{relation.name}.{column}"


def test_a_column_type_the_format_cannot_encode_is_refused_by_name(
    engine_schema: psycopg.Connection,
):
    """A table this format cannot carry is named, not silently stringified."""
    engine_schema.execute("CREATE TABLE helena_durability_probe (horizon INTERVAL)")
    with pytest.raises(durability.DurabilityError) as refused:
        durability.durable_relations(engine_schema)
    assert "helena_durability_probe.horizon" in str(refused.value)
    assert "interval" in str(refused.value)


def test_a_backup_of_a_schema_that_holds_nothing_is_a_header_and_a_trailer(
    migrated_engine: psycopg.Connection,
):
    """An empty store backs up to two lines, and they verify.

    Zero rows is a state and not an error — a deployment that has ingested
    nothing yet has a backup, and it says so.
    """
    lines = list(
        durability.back_up(migrated_engine, taken_at=datetime.now(timezone.utc))
    )
    assert len(lines) == 2
    header = durability.verify(lines)
    assert header.rows == 0
    assert header.relations, "an empty schema still declares its relations"
    assert [entry.version for entry in header.ledger] == [
        migration.version for migration in migrations.discover()
    ]


# --- What a backup refuses ---------------------------------------------------


def test_a_backup_with_no_trailer_is_refused_as_truncated(drill: Drill):
    """`concept/instruction.md` §2: truncation is visible or it is a bug."""
    with pytest.raises(BackupIncomplete) as refused:
        durability.verify(list(drill.lines[:-1]))
    assert "truncated" in str(refused.value)


def test_an_edited_row_is_refused_by_the_digest(drill: Drill):
    lines = list(drill.lines)
    lines[1] = lines[1].replace("tenant-under-test", "tenant-under-tesX")
    with pytest.raises(BackupIncomplete) as refused:
        durability.verify(lines)
    assert "truncated or edited" in str(refused.value)


def test_a_backup_missing_a_row_is_refused_even_with_a_correct_digest(drill: Drill):
    """A digest alone would not catch a row dropped before the trailer was written.

    So the header's declared count and the trailer's are both compared against
    the lines that are there — three numbers that have to agree rather than one
    that cannot disagree with itself.
    """
    with pytest.raises(BackupIncomplete) as refused:
        durability.verify(restamped([drill.lines[0], *drill.lines[2:]]))
    assert "row line(s)" in str(refused.value)


def test_a_restore_into_a_schema_that_already_holds_rows_is_refused(drill: Drill):
    """Every table has a primary key, so a restore onto rows would upsert.

    The refusal fires before the first INSERT — this test restores the backup
    into the schema it came from, and the assertion is that the schema is
    untouched afterwards.
    """
    with pytest.raises(RestoreRefused) as refused:
        durability.restore(drill.source, list(drill.lines))
    assert "already holds" in str(refused.value)
    untouched = {
        name: rows
        for name, rows in contents(drill.source).items()
        if name not in drill.clock_bound
    }
    assert untouched == {
        name: rows
        for name, rows in drill.before.items()
        if name not in drill.clock_bound
    }, (
        "a refused restore wrote something, which is the one thing it must not "
        "do: the engine has no transaction to roll back"
    )


def test_a_restore_into_a_differently_migrated_schema_is_refused(
    engine_schema: psycopg.Connection, drill: Drill, tmp_path: Path
):
    """The ledger is compared, so a backup cannot land in a schema it does not fit.

    Built by applying a truncated migration directory: four files instead of
    twenty-one. `concept/instruction.md` §2 forbids migrating a stored row
    forward, and adapting a row to a schema it was not written against is
    exactly that.
    """
    partial = tmp_path / "migrations"
    partial.mkdir()
    for migration in migrations.discover()[:4]:
        (partial / migration.path.name).write_bytes(migration.path.read_bytes())
    migrations.apply(engine_schema, partial)
    with pytest.raises(RestoreRefused) as refused:
        durability.restore(engine_schema, list(drill.lines))
    assert "migration ledger" in str(refused.value)


def test_a_restore_into_a_reshaped_relation_is_refused(drill: Drill):
    """A column set that differs is named rather than reconciled.

    The header is edited and the trailer restamped, so what is being measured is
    the schema comparison and not the digest that already caught it once.
    """
    header = drill.header.model_dump(mode="json")
    reshaped = dict(header["relations"][0])
    reshaped["columns"] = [*reshaped["columns"][:-1]]
    header["relations"] = [reshaped, *header["relations"][1:]]
    lines = restamped([json.dumps(header), *drill.lines[1:]])
    with pytest.raises(RestoreRefused) as refused:
        durability.restore(drill.target, lines)
    assert reshaped["name"] in str(refused.value)
    assert "different columns" in str(refused.value)


def test_a_per_relation_count_that_disagrees_refuses_before_any_insert(
    drill: Drill, migrated_engine: psycopg.Connection
):
    """A count wrong per relation but right in total refuses with nothing written.

    `verify` cannot catch this one, and that is the point of building it this
    way: it compares the header's total, the trailer's and the lines actually
    present, and swapping two relations' declared counts leaves all three
    agreeing. The check that does catch it is per relation — and what this test
    measures is WHERE it fires, not that it fires.

    It used to run in the same loop as the INSERT, so a disagreement on a later
    relation was raised only after the earlier ones had been written. That is a
    half-restored store, and the engine has no transaction around a
    multi-statement write to roll it back — the ordering `restore` documents
    ("every refusal here fires before the first INSERT") is the only thing
    standing between a bad backup and a store that is neither the backup nor
    what was there before. The swap deliberately leaves the FIRST populated
    relation's count correct, so a restore that validated lazily would insert it
    and this assertion would find those rows.
    """
    populated = [relation for relation in drill.header.relations if relation.rows]
    candidates = [
        (i, j)
        for i in range(1, len(populated))
        for j in range(i + 1, len(populated))
        if populated[i].rows != populated[j].rows
    ]
    assert candidates, (
        "the drill state has no two later relations with different row counts, "
        "so this test cannot place a mismatch after a correct one"
    )
    i, j = candidates[0]
    swap = {populated[i].name: populated[j].rows, populated[j].name: populated[i].rows}

    header = drill.header.model_dump(mode="json")
    header["relations"] = [
        {**entry, "rows": swap.get(entry["name"], entry["rows"])}
        for entry in header["relations"]
    ]
    lines = restamped([json.dumps(header), *drill.lines[1:]])

    durability.verify(lines)  # the totals still agree; this is not what catches it
    before = contents(migrated_engine)
    with pytest.raises(BackupIncomplete) as refused:
        durability.restore(migrated_engine, lines)
    assert populated[i].name in str(refused.value)

    # Compared against a snapshot rather than against emptiness: `contents` reads
    # every relation, and some are views over a constant that have rows in an
    # untouched schema. Clock-bound relations are excluded for the reason
    # `test_a_restore_into_a_schema_that_already_holds_rows_is_refused` excludes
    # them — they move on their own.
    migrated_engine.execute("FLUSH")  # so an INSERT that did happen is visible
    after = contents(migrated_engine)
    changed = {
        name
        for name in before
        if name not in drill.clock_bound and before[name] != after[name]
    }
    assert not changed, (
        f"a refused restore wrote {sorted(changed)}; the refusal has to come "
        f"before the first INSERT because the engine has no transaction to roll back"
    )


# --- What a restore reconstructs --------------------------------------------


def test_the_drill_built_a_state_worth_restoring(drill: Drill):
    """The run this module is about: a hit, an escalation and stored assessments.

    Here so that every comparison below is known not to be vacuous. A restore of
    an empty schema into an empty schema would pass every one of them.
    """
    assert drill.run.counts.normalized == drill.run.capture.record_count
    assert drill.run.assessments, "the run stored no assessment"
    assert drill.run.messages, "the run emitted no message"
    for relation in LEARNED + ("helena_normalized_events",):
        assert drill.before[relation], f"{relation} is empty before the backup"


def test_the_restore_put_back_every_row_the_backup_carried(drill: Drill):
    """Produced against materialised, per relation. §7: the counts reconcile."""
    assert drill.restored.total == drill.header.rows
    assert drill.restored.reconciles, (
        f"inserted {drill.restored.rows}, the schema holds "
        f"{drill.restored.materialized}"
    )
    assert drill.restored.rows == {
        relation.name: relation.rows
        for relation in drill.header.relations
        if relation.rows
    }


def test_the_restored_schema_holds_the_rows_the_backup_came_from(drill: Drill):
    """Every relation that does not read the clock is identical in both schemas.

    Tables and views alike, which is the claim worth making: the tables were
    restored and everything above them rebuilt itself from them, so "the
    pipeline state" came back rather than "the rows came back".
    """
    assert set(drill.after) == set(drill.before), "the two schemas differ in shape"
    differing = {
        name
        for name, rows in drill.before.items()
        if drill.after[name] != rows
    }
    assert differing <= drill.clock_bound, (
        f"{sorted(differing - drill.clock_bound)} did not come back, and none of "
        f"them reads the clock"
    )


def test_the_materialized_views_rebuilt_without_being_in_the_backup(drill: Drill):
    """A restore copies tables; the engine rebuilds the views from them.

    Measured over the whole schema rather than the one view `docs/runbook.md` §8
    measured: no materialized view is in the backup, and every one of them that
    does not read the clock holds what it held. This is what makes a logical
    backup of the tables a backup of the store.
    """
    materialized = {
        name
        for name, kind in relations(drill.target).items()
        if kind == "MATERIALIZED VIEW"
    }
    assert materialized, "the schema has no materialized view to rebuild"
    assert not materialized & {
        relation.name for relation in drill.header.relations
    }, "a materialized view is in the backup; it would be restored, not rebuilt"
    rebuilt = {
        name
        for name in materialized - drill.clock_bound
        if drill.after[name] and drill.after[name] == drill.before[name]
    }
    assert rebuilt, (
        f"no materialized view outside {sorted(drill.clock_bound)} came back "
        f"with rows; the restore proved nothing about the rebuild"
    )


def test_the_relations_that_may_differ_are_exactly_the_ones_that_read_the_clock(
    drill: Drill,
):
    """The exception set is derived from the engine's definitions, and no table is in it.

    Two properties, and the second is the one that matters: a **table** is never
    clock-dependent, so what the backup carries is exact. What may come back
    differently is only ever derived — and after long enough it will, because
    `helena_signal_host_context_retained` filters on a 24-hour horizon evaluated
    as rows arrive. A restore taken beyond that horizon does not bring the
    retained views back, and that is recorded as a residual risk in
    `docs/runbook.md` §15 rather than claimed here: this suite cannot let a day
    pass between the backup and the restore.
    """
    assert drill.clock_bound, "no relation reads the clock, which cannot be right"
    tables = {
        name for name, kind in relations(drill.source).items() if kind == "BASE TABLE"
    }
    assert not drill.clock_bound & tables
    for name in drill.clock_bound:
        reachable = definitions(drill.source)[name]
        assert CLOCK in reachable.lower() or any(
            re.search(rf"\b{other}\b", reachable) for other in drill.clock_bound
        )


# --- What a replay reconstructs, and what it does not ------------------------


def test_a_replay_onto_a_restored_schema_changes_nothing(
    drill: Drill, broker_bootstrap: str
):
    """Replay is idempotent against a restored store, so the two recover together.

    Every assigned field is derived from the capture, the offset and the
    configured identity, and an INSERT onto an existing key is an upsert
    (`docs/runbook.md` §8) — so a replay after a restore rewrites the same rows.
    That is what makes "restore, then replay whatever the backup predates" a
    procedure rather than a gamble.
    """
    counts = replay_into(drill.target, drill.run.capture, broker_bootstrap)
    assert counts.normalized == drill.run.capture.record_count
    after = contents(drill.target)
    differing = {
        name for name, rows in drill.after.items() if after[name] != rows
    }
    assert differing <= drill.clock_bound, sorted(differing - drill.clock_bound)


def test_a_replay_without_a_restore_does_not_bring_back_an_assessment(
    migrated_engine: psycopg.Connection, drill: Drill, broker_bootstrap: str
):
    """The claim this module exists for: the engine's tables are the record.

    A capture replayed into an empty migrated schema reconstructs the input and
    everything derived from it — the normalized events, and the host context and
    entities the engine aggregates from them. It reconstructs **nothing** of what
    the pipeline learned: no feed snapshot, no enrichment evidence, no
    assessment, no citation. Re-asking the model would be a different run and
    re-fetching the feed would be a different snapshot (`concept/08`: *"a later
    snapshot changes what an identical context would say"*), so those rows are
    not a cache — they are the record, and a backup is the only thing that
    carries them.
    """
    counts = replay_into(migrated_engine, drill.run.capture, broker_bootstrap)
    assert counts.normalized == drill.run.capture.record_count
    recovered = contents(migrated_engine)
    assert recovered["helena_normalized_events"] == (
        drill.before["helena_normalized_events"]
    ), "the replay did not reproduce the events, so the comparison below is moot"
    assert recovered["helena_signal_host_context"], "no context was aggregated"
    for relation in LEARNED:
        assert drill.before[relation], f"{relation} was empty in the source run"
        assert not recovered[relation], (
            f"{relation} came back from a replay alone, which would mean the "
            f"engine's tables are re-derivable from the capture. They are not"
        )


# --- The other half of the durable record ------------------------------------


def test_the_capture_store_check_verifies_every_hash(tmp_path: Path):
    """Reachable, and every file hashes to its own name. Counts, not adjectives."""
    checked = durability.check_capture_store(FIXTURE_CAPTURES)
    scanned = scan_captures(FIXTURE_CAPTURES)
    assert {capture.sha256 for capture in checked.captures} == set(scanned)
    assert checked.records == sum(
        capture.record_count for capture in scanned.values()
    )
    assert "verified against its own sha256" in checked.summary()


def test_a_reachable_capture_store_holding_nothing_is_zero_and_not_an_error(
    tmp_path: Path,
):
    """`concept/instruction.md` §2: absence is not emptiness — and neither is it an error.

    A deployment that has retained nothing yet has a reachable store with no
    captures in it. That is a state, it is reported as zero, and it is the state
    a mistyped directory must not be confused with — see the test below.
    """
    empty = tmp_path / "empty"
    empty.mkdir()
    checked = durability.check_capture_store(empty)
    assert checked.captures == ()
    assert checked.records == 0


def test_an_unreachable_capture_store_is_not_an_empty_one(tmp_path: Path):
    """The defect this task found: a glob over a missing directory returns nothing.

    Three paths that are not a capture store, each named. Before task 53 all
    three returned `{}` — the same value as a store that is there and holds
    nothing — so a mistyped `--captures` read as *"this deployment retained no
    captures"* and `helena.status` would have printed it as a deployment that
    lost every record it ever ingested (`docs/runbook.md` §13.1).
    """
    for path in (
        tmp_path / "not-there",
        FIXTURE_CAPTURES / "README.md",
        PROJECT_ROOT / "data" / "ingest" / "flow-sample.jsonl",
    ):
        with pytest.raises(CaptureStoreUnreachable) as unreachable:
            durability.check_capture_store(path)
        assert str(path) in str(unreachable.value)


def test_a_capture_that_changed_under_its_name_is_a_different_failure(tmp_path: Path):
    """Corrupt is not unreachable, and the operator does something else about it.

    The hash matters because a capture's sha256 is half of every event id and
    every raw-record reference in the store: a capture that changed under its
    name makes every citation pointing into it a citation to different records.
    """
    original = sorted(FIXTURE_CAPTURES.glob("*.jsonl"))[0]
    corrupted = tmp_path / original.name
    corrupted.write_bytes(original.read_bytes() + b'{"ts":"1970-01-01T00:00:00Z"}\n')
    assert describe_capture(corrupted).sha256 != corrupted.stem
    with pytest.raises(CaptureError) as failed:
        durability.check_capture_store(tmp_path)
    assert not isinstance(failed.value, CaptureStoreUnreachable)
    assert "is not the capture its name claims" in str(failed.value)


# --- The command, the constants and the record -------------------------------


def test_the_command_takes_verifies_and_restores_a_backup(
    drill: Drill,
    migrated_engine: psycopg.Connection,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
):
    """`scripts/backup.py` end to end: --out, --verify, --restore --schema.

    Through `main()` with an argv, because that is what an operator runs and
    because the runbook's procedure is these three commands in this order. The
    schema arguments are the two throwaway schemas this module already has, which
    is the only form a "throwaway instance" takes on a machine that runs one
    engine (`docs/runbook.md` §2).
    """
    (source,) = drill.source.execute("SELECT current_schema()").fetchone()
    (target,) = migrated_engine.execute("SELECT current_schema()").fetchone()
    assert backup.main(["--out", str(tmp_path), "--schema", source]) == 0
    written = sorted(tmp_path.glob("*.jsonl"))
    assert len(written) == 1
    assert backup.main(["--verify", str(written[0])]) == 0
    assert backup.main(["--restore", str(written[0]), "--schema", target]) == 0
    printed = capsys.readouterr().out
    assert f"restored {written[0]} into schema {target}" in printed
    assert rows_of(migrated_engine, "helena_analytical_assessment") == (
        drill.before["helena_analytical_assessment"]
    )


def test_the_command_refuses_a_schema_name_it_would_have_to_interpolate(
    tmp_path: Path,
):
    """`SET search_path` takes an identifier and not a parameter, so the name is checked."""
    with pytest.raises(SystemExit) as refused:
        backup.main(["--out", str(tmp_path), "--schema", "public; DROP SCHEMA public"])
    assert "is not a schema name" in str(refused.value)


def test_the_chunk_size_is_the_one_the_loader_measured():
    """Two copies of a measured constant, asserted equal rather than allowed to drift.

    `helena.enrichment` measured 500-row multi-row INSERTs at 1.2 s against 15.9 s
    for one statement per row, on this engine. The restore path is a second use
    of that measurement, and `concept/instruction.md` §2 is explicit that two
    copies which can drift are worse than none.
    """
    assert durability.INSERT_CHUNK_ROWS == enrichment.INSERT_CHUNK_ROWS


def test_the_runbook_records_the_model_the_exclusions_and_a_recovery_time(
    drill: Drill,
):
    """§15 is part of this increment, and what it has to say is checked.

    `concept/instruction.md` §5: important knowledge goes in the repository. The
    two exclusions are the ones a reader would otherwise assume are covered —
    the broker and the output topic — and the recovery time has to be a
    measurement rather than an adjective, so the drill's own figure is what §15
    quotes and this test requires a number to be there.
    """
    runbook = RUNBOOK.read_text()
    assert "## 15. Durability" in runbook
    section = runbook.split("## 15. Durability", 1)[1].split("\n## ", 1)[0]
    for required in (
        "scripts/backup.py",
        "**The broker**",
        "**The output topic**",
        "### Recovery time",
        "### Residual risk",
        "### The startup check",
    ):
        assert required in section, f"§15 does not mention {required!r}"
    assert re.search(r"\d+\.\d+\s*s", section), (
        "§15 records no measured recovery time, and the drill in this module "
        f"took {drill.seconds:.1f} s"
    )
    assert DECISION.exists(), f"{DECISION} is the decision record for the model"
    assert "scripts/backup.py" in DECISION.read_text()
