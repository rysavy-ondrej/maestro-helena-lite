"""The view-layering boundary and the materialization policy.

`concept/03-architecture.md` puts three view layers in the Context Builder --
**flatten -> signal -> analytical** -- and one rule about how they may refer to
each other: an analytical view reads the signal layer, **never the flatten layer
and never the source**. Beside it sits a measured one: **do not materialize an
intermediate that only feeds an aggregate**, because a materialized intermediate
cost 42 % more disk than the same query as a plain view, storing rows nothing
reads. Both are conventions until something can fail, and this file is what
fails.

The rule is enforced over what the **engine** holds, not over the text of the
`.sql` files. Every object declares, in a comment block above its `CREATE`, which
layer it is in, whether it is a view or a materialized view, what it reads and
what reads it -- and `test_the_declared_reads_are_the_dependencies_the_engine
_recorded` proves that block equal to `rw_catalog.rw_depend` on a running engine
before any layering conclusion is drawn from it. A comment that has drifted from
the SQL fails there rather than quietly making the layering test agree with a
lie.

The parser and the rule live in `helena.migrations`, which is the module that
already owns the file format.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import psycopg
import pytest

from helena import migrations
from helena.config import Settings
from helena.migrations import Declaration, DeclarationError
from helena.normalizer import EventStore, NormalizedEvent, Normalizer, scan_captures

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

import dev_check  # noqa: E402  (needs the path above)

# The same environment and the same capture tests/test_context.py uses: values
# that are obviously not credentials, and ten real records covering every layer.
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
FIXTURE_CAPTURES = Path(__file__).resolve().parent / "fixtures" / "captures"
LAYERS_CAPTURE = "ace6ca33f7bf8aa949f79124abf33fc115cfd0909e9dea798f4762cf87af8318"

# How long the engine may take to account for what it has just written.
# `rw_catalog.rw_table_stats` is filled from what has been flushed to storage,
# so it lags an INSERT by a checkpoint rather than being wrong.
STATS_TIMEOUT_SECONDS = 120.0


@pytest.fixture(scope="module")
def declared() -> dict[str, Declaration]:
    """Every object the migrations create, as its own file declares it."""
    return migrations.declarations()


def synthetic(tmp_path: Path, sql: str) -> list[migrations.Migration]:
    """One migration file on disk, for the cases the repository does not hold."""
    (tmp_path / "0001_synthetic.sql").write_text(sql)
    return migrations.discover(tmp_path)


# --- What the files declare, and what the engine says ------------------------


def test_every_object_the_migrations_create_declares_itself():
    """Parsing is the assertion: `declarations()` refuses an undeclared object.

    Nothing is listed here on purpose. A test that named the objects would pass
    for a new one whose declaration nobody wrote, because nobody would have added
    it to the list either.

    It calls the parser rather than taking the `declared` fixture, so a migration
    that does not declare itself fails *here*, by name, instead of only erroring
    every other test in this file.
    """
    declared = migrations.declarations()
    assert declared
    for name, declaration in declared.items():
        assert declaration.layer in migrations.LAYERS
        assert declaration.kind in migrations.TABLE_TYPES
        assert name not in declaration.reads


@pytest.mark.integration
def test_the_schema_holds_exactly_what_the_migrations_declare(
    migrated_engine: psycopg.Connection, declared: dict[str, Declaration]
):
    """Declared object and kind against `information_schema`, both directions.

    Scoped to the `helena_` prefix every migration object carries, because the
    migrated schema is shared across the run and other tests build `probe_`
    objects in it -- one of which (`tests/test_context.py`'s eviction probe)
    outlives the test that made it.
    """
    found = dict(
        migrated_engine.execute(
            r"SELECT table_name, table_type FROM information_schema.tables "
            r"WHERE table_schema = current_schema() "
            r"AND table_name LIKE 'helena\_%' ESCAPE '\'"
        ).fetchall()
    )
    assert found == {
        name: declaration.table_type for name, declaration in declared.items()
    }


@pytest.mark.integration
def test_the_declared_reads_are_the_dependencies_the_engine_recorded(
    migrated_engine: psycopg.Connection, declared: dict[str, Declaration]
):
    """`Reads:` against `rw_catalog.rw_depend`, expanded the way the engine does.

    The engine does not record what a definition mentions; it records what the
    plan depends on, and **a plain view is inlined into the plan of whatever
    reads it**. So a materialized view over a plain view over a table depends on
    all three, and the expansion stops at a table or a materialized view because
    those are read rather than inlined.

    That is the same fact the materialization policy rests on -- a plain view is
    a query the reader absorbs and stores nothing for -- so asserting it here
    both validates the declarations and pins the behaviour the policy assumes.
    """
    recorded: dict[str, set[str]] = {name: set() for name in declared}
    for reader, target in migrated_engine.execute(
        "SELECT o.name, r.name FROM rw_catalog.rw_depend d "
        "JOIN rw_catalog.rw_relations o ON o.id = d.objid "
        "JOIN rw_catalog.rw_relations r ON r.id = d.refobjid "
        "WHERE o.schema_id = (SELECT id FROM rw_catalog.rw_schemas "
        "WHERE name = current_schema())"
    ).fetchall():
        if reader in recorded:  # a `probe_` object another test left behind
            recorded[reader].add(target)
    assert migrations.reads_the_engine_records(declared) == recorded


@pytest.mark.integration
def test_every_relation_that_reads_an_object_is_named_in_its_read_by(
    migrated_engine: psycopg.Connection, declared: dict[str, Declaration]
):
    """`Read by:` is complete for relations, so a new reader edits the old file.

    The integration marker is deliberate even though the check is over the files:
    it is only worth trusting after the test above has shown the `Reads:` lines
    equal to what the engine recorded, and the ordering the suite applies puts
    that first.
    """
    readers: dict[str, set[str]] = {name: set() for name in declared}
    for name, declaration in declared.items():
        for target in declaration.reads:
            readers[target].add(name)
    missing = {
        name: sorted(readers[name] - declaration.read_by)
        for name, declaration in declared.items()
        if readers[name] - declaration.read_by
    }
    assert missing == {}


def test_every_reader_outside_the_engine_is_a_file_that_exists(
    declared: dict[str, Declaration],
):
    """A `Read by:` naming a module or a test names one that is still there."""
    missing = sorted(
        f"{name} is read by {reader}, which does not exist"
        for name, declaration in declared.items()
        for reader in declaration.readers_outside_the_engine
        if not (PROJECT_ROOT / reader).exists()
    )
    assert missing == []


# --- The layering rule -------------------------------------------------------


def test_no_object_reads_across_a_layer_boundary_it_may_not(
    declared: dict[str, Declaration],
):
    """The invariant itself, over the declarations the engine has agreed with."""
    assert migrations.layering_violations(declared) == []


def test_an_analytical_view_over_the_flatten_layer_is_a_violation(tmp_path: Path):
    """The `analytical` row of the rule, which no object is in yet.

    Written as a migration file rather than as a hand-built mapping, so what is
    exercised is the same parse the repository's own files go through. Both
    illegal reads are named, not just the first: an analytical view that reached
    past the signal layer would usually reach past it twice.
    """
    declared = migrations.declarations(
        synthetic(
            tmp_path,
            """-- Layer:    source
-- Object:   TABLE.
-- Reads:    nothing.
-- Read by:  probe_flatten.
CREATE TABLE probe_events (event_id VARCHAR PRIMARY KEY);

-- Layer:    flatten
-- Object:   VIEW (plain).
-- Reads:    probe_events
-- Read by:  probe_analytical.
CREATE VIEW probe_flatten AS SELECT event_id FROM probe_events;

-- Layer:    analytical
-- Object:   VIEW (plain).
-- Reads:    probe_flatten, probe_events
-- Read by:  nobody yet.
CREATE VIEW probe_analytical AS
SELECT f.event_id FROM probe_flatten f JOIN probe_events e USING (event_id);
""",
        )
    )
    assert migrations.layering_violations(declared) == [
        "probe_analytical (analytical) reads probe_events (source); the "
        "analytical layer may read reference, signal",
        "probe_analytical (analytical) reads probe_flatten (flatten); the "
        "analytical layer may read reference, signal",
    ]


def test_a_signal_view_may_read_the_flatten_layer(tmp_path: Path):
    """The other side of the same rule: the boundary is directional, not a wall."""
    declared = migrations.declarations(
        synthetic(
            tmp_path,
            """-- Layer:    source
-- Object:   TABLE.
-- Reads:    nothing.
-- Read by:  probe_flatten.
CREATE TABLE probe_events (event_id VARCHAR PRIMARY KEY);

-- Layer:    flatten
-- Object:   VIEW (plain).
-- Reads:    probe_events
-- Read by:  probe_signal.
CREATE VIEW probe_flatten AS SELECT event_id FROM probe_events;

-- Layer:    signal
-- Object:   MATERIALIZED VIEW.
-- Reads:    probe_flatten
-- Read by:  tests/test_view_layering.py.
CREATE MATERIALIZED VIEW probe_signal AS
SELECT event_id, count(*) AS n FROM probe_flatten GROUP BY event_id;
""",
        )
    )
    assert migrations.layering_violations(declared) == []


# --- What a declaration has to say -------------------------------------------


@pytest.mark.parametrize("field", migrations.DECLARED_FIELDS)
def test_a_declaration_missing_a_field_is_refused(tmp_path: Path, field: str):
    """Each of the four, dropped one at a time, named in the message."""
    block = {
        "Layer": "-- Layer:    source",
        "Object": "-- Object:   TABLE.",
        "Reads": "-- Reads:    nothing.",
        "Read by": "-- Read by:  tests/test_view_layering.py.",
    }
    del block[field]
    sql = "\n".join(block.values()) + "\nCREATE TABLE probe_events (a VARCHAR);\n"
    with pytest.raises(DeclarationError) as refusal:
        migrations.declarations(synthetic(tmp_path, sql))
    assert f"has no {field}" in str(refusal.value)


def test_an_object_with_no_declaration_block_at_all_is_refused(tmp_path: Path):
    with pytest.raises(DeclarationError, match="has no Layer, Object, Reads, Read by"):
        migrations.declarations(
            synthetic(tmp_path, "CREATE TABLE probe_events (a VARCHAR);\n")
        )


def test_a_materialized_view_with_no_declared_reader_is_refused(tmp_path: Path):
    """The materialization policy, from the side that costs disk.

    A plain view with no reader is a definition nothing evaluates. A materialized
    view with no reader is a streaming job and its state, paid for continuously
    for rows nobody looks at -- so the empty `Read by:` is refused for one and
    not for the other.
    """
    declaration = """-- Layer:    signal
-- Object:   {object}
-- Reads:    nothing.
-- Read by:  nobody, yet.
CREATE {create} probe_thing AS SELECT 1 AS a;
"""
    with pytest.raises(DeclarationError, match="names nobody"):
        migrations.declarations(
            synthetic(
                tmp_path,
                declaration.format(
                    object="MATERIALIZED VIEW.", create="MATERIALIZED VIEW"
                ),
            )
        )
    # The same file as a plain view parses: nothing is being paid for.
    assert migrations.declarations(
        synthetic(tmp_path, declaration.format(object="VIEW (plain).", create="VIEW"))
    )["probe_thing"].read_by == frozenset()


# --- Dropping, which is the only way to change a view ------------------------
#
# RisingWave has no `CREATE OR REPLACE VIEW`, so changing one is dropping it and
# creating it again -- what sql/migrations/0010_entity_value_null_guard.sql does.
# `declarations()` therefore walks the statements in the order they run instead
# of collecting every `CREATE`, and these are the four things that walk can see.

_DECLARED = """-- Layer:    signal
-- Object:   VIEW (plain).
-- Reads:    {reads}
-- Read by:  tests/test_view_layering.py.
CREATE VIEW {name} AS SELECT 1 AS a;
"""


def _view(name: str, reads: str = "nothing.") -> str:
    return _DECLARED.format(name=name, reads=reads)


def test_a_view_recreated_after_a_drop_is_the_later_declaration(tmp_path: Path):
    """The whole point: a migration may change a view by replacing it.

    Before this, `declarations()` refused any relation created twice anywhere in
    the sequence, which made the pattern sql/migrations/0009's own head
    prescribes -- "a new migration that drops and recreates every object here" --
    impossible to carry out.
    """
    declared = migrations.declarations(
        synthetic(
            tmp_path,
            _view("probe_thing")
            + "\nDROP VIEW probe_thing;\n\n"
            + _DECLARED.format(name="probe_thing", reads="probe_other.").replace(
                "-- Layer:    signal", "-- Layer:    analytical"
            ),
        )
    )
    assert declared["probe_thing"].layer == "analytical"
    assert declared["probe_thing"].reads == frozenset({"probe_other"})


def test_a_view_created_twice_without_a_drop_is_still_refused(tmp_path: Path):
    with pytest.raises(DeclarationError, match="created twice"):
        migrations.declarations(
            synthetic(tmp_path, _view("probe_thing") + "\n" + _view("probe_thing"))
        )


def test_dropping_something_no_migration_created_is_refused(tmp_path: Path):
    with pytest.raises(DeclarationError, match="nothing has created it"):
        migrations.declarations(synthetic(tmp_path, "DROP VIEW probe_thing;\n"))


def test_dropping_something_still_read_is_refused(tmp_path: Path):
    """The engine refuses this drop; refusing it here is refusing it earlier.

    Nothing has touched the engine when this fires, which is the shape of every
    other refusal in `helena.migrations`.
    """
    sql = (
        _view("probe_thing")
        + "\n"
        + _view("probe_reader", reads="probe_thing.")
        + "\nDROP VIEW probe_thing;\n"
    )
    with pytest.raises(DeclarationError, match="probe_reader still reads it"):
        migrations.declarations(synthetic(tmp_path, sql))


def test_a_cascading_drop_is_refused(tmp_path: Path):
    """A file whose effect is larger than its text cannot be reviewed.

    `DROP ... CASCADE` on the entity view takes six objects it does not name.
    0010 drops all seven by name and in order instead, which is why the order is
    checkable at all.
    """
    sql = _view("probe_thing") + "\nDROP VIEW probe_thing CASCADE;\n"
    with pytest.raises(DeclarationError, match="CASCADE"):
        migrations.declarations(synthetic(tmp_path, sql))


def test_the_repository_drops_nothing_it_does_not_recreate():
    """Over the real migrations, and not a synthetic one.

    0010 drops seven objects and creates seven; a file that dropped one and
    forgot it would leave a relation other declarations still name as a reader,
    which `layering_violations` reports from the other side. This asserts the
    count directly so the failure names the missing object rather than its
    readers.
    """
    declared = migrations.declarations()
    for name in (
        "helena_signal_entity_observations",
        "helena_signal_context_entities",
        "helena_signal_context_entities_retained",
        "helena_signal_domain_suffix_candidates",
        "helena_signal_domain_public_suffix",
        "helena_signal_domain_registrable",
        "helena_signal_context_domains",
    ):
        assert name in declared, f"{name} is dropped and never recreated"
        assert declared[name].migration == "0010_entity_value_null_guard.sql"


def test_a_declaration_that_disagrees_with_its_own_create_is_refused(tmp_path: Path):
    """The field says materialized, the SQL says plain. That is the drift."""
    with pytest.raises(DeclarationError, match="declares itself a MATERIALIZED VIEW"):
        migrations.declarations(
            synthetic(
                tmp_path,
                """-- Layer:    signal
-- Object:   MATERIALIZED VIEW.
-- Reads:    nothing.
-- Read by:  tests/test_view_layering.py.
CREATE VIEW probe_thing AS SELECT 1 AS a;
""",
            )
        )


def test_reads_must_be_relations_rather_than_prose(tmp_path: Path):
    with pytest.raises(DeclarationError, match="as a list of relations"):
        migrations.declarations(
            synthetic(
                tmp_path,
                """-- Layer:    flatten
-- Object:   VIEW (plain).
-- Reads:    the normalized events, mostly
-- Read by:  tests/test_view_layering.py.
CREATE VIEW probe_thing AS SELECT 1 AS a;
""",
            )
        )


# --- What the policy costs, read off a running engine ------------------------


def store_layer_capture(connection: psycopg.Connection) -> None:
    """The ten-record layer capture, through the real ingestion path."""
    configured = Settings.load(environ=ENVIRONMENT, env_file=None)
    normalizer = Normalizer.from_settings(configured)
    store = EventStore(connection=connection, identity=configured.identity)
    for result in normalizer.normalize_capture(
        scan_captures(FIXTURE_CAPTURES)[LAYERS_CAPTURE]
    ):
        assert isinstance(result, NormalizedEvent), result
        store.record(result)
    connection.execute("FLUSH")


def stored_bytes(connection: psycopg.Connection, *names: str) -> dict[str, int]:
    """Wait until the engine has accounted for `names`, then report their bytes.

    A bounded wait rather than a sleep, and a failure rather than a zero: a test
    that read the stats too early and concluded "it stores nothing" would prove
    the policy by not looking.
    """
    deadline = time.monotonic() + STATS_TIMEOUT_SECONDS
    while True:
        connection.execute("FLUSH")
        stored = dev_check.storage(connection)
        sizes = {name: stored[name][1] for name in names}
        if all(sizes.values()) or time.monotonic() >= deadline:
            assert all(sizes.values()), (
                f"the engine still reports {sizes} after "
                f"{STATS_TIMEOUT_SECONDS:.0f} s; rw_table_stats never filled"
            )
            return sizes
        time.sleep(2.0)


@pytest.mark.integration
def test_a_plain_view_stores_nothing_and_the_check_says_so(
    migrated_engine: psycopg.Connection, declared: dict[str, Declaration]
):
    """The materialization policy as the engine accounts for it.

    Every byte `scripts/dev_check.py --storage` reports belongs to a table or a
    materialized view; the nineteen plain views report zero, with records in the
    store and the whole layer above them running. That is what the policy buys,
    and it is the reason a plain view is the default rather than a preference.
    """
    store_layer_capture(migrated_engine)
    stored_bytes(migrated_engine, "helena_normalized_events")
    stored = {
        name: value
        for name, value in dev_check.storage(migrated_engine).items()
        if name.startswith("helena_")  # not another test's `probe_` object
    }

    assert set(stored) == set(declared)
    plain = {name for name, (kind, _) in stored.items() if kind == "view"}
    assert plain == {
        name for name, declaration in declared.items() if declaration.kind == "VIEW"
    }
    assert {name: size for name, (_, size) in stored.items() if name in plain} == {
        name: 0 for name in plain
    }
    assert sum(size for _, size in stored.values()) > 0


@pytest.mark.integration
def test_materializing_an_intermediate_that_feeds_an_aggregate_costs_disk(
    migrated_engine: psycopg.Connection,
):
    """The measurement the policy is made of, taken here rather than quoted.

    Two pipelines over the same rows and producing the same aggregate: one over
    `helena_flatten_flows` as it is -- a plain view, inlined into the aggregate's
    plan -- and one over a materialized copy of it, which is
    `concept/03-architecture.md`'s "materialized intermediate that only feeds an
    aggregate". The second stores the flow rows as well as the aggregate, and
    nothing reads them.

    What is asserted is the direction, because the size of the difference is a
    property of the input -- the aggregation factor -- and not a constant.
    Measured on 2026-09-04: **+12 %** over this ten-record capture, and **+56 %**
    over 73 flow rows (these ten plus `data/ingest/flow-sample.jsonl`) collapsing
    into 2 contexts. `concept/03-architecture.md`'s 42 % is a third workload's
    number and is not reproduced here; what the check gives is the number for
    whatever is actually loaded, which is the point of having it. Run the suite
    with `-s` to see this one, or `uv run scripts/dev_check.py --storage`
    against a running engine.
    """
    store_layer_capture(migrated_engine)
    aggregate = """
    SELECT f.tenant, f.sensor, f.src_address AS host, f.window_start,
           count(*)::BIGINT AS flow_count,
           sum(f.bytes_sent)::BIGINT AS bytes_sent,
           sum(f.bytes_received)::BIGINT AS bytes_received
    FROM TUMBLE({source}, flow_start, INTERVAL '5 minutes') f
    GROUP BY f.tenant, f.sensor, f.src_address, f.window_start
    """
    probes = ("probe_over_a_view", "probe_intermediate", "probe_over_the_intermediate")
    try:
        migrated_engine.execute(
            "CREATE MATERIALIZED VIEW probe_over_a_view AS "
            + aggregate.format(source="helena_flatten_flows")
        )
        migrated_engine.execute(
            "CREATE MATERIALIZED VIEW probe_intermediate AS "
            "SELECT * FROM helena_flatten_flows"
        )
        migrated_engine.execute(
            "CREATE MATERIALIZED VIEW probe_over_the_intermediate AS "
            + aggregate.format(source="probe_intermediate")
        )
        sizes = stored_bytes(migrated_engine, *probes)
        plain_view = sizes["probe_over_a_view"]
        materialized = sizes["probe_intermediate"] + sizes["probe_over_the_intermediate"]
        print(
            f"\nmaterialized intermediate: {materialized:,} bytes against "
            f"{plain_view:,} for the same aggregate over a plain view "
            f"(+{100 * (materialized / plain_view - 1):.0f} %)"
        )
        assert materialized > plain_view
        # The extra is the intermediate, and it is rows nothing reads: the two
        # pipelines produce the same aggregate.
        assert (
            migrated_engine.execute("SELECT count(*) FROM probe_over_a_view").fetchone()
            == migrated_engine.execute(
                "SELECT count(*) FROM probe_over_the_intermediate"
            ).fetchone()
        )
    finally:
        for probe in reversed(probes):
            migrated_engine.execute(f"DROP MATERIALIZED VIEW IF EXISTS {probe}")


@pytest.mark.integration
def test_the_storage_check_refuses_a_schema_with_no_migrations(
    engine_schema: psycopg.Connection,
):
    """`--storage` on an unmigrated store says so rather than printing nothing.

    It is the one failure the check has, and an empty report would read as "the
    schema costs nothing" -- which is true of an empty schema and useless.
    """
    assert dev_check.storage(engine_schema) == {}
    with pytest.raises(dev_check.CheckFailed, match="make migrate"):
        dev_check.storage_report(dev_check.storage(engine_schema))


def test_the_layer_vocabulary_is_what_the_concept_note_names():
    """A layer added to `LAYERS` without a rule would default to reading nothing.

    `MAY_READ` is the rule; this asserts the two cannot drift apart, and pins the
    row the invariant is about.
    """
    assert set(migrations.MAY_READ) == set(migrations.LAYERS)
    assert migrations.MAY_READ["analytical"] == frozenset({"signal", "reference"})
    assert migrations.MAY_READ["flatten"] == frozenset({"source"})


def test_the_layer_capture_is_the_one_the_context_tests_use():
    """One capture, named in two files. Asserted rather than assumed equal."""
    records = (FIXTURE_CAPTURES / f"{LAYERS_CAPTURE}.jsonl").read_bytes().splitlines()
    assert len(records) == 10
    assert all(json.loads(line) for line in records)
