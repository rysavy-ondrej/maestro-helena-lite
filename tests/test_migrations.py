"""The migration runner, by execution against a real engine.

Two halves, deliberately. `discover` and `pending` are pure — they compare files
on disk with a ledger already read — so every refusal is tested without an
engine and, more to the point, is *proved* to fire before one is touched. Applying
is tested against RisingWave itself, because the things that would break it are
things only RisingWave decides: whether DDL is transactional, whether an inserted
row is readable before `FLUSH`, whether `CREATE TABLE IF NOT EXISTS` means what
it says.

The throwaway instance is `engine_dsn` from conftest — in-memory, started by the
fixture when nothing answers — and the throwaway *store* is a schema per test.
"""

from __future__ import annotations

import shutil
from datetime import datetime, timezone
from pathlib import Path

import psycopg
import pytest

from helena import migrations
from helena.migrations import LedgerRow, Migration, MigrationError, MigrationFailed

LEDGER_FILE = "0001_schema_migrations.sql"


def _write(directory: Path, filename: str, sql: str) -> Path:
    path = directory / filename
    path.write_text(sql)
    return path


def _with_ledger(directory: Path) -> Path:
    """A migration directory whose 0001 is the real ledger migration.

    Copied rather than re-written: a fabricated ledger would let these tests pass
    against a table the deployment does not have.
    """
    shutil.copy(migrations.MIGRATIONS_DIR / LEDGER_FILE, directory / LEDGER_FILE)
    return directory


def _row(
    migration: Migration, *, status: str = migrations.APPLIED, error: str | None = None
) -> LedgerRow:
    return LedgerRow(
        version=migration.version,
        name=migration.name,
        checksum=migration.checksum,
        status=status,
        error=error,
        applied_at=datetime.now(timezone.utc),
    )


# --- the files on disk -------------------------------------------------------


def test_the_repositorys_migration_set_is_discoverable_and_in_order():
    found = migrations.discover()
    assert [m.version for m in found] == list(range(1, len(found) + 1))
    assert found[0].path.name == LEDGER_FILE
    assert found[0].checksum == migrations.checksum(found[0].path.read_bytes())


def test_a_gap_in_the_numbering_is_refused(tmp_path: Path):
    _write(tmp_path, "0001_first.sql", "SELECT 1;")
    _write(tmp_path, "0003_third.sql", "SELECT 1;")
    with pytest.raises(MigrationError, match="0002"):
        migrations.discover(tmp_path)


def test_numbering_that_does_not_start_at_one_is_refused(tmp_path: Path):
    _write(tmp_path, "0002_second.sql", "SELECT 1;")
    with pytest.raises(MigrationError, match="contiguous"):
        migrations.discover(tmp_path)


def test_two_files_sharing_a_version_are_refused(tmp_path: Path):
    _write(tmp_path, "0001_one.sql", "SELECT 1;")
    _write(tmp_path, "0001_other.sql", "SELECT 2;")
    with pytest.raises(MigrationError, match="share version 0001"):
        migrations.discover(tmp_path)


def test_a_sql_file_that_is_not_numbered_is_refused(tmp_path: Path):
    _write(tmp_path, "0001_first.sql", "SELECT 1;")
    _write(tmp_path, "scratch.sql", "SELECT 1;")
    with pytest.raises(MigrationError, match="NNNN_name.sql"):
        migrations.discover(tmp_path)


def test_an_empty_migration_file_is_refused(tmp_path: Path):
    _write(tmp_path, "0001_nothing.sql", "\n\n")
    with pytest.raises(MigrationError, match="is empty"):
        migrations.discover(tmp_path)


def test_a_missing_migration_directory_is_refused(tmp_path: Path):
    with pytest.raises(MigrationError, match="not a directory"):
        migrations.discover(tmp_path / "nowhere")


def test_a_file_that_is_not_sql_is_not_a_migration(tmp_path: Path):
    _write(tmp_path, "0001_first.sql", "SELECT 1;")
    (tmp_path / "notes.md").write_text("not a migration")
    assert [m.name for m in migrations.discover(tmp_path)] == ["first"]


# --- the files against the ledger, before any engine is touched --------------


def test_pending_is_everything_the_ledger_does_not_have(tmp_path: Path):
    _write(tmp_path, "0001_first.sql", "SELECT 1;")
    _write(tmp_path, "0002_second.sql", "SELECT 2;")
    found = migrations.discover(tmp_path)
    assert migrations.pending(found, {}) == found
    assert migrations.pending(found, {1: _row(found[0])}) == [found[1]]
    assert migrations.pending(found, {v + 1: _row(m) for v, m in enumerate(found)}) == []


def test_an_edit_to_an_applied_migration_is_refused(tmp_path: Path):
    _write(tmp_path, "0001_first.sql", "SELECT 1;")
    applied = _row(migrations.discover(tmp_path)[0])
    _write(tmp_path, "0001_first.sql", "SELECT 1; -- one more comment\n")
    with pytest.raises(MigrationError, match="has changed since it was applied"):
        migrations.pending(migrations.discover(tmp_path), {1: applied})


def test_renaming_an_applied_migration_is_refused(tmp_path: Path):
    _write(tmp_path, "0001_first.sql", "SELECT 1;")
    applied = _row(migrations.discover(tmp_path)[0])
    (tmp_path / "0001_first.sql").rename(tmp_path / "0001_renamed.sql")
    with pytest.raises(MigrationError, match="applied as 'first'"):
        migrations.pending(migrations.discover(tmp_path), {1: applied})


def test_a_recorded_version_with_no_file_is_refused(tmp_path: Path):
    _write(tmp_path, "0001_first.sql", "SELECT 1;")
    _write(tmp_path, "0002_second.sql", "SELECT 2;")
    found = migrations.discover(tmp_path)
    ledger = {1: _row(found[0]), 2: _row(found[1])}
    (tmp_path / "0002_second.sql").unlink()
    with pytest.raises(MigrationError, match="no file for it"):
        migrations.pending(migrations.discover(tmp_path), ledger)


def test_a_gap_in_the_ledger_is_refused(tmp_path: Path):
    _write(tmp_path, "0001_first.sql", "SELECT 1;")
    _write(tmp_path, "0002_second.sql", "SELECT 2;")
    found = migrations.discover(tmp_path)
    with pytest.raises(MigrationError, match="contiguous"):
        migrations.pending(found, {2: _row(found[1])})


def test_a_failed_row_stops_everything(tmp_path: Path):
    _write(tmp_path, "0001_first.sql", "SELECT 1;")
    found = migrations.discover(tmp_path)
    ledger = {1: _row(found[0], status=migrations.FAILED, error="boom")}
    with pytest.raises(MigrationFailed, match="half-migrated") as raised:
        migrations.pending(found, ledger)
    assert raised.value.version == 1
    assert raised.value.recorded_in_ledger is True


def test_a_status_that_is_neither_applied_nor_failed_is_refused(tmp_path: Path):
    """`applied`, `failed` and absent are three things and stay three things."""
    _write(tmp_path, "0001_first.sql", "SELECT 1;")
    found = migrations.discover(tmp_path)
    with pytest.raises(MigrationError, match="neither"):
        migrations.pending(found, {1: _row(found[0], status="probably")})


# --- against the engine ------------------------------------------------------


@pytest.mark.integration
def test_the_full_migration_set_applies_cleanly_from_empty(
    engine_schema: psycopg.Connection,
):
    applied = migrations.apply(engine_schema)
    on_disk = migrations.discover()

    assert [m.version for m in applied] == [m.version for m in on_disk]

    ledger = migrations.recorded(engine_schema)
    # Produced versus materialised: one row per file, no more and no fewer.
    assert len(ledger) == len(on_disk)
    for migration in on_disk:
        row = ledger[migration.version]
        assert row.status == migrations.APPLIED
        assert row.error is None
        assert row.name == migration.name
        assert row.checksum == migration.checksum


@pytest.mark.integration
def test_the_ledger_constant_names_the_table_the_migration_creates(
    migrated_engine: psycopg.Connection,
):
    """The two copies of the table name, asserted equal by asking the engine.

    Grepping the .sql file would find the name in the comment that explains it.
    """
    row = migrated_engine.execute(
        "SELECT count(*) FROM information_schema.tables "
        "WHERE table_schema = current_schema() AND table_name = %s",
        (migrations.LEDGER_TABLE,),
    ).fetchone()
    assert row == (1,)


@pytest.mark.integration
def test_applying_twice_applies_nothing_the_second_time(
    engine_schema: psycopg.Connection,
):
    first = migrations.apply(engine_schema)
    assert first
    before = migrations.recorded(engine_schema)

    assert migrations.apply(engine_schema) == []
    assert migrations.recorded(engine_schema) == before


@pytest.mark.integration
def test_an_applied_file_that_changed_on_disk_is_refused_by_the_engine(
    engine_schema: psycopg.Connection, tmp_path: Path
):
    directory = _with_ledger(tmp_path)
    _write(directory, "0002_a_table.sql", "CREATE TABLE edited_later (x INT);")
    migrations.apply(engine_schema, directory)

    _write(directory, "0002_a_table.sql", "CREATE TABLE edited_later (x INT, y INT);")
    with pytest.raises(MigrationError, match="has changed since it was applied"):
        migrations.apply(engine_schema, directory)


@pytest.mark.integration
def test_a_migration_applied_later_is_the_only_one_that_runs(
    engine_schema: psycopg.Connection, tmp_path: Path
):
    directory = _with_ledger(tmp_path)
    _write(directory, "0002_first_table.sql", "CREATE TABLE grown_one (x INT);")
    migrations.apply(engine_schema, directory)

    _write(directory, "0003_second_table.sql", "CREATE TABLE grown_two (x INT);")
    applied = migrations.apply(engine_schema, directory)

    assert [m.version for m in applied] == [3]
    tables = engine_schema.execute(
        "SELECT table_name FROM information_schema.tables "
        "WHERE table_schema = current_schema() ORDER BY table_name"
    ).fetchall()
    assert [name for (name,) in tables] == [
        "grown_one",
        "grown_two",
        migrations.LEDGER_TABLE,
    ]


@pytest.mark.integration
def test_a_failing_migration_is_recorded_and_blocks_the_next_run(
    engine_schema: psycopg.Connection, tmp_path: Path
):
    """The half-migrated store, measured rather than assumed.

    RisingWave has no transaction around DDL, so the first statement of 0002 is
    still there after the second one raises. That is exactly why the ledger keeps
    a `failed` row: without it, the next run would try to create `half_applied`
    again and the error would be about a duplicate table rather than about a
    migration that did not finish.
    """
    directory = _with_ledger(tmp_path)
    _write(
        directory,
        "0002_half_applied.sql",
        "CREATE TABLE half_applied (x INT);\nCREATE TABLE half_applied (x INT);\n",
    )

    with pytest.raises(MigrationFailed) as raised:
        migrations.apply(engine_schema, directory)
    assert raised.value.version == 2
    assert raised.value.recorded_in_ledger is True

    left_behind = engine_schema.execute(
        "SELECT count(*) FROM information_schema.tables "
        "WHERE table_schema = current_schema() AND table_name = 'half_applied'"
    ).fetchone()
    assert left_behind == (1,)

    ledger = migrations.recorded(engine_schema)
    assert ledger[1].status == migrations.APPLIED
    assert ledger[2].status == migrations.FAILED
    assert ledger[2].error

    with pytest.raises(MigrationFailed, match="recorded as failed"):
        migrations.apply(engine_schema, directory)

    # And once a human has undone it, the runner moves again.
    engine_schema.execute("DROP TABLE half_applied")
    engine_schema.execute(f"DELETE FROM {migrations.LEDGER_TABLE} WHERE version = 2")
    engine_schema.execute("FLUSH")
    _write(directory, "0002_half_applied.sql", "CREATE TABLE half_applied (x INT);\n")
    assert [m.version for m in migrations.apply(engine_schema, directory)] == [2]


@pytest.mark.integration
def test_a_first_migration_that_fails_says_it_could_not_be_recorded(
    engine_schema: psycopg.Connection, tmp_path: Path
):
    """0001 creates the ledger, so its own failure has nowhere to be written."""
    _write(tmp_path, "0001_broken.sql", "CREATE TABLE ( ;")
    with pytest.raises(MigrationFailed, match="NOT recorded") as raised:
        migrations.apply(engine_schema, tmp_path)
    assert raised.value.recorded_in_ledger is False
    assert migrations.recorded(engine_schema) == {}


@pytest.mark.integration
def test_a_connection_that_is_not_in_autocommit_is_refused(engine_dsn: str):
    with psycopg.connect(engine_dsn, connect_timeout=5) as connection:
        with pytest.raises(MigrationError, match="autocommit"):
            migrations.apply(connection)


@pytest.mark.integration
def test_the_migrated_engine_fixture_is_ready_to_be_queried(
    migrated_engine: psycopg.Connection,
):
    """What every later increment takes: an engine holding the schema."""
    assert set(migrations.recorded(migrated_engine)) == {
        m.version for m in migrations.discover()
    }
