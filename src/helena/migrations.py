"""Migrations — the engine's schema as plain numbered `.sql` files, applied in order.

`concept/06-technology.md` settles both halves of this: the engine's view and
model definitions are **project source in their own right**, and migrations are
**plain numbered `.sql` files applied in order, tested by execution against a
throwaway instance**. No SQL transformation framework — that would be a major
dependency sitting in the data path ahead of any measured need for it.

So this module is small on purpose. It discovers `sql/migrations/NNNN_name.sql`,
decides what is pending, and executes each pending file against a connection.
Everything else it does is refusal:

| It refuses when | Because |
| --- | --- |
| a `.sql` file does not match `NNNN_name.sql` | an unordered file has no place in an ordered sequence |
| two files share a version | "in order" stops being defined |
| the versions are not `1..N` with no gap | a gap means a file was lost, or one was written against a number that has already shipped |
| a recorded version has no file | same, from the other side |
| an applied file's checksum or name changed | the engine no longer holds what the repository says it holds |
| a recorded version is `failed` | the store is half-migrated and a human has to look |
| the connection is not in autocommit | RisingWave DDL outside autocommit is not visible to the next statement |

None of those touch the engine before they fire, except the ones that have to
read the ledger.

**The ledger is migration 0001, not a constant in this file.** The runner reads
`helena_schema_migrations` to decide what is pending, and when that table does
not exist, nothing has been applied — which is exactly the empty state. The one
consequence to know: if 0001 itself fails there is nowhere to record that it
failed, and the raised error says so rather than pretending otherwise.

**There is no rollback and there cannot be one.** RisingWave has no transaction
around DDL — measured, not assumed: `CREATE TABLE a; CREATE TABLE a` in one
statement leaves `a` behind and then raises. A file that fails partway therefore
leaves whatever ran before the failure in place, and the ledger records the
version as `failed` so that the half-migrated state is visible and countable
instead of being rediscovered later by a confusing error. Recovery is manual and
deliberate: undo what the file did, delete the `failed` row, fix the file.

**Ordering rule for a deployment.** Every view a deployment needs must exist
*before* data starts flowing. The broker is consume-once and restart-volatile
(`concept/03-architecture.md`, "What is *not* a store"), so a record consumed
before a view existed is gone: a view created later starts empty and there is
nothing to replay it from except a retained source capture. Migrate first, then
start ingest — see `docs/runbook.md`.

Reads: `sql/migrations/*.sql` and the `helena_schema_migrations` table.
Writes: whatever the migration files write, plus one ledger row per file.

Maturity: experimental — exercised by `tests/test_migrations.py` against a real
engine, including the failure paths. It has applied exactly one migration set on
one engine version, and no deployment has run against it.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import psycopg

PROJECT_ROOT = Path(__file__).resolve().parents[2]
MIGRATIONS_DIR = PROJECT_ROOT / "sql" / "migrations"

# The table migration 0001 creates. Two copies of this name exist — here and in
# the .sql file — so a test asserts them equal the only way that means anything:
# by applying the migrations and asking the engine what it now holds.
LEDGER_TABLE = "helena_schema_migrations"

# The two statuses a ledger row can carry. They are never collapsed: `applied`
# means the whole file ran, `failed` means part of it may have.
APPLIED = "applied"
FAILED = "failed"

FILENAME = re.compile(r"^(\d{4})_([a-z0-9]+(?:_[a-z0-9]+)*)\.sql$")


class MigrationError(Exception):
    """The files and the ledger disagree, so nothing was executed.

    Every case is a refusal *before* any migration ran, which is why it is worth
    telling apart from `MigrationFailed`: the store is exactly as it was.
    """


class MigrationFailed(MigrationError):
    """A migration file raised while it was being executed.

    The store may be half-migrated — RisingWave has no transaction around DDL —
    and `recorded_in_ledger` says whether that fact reached the engine.
    """

    def __init__(self, message: str, *, version: int, recorded_in_ledger: bool):
        super().__init__(message)
        self.version = version
        self.recorded_in_ledger = recorded_in_ledger


@dataclass(frozen=True)
class Migration:
    """One `NNNN_name.sql` file on disk."""

    version: int
    name: str
    path: Path
    checksum: str
    sql: str

    @property
    def label(self) -> str:
        return f"{self.version:04d}_{self.name}.sql"


@dataclass(frozen=True)
class LedgerRow:
    """One row of `helena_schema_migrations`, as the engine holds it."""

    version: int
    name: str
    checksum: str
    status: str
    error: str | None
    applied_at: datetime


def checksum(content: bytes) -> str:
    """The sha256 of a migration file's bytes, as recorded in the ledger."""
    return hashlib.sha256(content).hexdigest()


def discover(directory: Path = MIGRATIONS_DIR) -> list[Migration]:
    """Every migration in `directory`, in order, or a `MigrationError`.

    Only `*.sql` is considered a migration; a `.sql` file that does not match
    `NNNN_name.sql` is an error rather than something skipped quietly, because
    a skipped migration is indistinguishable from an applied one afterwards.
    """
    if not directory.is_dir():
        raise MigrationError(
            f"{directory} is not a directory; it holds the numbered migration "
            f"files and there is nothing to apply without it"
        )
    found: dict[int, Migration] = {}
    for path in sorted(directory.glob("*.sql")):
        match = FILENAME.match(path.name)
        if match is None:
            raise MigrationError(
                f"{path} is not named NNNN_name.sql (four digits, an "
                f"underscore, then lowercase words separated by underscores)"
            )
        version = int(match.group(1))
        if version < 1:
            raise MigrationError(f"{path} numbers itself 0000; versions start at 0001")
        if version in found:
            raise MigrationError(
                f"{path.name} and {found[version].label} share version "
                f"{version:04d}; 'applied in order' has no meaning for two files "
                f"with the same number"
            )
        content = path.read_bytes()
        if not content.strip():
            raise MigrationError(f"{path} is empty; delete it or write the migration")
        found[version] = Migration(
            version=version,
            name=match.group(2),
            path=path,
            checksum=checksum(content),
            sql=content.decode("utf-8"),
        )
    _require_contiguous(sorted(found), f"the migration files in {directory}")
    return [found[version] for version in sorted(found)]


def recorded(connection: psycopg.Connection) -> dict[int, LedgerRow]:
    """The ledger, keyed by version — empty when the ledger table does not exist.

    An absent ledger is the empty state, not an error: migration 0001 is what
    creates it.
    """
    _require_autocommit(connection)
    if not _ledger_exists(connection):
        return {}
    rows = connection.execute(
        f"SELECT version, name, checksum, status, error, applied_at "
        f"FROM {LEDGER_TABLE} ORDER BY version"
    ).fetchall()
    return {row[0]: LedgerRow(*row) for row in rows}


def pending(
    migrations: Sequence[Migration], ledger: Mapping[int, LedgerRow]
) -> list[Migration]:
    """What is left to apply, or a `MigrationError` saying why nothing can be.

    Pure: it compares two things that have already been read, so every refusal
    below can be tested without an engine and fires before one is touched.
    """
    on_disk = {migration.version: migration for migration in migrations}
    for version in sorted(ledger):
        row = ledger[version]
        if row.status == FAILED:
            raise MigrationFailed(
                f"{version:04d}_{row.name}.sql is recorded as failed in "
                f"{LEDGER_TABLE} ({row.error}). Part of it may have been "
                f"applied — RisingWave has no transaction around DDL — so the "
                f"store is half-migrated. Undo what the file did, delete the "
                f"row, then run again.",
                version=version,
                recorded_in_ledger=True,
            )
        if row.status != APPLIED:
            raise MigrationError(
                f"{LEDGER_TABLE} records version {version:04d} with status "
                f"{row.status!r}, which is neither {APPLIED!r} nor {FAILED!r}"
            )
        migration = on_disk.get(version)
        if migration is None:
            raise MigrationError(
                f"version {version:04d} ({row.name}) is recorded as applied but "
                f"there is no file for it. The engine holds something the "
                f"repository no longer describes; restore the file rather than "
                f"deleting the row."
            )
        if migration.name != row.name:
            raise MigrationError(
                f"version {version:04d} was applied as {row.name!r} and the file "
                f"is now named {migration.name!r}. Renaming an applied migration "
                f"makes the ledger stop naming what ran."
            )
        if migration.checksum != row.checksum:
            raise MigrationError(
                f"{migration.label} has changed since it was applied "
                f"(sha256 {migration.checksum}, ledger has {row.checksum}). The "
                f"engine does not hold what this file says; write a new "
                f"migration instead of editing an applied one."
            )
    _require_contiguous(sorted(ledger), f"the versions recorded in {LEDGER_TABLE}")
    return [migration for migration in migrations if migration.version not in ledger]


def apply(
    connection: psycopg.Connection, directory: Path = MIGRATIONS_DIR
) -> list[Migration]:
    """Apply every pending migration in order. Returns what it applied.

    Idempotent: a second call over an unchanged directory applies nothing and
    returns an empty list.
    """
    _require_autocommit(connection)
    migrations = discover(directory)
    applied: list[Migration] = []
    for migration in pending(migrations, recorded(connection)):
        try:
            connection.execute(migration.sql)
        except psycopg.Error as error:
            noted = _note(connection, migration, FAILED, str(error))
            raise MigrationFailed(
                f"{migration.label} failed: {error}. RisingWave has no "
                f"transaction around DDL, so whatever ran before the failing "
                f"statement is still there."
                + (
                    f" It is recorded as {FAILED} in {LEDGER_TABLE}."
                    if noted
                    else f" It is NOT recorded in {LEDGER_TABLE}, because that "
                    f"table does not exist — this migration is what creates it."
                ),
                version=migration.version,
                recorded_in_ledger=noted,
            ) from error
        _note(connection, migration, APPLIED, None)
        applied.append(migration)
    return applied


def _note(
    connection: psycopg.Connection, migration: Migration, status: str, error: str | None
) -> bool:
    """Write one ledger row. False when there is no ledger to write it to."""
    if not _ledger_exists(connection):
        return False
    connection.execute(
        f"INSERT INTO {LEDGER_TABLE} "
        f"(version, name, checksum, status, error, applied_at) "
        f"VALUES (%s, %s, %s, %s, %s, %s)",
        (
            migration.version,
            migration.name,
            migration.checksum,
            status,
            error,
            datetime.now(timezone.utc),
        ),
    )
    # RisingWave makes an inserted row readable only after a FLUSH, so without
    # this the next `recorded()` would report the migration as pending.
    connection.execute("FLUSH")
    return True


def _ledger_exists(connection: psycopg.Connection) -> bool:
    row = connection.execute(
        "SELECT count(*) FROM information_schema.tables "
        "WHERE table_schema = current_schema() AND table_name = %s",
        (LEDGER_TABLE,),
    ).fetchone()
    return bool(row and row[0])


def _require_autocommit(connection: psycopg.Connection) -> None:
    if not connection.autocommit:
        raise MigrationError(
            "the connection is not in autocommit. RisingWave DDL run inside an "
            "open transaction is not visible to the statements that follow it, "
            "so a migration would appear to apply and then not be there."
        )


def _require_contiguous(versions: Sequence[int], what: str) -> None:
    """Versions must be exactly 1..N. A gap is a lost file, not a style choice."""
    expected = list(range(1, len(versions) + 1))
    if list(versions) != expected:
        # There is always something missing: the set is sorted and distinct, so
        # if it is not 1..N then some number below its own maximum is absent.
        missing = sorted(set(expected) - set(versions))
        raise MigrationError(
            f"{what} are {[f'{v:04d}' for v in versions]}, which is not a "
            f"contiguous sequence from 0001: "
            f"{[f'{v:04d}' for v in missing]} not there"
        )
