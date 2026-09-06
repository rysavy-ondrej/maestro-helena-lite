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
| an object has no declaration block, or one missing a field | a view that does not say what it is and what reads it is how a layer boundary rots |
| a materialized view names nobody who reads it | that is a streaming job and its state, paid for rows nothing looks at |
| an object is created while one of that name is live | the engine refuses it, and the file believes it created something |
| an object is dropped that nothing created | the file is undoing something no file did |
| an object is dropped while a live object still reads it | the engine refuses that drop; the dependents come first |
| a drop says `CASCADE` | it takes objects the file does not name, and a file whose effect is larger than its text cannot be reviewed |
| a replaced definition does not declare `Superseded by:` | the `CREATE` left behind is one the engine never holds, and editing it changes nothing anywhere |
| a `Superseded by:` names a migration that does not recreate the object | it sends a reader to a definition that is not there |

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

**Every object a migration creates declares itself** in a comment block above
its `CREATE` — which layer it is in, whether it is a view or a materialized view,
what it reads and what reads it. The engine strips comments, so the file is the
only place that block can live, and this module is where it is read:
`declarations()` parses it, `layering_violations()` is
`concept/03-architecture.md`'s flatten → signal → analytical rule over what it
says, and `reads_the_engine_records()` is how what it says is checked against
`rw_catalog.rw_depend` rather than believed. See `tests/test_view_layering.py`
and `docs/decisions/0016-view-layering-and-materialization-policy.md`.

**Changing a view means dropping it and creating it again**, because RisingWave
has no `CREATE OR REPLACE VIEW` — and dropping it means dropping everything
standing on it first. `declarations()` therefore reports what the schema holds
*after every migration has run* rather than every `CREATE` any of them contains:
it walks the statements in the order they execute and checks each against what
exists at that point. `sql/migrations/0010_entity_value_null_guard.sql` is the
first file to use this, and it drops seven objects by name rather than one with
`CASCADE`, which this module refuses for the reason the declaration blocks exist
at all.

The `CREATE` left behind in the earlier file is then a definition the engine does
not hold, and the trap that sets is a person opening it, fixing something, and
changing nothing anywhere. **`Superseded by:` is the fifth declared field and the
only optional one**: it names the migration that replaced this definition, it is
checked in both directions by the walk, and `superseded()` returns the replaced
definitions. Writing a superseding migration therefore means editing the file it
supersedes — an applied file, whose checksum changes — which is a real cost and
is the same one task 17's declaration retrofit paid. `docs/runbook.md`, "Editing
a migration that has already been applied", says what it does to a store.

Reads: `sql/migrations/*.sql` and the `helena_schema_migrations` table.
Writes: whatever the migration files write, plus one ledger row per file.

Maturity: experimental — exercised by `tests/test_migrations.py` against a real
engine, including the failure paths, and by `tests/test_view_layering.py` for the
declarations. It has applied exactly one migration set on one engine version, and
no deployment has run against it.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
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


# --- Declarations: what each object is, which layer it is in, and who reads it


# The layers an object can declare itself into. The middle three are
# `concept/03-architecture.md`'s view stack -- **flatten -> signal ->
# analytical** -- and the other three are what that stack stands on and beside:
# `source` is what ingestion writes, `reference` is a constant or a
# snapshot-versioned feed table, and `operational` is the engine's own
# bookkeeping, which the pipeline does not read at all.
LAYERS = ("operational", "source", "reference", "flatten", "signal", "analytical")

# Which layer may read which. The row that matters is `analytical`: it reads the
# signal layer, **never the flatten layer and never the source** -- the
# invariant in `concept/instruction.md` §2 and `concept/03-architecture.md`.
# `flatten` reading only `source` is the same rule from the bottom: a flatten
# view that read another one would make the layer a stack of its own.
MAY_READ: Mapping[str, frozenset[str]] = {
    "operational": frozenset(),
    "source": frozenset({"source"}),
    "reference": frozenset({"reference"}),
    "flatten": frozenset({"source"}),
    "signal": frozenset({"flatten", "signal", "reference"}),
    "analytical": frozenset({"signal", "reference"}),
}

# What the engine reports for each, in `information_schema.tables.table_type`.
TABLE_TYPES = {
    "TABLE": "BASE TABLE",
    "VIEW": "VIEW",
    "MATERIALIZED VIEW": "MATERIALIZED VIEW",
}

DECLARED_FIELDS = ("Layer", "Object", "Reads", "Read by")

# One optional field, and the only one. It names the migration that **takes this
# definition out of service**, which happens two ways and means the same thing to
# a reader either way:
#
#   replaced  the migration drops the object and creates it again. This is how a
#             view is changed here at all -- RisingWave has no
#             `CREATE OR REPLACE VIEW` -- and 0010 is the first case.
#   removed   the migration drops it and nothing recreates it, because the object
#             was superseded by something with a different name. 0013 does that
#             to 0012's per-feed load table.
#
# One field for both, because the question a reader has is the same in both
# cases: *is the CREATE I am looking at what the engine holds?* Two fields would
# make them answer it twice.
#
# It exists because the alternative is a trap. After 0010 supersedes it, the
# `CREATE VIEW helena_signal_entity_observations` in 0007 is a definition the
# engine never uses: editing it to fix something silently does nothing, and
# nothing in 0007 says so. This is what says so, in the file a person would open.
#
# It is checked in both directions rather than believed (`declarations()`), so it
# cannot drift: a definition that declares it must actually be superseded by that
# migration, and a definition that *is* superseded must declare it. That second
# direction is what makes writing a superseding migration a retrofit of the file
# it supersedes -- see `docs/runbook.md`, "Editing a migration that has already
# been applied", for what that costs a store that has applied it.
SUPERSEDED_BY = "Superseded by"

_CREATE = re.compile(
    r"^CREATE\s+(TABLE|MATERIALIZED\s+VIEW|VIEW)\s+"
    r"(?:IF\s+NOT\s+EXISTS\s+)?([a-z][a-z0-9_]*)",
    re.MULTILINE,
)
# A migration may take an object away as well as add one. RisingWave has no
# `CREATE OR REPLACE VIEW` (measured: "Feature is not yet implemented"), so
# *changing* a view is dropping it and creating it again, which is what
# sql/migrations/0009_retention_boundary.sql's head means by "a new migration
# that drops and recreates every object here".
#
# `CASCADE` is deliberately not in this pattern, and a migration in this
# repository must not use it. A cascading drop takes objects the file does not
# name -- seven of them, for the entity views -- and a file whose effect is
# larger than its text is exactly the thing the declaration blocks exist to
# prevent. Drop dependents first, by name, and the file says what it destroys.
_DROP = re.compile(
    r"^DROP\s+(TABLE|MATERIALIZED\s+VIEW|VIEW)\s+"
    r"(?:IF\s+EXISTS\s+)?([a-z][a-z0-9_]*)\s*(CASCADE)?",
    re.MULTILINE,
)
_DECLARED_FIELD = re.compile(
    r"^--\s(Layer|Object|Reads|Read by|Superseded by):\s+(\S.*)$"
)
_CONTINUATION = re.compile(r"^--\s{4,}(\S.*)$")
_DECLARED_KIND = re.compile(r"(?:plain\s+)?(MATERIALIZED\s+VIEW|VIEW|TABLE)\b", re.I)
# `Reads:` is a list and is parsed as one, so any relation name is recognised
# there. `Read by:` is prose -- it says *why* something reads this, and names
# modules and tests as well as relations -- so a relation is recognised in it by
# the prefix every object in this schema carries. A migration that dropped the
# prefix would be a naming decision, and this is one of the places it would cost.
_IDENTIFIER = re.compile(r"[a-z][a-z0-9_]*")
_READS_LIST = re.compile(r"^[a-z][a-z0-9_]*(?:,\s*[a-z][a-z0-9_]*)*\.?$")
_RELATION = re.compile(r"\bhelena_[a-z0-9_]+\b")
_REPOSITORY_FILE = re.compile(r"\b(?:src|tests|scripts)/[A-Za-z0-9_./-]+\.py\b")
_MODULE_SYMBOL = re.compile(r"\bhelena\.([a-z][a-z0-9_]*)\.[A-Za-z_]")


class DeclarationError(MigrationError):
    """A migration file does not say what one of its objects is.

    Every view declares whether it is a view or a materialized view and what
    reads it (`concept/instruction.md` §7), and the declaration is a comment
    block above the `CREATE` -- the engine strips comments, so this is the only
    place it can live. An object without one is this error rather than an object
    nobody notices.
    """


@dataclass(frozen=True)
class Declaration:
    """The declaration block above one `CREATE`, as the file states it."""

    relation: str
    kind: str
    layer: str
    reads: frozenset[str]
    read_by: frozenset[str]
    readers_outside_the_engine: frozenset[str]
    migration: str
    line: int
    # The migration this definition declares takes it out of service, or None
    # for a definition the engine still holds. See `SUPERSEDED_BY`.
    superseded_by: str | None = None
    # The migration that actually dropped it, filled in by the walk. None while
    # the object is live. `superseded_by` is the claim; this is the fact, and
    # `declarations()` refuses a file where they disagree.
    superseded_in: str | None = None

    @property
    def materialized(self) -> bool:
        return self.kind == "MATERIALIZED VIEW"

    @property
    def table_type(self) -> str:
        """What `information_schema.tables` reports for an object of this kind."""
        return TABLE_TYPES[self.kind]


def declarations(
    migrations: Sequence[Migration] | None = None,
) -> dict[str, Declaration]:
    """Every object the migrations create, keyed by relation name.

    The result is what the schema holds **after every migration has run**, not
    every `CREATE` any of them contains. The two differ once a migration drops an
    object and creates it again, which is the only way to change a view here:
    RisingWave has no `CREATE OR REPLACE VIEW`. So the statements are walked in
    order -- in file order within a migration, in version order across them --
    and each one is checked against what exists at that point.

    Raises `DeclarationError` when an object has no declaration block, when a
    block is missing a field, when `Reads:` is not a list of relations, when a
    materialized view names nobody who reads it -- a materialized view with no
    reader is the 42 % `concept/03-architecture.md` measures, paid for rows
    nothing looks at -- and for the three things a walk in order can see that a
    set of `CREATE`s cannot:

    * an object created while one of that name already exists. This is the check
      that was here before, and it now means what it says rather than "created
      twice anywhere in the sequence": a recreation after a drop is legal.
    * an object dropped that does not exist at that point -- a file undoing
      something no file did.
    * an object dropped while a surviving object still declares that it reads
      it. RisingWave refuses that drop, and refusing it here means the refusal
      arrives before anything touched the engine, which is the whole shape of
      this module.
    * a `Superseded by:` that is not true, in either direction -- a definition
      claiming to be superseded by a migration that does not drop it, or a
      definition that is dropped and does not say so. `superseded()` returns
      the definitions this walk stepped over, replaced and removed alike.
    """
    found, _ = _walk(discover() if migrations is None else migrations)
    return found


def superseded(
    migrations: Sequence[Migration] | None = None,
) -> list[Declaration]:
    """Every definition a later migration dropped and replaced, in the order it went.

    These are the `CREATE`s in the tree that the engine does not hold, and they
    come in two kinds that read the same way to whoever opens the file: 0010
    **replaces** seven of 0007's, 0008's and 0009's definitions, and 0013
    **removes** two of 0012's outright, because a per-feed load table was
    superseded by one snapshot table for every source. Editing any of them where
    it was first written changes nothing anywhere.

    Each carries a `Superseded by:` naming the migration that dropped it, checked
    by the walk rather than trusted.
    """
    _, retired = _walk(discover() if migrations is None else migrations)
    return retired


def _walk(
    migrations: Sequence[Migration],
) -> tuple[dict[str, Declaration], list[Declaration]]:
    """The live objects and the replaced definitions, from one pass in order."""
    found: dict[str, Declaration] = {}
    # Definitions that have been dropped, newest last, keyed by relation. A
    # relation can appear more than once over a long enough history.
    retired: list[Declaration] = []
    for migration in migrations:
        lines = migration.sql.splitlines()
        for match in _statements(migration.sql):
            number = migration.sql.count("\n", 0, match.start()) + 1
            where = f"{migration.label} line {number}"
            relation = match.group(2)
            kind = " ".join(match.group(1).split()).upper()
            if match.re is _DROP:
                if match.group(3):
                    raise DeclarationError(
                        f"{where}: {relation} is dropped with CASCADE, which "
                        f"takes objects this file does not name. Drop the "
                        f"dependents first, by name, so the file says what it "
                        f"destroys."
                    )
                if relation not in found:
                    raise DeclarationError(
                        f"{where}: {relation} is dropped, and nothing has "
                        f"created it"
                    )
                still_reading = sorted(
                    name for name, declaration in found.items()
                    if name != relation and relation in declaration.reads
                )
                if still_reading:
                    raise DeclarationError(
                        f"{where}: {relation} is dropped while "
                        f"{', '.join(still_reading)} still reads it. The engine "
                        f"refuses that drop; drop the readers first."
                    )
                retiring = found.pop(relation)
                retired.append(
                    replace(retiring, superseded_in=migration.label)
                )
                continue
            if relation in found:
                raise DeclarationError(
                    f"{where}: {relation} is created twice; "
                    f"{found[relation].migration} created it already and "
                    f"nothing has dropped it"
                )
            found[relation] = _declaration(
                relation=relation,
                kind=kind,
                block=_block_above(lines, number),
                migration=migration.label,
                line=number,
            )
    # Both directions, once, over what the walk actually saw. A definition that
    # was taken out of service and does not say so leaves a `CREATE` in the tree
    # that the engine does not hold; a definition that says so and was not is a
    # reader sent to look for something that is still right there.
    for declaration in retired:
        if declaration.superseded_by is None:
            raise DeclarationError(
                f"{declaration.migration} line {declaration.line}: "
                f"{declaration.relation} is dropped by "
                f"{declaration.superseded_in}, so this definition is one the "
                f"engine no longer holds and nothing here says so. Add "
                f"`-- {SUPERSEDED_BY}: {declaration.superseded_in}` to its "
                f"declaration block. That is an edit to an applied migration -- "
                f"see docs/runbook.md, \"Editing a migration that has already "
                f"been applied\"."
            )
        if declaration.superseded_by != declaration.superseded_in:
            raise DeclarationError(
                f"{declaration.migration} line {declaration.line}: "
                f"{declaration.relation} says it is superseded by "
                f"{declaration.superseded_by!r} and it is "
                f"{declaration.superseded_in!r} that drops it"
            )
    for declaration in found.values():
        if declaration.superseded_by is not None:
            raise DeclarationError(
                f"{declaration.migration} line {declaration.line}: "
                f"{declaration.relation} declares itself superseded by "
                f"{declaration.superseded_by!r}, and it is what the engine "
                f"holds -- nothing drops it"
            )
    return found, retired


def _statements(sql: str) -> list[re.Match[str]]:
    """Every `CREATE` and `DROP` in one migration, in the order it runs.

    Two patterns over one string, merged by position, because the order the
    statements appear in is the order the engine applies them and a drop that
    was checked out of order would be checked against a schema that never
    existed.
    """
    return sorted(
        [*_CREATE.finditer(sql), *_DROP.finditer(sql)], key=lambda m: m.start()
    )


def _block_above(lines: Sequence[str], number: int) -> list[str]:
    """The unbroken run of comment lines immediately above line `number`."""
    start = number - 1
    while start > 0 and lines[start - 1].startswith("--"):
        start -= 1
    return list(lines[start : number - 1])


def _fields(block: Sequence[str]) -> dict[str, str]:
    """The declared fields of one comment block, continuation lines joined.

    A field runs until a line that is not indented under it, so the prose the
    rest of the block carries is not read as part of the last field.
    """
    found: dict[str, list[str]] = {}
    current: list[str] | None = None
    for line in block:
        field = _DECLARED_FIELD.match(line)
        if field is not None:
            current = found.setdefault(field.group(1), [])
            current.append(field.group(2).strip())
            continue
        more = _CONTINUATION.match(line)
        if more is not None and current is not None:
            current.append(more.group(1).strip())
            continue
        current = None
    return {name: " ".join(parts) for name, parts in found.items()}


def _declaration(
    *, relation: str, kind: str, block: Sequence[str], migration: str, line: int
) -> Declaration:
    where = f"{migration} line {line}: {relation}"
    fields = _fields(block)
    missing = [name for name in DECLARED_FIELDS if name not in fields]
    if missing:
        raise DeclarationError(
            f"{where} has no {', '.join(missing)} in the comment block above "
            f"its CREATE. Every object declares `Layer:`, `Object:` (view or "
            f"materialized view), `Reads:` and `Read by:`."
        )

    layer = fields["Layer"].split()[0].rstrip(".").lower()
    if layer not in LAYERS:
        raise DeclarationError(
            f"{where} declares layer {layer!r}, which is not one of "
            f"{', '.join(LAYERS)}"
        )

    declared_kind = _kind(fields["Object"])
    if declared_kind is None:
        raise DeclarationError(
            f"{where} does not say whether it is a TABLE, a VIEW or a "
            f"MATERIALIZED VIEW: Object: {fields['Object']!r}"
        )
    if declared_kind != kind:
        raise DeclarationError(
            f"{where} declares itself a {declared_kind} and the CREATE makes it "
            f"a {kind}"
        )

    # Only the first sentence of `Reads:` is the list; a note may follow it.
    reads = re.split(r"\.\s", fields["Reads"].strip(), maxsplit=1)[0].strip()
    if reads.rstrip(".").lower() == "nothing":
        read = frozenset()
    elif _READS_LIST.match(reads):
        read = frozenset(_IDENTIFIER.findall(reads))
    else:
        raise DeclarationError(
            f"{where} does not declare what it reads as a list of relations: "
            f"Reads: {reads!r}. Write the names it selects from, comma "
            f"separated, or `nothing`."
        )
    if relation in read:
        raise DeclarationError(f"{where} declares that it reads itself")

    read_by = frozenset(_RELATION.findall(fields["Read by"])) - {relation}
    outside = frozenset(_REPOSITORY_FILE.findall(fields["Read by"])) | frozenset(
        f"src/helena/{module}.py" for module in _MODULE_SYMBOL.findall(fields["Read by"])
    )
    if declared_kind == "MATERIALIZED VIEW" and not (read_by or outside):
        raise DeclarationError(
            f"{where} is a MATERIALIZED VIEW and its `Read by:` names nobody. "
            f"Materialize where something is queried or joined from; a "
            f"materialized view nothing reads is disk paid for rows nobody "
            f"looks at (`concept/03-architecture.md`)."
        )
    return Declaration(
        relation=relation,
        kind=kind,
        layer=layer,
        reads=read,
        read_by=read_by,
        readers_outside_the_engine=outside,
        migration=migration,
        line=line,
        superseded_by=_superseding_migration(fields, where),
    )


def _superseding_migration(fields: Mapping[str, str], where: str) -> str | None:
    """The migration label in `Superseded by:`, or None if the field is absent.

    Only the first word is the label; a note may follow it, the way a note may
    follow the list in `Reads:`. A block that named the migration and stopped
    would be correct and unhelpful -- the useful sentence is the one saying that
    the definition below it is not what the engine holds.
    """
    if SUPERSEDED_BY not in fields:
        return None
    label = fields[SUPERSEDED_BY].split(maxsplit=1)[0].rstrip(".")
    if not FILENAME.match(label):
        raise DeclarationError(
            f"{where} declares `{SUPERSEDED_BY}: {label}`, which is not a "
            f"migration file name. Name the file that drops this object and "
            f"creates it again, as NNNN_name.sql."
        )
    return label


def _kind(declared: str) -> str | None:
    """What `Object:` opens with. Anchored, because the prose after it says
    "view" about other things and a substring search would read that."""
    match = _DECLARED_KIND.match(declared)
    if match is None:
        return None
    return " ".join(match.group(1).split()).upper()


def layering_violations(declared: Mapping[str, Declaration]) -> list[str]:
    """Every declared read that crosses a layer boundary it may not.

    The list is empty or the layering rule is broken. Kept a pure function over
    the declarations so that the `analytical` row of `MAY_READ` -- the one the
    invariant is actually about, and the one no object in this repository is in
    yet -- can be shown to fire.
    """
    broken = []
    for name, declaration in sorted(declared.items()):
        for target in sorted(declaration.reads):
            if target not in declared:
                broken.append(
                    f"{name} ({declaration.layer}) reads {target}, which no "
                    f"migration creates"
                )
                continue
            into = declared[target].layer
            if into not in MAY_READ[declaration.layer]:
                broken.append(
                    f"{name} ({declaration.layer}) reads {target} ({into}); the "
                    f"{declaration.layer} layer may read "
                    f"{', '.join(sorted(MAY_READ[declaration.layer])) or 'nothing'}"
                )
    return broken


def reads_the_engine_records(declared: Mapping[str, Declaration]) -> dict[str, set[str]]:
    """The declared reads expanded the way the engine expands them.

    A plain view is inlined into the plan of whatever reads it, so RisingWave
    records the reader as depending on what the view reads as well as on the
    view; a materialized view and a table are where that expansion stops. This
    is what `rw_catalog.rw_depend` holds, and computing it from the declarations
    is how the declarations are checked against the engine rather than believed.
    """

    def expand(name: str, seen: frozenset[str]) -> set[str]:
        found: set[str] = set()
        for target in declared[name].reads:
            found.add(target)
            if target in declared and declared[target].kind == "VIEW":
                if target in seen:
                    raise DeclarationError(
                        f"{target} is reached from itself through plain views"
                    )
                found |= expand(target, seen | {target})
        return found

    return {name: expand(name, frozenset({name})) for name in declared}
