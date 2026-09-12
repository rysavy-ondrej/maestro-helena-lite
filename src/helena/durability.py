"""Durability — what the durable record is, and how the one store is copied out.

`concept/08-open-questions.md` files this under *cross-cutting and urgent*:
*"Durability and backup for the single store, now that findings and evidence
exist only there, which is a correctness concern rather than an ops detail."*
That sentence is the whole reason this module is not a shell script.

## The durable record is two things, and neither of them is the broker

    retained captures on disk   +   the engine's durable tables

**The retained captures** are the input as it arrived. `concept/02` calls a
capture *"a retained file of flow records, identified by the hash of the file.
The captures are the project's durable record"*, and `helena.normalizer` is
where one is described and read. What a replay reconstructs from them is
everything that is *derived from the input*: the normalized events, the
quarantine rows, and — because the views above them backfill from the table —
the flatten and signal layers.

**The engine's durable tables** are everything the pipeline *learned*, and
nothing outside the engine holds any of it: the feed snapshots an assessment
cited, the enrichment evidence, the analyst's cached provider responses, and the
assessments themselves with their citation, gap, pattern, retrieval and
disclosure rows. A capture replay does not reconstruct one row of that. Re-asking
the model produces a different run, and re-fetching a feed produces a *different
snapshot* — `concept/08` again: *"a later snapshot changes what an identical
context would say"*. So the tables are not a cache of something re-derivable;
they are the record, and copying them out is the only thing that makes them
survivable.

**What is excluded, and why it is excluded rather than merely unimplemented:**

| Not backed up | Because |
| --- | --- |
| The broker | `concept/07`: *"the broker retains nothing you can rely on"* — consume-once, restart-volatile, a topic never re-readable. There is nothing to copy |
| The output topic | `concept/03`: egress only, *"nothing may be recoverable only from it"*. Backing it up would be backing up a projection of rows that are already in the backup |
| Materialized views | Derived. A restore applies the migrations and the views rebuild from the tables — measured, see `RESTORE_REBUILDS` below |
| In-flight framework state | `concept/03`: *"an interrupted run is simply re-run"*. There is no checkpoint to lose |

## Why a backup file is not a second store

`concept/instruction.md` §2 forbids a second store, and this module does not add
one. Nothing in the package reads a backup: no stage consults it, no lookup falls
back to it, and nothing is recoverable *only* from it. It is a copy of the one
store, taken by an operator command, and the code here never touches a path — it
turns a connection into lines of text and lines of text back into rows.
`scripts/backup.py` is what owns the file, which is also what keeps
`tests/test_architecture_boundary.py`'s *"the package writes to no file and starts
no process"* true.

## The format, and the two things it refuses

A backup is JSON lines: a **header**, then one line per row, then a **trailer**.

- The header carries the migration ledger, the relations, and **each relation's
  columns with their types** — so a restore into a schema that is not the schema
  the backup came from is refused by comparison rather than discovered by an
  INSERT that happens to fit.
- The trailer carries the row count and the sha256 of every preceding line. A
  backup whose trailer is missing or does not verify is `BackupIncomplete`:
  `concept/instruction.md` §2, *"truncation is visible or it is a bug"*. This is
  what a half-written file looks like, and it is the reason the digest is at the
  end where a streaming writer can put it.

Two failures are worth telling apart from each other and from a bad file:

- **`BackupMoved`** — a relation held more or fewer rows when it was read than
  its declared count. RisingWave has no multi-statement read transaction, so a
  backup taken while records are flowing is *not* a point-in-time snapshot. The
  counts are re-checked per relation so that the hazard is detected rather than
  documented; take a backup with ingestion quiesced.
- **`RestoreRefused`** — the target's migration ledger, relation set or column
  types differ, or a target relation already holds rows. A restore into a
  non-empty table would *upsert* (every table has a primary key), leaving a store
  that is neither the backup nor what was there before.

## Restore reads the whole backup before it writes a row

Deliberate, and it costs memory. RisingWave has no transaction around a
multi-statement write, so there is no way to roll a half-applied restore back; the
only cheap guarantee available is to refuse the file *before* the first INSERT.
`docs/runbook.md` §15 records the ceiling that places on a backup's size.

Maturity: experimental — the backup, the restore, the four refusals and the
capture-store check are exercised by execution in `tests/test_durability.py`
against a real engine, including a full pipeline state backed up out of one
migrated schema and restored into another, and a replay over the broker onto the
restored schema. What has not been exercised is a restore into a *different
engine process* (one engine per machine: `docs/runbook.md` §2), a backup of a
store larger than a fixture, and a restore across a RisingWave version change.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from pathlib import Path
from typing import Any, Literal

import psycopg
from psycopg.types.json import Jsonb
from pydantic import BaseModel, ConfigDict, NonNegativeInt

from helena import migrations
from helena.normalizer import Capture, CaptureStoreUnreachable, scan_captures

__all__ = [
    "BACKUP_FORMAT_VERSION",
    "BackupHeader",
    "BackupIncomplete",
    "BackupMoved",
    "BackupTrailer",
    "CaptureStoreCheck",
    # Re-exported from `helena.normalizer`, where the capture store is, so that
    # `check_capture_store`'s caller has one import for the check and the two
    # errors it raises.
    "CaptureStoreUnreachable",
    "DurabilityError",
    "RelationSchema",
    "RestoreRefused",
    "RestoreResult",
    "back_up",
    "check_capture_store",
    "durable_relations",
    "read_header",
    "restore",
    "verify",
]

# The shape of the file. A change to the field set, to what a line means, or to
# how a value is encoded is a format change and bumps this — a reader that
# guessed at an older shape would restore a store nobody took a backup of.
BACKUP_FORMAT_VERSION = "v1"

# What a restore rebuilds without being told to: every materialized view in the
# schema. `docs/runbook.md` §8 measured it for one view and this module's tests
# measure it for the whole schema — a materialized view created over a table
# backfills from the table, so applying the migrations to the target and
# inserting the tables' rows is the whole of a restore.
RESTORE_REBUILDS = "materialized views, from the tables the migrations create"

# The column types this format encodes, and how. A type that is not here is a
# refusal at backup time rather than a value written in whatever repr() gave:
# `helena_analytical_run_metrics` and friends hold `interval` and array columns,
# and the day a migration puts one on a *table* the backup must say so rather
# than round-trip it wrongly.
#
# The mapping is by `information_schema.columns.data_type`, which is what the
# engine itself calls the type — not by what the migration file wrote.
JSON_PASSTHROUGH = frozenset(
    {"character varying", "text", "bigint", "integer", "smallint", "boolean"}
)
TIMESTAMPTZ = "timestamp with time zone"
BYTEA = "bytea"
JSONB = "jsonb"
NUMERIC = "numeric"
DOUBLE = "double precision"
ENCODED_TYPES = JSON_PASSTHROUGH | {TIMESTAMPTZ, BYTEA, JSONB, NUMERIC, DOUBLE}

# Rows per INSERT on the restore path, and the number is
# `helena.enrichment.INSERT_CHUNK_ROWS`'s for the same measured reason — 500-row
# multi-row INSERTs beat one statement per row by 13x against this engine. It is
# not imported from there because that constant is a property of the feed loader
# it was measured for; this is a second use of the same measurement, and the two
# are asserted equal by `tests/test_durability.py` so they cannot drift into two
# different answers to one question.
INSERT_CHUNK_ROWS = 500


class DurabilityError(Exception):
    """The durable record is not in the state a backup or a restore needs.

    Three subclasses, never collapsed, because the operator does a different
    thing about each: a file that is not whole, a store that moved while it was
    read, and a target that cannot receive this backup. The fourth thing that
    can be wrong is the *other* half of the durable record, and it is
    `helena.normalizer.CaptureStoreUnreachable` — an error about the capture
    store belongs where the capture store is, so that every caller of
    `scan_captures` gets it and not only this module.
    """


class BackupIncomplete(DurabilityError):
    """The file is not a whole backup: no trailer, or the digest does not verify.

    This is what a truncated write, a partial copy or an edited backup looks
    like. It is refused before a single row is restored.
    """


class BackupMoved(DurabilityError):
    """A relation's row count changed between being counted and being read.

    The engine has no multi-statement read transaction, so a backup taken under
    live ingestion is not a point-in-time snapshot. Quiesce and retake it.
    """


class RestoreRefused(DurabilityError):
    """The target cannot receive this backup, and nothing was written.

    The ledger, the relation set or the column types differ, or a relation
    already holds rows. Named rather than reconciled: a restore that adapted
    would produce a store that agrees with neither side.
    """


class RelationSchema(BaseModel):
    """One relation of the backup: its columns, their types, and its row count.

    The columns are in `ordinal_position` order and the order is part of the
    comparison — two schemas whose columns are the same set in a different order
    are not the same schema, and a positional INSERT into them means two
    different things.
    """

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    name: str
    columns: tuple[tuple[str, str], ...]
    rows: NonNegativeInt


class LedgerEntry(BaseModel):
    """One migration as the source's ledger recorded it.

    `applied_at` and `error` are deliberately absent. A restore compares this
    against the target's ledger, and the target applied the same files at a
    different time — comparing the timestamp would refuse every restore there
    is. `status` is compared, so a source or a target with a `failed` migration
    row is visible instead of being averaged away.
    """

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    version: int
    name: str
    checksum: str
    status: str


class BackupHeader(BaseModel):
    """The first line: what this backup is of, and what schema it came out of."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    kind: Literal["header"] = "header"
    format_version: Literal["v1"] = BACKUP_FORMAT_VERSION
    taken_at: datetime
    engine_version: str
    schema_name: str
    ledger: tuple[LedgerEntry, ...]
    relations: tuple[RelationSchema, ...]

    @property
    def rows(self) -> int:
        return sum(relation.rows for relation in self.relations)


class BackupTrailer(BaseModel):
    """The last line: the row count, and the digest of every line before it.

    At the end because that is where a streaming writer can put it, and the
    consequence is the property that matters: a file without a verifying trailer
    is not a backup, so a truncated one cannot be mistaken for a small one.
    """

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    kind: Literal["trailer"] = "trailer"
    rows: NonNegativeInt
    body_sha256: str


@dataclass(frozen=True)
class RestoreResult:
    """What a restore put back, per relation, and what rebuilt itself.

    `rows` is counted from the INSERTs and `materialized` is read back out of
    the target afterwards, so the two can disagree — and if they do, that is the
    finding. `concept/instruction.md` §7: produced-versus-materialised counts
    reconcile.
    """

    schema_name: str
    rows: dict[str, int]
    materialized: dict[str, int]

    @property
    def total(self) -> int:
        return sum(self.rows.values())

    @property
    def reconciles(self) -> bool:
        return self.rows == self.materialized


@dataclass(frozen=True)
class CaptureStoreCheck:
    """The startup answer about the capture store: reachable, and verified.

    Returned only when the directory *is* a readable directory and every capture
    in it hashed to its own name — anything else raised. `captures` of zero is
    therefore "reachable and holding nothing", which is a real state and is not
    the same fact as "unreachable".
    """

    directory: Path
    captures: tuple[Capture, ...]

    @property
    def records(self) -> int:
        return sum(capture.record_count for capture in self.captures)

    @property
    def byte_size(self) -> int:
        return sum(capture.byte_size for capture in self.captures)

    def summary(self) -> str:
        return (
            f"{self.directory}: {len(self.captures)} capture(s), "
            f"{self.records} record(s), {self.byte_size:,} bytes, "
            f"every file verified against its own sha256"
        )


def check_capture_store(directory: Path) -> CaptureStoreCheck:
    """The startup check: the capture store is reachable and its hashes verify.

    Three outcomes and they stay three: `CaptureStoreUnreachable` for a path that
    is not a readable directory, `helena.normalizer.CaptureError` for a file that
    is not named by its own digest or does not hash to it, and a
    `CaptureStoreCheck` — possibly of zero captures — for a store that is there
    and whole.

    The hash check is not an extra: a capture's sha256 is half of every event id
    and every raw-record reference in the store, so a capture that changed under
    its name makes every citation that points into it a citation to something
    else. `scan_captures` is what verifies it, and this is the caller that makes
    it a startup condition rather than something a replay finds out.
    """
    return CaptureStoreCheck(
        directory=directory, captures=tuple(scan_captures(directory).values())
    )


def durable_relations(connection: psycopg.Connection) -> list[RelationSchema]:
    """Every base table in the current schema except the ledger, with its columns.

    Read from the catalogue and not from a list here, for the reason
    `tests/conftest.py` reads it from the catalogue too: a migration that adds a
    table has to be in the backup without anyone remembering to add it. A list
    in this file would be a second, quieter definition of "durable", and the
    failure mode is a table that is silently not backed up.

    The ledger is excluded because it is not data — it is the schema's identity,
    it travels in the header, and a restore *compares* it rather than writing it.
    Inserting migration rows into a target that had just applied the same files
    would be telling the runner about work it had already done.
    """
    tables = [
        name
        for (name,) in connection.execute(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema = current_schema() AND table_type = 'BASE TABLE' "
            "ORDER BY table_name"
        ).fetchall()
        if name != migrations.LEDGER_TABLE
    ]
    columns: dict[str, list[tuple[str, str]]] = {name: [] for name in tables}
    for name, column, data_type in connection.execute(
        "SELECT table_name, column_name, data_type FROM information_schema.columns "
        "WHERE table_schema = current_schema() ORDER BY table_name, ordinal_position"
    ).fetchall():
        if name in columns:
            columns[name].append((column, data_type))
    relations = []
    for name in tables:
        if not columns[name]:
            raise DurabilityError(
                f"{name} is a base table the catalogue gives no columns for; "
                f"a backup cannot name what it would copy"
            )
        for column, data_type in columns[name]:
            if data_type not in ENCODED_TYPES:
                raise DurabilityError(
                    f"{name}.{column} is {data_type}, which backup format "
                    f"{BACKUP_FORMAT_VERSION} does not encode. Extend the format "
                    f"and bump it; a value written in whatever repr() produced "
                    f"would restore as something else"
                )
        relations.append(
            RelationSchema(
                name=name,
                columns=tuple(columns[name]),
                rows=_count(connection, name),
            )
        )
    return relations


def back_up(connection: psycopg.Connection, *, taken_at: datetime) -> Iterator[str]:
    """The current schema as backup lines: header, one row per line, trailer.

    Yields line by line, so a writer never holds the whole backup as one string.
    It is NOT streaming end to end and the difference is worth stating: `_read`
    iterates a client-side psycopg cursor, which materializes a relation's whole
    result set on `execute()`, so peak memory is the largest single relation
    rather than the whole store. Making it the largest single ROW means a
    server-side cursor (`connection.cursor(name=…)`), which is a change to
    measure rather than to assume — the largest relation here is a 3 375-claim
    snapshot and fits comfortably.

    Each relation's declared count is taken before its rows are read and checked
    against what was read, which is how a store that moved under the reader
    becomes `BackupMoved` instead of a backup that is quietly short.
    """
    relations = durable_relations(connection)
    header = BackupHeader(
        taken_at=taken_at,
        engine_version=_engine_version(connection),
        schema_name=_schema_name(connection),
        ledger=tuple(
            LedgerEntry(
                version=row.version,
                name=row.name,
                checksum=row.checksum,
                status=row.status,
            )
            for row in migrations.recorded(connection).values()
        ),
        relations=tuple(relations),
    )
    digest = hashlib.sha256()
    written = 0

    def line(payload: str) -> str:
        digest.update(payload.encode("utf-8"))
        digest.update(b"\n")
        return payload

    yield line(header.model_dump_json())
    for relation in relations:
        read = 0
        for row in _read(connection, relation):
            read += 1
            written += 1
            yield line(json.dumps(row, allow_nan=False, separators=(",", ":")))
        if read != relation.rows:
            raise BackupMoved(
                f"{relation.name} declared {relation.rows} row(s) and read "
                f"{read}; the store changed while it was being copied, so this "
                f"backup would not be a consistent point. Quiesce ingestion and "
                f"take it again"
            )
    yield BackupTrailer(rows=written, body_sha256=digest.hexdigest()).model_dump_json()


def read_header(lines: Sequence[str]) -> BackupHeader:
    """The header alone, without verifying the body. For `--list`-style reads.

    Anything that is going to *write* rows uses `verify` instead, which is what
    checks the file is whole.
    """
    if not lines:
        raise BackupIncomplete("the backup is empty; it has no header line")
    return BackupHeader.model_validate_json(lines[0])


def verify(lines: Sequence[str]) -> BackupHeader:
    """Check the file is whole, and return its header.

    Four ways it is not whole, and each names itself: no lines, a first line that
    is not a header, a last line that is not a trailer, and a digest or a row
    count the trailer disagrees with.
    """
    header = read_header(lines)
    if len(lines) < 2:
        raise BackupIncomplete(
            "the backup has a header and no trailer, so it was not finished "
            "being written"
        )
    try:
        trailer = BackupTrailer.model_validate_json(lines[-1])
    except ValueError as error:
        raise BackupIncomplete(
            f"the last line of the backup is not a trailer, so the file is "
            f"truncated: {error}"
        ) from None
    body = "".join(f"{line}\n" for line in lines[:-1])
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    if digest != trailer.body_sha256:
        raise BackupIncomplete(
            f"the backup's body hashes to {digest} and its trailer records "
            f"{trailer.body_sha256}; the file has been truncated or edited"
        )
    rows = len(lines) - 2
    if rows != trailer.rows or rows != header.rows:
        raise BackupIncomplete(
            f"the backup holds {rows} row line(s), its trailer records "
            f"{trailer.rows} and its header declares {header.rows}"
        )
    return header


def restore(
    connection: psycopg.Connection, lines: Sequence[str]
) -> RestoreResult:
    """Put a verified backup's rows back into the current schema.

    The order is the whole design: verify the file, compare the target against
    the header, check every target relation is empty, and only then INSERT. The
    engine has no transaction around a multi-statement write, so a refusal after
    the first INSERT would leave a half-restored store — every refusal here
    fires before one.

    The materialized views are not restored and must not be: they rebuild from
    the tables the migrations created (`RESTORE_REBUILDS`). What comes back is
    read out of the target afterwards and reconciled against what was inserted.
    """
    header = verify(lines)
    target = {relation.name: relation for relation in durable_relations(connection)}
    _require_same_schema(connection, header, target)
    for name, relation in target.items():
        if relation.rows:
            raise RestoreRefused(
                f"{name} already holds {relation.rows} row(s) in "
                f"{_schema_name(connection)}. Every table has a primary key, so "
                f"inserting would upsert and leave a store that is neither this "
                f"backup nor what is there now; empty the schema or migrate a "
                f"new one"
            )
    inserted: dict[str, int] = {relation.name: 0 for relation in header.relations}
    grouped: dict[str, list[dict[str, Any]]] = {name: [] for name in inserted}
    for payload in lines[1:-1]:
        row = json.loads(payload)
        name = row["relation"]
        if name not in grouped:
            raise RestoreRefused(
                f"the backup holds a row for {name}, which its own header does "
                f"not declare"
            )
        grouped[name].append(row["values"])
    for relation in header.relations:
        rows = grouped[relation.name]
        if len(rows) != relation.rows:
            raise BackupIncomplete(
                f"the backup declares {relation.rows} row(s) of "
                f"{relation.name} and holds {len(rows)}"
            )
    for relation in header.relations:
        inserted[relation.name] = _insert(
            connection, relation, grouped[relation.name]
        )
    connection.execute("FLUSH")
    return RestoreResult(
        schema_name=_schema_name(connection),
        rows={name: count for name, count in inserted.items() if count},
        materialized={
            relation.name: _count(connection, relation.name)
            for relation in header.relations
            if _count(connection, relation.name)
        },
    )


def _require_same_schema(
    connection: psycopg.Connection,
    header: BackupHeader,
    target: dict[str, RelationSchema],
) -> None:
    """Refuse unless the target is the schema this backup came out of.

    Two checks that catch two different things: the ledger differs when the
    target was migrated from different files, and the columns differ when
    something reshaped a relation without a migration. Neither is reconciled —
    `concept/instruction.md` §2 forbids migrating stored rows forward, and
    adapting a row to a column set it was not written against is exactly that.
    """
    ledger = tuple(
        LedgerEntry(
            version=row.version, name=row.name, checksum=row.checksum, status=row.status
        )
        for row in migrations.recorded(connection).values()
    )
    if ledger != header.ledger:
        raise RestoreRefused(
            f"the target's migration ledger is not the backup's: the backup was "
            f"taken at {_labels(header.ledger)} and this schema holds "
            f"{_labels(ledger)}. Apply the same migrations before restoring; a "
            f"row is never migrated forward"
        )
    missing = {relation.name for relation in header.relations} - set(target)
    extra = set(target) - {relation.name for relation in header.relations}
    if missing or extra:
        raise RestoreRefused(
            f"the target's relations are not the backup's: missing "
            f"{sorted(missing)}, unexpected {sorted(extra)}"
        )
    for relation in header.relations:
        if target[relation.name].columns != relation.columns:
            raise RestoreRefused(
                f"{relation.name} has different columns in the target: the "
                f"backup carries {relation.columns} and the target has "
                f"{target[relation.name].columns}"
            )


def _labels(ledger: tuple[LedgerEntry, ...]) -> str:
    if not ledger:
        return "no migrations at all"
    return (
        f"{len(ledger)} migration(s) through "
        f"{ledger[-1].version:04d}_{ledger[-1].name}"
    )


def _read(
    connection: psycopg.Connection, relation: RelationSchema
) -> Iterator[dict[str, Any]]:
    """One relation's rows, encoded, as `{"relation": …, "values": {…}}`.

    Named columns rather than `SELECT *`, so the row's field names are the
    header's and a column added to the target later cannot shift a value into
    the wrong place.
    """
    names = [column for column, _ in relation.columns]
    types = dict(relation.columns)
    with connection.cursor() as cursor:
        cursor.execute(
            f"SELECT {', '.join(names)} FROM {relation.name}"  # noqa: S608 — catalogue names
        )
        for row in cursor:
            yield {
                "relation": relation.name,
                "values": {
                    name: _encode(value, types[name], relation.name, name)
                    for name, value in zip(names, row, strict=True)
                },
            }


def _encode(value: Any, data_type: str, relation: str, column: str) -> Any:
    """One value as JSON, by the column's type rather than by the value's class.

    By the type on purpose: a `jsonb` column holding the string `"x"` and a
    `varchar` holding `"x"` arrive as the same Python object and have to be
    restored differently, so the decision cannot be made from the value.
    """
    if value is None:
        return None
    if data_type == TIMESTAMPTZ:
        if not isinstance(value, datetime) or value.tzinfo is None:
            raise DurabilityError(
                f"{relation}.{column} is {TIMESTAMPTZ} and the engine returned "
                f"{value!r}, which carries no time zone"
            )
        return value.isoformat()
    if data_type == BYTEA:
        return bytes(value).hex()
    if data_type == NUMERIC:
        return str(value)
    return value


def _insert(
    connection: psycopg.Connection, relation: RelationSchema, rows: list[dict[str, Any]]
) -> int:
    """Insert one relation's rows in chunks, and return how many were inserted.

    Every column is named and every row supplies every column, so a row whose
    key set is not the relation's is a refusal rather than a NULL nobody asked
    for.
    """
    names = [column for column, _ in relation.columns]
    types = dict(relation.columns)
    placeholders = f"({', '.join(['%s'] * len(names))})"
    inserted = 0
    for start in range(0, len(rows), INSERT_CHUNK_ROWS):
        chunk = rows[start : start + INSERT_CHUNK_ROWS]
        parameters: list[Any] = []
        for row in chunk:
            if set(row) != set(names):
                raise RestoreRefused(
                    f"a {relation.name} row in the backup carries columns "
                    f"{sorted(row)} and the relation has {sorted(names)}"
                )
            parameters.extend(
                _decode(row[name], types[name], relation.name, name) for name in names
            )
        connection.execute(
            f"INSERT INTO {relation.name} ({', '.join(names)}) VALUES "  # noqa: S608
            f"{', '.join([placeholders] * len(chunk))}",
            parameters,
        )
        inserted += len(chunk)
    return inserted


def _decode(value: Any, data_type: str, relation: str, column: str) -> Any:
    """One encoded value back into what the column takes."""
    if value is None:
        return None
    if data_type == TIMESTAMPTZ:
        return datetime.fromisoformat(value)
    if data_type == BYTEA:
        return bytes.fromhex(value)
    if data_type == NUMERIC:
        return Decimal(value)
    if data_type == JSONB:
        return Jsonb(value)
    if data_type not in ENCODED_TYPES:
        raise RestoreRefused(
            f"{relation}.{column} is {data_type}, which backup format "
            f"{BACKUP_FORMAT_VERSION} does not encode"
        )
    return value


def _count(connection: psycopg.Connection, relation: str) -> int:
    (count,) = connection.execute(
        f"SELECT count(*) FROM {relation}"  # noqa: S608 — a catalogue name
    ).fetchone()
    return int(count)


def _schema_name(connection: psycopg.Connection) -> str:
    (name,) = connection.execute("SELECT current_schema()").fetchone()
    return str(name)


def _engine_version(connection: psycopg.Connection) -> str:
    """What the engine says it is, recorded so a restore elsewhere can be read.

    Not compared by `restore`: a logical backup is the form that can cross an
    engine version, and refusing one would remove the only reason to prefer it
    over copying the store directory. It is recorded so that a restore into a
    different version is a known fact afterwards rather than a guess.
    """
    (version,) = connection.execute("SELECT version()").fetchone()
    return str(version)
