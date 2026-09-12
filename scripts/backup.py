#!/usr/bin/env python3
"""Copy the engine's durable tables out, check a copy, or put one back.

The engine holds the half of the durable record that nothing else holds — the
feed snapshots an assessment cited, the enrichment evidence, the cached provider
responses and the assessments with their citation rows. A capture replay
reconstructs the input side and not one row of that, so this command is the only
thing that makes it survivable. `helena.durability` is the model and the reason
for each refusal; `docs/runbook.md` §15 is the procedure, the residual risk and
the measured recovery time.

    uv run scripts/backup.py --out .backups                 # take one
    uv run scripts/backup.py --verify .backups/<file>       # is it whole?
    uv run scripts/backup.py --restore .backups/<file>      # put it back
    uv run scripts/backup.py --restore <file> --schema helena_restore_test

The other half of the durable record — the retained captures — is checked by
`uv run scripts/dev_check.py --captures DIR`, which is where the startup checks
live and which `scripts/dev-up` already runs.

`--schema` is how a restore is rehearsed on this machine: `single_node` binds
fixed meta and compute ports so a second engine cannot run beside the first
(`docs/runbook.md` §2), and a migrated schema of its own is the throwaway
instance that is actually available. It applies to `--restore` and `--verify`
does not need it.

This file is where the bytes live, deliberately. `helena.durability` turns a
connection into lines and lines back into rows and touches no path, which is
what keeps `tests/test_architecture_boundary.py`'s "the package writes to no
file and starts no process" true — a backup is a copy of the one store, not a
second one.

Maturity: experimental — the round trip it drives is exercised against a real
engine by `tests/test_durability.py`, including a full pipeline state restored
into a second schema. This entry point's own argument handling is exercised by
that module too; what has not been exercised is a restore into a different
engine process or across an engine version.
"""

from __future__ import annotations

import argparse
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import psycopg

from helena import durability
from helena.config import Settings

# A schema name this command will put in a statement. Operator-supplied and
# therefore checked rather than trusted: `SET search_path` takes an identifier,
# not a parameter, so the only safe form is one this pattern accepts.
SCHEMA_NAME = re.compile(r"^[a-z_][a-z0-9_]*$")

# `helena-backup-<utc>.jsonl`. The timestamp is in the name because the one
# question asked of a backup directory is which copy is the newest, and sorting
# by name answers it.
FILENAME = "helena-backup-%Y%m%dT%H%M%SZ.jsonl"


def connect(schema: str | None) -> psycopg.Connection:
    """A connection to the configured engine, on `schema` if one was named.

    Through `helena.config` rather than the environment, so this connects to
    exactly what the pipeline connects to and fails the same way when a variable
    is missing. Autocommit because RisingWave has no transaction around a
    multi-statement write — `helena.durability.restore` refuses before its first
    INSERT for that reason rather than rolling anything back.
    """
    dsn = Settings.load().infrastructure.risingwave_dsn
    connection = psycopg.connect(dsn, autocommit=True, connect_timeout=10)
    if schema is not None:
        if not SCHEMA_NAME.match(schema):
            connection.close()
            raise SystemExit(f"FAILED: {schema!r} is not a schema name")
        connection.execute(f"SET search_path TO {schema}")
    return connection


def take(directory: Path, *, schema: str | None) -> list[str]:
    """Write one backup into `directory` and describe what it holds.

    Streamed line by line, so a backup of a store larger than memory can be
    written — which is not true of restoring one, and §15 of the runbook records
    that asymmetry as the ceiling it is.
    """
    directory.mkdir(parents=True, exist_ok=True)
    taken_at = datetime.now(timezone.utc)
    path = directory / taken_at.strftime(FILENAME)
    if path.exists():
        raise SystemExit(f"FAILED: {path} already exists")
    with connect(schema) as connection:
        written = 0
        with path.open("w", encoding="utf-8") as out:
            for line in durability.back_up(connection, taken_at=taken_at):
                out.write(f"{line}\n")
                written += 1
    header = durability.verify(path.read_text(encoding="utf-8").splitlines())
    return [
        f"wrote {path} ({path.stat().st_size:,} bytes, {written} line(s))",
        *describe(header),
    ]


def describe(header: durability.BackupHeader) -> list[str]:
    """One line per relation that holds something, then the totals."""
    lines = [
        f"  {relation.rows:>9,} row(s)  {relation.name}"
        for relation in sorted(
            header.relations, key=lambda relation: (-relation.rows, relation.name)
        )
        if relation.rows
    ]
    empty = sum(1 for relation in header.relations if not relation.rows)
    return [
        f"taken at {header.taken_at.isoformat()} from schema "
        f"{header.schema_name}, format {header.format_version}",
        *lines,
        f"  {header.rows:>9,} row(s)  in total, across "
        f"{len(header.relations) - empty} relation(s); {empty} empty",
        f"  migrations: {len(header.ledger)} recorded, through "
        f"{header.ledger[-1].version:04d}_{header.ledger[-1].name}"
        if header.ledger
        else "  migrations: none recorded — this schema was never migrated",
    ]


def put_back(path: Path, *, schema: str | None) -> list[str]:
    """Restore `path` into the configured engine, or refuse and change nothing."""
    lines = path.read_text(encoding="utf-8").splitlines()
    with connect(schema) as connection:
        result = durability.restore(connection, lines)
    reported = [
        f"restored {path} into schema {result.schema_name}: "
        f"{result.total:,} row(s) across {len(result.rows)} relation(s)"
    ]
    if not result.reconciles:
        raise SystemExit(
            f"FAILED: the restore inserted {result.rows} and the schema now "
            f"holds {result.materialized}; the two do not reconcile"
        )
    reported.append(
        f"the materialized views rebuilt themselves from the tables "
        f"({durability.RESTORE_REBUILDS})"
    )
    return reported


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument(
        "--out", type=Path, metavar="DIR", help="take a backup into DIR"
    )
    action.add_argument(
        "--verify", type=Path, metavar="FILE", help="check FILE is a whole backup"
    )
    action.add_argument(
        "--restore", type=Path, metavar="FILE", help="restore FILE into the engine"
    )
    parser.add_argument(
        "--schema",
        metavar="NAME",
        help="run against this schema rather than the connection's default",
    )
    arguments = parser.parse_args(argv)

    try:
        if arguments.out is not None:
            reported = take(arguments.out, schema=arguments.schema)
        elif arguments.verify is not None:
            reported = describe(
                durability.verify(
                    arguments.verify.read_text(encoding="utf-8").splitlines()
                )
            )
        else:
            reported = put_back(arguments.restore, schema=arguments.schema)
    except durability.DurabilityError as failure:
        print(f"FAILED: {failure}", file=sys.stderr)
        return 1
    except (psycopg.Error, OSError) as failure:
        print(f"FAILED: {failure}", file=sys.stderr)
        return 1
    for line in reported:
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
