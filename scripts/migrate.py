#!/usr/bin/env python3
"""Apply the numbered migrations in sql/migrations/ to the configured engine.

    uv run scripts/migrate.py            apply everything pending, in order
    uv run scripts/migrate.py --status   say what is applied and what is not

The runner is `helena.migrations`; this is the way to run it by hand. The engine
address comes from `RISINGWAVE_DSN` through `helena.config`, so this migrates
exactly the engine the pipeline connects to.

**Migrate before data flows.** The broker is consume-once and restart-volatile,
so a record consumed before a view existed is gone and the view starts empty —
see docs/runbook.md.

Maturity: experimental — the runner underneath it is exercised by
tests/test_migrations.py against a real engine; this wrapper is not, beyond
being run by hand.
"""

from __future__ import annotations

import argparse
import sys

import psycopg

from helena import migrations
from helena.config import Settings


def _report(connection: psycopg.Connection) -> int:
    ledger = migrations.recorded(connection)
    for migration in migrations.discover():
        row = ledger.get(migration.version)
        if row is None:
            print(f"pending  {migration.label}")
        else:
            print(f"{row.status:<8} {migration.label}  {row.applied_at:%Y-%m-%d %H:%M}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--status",
        action="store_true",
        help="print what is applied and what is pending; apply nothing",
    )
    arguments = parser.parse_args(argv)

    dsn = Settings.load().infrastructure.risingwave_dsn
    try:
        with psycopg.connect(dsn, autocommit=True, connect_timeout=5) as connection:
            if arguments.status:
                return _report(connection)
            applied = migrations.apply(connection)
    except migrations.MigrationError as refused:
        print(f"FAILED: {refused}", file=sys.stderr)
        return 1
    except psycopg.Error as error:
        # The DSN is an address, not a credential, but it is still configuration
        # and it is not what went wrong — the engine is.
        print(f"FAILED: the engine did not answer: {error}", file=sys.stderr)
        return 1
    if not applied:
        print("nothing to apply; the engine is up to date")
    for migration in applied:
        print(f"applied  {migration.label}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
