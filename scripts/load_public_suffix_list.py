#!/usr/bin/env python3
"""Fetch the Public Suffix List into the engine's reference table.

    uv run scripts/load_public_suffix_list.py            fetch and load
    uv run scripts/load_public_suffix_list.py --status   say what is loaded

The loader is `helena.enrichment.load_public_suffix_list`; this is the way to run
it on a schedule, which is what "its own schedule" means here — cron, a timer, a
hand-run before a demo. Nothing in this repository schedules anything, and a
scheduler with its own state would be a second store.

**The URL is here rather than in configuration, deliberately.**
`concept/05-threat-intelligence.md` opens with "adding a source is a governed
decision, not a configuration convenience", and a source URL in the environment
is exactly that convenience: it makes swapping the list for something else a
deployment detail rather than a decision. This is the one place it is written,
the loader takes it as an argument, and `helena.enrichment` holds no URL at all —
`tests/test_broker.py::test_no_module_in_the_package_holds_a_broker_address` is
what keeps it that way.

Every load, including a failed one, writes a row to
`helena_reference_public_suffix_load`. A failed fetch leaves the previous
snapshot in place; this script's exit status says what happened so a scheduler
can notice, and the row is what an operator reads afterwards.

Maturity: experimental — the loader underneath it is exercised by
tests/test_enrichment.py against a real engine and against the live list; this
wrapper is not, beyond being run by hand.
"""

from __future__ import annotations

import argparse
import sys

import psycopg

from helena.config import Settings
from helena.enrichment import (
    FAILED,
    PUBLIC_SUFFIX_LOAD_TABLE,
    PUBLIC_SUFFIX_TABLE,
    load_public_suffix_list,
)
from helena.observability import Redactor

# The published list. One `.dat` file, no credential, UTF-8, refreshed by the
# publisher several times a week.
PUBLIC_SUFFIX_LIST_URL = "https://publicsuffix.org/list/public_suffix_list.dat"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--status",
        action="store_true",
        help="report the loaded snapshot and the last attempts, load nothing",
    )
    parser.add_argument(
        "--url",
        default=PUBLIC_SUFFIX_LIST_URL,
        help="where to fetch the list from (default: the published list)",
    )
    arguments = parser.parse_args(argv)

    settings = Settings.load()
    redactor = Redactor.from_settings(settings)
    with psycopg.connect(
        settings.infrastructure.risingwave_dsn, autocommit=True
    ) as connection:
        if arguments.status:
            return _status(connection)
        load = load_public_suffix_list(
            connection,
            source_url=arguments.url,
            redactor=redactor,
        )

    print(
        f"{load.status}: {load.rule_count if load.rule_count is not None else '-'} "
        f"rules, snapshot {load.snapshot_version or '-'}"
    )
    if load.status == FAILED:
        print(f"  {load.failure_reason}: {load.failure_detail}", file=sys.stderr)
        return 1
    return 0


def _status(connection: psycopg.Connection) -> int:
    connection.execute("FLUSH")
    held = connection.execute(
        f"SELECT snapshot_version, count(*) FROM {PUBLIC_SUFFIX_TABLE} "
        f"GROUP BY snapshot_version"
    ).fetchall()
    if not held:
        print("no snapshot loaded")
    for version, count in held:
        print(f"snapshot {version}: {count} rules")

    attempts = connection.execute(
        f"SELECT attempted_at, status, failure_reason FROM {PUBLIC_SUFFIX_LOAD_TABLE} "
        f"ORDER BY attempted_at DESC LIMIT 5"
    ).fetchall()
    for attempted_at, status, failure_reason in attempts:
        print(f"{attempted_at.isoformat()}  {status}  {failure_reason or ''}".rstrip())
    return 0 if held else 1


if __name__ == "__main__":
    sys.exit(main())
