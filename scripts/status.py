#!/usr/bin/env python3
"""What the pipeline's own numbers say, read out of the engine as plain SQL.

    uv run scripts/status.py
    uv run scripts/status.py --captures data/ingest

This is `helena status`. It prints, for the configured tenant and sensor:

  * the end-to-end reconciliation — capture records, normalized, quarantined,
    contexts, assessments and emittable messages;
  * what the retention boundary is dropping, as a rate with the horizon beside
    it, so a misconfigured horizon shows up as a number rather than as missing
    evidence nobody knows is missing;
  * each feed's snapshot age against its own schedule, with `missing`, `stale`
    and `ok` kept apart;
  * latency, cost, tokens, retry rate and cache state per model;
  * the typed failures by reason;
  * the escalation rate and which trigger caused it;
  * cache hit against live query per source, and the typed retrieval failures.

**Every number here is a `SELECT`, and none of it needs this command.** The views
are in `sql/migrations/0021_pipeline_observability.sql`, `0009` and `0020`, and
an operator with `psql` gets the same answers without running any of this
project's code. That is the property `concept/07-principles.md` chose over a
hosted tracer: *"the audit record is the stored assessment, not a trace UI ...
queryable in a way a trace UI is not"*. No tracing service is configured, no
metric is exported anywhere, and adding either is an egress decision under
`concept/instruction.md` §3 rather than a configuration detail.

`--captures DIR` is how many records **existed**. It is not in the engine and
cannot be: the broker is consume-once and restart-volatile, so the count lives in
the retained capture file and nowhere else. Without it the reconciliation says so
and refuses to compute `unaccounted`, rather than using 0 and reporting a
deployment that lost everything.

**Where a rate cannot honestly be computed, the reason is printed instead of a
number.** `0.0` over an empty denominator would read as good news — "the boundary
dropped nothing", "triage escalates nothing", "this model is free" — when the
truth is that nothing has run yet.

Exit status is 0 when the report was produced. It is not a health check and does
not decide what a bad number is; that is the operator's call, and
`docs/runbook.md` §13 is where the numbers are explained.

Maturity: experimental — `helena.status` underneath it is exercised by
tests/test_status.py against the pinned engine, over assessments written by the
real writer and a capture ingested through the real path. This wrapper is run by
hand.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

import psycopg

from helena import status
from helena.config import ConfigurationError, Settings
from helena.normalizer import CaptureError, scan_captures


def _arguments(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--captures",
        type=Path,
        default=None,
        metavar="DIR",
        help=(
            "the retained capture directory. How many records existed is a "
            "property of the file and of nothing else, so without this the "
            "reconciliation reports what it has and refuses to guess the rest"
        ),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    arguments = _arguments(argv)
    try:
        settings = Settings.load()
    except ConfigurationError as refused:
        print(f"FAILED: {refused}", file=sys.stderr)
        return 2

    captures = None
    if arguments.captures is not None:
        if not arguments.captures.is_dir():
            print(
                f"FAILED: {arguments.captures} is not a directory", file=sys.stderr
            )
            return 2
        try:
            captures = scan_captures(arguments.captures)
        except CaptureError as refused:
            print(f"FAILED: {refused}", file=sys.stderr)
            return 2

    try:
        with psycopg.connect(settings.infrastructure.risingwave_dsn) as connection:
            report = status.report(
                connection,
                settings.identity,
                read_at=datetime.now(timezone.utc),
                captures=captures,
            )
    except psycopg.Error as error:
        print(f"FAILED: the engine did not answer: {error}", file=sys.stderr)
        return 1

    print(status.render(report), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
