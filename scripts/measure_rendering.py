#!/usr/bin/env python3
"""Measure what a real capture renders to: entity rows per host, and characters.

    uv run scripts/measure_rendering.py
    uv run scripts/measure_rendering.py --capture data/ingest/flow-sample.jsonl
    uv run scripts/measure_rendering.py --budget 4000

`concept/08-open-questions.md` leaves the numeric budget values open and
`prds/prd.json` task 29 says why this script exists: *"how many entity rows a
busy host produces is unmeasured — the fixture is one host for two minutes."*
So the number is read off a real capture put through the real ingest path rather
than argued from the shape of the data. `make rendering-size` runs it, and
`config/rendering.toml` cites what it produced.

**It shifts the capture's timestamps forward by a whole number of windows.**
Every record in this repository is dated 2024-06-01 and the retention boundary
(`sql/migrations/0009_retention_boundary.sql`) does not show a context that old,
so a rendering of the file as it stands is a rendering of nothing. Shifting by a
multiple of the window length keeps the capture's own window structure — the flow
sample crosses a boundary and produces two contexts, and collapsing them into one
would measure a host that does not exist.

It writes into a schema of its own on the configured engine and drops it again,
so it neither reads nor disturbs a deployment's data. Nothing is loaded from a
threat feed, so every lookup is `missing`: the sizes below are therefore a
**lower bound** on an enriched rendering — a claim adds to its entity's line.
Measured on the layer-coverage capture, one ThreatFox hit added 922 characters
across the whole rendering.

Exit status is 0 when every live context rendered, 1 when one refused.

Maturity: experimental — this is an instrument, not part of the pipeline. What it
reports comes from `helena.normalizer`, `helena.rendering` and the migrated
schema, so it measures the code the prototype runs rather than a copy of it.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from uuid import uuid4

import psycopg

from helena import hosts, migrations, rendering
from helena.config import ConfigurationError, Settings
from helena.context import ContextOutsideRetention
from helena.normalizer import CaptureError, EventStore, Normalizer, describe_capture
from helena.rendering import v1

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CAPTURE = PROJECT_ROOT / "data" / "ingest" / "flow-sample.jsonl"

#: The context window `sql/migrations/0006_host_context.sql` tumbles on, in
#: seconds. Shifting by a multiple of it is what preserves the capture's own
#: window boundaries.
WINDOW_SECONDS = 300


def _shifted(capture: Path, destination: Path) -> tuple[Path, float]:
    """The capture with every `ts` moved forward a whole number of windows."""
    records = [json.loads(line) for line in capture.read_bytes().splitlines()]
    if not records:
        raise CaptureError(f"{capture} holds no records")
    latest = max(record["ts"] for record in records)
    shift = (int(time.time() // WINDOW_SECONDS) - int(latest // WINDOW_SECONDS)) * (
        WINDOW_SECONDS
    )
    destination.write_bytes(
        b"".join(
            json.dumps({**record, "ts": record["ts"] + shift}).encode() + b"\n"
            for record in records
        )
    )
    return destination, shift


def _ingest(connection: psycopg.Connection, settings: Settings, capture: Path) -> None:
    normalizer = Normalizer.from_settings(settings)
    events = EventStore(connection=connection, identity=settings.identity)
    for result in normalizer.normalize_capture(describe_capture(capture)):
        events.record(result)
    connection.execute("FLUSH")


def _report(
    connection: psycopg.Connection, settings: Settings, budget: rendering.RenderingBudget
) -> int:
    store = rendering.RenderingStore(connection=connection, identity=settings.identity)
    configuration = hosts.load()
    contexts = connection.execute(
        "SELECT context_id, host, window_start FROM helena_signal_host_context_live "
        "ORDER BY host, window_start"
    ).fetchall()
    if not contexts:
        print("no live context: the capture produced nothing inside the retention boundary")
        return 1
    print(f"budget: {budget.characters} characters")
    failures = 0
    for context_id, host, window_start in contexts:
        try:
            projection = store.project(context_id)
        except ContextOutsideRetention as gone:
            print(f"{host} {window_start}: {gone}")
            failures += 1
            continue
        counted: dict[str, int] = {}
        for entity in projection.entities:
            counted[entity.entity_type] = counted.get(entity.entity_type, 0) + 1
        produced = v1.render(
            projection, configuration.attributes_for(projection.host), budget
        )
        sizes = {part.section: len(part.body) for part in produced.sections}
        print(f"\n{host}  window {window_start}  context {context_id}")
        print(
            f"  entity rows: {sum(counted.values())}  "
            + "  ".join(f"{kind}={count}" for kind, count in sorted(counted.items()))
            + f"  tls_tuples={len(projection.tls)}"
        )
        print(f"  rendering: {sum(sizes.values())} characters")
        for part in produced.sections:
            dropped = (
                f"  TRUNCATED kept {part.truncation.kept} of {part.truncation.total}"
                if part.truncation is not None
                else ""
            )
            print(
                f"    {part.section:<22} {sizes[part.section]:>6} chars  "
                f"{len(part.body.splitlines()):>4} lines  "
                f"{len(part.evidence_ids):>3} cited{dropped}"
            )
    return 1 if failures else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--capture",
        type=Path,
        default=DEFAULT_CAPTURE,
        help=f"the capture to measure (default: {DEFAULT_CAPTURE})",
    )
    parser.add_argument(
        "--budget",
        type=int,
        default=None,
        help="a character budget to measure at, instead of config/rendering.toml",
    )
    arguments = parser.parse_args(argv)

    try:
        settings = Settings.load()
        budget = (
            rendering.RenderingBudget(characters=arguments.budget)
            if arguments.budget is not None
            else rendering.budget()
        )
    except (ConfigurationError, rendering.RenderingError) as error:
        print(f"FAILED: {error}", file=sys.stderr)
        return 1

    schema = f"helena_measure_{uuid4().hex}"
    try:
        with psycopg.connect(
            settings.infrastructure.risingwave_dsn, autocommit=True, connect_timeout=5
        ) as connection:
            connection.execute(f"CREATE SCHEMA {schema}")
            try:
                connection.execute(f"SET search_path TO {schema}")
                migrations.apply(connection)
                shifted, shift = _shifted(
                    arguments.capture, Path(f"/tmp/{schema}.jsonl")  # noqa: S108
                )
                print(
                    f"{arguments.capture}: shifted forward "
                    f"{shift / WINDOW_SECONDS:.0f} windows to reach the retention "
                    f"boundary"
                )
                _ingest(connection, settings, shifted)
                return _report(connection, settings, budget)
            finally:
                connection.execute("SET search_path TO public")
                connection.execute(f"DROP SCHEMA {schema} CASCADE")
    except (CaptureError, hosts.HostAttributesError, rendering.RenderingError) as error:
        print(f"FAILED: {error}", file=sys.stderr)
        return 1
    except psycopg.Error as error:
        print(f"FAILED: the engine did not answer: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
