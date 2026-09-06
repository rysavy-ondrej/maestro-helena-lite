#!/usr/bin/env python3
"""Fetch the ThreatFox export into the engine's enrichment evidence table.

    uv run scripts/load_threatfox.py            fetch and load
    uv run scripts/load_threatfox.py --status   say what is loaded

The loader is `helena.enrichment.load_threatfox`; this is the way to run it on a
schedule, which is what `concept/05-threat-intelligence.md` means by "fetch each
static feed on its schedule". Nothing in this repository schedules anything, and
a scheduler with its own state would be a second store — cron, a timer, or a hand
run before a demo.

**The URL is here rather than in configuration, deliberately**, and the same
argument `scripts/load_public_suffix_list.py` makes:
`concept/05-threat-intelligence.md` opens with "adding a source is a governed
decision, not a configuration convenience", and a source URL in the environment
is exactly that convenience — it makes swapping the feed for something else a
deployment detail rather than a decision. This is the one place it is written,
the loader takes it as an argument, and `helena.enrichment` holds no URL at all.
`tests/test_broker.py::test_no_module_in_the_package_holds_a_broker_address` is
what keeps it that way.

**Which export, and why not the other two.** The structured JSON export carries
the port, the confidence, the threat type and the compromised flag. The RPZ and
hosts-file variants drop all four, which is to say they drop exactly the
distinctions the composition rule turns on: a C2 on one port matched against a
host that contacted another is a weaker claim, and neither of those formats can
express the difference.

**No credential.** Measured 2026-09-06, and re-measured rather than trusted:
`GET threatfox.abuse.ch/export/json/recent/` returns **200 with no credential at
all**, while the API at `threatfox-api.abuse.ch/api/v1/` returns **401** without
an `Auth-Key` header. Until 2026-09-03 the concept note said the bulk export
carried a key in the URL path; it was wrong and is corrected there. Do not build
this around a key it does not want. **Re-measure before trusting it** — abuse.ch
changes its auth on its own schedule, and a bulk export that is open today may
not be tomorrow. Probe with status codes; never by printing a key.

Every load, including a failed one, writes a row to
`helena_reference_threatfox_load`. A failed fetch leaves the previous snapshot in
place; this script's exit status says what happened so a scheduler can notice,
and the row is what an operator reads afterwards.

Maturity: experimental — the loader underneath it is exercised by
`tests/test_threatfox.py` against a real engine and a committed extract of a real
export; this wrapper is not, beyond being run by hand.
"""

from __future__ import annotations

import argparse
import sys

import psycopg

from helena.config import Settings
from helena.enrichment import (
    ENRICHMENT_EVIDENCE_TABLE,
    FAILED,
    THREATFOX_LOAD_TABLE,
    THREATFOX_MIN_FETCH_INTERVAL_SECONDS,
    THREATFOX_SOURCE,
    load_threatfox,
)
from helena.observability import Redactor

# The published structured export. One JSON file, no credential, a rolling
# recent window. See the module docstring for why it is here and not in
# configuration, and for which export this is.
THREATFOX_EXPORT_URL = "https://threatfox.abuse.ch/export/json/recent/"


def _status(connection: psycopg.Connection) -> int:
    """What is loaded, and what the last attempt did."""
    claims = connection.execute(
        f"SELECT snapshot_version, count(*) FROM {ENRICHMENT_EVIDENCE_TABLE} "
        f"WHERE source_id = %s GROUP BY snapshot_version",
        (THREATFOX_SOURCE,),
    ).fetchall()
    if not claims:
        print("no ThreatFox snapshot is loaded")
    for version, count in claims:
        print(f"snapshot {version}  {count} claim(s)")
    attempts = connection.execute(
        f"SELECT attempted_at, status, failure_reason, claims_stored, "
        f"skipped_no_entity, unseen_threat_types FROM {THREATFOX_LOAD_TABLE} "
        f"ORDER BY attempted_at DESC LIMIT 5"
    ).fetchall()
    if not attempts:
        print("no load has been attempted")
        return 0
    print("\nrecent attempts:")
    for attempted_at, status, reason, stored, skipped, unseen in attempts:
        detail = f" ({reason})" if reason else (
            f"  {stored} stored, {skipped} skipped, {unseen} unseen threat type(s)"
        )
        print(f"  {attempted_at:%Y-%m-%d %H:%M:%S}  {status}{detail}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--status", action="store_true", help="say what is loaded and stop"
    )
    parser.add_argument(
        "--url", default=THREATFOX_EXPORT_URL, help=argparse.SUPPRESS
    )
    arguments = parser.parse_args(argv)

    settings = Settings.load()
    redactor = Redactor.from_settings(settings)
    with psycopg.connect(
        settings.infrastructure.risingwave_dsn, autocommit=True
    ) as connection:
        if arguments.status:
            return _status(connection)
        load = load_threatfox(
            connection,
            tenant=settings.identity.tenant,
            sensor=settings.identity.sensor,
            source_url=arguments.url,
            redactor=redactor,
        )

    if load.status == FAILED:
        print(
            f"load failed: {load.failure_reason}: {load.failure_detail}\n"
            f"the previous snapshot is untouched.",
            file=sys.stderr,
        )
        return 1
    print(
        f"{load.status}: snapshot {load.snapshot_version}\n"
        f"  {load.entries_read} entries read\n"
        f"  {load.claims_stored} claims stored\n"
        f"  {load.skipped_no_entity} skipped — no HELENA entity for the indicator\n"
        f"  {load.unseen_threat_types} entry(ies) with a threat type this mapping "
        f"has not seen"
    )
    if load.unseen_threat_types:
        print(
            "\nAn unseen threat type emitted the parent rather than a guessed "
            "child, which is correct and is also worth looking at: the source's "
            "vocabulary has grown since the mapping was written."
        )
    print(
        f"\nFetch no more often than every "
        f"{THREATFOX_MIN_FETCH_INTERVAL_SECONDS // 3600}h — fair-use terms bind "
        f"this feed."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
