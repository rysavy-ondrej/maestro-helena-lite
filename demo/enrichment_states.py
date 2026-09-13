#!/usr/bin/env python3
"""Four enrichment states over one capture, and why none of them means "safe".

    demo/run-demo 4
    uv run demo/enrichment_states.py          # if the engine and broker are up

`concept/instruction.md` §2: **`stale`, `failed`, `missing` and `no_match` are
four different things**, and a typed error is a fifth. Never collapse them, at
any layer, for any reason.

That is a rule, and a rule is easy to agree with and hard to check. This runs the
**same 62 records** four times, changing only what the feed did, and prints the
enriched context each time. The four runs differ in one thing each:

  | Run | What the feed did | The row says |
  | --- | --- | --- |
  | 1 | loaded a minute before the window | `ok`, and `no_match` per entity |
  | 2 | loaded three hours before the window | `stale` — older than the source's own refresh floor |
  | 3 | loaded only *after* the window had happened | `missing` — a snapshot exists, and none covers this window |
  | 4 | attempted and failed | `failed` — asked, and the asking broke |

**Run 3 is not "no load at all", and finding that out is half the demo.** With
nothing ever loaded there is no source in the load ledger, and
`sql/migrations/0015_enriched_context.sql` takes its source list from that
ledger — so the enriched context has **no rows at all** rather than rows reading
`missing`. `missing` is a deployment that *has* a source and holds no snapshot
covering this window, which is the ordinary shape of it: traffic older than
anything the feed still publishes. That is the same wall
`docs/evaluation-corpus.md` §4 describes for an archived capture.

**The point is the last column.** `no_match` is a lookup outcome: a snapshot was
consulted and said nothing about this entity. `missing` is that no snapshot
existed to consult. `failed` is that consulting it broke. A pipeline that printed
"clean" for all three would be telling an operator that an outage and a
clean bill of health are the same fact.

The `stale` threshold is not a number in this file. It is
`helena.enrichment.SOURCES["threatfox"].refresh_interval_seconds`, the source's
own fetch floor, applied by `sql/migrations/0015_enriched_context.sql`.

## What it does not show

**No assessment.** No agent is called and no verdict exists; this is the layer
underneath one. **Nothing about verdict quality** — there is no labelled corpus,
and there is nothing here that could produce a claim about one.

Maturity: experimental — a demonstration, not a tested component. The states it
prints are covered by `tests/test_acceptance_enrichment.py`, which asserts them;
this script is exercised by running it.
"""

from __future__ import annotations

import sys
import tempfile
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from _common import (  # noqa: E402
    BOLD,
    DIM,
    GREEN,
    RESET,
    YELLOW,
    banner,
    current_window,
    enrichment_rows,
    ingest,
    live_contexts,
    load_feed,
    load_suffixes,
    note,
    print_states,
    rule,
    sample_records,
    schema,
    settings_for,
    stage,
    stage_capture,
    utc,
)
from helena import enrichment  # noqa: E402

#: The source's own fetch floor, which is what decides `ok` from `stale`. Read
#: from the descriptor rather than written here, so a demo cannot disagree with
#: the registry about what stale means.
REFRESH_FLOOR = enrichment.SOURCES["threatfox"].refresh_interval_seconds

RUNS = (
    ("ok", "loaded a minute before the window", timedelta(minutes=1), "load"),
    (
        "stale",
        f"loaded well before the source's own {REFRESH_FLOOR / 3600:.0f}h refresh floor",
        timedelta(seconds=REFRESH_FLOOR * 3 + 600),
        "load",
    ),
    (
        "missing",
        "loaded, but only AFTER this window had already happened",
        timedelta(hours=-2),
        "load",
    ),
    ("failed", "attempted, and the attempt broke", timedelta(minutes=1), "fail"),
)


def main() -> int:
    print(f"{BOLD}MAESTRO HELENA — four enrichment states, one capture{RESET}")
    rule()
    settings = settings_for()
    print(f"  tenant={settings.identity.tenant}  sensor={settings.identity.sensor}")
    note("the same 62 records four times; only the feed differs")

    records = sample_records()
    window = current_window()
    seen: dict[str, list[tuple]] = {}

    for number, (expected, description, lead, action) in enumerate(RUNS, start=1):
        banner(f"RUN {number} — {expected.upper()}: the feed {description}")
        with schema(settings) as (connection, name):
            stage(1, "Reference data and the capture")
            load_suffixes(connection, settings, when=utc(window) - timedelta(minutes=5))
            with tempfile.TemporaryDirectory(prefix="helena-demo-") as staging:
                capture = stage_capture(records, Path(staging), window=window)
                counts = ingest(settings, connection, capture)
            print(f"  schema       {name}")
            print(f"  records      {counts.normalized} normalized, "
                  f"{counts.quarantine.quarantined} quarantined")

            stage(2, "What the feed did")
            if action == "fail":
                # A URL that resolves to nothing: the loader records a typed
                # failure and leaves any previous snapshot in place. There is no
                # previous one here, which is what makes the row `failed` rather
                # than `stale`.
                load = load_feed(
                    connection,
                    settings,
                    when=utc(window) - lead,
                    url="https://threatfox.invalid/export/json/recent/",
                )
                print(f"  {YELLOW}load failed{RESET}: {load.failure_reason}")
                note("the previous snapshot would be left in place; there is none")
            else:
                load = load_feed(connection, settings, when=utc(window) - lead)
                stamp = utc(window) - lead
                print(f"  loaded       {stamp.isoformat()}")
                print(f"  snapshot     {(load.snapshot_version or '—')[:16]}…")
                print(f"  claims       {(load.counts or {}).get('claims_stored', 0)}")
            connection.execute("FLUSH")

            stage(3, "The enriched context")
            contexts = live_contexts(connection)
            rows = enrichment_rows(connection)
            seen[expected] = rows
            print(f"  contexts     {len(contexts)}")
            note("lookup status x what the snapshot said:")
            print_states(rows)

    banner("THE FOUR, SIDE BY SIDE")
    print(f"\n  {'run':<10} {'status':<10} {'what the row says':<34} rows")
    rule()
    for expected, _, _, _ in RUNS:
        rows = seen.get(expected) or []
        if not rows:
            print(f"  {expected:<10} {DIM}(no entity rows){RESET}")
            continue
        for status, classification, count in rows:
            print(f"  {expected:<10} {BOLD}{status:<10}{RESET} {classification:<34} {count}")

    statuses = {
        expected: {status for status, _, _ in (seen.get(expected) or [])}
        for expected, _, _, _ in RUNS
    }
    distinct = {expected: sorted(found) for expected, found in statuses.items()}
    print()
    if all(expected in found for expected, found in statuses.items()):
        print(f"  {GREEN}Four runs, four different statuses.{RESET} {distinct}")
    else:
        print(f"  statuses observed: {distinct}")
    print(
        f"\n{DIM}  `no_match` is a snapshot consulted and saying nothing about this\n"
        f"  entity. `missing` is no snapshot to consult. `failed` is the consulting\n"
        f"  breaking. `stale` is a snapshot older than the source's own refresh\n"
        f"  floor. NONE of the four is a statement that anything is safe, and a\n"
        f"  pipeline that printed one word for all of them would be saying an\n"
        f"  outage and a clean bill of health are the same fact.{RESET}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
