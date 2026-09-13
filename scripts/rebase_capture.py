#!/usr/bin/env python3
"""Move a capture's records in time, so a corpus and a feed snapshot can overlap.

    uv run scripts/rebase_capture.py --source data/connections/network-day/20250920 --out .corpus/day --ending-now
    uv run scripts/rebase_capture.py --source data/connections/network-day/20250920 --out .corpus/day --starting 2026-09-13T00:00:00Z
    uv run scripts/rebase_capture.py --source one.ndjson.gz --out .corpus/x --by 31536000
    uv run scripts/rebase_capture.py --source .corpus/day --out /tmp/check --by 0 --verify-only

## Why this exists

The enrichment join matches the feed snapshot whose validity interval covers the
context's window, and a snapshot's interval begins when it was **fetched**
(`sql/migrations/0015_enriched_context.sql`). The retained day capture is dated
2025-09-20 and no snapshot fetchable today reaches back to it, so every entity
comes back unenriched and no request can be built at all -- `docs/acceptance.md`
finding 1. Moving the records forward is what lets the two halves overlap.

`ts` is a field of the input contract, so moving it is a contract-permitted
change to a real record -- the same thing `tests/test_end_to_end.py` does to the
committed fixture and for the same reason.

## What this does NOT make

**A rebased capture is a test fixture, not an evaluation corpus, and nothing here
should be read as producing one.** The traffic was observed in September 2025 and
the feed snapshot it will be joined against was published a year later. Any match
that results is an accident of a rolling sighting window, and any miss is not
evidence of anything. `docs/evaluation-corpus.md` says what a corpus would have
to be -- labelled, time-correct, multi-host, with contemporaneous enrichment --
and this script produces none of those properties. It makes the pipeline
*runnable* over volume. It does not make its verdicts *measurable*.

## The four fields that move, and the rule that finds a fifth

Measured against `data/connections/network-day/20250920` rather than assumed from the sample: the
day capture carries **four** absolute epochs and `data/connections/maintainer-host/flow-sample.jsonl`
carries **one**. Shifting only `ts`, which is all the sample would have taught,
leaves every TCP segment and UDP datagram a year behind its own flow.

| Field | What it is | Moves |
| --- | --- | --- |
| `ts` | when the flow started; the window is taken from it | yes |
| `tx` | when the producer exported the batch (`helena.normalizer`) | yes |
| `tcp.segs[].ts` | per-segment arrival | yes |
| `udp.dgms[].ts` | per-datagram arrival | yes |
| `td` | a **duration** | no |
| `dns.responses[].ttl` | a **duration** | no |

A number anywhere else in the record that falls in the epoch-plausible range is a
**refusal, naming the path**, not a field left behind. That is the whole safety
argument here: this script cannot know a future producer's field names, so it
fails loudly on an unrecognised timestamp rather than silently writing a record
whose parts disagree about when they happened.

Maturity: `experimental` -- the paths it drives are covered by
`tests/test_rebase.py`; the corpus it produces is not evidence of anything.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from helena.normalizer import CAPTURE_SUFFIX, describe_capture  # noqa: E402

#: Absolute epochs, as `(container, key)` walked from the record root. Measured
#: over `data/connections/network-day/20250920` and `data/connections/maintainer-host/flow-sample.jsonl`.
EPOCH_FIELDS = ("ts", "tx")
EPOCH_LISTS = (("tcp", "segs", "ts"), ("udp", "dgms", "ts"))

#: A number in this range is a second-resolution epoch between 2001 and 2033. A
#: value here that this script does not know how to move is the failure it exists
#: to prevent, so the range is deliberately wide: a false alarm costs a line in
#: `EPOCH_FIELDS`, and a miss costs a corpus whose records disagree with
#: themselves in a way nothing downstream can detect.
EPOCH_LOW, EPOCH_HIGH = 1_000_000_000, 2_000_000_000

#: Durations and counters that live in the same numeric range as nothing, but are
#: named here so the scan can say "known, and deliberately not moved".
NOT_TIMES = frozenset({"td", "ttl", "len", "num", "ct"})


class RebaseError(RuntimeError):
    """An input this script refuses, naming the record and the path."""


@dataclass
class Summary:
    """What one run moved, for the manifest and for the operator."""

    files: int = 0
    records: int = 0
    delta_seconds: float = 0.0
    source_first: float = 0.0
    source_last: float = 0.0
    written: list[str] = field(default_factory=list)

    @property
    def first(self) -> datetime:
        return datetime.fromtimestamp(self.source_first + self.delta_seconds, timezone.utc)

    @property
    def last(self) -> datetime:
        return datetime.fromtimestamp(self.source_last + self.delta_seconds, timezone.utc)


def read_records(path: Path) -> Iterator[dict[str, Any]]:
    """Every record of one capture file, gzipped or not."""
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt") as handle:  # type: ignore[operator]
        for number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as bad:
                raise RebaseError(f"{path}:{number} is not JSON: {bad}") from bad
            if not isinstance(record, dict):
                raise RebaseError(f"{path}:{number} is not a JSON object")
            yield record


def sources(path: Path) -> list[Path]:
    """The capture files under `path`, or `path` itself, in name order."""
    if path.is_file():
        return [path]
    if not path.is_dir():
        raise RebaseError(f"{path} is neither a file nor a directory")
    found = sorted(
        child
        for child in path.iterdir()
        if child.is_file()
        and (
            child.suffixes[-2:] == [".ndjson", ".gz"]
            or child.suffix in {".ndjson", ".jsonl"}
        )
    )
    if not found:
        raise RebaseError(f"{path} holds no .ndjson, .ndjson.gz or .jsonl file")
    return found


def unknown_epochs(record: Any, path: str = "") -> list[str]:
    """Paths holding an epoch-shaped number this script would not move.

    The safety net. `EPOCH_FIELDS` and `EPOCH_LISTS` are what was measured over
    the two captures in this repository; a producer that adds a fifth timestamp
    would otherwise have it silently left behind, and a record whose segments
    predate its own start is not something any downstream check would catch.
    """
    found: list[str] = []
    if isinstance(record, dict):
        for key, value in record.items():
            here = f"{path}/{key}"
            known = key in EPOCH_FIELDS or any(
                here.endswith(f"/{container}/{name}[]/{leaf}") or key == leaf
                for container, name, leaf in EPOCH_LISTS
            )
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                if EPOCH_LOW <= value <= EPOCH_HIGH and not known and key not in NOT_TIMES:
                    found.append(here)
            else:
                found.extend(unknown_epochs(value, here))
    elif isinstance(record, list):
        for item in record:
            found.extend(unknown_epochs(item, f"{path}[]"))
    return found


def shift(record: dict[str, Any], delta: float) -> dict[str, Any]:
    """`record` with every absolute epoch moved by `delta`, and nothing else touched.

    Returns a new object rather than mutating: the caller reads the source twice
    (once to find the earliest `ts`, once to write) and a mutated record would
    make the second pass depend on the first.
    """
    moved = json.loads(json.dumps(record))
    for key in EPOCH_FIELDS:
        value = moved.get(key)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            moved[key] = value + delta
    for container, name, leaf in EPOCH_LISTS:
        table = moved.get(container)
        if not isinstance(table, dict):
            continue
        rows = table.get(name)
        if not isinstance(rows, list):
            continue
        for row in rows:
            if isinstance(row, dict) and isinstance(row.get(leaf), (int, float)):
                row[leaf] = row[leaf] + delta
    return moved


def span(paths: list[Path]) -> tuple[float, float, int]:
    """The earliest `ts`, the latest, and how many records carry one.

    Every record is read and checked here, before anything is written, so a
    capture holding an unmovable timestamp fails before it has produced half an
    output directory.
    """
    first = last = None
    counted = 0
    for path in paths:
        for number, record in enumerate(read_records(path), start=1):
            stamp = record.get("ts")
            if not isinstance(stamp, (int, float)) or isinstance(stamp, bool):
                raise RebaseError(
                    f"{path}:{number} has ts={stamp!r}. Every record is windowed "
                    f"on `ts` and a record without one cannot be moved or binned."
                )
            strays = unknown_epochs(record)
            if strays:
                raise RebaseError(
                    f"{path}:{number} holds epoch-shaped values this script does "
                    f"not know how to move: {strays}. Add them to EPOCH_FIELDS or "
                    f"EPOCH_LISTS -- leaving one behind writes a record whose "
                    f"parts disagree about when they happened, and nothing "
                    f"downstream would catch it."
                )
            first = stamp if first is None else min(first, stamp)
            last = stamp if last is None else max(last, stamp)
            counted += 1
    if first is None:
        raise RebaseError("the source holds no records")
    return first, last, counted


def rebase(
    source: Path, out: Path, *, delta: float, dry_run: bool = False
) -> Summary:
    """Write every source file into `out`, shifted, as capture-store files.

    Output is named `<sha256>.jsonl` because that is what a capture *is*
    (`docs/decisions/0010-capture-identity.md`) and what `scan_captures` and
    `scripts/replay_capture.py` accept. One output file per input file, so the
    day keeps its ten-minute chunking and can be replayed incrementally.
    """
    paths = sources(source)
    first, last, counted = span(paths)
    summary = Summary(
        files=len(paths),
        records=counted,
        delta_seconds=delta,
        source_first=first,
        source_last=last,
    )
    if dry_run:
        return summary

    out.mkdir(parents=True, exist_ok=True)
    for path in paths:
        staged = out / f".{path.name}.staging"
        with staged.open("wb") as handle:
            for record in read_records(path):
                moved = shift(record, delta)
                if moved.get("tx") is not None:
                    # The invariant `helena.normalizer` measured over this
                    # capture: the export time is never before the flow ended.
                    # A constant shift preserves it, so a violation here means
                    # the shift was not constant -- a bug in this script rather
                    # than in the data.
                    if moved["tx"] < moved["ts"] + moved.get("td", 0.0) - 1e-6:
                        raise RebaseError(
                            f"{path}: tx fell before ts+td after the shift, which "
                            f"a constant delta cannot do. This is a bug here."
                        )
                handle.write(
                    json.dumps(moved, separators=(",", ":")).encode() + b"\n"
                )
        described = describe_capture(staged)
        final = out / f"{described.sha256}{CAPTURE_SUFFIX}"
        staged.replace(final)
        summary.written.append(final.name)
    return summary


def manifest(summary: Summary, source: Path, out: Path) -> dict[str, Any]:
    """What was done, written beside the output.

    **A rebased capture that does not say it was rebased is a lie by omission.**
    Anything reading this directory later has no way to tell 2026 traffic from
    2025 traffic moved into 2026, and the difference is the whole reason
    `docs/evaluation-corpus.md` says a corpus must be captured and enriched
    contemporaneously.
    """
    return {
        "kind": "rebased-capture",
        "written_by": "scripts/rebase_capture.py",
        "source": str(source),
        "files": summary.files,
        "records": summary.records,
        "delta_seconds": summary.delta_seconds,
        "source_span_utc": [
            datetime.fromtimestamp(summary.source_first, timezone.utc).isoformat(),
            datetime.fromtimestamp(summary.source_last, timezone.utc).isoformat(),
        ],
        "rebased_span_utc": [summary.first.isoformat(), summary.last.isoformat()],
        "captures": sorted(summary.written),
        "not_an_evaluation_corpus": (
            "The traffic was observed at source_span_utc and will be joined "
            "against a feed snapshot published later. Matches are an accident of "
            "a rolling sighting window and misses are not evidence. See "
            "docs/evaluation-corpus.md."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--source", required=True, type=Path, help="file or directory")
    parser.add_argument("--out", type=Path, help="output directory")
    when = parser.add_mutually_exclusive_group(required=True)
    when.add_argument(
        "--ending-now",
        action="store_true",
        help="the LAST record lands now, so the whole capture is in the past",
    )
    when.add_argument("--starting", help="ISO-8601 instant for the FIRST record")
    when.add_argument("--by", type=float, help="shift by this many seconds")
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="read and check the source, write nothing",
    )
    arguments = parser.parse_args(argv)

    try:
        paths = sources(arguments.source)
        first, last, counted = span(paths)
    except RebaseError as refused:
        print(f"refused: {refused}", file=sys.stderr)
        return 2

    if arguments.by is not None:
        delta = arguments.by
    elif arguments.starting:
        try:
            target = datetime.fromisoformat(arguments.starting.replace("Z", "+00:00"))
        except ValueError:
            print(f"--starting {arguments.starting!r} is not ISO-8601", file=sys.stderr)
            return 2
        if target.tzinfo is None:
            target = target.replace(tzinfo=timezone.utc)
        delta = target.timestamp() - first
    else:
        delta = datetime.now(timezone.utc).timestamp() - last

    if arguments.verify_only:
        print(f"ok: {counted} record(s) in {len(paths)} file(s), every timestamp known")
        return 0
    if arguments.out is None:
        print("--out is required unless --verify-only", file=sys.stderr)
        return 2

    try:
        summary = rebase(arguments.source, arguments.out, delta=delta)
    except RebaseError as refused:
        print(f"refused: {refused}", file=sys.stderr)
        return 2

    record = manifest(summary, arguments.source, arguments.out)
    (arguments.out / "MANIFEST.json").write_text(json.dumps(record, indent=2) + "\n")

    print(f"{summary.records} record(s) in {summary.files} file(s)")
    print(f"  shifted by   {summary.delta_seconds:+.1f}s "
          f"({summary.delta_seconds / 86400:+.2f} days)")
    print(f"  was          {record['source_span_utc'][0]} -> {record['source_span_utc'][1]}")
    print(f"  now          {record['rebased_span_utc'][0]} -> {record['rebased_span_utc'][1]}")
    print(f"  written to   {arguments.out}  ({len(summary.written)} capture(s) + MANIFEST.json)")
    print()
    # The half an operator gets wrong: the snapshot has to be OLDER than the
    # traffic, because a snapshot's validity interval begins when it was fetched
    # and the join asks which interval covers the context's window.
    lead = summary.first - timedelta(minutes=1)
    print("  For the enrichment join to cover these windows, load a feed snapshot")
    print(f"  dated at or before {lead.isoformat()} -- `helena.enrichment.load_threatfox`")
    print("  takes `now=` for exactly this. A snapshot loaded after the traffic")
    print("  does not enrich it (sql/migrations/0015_enriched_context.sql).")
    print()
    print("  This is a test fixture, not an evaluation corpus. See the manifest.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
