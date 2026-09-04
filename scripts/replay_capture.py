#!/usr/bin/env python3
"""Replay a retained capture through the live ingestion path.

    uv run scripts/replay_capture.py --captures <dir> <sha256>
    uv run scripts/replay_capture.py --captures <dir> <sha256> --rate 200
    uv run scripts/replay_capture.py --captures <dir> <sha256> --ingest

The capture is addressed by its own hash, which is what the file is named
(`helena.normalizer.scan_captures`), and its records go onto `HELENA_INGEST_TOPIC`
in the same wire form a sensor uses. Nothing here parses a record: the adapter,
the identity stamping and the two stores are reached through
`helena.normalizer`, so replay exercises the pipeline rather than a copy of it.

`--ingest` also runs the **ingestion** side in this process and reports
produced-versus-materialised counts at the end. Use it when no consumer is
running — which is the case in this prototype, so it is also how a replay
actually reaches the store. It assumes this replay is the only producer on the
topic while it runs: the counters are per capture and refuse a set that does not
reconcile, so anything else arriving on the topic meanwhile is reported as a
failure to reconcile rather than folded into the numbers.

Backfilling a view added to a running deployment is what this is for — see
docs/runbook.md §8. The broker is consume-once, so the view starts empty and the
retained capture is the only thing left to fill it from.

Exit status is 0 only when the run did what it said: every record published,
and, with `--ingest`, every record accounted for in the store.

Maturity: experimental — `publish_capture` and `consume_ingest_topic` underneath
it are exercised by tests/test_normalizer.py against the pinned broker and
engine; this wrapper's publishing path is covered there too, and its `--ingest`
path is run by hand (see prds/reports/task-11.json).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import psycopg
from pydantic import ValidationError

from helena.broker import (
    DEFAULT_IDLE_TIMEOUT_SECONDS,
    BrokerConsumer,
    BrokerError,
    BrokerProducer,
)
from helena.config import ConfigurationError, Settings
from helena.normalizer import (
    Capture,
    CaptureError,
    EventStore,
    IngestCounts,
    IngestMessageError,
    Normalizer,
    Quarantine,
    consume_ingest_topic,
    ingest_counts,
    publish_capture,
    scan_captures,
)


def _capture(directory: Path, sha256: str) -> Capture:
    """The capture `sha256` in `directory`, or a `CaptureError` saying so.

    `scan_captures` checks every file in the directory against its own name, so
    a capture that no longer hashes to what it claims fails the lookup rather
    than being replayed under a reference that addresses different bytes.
    """
    captures = scan_captures(directory)
    capture = captures.get(sha256)
    if capture is None:
        raise CaptureError(
            f"{directory} holds no capture {sha256}; it holds "
            f"{len(captures)} capture(s). A capture is addressed by the hash of "
            f"its own bytes, which is also its filename."
        )
    return capture


def _report(counts: IngestCounts) -> None:
    """The four numbers, each labelled with where it came from.

    `helena.normalizer.ingest_counts` has already refused any set that does not
    reconcile, so this prints numbers that add up or nothing at all — the point
    of showing them is which one is short, not whether to trust them.
    """
    print(f"  records     {counts.records:>6}  the retained capture")
    print(f"  consumed    {counts.consumed:>6}  off the ingest topic")
    print(f"  normalized  {counts.normalized:>6}  helena_ingest_counts")
    print(
        f"  quarantined {counts.quarantine.quarantined:>6}  "
        f"helena_ingest_quarantine_counts"
    )
    for reason, count in sorted(counts.quarantine.by_reason.items()):
        print(f"    {reason:<20} {count:>6}")
    if counts.complete:
        print("every record of the capture reached the store")
    else:
        print(
            f"INCOMPLETE: {counts.records - counts.consumed} record(s) never "
            f"came off the topic. The broker keeps nothing to recover them "
            f"from; the capture is still on disk, so replay it again.",
            file=sys.stderr,
        )


def _ingest(settings: Settings, capture: Capture, idle_timeout: float) -> IngestCounts:
    """Consume the ingest topic into the store, and reconcile the run.

    The same three calls a live consumer makes, in the same order. The engine
    connection is autocommit because RisingWave DDL and reads behave that way
    (docs/runbook.md §5), and the stores are addressed under the configured
    identity — the normalizer refuses them otherwise.
    """
    topic = settings.infrastructure.ingest_topic
    normalizer = Normalizer.from_settings(settings)
    with psycopg.connect(
        settings.infrastructure.risingwave_dsn, autocommit=True, connect_timeout=5
    ) as connection:
        events = EventStore(connection=connection, identity=settings.identity)
        quarantine = Quarantine(connection=connection, identity=settings.identity)
        with BrokerConsumer.from_settings(settings) as consumer:
            consumed = normalizer.ingest_messages(
                consume_ingest_topic(consumer, topic, idle_timeout=idle_timeout),
                events,
                quarantine,
            )
        return ingest_counts(
            capture=capture,
            consumed=consumed,
            events=events,
            quarantine=quarantine,
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="replay-capture", description=__doc__.splitlines()[0]
    )
    parser.add_argument(
        "capture",
        metavar="<sha256>",
        help="the capture to replay, by the hash its file is named with",
    )
    parser.add_argument(
        "--captures",
        required=True,
        type=Path,
        metavar="DIR",
        help=(
            "the directory of retained captures. Required and without a "
            "default: replaying the wrong directory publishes another "
            "deployment's records under this one's identity"
        ),
    )
    parser.add_argument(
        "--rate",
        type=float,
        default=None,
        metavar="PER_SECOND",
        help=(
            "records per second, as a floor on how fast they are published. "
            "Unset publishes as fast as the broker accepts them"
        ),
    )
    parser.add_argument(
        "--ingest",
        action="store_true",
        help=(
            "also consume the topic into the store in this process, through "
            "the live ingestion path, and report produced-versus-materialised "
            "counts at the end"
        ),
    )
    parser.add_argument(
        "--idle-timeout",
        type=float,
        default=DEFAULT_IDLE_TIMEOUT_SECONDS,
        metavar="SECONDS",
        help=(
            "with --ingest, how long the consumer waits for a message before "
            "deciding the topic has gone quiet"
        ),
    )
    arguments = parser.parse_args(argv)
    if arguments.rate is not None and arguments.rate <= 0:
        parser.error("--rate must be greater than zero records per second")

    try:
        settings = Settings.load()
        capture = _capture(arguments.captures, arguments.capture)
    except (ConfigurationError, CaptureError, OSError) as refused:
        print(f"FAILED: {refused}", file=sys.stderr)
        return 1

    topic = settings.infrastructure.ingest_topic
    try:
        with BrokerProducer.from_settings(settings) as producer:
            published = publish_capture(
                capture, producer, topic, rate=arguments.rate
            )
    except (BrokerError, CaptureError) as error:
        print(f"FAILED: {error}", file=sys.stderr)
        return 1
    print(f"published {published} of {capture.record_count} record(s) to {topic}")
    if published != capture.record_count:
        print(
            f"FAILED: the capture holds {capture.record_count} record(s)",
            file=sys.stderr,
        )
        return 1
    if not arguments.ingest:
        return 0

    try:
        counts = _ingest(settings, capture, arguments.idle_timeout)
    except IngestMessageError as refused:
        print(f"FAILED: {refused}", file=sys.stderr)
        return 1
    except ValidationError as refused:
        # `IngestCounts` refuses a set that does not add up. Printing plausible
        # numbers instead would be the prototype that runs and lies.
        print(f"FAILED: the counters do not reconcile: {refused}", file=sys.stderr)
        return 1
    except (BrokerError, ConfigurationError) as error:
        print(f"FAILED: {error}", file=sys.stderr)
        return 1
    except psycopg.Error as error:
        print(f"FAILED: the engine did not answer: {error}", file=sys.stderr)
        return 1
    _report(counts)
    return 0 if counts.complete else 1


if __name__ == "__main__":
    sys.exit(main())
