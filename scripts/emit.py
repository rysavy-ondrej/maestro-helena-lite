#!/usr/bin/env python3
"""Emit every terminal outcome the store holds to the output topic.

    uv run scripts/emit.py
    uv run scripts/emit.py --count

Every assessed context leaves here, once per terminal outcome — `normal`
verdicts, `suspicious` ones and typed failures alike, and an escalated context
once, under the analyst's identifier and carrying the triage decision that led to
it (`concept/03-architecture.md`). The topic is `HELENA_OUTPUT_TOPIC` and the
broker is `KAFKA_BOOTSTRAP_SERVERS`; neither is a flag, because a topic typed on
a command line is a topic that can differ between two runs of the same
deployment.

**Delivery is at-least-once and this command does not remember what it emitted.**
Running it twice puts the same messages on the topic twice; the consumer discards
the repeat by `assessment_id`, which is stable across runs. That is the contract,
not a limitation to work around — see
`docs/decisions/0037-at-least-once-emission.md` §2. What it does mean in practice
is that this is a **drain**, not a tail: there is no cursor, and at prototype
scale the whole store is re-emitted each time.

`--count` asks the engine and produces nothing. It is the answer to "the consumer
sees nothing": the broker discards its queue on restart and keeps nothing after a
read, so the engine is the only side that still knows how many messages there
were (`docs/runbook.md` §12).

Exit status is 0 only when every message the store held reached the broker.

Maturity: experimental — `helena.sink.emit` underneath it is exercised by
tests/test_sink.py against the pinned engine and the pinned broker, including the
drain back off the topic. This wrapper is run by hand; no consumer outside this
project has read one of these messages.
"""

from __future__ import annotations

import argparse
import sys

import psycopg

from helena import sink
from helena.broker import BrokerError, BrokerProducer
from helena.config import ConfigurationError, Settings


def _arguments(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--count",
        action="store_true",
        help=(
            "ask the engine how many messages there are to emit and produce "
            "nothing. This is how 'nothing arrived' is told apart from 'nothing "
            "was assessed'"
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

    identity = settings.identity
    topic = settings.infrastructure.output_topic
    try:
        with psycopg.connect(settings.infrastructure.risingwave_dsn) as connection:
            store = sink.SinkStore(connection=connection, identity=identity)
            if arguments.count:
                pending = store.pending()
                print(
                    f"{pending} message(s) to emit for "
                    f"{identity.tenant}/{identity.sensor}, per "
                    f"{sink.EMISSION_COUNTS_VIEW}"
                )
                if pending == 0:
                    print(
                        "nothing has been assessed — which is a different thing "
                        "from nothing having arrived at a consumer"
                    )
                return 0
            with BrokerProducer.from_settings(settings) as producer:
                counts = sink.emit(store=store, producer=producer, topic=topic)
    except psycopg.Error as error:
        print(f"FAILED: the engine did not answer: {error}", file=sys.stderr)
        return 1
    except (BrokerError, sink.SinkError) as refused:
        print(f"FAILED: {refused}", file=sys.stderr)
        return 1

    print(f"emitted {counts.emitted} of {counts.pending} message(s) to {topic}")
    if not counts.complete:
        # Not a failure of this run: a pass that landed while the drain was in
        # flight is a message the next one emits. Said out loud anyway, because
        # the alternative is an operator reading two numbers and guessing.
        print(
            f"{counts.pending - counts.emitted} message(s) were assessed after "
            f"this run read its list and were not emitted; run it again"
        )
    return 0 if counts.complete else 1


if __name__ == "__main__":
    raise SystemExit(main())
