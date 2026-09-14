#!/usr/bin/env python3
"""Read the output topic and print what a consumer would see.

    uv run scripts/consume_output.py              # what is on the topic now
    uv run scripts/consume_output.py --follow     # ... and keep waiting
    uv run scripts/consume_output.py --json       # the bytes, one per line
    uv run scripts/consume_output.py --evidence   # with the cited rows expanded

This is the consumer side of `scripts/emit.py`, and it is the shape
`concept/03-architecture.md` has in mind by *"the analyst workflow / SIEM: a
consumer of the output topic"* — the pipeline's only egress, read the way
anything downstream would read it.

**It reads the topic, never the store.** A reader that fell back to SQL when the
topic was empty would hide the one failure this is useful for catching: an
assessment that exists and was never emitted. `uv run scripts/emit.py --count`
is the other half of that question and asks the engine instead.

## What you are looking at, and what you inherit by forwarding it

`docs/runbook.md` §11: the output topic carries **internal addresses, hostnames
and retrieved external text**, and no redaction is performed because the broker
is local. Every message says so itself in its `caveat` field. **Anything that
forwards this off-site inherits the disclosure obligations**, which is a decision
and not a plumbing detail.

## Reading the outcome

Two terminal kinds and they are not interchangeable
(`concept/instruction.md` §2):

- `verdict` — a classification the run reached, with `confidence` and the
  citations that support it.
- `typed_failure` — a run that did not reach one. It carries `failure_reason`
  and **no verdict**, and it is emitted rather than dropped, because a failure a
  consumer never sees is a silent drop.

A `normal` verdict with **no model version** is a third thing worth knowing on
sight: the pre-triage gate cleared that context without a model reading it
(`docs/decisions/0047-the-pre-triage-gate.md`). It establishes the absence of
nothing, and `--verbose` prints the distinction.

Maturity: `experimental` — the emission path it reads is covered by
`tests/test_sink.py` and `tests/test_end_to_end.py`; this reader is exercised by
running it.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from helena import sink  # noqa: E402
from helena.orchestration import TYPED_FAILURE  # noqa: E402
from helena.broker import BrokerConsumer, BrokerError  # noqa: E402
from helena.config import ConfigurationError, Settings  # noqa: E402

BOLD, DIM, GREEN, YELLOW, RED, RESET = (
    "\033[1m",
    "\033[2m",
    "\033[32m",
    "\033[33m",
    "\033[31m",
    "\033[0m",
)
if not sys.stdout.isatty():
    BOLD = DIM = GREEN = YELLOW = RED = RESET = ""


def describe(message: sink.OutputMessage, *, evidence: bool, verbose: bool) -> None:
    """One message, as a reader would want it: the outcome first."""
    if message.outcome_kind == TYPED_FAILURE:
        head = f"{RED}{message.failure_reason}{RESET}"
    elif message.verdict == "normal":
        head = f"{DIM}{message.classification or message.verdict}{RESET}"
    else:
        head = f"{GREEN}{BOLD}{message.classification or message.verdict}{RESET}"

    print(
        f"{message.assessed_at:%Y-%m-%d %H:%M:%S}  {message.host:<15} "
        f"{message.emitter:<8} {head}"
    )
    print(
        f"  {DIM}window {message.window_start:%H:%M}–{message.window_end:%H:%M}  "
        f"context {message.context_id[:12]}…  assessment {message.assessment_id[:12]}…{RESET}"
    )
    if message.confidence is not None:
        print(f"  confidence     {message.confidence}")
    if message.failure_detail:
        print(f"  {RED}detail{RESET}         {message.failure_detail[:100]}")
    print(
        f"  entities {len(message.entities)}   citations {len(message.citations)}   "
        f"gaps {len(message.gaps)}   retrievals {len(message.retrievals)}"
    )

    # The gate's signature: a classification with nothing that answered.
    if message.verdict is not None and message.versions.model_version is None:
        print(
            f"  {YELLOW}no model version{RESET} — the pre-triage gate cleared this "
            f"context;\n  {DIM}nothing read the traffic, so the verdict establishes "
            f"the absence of nothing{RESET}"
        )
    if message.narrative:
        print(f"  {message.narrative[:160]}")

    claimed = [
        (entity.entity_value, row.source_id, row.classification, row.confidence)
        for entity in message.entities
        for row in entity.evidence
        if row.classification not in (None, "no_match")
    ]
    if claimed:
        print(f"  {GREEN}claims{RESET}")
        for value, source, classification, confidence in claimed[:6]:
            print(f"    {value[:44]:<44} {source} {classification} {confidence}")
    if evidence and message.citations:
        print(f"  {DIM}cited{RESET}")
        for citation in message.citations:
            print(f"    {citation.evidence_id[:24]}…  as {citation.role}")
    if verbose:
        print(f"  {DIM}caveat: {message.caveat}{RESET}")
    print()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--follow",
        action="store_true",
        help="keep waiting after the topic goes quiet, instead of returning",
    )
    parser.add_argument(
        "--idle",
        type=float,
        default=5.0,
        help="seconds of quiet before returning (default 5; ignored with --follow)",
    )
    parser.add_argument("--json", action="store_true", help="the bytes, one per line")
    parser.add_argument(
        "--evidence", action="store_true", help="expand the cited evidence ids"
    )
    parser.add_argument("--verbose", action="store_true", help="include the caveat")
    arguments = parser.parse_args(argv)

    try:
        settings = Settings.load()
    except ConfigurationError as refused:
        print(f"FAILED: {refused}", file=sys.stderr)
        return 2

    topic = settings.infrastructure.output_topic
    bootstrap = settings.infrastructure.kafka_bootstrap_servers
    if not arguments.json:
        print(f"{BOLD}{topic}{RESET} on {bootstrap}")
        print(f"{DIM}egress: internal addresses, hostnames and retrieved external "
              f"text, unredacted.\nAnything forwarding this off-site inherits the "
              f"disclosure obligations (runbook §11).{RESET}\n")

    seen = 0
    try:
        with BrokerConsumer(bootstrap) as consumer:
            while True:
                for message in consumer.consume(topic, idle_timeout=arguments.idle):
                    seen += 1
                    if arguments.json:
                        sys.stdout.write(message.value.decode() + "\n")
                        sys.stdout.flush()
                        continue
                    try:
                        parsed = sink.OutputMessage.model_validate_json(message.value)
                    except Exception as invalid:  # noqa: BLE001 — a reader's own problem
                        # Printed rather than raised: a consumer that died on one
                        # unreadable message would stop reading the ones after it,
                        # and this is a reader, not the pipeline.
                        print(f"{RED}offset {message.offset}: not an OutputMessage"
                              f"{RESET}: {invalid}", file=sys.stderr)
                        continue
                    describe(parsed, evidence=arguments.evidence, verbose=arguments.verbose)
                if not arguments.follow:
                    break
    except BrokerError as error:
        print(f"FAILED: {error}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        pass

    if not arguments.json:
        print(f"{DIM}{seen} message(s){RESET}")
        if seen == 0:
            print(
                "nothing on the topic. `uv run scripts/emit.py --count` asks the\n"
                "engine how many assessments are waiting — a store with pending\n"
                "rows and an empty topic is an emission that has not run, which is\n"
                "a different fault from nothing having been assessed."
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
