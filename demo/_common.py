"""What demos 4-8 all need: a private schema, a capture, ingestion, a fake model.

Underscore-prefixed, so it is a helper rather than a demo —
`tests/test_demos.py` globs `demo/*.py` and skips names starting with `_`.

**Why this exists and demos 1-3 do not use it.** Those three duplicate their
display helpers and their setup, which was fine at three and is not at eight:
five more demos each opening a schema, applying migrations, staging a capture and
crossing the broker is the same forty lines five times, and forty lines copied
five times is five places for "how a demo sets up" to drift. Demos 1-3 are left
as they are rather than refactored, because they work, are committed, and demo 3
costs live model calls to re-verify — the duplication between them and this file
is real and recorded in `docs/demos.md` rather than hidden.

Nothing here reimplements a pipeline stage. The migrations are applied by
`helena.migrations`, records cross the wire through `helena.broker`, and the
contexts come out of views the engine computed.
"""

from __future__ import annotations

import json
import sys
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Iterator

import psycopg

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from helena import enrichment, migrations  # noqa: E402
from helena.broker import BrokerConsumer, BrokerProducer  # noqa: E402
from helena.config import Settings  # noqa: E402
from helena.normalizer import (  # noqa: E402
    CAPTURE_SUFFIX,
    EventStore,
    Normalizer,
    Quarantine,
    consume_ingest_topic,
    describe_capture,
    ingest_counts,
    publish_capture,
)
from helena.observability import Redactor  # noqa: E402

SAMPLE = ROOT / "data" / "ingest" / "flow-sample.jsonl"
THREATFOX_EXPORT_URL = "https://threatfox.abuse.ch/export/json/recent/"
PUBLIC_SUFFIX_LIST_URL = "https://publicsuffix.org/list/public_suffix_list.dat"

#: `sql/migrations/0006_host_context.sql` tumbles on INTERVAL '5 minutes'.
WINDOW_SECONDS = 300

BOLD, DIM, CYAN, GREEN, YELLOW, RED, RESET = (
    "\033[1m",
    "\033[2m",
    "\033[36m",
    "\033[32m",
    "\033[33m",
    "\033[31m",
    "\033[0m",
)
if not sys.stdout.isatty():
    BOLD = DIM = CYAN = GREEN = YELLOW = RED = RESET = ""


def stage(number: int, title: str) -> None:
    print(f"\n{BOLD}{CYAN}[{number}]{RESET} {BOLD}{title}{RESET}")


def rule() -> None:
    print(f"{DIM}{'-' * 78}{RESET}")


def banner(text: str) -> None:
    print(f"\n{BOLD}{'=' * 78}{RESET}\n{BOLD}{text}{RESET}\n{BOLD}{'=' * 78}{RESET}")


def note(text: str) -> None:
    print(f"  {DIM}{text}{RESET}")


def current_window() -> float:
    """The start of the tumbling window `now` falls in, as a timestamp."""
    return float(int(time.time() // WINDOW_SECONDS) * WINDOW_SECONDS)


def sample_records() -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in SAMPLE.read_bytes().splitlines()
        if line.strip()
    ]


def stage_capture(
    records: list[dict[str, Any]], directory: Path, *, window: float
) -> Any:
    """Records re-stamped into `window`, written under their own sha256.

    `ts` is a field of the input contract, so moving it is a contract-permitted
    change to a real record — `tests/test_end_to_end.py::current_window` says the
    same, and `scripts/rebase_capture.py` is the same operation for a whole
    corpus. The committed sample is dated 2024-06-01 and the retention boundary
    does not show a context that old.
    """
    directory.mkdir(parents=True, exist_ok=True)
    staged = directory / f"staging-{uuid.uuid4().hex}.jsonl"
    staged.write_bytes(
        b"".join(
            json.dumps({**record, "ts": window + 1}).encode() + b"\n"
            for record in records
        )
    )
    described = describe_capture(staged)
    final = directory / f"{described.sha256}{CAPTURE_SUFFIX}"
    staged.replace(final)
    return describe_capture(final)


def settings_for(*, model_url: str | None = None) -> Settings:
    """The deployment's own settings, optionally pointed at a scripted endpoint.

    The process environment wins over `.env` (`helena.config.Settings.load`), so
    layering the three model URLs over it is how a demo runs against a local
    fake without editing anything on disk. Every other variable — the identity,
    the engine, the broker — is this deployment's real one.
    """
    import os

    if model_url is None:
        return Settings.load()
    return Settings.load(
        environ={
            **os.environ,
            "LLM_URL": model_url,
            # The per-agent values are resolved BEFORE the general one, so a
            # `.env` that sets them would otherwise win and the demo would call
            # the real endpoint while claiming to be scripted.
            "LLM_URL_TRIAGE": model_url,
            "LLM_URL_ANALYST": model_url,
        }
    )


@contextmanager
def schema(settings: Settings, *, keep: bool = False) -> Iterator[tuple[psycopg.Connection, str]]:
    """A schema of this run's own, migrated, and dropped afterwards.

    So a demo can be run beside a live deployment without touching its data. The
    throwaway unit is a schema and not a process, for the reason
    `docs/runbook.md` §2 gives: `single_node` binds fixed meta and compute ports
    and a second engine cannot run beside the first.
    """
    name = f"helena_demo_{uuid.uuid4().hex[:12]}"
    connection = psycopg.connect(
        settings.infrastructure.risingwave_dsn, autocommit=True, connect_timeout=10
    )
    try:
        connection.execute(f"CREATE SCHEMA {name}")
        connection.execute(f"SET search_path TO {name}")
        migrations.apply(connection)
        yield connection, name
    finally:
        if keep:
            print(f"\n{DIM}kept: schema {name}{RESET}")
        else:
            try:
                connection.execute("SET search_path TO public")
                connection.execute(f"DROP SCHEMA {name} CASCADE")
            except Exception as error:  # noqa: BLE001 — cleanup must not mask a result
                print(f"{DIM}could not drop {name}: {error}{RESET}", file=sys.stderr)
        connection.close()


def ingest(settings: Settings, connection: psycopg.Connection, capture: Any) -> Any:
    """Publish a capture over the Kafka wire protocol and consume it back.

    Both ends of the broker, because the point of a demo is the shipped path: a
    normalizer called with a file would skip the half that has a wire format.
    """
    topic = f"helena-demo-{uuid.uuid4().hex[:8]}"
    normalizer = Normalizer.from_settings(settings)
    events = EventStore(connection=connection, identity=settings.identity)
    quarantine = Quarantine(connection=connection, identity=settings.identity)
    with BrokerProducer.from_settings(settings) as producer:
        producer.create_topic(topic)
        publish_capture(capture, producer, topic)
    with BrokerConsumer.from_settings(settings) as consumer:
        consumed = normalizer.ingest_messages(
            consume_ingest_topic(consumer, topic, idle_timeout=5.0), events, quarantine
        )
    connection.execute("FLUSH")
    return ingest_counts(
        capture=capture, consumed=consumed, events=events, quarantine=quarantine
    )


def load_suffixes(connection: psycopg.Connection, settings: Settings, *, when: datetime):
    return enrichment.load_public_suffix_list(
        connection,
        source_url=PUBLIC_SUFFIX_LIST_URL,
        redactor=Redactor.from_settings(settings),
        now=when,
    )


def load_feed(
    connection: psycopg.Connection,
    settings: Settings,
    *,
    when: datetime,
    raw: bytes | None = None,
    url: str = THREATFOX_EXPORT_URL,
):
    """One ThreatFox load, dated `when`.

    `now=` is what dates the snapshot, and dating it is the whole mechanism a
    demo needs: a snapshot's validity interval begins at `attempted_at`, so
    `when` decides whether a window is covered, and how far in the past it is
    decides whether the row reads `ok` or `stale`.
    """
    return enrichment.load_threatfox(
        connection,
        tenant=settings.identity.tenant,
        sensor=settings.identity.sensor,
        source_url=url,
        redactor=Redactor.from_settings(settings),
        raw=raw,
        now=when,
    )


def live_contexts(connection: psycopg.Connection, *, attempts: int = 12) -> list[str]:
    """The contexts the engine has computed, once it has caught up.

    Polled rather than read once: the views behind
    `helena_signal_host_context_live` are a streaming job, so a read taken the
    instant the last record lands can see one that is still behind.
    """
    for _ in range(attempts):
        connection.execute("FLUSH")
        rows = [
            context_id
            for (context_id,) in connection.execute(
                "SELECT context_id FROM helena_signal_host_context_live "
                "ORDER BY context_id"
            ).fetchall()
        ]
        if rows:
            return rows
        time.sleep(1.0)
    return []


def enrichment_rows(connection: psycopg.Connection) -> list[tuple]:
    """`(status, classification, count)` over the enriched context.

    `status` is what happened to the **lookup** and `classification` is what the
    snapshot **said**. `concept/instruction.md` §2 forbids collapsing them, so
    every demo that prints one prints both.
    """
    return connection.execute(
        "SELECT status, coalesce(classification, '(no snapshot consulted)'), count(*) "
        "FROM helena_analytical_enriched_context "
        "GROUP BY status, classification ORDER BY status, 2"
    ).fetchall()


def print_states(rows: list[tuple]) -> None:
    if not rows:
        print(f"    {DIM}(no entity rows){RESET}")
        return
    for status, classification, count in rows:
        colour = GREEN if classification not in ("no_match", "(no snapshot consulted)") else DIM
        mark = {"ok": GREEN, "stale": YELLOW, "failed": RED, "missing": YELLOW}.get(status, "")
        print(f"    {mark}{status:<9}{RESET} {colour}{classification:<28}{RESET} {count}")


class Scripted:
    """An OpenAI-compatible endpoint on the loopback interface, answering a script.

    A demo that needs a *specific* model answer — an invalid one, a `suspicious`
    one — cannot get it from a live model, and waiting for one to happen is not a
    demonstration. `tests/test_assessments.py` has the same device for the same
    reason; this is the demo's copy because a demo importing from `tests/` would
    make the test suite a runtime dependency of the demo directory.
    """

    def __init__(self, script: list[Any]) -> None:
        self.script = list(script)
        self.calls = 0
        endpoint = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self) -> None:  # noqa: N802 — the stdlib's name
                length = int(self.headers.get("Content-Length", 0))
                self.rfile.read(length)
                endpoint.calls += 1
                if not endpoint.script:
                    self.send_error(500, "the endpoint was called more than scripted")
                    return
                body = json.dumps(endpoint.script.pop(0)).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args: object) -> None:
                """The stdlib handler logs to stderr; a demo has its own channel."""

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        host, port = self.server.server_address[:2]
        return f"http://{host}:{port}/v1"

    def __enter__(self) -> Scripted:
        self.thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def answered(content: str, *, prompt: int = 40, completion: int = 20) -> dict:
    """One chat-completions response carrying `content`."""
    return {
        "id": "chatcmpl-demo",
        "object": "chat.completion",
        "model": "model-under-demo",
        "choices": [
            {"index": 0, "message": {"role": "assistant", "content": content},
             "finish_reason": "stop"}
        ],
        "usage": {
            "prompt_tokens": prompt,
            "completion_tokens": completion,
            "total_tokens": prompt + completion,
        },
    }


def said(**fields: Any) -> str:
    return json.dumps(fields)


def minutes(count: float) -> timedelta:
    return timedelta(minutes=count)


def utc(stamp: float) -> datetime:
    return datetime.fromtimestamp(stamp, timezone.utc)
