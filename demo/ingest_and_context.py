#!/usr/bin/env python3
"""Put the sample capture through ingest and context, and print what came out.

    demo/run-demo                      # brings the engine and broker up first
    uv run demo/ingest_and_context.py  # if they are already up

Six stages, each one the real code path rather than a narration of it: the
migrations are applied by `helena.migrations`, the records go over the Kafka
wire protocol through `helena.broker`, they are parsed and stamped by
`helena.normalizer`, and the contexts are read back out of views the engine
computed. Nothing here reimplements a stage in order to show it.

**It leaves nothing behind.** Everything lands in a schema of its own, named
for this run and dropped at the end, and the records go to their own topic. So
this can be run against a live deployment's engine without touching its data,
and it does not care what the store already holds -- including a store whose
migration ledger predates the declaration retrofit of task 17.

Maturity: experimental -- a demonstration, not a tested component. The paths it
drives are covered by tests/test_normalizer.py and tests/test_context.py; this
script is exercised by running it.
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import uuid
from pathlib import Path

import psycopg

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from helena import migrations  # noqa: E402
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

SAMPLE = ROOT / "data" / "ingest" / "flow-sample.jsonl"

BOLD, DIM, CYAN, GREEN, RESET = "\033[1m", "\033[2m", "\033[36m", "\033[32m", "\033[0m"
if not sys.stdout.isatty():
    BOLD = DIM = CYAN = GREEN = RESET = ""


def stage(number: int, title: str) -> None:
    print(f"\n{BOLD}{CYAN}[{number}/6]{RESET} {BOLD}{title}{RESET}")


def rule() -> None:
    print(DIM + "-" * 78 + RESET)


def show_one_raw_record(capture_file: Path) -> None:
    """The input contract, as the producer supplies it — and the flatten trap."""
    record = json.loads(capture_file.read_text().splitlines()[0])
    print(f"  {DIM}first record of the capture, exactly as it arrived:{RESET}")
    print(f"    id={record['id']}  {record['ip']['src']} -> {record['ip']['dst']}")
    answers = (record.get("dns") or {}).get("responses") or []
    if answers:
        print(f"  {DIM}its DNS answer chain — note where the address actually is:{RESET}")
        for index, answer in enumerate(answers):
            mark = f"  {GREEN}<- the resolved address, at index {index}{RESET}" if answer["rt"] == "A" else ""
            print(f"    [{index}] {answer['rt']:<6} {answer['qn']} -> {answer['rv']}{mark}")
    print(
        f"  {DIM}the record carries no tenant, sensor, schema version or capture"
        f" reference.{RESET}\n  {DIM}All four are assigned at ingestion, from"
        f" configuration.{RESET}"
    )


def print_table(rows: list[dict], columns: list[tuple[str, str]]) -> None:
    if not rows:
        print(f"  {DIM}(no rows){RESET}")
        return
    widths = {}
    for key, heading in columns:
        widths[key] = max(len(heading), *(len(str(r[key])) for r in rows))
    print("  " + "  ".join(h.ljust(widths[k]) for k, h in columns))
    print("  " + DIM + "  ".join("-" * widths[k] for k, _ in columns) + RESET)
    for row in rows:
        print("  " + "  ".join(str(row[k]).ljust(widths[k]) for k, _ in columns))


def main() -> int:
    print(f"{BOLD}MAESTRO HELENA — ingest and context, end to end{RESET}")
    rule()

    # ---- 1. configuration -------------------------------------------------
    stage(1, "Resolve configuration")
    settings = Settings.load()
    print(f"  tenant={settings.identity.tenant}  sensor={settings.identity.sensor}")
    print(f"  {DIM}identity comes from the environment and is never read from a record{RESET}")

    schema = f"helena_demo_{uuid.uuid4().hex[:12]}"
    topic = f"helena-demo-{uuid.uuid4().hex[:12]}"
    staging = Path(tempfile.mkdtemp(prefix="helena-demo-"))

    connection = psycopg.connect(
        settings.infrastructure.risingwave_dsn, autocommit=True, connect_timeout=10
    )
    try:
        # ---- 2. schema ----------------------------------------------------
        stage(2, "Apply the engine's schema into a private demo schema")
        connection.execute(f"CREATE SCHEMA {schema}")
        connection.execute(f"SET search_path TO {schema}")
        applied = migrations.apply(connection)
        print(f"  {len(applied)} migration(s) applied into {schema}")
        print(f"  {DIM}a schema of its own, so a live deployment's data is untouched{RESET}")

        # ---- 3. the capture ------------------------------------------------
        stage(3, "Stage the sample as a capture, addressed by its own hash")
        described = describe_capture(SAMPLE)
        capture_file = staging / f"{described.sha256}{CAPTURE_SUFFIX}"
        shutil.copyfile(SAMPLE, capture_file)
        capture = describe_capture(capture_file)
        print(f"  sha256      {capture.sha256}")
        print(f"  records     {capture.record_count}")
        print(f"  bytes       {capture.byte_size}")
        rule()
        show_one_raw_record(capture_file)

        # ---- 4. the wire ---------------------------------------------------
        stage(4, "Publish every record over the Kafka wire protocol")
        with BrokerProducer.from_settings(settings) as producer:
            producer.create_topic(topic)
            published = publish_capture(capture, producer, topic)
        print(f"  published {published} record(s) to {topic}")

        # ---- 5. ingestion --------------------------------------------------
        stage(5, "Consume, parse, stamp identity, store")
        normalizer = Normalizer.from_settings(settings)
        events = EventStore(connection=connection, identity=settings.identity)
        quarantine = Quarantine(connection=connection, identity=settings.identity)
        with BrokerConsumer.from_settings(settings) as consumer:
            consumed = normalizer.ingest_messages(
                consume_ingest_topic(consumer, topic), events, quarantine
            )
        counts = ingest_counts(
            capture=capture, consumed=consumed, events=events, quarantine=quarantine
        )
        print(f"  records in the capture   {counts.records:>4}   {DIM}(the file){RESET}")
        print(f"  consumed off the topic   {counts.consumed:>4}")
        print(f"  normalized into events   {counts.normalized:>4}")
        print(f"  quarantined              {counts.quarantine.quarantined:>4}")
        verdict = (
            f"{GREEN}every record reached the store{RESET}"
            if counts.complete
            else "INCOMPLETE — see the counters above"
        )
        print(f"  {verdict}")

        # ---- 6. context -----------------------------------------------------
        stage(6, "Read the contexts the engine computed")
        cursor = connection.execute(
            "SELECT * FROM helena_signal_host_context ORDER BY window_start"
        )
        names = [d.name for d in cursor.description]
        rows = [dict(zip(names, r)) for r in cursor.fetchall()]
        print(f"  {len(rows)} host context(s), 5-minute tumbling windows:\n")
        print_table(
            [
                {
                    "window": str(r["window_start"])[11:19],
                    "flows": r["flow_count"],
                    "sent": r["bytes_sent"],
                    "recv": r["bytes_received"],
                    "psent": r["packets_sent"],
                    "precv": r["packets_received"],
                }
                for r in rows
            ],
            [("window", "WINDOW"), ("flows", "FLOWS"), ("sent", "BYTES OUT"),
             ("recv", "BYTES IN"), ("psent", "PKTS OUT"), ("precv", "PKTS IN")],
        )
        print(
            f"\n  {DIM}bidirectional and never summed: a beacon and a download differ"
            f" by direction.{RESET}"
        )
        for r in rows:
            print(f"  {DIM}context_id {r['context_id'][:32]}…  agg={r['aggregation_version']}{RESET}")

        entities = connection.execute(
            "SELECT entity_type, count(*) AS n FROM helena_signal_context_entities"
            " GROUP BY entity_type ORDER BY n DESC"
        ).fetchall()
        print(f"\n  {BOLD}entities extracted{RESET} (the join target enrichment will use):")
        print_table(
            [{"t": t, "n": n} for t, n in entities],
            [("t", "TYPE"), ("n", "COUNT")],
        )

        scope = connection.execute(
            "SELECT count(*) FILTER (WHERE observed_as_flow_destination) AS contacted,"
            "       count(*) FILTER (WHERE NOT observed_as_flow_destination) AS named_only"
            "  FROM helena_signal_context_entities WHERE entity_type = 'address'"
        ).fetchone()
        print(
            f"\n  {BOLD}scope, which is what the composition rule turns on{RESET}\n"
            f"    addresses actually contacted        {scope[0]:>4}\n"
            f"    addresses seen only as a DNS answer {scope[1]:>4}\n"
            f"  {DIM}an address a host resolved but never talked to is a weaker"
            f" claim than one it did.{RESET}"
        )

        top = connection.execute(
            "SELECT entity_value, observed_flow_count, observed_bytes_sent,"
            "       observed_in_tls, observed_in_dns_query"
            "  FROM helena_signal_context_entities WHERE entity_type = 'domain'"
            " ORDER BY observed_bytes_sent DESC, entity_value LIMIT 8"
        ).fetchall()
        print(f"\n  {BOLD}busiest domains, with the layers that observed them{RESET}")
        print_table(
            [
                {
                    "d": v[:44],
                    "f": flows,
                    "b": sent,
                    "l": ("TLS " if tls else "") + ("DNS" if dns else ""),
                }
                for v, flows, sent, tls, dns in top
            ],
            [("d", "DOMAIN"), ("f", "FLOWS"), ("b", "BYTES OUT"), ("l", "OBSERVED IN")],
        )
        print(
            f"\n  {DIM}a name in TLS SNI was connected to; a name seen only in a DNS"
            f" query may never have been.{RESET}"
        )

        rule()
        print(f"{GREEN}{BOLD}done{RESET} — ingest and context both ran against the real engine.")
        print(f"{DIM}Nothing is enriched and nothing is assessed: that is D3 and D4.{RESET}")
        return 0
    finally:
        try:
            connection.execute("SET search_path TO public")
            connection.execute(f"DROP SCHEMA {schema} CASCADE")
            print(f"{DIM}cleaned up: schema {schema} dropped{RESET}")
        finally:
            connection.close()
            shutil.rmtree(staging, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
