#!/usr/bin/env python3
"""Compute context over a day of one network's traffic, and print what came out.

    uv run demo/context_over_a_day.py                 # the whole day
    uv run demo/context_over_a_day.py --files 12      # the first two hours
    uv run demo/context_over_a_day.py --captures DIR  # a different capture set

`demo/ingest_and_context.py` walks the pipeline end to end on 62 records of one
host, where every number is small enough to check by eye. This one asks a
different question — *what does a context look like when there is enough traffic
for the answer to be interesting* — against `data/demo/20250920`: 143 captures,
239 850 records, 3 199 source addresses, 23.97 hours.

The stages are the same real code paths, and nothing is reimplemented to show it:
`helena.migrations` applies the schema, the records cross the broker over the
Kafka wire protocol, `helena.normalizer` parses and stamps them, and every number
in stage 6 is read back out of a view the engine computed.

**It leaves nothing behind.** A schema named for the run, dropped at the end, and
a topic of its own — so it is safe against an engine that already holds data.

**The capture is not in the repository and this script does not put it there.**
It carries a whole network's traffic and no recorded clearance of the kind
`data/ingest/README.md` gives the 62-record sample, so `.gitignore` keeps
`data/demo/` out and this reads it where it lies.

Maturity: experimental — a demonstration, not a tested component. The paths it
drives are covered by tests/test_normalizer.py and tests/test_context.py.
"""

from __future__ import annotations

import argparse
import gzip
import shutil
import sys
import tempfile
import time
import uuid
from pathlib import Path

import psycopg

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from helena import migrations  # noqa: E402
from helena.broker import BrokerConsumer, BrokerProducer  # noqa: E402
from helena.config import Settings  # noqa: E402
from helena.context import ContextStore  # noqa: E402
from helena.normalizer import (  # noqa: E402
    CAPTURE_SUFFIX,
    Capture,
    EventStore,
    Normalizer,
    Quarantine,
    consume_ingest_topic,
    describe_capture,
    publish_capture,
    scan_captures,
)

DEFAULT_CAPTURES = ROOT / "data" / "demo" / "20250920"

# The same URL `scripts/load_public_suffix_list.py` holds, and for the reason it
# gives: a source URL in configuration would make swapping the list a deployment
# detail rather than a governed decision.
PUBLIC_SUFFIX_LIST_URL = "https://publicsuffix.org/list/public_suffix_list.dat"

# The broker's retention default (`docs/runbook.md` §3, `RETENTION`), written
# here because the batch size below is derived from it and a number derived from
# an unnamed constant is a number nobody can check.
BROKER_RETENTION = "5 minutes"

# How many records to put on a topic before draining it.
#
# **Publishing the whole day and then consuming it loses most of it**, and this
# was measured rather than reasoned about: 239 850 records published in 7.6 s and
# then ingested at ~360/s takes 11 minutes to drain, the broker's retention is 5
# minutes, and 43 858 records — 18 % — were obliterated before the consumer
# reached them. The run reported `INCOMPLETE` and named the number, which is what
# the counters are for, but a demo that ingests 82 % of its input is not
# demonstrating ingestion.
#
# The answer is not a longer retention. `docs/runbook.md` §3 says so in as many
# words — "do not reach for it: a longer retention would make a topic look like a
# store for a while" — and `concept/03-architecture.md` is what it is protecting:
# the broker is consume-once and restart-volatile, and a backlog on it is a
# durability assumption the design does not make. A sensor produces while the
# normalizer consumes; it does not hand over a day in one go.
#
# So the day is published and drained in batches, each its own topic, with the
# batch small enough that nothing waits near the window. 25 000 records is ~70 s
# of ingestion at the measured rate — a 4x margin — and costs one idle timeout
# per batch to notice the topic has gone quiet.
BATCH_RECORDS = 25_000

BOLD, DIM, CYAN, GREEN, YELLOW, RESET = (
    "\033[1m", "\033[2m", "\033[36m", "\033[32m", "\033[33m", "\033[0m"
)
if not sys.stdout.isatty():
    BOLD = DIM = CYAN = GREEN = YELLOW = RESET = ""

STAGES = 7

# `\r` overwrites a line on a terminal and concatenates into an unreadable one in
# a redirected log, so progress is a terminal-only affordance and the summary
# line after each stage is what a log gets.
LIVE = sys.stdout.isatty()


def progress_line(text: str) -> None:
    if LIVE:
        print(f"\r  {text}", end="", flush=True)


def stage(number: int, title: str) -> None:
    print(f"\n{BOLD}{CYAN}[{number}/{STAGES}]{RESET} {BOLD}{title}{RESET}")


def rule() -> None:
    print(DIM + "-" * 78 + RESET)


def note(text: str) -> None:
    print(f"  {DIM}{text}{RESET}")


def thousands(value: object) -> str:
    return f"{value:,}".replace(",", " ") if isinstance(value, int) else str(value)


def print_table(rows: list[dict], columns: list[tuple[str, str]], right: set[str] = frozenset()) -> None:
    if not rows:
        print(f"  {DIM}(no rows){RESET}")
        return
    cells = [{k: thousands(r[k]) for k, _ in columns} for r in rows]
    widths = {k: max(len(h), *(len(c[k]) for c in cells)) for k, h in columns}
    print("  " + "  ".join(
        (h.rjust(widths[k]) if k in right else h.ljust(widths[k])) for k, h in columns
    ))
    print("  " + DIM + "  ".join("-" * widths[k] for k, _ in columns) + RESET)
    for cell in cells:
        print("  " + "  ".join(
            (cell[k].rjust(widths[k]) if k in right else cell[k].ljust(widths[k]))
            for k, _ in columns
        ))


def query(connection: psycopg.Connection, sql: str, params: tuple = ()) -> list[dict]:
    cursor = connection.execute(sql, params)
    names = [d.name for d in cursor.description]
    return [dict(zip(names, row)) for row in cursor.fetchall()]


def stage_captures(
    source: Path, staging: Path, limit: int | None
) -> tuple[list[Capture], int]:
    """Decompress each `.ndjson.gz` into a capture named by its own sha256.

    The capture contract is unchanged and is not being bent to fit a compressed
    file: a capture is the bytes on disk and its name is their digest, so the
    digest is taken over what was *written out*, not over the archive. Two
    archives that decompress to the same records are the same capture, which is
    the property the name is for.
    """
    archives = sorted(source.glob("*.ndjson.gz"))
    if not archives:
        raise SystemExit(f"{source} holds no *.ndjson.gz")
    if limit is not None:
        archives = archives[:limit]
    archive_bytes = sum(archive.stat().st_size for archive in archives)
    for index, archive in enumerate(archives, start=1):
        scratch = staging / "staging.jsonl"
        with gzip.open(archive, "rb") as compressed, open(scratch, "wb") as plain:
            shutil.copyfileobj(compressed, plain)
        described = describe_capture(scratch)
        scratch.rename(staging / f"{described.sha256}{CAPTURE_SUFFIX}")
        if index % 20 == 0 or index == len(archives):
            progress_line(f"staged {index}/{len(archives)} captures")
    if LIVE:
        print()
    # Read the directory back rather than trusting what was just written: this is
    # the path a deployment uses, and it re-checks every name against its bytes.
    staged = scan_captures(staging)
    if len(staged) < len(archives):
        # Two archives decompressed to the same bytes, so they are one capture and
        # the second overwrote the first's file. That is the identity rule working,
        # but it is also a directory holding a duplicate, and a count that quietly
        # dropped one would make every total below disagree with the directory.
        print(f"  {len(archives) - len(staged)} archive(s) hold bytes another "
              f"archive already held; identical content is one capture, so they "
              f"are ingested once.")
    return sorted(staged.values(), key=lambda c: c.path.name), archive_bytes


def batch_captures(captures: list[Capture], limit: int) -> list[list[Capture]]:
    """Group captures into batches of at most `limit` records each.

    A capture is never split: it is the unit a record's provenance is expressed
    in, and half of one on a topic would be a batch boundary inside a digest. A
    single capture larger than `limit` is its own batch, because the alternative
    is refusing to ingest it.
    """
    batches: list[list[Capture]] = []
    current: list[Capture] = []
    held = 0
    for capture in captures:
        if current and held + capture.record_count > limit:
            batches.append(current)
            current, held = [], 0
        current.append(capture)
        held += capture.record_count
    if current:
        batches.append(current)
    return batches


def histogram(rows: list[dict], key: str, label: str, width: int = 40) -> None:
    peak = max((r[key] for r in rows), default=0)
    if peak == 0:
        return
    for row in rows:
        bar = "█" * max(1, round(width * row[key] / peak)) if row[key] else ""
        print(f"  {str(row[label]):<7} {thousands(row[key]):>9}  {CYAN}{bar}{RESET}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--captures", type=Path, default=DEFAULT_CAPTURES,
                        help=f"directory of *.ndjson.gz captures (default {DEFAULT_CAPTURES})")
    parser.add_argument("--files", type=int, default=None,
                        help="use only the first N captures, for a quicker run")
    parser.add_argument("--no-suffix-list", action="store_true",
                        help="skip fetching the Public Suffix List")
    arguments = parser.parse_args()

    if not arguments.captures.is_dir():
        raise SystemExit(
            f"{arguments.captures} is not a directory.\n"
            f"The day capture is deliberately not in the repository — see "
            f"demo/README.md — so point --captures at wherever it is held."
        )

    print(f"{BOLD}MAESTRO HELENA — context computation over a day of a network{RESET}")
    rule()

    # ---- 1. configuration --------------------------------------------------
    stage(1, "Resolve configuration")
    settings = Settings.load()
    print(f"  tenant={settings.identity.tenant}  sensor={settings.identity.sensor}")
    note("identity comes from the environment and is never read from a record")

    schema = f"helena_day_{uuid.uuid4().hex[:12]}"
    topic = f"helena-day-{uuid.uuid4().hex[:12]}"
    staging = Path(tempfile.mkdtemp(prefix="helena-day-"))

    connection = psycopg.connect(
        settings.infrastructure.risingwave_dsn, autocommit=True, connect_timeout=10
    )
    try:
        # ---- 2. schema -----------------------------------------------------
        stage(2, "Apply the engine's schema into a private demo schema")
        connection.execute(f"CREATE SCHEMA {schema}")
        connection.execute(f"SET search_path TO {schema}")
        applied = migrations.apply(connection)
        print(f"  {len(applied)} migration(s) applied into {schema}")
        note("a schema of its own, so a live deployment's data is untouched")

        # ---- 3. the captures ------------------------------------------------
        stage(3, "Stage the compressed captures, each addressed by its own hash")
        started = time.monotonic()
        captures, archive_bytes = stage_captures(
            arguments.captures, staging, arguments.files
        )
        records = sum(capture.record_count for capture in captures)
        staged_bytes = sum(capture.byte_size for capture in captures)
        print(f"  captures    {thousands(len(captures))}")
        print(f"  records     {thousands(records)}")
        print(f"  bytes       {thousands(staged_bytes)}  "
              f"{DIM}(decompressed, from {thousands(archive_bytes)} on disk — "
              f"{staged_bytes / archive_bytes:.0f}x){RESET}")
        print(f"  staged in   {time.monotonic() - started:.1f}s")
        note(f"{len(captures)} captures rather than one file: each ten-minute archive")
        note("is its own capture, so a record's provenance is a digest and an offset")
        note("within it.")

        # ---- 4+5. the wire and ingestion, interleaved -------------------------
        stage(4, "Publish and ingest, a batch of captures at a time")
        note(f"one INSERT per record — {thousands(records)} of them; this is the slow part")
        note(f"batched because the broker's retention is {BROKER_RETENTION}: see the")
        note("comment on BATCH_RECORDS for what a single backlog costs.")
        normalizer = Normalizer.from_settings(settings)
        events = EventStore(connection=connection, identity=settings.identity)
        quarantine = Quarantine(connection=connection, identity=settings.identity)
        batches = batch_captures(captures, BATCH_RECORDS)
        started = time.monotonic()
        published = consumed = 0
        with (
            BrokerProducer.from_settings(settings) as producer,
            BrokerConsumer.from_settings(settings) as consumer,
        ):
            for number, batch in enumerate(batches, start=1):
                batch_topic = f"{topic}-{number:03d}"
                producer.create_topic(batch_topic)
                for capture in batch:
                    published += publish_capture(capture, producer, batch_topic)
                consumed += normalizer.ingest_messages(
                    consume_ingest_topic(consumer, batch_topic), events, quarantine
                )
                rate = consumed / (time.monotonic() - started)
                remaining = (records - consumed) / rate if rate else 0
                progress_line(
                    f"batch {number}/{len(batches)}: {thousands(consumed)}/"
                    f"{thousands(records)} ingested ({rate:,.0f}/s, "
                    f"~{remaining / 60:.1f} min left)"
                )
        elapsed = time.monotonic() - started
        if LIVE:
            print()
        print(f"  {len(batches)} batch(es), {thousands(published)} published and "
              f"{thousands(consumed)} consumed in {elapsed / 60:.1f} min "
              f"({consumed / elapsed:,.0f}/s)")

        # ---- 5. the counters ---------------------------------------------------
        stage(5, "Reconcile what was stored against what the files hold")
        # What each counter can honestly be reconciled against.
        #
        # `consumed` is a property of the *run* — the messages the consumer read
        # off the topics — and a batch carries several captures, so there is no
        # per-capture consumed count and `ingest_counts` is not asked to invent
        # one. What is per-capture is `normalized + quarantined == records`, read
        # back out of the engine's own two counter views in one query each rather
        # than in 143 round trips. The broker is consume-once, so the denominator
        # is the retained files and never the topics.
        connection.execute("FLUSH")
        by_capture = {capture.sha256: capture.record_count for capture in captures}
        normalized_by = {
            row["capture_sha256"]: row["normalized"]
            for row in query(connection,
                "SELECT capture_sha256, normalized FROM helena_ingest_counts"
                " WHERE tenant = %s AND sensor = %s",
                (settings.identity.tenant, settings.identity.sensor))
        }
        quarantined_by = {
            row["capture_sha256"]: row["quarantined"]
            for row in query(connection,
                "SELECT capture_sha256, sum(quarantined)::BIGINT AS quarantined"
                "  FROM helena_ingest_quarantine_counts"
                " WHERE tenant = %s AND sensor = %s GROUP BY capture_sha256",
                (settings.identity.tenant, settings.identity.sensor))
        }
        normalized = sum(normalized_by.values())
        quarantined = sum(quarantined_by.values())
        unreconciled = [
            digest[:12] for digest, held in by_capture.items()
            if normalized_by.get(digest, 0) + quarantined_by.get(digest, 0) != held
        ]
        print(f"  records in the captures  {thousands(records):>9}   {DIM}(the files){RESET}")
        print(f"  consumed off the topics  {thousands(consumed):>9}")
        print(f"  normalized into events   {thousands(normalized):>9}")
        print(f"  quarantined              {thousands(quarantined):>9}")
        if consumed != records:
            print(f"  {YELLOW}INCOMPLETE — {thousands(records - consumed)} record(s) "
                  f"never came off a topic. The broker is not a store: a record "
                  f"published and not read inside {BROKER_RETENTION} is gone."
                  f"{RESET}")
        elif unreconciled:
            print(f"  {YELLOW}{len(unreconciled)} capture(s) did not reconcile: "
                  f"{', '.join(unreconciled[:5])}{RESET}")
        else:
            print(f"  {GREEN}every record of all {len(captures)} captures reached "
                  f"the store, and each capture reconciles on its own{RESET}")
        if quarantined:
            for row in query(connection,
                             "SELECT reason, count(*) AS n FROM helena_ingest_quarantine"
                             " GROUP BY reason ORDER BY n DESC"):
                print(f"    {row['reason']:<20} {thousands(row['n']):>8}")
            note("this capture refused 100% of its records until the flow-record")
            note("contract's requiredness was re-measured over both captures — see")
            note("`helena.normalizer`, 'Which fields are required'.")

        # ---- 6. context --------------------------------------------------------
        stage(6, "Read the contexts the engine computed")
        connection.execute("FLUSH")

        shape = query(connection,
            "SELECT count(*) AS contexts, count(DISTINCT host) AS hosts,"
            "       count(DISTINCT window_start) AS windows,"
            "       min(window_start) AS first_window, max(window_start) AS last_window"
            "  FROM helena_signal_host_context")[0]
        print(f"  {thousands(shape['contexts'])} contexts — one row per host per "
              f"five-minute window in which that host sent something")
        if not shape["contexts"]:
            raise SystemExit(
                "  no contexts were computed. Every record was quarantined, or the "
                "capture holds none — stage 5's counters say which."
            )
        print(f"    hosts    {thousands(shape['hosts']):>9}")
        print(f"    windows  {thousands(shape['windows']):>9}   "
              f"{DIM}{shape['first_window']} … {shape['last_window']}{RESET}")
        density = shape["contexts"] / (shape["hosts"] * shape["windows"])
        note(f"{density:.1%} of the host×window grid is populated — a context exists")
        note(f"only where there was traffic, so this is not "
             f"{thousands(shape['hosts'])} × {thousands(shape['windows'])} rows.")

        print(f"\n  {BOLD}the day, by hour{RESET} {DIM}(flows, summed over every host){RESET}")
        histogram(query(connection,
            "SELECT to_char(window_start, 'HH24:00') AS hour,"
            "       sum(flow_count)::BIGINT AS flows"
            "  FROM helena_signal_host_context GROUP BY 1 ORDER BY 1"), "flows", "hour")

        print(f"\n  {BOLD}busiest hosts{RESET}")
        print_table(query(connection,
            "SELECT host, count(*)::BIGINT AS windows, sum(flow_count)::BIGINT AS flows,"
            "       sum(bytes_sent)::BIGINT AS sent, sum(bytes_received)::BIGINT AS recv"
            "  FROM helena_signal_host_context"
            " GROUP BY host ORDER BY flows DESC LIMIT 10"),
            [("host", "HOST"), ("windows", "WINDOWS"), ("flows", "FLOWS"),
             ("sent", "BYTES OUT"), ("recv", "BYTES IN")],
            right={"windows", "flows", "sent", "recv"})
        note("`helena_signal_host_context` groups by src_address and filters nothing,")
        note("so multicast and broadcast senders are hosts here too. On 62 records of")
        note("one endpoint that never came up; on a LAN it is most of the top of the")
        note("table, and any reader of this view has to know it.")

        print(f"\n  {BOLD}direction, which a single total would hide{RESET}")
        print_table(query(connection,
            "SELECT host, sum(flow_count)::BIGINT AS flows,"
            "       sum(bytes_sent)::BIGINT AS sent, sum(bytes_received)::BIGINT AS recv,"
            "       round(sum(bytes_received)::NUMERIC"
            "             / greatest(sum(bytes_sent), 1), 1) AS ratio"
            "  FROM helena_signal_host_context GROUP BY host"
            " HAVING sum(bytes_sent) > 100000 ORDER BY ratio DESC LIMIT 5"),
            [("host", "HOST"), ("flows", "FLOWS"), ("sent", "BYTES OUT"),
             ("recv", "BYTES IN"), ("ratio", "IN/OUT")],
            right={"flows", "sent", "recv", "ratio"})
        note("a host pulling back far more than it sends is downloading; one sending")
        note("steadily and receiving nothing — the zero-ratio rows — is not talking to")
        note("anything that answers, which on a LAN is usually broadcast or discovery")
        note("rather than anything sinister. Summing the two into one 'bytes' column")
        note("would erase the only thing that tells those two shapes apart.")

        print(f"\n  {BOLD}entities extracted{RESET} {DIM}(the join target enrichment will use){RESET}")
        print_table(query(connection,
            "SELECT entity_type AS t,"
            "       count(*) FILTER (WHERE entity_value IS NOT NULL) AS n,"
            "       count(*) FILTER (WHERE entity_value IS NULL) AS empty"
            "  FROM helena_signal_context_entities GROUP BY 1 ORDER BY n DESC"),
            [("t", "TYPE"), ("n", "COUNT"), ("empty", "NULL VALUE")], right={"n", "empty"})

        blank = query(connection,
            "SELECT count(*) AS n FROM helena_signal_context_entities"
            " WHERE entity_value IS NULL")[0]["n"]
        if blank:
            print(f"\n  {YELLOW}{thousands(blank)} of those rows have a NULL "
                  f"entity_value, which migration 0010 exists to make impossible."
                  f" Something reintroduced one.{RESET}")
        else:
            note("the NULL VALUE column is zero, and it did not start that way. Before")
            note("migration 0010 this capture produced 1 043 valueless entities: four")
            note("branches of the entity view read tls.sni, tls.ja3, tls.ja4 and a")
            note("request uri without a NULL guard, which was safe only while the")
            note("flow-record contract required all four. A flow captured")
            note("mid-connection has TLS records and no handshake, so there is no name")
            note("to extract — and because the rows below group by entity_value, every")
            note("such flow in a context collapsed into one phantom row carrying their")
            note("combined traffic and joinable to nothing.")

        scope = query(connection,
            "SELECT count(*) FILTER (WHERE observed_as_flow_destination) AS contacted,"
            "       count(*) FILTER (WHERE NOT observed_as_flow_destination) AS named_only"
            "  FROM helena_signal_context_entities WHERE entity_type = 'address'")[0]
        print(f"\n  {BOLD}scope, which is what the composition rule turns on{RESET}")
        print(f"    addresses actually contacted        {thousands(scope['contacted']):>9}")
        print(f"    addresses seen only as a DNS answer {thousands(scope['named_only']):>9}")
        note("an address a host resolved but never talked to is a weaker claim than one")
        note("it connected to, and a row that could not tell those apart could not")
        note("support the rule.")

        print(f"\n  {BOLD}busiest domains, with the layers that observed them{RESET}")
        print_table([
            {"d": row["entity_value"][:44], "f": row["observed_flow_count"],
             "b": row["observed_bytes_sent"],
             "l": ("TLS " if row["observed_in_tls"] else "")
                  + ("DNS" if row["observed_in_dns_query"] else "")}
            # Summed across contexts. A row of `helena_signal_context_entities`
            # is one (entity, context) pair, so without the GROUP BY a name seen
            # in eight windows is eight rows and the table lists it eight times.
            for row in query(connection,
                "SELECT entity_value,"
                "       sum(observed_flow_count)::BIGINT  AS observed_flow_count,"
                "       sum(observed_bytes_sent)::BIGINT  AS observed_bytes_sent,"
                "       bool_or(observed_in_tls)          AS observed_in_tls,"
                "       bool_or(observed_in_dns_query)    AS observed_in_dns_query"
                "  FROM helena_signal_context_entities"
                " WHERE entity_type = 'domain' AND entity_value IS NOT NULL"
                " GROUP BY entity_value"
                " ORDER BY observed_bytes_sent DESC, entity_value LIMIT 10")],
            [("d", "DOMAIN"), ("f", "FLOWS"), ("b", "BYTES OUT"), ("l", "OBSERVED IN")],
            right={"f", "b"})
        note("a name in TLS SNI was connected to; a name seen only in a DNS query may")
        note("never have been. That is what the rendering gets instead of per-domain")
        note("byte counts, because a name carries the traffic of the flows that")
        note("*mentioned* it.")

        # ---- registrable domains, if the list can be fetched -----------------
        if not arguments.no_suffix_list:
            print(f"\n  {BOLD}registrable domains{RESET} "
                  f"{DIM}(the Public Suffix List, migration 0008){RESET}")
            try:
                from helena.enrichment import FAILED, load_public_suffix_list  # noqa: PLC0415
                from helena.observability import Redactor  # noqa: PLC0415
                load = load_public_suffix_list(
                    connection,
                    source_url=PUBLIC_SUFFIX_LIST_URL,
                    redactor=Redactor.from_settings(settings),
                )
                if load.status == FAILED:
                    raise RuntimeError(f"{load.failure_reason}: {load.failure_detail}")
                connection.execute("FLUSH")
                print(f"    {thousands(load.rule_count)} suffix rules, snapshot "
                      f"{load.snapshot_version}")
                collapse = query(connection,
                    "SELECT count(DISTINCT observed_name) AS names,"
                    "       count(DISTINCT observed_name) FILTER ("
                    "           WHERE registrable_domain IS NOT NULL"
                    "       ) AS derived,"
                    "       count(DISTINCT registrable_domain) AS registrable"
                    "  FROM helena_signal_domain_registrable")[0]
                print(f"    {thousands(collapse['derived'])} of "
                      f"{thousands(collapse['names'])} distinct names collapse to "
                      f"{thousands(collapse['registrable'])} registrable domains")
                print_table(query(connection,
                    "SELECT registrable_domain_status AS s,"
                    "       count(DISTINCT observed_name) AS n"
                    "  FROM helena_signal_domain_registrable"
                    " GROUP BY 1 ORDER BY n DESC"),
                    [("s", "STATUS"), ("n", "NAMES")], right={"n"})
                note("a name that *is* a public suffix has no registrable domain to")
                note("derive, and neither has one the list does not cover — two")
                note("different answers, and the view says which rather than")
                note("returning the name itself and hoping nobody notices.")
                print_table(query(connection,
                    "SELECT registrable_domain AS d,"
                    "       count(DISTINCT observed_name) AS n"
                    "  FROM helena_signal_domain_registrable"
                    " WHERE registrable_domain IS NOT NULL"
                    " GROUP BY 1 ORDER BY n DESC, d LIMIT 8"),
                    [("d", "REGISTRABLE DOMAIN"), ("n", "NAMES")], right={"n"})
                note("two names under one registrable domain are one owner and two")
                note("hosts, and a feed that lists one of the names means something")
                note("quite different from a feed that lists the domain. Over the")
                note("whole day the table's second row is `com.akadns.net`, a CDN's")
                note("own public suffix — every name under one of those belongs to a")
                note("different customer, which is why the list decides where the")
                note("boundary is instead of a count of labels.")
            except Exception as failure:  # noqa: BLE001 — a demo, not a component
                print(f"    {YELLOW}skipped: {type(failure).__name__}: {failure}{RESET}")
                note("the list is fetched over the network; --no-suffix-list skips it.")

        # ---- 7. the retention boundary ------------------------------------------
        stage(7, "The retention boundary, which this capture is entirely outside")
        rejections = ContextStore(
            connection=connection, identity=settings.identity
        ).rejections()
        retained = query(connection,
            "SELECT count(*) AS n FROM helena_signal_host_context_retained")[0]["n"]
        print(f"  retention horizon            {rejections.horizon}")
        print(f"  contexts aggregated          {thousands(rejections.contexts):>9}")
        print(f"  contexts outside it          "
              f"{thousands(rejections.contexts_outside_boundary):>9}")
        print(f"  records aggregated           {thousands(rejections.records):>9}")
        print(f"  records outside it           "
              f"{thousands(rejections.records_outside_boundary):>9}"
              f"   {DIM}({rejections.rate:.1%} — the rejection rate){RESET}")
        print(f"  rows in the retained view    {thousands(retained):>9}")
        print()
        note(f"The capture was taken on {shape['first_window'].date()}. Everything in it")
        note("is older than the 24-hour horizon, so the retained view is empty and")
        note("nothing here can be frozen or cited — `freeze` raises")
        note("ContextOutsideRetention rather than copying a row.")
        print()
        note("This is the boundary working, not the demo failing: the signal layer")
        note("computed every context, and the layer above it dropped all of them for")
        note("being older than a day. Contexts are still visible below the boundary")
        note("(everything stage 6 printed came from there) and the state above it is")
        note("gone, which is the point of putting the filter in a materialized view.")
        note("A demo of the boundary passing traffic through needs a capture from")
        note("today; this one can only show it holding.")

        rule()
        print(f"{GREEN}{BOLD}done{RESET} — {thousands(shape['contexts'])} contexts over "
              f"{thousands(shape['hosts'])} hosts, computed by the engine from "
              f"{thousands(records)} records.")
        note("Nothing is enriched and nothing is assessed: that is D3 and D4.")
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
