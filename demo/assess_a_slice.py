#!/usr/bin/env python3
"""Put one capture through all six stages, twice, and print what a consumer reads.

    demo/run-demo 3                    # brings the engine and broker up first
    uv run demo/assess_a_slice.py      # if they are already up
    uv run demo/assess_a_slice.py --help

Demo 1 shows ingest and context. Demo 2 shows context at the scale of a network
day. **Neither shows an assessment**, because neither enriches: until D3-D7 the
stages after context did not exist. This one runs all six of `concept/01`'s
stages -- ingest, context, enrich, triage, analyse, emit -- over the shipped code
paths, against the live model endpoint `.env` configures, and drains the output
topic at the end so what is printed last is what a consumer actually reads.

**It runs the same capture twice, and the contrast is the demonstration.**

  Pass A -- the feed exactly as ThreatFox published it minutes ago. Ordinary
            traffic against a two-day sighting window of a few thousand
            indicators matches nothing, so this is what the honest answer looks
            like: `no_match` everywhere, and a verdict that says so.
  Pass B -- the same capture and the same feed, with **one entry repointed at a
            domain this capture really contains**, so the join matches and the
            escalation path runs: triage escalates and the analyst is reached.

**The model is live, so pass B's ending is not fixed.** Observed both ways: a
`suspicious` verdict citing the stored evidence row, and -- from the same model
on another run -- a `suspicious` label with NO citation three attempts running,
which the contract refused every time and which reached the topic as a typed
`schema_invalid` failure with no verdict. The second is not the demo breaking; it
is `concept/01`'s CLAIM-2 happening for real, and neither ending is scripted.

Pass B's indicator is planted and the output says so every time it is printed.
It is the device `tests/test_end_to_end.py`, `tests/test_rendering.py` and
`tests/test_enriched.py` all use for the same reason: the extract names real
indicators and the capture is one host's routine traffic, so nothing in one
appears in the other -- realistic, and useless for showing a join.

## Why the capture is re-stamped into the current window

`data/ingest/flow-sample.jsonl` is dated 2024-06-01 and the retention boundary
(`sql/migrations/0009_retention_boundary.sql`) does not show a context that old.
Every record is therefore re-stamped into the window this run falls in -- `ts` is
a field of the input contract, so moving it is a contract-permitted change to a
real record, and `tests/test_end_to_end.py::current_window` says the same.

**This is what makes the run time-correct rather than merely convenient.** The
snapshot is fetched now and dated a minute before the window, so the interval
`helena_reference_feed_snapshot_validity` derives really does cover the context
the join asks about (`sql/migrations/0015_enriched_context.sql`). Pointing this
at an archived capture would not work and must not be made to: a 2025 capture
against a 2026 snapshot matches no validity interval, every entity comes back
unenriched, and no request can be built at all -- see `docs/acceptance.md`,
finding 1, and `docs/evaluation-corpus.md` §4 on why retroactive enrichment of an
archived capture is impossible rather than merely stale.

## What it does not show

**Nothing about whether the verdicts are right.** There is no labelled corpus,
so accuracy, recall, false-positive rate, escalation rate, latency and cost are
not claimable and are not claimed -- `docs/acceptance.md` is the checklist and
this script demonstrates the same four properties it does, no more.

**No live provider lookup.** The analyst runs with `provider_tools=()`, so it
reasons over stored evidence and cites it, and nothing here spends the daily
quota `docs/evaluation-corpus.md` sizes. The tool layer is exercised by
`tests/test_tools.py` and `tests/test_providers.py`.

**One host, one window.** 62 records of the maintainer's own traffic. Demo 2 is
where volume lives; this is where the assessment does.

Maturity: experimental -- a demonstration, not a tested component. The paths it
drives are covered by `tests/test_end_to_end.py`, which asserts over them; this
script is exercised by running it.
"""

from __future__ import annotations

import argparse
import io
import json
import shutil
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import psycopg

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from helena import (  # noqa: E402
    agents,
    analyst,
    budgets,
    disclosure,
    enrichment,
    migrations,
    observability,
    orchestration,
    policy,
    rendering,
    sink,
    triage,
)
from helena import hosts  # noqa: E402
from helena.agents import ModelClient  # noqa: E402
from helena.broker import BrokerConsumer, BrokerProducer  # noqa: E402
from helena.config import Settings  # noqa: E402
from helena.contracts.v1 import (  # noqa: E402
    CONTRACT_VERSION,
    AgentFailure as contract_failure,
    SCHEDULED_TRIAGE,
    AgentRequest,
    RequestVersions,
)
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
from helena.policy import v1 as policy_v1  # noqa: E402
from helena.rendering import v1 as rendering_v1  # noqa: E402
from helena.taxonomy import ANALYST, TRIAGE  # noqa: E402

SAMPLE = ROOT / "data" / "ingest" / "flow-sample.jsonl"

#: The same two URLs `scripts/load_threatfox.py` and `demo/context_over_a_day.py`
#: hold. Neither carries a credential: the recent export answers 200 with nothing
#: attached, which `docs/runbook.md` §14 measures rather than assumes.
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


def current_window() -> float:
    """The start of the tumbling window `now` falls in, as a timestamp."""
    return float(int(time.time() // WINDOW_SECONDS) * WINDOW_SECONDS)


def restamped(source: Path, destination: Path, *, window: float) -> Path:
    """`source` with every record's `ts` moved into `window`, addressed by its hash.

    Written under its own sha256 because that is what a capture is
    (`docs/decisions/0010-capture-identity.md`): the re-stamped file is a
    different capture from the one on disk and is addressed as one.
    """
    records = [json.loads(line) for line in source.read_bytes().splitlines() if line]
    staged = destination / "restamped.jsonl"
    staged.write_bytes(
        b"".join(
            json.dumps({**record, "ts": window + 1}).encode() + b"\n"
            for record in records
        )
    )
    described = describe_capture(staged)
    final = destination / f"{described.sha256}{CAPTURE_SUFFIX}"
    shutil.move(staged, final)
    return final


def planted(raw: bytes, entity_value: str, ioc_type: str = "domain") -> bytes:
    """The fetched export with one entry repointed at an entity the capture has.

    Exactly `tests/test_end_to_end.py::targeted`. The first entry by key order is
    the one moved, so which entry it is does not depend on what the feed happened
    to publish this minute.
    """
    document = json.loads(raw)
    key = sorted(document)[0]
    document[key][0]["ioc_type"] = ioc_type
    document[key][0]["ioc_value"] = entity_value
    return json.dumps(document).encode()


def first_domain(connection: psycopg.Connection) -> str | None:
    row = connection.execute(
        "SELECT entity_value FROM helena_signal_context_entities "
        "WHERE entity_type = 'domain' ORDER BY entity_value LIMIT 1"
    ).fetchone()
    return row[0] if row else None


def snapshot_at(
    connection: psycopg.Connection, window_start: datetime, *, tenant: str, sensor: str
) -> str | None:
    """The snapshot the enrichment join matched at `window_start`, or `None`.

    Reads the validity view the join itself reads rather than taking today's
    snapshot, which is `concept/02`'s "replay joins the snapshot current at event
    time, not today's" applied to the request.

    `RequestVersions.enrichment_snapshot_version` is **one** identifier, so two
    sources with two current snapshots would have no single value to record. That
    is an open contract question (`docs/acceptance.md`, finding 1) and this demo
    loads one source, so it does not arise here -- but it is why this returns
    rather than picks, and why a second source would need the question answered
    first.
    """
    rows = connection.execute(
        "SELECT source_id, snapshot_version FROM helena_reference_feed_snapshot_validity "
        "WHERE tenant = %s AND sensor = %s AND valid_from <= %s "
        "AND (valid_to IS NULL OR valid_to > %s) ORDER BY source_id",
        (tenant, sensor, window_start, window_start),
    ).fetchall()
    if len(rows) > 1:
        raise SystemExit(
            f"{len(rows)} sources hold a snapshot valid at {window_start}, and "
            f"RequestVersions.enrichment_snapshot_version is one identifier. "
            f"See docs/acceptance.md finding 1 -- this is the open contract "
            f"question, and picking one here would record a version that "
            f"describes part of the join."
        )
    return rows[0][1] if rows else None


def live_contexts(connection: psycopg.Connection, *, attempts: int = 10) -> list[str]:
    """The contexts the engine has computed, once it has caught up.

    Polled rather than read once: the materialized views behind
    `helena_signal_host_context_live` are a streaming job, so a read taken the
    instant after the last record lands can see a view that is still behind.
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


def aggregation_version(
    connection: psycopg.Connection, context_id: str, *, tenant: str, sensor: str
) -> str:
    """The aggregation version as the engine stamped it, not the Python constant.

    A request recording the constant while the engine aggregated under another
    would record a version the context does not have.
    """
    (version,) = connection.execute(
        "SELECT aggregation_version FROM helena_signal_host_context_live "
        "WHERE tenant = %s AND sensor = %s AND context_id = %s",
        (tenant, sensor, context_id),
    ).fetchone()
    return version


def triage_request(
    projection: rendering.ContextProjection,
    *,
    connection: psycopg.Connection,
    settings: Settings,
    snapshot: str,
    normalization_snapshot: str,
    budget: rendering.RenderingBudget,
    prompt: Any,
    budget_policy: Any,
) -> AgentRequest:
    """The triage request for one live context, versions and all.

    **Nothing in `src/helena` builds this, and that is a finding rather than an
    oversight this script routes around.** `helena.orchestration.assess` is
    entered with a request; the scheduler that would turn "every live context"
    into requests is not part of the first version (`concept/01`: the analyst is
    served indirectly, through the output topic). So this is the demo's, written
    the same way `tests/test_end_to_end.py` writes its own and for the same
    reason -- take every version from the thing that produced it, and never
    invent one the store cannot supply.
    """
    rendered = rendering_v1.render(
        projection, hosts.load().attributes_for(projection.host), budget
    )
    return AgentRequest(
        tenant=projection.tenant,
        sensor=projection.sensor,
        emitter=TRIAGE,
        host=projection.host,
        window_start=projection.statistics.window_start,
        window_end=projection.statistics.window_end,
        context_id=projection.context_id,
        context_version=projection.context_version,
        trigger=SCHEDULED_TRIAGE,
        rendering=rendered,
        budgets=budget_policy.for_emitter(TRIAGE),
        versions=RequestVersions(
            prompt_version=prompt.version,
            schema_version=CONTRACT_VERSION,
            rendering_version=rendering_v1.RENDERING_VERSION,
            taxonomy_version="v1",
            enrichment_snapshot_version=snapshot,
            normalization_snapshot_version=normalization_snapshot,
            policy_version=policy_v1.POLICY_VERSION,
            aggregation_version=aggregation_version(
                connection,
                projection.context_id,
                tenant=projection.tenant,
                sensor=projection.sensor,
            ),
            model_requested=settings.triage.model,
        ),
    )


@dataclass
class PassResult:
    """What one pass produced, for the comparison printed at the end."""

    label: str
    planted_entity: str | None
    snapshot_version: str | None
    claims: int
    contexts: int
    verdicts: tuple[str, ...]
    escalated: int
    failures: tuple[str, ...]
    citations: int
    emitted: int
    #: Contexts cleared without a model. NOT a failure and never counted as one.
    gated: int = 0


def run_pass(
    *,
    settings: Settings,
    label: str,
    plant: bool,
    export: bytes,
    keep: bool,
) -> PassResult:
    """One capture through all six stages, in a schema and topics of its own."""
    banner(f"{label}")

    identity = settings.identity
    redactor = Redactor.from_settings(settings)
    schema = f"helena_demo_{uuid.uuid4().hex[:12]}"
    ingest_topic = f"helena-demo-ingest-{uuid.uuid4().hex[:8]}"
    output_topic = f"helena-demo-output-{uuid.uuid4().hex[:8]}"
    staging = Path(tempfile.mkdtemp(prefix="helena-demo-"))
    window = current_window()
    window_start = datetime.fromtimestamp(window, tz=timezone.utc)
    log = io.StringIO()

    # The policy objects a deployment loads once and hands to every run, loaded
    # from the committed configuration rather than invented here.
    triage_prompt = triage.version("v1")
    analyst_prompt = analyst.version("v1")
    budget_policy = budgets.load()
    render_budget = rendering.budget()
    gate = policy.triage_gate()

    connection = psycopg.connect(
        settings.infrastructure.risingwave_dsn, autocommit=True, connect_timeout=10
    )
    try:
        stage(1, "A schema of this run's own, with the shipped migrations in it")
        connection.execute(f"CREATE SCHEMA {schema}")
        connection.execute(f"SET search_path TO {schema}")
        applied = migrations.apply(connection)
        print(f"  {len(applied)} migration(s) into {schema}")
        print(f"  window       {window_start:%Y-%m-%d %H:%M:%S} UTC")
        print(f"  {DIM}a live deployment's data is untouched by any of this{RESET}")

        stage(2, "The normalization reference — the Public Suffix List")
        suffixes = enrichment.load_public_suffix_list(
            connection,
            source_url=PUBLIC_SUFFIX_LIST_URL,
            redactor=redactor,
            now=window_start - timedelta(minutes=2),
        )
        if not suffixes.snapshot_version:
            raise SystemExit(f"the suffix list did not load: {suffixes.failure_reason}")
        print(f"  snapshot     {suffixes.snapshot_version[:16]}…")
        print(f"  {DIM}a registrable domain is derived against this, not guessed{RESET}")

        stage(3, "The capture, re-stamped into this window and addressed by its hash")
        capture_file = restamped(SAMPLE, staging, window=window)
        capture = describe_capture(capture_file)
        print(f"  sha256       {capture.sha256}")
        print(f"  records      {capture.record_count}")
        print(f"  {DIM}`ts` is an input-contract field; moving it is permitted{RESET}")

        stage(4, "Ingest — over the Kafka wire protocol, and back off it")
        normalizer = Normalizer.from_settings(settings)
        events = EventStore(connection=connection, identity=identity)
        quarantine = Quarantine(connection=connection, identity=identity)
        with BrokerProducer.from_settings(settings) as producer:
            producer.create_topic(ingest_topic)
            published = publish_capture(capture, producer, ingest_topic)
        with BrokerConsumer.from_settings(settings) as consumer:
            consumed = normalizer.ingest_messages(
                consume_ingest_topic(consumer, ingest_topic, idle_timeout=5.0),
                events,
                quarantine,
            )
        connection.execute("FLUSH")
        counts = ingest_counts(
            capture=capture, consumed=consumed, events=events, quarantine=quarantine
        )
        print(f"  published    {published}")
        print(f"  consumed     {counts.consumed}")
        print(f"  normalized   {counts.normalized}")
        print(f"  quarantined  {counts.quarantine.quarantined}")
        print(
            f"  {GREEN}every record reached the store{RESET}"
            if counts.complete
            else f"  {RED}INCOMPLETE{RESET} — the counters above do not reconcile"
        )

        stage(5, "Context — what the engine aggregated while the records landed")
        contexts = live_contexts(connection)
        entity = first_domain(connection)
        print(f"  contexts     {len(contexts)}")
        print(f"  first domain {entity}")
        if not contexts:
            raise SystemExit("the engine computed no live context; nothing to assess")

        stage(6, "Enrich — the snapshot, dated before the window it must cover")
        raw = export
        planted_entity = None
        if plant:
            if entity is None:
                raise SystemExit("no domain entity to plant an indicator against")
            planted_entity = entity
            raw = planted(export, entity)
            print(f"  {YELLOW}PLANTED{RESET}  one entry repointed at {BOLD}{entity}{RESET}")
            print(f"  {DIM}so the join matches; this is not a real listing{RESET}")
        load = enrichment.load_threatfox(
            connection,
            tenant=identity.tenant,
            sensor=identity.sensor,
            source_url=THREATFOX_EXPORT_URL,
            redactor=redactor,
            raw=raw,
            now=window_start - timedelta(minutes=1),
        )
        connection.execute("FLUSH")
        if load.outcome == enrichment.FAILED:
            raise SystemExit(f"the feed did not load: {load.failure_reason}")
        snapshot = snapshot_at(
            connection, window_start, tenant=identity.tenant, sensor=identity.sensor
        )
        claims = int((load.counts or {}).get("claims_stored") or 0)
        print(f"  snapshot     {(snapshot or '—')[:16]}…")
        print(f"  claims       {claims}")
        # `status` and `classification` are two different facts and the view
        # keeps them apart on purpose: `status` is what happened to the LOOKUP
        # (ok / stale / failed / missing) and `classification` is what the
        # snapshot SAID -- a claim, or `no_match` where it was consulted and said
        # nothing, or NULL where there was no snapshot to consult. Collapsing
        # them is what `concept/instruction.md` §2 forbids, so both are printed.
        statuses = connection.execute(
            "SELECT status, coalesce(classification, '(no snapshot consulted)'), "
            "count(*) FROM helena_analytical_enriched_context "
            "GROUP BY status, classification ORDER BY status, 2"
        ).fetchall()
        print(f"  {DIM}enriched-context rows — lookup status x what it said:{RESET}")
        for status, classification, count in statuses:
            mark = GREEN if classification not in ("no_match", "(no snapshot consulted)") else DIM
            print(f"    {status:<9} {mark}{classification:<28}{RESET} {count}")
        if snapshot is None:
            raise SystemExit(
                "no snapshot is valid at this window, so no request can be built "
                "at all — docs/acceptance.md finding 1"
            )

        stage(7, "Render and build the request — the scheduler this repo does not have")
        store = rendering.RenderingStore(connection=connection, identity=identity)
        projections = tuple(store.project(context_id) for context_id in contexts)
        requests = tuple(
            triage_request(
                projection,
                connection=connection,
                settings=settings,
                snapshot=snapshot,
                normalization_snapshot=suffixes.snapshot_version,
                budget=render_budget,
                prompt=triage_prompt,
                budget_policy=budget_policy,
            )
            for projection in projections
        )
        rendered = requests[0].rendering
        size = sum(len(section.body) for section in rendered.sections)
        print(f"  requests     {len(requests)}")
        print(f"  rendering    {rendered.version}, {len(rendered.sections)} section(s), "
              f"{size} characters against a budget of {render_budget.characters}")
        for section in rendered.sections:
            print(f"    {DIM}{section.section:<22}{RESET} {len(section.body):>6} chars")
        print(f"  {DIM}every version on the request came from what produced it{RESET}")

        stage(8, "Assess — triage, the routing `if`, and the analyst if it fires")
        print(f"  {DIM}against {settings.triage.model} / {settings.analyst.model}, "
              f"the endpoint .env configures{RESET}")
        logger = observability.StructuredLogger(
            component="demo",
            tenant=identity.tenant,
            sensor=identity.sensor,
            redactor=redactor,
            stream=log,
        )
        assessments = []
        store_out = orchestration.AssessmentStore(
            connection=connection, prices=budgets.model_prices()
        )
        print(f"  {DIM}pre-triage gate: min_suspicious_indicators="
              f"{gate.min_suspicious_indicators} "
              f"({'on' if gate.enabled else 'off'}), "
              f"version {gate.triage_gate_version}{RESET}")
        triage_client = ModelClient.for_agent(settings, "triage", stream=log)
        analyst_client = ModelClient.for_agent(settings, "analyst", stream=log)
        for projection, asked in zip(projections, requests, strict=True):
            assessment = orchestration.assess(
                asked,
                projection=projection,
                triage_client=triage_client,
                analyst_client=analyst_client,
                retry=agents.RetryPolicy(attempts=3),
                triage_prompt=triage_prompt,
                analyst_prompt=analyst_prompt,
                # No live provider lookup: this demo spends no daily quota.
                provider_tools=(),
                thresholds=policy.thresholds(),
                budget_policy=budget_policy,
                send_policy=disclosure.send_policy(),
                inherit=analyst.Inheritance(inherit_triage_rationale=False),
                logger=logger,
                # The real configured gate, so the demo shows what a deployment
                # actually does. At the shipped `min_suspicious_indicators = 1`
                # pass A is cleared without a model and pass B is not, which is
                # the same contrast this demo was already built around --
                # docs/decisions/0047-the-pre-triage-gate.md.
                triage_gate=gate,
            )
            store_out.store(assessment, at=datetime.now(timezone.utc))
            assessments.append(assessment)
        connection.execute("FLUSH")

        # `Assessment` is six things, none derivable from another: the triage
        # outcome is an `AgentResult` OR an `AgentFailure`, and `trigger` is the
        # analyst's reason for having run and is `None` exactly when it did not.
        # A failure is read off the type rather than off a truthy attribute,
        # because a failure that printed as "no verdict" would be the collapse
        # `concept/instruction.md` §2 forbids.
        failures: list[str] = []
        gated_count = 0
        escalated = 0
        for assessment in assessments:
            outcome = assessment.triage
            if isinstance(outcome, policy.GateDecision):
                gated_count += 1
                print(f"  triage       {YELLOW}NOT RUN{RESET} — the gate cleared "
                      f"this context on {outcome.claims_read} claim(s), below "
                      f"the configured {outcome.min_suspicious_indicators}")
                print(f"  {DIM}emitted as `normal` with NO model version, because "
                      f"nothing answered. docs/hazards.md §11 is what that "
                      f"verdict does not establish.{RESET}")
            elif isinstance(outcome, contract_failure):
                failures.append(outcome.reason)
                print(f"  triage       {YELLOW}typed failure: {outcome.reason}{RESET}")
                print(f"  {DIM}stored with no verdict, and emitted anyway{RESET}")
            else:
                print(f"  triage       {BOLD}answered{RESET} "
                      f"{DIM}(labels are on the message below){RESET}")
            if assessment.trigger is not None:
                escalated += 1
                print(f"  escalated    {BOLD}{assessment.trigger}{RESET}")
            if assessment.escalation is not None:
                print(f"  {DIM}deterministic escalation computed independently "
                      f"of what triage said{RESET}")
        print(f"  escalated    {escalated} of {len(assessments)}")

        stage(9, "Emit, then read the output topic back as a consumer would")
        sink_store = sink.SinkStore(connection=connection, identity=identity)
        with BrokerProducer.from_settings(settings) as producer:
            producer.create_topic(output_topic)
            emission = sink.emit(
                store=sink_store, producer=producer, topic=output_topic
            )
        with BrokerConsumer(settings.infrastructure.kafka_bootstrap_servers) as consumer:
            drained = [
                message.value for message in consumer.consume(output_topic, idle_timeout=5.0)
            ]
        messages = [sink.OutputMessage.model_validate_json(value) for value in drained]
        print(f"  emitted      {getattr(emission, 'emitted', len(messages))}")
        print(f"  drained      {len(messages)} message(s) off {output_topic}")

        citations = 0
        verdicts: list[str] = []
        for message in messages:
            rule()
            document = json.loads(message.model_dump_json())
            trimmed = {
                key: document[key]
                for key in ("tenant", "sensor", "host", "context_id")
                if key in document
            }
            print(f"  {DIM}{json.dumps(trimmed)}{RESET}")
            if document.get("verdict") is not None:
                verdicts.append(str(document["verdict"]))
            for name in (
                "outcome_kind", "verdict", "classification", "confidence",
                "failure_reason", "failure_detail",
            ):
                if document.get(name) is not None:
                    print(f"  {name:<14} {BOLD}{document[name]}{RESET}")
            cited = document.get("citations") or []
            entities = document.get("entities") or []
            gaps = document.get("gaps") or []
            citations += len(cited)
            print(f"  citations      {len(cited)} row(s) of stored evidence")
            print(f"  gaps           {len(gaps)}")
            print(f"  entities       {len(entities)}")
            # `evidence` empty is "no source was ever asked", which is not
            # `no_match` and not `missing`. Printed as `—` so the three stay
            # distinguishable here too.
            # Entities that a source actually said something about are shown
            # first. Sorted alphabetically, 131 `no_match` rows bury the one row
            # the assessment turned on, which is the row a reader is looking for.
            def _said_something(row: dict) -> bool:
                return any(
                    item.get("classification") not in (None, "no_match")
                    for item in (row.get("evidence") or [])
                )

            ordered = sorted(entities, key=lambda row: not _said_something(row))
            shown = [row for row in ordered if _said_something(row)][:8]
            shown += [row for row in ordered if not _said_something(row)][
                : max(0, 8 - len(shown))
            ]
            for row in shown:
                evidence = row.get("evidence") or []
                # status is what happened to the lookup; classification is what
                # the snapshot said. Both, because "ok" alone reads as a hit.
                said = ", ".join(
                    f"{item.get('status','?')}/{item.get('classification') or 'no_match'}"
                    for item in evidence
                ) or "— (no source asked)"
                hit = any(
                    item.get("classification") not in (None, "no_match")
                    for item in evidence
                )
                print(
                    f"    {row.get('entity_type','?'):<10} "
                    f"{str(row.get('entity_value',''))[:30]:<30} "
                    f"{(GREEN + BOLD) if hit else DIM}{said}{RESET}"
                )

        return PassResult(
            label=label,
            planted_entity=planted_entity,
            snapshot_version=snapshot,
            claims=claims,
            contexts=len(contexts),
            verdicts=tuple(verdicts),
            escalated=escalated,
            failures=tuple(failures),
            citations=citations,
            emitted=len(messages),
            gated=gated_count,
        )
    finally:
        if keep:
            print(f"\n{DIM}kept: schema {schema}, staging {staging}{RESET}")
        else:
            try:
                connection.execute("SET search_path TO public")
                connection.execute(f"DROP SCHEMA {schema} CASCADE")
            except Exception as error:  # noqa: BLE001 — cleanup must not mask a result
                print(f"{DIM}could not drop {schema}: {error}{RESET}", file=sys.stderr)
            shutil.rmtree(staging, ignore_errors=True)
        connection.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--pass",
        dest="which",
        choices=("both", "a", "b"),
        default="both",
        help="which pass to run (default: both, and the contrast is the point)",
    )
    parser.add_argument(
        "--keep",
        action="store_true",
        help="leave the demo schema and staging directory behind",
    )
    arguments = parser.parse_args(argv)

    print(f"{BOLD}MAESTRO HELENA — one capture through all six stages{RESET}")
    rule()

    settings = Settings.load()
    print(f"  tenant={settings.identity.tenant}  sensor={settings.identity.sensor}")
    print(f"  {DIM}identity comes from the environment, never from a record{RESET}")

    # Fetched once and shared by both passes, so the two runs differ in exactly
    # one thing -- whether an entry was repointed -- and not in which minute of
    # the rolling window they caught.
    print(f"\n  fetching {THREATFOX_EXPORT_URL}")
    export = enrichment.fetch_threatfox(
        THREATFOX_EXPORT_URL, redactor=Redactor.from_settings(settings)
    )
    print(f"  {len(export):,} bytes, no credential attached "
          f"{DIM}(docs/runbook.md §14){RESET}")

    results: list[PassResult] = []
    if arguments.which in ("both", "a"):
        results.append(
            run_pass(
                settings=settings,
                label="PASS A — the feed exactly as ThreatFox published it",
                plant=False,
                export=export,
                keep=arguments.keep,
            )
        )
    if arguments.which in ("both", "b"):
        results.append(
            run_pass(
                settings=settings,
                label="PASS B — one entry repointed at a domain this capture has",
                plant=True,
                export=export,
                keep=arguments.keep,
            )
        )

    banner("WHAT THE TWO PASSES SHOW")
    for result in results:
        print(f"\n{BOLD}{result.label}{RESET}")
        if result.planted_entity:
            print(f"  planted        {YELLOW}{result.planted_entity}{RESET}")
        print(f"  claims stored  {result.claims}")
        print(f"  contexts       {result.contexts}")
        print(f"  verdicts       {', '.join(result.verdicts) or '—'}")
        print(f"  gated          {result.gated}"
              f"{'  ← cleared without a model' if result.gated else ''}")
        print(f"  typed failures {', '.join(result.failures) or 'none'}")
        print(f"  escalated      {result.escalated}")
        print(f"  cited rows     {result.citations}")
        print(f"  on the topic   {result.emitted}")

    # Stated against what the passes actually produced rather than as a fixed
    # sentence: a run that cited nothing must not print that it cited evidence.
    cited_any = any(result.citations for result in results)
    print(
        f"\n{DIM}What this demonstrates: the six stages compose over the wire, and\n"
        f"every claim on the topic is traceable to a stored row. "
        + (
            "Citations were\nmade and resolve to stored evidence.\n"
            if cited_any
            else "No citation was\nmade in these passes -- a `normal` verdict over a context where every\n"
            "lookup said `no_match` has nothing to cite, which is the honest\n"
            "outcome and not a missing feature.\n"
        )
        + f"\nWhat it does NOT demonstrate, and what nothing here can until a labelled\n"
        f"corpus exists: whether the verdicts are RIGHT. See docs/acceptance.md for\n"
        f"the claimable properties and the ones that are explicitly not claimable.{RESET}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
