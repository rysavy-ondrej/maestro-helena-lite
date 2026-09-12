"""Acceptance: the six stages composed over the wire, and what that is allowed to mean.

This is the D9 run `prds/prd.json` task 52 asks for, and it is the executable half
of `docs/acceptance.md`. Everything else in this suite tests a stage against the
stages beside it; what is tested here is that a record published to the broker
becomes a message on the output topic, through the engine, the loader, the
renderer, a model and the sink, with nothing simulated in between.

`concept/01-goal-and-scope.md` closes with the only paragraph that says what a
run like this may be read as, and it is the specification for this module:

    **Claimable:** every verdict and explanation cites stored evidence; source
    outages, stale evidence, invalid model responses and partial context are
    visible rather than absorbed; a new enrichment source can be added without
    changing identity, provenance or assessment contracts; no autonomous
    remediation occurs.

    **Not claimable:** accuracy, recall, false-positive rate, escalation rate,
    latency or cost; that triage reduces caseload without suppressing
    high-confidence detections; that identical inputs replay identically.

So `CLAIMS` below holds the four claimable properties, each as its own
identifier, and every test is named for the one it executes. `docs/acceptance.md`
is the checklist a person reads; `test_the_checklist_states_the_claims_the_note_permits`
and `test_every_claimable_property_has_a_test_named_for_it` are what keep the
three — the note, the checklist and this module — from drifting apart. The
not-claimable list is enforced in the other direction: it has to be *present*, in
the checklist, beside the claims it qualifies, and
`tests/test_conformance.py`'s MNH-20 is what stops any committed file claiming
one of them anyway.

### What the run is made of

Real, in the order a deployment does it: the pinned broker and the pinned engine
(`tests/conftest.py` starts them when nothing is listening), `sql/migrations/`
applied by the real runner, a ThreatFox snapshot through the real loader, the
committed ten-record capture published record-by-record over the Kafka wire
protocol, consumed back off the topic, normalized and stored, aggregated into a
host context by the engine's own views, projected, rendered, assessed through
`helena.orchestration.assess`, written as typed rows, emitted by `helena.sink`
and drained off the output topic by a consumer that knows nothing but the bytes.

**The model is the one thing that is scripted, and it is a real HTTP endpoint on
the loopback interface** — `tests/test_assessments.py`'s `_Endpoint`, reused. A
run that called the configured endpoint would measure that model's mood: task 51
recorded a live analyst run returning `schema_invalid` once and validating the
next time, which is model behaviour and not a property of the pipeline. What a
live endpoint is for is `tests/test_agents.py` and `tests/test_analyst.py`, which
call it; what this module is for is the composition around it, and the invalid
response below is scripted precisely so that the *pipeline's* handling of one is
deterministic.

### What this module deliberately does not do

It does not assert that any verdict is right, and it cannot: the labelled
evaluation corpus does not exist (`concept/08-open-questions.md`), so accuracy,
recall, escalation rate, latency and cost are unmeasured here and are named as
unmeasured in `docs/acceptance.md`. The model's answers below are scripted, which
makes them the *input* to the assertions rather than evidence about a model.

Maturity: experimental. Every test executes the whole pipeline. What building it
found — two contract gaps, a join that overstates coverage, and three limits of
the run itself — is in the checklist's "what this run does not demonstrate", and
two of those are pinned by tests here, because a gate that hides what it could
not reach is worse than no gate.
"""

from __future__ import annotations

import io
import json
import re
import socket
import time
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import psycopg
import pytest

from helena import (
    agents,
    analyst,
    budgets,
    disclosure,
    enrichment,
    hosts,
    migrations,
    observability,
    orchestration,
    policy,
    rendering,
    sink,
    triage,
)
from helena.broker import BrokerConsumer, BrokerProducer
from helena.config import Settings
from helena.contracts.v1 import CONTRACT_VERSION, SCHEDULED_TRIAGE, AgentRequest, RequestVersions
from helena.enrichment import load_threatfox
from helena.normalizer import (
    Capture,
    EventStore,
    IngestCounts,
    Normalizer,
    Quarantine,
    consume_ingest_topic,
    describe_capture,
    ingest_counts,
    publish_capture,
)
from helena.observability import Redactor
from helena.policy import v1 as policy_v1
from helena.rendering import v1 as rendering_v1
from helena.taxonomy import ANALYST, TRIAGE
from helena.versions import VERSION_COLUMNS

from test_assessments import _Endpoint, answered  # noqa: E402 — the scripted endpoint

pytestmark = [pytest.mark.acceptance, pytest.mark.integration]

PROJECT_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures"
CHECKLIST = PROJECT_ROOT / "docs" / "acceptance.md"
NOTE = PROJECT_ROOT / "concept" / "01-goal-and-scope.md"

#: The ten-record layer-coverage capture. Every record is a byte-for-byte copy of
#: a line of `data/ingest/flow-sample.jsonl`; `tests/fixtures/captures/README.md`
#: says what each offset is for.
LAYERS_CAPTURE = "ace6ca33f7bf8aa949f79124abf33fc115cfd0909e9dea798f4762cf87af8318"
THREATFOX_EXTRACT = (FIXTURES / "threatfox" / "export.json").read_bytes()
#: The committed Public Suffix List extract, loaded over a `file:` URL so the
#: normalization snapshot dimension is a real snapshot rather than a literal.
PUBLIC_SUFFIX_EXTRACT = FIXTURES / "public-suffix-list" / "extract.dat"

TENANT, SENSOR = "tenant-under-test", "sensor-under-test"
FEED_URL = "https://threatfox.invalid/export/json/recent/"
#: `sql/migrations/0006_host_context.sql` tumbles on INTERVAL '5 minutes'.
WINDOW_SECONDS = 300

#: The policy objects a deployment loads once and hands to every run. Passed in
#: rather than loaded inside `assess`, for the reason that function gives: a run
#: scored against a policy it never ran under is a measurement of nothing.
TRIAGE_PROMPT = triage.version("v1")
ANALYST_PROMPT = analyst.version("v1")
THRESHOLDS = policy.thresholds()
BUDGET_POLICY = budgets.load()
SEND_POLICY = disclosure.send_policy()
PRICES = budgets.model_prices()
RETRY = agents.RetryPolicy(attempts=3)
INHERIT = analyst.Inheritance(inherit_triage_rationale=False)
#: A budget nothing in the committed capture can exceed, for the runs that are
#: not about truncation. `tests/test_rendering.py` owns what the configured value
#: is worth; a run here that used it would start passing or failing because
#: somebody edited `config/rendering.toml`.
UNBOUNDED = rendering.RenderingBudget(characters=1_000_000)


# --- The four claimable properties, as identifiers ---------------------------

#: `concept/01`'s claimable sentence, split at its semicolons, verbatim. A clause
#: that is reworded in the note fails `test_the_claims_here_are_the_notes_own`
#: until the wording is carried across, which is the same device
#: `tests/test_conformance.py` uses for the must-never-happen table.
CLAIMS: dict[str, str] = {
    "CLAIM-1": "every verdict and explanation cites stored evidence",
    "CLAIM-2": (
        "source outages, stale evidence, invalid model responses and partial "
        "context are visible rather than absorbed"
    ),
    "CLAIM-3": (
        "a new enrichment source can be added without changing identity, "
        "provenance or assessment contracts"
    ),
    "CLAIM-4": "no autonomous remediation occurs",
}

#: What may not be claimed, from the same paragraph. These are asserted to be in
#: the checklist rather than executed — there is nothing to execute, which is the
#: point: the measurement needs a labelled corpus and there is not one.
NOT_CLAIMABLE: tuple[str, ...] = (
    "accuracy, recall, false-positive rate, escalation rate, latency or cost",
    "that triage reduces caseload without suppressing high-confidence detections",
    "that identical inputs replay identically",
)


def environment(*, bootstrap: str, ingest_topic: str, output_topic: str) -> dict[str, str]:
    """A deployment's environment, with this run's own topics.

    The topics are per run and the addresses are the fixtures': two runs sharing
    an ingest topic would consume each other's records, and the reconciliation
    below refuses a set that does not add up rather than folding a stranger's
    records into the numbers (`helena.normalizer.IngestCounts`).
    """
    return {
        "LLM_URL": "http://model.invalid/v1",
        "LLM_TOKEN": "token-under-test",
        "LLM_MODEL": "model-under-test",
        "HELENA_TENANT": TENANT,
        "HELENA_SENSOR": SENSOR,
        "HELENA_INPUT_FORMAT": "flow-json",
        "ABUSECH_AUTH_KEY": "abusech-key-under-test",
        "VIRUSTOTAL_AUTH_KEY": "virustotal-key-under-test",
        "RISINGWAVE_DSN": "postgresql://root@localhost:4566/dev",
        "KAFKA_BOOTSTRAP_SERVERS": bootstrap,
        "HELENA_INGEST_TOPIC": ingest_topic,
        "HELENA_OUTPUT_TOPIC": output_topic,
    }


def current_window() -> float:
    """The start of the tumbling window `now` falls in, as a timestamp.

    The committed capture is dated 2024-06-01 and the retention boundary
    (`sql/migrations/0009_retention_boundary.sql`) does not show a context that
    old, so every record is re-stamped into this window. `ts` is a field of the
    input contract, so moving it is a contract-permitted change to a real record.
    """
    return float(int(time.time() // WINDOW_SECONDS) * WINDOW_SECONDS)


# --- The harness -------------------------------------------------------------
#
# One function runs the pipeline and one object holds what it produced, so that
# every test below asserts over a run that really happened rather than over a
# stage called in isolation. The stages are the shipped ones: nothing here parses
# a record, maps a feed entry, computes a context or assembles a message.


class AcceptanceGap(AssertionError):
    """The run reached a question the shipped contracts have no answer for.

    Its own type, and it fails the run loudly rather than choosing: an end-to-end
    harness that picked a plausible value for something the pipeline cannot
    supply would be demonstrating the harness. Every place it is raised is
    written up in `docs/acceptance.md` under "what this run does not
    demonstrate".
    """


@dataclass(frozen=True)
class Run:
    """What one end-to-end pass produced, at every stage it crossed."""

    connection: psycopg.Connection
    capture: Capture
    #: records / consumed / normalized / quarantined, reconciled on construction.
    counts: IngestCounts
    window_start: datetime
    #: The feed snapshot the enrichment join matched at the window, or `None`
    #: where the run was built with no source that answered.
    snapshot_version: str | None
    #: The entity the feed extract was repointed at, so a test can name the row
    #: the claim is about.
    matched: str
    projections: tuple[rendering.ContextProjection, ...]
    requests: tuple[AgentRequest, ...]
    assessments: tuple[orchestration.Assessment, ...]
    emission: sink.EmissionCounts
    #: What a consumer that knows nothing but the bytes read off the output topic.
    messages: tuple[sink.OutputMessage, ...]
    headers: tuple[dict[str, bytes], ...]
    #: Every outbound TCP connection opened while the run was in flight.
    connected_to: tuple[tuple[str, int], ...]
    #: `host:port` of the scripted endpoint the prompts went to, so CLAIM-4 can
    #: name every address the run was allowed to reach rather than allow a range.
    endpoint_host: str
    #: The structured log the run wrote, one JSON object per line.
    log: str

    @property
    def message(self) -> sink.OutputMessage:
        assert len(self.messages) == 1, (
            f"this run emitted {len(self.messages)} messages; `message` is for "
            f"the single-context runs"
        )
        return self.messages[0]

    def entity(self, value: str) -> sink.EmittedEntity:
        found = [row for row in self.message.entities if row.entity_value == value]
        assert len(found) == 1, f"{value} is on {len(found)} entity rows of the message"
        return found[0]

    def log_lines(self, event: str) -> list[dict[str, Any]]:
        """The `fields` of every record the run logged under `event`.

        `helena.observability.StructuredLogger` puts the caller's keywords under
        `fields` and keeps the record's own envelope — timestamp, level,
        component, tenant, sensor, event — beside them, so this returns the half
        a caller passed in.
        """
        return [
            record["fields"]
            for record in (json.loads(line) for line in self.log.splitlines() if line)
            if record.get("event") == event
        ]


def a_topic(what: str) -> str:
    """A topic of this run's own. The broker keeps topics for the session."""
    return f"helena-e2e-{what}-{uuid.uuid4().hex[:12]}"


def restamped_capture(path: Path, *, window: float, records: list[dict] | None = None) -> Capture:
    """The layer-coverage capture re-stamped into `window`, written to `path`.

    One context rather than the two the fixture's own timestamps produce: the
    file is one host's traffic and a context is one host in one window, so
    collapsing it into a single window is what makes the run one context whose
    every number can be checked.
    """
    if records is None:
        source = FIXTURES / "captures" / f"{LAYERS_CAPTURE}.jsonl"
        records = [json.loads(line) for line in source.read_bytes().splitlines()]
    path.write_bytes(
        b"".join(
            json.dumps({**record, "ts": window + 1}).encode() + b"\n" for record in records
        )
    )
    return describe_capture(path)


def redactor(settings: Settings) -> Redactor:
    return Redactor.from_settings(settings)


def load_feed(
    connection: psycopg.Connection,
    raw: bytes,
    *,
    now: datetime,
    settings: Settings,
    url: str = FEED_URL,
) -> Any:
    return load_threatfox(
        connection,
        tenant=TENANT,
        sensor=SENSOR,
        source_url=url,
        redactor=redactor(settings),
        raw=raw,
        now=now,
    )


def targeted(raw: bytes, entity_value: str, ioc_type: str = "domain") -> bytes:
    """The committed extract with one entry repointed at an entity the capture has.

    The extract names indicators from the real feed and the capture is one
    Windows host's routine traffic, so nothing in one appears in the other —
    realistic, and useless for testing a join. The same device
    `tests/test_rendering.py` and `tests/test_enriched.py` use.
    """
    document = json.loads(raw)
    key = sorted(document)[0]
    document[key][0]["ioc_type"] = ioc_type
    document[key][0]["ioc_value"] = entity_value
    return json.dumps(document).encode()


def first_entity(connection: psycopg.Connection, entity_type: str = "domain") -> str:
    value = connection.execute(
        "SELECT entity_value FROM helena_signal_context_entities "
        "WHERE entity_type = %s ORDER BY entity_value LIMIT 1",
        (entity_type,),
    ).fetchone()
    assert value, f"the capture produced no {entity_type} entity"
    return value[0]


def snapshot_at(connection: psycopg.Connection, window_start: datetime) -> str | None:
    """The snapshot the enrichment join matched at `window_start`, or `None`.

    `RequestVersions.enrichment_snapshot_version` is **one** identifier — "the
    feed snapshot the enrichment join matched against"
    (`docs/decisions/0008-version-registry.md`) — so this reads the validity view
    the join itself reads rather than taking today's snapshot, which is
    `concept/02`'s "replay joins the snapshot current at event time, not
    today's" applied to the request.

    Two sources with two current snapshots therefore have no single value to
    record, and that is raised rather than picked from: see `AcceptanceGap` and
    the checklist. `None` — nothing valid at the window — is returned rather than
    raised, because it is the input to the source-outage run.
    """
    rows = connection.execute(
        "SELECT source_id, snapshot_version FROM helena_reference_feed_snapshot_validity "
        "WHERE tenant = %s AND sensor = %s AND valid_from <= %s "
        "AND (valid_to IS NULL OR valid_to > %s) "
        "ORDER BY source_id",
        (TENANT, SENSOR, window_start, window_start),
    ).fetchall()
    if len(rows) > 1:
        raise AcceptanceGap(
            f"{len(rows)} sources hold a snapshot valid at {window_start} "
            f"({[source for source, _ in rows]}), and "
            f"`RequestVersions.enrichment_snapshot_version` is one identifier. "
            f"Which snapshot a multi-source assessment records is open "
            f"(concept/08-open-questions.md); picking one here would record a "
            f"version that describes part of the join."
        )
    return rows[0][1] if rows else None


@dataclass
class _Dialled:
    """Every outbound TCP connection opened while the block is armed.

    The opposite of `helena.network.no_network`, which refuses one: this records
    and lets it through, because what CLAIM-4 needs is not "nothing left" — the
    pipeline's whole job is to reach a model and a broker — but the **list** of
    places the run could have written to, checked against the two it is allowed
    to have.

    It patches the same call `helena.network` does, `socket.socket.connect`, and
    restores it the same way. What it does not see is a connection opened before
    it was armed: the engine connection is the fixture's, which is named in the
    assertion rather than left implied.
    """

    dialled: list[tuple[str, int]] = field(default_factory=list)

    def __enter__(self) -> _Dialled:
        self._original = socket.socket.connect

        def recording(sock: Any, address: Any, *rest: Any) -> Any:
            if isinstance(address, tuple) and len(address) >= 2:
                self.dialled.append((str(address[0]), int(address[1])))
            return self._original(sock, address, *rest)

        socket.socket.connect = recording  # type: ignore[method-assign]
        return self

    def __exit__(self, *_exc: object) -> None:
        # `connect` is inherited from the C type rather than defined on the class,
        # so it is removed rather than assigned back — `helena.network` has the
        # measurement and the reason.
        del socket.socket.connect


#: What a feed plan does: whatever loading this run needs, given the connection,
#: the entity the extract may be repointed at, and the window the context is in.
FeedPlan = Callable[[psycopg.Connection, str, datetime, Settings], None]


def fresh_hit(
    connection: psycopg.Connection, matched: str, window: datetime, settings: Settings
) -> None:
    """One snapshot, loaded a minute before the window, holding a claim about `matched`."""
    load_feed(
        connection,
        targeted(THREATFOX_EXTRACT, matched),
        now=window - timedelta(minutes=1),
        settings=settings,
    )


def run_pipeline(
    connection: psycopg.Connection,
    *,
    bootstrap: str,
    tmp_path: Path,
    script: Callable[[tuple[AgentRequest, ...]], list[Any]],
    feed: FeedPlan = fresh_hit,
    budget: rendering.RenderingBudget | None = None,
    records: list[dict] | None = None,
) -> Run:
    """Ingest → context → enrich → triage → analyse → emit, over the wire, once.

    `concept/01`'s six stages in the order it lists them, each through the
    shipped code path. The only thing supplied is `script`: what the scripted
    endpoint answers, in order. It is a callable over the requests rather than a
    list, because an answer that cites evidence can only be written once the
    rendering exists — an `evidence_id` is a sha256 over the claim, the snapshot
    and the identity, so a hand-written one would be a citation to nothing, which
    the contract refuses. Scripting it this way is what makes the model's answer
    an *input* to the run rather than a source of flakiness in it.

    The feed is loaded **after** the capture has been ingested and **dated
    before** the window, and the order is not an accident. The extract has to be
    repointed at an entity the capture actually has, which is not known until the
    entities exist; what decides whether a snapshot covers a window is its
    `attempted_at` and not the wall time of the load, so a snapshot dated a
    minute before the window is the snapshot that window's join matches
    (`sql/migrations/0015_enriched_context.sql`).
    """
    ingest_topic, output_topic = a_topic("ingest"), a_topic("output")
    settings = Settings.load(
        environ=environment(
            bootstrap=bootstrap, ingest_topic=ingest_topic, output_topic=output_topic
        ),
        env_file=None,
    )
    identity = settings.identity
    window = current_window()
    window_start = datetime.fromtimestamp(window, tz=timezone.utc)
    stream = io.StringIO()
    logger = observability.StructuredLogger(
        component="acceptance",
        tenant=TENANT,
        sensor=SENSOR,
        redactor=redactor(settings),
        stream=stream,
    )

    # Stage 0 — the Public Suffix List, so that the normalization snapshot
    # dimension on every request below is a snapshot this run loaded rather than
    # a literal. Over a `file:` URL: no test needs the network for it.
    suffixes = enrichment.load_public_suffix_list(
        connection,
        source_url=PUBLIC_SUFFIX_EXTRACT.as_uri(),
        redactor=redactor(settings),
        now=window_start - timedelta(minutes=2),
    )
    assert suffixes.snapshot_version, f"the list did not load: {suffixes}"

    capture = restamped_capture(
        tmp_path / f"{uuid.uuid4().hex}.jsonl", window=window, records=records
    )
    events = EventStore(connection=connection, identity=identity)
    quarantine = Quarantine(connection=connection, identity=identity)
    normalizer = Normalizer.from_settings(settings)

    with _Dialled() as dialled:
        # Stage 1 — ingest. Published record by record over the Kafka wire
        # protocol and consumed back off the topic, so the run crosses the broker
        # rather than calling the normalizer with a file.
        with BrokerProducer.from_settings(settings) as producer:
            published = publish_capture(capture, producer, ingest_topic)
        assert published == capture.record_count
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

        # Stages 2 and 3 — the engine aggregated the context and its entities
        # while the records landed; the loader writes the snapshot whose validity
        # interval covers the window, which is the one the join matches.
        matched = first_entity(connection)
        feed(connection, matched, window_start, settings)
        connection.execute("FLUSH")
        snapshot = snapshot_at(connection, window_start)

        # The rendering is built before the endpoint is scripted, for the reason
        # `script` gives: a citation names an identifier the rendering showed.
        projections = tuple(
            rendering.RenderingStore(connection=connection, identity=identity).project(
                context_id
            )
            for context_id in live_contexts(connection)
        )
        requests = tuple(
            triage_request(
                projection,
                connection=connection,
                settings=settings,
                snapshot=snapshot,
                normalization_snapshot=suffixes.snapshot_version,
                budget=budget or UNBOUNDED,
            )
            for projection in projections
        )

        # Stages 4 and 5 — one pass per live context, routed by the shipped `if`.
        assessments = []
        store = orchestration.AssessmentStore(connection=connection, prices=PRICES)
        with _Endpoint(script(requests)) as endpoint:
            endpoint_host = endpoint.host
            for projection, asked in zip(projections, requests, strict=True):
                assessment = orchestration.assess(
                    asked,
                    projection=projection,
                    triage_client=endpoint.client(TRIAGE, stream),
                    analyst_client=endpoint.client(ANALYST, stream),
                    retry=RETRY,
                    triage_prompt=TRIAGE_PROMPT,
                    analyst_prompt=ANALYST_PROMPT,
                    provider_tools=(),
                    thresholds=THRESHOLDS,
                    budget_policy=BUDGET_POLICY,
                    send_policy=SEND_POLICY,
                    inherit=INHERIT,
                    logger=logger,
                )
                store.store(assessment, at=datetime.now(timezone.utc))
                assessments.append(assessment)

        # Stage 6 — emit, and drain what a consumer would actually read.
        sink_store = sink.SinkStore(connection=connection, identity=identity)
        with BrokerProducer.from_settings(settings) as producer:
            emission = sink.emit(store=sink_store, producer=producer, topic=output_topic)
        drained = drain(bootstrap, output_topic)

    return Run(
        connection=connection,
        capture=capture,
        counts=counts,
        window_start=window_start,
        snapshot_version=snapshot,
        matched=matched,
        projections=projections,
        requests=requests,
        assessments=tuple(assessments),
        emission=emission,
        messages=tuple(
            sink.OutputMessage.model_validate_json(value) for _, value in drained
        ),
        headers=tuple(headers for headers, _ in drained),
        connected_to=tuple(dialled.dialled),
        endpoint_host=endpoint_host,
        log=stream.getvalue(),
    )


def live_contexts(connection: psycopg.Connection) -> list[str]:
    connection.execute("FLUSH")
    return [
        context_id
        for (context_id,) in connection.execute(
            "SELECT context_id FROM helena_signal_host_context_live "
            "ORDER BY host, window_start"
        ).fetchall()
    ]


def triage_request(
    projection: rendering.ContextProjection,
    *,
    connection: psycopg.Connection,
    settings: Settings,
    snapshot: str | None,
    normalization_snapshot: str,
    budget: rendering.RenderingBudget,
) -> AgentRequest:
    """The triage request for one live context, versions and all.

    **Nothing in the package builds this**, and that is a finding rather than an
    oversight to route around: `helena.orchestration.assess` is entered with a
    request, and the scheduler that would turn "every live context" into requests
    is not part of the first version (`concept/01`, "the analyst is served
    indirectly, through the output topic"). So this is the harness's, written to
    take every version from the thing that produced it and to refuse rather than
    invent the one the store cannot supply.
    """
    if snapshot is None:
        raise AcceptanceGap(
            "no feed snapshot was valid at this context's window, and "
            "`RequestVersions.enrichment_snapshot_version` has no value for a "
            "join that matched none. A deployment whose only source has never "
            "loaded successfully therefore cannot build a request at all — see "
            "docs/acceptance.md, 'what this run does not demonstrate'."
        )
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
        budgets=BUDGET_POLICY.for_emitter(TRIAGE),
        versions=RequestVersions(
            prompt_version=TRIAGE_PROMPT.version,
            schema_version=CONTRACT_VERSION,
            rendering_version=rendering_v1.RENDERING_VERSION,
            taxonomy_version="v1",
            enrichment_snapshot_version=snapshot,
            normalization_snapshot_version=normalization_snapshot,
            policy_version=policy_v1.POLICY_VERSION,
            aggregation_version=aggregation_version(connection, projection.context_id),
            model_requested=settings.triage.model,
        ),
    )


def aggregation_version(connection: psycopg.Connection, context_id: str) -> str:
    """The aggregation version, as the engine stamped it on this context.

    Read off the row rather than taken from `helena.versions.AGGREGATION_VERSION`:
    a request that recorded the Python constant while the engine had aggregated
    under another would record a version the context does not have, which is the
    drift `tests/test_versions.py` asserts against from the other side. It is a
    column of `helena_signal_host_context_live` rather than of the projection,
    because the projection is what a *rendering* is built from and a version is
    not something a model is shown.
    """
    (version,) = connection.execute(
        "SELECT aggregation_version FROM helena_signal_host_context_live "
        "WHERE tenant = %s AND sensor = %s AND context_id = %s",
        (TENANT, SENSOR, context_id),
    ).fetchone()
    return version


def drain(bootstrap: str, topic: str) -> list[tuple[dict[str, bytes], bytes]]:
    """Everything on `topic`, headers and value, in offset order."""
    with BrokerConsumer(bootstrap) as consumer:
        return [
            (dict(message.headers), message.value)
            for message in consumer.consume(topic, idle_timeout=3.0)
        ]


@pytest.fixture(scope="module")
def module_engine(engine_dsn: str) -> Iterator[psycopg.Connection]:
    """A migrated schema of this module's own, for the runs a test reads twice.

    `migrated_engine` is function-scoped and empties the data tables on the way
    in, which is what every scenario run below wants and is exactly what the
    reference run must not have: it is expensive — the wire, the engine's own
    aggregation and two model calls — and eight tests read what it produced. So
    it gets a schema that lives as long as the module does.

    A schema and not a second engine: `single_node` binds fixed meta and compute
    ports, so a second one cannot run beside the first (`tests/conftest.py`).
    Autocommit for the reason that file gives — RisingWave DDL inside an open
    transaction is not visible to the statements after it.
    """
    schema = f"helena_e2e_{uuid.uuid4().hex}"
    with psycopg.connect(engine_dsn, autocommit=True, connect_timeout=5) as connection:
        connection.execute(f"CREATE SCHEMA {schema}")
        try:
            connection.execute(f"SET search_path TO {schema}")
            migrations.apply(connection)
            yield connection
        finally:
            connection.execute("SET search_path TO public")
            connection.execute(f"DROP SCHEMA {schema} CASCADE")


# --- The reference run -------------------------------------------------------
#
# One run that goes all the way through with a hit in it, and the tests that read
# what came off the topic. The scripts below are what the endpoint answers; they
# are written against the request that reached it, so a citation names an
# identifier the rendering really showed.


def triage_answer(
    evidence_id: str, *, classification: str = "suspicious", **overrides: Any
) -> str:
    return json.dumps(
        {
            "classification": classification,
            "confidence": 0.6,
            "citations": [{"evidence_id": evidence_id, "stance": "supporting"}],
            **overrides,
        }
    )


def analyst_answer(evidence_id: str, **overrides: Any) -> str:
    return json.dumps(
        {
            "classification": "malicious.c2",
            "confidence": 0.8,
            "citations": [{"evidence_id": evidence_id, "stance": "supporting"}],
            "gaps": [
                {
                    "kind": "missing",
                    "detail": "no source in this deployment covers a fingerprint",
                }
            ],
            "evidence_package": {
                "patterns": ["the host resolved a name the snapshot lists"],
                "narrative": (
                    "the host resolved a name that the loaded ThreatFox snapshot "
                    "carries a claim about"
                ),
            },
            **overrides,
        }
    )


def cited_evidence(asked: AgentRequest) -> str:
    """One evidence identifier the rendering that reached the model showed.

    The rendering's `evidence_ids` are the only identifiers a citation may name
    (`helena.contracts.v1`), which is CLAIM-1 enforced at the contract: an agent
    cannot cite what it was not shown, and what it was shown is a stored row.
    """
    shown = sorted(asked.rendering.evidence_ids)
    assert shown, "the rendering showed no evidence to cite"
    return shown[0]


def escalating_script(requests: tuple[AgentRequest, ...]) -> list[Any]:
    """Triage says `suspicious`; the analyst answers with a citation it was shown."""
    script: list[Any] = []
    for asked in requests:
        script.append(answered(triage_answer(cited_evidence(asked))))
        # Two analyst answers per escalated pass: `helena.analyst.run` asks once
        # for the retrieval step and once for the verdict, which is the loop
        # `tests/test_assessments.py` scripts the same way.
        script.append(answered(analyst_answer(cited_evidence(asked))))
        script.append(answered(analyst_answer(cited_evidence(asked))))
    return script


@pytest.fixture(scope="module")
def reference(
    module_engine: psycopg.Connection,
    broker_bootstrap: str,
    tmp_path_factory: pytest.TempPathFactory,
) -> Run:
    """The run every CLAIM-1 and CLAIM-4 test reads: a fresh snapshot and a hit.

    Module-scoped, because it is the expensive one — the wire, the engine's
    aggregation and two model calls — and every test over it is a read of what it
    produced. The scenario runs below each build their own, because a status is a
    property of a window and a load history rather than of an assertion.
    """
    return run_pipeline(
        module_engine,
        bootstrap=broker_bootstrap,
        tmp_path=tmp_path_factory.mktemp("reference"),
        script=escalating_script,
    )


def test_the_six_stages_compose(reference: Run):
    """The run itself: a record published to the broker became a message on the topic.

    `concept/01`'s six stages, each having produced what the next one read, and
    each number read from a different side of the thing it counts — the capture
    file, the run, the engine, and the bytes off the topic. This is the weakest
    of the assertions in this module and it is deliberately first: everything
    below is a property *of* a run, and a run that did not happen would make all
    of them vacuous.
    """
    # 1 ingest: published, consumed, and reconciled against the retained file.
    assert reference.counts.records == reference.capture.record_count == 10
    assert reference.counts.consumed == reference.counts.records
    assert reference.counts.normalized + reference.counts.quarantine.quarantined == 10
    stored = reference.connection.execute(
        "SELECT DISTINCT capture_sha256 FROM helena_normalized_events"
    ).fetchall()
    assert stored == [(reference.capture.sha256,)], (
        "the stored events do not all reference the capture this run published"
    )

    # 2 context, 3 enrich: the engine aggregated one host in one window, and a
    # snapshot was valid for it.
    assert len(reference.projections) == 1, "the capture is one host in one window"
    assert reference.projections[0].entities, "the context carries no entities"
    assert reference.snapshot_version, "no snapshot was valid at the window"

    # 4/5 triage and analyse: the route was taken by the deterministic `if`, and
    # the log says so before the message does.
    (routed,) = reference.log_lines(orchestration.ROUTED)
    assert routed["trigger"] == reference.message.trigger
    assert [assessment.trigger for assessment in reference.assessments] == [
        reference.message.trigger
    ]

    # 6 emit: one message, complete, and carrying the two headers a consumer
    # deduplicates and versions on.
    assert reference.emission.complete
    assert len(reference.messages) == 1
    assert reference.message.outcome_kind == "verdict", (
        reference.message.failure_reason,
        reference.message.failure_detail,
        reference.message.emitter,
    )
    (headers,) = reference.headers
    assert headers[sink.OUTPUT_HEADER_ASSESSMENT].decode() == reference.message.assessment_id
    assert headers[sink.OUTPUT_HEADER_MESSAGE_VERSION].decode() == sink.MESSAGE_VERSION


# --- CLAIM-1: every verdict and explanation cites stored evidence -------------


def stored_evidence(connection: psycopg.Connection, context_id: str) -> dict[str, dict]:
    """Every enrichment-evidence row the store holds for one context, by identifier."""
    cursor = connection.execute(
        "SELECT evidence_id, source_id, source_tier, evidence_tier, snapshot_version, "
        "classification, entity_type, entity_value, status "
        "FROM helena_analytical_enriched_context "
        "WHERE tenant = %s AND sensor = %s AND context_id = %s "
        "AND evidence_id IS NOT NULL",
        (TENANT, SENSOR, context_id),
    )
    names = [column.name for column in cursor.description]
    return {row[0]: dict(zip(names, row, strict=True)) for row in cursor.fetchall()}


def test_claim1_every_citation_on_the_topic_resolves_to_a_stored_evidence_row(
    reference: Run,
):
    """`concept/01`: *every verdict and explanation cites stored evidence*.

    Resolved the way a consumer would have to: the identifier off the topic,
    looked up in the store, coming back as one row with a source, a tier and the
    snapshot it matched. A citation that resolved to nothing would be a verdict
    whose evidence exists only in the sentence that mentions it — which is the
    failure `concept/01` says the project exists to prevent.
    """
    held = stored_evidence(reference.connection, reference.projections[0].context_id)
    assert held, "the context carries no evidence rows at all"

    message = reference.message
    assert message.citations, "the verdict on the topic cites nothing"
    for citation in message.citations:
        row = held.get(citation.evidence_id)
        assert row is not None, (
            f"citation {citation.evidence_id} resolves to no stored row; the "
            f"context holds {sorted(held)}"
        )
        assert row["source_id"] and row["snapshot_version"] and row["source_tier"]
        assert row["classification"]


def test_claim1_the_cited_rows_are_the_ones_the_rendering_showed(reference: Run):
    """An agent can only cite what it was shown, and what it was shown is stored.

    The property is CLAIM-1's mechanism rather than a restatement of it: the
    rendering's evidence identifiers come out of `helena_analytical_enriched_context`
    through `helena.rendering`, so "cites stored evidence" holds because there is
    no other identifier in the room. Asserted over the run rather than over the
    contract, because what this module adds is that the two really are the same
    set once the engine, the loader and the renderer have all run.
    """
    asked = reference.requests[0]
    held = stored_evidence(reference.connection, asked.context_id)
    shown = set(asked.rendering.evidence_ids)

    assert shown, "the rendering showed no evidence"
    assert shown <= set(held), f"the rendering showed {shown - set(held)}, which is not stored"
    assert {citation.evidence_id for citation in reference.message.citations} <= shown


def test_claim1_the_explanation_on_the_topic_carries_its_citations_and_its_path(
    reference: Run,
):
    """The narrative, the patterns, the triage decision that led here, and the versions.

    `concept/03`: an escalated context is emitted once, *"carrying the analyst's
    verdict and the triage decision that led to it"*. An explanation that
    arrived without the citations, or without the run that produced it, would be
    exactly the untraceable confident verdict `concept/01` rejects.
    """
    message = reference.message
    assert message.emitter == ANALYST
    assert message.narrative
    assert message.patterns
    assert message.citations
    assert message.triage is not None
    assert message.triage.trigger == SCHEDULED_TRIAGE
    assert message.trigger == "triage_suspicious"
    # Every version dimension a citable row records, on the message. A citation
    # that could not say which snapshot, prompt or taxonomy produced it would
    # resolve to a row nobody can replay.
    recorded = message.versions.model_dump()
    assert set(VERSION_COLUMNS) <= set(recorded)
    assert all(recorded[column] for column in VERSION_COLUMNS)
    assert recorded["enrichment_snapshot_version"] == reference.snapshot_version


def test_claim1_the_evidence_the_message_carries_is_the_store_field_for_field(
    reference: Run,
):
    """The message is a projection of stored rows, not a second account of them.

    `concept/03`: agent output is stored as typed rows with citation joins, and
    the sink reads them back. So every evidence row on the topic has to be the
    row the engine holds — same source, same tier, same snapshot, same claim.
    """
    held = stored_evidence(reference.connection, reference.projections[0].context_id)
    seen = 0
    for entity in reference.message.entities:
        for evidence in entity.evidence:
            if evidence.evidence_id is None:
                continue
            row = held[evidence.evidence_id]
            assert evidence.source_id == row["source_id"]
            assert evidence.source_tier == row["source_tier"]
            assert evidence.evidence_tier == row["evidence_tier"]
            assert evidence.snapshot_version == row["snapshot_version"]
            assert evidence.classification == row["classification"]
            assert evidence.status == row["status"]
            assert entity.entity_value == row["entity_value"]
            seen += 1
    assert seen == len(held), (
        f"the message carries {seen} of the {len(held)} evidence rows the store "
        f"holds for this context"
    )


INVENTED = "a" * 64


def inventing_script(requests: tuple[AgentRequest, ...]) -> list[Any]:
    """A model that cites an identifier of the right shape that it was never shown."""
    return [
        answered(triage_answer(INVENTED)) for _ in requests for _ in range(RETRY.attempts)
    ]


@pytest.fixture
def inventing_run(
    migrated_engine: psycopg.Connection, broker_bootstrap: str, tmp_path: Path
) -> Run:
    return run_pipeline(
        migrated_engine,
        bootstrap=broker_bootstrap,
        tmp_path=tmp_path,
        script=inventing_script,
    )


def test_claim1_a_citation_to_evidence_the_rendering_did_not_show_is_refused(
    inventing_run: Run,
):
    """The other direction of CLAIM-1, and the one that makes it a property.

    "Every verdict cites stored evidence" is worth nothing if a verdict citing
    something else were stored anyway. So the model here answers with a citation
    of exactly the right shape — sixty-four hex characters — naming evidence the
    rendering did not show, three times, and what reaches the topic is a **typed
    failure with no verdict**: the pairing check refuses it, the retry feeds the
    validation error back, and the run ends without a classification rather than
    with one nobody can resolve.
    """
    assert INVENTED not in inventing_run.requests[0].rendering.evidence_ids

    message = inventing_run.message
    assert message.outcome_kind == "typed_failure"
    assert message.failure_reason == "schema_invalid"
    assert message.verdict is None
    assert message.citations == ()
    assert INVENTED in message.failure_detail


# --- CLAIM-4: no autonomous remediation --------------------------------------


def test_claim4_the_only_address_python_code_dialled_in_the_run_was_the_model(
    reference: Run, broker_bootstrap: str
):
    """*No autonomous remediation occurs — there is no write path to any external system.*

    Read off the sockets rather than off the module list: every outbound
    connection **Python code** opened while the run was in flight is recorded,
    and there is exactly one address among them. A component that "just called an
    API" to block an address would be a second one, and it would be caught here
    whether it was written with `urllib`, `http.client`, a vendored SDK or a
    socket of its own — which an import scan is not.

    **What this recorder cannot see is measured here rather than assumed.** The
    broker and the engine are reached through C clients — librdkafka under
    `confluent_kafka` and libpq under `psycopg` — which call `connect(2)`
    themselves and never pass through `socket.socket.connect`, so neither
    appears below. That is asserted in both directions: the broker's port is
    absent, and the model endpoint's is present, so a run that had armed nothing
    fails rather than passing quietly. Those two clients are the whole of what
    may reach the network in C: `tests/test_dependency_boundary.py` closes the
    approved distribution set by equality and `tests/test_broker.py` closes which
    module may hold a Kafka client at all.

    Three things are outside the boundary and each is named rather than implied.
    The **engine** is the single store and writing to it is what the pipeline is.
    The **ingest topic** is produced to by this harness standing in for a sensor,
    which in a deployment is outside the system (`concept/01`). What is left —
    the one channel the package itself writes through — is the **output topic**,
    which is egress and not an actuator.
    """
    _, _, broker_port = broker_bootstrap.rpartition(":")
    _, _, endpoint_port = reference.endpoint_host.rpartition(":")
    dialled = {address[1] for address in reference.connected_to}

    assert dialled == {int(endpoint_port)}, (
        f"the run dialled {sorted(dialled)} from Python; the only address it may "
        f"reach that way is the model endpoint {reference.endpoint_host}"
    )
    assert int(broker_port) not in dialled, (
        "the broker was reached through Python rather than through librdkafka. "
        "That is not a failure of the pipeline — it means this recorder's blind "
        "spot has moved, and the assertion above is now covering a different set "
        "of connections than its docstring says"
    )


def test_claim4_the_only_thing_that_left_the_network_was_a_prompt(reference: Run):
    """The disclosure ledger, off the topic: one channel, and it is inference.

    `concept/07`'s disclosure table makes a prompt egress and requires it to be
    recorded. What the ledger being *only* `model_inference` says here is that no
    provider was called and nothing else was sent anywhere — and the ledger is on
    the message rather than in a log, so a consumer can check it too.
    """
    channels = {row.channel for row in reference.message.disclosures}
    assert channels == {disclosure.MODEL_INFERENCE}
    for row in reference.message.disclosures:
        assert row.disclosed_to == reference.endpoint_host
        assert "://" not in row.disclosed_to, "a host, never a URL"
        assert row.query_digest and row.send_policy_version


def test_claim4_nothing_on_the_output_topic_names_an_action_to_take(reference: Run):
    """No field a consumer could read as an instruction, anywhere in the message.

    `concept/01` rejects a Response Agent *"even as a future lane in a diagram"*,
    and `tests/test_contracts.py` holds the agent contract to the same field set.
    The output message is the other end of the same rule and had no test for it:
    it is the one shape that leaves this system, so a `recommended_actions` here
    would be the remediation channel arriving through the consumer.
    """
    from test_contracts import FORBIDDEN_FIELDS

    checked = set()
    for model in _message_models(sink.OutputMessage):
        offending = sorted(set(model.model_fields) & FORBIDDEN_FIELDS)
        assert offending == [], f"{model.__name__} declares {offending}"
        checked.add(model.__name__)
    assert {"OutputMessage", "EmittedEntity", "EmittedEvidence", "EmittedGap"} <= checked

    # And the instance that really crossed the wire carries nothing beyond the
    # shape: `extra="forbid"` is what makes the absence a property rather than a
    # statement about the fields somebody remembered to look at.
    on_the_wire = json.loads(reference.message.model_dump_json())
    assert set(on_the_wire) == set(sink.OutputMessage.model_fields)


def _message_models(model: Any, seen: set[Any] | None = None) -> Iterator[Any]:
    """Every Pydantic model reachable from `model`'s fields, including itself."""
    from pydantic import BaseModel

    seen = set() if seen is None else seen
    if model in seen:
        return
    seen.add(model)
    yield model
    for field_info in model.model_fields.values():
        for candidate in (field_info.annotation, *getattr(field_info.annotation, "__args__", ())):
            if isinstance(candidate, type) and issubclass(candidate, BaseModel):
                yield from _message_models(candidate, seen)


# --- CLAIM-2: outages, staleness, invalid responses and partial context -------
#
# Four conditions, and `concept/instruction.md` §2 forbids collapsing any of them
# into another. Each one below is built as its own run, because a status is a
# property of a window and a load history rather than of an assertion — and each
# is read off the **output topic**, because "visible" means visible to whoever
# reads the message, not to whoever reads the store.


def stale_snapshot(
    connection: psycopg.Connection, matched: str, window: datetime, settings: Settings
) -> None:
    """One snapshot, loaded two days before the window it is read for.

    ThreatFox's declared refresh interval is an hour
    (`helena.enrichment.THREATFOX_MIN_FETCH_INTERVAL_SECONDS`), so a snapshot
    this old is one the publisher has already moved past. The claim stands:
    `concept/02` is explicit that removal from a feed is not exoneration.
    """
    load_feed(
        connection,
        targeted(THREATFOX_EXTRACT, matched),
        now=window - timedelta(days=2),
        settings=settings,
    )


@pytest.fixture
def stale_run(
    migrated_engine: psycopg.Connection, broker_bootstrap: str, tmp_path: Path
) -> Run:
    return run_pipeline(
        migrated_engine,
        bootstrap=broker_bootstrap,
        tmp_path=tmp_path,
        script=escalating_script,
        feed=stale_snapshot,
    )


def test_claim2_stale_evidence_reaches_the_topic_as_stale_and_keeps_its_claim(
    stale_run: Run,
):
    """A claim with a date on it, and a reader who can see the date.

    Two halves, and dropping either is the failure. The status has to say `stale`
    — a consumer that read it as `ok` would treat a snapshot the publisher has
    replaced as current — and the claim has to still be there, because
    `concept/02` says an aged snapshot is evidence with a date on it rather than
    evidence withdrawn.
    """
    row = one_evidence(stale_run, stale_run.matched)
    assert row.status == enrichment.STALE
    assert row.classification == "malicious"
    assert row.snapshot_version == stale_run.snapshot_version
    assert row.snapshot_loaded_at < stale_run.window_start
    # And the verdict that cited it is still a verdict: staleness is a property
    # of the evidence, not a reason to refuse to assess.
    assert stale_run.message.outcome_kind == "verdict"


def one_evidence(run: Run, entity_value: str) -> sink.EmittedEvidence:
    """The single evidence row the message carries about one entity."""
    rows = run.entity(entity_value).evidence
    assert len(rows) == 1, f"{entity_value} carries {len(rows)} evidence rows"
    return rows[0]


def refusing_script(requests: tuple[AgentRequest, ...]) -> list[Any]:
    """A model that answers, and whose answer is not the schema it was asked for.

    Prose where a JSON object was asked for — the failure mode that is *not* an
    outage: the endpoint was reachable, it answered, it billed for the tokens and
    the answer is unusable. `RetryPolicy(attempts=3)` means three of these per
    run, and there are exactly three, so a fourth call would fail the endpoint's
    own assertion rather than silently pass.
    """
    return [
        answered("Certainly! Here is my assessment of this host: it looks fine to me.")
        for _ in requests
        for _ in range(RETRY.attempts)
    ]


@pytest.fixture
def invalid_model_run(
    migrated_engine: psycopg.Connection, broker_bootstrap: str, tmp_path: Path
) -> Run:
    return run_pipeline(
        migrated_engine,
        bootstrap=broker_bootstrap,
        tmp_path=tmp_path,
        script=refusing_script,
    )


def test_claim2_an_invalid_model_response_reaches_the_topic_as_a_typed_failure(
    invalid_model_run: Run,
):
    """`concept/instruction.md` §2: a failed run is stored as a typed failure and is emitted.

    Never a verdict and never a silent drop — which are the two things an
    implementation does with an unparseable answer when nobody is watching. The
    run below bills tokens, retries the declared number of times and ends with a
    row that says what went wrong and claims nothing about the host.
    """
    message = invalid_model_run.message
    assert message.outcome_kind == "typed_failure"
    assert message.failure_reason == "schema_invalid"
    assert message.failure_detail
    assert message.verdict is None
    assert message.classification is None
    assert message.confidence is None
    assert message.narrative is None
    # It is emitted, and it is emitted as the triage run's: a failure does not
    # escalate (`concept/04`), so no analyst ran and there is no triage decision
    # to carry beside a verdict that does not exist.
    assert invalid_model_run.emission.emitted == 1
    assert message.emitter == TRIAGE
    assert message.triage is None
    # The versions are still recorded. A failure with no version set would be a
    # row nobody could replay to find out what was asked.
    assert message.versions.prompt_version == TRIAGE_PROMPT.version
    assert message.versions.enrichment_snapshot_version == invalid_model_run.snapshot_version
    # `model_version` is NULL exactly where nothing answered; something did.
    assert message.versions.model_version


def test_claim2_partial_context_reaches_the_topic_as_gaps_and_negative_space(
    reference: Run,
):
    """Two different absences, and a reader who can tell them apart.

    The first is the agent's: a declared `Gap`, one of `concept/02`'s seven
    kinds, carried to the topic with its kind intact rather than folded into the
    confidence.

    The second is the store's, and it is the one an implementation loses by
    accident: a lookup that completed and found nothing is `ok` / `no_match` with
    an identifier of its own, which `concept/02` insists is an answer and not an
    absence. A consumer that mapped it onto "no evidence" would have read a
    completed negative as a gap, and `concept/02` says why that matters more here
    than anywhere else — with sparse coverage an enriched context is mostly
    negative space, so the negative space is most of what is being carried.
    """
    message = reference.message
    assert [gap.kind for gap in message.gaps] == ["missing"]
    assert message.gaps[0].detail

    answered_nothing = [
        row
        for entity in message.entities
        for row in entity.evidence
        if row.classification == enrichment.NO_MATCH
    ]
    assert answered_nothing, "no entity got a completed lookup that found nothing"
    assert all(row.status == enrichment.OK for row in answered_nothing)
    # A completed negative has no `evidence_id`, and that is the join rather than
    # an omission: `no_match` is the LEFT JOIN finding nothing to join, so there
    # is no stored row to identify. The consequence is worth saying out loud —
    # **a negative is an answer and is not a citable one**, so an agent cannot
    # cite "nobody has heard of this" and CLAIM-1 is about the positives.
    assert all(row.evidence_id is None for row in answered_nothing)
    # And the hit beside them, so the message really does carry both: negative
    # space that reads as negative space is only worth anything where a positive
    # would have read differently.
    assert one_evidence(reference, reference.matched).classification == "malicious"


def test_a_source_answers_no_match_about_entity_types_it_declares_it_does_not_cover(
    reference: Run,
):
    """A finding this run produced, recorded as a test rather than as a sentence.

    `helena.enrichment.SourceDescriptor` declares which kinds of indicator a
    source is about, and refuses a claim outside them — *"a JA3 list has nothing
    to say about a domain"*. The **join** does not read that declaration:
    `sql/migrations/0015_enriched_context.sql` takes its source list from the
    load ledger and LEFT JOINs every entity against every source that has ever
    been asked, so ThreatFox — which declares `address`, `domain` and `url` —
    produces `ok` / `no_match` rows for the `fingerprint` entities in this
    capture as well.

    It does not break the rule `no_match` exists for: the row is still a lookup
    outcome and still not a statement of safety, and nothing reads it as one. What
    it does is **overstate coverage** — a reader counting the sources consulted
    for a JA3 fingerprint counts one that could not have consulted anything, and
    `helena.enrichment.source_diversity` counts over claims, so a future
    composition rule reading these rows would count it too.

    Fixing it is not this increment's to do: the filter needs the declared entity
    types on the SQL side, and 0015's head refuses a second copy of the registry
    in SQL for the reason that a copy can disagree with the decision it copies. So
    it is written up in `docs/acceptance.md` and in the task report, and pinned
    here so that a change in either direction is noticed.
    """
    fingerprints = [
        entity for entity in reference.message.entities if entity.entity_type == "fingerprint"
    ]
    assert fingerprints, "the capture produced no fingerprint entities"
    assert "fingerprint" not in enrichment.source("threatfox").entity_types
    assert all(
        [(row.source_id, row.status, row.classification) for row in entity.evidence]
        == [("threatfox", enrichment.OK, enrichment.NO_MATCH)]
        for entity in fingerprints
    )


# --- CLAIM-3: a second enrichment source, and the outage of the first ---------
#
# `concept/01`: *a new enrichment source can be added without changing identity,
# provenance or assessment contracts.* The way to check that is to add one, and
# the way to add one is the way `sql/migrations/0014_feed_mapping_views.sql` says:
# *"Adding a feed is a mapping view and a line here."* So this section builds the
# migration set a second source would ship as, applies it into a schema of its
# own, and runs the whole pipeline over it.
#
# The same run carries CLAIM-2's fourth condition — a **source outage** — and not
# by coincidence. A source whose loads have all failed has no snapshot, and
# `RequestVersions.enrichment_snapshot_version` is one identifier, so a
# deployment whose *only* source has never loaded cannot build a request at all
# (`triage_request` raises `AcceptanceGap` saying so). A second source is what
# makes the outage of the first observable end to end, which is why it is here.

DEMO_SOURCE = "demolist"
DEMO_TABLE = "helena_reference_demolist"
DEMO_URL = "https://demolist.invalid/list.csv"

#: The second source's whole schema: its reference table, its mapping view, and
#: the line in the union. Appended to a copy of 0014, because that file is where
#: the union is and a view cannot be extended from a later migration without
#: recreating everything that reads it — which is itself a finding, written up in
#: `docs/acceptance.md`.
SECOND_SOURCE_SQL = f"""
-- {DEMO_TABLE}: the second source's snapshot, as its loader read it.
--
-- Layer:    reference. The same place helena_reference_threatfox sits.
-- Object:   TABLE. The snapshot itself; there is nothing below it.
-- Reads:    nothing.
-- Read by:  helena_reference_evidence_{DEMO_SOURCE} below.
CREATE TABLE IF NOT EXISTS {DEMO_TABLE} (
    tenant           VARCHAR NOT NULL,
    sensor           VARCHAR NOT NULL,
    snapshot_version VARCHAR NOT NULL,
    -- The publisher's own key for the record, as ThreatFox's indicator id is.
    record_id        VARCHAR NOT NULL,
    entity_type      VARCHAR NOT NULL,
    entity_value     VARCHAR NOT NULL,
    classification   VARCHAR NOT NULL,
    taxonomy_version VARCHAR NOT NULL,
    confidence_level INT NOT NULL,
    first_seen       TIMESTAMPTZ,
    PRIMARY KEY (tenant, sensor, snapshot_version, record_id)
);


-- helena_reference_evidence_{DEMO_SOURCE}: its rows in the evidence shape.
--
-- Layer:    reference.
-- Object:   VIEW (plain). A projection with a digest in it.
-- Reads:    {DEMO_TABLE}
-- Read by:  helena_reference_evidence below.
--
-- The digest is `sql/migrations/0014`'s, with the port case removed because this
-- source has no port-scoped indicator. That is the point of the exercise: the
-- construction is the evidence contract's and not this feed's, so a second
-- source produces identifiers of the same shape without anything downstream
-- knowing it exists.
CREATE VIEW helena_reference_evidence_{DEMO_SOURCE} AS
SELECT encode(
           sha256(
               convert_to(
                   octet_length(d.tenant)::VARCHAR || ':' || d.tenant
                   || octet_length(d.sensor)::VARCHAR || ':' || d.sensor
                   || octet_length('{DEMO_SOURCE}')::VARCHAR || ':' || '{DEMO_SOURCE}'
                   || octet_length(d.snapshot_version)::VARCHAR
                   || ':' || d.snapshot_version
                   || octet_length(d.entity_type)::VARCHAR || ':' || d.entity_type
                   || octet_length(d.entity_value)::VARCHAR || ':' || d.entity_value
                   || octet_length(d.classification)::VARCHAR || ':' || d.classification
                   || octet_length(d.entity_type)::VARCHAR || ':' || d.entity_type
                   || octet_length(d.entity_value)::VARCHAR || ':' || d.entity_value
                   || octet_length(d.record_id)::VARCHAR || ':' || d.record_id,
                   'UTF8'
               )
           ),
           'hex'
       )                                        AS evidence_id,
       d.tenant,
       d.sensor,
       '{DEMO_SOURCE}'                          AS source_id,
       'C'                                      AS source_tier,
       'enrichment'                             AS evidence_tier,
       d.snapshot_version,
       d.entity_type,
       d.entity_value,
       'ok'                                     AS status,
       d.classification,
       d.taxonomy_version,
       d.confidence_level::DOUBLE PRECISION / 100 AS confidence,
       d.entity_type                            AS scope_type,
       d.entity_value                           AS scope_value,
       d.first_seen,
       NULL::TIMESTAMPTZ                        AS last_seen,
       NULL::TIMESTAMPTZ                        AS valid_until,
       jsonb_build_object('record_id', d.record_id) AS native_evidence
FROM {DEMO_TABLE} d;
"""

#: The line in the union. 0014's own last statement, with the second source added.
SECOND_SOURCE_UNION = (
    "CREATE VIEW helena_reference_evidence AS\n"
    "SELECT * FROM helena_reference_evidence_threatfox\n"
    f"UNION ALL SELECT * FROM helena_reference_evidence_{DEMO_SOURCE};"
)
SHIPPED_UNION = (
    "CREATE VIEW helena_reference_evidence AS\nSELECT * FROM helena_reference_evidence_threatfox;"
)

DEMO_DESCRIPTOR = enrichment.SourceDescriptor(
    source_id=DEMO_SOURCE,
    tier=enrichment.Tier.C,
    entity_types=frozenset({"domain"}),
    # No schedule, like `sslbl-ja3`: a list with no publication cadence is not
    # late, and a refresh interval would make it permanently stale.
    refresh_interval_seconds=None,
    emits=frozenset({"suspicious", enrichment.NO_MATCH}),
    taxonomy_version="v1",
    emit_subset_version="v1",
    aggregator=False,
    caveat="A source that exists to be a second source. Not a feed.",
)


def second_source_migrations(destination: Path) -> Path:
    """`sql/migrations/`, with the feed-mapping migration extended by one source.

    Every file copied byte for byte except `0014_feed_mapping_views.sql`, whose
    union gains a line and which gains the table and the mapping view above.
    `test_claim3_adding_a_source_touched_one_migration_and_no_contract` asserts
    that is the whole of the diff.
    """
    destination.mkdir(parents=True, exist_ok=True)
    for path in sorted(migrations.MIGRATIONS_DIR.glob("*.sql")):
        text = path.read_text()
        if path.name == "0014_feed_mapping_views.sql":
            assert SHIPPED_UNION in text, (
                f"{path.name} no longer holds the union this test extends; the "
                f"second source has to be added to whatever replaced it"
            )
            text = text.replace(
                SHIPPED_UNION, SECOND_SOURCE_SQL + "\n\n" + SECOND_SOURCE_UNION
            )
        (destination / path.name).write_text(text)
    return destination


def load_demolist(
    connection: psycopg.Connection, *, entity_value: str, now: datetime
) -> str:
    """The second source's loader: write the snapshot, then the ledger row.

    The order is `load_threatfox`'s and it is the commit point
    (`tests/test_acceptance_enrichment.py`): the claims are written and flushed
    first, and the ledger row last, so a load in flight has no validity interval
    and its claims cannot be joined.

    It is a dozen lines because that is what a source adapter is once the
    contracts are doing their job — a table write and a `FeedSnapshot`. Nothing
    here computes an evidence identifier, decides a scope or sets a tier: those
    belong to the evidence contract and the mapping view makes them.
    """
    snapshot_version = now.isoformat()
    connection.execute(
        f"INSERT INTO {DEMO_TABLE} (tenant, sensor, snapshot_version, record_id, "
        f"entity_type, entity_value, classification, taxonomy_version, "
        f"confidence_level, first_seen) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
        (
            TENANT,
            SENSOR,
            snapshot_version,
            "demolist-1",
            "domain",
            entity_value,
            "suspicious",
            "v1",
            70,
            now - timedelta(days=7),
        ),
    )
    connection.execute("FLUSH")
    snapshot = enrichment.FeedSnapshot(
        source_id=DEMO_SOURCE,
        attempted_at=now,
        source_url=DEMO_URL,
        outcome=enrichment.LOADED,
        snapshot_version=snapshot_version,
        counts={"entries_read": 1, "claims_stored": 1, "skipped_no_entity": 0},
    )
    connection.execute(
        f"INSERT INTO {enrichment.FEED_SNAPSHOT_TABLE} (tenant, sensor, source_id, "
        f"attempted_at, source_url, outcome, snapshot_version, counts, "
        f"failure_reason, failure_detail) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
        (
            TENANT,
            SENSOR,
            snapshot.source_id,
            snapshot.attempted_at,
            snapshot.source_url,
            snapshot.outcome,
            snapshot.snapshot_version,
            psycopg.types.json.Jsonb(snapshot.counts),
            None,
            None,
        ),
    )
    connection.execute("FLUSH")
    return snapshot_version


def second_source_and_an_outage(
    connection: psycopg.Connection, matched: str, window: datetime, settings: Settings
) -> None:
    """The second source answers about `matched`; the first one's load fails.

    ThreatFox is loaded with bytes that parse to no entries at all, which is the
    failed load `tests/test_acceptance_enrichment.py` builds the same way. It has
    no earlier snapshot, so nothing covers the window and the status is `failed`
    — *we tried and could not* — rather than `missing`.
    """
    load_demolist(connection, entity_value=matched, now=window - timedelta(minutes=1))
    load_feed(connection, b"{}", now=window - timedelta(minutes=1), settings=settings)


@pytest.fixture(scope="module")
def extended_engine(
    engine_dsn: str, tmp_path_factory: pytest.TempPathFactory
) -> Iterator[psycopg.Connection]:
    """A schema migrated from the second source's migration set, and dropped after."""
    directory = second_source_migrations(tmp_path_factory.mktemp("second-source"))
    schema = f"helena_e2e_two_{uuid.uuid4().hex}"
    with psycopg.connect(engine_dsn, autocommit=True, connect_timeout=5) as connection:
        connection.execute(f"CREATE SCHEMA {schema}")
        try:
            connection.execute(f"SET search_path TO {schema}")
            migrations.apply(connection, directory)
            yield connection
        finally:
            connection.execute("SET search_path TO public")
            connection.execute(f"DROP SCHEMA {schema} CASCADE")


@pytest.fixture(scope="module")
def two_sources(
    extended_engine: psycopg.Connection,
    broker_bootstrap: str,
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[Run]:
    """One run over two registered sources: one answering, one out.

    The descriptor is registered for the run and removed after — a source's
    registration is a governed decision (`concept/05`), and a test that left one
    in the catalogue would have made that decision for the project.
    """
    enrichment.SOURCES[DEMO_SOURCE] = DEMO_DESCRIPTOR
    try:
        yield run_pipeline(
            extended_engine,
            bootstrap=broker_bootstrap,
            tmp_path=tmp_path_factory.mktemp("two-sources"),
            script=escalating_script,
            feed=second_source_and_an_outage,
        )
    finally:
        del enrichment.SOURCES[DEMO_SOURCE]


def test_claim3_the_second_sources_claim_reaches_the_agent_and_the_topic(
    two_sources: Run,
):
    """*A new enrichment source can be added without changing identity, provenance
    or assessment contracts.*

    The claim has to go all the way: into the enriched context, into the
    rendering the model saw, into a citation, and onto the output topic carrying
    its own source, tier and snapshot. A source that reached the store and not the
    prompt would be a source nothing uses.
    """
    row = [
        evidence
        for evidence in two_sources.entity(two_sources.matched).evidence
        if evidence.source_id == DEMO_SOURCE
    ]
    assert len(row) == 1, f"the second source put {len(row)} rows on the entity"
    (claim,) = row
    assert claim.status == enrichment.OK
    assert claim.classification == "suspicious"
    assert claim.source_tier == "C"
    assert claim.evidence_tier == enrichment.ENRICHMENT_TIER
    assert claim.snapshot_version == two_sources.snapshot_version
    assert claim.native_evidence == {"record_id": "demolist-1"}

    shown = set(two_sources.requests[0].rendering.evidence_ids)
    assert claim.evidence_id in shown, "the rendering did not show the second source"
    assert claim.evidence_id in {
        citation.evidence_id for citation in two_sources.message.citations
    }


def test_claim3_the_second_sources_identifier_is_the_contracts_and_not_its_own(
    two_sources: Run,
):
    """The evidence identifier is the evidence contract's construction, in SQL and in Python.

    `helena.enrichment.evidence_id` is the Python copy of the digest
    `sql/migrations/0014` builds, and `tests/test_mapping.py` asserts the two
    agree for a ThreatFox row. What is asserted here is that they agree for a
    source that module has never heard of — which is what "without changing
    identity" means: the second source's loader computed no identifier at all,
    and the one it got is the one the contract makes.
    """
    claim = next(
        evidence
        for evidence in two_sources.entity(two_sources.matched).evidence
        if evidence.source_id == DEMO_SOURCE
    )
    assert claim.evidence_id == enrichment.evidence_id(
        tenant=TENANT,
        sensor=SENSOR,
        source_id=DEMO_SOURCE,
        snapshot_version=claim.snapshot_version,
        entity_type="domain",
        entity_value=two_sources.matched,
        classification="suspicious",
        scope_type="domain",
        scope_value=two_sources.matched,
        native_record="demolist-1",
    )


def test_claim3_adding_a_source_touched_one_migration_and_no_contract(
    tmp_path: Path, two_sources: Run
):
    """What had to change to add it, checked by diffing rather than by recalling.

    Two halves. The migration set the second source ships as differs from the
    shipped one in exactly **one** file, and it is the feed-mapping migration
    whose own head says *"adding a feed is a mapping view and a line here"*.

    And the contracts a consumer, a replay or an agent depends on are the
    shipped ones, unchanged, while a message carrying the second source's claim
    was on the topic: the agent contract's version, the nine version dimensions,
    the sink's column list and the output message's field set. `two_sources` is
    a parameter rather than unused — the assertion is about a tree that produced
    that run, not about a tree nobody ran.
    """
    rebuilt = second_source_migrations(tmp_path / "migrations")
    differ = sorted(
        path.name
        for path in sorted(rebuilt.glob("*.sql"))
        if path.read_bytes() != (migrations.MIGRATIONS_DIR / path.name).read_bytes()
    )
    assert differ == ["0014_feed_mapping_views.sql"]
    assert {path.name for path in rebuilt.glob("*.sql")} == {
        path.name for path in migrations.MIGRATIONS_DIR.glob("*.sql")
    }

    assert CONTRACT_VERSION == "v1"
    assert VERSION_COLUMNS == (
        "model_version",
        "prompt_version",
        "schema_version",
        "rendering_version",
        "taxonomy_version",
        "enrichment_snapshot_version",
        "normalization_snapshot_version",
        "policy_version",
        "aggregation_version",
    )
    assert two_sources.message.versions.schema_version == CONTRACT_VERSION
    assert set(sink.OutputMessage.model_fields) == set(
        json.loads(two_sources.message.model_dump_json())
    )


def test_claim2_a_source_outage_reaches_the_topic_as_failed_and_never_as_no_match(
    two_sources: Run,
):
    """*Source outages ... are visible rather than absorbed.*

    ThreatFox's only load in this run failed, and it had no earlier snapshot, so
    there is nothing to consult for this window. The row that reaches the topic
    says `failed` and carries **no classification at all** — `concept/05` rule 4:
    a query that did not complete emits a typed error and no taxonomy object, and
    `concept/02` is emphatic that it is never `no_match` and never `unknown`.

    Both are on the same message, which is what makes this worth running end to
    end: one source answered and one did not, and a consumer can tell which.
    """
    rows = {
        evidence.source_id: evidence
        for evidence in two_sources.entity(two_sources.matched).evidence
    }
    assert set(rows) == {"threatfox", DEMO_SOURCE}

    out = rows["threatfox"]
    assert out.status == enrichment.QUERY_FAILED
    assert out.classification is None, "a query that did not complete classified something"
    assert out.evidence_id is None
    assert out.snapshot_version is None
    assert out.confidence is None

    assert rows[DEMO_SOURCE].status == enrichment.OK
    assert rows[DEMO_SOURCE].classification == "suspicious"
    # And the run still produced a verdict: an outage is a gap in the evidence,
    # not a reason to stop assessing — nor to let the verdict imply the source
    # said nothing.
    assert two_sources.message.outcome_kind == "verdict"


# --- The gap the run found ---------------------------------------------------


@pytest.fixture
def only_source_out(
    migrated_engine: psycopg.Connection, broker_bootstrap: str, tmp_path: Path
) -> Callable[[], Run]:
    def run() -> Run:
        return run_pipeline(
            migrated_engine,
            bootstrap=broker_bootstrap,
            tmp_path=tmp_path,
            script=escalating_script,
            feed=lambda connection, matched, window, settings: load_feed(
                connection, b"{}", now=window - timedelta(minutes=1), settings=settings
            ),
        )

    return run


def test_a_deployment_whose_only_source_is_out_cannot_record_a_snapshot_version(
    only_source_out: Callable[[], Run],
):
    """The second finding, and the reason the outage above needed two sources.

    `RequestVersions.enrichment_snapshot_version` is **one** identifier — "the
    feed snapshot the enrichment join matched against"
    (`docs/decisions/0008-version-registry.md`) — and it is required. A
    deployment whose only source has never loaded successfully has no snapshot to
    name, so there is no request it can build for a context it can otherwise
    assess: every entity's status is `failed`, which is exactly the state the
    pipeline is supposed to carry through and emit.

    Nothing is invented here to get past it. A sentinel would be a version naming
    no snapshot, and a plausible-looking one is what the version registry exists
    to prevent. So the harness raises, and the refusal is the test — the fix is a
    contract question (`concept/08-open-questions.md` still has the snapshot and
    versioning scheme open) and is written up in `docs/acceptance.md`.
    """
    with pytest.raises(AcceptanceGap, match="no feed snapshot was valid"):
        only_source_out()


# --- The checklist -----------------------------------------------------------


def _paragraph(text: str, heading: str) -> str:
    """The paragraph beginning `heading`, as one line."""
    found = re.search(rf"\*\*{re.escape(heading)}:\*\*(.+?)\n\n", text, re.DOTALL)
    assert found, f"concept/01-goal-and-scope.md no longer has a {heading!r} paragraph"
    return " ".join(found.group(1).split())


def _clauses(paragraph: str) -> tuple[str, ...]:
    return tuple(clause.strip().rstrip(".") for clause in paragraph.split(";"))


def test_the_claims_this_module_executes_are_the_notes_own():
    """`concept/01`'s paragraph, parsed on every run.

    The three ways this gate rots are closed the way
    `tests/test_conformance.py` closes them for the must-never-happen table: a
    claim added to the note has no identifier here and is red; a claim reworded
    no longer matches and is red; a claim removed leaves an identifier naming
    nothing and is red.
    """
    note = NOTE.read_text()
    assert _clauses(_paragraph(note, "Claimable")) == tuple(CLAIMS.values())
    assert _clauses(_paragraph(note, "Not claimable")) == NOT_CLAIMABLE


def test_every_claimable_property_has_a_test_named_for_it():
    """`CLAIM-3` is executed by `test_claim3_…`, or this module is a document."""
    here = Path(__file__).read_text()
    named = {
        found.group(1)
        for found in re.finditer(r"^def (test_claim(\d)_\w+)", here, re.MULTILINE)
    }
    for identifier in CLAIMS:
        number = identifier.split("-")[1]
        covering = {name for name in named if name.startswith(f"test_claim{int(number)}_")}
        assert covering, f"{identifier} has no test named for it: {CLAIMS[identifier]}"
    numbered = {int(found.group(2)) for found in re.finditer(r"^def (test_claim(\d)_\w+)", here, re.MULTILINE)}
    assert numbered == {int(identifier.split("-")[1]) for identifier in CLAIMS}


def test_the_checklist_states_the_claims_and_the_ones_it_may_not_make():
    """`docs/acceptance.md` is the artifact; this is what keeps it true.

    Both halves have to be present and the second is the one that matters: a
    checklist that listed what a run demonstrates and left out what it does not
    would be read as a claim about everything it did not mention.
    """
    assert CHECKLIST.exists(), f"{CHECKLIST} is the acceptance checklist task 52 writes"
    # Flattened, because a claim in a markdown file is wrapped across lines and a
    # test that required it on one line would be a formatting rule.
    checklist = " ".join(CHECKLIST.read_text().split())
    for identifier, claim in CLAIMS.items():
        assert claim in checklist, f"the checklist does not state {identifier}: {claim}"
        assert identifier in checklist, f"the checklist does not name {identifier}"
    for refused in NOT_CLAIMABLE:
        assert refused in checklist, f"the checklist does not refuse {refused!r}"


def test_the_checklist_names_the_test_that_demonstrates_each_claim():
    """Every test the checklist cites resolves, so deleting one is red at the claim."""
    checklist = CHECKLIST.read_text()
    here = Path(__file__).read_text()
    cited = set(re.findall(r"`(test_end_to_end::(\w+))`", checklist))
    assert cited, "the checklist cites no test; it is then a document and not a gate"
    for _, name in cited:
        assert re.search(rf"^def {name}\(", here, re.MULTILINE), (
            f"docs/acceptance.md cites {name}, which tests/test_end_to_end.py "
            f"does not define"
        )
    for identifier in CLAIMS:
        section = checklist.split(identifier, 1)[1]
        assert "test_end_to_end::" in section.split("CLAIM-")[0], (
            f"{identifier} cites no test in the checklist"
        )
