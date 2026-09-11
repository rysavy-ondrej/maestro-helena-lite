"""The sink: the emitted message, and the property that nothing lives only in it.

Mirrors `src/helena/sink.py` and `sql/migrations/0019_sink.sql`. The sentences
under test are `concept/03-architecture.md`'s:

- *"**Sink** | A sink over a view joining the enriched context, the terminal
  verdict and the cited evidence."*
- *"The message carries context identity and version, host and window, the entity
  rows with their traffic characteristics and enrichment evidence (with
  `no_match`, `stale`, `failed` and `missing` distinguishable), the verdict and
  its path, the citations, the retrieval and disclosure trace, and the full
  version set."*
- *"The output topic. Egress only. **Nothing may be recoverable only from it.**"*
- *"A context that was escalated is emitted **once**, carrying the analyst's
  verdict and the triage decision that led to it."*

**Every one of these runs against a real engine over rows a real writer wrote.**
The context and its entities come from the committed capture through the real
normalizer, the enrichment evidence from the committed ThreatFox extract through
the real loader, and the assessment from `helena.orchestration.AssessmentStore`.
A test that built the view's inputs by hand would be testing the hand.

The load-bearing one is
`test_every_field_of_the_message_is_recoverable_from_the_engine`: every field of
every object in the payload is recovered by a SQL query written against the
underlying tables — never against the sink view the message came out of — and
compared. `RECOVERED_FROM` is the map, and the structural test beside it fails
the moment a field is added without a route, so a field that exists only in the
topic arrives as a red test rather than as an un-auditable message.
"""

from __future__ import annotations

import json
import re
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg
import pytest

from helena import (
    analyst,
    budgets,
    disclosure,
    migrations,
    orchestration,
    sink,
    triage,
)
from helena.config import IngestionIdentity, Settings
from helena.contracts.v1 import (
    CACHE_HIT,
    CONTRACT_VERSION,
    CONTRADICTING,
    LIVE_QUERY,
    MISSING,
    MODEL_UNAVAILABLE,
    SCHEDULED_TRIAGE,
    STANCES,
    SUPPORTING,
    AgentFailure,
    AgentRequest,
    AgentResult,
    Citation,
    Cost,
    EvidencePackage,
    Gap,
    RenderedSection,
    Rendering,
    RequestVersions,
    RetrievalStep,
    SECTIONS,
)
from helena.enrichment import QueryFailure, load_threatfox
from helena.normalizer import EventStore, Normalizer, describe_capture
from helena.observability import Redactor
from helena.policy import v1 as rule
from helena.taxonomy import ANALYST, TRIAGE
from helena.versions import VERSION_COLUMNS

FIXTURES = Path(__file__).resolve().parent / "fixtures"
FIXTURE_CAPTURES = FIXTURES / "captures"
#: The same capture `tests/test_enriched.py` and `tests/test_context.py` use —
#: ten records covering every layer, so the entity rows are real ones.
LAYERS_CAPTURE = "ace6ca33f7bf8aa949f79124abf33fc115cfd0909e9dea798f4762cf87af8318"
THREATFOX_FIXTURE = FIXTURES / "threatfox" / "export.json"
RAW = THREATFOX_FIXTURE.read_bytes()
MESSAGE_SCHEMA = FIXTURES / "sink" / "message-v1.json"

TENANT, SENSOR = "tenant-under-test", "sensor-under-test"
OTHER_TENANT = "another-tenant"
FEED_URL = "https://threatfox.invalid/export/json/recent/"
WINDOW_SECONDS = 300
ASSESSED_AT = datetime(2026, 9, 11, 9, 0, tzinfo=timezone.utc)

ENVIRONMENT = {
    "LLM_URL": "http://model.invalid/v1",
    "LLM_TOKEN": "token-under-test",
    "LLM_MODEL": "model-under-test",
    "HELENA_TENANT": TENANT,
    "HELENA_SENSOR": SENSOR,
    "HELENA_INPUT_FORMAT": "flow-json",
    "ABUSECH_AUTH_KEY": "abusech-key-under-test",
    "VIRUSTOTAL_AUTH_KEY": "virustotal-key-under-test",
    "RISINGWAVE_DSN": "postgresql://root@localhost:4566/dev",
    "KAFKA_BOOTSTRAP_SERVERS": "localhost:9092",
    "HELENA_INGEST_TOPIC": "helena.ingest",
}

TRIAGE_PROMPT = triage.version("v1")
ANALYST_PROMPT = analyst.version("v1")
BUDGET_POLICY = budgets.load()
SEND_POLICY = disclosure.send_policy()
NO_PRICES = budgets.model_prices()
ENDPOINT = "model.invalid:8443"
#: An analyst-tier identifier: a citation that resolves to no row of the enriched
#: context, which is why `cited_as` is a denormalization and not the list.
RETRIEVED = "f" * 64


def settings() -> Settings:
    return Settings.load(environ=ENVIRONMENT, env_file=None)


def identity(tenant: str = TENANT) -> IngestionIdentity:
    return IngestionIdentity(tenant=tenant, sensor=SENSOR)


# --- A real context, real entities and real enrichment -----------------------


def store_capture(connection: psycopg.Connection, path: Path) -> None:
    """The layer capture re-stamped into the window `now` falls in, ingested for real.

    Re-stamped for the reason `tests/test_rendering.py`'s `live` fixture is:
    `helena_signal_host_context_live` is bounded by the retention horizon, and the
    committed capture is dated 2024-06-01, so its contexts are outside it. The
    sink joins the context through that view because it is the one object that
    defines what a citation pins (`sql/migrations/0009`), so a context the
    boundary has dropped is exactly the `context_resolved = FALSE` case and not
    the ordinary one.
    """
    records = [
        json.loads(line)
        for line in (FIXTURE_CAPTURES / f"{LAYERS_CAPTURE}.jsonl").read_bytes().splitlines()
    ]
    window = float(int(time.time() // WINDOW_SECONDS) * WINDOW_SECONDS)
    path.write_bytes(
        b"".join(
            json.dumps({**record, "ts": window + 1}).encode() + b"\n"
            for record in records
        )
    )
    configured = settings()
    normalizer = Normalizer.from_settings(configured)
    events = EventStore(connection=connection, identity=configured.identity)
    for result in normalizer.normalize_capture(describe_capture(path)):
        events.record(result)
    connection.execute("FLUSH")


def load_feed(connection: psycopg.Connection, raw: bytes, *, now: datetime):
    return load_threatfox(
        connection,
        tenant=TENANT,
        sensor=SENSOR,
        source_url=FEED_URL,
        redactor=Redactor.from_settings(settings()),
        raw=raw,
        now=now,
    )


def targeted(raw: bytes, entity_value: str, ioc_type: str = "domain") -> bytes:
    """The committed extract with one entry repointed at an entity the capture has.

    `tests/test_enriched.py`'s device, for its reason: the real feed and the real
    capture have nothing in common, which is realistic and useless for a join.
    """
    document = json.loads(raw)
    key = sorted(document)[0]
    document[key][0]["ioc_type"] = ioc_type
    document[key][0]["ioc_value"] = entity_value
    return json.dumps(document).encode()


def an_entity(connection: psycopg.Connection, entity_type: str = "domain") -> str:
    value = connection.execute(
        "SELECT entity_value FROM helena_signal_context_entities "
        "WHERE entity_type = %s ORDER BY entity_value LIMIT 1",
        (entity_type,),
    ).fetchone()
    assert value, f"the capture produced no {entity_type} entity"
    return value[0]


class Snapshot:
    """One real context, and the identifiers an assessment of it would carry."""

    def __init__(self, connection: psycopg.Connection) -> None:
        self.connection = connection
        row = connection.execute(
            "SELECT context_id, context_version, host, window_start, window_end "
            "FROM helena_signal_host_context_live "
            "WHERE tenant = %s AND sensor = %s ORDER BY window_start LIMIT 1",
            (TENANT, SENSOR),
        ).fetchone()
        assert row, "the capture produced no context"
        (
            self.context_id,
            self.context_version,
            self.host,
            self.window_start,
            self.window_end,
        ) = row

    def evidence_id(self, entity_value: str) -> str:
        found = self.connection.execute(
            "SELECT evidence_id FROM helena_analytical_enriched_context "
            "WHERE context_id = %s AND entity_value = %s AND evidence_id IS NOT NULL "
            "LIMIT 1",
            (self.context_id, entity_value),
        ).fetchone()
        assert found, f"nothing in the enriched context matched {entity_value!r}"
        return found[0]


def a_context(
    connection: psycopg.Connection, path: Path, *, loaded_at: timedelta | None
) -> psycopg.Connection:
    """One real context, its entities, and optionally one snapshot over them.

    `loaded_at` is how long BEFORE the window the feed loaded; `None` loads
    nothing at all, which is the deployment that has asked no source.
    """
    store_capture(connection, path)
    if loaded_at is not None:
        load_feed(
            connection,
            targeted(RAW, an_entity(connection)),
            now=Snapshot(connection).window_start - loaded_at,
        )
        connection.execute("FLUSH")
    return connection


@pytest.fixture
def enriched(
    migrated_engine: psycopg.Connection, tmp_path: Path
) -> psycopg.Connection:
    """The capture through the normalizer and the extract through the loader.

    One entry of the extract is repointed at a domain the capture really
    contains, so the enriched context holds a claim, `no_match` rows for every
    other entity, and an evidence identifier a citation can resolve against. The
    snapshot loads a minute before the window, so its status is `ok`.
    """
    return a_context(migrated_engine, tmp_path / "restamped.jsonl",
                     loaded_at=timedelta(seconds=60))


@pytest.fixture
def matched(enriched: psycopg.Connection) -> str:
    return an_entity(enriched)


# --- Assessments over that context -------------------------------------------


def versions(**overrides: str) -> RequestVersions:
    return RequestVersions(
        **{
            "prompt_version": TRIAGE_PROMPT.version,
            "schema_version": CONTRACT_VERSION,
            "rendering_version": "r1",
            "taxonomy_version": "v1",
            "enrichment_snapshot_version": "2026-09-01T00:00:00Z",
            "normalization_snapshot_version": "psl-2026-09-01",
            "policy_version": rule.POLICY_VERSION,
            "aggregation_version": "v1",
            "model_requested": "model-under-test",
            **overrides,
        }
    )


def a_rendering(shown: str, value: str) -> Rendering:
    body = f"domain {value} | threatfox=malicious evidence={shown}"
    return Rendering(
        version="r1",
        sections=tuple(
            RenderedSection(
                section=name,
                body=body if name == "domains_contacted" else f"<{name}>",
                evidence_ids=(shown,) if name == "domains_contacted" else (),
            )
            for name in SECTIONS
        ),
    )


def request(snapshot: Snapshot, shown: str, value: str, **overrides) -> AgentRequest:
    return AgentRequest(
        **{
            "tenant": TENANT,
            "sensor": SENSOR,
            "emitter": TRIAGE,
            "host": snapshot.host,
            "window_start": snapshot.window_start,
            "window_end": snapshot.window_end,
            "context_id": snapshot.context_id,
            "context_version": snapshot.context_version,
            "trigger": SCHEDULED_TRIAGE,
            "rendering": a_rendering(shown, value),
            "budgets": BUDGET_POLICY.for_emitter(TRIAGE),
            "versions": versions(),
            **overrides,
        }
    )


def a_cost(**overrides) -> Cost:
    return Cost(
        **{
            "prompt_tokens": 40,
            "completion_tokens": 20,
            "steps": 0,
            "live_queries": 0,
            "cache_hits": 0,
            "retries": 0,
            "wall_clock_seconds": 0.5,
            **overrides,
        }
    )


def a_result(emitter: str, shown: str, **overrides) -> AgentResult:
    fields: dict[str, object] = {
        "emitter": emitter,
        "classification": "suspicious",
        "confidence": 0.7,
        "citations": (Citation(evidence_id=shown, stance=SUPPORTING),),
        "cost": a_cost(),
        "versions": versions().completed_by("model-under-test-2026-05"),
        **overrides,
    }
    if emitter == ANALYST and "evidence_package" not in fields:
        fields["evidence_package"] = EvidencePackage(
            patterns=("beaconing on a fixed interval",),
            narrative="the traffic went both ways",
        )
    return AgentResult(**fields)


def a_failure(emitter: str = TRIAGE, **overrides) -> AgentFailure:
    return AgentFailure(
        **{
            "emitter": emitter,
            "reason": MODEL_UNAVAILABLE,
            "detail": "the endpoint did not answer",
            "gaps": (Gap(kind=MISSING, detail="no answer, so no assessment"),),
            "cost": a_cost(prompt_tokens=0, completion_tokens=0),
            "versions": versions(),
            **overrides,
        }
    )


def ledger(asked: AgentRequest, *, at: datetime) -> disclosure.Disclosures:
    rows = disclosure.Disclosures.of(asked, policy=SEND_POLICY)
    rows.record_model_call(
        model="model-under-test",
        disclosed_to=ENDPOINT,
        prompt=b'{"messages": []}',
        messages=2,
        at=at,
    )
    return rows


def store_pass(
    connection: psycopg.Connection,
    snapshot: Snapshot,
    shown: str,
    value: str,
    *,
    triage_outcome: AgentResult | AgentFailure | None = None,
    analysis: AgentResult | AgentFailure | None = None,
    retrievals: tuple[RetrievalStep, ...] = (),
) -> tuple[str, ...]:
    """One pass, stored by the real writer. Returns the identifiers it wrote."""
    asked = request(snapshot, shown, value)
    triage_result = (
        a_result(TRIAGE, shown) if triage_outcome is None else triage_outcome
    )
    if analysis is None:
        assessment = orchestration.Assessment(
            request=asked,
            escalation=None,
            triage=triage_result,
            triage_disclosures=ledger(asked, at=snapshot.window_end),
            trigger=None,
            analyst_request=None,
            analysis=None,
            analyst_disclosures=None,
        )
    else:
        escalated = orchestration.analyst_request(
            asked,
            trigger="triage_suspicious",
            prompt_version=ANALYST_PROMPT.version,
            granted=BUDGET_POLICY.for_emitter(ANALYST),
        )
        assessment = orchestration.Assessment(
            request=asked,
            escalation=None,
            triage=triage_result,
            triage_disclosures=ledger(asked, at=snapshot.window_end),
            trigger=escalated.trigger,
            analyst_request=escalated,
            analysis=analyst.Analysis(
                outcome=analysis, decision=None, retrievals=retrievals
            ),
            analyst_disclosures=ledger(escalated, at=snapshot.window_end),
        )
    written = orchestration.AssessmentStore(connection, prices=NO_PRICES).store(
        assessment, at=ASSESSED_AT
    )
    connection.execute("FLUSH")
    return written


@pytest.fixture
def triage_only(enriched: psycopg.Connection, matched: str):
    snapshot = Snapshot(enriched)
    shown = snapshot.evidence_id(matched)
    written = store_pass(enriched, snapshot, shown, matched)
    return snapshot, shown, written


@pytest.fixture
def escalated(enriched: psycopg.Connection, matched: str):
    snapshot = Snapshot(enriched)
    shown = snapshot.evidence_id(matched)
    written = store_pass(
        enriched,
        snapshot,
        shown,
        matched,
        triage_outcome=a_result(TRIAGE, shown),
        analysis=a_result(
            ANALYST,
            shown,
            classification="malicious.c2",
            citations=(
                Citation(evidence_id=shown, stance=SUPPORTING),
                Citation(evidence_id=RETRIEVED, stance=CONTRADICTING),
            ),
            gaps=(Gap(kind=MISSING, detail="no passive DNS for this name"),),
            cost=a_cost(live_queries=1, cache_hits=1),
            retrieval_trace=(
                # One of each outcome, and one of each exclusive branch: a
                # retrieval that produced evidence and one that produced a typed
                # error and no taxonomy object.
                RetrievalStep(
                    source_id="threatfox",
                    entity_type="domain",
                    entity_value=matched,
                    outcome=CACHE_HIT,
                    retrieved_at=ASSESSED_AT - timedelta(hours=2),
                    evidence_id=RETRIEVED,
                ),
                RetrievalStep(
                    source_id="threatfox",
                    entity_type="domain",
                    entity_value=matched,
                    outcome=LIVE_QUERY,
                    retrieved_at=ASSESSED_AT,
                    failure=QueryFailure(
                        source_id="threatfox",
                        entity_type="domain",
                        entity_value=matched,
                        reason="timeout",
                        detail="the provider did not answer",
                    ),
                ),
            ),
        ),
    )
    return snapshot, shown, written


def a_sink(connection: psycopg.Connection, tenant: str = TENANT) -> sink.SinkStore:
    return sink.SinkStore(connection=connection, identity=identity(tenant))


# --- The view and the constants it shares with Python ------------------------


def test_the_sink_view_is_the_column_list_this_module_holds(
    migrated_engine: psycopg.Connection,
):
    """`SINK_COLUMNS` drives the read; the engine is asked what it actually holds.

    Two copies of a relation's shape, asserted equal by execution — the reason
    `helena.orchestration.ASSESSMENT_COLUMNS` has the same test. In order,
    because the read zips names onto values positionally.
    """
    held = migrated_engine.execute(
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_schema = current_schema() AND table_name = %s "
        "ORDER BY ordinal_position",
        (sink.SINK_VIEW,),
    ).fetchall()
    assert [name for (name,) in held] == list(sink.SINK_COLUMNS)


def test_the_emitter_literals_in_the_view_are_the_ones_the_taxonomy_holds():
    """The view branches on `'analyst'` and `'triage'` as string literals.

    `concept/instruction.md` §2: two copies of a constant are asserted equal by a
    test. The SQL cannot import `helena.taxonomy`, so this is where the two meet.
    """
    text = (migrations.MIGRATIONS_DIR / "0019_sink.sql").read_text()
    statements = text[text.index("CREATE VIEW") :]
    literals = set(re.findall(r"emitter = '([a-z_]+)'", statements))
    assert literals == {triage.EMITTER, analyst.EMITTER}


def test_the_cited_roles_are_the_contract_stances():
    """`cited_as` carries a stance, and the message's vocabulary is the contract's."""
    assert sink.CITED_ROLES == STANCES


def test_the_emitted_version_fields_are_the_registry_s_nine_and_what_was_asked():
    """`EmittedVersions` is `VersionSet` plus `model_requested`, minus the requirement.

    The one difference is `model_version`, which is `None` exactly where nothing
    answered — see `helena.sink.EmittedVersions`. The field *names* may not
    drift, and this is what says so.
    """
    assert tuple(sink.EmittedVersions.model_fields) == (
        *VERSION_COLUMNS,
        "model_requested",
    )
    assert sink.EmittedVersions.model_fields["model_version"].is_required()


def test_the_sink_view_reads_its_own_layer_and_never_below_the_signal_one():
    """The layering change 0019 makes, checked against the declarations.

    `concept/instruction.md` §2's invariant is *"an analytical view never reads
    the flatten layer or the source directly"*, and it still holds: what changed
    is that `analytical` may now read `analytical`, which is the latitude
    `signal` and `reference` already had.
    """
    declared = migrations.declarations()
    assert declared[sink.SINK_VIEW].layer == "analytical"
    layers = {name: declaration.layer for name, declaration in declared.items()}
    assert {layers[read] for read in declared[sink.SINK_VIEW].reads} == {
        "analytical",
        "signal",
    }
    assert migrations.layering_violations(declared) == []


# --- One message per terminal outcome ----------------------------------------


@pytest.mark.integration
def test_a_triage_only_pass_emits_one_message_carrying_the_triage_verdict(
    enriched: psycopg.Connection, triage_only
):
    """*"Every assessed context is emitted, exactly once per terminal outcome."*"""
    snapshot, shown, written = triage_only
    store = a_sink(enriched)
    assert store.terminal() == written
    assert store.pending() == 1
    message = store.project(written[0])
    assert message.message_version == sink.MESSAGE_VERSION
    assert message.emitter == triage.EMITTER
    assert message.outcome_kind == orchestration.VERDICT
    assert message.verdict == "suspicious"
    assert message.classification == "suspicious"
    assert message.triage is None, "triage IS the terminal run here"
    assert message.context_id == snapshot.context_id
    assert message.context_version == snapshot.context_version
    assert message.context_resolved is True
    assert message.citations == (
        sink.EmittedCitation(evidence_id=shown, role=SUPPORTING),
    )


@pytest.mark.integration
def test_an_escalated_context_is_emitted_once_with_the_triage_decision_beside_it(
    enriched: psycopg.Connection, escalated
):
    """*"A context that was escalated is emitted **once**, carrying the analyst's
    verdict and the triage decision that led to it."*

    Two rows in the store, one message — and the triage row is not a message of
    its own, which `test_project_refuses_the_triage_half_of_an_escalated_pass`
    is the other half of.
    """
    snapshot, shown, written = escalated
    triage_id, analyst_id = written
    store = a_sink(enriched)
    assert store.pending() == 1
    assert store.terminal() == (analyst_id,)

    message = store.project(analyst_id)
    assert message.emitter == analyst.EMITTER
    assert message.classification == "malicious.c2"
    assert message.verdict == "malicious"
    assert message.triage is not None
    assert message.triage.assessment_id == triage_id
    assert message.triage.classification == "suspicious"
    assert message.triage.outcome_kind == orchestration.VERDICT
    assert message.trigger == "triage_suspicious"
    assert message.triage.trigger == SCHEDULED_TRIAGE


@pytest.mark.integration
def test_a_typed_failure_is_emitted_as_a_message_with_no_verdict(
    enriched: psycopg.Connection, matched: str
):
    """`concept/instruction.md` §2: *"A failed run is stored as a typed failure
    with no verdict, and is emitted. Never a verdict, never a silent drop."*

    Also the one case `helena.versions.VersionSet` could not carry: nothing
    answered, so `model_version` is `None` rather than a plausible name.
    """
    snapshot = Snapshot(enriched)
    shown = snapshot.evidence_id(matched)
    (written,) = store_pass(
        enriched, snapshot, shown, matched, triage_outcome=a_failure()
    )
    message = a_sink(enriched).project(written)
    assert message.outcome_kind == orchestration.TYPED_FAILURE
    assert message.verdict is None
    assert message.classification is None
    assert message.confidence is None
    assert message.failure_reason == MODEL_UNAVAILABLE
    assert message.gaps == (
        sink.EmittedGap(kind=MISSING, detail="no answer, so no assessment"),
    )
    assert message.citations == ()
    assert message.versions.model_version is None
    assert message.versions.model_requested == "model-under-test"
    # The context is still described in full: a failure says what could not be
    # assessed, not nothing about the window.
    assert message.entities
    assert message.host == snapshot.host


@pytest.mark.integration
def test_project_refuses_the_triage_half_of_an_escalated_pass(
    enriched: psycopg.Connection, escalated
):
    """The triage row of an escalated pass is not a message, and saying so is loud."""
    _, _, (triage_id, _) = escalated
    with pytest.raises(sink.SinkError, match="triage half"):
        a_sink(enriched).project(triage_id)


@pytest.mark.integration
def test_project_refuses_another_deployment_s_assessment(
    enriched: psycopg.Connection, triage_only
):
    """`concept/instruction.md` §6: a defaulted tenant is an isolation failure."""
    _, _, (written,) = triage_only
    other = a_sink(enriched, tenant=OTHER_TENANT)
    assert other.pending() == 0
    assert other.terminal() == ()
    with pytest.raises(sink.SinkError, match=OTHER_TENANT):
        other.project(written)


# --- The four absences, and the fifth this view adds -------------------------


@pytest.mark.integration
def test_the_claim_and_no_match_are_both_answers_and_are_not_the_same_field(
    enriched: psycopg.Connection, triage_only, matched: str
):
    """`status` says what the source did; `classification` says what it said.

    `concept/instruction.md` §2 forbids collapsing them, and a message that
    reported `no_match` as a status would have done exactly that.
    """
    _, _, (written,) = triage_only
    message = a_sink(enriched).project(written)
    by_value = {entity.entity_value: entity for entity in message.entities}
    claimed = [
        evidence
        for evidence in by_value[matched].evidence
        if evidence.classification == "malicious"
    ]
    assert claimed, "the repointed extract entry should have matched"
    assert {evidence.status for evidence in claimed} == {"ok"}
    assert all(evidence.evidence_id for evidence in claimed)

    others = [
        evidence
        for entity in message.entities
        for evidence in entity.evidence
        if entity.entity_value != matched
    ]
    assert others, "every other entity should carry an answer, not an absence"
    assert {evidence.classification for evidence in others} == {"no_match"}
    assert {evidence.evidence_id for evidence in others} == {None}
    assert "no_match" not in {evidence.status for evidence in others}


@pytest.mark.integration
def test_a_failed_load_reaches_the_message_as_failed_and_not_as_a_missing_source(
    migrated_engine: psycopg.Connection, tmp_path: Path
):
    """A source that was tried and could not answer. `concept/instruction.md` §2.

    `failed` and `missing` are both "no data" and are different facts, and they
    are mutually exclusive per source over one window by the way
    `sql/migrations/0015` derives the status — so they are two deployments here
    rather than two rows of one.
    """
    store_capture(migrated_engine, tmp_path / "restamped.jsonl")
    snapshot = Snapshot(migrated_engine)
    load_feed(migrated_engine, b"{}", now=snapshot.window_start - timedelta(hours=1))
    migrated_engine.execute("FLUSH")
    assert _emitted_evidence(migrated_engine, snapshot) == {("failed", None)}


@pytest.mark.integration
def test_a_window_before_any_snapshot_reaches_the_message_as_missing(
    migrated_engine: psycopg.Connection, tmp_path: Path
):
    """A source that was asked for and had nothing to look in at that time.

    Not `no_match` — there was nothing to consult — and not `failed`, because the
    load succeeded. The message has to keep all three apart or the distinction
    ends at the topic.
    """
    store_capture(migrated_engine, tmp_path / "restamped.jsonl")
    snapshot = Snapshot(migrated_engine)
    load_feed(migrated_engine, RAW, now=snapshot.window_start + timedelta(days=30))
    migrated_engine.execute("FLUSH")
    assert _emitted_evidence(migrated_engine, snapshot) == {("missing", None)}


@pytest.mark.integration
def test_a_stale_snapshot_keeps_its_claim_and_says_how_old_it_is(
    migrated_engine: psycopg.Connection, tmp_path: Path
):
    """`concept/02`: a feed going quiet is not exoneration.

    The claim stands, the status says the snapshot is past its own refresh
    window, and `snapshot_loaded_at` says when it was current. A message that
    dropped the claim, or that reported `stale` where `ok` belonged, would be
    editing the evidence on the way out.
    """
    a_context(
        migrated_engine, tmp_path / "restamped.jsonl", loaded_at=timedelta(hours=6)
    )
    snapshot = Snapshot(migrated_engine)
    matched = an_entity(migrated_engine)
    shown = snapshot.evidence_id(matched)
    (written,) = store_pass(migrated_engine, snapshot, shown, matched)
    message = a_sink(migrated_engine).project(written)
    claimed = [
        evidence
        for entity in message.entities
        for evidence in entity.evidence
        if evidence.classification not in (None, "no_match")
    ]
    assert claimed
    for evidence in claimed:
        assert evidence.status == "stale"
        assert evidence.classification == "malicious"
        assert evidence.snapshot_loaded_at is not None


def _emitted_evidence(
    connection: psycopg.Connection, snapshot: Snapshot
) -> set[tuple[str, str | None]]:
    """`(status, classification)` for every evidence row of one emitted message."""
    (written,) = store_pass(
        connection,
        snapshot,
        "a" * 64,
        an_entity(connection),
        triage_outcome=a_failure(),
    )
    message = a_sink(connection).project(written)
    return {
        (evidence.status, evidence.classification)
        for entity in message.entities
        for evidence in entity.evidence
    }


@pytest.mark.integration
def test_a_deployment_that_has_asked_no_source_emits_entities_with_no_evidence(
    migrated_engine: psycopg.Connection, tmp_path: Path
):
    """The fifth absence, which the enriched context cannot express.

    Its source list is the snapshot ledger, so with no feed ever loaded it yields
    no rows at all. The sink's LEFT JOIN turns that into entities with no
    evidence rather than into a context with no entities — a host that contacted
    nothing is the one thing this message may not say by accident.
    """
    store_capture(migrated_engine, tmp_path / "restamped.jsonl")
    snapshot = Snapshot(migrated_engine)
    (written,) = store_pass(
        migrated_engine,
        snapshot,
        "a" * 64,
        an_entity(migrated_engine),
        triage_outcome=a_failure(),
    )
    message = a_sink(migrated_engine).project(written)
    assert message.entities, "the host contacted things; the message must say so"
    assert all(entity.evidence == () for entity in message.entities)
    assert message.context_resolved is True


@pytest.mark.integration
def test_a_context_whose_version_has_moved_on_says_so_rather_than_emptying(
    enriched: psycopg.Connection, triage_only
):
    """`context_resolved` is the difference between "moved on" and "contacted nothing".

    The assessment names a context version; this one is not the store's any more,
    so the entity half is absent. A message that reported that as an empty entity
    list would be making a claim about the traffic out of a fact about the store.
    """
    snapshot, shown, (written,) = triage_only
    moved = Snapshot(enriched)
    moved.context_version = snapshot.context_version + "-moved"
    (other,) = store_pass(enriched, moved, shown, an_entity(enriched))
    message = a_sink(enriched).project(other)
    assert message.context_resolved is False
    assert message.entities == ()
    assert message.flow_count is None
    # And the run itself is still fully described.
    assert message.classification == "suspicious"
    assert message.citations


# --- Nothing is recoverable only from the topic ------------------------------


#: Where every field of the message comes from. The key is a dotted path through
#: the payload; the value names the relation a query recovers it from, or
#: `CODE_OWNED` for the two fields that are a constant of the emitter rather than
#: state.
#:
#: This is the map `concept/03`'s *"nothing may be recoverable only from it"*
#: becomes when it is executed rather than asserted, and the structural test
#: below fails for any field that is not in it.
CODE_OWNED = "the emitter, not the store"
ASSESSMENT = orchestration.ASSESSMENT_TABLE
CONTEXT = "helena_signal_host_context_live"
ENTITIES = "helena_signal_context_entities"
ENRICHED = "helena_analytical_enriched_context"

RECOVERED_FROM = {
    "message_version": CODE_OWNED,
    "caveat": CODE_OWNED,
    "assessment_id": ASSESSMENT,
    "tenant": ASSESSMENT,
    "sensor": ASSESSMENT,
    "host": ASSESSMENT,
    "context_id": ASSESSMENT,
    "context_version": ASSESSMENT,
    "window_start": ASSESSMENT,
    "window_end": ASSESSMENT,
    "assessed_at": ASSESSMENT,
    "context_resolved": CONTEXT,
    "flow_count": CONTEXT,
    "duration_seconds": CONTEXT,
    "bytes_sent": CONTEXT,
    "bytes_received": CONTEXT,
    "packets_sent": CONTEXT,
    "packets_received": CONTEXT,
    "emitter": ASSESSMENT,
    "trigger": ASSESSMENT,
    "outcome_kind": ASSESSMENT,
    "verdict": ASSESSMENT,
    "classification": ASSESSMENT,
    "confidence": ASSESSMENT,
    "narrative": ASSESSMENT,
    "failure_reason": ASSESSMENT,
    "failure_detail": ASSESSMENT,
    "entities.entity_type": ENTITIES,
    "entities.entity_value": ENTITIES,
    "entities.observed_as_flow_destination": ENTITIES,
    "entities.observed_in_dns_query": ENTITIES,
    "entities.observed_in_dns_response": ENTITIES,
    "entities.observed_in_tls": ENTITIES,
    "entities.observed_in_http": ENTITIES,
    "entities.observed_flow_count": ENTITIES,
    "entities.observed_bytes_sent": ENTITIES,
    "entities.observed_bytes_received": ENTITIES,
    "entities.observed_packets_sent": ENTITIES,
    "entities.observed_packets_received": ENTITIES,
    "entities.evidence.source_id": ENRICHED,
    "entities.evidence.status": ENRICHED,
    "entities.evidence.classification": ENRICHED,
    "entities.evidence.evidence_id": ENRICHED,
    "entities.evidence.source_tier": ENRICHED,
    "entities.evidence.evidence_tier": ENRICHED,
    "entities.evidence.snapshot_version": ENRICHED,
    "entities.evidence.snapshot_loaded_at": ENRICHED,
    "entities.evidence.taxonomy_version": ENRICHED,
    "entities.evidence.confidence": ENRICHED,
    "entities.evidence.scope_type": ENRICHED,
    "entities.evidence.scope_value": ENRICHED,
    "entities.evidence.first_seen": ENRICHED,
    "entities.evidence.last_seen": ENRICHED,
    "entities.evidence.native_evidence": ENRICHED,
    "entities.evidence.port_matched": ENRICHED,
    "entities.evidence.cited_as": orchestration.CITATION_TABLE,
    "triage.assessment_id": ASSESSMENT,
    "triage.trigger": ASSESSMENT,
    "triage.outcome_kind": ASSESSMENT,
    "triage.verdict": ASSESSMENT,
    "triage.classification": ASSESSMENT,
    "triage.confidence": ASSESSMENT,
    "triage.failure_reason": ASSESSMENT,
    "triage.failure_detail": ASSESSMENT,
    "triage.assessed_at": ASSESSMENT,
    "triage.model_version": ASSESSMENT,
    "triage.prompt_version": ASSESSMENT,
    "citations.evidence_id": orchestration.CITATION_TABLE,
    "citations.role": orchestration.CITATION_TABLE,
    "gaps.kind": orchestration.GAP_TABLE,
    "gaps.detail": orchestration.GAP_TABLE,
    "patterns": orchestration.PATTERN_TABLE,
    "retrievals.emitter": ASSESSMENT,
    "retrievals.source_id": orchestration.RETRIEVAL_TABLE,
    "retrievals.entity_type": orchestration.RETRIEVAL_TABLE,
    "retrievals.entity_value": orchestration.RETRIEVAL_TABLE,
    "retrievals.outcome": orchestration.RETRIEVAL_TABLE,
    "retrievals.retrieved_at": orchestration.RETRIEVAL_TABLE,
    "retrievals.evidence_id": orchestration.RETRIEVAL_TABLE,
    "retrievals.failure_reason": orchestration.RETRIEVAL_TABLE,
    "retrievals.failure_detail": orchestration.RETRIEVAL_TABLE,
    "disclosures.emitter": ASSESSMENT,
    "disclosures.channel": orchestration.DISCLOSURE_TABLE,
    "disclosures.source": orchestration.DISCLOSURE_TABLE,
    "disclosures.disclosed_to": orchestration.DISCLOSURE_TABLE,
    "disclosures.query": orchestration.DISCLOSURE_TABLE,
    "disclosures.query_digest": orchestration.DISCLOSURE_TABLE,
    "disclosures.disclosed_at": orchestration.DISCLOSURE_TABLE,
    "disclosures.send_policy_version": orchestration.DISCLOSURE_TABLE,
    **{f"versions.{column}": ASSESSMENT for column in VERSION_COLUMNS},
    "versions.model_requested": ASSESSMENT,
}


def _paths(model, prefix: str = "") -> set[str]:
    """Every leaf field of a message, as a dotted path."""
    found: set[str] = set()
    for name, field in model.model_fields.items():
        path = f"{prefix}{name}"
        nested = _nested_model(field.annotation)
        if nested is None:
            found.add(path)
        else:
            found |= _paths(nested, f"{path}.")
    return found


def _nested_model(annotation):
    from pydantic import BaseModel

    for candidate in (annotation, *getattr(annotation, "__args__", ())):
        if isinstance(candidate, type) and issubclass(candidate, BaseModel):
            return candidate
        for inner in getattr(candidate, "__args__", ()):
            if isinstance(inner, type) and issubclass(inner, BaseModel):
                return inner
    return None


def test_every_field_of_the_message_has_a_declared_recovery_route():
    """A field added without a route is a field that would exist only in the topic.

    The structural half of the rule. The executed half is below.
    """
    assert _paths(sink.OutputMessage) == set(RECOVERED_FROM)


def test_only_the_two_self_describing_fields_are_code_owned():
    """`concept/03` allows no third. Everything else is a projection of a row."""
    assert {
        path for path, source in RECOVERED_FROM.items() if source == CODE_OWNED
    } == {"message_version", "caveat"}


@pytest.mark.integration
def test_every_field_of_the_message_is_recoverable_from_the_engine(
    enriched: psycopg.Connection, escalated
):
    """The load-bearing test. *"Nothing may be recoverable only from it."*

    Every field is recovered by a query written against the underlying tables —
    never against `helena_analytical_sink`, which is where the message came from
    — and compared. An escalated pass, because it is the message with the most in
    it: two runs, a retrieval trace, two disclosure ledgers, a citation to
    analyst-tier evidence and one to enrichment-tier evidence.
    """
    snapshot, shown, (triage_id, analyst_id) = escalated
    message = a_sink(enriched).project(analyst_id)

    row = _one(enriched, f"SELECT * FROM {ASSESSMENT} WHERE assessment_id = %s",
               (analyst_id,))
    assert message.assessment_id == row["assessment_id"]
    assert message.tenant == row["tenant"]
    assert message.sensor == row["sensor"]
    assert message.host == row["host"]
    assert message.context_id == row["context_id"]
    assert message.context_version == row["context_version"]
    assert message.window_start == row["window_start"]
    assert message.window_end == row["window_end"]
    assert message.assessed_at == row["assessed_at"]
    assert message.emitter == row["emitter"]
    assert message.trigger == row["triggered_by"]
    assert message.classification == row["classification"]
    assert message.verdict == row["classification"].split(".")[0]
    assert message.outcome_kind == orchestration.VERDICT
    assert message.confidence == row["confidence"]
    assert message.narrative == row["narrative"]
    assert message.failure_reason == row["failure_reason"]
    assert message.failure_detail == row["failure_detail"]
    assert message.versions.model_requested == row["model_requested"]
    for column in VERSION_COLUMNS:
        assert getattr(message.versions, column) == row[column], column

    context = _one(
        enriched,
        f"SELECT * FROM {CONTEXT} WHERE context_id = %s AND context_version = %s",
        (snapshot.context_id, snapshot.context_version),
    )
    assert message.context_resolved is True
    assert message.flow_count == context["flow_count"]
    assert message.duration_seconds == context["duration_seconds"]
    assert message.bytes_sent == context["bytes_sent"]
    assert message.bytes_received == context["bytes_received"]
    assert message.packets_sent == context["packets_sent"]
    assert message.packets_received == context["packets_received"]

    entities = _rows(
        enriched,
        f"SELECT * FROM {ENTITIES} WHERE tenant = %s AND sensor = %s "
        f"AND context_id = %s",
        (TENANT, SENSOR, snapshot.context_id),
    )
    assert {entity.entity_value for entity in message.entities} == {
        row["entity_value"] for row in entities
    }
    stored = {(row["entity_type"], row["entity_value"]): row for row in entities}
    for entity in message.entities:
        against = stored[(entity.entity_type, entity.entity_value)]
        for field in sink.EmittedEntity.model_fields:
            if field == "evidence":
                continue
            assert getattr(entity, field) == against[field], field

    claims = _rows(
        enriched,
        f"SELECT * FROM {ENRICHED} WHERE tenant = %s AND sensor = %s "
        f"AND context_id = %s",
        (TENANT, SENSOR, snapshot.context_id),
    )
    by_key = {
        (row["entity_type"], row["entity_value"], row["source_id"]): row
        for row in claims
    }
    emitted = {
        (entity.entity_type, entity.entity_value, evidence.source_id): evidence
        for entity in message.entities
        for evidence in entity.evidence
    }
    assert set(emitted) == set(by_key)
    cited = dict(
        _pairs(
            enriched,
            f"SELECT evidence_id, role FROM {orchestration.CITATION_TABLE} "
            f"WHERE assessment_id = %s",
            (analyst_id,),
        )
    )
    for key, evidence in emitted.items():
        against = by_key[key]
        assert evidence.status == against["status"]
        assert evidence.classification == against["classification"]
        assert evidence.evidence_id == against["evidence_id"]
        assert evidence.source_tier == against["source_tier"]
        assert evidence.evidence_tier == against["evidence_tier"]
        assert evidence.snapshot_version == against["snapshot_version"]
        assert evidence.snapshot_loaded_at == against["snapshot_loaded_at"]
        assert evidence.taxonomy_version == against["taxonomy_version"]
        assert evidence.confidence == against["confidence"]
        assert evidence.scope_type == against["scope_type"]
        assert evidence.scope_value == against["scope_value"]
        assert evidence.first_seen == against["first_seen"]
        assert evidence.last_seen == against["last_seen"]
        assert evidence.native_evidence == against["native_evidence"]
        assert evidence.port_matched == against["port_matched"]
        assert evidence.cited_as == cited.get(against["evidence_id"])

    triage_row = _one(
        enriched, f"SELECT * FROM {ASSESSMENT} WHERE assessment_id = %s", (triage_id,)
    )
    assert message.triage is not None
    assert message.triage.assessment_id == triage_row["assessment_id"]
    assert message.triage.trigger == triage_row["triggered_by"]
    assert message.triage.outcome_kind == orchestration.VERDICT
    assert message.triage.classification == triage_row["classification"]
    assert message.triage.verdict == triage_row["classification"].split(".")[0]
    assert message.triage.confidence == triage_row["confidence"]
    assert message.triage.failure_reason == triage_row["failure_reason"]
    assert message.triage.failure_detail == triage_row["failure_detail"]
    assert message.triage.assessed_at == triage_row["assessed_at"]
    assert message.triage.model_version == triage_row["model_version"]
    assert message.triage.prompt_version == triage_row["prompt_version"]

    assert [(c.evidence_id, c.role) for c in message.citations] == _pairs(
        enriched,
        f"SELECT evidence_id, role FROM {orchestration.CITATION_TABLE} "
        f"WHERE assessment_id = %s ORDER BY evidence_id",
        (analyst_id,),
    )
    assert [(gap.kind, gap.detail) for gap in message.gaps] == _pairs(
        enriched,
        f"SELECT kind, detail FROM {orchestration.GAP_TABLE} "
        f"WHERE assessment_id = %s ORDER BY ordinal",
        (analyst_id,),
    )
    assert list(message.patterns) == [
        pattern
        for (pattern,) in enriched.execute(
            f"SELECT pattern FROM {orchestration.PATTERN_TABLE} "
            f"WHERE assessment_id = %s ORDER BY ordinal",
            (analyst_id,),
        ).fetchall()
    ]

    # The two traces are the PASS's, so they are recovered from both runs' rows.
    assert [
        (step.emitter, step.source_id, step.outcome, step.evidence_id,
         step.failure_reason)
        for step in message.retrievals
    ] == [
        (emitter, row["source_id"], row["outcome"], row["evidence_id"],
         row["failure_reason"])
        for identifier, emitter in ((triage_id, TRIAGE), (analyst_id, ANALYST))
        for row in _rows(
            enriched,
            f"SELECT * FROM {orchestration.RETRIEVAL_TABLE} "
            f"WHERE assessment_id = %s ORDER BY ordinal",
            (identifier,),
        )
    ]
    assert [
        (row.emitter, row.channel, row.source, row.disclosed_to, row.query,
         row.query_digest, row.disclosed_at, row.send_policy_version)
        for row in message.disclosures
    ] == [
        (emitter, row["channel"], row["source"], row["disclosed_to"], row["query"],
         row["query_digest"], row["disclosed_at"], row["send_policy_version"])
        for identifier, emitter in ((triage_id, TRIAGE), (analyst_id, ANALYST))
        for row in _rows(
            enriched,
            f"SELECT * FROM {orchestration.DISCLOSURE_TABLE} "
            f"WHERE assessment_id = %s ORDER BY ordinal",
            (identifier,),
        )
    ]
    assert message.retrievals and message.disclosures


def _rows(connection: psycopg.Connection, sql: str, params: tuple) -> list[dict]:
    connection.execute("FLUSH")
    found = connection.execute(sql, params)
    names = [column.name for column in found.description]
    return [dict(zip(names, values, strict=True)) for values in found.fetchall()]


def _one(connection: psycopg.Connection, sql: str, params: tuple) -> dict:
    found = _rows(connection, sql, params)
    assert len(found) == 1, f"{len(found)} rows for {params}"
    return found[0]


def _pairs(connection: psycopg.Connection, sql: str, params: tuple) -> list[tuple]:
    connection.execute("FLUSH")
    return [tuple(row) for row in connection.execute(sql, params).fetchall()]


# --- The shape is an interface -----------------------------------------------


def message_shape() -> str:
    """The JSON Schema of `OutputMessage` with the prose taken out.

    `description` is a docstring or a `#:` comment, and pinning those would make
    every clarification an interface change — which would teach whoever hits it
    to regenerate the fixture, and a pin people regenerate reflexively is not a
    pin. What stays is what §7 of
    `docs/decisions/0036-the-output-message.md` actually calls the interface: the
    field set, the types, and which fields are required.
    """

    def without_prose(node):
        if isinstance(node, dict):
            return {
                key: without_prose(value)
                for key, value in node.items()
                if key != "description"
            }
        if isinstance(node, list):
            return [without_prose(item) for item in node]
        return node

    return json.dumps(
        without_prose(sink.OutputMessage.model_json_schema()),
        indent=2,
        sort_keys=True,
    )


def test_the_message_schema_is_what_it_was():
    """The pinned shape of `MESSAGE_VERSION`. If this fails, read the fixture README.

    A change to the field set, a field's type or a field's meaning is an
    interface change: it bumps `MESSAGE_VERSION` and it comes with a decision
    record. Regenerating this file to make the test pass is how a consumer finds
    out by breaking.
    """
    assert message_shape() == MESSAGE_SCHEMA.read_text().rstrip("\n")
    assert sink.MESSAGE_VERSION == "v1"
    assert MESSAGE_SCHEMA.name == f"message-{sink.MESSAGE_VERSION}.json"


@pytest.mark.integration
def test_every_message_carries_the_redaction_caveat(
    enriched: psycopg.Connection, triage_only
):
    """`concept/03`: the payload is unredacted and a consumer inherits the duty.

    The pipeline cannot enforce it, so the statement travels with the bytes. The
    three things the note names are asserted present, because a caveat about
    content that is not there would be noise a consumer learns to ignore.
    """
    _, _, (written,) = triage_only
    message = a_sink(enriched).project(written)
    assert message.caveat == sink.MESSAGE_CAVEAT
    assert "inherits the redaction" in message.caveat
    # 1. internal addresses, 2. hostnames, 3. retrieved external text.
    assert message.host
    assert any(entity.entity_value for entity in message.entities)
    assert any(
        evidence.native_evidence is not None
        for entity in message.entities
        for evidence in entity.evidence
    )


def test_the_sink_neither_produces_nor_counts_what_was_delivered():
    """Emission is task 47's, and `helena.broker` is the one Kafka client.

    `concept/instruction.md` §2: *"the broker is addressed only through the Kafka
    wire protocol"*, and `tests/test_broker.py` asserts there is exactly one
    module that does. This is the sink's half of that: it reads the engine and
    builds bytes, and nothing here opens a socket.
    """
    source = (Path(sink.__file__)).read_text()
    for forbidden in ("confluent_kafka", "KafkaProducer", "import socket", "Producer("):
        assert forbidden not in source, forbidden


@pytest.mark.integration
def test_pending_counts_messages_and_not_the_view_s_rows(
    enriched: psycopg.Connection, escalated
):
    """*"A count of rows the sink view produced"* — at the grain a consumer
    reconciles against, which is messages.

    The view has one row per (terminal run x entity x source), so the raw row
    count is much larger and counting it would make "nothing arrived" impossible
    to tell from "one message arrived".
    """
    store = a_sink(enriched)
    (raw,) = enriched.execute(
        f"SELECT count(*) FROM {sink.SINK_VIEW} WHERE tenant = %s", (TENANT,)
    ).fetchone()
    assert raw > 1
    assert store.pending() == 1
    assert len(store.terminal()) == 1
