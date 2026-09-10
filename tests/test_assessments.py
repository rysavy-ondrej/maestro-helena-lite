"""The stored assessment: typed rows, citation joins, and no note anywhere.

Mirrors the persistence half of `src/helena/orchestration.py` and
`sql/migrations/0018_assessments.sql`. The sentences under test are
`concept/03-architecture.md`'s:

- *"**Agent output is stored as typed, queryable rows with citation joins, never
  as an opaque document.** The fields anyone would filter, join, group or
  aggregate on are typed columns ... Narrative stays a text column. **Evidence
  citations are join rows** — `(assessment, evidence, role)` — not an array
  buried in JSON."*
- `concept/02`: *"**Typed failure** — a run that could not produce a verdict,
  stored as an assessment row carrying the failure and **no** verdict — never a
  verdict, never a silent drop."*
- `concept/07`: *"an agent's claim about infrastructure is a **proposal**,
  validated against a schema and written by deterministic code"*, and *"memory
  entries ... must be structured claims with provenance, confidence and expiry —
  **never free-text summaries of retrieved content**."*

**Every assertion about the schema is made against a real engine.** The rows are
written by the real writer through `psycopg` and read back with SQL, because a
test that asserted on the migration's text would be reading the comment arguing
for a column rather than the column.

One test drives the whole thing end to end — a scripted OpenAI-compatible
endpoint on the loopback interface, `helena.orchestration.assess`, then the store
— because what is being checked is that the object the router returns is the
object the tables hold.
"""

from __future__ import annotations

import ast
import io
import json
import re
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
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
    observability,
    orchestration,
    policy,
    rendering,
    triage,
)
from helena.agents import ModelClient, RetryPolicy
from helena.config import ModelSettings, Secret
from helena.contracts.v1 import (
    CACHE_HIT,
    CONTRACT_VERSION,
    CONTRADICTING,
    GAP_KINDS,
    LIVE_QUERY,
    MODEL_UNAVAILABLE,
    SCHEDULED_TRIAGE,
    SCHEMA_INVALID,
    SECTIONS,
    SUPPORTING,
    TRIAGE_SUSPICIOUS,
    AgentFailure,
    AgentRequest,
    AgentResult,
    Budgets,
    Citation,
    Cost,
    EvidencePackage,
    Gap,
    RenderedSection,
    Rendering,
    RequestVersions,
    RetrievalStep,
)
from helena.enrichment import QueryFailure
from helena.policy import v1 as rule
from helena.rendering import ContextEntity, ContextProjection, EntityEnrichment
from helena.taxonomy import ANALYST, TRIAGE

pytestmark = pytest.mark.integration

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PACKAGE_ROOT = PROJECT_ROOT / "src" / "helena"

TENANT, SENSOR = "tenant-under-test", "sensor-under-test"
HOST = "10.127.0.100"
ADDRESS = "203.0.113.10"
DOMAIN = "c2.example.invalid"
WINDOW_START = datetime(2024, 6, 1, 12, 0, tzinfo=timezone.utc)
WINDOW_END = WINDOW_START + timedelta(minutes=5)
RECORDED_AT = datetime(2024, 6, 1, 12, 5, 30, tzinfo=timezone.utc)

#: The evidence id the synthetic rendering shows and the synthetic projection
#: carries — the same device `tests/test_orchestration.py` uses. A citation is
#: resolved against both, so the two have to agree.
SHOWN = "e" * 64
#: A second identifier, produced by a retrieval rather than by the rendering.
RETRIEVED = "f" * 64

TRIAGE_PROMPT = triage.version("v1")
ANALYST_PROMPT = analyst.version("v1")
THREE_ATTEMPTS = RetryPolicy(attempts=3)
OFF = analyst.Inheritance(inherit_triage_rationale=False)

THRESHOLDS = policy.thresholds()
BUDGET_POLICY = budgets.load()
SEND_POLICY = disclosure.send_policy()

#: No entry for the model under test, which is the committed file's own state.
NO_PRICES = budgets.model_prices()
#: A priced table, for the one thing the committed file cannot demonstrate.
PRICED = budgets.PriceTable(
    version="prices-under-test",
    prices={
        "model-under-test": budgets.ModelPrice(
            prompt_per_million=3.0, completion_per_million=15.0, currency="USD"
        )
    },
)

TABLES = (
    orchestration.ASSESSMENT_TABLE,
    orchestration.CITATION_TABLE,
    orchestration.GAP_TABLE,
    orchestration.PATTERN_TABLE,
    orchestration.RETRIEVAL_TABLE,
    orchestration.DISCLOSURE_TABLE,
)


# --- Builders ----------------------------------------------------------------


def versions(**overrides: str) -> RequestVersions:
    return RequestVersions(
        **{
            "prompt_version": TRIAGE_PROMPT.version,
            "schema_version": CONTRACT_VERSION,
            "rendering_version": "r1",
            "taxonomy_version": "v1",
            "enrichment_snapshot_version": "2024-06-01T00:00:00Z",
            "normalization_snapshot_version": "psl-2024-06-01",
            "policy_version": rule.POLICY_VERSION,
            "aggregation_version": "v1",
            "model_requested": "model-under-test",
            **overrides,
        }
    )


def a_rendering() -> Rendering:
    body = (
        f"address {ADDRESS} ports=443 bytes_sent=4200 bytes_received=51000 | "
        f"threatfox=malicious evidence={SHOWN}"
    )
    return Rendering(
        version="r1",
        sections=tuple(
            RenderedSection(
                section=name,
                body=body if name == "addresses_contacted" else f"<{name}> {DOMAIN}",
                evidence_ids=(SHOWN,) if name == "addresses_contacted" else (),
            )
            for name in SECTIONS
        ),
    )


def request(**overrides: object) -> AgentRequest:
    return AgentRequest(
        **{
            "tenant": TENANT,
            "sensor": SENSOR,
            "emitter": TRIAGE,
            "host": HOST,
            "window_start": WINDOW_START,
            "window_end": WINDOW_END,
            "context_id": "ctx-1",
            "context_version": "ctx-1/3",
            "trigger": SCHEDULED_TRIAGE,
            "rendering": a_rendering(),
            "budgets": BUDGET_POLICY.for_emitter(TRIAGE),
            "versions": versions(),
            **overrides,
        }
    )


def analyst_request(**overrides: object) -> AgentRequest:
    return orchestration.analyst_request(
        request(),
        trigger=overrides.pop("trigger", "deterministic_signal"),
        prompt_version=ANALYST_PROMPT.version,
        granted=BUDGET_POLICY.for_emitter(ANALYST),
    )


def a_projection(*, confidence: float = 1.0) -> ContextProjection:
    return ContextProjection(
        tenant=TENANT,
        sensor=SENSOR,
        host=HOST,
        context_id="ctx-1",
        context_version="ctx-1/3",
        statistics=rendering.ConnectionStatistics(
            window_start=WINDOW_START,
            window_end=WINDOW_END,
            completeness="open",
            flow_count=3,
            duration_seconds=42.0,
            bytes_sent=4200,
            bytes_received=51_000,
            packets_sent=30,
            packets_received=60,
        ),
        entities=(
            ContextEntity(
                entity_type="address",
                entity_value=ADDRESS,
                fingerprint_algorithm=None,
                observed_layers=("flow_destination",),
                observed_flow_count=3,
                observed_bytes_sent=4200,
                observed_bytes_received=51_000,
                ports=(443,),
                enrichment=(
                    EntityEnrichment(
                        source_id="threatfox",
                        source_tier="B",
                        status="ok",
                        classification="malicious",
                        confidence=confidence,
                        scope_type="address",
                        scope_value=ADDRESS,
                        port_matched=None,
                        evidence_id=SHOWN,
                        snapshot_version="2024-06-01T00:00:00Z",
                    ),
                ),
            ),
        ),
        tls=(),
    )


def a_cost(**overrides: object) -> Cost:
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


def a_result(emitter: str = TRIAGE, **overrides: object) -> AgentResult:
    """A verdict. The analyst's non-`normal` one carries the package `concept/04`
    requires of it, so a caller that is not testing the package does not have to
    supply one."""
    fields: dict[str, object] = {
        "emitter": emitter,
        "classification": "suspicious",
        "confidence": 0.7,
        "citations": (Citation(evidence_id=SHOWN, stance=SUPPORTING),),
        "cost": a_cost(),
        "versions": versions().completed_by("model-under-test-2026-05"),
        **overrides,
    }
    needs_package = (
        emitter == ANALYST and str(fields["classification"]).split(".")[0] != "normal"
    )
    if needs_package and "evidence_package" not in fields:
        fields["evidence_package"] = EvidencePackage(
            narrative="the traffic went both ways"
        )
    return AgentResult(**fields)


def a_failure(emitter: str = TRIAGE, **overrides: object) -> AgentFailure:
    return AgentFailure(
        **{
            "emitter": emitter,
            "reason": MODEL_UNAVAILABLE,
            "detail": "the endpoint did not answer",
            "cost": a_cost(prompt_tokens=0, completion_tokens=0),
            "versions": versions(),
            **overrides,
        }
    )


def ledger(asked: AgentRequest) -> disclosure.Disclosures:
    return disclosure.Disclosures.of(asked, policy=SEND_POLICY)


#: The endpoint the synthetic ledgers record. A host and a port, which is what
#: `helena.agents.ModelClient.endpoint_host` produces and what the column holds.
ENDPOINT = "model.invalid:8443"


def a_model_call(rows: disclosure.Disclosures, *, host: str = ENDPOINT):
    return rows.record_model_call(
        model="model-under-test",
        disclosed_to=host,
        prompt=b'{"messages": []}',
        messages=2,
        at=WINDOW_END,
    )


def an_assessment(
    *,
    triage_outcome: AgentResult | AgentFailure | None = None,
    analysis: AgentResult | AgentFailure | None = None,
    asked: AgentRequest | None = None,
    escalated: AgentRequest | None = None,
    disclose: bool = True,
) -> orchestration.Assessment:
    """One routed pass, assembled rather than run.

    `escalation` is `None` because nothing in the store reads it — see
    `helena.orchestration`'s "what is deliberately not here". Every other field is
    the real object the router would hand over.
    """
    asked = request() if asked is None else asked
    triage_ledger = ledger(asked)
    if disclose:
        a_model_call(triage_ledger)
    if analysis is None:
        return orchestration.Assessment(
            request=asked,
            escalation=None,
            triage=a_result() if triage_outcome is None else triage_outcome,
            triage_disclosures=triage_ledger,
            trigger=None,
            analyst_request=None,
            analysis=None,
            analyst_disclosures=None,
        )
    escalated = analyst_request() if escalated is None else escalated
    analyst_ledger = ledger(escalated)
    if disclose:
        a_model_call(analyst_ledger)
    return orchestration.Assessment(
        request=asked,
        escalation=None,
        triage=a_result() if triage_outcome is None else triage_outcome,
        triage_disclosures=triage_ledger,
        trigger=escalated.trigger,
        analyst_request=escalated,
        analysis=analyst.Analysis(outcome=analysis, decision=None, retrievals=()),
        analyst_disclosures=analyst_ledger,
    )


# --- Reading the store back ---------------------------------------------------


def rows(connection: psycopg.Connection, table: str, **where: object) -> list[dict]:
    """Every row of `table`, as dicts keyed by column name, ordered as stored."""
    connection.execute("FLUSH")
    clause = " AND ".join(f"{name} = %s" for name in where)
    order = {
        orchestration.ASSESSMENT_TABLE: "assessment_id",
        orchestration.CITATION_TABLE: "evidence_id",
    }.get(table, "ordinal")
    found = connection.execute(
        f"SELECT * FROM {table}"
        + (f" WHERE {clause}" if where else "")
        + f" ORDER BY {order}",
        tuple(where.values()),
    )
    names = [column.name for column in found.description]
    return [dict(zip(names, values, strict=True)) for values in found.fetchall()]


def one(connection: psycopg.Connection, table: str, **where: object) -> dict:
    found = rows(connection, table, **where)
    assert len(found) == 1, f"{len(found)} rows in {table} for {where}"
    return found[0]


@pytest.fixture
def store(migrated_engine: psycopg.Connection) -> orchestration.AssessmentStore:
    return orchestration.AssessmentStore(migrated_engine, prices=NO_PRICES)


# --- The schema ---------------------------------------------------------------


def test_the_migration_creates_the_six_tables_the_writer_addresses(
    migrated_engine: psycopg.Connection,
):
    """The names in Python and the names in the engine, asserted equal by execution.

    Two copies of a relation name exist — `helena.orchestration`'s constants and
    the migration's `CREATE` — and this is the only way to check them that means
    anything (`concept/instruction.md` §2).
    """
    held = {
        name
        for (name,) in migrated_engine.execute(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema = current_schema() AND table_type = 'BASE TABLE'"
        ).fetchall()
    }
    assert set(TABLES) <= held


def test_every_column_concept_03_names_is_a_typed_column(
    migrated_engine: psycopg.Connection,
):
    """The note's own list, read off the engine's catalogue.

    *"host, tenant, context reference, window bounds, verdict and classification,
    confidence, timestamps, model / prompt / contract / rendering versions,
    budgets consumed, latency, tokens, cost, and cache-hit versus live-query
    counts."*

    `verdict` is the one that is deliberately absent: it is the root of the
    classification, the taxonomy already refuses a path whose root is not its
    first segment, and a stored copy would be a second copy of a fact that cannot
    disagree in the model and can in a table — the reading
    `helena.contracts.v1.AgentResult.root` and
    `sql/migrations/0017_analyst_lookup_cache.sql` already took. In SQL it is
    `split_part(classification, '.', 1)`, which is asserted below rather than
    described.
    """
    typed = {
        name: kind
        for name, kind in migrated_engine.execute(
            "SELECT column_name, data_type FROM information_schema.columns "
            "WHERE table_schema = current_schema() AND table_name = %s",
            (orchestration.ASSESSMENT_TABLE,),
        ).fetchall()
    }
    for named in (
        "host",
        "tenant",
        "context_id",
        "context_version",
        "window_start",
        "window_end",
        "classification",
        "confidence",
        "assessed_at",
        "model_version",
        "prompt_version",
        "schema_version",
        "rendering_version",
        "prompt_tokens",
        "completion_tokens",
        "wall_clock_seconds",
        "cache_hits",
        "live_queries",
        "model_cost",
        "endpoint_host",
    ):
        assert named in typed, named
    assert "verdict" not in typed
    assert typed["confidence"] == "double precision"
    assert typed["window_start"].startswith("timestamp")
    assert typed["cache_hits"] == "integer"


# --- One pass, stored ---------------------------------------------------------


def test_one_pass_writes_one_row_per_agent_run(
    store: orchestration.AssessmentStore, migrated_engine: psycopg.Connection
):
    """A pass that escalated is two rows sharing one context reference.

    Every column `concept/03` lists is a property of one **run** — the cost, the
    latency, the nine versions, the model that answered, the verdict. A row per
    pass would have to carry two of each or lose one.
    """
    written = store.store(
        an_assessment(analysis=a_result(ANALYST, classification="malicious.c2")),
        at=RECORDED_AT,
    )
    assert len(written) == 2
    assert len(set(written)) == 2

    stored = rows(migrated_engine, orchestration.ASSESSMENT_TABLE)
    assert len(stored) == 2
    assert {row["emitter"] for row in stored} == {TRIAGE, ANALYST}
    assert {row["context_id"] for row in stored} == {"ctx-1"}
    assert {row["context_version"] for row in stored} == {"ctx-1/3"}
    assert {row["assessed_at"] for row in stored} == {RECORDED_AT}

    by_emitter = {row["emitter"]: row for row in stored}
    assert by_emitter[TRIAGE]["triggered_by"] == SCHEDULED_TRIAGE
    assert by_emitter[ANALYST]["triggered_by"] == "deterministic_signal"
    assert by_emitter[ANALYST]["classification"] == "malicious.c2"
    # The verdict, derived in SQL rather than stored beside the path.
    verdicts = migrated_engine.execute(
        f"SELECT emitter, split_part(classification, '.', 1) "
        f"FROM {orchestration.ASSESSMENT_TABLE}"
    ).fetchall()
    assert dict(verdicts) == {TRIAGE: "suspicious", ANALYST: "malicious"}


def test_a_finished_pass_writes_the_triage_row_and_nothing_else(
    store: orchestration.AssessmentStore, migrated_engine: psycopg.Connection
):
    """`concept/03`'s `else: finish()`. One run happened, so one row exists."""
    written = store.store(an_assessment(), at=RECORDED_AT)
    assert len(written) == 1
    assert [row["emitter"] for row in rows(migrated_engine, orchestration.ASSESSMENT_TABLE)] == [
        TRIAGE
    ]


def test_the_row_carries_the_request_and_the_outcome_field_for_field(
    store: orchestration.AssessmentStore, migrated_engine: psycopg.Connection
):
    """What was asked, what was granted, what was spent, and what answered."""
    asked = request()
    outcome = a_result(cost=a_cost(prompt_tokens=1200, completion_tokens=300, retries=2))
    identifier, = store.store(an_assessment(asked=asked, triage_outcome=outcome), at=RECORDED_AT)
    row = one(migrated_engine, orchestration.ASSESSMENT_TABLE, assessment_id=identifier)

    assert (row["tenant"], row["sensor"], row["host"]) == (TENANT, SENSOR, HOST)
    assert (row["window_start"], row["window_end"]) == (WINDOW_START, WINDOW_END)
    assert row["classification"] == outcome.classification
    assert row["confidence"] == pytest.approx(outcome.confidence)
    assert row["failure_reason"] is None and row["failure_detail"] is None

    # The nine dimensions, under `helena.versions.VersionSet`'s own field names,
    # plus the tenth thing a request records: what was ASKED for.
    for dimension, value in outcome.versions.as_columns().items():
        assert row[dimension] == value, dimension
    assert row["model_version"] == "model-under-test-2026-05"
    assert row["model_requested"] == "model-under-test"

    # Granted, from `AgentRequest.budgets`.
    assert row["budget_tokens"] == asked.budgets.tokens
    assert row["budget_steps"] == asked.budgets.steps
    assert row["budget_live_queries"] == asked.budgets.live_queries
    assert row["budget_wall_clock_seconds"] == pytest.approx(
        asked.budgets.wall_clock_seconds
    )
    # Spent, from `helena.contracts.v1.Cost`.
    assert row["prompt_tokens"] == 1200
    assert row["completion_tokens"] == 300
    assert row["retries"] == 2
    assert row["wall_clock_seconds"] == pytest.approx(outcome.cost.wall_clock_seconds)
    assert (row["cache_hits"], row["live_queries"], row["steps"]) == (0, 0, 0)


def test_the_identifier_is_the_context_version_and_the_run_and_nothing_else(
    store: orchestration.AssessmentStore,
):
    """A re-run mints the identifier the first run did.

    `concept/03`: *"an interrupted run is simply re-run, because the versioned
    context already makes that correct rather than a fallback."* The outcome is
    not in the digest — two runs over one context version are the same assessment
    made twice.
    """
    first, = store.store(an_assessment(), at=RECORDED_AT)
    again, = store.store(
        an_assessment(triage_outcome=a_result(classification="normal", citations=())),
        at=RECORDED_AT + timedelta(hours=1),
    )
    assert first == again
    assert first == orchestration.assessment_id(
        tenant=TENANT,
        sensor=SENSOR,
        context_id="ctx-1",
        context_version="ctx-1/3",
        emitter=TRIAGE,
        trigger=SCHEDULED_TRIAGE,
    )
    # A different tenant is a different assessment, or the upsert would be a
    # cross-tenant overwrite that looks like it is working.
    assert first != orchestration.assessment_id(
        tenant="other",
        sensor=SENSOR,
        context_id="ctx-1",
        context_version="ctx-1/3",
        emitter=TRIAGE,
        trigger=SCHEDULED_TRIAGE,
    )


def test_a_re_run_rewrites_its_own_rows_rather_than_doubling_them(
    store: orchestration.AssessmentStore, migrated_engine: psycopg.Connection
):
    """An upsert cannot remove a child row the second run no longer produces.

    So the writer deletes the run's children before it writes them. Without that,
    a re-run that cited less would leave the first run's citations standing and a
    query following them would read two runs as one.
    """
    store.store(
        an_assessment(
            triage_outcome=a_result(
                citations=(
                    Citation(evidence_id=SHOWN, stance=SUPPORTING),
                ),
                gaps=(Gap(kind="stale", detail="the snapshot was 4 days old"),),
            )
        ),
        at=RECORDED_AT,
    )
    identifier, = store.store(
        an_assessment(triage_outcome=a_result(classification="normal", citations=())),
        at=RECORDED_AT,
    )
    assert len(rows(migrated_engine, orchestration.ASSESSMENT_TABLE)) == 1
    assert rows(migrated_engine, orchestration.CITATION_TABLE) == []
    assert rows(migrated_engine, orchestration.GAP_TABLE) == []
    assert one(migrated_engine, orchestration.ASSESSMENT_TABLE, assessment_id=identifier)[
        "classification"
    ] == "normal"


# --- Re-running an interrupted assessment -------------------------------------
#
# `concept/03`: *"An assessment is one function call over one versioned context
# snapshot. No checkpointing, no durable in-flight state anywhere outside the
# engine; an interrupted run is simply re-run, because the versioned context
# already makes that correct rather than a fallback."*
#
# There is no resume to test, then. What "well-defined" has to mean is that after
# the re-run, what the store holds for that context version is what the last
# completed pass produced and nothing else — including when the re-run routed
# differently from the run it replaced, and including the child rows an
# interrupted run wrote before it died.


class _Killed(Exception):
    """What a run that stopped mid-write raises. Never caught by the writer."""


class _CutAt:
    """A connection that stops at the nth statement matching `stop_before`.

    The way a killed process stops: no rollback, no cleanup, and whatever was
    already executed stays executed. Used to leave the exact residue `_one`'s
    write order can leave — the child rows of a run whose assessment row was
    never written — so the re-run's cleanup is tested against real rows rather
    than against a description of them.
    """

    def __init__(self, connection: psycopg.Connection, *, prefix: str, nth: int):
        self._connection = connection
        self._prefix = prefix
        self._remaining = nth

    def execute(self, statement: str, params: tuple | None = None):
        if statement.startswith(self._prefix):
            self._remaining -= 1
            if self._remaining == 0:
                raise _Killed(statement[: len(self._prefix)])
        return self._connection.execute(statement, params)


def a_pass(*, trigger: str) -> orchestration.Assessment:
    """An escalated pass, under the trigger that named the branch it took."""
    return an_assessment(
        analysis=a_result(
            ANALYST,
            classification="malicious.c2",
            citations=(Citation(evidence_id=SHOWN, stance=SUPPORTING),),
            gaps=(Gap(kind="stale", detail="the snapshot was 4 days old"),),
        ),
        escalated=analyst_request(trigger=trigger),
    )


def child_rows(connection: psycopg.Connection, identifier: str) -> dict[str, int]:
    """How many rows each child table holds for one run."""
    return {
        table: len(rows(connection, table, assessment_id=identifier))
        for table in orchestration.CHILD_TABLES
    }


def test_a_re_run_that_routed_differently_supersedes_the_run_it_replaced(
    store: orchestration.AssessmentStore, migrated_engine: psycopg.Connection
):
    """One context version holds one assessment, not one per way it was reached.

    The identifier carries the trigger, so a re-run that escalated on the evidence
    where the first escalated on triage would otherwise mint a second analyst row
    and leave the first standing beside it — two live verdicts over one snapshot,
    which is the thing `assessment_id` keeping the outcome out of the digest
    exists to prevent, one level up.
    """
    first = store.store(a_pass(trigger=TRIAGE_SUSPICIOUS), at=RECORDED_AT)
    assert len(first) == 2
    again = store.store(
        a_pass(trigger="deterministic_signal"),
        at=RECORDED_AT + timedelta(hours=1),
    )

    assert again[0] == first[0], "the triage run is the same run, re-run"
    assert again[1] != first[1], "the analyst run was reached another way"
    stored = rows(migrated_engine, orchestration.ASSESSMENT_TABLE)
    assert sorted(row["assessment_id"] for row in stored) == sorted(again)
    assert [row["triggered_by"] for row in stored if row["emitter"] == ANALYST] == [
        "deterministic_signal"
    ]
    # And the superseded run took its citations, gaps and disclosures with it.
    assert child_rows(migrated_engine, first[1]) == dict.fromkeys(
        orchestration.CHILD_TABLES, 0
    )


def test_a_re_run_collects_the_child_rows_an_interrupted_run_left(
    store: orchestration.AssessmentStore, migrated_engine: psycopg.Connection
):
    """`_one` writes the children first, so a killed run can leave them orphaned.

    They are in the engine rather than outside it, which is what `concept/03`
    permits at all — but nothing keyed on what is *present* would ever find them,
    because their assessment row does not exist. The re-run addresses all three
    identifiers a snapshot could hold by key, so it collects them.
    """
    cut = orchestration.AssessmentStore(
        _CutAt(
            migrated_engine,
            prefix=f"INSERT INTO {orchestration.ASSESSMENT_TABLE} ",
            nth=2,
        ),
        prices=NO_PRICES,
    )
    with pytest.raises(_Killed):
        cut.store(a_pass(trigger=TRIAGE_SUSPICIOUS), at=RECORDED_AT)
    migrated_engine.execute("FLUSH")

    orphaned = orchestration.assessment_id(
        tenant=TENANT,
        sensor=SENSOR,
        context_id="ctx-1",
        context_version="ctx-1/3",
        emitter=ANALYST,
        trigger=TRIAGE_SUSPICIOUS,
    )
    # The residue is real: the analyst's children are there and its row is not.
    assert child_rows(migrated_engine, orphaned)[orchestration.CITATION_TABLE] == 1
    assert rows(
        migrated_engine, orchestration.ASSESSMENT_TABLE, assessment_id=orphaned
    ) == []

    # The re-run finished rather than escalating, so it never addresses the
    # orphan's identifier as one of its own — and collects it anyway.
    triage_only, = store.store(an_assessment(), at=RECORDED_AT)
    assert child_rows(migrated_engine, orphaned) == dict.fromkeys(
        orchestration.CHILD_TABLES, 0
    )
    assert [row["assessment_id"] for row in rows(
        migrated_engine, orchestration.ASSESSMENT_TABLE
    )] == [triage_only]


# --- Citations are join rows --------------------------------------------------


def test_citations_are_join_rows_carrying_the_role(
    store: orchestration.AssessmentStore, migrated_engine: psycopg.Connection
):
    """`(assessment, evidence, role)`, and both roles survive the round trip.

    `concept/03`: *"an array is where a query goes to die."* So the property under
    test is that a query can follow them: the count per role is a `GROUP BY`, not
    a deserialization.
    """
    identifier, = store.store(
        an_assessment(
            triage_outcome=a_result(
                citations=(
                    Citation(evidence_id=SHOWN, stance=SUPPORTING),
                    Citation(evidence_id=RETRIEVED, stance=CONTRADICTING),
                ),
                retrieval_trace=(),
            ),
            asked=request(
                rendering=Rendering(
                    version="r1",
                    sections=tuple(
                        RenderedSection(
                            section=name,
                            body=f"<{name}>",
                            evidence_ids=(SHOWN, RETRIEVED)
                            if name == "addresses_contacted"
                            else (),
                        )
                        for name in SECTIONS
                    ),
                )
            ),
        ),
        at=RECORDED_AT,
    )
    joined = migrated_engine.execute(
        f"SELECT role, count(*) FROM {orchestration.CITATION_TABLE} "
        f"WHERE assessment_id = %s GROUP BY role",
        (identifier,),
    ).fetchall()
    assert dict(joined) == {SUPPORTING: 1, CONTRADICTING: 1}


def test_a_citation_resolves_to_the_evidence_row_it_names(
    store: orchestration.AssessmentStore, migrated_engine: psycopg.Connection
):
    """The join the table exists for, executed against the evidence store.

    One `evidence_id` vocabulary across both tiers, so following a citation is one
    join and not a branch on where the claim came from.
    """
    migrated_engine.execute(
        "INSERT INTO helena_reference_analyst_evidence (tenant, sensor, evidence_id, "
        "source_id, endpoint, source_tier, snapshot_version, entity_type, "
        "entity_value, entity_value_key, classification, taxonomy_version, "
        "confidence, scope_type, scope_value, retrieved_at, expires_at) "
        "VALUES (%s, %s, %s, 'threatfox', 'search_ioc', 'B', 'digest', 'address', "
        "%s, %s, 'malicious', 'v1', 0.9, 'address', %s, %s, %s)",
        (TENANT, SENSOR, SHOWN, ADDRESS, ADDRESS, ADDRESS, WINDOW_START, WINDOW_END),
    )
    identifier, = store.store(an_assessment(), at=RECORDED_AT)
    resolved = migrated_engine.execute(
        f"SELECT c.role, e.classification, e.source_id "
        f"FROM {orchestration.CITATION_TABLE} c "
        f"JOIN helena_reference_analyst_evidence e USING (evidence_id) "
        f"WHERE c.assessment_id = %s",
        (identifier,),
    ).fetchall()
    assert resolved == [(SUPPORTING, "malicious", "threatfox")]


def test_a_proposals_citations_are_not_the_assessments_citations(
    store: orchestration.AssessmentStore, migrated_engine: psycopg.Connection
):
    """`concept/07`: an agent's claim about infrastructure is a **proposal**.

    A proposal's evidence is the proposal's. Folding it into the join rows would
    make the verdict look as though it cited it, and the findings table that would
    hold the proposal does not exist yet — see `helena.orchestration`'s "what is
    deliberately not here".
    """
    from helena.contracts.v1 import ProposedClaim

    outcome = a_result(
        ANALYST,
        classification="malicious.c2",
        evidence_package=EvidencePackage(patterns=(), narrative="."),
        citations=(Citation(evidence_id=SHOWN, stance=SUPPORTING),),
        proposed_claims=(
            ProposedClaim(
                subject_type="address",
                subject_value=ADDRESS,
                claim="the address is command-and-control infrastructure",
                confidence=0.6,
                citations=(Citation(evidence_id=SHOWN, stance=SUPPORTING),),
            ),
        ),
    )
    identifier = store.store(an_assessment(analysis=outcome), at=RECORDED_AT)[1]
    assert [row["evidence_id"] for row in rows(
        migrated_engine, orchestration.CITATION_TABLE, assessment_id=identifier
    )] == [SHOWN]
    assert one(
        migrated_engine, orchestration.CITATION_TABLE, assessment_id=identifier
    )["role"] == SUPPORTING


# --- Typed failures -----------------------------------------------------------


@pytest.mark.parametrize(
    "failure",
    [
        pytest.param(a_failure(), id=MODEL_UNAVAILABLE),
        pytest.param(
            a_failure(
                reason=SCHEMA_INVALID,
                detail="three answers, none of which validated",
                model_version="model-under-test-2026-05",
                gaps=(Gap(kind="missing", detail="no verdict was produced"),),
            ),
            id=SCHEMA_INVALID,
        ),
    ],
)
def test_a_typed_failure_is_a_row_carrying_the_failure_and_no_verdict(
    store: orchestration.AssessmentStore,
    migrated_engine: psycopg.Connection,
    failure: AgentFailure,
):
    """`concept/02`: never a verdict, never a silent drop.

    The three verdict columns are NULL and the two failure columns are not, and
    the row is there — which is the half a silent drop would fail.
    """
    identifier, = store.store(an_assessment(triage_outcome=failure), at=RECORDED_AT)
    row = one(migrated_engine, orchestration.ASSESSMENT_TABLE, assessment_id=identifier)
    assert row["classification"] is None
    assert row["confidence"] is None
    assert row["narrative"] is None
    assert row["failure_reason"] == failure.reason
    assert row["failure_detail"] == failure.detail
    # `model_unavailable` means nothing answered, so no reported identity exists
    # and recording the configured one in its place would be the substitution
    # `docs/decisions/0008-version-registry.md` exists to prevent.
    assert row["model_version"] == failure.model_version
    assert row["model_requested"] == "model-under-test"
    # It still records what it spent and what it could not see.
    assert row["prompt_tokens"] == 0
    assert len(rows(migrated_engine, orchestration.GAP_TABLE, assessment_id=identifier)) == len(
        failure.gaps
    )


def test_no_stored_row_carries_both_a_verdict_and_a_failure(
    store: orchestration.AssessmentStore, migrated_engine: psycopg.Connection
):
    """The property, asserted over the store rather than over one writer call.

    RisingWave has no CHECK constraint, so this is what stands in for one: a
    query over every row asking whether either side is half-populated.
    """
    store.store(an_assessment(analysis=a_result(ANALYST, classification="normal")), at=RECORDED_AT)
    store.store(
        an_assessment(triage_outcome=a_failure(), asked=request(context_id="ctx-2")),
        at=RECORDED_AT,
    )
    broken = migrated_engine.execute(
        f"SELECT assessment_id FROM {orchestration.ASSESSMENT_TABLE} "
        f"WHERE (classification IS NULL) = (failure_reason IS NULL)"
    ).fetchall()
    assert broken == []


# --- Gaps ---------------------------------------------------------------------


def test_the_seven_gap_kinds_stay_seven(
    store: orchestration.AssessmentStore, migrated_engine: psycopg.Connection
):
    """`concept/instruction.md` §2: never collapse them, at any layer, for any reason.

    A gaps table is a layer. All seven round-trip, distinctly, and two gaps of one
    kind are two rows — a run can be missing two things.
    """
    gaps = tuple(
        Gap(kind=kind, detail=f"detail for {kind}") for kind in GAP_KINDS
    ) + (Gap(kind="missing", detail="and a second missing thing"),)
    identifier = store.store(
        an_assessment(
            analysis=a_result(
                ANALYST,
                classification="unknown",
                citations=(),
                gaps=gaps,
                evidence_package=EvidencePackage(narrative="nothing resolved"),
            )
        ),
        at=RECORDED_AT,
    )[1]
    stored = rows(migrated_engine, orchestration.GAP_TABLE, assessment_id=identifier)
    assert [row["kind"] for row in stored] == [gap.kind for gap in gaps]
    assert len({row["kind"] for row in stored}) == len(GAP_KINDS)
    assert [row["detail"] for row in stored] == [gap.detail for gap in gaps]


# --- The retrieval trace ------------------------------------------------------


def test_the_trace_tells_a_cache_hit_from_a_live_query_and_types_the_failure(
    store: orchestration.AssessmentStore, migrated_engine: psycopg.Connection
):
    """`concept/07`: two runs that differ only in cache state must be distinguishable.

    And `concept/05` rule 4: a query that did not complete emits a typed error and
    no taxonomy object — so the evidence id and the failure are exclusive on the
    row, exactly as they are on the step.
    """
    trace = (
        RetrievalStep(
            source_id="threatfox",
            entity_type="address",
            entity_value=ADDRESS,
            outcome=LIVE_QUERY,
            retrieved_at=WINDOW_END,
            evidence_id=RETRIEVED,
        ),
        RetrievalStep(
            source_id="threatfox",
            entity_type="domain",
            entity_value=DOMAIN,
            outcome=CACHE_HIT,
            retrieved_at=WINDOW_START,
            evidence_id=SHOWN,
        ),
        RetrievalStep(
            source_id="threatfox",
            entity_type="url",
            entity_value=f"http://{DOMAIN}/a",
            outcome=LIVE_QUERY,
            retrieved_at=WINDOW_END,
            failure=QueryFailure(
                source_id="threatfox",
                entity_type="url",
                entity_value=f"http://{DOMAIN}/a",
                reason=enrichment.TIMEOUT,
                detail="the provider did not answer within the budget",
            ),
        ),
    )
    identifier = store.store(
        an_assessment(
            analysis=a_result(
                ANALYST,
                classification="malicious.c2",
                citations=(Citation(evidence_id=RETRIEVED, stance=SUPPORTING),),
                retrieval_trace=trace,
                evidence_package=EvidencePackage(narrative="."),
                cost=a_cost(steps=3, live_queries=2, cache_hits=1),
            )
        ),
        at=RECORDED_AT,
    )[1]
    stored = rows(migrated_engine, orchestration.RETRIEVAL_TABLE, assessment_id=identifier)
    assert [row["outcome"] for row in stored] == [LIVE_QUERY, CACHE_HIT, LIVE_QUERY]
    # The cache hit carries the age of what it SERVED, not the age of the step.
    assert stored[1]["retrieved_at"] == WINDOW_START
    assert stored[0]["evidence_id"] == RETRIEVED and stored[0]["failure_reason"] is None
    assert stored[2]["evidence_id"] is None
    assert stored[2]["failure_reason"] == enrichment.TIMEOUT
    assert "did not answer" in stored[2]["failure_detail"]
    # The counts on the assessment row reconcile with the rows in the trace.
    row = one(migrated_engine, orchestration.ASSESSMENT_TABLE, assessment_id=identifier)
    assert row["live_queries"] == sum(1 for s in stored if s["outcome"] == LIVE_QUERY)
    assert row["cache_hits"] == sum(1 for s in stored if s["outcome"] == CACHE_HIT)


# --- Disclosures and the endpoint --------------------------------------------


def test_the_disclosure_rows_are_the_ledger_and_the_endpoint_is_read_off_them(
    store: orchestration.AssessmentStore, migrated_engine: psycopg.Connection
):
    """`concept/07`: what was disclosed is recorded on the assessment.

    Source, query, disclosed-to and when are columns; the cache-hit half is the
    retrieval trace on the same assessment. And the endpoint host is read off this
    ledger rather than off configuration, because configuration is what would be
    wrong in the cross-wiring case the column exists to catch.
    """
    asked = request()
    rows_of = ledger(asked)
    a_model_call(rows_of, host="wrong-endpoint.invalid:8443")
    assessment = orchestration.Assessment(
        request=asked,
        escalation=None,
        triage=a_result(),
        triage_disclosures=rows_of,
        trigger=None,
        analyst_request=None,
        analysis=None,
        analyst_disclosures=None,
    )
    identifier, = store.store(assessment, at=RECORDED_AT)
    disclosed = one(
        migrated_engine, orchestration.DISCLOSURE_TABLE, assessment_id=identifier
    )
    assert disclosed["channel"] == disclosure.MODEL_INFERENCE
    assert disclosed["source"] == "model-under-test"
    assert disclosed["disclosed_to"] == "wrong-endpoint.invalid:8443"
    assert disclosed["send_policy_version"] == SEND_POLICY.version
    assert len(disclosed["query_digest"]) == 64
    assert "://" not in disclosed["disclosed_to"]
    row = one(migrated_engine, orchestration.ASSESSMENT_TABLE, assessment_id=identifier)
    assert row["endpoint_host"] == "wrong-endpoint.invalid:8443"


def test_a_run_whose_prompt_never_left_records_no_endpoint_rather_than_the_configured_one(
    store: orchestration.AssessmentStore, migrated_engine: psycopg.Connection
):
    """NULL is "no prompt left", which is not "an endpoint failed".

    A run that ended on the clock before its first call disclosed nothing, and a
    configured host written in its place would erase the difference — the same
    collapse `concept/instruction.md` §2 forbids between four kinds of absence.
    """
    identifier, = store.store(an_assessment(disclose=False), at=RECORDED_AT)
    row = one(migrated_engine, orchestration.ASSESSMENT_TABLE, assessment_id=identifier)
    assert row["endpoint_host"] is None
    assert rows(migrated_engine, orchestration.DISCLOSURE_TABLE) == []


def test_two_endpoints_in_one_ledger_are_refused_rather_than_picked_from(
    store: orchestration.AssessmentStore,
):
    """One agent run has one client, so this is this project's own bug and is loud."""
    asked = request()
    rows_of = ledger(asked)
    a_model_call(rows_of, host="one.invalid:443")
    a_model_call(rows_of, host="two.invalid:443")
    with pytest.raises(orchestration.AssessmentError) as refused:
        store.store(
            orchestration.Assessment(
                request=asked,
                escalation=None,
                triage=a_result(),
                triage_disclosures=rows_of,
                trigger=None,
                analyst_request=None,
                analysis=None,
                analyst_disclosures=None,
            ),
            at=RECORDED_AT,
        )
    assert "one.invalid:443" in str(refused.value)


# --- Validation before the write ---------------------------------------------


def test_an_outcome_that_does_not_answer_the_request_is_refused(
    store: orchestration.AssessmentStore, migrated_engine: psycopg.Connection
):
    """`concept/07`: agents propose, code validates and writes — at the write.

    The pair is what only this check can see: a citation to evidence the rendering
    never showed and the trace never produced is a model citing evidence it was
    never handed, and a row written anyway would be an assessment nobody can
    resolve.
    """
    with pytest.raises(orchestration.AssessmentError) as refused:
        store.store(
            an_assessment(
                triage_outcome=a_result(
                    citations=(Citation(evidence_id="a" * 64, stance=SUPPORTING),)
                )
            ),
            at=RECORDED_AT,
        )
    assert "does not answer the request" in str(refused.value)
    assert rows(migrated_engine, orchestration.ASSESSMENT_TABLE) == []
    assert rows(migrated_engine, orchestration.CITATION_TABLE) == []


def test_a_price_table_is_required_and_is_not_a_dict():
    """The figure and the revision that produced it come from one object."""
    with pytest.raises(orchestration.AssessmentError):
        orchestration.AssessmentStore(None, prices={"model-under-test": 3.0})


# --- The derived cost ---------------------------------------------------------


def test_an_unpriced_model_stores_null_and_not_zero(
    store: orchestration.AssessmentStore, migrated_engine: psycopg.Connection
):
    """`config/policy.toml` prices nothing, so this deployment derives nothing.

    NULL is *not priced*. Reading it as free would be the same collapse
    `concept/instruction.md` §2 forbids between `missing` and `no_match`, applied
    to money — and the alternative, a plausible rate, is the invented external
    fact `concept/instruction.md` §0 is about.
    """
    identifier, = store.store(an_assessment(), at=RECORDED_AT)
    row = one(migrated_engine, orchestration.ASSESSMENT_TABLE, assessment_id=identifier)
    assert row["model_cost"] is None
    assert row["model_cost_currency"] is None
    assert row["model_prices_version"] is None


def test_a_priced_model_derives_the_cost_from_the_tokens_it_spent(
    migrated_engine: psycopg.Connection,
):
    """`concept/06`: monetary cost is derived and recorded per assessment.

    Derived from the two token counts and the price table, with the revision of
    that table recorded beside it — a stored figure whose price nobody can recover
    is a number nobody can check.
    """
    priced = orchestration.AssessmentStore(migrated_engine, prices=PRICED)
    identifier, = priced.store(
        an_assessment(
            triage_outcome=a_result(
                cost=a_cost(prompt_tokens=1_000_000, completion_tokens=200_000)
            )
        ),
        at=RECORDED_AT,
    )
    row = one(migrated_engine, orchestration.ASSESSMENT_TABLE, assessment_id=identifier)
    assert row["model_cost"] == pytest.approx(3.0 + 3.0)
    assert row["model_cost_currency"] == "USD"
    assert row["model_prices_version"] == "prices-under-test"


# --- No free-text note, anywhere ---------------------------------------------
#
# `concept/07-principles.md`: *"memory entries, if memory returns, must be
# **structured claims with provenance, confidence and expiry — never free-text
# summaries of retrieved content**. A free-text note is precisely the persistence
# channel by which attacker-influenced text reaches a future session's context."*
#
# Three properties, and each is a different way that channel could open.

#: The only columns in the assessment schema that hold a sentence rather than a
#: token, a digest, a version or a number. Declared, so that a seventh is a
#: deliberate edit with an argument beside it rather than a column that appears.
FREE_TEXT_COLUMNS = {
    (orchestration.ASSESSMENT_TABLE, "narrative"),
    (orchestration.ASSESSMENT_TABLE, "failure_detail"),
    (orchestration.GAP_TABLE, "detail"),
    (orchestration.PATTERN_TABLE, "pattern"),
    (orchestration.RETRIEVAL_TABLE, "failure_detail"),
    (orchestration.DISCLOSURE_TABLE, "query"),
}

#: Column and table names a note would arrive under. Not a spelling check — it is
#: the cheapest way to catch the shape of mistake this section exists to prevent,
#: and it covers the whole schema rather than these six tables.
NOTE_NAMES = re.compile(
    r"\bnote|memo|scratch|transcript|summary|thought|reasoning|"
    r"comment|rationale|chain_of|freeform|free_text",
    re.IGNORECASE,
)


def test_no_table_or_column_in_the_schema_is_shaped_like_a_note(
    migrated_engine: psycopg.Connection,
):
    """The whole store, not only these six tables.

    A note does not have to arrive in the assessment schema to be a note. What
    this refuses is the *shape*: a column whose name says it holds an agent's
    prose. `narrative` is the one the concept note asks for by name and it is not
    in the pattern.

    "observation" is deliberately **not** in the pattern. It is this project's
    word for *an entity was seen in traffic* — `helena_signal_entity_observations`
    is a measurement table — and the loose "observations" field the agent contract
    refuses is refused by `extra="forbid"` on every contract model and by
    `tests/test_contracts.py`, which is where that rule can be checked by name.
    """
    named = migrated_engine.execute(
        "SELECT table_name, column_name FROM information_schema.columns "
        "WHERE table_schema = current_schema()"
    ).fetchall()
    offenders = [
        f"{table}.{column}"
        for table, column in named
        if NOTE_NAMES.search(column) or NOTE_NAMES.search(table)
    ]
    assert not offenders, (
        "a column or table is named like an agent's note; agent output is stored "
        "as typed rows and its one sentence is `narrative` "
        "(`concept/03`, `concept/07`):\n" + "\n".join(offenders)
    )


def test_the_free_text_columns_of_the_assessment_schema_are_the_declared_six(
    store: orchestration.AssessmentStore, migrated_engine: psycopg.Connection
):
    """Every other string column holds a token, an identifier, a version or a digest.

    Demonstrated rather than declared: one run is stored whose every string field
    is filled, and each stored value outside the declared six is asserted to be a
    member of a closed vocabulary, a 64-character digest, a configured identifier
    or a version this test wrote.
    """
    identifier = store.store(
        an_assessment(
            analysis=a_result(
                ANALYST,
                classification="malicious.c2",
                gaps=(Gap(kind="truncated", detail="six domains were dropped"),),
                evidence_package=EvidencePackage(
                    patterns=("periodic beaconing",),
                    narrative="the address answered and traffic went both ways",
                ),
                retrieval_trace=(
                    RetrievalStep(
                        source_id="threatfox",
                        entity_type="address",
                        entity_value=ADDRESS,
                        outcome=LIVE_QUERY,
                        retrieved_at=WINDOW_END,
                        evidence_id=RETRIEVED,
                    ),
                ),
                citations=(Citation(evidence_id=RETRIEVED, stance=SUPPORTING),),
            ),
            asked=request(
                rendering=Rendering(
                    version="r1",
                    sections=tuple(
                        RenderedSection(
                            section=name,
                            body=f"<{name}>",
                            evidence_ids=(SHOWN,)
                            if name == "addresses_contacted"
                            else (),
                            truncation=None,
                        )
                        for name in SECTIONS
                    ),
                )
            ),
        ),
        at=RECORDED_AT,
    )[1]

    closed = (
        set(GAP_KINDS)
        | {SUPPORTING, CONTRADICTING, LIVE_QUERY, CACHE_HIT}
        | {TRIAGE, ANALYST, SCHEDULED_TRIAGE, "deterministic_signal"}
        | {TENANT, SENSOR, HOST, ADDRESS, DOMAIN, "ctx-1", "ctx-1/3"}
        | {"threatfox", "address", "domain", "url", "malicious.c2", "model-under-test"}
        | {"model-under-test-2026-05", SEND_POLICY.version, "USD", ENDPOINT}
        | set(disclosure.CHANNELS)
        | set(versions().model_dump().values())
        | {SHOWN, RETRIEVED, identifier}
    )
    loose: list[str] = []
    for table in TABLES:
        for row in rows(migrated_engine, table, assessment_id=identifier):
            for column, value in row.items():
                if not isinstance(value, str) or value is None:
                    continue
                if (table, column) in FREE_TEXT_COLUMNS:
                    continue
                if value in closed or re.fullmatch(r"[0-9a-f]{64}", value):
                    continue
                loose.append(f"{table}.{column} = {value!r}")
    assert not loose, (
        "a string outside the declared free-text columns is not a token, an "
        "identifier or a digest:\n" + "\n".join(loose)
    )
    # And the declared six are the ones the engine actually has as text columns.
    declared = {table for table, _ in FREE_TEXT_COLUMNS}
    assert declared <= set(TABLES)


def test_the_agents_own_sentences_land_only_where_this_test_expects_them(
    store: orchestration.AssessmentStore, migrated_engine: psycopg.Connection
):
    """Three markers, three columns, and nothing else in the whole store holds them.

    The narrative is `concept/03`'s text column and the patterns are the rest of
    `concept/02`'s evidence package; a gap detail is what keeps `unknown`
    falsifiable. Each is a bounded, declared field of the frozen contract. What
    this asserts is that none of them leaks into a second column, a second table
    or a general-purpose note — searched over every text column of every table in
    the schema, not only over the six this increment added.
    """
    markers = {
        "narrative": "MARKERNARRATIVE",
        "pattern": "MARKERPATTERN",
        "gap": "MARKERGAP",
    }
    store.store(
        an_assessment(
            analysis=a_result(
                ANALYST,
                classification="unknown",
                citations=(),
                gaps=(Gap(kind="failed", detail=f"the lookup {markers['gap']}"),),
                evidence_package=EvidencePackage(
                    patterns=(f"a pattern {markers['pattern']}",),
                    narrative=f"a narrative {markers['narrative']}",
                ),
            )
        ),
        at=RECORDED_AT,
    )
    found = {name: set() for name in markers}
    for table, column in _text_columns(migrated_engine):
        for name, marker in markers.items():
            hit = migrated_engine.execute(
                f"SELECT count(*) FROM {table} WHERE {column} LIKE %s",
                (f"%{marker}%",),
            ).fetchall()[0][0]
            if hit:
                found[name].add(f"{table}.{column}")
    assert found["narrative"] == {f"{orchestration.ASSESSMENT_TABLE}.narrative"}
    assert found["pattern"] == {f"{orchestration.PATTERN_TABLE}.pattern"}
    assert found["gap"] == {f"{orchestration.GAP_TABLE}.detail"}


def _text_columns(connection: psycopg.Connection) -> list[tuple[str, str]]:
    """Every string column of every base table in the schema."""
    connection.execute("FLUSH")
    return [
        (table, column)
        for table, column in connection.execute(
            "SELECT c.table_name, c.column_name "
            "FROM information_schema.columns c "
            "JOIN information_schema.tables t "
            "  ON t.table_schema = c.table_schema AND t.table_name = c.table_name "
            "WHERE c.table_schema = current_schema() "
            "  AND t.table_type = 'BASE TABLE' "
            "  AND c.data_type IN ('character varying', 'text')"
        ).fetchall()
    ]


#: The three modules `tests/test_untrusted.py` asserts are the only ones that
#: build a `helena.agents.Message`. Named here rather than discovered, because
#: this test is only as good as that set — and that test fails first if it moves.
PROMPT_MODULES = ("agents.py", "analyst/v1.py", "triage/v1.py")


def test_nothing_that_builds_a_prompt_can_read_a_stored_assessment():
    """The channel `concept/07` names, closed structurally rather than by review.

    *"A free-text note is precisely the persistence channel by which
    attacker-influenced text reaches a future session's context."* The narrative
    and the patterns are bounded and declared, but the property that matters is
    that **nothing which builds a prompt can read them back**: no module that
    constructs a model turn names an assessment table or imports the store.

    Read off the AST rather than off a grep, so a name in a docstring is not a
    finding and a name in a query is.
    """
    offenders = []
    for relative in PROMPT_MODULES:
        source = (PACKAGE_ROOT / relative).read_text()
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                for table in TABLES:
                    if table in node.value:
                        offenders.append(f"{relative}:{node.lineno}: names {table}")
            if isinstance(node, ast.Name) and node.id in {
                "AssessmentStore",
                "ASSESSMENT_TABLE",
            }:
                offenders.append(f"{relative}:{node.lineno}: uses {node.id}")
            if isinstance(node, ast.Attribute) and node.attr in {
                "AssessmentStore",
                "ASSESSMENT_TABLE",
            }:
                offenders.append(f"{relative}:{node.lineno}: uses {node.attr}")
    assert not offenders, (
        "a module that builds a prompt can reach the stored assessment; a stored "
        "sentence that can be read back into a prompt is the memory-poisoning "
        "channel `concept/07` names:\n" + "\n".join(offenders)
    )


# --- End to end ---------------------------------------------------------------


class _Endpoint:
    """A real OpenAI-compatible endpoint on the loopback interface, scripted.

    The same shape `tests/test_orchestration.py` uses, and here for the same
    reason: what is under test is that the object the router returns is the object
    the tables hold, so the router has to have actually run.
    """

    def __init__(self, script: list[Any]) -> None:
        self.script = list(script)
        endpoint = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self) -> None:  # noqa: N802 — the stdlib's name
                length = int(self.headers.get("Content-Length", 0))
                self.rfile.read(length)
                assert endpoint.script, "the endpoint was called more times than scripted"
                body = json.dumps(endpoint.script.pop(0)).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args: object) -> None:
                """The stdlib handler logs to stderr; the suite has its own channel."""

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> _Endpoint:
        self.thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_port}/v1/"

    @property
    def host(self) -> str:
        return f"127.0.0.1:{self.server.server_port}"

    def client(self, agent: str, stream: io.StringIO) -> ModelClient:
        return ModelClient(
            ModelSettings(
                agent=agent,
                endpoint_url=self.url,
                token=Secret("token-under-test"),
                model="model-under-test",
                source={
                    "LLM_URL": "LLM_URL",
                    "LLM_TOKEN": "LLM_TOKEN",
                    "LLM_MODEL": "LLM_MODEL",
                },
            ),
            logger=observability.StructuredLogger(
                component=f"agents.{agent}",
                tenant=TENANT,
                sensor=SENSOR,
                redactor=observability.Redactor(["token-under-test"]),
                stream=stream,
            ),
        )


def answered(content: str, *, prompt: int = 40, completion: int = 20) -> dict:
    return {
        "id": "cmpl-1",
        "model": "model-under-test-2026-05",
        "choices": [
            {
                "index": 0,
                "finish_reason": "stop",
                "message": {"role": "assistant", "content": content},
            }
        ],
        "usage": {"prompt_tokens": prompt, "completion_tokens": completion},
    }


def test_a_routed_pass_is_stored_as_the_rows_the_router_produced(
    store: orchestration.AssessmentStore, migrated_engine: psycopg.Connection
):
    """The whole path: a real endpoint, the real router, the real writer.

    The projection escalates on its own, so `concept/03`'s first branch fires and
    the analyst runs with no tools bound — which keeps this a persistence test.
    What is asserted is that every field of the two in-process outcomes is on the
    two rows, including the endpoint the prompts actually went to.
    """
    stream = io.StringIO()
    triage_said = json.dumps({"classification": "normal", "confidence": 0.9})
    analyst_said = json.dumps(
        {
            "classification": "malicious.c2",
            "confidence": 0.85,
            "citations": [{"evidence_id": SHOWN, "stance": SUPPORTING}],
            "evidence_package": {
                "patterns": ["regular contact with a listed address"],
                "narrative": "the host reached a listed command-and-control address",
            },
        }
    )
    with _Endpoint(
        [answered(triage_said), answered(analyst_said), answered(analyst_said)]
    ) as endpoint:
        assessment = orchestration.assess(
            request(),
            projection=a_projection(),
            triage_client=endpoint.client(TRIAGE, stream),
            analyst_client=endpoint.client(ANALYST, stream),
            retry=THREE_ATTEMPTS,
            triage_prompt=TRIAGE_PROMPT,
            analyst_prompt=ANALYST_PROMPT,
            provider_tools=(),
            thresholds=THRESHOLDS,
            budget_policy=BUDGET_POLICY,
            send_policy=SEND_POLICY,
            inherit=OFF,
            logger=observability.StructuredLogger(
                component="orchestration",
                tenant=TENANT,
                sensor=SENSOR,
                redactor=observability.Redactor(["token-under-test"]),
                stream=stream,
            ),
        )
        assert assessment.trigger == "deterministic_signal"
        written = store.store(assessment, at=RECORDED_AT)
        assert len(written) == 2

        stored = {
            row["emitter"]: row
            for row in rows(migrated_engine, orchestration.ASSESSMENT_TABLE)
        }
        assert stored[TRIAGE]["classification"] == "normal"
        assert stored[ANALYST]["classification"] == "malicious.c2"
        # A `normal` triage decision returns verdict and confidence only, so the
        # escalation that reached the analyst is not one triage cited.
        assert rows(
            migrated_engine,
            orchestration.CITATION_TABLE,
            assessment_id=written[0],
        ) == []
        assert [
            row["evidence_id"]
            for row in rows(
                migrated_engine,
                orchestration.CITATION_TABLE,
                assessment_id=written[1],
            )
        ] == [SHOWN]
        assert [
            row["pattern"]
            for row in rows(
                migrated_engine,
                orchestration.PATTERN_TABLE,
                assessment_id=written[1],
            )
        ] == ["regular contact with a listed address"]
        assert "command-and-control" in stored[ANALYST]["narrative"]
        # The endpoint the prompt actually went to, on both rows.
        assert stored[TRIAGE]["endpoint_host"] == endpoint.host
        assert stored[ANALYST]["endpoint_host"] == endpoint.host
        assert stored[ANALYST]["model_version"] == "model-under-test-2026-05"
        # The analyst's prompt version is its own, and the rest are echoed.
        assert stored[TRIAGE]["prompt_version"] == TRIAGE_PROMPT.version
        assert stored[ANALYST]["prompt_version"] == ANALYST_PROMPT.version
        assert stored[ANALYST]["policy_version"] == rule.POLICY_VERSION
        # Every model call that left is a disclosure row on its own run's row.
        for identifier in written:
            channels = {
                row["channel"]
                for row in rows(
                    migrated_engine,
                    orchestration.DISCLOSURE_TABLE,
                    assessment_id=identifier,
                )
            }
            assert channels == {disclosure.MODEL_INFERENCE}
