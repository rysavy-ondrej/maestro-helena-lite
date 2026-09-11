"""Assessment replay: the stored run, read back against the version it recorded.

The sentences under test are `concept/instruction.md` §2, "Reproducibility":

- *"**Replay validates against the version the assessment recorded**, never
  against current code. Historical schema classes are retained frozen; migrating
  old rows forward is forbidden."*
- *"**Replay reads stored responses and never re-queries a live provider.**"*

and `concept/04`'s reason the context version is on the request at all — it *"is
what makes replay possible"* — which is what `reconstruct` cashes in: the
rendering is not stored, so it is rebuilt from the recorded context version under
the recorded rendering version, and a projection at any other version is refused.

**Everything here runs.** The rows are written by the real writer and read back
by the real reader through a real engine; the version dispatch is exercised
against a contract version that is *not* the current one, installed as a module
the loader has to find by name; the no-live-query property is measured the way
task 41 measured it — with a provider adapter that raises on contact, so there is
no path in which a provider was reached and the assertions still hold; and the
event-time snapshot join is measured through the whole rendering path over a real
capture and two real feed loads.

`tests/test_replay.py` is the outbound-network guard underneath all of this.
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta
from types import ModuleType
from typing import Any

import psycopg
import pytest
from pydantic import BaseModel, ConfigDict, ValidationError

from helena import (
    analyst,
    contracts,
    disclosure,
    enrichment,
    hosts,
    observability,
    orchestration,
    rendering,
    tools,
)
from helena.config import Settings
from helena.contracts import UnknownVersion
from helena.contracts.v1 import (
    CACHE_HIT,
    CONTRACT_VERSION,
    CONTRADICTING,
    DETERMINISTIC_SIGNAL,
    MISSING,
    MODEL_UNAVAILABLE,
    SCHEDULED_TRIAGE,
    SUPPORTING,
    AgentResult,
    Citation,
    EvidencePackage,
    Gap,
    RetrievalStep,
)
from helena.enrichment import QueryFailure
from helena.rendering import ContextEntity, EntityEnrichment, RenderingStore
from helena.rendering import v1 as rendering_v1
from helena.taxonomy import ANALYST, TRIAGE

# The assessment scaffolding is imported rather than rebuilt: `test_assessments`
# already owns the builders for a request, a projection, an outcome, a ledger and
# a routed pass, and a second copy here would be a second definition of what a
# stored assessment looks like — which is the drift this module exists to catch.
from test_assessments import (  # noqa: E402 — see the comment above
    ADDRESS,
    ANALYST_PROMPT,
    BUDGET_POLICY,
    HOST,
    RECORDED_AT,
    SEND_POLICY,
    SENSOR,
    SHOWN,
    TENANT,
    THREE_ATTEMPTS,
    TRIAGE_PROMPT,
    WINDOW_END,
    WINDOW_START,
    _Endpoint,
    a_cost,
    a_failure,
    a_model_call,
    a_projection as _one_claim_projection,
    a_result,
    an_assessment,
    answered,
    ledger,
    store,  # noqa: F401 — a fixture, used by name
)
from test_enriched import an_entity  # noqa: E402 — one query, not a second copy

# The real-context scaffolding comes from `test_rendering`, which already
# re-stamps the layer-coverage capture into the window `now` falls in — which is
# what puts the context inside the retention boundary, and therefore inside
# `helena_signal_host_context_live`, which is what a projection reads.
from test_rendering import (  # noqa: E402
    RAW,
    live,  # noqa: F401 — a fixture, used by name
    load,
    project,
    targeted,
)

pytestmark = pytest.mark.integration

#: The rendering version this tree holds. The rendering `test_assessments` builds
#: by hand records `r1`, which is a version no module implements — fine for a
#: writer test and useless here, because a replay has to *rebuild* the rendering
#: from the version the row recorded.
RENDERING_VERSION = rendering_v1.RENDERING_VERSION

ATTRIBUTES = hosts.load().attributes_for(HOST)
BUDGET = rendering.budget()

#: A second claim, on a domain, so the rendering shows two evidence ids. One is
#: enough for everything except the citation set, and the citation set is where
#: the stored schema loses something (`CITATION_TABLE` has no ordinal), so it is
#: the thing a round-trip test has to be able to see.
DOMAIN = "c2.example.invalid"
OTHER = "d" * 64

MODEL_ANSWERED = "model-under-test-2026-05"
TOOL_NAME = f"lookup_{enrichment.THREATFOX_SOURCE}_search_ioc"

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
    "HELENA_OUTPUT_TOPIC": "helena.output",
}

PROJECT_ROOT = __import__("pathlib").Path(__file__).resolve().parent.parent


def settings(**overrides: str) -> Settings:
    return Settings.load(environ={**ENVIRONMENT, **overrides}, env_file=None)


# --- Builders: the same pass, rendered by the real renderer -------------------


def versions(**overrides: str) -> Any:
    """`test_assessments`' version set, at a rendering version that exists."""
    from test_assessments import versions as stored_versions

    return stored_versions(rendering_version=RENDERING_VERSION, **overrides)


def a_projection(**overrides: object) -> Any:
    """`test_assessments`' projection, plus the domain claim described above."""
    base = _one_claim_projection(**overrides)
    return base.model_copy(
        update={
            "entities": (
                *base.entities,
                ContextEntity(
                    entity_type="domain",
                    entity_value=DOMAIN,
                    fingerprint_algorithm=None,
                    observed_layers=("dns_query",),
                    observed_flow_count=0,
                    observed_bytes_sent=0,
                    observed_bytes_received=0,
                    ports=(),
                    enrichment=(
                        EntityEnrichment(
                            source_id=enrichment.THREATFOX_SOURCE,
                            source_tier="B",
                            status="ok",
                            classification="malicious",
                            confidence=0.9,
                            scope_type="domain",
                            scope_value=DOMAIN,
                            port_matched=None,
                            evidence_id=OTHER,
                            snapshot_version="2024-06-01T00:00:00Z",
                        ),
                    ),
                ),
            )
        }
    )


def a_rendering(projection: Any = None) -> Any:
    """The real rendering of the synthetic projection, under `v1`.

    What `reconstruct` rebuilds, so the request the store is given has to be the
    same object a rebuild would produce — otherwise the test would be measuring
    the difference between two renderers.
    """
    return rendering.version(RENDERING_VERSION).render(
        a_projection() if projection is None else projection, ATTRIBUTES, BUDGET
    )


def request(**overrides: object) -> Any:
    from test_assessments import request as stored_request

    return stored_request(
        **{"rendering": a_rendering(), "versions": versions(), **overrides}
    )


def escalated_request(**overrides: object) -> Any:
    return orchestration.analyst_request(
        request(**overrides),
        trigger=DETERMINISTIC_SIGNAL,
        prompt_version=ANALYST_PROMPT.version,
        granted=BUDGET_POLICY.for_emitter(ANALYST),
    )


def a_verdict(emitter: str = TRIAGE, **overrides: object) -> AgentResult:
    return a_result(
        emitter,
        **{"versions": versions().completed_by(MODEL_ANSWERED), **overrides},
    )


def stored_pass(
    *,
    triage_outcome: Any = None,
    analysis: Any = None,
) -> tuple[Any, ...]:
    """One routed pass, assembled with the real rendering and handed to the writer."""
    asked = request()
    escalated = escalated_request() if analysis is not None else None
    return an_assessment(
        triage_outcome=a_verdict() if triage_outcome is None else triage_outcome,
        analysis=analysis,
        asked=asked,
        escalated=escalated,
    )


def unreachable(reached: list) -> Any:
    """A provider adapter that fails the test if a replay ever reaches it.

    Task 41's device, and the reason for it is unchanged: the adapter is the only
    thing that can reach a provider and the only thing the credential is handed
    to, so an adapter that was not called is an indicator that was not sent and a
    key that was never revealed. A counter could be wrong; this cannot.
    """

    def ask(call: tools.ToolCall, credential: Any) -> Any:
        reached.append(call)
        raise AssertionError(
            f"a replay queried {call.source_id} about {call.entity_type}; that is "
            f"a new investigation with a different answer, not a replay"
        )

    return ask


def replay_tool(reached: list, connection: psycopg.Connection) -> tools.ProviderTool:
    configured = settings()
    return tools.ProviderTool(
        source_id=enrichment.THREATFOX_SOURCE,
        endpoint="search_ioc",
        credential=configured.providers.abusech_auth_key,
        ask=unreachable(reached),
        cache=tools.EvidenceCache(connection),
        retention_seconds=enrichment.THREATFOX_MIN_FETCH_INTERVAL_SECONDS,
        send_policy=SEND_POLICY,
        replay=True,
        logger=observability.logger("tools", configured, stream=io.StringIO()),
        redactor=observability.Redactor.from_settings(configured),
    )


def called(name: str, arguments: dict) -> dict:
    """One completion asking for a tool, as the endpoint returns it."""
    return {
        "id": "cmpl-1",
        "model": MODEL_ANSWERED,
        "choices": [
            {
                "index": 0,
                "finish_reason": "tool_calls",
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "index": 0,
                            "id": "call-1",
                            "type": "function",
                            "function": {
                                "name": name,
                                "arguments": json.dumps(arguments),
                            },
                        }
                    ],
                },
            }
        ],
        "usage": {"prompt_tokens": 40, "completion_tokens": 20},
    }


def said(**fields: Any) -> str:
    return json.dumps(fields)


# --- Writing a row the writer would not write ---------------------------------
#
# Two tests below need a row that `AssessmentStore` cannot produce: one recording
# a contract version this tree does not hold, and one carrying both terminal
# outcomes. They are written with SQL for that reason, against the same column
# list the writer and the reader share, so a column added to the schema reaches
# this helper rather than leaving it silently short.


def a_row(**overrides: object) -> dict[str, object]:
    granted = BUDGET_POLICY.for_emitter(TRIAGE)
    row: dict[str, object] = {
        "assessment_id": "a" * 64,
        "tenant": TENANT,
        "sensor": SENSOR,
        "host": HOST,
        "context_id": "ctx-1",
        "context_version": "ctx-1/3",
        "window_start": WINDOW_START,
        "window_end": WINDOW_END,
        "emitter": TRIAGE,
        "triggered_by": SCHEDULED_TRIAGE,
        "assessed_at": RECORDED_AT,
        "classification": "normal",
        "confidence": 0.9,
        "narrative": None,
        "failure_reason": None,
        "failure_detail": None,
        "model_version": MODEL_ANSWERED,
        "model_requested": "model-under-test",
        "budget_steps": granted.steps,
        "budget_tokens": granted.tokens,
        "budget_wall_clock_seconds": granted.wall_clock_seconds,
        "budget_live_queries": granted.live_queries,
        "prompt_tokens": 40,
        "completion_tokens": 20,
        "steps": 0,
        "live_queries": 0,
        "cache_hits": 0,
        "retries": 0,
        "wall_clock_seconds": 0.5,
        "model_cost": None,
        "model_cost_currency": None,
        "model_prices_version": None,
        "endpoint_host": "model.invalid:8443",
    }
    recorded = versions()
    for dimension in ("prompt_version", "schema_version", "rendering_version",
                      "taxonomy_version", "enrichment_snapshot_version",
                      "normalization_snapshot_version", "policy_version",
                      "aggregation_version"):
        row[dimension] = getattr(recorded, dimension)
    row.update(overrides)
    return row


def insert(connection: psycopg.Connection, **overrides: object) -> str:
    row = a_row(**overrides)
    assert sorted(row) == sorted(orchestration.ASSESSMENT_COLUMNS)
    connection.execute(
        f"INSERT INTO {orchestration.ASSESSMENT_TABLE} "
        f"({', '.join(orchestration.ASSESSMENT_COLUMNS)}) "
        f"VALUES ({', '.join(['%s'] * len(orchestration.ASSESSMENT_COLUMNS))})",
        tuple(row[column] for column in orchestration.ASSESSMENT_COLUMNS),
    )
    connection.execute("FLUSH")
    return str(row["assessment_id"])


# --- The column list the writer writes and the reader selects -----------------


def test_the_column_list_is_the_one_the_engine_holds(
    migrated_engine: psycopg.Connection,
):
    """Two copies of a column set, asserted equal by asking the engine.

    `ASSESSMENT_COLUMNS` is what the INSERT names and what the SELECT names, so
    it is one copy in Python — but it is a second copy of the migration, and
    `concept/instruction.md` §2 makes two copies that can drift worse than none.
    """
    # Scoped to this connection's own schema. `information_schema` is engine-wide
    # and only one engine runs per machine (docs/runbook.md §2), so a `public`
    # schema left behind by a dev store or a scratch session holds a second
    # `helena_analytical_assessment` -- and without the filter this test compares
    # `ASSESSMENT_COLUMNS` against both of them concatenated and fails for a
    # reason that has nothing to do with the code under test.
    held = [
        name
        for (name,) in migrated_engine.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_schema = current_schema() AND table_name = %s "
            "ORDER BY ordinal_position",
            (orchestration.ASSESSMENT_TABLE,),
        ).fetchall()
    ]
    assert list(orchestration.ASSESSMENT_COLUMNS) == held


# --- Reading a stored run back ------------------------------------------------


def test_a_stored_verdict_reads_back_as_the_result_it_stored(
    store: orchestration.AssessmentStore, migrated_engine: psycopg.Connection
):
    """Every field of the outcome, off the typed rows rather than a document.

    The citations are compared as a set: `CITATION_TABLE` carries no ordinal, so
    the order the model listed them in is not stored and a replay cannot invent
    one. The contract validates the set, and this test says so out loud rather
    than leaving a later reader to discover it.
    """
    original = a_verdict(
        classification="suspicious",
        citations=(
            Citation(evidence_id=SHOWN, stance=SUPPORTING),
            Citation(evidence_id=OTHER, stance=CONTRADICTING),
        ),
        gaps=(Gap(kind=MISSING, detail="no reverse DNS for the address"),),
    )
    (identifier,) = store.store(
        an_assessment(triage_outcome=original, asked=request()), at=RECORDED_AT
    )

    stored = orchestration.read_assessment(migrated_engine, identifier)

    assert stored.assessment_id == identifier
    assert stored.emitter == TRIAGE and stored.trigger == SCHEDULED_TRIAGE
    assert (stored.context_id, stored.context_version) == ("ctx-1", "ctx-1/3")
    assert stored.schema_version == CONTRACT_VERSION
    assert stored.model_version == MODEL_ANSWERED
    assert stored.versions["model_requested"] == "model-under-test"
    assert dict(stored.budgets) == dict(BUDGET_POLICY.for_emitter(TRIAGE))
    assert stored.outcome.classification == original.classification
    assert stored.outcome.confidence == original.confidence
    assert stored.outcome.cost == original.cost
    assert stored.outcome.versions == original.versions
    assert stored.outcome.gaps == original.gaps
    assert set(stored.outcome.citations) == set(original.citations)


def test_a_stored_typed_failure_reads_back_as_a_failure_and_never_as_a_verdict(
    store: orchestration.AssessmentStore, migrated_engine: psycopg.Connection
):
    """`concept/02`: a typed failure is a row carrying the failure and no verdict."""
    original = a_failure(
        versions=versions(), gaps=(Gap(kind=MISSING, detail="nothing answered"),)
    )
    (identifier,) = store.store(
        an_assessment(triage_outcome=original, asked=request()), at=RECORDED_AT
    )

    stored = orchestration.read_assessment(migrated_engine, identifier)

    assert stored.outcome.reason == MODEL_UNAVAILABLE
    assert stored.outcome.detail == original.detail
    assert stored.outcome.gaps == original.gaps
    assert stored.outcome.model_version is None
    assert not hasattr(stored.outcome, "classification")
    assert stored.model_version is None


def test_the_retrieval_trace_survives_the_round_trip_with_its_typed_failure(
    store: orchestration.AssessmentStore, migrated_engine: psycopg.Connection
):
    """A cache hit and a failed query are two rows, and they stay two things.

    `concept/07`: two runs that differ only in cache state must be
    distinguishable afterwards — so the outcome, the underlying record's
    retrieval time and the typed failure all have to come back off the row.
    """
    retrieved_at = WINDOW_END + timedelta(minutes=1)
    trace = (
        RetrievalStep(
            source_id=enrichment.THREATFOX_SOURCE,
            entity_type="address",
            entity_value=ADDRESS,
            outcome=CACHE_HIT,
            retrieved_at=retrieved_at,
            evidence_id=SHOWN,
        ),
        RetrievalStep(
            source_id=enrichment.THREATFOX_SOURCE,
            entity_type="domain",
            entity_value="c2.example.invalid",
            outcome=CACHE_HIT,
            retrieved_at=retrieved_at,
            failure=QueryFailure(
                source_id=enrichment.THREATFOX_SOURCE,
                entity_type="domain",
                entity_value="c2.example.invalid",
                reason=enrichment.QUERY_FAILURE_REASONS[0],
                detail="the provider did not answer in time",
            ),
        ),
    )
    analysis = a_verdict(
        ANALYST,
        classification="malicious.c2",
        retrieval_trace=trace,
        cost=a_cost(steps=2, cache_hits=1),
        evidence_package=EvidencePackage(
            patterns=("regular contact",), narrative="it went both ways"
        ),
    )
    written = store.store(
        an_assessment(
            triage_outcome=a_verdict(),
            analysis=analysis,
            asked=request(),
            escalated=escalated_request(),
        ),
        at=RECORDED_AT,
    )

    stored = orchestration.read_assessment(migrated_engine, written[1])

    assert stored.outcome.retrieval_trace == trace
    assert stored.outcome.evidence_package.patterns == ("regular contact",)
    assert stored.outcome.evidence_package.narrative == "it went both ways"


def test_an_identifier_nothing_stored_is_a_refusal_that_says_where_it_looked(
    migrated_engine: psycopg.Connection,
):
    with pytest.raises(orchestration.ReplayError, match="holds no assessment"):
        orchestration.read_assessment(migrated_engine, "0" * 64)


def test_a_row_carrying_both_terminal_outcomes_is_refused_rather_than_picked_from(
    migrated_engine: psycopg.Connection,
):
    """The writer cannot produce one; a reader that met one would have to choose.

    `concept/02` makes a verdict and a typed failure the two terminal outcomes,
    and `concept/instruction.md` §2 forbids collapsing them. A reader that
    preferred the verdict would turn a corrupt row into a confident one.
    """
    identifier = insert(
        migrated_engine, failure_reason=MODEL_UNAVAILABLE, failure_detail="no answer"
    )
    with pytest.raises(orchestration.ReplayError, match="a verdict and a failure"):
        orchestration.read_assessment(migrated_engine, identifier)


# --- The version the row recorded, and not the current one --------------------


def _v0_module() -> ModuleType:
    """A frozen contract version that is not this tree's current one.

    `helena.contracts` holds exactly one version, so the property "replay
    validates against the version the row recorded" cannot be demonstrated by
    reading `v1` — that is also what current code is. This builds the version a
    later `v2` would make historical: a module the loader finds by name, holding
    its own classes and its own `check_exchange`.

    It is deliberately *not* a file in `helena/contracts/`: adding one would make
    every other test's "there is one contract version" true of two, and
    `tests/test_package_layout.py` would then be asserting a version nothing ever
    stored. It is installed in `sys.modules` for one test and removed after it,
    which is exactly the surface `contracts.version` addresses.
    """
    module = ModuleType("helena.contracts.v0")

    class _Model(BaseModel):
        model_config = ConfigDict(
            strict=True, extra="forbid", frozen=True, protected_namespaces=()
        )

    class Versions(_Model):
        prompt_version: str
        schema_version: str
        rendering_version: str
        taxonomy_version: str
        enrichment_snapshot_version: str
        normalization_snapshot_version: str
        policy_version: str
        aggregation_version: str
        model_requested: str

    class ResultVersions(Versions):
        model_requested: str | None = None
        model_version: str

    class Cost(_Model):
        prompt_tokens: int
        completion_tokens: int
        steps: int
        live_queries: int
        cache_hits: int
        retries: int
        wall_clock_seconds: float

    class Citation(_Model):
        evidence_id: str
        stance: str

    class Gap(_Model):
        kind: str
        detail: str

    class Request(_Model):
        tenant: str
        sensor: str
        emitter: str
        host: str
        window_start: datetime
        window_end: datetime
        context_id: str
        context_version: str
        trigger: str
        rendering: dict
        budgets: dict
        versions: Versions

    class Result(_Model):
        """v0's verdict: no proposed claims, and a narrative that was 200 characters.

        Two differences from `v1`, and they are the point. The payload the reader
        assembles from the columns carries no proposals, so it fits both shapes —
        and the shape it is given is the one the row named, which this test then
        asserts by class.
        """

        emitter: str
        classification: str
        confidence: float
        citations: tuple[Citation, ...] = ()
        evidence_package: dict | None = None
        retrieval_trace: tuple[dict, ...] = ()
        gaps: tuple[Gap, ...] = ()
        cost: Cost
        versions: ResultVersions

    class Failure(_Model):
        emitter: str
        reason: str
        detail: str
        gaps: tuple[Gap, ...] = ()
        cost: Cost
        versions: Versions
        model_version: str | None = None

    paired: list[tuple[Any, Any]] = []

    def check_exchange(asked: Any, outcome: Any) -> None:
        """v0's pairing rules. Records the pair, so a test can see whose ran."""
        paired.append((asked, outcome))

    module.CONTRACT = contracts.ContractVersion(
        version="v0", request=Request, result=Result, failure=Failure
    )
    module.check_exchange = check_exchange
    module.paired = paired
    return module


@pytest.fixture
def v0() -> Any:
    """`helena.contracts.v0`, for one test, removed afterwards."""
    module = _v0_module()
    sys.modules[module.__name__] = module
    try:
        yield module
    finally:
        del sys.modules[module.__name__]


def test_a_schema_version_that_is_no_longer_current_still_replays(
    v0: ModuleType, migrated_engine: psycopg.Connection
):
    """The invariant this whole increment exists for, with a control beside it.

    `concept/instruction.md` §2: *"replay validates against the version the
    assessment recorded, never against current code."* The row records `v0`, so
    the outcome that comes back is an instance of `v0`'s class — and the control
    is that the current contract **refuses** the same row, because `v1` will not
    validate an outcome recording another version's `schema_version`. Without
    that half, a reader that had quietly used `v1` would pass this test.
    """
    identifier = insert(migrated_engine, schema_version="v0")

    stored = orchestration.read_assessment(migrated_engine, identifier)

    assert stored.schema_version == "v0"
    assert isinstance(stored.outcome, v0.CONTRACT.result)
    assert not isinstance(stored.outcome, AgentResult)
    assert stored.outcome.classification == "normal"
    assert stored.outcome.versions.model_version == MODEL_ANSWERED
    # The control: current code cannot hold this row at all.
    with pytest.raises(ValidationError):
        AgentResult(
            emitter=TRIAGE,
            classification="normal",
            confidence=0.9,
            cost=a_cost(),
            versions=versions(schema_version="v0").completed_by(MODEL_ANSWERED),
        )


def test_the_pairing_rules_a_reconstruction_is_checked_under_are_the_recorded_ones(
    v0: ModuleType, migrated_engine: psycopg.Connection
):
    """`contracts.rules(recorded)`, not `contracts.v1.check_exchange`.

    The rules that hold between a request and its outcome belong to the version
    as much as the classes do. `v0`'s records the pair it was given, so this can
    assert whose ran rather than inferring it from an absence of errors.
    """
    identifier = insert(migrated_engine, schema_version="v0")
    stored = orchestration.read_assessment(migrated_engine, identifier)

    rebuilt = orchestration.reconstruct(
        stored, projection=a_projection(), attributes=ATTRIBUTES, budget=BUDGET
    )

    assert isinstance(rebuilt, v0.CONTRACT.request)
    assert [(asked, outcome) for asked, outcome in v0.paired] == [
        (rebuilt, stored.outcome)
    ]


def test_a_schema_version_this_tree_does_not_hold_is_refused_not_migrated(
    migrated_engine: psycopg.Connection,
):
    """A row nothing here can validate is a replay that cannot run.

    Distinct from a row that is wrong, and `docs/decisions/0008-version-registry.md`
    is why it may not fall back: validating it against `v1` would be the forward
    migration the registry exists to prevent, run silently.
    """
    identifier = insert(migrated_engine, schema_version="v7")
    with pytest.raises(UnknownVersion, match="no contract version 'v7'"):
        orchestration.read_assessment(migrated_engine, identifier)


def test_a_stored_package_the_current_contract_requires_and_cannot_hold_is_refused(
    store: orchestration.AssessmentStore, migrated_engine: psycopg.Connection
):
    """The one fidelity gap in the stored schema, made loud rather than papered over.

    An evidence package is written as its parts — patterns as rows, narrative as
    a column — so a package with neither leaves no trace, and an analyst verdict
    that is not `normal` requires one. Such a row refuses to assemble rather than
    being handed an empty package it may never have had.
    """
    analysis = a_verdict(
        ANALYST, classification="malicious.c2", evidence_package=EvidencePackage()
    )
    written = store.store(
        an_assessment(
            triage_outcome=a_verdict(),
            analysis=analysis,
            asked=request(),
            escalated=escalated_request(),
        ),
        at=RECORDED_AT,
    )

    with pytest.raises(orchestration.ReplayError, match="do not validate against"):
        orchestration.read_assessment(migrated_engine, written[1])


# --- Reconstructing the request -----------------------------------------------


def test_the_request_is_rebuilt_from_the_recorded_context_and_rendering_versions(
    store: orchestration.AssessmentStore, migrated_engine: psycopg.Connection
):
    """Field for field the request that ran, with the rendering rebuilt.

    The rendering is not stored — `concept/04` puts the context reference *and its
    version* on the request precisely so it does not have to be — so this is the
    test that the two paths meet: what the writer stored plus what the renderer
    produces is the request the run was made from.
    """
    asked = request()
    (identifier,) = store.store(
        an_assessment(triage_outcome=a_verdict(), asked=asked), at=RECORDED_AT
    )
    stored = orchestration.read_assessment(migrated_engine, identifier)

    rebuilt = orchestration.reconstruct(
        stored, projection=a_projection(), attributes=ATTRIBUTES, budget=BUDGET
    )

    assert rebuilt == asked


def test_a_projection_at_another_context_version_is_refused(
    store: orchestration.AssessmentStore, migrated_engine: psycopg.Connection
):
    """A revision mints a new version, and replaying against it scores another snapshot."""
    (identifier,) = store.store(
        an_assessment(triage_outcome=a_verdict(), asked=request()), at=RECORDED_AT
    )
    stored = orchestration.read_assessment(migrated_engine, identifier)
    revised = a_projection().model_copy(update={"context_version": "ctx-1/4"})

    with pytest.raises(orchestration.ReplayError, match="context_version"):
        orchestration.reconstruct(
            stored, projection=revised, attributes=ATTRIBUTES, budget=BUDGET
        )


def test_a_citation_the_rebuilt_rendering_no_longer_shows_stops_the_replay(
    store: orchestration.AssessmentStore, migrated_engine: psycopg.Connection
):
    """The pairing check earns its place here rather than being a formality.

    If the evidence the assessment cited is not in the rebuilt rendering, the
    inputs have moved and the reconstruction is of a different run — which is
    exactly what `check_exchange`'s third rule is about, applied to a request
    nobody kept.
    """
    (identifier,) = store.store(
        an_assessment(
            triage_outcome=a_verdict(
                classification="suspicious",
                citations=(Citation(evidence_id=SHOWN, stance=SUPPORTING),),
            ),
            asked=request(),
        ),
        at=RECORDED_AT,
    )
    stored = orchestration.read_assessment(migrated_engine, identifier)
    moved = a_projection()
    moved = moved.model_copy(
        update={
            "entities": (
                moved.entities[0].model_copy(
                    update={
                        "enrichment": (
                            moved.entities[0].enrichment[0].model_copy(
                                update={"evidence_id": "c" * 64}
                            ),
                        )
                    }
                ),
            )
        }
    )

    with pytest.raises(orchestration.ReplayError, match="do not pair"):
        orchestration.reconstruct(
            stored, projection=moved, attributes=ATTRIBUTES, budget=BUDGET
        )


# --- Re-asking: the recorded prompt, and no provider ---------------------------


def test_a_replayed_analyst_run_queries_no_provider_and_reveals_no_key(
    store: orchestration.AssessmentStore, migrated_engine: psycopg.Connection
):
    """The step `prd.json` asks for by name, measured at the adapter.

    The model **is** called — a replay re-asks the question — and the tool loop
    runs: the endpoint asks for a lookup, the replaying tool resolves it from the
    store, finds nothing recorded for that indicator and refuses with
    `no_stored_response`. Nothing reaches the adapter, so nothing reaches a
    provider and the credential is never handed over.
    """
    analysis = a_verdict(
        ANALYST,
        classification="malicious.c2",
        cost=a_cost(steps=1),
        evidence_package=EvidencePackage(narrative="the traffic went both ways"),
    )
    written = store.store(
        an_assessment(
            triage_outcome=a_verdict(),
            analysis=analysis,
            asked=request(),
            escalated=escalated_request(),
        ),
        at=RECORDED_AT,
    )
    stored = orchestration.read_assessment(migrated_engine, written[1])
    projection = a_projection()
    rebuilt = orchestration.reconstruct(
        stored, projection=projection, attributes=ATTRIBUTES, budget=BUDGET
    )
    reached: list = []
    answer = said(
        classification="malicious.c2",
        confidence=0.8,
        citations=[{"evidence_id": SHOWN, "stance": SUPPORTING}],
        evidence_package={"patterns": ["beaconing"], "narrative": "it went both ways"},
    )
    stream = io.StringIO()

    with _Endpoint(
        [
            called(TOOL_NAME, {"entity_type": "address", "entity_value": ADDRESS}),
            answered(""),
            answered(answer),
        ]
    ) as endpoint:
        replayed = orchestration.rerun(
            stored,
            rebuilt,
            client=endpoint.client(ANALYST, stream),
            retry=THREE_ATTEMPTS,
            send_policy=SEND_POLICY,
            projection=projection,
            provider_tools=[replay_tool(reached, migrated_engine)],
            inherit=analyst.Inheritance(inherit_triage_rationale=False),
        )

    assert reached == []
    assert replayed.outcome.cost.live_queries == 0
    assert [step.outcome for step in replayed.outcome.retrieval_trace] == []
    # The refusal is the tool's rather than the loop's, which is the difference
    # between "a replay had nothing stored" and "the loop would not ask".
    assert [
        retrieval.lookup.refusal.reason for retrieval in replayed.analysis.retrievals
    ] == [tools.NO_STORED_RESPONSE]
    assert {row.channel for row in replayed.disclosures.rows} == {
        disclosure.MODEL_INFERENCE
    }
    assert not [
        row
        for row in replayed.disclosures.rows
        if row.channel == disclosure.PROVIDER_LOOKUP
    ]


def test_a_provider_tool_that_is_not_a_replay_is_refused_before_the_model_is_called(
    store: orchestration.AssessmentStore, migrated_engine: psycopg.Connection
):
    """`concept/07`: a replay that calls the provider again is not a replay.

    The refusal is at the entry point rather than inside the loop, so the check
    is one decision about one run and no model has been called by the time it
    fires — asserted by scripting an endpoint that would fail the test if it were
    reached.
    """
    analysis = a_verdict(
        ANALYST,
        classification="malicious.c2",
        evidence_package=EvidencePackage(narrative="the traffic went both ways"),
    )
    written = store.store(
        an_assessment(
            triage_outcome=a_verdict(),
            analysis=analysis,
            asked=request(),
            escalated=escalated_request(),
        ),
        at=RECORDED_AT,
    )
    stored = orchestration.read_assessment(migrated_engine, written[1])
    projection = a_projection()
    rebuilt = orchestration.reconstruct(
        stored, projection=projection, attributes=ATTRIBUTES, budget=BUDGET
    )
    configured = settings()
    live = tools.ProviderTool(
        source_id=enrichment.THREATFOX_SOURCE,
        endpoint="search_ioc",
        credential=configured.providers.abusech_auth_key,
        ask=unreachable([]),
        cache=tools.EvidenceCache(migrated_engine),
        retention_seconds=enrichment.THREATFOX_MIN_FETCH_INTERVAL_SECONDS,
        send_policy=SEND_POLICY,
        replay=False,
        logger=observability.logger("tools", configured, stream=io.StringIO()),
        redactor=observability.Redactor.from_settings(configured),
    )

    with _Endpoint([]) as endpoint:
        with pytest.raises(orchestration.ReplayError, match="are not replays"):
            orchestration.rerun(
                stored,
                rebuilt,
                client=endpoint.client(ANALYST, io.StringIO()),
                retry=THREE_ATTEMPTS,
                send_policy=SEND_POLICY,
                projection=projection,
                provider_tools=[live],
                inherit=analyst.Inheritance(inherit_triage_rationale=False),
            )


def test_a_triage_replay_offered_a_tool_is_refused(
    store: orchestration.AssessmentStore, migrated_engine: psycopg.Connection
):
    """`concept/04`: triage has no tools at all, so a replay of one has none either."""
    (identifier,) = store.store(
        an_assessment(triage_outcome=a_verdict(), asked=request()), at=RECORDED_AT
    )
    stored = orchestration.read_assessment(migrated_engine, identifier)
    projection = a_projection()
    rebuilt = orchestration.reconstruct(
        stored, projection=projection, attributes=ATTRIBUTES, budget=BUDGET
    )

    with _Endpoint([]) as endpoint:
        with pytest.raises(orchestration.ReplayError, match="no tools at all"):
            orchestration.rerun(
                stored,
                rebuilt,
                client=endpoint.client(TRIAGE, io.StringIO()),
                retry=THREE_ATTEMPTS,
                send_policy=SEND_POLICY,
                projection=projection,
                provider_tools=[replay_tool([], migrated_engine)],
            )


def test_a_triage_run_replays_under_the_prompt_version_the_row_recorded(
    store: orchestration.AssessmentStore, migrated_engine: psycopg.Connection
):
    """The whole loop for the common case: store, read, rebuild, re-ask, diff."""
    (identifier,) = store.store(
        an_assessment(
            triage_outcome=a_verdict(
                classification="normal", confidence=0.9, citations=()
            ),
            asked=request(),
        ),
        at=RECORDED_AT,
    )
    stored = orchestration.read_assessment(migrated_engine, identifier)
    projection = a_projection()
    rebuilt = orchestration.reconstruct(
        stored, projection=projection, attributes=ATTRIBUTES, budget=BUDGET
    )

    with _Endpoint(
        [
            answered(
                said(
                    classification="suspicious",
                    confidence=0.4,
                    citations=[{"evidence_id": SHOWN, "stance": SUPPORTING}],
                )
            )
        ]
    ) as endpoint:
        replayed = orchestration.rerun(
            stored,
            rebuilt,
            client=endpoint.client(TRIAGE, io.StringIO()),
            retry=THREE_ATTEMPTS,
            send_policy=SEND_POLICY,
            projection=projection,
        )

    assert replayed.analysis is None
    assert replayed.outcome.versions.prompt_version == TRIAGE_PROMPT.version
    assert orchestration.compare(stored.outcome, replayed.outcome) == (
        orchestration.Difference(
            dimension="verdict", original="normal", replayed="suspicious"
        ),
        orchestration.Difference(
            dimension="path", original="normal", replayed="suspicious"
        ),
        orchestration.Difference(dimension="confidence", original=0.9, replayed=0.4),
        orchestration.Difference(
            dimension="citations",
            original=(),
            replayed=((SHOWN, SUPPORTING),),
        ),
    )


# --- The diff -----------------------------------------------------------------


def test_two_identical_outcomes_differ_nowhere():
    assert orchestration.compare(a_verdict(), a_verdict()) == ()


def test_the_diff_names_the_citations_that_moved():
    """Citations as a set of `(evidence id, stance)`, which is what is stored."""
    original = a_verdict(
        classification="suspicious",
        citations=(Citation(evidence_id=SHOWN, stance=SUPPORTING),),
    )
    replayed = a_verdict(
        classification="suspicious",
        citations=(Citation(evidence_id=SHOWN, stance=CONTRADICTING),),
    )

    (difference,) = orchestration.compare(original, replayed)

    assert difference.dimension == "citations"
    assert difference.original == ((SHOWN, SUPPORTING),)
    assert difference.replayed == ((SHOWN, CONTRADICTING),)


def test_a_replay_that_failed_where_the_original_answered_is_not_a_changed_verdict():
    """`concept/instruction.md` §2: a typed failure is never collapsed into a verdict.

    The diff says the kind of outcome moved and leaves the verdict dimensions
    reading `None`, which is the one reading that cannot be mistaken for "it
    answered something else".
    """
    differences = {
        difference.dimension: difference
        for difference in orchestration.compare(
            a_verdict(classification="suspicious"), a_failure(versions=versions())
        )
    }

    assert differences["outcome_kind"].original == orchestration.VERDICT
    assert differences["outcome_kind"].replayed == orchestration.TYPED_FAILURE
    assert differences["failure_reason"].replayed == MODEL_UNAVAILABLE
    assert differences["verdict"].replayed is None
    assert differences["path"].replayed is None
    assert differences["confidence"].replayed is None


def test_the_dimensions_are_reported_in_one_declared_order():
    """A diff a person reads twice should read the same way twice."""
    differences = orchestration.compare(
        a_verdict(classification="suspicious", confidence=0.7),
        a_failure(versions=versions()),
    )
    order = [difference.dimension for difference in differences]
    assert order == [
        dimension
        for dimension in orchestration.REPLAY_DIMENSIONS
        if dimension in set(order)
    ]


# --- Over real data: the snapshot that was current at event time ---------------


@pytest.fixture
def a_real_context(live: psycopg.Connection) -> dict[str, Any]:
    """One real context out of the store, enriched against a snapshot that predates it.

    The capture is the committed layer-coverage one, re-stamped into the window
    `now` falls in by `tests/test_rendering.py`'s `live` fixture — which is what
    puts it inside the retention boundary, and therefore inside the live view a
    projection reads. The feed extract is the committed ThreatFox one with a
    single entry repointed at an entity the capture actually has, which is
    `tests/test_enriched.py`'s device, reused rather than reinvented.
    """
    value = an_entity(live, "domain")
    projection = project(live)
    window = projection.statistics.window_start
    before = load(live, targeted(RAW, value), now=window - timedelta(minutes=1))
    return {
        "connection": live,
        "identity": Settings.load(environ={**ENVIRONMENT}, env_file=None).identity,
        "value": value,
        "window": window,
        "snapshot": before.snapshot_version,
        # Re-read after the load: the claim is what the projection now carries.
        "projection": project(live),
    }


def _real_request(real: dict[str, Any]) -> Any:
    """A triage request over the real projection, citing what the rendering shows."""
    from test_assessments import request as stored_request

    projection = real["projection"]
    rendered = rendering.version(RENDERING_VERSION).render(
        projection,
        hosts.load().attributes_for(projection.host),
        BUDGET,
    )
    return stored_request(
        host=projection.host,
        context_id=projection.context_id,
        context_version=projection.context_version,
        window_start=projection.statistics.window_start,
        window_end=projection.statistics.window_end,
        rendering=rendered,
        versions=versions(enrichment_snapshot_version=real["snapshot"]),
    )


def test_a_replay_renders_the_feed_snapshot_that_was_current_at_event_time(
    a_real_context: dict[str, Any], store: orchestration.AssessmentStore
):
    """`concept/02`: replay joins the snapshot current at event time, not today's.

    `tests/test_enriched.py` asserts this of the view. What is asserted here is
    that it survives the whole replay path: a snapshot loaded after the
    assessment was made does not reach the rebuilt rendering, so the citation the
    assessment made still resolves and the reconstruction still pairs. Without
    it, every stored assessment would stop reconstructing the moment a feed
    refreshed.
    """
    connection = a_real_context["connection"]
    asked = _real_request(a_real_context)
    cited = sorted(asked.rendering.evidence_ids)
    assert cited, "the real rendering showed no evidence to cite"
    outcome = a_verdict(
        classification="suspicious",
        citations=(Citation(evidence_id=cited[0], stance=SUPPORTING),),
        versions=versions(
            enrichment_snapshot_version=a_real_context["snapshot"]
        ).completed_by(MODEL_ANSWERED),
    )
    (identifier,) = store.store(
        an_assessment(triage_outcome=outcome, asked=asked), at=RECORDED_AT
    )

    # A newer snapshot, loaded long after the window the assessment scored.
    after = load(
        connection,
        targeted(RAW, a_real_context["value"], ioc_type="url"),
        now=a_real_context["window"] + timedelta(days=30),
    )
    assert after.snapshot_version != a_real_context["snapshot"]

    stored = orchestration.read_assessment(connection, identifier)
    projection = RenderingStore(
        connection=connection, identity=a_real_context["identity"]
    ).project(stored.context_id)
    rebuilt = orchestration.reconstruct(
        stored,
        projection=projection,
        attributes=hosts.load().attributes_for(stored.host),
        budget=BUDGET,
    )

    bodies = "\n".join(section.body for section in rebuilt.rendering.sections)
    assert a_real_context["snapshot"] in bodies
    assert after.snapshot_version not in bodies
    assert sorted(rebuilt.rendering.evidence_ids) == cited


# --- The command --------------------------------------------------------------
#
# `scripts/replay_assessment.py` is a wrapper, and what a wrapper gets wrong is
# argument handling, exit status and how it prints what it found. Those are what
# is tested here: the argv half in a subprocess, run the way an operator runs it,
# and the printing half in process.
#
# **What is deliberately not here is the wrapper against a stored assessment**,
# and the reason is measured rather than assumed. The suite's schema is a
# `search_path` of its own (`tests/conftest.py`) because `single_node` binds
# fixed ports and a second engine cannot run beside the first; RisingWave
# **ignores the libpq `options=-csearch_path=...` startup parameter** — measured,
# a connection made with it reports `current_schema()` as `public` — so a
# subprocess cannot be pointed at the schema the test wrote into, and a
# `--schema` flag would be a configuration key that exists for a test. The
# command was run by hand against a real engine instead; prds/reports/task-45.json
# records what it printed. Everything underneath it is exercised above.

sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

import replay_assessment  # noqa: E402 — needs the path above


def replay_command(*arguments: str, **environment: str) -> subprocess.CompletedProcess:
    """`scripts/replay_assessment.py` in a subprocess, with an explicit environment.

    The process environment wins over `.env` (`helena.config.Settings.load`), so
    the values here are what the command resolves — a run that fell through to
    the developer's own `.env` would read that deployment's store.
    """
    return subprocess.run(
        ["uv", "run", "scripts/replay_assessment.py", *arguments],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        timeout=300,
        env={**os.environ, **ENVIRONMENT, **environment},
    )


def test_the_command_needs_an_assessment_to_replay():
    """Argument handling, in the process an operator would start.

    The one subprocess assertion left, and it is the one that needs no store:
    an empty `RISINGWAVE_DSN` does not exercise the startup failure here, because
    `helena.config.Settings.load` then falls back to the `.env` file the way it
    is meant to — that path is `tests/test_config.py`'s.
    """
    result = replay_command()
    assert result.returncode == 2
    assert "<id>" in result.stderr


def test_the_command_prints_a_typed_failure_as_one_and_not_as_an_empty_verdict():
    """The two terminal outcomes print as two things, here as everywhere else."""
    assert replay_assessment._outcome_line(a_failure(versions=versions())).startswith(
        "typed failure: model_unavailable"
    )
    assert "confidence" in replay_assessment._outcome_line(a_verdict())


def test_the_command_prints_the_dimensions_that_moved(capsys):
    """The diff a person reads, over the two outcomes the module compared."""
    stored = orchestration.StoredAssessment(
        assessment_id="a" * 64,
        tenant=TENANT,
        sensor=SENSOR,
        host=HOST,
        context_id="ctx-1",
        context_version="ctx-1/3",
        window_start=WINDOW_START,
        window_end=WINDOW_END,
        emitter=TRIAGE,
        trigger=SCHEDULED_TRIAGE,
        assessed_at=RECORDED_AT,
        contract_version=contracts.version(CONTRACT_VERSION),
        versions={"prompt_version": TRIAGE_PROMPT.version},
        budgets=dict(BUDGET_POLICY.for_emitter(TRIAGE)),
        model_version=MODEL_ANSWERED,
        outcome=a_verdict(classification="suspicious", confidence=0.7),
    )
    asked = request()
    replayed = orchestration.ReplayedRun(
        request=asked,
        outcome=a_verdict(classification="suspicious", confidence=0.2),
        analysis=None,
        disclosures=ledger(asked),
    )
    a_model_call(replayed.disclosures)

    replay_assessment._report(replayed, stored)

    printed = capsys.readouterr().out
    assert "0 live quer" in printed
    assert "0 of them to a provider" in printed
    assert "confidence" in printed and "0.7 -> 0.2" in printed
