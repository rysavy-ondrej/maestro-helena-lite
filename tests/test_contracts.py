"""The agent contract: what may cross the boundary, and what may not.

`concept/04-the-two-agents.md` gives one versioned request/result pair for both
agents, three fields that were deliberately not adopted, and a citation rule with
exactly two exemptions. `concept/07-principles.md` adds the agent boundary, the
budget dimensions, the retrieval trace and the typed failure.

Every test below is one of those sentences, made to fail if the shape stops
holding it. Nothing here needs an engine: the contract is Pydantic classes and a
pairing rule, and `docs/decisions/0017-the-agent-contract.md` records why the
storage of an assessment -- which does need one -- is a later increment.
"""

from __future__ import annotations

import ast
import inspect
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from pydantic import BaseModel, ValidationError

from helena import contracts, taxonomy
from helena.contracts import ContractError, ContractVersion, UnknownVersion
from helena.contracts.v1 import (
    BUDGET_EXHAUSTED,
    CACHE_HIT,
    CONTRACT,
    CONTRACT_VERSION,
    CONTRADICTING,
    DETERMINISTIC_SIGNAL,
    FAILURE_REASONS,
    GAP_KINDS,
    LIVE_QUERY,
    MAX_DETAIL,
    MODEL_UNAVAILABLE,
    REQUEST_VERSION_DIMENSIONS,
    SCHEDULED_TRIAGE,
    SCHEMA_INVALID,
    SECTIONS,
    STANCES,
    SUPPORTING,
    TIMED_OUT,
    TRIAGE_SUSPICIOUS,
    TRIGGERS,
    TRUNCATED,
    AgentFailure,
    AgentRequest,
    AgentResult,
    Budgets,
    Citation,
    Cost,
    EvidencePackage,
    Gap,
    ProposedClaim,
    RenderedSection,
    Rendering,
    RequestVersions,
    RetrievalStep,
    Truncation,
    check_exchange,
)
from helena.enrichment import QueryFailure
from helena.taxonomy import ANALYST, TRIAGE, TaxonomyError
from helena.versions import VERSION_COLUMNS, VersionSet

WINDOW_START = datetime(2024, 6, 1, 12, 0, tzinfo=timezone.utc)
WINDOW_END = WINDOW_START + timedelta(minutes=5)

# Two evidence ids the rendering shows, and one it does not. Real digests are 64
# hex characters (`helena.enrichment.evidence_id`); these stand in for two rows
# and nothing here depends on their shape.
SHOWN = "e" * 64
ALSO_SHOWN = "f" * 64
NEVER_SHOWN = "0" * 64


def versions(**overrides: str) -> RequestVersions:
    """A request's versions. Every dimension, because none of them defaults."""
    return RequestVersions(
        **{
            "prompt_version": "p1",
            "schema_version": CONTRACT_VERSION,
            "rendering_version": "r1",
            "taxonomy_version": "v1",
            "enrichment_snapshot_version": "2024-06-01T00:00:00Z",
            "normalization_snapshot_version": "psl-2024-06-01",
            "policy_version": "pol1",
            "aggregation_version": "v1",
            "model_requested": "vendor/Small-Model",
            **overrides,
        }
    )


def rendering(
    *,
    version: str = "r1",
    evidence_ids: tuple[str, ...] = (SHOWN, ALSO_SHOWN),
    truncated_section: str | None = None,
) -> Rendering:
    """The five parts, with the evidence ids hung off the addresses section."""
    sections = []
    for name in SECTIONS:
        sections.append(
            RenderedSection(
                section=name,
                body=f"<{name}>",
                evidence_ids=evidence_ids if name == "addresses_contacted" else (),
                truncation=(
                    Truncation(section=name, kept=3, total=40)
                    if name == truncated_section
                    else None
                ),
            )
        )
    return Rendering(version=version, sections=tuple(sections))


def cost(**overrides: object) -> Cost:
    return Cost(
        **{
            "prompt_tokens": 1200,
            "completion_tokens": 80,
            "steps": 0,
            "live_queries": 0,
            "cache_hits": 0,
            "retries": 0,
            "wall_clock_seconds": 1.5,
            **overrides,
        }
    )


def request(*, emitter: str = TRIAGE, **overrides: object) -> AgentRequest:
    triage = emitter == TRIAGE
    return AgentRequest(
        **{
            "tenant": "acme",
            "sensor": "sensor-1",
            "emitter": emitter,
            "host": "10.127.0.100",
            "window_start": WINDOW_START,
            "window_end": WINDOW_END,
            "context_id": "ctx-1",
            "context_version": "ctx-1/3",
            "trigger": SCHEDULED_TRIAGE if triage else TRIAGE_SUSPICIOUS,
            "rendering": rendering(),
            "budgets": Budgets(
                steps=0 if triage else 6,
                tokens=8000,
                wall_clock_seconds=20.0,
                live_queries=0 if triage else 6,
            ),
            "versions": versions(),
            **overrides,
        }
    )


def result(*, emitter: str = TRIAGE, **overrides: object) -> AgentResult:
    return AgentResult(
        **{
            "emitter": emitter,
            "classification": "normal",
            "confidence": 0.9,
            "cost": cost(),
            "versions": versions().completed_by("vendor/Small-Model-2026-05"),
            **overrides,
        }
    )


def failure(**overrides: object) -> AgentFailure:
    return AgentFailure(
        **{
            "emitter": TRIAGE,
            "reason": SCHEMA_INVALID,
            "detail": "three attempts, none matching the result schema",
            "cost": cost(retries=3),
            "versions": versions(),
            "model_version": "vendor/Small-Model-2026-05",
            **overrides,
        }
    )


# --- The versioned package ---------------------------------------------------


def test_the_loader_returns_the_three_classes_of_a_version():
    """`concept/07` makes a typed failure and a verdict the two terminal outcomes."""
    contract = contracts.version("v1")
    assert isinstance(contract, ContractVersion)
    assert contract.version == "v1"
    assert (contract.request, contract.result, contract.failure) == (
        AgentRequest,
        AgentResult,
        AgentFailure,
    )
    assert contract is CONTRACT


def test_a_version_this_tree_does_not_hold_is_not_a_fallback_to_the_current_one():
    """A recorded `schema_version` whose module is absent is a replay that cannot run."""
    with pytest.raises(UnknownVersion, match="no contract version 'v7'"):
        contracts.version("v7")
    with pytest.raises(UnknownVersion, match="not a version identifier"):
        contracts.version("../v1")


def test_the_request_versions_are_the_registry_minus_the_model():
    """The two copies of the dimension list, asserted equal.

    `helena.versions.VERSION_COLUMNS` is the nine dimensions a citable row
    records. A request knows eight of them; the ninth is what the response
    reported. A tenth dimension added to the registry has to be a failing test
    here, not a version this contract quietly stops carrying.
    """
    assert set(REQUEST_VERSION_DIMENSIONS) | {"model_version"} == set(VERSION_COLUMNS)
    assert "model_version" not in REQUEST_VERSION_DIMENSIONS
    assert set(REQUEST_VERSION_DIMENSIONS) | {"model_requested"} == set(
        RequestVersions.model_fields
    )


def test_completed_by_takes_the_reported_identity_and_never_the_configured_one():
    """ADR-0008: the configured name is the thing that stays stable while what answers changes."""
    complete = versions().completed_by("vendor/Small-Model-2026-05")
    assert isinstance(complete, VersionSet)
    assert complete.model_version == "vendor/Small-Model-2026-05"
    assert complete.prompt_version == "p1"
    # There is no argument-free variant: a caller with nothing to pass would
    # otherwise record a plausible value rather than failing.
    with pytest.raises(TypeError):
        versions().completed_by()  # type: ignore[call-arg]


@pytest.mark.parametrize("model", [AgentRequest, AgentResult, AgentFailure])
def test_a_contract_object_records_this_module_s_own_version(model: type[BaseModel]):
    """Replay validates against the module the version names, so the two agree here."""
    drifted = versions(schema_version="v2")
    builders = {
        AgentRequest: lambda: request(versions=drifted),
        AgentResult: lambda: result(versions=drifted.completed_by("m")),
        AgentFailure: lambda: failure(versions=drifted),
    }
    with pytest.raises(ValidationError, match="schema_version"):
        builders[model]()


# --- The three fields that were deliberately not adopted ---------------------

# `concept/04`: a per-invocation free-text task, loose observations or relevant
# context, and recommended actions. Spelled every way a later author might reach
# for one.
FORBIDDEN_FIELDS = frozenset(
    {
        "task",
        "instruction",
        "instructions",
        "observations",
        "observation",
        "relevant_context",
        "context",
        "additional_context",
        "notes",
        "recommended_actions",
        "recommendations",
        "actions",
        "remediation",
        "response",
        "headers",
    }
)

CONTRACT_MODELS = (
    AgentRequest,
    AgentResult,
    AgentFailure,
    Budgets,
    Citation,
    Cost,
    EvidencePackage,
    Gap,
    ProposedClaim,
    RenderedSection,
    Rendering,
    RequestVersions,
    RetrievalStep,
    Truncation,
)


def test_every_model_in_the_version_module_is_covered_by_these_tests():
    """A model added to `v1` cannot escape the field tests below by being new."""
    from helena.contracts import v1

    defined = {
        value
        for value in vars(v1).values()
        if inspect.isclass(value)
        and issubclass(value, BaseModel)
        and value.__module__ == v1.__name__
    }
    assert defined == set(CONTRACT_MODELS)


@pytest.mark.parametrize("model", CONTRACT_MODELS, ids=lambda m: m.__name__)
def test_no_free_text_task_observation_or_recommended_action_field_exists(
    model: type[BaseModel],
):
    """`concept/04`, and `concept/instruction.md` §2's "typed boundaries"."""
    offending = sorted(set(model.model_fields) & FORBIDDEN_FIELDS)
    assert offending == [], (
        f"{model.__name__} declares {offending}. A free-text task is a varying "
        f"instruction channel into the model; loose observations carry the "
        f"rendering's content without its guarantees; recommended actions have no "
        f"consumer and invite the remediation channel the concept excludes."
    )


@pytest.mark.parametrize("model", CONTRACT_MODELS, ids=lambda m: m.__name__)
def test_no_caller_can_add_a_field_at_runtime(model: type[BaseModel]):
    """`extra="forbid"` is what makes the absence above a property of the shape."""
    assert model.model_config["extra"] == "forbid"
    assert model.model_config["frozen"] is True
    assert model.model_config["strict"] is True


def test_the_absent_fields_are_absent_from_the_source_as_well():
    """Not a field, and not a comment claiming one is coming.

    The parametrized test above reads `model_fields`, so it would miss a field
    added to a model this file forgot to list. This reads the module.
    """
    source = Path(contracts.v1.__file__).read_text()
    module = ast.parse(source)
    annotated = {
        node.target.id
        for node in ast.walk(module)
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
    }
    assert annotated & FORBIDDEN_FIELDS == set()


# --- The request -------------------------------------------------------------


def test_the_request_carries_the_context_reference_and_its_version():
    """`concept/04`: the version "is what makes replay possible"."""
    built = request()
    assert (built.context_id, built.context_version) == ("ctx-1", "ctx-1/3")
    assert (built.window_start, built.window_end) == (WINDOW_START, WINDOW_END)


@pytest.mark.parametrize(
    "field", ["tenant", "sensor", "host", "context_id", "context_version"]
)
def test_a_blank_identity_field_is_refused(field: str):
    """`concept/instruction.md` §6: a tenant that silently defaults is an isolation failure."""
    with pytest.raises(ValidationError, match="is blank"):
        request(**{field: "   "})


def test_the_window_is_a_window():
    with pytest.raises(ValidationError, match="ends at or before it starts"):
        request(window_end=WINDOW_START)


def test_the_trigger_and_the_emitter_have_to_agree():
    """`concept/04`: two independent inputs reach the analyst, and neither reaches triage."""
    assert set(TRIGGERS) == {SCHEDULED_TRIAGE, TRIAGE_SUSPICIOUS, DETERMINISTIC_SIGNAL}
    with pytest.raises(ValidationError, match="a triage run is triggered by"):
        request(emitter=TRIAGE, trigger=DETERMINISTIC_SIGNAL)
    with pytest.raises(ValidationError, match="the analyst is reached by"):
        request(
            emitter=ANALYST,
            trigger=SCHEDULED_TRIAGE,
            budgets=Budgets(
                steps=6, tokens=8000, wall_clock_seconds=20.0, live_queries=6
            ),
        )
    # Both of the analyst's triggers are accepted.
    for trigger in (TRIAGE_SUSPICIOUS, DETERMINISTIC_SIGNAL):
        assert request(emitter=ANALYST, trigger=trigger).trigger == trigger


def test_triage_may_not_be_given_a_tool_budget_at_all():
    """`concept/04`: tools "none at all", retrieval "none -- no lookups, no waiting"."""
    with pytest.raises(ValidationError, match="triage has no tools at all"):
        request(
            budgets=Budgets(
                steps=1, tokens=8000, wall_clock_seconds=20.0, live_queries=0
            )
        )
    with pytest.raises(ValidationError, match="triage has no tools at all"):
        request(
            budgets=Budgets(
                steps=0, tokens=8000, wall_clock_seconds=20.0, live_queries=1
            )
        )


def test_a_run_with_no_tokens_or_no_clock_can_only_fail():
    for bad in ({"tokens": 0}, {"wall_clock_seconds": 0.0}):
        with pytest.raises(ValidationError):
            Budgets(
                **{
                    "steps": 0,
                    "tokens": 8000,
                    "wall_clock_seconds": 20.0,
                    "live_queries": 0,
                    **bad,
                }
            )


def test_the_rendering_version_has_one_meaning_in_a_request():
    """Two copies of a version constant, asserted equal (`concept/instruction.md` §2)."""
    with pytest.raises(ValidationError, match="two copies of a version"):
        request(rendering=rendering(version="r2"))


# --- The rendering -----------------------------------------------------------


def test_the_rendering_is_the_five_parts_exactly_once_each_and_in_order():
    """`concept/04`: "a bounded, versioned projection ... in five parts"."""
    assert SECTIONS == (
        "host",
        "domains_contacted",
        "addresses_contacted",
        "tls_parameters",
        "connection_statistics",
    )
    full = rendering()
    assert tuple(section.section for section in full.sections) == SECTIONS

    def with_sections(names):
        return Rendering(
            version="r1",
            sections=tuple(
                RenderedSection(section=name, body="") for name in names
            ),
        )

    with pytest.raises(ValidationError, match="the five parts are"):
        with_sections([name for name in SECTIONS if name != "tls_parameters"])
    with pytest.raises(ValidationError, match="the five parts are"):
        with_sections(list(reversed(SECTIONS)))
    with pytest.raises(ValidationError, match="the five parts are"):
        with_sections([*SECTIONS, "host"])


def test_a_truncation_record_that_dropped_nothing_is_refused():
    """A no-op record is indistinguishable from a real one to a reader."""
    with pytest.raises(ValidationError, match="dropped nothing"):
        Truncation(section="domains_contacted", kept=40, total=40)
    with pytest.raises(ValidationError, match="dropped nothing"):
        Truncation(section="domains_contacted", kept=41, total=40)
    dropped = Truncation(section="domains_contacted", kept=3, total=40)
    assert (dropped.kept, dropped.total) == (3, 40)


def test_a_truncation_record_belongs_to_the_section_it_names():
    with pytest.raises(ValidationError, match="unattributable"):
        RenderedSection(
            section="host",
            body="",
            truncation=Truncation(section="domains_contacted", kept=3, total=40),
        )


def test_the_rendering_reports_what_it_showed_and_what_it_dropped():
    """`concept/04`: every enriched value is citable, and truncation is visible."""
    truncated = rendering(truncated_section="domains_contacted")
    assert truncated.evidence_ids == frozenset({SHOWN, ALSO_SHOWN})
    assert [record.section for record in truncated.truncations] == [
        "domains_contacted"
    ]
    assert rendering().truncations == ()


def test_a_section_cannot_show_the_same_evidence_row_twice():
    with pytest.raises(ValidationError, match="lists an evidence id twice"):
        RenderedSection(section="host", body="", evidence_ids=(SHOWN, SHOWN))


# --- The result: the taxonomy, per emitter ----------------------------------


def test_triage_emits_two_roots_and_the_analyst_four():
    """`concept/04`'s table, enforced through `helena.taxonomy`'s closed roots."""
    assert result(classification="suspicious", citations=(
        Citation(evidence_id=SHOWN, stance=SUPPORTING),
    )).root == "suspicious"
    for refused in ("malicious.c2", "unknown"):
        with pytest.raises(TaxonomyError):
            result(classification=refused)
    analyst = result(
        emitter=ANALYST,
        classification="malicious.c2",
        citations=(Citation(evidence_id=SHOWN, stance=SUPPORTING),),
        evidence_package=EvidencePackage(narrative="bidirectional traffic to a C2 hit"),
    )
    assert analyst.root == "malicious"


def test_unknown_has_no_children_and_a_path_outside_the_vocabulary_is_refused():
    """`concept/02`: a child would claim a specificity the run does not have."""
    with pytest.raises(TaxonomyError):
        result(
            emitter=ANALYST,
            classification="unknown.enrichment_failed",
            gaps=(Gap(kind="failed", detail="every source failed"),),
        )
    with pytest.raises(TaxonomyError):
        result(classification="suspicious.invented")


def test_a_declared_but_unused_path_is_refused_for_emission():
    """`for_emission`, not `resolve`: "declared but unused" is not "invalid"."""
    with pytest.raises(TaxonomyError, match="declared in v1 and unused"):
        result(
            classification="suspicious.anomalous_dns",
            citations=(Citation(evidence_id=SHOWN, stance=SUPPORTING),),
        )


def test_the_root_is_derived_and_is_not_a_second_stored_copy():
    assert "root" not in AgentResult.model_fields
    assert result().root == "normal"


# --- The result: the citation rule ------------------------------------------


def test_a_normal_triage_decision_returns_verdict_and_confidence_only():
    """`concept/04`: "that costs nothing on the overwhelmingly common path"."""
    clean = result(classification="normal")
    assert (clean.citations, clean.evidence_package) == ((), None)
    with pytest.raises(ValidationError, match="verdict and confidence only"):
        result(
            classification="normal",
            citations=(Citation(evidence_id=SHOWN, stance=SUPPORTING),),
        )


def test_a_suspicious_triage_decision_requires_a_citation():
    """"gives auditability exactly where a decision was made to spend analysis"."""
    with pytest.raises(ValidationError, match="requires at least one citation"):
        result(classification="suspicious")
    assert result(
        classification="suspicious",
        citations=(Citation(evidence_id=SHOWN, stance=SUPPORTING),),
    ).citations


def test_unknown_is_exempt_from_citations_and_its_gaps_are_mandatory():
    """"which is what stops the exemption becoming an unfalsifiable shrug"."""
    with pytest.raises(ValidationError, match="unfalsifiable shrug"):
        result(emitter=ANALYST, classification="unknown", evidence_package=EvidencePackage())
    unassessable = result(
        emitter=ANALYST,
        classification="unknown",
        gaps=(Gap(kind="failed", detail="every enrichment source failed to load"),),
        evidence_package=EvidencePackage(narrative="nothing could be established"),
    )
    assert unassessable.citations == ()


def test_an_analyst_verdict_that_is_not_normal_requires_citations_and_a_package():
    for missing in ({"citations": ()}, {"evidence_package": None}):
        with pytest.raises(ValidationError):
            result(
                **{
                    "emitter": ANALYST,
                    "classification": "malicious.c2",
                    "citations": (Citation(evidence_id=SHOWN, stance=SUPPORTING),),
                    "evidence_package": EvidencePackage(narrative="n"),
                    **missing,
                }
            )


def test_one_evidence_row_cannot_both_support_and_contradict_a_verdict():
    assert set(STANCES) == {SUPPORTING, CONTRADICTING}
    with pytest.raises(ValidationError, match="cited twice"):
        result(
            classification="suspicious",
            citations=(
                Citation(evidence_id=SHOWN, stance=SUPPORTING),
                Citation(evidence_id=SHOWN, stance=CONTRADICTING),
            ),
        )


def test_a_citation_says_what_the_row_showed():
    with pytest.raises(ValidationError, match="is not one of"):
        Citation(evidence_id=SHOWN, stance="mentioned")
    with pytest.raises(ValidationError, match="resolves to nothing"):
        Citation(evidence_id="  ", stance=SUPPORTING)


# --- The result: the asymmetry ----------------------------------------------


def test_a_triage_result_cannot_carry_the_analyst_s_apparatus():
    """`concept/04`: the two stages differ in where their information comes from."""
    step = RetrievalStep(
        source_id="threatfox",
        entity_type="address",
        entity_value="45.192.105.203",
        outcome=LIVE_QUERY,
        retrieved_at=WINDOW_END,
        evidence_id=SHOWN,
    )
    with pytest.raises(ValidationError, match="no tools and no retrieval"):
        result(
            classification="suspicious",
            citations=(Citation(evidence_id=SHOWN, stance=SUPPORTING),),
            retrieval_trace=(step,),
        )
    with pytest.raises(ValidationError, match="an evidence package is the analyst's"):
        result(classification="suspicious",
               citations=(Citation(evidence_id=SHOWN, stance=SUPPORTING),),
               evidence_package=EvidencePackage())
    with pytest.raises(ValidationError, match="proposes a claim"):
        result(
            classification="suspicious",
            citations=(Citation(evidence_id=SHOWN, stance=SUPPORTING),),
            proposed_claims=(
                ProposedClaim(
                    subject_type="domain",
                    subject_value="cdn.example",
                    claim="shared infrastructure",
                    confidence=0.6,
                    citations=(Citation(evidence_id=SHOWN, stance=SUPPORTING),),
                ),
            ),
        )


@pytest.mark.parametrize("spent", ["steps", "live_queries", "cache_hits"])
def test_a_triage_run_that_reports_a_lookup_is_refused(spent: str):
    """Whatever the code says it did, a non-zero count here is a lookup that happened."""
    with pytest.raises(ValidationError, match="triage has no tools at all"):
        result(cost=cost(**{spent: 1}))
    with pytest.raises(ValidationError, match="triage has no tools at all"):
        failure(cost=cost(**{spent: 1}))


# --- The result: budgets and gaps -------------------------------------------


def test_the_seven_gap_kinds_are_all_there_and_none_is_a_synonym():
    """`concept/instruction.md` §2: never collapse these, at any layer, for any reason."""
    assert set(GAP_KINDS) == {
        "missing",
        "stale",
        "in_flight",
        "failed",
        "no_match",
        "truncated",
        "budget_exhausted",
    }
    assert len(GAP_KINDS) == len(set(GAP_KINDS))
    with pytest.raises(ValidationError, match="is not one of"):
        Gap(kind="empty", detail="nothing came back")


def test_a_gap_records_what_was_missing_and_not_merely_that_something_was():
    with pytest.raises(ValidationError, match="is blank"):
        Gap(kind="stale", detail="  ")
    with pytest.raises(ValidationError, match="the limit is"):
        Gap(kind="stale", detail="x" * (MAX_DETAIL + 1))


def test_a_budget_exhausted_run_may_return_unknown_and_never_normal():
    """`concept/07`: it established the absence of nothing."""
    exhausted = Gap(kind=BUDGET_EXHAUSTED, detail="the live-query budget ran out")
    with pytest.raises(ValidationError, match="never return `normal`"):
        result(
            emitter=ANALYST,
            classification="normal",
            citations=(Citation(evidence_id=SHOWN, stance=SUPPORTING),),
            gaps=(exhausted,),
        )
    degraded = result(
        emitter=ANALYST,
        classification="unknown",
        gaps=(exhausted,),
        evidence_package=EvidencePackage(narrative="stopped early"),
    )
    assert degraded.root == "unknown"


# --- The retrieval trace -----------------------------------------------------


def test_a_retrieval_step_produced_a_row_or_a_typed_failure_and_never_both():
    """`concept/05` rule 4: a failed query emits a typed error and no taxonomy object."""
    common = {
        "source_id": "threatfox",
        "entity_type": "address",
        "entity_value": "45.192.105.203",
        "outcome": CACHE_HIT,
        "retrieved_at": WINDOW_START,
    }
    with pytest.raises(ValidationError, match="neither"):
        RetrievalStep(**common)
    with pytest.raises(ValidationError, match="both"):
        RetrievalStep(
            **common,
            evidence_id=SHOWN,
            failure=QueryFailure(
                source_id="threatfox",
                entity_type="address",
                entity_value="45.192.105.203",
                reason="timeout",
            ),
        )
    served = RetrievalStep(**common, evidence_id=SHOWN)
    assert (served.outcome, served.retrieved_at) == (CACHE_HIT, WINDOW_START)


def test_a_step_s_failure_is_about_the_thing_the_step_queried():
    with pytest.raises(ValidationError, match="and its failure names"):
        RetrievalStep(
            source_id="threatfox",
            entity_type="address",
            entity_value="45.192.105.203",
            outcome=LIVE_QUERY,
            retrieved_at=WINDOW_START,
            failure=QueryFailure(
                source_id="threatfox",
                entity_type="domain",
                entity_value="example.test",
                reason="timeout",
            ),
        )


def test_a_cache_hit_and_a_live_query_stay_distinguishable_afterwards():
    """`concept/07`: two runs that differ only in cache state must be told apart."""
    trace = tuple(
        RetrievalStep(
            source_id="threatfox",
            entity_type="address",
            entity_value="45.192.105.203",
            outcome=outcome,
            retrieved_at=WINDOW_START,
            evidence_id=SHOWN,
        )
        for outcome in (CACHE_HIT, LIVE_QUERY)
    )
    assert [step.outcome for step in trace] == [CACHE_HIT, LIVE_QUERY]
    spent = cost(live_queries=1, cache_hits=1, steps=2)
    assert (spent.cache_hits, spent.live_queries) == (1, 1)


# --- Proposals ---------------------------------------------------------------


def test_a_proposal_with_nothing_behind_it_is_a_guess():
    """`concept/07`: a proposal is validated by deterministic code, and a guess is unvalidatable."""
    with pytest.raises(ValidationError, match="at least one citation"):
        ProposedClaim(
            subject_type="address",
            subject_value="45.192.105.203",
            claim="belongs to a bulletproof hosting range",
            confidence=0.7,
            citations=(),
        )


def test_a_proposal_is_about_an_entity_the_vocabulary_has():
    with pytest.raises(ValidationError, match="is not among"):
        ProposedClaim(
            subject_type="asn",
            subject_value="AS64500",
            claim="hosting",
            confidence=0.7,
            citations=(Citation(evidence_id=SHOWN, stance=SUPPORTING),),
        )


# --- Cost --------------------------------------------------------------------


def test_the_cost_records_the_measured_dimensions_and_invents_no_currency():
    """`concept/06`: monetary cost is derived, and no price table exists here."""
    assert "currency" not in Cost.model_fields
    assert "usd" not in Cost.model_fields
    assert "retries" in Cost.model_fields
    assert set(Cost.model_fields) == {
        "prompt_tokens",
        "completion_tokens",
        "steps",
        "live_queries",
        "cache_hits",
        "retries",
        "wall_clock_seconds",
    }


# --- The typed failure envelope ---------------------------------------------


def test_the_failure_envelope_has_nowhere_to_put_a_verdict():
    """`concept/02`: the failure and **no** verdict -- never a verdict, never a drop."""
    forbidden = {"classification", "root", "verdict", "confidence", "citations",
                 "evidence_package", "proposed_claims"}
    assert set(AgentFailure.model_fields) & forbidden == set()
    with pytest.raises(ValidationError):
        AgentFailure(
            emitter=TRIAGE,
            reason=SCHEMA_INVALID,
            detail="d",
            cost=cost(),
            versions=versions(),
            model_version="m",
            classification="normal",
        )


def test_the_failure_reasons_are_closed_and_budget_exhaustion_is_not_one():
    """`concept/07`: budget exhaustion degrades to `unknown`, which is a verdict."""
    assert set(FAILURE_REASONS) == {SCHEMA_INVALID, MODEL_UNAVAILABLE, TIMED_OUT}
    assert BUDGET_EXHAUSTED not in FAILURE_REASONS
    with pytest.raises(ValidationError, match="is not one of"):
        failure(reason=BUDGET_EXHAUSTED)


def test_a_failure_records_the_model_that_answered_only_where_one_did():
    """ADR-0008: the configured name is never recorded as the identity that answered."""
    with pytest.raises(ValidationError, match="the identity that answered is known"):
        failure(reason=SCHEMA_INVALID, model_version=None)
    with pytest.raises(ValidationError, match="nothing answered"):
        failure(reason=MODEL_UNAVAILABLE, model_version="vendor/Small-Model-2026-05")
    unreachable = failure(
        reason=MODEL_UNAVAILABLE, model_version=None, detail="connection refused"
    )
    assert unreachable.model_version is None
    # A timeout may or may not have seen a response; both are accepted.
    assert failure(reason=TIMED_OUT, model_version=None).model_version is None
    assert failure(reason=TIMED_OUT).model_version is not None


def test_a_failure_detail_is_a_sentence_and_not_a_provider_response():
    with pytest.raises(ValidationError, match="the limit is"):
        failure(detail="x" * (MAX_DETAIL + 1))
    with pytest.raises(ValidationError, match="is blank"):
        failure(detail=" ")


# --- The exchange ------------------------------------------------------------


def test_a_matching_request_and_result_pass():
    check_exchange(request(), result())
    check_exchange(request(), failure())


def test_a_result_from_the_other_agent_is_not_this_request_s():
    with pytest.raises(ContractError, match="the request is for"):
        check_exchange(
            request(emitter=TRIAGE),
            result(
                emitter=ANALYST,
                citations=(Citation(evidence_id=SHOWN, stance=SUPPORTING),),
            ),
        )


@pytest.mark.parametrize("dimension", REQUEST_VERSION_DIMENSIONS)
def test_every_version_dimension_has_to_come_back_unchanged(dimension: str):
    """`concept/04`: "the echoed versions" -- this is what makes *echoed* mean something."""
    if dimension in ("schema_version", "taxonomy_version"):
        # These two are refused one step earlier, by the object itself, because
        # each names a module that has to exist for the result to mean anything:
        # the contract version replay validates against, and the vocabulary the
        # classification is drawn from.
        with pytest.raises((ValidationError, TaxonomyError)):
            result(versions=versions(**{dimension: "drifted"}).completed_by("m"))
        return
    drifted = versions(**{dimension: "drifted"}).completed_by("vendor/Small-Model-2026-05")
    with pytest.raises(ContractError, match="does not echo"):
        check_exchange(request(), result(versions=drifted))


def test_a_citation_has_to_resolve_to_something_the_run_was_given():
    """A model citing evidence it was never handed is what a stable id makes detectable."""
    with pytest.raises(ContractError, match="which the rendering did not show"):
        check_exchange(
            request(),
            result(
                classification="suspicious",
                citations=(Citation(evidence_id=NEVER_SHOWN, stance=SUPPORTING),),
            ),
        )
    check_exchange(
        request(),
        result(
            classification="suspicious",
            citations=(Citation(evidence_id=ALSO_SHOWN, stance=CONTRADICTING),),
        ),
    )


def test_the_analyst_may_cite_what_its_own_retrieval_produced():
    """The rendering is not the only source: a live lookup mints an evidence row."""
    fetched = "a" * 64
    analyst_result = result(
        emitter=ANALYST,
        classification="malicious.c2",
        citations=(Citation(evidence_id=fetched, stance=SUPPORTING),),
        evidence_package=EvidencePackage(
            patterns=("sustained bidirectional traffic",),
            narrative="the address is a live C2 and the host exchanged data with it",
        ),
        retrieval_trace=(
            RetrievalStep(
                source_id="threatfox",
                entity_type="address",
                entity_value="45.192.105.203",
                outcome=LIVE_QUERY,
                retrieved_at=WINDOW_END,
                evidence_id=fetched,
            ),
        ),
        cost=cost(live_queries=1, steps=1),
    )
    check_exchange(request(emitter=ANALYST), analyst_result)


def test_a_proposal_s_citations_are_checked_too():
    proposal = ProposedClaim(
        subject_type="domain",
        subject_value="cdn.example",
        claim="shared infrastructure serving many tenants",
        confidence=0.6,
        citations=(Citation(evidence_id=NEVER_SHOWN, stance=SUPPORTING),),
    )
    with pytest.raises(ContractError, match="which the rendering did not show"):
        check_exchange(
            request(emitter=ANALYST),
            result(
                emitter=ANALYST,
                classification="suspicious",
                citations=(Citation(evidence_id=SHOWN, stance=SUPPORTING),),
                evidence_package=EvidencePackage(narrative="n"),
                proposed_claims=(proposal,),
            ),
        )


def test_a_truncated_rendering_is_still_truncated_in_the_stored_outcome():
    """`concept/instruction.md` §2: truncation is visible or it is a bug."""
    truncated = request(rendering=rendering(truncated_section="domains_contacted"))
    with pytest.raises(ContractError, match="records no 'truncated' gap"):
        check_exchange(truncated, result())
    with pytest.raises(ContractError, match="records no 'truncated' gap"):
        check_exchange(truncated, failure())
    honest = result(
        gaps=(Gap(kind=TRUNCATED, detail="3 of 40 domains rendered"),),
    )
    check_exchange(truncated, honest)


def test_a_normal_triage_decision_may_still_report_a_truncation():
    """Verdict and confidence only does not mean "and no record of what was dropped"."""
    honest = result(gaps=(Gap(kind=TRUNCATED, detail="3 of 40 domains rendered"),))
    assert honest.root == "normal" and honest.citations == ()


# --- The evidence package ----------------------------------------------------


def test_the_package_does_not_hold_a_second_copy_of_the_citations_or_the_gaps():
    """One fact, one place: `concept/instruction.md` §2 on two copies that can drift."""
    assert set(EvidencePackage.model_fields) == {"patterns", "narrative"}
    assert "indicators" not in EvidencePackage.model_fields
    assert "missing_information" not in EvidencePackage.model_fields


def test_the_narrative_is_bounded():
    from helena.contracts.v1 import MAX_NARRATIVE

    with pytest.raises(ValidationError, match="the limit is"):
        EvidencePackage(narrative="x" * (MAX_NARRATIVE + 1))


# --- The one contract, not two ----------------------------------------------


def test_there_is_one_request_class_and_one_result_class_for_both_agents():
    """`concept/04`: "one versioned typed request / result pair covers every agent"."""
    assert taxonomy.EMITTERS == (TRIAGE, ANALYST)
    for emitter in taxonomy.EMITTERS:
        assert type(request(emitter=emitter)) is AgentRequest
    assert type(result(emitter=TRIAGE)) is AgentResult
    assert (
        type(
            result(
                emitter=ANALYST,
                classification="normal",
                citations=(Citation(evidence_id=SHOWN, stance=SUPPORTING),),
            )
        )
        is AgentResult
    )


def test_the_normal_exemption_is_triage_s_alone():
    """`concept/04` exempts "a `normal` **triage** decision", not every `normal`.

    The analyst reached its `normal` by spending analysis, and
    `concept/02`'s composition rule is why that has to be cited: "`normal` on
    contacted indicators **never** establishes `normal` for the context on its
    own". An uncited analyst `normal` would be the one verdict in the system with
    nothing behind it.
    """
    with pytest.raises(ValidationError, match="requires at least one citation"):
        result(emitter=ANALYST, classification="normal")
    assert result(
        emitter=ANALYST,
        classification="normal",
        citations=(Citation(evidence_id=SHOWN, stance=CONTRADICTING),),
    ).root == "normal"
