"""The composition rule: scope before severity, as something that fails.

Mirrors `src/helena/policy/`. The sentences under test are
`concept/02-concepts-and-taxonomy.md`'s, not the code's — the whole of "The
composition rule — scope before severity", one case per bullet:

- *"A C2 hit on a contacted address **with actual bidirectional traffic**
  supports `malicious.c2` for the host."*
- *"The same hit with one failed connection and no bytes returned does not. That
  is `suspicious` at most."*
- *"A phishing domain contacted means the *user was targeted*, not that the host
  is compromised."*
- *"A malicious indicator on **shared infrastructure** ... transfers nothing to
  the host without corroboration."*
- *"`normal` on contacted indicators **never** establishes `normal` for the
  context on its own."*
- and the note's own recorded limitation: *"The scope test works on **address**
  entities and not on **domain** ones."*

The rule table is the first block below and it is the point of this file: one row
per rule, each naming the rule it expects to fire and the verdict the evidence is
then permitted to carry. The engine tests at the end run the same rules over a
real capture and a real ThreatFox load, so the port-scoped case in particular is
decided by `port_matched` as the view actually computes it rather than as a
fixture asserts it.
"""

from __future__ import annotations

import ast
import json
import time
from datetime import datetime, timezone
from pathlib import Path

import psycopg
import pytest
from pydantic import ValidationError

from helena import policy, rendering, triage
from helena.config import Settings
from helena.contracts.v1 import (
    CONTRACT_VERSION,
    CONTRADICTING,
    MISSING,
    SCHEMA_INVALID,
    SUPPORTING,
    AgentFailure,
    AgentResult,
    Citation,
    Cost,
    EvidencePackage,
    Gap,
    RequestVersions,
)
from helena.enrichment import (
    ENRICHMENT_STATUSES,
    OK,
    SOURCES,
    Claim,
    Tier,
    load_threatfox,
    source_diversity,
)
from helena.normalizer import EventStore, Normalizer, describe_capture
from helena.observability import Redactor
from helena.policy import Support, supports_for, supports_in
from helena.policy import v1 as rule
from helena.taxonomy import ANALYST, TRIAGE
from helena.versions import VersionSet

PROJECT_ROOT = Path(__file__).resolve().parent.parent
FIXTURE_CAPTURES = PROJECT_ROOT / "tests" / "fixtures" / "captures"
LAYERS_CAPTURE = "ace6ca33f7bf8aa949f79124abf33fc115cfd0909e9dea798f4762cf87af8318"
THREATFOX_FIXTURE = PROJECT_ROOT / "tests" / "fixtures" / "threatfox" / "export.json"
RAW = THREATFOX_FIXTURE.read_bytes()

TENANT, SENSOR = "tenant-under-test", "sensor-under-test"
URL = "https://threatfox.invalid/export/json/recent/"
WINDOW_SECONDS = 300

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

#: Evidence identifiers. Real ones are a 64-character sha256; nothing here
#: recomputes one, so what matters is that they are distinct and stable.
FIRST = "a" * 64
SECOND = "b" * 64


# --- Builders ----------------------------------------------------------------


def versions(**overrides: str) -> VersionSet:
    return VersionSet(
        **{
            "model_version": "model-under-test",
            "prompt_version": "v1",
            "schema_version": CONTRACT_VERSION,
            "rendering_version": "v1",
            "taxonomy_version": "v1",
            "enrichment_snapshot_version": "2024-06-01T00:00:00Z",
            "normalization_snapshot_version": "psl-2024-06-01",
            "policy_version": rule.POLICY_VERSION,
            "aggregation_version": "v1",
            **overrides,
        }
    )


def cost() -> Cost:
    return Cost(
        prompt_tokens=100,
        completion_tokens=20,
        steps=0,
        live_queries=0,
        cache_hits=0,
        retries=0,
        wall_clock_seconds=0.4,
    )


def result(
    classification: str,
    *,
    emitter: str = ANALYST,
    citations: tuple[Citation, ...] = (),
    gaps: tuple[Gap, ...] = (),
    **overrides: object,
) -> AgentResult:
    """One verdict, with the contract's own requirements filled in.

    `evidence_package` is supplied for every non-`normal` analyst verdict because
    the contract requires one there; it carries nothing, since the composition
    rule reads citations and traffic and never a narrative.
    """
    root = classification.split(".")[0]
    package = (
        EvidencePackage()
        if emitter == ANALYST and root != "normal"
        else None
    )
    return AgentResult(
        **{
            "emitter": emitter,
            "classification": classification,
            "confidence": 0.8,
            "citations": citations,
            "gaps": gaps,
            "evidence_package": package,
            "cost": cost(),
            "versions": versions(),
            **overrides,
        }
    )


def support(
    evidence_id: str = FIRST,
    *,
    stance: str = SUPPORTING,
    entity_type: str = rule.ADDRESS,
    entity_value: str = "203.0.113.10",
    classification: str = "malicious",
    scope_type: str | None = None,
    scope_value: str | None = None,
    port_matched: bool | None = None,
    layers: tuple[str, ...] = (rule.FLOW_DESTINATION,),
    sent: int = 4200,
    received: int = 51_000,
    ports: tuple[int, ...] = (443,),
    source_id: str = "threatfox",
    source_tier: str = "B",
    status: str = "ok",
    confidence: float | None = 1.0,
) -> Support:
    return Support(
        evidence_id=evidence_id,
        stance=stance,
        entity_type=entity_type,
        entity_value=entity_value,
        classification=classification,
        confidence=confidence,
        scope_type=scope_type or entity_type,
        scope_value=scope_value or entity_value,
        port_matched=port_matched,
        source_id=source_id,
        source_tier=source_tier,
        status=status,
        observed_layers=layers,
        observed_flow_count=3,
        observed_bytes_sent=sent,
        observed_bytes_received=received,
        ports=ports,
    )


def cite(*supports: Support) -> tuple[Citation, ...]:
    """The citations a result carries for these supports, stances included."""
    return tuple(
        Citation(evidence_id=item.evidence_id, stance=item.stance) for item in supports
    )


def decide(classification: str, *supports: Support, **overrides: object):
    """Constrain one verdict against exactly these supports."""
    verdict = result(classification, citations=cite(*supports), **overrides)
    return rule.constrain(verdict, supports)


# --- The rule table ----------------------------------------------------------
#
# One row per rule, plus the permitted cases each rule is the negation of. Every
# row states the whole answer -- the outcome, what is then permitted, which rules
# fired and which gaps were recorded -- because a case that asserted only the
# outcome would pass while the decision named the wrong rule.

A_CONTACTED_ADDRESS = support(sent=4200, received=51_000)
A_FAILED_CONNECTION = support(sent=120, received=0)
A_RESOLVED_NAME_ONLY = support(layers=("dns_query",), sent=0, received=0, ports=())
A_DOMAIN_IN_TLS = support(
    entity_type="domain",
    entity_value="c2.example.invalid",
    layers=("dns_query", "tls"),
    sent=900,
    received=1400,
    ports=(),
)
A_PORT_THE_HOST_MISSED = support(
    scope_type=rule.ADDRESS_PORT_SCOPE,
    scope_value="203.0.113.10:8000",
    port_matched=False,
)
A_PORT_THE_HOST_REACHED = support(
    scope_type=rule.ADDRESS_PORT_SCOPE,
    scope_value="203.0.113.10:443",
    port_matched=True,
)
A_RESOLVER = support(entity_value="203.0.113.53", ports=(53,))
A_CLEAN_CLAIM = support(classification="normal")
A_CONTRADICTION = support(stance=CONTRADICTING)
A_SECOND_ADDRESS = support(
    SECOND, entity_value="198.51.100.7", ports=(443,), sent=800, received=9000
)

CASES = [
    # (name, proposed, supports, outcome, permits, rules fired, gaps)
    (
        "a c2 hit on a contacted address with bidirectional traffic stands",
        "malicious.c2",
        (A_CONTACTED_ADDRESS,),
        rule.PERMITTED,
        "malicious.c2",
        (),
        (rule.SHARED_INFRASTRUCTURE_UNDETERMINED,),
    ),
    (
        "the same hit with one failed connection and no bytes returned does not",
        "malicious.c2",
        (A_FAILED_CONNECTION,),
        rule.CONSTRAINED,
        rule.SUSPICIOUS,
        (rule.TRAFFIC_NOT_BIDIRECTIONAL,),
        (),
    ),
    (
        "a name the host only resolved carries no traffic of the connection",
        "malicious.c2",
        (A_RESOLVED_NAME_ONLY,),
        rule.CONSTRAINED,
        rule.SUSPICIOUS,
        (rule.TRAFFIC_NOT_BIDIRECTIONAL,),
        (),
    ),
    (
        "a phishing domain contacted does not make the host compromised",
        "malicious.compromised",
        (A_CONTACTED_ADDRESS,),
        rule.CONSTRAINED,
        rule.SUSPICIOUS,
        (rule.CONTACT_IS_NOT_COMPROMISE,),
        (),
    ),
    (
        "the same contact does reach the path that means the user was targeted",
        "malicious.phishing",
        (A_CONTACTED_ADDRESS,),
        rule.PERMITTED,
        "malicious.phishing",
        (),
        (rule.SHARED_INFRASTRUCTURE_UNDETERMINED,),
    ),
    (
        "a claim scoped to a port the host never reached is suspicious at most",
        "malicious.c2",
        (A_PORT_THE_HOST_MISSED,),
        rule.CONSTRAINED,
        rule.SUSPICIOUS,
        (rule.PORT_NOT_REACHED,),
        (),
    ),
    (
        "a claim scoped to the port the host did reach stands",
        "malicious.c2",
        (A_PORT_THE_HOST_REACHED,),
        rule.PERMITTED,
        "malicious.c2",
        (),
        (rule.SHARED_INFRASTRUCTURE_UNDETERMINED,),
    ),
    (
        "domain-only support is downgraded and the reason is recorded",
        "malicious.phishing",
        (A_DOMAIN_IN_TLS,),
        rule.CONSTRAINED,
        rule.SUSPICIOUS,
        (rule.NAME_CARRIES_NO_TRAFFIC,),
        (rule.DOMAIN_SCOPE_UNTESTABLE,),
    ),
    (
        "a malicious indicator on shared infrastructure transfers nothing",
        "malicious.c2",
        (A_RESOLVER,),
        rule.CONSTRAINED,
        None,
        (rule.SHARED_INFRASTRUCTURE,),
        (),
    ),
    (
        "one support off the shared infrastructure is the corroboration",
        "malicious.c2",
        (A_RESOLVER, A_SECOND_ADDRESS),
        rule.PERMITTED,
        "malicious.c2",
        (),
        (rule.SHARED_INFRASTRUCTURE_UNDETERMINED,),
    ),
    (
        "normal on contacted indicators never establishes normal for the context",
        "normal.known_service",
        (A_CLEAN_CLAIM,),
        rule.CONSTRAINED,
        None,
        (rule.NORMAL_BY_ABSENCE,),
        (),
    ),
    (
        "a malicious verdict citing only what argues against it composes nothing",
        "malicious.c2",
        (A_CONTRADICTION,),
        rule.CONSTRAINED,
        None,
        (rule.UNSUPPORTED_SEVERITY,),
        (),
    ),
    (
        "two rules that cap agree, and the decision names both",
        "malicious.compromised",
        (A_DOMAIN_IN_TLS,),
        rule.CONSTRAINED,
        rule.SUSPICIOUS,
        (rule.CONTACT_IS_NOT_COMPROMISE, rule.NAME_CARRIES_NO_TRAFFIC),
        (rule.DOMAIN_SCOPE_UNTESTABLE,),
    ),
    (
        "a rule that permits nothing beats a rule that caps",
        "malicious.compromised",
        (A_RESOLVER,),
        rule.CONSTRAINED,
        None,
        (rule.CONTACT_IS_NOT_COMPROMISE, rule.SHARED_INFRASTRUCTURE),
        (),
    ),
    (
        "a suspicious verdict is already inside every cap and is left alone",
        "suspicious.low_reputation",
        (A_FAILED_CONNECTION,),
        rule.PERMITTED,
        "suspicious.low_reputation",
        (),
        (),
    ),
]


@pytest.mark.parametrize(
    ("proposed", "supports", "outcome", "permits", "rules", "gaps"),
    [case[1:] for case in CASES],
    ids=[case[0] for case in CASES],
)
def test_the_composition_rule(
    proposed: str,
    supports: tuple[Support, ...],
    outcome: str,
    permits: str | None,
    rules: tuple[str, ...],
    gaps: tuple[str, ...],
):
    decision = decide(proposed, *supports)
    assert decision.outcome == outcome
    assert decision.permits == permits
    assert tuple(finding.rule for finding in decision.findings) == rules
    assert tuple(gap.kind for gap in decision.gaps) == gaps
    assert decision.policy_version == rule.POLICY_VERSION
    assert decision.proposed == proposed


def test_every_rule_has_a_case_in_the_table():
    """A rule nobody exercises is a rule nobody knows the behaviour of.

    The table is the suite for this module, so a `v2`-shaped edit that adds a
    rule and forgets a row fails here rather than shipping untested policy.
    """
    exercised = {name for case in CASES for name in case[5]}
    assert exercised == set(rule.RULES)


def test_every_gap_kind_has_a_case_in_a_table():
    """Both tables together, because the two rules record different gaps.

    `FRESHNESS_ADEQUACY_UNTESTED` is the escalation evaluator's — a verdict is
    constrained by what the evidence can support and never by how old the
    snapshot was — so a check against the composition table alone would either
    fail or force a gap into a rule that has nothing to say about it.
    """
    exercised = {kind for case in CASES for kind in case[6]}
    exercised |= {kind for case in ESCALATION_CASES for kind in case[4]}
    assert exercised == set(rule.GAP_KINDS)


def test_the_rule_functions_are_in_the_declared_order():
    """`RULES` is what a decision records; `_RULE_FUNCTIONS` is what runs.

    Two copies of one list, so they are asserted equal — by firing each function
    on a case built to trip it rather than by reading a name off the function,
    which would pass for a pair that had been reordered together.
    """
    fired = [
        finding.rule
        for case in CASES
        for finding in decide(case[1], *case[2]).findings
    ]
    assert set(fired) == set(rule.RULES)
    for case in CASES:
        recorded = [finding.rule for finding in decide(case[1], *case[2]).findings]
        assert recorded == sorted(recorded, key=rule.RULES.index)


# --- The constants that have two homes ---------------------------------------


def test_the_flow_destination_layer_is_spelled_the_way_the_projection_spells_it():
    """Two copies of a constant, asserted equal (`concept/instruction.md` §2).

    `helena.policy.v1` may not import the rendering package's tuple — a frozen
    version reading a constant another package is free to change is the in-place
    revision the version rules exist to prevent — so the name is copied and this
    is what stops the copies drifting.
    """
    assert rule.FLOW_DESTINATION in dict(rendering.OBSERVATION_LAYERS).values()
    assert dict(rendering.OBSERVATION_LAYERS)["observed_as_flow_destination"] == (
        rule.FLOW_DESTINATION
    )


def test_every_capped_root_is_a_verdict_the_emitter_could_have_given():
    """A cap the taxonomy refuses would be the policy inventing a label."""
    from helena import taxonomy

    for emitter in (TRIAGE, ANALYST):
        resolved = taxonomy.for_emission(
            rule.SUSPICIOUS, level=taxonomy.CONTEXT, version="v1", emitter=emitter
        )
        assert resolved.is_root


def test_the_severity_scale_holds_no_unknown():
    """`unknown` means unassessable, which is not a severity.

    `concept/02` keeps it *"deliberately distinct from `suspicious`, which means
    analysis ran and could not settle it"*, and a scale with it on would let a cap
    turn an unassessable run into a graded one.
    """
    assert "unknown" not in rule.SEVERITY
    verdict = result("unknown", gaps=(Gap(kind=MISSING, detail="nothing loaded"),))
    decision = rule.constrain(verdict, ())
    assert decision.outcome == rule.PERMITTED
    assert decision.permits == "unknown"
    assert decision.findings == ()


def test_an_uncited_triage_normal_is_not_the_absence_rule():
    """`concept/04` makes an uncited `normal` triage decision the cheap common path.

    The rule is *"`normal` on contacted indicators never establishes `normal` on
    its own"*, and a verdict citing no indicator at all did not rest on one. The
    failure mode of reading a context of nothing but `no_match` as clean is not
    visible here — a `no_match` carries no identifier to cite — and ADR-0022 §4
    says whose it is instead.
    """
    decision = rule.constrain(result("normal", emitter=TRIAGE), ())
    assert decision.outcome == rule.PERMITTED
    assert decision.findings == ()


def test_one_adverse_claim_among_the_citations_takes_the_absence_rule_out():
    """*"on its own"* is the operative phrase and it is read as written."""
    adverse = support(SECOND, classification="suspicious")
    decision = decide("normal.known_service", A_CLEAN_CLAIM, adverse)
    assert decision.outcome == rule.PERMITTED
    assert decision.findings == ()


# --- What the policy refuses to be asked -------------------------------------


def test_a_result_recording_another_policy_version_is_refused():
    verdict = result(
        "malicious.c2",
        citations=cite(A_CONTACTED_ADDRESS),
        versions=versions(policy_version="v9"),
    )
    with pytest.raises(policy.PolicyError, match="policy_version 'v9'"):
        rule.constrain(verdict, (A_CONTACTED_ADDRESS,))


def test_a_support_list_that_is_not_the_result_s_citations_is_refused():
    """A rule's answer is a function of exactly the cited evidence.

    Handed a shorter list it would return something that looks like a decision
    and was taken without half the evidence — which is the one failure mode of
    this stage that produces a *lower* alert rate and no error at all.
    """
    verdict = result(
        "malicious.c2", citations=cite(A_RESOLVER, A_SECOND_ADDRESS)
    )
    with pytest.raises(policy.PolicyError, match="cites"):
        rule.constrain(verdict, (A_RESOLVER,))


def test_a_decision_that_permits_and_carries_a_finding_is_refused():
    """The two halves of the outcome cannot disagree.

    `constrain` cannot build one — every rule that fires caps below `malicious` —
    but the shape is what makes a stored decision readable, so it is checked
    rather than argued.
    """
    with pytest.raises(ValidationError, match="constrained something"):
        rule.Decision(
            policy_version=rule.POLICY_VERSION,
            taxonomy_version="v1",
            emitter=ANALYST,
            proposed="malicious.c2",
            outcome=rule.PERMITTED,
            permits="malicious.c2",
            findings=(
                rule.Finding(
                    rule=rule.TRAFFIC_NOT_BIDIRECTIONAL,
                    permits=rule.SUSPICIOUS,
                    detail="a finding on a permitted decision",
                ),
            ),
        )


def test_a_constrained_decision_names_the_rule_that_constrained_it():
    with pytest.raises(ValidationError, match="names the rule"):
        rule.Decision(
            policy_version=rule.POLICY_VERSION,
            taxonomy_version="v1",
            emitter=ANALYST,
            proposed="malicious.c2",
            outcome=rule.CONSTRAINED,
            permits=rule.SUSPICIOUS,
        )


def test_a_finding_permits_a_root_and_never_a_path():
    """*"Emit the parent rather than guessing a child"* (`concept/02`)."""
    with pytest.raises(ValidationError, match="permits at most a root"):
        rule.Finding(
            rule=rule.TRAFFIC_NOT_BIDIRECTIONAL,
            permits="suspicious.low_reputation",
            detail="a cap that names a child",
        )


def test_a_gap_kind_outside_the_policy_s_own_vocabulary_is_refused():
    """The policy's kinds are its own, and the contract's seven are not them.

    None of `helena.contracts.v1.GAP_KINDS` names a test that does not apply, and
    spelling `missing` here would collapse "the lookup did not happen" into "the
    rule could not be run".
    """
    with pytest.raises(ValidationError, match="gap kind 'missing'"):
        rule.Gap(kind=MISSING, detail="the contract's word, not this one's")


def test_a_support_observed_by_no_layer_is_refused():
    with pytest.raises(ValidationError, match="observed by no"):
        support(layers=())


# --- Deterministic escalation ------------------------------------------------
#
# `concept/04-the-two-agents.md`, "What escalates":
#
#   The enrichment evidence escalates on its own -- a Tier A, or a
#   high-confidence Tier B, malicious classification whose traffic
#   characteristics support it -- regardless of the triage verdict. An LLM
#   returning `normal` may not bury a high-confidence match.
#
# One row per rule that can hold a claim back, plus the cases each rule is the
# negation of, and every row states the whole answer: whether the context
# escalated, what each candidate's traffic supports, which rules named it, and
# which gaps were recorded.


def thresholds() -> policy.Thresholds:
    """The project's own `config/policy.toml`, not a fixture of one.

    The file is what a deployment edits, so a suite that read a temporary copy
    would pass with the committed file saying anything at all.
    """
    return policy.thresholds()


#: No registered source is tier A -- `helena.enrichment.SOURCES` holds a B and a
#: C -- so the tier is supplied on the support directly. The rule is about the
#: tier, the tier belongs to the source descriptor, and adding a source is a
#: governed decision (`concept/05-threat-intelligence.md`) rather than a fixture.
A_TIER_A_HIT = support(source_tier=rule.TIER_A, confidence=None)
A_TIER_B_AT_THE_THRESHOLD = support(confidence=0.80)
A_TIER_B_BELOW_IT = support(confidence=0.50)
A_TIER_B_WITH_NO_CONFIDENCE = support(confidence=None)
A_TIER_C_HIT = support(source_tier="C", source_id="sslbl-ja3")
A_STALE_TIER_A_HIT = support(source_tier=rule.TIER_A, confidence=None, status="stale")
A_RESOLVER_TIER_A = support(
    source_tier=rule.TIER_A, confidence=None, entity_value="203.0.113.53", ports=(53,)
)
A_SECOND_ADDRESS_TIER_A = support(
    SECOND,
    source_tier=rule.TIER_A,
    confidence=None,
    entity_value="198.51.100.7",
    sent=800,
    received=9000,
)

ESCALATION_CASES = [
    # (name, supports, escalates, ((evidence id, rules, supports), ...), gaps)
    (
        "a tier A malicious hit the host exchanged bytes with escalates",
        (A_TIER_A_HIT,),
        True,
        ((FIRST, (), rule.MALICIOUS),),
        (rule.SHARED_INFRASTRUCTURE_UNDETERMINED,),
    ),
    (
        "a tier B hit at its source's configured threshold escalates",
        (A_TIER_B_AT_THE_THRESHOLD,),
        True,
        ((FIRST, (), rule.MALICIOUS),),
        (rule.SHARED_INFRASTRUCTURE_UNDETERMINED,),
    ),
    (
        "a tier B hit below its source's threshold does not",
        (A_TIER_B_BELOW_IT,),
        False,
        ((FIRST, (rule.BELOW_SOURCE_THRESHOLD,), rule.MALICIOUS),),
        (),
    ),
    (
        "a tier B hit reporting no confidence has not cleared the threshold",
        (A_TIER_B_WITH_NO_CONFIDENCE,),
        False,
        ((FIRST, (rule.NO_CONFIDENCE_REPORTED,), rule.MALICIOUS),),
        (),
    ),
    (
        "a tier C hit does not escalate however malicious it says the entity is",
        (A_TIER_C_HIT,),
        False,
        ((FIRST, (rule.TIER_DOES_NOT_ESCALATE,), rule.MALICIOUS),),
        (),
    ),
    (
        "a hit with one failed connection and no bytes returned does not escalate",
        (support(source_tier=rule.TIER_A, confidence=None, sent=120, received=0),),
        False,
        ((FIRST, (rule.TRAFFIC_NOT_BIDIRECTIONAL,), rule.SUSPICIOUS),),
        (),
    ),
    (
        "a hit scoped to a port the host never reached does not escalate",
        (
            support(
                source_tier=rule.TIER_A,
                confidence=None,
                scope_type=rule.ADDRESS_PORT_SCOPE,
                scope_value="203.0.113.10:8000",
                port_matched=False,
            ),
        ),
        False,
        ((FIRST, (rule.PORT_NOT_REACHED,), rule.SUSPICIOUS),),
        (),
    ),
    (
        "a name carries no traffic of its own, and the limitation is recorded",
        (
            support(
                source_tier=rule.TIER_A,
                confidence=None,
                entity_type="domain",
                entity_value="c2.example.invalid",
                layers=("dns_query", "tls"),
                ports=(),
            ),
        ),
        False,
        ((FIRST, (rule.NAME_CARRIES_NO_TRAFFIC,), rule.SUSPICIOUS),),
        (rule.DOMAIN_SCOPE_UNTESTABLE,),
    ),
    (
        "a hit on infrastructure this host used as a resolver transfers nothing",
        (A_RESOLVER_TIER_A,),
        False,
        ((FIRST, (rule.SHARED_INFRASTRUCTURE,), None),),
        (),
    ),
    (
        "one hit off the shared infrastructure is the corroboration",
        (A_RESOLVER_TIER_A, A_SECOND_ADDRESS_TIER_A),
        True,
        ((FIRST, (), rule.MALICIOUS), (SECOND, (), rule.MALICIOUS)),
        (rule.SHARED_INFRASTRUCTURE_UNDETERMINED,),
    ),
    (
        "a claim from a superseded snapshot still escalates, and says it is one",
        (A_STALE_TIER_A_HIT,),
        True,
        ((FIRST, (), rule.MALICIOUS),),
        (
            rule.SHARED_INFRASTRUCTURE_UNDETERMINED,
            rule.FRESHNESS_ADEQUACY_UNTESTED,
        ),
    ),
    (
        "a claim held back by the tier and by the traffic names both rules",
        (
            support(
                source_tier="C", source_id="sslbl-ja3", sent=120, received=0
            ),
        ),
        False,
        (
            (
                FIRST,
                (rule.TIER_DOES_NOT_ESCALATE, rule.TRAFFIC_NOT_BIDIRECTIONAL),
                rule.SUSPICIOUS,
            ),
        ),
        (),
    ),
    (
        "an evidence-level normal claim is not a candidate at all",
        (support(source_tier=rule.TIER_A, confidence=None, classification="normal"),),
        False,
        (),
        (),
    ),
]


@pytest.mark.parametrize(
    ("supports", "escalates", "candidates", "gaps"),
    [case[1:] for case in ESCALATION_CASES],
    ids=[case[0] for case in ESCALATION_CASES],
)
def test_deterministic_escalation(
    supports: tuple[Support, ...],
    escalates: bool,
    candidates: tuple[tuple[str, tuple[str, ...], str | None], ...],
    gaps: tuple[str, ...],
):
    escalation = rule.escalate(supports, thresholds())
    assert escalation.escalates is escalates
    assert (
        tuple(
            (candidate.evidence_id, candidate.rules, candidate.supports)
            for candidate in escalation.candidates
        )
        == candidates
    )
    assert tuple(gap.kind for gap in escalation.gaps) == gaps
    assert escalation.claims_read == len(supports)
    assert escalation.evidence_ids == tuple(
        evidence_id for evidence_id, rules, _ in candidates if not rules
    )


def test_every_escalation_rule_has_a_case_in_the_table():
    """A rule nobody exercises is a rule nobody knows the behaviour of."""
    exercised = {name for case in ESCALATION_CASES for _, rules, _ in case[3] for name in rules}
    assert exercised == set(rule.ESCALATION_RULES)


def test_the_escalation_rules_are_recorded_in_the_declared_order():
    """`ESCALATION_RULES` is the order a reader sees the tests in."""
    for case in ESCALATION_CASES:
        for candidate in rule.escalate(case[1], thresholds()).candidates:
            recorded = list(candidate.rules)
            assert recorded == sorted(recorded, key=rule.ESCALATION_RULES.index)


# --- Independent of triage, which is the whole point of it -------------------


def test_a_triage_verdict_of_normal_cannot_suppress_a_tier_a_match():
    """`concept/07-principles.md`'s named failure mode, as a test.

    *"Triage returning `normal` suppresses a Tier A match | Deterministic
    escalation is independent."* The two inputs are computed here over the same
    context and they disagree: `helena.triage.escalates` says no and the evidence
    says yes, and the analyst runs because `concept/03`'s routing `if` reaches the
    evidence first.
    """
    verdict = result("normal", emitter=TRIAGE)
    assert triage.escalates(verdict) is False

    escalation = rule.escalate((A_TIER_A_HIT,), thresholds())
    assert escalation.escalates is True
    assert escalation.evidence_ids == (FIRST,)
    assert escalation.candidates[0].source_tier == rule.TIER_A


def test_escalation_is_computed_when_triage_produced_a_typed_failure():
    """*"A triage failure does not escalate"* — and the evidence still does.

    `concept/04`: *"Failing closed is safe precisely because deterministic
    escalation is independent of whether triage ran at all."* This is the half
    that makes it safe, and until now it did not exist —
    `docs/decisions/0021-the-triage-runner.md` §6 recorded that as the one thing
    the triage runner left genuinely unsafe.
    """
    asked = versions().model_dump()
    asked.pop("model_version")
    failure = AgentFailure(
        emitter=TRIAGE,
        reason=SCHEMA_INVALID,
        detail="the model returned a classification outside the closed set",
        cost=cost(),
        versions=RequestVersions(model_requested="model-under-test", **asked),
        model_version="model-under-test",
    )
    assert triage.escalates(failure) is False

    escalation = rule.escalate((A_TIER_A_HIT,), thresholds())
    assert escalation.escalates is True
    assert escalation.evidence_ids == (FIRST,)


def test_the_evaluator_has_no_parameter_a_verdict_could_arrive_through():
    """The invariant, asserted over the signature rather than trusted.

    `concept/instruction.md` §2: *"Deterministic escalation is independent of
    triage. A `normal` from a model may not suppress a high-confidence match."*
    The way that gets broken is not a rule that reads a verdict — it is a later
    increment passing the triage result in so the evaluator can skip work when
    triage already said `normal`, which looks like an optimisation and is the
    suppression.
    """
    from inspect import signature

    parameters = signature(rule.escalate).parameters
    assert list(parameters) == ["supports", "thresholds"]
    annotations = {name: str(p.annotation) for name, p in parameters.items()}
    for annotation in annotations.values():
        assert "AgentResult" not in annotation
        assert "AgentFailure" not in annotation
        assert "Decision" not in annotation
    module = ast.parse(Path(rule.__file__).read_text())
    reachable = {
        node.name: node
        for node in module.body
        if isinstance(node, ast.FunctionDef)
        and node.name in ("escalate", "_candidate", "_supported_root")
    }
    assert set(reachable) == {"escalate", "_candidate", "_supported_root"}
    named = {
        node.id if isinstance(node, ast.Name) else node.attr
        for function in reachable.values()
        for node in ast.walk(function)
        if isinstance(node, (ast.Name, ast.Attribute))
    }
    assert not named & {"AgentResult", "AgentFailure", "Decision", "constrain"}


# --- The aggregator rule -----------------------------------------------------


def test_one_source_s_many_rows_about_one_entity_are_one_independent_source():
    """*"An aggregator is never counted as many votes"* (`concept/02`, rule 2).

    Counted through `helena.enrichment.source_diversity`, so the three
    consequences that function documents hold here without being restated: one
    source making forty claims is one, an aggregator republishing forty entries
    is one, and the same origin reaching us twice is one. What that stops is a
    below-threshold claim being lifted by the number of rows behind it, which is
    the one way a confidence could be raised without anyone deciding to.
    """
    rows = tuple(
        support(evidence_id=str(index) * 64, confidence=0.50)
        for index in range(1, 4)
    )
    escalation = rule.escalate(rows, thresholds())
    assert escalation.escalates is False
    assert {candidate.independent_sources for candidate in escalation.candidates} == {1}
    assert source_diversity(
        [
            Claim(
                source_id=item.source_id,
                entity_type=item.entity_type,
                entity_value=item.entity_value,
                path=item.classification,
            )
            for item in rows
        ]
    ) == 1


def test_the_count_is_of_sources_and_the_escalation_is_still_per_claim():
    """Two sources on one entity is two, and the one above threshold escalates.

    The count does not decide anything in this version — `concept/04` conditions
    independent escalation on the tier and the source's own confidence and on
    nothing else — so this is what it looks like when it is right: recorded
    beside a decision it did not make.
    """
    below = support(confidence=0.50)
    above = support(SECOND, source_tier=rule.TIER_A, confidence=None, source_id="sslbl-ja3")
    escalation = rule.escalate((below, above), thresholds())
    assert escalation.evidence_ids == (SECOND,)
    assert {candidate.independent_sources for candidate in escalation.candidates} == {2}


# --- The thresholds file -----------------------------------------------------


def write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "policy.toml"
    path.write_text(text)
    return path


def test_the_committed_policy_file_covers_every_tier_b_source():
    """The file a deployment actually edits, read as the loader reads it."""
    loaded = policy.thresholds()
    assert loaded.policy_version == rule.POLICY_VERSION
    assert loaded.thresholds_version.strip()
    assert set(loaded.by_source) == {
        source_id
        for source_id, descriptor in SOURCES.items()
        if descriptor.tier is policy.THRESHOLD_TIER
    }


def test_the_threshold_tier_is_the_tier_the_registry_qualifies_on_confidence():
    """Tier A escalates on scope and freshness; tier B escalates on a number.

    Two copies of `concept/02`'s tier table — the enum's own
    `escalates_independently` and this version's `ESCALATING_TIERS` — asserted
    equal, because a frozen version may not import a constant another package is
    free to change and two copies that can drift are worse than none.
    """
    assert policy.THRESHOLD_TIER is Tier.B
    assert set(rule.ESCALATING_TIERS) == {
        tier.value for tier in Tier if tier.escalates_independently
    }
    assert (rule.TIER_A, rule.TIER_B) == (Tier.A.value, Tier.B.value)


def test_the_ok_status_is_spelled_the_way_the_store_spells_it():
    """The other copied constant. `concept/instruction.md` §2, same rule."""
    assert rule.STATUS_OK == OK
    assert rule.STATUS_OK in ENRICHMENT_STATUSES


def test_an_absent_policy_file_is_a_startup_failure_and_never_a_default(tmp_path: Path):
    with pytest.raises(policy.PolicyError, match="never a default threshold"):
        policy.thresholds(tmp_path / "absent.toml")


def test_a_policy_file_that_is_not_toml_names_the_path(tmp_path: Path):
    with pytest.raises(policy.PolicyError, match="not readable TOML"):
        policy.thresholds(write(tmp_path, "policy_version = \n"))


def test_a_key_nothing_reads_is_refused(tmp_path: Path):
    document = (
        'policy_version = "v1"\nthresholds_version = "t1"\n'
        'escalate_everything = true\n\n[thresholds]\nthreatfox = 0.8\n'
    )
    with pytest.raises(policy.PolicyError, match="nothing reads"):
        policy.thresholds(write(tmp_path, document))


@pytest.mark.parametrize("key", ["policy_version", "thresholds_version"])
def test_a_policy_file_that_declares_no_version_is_refused(tmp_path: Path, key: str):
    lines = {"policy_version": '"v1"', "thresholds_version": '"t1"'}
    document = "".join(
        f"{name} = {value}\n" for name, value in lines.items() if name != key
    )
    with pytest.raises(policy.PolicyError, match=f"declares no {key}"):
        policy.thresholds(write(tmp_path, document + "\n[thresholds]\nthreatfox = 0.8\n"))


def test_a_threshold_for_a_source_nobody_registered_is_refused(tmp_path: Path):
    document = (
        'policy_version = "v1"\nthresholds_version = "t1"\n\n[thresholds]\n'
        'threatfox = 0.8\nnot-a-feed = 0.9\n'
    )
    with pytest.raises(policy.PolicyError, match="not a\n?\\s*registered source"):
        policy.thresholds(write(tmp_path, document))


def test_a_threshold_for_a_tier_that_does_not_read_one_is_refused(tmp_path: Path):
    """A key nothing reads is a policy somebody set and nothing applies."""
    document = (
        'policy_version = "v1"\nthresholds_version = "t1"\n\n[thresholds]\n'
        'threatfox = 0.8\n"sslbl-ja3" = 0.9\n'
    )
    with pytest.raises(policy.PolicyError, match="which is tier C"):
        policy.thresholds(write(tmp_path, document))


def test_a_registered_tier_b_source_the_file_is_silent_about_is_refused(tmp_path: Path):
    document = 'policy_version = "v1"\nthresholds_version = "t1"\n\n[thresholds]\n'
    with pytest.raises(policy.PolicyError, match="escalate on a number nobody chose"):
        policy.thresholds(write(tmp_path, document))


@pytest.mark.parametrize("value", ["1.5", "-0.1", "80"])
def test_a_confidence_outside_the_scale_a_claim_carries_is_refused(
    tmp_path: Path, value: str
):
    """`sql/migrations/0014` divides the feed's 0-100 by 100 before it is a claim.

    `80` is the trap this catches: the feed's own scale copied into the file
    unchanged, which would make every claim below the threshold and escalate
    nothing, silently.
    """
    document = (
        f'policy_version = "v1"\nthresholds_version = "t1"\n\n[thresholds]\n'
        f"threatfox = {value}\n"
    )
    with pytest.raises(policy.PolicyError, match="between 0 and 1"):
        policy.thresholds(write(tmp_path, document))


def test_a_threshold_that_is_not_a_number_is_refused(tmp_path: Path):
    document = (
        'policy_version = "v1"\nthresholds_version = "t1"\n\n[thresholds]\n'
        'threatfox = "high"\n'
    )
    with pytest.raises(policy.PolicyError, match="a confidence threshold is a number"):
        policy.thresholds(write(tmp_path, document))


def test_a_threshold_set_written_for_another_policy_version_is_refused():
    """The same check `constrain` makes on a result, for the same reason."""
    other = policy.Thresholds(
        policy_version="v9", thresholds_version="t1", by_source={"threatfox": 0.8}
    )
    with pytest.raises(policy.PolicyError, match="policy_version 'v9'"):
        rule.escalate((A_TIER_A_HIT,), other)


def test_a_source_with_no_configured_threshold_is_a_loud_failure_not_a_guess():
    """`for_source` never answers with a number nobody configured."""
    empty = policy.Thresholds(
        policy_version=rule.POLICY_VERSION, thresholds_version="t1", by_source={}
    )
    with pytest.raises(policy.PolicyError, match="no confidence threshold"):
        rule.escalate((A_TIER_B_AT_THE_THRESHOLD,), empty)


def test_every_escalation_records_the_policy_version_and_the_thresholds_version():
    """`v1.py` is frozen and `config/policy.toml` is not, so both are recorded."""
    loaded = thresholds()
    for case in ESCALATION_CASES:
        escalation = rule.escalate(case[1], loaded)
        assert escalation.policy_version == rule.POLICY_VERSION
        assert escalation.thresholds_version == loaded.thresholds_version


def test_an_escalation_naming_evidence_no_candidate_escalated_is_refused():
    with pytest.raises(ValidationError, match="cites evidence"):
        rule.Escalation(
            policy_version=rule.POLICY_VERSION,
            thresholds_version="t1",
            escalates=True,
            evidence_ids=(FIRST,),
            claims_read=0,
        )


def test_a_candidate_that_escalates_on_traffic_that_did_not_support_it_is_refused():
    with pytest.raises(ValidationError, match="traffic characteristics support it"):
        rule.Candidate(
            evidence_id=FIRST,
            entity_type=rule.ADDRESS,
            entity_value="203.0.113.10",
            source_id="threatfox",
            source_tier=rule.TIER_A,
            confidence=None,
            status=rule.STATUS_OK,
            supports=rule.SUSPICIOUS,
            escalates=True,
            rules=(),
            independent_sources=1,
            detail="a candidate escalating on suspicious support",
        )


# --- The version loader ------------------------------------------------------


def test_the_policy_version_loads_by_name():
    loaded = policy.version("v1")
    assert loaded.version == rule.POLICY_VERSION
    assert loaded.constrain is rule.constrain


def test_a_policy_version_this_tree_does_not_hold_is_its_own_failure():
    with pytest.raises(policy.UnknownVersion, match="no policy version 'v9'"):
        policy.version("v9")


def test_a_version_identifier_that_is_not_one_is_refused_before_the_import():
    with pytest.raises(policy.UnknownVersion, match="not a version identifier"):
        policy.version("../v1")


# --- Against a real context in a real engine ---------------------------------


def settings() -> Settings:
    return Settings.load(environ=ENVIRONMENT, env_file=None)


def current_window() -> float:
    return float(int(time.time() // WINDOW_SECONDS) * WINDOW_SECONDS)


def layers_records() -> list[dict]:
    path = FIXTURE_CAPTURES / f"{LAYERS_CAPTURE}.jsonl"
    return [json.loads(line) for line in path.read_bytes().splitlines()]


def targeted(raw: bytes, entity_value: str, ioc_type: str) -> bytes:
    """The committed extract with one entry repointed at an entity the capture has."""
    document = json.loads(raw)
    key = sorted(document)[0]
    document[key][0]["ioc_type"] = ioc_type
    document[key][0]["ioc_value"] = entity_value
    return json.dumps(document).encode()


@pytest.fixture
def live(migrated_engine: psycopg.Connection, tmp_path: Path) -> psycopg.Connection:
    """The layer-coverage capture, re-stamped into the window `now` falls in.

    The same shape `tests/test_rendering.py` uses and for the same reason: the
    projection reads `helena_signal_host_context_live`, which is inside the
    retention boundary, and every fixture here is dated 2024-06-01.
    """
    path = tmp_path / "restamped.jsonl"
    records = [{**record, "ts": current_window() + 1} for record in layers_records()]
    path.write_bytes(
        b"".join(json.dumps(record).encode() + b"\n" for record in records)
    )
    configured = settings()
    normalizer = Normalizer.from_settings(configured)
    events = EventStore(connection=migrated_engine, identity=configured.identity)
    for outcome in normalizer.normalize_capture(describe_capture(path)):
        events.record(outcome)
    migrated_engine.execute("FLUSH")
    return migrated_engine


def load(connection: psycopg.Connection, raw: bytes) -> None:
    """Load the extract as the snapshot current when this window started.

    At the window's own start, which is what task 25 recorded as satisfying both
    halves at once: the join needs `window_start >= valid_from` and the freshness
    test needs `valid_from` inside ThreatFox's 3 600-second refresh interval, and
    a load *after* the window silently produces no claim at all.
    """
    load_threatfox(
        connection,
        tenant=TENANT,
        sensor=SENSOR,
        source_url=URL,
        redactor=Redactor.from_settings(settings()),
        raw=raw,
        now=datetime.fromtimestamp(current_window(), tz=timezone.utc),
    )


def project(connection: psycopg.Connection) -> rendering.ContextProjection:
    found = connection.execute(
        "SELECT context_id FROM helena_signal_host_context_live"
    ).fetchall()
    assert len(found) == 1, f"expected one live context, got {len(found)}"
    store = rendering.RenderingStore(
        connection=connection, identity=settings().identity
    )
    return store.project(found[0][0])


def a_contacted_port(connection: psycopg.Connection) -> tuple[str, int]:
    reached = connection.execute(
        "SELECT entity_value, port FROM helena_signal_context_entity_ports "
        "ORDER BY entity_value, port LIMIT 1"
    ).fetchone()
    assert reached, "the capture produced no contacted port"
    return reached[0], reached[1]


def the_claim(projection: rendering.ContextProjection, entity_value: str):
    """The one claim the load produced about `entity_value`, and its entity."""
    found = [
        (entity, record)
        for entity in projection.entities
        if entity.entity_value == entity_value
        for record in entity.enrichment
        if record.has_claim
    ]
    assert len(found) == 1, f"{entity_value} carries {len(found)} claims, expected one"
    return found[0]


@pytest.mark.integration
def test_a_real_port_scoped_hit_the_host_reached_composes_to_malicious(
    live: psycopg.Connection,
):
    """The whole path: a capture, a feed load, the view's `port_matched`, the rule.

    Nothing here asserts on SQL text or on a fixture's idea of the traffic. The
    address is one the capture actually contacted, the port is one it actually
    reached, and the bytes are the ones the aggregate computed.
    """
    address, port = a_contacted_port(live)
    load(live, targeted(RAW, f"{address}:{port}", "ip:port"))
    projection = project(live)
    entity, claim = the_claim(projection, address)
    assert claim.port_matched is True
    assert entity.observed_bytes_sent > 0 and entity.observed_bytes_received > 0

    verdict = result(
        "malicious.c2",
        citations=(Citation(evidence_id=claim.evidence_id, stance=SUPPORTING),),
    )
    supports = supports_for(verdict, projection)
    assert [item.evidence_id for item in supports] == [claim.evidence_id]
    assert supports[0].scope_type == rule.ADDRESS_PORT_SCOPE

    decision = rule.constrain(verdict, supports)
    assert decision.outcome == rule.PERMITTED
    assert decision.permits == "malicious.c2"
    assert [gap.kind for gap in decision.gaps] == [
        rule.SHARED_INFRASTRUCTURE_UNDETERMINED
    ]


@pytest.mark.integration
def test_a_real_hit_on_a_port_the_host_never_reached_is_suspicious_at_most(
    live: psycopg.Connection,
):
    """The same address, the same traffic, a different port on the claim.

    `sql/migrations/0015_enriched_context.sql` keeps the `port_matched = false`
    row deliberately, saying the composition rule is what decides what it is
    worth. This is that decision, taken over the row the view produced.
    """
    address, port = a_contacted_port(live)
    elsewhere = 1 if port != 1 else 2
    load(live, targeted(RAW, f"{address}:{elsewhere}", "ip:port"))
    projection = project(live)
    _, claim = the_claim(projection, address)
    assert claim.port_matched is False

    verdict = result(
        "malicious.c2",
        citations=(Citation(evidence_id=claim.evidence_id, stance=SUPPORTING),),
    )
    decision = rule.constrain(verdict, supports_for(verdict, projection))
    assert decision.outcome == rule.CONSTRAINED
    assert decision.permits == rule.SUSPICIOUS
    assert [finding.rule for finding in decision.findings] == [rule.PORT_NOT_REACHED]
    assert f"{address}:{elsewhere}" in decision.findings[0].detail


@pytest.mark.integration
def test_a_real_domain_hit_is_downgraded_and_records_the_limitation(
    live: psycopg.Connection,
):
    """The honest limitation, over a name the capture really carries.

    The feeds most likely to hit list domains, so this is the common case rather
    than the corner one — and the gap is what stops a capped verdict reading as a
    verdict nothing supported.
    """
    name = live.execute(
        "SELECT entity_value FROM helena_signal_context_entities "
        "WHERE entity_type = 'domain' ORDER BY entity_value LIMIT 1"
    ).fetchone()[0]
    load(live, targeted(RAW, name, "domain"))
    projection = project(live)
    entity, claim = the_claim(projection, name)
    assert entity.entity_type == "domain"
    assert claim.port_matched is None

    verdict = result(
        "malicious.phishing",
        citations=(Citation(evidence_id=claim.evidence_id, stance=SUPPORTING),),
    )
    decision = rule.constrain(verdict, supports_for(verdict, projection))
    assert decision.outcome == rule.CONSTRAINED
    assert decision.permits == rule.SUSPICIOUS
    assert [finding.rule for finding in decision.findings] == [
        rule.NAME_CARRIES_NO_TRAFFIC
    ]
    assert [gap.kind for gap in decision.gaps] == [rule.DOMAIN_SCOPE_UNTESTABLE]


@pytest.mark.integration
def test_a_citation_the_projection_cannot_resolve_is_a_loud_failure(
    live: psycopg.Connection,
):
    """Never a dropped support: the rule's answer is a function of its input.

    `check_exchange` has already refused a citation the *rendering* did not show,
    so an unresolvable one here means the projection is not the one the request
    was built from — and a policy that ignored it would decide without evidence it
    was told about.
    """
    load(live, targeted(RAW, an_address(live), "ip:port"))
    projection = project(live)
    verdict = result(
        "malicious.c2", citations=(Citation(evidence_id=FIRST, stance=SUPPORTING),)
    )
    with pytest.raises(policy.PolicyError, match="holds no claim"):
        supports_for(verdict, projection)


def an_address(connection: psycopg.Connection) -> str:
    address, port = a_contacted_port(connection)
    return f"{address}:{port}"


# --- Escalation over a real context in a real engine -------------------------


def at_confidence(raw: bytes, entity_value: str, ioc_type: str, level: int) -> bytes:
    """`targeted`, with the entry's own confidence set to a chosen level.

    The committed extract's first entry reports 100. The threshold cases need a
    real row on the other side of `config/policy.toml`'s number, and rewriting
    the feed's `confidence_level` is the only honest way to get one — the value
    then travels the whole path, through
    `sql/migrations/0014_feed_mapping_views.sql`'s division by 100, rather than
    being asserted about.
    """
    document = json.loads(targeted(raw, entity_value, ioc_type))
    document[sorted(document)[0]][0]["confidence_level"] = level
    return json.dumps(document).encode()


@pytest.mark.integration
def test_a_real_high_confidence_hit_the_host_reached_escalates_on_its_own(
    live: psycopg.Connection,
):
    """The whole path, with no model anywhere in it.

    A capture, a feed load, the view's own `port_matched` and `confidence`, the
    thresholds the committed file carries, and a routing decision that no agent
    contributed to.
    """
    address, port = a_contacted_port(live)
    load(live, targeted(RAW, f"{address}:{port}", "ip:port"))
    projection = project(live)
    _, claim = the_claim(projection, address)
    assert claim.confidence == 1.0 and claim.port_matched is True

    escalation = rule.escalate(supports_in(projection), thresholds())
    assert escalation.escalates is True
    assert escalation.evidence_ids == (claim.evidence_id,)
    assert escalation.claims_read >= 1
    caused = escalation.candidates[0]
    assert caused.source_id == "threatfox" and caused.source_tier == rule.TIER_B
    assert caused.supports == rule.MALICIOUS
    assert [gap.kind for gap in escalation.gaps] == [
        rule.SHARED_INFRASTRUCTURE_UNDETERMINED
    ]


@pytest.mark.integration
def test_a_real_hit_below_the_configured_threshold_does_not_escalate(
    live: psycopg.Connection,
):
    """The threshold, decided over a confidence the view computed.

    50 is the feed's own second mode and it is what the extract's other domain
    entry carries; through the mapping view it is 0.5, and
    `config/policy.toml` asks for 0.80.
    """
    address, port = a_contacted_port(live)
    load(live, at_confidence(RAW, f"{address}:{port}", "ip:port", 50))
    projection = project(live)
    _, claim = the_claim(projection, address)
    assert claim.confidence == 0.5

    escalation = rule.escalate(supports_in(projection), thresholds())
    assert escalation.escalates is False
    assert escalation.evidence_ids == ()
    assert [candidate.rules for candidate in escalation.candidates] == [
        (rule.BELOW_SOURCE_THRESHOLD,)
    ]


@pytest.mark.integration
def test_a_real_hit_on_a_port_the_host_never_reached_does_not_escalate(
    live: psycopg.Connection,
):
    """Step 3 of the task, over the row the view actually produced.

    Same address, same bytes, same confidence — a port the capture did not reach.
    `concept/04` escalates a malicious classification *whose traffic
    characteristics support it*, and this one's do not.
    """
    address, port = a_contacted_port(live)
    elsewhere = 1 if port != 1 else 2
    load(live, targeted(RAW, f"{address}:{elsewhere}", "ip:port"))
    projection = project(live)
    _, claim = the_claim(projection, address)
    assert claim.port_matched is False and claim.confidence == 1.0

    escalation = rule.escalate(supports_in(projection), thresholds())
    assert escalation.escalates is False
    assert [candidate.rules for candidate in escalation.candidates] == [
        (rule.PORT_NOT_REACHED,)
    ]
    assert escalation.candidates[0].supports == rule.SUSPICIOUS


@pytest.mark.integration
def test_a_real_domain_hit_does_not_escalate_and_records_the_limitation(
    live: psycopg.Connection,
):
    """Where this will under-fire, said out loud and over real data.

    `concept/02` calls the domain scope gap the place *"that bites precisely
    where it matters most, since the feeds most likely to hit list domains"* —
    433 of the ThreatFox snapshot's entries are domains. A name carries the
    traffic of the flows that mentioned it, so the traffic clause cannot be
    satisfied for one, and the gap is what stops the quiet result reading as a
    clean one.
    """
    name = live.execute(
        "SELECT entity_value FROM helena_signal_context_entities "
        "WHERE entity_type = 'domain' ORDER BY entity_value LIMIT 1"
    ).fetchone()[0]
    load(live, targeted(RAW, name, "domain"))
    projection = project(live)
    _, claim = the_claim(projection, name)

    escalation = rule.escalate(supports_in(projection), thresholds())
    assert escalation.escalates is False
    assert [candidate.rules for candidate in escalation.candidates] == [
        (rule.NAME_CARRIES_NO_TRAFFIC,)
    ]
    assert [gap.kind for gap in escalation.gaps] == [rule.DOMAIN_SCOPE_UNTESTABLE]


@pytest.mark.integration
def test_a_context_whose_lookups_all_missed_escalates_nothing_and_says_so(
    live: psycopg.Connection,
):
    """*"Nothing escalated"* and *"there was nothing to read"* are different rows.

    `concept/instruction.md` §2 keeps `no_match` distinct from the other three at
    every layer, and a `no_match` carries no evidence identifier to cite — so it
    contributes no support and `claims_read` is what keeps the distinction
    visible. This is the case `docs/decisions/0022-the-composition-rule.md` §4
    said the composition rule could not see.
    """
    load(live, RAW)
    projection = project(live)
    assert not [
        record
        for entity in projection.entities
        for record in entity.enrichment
        if record.has_claim
    ]
    escalation = rule.escalate(supports_in(projection), thresholds())
    assert escalation.escalates is False
    assert escalation.claims_read == 0
    assert escalation.candidates == ()


@pytest.mark.integration
def test_supports_in_reads_every_claim_and_supports_for_reads_the_cited_ones(
    live: psycopg.Connection,
):
    """The two reads answer different questions, over one projection.

    `supports_for` is a function of what a model chose to cite; `supports_in` is
    a function of the store. That difference is what makes deterministic
    escalation independent, so it is asserted over a real context rather than
    argued in a docstring.
    """
    address, port = a_contacted_port(live)
    load(live, targeted(RAW, f"{address}:{port}", "ip:port"))
    projection = project(live)
    _, claim = the_claim(projection, address)

    uncited = result("normal", emitter=TRIAGE)
    assert supports_for(uncited, projection) == ()
    read = supports_in(projection)
    assert [item.evidence_id for item in read] == [claim.evidence_id]
    assert {item.stance for item in read} == {SUPPORTING}
