"""Policy v1 — the first frozen composition rule. Never edited; superseded by a `v2`.

Every rule below is one sentence of `concept/02-concepts-and-taxonomy.md`'s "The
composition rule — scope before severity", quoted beside the code it became so
the derivation can be read rather than taken. Nothing here is invented: where the
note gives no test, the absence is recorded as a gap rather than filled in with a
plausible one.

**This file is frozen the moment an assessment records `policy_version = "v1"`.**
`docs/decisions/0008-version-registry.md`: a revision is `v2` beside it, with this
left importable exactly as it was. `docs/decisions/0022-the-composition-rule.md`
carries the argument for every choice below, including the three places this
version is weaker than the note it implements.

## What a decision is, and what it is not

`constrain` returns a `Decision`: the verdict the model proposed, the verdict the
cited evidence permits, and every rule that fired with the evidence it read. It
**does not** return a verdict of its own and it does not touch the
`AgentResult` — `concept/07-principles.md` keeps inference append-only, and the
result is the record of what the model said.

`permits` is deliberately three-valued:

| `permits` | Meaning |
| --- | --- |
| the proposed path | the cited evidence can support what the model said |
| a weaker root | the evidence supports at most this, and `concept/02`'s *"emit the parent rather than guessing a child"* is why it is a bare root and not a path |
| `None` | the cited evidence supports **no** context verdict at all |

`None` is not `normal` and it is not `unknown`. It is the statement that this
evidence establishes nothing about this host, and turning that into a verdict is
a decision for whatever routes on it — this policy refuses to make it, because
both of the available answers would be a claim the evidence does not carry.

## What this version cannot test, and says so

Two of `concept/02`'s five bullets are only partly testable here, and both are
recorded as a `Gap` on the decision rather than quietly approximated:

- **The scope test works on address entities and not on domain ones.** The note
  says so itself, and calls it the place *"that bites precisely where it matters
  most, since the feeds most likely to hit list domains."* A name carries the
  traffic of the flows that *mentioned* it, not of the connection to the address
  it resolved to, so domain-only support is capped and `DOMAIN_SCOPE_UNTESTABLE`
  records why.
- **Shared infrastructure is only determinable here in one case.** A CDN, a cloud
  tenant and a shared subdomain are external facts, and nothing in this
  repository holds one: `helena.enrichment`'s registry has two feeds and neither
  says so, and the Public Suffix List is registered nowhere precisely because
  *"it makes no claim about any entity, and it can neither escalate nor
  suppress"*. What is observable is a **resolver** — an address this host reached
  on port 53 — so that case is tested and the rest is
  `SHARED_INFRASTRUCTURE_UNDETERMINED`, recorded on every verdict the absence of
  the test let through.

## The second rule: what escalates without asking the model

`escalate` is `concept/04-the-two-agents.md`'s other independent input to the
analyst, and it is in this module because it applies the same seven sentences:

> The enrichment evidence escalates on its own — **a Tier A, or a
> high-confidence Tier B, malicious classification whose traffic characteristics
> support it** — regardless of the triage verdict.

Three conditions, and each is a clause of that sentence:

| Clause | Test |
| --- | --- |
| *a Tier A, or a high-confidence Tier B* | `ESCALATING_TIERS`, and `Thresholds.for_source` for the tier the note qualifies |
| *malicious classification* | the claim's own evidence-level root |
| *whose traffic characteristics support it* | the composition rule above, per claim, through `_supported_root` |

It takes no `AgentResult` and no `Decision`. `concept/instruction.md` §2: *"a
`normal` from a model may not suppress a high-confidence match"*, and the
strongest form of that is an evaluator with nowhere for a verdict to arrive.

**Every malicious claim in the context becomes a `Candidate`**, escalating or
not, with the rules that held it back named. A record of only what escalated
would answer "why did this run the analyst" and not "why did this one not", and
the second question is the one an unexplained quiet stream raises.

Maturity: experimental — exercised by `tests/test_policy.py`. Nothing calls this
in a running pipeline, no decision has been stored, and no rule's threshold has
been calibrated against a labelled outcome, because there is no labelled corpus
(`concept/08-open-questions.md`) — which is also why `config/policy.toml`'s 0.80
is a candidate rather than a settled number. What is demonstrated is that each
rule refuses what the note says it must refuse.
"""

from __future__ import annotations

from collections.abc import Sequence

from pydantic import BaseModel, ConfigDict, NonNegativeInt, PositiveInt

from helena import taxonomy
from helena.contracts import v1 as contract
from helena.enrichment import Claim, source_diversity
from helena.policy import PolicyError, PolicyVersion, Support, Thresholds

__all__ = [
    "ADDRESS",
    "ADDRESS_PORT_SCOPE",
    "BELOW_SOURCE_THRESHOLD",
    "CONSTRAINED",
    "CONTACT_IS_NOT_COMPROMISE",
    "DOMAIN_SCOPE_UNTESTABLE",
    "ESCALATING_TIERS",
    "ESCALATION_RULES",
    "FLOW_DESTINATION",
    "FRESHNESS_ADEQUACY_UNTESTED",
    "GAP_DETAIL",
    "GAP_KINDS",
    "HOST_STATE_PATHS",
    "MALICIOUS",
    "NAME_CARRIES_NO_TRAFFIC",
    "NON_ADVERSE",
    "NORMAL",
    "NORMAL_BY_ABSENCE",
    "NO_CONFIDENCE_REPORTED",
    "OUTCOMES",
    "PERMITTED",
    "POLICY",
    "POLICY_VERSION",
    "PORT_NOT_REACHED",
    "RESOLVER_PORT",
    "RULES",
    "SEVERITY",
    "SHARED_INFRASTRUCTURE",
    "SHARED_INFRASTRUCTURE_UNDETERMINED",
    "STATUS_OK",
    "SUSPICIOUS",
    "TIER_A",
    "TIER_B",
    "TIER_DOES_NOT_ESCALATE",
    "TRAFFIC_NOT_BIDIRECTIONAL",
    "UNSUPPORTED_SEVERITY",
    "Candidate",
    "Decision",
    "Escalation",
    "Finding",
    "Gap",
    "constrain",
    "escalate",
]

#: This module's own version. `constrain` refuses a result whose
#: `versions.policy_version` is anything else -- two copies of a version constant
#: asserted equal (`concept/instruction.md` §2), and the copies here are the
#: module name and the value a row will record.
POLICY_VERSION = "v1"

# --- The severity ordering ---------------------------------------------------
#
# The three context roots that are on a scale, in `concept/02`'s own order:
# `normal` "identified legitimate service use", `suspicious` "a material risk
# signal, but malicious purpose is not established", `malicious` "known to have
# performed or supported malicious activity".
#
# **`unknown` is deliberately not here.** `concept/02`: it "means the context was
# **unassessable** ... It is deliberately distinct from `suspicious`, which means
# analysis ran and could not settle it." Unassessability is not a severity, so it
# has no place on a scale, and no rule below has a precondition that reaches it:
# an `unknown` verdict passes through this policy unconstrained, because there is
# nothing the composition rule has to say about a run that established nothing.
NORMAL = contract.NORMAL
SUSPICIOUS = "suspicious"
MALICIOUS = "malicious"
SEVERITY = {NORMAL: 0, SUSPICIOUS: 1, MALICIOUS: 2}

# --- The two outcomes --------------------------------------------------------
#
# The task's own words, and they are the whole vocabulary: either the evidence
# can support what was proposed, or it cannot and the decision says what it can
# support instead.
PERMITTED = "permitted"
CONSTRAINED = "constrained"
OUTCOMES = (PERMITTED, CONSTRAINED)

# --- The rules ---------------------------------------------------------------
#
# One identifier per rule, and the identifier is what a stored decision records.
# Named rather than numbered so that a `v2` that drops one leaves a `v1` decision
# still readable -- a number would silently mean a different rule.
NORMAL_BY_ABSENCE = "normal_is_not_established_by_absent_adverse_evidence"
UNSUPPORTED_SEVERITY = "malicious_needs_a_supporting_citation"
CONTACT_IS_NOT_COMPROMISE = "contact_is_not_compromise"
TRAFFIC_NOT_BIDIRECTIONAL = "address_support_needs_bidirectional_traffic"
PORT_NOT_REACHED = "a_port_scoped_claim_needs_the_port_the_host_reached"
NAME_CARRIES_NO_TRAFFIC = "a_name_carries_no_traffic_of_its_own"
SHARED_INFRASTRUCTURE = "shared_infrastructure_transfers_nothing_without_corroboration"

#: Every rule, in the order they are applied. The order does not change the
#: answer -- `constrain` takes the weakest permission any rule reached, and
#: `None` beats every root -- but it is the order a reader sees the findings in,
#: and it runs from the rule about `normal` to the rules about `malicious`.
RULES = (
    NORMAL_BY_ABSENCE,
    UNSUPPORTED_SEVERITY,
    CONTACT_IS_NOT_COMPROMISE,
    TRAFFIC_NOT_BIDIRECTIONAL,
    PORT_NOT_REACHED,
    NAME_CARRIES_NO_TRAFFIC,
    SHARED_INFRASTRUCTURE,
)

# --- The gaps ----------------------------------------------------------------
#
# `concept/02` calls a gap "a recorded thing the run could not see". These two
# are things the *policy* could not see, and they are the policy's own vocabulary
# rather than `helena.contracts.v1.GAP_KINDS`: none of the contract's seven kinds
# names a test that does not apply, and spelling one of them here -- `missing` is
# the tempting one -- would collapse "the lookup did not happen" into "the rule
# could not be run", which is the class of collapse `concept/instruction.md` §2
# refuses at every layer. `docs/decisions/0022-the-composition-rule.md` §5 records
# that attaching one of these to an `AgentResult` needs a contract decision.
DOMAIN_SCOPE_UNTESTABLE = "domain_scope_untestable"
SHARED_INFRASTRUCTURE_UNDETERMINED = "shared_infrastructure_undetermined"
#: The third, and it belongs to `escalate`. `concept/02` lets a tier A source
#: establish `malicious` by itself *"if scope and freshness are adequate"*. Scope
#: is tested -- that is the whole composition rule -- and **adequate** freshness
#: is not: what this version has is `status`, which says the snapshot is older
#: than the feed's own refresh interval, and no rule for what that costs. It does
#: not suppress, because `concept/02` normalization rule 3 is explicit that
#: *"removal from a feed is not exoneration"* and that delisting *may* reduce
#: confidence -- reducing it by an amount nobody has measured would be inventing
#: the threshold this gap exists to say is missing.
FRESHNESS_ADEQUACY_UNTESTED = "freshness_adequacy_untested"
GAP_KINDS = (
    DOMAIN_SCOPE_UNTESTABLE,
    SHARED_INFRASTRUCTURE_UNDETERMINED,
    FRESHNESS_ADEQUACY_UNTESTED,
)

#: What each gap means, in one place, so the sentence a decision records is the
#: frozen one rather than whichever wording the rule that raised it used.
GAP_DETAIL = {
    DOMAIN_SCOPE_UNTESTABLE: (
        "the scope test works on address entities and not on domain ones: a name "
        "carries the traffic of the flows that mentioned it -- a DNS lookup -- "
        "not of the connection to the address it resolved to. What is left is "
        "which layers observed the name, which is weaker than bytes and not "
        "nothing (concept/02)."
    ),
    SHARED_INFRASTRUCTURE_UNDETERMINED: (
        "a malicious indicator on shared infrastructure transfers nothing without "
        "corroboration, and this policy version can only recognise one kind: an "
        "address this host reached on port 53, which is a resolver. A CDN, a "
        "cloud tenant and a shared subdomain are external facts no source in this "
        "deployment supplies, so the test was not run over the support that let "
        "this verdict stand (concept/02)."
    ),
    FRESHNESS_ADEQUACY_UNTESTED: (
        "a tier A source may establish malicious by itself where scope and "
        "freshness are adequate, and this version tests scope only. A claim here "
        "matched a snapshot the feed has already replaced, which is recorded as "
        "its status and does not suppress it: removal from a feed is not "
        "exoneration, and how much a delisting should reduce confidence is a "
        "number nobody has measured (concept/02)."
    ),
}

# --- Vocabulary the rules read -----------------------------------------------

#: The observation layer that means the host actually sent packets to the entity.
#: A second copy of the name `helena.rendering.OBSERVATION_LAYERS` produces, and
#: `tests/test_policy.py` asserts the two equal -- two copies that can drift are
#: worse than none (`concept/instruction.md` §2). It is copied rather than
#: imported because a frozen version may not depend on a constant the rendering
#: package is free to change.
FLOW_DESTINATION = "flow_destination"

#: The entity type the scope test works on. `concept/02` names it: *"The scope
#: test works on **address** entities and not on **domain** ones."*
ADDRESS = "address"

#: The scope a port-qualified indicator carries, from
#: `sql/migrations/0014_feed_mapping_views.sql`. An `ip:port` claim is about the
#: address *on that port*, and `port_matched` is what says whether the host went
#: there.
ADDRESS_PORT_SCOPE = "address:port"

#: The evidence-level roots that are not adverse. `concept/02`: `no_match` is
#: *"a lookup outcome, never a statement of safety"* and `normal` is
#: *"affirmatively known to support harmless activity at that scope and time"* --
#: and neither of them, on a contacted indicator, establishes `normal` for the
#: context.
NON_ADVERSE = ("normal", "no_match")

#: The context paths that assert something about **the host itself** rather than
#: about something it contacted. `concept/02`'s malicious family reads as
#: "contacted C2, retrieved a payload, reached phishing infrastructure (**a
#: targeted user, not necessarily a compromised host**), conducted hostile
#: activity itself, sent spam, exfiltrated, or shows confirmed compromise" -- the
#: first three are contact and the last four are the host acting or being
#: compromised.
#:
#: This is where the phishing sentence lands. `malicious.phishing` is a *contact*
#: path and survives this rule; `malicious.compromised` does not, because a
#: phishing domain contacted means the user was targeted and not that the host is
#: compromised, and no enrichment claim is about the host at all.
HOST_STATE_PATHS = (
    "malicious.compromised",
    "malicious.hostile",
    "malicious.spam",
    "malicious.exfiltration",
)

# --- The escalation vocabulary -----------------------------------------------
#
# `concept/02`'s tier table, as the two letters this version reads. Copied rather
# than imported from `helena.enrichment.Tier` for the reason `FLOW_DESTINATION`
# is copied -- a frozen version may not depend on a constant another package is
# free to change -- and `tests/test_policy.py` asserts the two sets equal.
TIER_A = "A"
TIER_B = "B"

#: The enrichment status that means the snapshot the claim matched was still the
#: one the feed publishes. A second copy of `helena.enrichment.OK`, copied for the
#: reason `FLOW_DESTINATION` is and asserted equal by `tests/test_policy.py`.
#: Anything else is a claim whose freshness this version records and does not
#: weigh — `FRESHNESS_ADEQUACY_UNTESTED`.
STATUS_OK = "ok"

#: The tiers `concept/04` lets escalate at all: *"a Tier A, or a high-confidence
#: Tier B, malicious classification"*. C is "normally `suspicious`" and D is
#: "context only", and neither reaches the question.
ESCALATING_TIERS = (TIER_A, TIER_B)

#: The two reasons a claim never reaches the traffic test. Named beside the
#: composition rules because an escalation record names both kinds in one list,
#: and a reader asking why a hit did not escalate should not have to know which
#: half of the policy refused it.
TIER_DOES_NOT_ESCALATE = "the_tier_does_not_escalate_independently"
BELOW_SOURCE_THRESHOLD = "below_the_source_s_confidence_threshold"
NO_CONFIDENCE_REPORTED = "no_confidence_reported_where_the_tier_needs_one"

#: Every rule an escalation can name, in the order they are applied. The first
#: three are this rule's own and the rest are the composition rule's, applied to
#: one claim rather than to a verdict -- the same rules, because a hit whose
#: traffic does not support a `malicious` verdict does not support a `malicious`
#: escalation either, and two copies under one `policy_version` would drift.
ESCALATION_RULES = (
    TIER_DOES_NOT_ESCALATE,
    NO_CONFIDENCE_REPORTED,
    BELOW_SOURCE_THRESHOLD,
    TRAFFIC_NOT_BIDIRECTIONAL,
    PORT_NOT_REACHED,
    NAME_CARRIES_NO_TRAFFIC,
    SHARED_INFRASTRUCTURE,
)

#: The port that makes an address a resolver for this host. IANA's, and observed
#: rather than looked up: `helena_signal_context_entity_ports` records the
#: destination ports the host actually reached, so "this host used that address
#: as a resolver" is a fact about this capture and not an external claim about
#: the address.
RESOLVER_PORT = 53

_POLICY_MODEL_CONFIG = ConfigDict(
    strict=True,
    extra="forbid",
    frozen=True,
    hide_input_in_errors=True,
)


def _bounded(text: str) -> str:
    """A recorded reason is a sentence. The bound is the contract's, for its reason."""
    limit = contract.MAX_DETAIL
    return text if len(text) <= limit else text[: limit - 1] + "…"


class Gap(BaseModel):
    """A thing the composition rule could not test, recorded as an outcome.

    First-class, because `concept/02` states both of them as limitations of the
    rule itself rather than as accidents of an implementation, and a limitation
    that lives only in a docstring is one a later reader takes for a solved
    problem.
    """

    model_config = _POLICY_MODEL_CONFIG

    kind: str
    detail: str

    def model_post_init(self, _context: object) -> None:
        if self.kind not in GAP_KINDS:
            raise ValueError(f"gap kind {self.kind!r} is not one of {list(GAP_KINDS)}")
        if not self.detail.strip():
            raise ValueError("a gap with no detail records that something was untested "
                             "without recording what")


class Finding(BaseModel):
    """One rule that fired: what it permits, why, and the evidence it read.

    A finding exists only where a rule *constrained* something. A rule that
    passed produces nothing — a record saying "this rule had no objection" would
    be a row per rule per assessment, and the question anyone asks of a stored
    decision is which rule cut it down.
    """

    model_config = _POLICY_MODEL_CONFIG

    rule: str
    #: The most this rule permits: a context root, or `None` for "this evidence
    #: establishes nothing". Never a path — see the module docstring.
    permits: str | None
    detail: str
    #: The evidence identifiers this rule read. Empty where the rule fired on the
    #: *absence* of a support.
    evidence_ids: tuple[str, ...] = ()
    #: The gap this finding records, or empty where it records none.
    gap: str = ""

    def model_post_init(self, _context: object) -> None:
        if self.rule not in RULES:
            raise ValueError(f"rule {self.rule!r} is not one of {list(RULES)}")
        if self.permits is not None and self.permits not in SEVERITY:
            raise ValueError(
                f"a rule permits at most a root on the severity scale "
                f"{sorted(SEVERITY)}, and this one permits {self.permits!r}"
            )
        if not self.detail.strip():
            raise ValueError(f"{self.rule}: a finding with no detail says nothing")
        if self.gap and self.gap not in GAP_KINDS:
            raise ValueError(f"gap kind {self.gap!r} is not one of {list(GAP_KINDS)}")


class Decision(BaseModel):
    """What the composition rule permits this verdict to be read as.

    Stored beside an assessment, never in place of one: `proposed` is what the
    model said and stays exactly that, and `permits` is what the cited evidence
    can carry. Two records rather than one, because
    `concept/07-principles.md` appends inference and never overwrites a fact, and
    because an evaluation that could not tell a model's answer from a policy's
    correction of it would be measuring the wrong thing.
    """

    model_config = _POLICY_MODEL_CONFIG

    #: The policy version that decided. `POLICY_VERSION`, always — a decision
    #: recording another version would be replayed against rules it never ran.
    policy_version: str
    #: The taxonomy version `permits` was resolved against, from the result.
    taxonomy_version: str
    emitter: str
    proposed: str
    outcome: str
    permits: str | None
    findings: tuple[Finding, ...] = ()
    gaps: tuple[Gap, ...] = ()

    def model_post_init(self, _context: object) -> None:
        if self.policy_version != POLICY_VERSION:
            raise ValueError(
                f"this is policy {POLICY_VERSION!r} and the decision records "
                f"{self.policy_version!r}"
            )
        if self.outcome not in OUTCOMES:
            raise ValueError(f"outcome {self.outcome!r} is not one of {list(OUTCOMES)}")
        if (self.outcome == PERMITTED) != (self.permits == self.proposed):
            raise ValueError(
                f"the decision is {self.outcome!r} and permits {self.permits!r} "
                f"against a proposed {self.proposed!r}. {PERMITTED!r} means the "
                f"proposal stands unchanged and {CONSTRAINED!r} means it does not; "
                f"a decision that said one and did the other would be unreadable."
            )
        if self.outcome == CONSTRAINED and not self.findings:
            raise ValueError(
                "a constrained decision names the rule that constrained it; a "
                "constraint nobody can attribute is a policy that cannot be argued "
                "with"
            )
        if self.outcome == PERMITTED and self.findings:
            raise ValueError(
                f"the decision permits {self.proposed!r} and carries findings "
                f"{[finding.rule for finding in self.findings]}; a rule that fired "
                f"constrained something"
            )


def constrain(
    result: contract.AgentResult, supports: Sequence[Support]
) -> Decision:
    """Apply the composition rule to one verdict and the evidence cited for it.

    The three inputs `concept/02` requires are the verdict (`result.classification`),
    the cited evidence and the per-entity traffic — the last two fused into one
    `Support` per citation by `helena.policy.supports_for`, because *"a row
    carrying only a classification cannot tell those cases apart"*.

    Raises `PolicyError` for the things that are the caller's fault: a result
    recording another policy version, and a support list that is not this
    result's citations. Neither is a verdict the rule could constrain — a policy
    handed a partial support list would return an answer that looks like a
    decision and was taken without half the evidence.
    """
    if result.versions.policy_version != POLICY_VERSION:
        raise PolicyError(
            f"this is policy {POLICY_VERSION!r} and the result records "
            f"policy_version {result.versions.policy_version!r}. A stored "
            f"assessment is re-constrained against the rules it recorded, so "
            f"applying these to it would score it against a policy it never ran."
        )
    cited = {citation.evidence_id for citation in result.citations}
    given = {support.evidence_id for support in supports}
    if cited != given:
        raise PolicyError(
            f"the result cites {sorted(cited)} and the supports resolve "
            f"{sorted(given)}. The rule's answer is a function of exactly the "
            f"cited evidence, so a support list that is not it decides a different "
            f"question."
        )

    proposed = result.classification
    root = result.root
    supporting = tuple(
        support for support in supports if support.stance == contract.SUPPORTING
    )
    findings = tuple(
        finding
        for rule in _RULE_FUNCTIONS
        if (finding := rule(proposed, root, supporting)) is not None
    )
    permits = _permitted(proposed, root, findings)
    if permits is not None and permits != proposed:
        # The constrained verdict has to be one this emitter could have given
        # under the version the result recorded. A cap the taxonomy refuses would
        # be the policy inventing a label.
        taxonomy.for_emission(
            permits,
            level=taxonomy.CONTEXT,
            version=result.versions.taxonomy_version,
            emitter=result.emitter,
        )
    return Decision(
        policy_version=POLICY_VERSION,
        taxonomy_version=result.versions.taxonomy_version,
        emitter=result.emitter,
        proposed=proposed,
        outcome=PERMITTED if permits == proposed else CONSTRAINED,
        permits=permits,
        findings=findings,
        gaps=_gaps(permits, findings),
    )


def _permitted(
    proposed: str, root: str, findings: tuple[Finding, ...]
) -> str | None:
    """The weakest permission any rule reached, and `None` beats every root.

    A rule that permits nothing has said the evidence establishes nothing, and no
    other rule's ceiling can put that back. Otherwise the ceiling is the lowest
    severity reached, and it only changes the answer when the proposal is above
    it: a rule capping at `suspicious` leaves `suspicious.low_reputation` exactly
    where it was.
    """
    if not findings:
        return proposed
    if any(finding.permits is None for finding in findings):
        return None
    ceiling = min(
        (finding.permits for finding in findings), key=lambda root_: SEVERITY[root_]
    )
    return ceiling if SEVERITY[root] > SEVERITY[ceiling] else proposed


def _gaps(permits: str | None, findings: tuple[Finding, ...]) -> tuple[Gap, ...]:
    """The tests that did not run, recorded once each and in `GAP_KINDS` order.

    Two sources: a rule that fired and knows it was working around a limitation,
    and the one limitation that shows up when **no** rule fired — a `malicious`
    verdict that survives has survived a shared-infrastructure test this version
    could only run for a resolver, and that is worth recording exactly where it
    changed nothing visible.
    """
    kinds = {finding.gap for finding in findings if finding.gap}
    if permits is not None and permits.split(".")[0] == MALICIOUS:
        kinds.add(SHARED_INFRASTRUCTURE_UNDETERMINED)
    return tuple(
        Gap(kind=kind, detail=GAP_DETAIL[kind]) for kind in GAP_KINDS if kind in kinds
    )


# --- The rules, one function each --------------------------------------------
#
# Every one takes the proposed path, its root and the **supporting** citations,
# and returns a `Finding` where it constrains and `None` where it does not. A
# contradicting citation is evidence *against* the verdict and is deliberately
# not read here: `concept/02` writes the rule as what evidence can *support* what
# verdict, and a rule that treated a contradiction as support would be reading a
# citation's stance backwards.


def _contacted_with_traffic_both_ways(support: Support) -> bool:
    """`concept/02`'s "actual bidirectional traffic", as a predicate.

    All three conditions, because dropping any one of them is a case the note
    names: the host has to have been a flow destination (rather than only having
    resolved the name), and bytes have to have gone **both** ways — *"the same hit
    with one failed connection and no bytes returned"* is a connection attempt
    with a non-zero sent count and a zero received one.
    """
    return (
        FLOW_DESTINATION in support.observed_layers
        and support.observed_bytes_sent > 0
        and support.observed_bytes_received > 0
    )


def _is_shared_infrastructure(support: Support) -> bool:
    """The one shared-infrastructure case this version can determine: a resolver.

    `concept/02` lists four — *"a CDN, a cloud tenant, a resolver, a shared
    subdomain"* — and three of them are external facts about the address or the
    name that no source in this deployment supplies. A resolver is not: the host
    reached this address on port 53, which is in the capture.
    """
    return support.entity_type == ADDRESS and RESOLVER_PORT in support.ports


def _normal_by_absence(
    proposed: str, root: str, supporting: tuple[Support, ...]
) -> Finding | None:
    """*"`normal` on contacted indicators never establishes `normal` for the context."*

    `concept/02`, in full: *"never establishes `normal` for the context **on its
    own**: coverage is sparse, and absence of adverse evidence is not evidence of
    absence."* On its own is the operative phrase and it is why this reads every
    supporting citation: one adverse claim among them and the verdict rests on
    something else, which this rule has nothing to say about.

    **A `normal` with no citations at all is not this case.** `concept/04` makes
    an uncited `normal` triage decision the cheap common path, and a model that
    called a window ordinary on its traffic has not cited a clean indicator as its
    reason. The failure this rule is named for — reading a context of nothing but
    `no_match` as a clean bill of health — is *not* visible from citations, because
    a `no_match` carries no evidence identifier to cite; it is the escalation
    evaluator's to catch, and `docs/decisions/0022-the-composition-rule.md` §4
    says so rather than letting this rule look like it covers it.
    """
    if root != NORMAL or not supporting:
        return None
    if any(support.classification not in NON_ADVERSE for support in supporting):
        return None
    return Finding(
        rule=NORMAL_BY_ABSENCE,
        permits=None,
        detail=_bounded(
            f"{proposed!r} is cited entirely from evidence-level "
            f"{sorted({support.classification for support in supporting})}, and "
            f"`normal` on contacted indicators never establishes `normal` for the "
            f"context on its own: coverage is sparse, and absence of adverse "
            f"evidence is not evidence of absence."
        ),
        evidence_ids=tuple(support.evidence_id for support in supporting),
    )


def _unsupported_severity(
    proposed: str, root: str, supporting: tuple[Support, ...]
) -> Finding | None:
    """A `malicious` verdict with nothing supporting it composes nothing.

    The contract already requires a citation on it, so this is the case where
    every citation is `contradicting`: the model named evidence it was arguing
    *against* and called the context malicious anyway. There is no cited evidence
    for the rule to weigh, so there is nothing that could support the verdict.

    **Not extended to `suspicious`**, and that is a decision rather than an
    oversight. `suspicious` is *"a material risk signal, but malicious purpose is
    not established"*, and a model may reach it from the traffic rather than from
    a claim — `concept/02` puts anomalous volume and periodicity in that family.
    Requiring a supporting claim there would refuse a verdict the vocabulary
    supports.
    """
    if root != MALICIOUS or supporting:
        return None
    return Finding(
        rule=UNSUPPORTED_SEVERITY,
        permits=None,
        detail=_bounded(
            f"{proposed!r} is cited by nothing that supports it. An evidence-level "
            f"classification about a contacted indicator does not become the "
            f"context verdict, and here there is not even one to compose from."
        ),
    )


def _contact_is_not_compromise(
    proposed: str, root: str, supporting: tuple[Support, ...]
) -> Finding | None:
    """A phishing domain contacted means the user was targeted, not that the host is compromised.

    `concept/02`, verbatim. Generalised to the shape the taxonomy already has:
    `HOST_STATE_PATHS` are the four paths that assert something about the host
    itself, and every enrichment claim is about an indicator the host *contacted*.
    So contact can reach `malicious.phishing` — the path whose own gloss is *"a
    targeted user, not necessarily a compromised host"* — and cannot reach
    `malicious.compromised`, which is the sentence this rule is.

    The cap is `suspicious` rather than the contact path the evidence would
    support, because naming one would mean deciding *which* kind of contact this
    was, and `concept/02`'s syntax rule is to *"emit the parent rather than
    guessing a child"*.
    """
    if proposed not in HOST_STATE_PATHS or not supporting:
        return None
    return Finding(
        rule=CONTACT_IS_NOT_COMPROMISE,
        permits=SUSPICIOUS,
        detail=_bounded(
            f"{proposed!r} is a statement about this host, and it is cited from "
            f"{len(supporting)} claim(s) about indicators the host contacted. A "
            f"phishing domain contacted means the user was targeted, not that the "
            f"host is compromised; no enrichment-tier claim is about the host at "
            f"all."
        ),
        evidence_ids=tuple(support.evidence_id for support in supporting),
    )


def _traffic_not_bidirectional(
    proposed: str, root: str, supporting: tuple[Support, ...]
) -> Finding | None:
    """*"The same hit with one failed connection and no bytes returned does not."*

    `concept/02`: *"A C2 hit on a contacted address **with actual bidirectional
    traffic** supports `malicious.c2` for the host. The same hit with one failed
    connection and no bytes returned does not. That is `suspicious` at most, and
    possibly a host that resolved a name and gave up."*

    Fires only where there **is** address support — the case with none at all is
    `_name_carries_no_traffic` below, and the two are kept apart because the
    reason a reader needs is different: one is a connection that did not carry
    data, the other is a scope the test does not work on.
    """
    if root != MALICIOUS:
        return None
    addresses = tuple(
        support for support in supporting if support.entity_type == ADDRESS
    )
    if not addresses or any(map(_contacted_with_traffic_both_ways, addresses)):
        return None
    return Finding(
        rule=TRAFFIC_NOT_BIDIRECTIONAL,
        permits=SUSPICIOUS,
        detail=_bounded(
            f"{proposed!r} is supported by {len(addresses)} address claim(s) and "
            f"none of them is an address this host contacted with bytes in both "
            f"directions. That is `suspicious` at most, and possibly a host that "
            f"resolved a name and gave up."
        ),
        evidence_ids=tuple(support.evidence_id for support in addresses),
    )


def _port_not_reached(
    proposed: str, root: str, supporting: tuple[Support, ...]
) -> Finding | None:
    """Scope before severity, in its narrowest form: the claim is about a port the host never used.

    An `ip:port` indicator is a claim about the address **on that port**
    (`sql/migrations/0014_feed_mapping_views.sql`), and
    `helena_analytical_enriched_context` computes `port_matched` and deliberately
    does not filter on it: *"a false row is kept, because `concept/02` says that
    hit is suspicious at most rather than nothing at all, and filtering it would
    be the view making the composition rule's decision."* This is that decision,
    made where the traffic is.

    Fires only where the traffic *would* otherwise have supported the verdict, so
    it and `_traffic_not_bidirectional` never both fire: they are the two ways
    address support fails, and a decision naming both would say the connection
    both happened and did not.
    """
    if root != MALICIOUS:
        return None
    carried = tuple(
        support
        for support in supporting
        if support.entity_type == ADDRESS and _contacted_with_traffic_both_ways(support)
    )
    if not carried:
        return None
    mismatched = tuple(support for support in carried if support.port_matched is False)
    if len(mismatched) != len(carried):
        return None
    return Finding(
        rule=PORT_NOT_REACHED,
        permits=SUSPICIOUS,
        detail=_bounded(
            "every address claim supporting this verdict is scoped to a port this "
            "host did not reach — "
            + ", ".join(sorted({support.scope_value for support in mismatched}))
            + ". The traffic is real and it is not the traffic the claim is about."
        ),
        evidence_ids=tuple(support.evidence_id for support in mismatched),
    )


def _name_carries_no_traffic(
    proposed: str, root: str, supporting: tuple[Support, ...]
) -> Finding | None:
    """The honest limitation, as a rule rather than as a footnote.

    `concept/02`: *"The scope test works on **address** entities and not on
    **domain** ones, because a name carries the traffic of the flows that
    *mentioned* it — a DNS lookup — not of the connection to the address it
    resolved to. That bites precisely where it matters most, since the feeds most
    likely to hit list domains."*

    So a `malicious` verdict supported by no address claim at all is capped, and
    the reason is recorded as a gap rather than left implicit. The layers that
    observed the names go in the detail, because they are what remains: *"a name
    in TLS SNI was connected to, where a name seen only in a DNS query may never
    have been. Weaker than bytes, and not nothing."*
    """
    if root != MALICIOUS or not supporting:
        return None
    if any(support.entity_type == ADDRESS for support in supporting):
        return None
    observed = sorted(
        {layer for support in supporting for layer in support.observed_layers}
    )
    return Finding(
        rule=NAME_CARRIES_NO_TRAFFIC,
        permits=SUSPICIOUS,
        detail=_bounded(
            f"{proposed!r} is supported only by claims about "
            f"{sorted({support.entity_type for support in supporting})} entities, "
            f"which carry the traffic of the flows that mentioned them and not of "
            f"the connection they name. What is observed of them is "
            f"{observed}: weaker than bytes, and not nothing."
        ),
        evidence_ids=tuple(support.evidence_id for support in supporting),
        gap=DOMAIN_SCOPE_UNTESTABLE,
    )


def _shared_infrastructure(
    proposed: str, root: str, supporting: tuple[Support, ...]
) -> Finding | None:
    """*"A malicious indicator on shared infrastructure transfers nothing without corroboration."*

    `concept/02`, and the corroboration is what the condition below is: a
    supporting claim that is **not** on shared infrastructure is the corroboration,
    so the rule fires only where every one of them is. It permits nothing rather
    than capping, because the note's word is *transfers nothing* — not "transfers
    less".

    What counts as shared is `_is_shared_infrastructure`, and this version can
    only see one of the note's four cases. The other three are recorded as
    `SHARED_INFRASTRUCTURE_UNDETERMINED` on any verdict this rule let through.
    """
    if root != MALICIOUS or not supporting:
        return None
    if not all(map(_is_shared_infrastructure, supporting)):
        return None
    return Finding(
        rule=SHARED_INFRASTRUCTURE,
        permits=None,
        detail=_bounded(
            f"every claim supporting {proposed!r} is about infrastructure this "
            f"host used as a resolver (port {RESOLVER_PORT}), and nothing else "
            f"corroborates it. A malicious indicator on shared infrastructure "
            f"transfers nothing to the host without corroboration."
        ),
        evidence_ids=tuple(support.evidence_id for support in supporting),
    )


#: The rule functions, in `RULES` order. A tuple and not a dict, because the
#: order is the order findings are recorded in and a mapping would make it
#: incidental.
_RULE_FUNCTIONS = (
    _normal_by_absence,
    _unsupported_severity,
    _contact_is_not_compromise,
    _traffic_not_bidirectional,
    _port_not_reached,
    _name_carries_no_traffic,
    _shared_infrastructure,
)


# --- Deterministic escalation ------------------------------------------------
#
# `concept/04`'s second independent input, and `concept/03`'s routing `if`:
#
#     if evidence escalates independently (tier A, or tier B above threshold):
#         run_analyst(trigger="deterministic_signal")   # independent of triage
#
# The record below is the left-hand side of that line, computed from the store.


class Candidate(BaseModel):
    """One malicious claim in the context, and what the policy made of it.

    Every malicious claim becomes one of these, escalating or not. A record of
    only the escalating ones would answer *why did this run the analyst* and not
    *why did this one not*, and the second question is the one an unexplained
    quiet stream raises — the failure mode `concept/07-principles.md` calls
    "triage returning `normal` suppresses a Tier A match" looks exactly like a
    context with no candidates until somebody can see the candidates.
    """

    model_config = _POLICY_MODEL_CONFIG

    #: What a caller cites this escalation by. `concept/04` requires an evidence
    #: identifier on every enriched value, and this is the one the claim carries.
    evidence_id: str
    entity_type: str
    entity_value: str
    source_id: str
    source_tier: str
    #: The source's own number, `None` where it reported none. Not a routing
    #: constant (`concept/04`) — it is compared against configured policy and the
    #: comparison is recorded.
    confidence: float | None
    #: `ok` or `stale`. Carried because the freshness clause is untested here and
    #: a gap that could not name the claim it was about would be a footnote.
    status: str
    #: The strongest context root this claim's traffic and scope support, by the
    #: composition rule above: `malicious`, `suspicious`, or `None` for evidence
    #: that transfers nothing. Never a path — the evidence taxonomy is roots-only
    #: and naming a child would be inventing the reason.
    supports: str | None
    escalates: bool
    #: Every rule that held it back, in `ESCALATION_RULES` order. Empty exactly
    #: where it escalates.
    rules: tuple[str, ...]
    #: How many independent sources make a malicious claim about this entity,
    #: counted by `helena.enrichment.source_diversity` — so an aggregator's
    #: republications are one vote and one source's forty rows are one vote.
    independent_sources: PositiveInt
    detail: str
    gap: str = ""

    def model_post_init(self, _context: object) -> None:
        outside = [name for name in self.rules if name not in ESCALATION_RULES]
        if outside:
            raise ValueError(f"{outside} are not among {list(ESCALATION_RULES)}")
        if list(self.rules) != sorted(self.rules, key=ESCALATION_RULES.index):
            raise ValueError(
                f"{list(self.rules)} is not in ESCALATION_RULES order; the order "
                f"is what a reader sees them in and a decision that recorded them "
                f"in another one would read as a different sequence of tests"
            )
        if self.escalates != (not self.rules):
            raise ValueError(
                f"{self.evidence_id} escalates={self.escalates} with rules "
                f"{list(self.rules)}. A claim escalates exactly where no rule held "
                f"it back; a candidate that said one and did the other could not "
                f"be argued with."
            )
        if self.supports is not None and self.supports not in SEVERITY:
            raise ValueError(
                f"a claim supports at most a root on the severity scale "
                f"{sorted(SEVERITY)}, and this one supports {self.supports!r}"
            )
        if self.escalates and self.supports != MALICIOUS:
            raise ValueError(
                f"{self.evidence_id} escalates and its traffic supports "
                f"{self.supports!r}. `concept/04` escalates a malicious "
                f"classification *whose traffic characteristics support it*."
            )
        if not self.detail.strip():
            raise ValueError(f"{self.evidence_id}: a candidate with no detail says nothing")
        if self.gap and self.gap not in GAP_KINDS:
            raise ValueError(f"gap kind {self.gap!r} is not one of {list(GAP_KINDS)}")


class Escalation(BaseModel):
    """Whether the evidence escalates on its own, and which evidence did it.

    Stored beside an assessment and computed whether or not there is one:
    `concept/04` makes this input independent of whether triage ran at all, so an
    escalation for a context whose triage produced a typed failure is the normal
    case and not an edge one.
    """

    model_config = _POLICY_MODEL_CONFIG

    #: The rules that decided. `POLICY_VERSION`, always.
    policy_version: str
    #: The revision of `config/policy.toml` whose numbers decided. `v1` is frozen
    #: and the file is not, so an escalation recording only the policy version
    #: could not be replayed against the threshold that actually applied.
    thresholds_version: str
    escalates: bool
    #: The evidence ids that caused it, in the order the claims were read. Empty
    #: exactly where nothing escalated.
    evidence_ids: tuple[str, ...]
    #: Every claim that was read at all, whether or not it was malicious. So
    #: "nothing escalated" and "there was nothing to read" are different rows.
    claims_read: NonNegativeInt
    candidates: tuple[Candidate, ...] = ()
    gaps: tuple[Gap, ...] = ()

    def model_post_init(self, _context: object) -> None:
        if self.policy_version != POLICY_VERSION:
            raise ValueError(
                f"this is policy {POLICY_VERSION!r} and the escalation records "
                f"{self.policy_version!r}"
            )
        if not self.thresholds_version.strip():
            raise ValueError(
                "an escalation records which threshold revision decided it; "
                "without one the number that escalated is not recoverable"
            )
        caused = tuple(
            candidate.evidence_id
            for candidate in self.candidates
            if candidate.escalates
        )
        if self.evidence_ids != caused:
            raise ValueError(
                f"the escalation names {list(self.evidence_ids)} and its candidates "
                f"escalate {list(caused)}. The identifiers are what a caller cites, "
                f"so a list that is not the escalating candidates cites evidence "
                f"that did not do it."
            )
        if self.escalates != bool(self.evidence_ids):
            raise ValueError(
                f"escalates={self.escalates} with {len(self.evidence_ids)} "
                f"evidence ids. An escalation nobody can attribute is a routing "
                f"decision that cannot be argued with."
            )
        if self.claims_read < len(self.candidates):
            raise ValueError(
                f"{len(self.candidates)} candidates out of {self.claims_read} "
                f"claims read; a candidate is one of the claims"
            )


def escalate(supports: Sequence[Support], thresholds: Thresholds) -> Escalation:
    """What the evidence escalates on its own, regardless of any triage verdict.

    `concept/04`: *"The enrichment evidence escalates on its own — a Tier A, or a
    high-confidence Tier B, malicious classification whose traffic characteristics
    support it — regardless of the triage verdict. An LLM returning `normal` may
    not bury a high-confidence match."*

    `supports` is every claim the context holds, from
    `helena.policy.supports_in`. **There is no parameter a verdict could arrive
    through, and that is the invariant rather than an omission** — an evaluator
    that took the triage result "to skip work when triage already said `normal`"
    would be the suppression `concept/instruction.md` §2 forbids, written as an
    optimisation.

    Raises `PolicyError` for the one thing that is the caller's fault: a threshold
    set written for another policy version. Applying it here would escalate on a
    number chosen for rules it was not written for.
    """
    if thresholds.policy_version != POLICY_VERSION:
        raise PolicyError(
            f"this is policy {POLICY_VERSION!r} and the thresholds record "
            f"policy_version {thresholds.policy_version!r}. A threshold is the "
            f"number one version's rules read, so applying it here would escalate "
            f"on a value chosen for rules that are not these."
        )
    adverse = tuple(
        support for support in supports if _root(support.classification) == MALICIOUS
    )
    diversity = _independent_sources(adverse)
    candidates = tuple(
        _candidate(support, adverse, thresholds, diversity) for support in adverse
    )
    caused = tuple(
        candidate.evidence_id for candidate in candidates if candidate.escalates
    )
    return Escalation(
        policy_version=POLICY_VERSION,
        thresholds_version=thresholds.thresholds_version,
        escalates=bool(caused),
        evidence_ids=caused,
        claims_read=len(supports),
        candidates=candidates,
        gaps=_escalation_gaps(bool(caused), candidates),
    )


def _root(classification: str) -> str:
    return classification.split(".")[0]


def _independent_sources(adverse: Sequence[Support]) -> dict[tuple[str, str], int]:
    """How many independent sources call each entity malicious.

    `concept/02` normalization rule 2, and it is counted by
    `helena.enrichment.source_diversity` rather than re-implemented here: *"Do not
    double-count correlated sources. Evidence copied through an aggregator is not
    an independent vote; retain the origin and count source diversity. **An
    aggregator is never counted as many votes.**"*

    So the count is over who the evidence is *from*, and one source's forty rows
    about one address are one. **Nothing in this version raises a threshold on
    it**: `concept/04` conditions independent escalation on the tier and the
    source's own confidence and on nothing else, and a corroboration rule that
    lifted a below-threshold claim would be inventing a requirement
    (`concept/instruction.md` §4). The number is recorded because a count that is
    right is what stops a later increment reading rows as votes.
    """
    grouped: dict[tuple[str, str], list[Claim]] = {}
    for support in adverse:
        key = (support.entity_type, support.entity_value)
        grouped.setdefault(key, []).append(
            Claim(
                source_id=support.source_id,
                entity_type=support.entity_type,
                entity_value=support.entity_value,
                path=support.classification,
            )
        )
    return {key: source_diversity(claims) for key, claims in grouped.items()}


def _supported_root(
    support: Support, adverse: Sequence[Support]
) -> tuple[str | None, tuple[str, ...], str, str]:
    """The composition rule, applied to one claim: root, rules, detail, gap.

    The same four predicates `constrain` applies to a verdict, in the same order
    and reading the same helpers — *"a hit whose traffic does not support it does
    not escalate as `malicious`"* is the same sentence as *"the same hit with one
    failed connection and no bytes returned does not"*, asked of one claim rather
    than of a citation set.

    Corroboration for the shared-infrastructure case is read across the whole
    context, which is this rule's analogue of `constrain` reading it across the
    citation set: a malicious claim about something that is *not* shared
    infrastructure is what stops a resolver hit transferring nothing.
    """
    if support.entity_type != ADDRESS:
        return (
            SUSPICIOUS,
            (NAME_CARRIES_NO_TRAFFIC,),
            f"a {support.entity_type} carries the traffic of the flows that "
            f"mentioned it and not of the connection it names; what is observed "
            f"of it is {list(support.observed_layers)}, which is weaker than "
            f"bytes and not nothing",
            DOMAIN_SCOPE_UNTESTABLE,
        )
    corroborated = any(
        other.evidence_id != support.evidence_id
        and not _is_shared_infrastructure(other)
        for other in adverse
    )
    if _is_shared_infrastructure(support) and not corroborated:
        return (
            None,
            (SHARED_INFRASTRUCTURE,),
            f"this host used {support.entity_value} as a resolver (port "
            f"{RESOLVER_PORT}) and nothing else corroborates the claim; a "
            f"malicious indicator on shared infrastructure transfers nothing to "
            f"the host without corroboration",
            "",
        )
    if not _contacted_with_traffic_both_ways(support):
        return (
            SUSPICIOUS,
            (TRAFFIC_NOT_BIDIRECTIONAL,),
            f"the host did not exchange bytes in both directions with "
            f"{support.entity_value} — sent {support.observed_bytes_sent}, "
            f"received {support.observed_bytes_received}, observed by "
            f"{list(support.observed_layers)}. That is suspicious at most, and "
            f"possibly a host that resolved a name and gave up",
            "",
        )
    if support.port_matched is False:
        return (
            SUSPICIOUS,
            (PORT_NOT_REACHED,),
            f"the claim is scoped to {support.scope_value}, a port this host did "
            f"not reach. The traffic is real and it is not the traffic the claim "
            f"is about",
            "",
        )
    return (
        MALICIOUS,
        (),
        f"the host exchanged bytes in both directions with {support.entity_value} "
        f"and the claim's scope {support.scope_value!r} is the traffic that "
        f"happened",
        "",
    )


def _candidate(
    support: Support,
    adverse: Sequence[Support],
    thresholds: Thresholds,
    diversity: dict[tuple[str, str], int],
) -> Candidate:
    """One malicious claim, weighed against the tier, the threshold and the traffic."""
    supported, rules, detail, gap = _supported_root(support, adverse)
    tier_rules: tuple[str, ...] = ()
    if support.source_tier not in ESCALATING_TIERS:
        tier_rules = (TIER_DOES_NOT_ESCALATE,)
        detail = (
            f"tier {support.source_tier} does not escalate independently; "
            f"{list(ESCALATING_TIERS)} do. " + detail
        )
    elif support.source_tier == TIER_B:
        # `concept/02`: tier B is "usually malicious **when high confidence**".
        # What counts as high is per source and comes from `config/policy.toml`,
        # never from a constant here -- and a source that reported no confidence
        # at all has not reached the threshold rather than having cleared it.
        threshold = thresholds.for_source(support.source_id)
        if support.confidence is None:
            tier_rules = (NO_CONFIDENCE_REPORTED,)
            detail = (
                f"{support.source_id} is tier {TIER_B} and reported no confidence, "
                f"and tier {TIER_B} escalates only when confidence is high "
                f"(>= {threshold}). " + detail
            )
        elif support.confidence < threshold:
            tier_rules = (BELOW_SOURCE_THRESHOLD,)
            detail = (
                f"{support.source_id} reported {support.confidence} and its "
                f"configured threshold is {threshold}. " + detail
            )
    combined = tuple(
        name for name in ESCALATION_RULES if name in set(tier_rules) | set(rules)
    )
    return Candidate(
        evidence_id=support.evidence_id,
        entity_type=support.entity_type,
        entity_value=support.entity_value,
        source_id=support.source_id,
        source_tier=support.source_tier,
        confidence=support.confidence,
        status=support.status,
        supports=supported,
        escalates=not combined,
        rules=combined,
        independent_sources=diversity[(support.entity_type, support.entity_value)],
        detail=_bounded(detail),
        gap=gap or (FRESHNESS_ADEQUACY_UNTESTED if support.status != STATUS_OK else ""),
    )


def _escalation_gaps(
    escalates: bool, candidates: tuple[Candidate, ...]
) -> tuple[Gap, ...]:
    """The tests that did not run, recorded once each and in `GAP_KINDS` order.

    The shared-infrastructure one is recorded on an escalation that *happened*,
    for the reason `_gaps` records it on a verdict that stood: three of the note's
    four cases were never tested, and an escalation that hid that would read as a
    tested CDN rule.
    """
    kinds = {candidate.gap for candidate in candidates if candidate.gap}
    if escalates:
        kinds.add(SHARED_INFRASTRUCTURE_UNDETERMINED)
    return tuple(
        Gap(kind=kind, detail=GAP_DETAIL[kind]) for kind in GAP_KINDS if kind in kinds
    )


POLICY = PolicyVersion(
    version=POLICY_VERSION, constrain=constrain, escalate=escalate
)
