"""Policy — the composition rule, as code the model cannot argue with.

`concept/02-concepts-and-taxonomy.md`, "The composition rule — scope before
severity": *"An evidence-level classification about a contacted indicator does
not become the context verdict. This is the boundary between the two levels, and
the single most consequential rule in the taxonomy."* And, in the same note's
last paragraph:

> The composition rule should live as **explicit, testable policy** rather than
> in the model's judgement: the model classifies, the policy constrains what
> evidence can support what verdict. **This is where over-alerting will come from
> if it is wrong.**

So the rule is here, in deterministic code, and not in `helena.triage.v1`'s
words. A rule written into a prompt is a suggestion a model may be argued out of
by the data it is reading; a rule written here is a constraint on what the run is
allowed to have concluded.

## Where it runs relative to the prompt

**After.** The order is fixed and each step is a different actor:

| | |
| --- | --- |
| `helena.triage.v1` | tells the model *how to read* the rendering. It does not state the composition rule |
| `helena.agents.assess` | gets an answer and validates it against the frozen contract |
| `helena.triage.run` | pairs the answer with its request (`check_exchange`) |
| **`helena.policy`** | **asks whether the cited evidence can support the verdict the model gave** |

It runs on the model's own answer, and **it does not rewrite it.**
`concept/07-principles.md` keeps inference append-only — *"appended, never
overwriting a fact"* — and `AgentResult` is the record of what the model said.
The `Decision` a version's `constrain` returns is a **second** typed record
beside it, saying what that answer is permitted to be read as. Nothing here
mutates a result, and nothing here produces a verdict of its own.

**It is not the escalation evaluator.** `concept/04`'s second, independent input
to the analyst — a Tier A or high-confidence Tier B classification escalating
*regardless of the triage verdict* — reads the store rather than a model's
answer, and is deliberately not this. It is task 33's, it will read the same
`Support` records, and it applies this rule so that a hit whose traffic does not
support it does not escalate as `malicious`.

## What is machinery here and what is frozen in a version

The same split `helena.rendering` makes, for the same reason. `policy_version` is
one of the nine dimensions `helena.versions.VersionSet` records, so *the rule
that constrained an assessment* has to be reconstructible from the identifier a
stored row holds — and a revision is `v2` beside `v1`, never an edit.

- **Here**: `Support` — one cited claim with the per-entity traffic beside it —
  and `supports_for`, which is the read that fuses a result's citations with a
  `helena.rendering.ContextProjection`. That is *how the input is assembled*, and
  it moves when the store's shape moves.
- **In `vN.py`**: the rules themselves, their names, the severity ordering, the
  paths that assert something about the host rather than about a contacted
  indicator, and the `Decision` a run records. Those are *what the rule is*, and
  a stored assessment recording `policy_version = "v1"` is entitled to have them
  stay exactly as they were.

`tests/test_package_layout.py` enforces that nothing else lives in the package.

## The two inputs, and why the traffic has to be one of them

`concept/02` again: *"This is why per-entity traffic columns exist at all, and
why they sit on the same row as the verdict: a row carrying only a
classification cannot tell those cases apart."* A `Support` is therefore the
claim **and** the traffic of the flows the entity was observed in, resolved
together — a policy given only the classification could not distinguish a C2 hit
the host exchanged data with from one it failed to connect to, which is the whole
of the rule.

Reads: nothing from the store — it is given a projection that was already read.
Writes: nothing.

Maturity: experimental — exercised by `tests/test_policy.py`, table-driven, one
case per rule, plus a case built from a real capture and a real ThreatFox load in
a real engine. **No assessment has been constrained in a running pipeline**:
nothing calls this yet, no decision is stored, and whether the rules produce the
right answer on real traffic is unmeasured for the reason everything else here is
— there is no labelled corpus (`concept/08-open-questions.md`). What is
demonstrated is that each sentence of `concept/02`'s composition rule refuses
what it says it refuses.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import ModuleType
from typing import Any

from pydantic import BaseModel, ConfigDict, NonNegativeInt

from helena.contracts import v1 as contract
from helena.enrichment import ENRICHMENT_STATUSES, ENTITY_TYPES
from helena.rendering import ContextProjection

__all__ = [
    "PolicyError",
    "PolicyVersion",
    "Support",
    "UnknownVersion",
    "supports_for",
    "version",
]


class PolicyError(Exception):
    """The policy was asked something it cannot answer honestly.

    One exception type with a stated reason, the way `helena.rendering.RenderingError`
    is one: every case is the same refusal to constrain a verdict against evidence
    the policy cannot see all of, and a caller catching three of these would be
    enumerating the ways it might have been handed the wrong pair.
    """


class UnknownVersion(PolicyError):
    """A policy version was asked for that this package does not hold.

    Distinct, for the reason `helena.triage.UnknownVersion` is distinct: a stored
    assessment recording a `policy_version` whose module is absent is a run whose
    constraint cannot be reconstructed, not a value that is invalid.
    """


class Support(BaseModel):
    """One cited claim, with the traffic of the entity it is about beside it.

    Frozen, and deliberately **data only**: every predicate over these fields —
    what counts as contact, what counts as traffic in both directions, what
    counts as shared infrastructure — belongs to a policy version, because those
    are the thresholds the rule *is*. A property here would be a rule that every
    future version inherits without recording it.

    The claim half is `helena.rendering.EntityEnrichment`'s and the traffic half
    is `helena.rendering.ContextEntity`'s. They are one object here because
    `concept/02` says the rule needs them on one row: *"a row carrying only a
    classification cannot tell those cases apart."*
    """

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    #: The stable evidence identifier the result cited.
    evidence_id: str
    #: `supporting` or `contradicting`, from the citation.
    stance: str

    # --- what the claim is about -------------------------------------------
    entity_type: str
    entity_value: str
    #: The evidence-level classification, which is never `None` here: a citation
    #: resolves to a claim, and a lookup that found nothing produced no
    #: identifier to cite.
    classification: str
    confidence: float | None
    #: `address`, `domain`, `url` or `address:port` — what the claim is *about*,
    #: which is not always the entity it attaches to. This is the field the rule
    #: is named after.
    scope_type: str
    scope_value: str
    #: Three-valued: `None` where the claim is not port-scoped, `False` where the
    #: host reached this address on other ports only.
    port_matched: bool | None
    source_id: str
    source_tier: str
    #: `ok` / `stale` / `failed` / `missing`. Carried because a rule may read it
    #: and because collapsing it into the classification is what
    #: `concept/instruction.md` §2 forbids at every layer.
    status: str

    # --- what the host did with it ------------------------------------------
    #: Which layers observed the entity, in `helena.rendering.OBSERVATION_LAYERS`
    #: order. `concept/02`: *"a name in TLS SNI was connected to, where a name
    #: seen only in a DNS query may never have been. Weaker than bytes, and not
    #: nothing."*
    observed_layers: tuple[str, ...]
    observed_flow_count: NonNegativeInt
    observed_bytes_sent: NonNegativeInt
    observed_bytes_received: NonNegativeInt
    #: The destination ports the host reached on this address, ascending. Empty
    #: for every other entity type.
    ports: tuple[int, ...] = ()

    def model_post_init(self, _context: object) -> None:
        if self.stance not in contract.STANCES:
            raise ValueError(
                f"stance {self.stance!r} is not one of {list(contract.STANCES)}"
            )
        if self.entity_type not in ENTITY_TYPES:
            raise ValueError(
                f"entity type {self.entity_type!r} is not among {sorted(ENTITY_TYPES)}"
            )
        if self.status not in ENRICHMENT_STATUSES:
            raise ValueError(
                f"status {self.status!r} is not one of {list(ENRICHMENT_STATUSES)}"
            )
        if not self.observed_layers:
            raise ValueError(
                f"{self.entity_type} {self.entity_value!r} was observed by no "
                f"layer; every entity row comes from an observation"
            )


def supports_for(
    result: contract.AgentResult, projection: ContextProjection
) -> tuple[Support, ...]:
    """Resolve a result's citations against the context they were drawn from.

    One `Support` per citation, in the result's own citation order, each carrying
    the claim the identifier names and the traffic of the entity that claim is
    about.

    **A citation that does not resolve is a `PolicyError`, never a dropped
    support.** `helena.contracts.v1.check_exchange` has already refused a result
    citing an identifier the *rendering* did not show, and the rendering's
    identifiers come from this projection — so an unresolvable one here means the
    projection is not the one the request was built from. Ignoring it would
    silently remove a support from the rule's input, and the rule's answer is a
    function of exactly that input.

    `proposed_claims` are deliberately not read. A proposal is a claim about
    *infrastructure* that deterministic code validates and writes
    (`concept/07`); the composition rule is about what the **context verdict**
    may be, and the two are different questions with different subjects.
    """
    claims: dict[str, tuple[Any, Any]] = {
        record.evidence_id: (entity, record)
        for entity in projection.entities
        for record in entity.enrichment
        if record.evidence_id is not None
    }
    unresolvable = sorted(
        citation.evidence_id
        for citation in result.citations
        if citation.evidence_id not in claims
    )
    if unresolvable:
        raise PolicyError(
            f"context {projection.context_id!r} holds no claim for {unresolvable}, "
            f"which the result cites. The composition rule reads the traffic beside "
            f"every cited claim, so a citation this projection cannot resolve is a "
            f"support the rule would silently decide without."
        )
    return tuple(
        _support(citation, *claims[citation.evidence_id])
        for citation in result.citations
    )


def _support(citation: contract.Citation, entity: Any, record: Any) -> Support:
    """One citation, one entity row and one claim row, fused into the rule's input."""
    if record.classification is None:  # pragma: no cover — the store cannot produce it
        raise PolicyError(
            f"{record.source_id} carries evidence id {record.evidence_id!r} for "
            f"{entity.entity_type} {entity.entity_value!r} and no classification. "
            f"An identifier exists exactly where a claim does."
        )
    return Support(
        evidence_id=citation.evidence_id,
        stance=citation.stance,
        entity_type=entity.entity_type,
        entity_value=entity.entity_value,
        classification=record.classification,
        confidence=record.confidence,
        scope_type=record.scope_type,
        scope_value=record.scope_value,
        port_matched=record.port_matched,
        source_id=record.source_id,
        source_tier=record.source_tier,
        status=record.status,
        observed_layers=tuple(entity.observed_layers),
        observed_flow_count=entity.observed_flow_count,
        observed_bytes_sent=entity.observed_bytes_sent,
        observed_bytes_received=entity.observed_bytes_received,
        ports=tuple(entity.ports),
    )


@dataclass(frozen=True)
class PolicyVersion:
    """One version's composition rule: the shape every version module supplies.

    A callable and a value rather than a class with one method, for the reason
    `helena.rendering.RenderingVersion` and `helena.triage.TriagePrompt` give: the
    rule is a function of a result and its supports and holds no state.
    """

    version: str
    #: `(result, supports) -> Decision`. The `Decision` class is the version's
    #: own — a `v2` whose rules produced a different record of what it decided
    #: must not have to change what a `v1` decision meant.
    constrain: Any


def _load(identifier: str) -> PolicyVersion:
    """The composition rule of one policy version.

    Imported by name rather than held in a registry dict, so adding `v2` is
    adding a module and nothing else. The same loader `helena.taxonomy`,
    `helena.contracts`, `helena.hosts`, `helena.rendering` and `helena.triage`
    use.
    """
    from importlib import import_module  # noqa: PLC0415 — one call, at the edge

    if not identifier.isidentifier():
        raise UnknownVersion(
            f"{identifier!r} is not a version identifier; versions are module "
            f"names like 'v1'"
        )
    try:
        module: ModuleType = import_module(f"{__name__}.{identifier}")
    except ModuleNotFoundError as absent:
        raise UnknownVersion(
            f"no policy version {identifier!r}. An assessment that recorded it "
            f"cannot be re-constrained against this tree, so what the rule "
            f"permitted is not reproducible here."
        ) from absent
    policy = getattr(module, "POLICY", None)
    if not isinstance(policy, PolicyVersion):
        raise UnknownVersion(
            f"{module.__name__} does not define a PolicyVersion named POLICY"
        )
    if policy.version != identifier:
        raise UnknownVersion(
            f"{module.__name__} declares version {policy.version!r}; a version "
            f"module and the version it declares must agree"
        )
    return policy


#: Public name for the loader, so `version` reads as what a caller wants.
version = _load
