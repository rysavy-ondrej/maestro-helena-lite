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

## The other rule in here, and why it takes no result at all

`concept/04`'s second, independent input to the analyst — a Tier A or
high-confidence Tier B classification escalating *regardless of the triage
verdict* — is `vN.escalate`, and it is in this package because it is the same
frozen policy version deciding: the rule that says a hit whose traffic does not
support it does not escalate as `malicious` **is** the composition rule, and two
copies of it under one `policy_version` is the drift the version rules exist to
prevent.

Everything else about it is the opposite of `constrain`:

| | `constrain` | `escalate` |
| --- | --- | --- |
| Input | one `AgentResult` and the evidence it cited | every claim the context holds |
| Built by | `supports_for` — resolves citations | `supports_in` — reads the projection |
| Reads a model's answer | yes, it is *about* one | **no, and that is the invariant** |

`concept/instruction.md` §2: *"Deterministic escalation is independent of triage.
A `normal` from a model may not suppress a high-confidence match."* So `escalate`
has no parameter a verdict could arrive through, and `tests/test_policy.py`
asserts that over its signature rather than trusting the code to keep it — the
failure this rule prevents is a later increment "helpfully" passing the triage
result in so the evaluator can skip work when triage already said `normal`.

## What is machinery here and what is frozen in a version

The same split `helena.rendering` makes, for the same reason. `policy_version` is
one of the nine dimensions `helena.versions.VersionSet` records, so *the rule
that constrained an assessment* has to be reconstructible from the identifier a
stored row holds — and a revision is `v2` beside `v1`, never an edit.

- **Here**: `Support` — one claim with the per-entity traffic beside it — and the
  two reads that assemble them, `supports_for` (a result's citations) and
  `supports_in` (every claim in a projection). Plus `Thresholds` and the loader
  that reads `config/policy.toml`, because *which sources need a number* moves
  with the registry and the file is not frozen. That is all *how the input is
  assembled*, and it moves when the store's shape moves.
- **In `vN.py`**: the rules themselves, their names, the severity ordering, the
  paths that assert something about the host rather than about a contacted
  indicator, what a threshold *does*, and the `Decision` and `Escalation` a run
  records. Those are *what the rule is*, and a stored assessment recording
  `policy_version = "v1"` is entitled to have them stay exactly as they were.

The threshold **values** are in neither: they are configuration, they are
recorded on the escalation that applied them (`thresholds_version`), and
`config/policy.toml` carries the argument for the number that is in it.

`tests/test_package_layout.py` enforces that nothing else lives in the package.

## The two inputs, and why the traffic has to be one of them

`concept/02` again: *"This is why per-entity traffic columns exist at all, and
why they sit on the same row as the verdict: a row carrying only a
classification cannot tell those cases apart."* A `Support` is therefore the
claim **and** the traffic of the flows the entity was observed in, resolved
together — a policy given only the classification could not distinguish a C2 hit
the host exchanged data with from one it failed to connect to, which is the whole
of the rule.

Reads: nothing from the store — it is given a projection that was already read —
and `config/policy.toml` for the thresholds. Writes: nothing.

Maturity: experimental — exercised by `tests/test_policy.py`, table-driven, one
case per rule, plus cases built from a real capture and a real ThreatFox load in
a real engine. **Nothing has been constrained or escalated in a running
pipeline**: nothing calls this yet, no decision is stored, and whether the rules
produce the right answer on real traffic is unmeasured for the reason everything
else here is — there is no labelled corpus
(`concept/08-open-questions.md`), and the same note lists the confidence
threshold itself as an open question. What is demonstrated is that each sentence
of `concept/02`'s composition rule refuses what it says it refuses, and that
escalation is computed from the store with no route for a triage answer to reach
it.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any

from pydantic import BaseModel, ConfigDict, NonNegativeInt

from helena.contracts import v1 as contract
from helena.enrichment import ENRICHMENT_STATUSES, ENTITY_TYPES, SOURCES, Tier
from helena.rendering import ContextProjection

__all__ = [
    "BUDGET_KEYS",
    "DISCLOSURE_KEYS",
    "POLICY_FILE",
    "PolicyError",
    "PolicyVersion",
    "Support",
    "THRESHOLD_KEYS",
    "THRESHOLD_TIER",
    "Thresholds",
    "UnknownVersion",
    "supports_for",
    "supports_in",
    "thresholds",
    "version",
]

PROJECT_ROOT = Path(__file__).resolve().parents[3]

#: The fixed configuration the escalation thresholds are read from. A path and
#: not an environment variable, for the reason `helena.rendering.BUDGET_FILE` and
#: `helena.hosts.ATTRIBUTES_FILE` give: it is a location, and a deployment that
#: keeps its policy elsewhere passes the path. A missing file is a loud failure
#: naming it, never a default threshold.
POLICY_FILE = PROJECT_ROOT / "config" / "policy.toml"

#: The top-level keys of that file `thresholds()` reads, and the ones
#: `helena.budgets.load` and `helena.disclosure.send_policy` read out of the same
#: file. Three tables of one policy file, because `concept/07-principles.md` puts
#: budget values and confidence thresholds in one sentence as the two things that
#: are policy rather than constants in a branch, and puts *what may be sent to
#: which source* under "governed policy" in the same note.
#:
#: All three sets are named here, in the module that owns the path, so that no
#: loader can drift into rejecting a key another one requires: each refuses a key
#: **nothing** reads and none refuses a key another reads. `helena.budgets` and
#: `helena.disclosure` import them rather than keeping a second copy.
THRESHOLD_KEYS = frozenset({"policy_version", "thresholds_version", "thresholds"})
BUDGET_KEYS = frozenset({"budgets", "rate_limits"})
DISCLOSURE_KEYS = frozenset({"send_policy", "send_policy_version"})

#: The one tier whose independent escalation is conditional on a number.
#: `concept/02`: Tier A "may establish `malicious` by itself if scope and
#: freshness are adequate" — no number — and Tier B is "usually malicious **when
#: high confidence**". Tiers C and D do not escalate independently at all, so a
#: threshold for one would be a key nothing reads.
#:
#: It is here rather than in a version module because it is what decides which
#: *entries the file must carry*, and that moves with `helena.enrichment.SOURCES`
#: — machinery, not rule. What a threshold **does** is `vN.escalate`'s.
THRESHOLD_TIER = Tier.B


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


def supports_in(projection: ContextProjection) -> tuple[Support, ...]:
    """Every claim the context holds, with the traffic of the entity it is about.

    The escalation evaluator's input, and it is deliberately **not**
    `supports_for`: that one asks what the evidence a model chose to cite can
    support, and this one asks what the evidence escalates on its own. A read
    built from citations would make deterministic escalation a function of the
    triage answer, which is the one thing `concept/instruction.md` §2 says it may
    not be — *"a `normal` from a model may not suppress a high-confidence match"*.
    So this takes no result, and the ordering is the projection's own.

    Every support is `supporting`. A `Support`'s stance records how a **citation**
    framed a claim, and a claim read straight out of the store has no framing but
    its own: it is evidence for what it says. Nothing here can produce a
    `contradicting` support, because nothing here is arguing.

    An entity with no claims contributes nothing — a `no_match`, a `missing` or a
    failed lookup carries no evidence identifier, and there is nothing for a rule
    to escalate on. Those four remain four different things one layer down, in
    `helena.rendering.EntityEnrichment.status`, and the escalation record says how
    many claims it read so that "nothing escalated" and "there was nothing to
    read" are not the same sentence.
    """
    return tuple(
        _support(
            contract.Citation(
                evidence_id=record.evidence_id, stance=contract.SUPPORTING
            ),
            entity,
            record,
        )
        for entity in projection.entities
        for record in entity.enrichment
        if record.evidence_id is not None
    )


class Thresholds(BaseModel):
    """The per-source confidence thresholds, as loaded, with both versions.

    Frozen, and it carries `policy_version` so that a version module can refuse a
    threshold set written for another one — the same check `constrain` makes on a
    result. `thresholds_version` is what an escalation records: `vN.py` is frozen
    and `config/policy.toml` is not, so a decision that recorded only the policy
    version could not be replayed against the number that actually decided it.
    """

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    policy_version: str
    thresholds_version: str
    #: `source_id` -> the confidence a claim from that source must reach. One
    #: entry per registered `THRESHOLD_TIER` source, and no others.
    by_source: dict[str, float]

    def for_source(self, source_id: str) -> float:
        """The threshold for `source_id`, or a `PolicyError` naming what is loaded.

        Never a default. A source that reached the confidence test without a
        threshold is a source `thresholds()` should have refused to load without,
        and answering with a number nobody configured is how a feed escalates on
        a value that was never anyone's decision.
        """
        try:
            return self.by_source[source_id]
        except KeyError:
            raise PolicyError(
                f"no confidence threshold is configured for {source_id!r}; "
                f"{sorted(self.by_source)} are. `concept/02` conditions tier "
                f"{THRESHOLD_TIER.value} escalation on high confidence, and what "
                f"counts as high is per source and never a default."
            ) from None


def thresholds(path: Path | str = POLICY_FILE) -> Thresholds:
    """Read the escalation thresholds, or fail naming what is wrong with the file.

    TOML, so the file is `tomllib` and no dependency — the same reader
    `helena.hosts.load` and `helena.rendering.budget` use:

        policy_version = "v1"
        thresholds_version = "2026-09-09"

        [thresholds]
        threatfox = 0.80

    Every failure is loud and names the path, and there is no fallback value:
    `concept/07-principles.md` makes thresholds **policy** rather than constants
    in a branch, and a threshold that defaulted would be the silent configuration
    default `concept/instruction.md` §6 lists by name.

    The coverage check is the point of the loader. Every registered
    `THRESHOLD_TIER` source must have an entry — a feed whose threshold nobody
    set would otherwise escalate on whatever the code guessed — and a source that
    is not one must not, because a threshold that nothing reads is a decision
    somebody recorded and nothing applies.
    """
    path = Path(path)
    try:
        raw = path.read_bytes()
    except FileNotFoundError as absent:
        raise PolicyError(
            f"no escalation policy at {path}. The per-source confidence "
            f"thresholds are policy and not constants in this package, so an "
            f"absent file is a startup failure and never a default threshold."
        ) from absent
    try:
        document = tomllib.loads(raw.decode())
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as malformed:
        raise PolicyError(f"{path} is not readable TOML: {malformed}") from malformed

    unexpected = sorted(set(document) - THRESHOLD_KEYS - BUDGET_KEYS - DISCLOSURE_KEYS)
    if unexpected:
        raise PolicyError(
            f"{path} has top-level keys {unexpected}; this loader reads "
            f"{sorted(THRESHOLD_KEYS)}, `helena.budgets.load` reads "
            f"{sorted(BUDGET_KEYS)} and `helena.disclosure.send_policy` reads "
            f"{sorted(DISCLOSURE_KEYS)}. A key nothing reads is a policy somebody "
            f"set and nothing applies."
        )
    declared = {
        key: document.get(key) for key in ("policy_version", "thresholds_version")
    }
    for key, value in declared.items():
        if not isinstance(value, str) or not value.strip():
            raise PolicyError(
                f"{path} declares no {key}. A threshold set that did not say "
                f"which rules it was written for, or which revision of itself "
                f"decided, could not be replayed against either."
            )

    table = document.get("thresholds", {})
    if not isinstance(table, dict):
        raise PolicyError(
            f"{path}: [thresholds] is {type(table).__name__}, and it is a table "
            f"of source id -> confidence"
        )
    for source_id, value in table.items():
        if source_id not in SOURCES:
            raise PolicyError(
                f"{path} sets a threshold for {source_id!r}, which is not a "
                f"registered source ({sorted(SOURCES)}). Adding a source is a "
                f"governed decision (concept/05-threat-intelligence.md), not a "
                f"line in this file."
            )
        if SOURCES[source_id].tier is not THRESHOLD_TIER:
            raise PolicyError(
                f"{path} sets a threshold for {source_id!r}, which is tier "
                f"{SOURCES[source_id].tier.value}. Only tier "
                f"{THRESHOLD_TIER.value} escalates on a confidence number "
                f"(concept/02-concepts-and-taxonomy.md), so this one would be "
                f"read by nothing."
            )
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            raise PolicyError(
                f"{path}: thresholds.{source_id} is {type(value).__name__}, and a "
                f"confidence threshold is a number"
            )
        if not 0.0 <= float(value) <= 1.0:
            raise PolicyError(
                f"{path}: thresholds.{source_id} is {value}, and a confidence is "
                f"between 0 and 1 — `sql/migrations/0014_feed_mapping_views.sql` "
                f"divides the feed's own scale by 100 before it reaches a claim"
            )
    absent = sorted(
        source_id
        for source_id, descriptor in SOURCES.items()
        if descriptor.tier is THRESHOLD_TIER and source_id not in table
    )
    if absent:
        raise PolicyError(
            f"{path} sets no threshold for {absent}, which are tier "
            f"{THRESHOLD_TIER.value} sources. `concept/02` lets a tier "
            f"{THRESHOLD_TIER.value} match escalate independently *when high "
            f"confidence*, and what counts as high is per source — so a "
            f"registered one this file is silent about is a feed that would "
            f"escalate on a number nobody chose."
        )
    return Thresholds(
        policy_version=declared["policy_version"],
        thresholds_version=declared["thresholds_version"],
        by_source={source_id: float(value) for source_id, value in table.items()},
    )


@dataclass(frozen=True)
class PolicyVersion:
    """One version's rules: the shape every version module supplies.

    Callables and a value rather than a class with methods, for the reason
    `helena.rendering.RenderingVersion` and `helena.triage.TriagePrompt` give: the
    rules are functions of their inputs and hold no state.
    """

    version: str
    #: `(result, supports) -> Decision`. The `Decision` class is the version's
    #: own — a `v2` whose rules produced a different record of what it decided
    #: must not have to change what a `v1` decision meant.
    constrain: Any
    #: `(supports, thresholds) -> Escalation`. Deliberately not `(result, ...)`:
    #: `concept/04` makes this input independent of whether triage ran at all, so
    #: there is nowhere for a verdict to enter.
    escalate: Any


def _load(identifier: str) -> PolicyVersion:
    """The rules of one policy version.

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
