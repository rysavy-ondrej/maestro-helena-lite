"""Contract v1 — the first frozen request/result pair. Never edited; superseded by a `v2`.

Everything here is read off `concept/04-the-two-agents.md` ("One contract for
both"), `concept/02-concepts-and-taxonomy.md` (citation, evidence package, gap,
typed failure) and `concept/07-principles.md` (the agent boundary, partial
results, budgets, caching). Where a note names a field, the field is here under
that name; where a rule is stated in prose, the prose is quoted beside the check
it became, so the derivation can be read rather than taken.

**This file is frozen the moment an assessment records `schema_version = "v1"`.**
`docs/decisions/0008-version-registry.md`: a revision is `v2` beside it, with this
left importable exactly as it was. `docs/decisions/0017-the-agent-contract.md`
carries the argument for every shape below, including the four places this
contract says something `concept/04` does not.

## One contract, and the asymmetry as rules rather than as a second shape

`concept/04` makes Triage and Analyst *deliberately* asymmetric — no tools, no
retrieval, two roots, enrichment-tier evidence only on one side; tools, live
retrieval, four roots on the other — and in the same breath gives them **one**
contract. So the asymmetry is enforced as validation on `AgentResult` keyed by
`emitter`, and there is no `TriageResult` class. Two classes would be two places
every later rule has to be written, and the first one forgotten is a triage run
that quietly returned `malicious`.

## The three fields that are deliberately absent

`concept/04` names them and gives concept-level reasons. They are absent here,
`extra="forbid"` is set on every model so no caller can add one at runtime, and
`tests/test_contracts.py` asserts by name that none exists:

- a free-text **task** per invocation — *"a varying instruction channel into the
  model: it would make triage input non-uniform, make assessments incomparable
  across hosts and time, and give attacker-influenced content a route into the
  instruction position"*;
- loose **observations** / **relevant context** — *"would carry the same content
  as the bounded, versioned, citation-carrying rendering **without** the
  guarantees that make an assessment replayable"*;
- **recommended actions** — *"has no consumer and invites the remediation channel
  the concept excludes"*.

The rendering is the *only* channel for context, and it is versioned, sectioned,
citation-carrying and explicit about what it dropped.

## What a version module may not import, and what it must

The constants below — the triggers, the section names, the stances, the gap
kinds, the retrieval outcomes, the failure reasons — live **here** rather than in
`helena/contracts/__init__.py`, because a constant in the package would be one
every frozen version imports and editing it would edit `v1` through a side door.

Three shapes come from outside and are frozen by reference:
`helena.versions.VersionSet` (the nine dimensions), `helena.taxonomy` (the
classification syntax and the closed roots per emitter) and
`helena.enrichment.QueryFailure` (the typed error a provider query produces).
Re-spelling them here would be a second implementation of each per contract
version. `docs/decisions/0017-the-agent-contract.md` records the cost.

Maturity: experimental — exercised by `tests/test_contracts.py`. No model has been
called, nothing has been stored or emitted, and no result has been replayed
against a recorded `schema_version`; what is demonstrated is that these shapes
refuse what the concept notes say they must refuse.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import (
    BaseModel,
    ConfigDict,
    NonNegativeFloat,
    NonNegativeInt,
    PositiveFloat,
    PositiveInt,
)

from helena import taxonomy
from helena.contracts import ContractError, ContractVersion
from helena.enrichment import ENTITY_TYPES, MAX_FAILURE_DETAIL, QueryFailure
from helena.versions import Version, VersionSet

__all__ = [
    "AgentFailure",
    "AgentRequest",
    "AgentResult",
    "BUDGET_EXHAUSTED",
    "Budgets",
    "CACHE_HIT",
    "CONTRACT",
    "CONTRACT_VERSION",
    "CONTRADICTING",
    "Citation",
    "Cost",
    "DETERMINISTIC_SIGNAL",
    "EvidencePackage",
    "FAILED",
    "FAILURE_REASONS",
    "GAP_KINDS",
    "Gap",
    "IN_FLIGHT",
    "LIVE_QUERY",
    "MAX_DETAIL",
    "MAX_NARRATIVE",
    "MISSING",
    "MODEL_UNAVAILABLE",
    "NORMAL",
    "NO_MATCH",
    "ProposedClaim",
    "REQUEST_VERSION_DIMENSIONS",
    "RETRIEVAL_OUTCOMES",
    "RenderedSection",
    "Rendering",
    "RequestVersions",
    "RetrievalStep",
    "SCHEDULED_TRIAGE",
    "SCHEMA_INVALID",
    "SECTIONS",
    "STALE",
    "STANCES",
    "SUPPORTING",
    "TIMED_OUT",
    "TRIAGE_SUSPICIOUS",
    "TRIGGERS",
    "TRUNCATED",
    "Truncation",
    "UNKNOWN",
    "check_exchange",
]

#: This module's own version. `AgentRequest` refuses a request whose
#: `versions.schema_version` is anything else -- two copies of a version constant
#: are asserted equal (`concept/instruction.md` §2), and the copies here are the
#: module name and the value a row will record.
CONTRACT_VERSION = "v1"

# --- The trigger ------------------------------------------------------------
#
# `concept/04`: the request carries "the trigger (scheduled triage,
# triage-suspicious, or deterministic escalation)". The three are not
# interchangeable and they are not symmetric: the first is the only way a triage
# run begins, and the other two are the two independent inputs that reach the
# analyst -- "**Triage returned `suspicious`**" and "**the enrichment evidence
# escalates on its own** ... regardless of the triage verdict". `AgentRequest`
# enforces that pairing, so a request cannot claim an analyst was run on a
# schedule or that triage was reached by an escalation.
SCHEDULED_TRIAGE = "scheduled_triage"
TRIAGE_SUSPICIOUS = "triage_suspicious"
DETERMINISTIC_SIGNAL = "deterministic_signal"
TRIGGERS = (SCHEDULED_TRIAGE, TRIAGE_SUSPICIOUS, DETERMINISTIC_SIGNAL)

# --- The rendering ----------------------------------------------------------
#
# `concept/04`, "What the Triage Agent sees": "a bounded, versioned projection of
# the enriched host context, **in five parts**". The five are closed and ordered
# here; what goes *in* one is the rendering version's business, not the
# contract's, and the renderer is built by a later increment.
#
# Every one of the five is always present. `concept/04`'s rule about the host
# attributes -- "when unknown it is rendered as unknown, **never omitted, never
# guessed**" -- is the same rule one level up: a section that could be absent
# would make "this host contacted no domains" and "the domain section was not
# rendered" the same thing to an agent.
HOST = "host"
DOMAINS_CONTACTED = "domains_contacted"
ADDRESSES_CONTACTED = "addresses_contacted"
TLS_PARAMETERS = "tls_parameters"
CONNECTION_STATISTICS = "connection_statistics"
SECTIONS = (
    HOST,
    DOMAINS_CONTACTED,
    ADDRESSES_CONTACTED,
    TLS_PARAMETERS,
    CONNECTION_STATISTICS,
)

# --- Citations --------------------------------------------------------------
#
# `concept/02`: "**Citation** -- a reference to a stable evidence identifier,
# marked `supporting` or `contradicting`." Two stances, closed: a citation that
# could be neither would let an agent point at a row without saying what it
# thought the row showed, which is a reference and not a citation.
SUPPORTING = "supporting"
CONTRADICTING = "contradicting"
STANCES = (SUPPORTING, CONTRADICTING)

# --- Gaps -------------------------------------------------------------------
#
# `concept/02`: "**Gap** -- a recorded thing the run could not see: missing,
# stale, in-flight, failed, found-nothing, truncated, budget-exhausted." All
# seven, closed, and none of them collapsed into another: `concept/instruction.md`
# §2 makes `stale` / `failed` / `missing` / `no_match` and a typed error five
# different things "at any layer, for any reason", and a gap list is a layer.
#
# `no_match` is the note's "found-nothing", spelled as
# `helena.enrichment.NO_MATCH` spells it, because it is the same fact reaching
# the agent boundary and a second name for it is the drift the vocabulary rules
# exist to prevent.
MISSING = "missing"
STALE = "stale"
IN_FLIGHT = "in_flight"
FAILED = "failed"
NO_MATCH = "no_match"
TRUNCATED = "truncated"
BUDGET_EXHAUSTED = "budget_exhausted"
GAP_KINDS = (MISSING, STALE, IN_FLIGHT, FAILED, NO_MATCH, TRUNCATED, BUDGET_EXHAUSTED)

# --- The retrieval trace ----------------------------------------------------
#
# `concept/07`, "Caching": "the retrieval trace records, per result, **whether it
# was a cache hit or a live query**, and the retrieval time of the underlying
# record. Two runs that differ only in cache state must be distinguishable
# afterwards." Two outcomes, closed, and both of them are *successful* retrievals
# -- a query that did not complete is a `QueryFailure` on the step, never a third
# outcome value, because rule 4 of `concept/05` says a failure carries a typed
# error and no result at all.
CACHE_HIT = "cache_hit"
LIVE_QUERY = "live_query"
RETRIEVAL_OUTCOMES = (CACHE_HIT, LIVE_QUERY)

# --- The typed failure ------------------------------------------------------
#
# `concept/07`: "Triage could not assess the context -> a **typed failure**, not a
# third label", and "schema-invalid model output is retried ... a small bounded
# number of times, and then becomes a typed failure".
#
# Three reasons, and each is a different thing an operator would do something
# about:
#
#   schema_invalid      the model answered and the answer never validated, with
#                       the bounded retries spent. `AgentFailure` requires the
#                       reported model version here, because there was a response
#   model_unavailable   no usable response at all -- the endpoint refused,
#                       errored or could not be reached. No reported model
#                       version exists and recording the configured one instead
#                       would be the exact lie ADR-0008 forbids
#   timed_out           the wall-clock budget was spent before a verdict
#
# **Budget exhaustion is not here on purpose.** `concept/07`: "budget exhausted
# mid-analysis -> a verdict on what was gathered, with exhaustion and gaps
# explicit -- but **never `normal`**; it degrades to `unknown`". That is an
# `AgentResult` with a `budget_exhausted` gap, and `AgentResult` enforces the
# "never `normal`" half. A failure reason for it would turn a verdict the concept
# requires into a non-verdict.
SCHEMA_INVALID = "schema_invalid"
MODEL_UNAVAILABLE = "model_unavailable"
TIMED_OUT = "timed_out"
FAILURE_REASONS = (SCHEMA_INVALID, MODEL_UNAVAILABLE, TIMED_OUT)

# The two context roots this contract has rules of its own about. Every other
# root check is `helena.taxonomy`'s, per emitter.
NORMAL = "normal"
UNKNOWN = "unknown"

#: Bound on any operator-facing diagnostic. The same bound
#: `helena.enrichment.QueryFailure` uses, for the same reason it gives: a
#: diagnostic is a sentence, and an unbounded one is where a provider response
#: ends up.
MAX_DETAIL = MAX_FAILURE_DETAIL

#: Bound on the analyst's narrative. `concept/03`: "narrative stays a text
#: column". Bounded because it is the one long free-text field on the result and
#: an unbounded one is where a model's whole chain of thought would land.
MAX_NARRATIVE = 4000

#: The version dimensions that are known **before** the call, which is every
#: dimension except the model's. `tests/test_contracts.py` asserts these eight
#: plus `model_version` are exactly `helena.versions.VERSION_COLUMNS`, so a tenth
#: dimension added to the registry is a failing test here rather than a version
#: this contract quietly stops carrying.
REQUEST_VERSION_DIMENSIONS = (
    "prompt_version",
    "schema_version",
    "rendering_version",
    "taxonomy_version",
    "enrichment_snapshot_version",
    "normalization_snapshot_version",
    "policy_version",
    "aggregation_version",
)

# Every model in this module. Frozen, because a request describes a call that is
# being made and a result describes one that has happened; strict, because a
# contract that coerced `"0.9"` into a confidence would be validating the string
# it was handed rather than the field it declares; `extra="forbid"`, because that
# is what makes "no task field, no observations, no recommended actions" a
# property of the shape rather than of a review; and `protected_namespaces=()`
# because `model_requested` and `model_version` are field names and Pydantic
# reserves the `model_` prefix for its own methods.
_CONTRACT_MODEL_CONFIG = ConfigDict(
    strict=True,
    extra="forbid",
    frozen=True,
    # A rejected value is echoed in a Pydantic ValidationError, and task 01
    # measured the accident this guards against: a credential passed to the wrong
    # field lands in a traceback.
    hide_input_in_errors=True,
    protected_namespaces=(),
)


def _bounded(name: str, value: str, limit: int) -> None:
    """Refuse a blank or over-long operator-facing string."""
    if not value.strip():
        raise ValueError(f"{name} is blank; a recorded reason that says nothing is not one")
    if len(value) > limit:
        raise ValueError(
            f"{name} is {len(value)} characters and the limit is {limit}; an "
            f"unbounded diagnostic is where a provider response ends up"
        )


class Truncation(BaseModel):
    """What one rendering section dropped: named, counted, and never implicit.

    `concept/instruction.md` §2: "**truncation is visible or it is a bug**", and
    `concept/07` again: "rendering too large -> truncated **visibly** -- silent
    truncation is a correctness bug".

    `kept` must be strictly less than `total`. A record with `kept == total`
    would say a section was truncated when it was not, and a reader cannot tell
    an honest no-op record from a real one; a section that dropped nothing
    carries no record at all.

    **The size budget itself is not here.** `concept/08-open-questions.md` lists
    the numeric budget values as open, and a limit invented in the contract would
    be a policy constant in a branch, which `concept/07` forbids. What the
    contract guarantees is that dropping something is recorded, not how much may
    be dropped.
    """

    model_config = _CONTRACT_MODEL_CONFIG

    section: str
    #: How many items of this section the rendering carries.
    kept: NonNegativeInt
    #: How many there were before the budget was applied.
    total: NonNegativeInt

    def model_post_init(self, _context: object) -> None:
        if self.section not in SECTIONS:
            raise ValueError(f"section {self.section!r} is not one of {list(SECTIONS)}")
        if self.kept >= self.total:
            raise ValueError(
                f"{self.section}: kept {self.kept} of {self.total}, which dropped "
                f"nothing. A truncation record is what says something was dropped; "
                f"a section that kept everything carries none."
            )


class RenderedSection(BaseModel):
    """One of the five parts of the rendering, with what it cited and what it dropped.

    `body` is the rendering version's own product and this contract does not look
    inside it -- `rendering_version` is what pins its shape, and the renderer is a
    later increment. What the contract does hold is the two things
    `concept/04` requires of every part: **what it dropped**, and **the stable
    evidence identifiers it showed**.

    `evidence_ids` exists because of `concept/04`'s first property of the
    rendering: "**every enriched value is citable**, carrying a stable evidence
    identifier, or triage cannot cite its reasoning and the finding cannot be
    replayed". Listing them makes that checkable rather than aspirational --
    `check_exchange` refuses a result citing an identifier the request never
    showed it, which is a model citing evidence it was not given.
    """

    model_config = _CONTRACT_MODEL_CONFIG

    section: str
    body: str
    #: The stable evidence identifiers this section rendered, in the order it
    #: rendered them. Empty where the section carries no enriched value -- the
    #: connection statistics are measurements, not claims.
    evidence_ids: tuple[str, ...] = ()
    truncation: Truncation | None = None

    def model_post_init(self, _context: object) -> None:
        if self.section not in SECTIONS:
            raise ValueError(f"section {self.section!r} is not one of {list(SECTIONS)}")
        if self.truncation is not None and self.truncation.section != self.section:
            raise ValueError(
                f"section {self.section!r} carries a truncation record for "
                f"{self.truncation.section!r}; a record naming another section "
                f"makes the dropped rows unattributable"
            )
        if len(set(self.evidence_ids)) != len(self.evidence_ids):
            raise ValueError(
                f"section {self.section!r} lists an evidence id twice; the same "
                f"claim rendered twice is one claim, and a duplicate would count "
                f"as two in anything that reads this"
            )


class Rendering(BaseModel):
    """The bounded, versioned, five-part projection an agent is given.

    `concept/04`: "a bounded, versioned projection of the enriched host context,
    in five parts", and the rendering "is versioned, so what triage saw is pinned
    rather than re-derived later".

    All five sections, exactly once each, in the order `SECTIONS` gives. Not a
    mapping: the order is part of what the agent saw, and a dict would make two
    renderings that differ only in order compare equal while producing different
    prompts.
    """

    model_config = _CONTRACT_MODEL_CONFIG

    #: The rendering version. `AgentRequest` refuses one that disagrees with
    #: `versions.rendering_version` -- two copies of a version constant, asserted
    #: equal (`concept/instruction.md` §2).
    version: Version
    sections: tuple[RenderedSection, ...]

    def model_post_init(self, _context: object) -> None:
        rendered = tuple(section.section for section in self.sections)
        if rendered != SECTIONS:
            raise ValueError(
                f"the rendering has sections {list(rendered)} and the five parts "
                f"are {list(SECTIONS)}, each exactly once and in that order. A "
                f"section that could be absent would make 'nothing was observed' "
                f"and 'nothing was rendered' the same thing to an agent."
            )

    @property
    def evidence_ids(self) -> frozenset[str]:
        """Every stable evidence identifier this rendering showed."""
        return frozenset(
            evidence_id
            for section in self.sections
            for evidence_id in section.evidence_ids
        )

    @property
    def truncations(self) -> tuple[Truncation, ...]:
        """The truncation records, in section order. Empty where nothing was dropped."""
        return tuple(
            section.truncation
            for section in self.sections
            if section.truncation is not None
        )


class Budgets(BaseModel):
    """The four dimensions enforced per agent run, from `concept/07`, "Budgets".

    | Dimension | The real limit it maps to |
    | --- | --- |
    | Step / tool-call count | The unbounded tool loop |
    | Token budget | Model service rate limits and quotas |
    | Wall-clock timeout | Stream latency |
    | Live external query count | Provider quotas |

    Every one is required, with no default: "budget values are **policy**, not
    constants in a branch", and a default here would be a constant in a branch
    with extra steps. `tokens` and `wall_clock_seconds` are strictly positive
    because a run given neither can only ever produce a failure; `steps` and
    `live_queries` may be zero, and for triage they must be -- that is what "no
    tools at all" is, expressed as policy rather than as a code path.

    **The wall clock and the live-query budget are set against each other**, not
    independently (`concept/07`: at a few lookups per minute an analyst run
    checking six indicators spends over a minute on the rate limit alone). This
    contract carries both and checks neither against the other, because the ratio
    is a property of the providers a deployment enabled and is not knowable here.
    """

    model_config = _CONTRACT_MODEL_CONFIG

    steps: NonNegativeInt
    tokens: PositiveInt
    wall_clock_seconds: PositiveFloat
    live_queries: NonNegativeInt


class RequestVersions(BaseModel):
    """The versions known before the call: eight dimensions, and the model asked for.

    `concept/04`: the request carries "the full version set -- prompt, schema,
    rendering, taxonomy and model identity".

    **This is not a `VersionSet`, and the difference is one field.**
    `helena.versions.VersionSet.model_version` is "the model as the endpoint
    reported it **in the response**, not as it was configured -- the configured
    name is the thing that stays stable while what answers to it changes"
    (`docs/decisions/0008-version-registry.md`). A request is written before any
    response exists, so it cannot carry that value, and putting the configured
    name in that field would be exactly the substitution the registry exists to
    prevent: a recorded version that looks measured and was assumed.

    So the request carries the eight dimensions that *are* known plus
    `model_requested` -- what this deployment asked for -- and `completed_by`
    turns it into the nine-dimension `VersionSet` once the response has said what
    answered. `AgentResult` carries that `VersionSet`; `AgentFailure` carries this
    object and an optional reported version, because a failure may be a run where
    nothing answered at all.
    """

    model_config = _CONTRACT_MODEL_CONFIG

    prompt_version: Version
    #: The agent contract this request is written against. `AgentRequest` refuses
    #: anything but this module's own `CONTRACT_VERSION`.
    schema_version: Version
    rendering_version: Version
    taxonomy_version: Version
    enrichment_snapshot_version: Version
    normalization_snapshot_version: Version
    policy_version: Version
    aggregation_version: Version
    #: The model this deployment asked for, from configuration. Never what
    #: answered -- see the class docstring.
    model_requested: Version

    def completed_by(self, model_version: str) -> VersionSet:
        """The nine-dimension `VersionSet`, with the identity the response reported.

        The one bridge between a request's versions and a stored row's. It takes
        the reported version rather than defaulting to `model_requested`, because
        a caller that had nothing to pass would then record a plausible value
        instead of failing.
        """
        return VersionSet(
            model_version=model_version,
            **{
                dimension: getattr(self, dimension)
                for dimension in REQUEST_VERSION_DIMENSIONS
            },
        )


class AgentRequest(BaseModel):
    """What deterministic code hands an agent. One shape for both agents.

    `concept/04`, "One contract for both": the request carries "the tenant, the
    host and window in event time, the context reference **and its version**
    (which is what makes replay possible), the trigger ..., the rendering with
    explicit truncation, the budgets, and the full version set".

    **`sensor` is here and `concept/04` does not name it.** The context reference
    does not resolve without it: `helena.context.FrozenContext` is keyed by
    `(tenant, sensor, context_id, context_version)`, so a request carrying the
    tenant alone names a context that may exist under several sensors. Recorded
    as a deliberate addition in `docs/decisions/0017-the-agent-contract.md` rather
    than slipped in.

    **`emitter` is here for the same kind of reason.** `concept/04` closes the
    roots per agent and gives the two agents different tool access; a request that
    did not say which agent it is for would leave every one of those rules with
    nothing to key on. It is `helena.taxonomy`'s `triage` / `analyst`, not a
    second spelling.

    The trigger and the emitter are checked against each other:
    `scheduled_triage` is the only way a triage run begins, and
    `triage_suspicious` and `deterministic_signal` are `concept/04`'s "two
    independent inputs [that] reach the Analyst Agent". A request pairing them
    the other way would describe a pipeline this one is not.
    """

    model_config = _CONTRACT_MODEL_CONFIG

    tenant: str
    sensor: str
    #: `triage` or `analyst`, from `helena.taxonomy.EMITTERS`.
    emitter: str
    host: str
    #: The window in **event time**, from the context. Not the time the request
    #: was built: an assessment replayed later has to score the window that ran.
    window_start: datetime
    window_end: datetime
    #: The context reference and its version. `concept/04`: the version "is what
    #: makes replay possible" -- `context_id` is stable across revisions and
    #: `context_version` says which numbers were seen.
    context_id: str
    context_version: str
    trigger: str
    rendering: Rendering
    budgets: Budgets
    versions: RequestVersions

    def model_post_init(self, _context: object) -> None:
        for name in ("tenant", "sensor", "host", "context_id", "context_version"):
            if not getattr(self, name).strip():
                raise ValueError(
                    f"{name} is blank. A defaulted or empty tenant is an isolation "
                    f"failure that looks like it is working "
                    f"(`concept/instruction.md` §6)."
                )
        if self.emitter not in taxonomy.EMITTERS:
            raise ValueError(
                f"emitter {self.emitter!r} is not one of {list(taxonomy.EMITTERS)}"
            )
        if self.trigger not in TRIGGERS:
            raise ValueError(f"trigger {self.trigger!r} is not one of {list(TRIGGERS)}")
        if self.emitter == taxonomy.TRIAGE and self.trigger != SCHEDULED_TRIAGE:
            raise ValueError(
                f"a triage run is triggered by {SCHEDULED_TRIAGE!r} and this one "
                f"says {self.trigger!r}; the other two triggers are the analyst's"
            )
        if self.emitter == taxonomy.ANALYST and self.trigger == SCHEDULED_TRIAGE:
            raise ValueError(
                f"the analyst is reached by {TRIAGE_SUSPICIOUS!r} or "
                f"{DETERMINISTIC_SIGNAL!r}, never by {SCHEDULED_TRIAGE!r}; "
                f"analysis is the selective stage"
            )
        if self.window_end <= self.window_start:
            raise ValueError(
                f"the window is {self.window_start} to {self.window_end}, which "
                f"ends at or before it starts"
            )
        if self.versions.schema_version != CONTRACT_VERSION:
            raise ValueError(
                f"this is contract {CONTRACT_VERSION!r} and the request records "
                f"schema_version {self.versions.schema_version!r}. Replay validates "
                f"against the module the version names, so a request validated here "
                f"and recording another version would be replayed against classes "
                f"it never saw."
            )
        if self.rendering.version != self.versions.rendering_version:
            raise ValueError(
                f"the rendering says version {self.rendering.version!r} and the "
                f"version set records {self.versions.rendering_version!r}; two "
                f"copies of a version that can drift are worse than none"
            )
        if self.emitter == taxonomy.TRIAGE and (
            self.budgets.steps or self.budgets.live_queries
        ):
            raise ValueError(
                f"triage has no tools at all (`concept/04`) and this request "
                f"budgets {self.budgets.steps} steps and "
                f"{self.budgets.live_queries} live queries. A budget that permits "
                f"a lookup is a lookup nobody has to justify."
            )


class Citation(BaseModel):
    """A reference to a stable evidence identifier, marked supporting or contradicting.

    `concept/02`. The identifier is `helena.enrichment.evidence_id`'s -- a digest
    of the claim, stable across replays -- so a citation resolves to the row that
    was cited rather than to whatever now occupies a position.

    `concept/03`: "**evidence citations are join rows** -- `(assessment,
    evidence, role)` -- not an array buried in JSON, because citations are the
    thing most queries follow and an array is where a query goes to die." This is
    that row's payload; the increment that stores an assessment writes the join.
    """

    model_config = _CONTRACT_MODEL_CONFIG

    evidence_id: str
    stance: str

    def model_post_init(self, _context: object) -> None:
        if not self.evidence_id.strip():
            raise ValueError("a citation with no evidence id resolves to nothing")
        if self.stance not in STANCES:
            raise ValueError(
                f"stance {self.stance!r} is not one of {list(STANCES)}; a citation "
                f"that says neither is a reference, not a citation"
            )


class Gap(BaseModel):
    """A recorded thing the run could not see.

    `concept/02` names the seven kinds and `concept/instruction.md` §2 forbids
    collapsing any of them into another. The gaps list is also the audit trail
    that makes `unknown` falsifiable: `concept/04` exempts `unknown` from
    citations "because a run whose enrichment entirely failed has no evidence row
    to point at; its audit trail is the **mandatory** gaps list, which is what
    stops the exemption becoming an unfalsifiable shrug".

    `detail` is required and bounded. A gap with no detail records that something
    was missing without recording what, which is the shrug in a different costume.
    """

    model_config = _CONTRACT_MODEL_CONFIG

    kind: str
    detail: str

    def model_post_init(self, _context: object) -> None:
        if self.kind not in GAP_KINDS:
            raise ValueError(f"gap kind {self.kind!r} is not one of {list(GAP_KINDS)}")
        _bounded("gap detail", self.detail, MAX_DETAIL)


class RetrievalStep(BaseModel):
    """One result the analyst's tool loop produced: where from, when, and how.

    `concept/07`, "Caching": "the retrieval trace records, per result, whether it
    was a cache hit or a live query, and **the retrieval time of the underlying
    record**. Two runs that differ only in cache state must be distinguishable
    afterwards." All three are here, and `retrieved_at` is the underlying
    record's time, not this step's -- a cache hit's value is the age of what was
    served, which is the number that says whether the answer was current.

    Exactly one of `evidence_id` and `failure`. A query that completed produced an
    evidence row, `no_match` included -- "a lookup outcome, never a statement of
    safety". A query that did not complete produced a `QueryFailure`, which
    `concept/05` rule 4 requires to carry a typed error **and no taxonomy
    object**. A step with both would be a failure that also classified something;
    a step with neither would be a retrieval nobody can account for.
    """

    model_config = _CONTRACT_MODEL_CONFIG

    source_id: str
    entity_type: str
    entity_value: str
    outcome: str
    #: When the record served here was retrieved from the provider. For a live
    #: query, now; for a cache hit, when the cached record was fetched.
    retrieved_at: datetime
    evidence_id: str | None = None
    failure: QueryFailure | None = None

    def model_post_init(self, _context: object) -> None:
        if self.outcome not in RETRIEVAL_OUTCOMES:
            raise ValueError(
                f"outcome {self.outcome!r} is not one of {list(RETRIEVAL_OUTCOMES)}"
            )
        if self.entity_type not in ENTITY_TYPES:
            raise ValueError(
                f"entity type {self.entity_type!r} is not among {sorted(ENTITY_TYPES)}"
            )
        produced = self.evidence_id is not None
        failed = self.failure is not None
        if produced == failed:
            raise ValueError(
                "a retrieval step produced either an evidence row or a typed "
                "failure, and this one has "
                + ("both" if produced else "neither")
                + ". A failed query emits a typed error and no taxonomy object "
                "(`concept/05`, rule 4)."
            )
        if self.failure is not None and (
            self.failure.source_id != self.source_id
            or self.failure.entity_type != self.entity_type
            or self.failure.entity_value != self.entity_value
        ):
            raise ValueError(
                f"the step queried {self.source_id!r} for "
                f"{self.entity_type}:{self.entity_value!r} and its failure names "
                f"{self.failure.source_id!r} for "
                f"{self.failure.entity_type}:{self.failure.entity_value!r}"
            )


class ProposedClaim(BaseModel):
    """An agent's claim about infrastructure. A proposal, never a write.

    `concept/07`: "an agent's claim about infrastructure is a **proposal**,
    validated against a schema and written by deterministic code", and
    `concept/04`: the analyst "writes nothing -- it proposes".

    `citations` is required and non-empty. A proposal with nothing behind it is a
    guess, and the point of routing agent claims through deterministic code is
    that code can check them; there is nothing to check in an uncited assertion.
    """

    model_config = _CONTRACT_MODEL_CONFIG

    subject_type: str
    subject_value: str
    #: What is being claimed about the subject, in words. Bounded, and it is a
    #: proposal about *infrastructure* -- not an action, not a verdict.
    claim: str
    #: Confidence in the claim, 0.0-1.0. `concept/02`'s reading applies: this is
    #: confidence in the mapping, not a probability of maliciousness.
    confidence: float
    citations: tuple[Citation, ...]

    def model_post_init(self, _context: object) -> None:
        if self.subject_type not in ENTITY_TYPES:
            raise ValueError(
                f"subject type {self.subject_type!r} is not among {sorted(ENTITY_TYPES)}"
            )
        if not self.subject_value.strip():
            raise ValueError("a proposed claim with no subject is about nothing")
        _bounded("claim", self.claim, MAX_DETAIL)
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence {self.confidence} is outside 0.0-1.0")
        if not self.citations:
            raise ValueError(
                "a proposed claim carries at least one citation; deterministic "
                "code validates a proposal, and there is nothing to validate in "
                "an uncited assertion"
            )


class EvidencePackage(BaseModel):
    """The analyst's assembled reasoning over the cited evidence.

    `concept/02`: "**Evidence package** -- assembled cited evidence: indicators,
    patterns, missing information, narrative."

    **Two of those four are not fields here, and that is the point.** The
    indicators *are* `AgentResult.citations` and the missing information *is*
    `AgentResult.gaps`; copying either into the package would be two copies of one
    fact that can disagree, which `concept/instruction.md` §2 rejects in the same
    words it uses for version constants. What is left is what the package adds
    over the citations: the patterns the analyst says it saw, and the narrative
    that ties them together. `docs/decisions/0017-the-agent-contract.md` records
    the reading.

    The narrative is bounded and is an **output**, not an instruction channel:
    `concept/03` keeps it as a text column beside the typed ones, and nothing
    reads it back into a prompt.
    """

    model_config = _CONTRACT_MODEL_CONFIG

    #: The traffic or infrastructure patterns the analyst names, one per entry.
    patterns: tuple[str, ...] = ()
    narrative: str = ""

    def model_post_init(self, _context: object) -> None:
        for pattern in self.patterns:
            _bounded("pattern", pattern, MAX_DETAIL)
        if len(self.narrative) > MAX_NARRATIVE:
            raise ValueError(
                f"the narrative is {len(self.narrative)} characters and the limit "
                f"is {MAX_NARRATIVE}"
            )


class Cost(BaseModel):
    """What the run actually spent. Measured by orchestration, never by the model.

    `concept/03`: the typed columns include "budgets consumed, latency, tokens,
    cost, and **cache-hit versus live-query counts**". All of those are here
    except one.

    **There is no monetary field.** `concept/06`: "monetary model cost is
    **derived** and recorded per assessment, not separately capped -- capping it
    would double-count the enforced budget dimensions." Derived from the token
    counts and a price table, and no price table exists in this repository; a
    currency column filled from a guessed rate would be an invented external fact,
    which is the class of error this project has been burned by repeatedly.

    `retries` is here because `concept/07` makes it a measurement in its own
    right: "retries count against the budget, and **the retry count per model is
    itself a quality metric**."
    """

    model_config = _CONTRACT_MODEL_CONFIG

    prompt_tokens: NonNegativeInt
    completion_tokens: NonNegativeInt
    #: Steps of the tool loop. Zero for triage, which has no loop.
    steps: NonNegativeInt
    live_queries: NonNegativeInt
    cache_hits: NonNegativeInt
    #: Schema-validation retries spent. `concept/07`: a quality metric, not an
    #: implementation detail.
    retries: NonNegativeInt
    wall_clock_seconds: NonNegativeFloat


def _check_agent_asymmetry(emitter: str, cost: Cost) -> None:
    """Triage has no tools, so it can have spent nothing on them.

    `concept/04`'s table: triage tools "**none at all**", retrieval "none -- no
    lookups, no waiting". A triage run reporting a live query is a run that
    reached a provider, whatever the code says it did.
    """
    if emitter != taxonomy.TRIAGE:
        return
    spent = {
        "steps": cost.steps,
        "live_queries": cost.live_queries,
        "cache_hits": cost.cache_hits,
    }
    reached = {name: value for name, value in spent.items() if value}
    if reached:
        raise ValueError(
            f"a triage run reports {reached}; triage has no tools at all and no "
            f"retrieval, so a non-zero count here is a lookup that happened"
        )


class AgentResult(BaseModel):
    """A verdict. One shape for both agents, with the asymmetry as rules.

    `concept/04`: the result carries "the root and classification path,
    confidence (a number to measure, not a routing constant), citations by stable
    evidence id marked supporting or contradicting, an evidence package for the
    analyst's non-`normal` verdicts, the retrieval trace, the gaps, any proposed
    claims, the cost, the echoed versions".

    **The root is derived, not stored.** `helena.enrichment.EnrichmentEvidence`
    made the same call for the same reason: the taxonomy already refuses a path
    whose root is not its first segment, so a stored root would be a second copy
    of a fact that cannot disagree in the model and can in a table.

    ## The citation rule, from `concept/04`

    > **Citations are required except on two paths.** A `normal` triage decision
    > returns verdict and confidence only -- that costs nothing on the
    > overwhelmingly common path and gives auditability exactly where a decision
    > was made to spend analysis. `unknown` is exempt too, because a run whose
    > enrichment entirely failed has no evidence row to point at; its audit trail
    > is the **mandatory** gaps list.

    So: `unknown` requires a non-empty `gaps` and exempts citations; a `normal`
    **triage** decision carries no citations at all; everything else requires at
    least one. Gaps stay permitted on a `normal` triage decision, because
    `concept/07` requires truncation to be visible and a truncated rendering that
    triaged clean still truncated something.

    ## What triage may not carry at all

    No evidence package, no retrieval trace, no proposed claims, and a cost that
    reports no tool use. `concept/04`'s asymmetry is *"where their information
    comes from"*, and a triage result carrying a retrieval trace would be a triage
    run that retrieved.

    ## What a budget-exhausted run may not be

    `concept/07`: "a budget-truncated analyst run returns `normal`" is listed
    under what must never happen -- "it established the absence of nothing". A
    result carrying a `budget_exhausted` gap is refused if its root is `normal`.
    """

    model_config = _CONTRACT_MODEL_CONFIG

    #: `triage` or `analyst`. Carried on the result as well as on the request
    #: because the closed root set is per emitter, so a stored result has to be
    #: validatable on its own -- which is what replay does.
    emitter: str
    #: The dot-delimited, most-specific supported path, resolved against
    #: `versions.taxonomy_version` for this emitter.
    classification: str
    #: `concept/04`: "a number to measure, not a routing constant." Nothing here
    #: branches on it; it is recorded so calibration has something to calibrate.
    confidence: float
    citations: tuple[Citation, ...] = ()
    evidence_package: EvidencePackage | None = None
    retrieval_trace: tuple[RetrievalStep, ...] = ()
    gaps: tuple[Gap, ...] = ()
    proposed_claims: tuple[ProposedClaim, ...] = ()
    cost: Cost
    #: The echoed versions, completed by the identity the response reported.
    #: `RequestVersions.completed_by` is what builds one.
    versions: VersionSet

    @property
    def root(self) -> str:
        """The root of the classification -- derived, never stored."""
        return self.classification.split(".")[0]

    @property
    def evidence_ids(self) -> frozenset[str]:
        """Every evidence identifier this result cites, package and proposals included."""
        return frozenset(
            citation.evidence_id
            for citation in (
                *self.citations,
                *(
                    citation
                    for claim in self.proposed_claims
                    for citation in claim.citations
                ),
            )
        )

    def model_post_init(self, _context: object) -> None:
        if self.emitter not in taxonomy.EMITTERS:
            raise ValueError(
                f"emitter {self.emitter!r} is not one of {list(taxonomy.EMITTERS)}"
            )
        if self.versions.schema_version != CONTRACT_VERSION:
            raise ValueError(
                f"this is contract {CONTRACT_VERSION!r} and the result records "
                f"schema_version {self.versions.schema_version!r}"
            )
        # Raises TaxonomyError -- not a ValidationError -- for the reason
        # `EnrichmentEvidence` gives: a path the vocabulary does not have is a
        # taxonomy fact, and "not in the vocabulary" and "declared but unused"
        # are two different ones a caller may treat differently.
        taxonomy.for_emission(
            self.classification,
            level=taxonomy.CONTEXT,
            version=self.versions.taxonomy_version,
            emitter=self.emitter,
        )
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence {self.confidence} is outside 0.0-1.0")

        cited = [citation.evidence_id for citation in self.citations]
        if len(set(cited)) != len(cited):
            raise ValueError(
                "the same evidence id is cited twice; one row cannot both support "
                "and contradict a verdict, and a repeated stance counts once"
            )

        triage = self.emitter == taxonomy.TRIAGE
        if self.root == UNKNOWN:
            if not self.gaps:
                raise ValueError(
                    "`unknown` is exempt from citations only because the gaps list "
                    "is mandatory instead; without it the exemption is an "
                    "unfalsifiable shrug (`concept/04`)"
                )
        elif triage and self.root == NORMAL:
            if self.citations:
                raise ValueError(
                    "a `normal` triage decision returns verdict and confidence "
                    "only (`concept/04`); this one carries "
                    f"{len(self.citations)} citations"
                )
        elif not self.citations:
            raise ValueError(
                f"{self.classification!r} from {self.emitter} requires at least "
                f"one citation. Citations are required except on a `normal` "
                f"triage decision and on `unknown` (`concept/04`)."
            )

        if any(gap.kind == BUDGET_EXHAUSTED for gap in self.gaps) and self.root == NORMAL:
            raise ValueError(
                "a run that exhausted its budget may return `unknown` and may "
                "never return `normal`: it established the absence of nothing "
                "(`concept/02`, `concept/07`)"
            )

        if triage:
            if self.evidence_package is not None:
                raise ValueError(
                    "an evidence package is the analyst's; triage answers is this "
                    "worth analysing, and assembles nothing"
                )
            if self.retrieval_trace:
                raise ValueError(
                    "a triage result carries a retrieval trace, and triage has no "
                    "tools and no retrieval at all (`concept/04`)"
                )
            if self.proposed_claims:
                raise ValueError(
                    "a triage result proposes a claim; proposals come from the "
                    "analyst, which is the stage with the knowledge to make one"
                )
        elif self.root != NORMAL and self.evidence_package is None:
            raise ValueError(
                f"an analyst verdict of {self.classification!r} carries an evidence "
                f"package (`concept/04`); only a `normal` analyst verdict may omit one"
            )
        _check_agent_asymmetry(self.emitter, self.cost)


class AgentFailure(BaseModel):
    """A run that produced no verdict. The failure, and nothing that could be read as one.

    `concept/02`: "**Typed failure** -- a run that could not produce a verdict,
    stored as an assessment row carrying the failure and **no** verdict -- never a
    verdict, never a silent drop." `concept/07`: "a failed run is stored as a
    typed failure with no verdict, and is emitted", and collapsing a typed failure
    into a verdict "makes the evaluation denominator *successes* rather than
    *contexts*, and hides a degrading model behind a stable-looking accuracy
    number".

    **The rule is enforced by the shape**, the way `helena.enrichment.QueryFailure`
    enforces its own: there is no `classification` field, no `root`, no
    `confidence` and no `citations`, and `extra="forbid"` means a caller cannot
    add one. A verdict cannot be smuggled through this object because there is
    nowhere to put it.

    **`versions` is a `RequestVersions`, not a `VersionSet`**, and `model_version`
    is separate and optional. A `model_unavailable` failure is a run where nothing
    answered, so no reported model identity exists; recording the configured name
    in its place would be the substitution `docs/decisions/0008-version-registry.md`
    exists to prevent. `schema_invalid` is the opposite case -- the model answered,
    repeatedly, and none of it validated -- so a reported version is required
    there.
    """

    model_config = _CONTRACT_MODEL_CONFIG

    emitter: str
    reason: str
    #: What went wrong, for an operator. Bounded, and never a provider response,
    #: a header or a credential.
    detail: str
    #: What the run could not see. Permitted rather than required: a failure is
    #: not obliged to have discovered a gap, and an empty list here is a run that
    #: fell over before it found one.
    gaps: tuple[Gap, ...] = ()
    cost: Cost
    versions: RequestVersions
    #: The identity the model's response reported, where there was a response.
    model_version: Version | None = None

    def model_post_init(self, _context: object) -> None:
        if self.emitter not in taxonomy.EMITTERS:
            raise ValueError(
                f"emitter {self.emitter!r} is not one of {list(taxonomy.EMITTERS)}"
            )
        if self.reason not in FAILURE_REASONS:
            raise ValueError(
                f"reason {self.reason!r} is not one of {list(FAILURE_REASONS)}"
            )
        _bounded("failure detail", self.detail, MAX_DETAIL)
        if self.versions.schema_version != CONTRACT_VERSION:
            raise ValueError(
                f"this is contract {CONTRACT_VERSION!r} and the failure records "
                f"schema_version {self.versions.schema_version!r}"
            )
        if self.reason == SCHEMA_INVALID and self.model_version is None:
            raise ValueError(
                f"{SCHEMA_INVALID!r} means the model answered and the answer never "
                f"validated, so the identity that answered is known and is recorded"
            )
        if self.reason == MODEL_UNAVAILABLE and self.model_version is not None:
            raise ValueError(
                f"{MODEL_UNAVAILABLE!r} means nothing answered, and a reported "
                f"model version says something did"
            )
        _check_agent_asymmetry(self.emitter, self.cost)


def check_exchange(request: AgentRequest, outcome: AgentResult | AgentFailure) -> None:
    """The rules that hold between a request and what it produced. Raises `ContractError`.

    Three of them, and none can be checked by either object alone:

    1. **The emitter matches.** A result validated against the analyst's root set
       and paired with a triage request is a verdict nothing asked for.
    2. **The versions are echoed.** `concept/04` puts "the echoed versions" on the
       result; this is what makes the word *echoed* mean something. The eight
       dimensions known before the call must come back unchanged -- the ninth,
       the model identity, is the one thing the response is allowed to tell us.
    3. **Every citation resolves to something the run was actually given.** A
       result may cite an evidence id the rendering showed, or one its own
       retrieval trace produced, and nothing else. A citation to neither is a
       model citing evidence it was never handed, which is precisely the failure
       a stable evidence identifier exists to make detectable.

    And one rule about visibility rather than about pairing: **a rendering that
    truncated something requires a `truncated` gap on the outcome.**
    `concept/instruction.md` §2 -- "truncation is visible or it is a bug" -- and
    the place it has to stay visible is the record of the run, not only the input
    to it. Without this the rendering could drop half a host's domains and the
    stored assessment would read as a complete assessment.
    """
    if request.emitter != outcome.emitter:
        raise ContractError(
            f"the request is for {request.emitter!r} and the outcome came from "
            f"{outcome.emitter!r}"
        )

    # One comprehension over both outcome kinds: `AgentResult.versions` is a
    # `VersionSet` and `AgentFailure.versions` a `RequestVersions`, and the eight
    # dimensions below are the fields the two have in common by construction --
    # which is what `REQUEST_VERSION_DIMENSIONS` names.
    drifted = {
        dimension: (
            getattr(request.versions, dimension),
            getattr(outcome.versions, dimension),
        )
        for dimension in REQUEST_VERSION_DIMENSIONS
        if getattr(request.versions, dimension)
        != getattr(outcome.versions, dimension)
    }
    if drifted:
        raise ContractError(
            f"the outcome does not echo the request's versions: {drifted} "
            f"(request, outcome). A replayed assessment is validated against the "
            f"versions it recorded, so a recorded version that is not the one that "
            f"ran makes the replay score something else."
        )

    if isinstance(outcome, AgentResult):
        available = request.rendering.evidence_ids | {
            step.evidence_id
            for step in outcome.retrieval_trace
            if step.evidence_id is not None
        }
        unresolvable = sorted(outcome.evidence_ids - available)
        if unresolvable:
            raise ContractError(
                f"the result cites {unresolvable}, which the rendering did not "
                f"show and the retrieval trace did not produce. A citation has to "
                f"resolve to a stable evidence row the run was given."
            )

    if request.rendering.truncations and not any(
        gap.kind == TRUNCATED for gap in outcome.gaps
    ):
        dropped = [truncation.section for truncation in request.rendering.truncations]
        raise ContractError(
            f"the rendering truncated {dropped} and the outcome records no "
            f"{TRUNCATED!r} gap. Silent truncation is a correctness bug, and an "
            f"assessment that does not record it reads as a complete one."
        )


CONTRACT = ContractVersion(
    version=CONTRACT_VERSION,
    request=AgentRequest,
    result=AgentResult,
    failure=AgentFailure,
)
