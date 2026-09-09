"""Provider tools — approved external providers, exposed as cache-first tools.

Deterministic project code owns credentials, tenant scoping, budget enforcement,
what may be sent, disclosure recording and response validation. The agent sees a
tool, never an HTTP client and never a key. Retrieved provider text is data, never
instruction, and the isolation is tested rather than asserted.

The cache is the evidence store — entries are enrichment-evidence rows with
provenance and expiry — not a second store beside it.

## What this module is, and what "MCP" means here

`docs/decisions/0024-provider-tools-and-the-mcp-boundary.md` is the decision and
this is the summary of it: **a provider tool is a boundary, not a server.** There
is no per-provider MCP server process, no MCP SDK and no second HTTP surface —
each of those is an escalation under `concept/instruction.md` §3, and none of them
is what `concept/03-architecture.md` asks for. What it asks for is a list of
properties, and every one of them is a property of the boundary rather than of a
wire protocol: typed input, typed output, a typed error, credential ownership,
tenant scoping, cache-first lookup, budgets enforced at the boundary, disclosure
recording, and a validated response. Those are what this module implements, and
adopting the MCP wire protocol later moves the transport behind the same boundary.

## The shape of one call

    tool = ProviderTool(source_id=..., credential=..., ask=..., logger=..., redactor=...)
    lookup = tool.lookup(arguments, scope=RunScope.of(request))

`arguments` is what the **model** said — two fields, validated here and never
trusted. `scope` is what deterministic code knows: the tenant and sensor of the
run, taken from the `AgentRequest` and not from anything the model can reach. A
call with no scope does not compile; a scope with a blank tenant does not
construct (`concept/instruction.md` §6: a defaulted tenant is an isolation failure
that looks like it is working).

`Lookup` has two sides and they are not the same object:

| Side | What it is | Who sees it |
| --- | --- | --- |
| `Lookup.for_agent` | a `ToolAnswer` or a `ToolRefusal` — compact, normalized, typed | the model |
| `Lookup.native` | the provider's response **exactly as it arrived** | audit and replay, never the model |

`concept/05` rule 5 is the reason there are two: *"retain the native payload for
audit; the compact normalized object is what downstream consumers compare across
sources."* Retaining it and showing it are different acts, and this is where they
are different.

## The four ways a call does not produce a claim

None of them is `no_match`, and none of them collapses into another
(`concept/instruction.md` §2):

| What happened | What the agent gets | Cost |
| --- | --- | --- |
| the tool layer would not send the call at all | `ToolRefusal`, with a typed reason | a step, no live query |
| the query ran and did not complete | `ToolAnswer` whose one step carries a `QueryFailure` | a step and a live query |
| the query completed and the provider lists nothing | evidence classified `no_match` — an answer | a step and a live query |
| the source is not registered | no tool exists; `ProviderTool` cannot be built | nothing |

Three of the refusals are the run's budget rather than the call: a spent step
count, a spent live-query quota and a spent wall clock all arrive as a
`ToolRefusal` carrying `budget_exhausted`. They are refusals and not failures
because nothing was queried — see "Budgets, at this boundary" below.

The last one is deliberate: `ProviderTool` resolves its descriptor through
`helena.enrichment.source`, so a tool for an unregistered source raises
`SourceError` at construction. **Registration is the gate**, and adding a source
stays the governed decision `concept/05` says it is rather than becoming a
constructor argument.

## Cache-first, where the cache is the evidence store

`concept/07`: *"On each call it looks for a valid, unexpired record for its
source, endpoint and indicator, and returns it without touching the network; it
queries only on a miss or an expiry."* `EvidenceCache` is that lookup and it is
**not a second store** — it reads and writes
`sql/migrations/0017_analyst_lookup_cache.sql`'s two tables in the one streaming
engine, in the evidence shape 0011 defined. A separate opaque cache was rejected
because an assessment could then cite something the cache had already evicted,
and nothing here evicts: `expires_at` bounds *validity*, never lifetime.

Five things follow, and `docs/decisions/0025-the-lookup-cache.md` argues each:

| | |
| --- | --- |
| a hit costs nothing and **discloses nothing** | the indicator was disclosed when the entry was fetched, so caching is a privacy control as much as a cost control |
| `no_match` **is cached** | most lookups miss; caching only hits would leave the cache almost never useful and re-disclose the same indicator every run |
| a failure is **not** cached | an outage is not a record of what a source said, and caching one would let a five-minute outage suppress every query for the retention window |
| an expired entry is served **explicitly stale** when the live query fails | the record was not evicted, so it is still there and still citable; `concept/02` defines `stale` as exactly this — the claim stands and its age is part of what it is worth |
| retention is per source **and** per endpoint | a registration date never changes while a risk score moves, so one number for a provider is one number too few |

`retrieved_at` on the retrieval step is the **underlying record's** time on a
cache hit, not the step's, which is what makes two runs differing only in cache
state distinguishable afterwards.

## Budgets, at this boundary

`concept/07`: **"budgets are enforced at the tool boundary, so an agent cannot
reason its way around them"**, and `concept/05`'s tool rules say the same in the
same words. `lookup` takes a `helena.budgets.RunBudget` — keyword-only, no
default, one per agent run — and charges it before it does anything else:

| | |
| --- | --- |
| a step | every accepted call, including one then refused as malformed. That is what bounds the loop |
| the wall clock | checked on the same ledger the model calls use, so a provider wait shortens the time left to reason |
| a live query | **after** the cache read, so a hit costs nothing and discloses nothing |
| tokens | not here. A tool call spends none; `helena.agents.assess` charges those |

There is no argument a model could put a budget in and no prompt line that could
grant one, which is the property the boundary is for. What the model sees when a
dimension is spent is a typed `ToolRefusal`, and what the *assessment* records is
a `budget_exhausted` gap from `RunBudget.gap()` — `helena.budgets.degraded` is
what puts it there, and it is why a truncated run may return `unknown` and may
never return `normal`.

Reads: `helena.enrichment.SOURCES` (the descriptor: tier, entity types, declared
subset) and `helena_reference_evidence_analyst`. Writes:
`helena_reference_analyst_response` (the bytes, before they are evaluated) and
`helena_reference_analyst_evidence` (the claims read out of them).

Maturity: experimental — the layer is exercised end to end against a stand-in
provider adapter over the committed ThreatFox export shape, against a real
migrated engine for the cache, and against the real credential from `.env` for
the isolation properties. **No live provider has been queried through it**: the
query surface of the hunting API is confirmed, and the adapter written against
it, in the first-live-provider increment. The disclosure record is named in the
docstring above because it is the layer's, and is **not built here** — see the
"deliberately not here" section below.

## Deliberately not here, and named so a green suite does not read as a finished layer

- **Pacing calls to the configured rate.** `config/policy.toml` states the rate
  the tool layer holds itself to, and the live-query budget is derived from it;
  nothing sleeps between calls. The adapter that speaks to a live provider is
  what has to, and the wall-clock budget is what catches it when it does.
- **The disclosure record.** A call is logged locally; no disclosure row exists,
  and the send policy that decides *what may be sent to which source* is not
  written. In particular an indicator the model invents is sent as readily as one
  the context observed — `ToolCall` bounds and types the argument, it does not
  check it against the host context.
- **Aggregator origin retention** (`concept/05` rule 7). `ProviderClaim` has no
  origin field and `EnrichmentEvidence` has no column for one; no registered
  source is an aggregator, and the first one that is arrives with both.
- **Pruning the cache.** Nothing is ever deleted, deliberately (see above), and
  nothing bounds the growth either. What a prune may keep is a function of how
  far back replay has to reach, which `concept/08` still lists as open.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import psycopg
from psycopg.types.json import Jsonb
from pydantic import BaseModel, ConfigDict, ValidationError

from helena import taxonomy
from helena.budgets import BudgetExhausted, RunBudget
from helena.config import Secret
from helena.contracts import v1 as contract
from helena.enrichment import (
    ANALYST_TIER,
    ENTITY_TYPES,
    MALFORMED_RESPONSE,
    MAX_FAILURE_DETAIL,
    NO_MATCH,
    OK,
    QUERY_FAILURE_REASONS,
    STALE,
    Claim,
    EnrichmentEvidence,
    QueryFailure,
    SourceDescriptor,
    Tier,
    UndeclaredClaim,
    check_claim,
    evidence_id,
    source,
)
from helena.observability import Redactor, StructuredLogger

__all__ = [
    "ANALYST_EVIDENCE_TABLE",
    "ANALYST_EVIDENCE_VIEW",
    "ANALYST_RESPONSE_TABLE",
    "BUDGET_EXHAUSTED",
    "DEFAULT_PORTS",
    "ENDPOINT",
    "ENTITY_TYPE_NOT_COVERED",
    "MALFORMED_ARGUMENTS",
    "MAX_INDICATOR",
    "REFUSAL_REASONS",
    "CacheEntry",
    "CacheKey",
    "EvidenceCache",
    "Lookup",
    "NativeResponse",
    "ProviderAnswer",
    "ProviderClaim",
    "ProviderQueryFailed",
    "ProviderTool",
    "RunScope",
    "ToolAnswer",
    "ToolCall",
    "ToolError",
    "ToolRefusal",
    "Unscoped",
    "content",
    "normalize_indicator",
    "response_version",
]

#: How long an indicator a model asks about may be. A domain is at most 253
#: characters and a URL in this project's own data is far shorter than this; the
#: bound is here because an unbounded tool argument is a way to push a payload at
#: a provider through a tool that was asked for an indicator. It is a bound, not
#: a send policy: whether an indicator the context never observed may be sent at
#: all is the send-policy increment's decision, and until it lands one can be.
MAX_INDICATOR = 2048

#: Why the tool layer would not send a call. **Not** a `QueryFailure`: nothing
#: was queried, so there is no provider to attribute a failure to, and calling it
#: a `transport_error` would be recording an outage that did not happen. Not a
#: `no_match` either, which is an answer.
#:
#:   malformed_arguments      what the model produced is not a tool call: a
#:                            missing field, an extra one, a blank indicator, one
#:                            longer than `MAX_INDICATOR`, an unknown entity type
#:   entity_type_not_covered  a well-formed call about something this source does
#:                            not answer about -- `concept/05`, "a JA3 list has
#:                            nothing to say about a domain"
#:   budget_exhausted         the run has no step, no live query or no wall clock
#:                            left. `concept/07`: budgets are enforced at the tool
#:                            boundary "so an agent cannot reason its way around
#:                            them", and this is the boundary saying so in a field
#:                            the model can read and not argue with
MALFORMED_ARGUMENTS = "malformed_arguments"
ENTITY_TYPE_NOT_COVERED = "entity_type_not_covered"
#: The gap kind, reused rather than respelled: the refusal the model sees and the
#: gap the assessment records are the same fact at two layers, and a second
#: spelling of it is the drift `concept/instruction.md` §2 rejects for version
#: constants. `tests/test_tools.py` asserts they are one string.
BUDGET_EXHAUSTED = contract.BUDGET_EXHAUSTED
REFUSAL_REASONS = (MALFORMED_ARGUMENTS, ENTITY_TYPE_NOT_COVERED, BUDGET_EXHAUSTED)


class ToolError(RuntimeError):
    """The tool layer was misconfigured or misused. Never a provider's fault."""


class Unscoped(ToolError):
    """A call arrived without the tenant and sensor that scope it.

    Its own error because of what the alternative looks like: a defaulted tenant
    is an isolation failure that looks like it is working
    (`concept/instruction.md` §6), and a lookup that quietly used the empty string
    would mint evidence identifiers no deployment owns.
    """


class ProviderQueryFailed(Exception):
    """The adapter's way of saying the query did not complete.

    Carries one of `helena.enrichment.QUERY_FAILURE_REASONS` and a bounded
    detail, and becomes a `QueryFailure` on the retrieval step **with no taxonomy
    object** (`concept/05` rule 4: a timeout is never `no_match` and never
    `unknown`).

    One exception with a typed reason rather than five classes: the vocabulary
    already exists and is closed, and a second spelling of it in a class
    hierarchy is the drift the version rules exist to prevent.

    Anything else an adapter raises **propagates**. Catching every exception and
    calling it a provider failure is `concept/instruction.md` §6's "catching an
    exception and continuing": a bug in the adapter would then be recorded as an
    outage at the provider, and the count of provider failures would stop meaning
    anything.
    """

    def __init__(self, reason: str, detail: str = "") -> None:
        if reason not in QUERY_FAILURE_REASONS:
            raise ToolError(
                f"reason {reason!r} is not one of {list(QUERY_FAILURE_REASONS)}"
            )
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


# --- What the model may say, and what deterministic code adds to it -----------


class ToolCall(BaseModel):
    """The two arguments a model may give a provider tool. Validated, never trusted.

    **There is no tenant field, and that is the design.** `concept/03`: the tool
    layer owns tenant scoping. A tenant the model could name is a tenant the model
    could get wrong, so the scope comes from the `AgentRequest` through `RunScope`
    and the model is not offered a way to influence it.

    The closed vocabulary on `entity_type` is enforced here, in a validator, which
    means `model_json_schema()` cannot see it -- the measurement in
    `docs/decisions/0020-the-model-client.md` §3 says an unenumerated closed
    vocabulary is one the model invents a value for. `ProviderTool.declaration`
    injects the enum, and narrows it further to what the source covers.
    """

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    entity_type: str
    entity_value: str

    def model_post_init(self, _context: object) -> None:
        if self.entity_type not in ENTITY_TYPES:
            raise ValueError(
                f"entity type {self.entity_type!r} is not among {sorted(ENTITY_TYPES)}"
            )
        if not self.entity_value.strip():
            raise ValueError("a blank indicator is not something to ask about")
        if len(self.entity_value) > MAX_INDICATOR:
            raise ValueError(
                f"the indicator is {len(self.entity_value)} characters and the "
                f"bound is {MAX_INDICATOR}"
            )


@dataclass(frozen=True)
class RunScope:
    """The tenant and sensor one agent run is scoped to. Not the model's to choose.

    `of` takes them from the request, which is the only place they come from:
    `helena.contracts.v1.AgentRequest` already refuses a blank tenant, so a scope
    built from a request cannot be blank, and one built directly is checked here
    for the case a caller assembles it by hand.
    """

    tenant: str
    sensor: str

    def __post_init__(self) -> None:
        for name in ("tenant", "sensor"):
            if not getattr(self, name).strip():
                raise Unscoped(
                    f"{name} is blank. A defaulted or empty tenant is an "
                    f"isolation failure that looks like it is working "
                    f"(`concept/instruction.md` §6)."
                )

    @classmethod
    def of(cls, request: contract.AgentRequest) -> RunScope:
        return cls(tenant=request.tenant, sensor=request.sensor)


# --- What a provider adapter hands back --------------------------------------


@dataclass(frozen=True)
class ProviderClaim:
    """One statement an adapter read out of a provider's answer.

    The adapter's whole job, per `concept/05` rules 1-3: map deterministically
    from native fields into the source's declared subset, and emit the parent
    rather than guessing a child. It does **not** decide whether the path is
    declared -- that is checked here, against the registry, so a mapping and its
    declaration cannot drift apart quietly.

    `native_record` is the publisher's own identifier for the record, and it is in
    the evidence digest for the reason `helena.enrichment.evidence_id` gives: a
    digest over source, response and entity alone would make several claims about
    one entity a single row and silently keep the last.
    """

    path: str
    scope_type: str
    scope_value: str
    native_record: str
    confidence: float | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    valid_until: datetime | None = None
    native_evidence: Mapping[str, Any] | None = None

    @property
    def evidence(self) -> dict[str, Any]:
        """The minimal native fields that justify this mapping -- `concept/05` rule 5.

        *Minimal* is the operative word and it is the adapter's judgement: what
        justifies this mapping, not the provider's whole response. The whole
        response is `NativeResponse`, and it is not agent-visible.
        """
        return dict(self.native_evidence or {})


@dataclass(frozen=True)
class ProviderAnswer:
    """A completed query: the body exactly as it arrived, and what was read out of it.

    `claims` is never empty. A provider that lists nothing has **answered**, and
    the answer is a claim of `no_match` -- "a lookup outcome, never a statement of
    safety" (`concept/02`). An empty tuple would be a third thing between an
    answer and a failure, which is the collapse `concept/instruction.md` §2
    forbids, so it is refused here rather than interpreted.
    """

    body: bytes
    claims: tuple[ProviderClaim, ...]

    def __post_init__(self) -> None:
        if not self.claims:
            raise ToolError(
                "a completed query with no claims: a provider that lists nothing "
                f"answered {NO_MATCH!r}, and an empty result would be neither an "
                "answer nor a failure"
            )


class NativeResponse(BaseModel):
    """The provider's response, retained for audit. Never shown to the agent.

    `concept/05` rule 5 and the MCP-tool rules: retain the native payload, and
    *"store the response before it is evaluated, cited by stable identifier, or an
    assessment that depended on a live lookup cannot be replayed because the
    provider's answer will have changed."*

    `response_version` is that identifier, and it is what a live answer has
    instead of a feed snapshot: a digest of the bytes. Two calls that got the same
    answer carry the same version and mint the same evidence identifiers, which is
    the property replay needs and the cache increment will store against.

    The bytes are held **exactly as they arrived** -- the same rule quarantine
    follows -- because a payload normalized before it is stored is a payload no
    audit can compare against what the provider actually sent.
    """

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    source_id: str
    entity_type: str
    entity_value: str
    retrieved_at: datetime
    body: bytes

    @property
    def response_version(self) -> str:
        return response_version(self.body)


def response_version(body: bytes) -> str:
    """The stable identifier of one provider answer: a digest of its bytes."""
    return hashlib.sha256(body).hexdigest()


def _why(invalid: ValidationError) -> str:
    """A validation failure as field-and-reason, built from the error's structure.

    Not `str(invalid)`, and the two differences are both about what crosses back
    to the agent. Pydantic's rendering echoes the **input** -- which is text the
    model or a provider chose, coming back through a field the tool layer is
    supposed to own -- and it appends a documentation **URL**, which puts a link
    in a place this project's rule says a URL may not be. `errors()` gives the
    location and the message with neither.
    """
    return "; ".join(
        f"{'.'.join(str(part) for part in error['loc'])}: {error['msg']}"
        for error in invalid.errors()
    )


# --- What the agent sees ------------------------------------------------------


class ToolRefusal(BaseModel):
    """The tool layer would not send this call. No provider was asked.

    Agent-visible, typed, and countable. It is deliberately not a `QueryFailure`:
    nothing was queried, and recording a refusal as a provider outage would make
    the provider-failure count a number nobody can act on.
    """

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    source_id: str
    reason: str
    #: What the caller may do about it, in words. Redacted and bounded by the
    #: tool that builds it, for the reason `QueryFailure.detail` is: an unbounded
    #: diagnostic is where a payload ends up.
    detail: str = ""

    def model_post_init(self, _context: object) -> None:
        if self.reason not in REFUSAL_REASONS:
            raise ValueError(f"reason {self.reason!r} is not one of {list(REFUSAL_REASONS)}")
        if len(self.detail) > MAX_FAILURE_DETAIL:
            raise ValueError(
                f"detail is {len(self.detail)} characters and the limit is "
                f"{MAX_FAILURE_DETAIL}"
            )


class ToolAnswer(BaseModel):
    """One completed call, as the agent sees it: compact, normalized, citable.

    Two collections and they answer different questions. `evidence` is *what the
    source said*, in the shape every other source's claims are compared in.
    `steps` is *how it got here* -- `concept/07`'s retrieval trace, one step per
    record, recording cache-hit-or-live and the retrieval time of the underlying
    record.

    `evidence_tier` is `analyst` on everything this layer produces, and that tag
    is what keeps a live lookup out of the precomputed triage path
    (`concept/03`): without it a report fetched during one investigation would
    appear in the context of every later host that talked to the same address.

    A query that did not complete is **one step carrying a `QueryFailure` and no
    evidence at all**. `concept/05` rule 4: a typed error, and no taxonomy object.

    **One case puts a failure beside evidence, and only one:** the live query
    failed and the cache still held an expired record, which is served
    explicitly `stale`. Rule 4 is not bent by it, because the rule is about a
    *query's own* result and there are two retrievals in that answer -- the live
    query, which produced a typed error and no taxonomy object, and the cache
    read, which produced rows from a query that completed days ago. Both are
    steps, both are visible, and the served rows say `stale` on every one. A
    failure beside an `ok` row is still refused here.
    """

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    source_id: str
    evidence_tier: str
    evidence: tuple[EnrichmentEvidence, ...]
    steps: tuple[contract.RetrievalStep, ...]

    def model_post_init(self, _context: object) -> None:
        if self.evidence_tier != ANALYST_TIER:
            raise ValueError(
                f"a provider tool produces {ANALYST_TIER!r}-tier evidence and this "
                f"answer says {self.evidence_tier!r}; the tier is what keeps a "
                f"live lookup out of the triage path (`concept/03`)"
            )
        if not self.steps:
            raise ValueError("a completed call produced no retrieval step")
        failures = [step for step in self.steps if step.failure is not None]
        if failures:
            fresh = [record for record in self.evidence if record.status != STALE]
            if len(failures) > 1 or fresh:
                raise ValueError(
                    "a query that did not complete emits a typed error and no "
                    "taxonomy object (`concept/05` rule 4). The one answer that "
                    "carries both is a failed live query beside an expired record "
                    f"served explicitly stale, and this one has {len(failures)} "
                    f"failures and {len(fresh)} claims that are not stale"
                )
            if len(self.steps) != len(self.evidence) + 1:
                raise ValueError(
                    f"{len(self.steps)} steps for {len(self.evidence)} stale "
                    "records and one failure; the trace has to account for every "
                    "record it served and for the query that did not complete"
                )
        cited = {step.evidence_id for step in self.steps if step.failure is None}
        produced = {record.evidence_id for record in self.evidence}
        if cited != produced:
            raise ValueError(
                "every retrieval step cites a record of this answer and every "
                "record has a step; a step citing an identifier that is not "
                "here is a citation nothing resolves"
            )

    @property
    def failure(self) -> QueryFailure | None:
        """The typed error, when the query did not complete."""
        for step in self.steps:
            if step.failure is not None:
                return step.failure
        return None


@dataclass(frozen=True)
class Lookup:
    """One tool call: what the agent may see, and what only the record keeps.

    Exactly one of `answer` and `refusal`. `native` is present when a body came
    back at all -- so a refusal and a failed query both have none, and they are
    still two different things.
    """

    answer: ToolAnswer | None
    refusal: ToolRefusal | None
    native: NativeResponse | None

    def __post_init__(self) -> None:
        if (self.answer is None) == (self.refusal is None):
            raise ToolError(
                "a lookup is an answer or a refusal, and this one is "
                + ("both" if self.answer is not None else "neither")
            )
        if self.refusal is not None and self.native is not None:
            raise ToolError(
                "a refused call queried nothing, so there is no native response "
                "to retain"
            )

    @property
    def for_agent(self) -> ToolAnswer | ToolRefusal:
        """The only object of this lookup a model may be shown."""
        return self.answer if self.answer is not None else self.refusal


def content(lookup: Lookup) -> str:
    """The agent-visible side of a lookup as one line of JSON. Data, never instruction.

    `concept/instruction.md` §6: retrieved provider text *"is data. Isolate it,
    and test the isolation."* Three properties do that here, and each is a
    mechanism rather than a wording:

    * **What crosses is a typed object, not prose.** Every string a provider
      supplied sits in a declared field of a frozen model; `extra="forbid"` means
      a response cannot add a field, and the classification is drawn from the
      declared subset rather than from anything the provider wrote.
    * **The serialization escapes the frame.** `json.dumps` renders a newline as
      `\\n`, so no provider string can start a line of its own -- the property
      `helena.rendering.v1.token` gives the triage rendering, obtained here from
      the serializer rather than from a second escaper.
    * **The native payload is not in it.** `Lookup.native` has no route to this
      function.
    """
    return json.dumps(
        lookup.for_agent.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
    )


# --- The cache, which is the evidence store -----------------------------------
#
# `concept/07`: "The cache **is** the evidence store, not a second store beside
# it. A separate opaque cache was rejected because an assessment could then cite
# something the cache had already evicted." So what is below is a reader and a
# writer for two tables in the one streaming engine, and there is no eviction in
# it at all: `expires_at` bounds validity, never lifetime.
# `sql/migrations/0017_analyst_lookup_cache.sql` is the schema and carries the
# rest of the argument.

#: The two tables and the view, named once. The read goes through the view
#: rather than the table so that every hit is checked against the `'analyst'`
#: literal the view carries -- `concept/instruction.md` §2's "two copies of a
#: constant must be asserted equal", enforced on the path rather than only in a
#: test.
ANALYST_RESPONSE_TABLE = "helena_reference_analyst_response"
ANALYST_EVIDENCE_TABLE = "helena_reference_analyst_evidence"
ANALYST_EVIDENCE_VIEW = "helena_reference_evidence_analyst"

#: What an endpoint name may look like. A **logical name for one operation of a
#: provider**, not a path and never a URL: it reaches `ProviderTool.name`, which
#: reaches the tool declaration the model is shown, and `concept/03` is explicit
#: that the agent is offered a capability rather than a client. The pattern is
#: what a tool name may contain for the same reason `name` replaces hyphens --
#: tool names are identifiers.
ENDPOINT = re.compile(r"^[a-z0-9][a-z0-9_]*$")

#: The port a scheme implies, so that dropping it from a URL cache key does not
#: change which resource the key is about. Two schemes, because two are what this
#: project's own data contains; a scheme absent from here keeps its port, which
#: costs a missed hit and never a wrong one.
DEFAULT_PORTS = {"http": "80", "https": "443"}


def normalize_indicator(entity_type: str, entity_value: str) -> str:
    """The indicator as a cache key: one spelling per thing asked about.

    `concept/08` lists this as an open question with a measurement attached to
    it -- *"cache-key normalization, because inconsistent keys quietly halve the
    hit rate"* -- and the rule that resolves it has to be stated before the
    folding is, because the folding is only safe under it:

        **Fold only what the identifier's own specification makes equivalent,
        and when in doubt leave the value exactly as it is.**

    The asymmetry is the whole argument. A fold that is too timid costs one
    live query and one re-disclosure of an indicator that was already
    disclosed. A fold that is too eager serves *one indicator's evidence for a
    different indicator*, which is a wrong answer with a citation on it. So
    every rule below is a documented equivalence and nothing here is a guess:

    | Type | Folded | Left alone |
    | --- | --- | --- |
    | `address` | the textual form, through `ipaddress` -- `2001:0DB8::0001` and `2001:db8::1` are one address (RFC 5952) | anything that does not parse as an address |
    | `domain` | ASCII case and trailing dots, matching what `sql/migrations/0008` does to an observed name | IDN forms: `xn--55qx5d.cn` and its U-label stay two keys |
    | `url` | the scheme's case, the host's case, a default port, and an empty path (RFC 3986 §6.2.2-6.2.3) | the path's case, the query, the fragment, and anything that is not a hierarchical URI |
    | `fingerprint` | case -- a JA3 is a hex digest | everything else |

    Two of those "left alone" rows are deliberate gaps rather than oversights.
    **IDN is not folded** because the fold needs an IDNA implementation this
    project does not have a dependency for, and `sql/migrations/0008` already
    records that the engine has no IDNA function either and that the loader
    punycodes instead. **The fragment is not dropped** even though a server
    never sees one, because a threat-intelligence provider matches the literal
    URL string it was given, so two URLs differing only in a fragment are two
    questions until a provider says otherwise.

    Normalization never changes **what is sent**: the adapter is handed the
    `ToolCall` with the caller's own spelling, and this value is the key the
    store is searched by and the subject the claim is recorded against.

    Raises `ToolError` for an entity type with no rule, rather than returning the
    value unfolded -- a fifth entity type added to `ENTITY_TYPES` would otherwise
    get no normalization and nobody would find out.
    """
    text = entity_value.strip()
    try:
        rule = _NORMALIZERS[entity_type]
    except KeyError:
        raise ToolError(
            f"no cache-key normalization is defined for entity type "
            f"{entity_type!r}; an unnormalized key is a hit rate nobody measures"
        ) from None
    return rule(text)


def _normalized_address(text: str) -> str:
    """The address's own textual form, or the text untouched if it is not one."""
    try:
        return ipaddress.ip_address(text).compressed
    except ValueError:
        return text


def _normalized_domain(text: str) -> str:
    """Lowercased and stripped of trailing dots -- 0008's rule, in Python.

    Not byte-identical to the engine's: RisingWave 3.0.3's `lower()` is
    ASCII-only (measured, `sql/migrations/0008`) and Python's is not, so a
    non-ASCII U-label in uppercase folds here and does not there. Nothing joins
    this key against `normalized_name` today; the increment that joins an
    analyst-tier claim to a context owes the reconciliation, and this is where it
    is written down.
    """
    return text.lower().rstrip(".")


def _normalized_url(text: str) -> str:
    """RFC 3986 syntax-based normalization, hand-rolled and no further.

    Hand-rolled because `helena.tools` imports no URL machinery at all -- the
    boundary test in `tests/test_tools.py` reads that off the module's own AST,
    and it is the property that makes "the layer holds no endpoint and no HTTP
    client" a fact rather than a promise. The parse below is therefore the
    smallest one that can lowercase a scheme and an authority.

    A value that is not a hierarchical URI is returned unchanged, which is the
    conservative direction: it can only cost a hit.
    """
    scheme, marker, rest = text.partition(":")
    if not marker or not rest.startswith("//") or not scheme.isascii() or not scheme:
        return text
    scheme = scheme.lower()
    rest = rest[2:]
    cut = min(
        (position for position in (rest.find(c) for c in "/?#") if position >= 0),
        default=len(rest),
    )
    authority, remainder = rest[:cut], rest[cut:]
    userinfo, at, host = authority.rpartition("@")
    host, colon, port = host.rpartition(":")
    if not colon:
        host, port = port, ""
    host = host.lower()
    if port in ("", DEFAULT_PORTS.get(scheme)):
        colon, port = "", ""
    if not remainder and scheme in DEFAULT_PORTS:
        # RFC 3986 §6.2.3: for a scheme that defines a hierarchical path, an
        # empty path and "/" identify the same resource.
        remainder = "/"
    return f"{scheme}:" + "//" + userinfo + at + host + colon + port + remainder


def _normalized_fingerprint(text: str) -> str:
    return text.lower()


_NORMALIZERS: Mapping[str, Callable[[str], str]] = {
    "address": _normalized_address,
    "domain": _normalized_domain,
    "url": _normalized_url,
    "fingerprint": _normalized_fingerprint,
}


@dataclass(frozen=True)
class CacheKey:
    """What a cached record is looked up by: source, endpoint and indicator.

    `concept/07` names those three; the tenant and the sensor are here for the
    reason they are in `evidence_id` and in the event id -- two deployments
    asking the same provider about the same address must not read each other's
    records, and a cache is the easiest place for that to happen quietly.
    """

    tenant: str
    sensor: str
    source_id: str
    endpoint: str
    entity_type: str
    #: The indicator as the caller asked about it. `indicator` is what is
    #: matched on; this is what was disclosed.
    entity_value: str

    @property
    def indicator(self) -> str:
        return normalize_indicator(self.entity_type, self.entity_value)

    @classmethod
    def of(cls, descriptor: SourceDescriptor, endpoint: str, call: ToolCall, scope: RunScope):
        return cls(
            tenant=scope.tenant,
            sensor=scope.sensor,
            source_id=descriptor.source_id,
            endpoint=endpoint,
            entity_type=call.entity_type,
            entity_value=call.entity_value,
        )

    @property
    def columns(self) -> tuple[str, str, str, str, str, str]:
        """The values of the WHERE clause below, in its order."""
        return (
            self.tenant,
            self.sensor,
            self.source_id,
            self.endpoint,
            self.entity_type,
            self.indicator,
        )


_WHERE_KEY = (
    "WHERE tenant = %s AND sensor = %s AND source_id = %s AND endpoint = %s "
    "AND entity_type = %s AND entity_value_key = %s"
)

#: The evidence columns a stored claim is rebuilt from, in one order used by the
#: SELECT and by the row that reads it.
_EVIDENCE_COLUMNS = (
    "evidence_id",
    "source_id",
    "source_tier",
    "snapshot_version",
    "entity_type",
    "entity_value",
    "classification",
    "taxonomy_version",
    "confidence",
    "scope_type",
    "scope_value",
    "first_seen",
    "last_seen",
    "valid_until",
    "native_evidence",
)


@dataclass(frozen=True)
class CacheEntry:
    """One stored answer: the response, the claims read out of it, and its dates.

    `status` is **not** a field, and that is the same decision
    `helena.enrichment.feed_status` made: `ok` and `stale` are properties of
    *now*, and a stored one would be wrong the moment time passed. `evidence`
    derives it against the clock the run was given, so two records served in one
    answer cannot disagree about what time it is.
    """

    key: CacheKey
    response_version: str
    retrieved_at: datetime
    expires_at: datetime
    body: bytes
    claims: tuple[Mapping[str, Any], ...]

    def expired(self, now: datetime) -> bool:
        return now >= self.expires_at

    def evidence(self, now: datetime) -> tuple[EnrichmentEvidence, ...]:
        """The stored claims as evidence rows, dated against `now`.

        The classification is re-validated on the way out -- but against the
        `taxonomy_version` **the row recorded**, which is what `EnrichmentEvidence`
        does with it, and never against today's declared subset.
        `concept/instruction.md` §2: replay validates against the version the
        assessment recorded, and migrating an old row forward is forbidden.
        """
        status = STALE if self.expired(now) else OK
        return tuple(
            EnrichmentEvidence(status=status, **claim) for claim in self.claims
        )

    @property
    def native(self) -> NativeResponse:
        """The provider's response as it arrived, rebuilt from the store.

        This is what makes replay a replay: the object a cache hit returns
        carries the same bytes the live query returned, so an assessment that
        depended on a lookup can be re-read against what the provider actually
        said rather than against what it would say today.
        """
        return NativeResponse(
            source_id=self.key.source_id,
            entity_type=self.key.entity_type,
            entity_value=self.key.entity_value,
            retrieved_at=self.retrieved_at,
            body=self.body,
        )


class EvidenceCache:
    """The cache-first read and the write behind it, over the one store.

    Not a store of its own: every statement below addresses
    `sql/migrations/0017_analyst_lookup_cache.sql`'s tables in the same engine
    the rest of the system uses, in the evidence shape `sql/migrations/0011`
    defined.

    It holds a `psycopg.Connection` and nothing else -- no state, no in-process
    dictionary in front of it. A memoization layer here would be the second store
    `concept/instruction.md` §2 forbids, and it would make two runs in one process
    differ from two runs in two.
    """

    __slots__ = ("_connection",)

    def __init__(self, connection: psycopg.Connection) -> None:
        self._connection = connection

    def read(self, key: CacheKey) -> CacheEntry | None:
        """The most recent stored answer for this key, expired or not. `None` on a miss.

        Expiry is **not** filtered here on purpose. The caller needs to tell a
        miss from an expiry: a miss means query, and an expiry means query and
        fall back to this record if the query does not complete. Filtering here
        would collapse the two into one absence, and the record that could have
        been served explicitly stale would be one nobody knew was there.
        """
        self._connection.execute("FLUSH")
        newest = self._connection.execute(
            f"SELECT snapshot_version, retrieved_at, expires_at "
            f"FROM {ANALYST_EVIDENCE_VIEW} {_WHERE_KEY} "
            f"ORDER BY retrieved_at DESC, snapshot_version DESC LIMIT 1",
            key.columns,
        ).fetchall()
        if not newest:
            return None
        response_version, retrieved_at, expires_at = newest[0]
        rows = self._connection.execute(
            f"SELECT evidence_tier, {', '.join(_EVIDENCE_COLUMNS)} "
            f"FROM {ANALYST_EVIDENCE_VIEW} {_WHERE_KEY} AND snapshot_version = %s",
            (*key.columns, response_version),
        ).fetchall()
        claims = []
        for tier, *values in rows:
            if tier != ANALYST_TIER:
                # The view's literal against Python's constant, on the read path
                # rather than only in a test. A drift here would tag a live
                # lookup as enrichment-tier evidence, which is what would put it
                # into the precomputed triage context of every later host.
                raise ToolError(
                    f"{ANALYST_EVIDENCE_VIEW} produced evidence tier {tier!r} and "
                    f"this layer writes {ANALYST_TIER!r}"
                )
            claim = dict(zip(_EVIDENCE_COLUMNS, values, strict=True))
            claim["source_tier"] = Tier(claim["source_tier"])
            claim["native_evidence"] = claim["native_evidence"] or {}
            claims.append(claim)
        return CacheEntry(
            key=key,
            response_version=response_version,
            retrieved_at=retrieved_at,
            expires_at=expires_at,
            body=self._body(key, response_version),
            claims=tuple(claims),
        )

    def _body(self, key: CacheKey, response_version: str) -> bytes:
        """The stored response the claims were read out of. Its absence is a bug.

        Loud rather than silent: the response is written before the claims are,
        so claims without one mean something removed a row this layer never
        deletes, and serving a hit whose native payload cannot be produced would
        be a replay that quietly stopped being one.
        """
        rows = self._connection.execute(
            f"SELECT body FROM {ANALYST_RESPONSE_TABLE} {_WHERE_KEY} "
            f"AND response_version = %s",
            (*key.columns, response_version),
        ).fetchall()
        if not rows:
            raise ToolError(
                f"{ANALYST_EVIDENCE_TABLE} holds claims from response "
                f"{response_version} and {ANALYST_RESPONSE_TABLE} holds no such "
                f"response; a claim whose response is gone cannot be replayed"
            )
        return bytes(rows[0][0])

    def store_response(self, key: CacheKey, native: NativeResponse) -> str:
        """Write the provider's bytes **before** anything is read out of them.

        `concept/05` rule 5: *"store the response before it is evaluated, cited
        by stable identifier, or an assessment that depended on a live lookup
        cannot be replayed."* The order is the point -- a response that will not
        map is on disk with its digest, and the claims that were not written
        beside it are why a later lookup treats the key as a miss.

        Returns the identifier it is cited by.
        """
        self._connection.execute(
            f"INSERT INTO {ANALYST_RESPONSE_TABLE} (tenant, sensor, source_id, "
            f"endpoint, entity_type, entity_value, entity_value_key, "
            f"response_version, retrieved_at, body) "
            f"VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (
                key.tenant,
                key.sensor,
                key.source_id,
                key.endpoint,
                key.entity_type,
                key.entity_value,
                key.indicator,
                native.response_version,
                native.retrieved_at,
                native.body,
            ),
        )
        self._connection.execute("FLUSH")
        return native.response_version

    def store_evidence(
        self,
        key: CacheKey,
        evidence: Sequence[EnrichmentEvidence],
        *,
        retrieved_at: datetime,
        expires_at: datetime,
    ) -> None:
        """Write the claims, with the retrieval time and the expiry beside them.

        `status` is not written -- see `CacheEntry`. Re-fetching an identical
        answer writes the same `evidence_id` and therefore the same row, with a
        later `retrieved_at` and `expires_at`: an upsert that is a refresh rather
        than a duplicate, which is the idempotence RisingWave's silent
        insert-onto-an-existing-key requires a key to provide.
        """
        for record in evidence:
            self._connection.execute(
                f"INSERT INTO {ANALYST_EVIDENCE_TABLE} (tenant, sensor, "
                f"evidence_id, source_id, endpoint, source_tier, "
                f"snapshot_version, entity_type, entity_value, entity_value_key, "
                f"classification, taxonomy_version, confidence, scope_type, "
                f"scope_value, first_seen, last_seen, valid_until, "
                f"native_evidence, retrieved_at, expires_at) "
                f"VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, "
                f"%s, %s, %s, %s, %s, %s, %s, %s)",
                (
                    key.tenant,
                    key.sensor,
                    record.evidence_id,
                    record.source_id,
                    key.endpoint,
                    record.source_tier.value,
                    record.snapshot_version,
                    record.entity_type,
                    record.entity_value,
                    key.indicator,
                    record.classification,
                    record.taxonomy_version,
                    record.confidence,
                    record.scope_type,
                    record.scope_value,
                    record.first_seen,
                    record.last_seen,
                    record.valid_until,
                    Jsonb(record.native_evidence),
                    retrieved_at,
                    expires_at,
                ),
            )
        self._connection.execute("FLUSH")


# --- The tool -----------------------------------------------------------------


class ProviderTool:
    """One approved provider, as the agent sees it: a name, two arguments, a typed answer.

    Composed, not subclassed. The provider-specific half is one injected callable
    -- `ask(call, credential) -> ProviderAnswer` -- which is the adapter that
    speaks the provider's protocol and maps its fields. Everything the tool
    *layer* owns is here and is the same for every provider, which is what makes
    "the layer owns credentials, scoping and validation" a fact about one piece of
    code rather than a rule each adapter has to remember.

    **The credential is injected at construction and is not reachable from
    anything the agent sees.** It is a `helena.config.Secret`, so `str`, `repr`
    and every Pydantic serialization render it redacted; it lives in a private
    slot with no property; and the only object that leaves this class is a
    `Lookup`, whose agent-visible side is built field by field from validated
    values. `tests/test_tools.py` asserts that over the real key from `.env`.

    The adapter is handed the `Secret` rather than the revealed string, so
    `reveal()` stays greppable and stays at the point of use.

    **One tool is one source and one endpoint**, and both are in the cache key
    and in the tool's name. `concept/07` puts the endpoint in the key -- "a valid,
    unexpired record for its source, endpoint and indicator" -- because two
    operations of one provider answer different questions about one indicator,
    and it puts the endpoint in the *retention* for the reason it gives: "a
    registration date never changes, multi-engine reputation moves as engines
    rescan, and risk scores sit between." So `retention_seconds` is a per-tool
    value with no default: a source-wide number would be one number too few, and
    a default would be the silent configuration `concept/instruction.md` §6 names.
    """

    __slots__ = (
        "_descriptor",
        "_endpoint",
        "_credential",
        "_ask",
        "_cache",
        "_retention",
        "_logger",
        "_redactor",
    )

    def __init__(
        self,
        *,
        source_id: str,
        endpoint: str,
        credential: Secret,
        ask: Callable[[ToolCall, Secret], ProviderAnswer],
        cache: EvidenceCache,
        retention_seconds: int,
        logger: StructuredLogger,
        redactor: Redactor,
    ) -> None:
        # Through the registry, so a tool for an unregistered source cannot be
        # built: adding a source is a governed decision (`concept/05`), and a
        # descriptor passed in as an argument would make it a constructor call.
        self._descriptor = source(source_id)
        if not ENDPOINT.match(endpoint):
            raise ToolError(
                f"{endpoint!r} is not an endpoint name. It has to match "
                f"{ENDPOINT.pattern} -- a logical name for one operation, "
                f"because it reaches the tool declaration the model is shown and "
                f"the agent is offered a capability, not a client"
            )
        if not isinstance(credential, Secret):
            raise ToolError(
                "a provider credential is a helena.config.Secret, not a "
                f"{type(credential).__name__}; a bare string is one that renders "
                "itself into a log line"
            )
        if not isinstance(retention_seconds, int) or retention_seconds <= 0:
            raise ToolError(
                f"retention for {source_id}/{endpoint} is "
                f"{retention_seconds!r}; it is configured per source and per "
                f"endpoint (`concept/07`) and a zero or absent one is a cache "
                f"that never hits pretending to be one that does"
            )
        self._endpoint = endpoint
        self._credential = credential
        self._ask = ask
        self._cache = cache
        self._retention = timedelta(seconds=retention_seconds)
        self._logger = logger
        self._redactor = redactor

    def __repr__(self) -> str:
        return f"ProviderTool({self._descriptor.source_id!r}, {self._endpoint!r})"

    @property
    def endpoint(self) -> str:
        """Which operation of the source this tool is. Part of the cache key."""
        return self._endpoint

    @property
    def retention(self) -> timedelta:
        """How long a record from this source and endpoint stays valid."""
        return self._retention

    @property
    def descriptor(self) -> SourceDescriptor:
        """What this tool declares: its tier, its entity types, its emit subset."""
        return self._descriptor

    @property
    def name(self) -> str:
        """The tool name a model is offered. Underscores, because tool names are identifiers.

        The endpoint is in it because one source may have several: two tools
        sharing a name is a tool the model cannot address, and the name is the
        only thing it addresses them by.
        """
        return f"lookup_{self._descriptor.source_id.replace('-', '_')}_{self._endpoint}"

    def declaration(self) -> dict[str, Any]:
        """The tool as the model is offered it: a name, a description, an input schema.

        Everything in it is derived from the descriptor, so what a model is told a
        tool answers about cannot drift from what the tool will accept. There is
        no URL and no endpoint in it, and there is nothing a credential could be
        in: the model is offered a capability, not a client.

        The `entity_type` enum is injected rather than generated, for the reason
        `helena.agents.CLOSED_VOCABULARIES` gives: the vocabulary is enforced in a
        validator, `model_json_schema()` renders the field as a bare string, and
        an unenumerated closed vocabulary is one the model fills with the nearest
        text it can see.
        """
        schema = ToolCall.model_json_schema()
        properties = dict(schema["properties"])
        properties["entity_type"] = {
            **properties["entity_type"],
            "enum": sorted(self._descriptor.entity_types),
        }
        return {
            "name": self.name,
            "description": (
                f"Ask {self._descriptor.source_id} about one indicator. Answers "
                f"about {', '.join(sorted(self._descriptor.entity_types))}. "
                f"Classifies into {', '.join(sorted(self._descriptor.emits))} "
                f"(taxonomy {self._descriptor.taxonomy_version}, subset "
                f"{self._descriptor.emit_subset_version}); source tier "
                f"{self._descriptor.tier.value}."
            ),
            "input_schema": {
                "type": "object",
                "properties": properties,
                "required": list(schema.get("required", ())),
                "additionalProperties": False,
            },
        }

    def lookup(
        self,
        arguments: Mapping[str, Any],
        *,
        scope: RunScope,
        budget: RunBudget,
        now: datetime | None = None,
    ) -> Lookup:
        """Ask this provider about one indicator, scoped to one tenant. Cache-first, budgeted.

        `scope` and `budget` are keyword-only and have no default: a call that did
        not say whose it is, or what bounds it, does not compile. That is the
        shape `concept/instruction.md` §6 asks for -- fail at the call, never a
        defaulted tenant, and never an unbounded loop -- and it is why this is
        where the budget is enforced rather than in a prompt: **there is no
        argument a model could put a budget in, and no sentence it could write
        that skips one** (`concept/07`).

        Three of the four dimensions are charged here, in this order, and the
        order is the whole of what makes a cache hit cheap:

        | | |
        | --- | --- |
        | a step, and the clock | before anything else. Every accepted call is a turn of the loop, including one refused as malformed |
        | a live query | **after** the cache read, because a hit sends nothing and spends no quota |
        | the token budget | not here at all -- a tool call spends none; `helena.agents.assess` charges those |

        A dimension with nothing left is a `ToolRefusal` carrying
        `budget_exhausted`, never an exception and never a `QueryFailure`: nothing
        was queried, so there is no provider to attribute an outage to, and a run
        that spent its budget is still a run that can produce a verdict on what it
        gathered.

        The rest of the order is `concept/07`'s, and each branch is a different fact:

        | | |
        | --- | --- |
        | a valid, unexpired record | served, **nothing is sent**, no live query charged, one `cache_hit` step per record |
        | nothing stored | queried, stored, served, `live_query` |
        | stored and expired | queried; the fresh answer replaces it |
        | stored, expired, and the query did not complete | the expired record served explicitly `stale`, **beside** the typed failure |
        | nothing stored and the query did not complete | the typed failure alone |
        | expired, or nothing stored, and no live query left | refused. See the note in the body: the stale fallback is not reused here |
        """
        retrieved_at = now or datetime.now(timezone.utc)
        try:
            # The step first, so an unbounded loop cannot be bought with
            # malformed calls, and the clock with it: a run whose wall clock is
            # spent is over, and reading the cache for it would be work nobody
            # can use.
            budget.charge_step()
            budget.check_clock()
        except BudgetExhausted as spent:
            return self._refuse(BUDGET_EXHAUSTED, spent.detail)
        try:
            call = ToolCall.model_validate(dict(arguments))
        except ValidationError as invalid:
            return self._refuse(MALFORMED_ARGUMENTS, _why(invalid))
        if call.entity_type not in self._descriptor.entity_types:
            return self._refuse(
                ENTITY_TYPE_NOT_COVERED,
                f"{self._descriptor.source_id} answers about "
                f"{sorted(self._descriptor.entity_types)}",
            )

        key = CacheKey.of(self._descriptor, self._endpoint, call, scope)
        stored = self._cache.read(key)
        if stored is not None and not stored.expired(retrieved_at):
            return self._served(key, stored, retrieved_at, budget=budget)

        try:
            # Charged before the call, not after: a query that did not complete
            # still reached the provider and still spent its quota, which is what
            # the dimension bounds. An exhausted budget refuses the call and does
            # **not** fall back to an expired record -- the stale fallback exists
            # because the provider was unreachable and the record is then the best
            # available answer, and a run out of quota is a different fact. Making
            # exhaustion serve stale rows would let a budget decide what the
            # evidence is.
            budget.charge_live_query()
        except BudgetExhausted as spent:
            return self._refuse(BUDGET_EXHAUSTED, spent.detail)

        try:
            answer = self._ask(call, self._credential)
        except ProviderQueryFailed as failed:
            if stored is not None:
                # Expired, and the provider is unreachable. The record was never
                # evicted -- that is what "the cache is the evidence store" buys
                # -- so it is still here and still citable, and `concept/02`
                # defines `stale` as exactly this: the claim stands and its age
                # is now part of what it is worth. The failure travels with it.
                return self._served(
                    key,
                    stored,
                    retrieved_at,
                    budget=budget,
                    failure=self._failure(call, failed),
                )
            return self._failed(call, failed, retrieved_at)

        native = NativeResponse(
            source_id=self._descriptor.source_id,
            entity_type=call.entity_type,
            entity_value=call.entity_value,
            retrieved_at=retrieved_at,
            body=answer.body,
        )
        # Before it is evaluated (`concept/05` rule 5). A response that will not
        # map is then on disk with its digest, which is the only way a
        # `malformed_response` can be investigated against what actually arrived.
        self._cache.store_response(key, native)
        try:
            evidence = self._evidence(call, answer, native, key)
        except (UndeclaredClaim, taxonomy.TaxonomyError, ValidationError) as undeclared:
            # `concept/05` rule 1 and rule 4 meeting: a response that does not
            # validate produces a typed error and **no taxonomy object at all**.
            # Not the claims that did validate -- a mapping that has drifted from
            # its declaration is not partially trustworthy, and half an answer is
            # the collapse of `failed` into `ok` one row at a time.
            #
            # Three ways it can fail and all three are the provider's response,
            # not this layer's: a path outside the declared subset, a path the
            # taxonomy version does not have, and a value that will not normalize
            # into an evidence row -- a confidence outside 0.0-1.0, a scope with
            # no value. Anything raised from anywhere else propagates.
            return self._failed(
                call,
                ProviderQueryFailed(MALFORMED_RESPONSE, str(undeclared)),
                retrieved_at,
                native=native,
            )

        self._cache.store_evidence(
            key,
            evidence,
            retrieved_at=retrieved_at,
            expires_at=retrieved_at + self._retention,
        )
        self._logger.info(
            "tools.lookup.completed",
            source_id=self._descriptor.source_id,
            endpoint=self._endpoint,
            entity_type=call.entity_type,
            outcome=contract.LIVE_QUERY,
            # `concept/07`: "a cache hit discloses nothing. The indicator was
            # already disclosed when the entry was fetched." This is the call
            # where it was, so the log says so -- and the disclosure *record*
            # that this field is not is the send-policy increment's.
            disclosed=True,
            records=len(evidence),
            response_version=native.response_version,
        )
        return Lookup(
            answer=ToolAnswer(
                source_id=self._descriptor.source_id,
                evidence_tier=ANALYST_TIER,
                evidence=evidence,
                steps=tuple(
                    contract.RetrievalStep(
                        source_id=self._descriptor.source_id,
                        entity_type=call.entity_type,
                        entity_value=call.entity_value,
                        outcome=contract.LIVE_QUERY,
                        retrieved_at=retrieved_at,
                        evidence_id=record.evidence_id,
                    )
                    for record in evidence
                ),
            ),
            refusal=None,
            native=native,
        )

    def _served(
        self,
        key: CacheKey,
        stored: CacheEntry,
        now: datetime,
        *,
        budget: RunBudget,
        failure: QueryFailure | None = None,
    ) -> Lookup:
        """A stored answer, served without touching the network.

        `retrieved_at` on every step is the **stored record's** time and not
        `now`: `concept/07` asks the trace to carry "the retrieval time of the
        underlying record", because the age of what was served is the number that
        says whether the answer was current, and because two runs differing only
        in cache state have to be distinguishable afterwards.

        `failure` is present only in the stale fallback -- the record had expired
        and the live query did not complete. It is a step of its own, so the
        outage stays countable and the served rows stay `stale` rather than
        either fact being quietly dropped.

        The hit is counted on the ledger and **nothing is charged**: `concept/03`
        puts "cache-hit versus live-query counts" on the assessment, and the count
        is per call rather than per record, because the unit a provider quota is
        spent in is the request. The stale fallback is the one call that appears
        in both counters, and it appears in both because it did both -- it reached
        the provider, which spent the quota, and then served stored rows.
        """
        budget.record_cache_hit()
        evidence = stored.evidence(now)
        steps = [
            contract.RetrievalStep(
                source_id=key.source_id,
                entity_type=key.entity_type,
                entity_value=key.entity_value,
                outcome=contract.CACHE_HIT,
                retrieved_at=stored.retrieved_at,
                evidence_id=record.evidence_id,
            )
            for record in evidence
        ]
        if failure is not None:
            steps.append(
                contract.RetrievalStep(
                    source_id=key.source_id,
                    entity_type=key.entity_type,
                    entity_value=key.entity_value,
                    outcome=contract.LIVE_QUERY,
                    retrieved_at=now,
                    failure=failure,
                )
            )
        self._logger.info(
            "tools.lookup.completed",
            source_id=key.source_id,
            endpoint=self._endpoint,
            entity_type=key.entity_type,
            outcome=contract.CACHE_HIT,
            # The property that makes caching a privacy control: a hit sends
            # nothing, so the indicator was disclosed once, when the entry was
            # fetched, however many runs read it afterwards. The stale fallback
            # is the exception and says so -- it reached the provider and the
            # provider did not answer, which is a disclosure either way.
            disclosed=failure is not None,
            status=STALE if failure is not None else OK,
            records=len(evidence),
            response_version=stored.response_version,
        )
        return Lookup(
            answer=ToolAnswer(
                source_id=key.source_id,
                evidence_tier=ANALYST_TIER,
                evidence=evidence,
                steps=tuple(steps),
            ),
            refusal=None,
            native=stored.native,
        )

    def _evidence(
        self,
        call: ToolCall,
        answer: ProviderAnswer,
        native: NativeResponse,
        key: CacheKey,
    ) -> tuple[EnrichmentEvidence, ...]:
        """Validate every claim against the declared subset, then normalize it.

        `check_claim` is the registry's own check and is reused rather than
        reimplemented: it refuses a path outside the published subset, a path the
        taxonomy version does not have, and a claim about an entity type the
        source does not cover.

        **The claim is recorded against the normalized indicator**, not against
        the spelling the caller used. A claim is about an address rather than
        about how somebody typed it, and it is what makes a cache hit and the
        live query that filled it produce byte-identical rows -- which is the
        property "two runs differing only in cache state" is measured against.
        What was disclosed is kept on the stored response, which has both.
        """
        records = []
        for claim in answer.claims:
            check_claim(
                Claim(
                    source_id=self._descriptor.source_id,
                    entity_type=call.entity_type,
                    entity_value=call.entity_value,
                    path=claim.path,
                )
            )
            records.append(
                EnrichmentEvidence(
                    evidence_id=evidence_id(
                        tenant=key.tenant,
                        sensor=key.sensor,
                        source_id=self._descriptor.source_id,
                        # A live answer has no feed snapshot; what dates it is
                        # the response it came out of. See `NativeResponse`.
                        snapshot_version=native.response_version,
                        entity_type=call.entity_type,
                        entity_value=key.indicator,
                        classification=claim.path,
                        scope_type=claim.scope_type,
                        scope_value=claim.scope_value,
                        native_record=claim.native_record,
                    ),
                    source_id=self._descriptor.source_id,
                    source_tier=self._descriptor.tier,
                    snapshot_version=native.response_version,
                    entity_type=call.entity_type,
                    entity_value=key.indicator,
                    status=OK,
                    classification=claim.path,
                    taxonomy_version=self._descriptor.taxonomy_version,
                    confidence=claim.confidence,
                    scope_type=claim.scope_type,
                    scope_value=claim.scope_value,
                    first_seen=claim.first_seen,
                    last_seen=claim.last_seen,
                    valid_until=claim.valid_until,
                    native_evidence=claim.evidence,
                )
            )
        return tuple(records)

    def _refuse(self, reason: str, detail: str) -> Lookup:
        refusal = ToolRefusal(
            source_id=self._descriptor.source_id,
            reason=reason,
            detail=self._diagnostic(detail),
        )
        self._logger.warning(
            "tools.lookup.refused",
            source_id=self._descriptor.source_id,
            reason=reason,
        )
        return Lookup(answer=None, refusal=refusal, native=None)

    def _failed(
        self,
        call: ToolCall,
        failed: ProviderQueryFailed,
        retrieved_at: datetime,
        *,
        native: NativeResponse | None = None,
    ) -> Lookup:
        """A query that did not complete: a typed error, and no taxonomy object."""
        failure = self._failure(call, failed)
        self._logger.warning(
            "tools.lookup.failed",
            source_id=self._descriptor.source_id,
            entity_type=call.entity_type,
            reason=failed.reason,
        )
        return Lookup(
            answer=ToolAnswer(
                source_id=self._descriptor.source_id,
                evidence_tier=ANALYST_TIER,
                evidence=(),
                steps=(
                    contract.RetrievalStep(
                        source_id=self._descriptor.source_id,
                        entity_type=call.entity_type,
                        entity_value=call.entity_value,
                        outcome=contract.LIVE_QUERY,
                        retrieved_at=retrieved_at,
                        failure=failure,
                    ),
                ),
            ),
            refusal=None,
            native=native,
        )

    def _failure(self, call: ToolCall, failed: ProviderQueryFailed) -> QueryFailure:
        """The adapter's typed refusal as the store's typed error, redacted.

        One builder, because a failure reaches two shapes -- a `Lookup` with no
        evidence, and a step beside a stale record -- and two constructions of
        one object are two places a detail could go unredacted.
        """
        return QueryFailure(
            source_id=self._descriptor.source_id,
            entity_type=call.entity_type,
            entity_value=call.entity_value,
            reason=failed.reason,
            detail=self._diagnostic(failed.detail),
        )

    def _diagnostic(self, detail: str) -> str:
        """Redacted, then bounded. In that order.

        The redactor first, because a detail is the one field a request URL
        reaches -- an adapter's exception message carries the URL it was fetching,
        and that is the exposure channel `concept/07` records a live key having
        already travelled down. Truncating first would leave a half-key in a
        string the redactor no longer recognizes.
        """
        return self._redactor.text(detail)[:MAX_FAILURE_DETAIL]
