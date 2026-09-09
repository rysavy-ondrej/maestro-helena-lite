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

The last one is deliberate: `ProviderTool` resolves its descriptor through
`helena.enrichment.source`, so a tool for an unregistered source raises
`SourceError` at construction. **Registration is the gate**, and adding a source
stays the governed decision `concept/05` says it is rather than becoming a
constructor argument.

Reads: `helena.enrichment.SOURCES` (the descriptor: tier, entity types, declared
subset). Writes: nothing durable yet — the store for a retrieved record is the
cache-as-evidence-store increment, which is what turns `retrieved_at` into a row
with an expiry.

Maturity: experimental — the layer is exercised end to end against a stand-in
provider adapter over the committed ThreatFox export shape, and against the real
credential from `.env` for the isolation properties. **No live provider has been
queried through it**: the query surface of the hunting API is confirmed, and the
adapter written against it, in the first-live-provider increment. Cache-first
lookup, budget enforcement and the disclosure record are named in the docstring
above because they are the layer's, and are **not built here** — see the
"deliberately not here" section below.

## Deliberately not here, and named so a green suite does not read as a finished layer

- **Cache-first lookup.** Every `Lookup` in this module is a `live_query`.
  Nothing consults a stored record and nothing writes one, so a second identical
  call queries the provider twice.
- **Budget enforcement.** Nothing counts steps, live queries, tokens or seconds.
- **The disclosure record.** A call is logged locally; no disclosure row exists,
  and the send policy that decides *what may be sent to which source* is not
  written. In particular an indicator the model invents is sent as readily as one
  the context observed — `ToolCall` bounds and types the argument, it does not
  check it against the host context.
- **Aggregator origin retention** (`concept/05` rule 7). `ProviderClaim` has no
  origin field and `EnrichmentEvidence` has no column for one; no registered
  source is an aggregator, and the first one that is arrives with both.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, ValidationError

from helena import taxonomy
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
    Claim,
    EnrichmentEvidence,
    QueryFailure,
    SourceDescriptor,
    UndeclaredClaim,
    check_claim,
    evidence_id,
    source,
)
from helena.observability import Redactor, StructuredLogger

__all__ = [
    "ENTITY_TYPE_NOT_COVERED",
    "MALFORMED_ARGUMENTS",
    "MAX_INDICATOR",
    "REFUSAL_REASONS",
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
MALFORMED_ARGUMENTS = "malformed_arguments"
ENTITY_TYPE_NOT_COVERED = "entity_type_not_covered"
REFUSAL_REASONS = (MALFORMED_ARGUMENTS, ENTITY_TYPE_NOT_COVERED)


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
        if failures and (len(self.steps) > 1 or self.evidence):
            raise ValueError(
                "a query that did not complete emits a typed error and no "
                "taxonomy object (`concept/05` rule 4), and this answer carries "
                f"{len(self.evidence)} claims beside it"
            )
        if not failures:
            cited = {step.evidence_id for step in self.steps}
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
    """

    __slots__ = ("_descriptor", "_credential", "_ask", "_logger", "_redactor")

    def __init__(
        self,
        *,
        source_id: str,
        credential: Secret,
        ask: Callable[[ToolCall, Secret], ProviderAnswer],
        logger: StructuredLogger,
        redactor: Redactor,
    ) -> None:
        # Through the registry, so a tool for an unregistered source cannot be
        # built: adding a source is a governed decision (`concept/05`), and a
        # descriptor passed in as an argument would make it a constructor call.
        self._descriptor = source(source_id)
        if not isinstance(credential, Secret):
            raise ToolError(
                "a provider credential is a helena.config.Secret, not a "
                f"{type(credential).__name__}; a bare string is one that renders "
                "itself into a log line"
            )
        self._credential = credential
        self._ask = ask
        self._logger = logger
        self._redactor = redactor

    def __repr__(self) -> str:
        return f"ProviderTool({self._descriptor.source_id!r})"

    @property
    def descriptor(self) -> SourceDescriptor:
        """What this tool declares: its tier, its entity types, its emit subset."""
        return self._descriptor

    @property
    def name(self) -> str:
        """The tool name a model is offered. Underscores, because tool names are identifiers."""
        return f"lookup_{self._descriptor.source_id.replace('-', '_')}"

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
        now: datetime | None = None,
    ) -> Lookup:
        """Ask this provider about one indicator, scoped to one tenant.

        `scope` is keyword-only and has no default: a call that did not say whose
        it is does not compile, which is the shape `concept/instruction.md` §6
        asks for -- fail at the call, never a defaulted tenant.
        """
        retrieved_at = now or datetime.now(timezone.utc)
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

        try:
            answer = self._ask(call, self._credential)
        except ProviderQueryFailed as failed:
            return self._failed(call, failed, retrieved_at)

        native = NativeResponse(
            source_id=self._descriptor.source_id,
            entity_type=call.entity_type,
            entity_value=call.entity_value,
            retrieved_at=retrieved_at,
            body=answer.body,
        )
        try:
            evidence = self._evidence(call, answer, native, scope)
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

        self._logger.info(
            "tools.lookup.completed",
            source_id=self._descriptor.source_id,
            entity_type=call.entity_type,
            outcome=contract.LIVE_QUERY,
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

    def _evidence(
        self,
        call: ToolCall,
        answer: ProviderAnswer,
        native: NativeResponse,
        scope: RunScope,
    ) -> tuple[EnrichmentEvidence, ...]:
        """Validate every claim against the declared subset, then normalize it.

        `check_claim` is the registry's own check and is reused rather than
        reimplemented: it refuses a path outside the published subset, a path the
        taxonomy version does not have, and a claim about an entity type the
        source does not cover.
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
                        tenant=scope.tenant,
                        sensor=scope.sensor,
                        source_id=self._descriptor.source_id,
                        # A live answer has no feed snapshot; what dates it is
                        # the response it came out of. See `NativeResponse`.
                        snapshot_version=native.response_version,
                        entity_type=call.entity_type,
                        entity_value=call.entity_value,
                        classification=claim.path,
                        scope_type=claim.scope_type,
                        scope_value=claim.scope_value,
                        native_record=claim.native_record,
                    ),
                    source_id=self._descriptor.source_id,
                    source_tier=self._descriptor.tier,
                    snapshot_version=native.response_version,
                    entity_type=call.entity_type,
                    entity_value=call.entity_value,
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
        failure = QueryFailure(
            source_id=self._descriptor.source_id,
            entity_type=call.entity_type,
            entity_value=call.entity_value,
            reason=failed.reason,
            detail=self._diagnostic(failed.detail),
        )
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

    def _diagnostic(self, detail: str) -> str:
        """Redacted, then bounded. In that order.

        The redactor first, because a detail is the one field a request URL
        reaches -- an adapter's exception message carries the URL it was fetching,
        and that is the exposure channel `concept/07` records a live key having
        already travelled down. Truncating first would leave a half-key in a
        string the redactor no longer recognizes.
        """
        return self._redactor.text(detail)[:MAX_FAILURE_DETAIL]
