"""Analyst — the rendering, plus live retrieval, plus one question: what is it?

`concept/04-the-two-agents.md` makes the Analyst Agent the selective half of the
pipeline: its input is *"the rendering, plus ... bounded cited case memory and
infrastructure knowledge"*, its tools are a *"budgeted tool loop over MCP provider
tools"*, its retrieval is *"live, on demand, case-driven"*, its verdicts are
`normal`, `suspicious`, `unknown` or `malicious` *"with a classification path"*,
and what it writes is **nothing — it proposes**.

This package holds the **runner**; `v1.py` holds the **prompt**. The split is
`helena.triage`'s and `docs/decisions/0008-version-registry.md`'s: an assessment
records `prompt_version`, so the words the model was shown and the field set it
was offered are frozen the moment a row records one.

## The two phases, and why they are two calls

**Measured, not chosen** (`helena.agents`, "Tool binding"): on the configured
endpoint a `response_format` `json_schema` and a `tools` list cannot be sent
together — the schema compiles to a grammar the model cannot leave, so a call
carrying both answers immediately and calls no tool. A loop built that way looks
like it works and retrieves nothing. So:

| Phase | Sent | Bounded by |
| --- | --- | --- |
| Retrieval | the instructions, the rendering, everything retrieved so far, and the **tools** | the step budget: a turn that charges no step ends the loop |
| Answer | the same messages, plus the **schema** and no tools | `helena.agents.assess`, with its bounded schema retry |

**It costs one extra model call per run and that is not hidden.** The loop cannot
know a turn was the last one until the model declines to call anything, so a run
that retrieves *n* times makes *n + 2* calls. A run with no tools at all makes one:
`_retrieve` returns immediately rather than spending a turn discovering there is
nothing to call. Measured against the configured endpoint over a real
4 964-character rendering with a two-step budget: 3 calls, 11 797 prompt tokens,
10 734 completion tokens, 109 s. `docs/decisions/0029-the-analyst-runner.md` §1 has
the table, including what the same run does when the token budget is too small —
this model spends thousands of completion tokens reasoning before it writes a
character, so a budget that is generous for one call is an empty completion by the
third.

The loop is **plain**. There is no planner, no sub-agent and no route by which a
model could select another agent: the tools offered are exactly the
`helena.tools.ProviderTool`s the caller handed in, every one of them a provider
lookup, and this package imports no other runner —
`tests/test_analyst.py::test_no_tool_selects_an_agent` asserts both, the second
over this module's own AST.

## What the model is never given a way to reach

| | |
| --- | --- |
| a budget | there is no argument for one and no sentence that grants one; `helena.tools` refuses at the boundary (`concept/07`) |
| a credential | the tool layer owns it; what crosses is a `ToolCall` and a typed answer |
| an indicator the context never observed | refused here, before anything is sent — see below |
| the retrieval trace | **code writes it**, the way code writes the truncation gap: `concept/07` makes the trace a record of what the retrieval actually did, and a model asked for it would be reporting on itself |

## The disclosure gap this closes, and the one it does not

`helena.tools` states the gap it cannot close: *"the send policy governs what
KINDS of thing and WHICH FIELDS may be sent and never asks where the value came
from ... closing it needs the host context beside the tool, which is the analyst
runner's shape rather than this layer's."* This is that shape. `run` takes the
`helena.rendering.ContextProjection` the request was rendered from, and a tool
call about an indicator the context did not observe is refused with
`indicator_not_observed` — **before** the send policy, the cache or the adapter is
reached, so nothing the model invented is disclosed to a provider.

Two consequences follow and both are deliberate:

- **The analyst cannot pivot.** An indicator learned from a provider's answer — a
  second address for the same malware family, say — cannot be looked up, because
  the monitored network never observed it. Whether that pivot should be permitted
  is a question `concept/` does not answer, so the conservative direction is taken
  and recorded here rather than decided quietly.
- **The composition rule becomes total.** Every analyst-tier claim is about an
  entity the context holds, so every claim has traffic beside it and
  `helena.policy.supports_for` can always build the input the rule needs.

The comparison is on the **normalized** indicator (`helena.tools.normalize_indicator`),
so a name the model retyped in another case is the same question and not a
refusal; the fold is the tool layer's own, and it errs towards a missed hit rather
than towards a wrong one.

## The composition rule is applied and the verdict is not rewritten

`concept/02` requires the rule to run against what the model said, and
`docs/decisions/0022-the-composition-rule.md` decided what it produces: a
**second** typed record beside the verdict, never an edit of it, because
`concept/07` keeps inference append-only and an evaluation that could not tell a
model's answer from a policy's correction of it would be scoring the policy while
reporting on the model. So `Analysis` carries both — `outcome` is what the model
said, `decision.permits` is what the cited evidence supports, and
`decision.findings` names the rule and quotes the evidence that cut it down. A
downgrade is therefore *recorded and attributable* rather than applied in place;
`prds/prd.json` task 39's step 6 asks for a downgrade and this is the shape the
invariant leaves for one. The report for this task records the difference.

**The one rewrite that does happen is not this one.** `helena.budgets.degraded` is
`concept/07`'s own: a run that exhausted a budget may not return `normal`, because
"it established the absence of nothing", so it degrades to `unknown` with the
exhaustion explicit. That is a rule about what a *truncated run* may claim, not
about what the evidence supports.

## `unknown` is unassessable, and `suspicious` is unsettled

`concept/02`: `unknown` *"means the context was **unassessable** ... deliberately
distinct from `suspicious`, which means analysis ran and could not settle it."*
The contract already makes the gaps list mandatory on `unknown`; what this runner
adds is that at least one of those gaps must be a thing the run **could not see**
— `missing`, `in_flight`, `failed`, `truncated` or `budget_exhausted` — and not
merely `no_match` or `stale`, which are answers about the world (*"a lookup
outcome, never a statement of safety"*, and *"the claim stands and its age is part
of what it is worth"*). A verdict that fails that test is a typed failure and not
a third label, exactly as a citation that does not resolve is.

Reads: `helena.agents` (the model path), `helena.tools` (the provider tools),
`helena.budgets` (one ledger), `helena.policy` (the composition rule),
`helena.taxonomy` (the closed root set), `config/agents.toml` (the inheritance
switch). Writes: nothing durable — the tool layer writes the lookup cache, and
`helena.agents` writes the structured log record.

Maturity: experimental — exercised against a scripted endpoint over the real tool
layer and a real migrated engine, and once against the real configured endpoint
with the real ThreatFox credential. No assessment has been stored, no `Decision`
has been stored, nothing routes on what this returns, and no verdict has been
measured against a label because there is no labelled corpus
(`concept/08-open-questions.md`).
"""

from __future__ import annotations

import json
import time
import tomllib
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType
from typing import Any

from pydantic import BaseModel, ConfigDict, ValidationError

from helena import agents, budgets, disclosure, taxonomy, tools
from helena import policy as composition
from helena.budgets import BudgetExhausted, RunBudget
from helena.contracts import ContractError
from helena.contracts import v1 as contract
from helena.enrichment import MAX_FAILURE_DETAIL
from helena.rendering import ContextEntity, ContextProjection

__all__ = [
    "BUDGET_EXHAUSTED",
    "CLASSIFICATION",
    "INDICATOR_NOT_OBSERVED",
    "LOOP_REFUSAL_REASONS",
    "MALFORMED_CALL",
    "TRACE_FIELD",
    "UNASSESSABLE_GAPS",
    "UNKNOWN_TOOL",
    "Analysis",
    "AnalystError",
    "AnalystPrompt",
    "Inheritance",
    "LoopRefusal",
    "Retrieval",
    "UnknownVersion",
    "classifications",
    "inheritance",
    "run",
    "version",
]

#: The emitter this package runs. One spelling, `helena.taxonomy`'s.
EMITTER = taxonomy.ANALYST

#: The result property whose closed set is per emitter — see
#: `helena.agents.proposal_schema`. The same name `helena.triage` uses, because it
#: is the contract's field name and not either runner's.
CLASSIFICATION = "classification"

#: The one result field this runner never offers the model. `concept/07` makes the
#: retrieval trace a record of *what the retrieval did* — cache hit or live query,
#: and the retrieval time of the underlying record — which is measured by
#: `helena.tools` and cannot be known to the model at all. Offering it would be
#: asking a model to report on the code that ran it, and `check_exchange` resolves
#: analyst-tier citations against this list, so a model that could write it could
#: also authorise its own citations.
TRACE_FIELD = "retrieval_trace"

#: Why this runner would not dispatch a tool call. **Not** `helena.tools`'
#: `REFUSAL_REASONS` and not a second copy of them: those are the refusals the
#: tool boundary makes about a call it was handed, and these are the three a
#: caller has to make *before* there is a tool to hand it to. Each is agent-visible
#: and countable, and none collapses into another.
#:
#:   unknown_tool             the model addressed a tool this run does not offer
#:   malformed_call           the arguments are not a JSON object at all, so there
#:                            is nothing for `helena.tools.ToolCall` to validate
#:   indicator_not_observed   a well-formed call about something the monitored
#:                            context never saw. See the module docstring: this is
#:                            the disclosure channel the tool layer cannot close
#:
#: `budget_exhausted` is the fourth and it is `helena.contracts.v1`'s own string,
#: reused rather than respelled for the reason `helena.tools.BUDGET_EXHAUSTED` is:
#: the refusal the model reads and the gap the assessment records are one fact at
#: two layers. `tests/test_analyst.py` asserts the three spellings are one string.
BUDGET_EXHAUSTED = contract.BUDGET_EXHAUSTED
UNKNOWN_TOOL = "unknown_tool"
MALFORMED_CALL = "malformed_call"
INDICATOR_NOT_OBSERVED = "indicator_not_observed"
LOOP_REFUSAL_REASONS = (
    BUDGET_EXHAUSTED,
    UNKNOWN_TOOL,
    MALFORMED_CALL,
    INDICATOR_NOT_OBSERVED,
)

#: The gap kinds that mean **the run could not see something**, which is what
#: `unknown` claims. The two that are missing are the two that are *answers*:
#: `concept/02` calls `no_match` "a lookup outcome, never a statement of safety"
#: and `stale` a claim that "stands, and its age is part of what it is worth". A
#: run whose gaps are only those two looked things up and got answers, so whatever
#: it could not settle, it was not unassessable.
UNASSESSABLE_GAPS = (
    contract.MISSING,
    contract.IN_FLIGHT,
    contract.FAILED,
    contract.TRUNCATED,
    contract.BUDGET_EXHAUSTED,
)


class AnalystError(Exception):
    """The analyst runner was misconfigured or misused. Never a model's fault.

    A model that answered badly produces a `helena.contracts.v1.AgentFailure`;
    this is raised for the things that are wrong before a call is made, or that
    are wrong about this code rather than about an answer.
    """


class UnknownVersion(AnalystError):
    """A prompt version was asked for that this package does not hold.

    Distinct for the reason `helena.triage.UnknownVersion` is: a stored assessment
    recording a `prompt_version` whose module is absent is a replay that cannot be
    reconstructed, not a value that is invalid.
    """


class LoopRefusal(BaseModel):
    """A tool call this runner would not dispatch. No provider tool was reached.

    Agent-visible, typed and countable, and deliberately a different object from
    `helena.tools.ToolRefusal`: that one names the **source** that was not asked,
    and three of these four have no source to name — an unknown tool has no
    descriptor, and a call whose arguments will not parse has no entity type. A
    refusal that had to invent a source id in order to be recorded would put a
    made-up value in the field an audit groups by.
    """

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    #: The tool the model addressed, as it spelled it.
    tool: str
    reason: str
    #: What the caller may do about it, in words. Bounded for the reason
    #: `helena.tools.ToolRefusal.detail` is: an unbounded diagnostic is where a
    #: payload ends up, and this one echoes text the model chose.
    detail: str = ""

    def model_post_init(self, _context: object) -> None:
        if self.reason not in LOOP_REFUSAL_REASONS:
            raise ValueError(
                f"reason {self.reason!r} is not one of {list(LOOP_REFUSAL_REASONS)}"
            )
        if len(self.detail) > MAX_FAILURE_DETAIL:
            raise ValueError(
                f"detail is {len(self.detail)} characters and the limit is "
                f"{MAX_FAILURE_DETAIL}"
            )


@dataclass(frozen=True)
class Retrieval:
    """One turn of the loop: what the model asked for, and what it got back.

    Exactly one of `lookup` and `refusal`, the way `helena.tools.Lookup` has
    exactly one of an answer and a refusal, and for the same reason: a record that
    could be neither would be a step nobody can account for.

    `arguments` is the **raw text the model produced**, kept because it is what
    the loop asked and because a repeated call is only visible as a repetition if
    what was asked is recorded. It reaches the model again inside the retrieved
    block — it is the model's own text, JSON-escaped by the serializer.
    """

    tool: str
    arguments: str
    lookup: tools.Lookup | None
    refusal: LoopRefusal | None

    def __post_init__(self) -> None:
        if (self.lookup is None) == (self.refusal is None):
            raise AnalystError(
                "a retrieval is a lookup or a refusal, and this one is "
                + ("both" if self.lookup is not None else "neither")
            )

    @property
    def for_agent(self) -> dict[str, Any]:
        """The only side of this retrieval a model may be shown.

        `helena.tools.Lookup.for_agent` is what decides that for a dispatched
        call — the native payload has no route here — and this adds only what the
        loop knows: which tool, and what was asked of it.
        """
        answer = (
            self.refusal if self.lookup is None else self.lookup.for_agent
        )
        return {
            "tool": self.tool,
            "asked": self.arguments,
            "result": answer.model_dump(mode="json"),
        }

    @property
    def steps(self) -> tuple[contract.RetrievalStep, ...]:
        """The retrieval steps this turn produced. Empty for a refusal: nothing ran."""
        if self.lookup is None or self.lookup.answer is None:
            return ()
        return self.lookup.answer.steps


@dataclass(frozen=True)
class AnalystPrompt:
    """One prompt version: what it is called, what it asks for, and how it asks.

    The same shape `helena.triage.TriagePrompt` has, for the reason it gives: a
    prompt is a function of a request and holds no state.

    `messages` is `(request, *, classifications, retrievals, inherited) ->
    tuple[helena.agents.Message, ...]`, and it is called **once per turn** with a
    longer `retrievals` each time. The conversation is rebuilt from the frozen text
    every turn rather than accumulated, which is what keeps the property
    `helena.agents._attempt_messages` has: no answer the model gave is ever an
    input to anything, and there is no `assistant` turn on the wire at all.
    """

    version: str
    #: The `helena.contracts.v1.AgentResult` fields this version asks the model
    #: for. `helena.agents.proposal_schema` refuses anything the contract does not
    #: let a model propose, and this runner refuses `TRACE_FIELD`.
    propose: tuple[str, ...]
    messages: Any


class Inheritance(BaseModel):
    """Whether the analyst is shown the triage rationale. Configuration, defaulting off.

    `concept/04`: *"The analyst does not inherit the triage rationale by default.
    It re-reads the enriched context and decides for itself — because the
    analyst's `normal` verdict is the direct measurement of triage precision, and
    that measurement is worthless if the analyst was anchored on triage's framing.
    The other arm stays measurable as a configuration switch rather than a
    contract change."*

    So it is a switch and not a contract field, which is the whole point: adding
    the triage verdict to `AgentRequest` would make every request carry it and
    would be a change to the agent contract (`concept/instruction.md` §3). It
    arrives as an argument to `run` instead, and this value decides whether the
    prompt is allowed to show it.

    There is **no default in the code**. `concept/instruction.md` §6 lists the
    silent configuration default by name, and the shape it would take here is the
    worst one: an experiment's control arm quietly becoming its treatment arm, with
    the measurement still reported as a measurement of triage.
    """

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    inherit_triage_rationale: bool


def inheritance(path: Path | str = agents.RETRY_FILE) -> Inheritance:
    """Read the inheritance switch, or fail naming what is wrong with the file.

    TOML, so the file is `tomllib` and no dependency — the same reader
    `helena.agents.retry_policy` uses on the same file:

        [analyst]
        inherit_triage_rationale = false

    The key sets are `helena.agents`' (`RETRY_KEYS`, `AGENT_KEYS`), imported rather
    than copied, so the two loaders of this file cannot drift into rejecting each
    other's table.
    """
    path = Path(path)
    try:
        raw = path.read_bytes()
    except FileNotFoundError as absent:
        raise AnalystError(
            f"no agent configuration at {path}. Whether the analyst inherits the "
            f"triage rationale is what makes the other arm of a measurement "
            f"measurable, so an absent file is a startup failure and never an "
            f"assumed arm."
        ) from absent
    try:
        document = tomllib.loads(raw.decode())
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as malformed:
        raise AnalystError(f"{path} is not readable TOML: {malformed}") from malformed
    unexpected = sorted(set(document) - agents.RETRY_KEYS - agents.AGENT_KEYS)
    if unexpected:
        raise AnalystError(
            f"{path} has top-level keys {unexpected}; the file is "
            f"{sorted(agents.RETRY_KEYS)} plus one table per agent "
            f"({sorted(agents.AGENT_KEYS)})"
        )
    table = document.get(EMITTER)
    if not isinstance(table, dict):
        raise AnalystError(
            f"{path} has no [{EMITTER}] table. The inheritance switch has no "
            f"default: `concept/04` makes the analyst's independence the thing "
            f"triage precision is measured with, and a run that assumed an arm "
            f"would report a measurement of something else."
        )
    try:
        return Inheritance(**table)
    except ValidationError as refused:
        raise AnalystError(f"{path}: [{EMITTER}] {refused}") from refused


def classifications(taxonomy_version: str) -> tuple[str, ...]:
    """The verdicts the analyst may return, looked up rather than written down.

    `helena.taxonomy`'s `emitter_roots[analyst]` closes the roots, and this returns
    **every emittable path under them**, not just the roots — which is where it
    differs from `helena.triage.classifications` and why the two are not one
    function. `concept/04`'s table gives the analyst *"`normal`, `suspicious`,
    `unknown` or `malicious`, **with a classification path**"*, and its question is
    *what is it*: an analyst that could only answer `malicious` would be a stage
    that ran the expensive retrieval and then declined to say what it found.

    Every candidate goes through `helena.taxonomy.for_emission`, so a path the
    version marks unused — `suspicious.anomalous_volume` under `v1`, which nothing
    can yet compute — is not offered rather than being offered and then refused.
    Resolved against the version the **request** records, never against current
    code, for the reason `helena.triage.classifications` gives.
    """
    vocabulary = taxonomy.version(taxonomy_version)
    roots = vocabulary.emitter_roots[EMITTER]
    offered = []
    for path in sorted(vocabulary.paths[taxonomy.CONTEXT]):
        if path.split(".")[0] not in roots:
            continue
        try:
            taxonomy.for_emission(
                path, level=taxonomy.CONTEXT, version=vocabulary, emitter=EMITTER
            )
        except taxonomy.UnusablePath:
            continue
        offered.append(path)
    if not offered:
        raise AnalystError(
            f"taxonomy {taxonomy_version} offers {EMITTER} no emittable context "
            f"path at all, so there is no verdict to ask for"
        )
    return tuple(offered)


@dataclass(frozen=True)
class Analysis:
    """What one analyst run produced: the answer, what it is permitted to be read
    as, and how it got there.

    Three records rather than one, and none of them is derivable from another:

    | | |
    | --- | --- |
    | `outcome` | what the **model** said, validated against the frozen contract, with the code-owned retrieval trace and gaps on it |
    | `decision` | what the **cited evidence** permits, from the frozen `policy_version` the request recorded. `None` exactly where there is no verdict to constrain |
    | `retrievals` | every turn of the loop, in order, refusals included |

    `concept/07` keeps inference append-only, so a constrained verdict is a second
    record beside the first and never an edit of it — see the module docstring.
    """

    outcome: contract.AgentResult | contract.AgentFailure
    decision: Any
    retrievals: tuple[Retrieval, ...]

    @property
    def retrieved(self) -> tuple[Any, ...]:
        """Every analyst-tier evidence row the loop produced, in the order it did.

        `helena.enrichment.EnrichmentEvidence` rows. What a later increment stores;
        what `helena.policy.supports_for` weighs, paired with the entity each is
        about.
        """
        return _retrieved(self.retrievals)


def run(
    request: contract.AgentRequest,
    *,
    client: agents.ModelClient,
    policy: agents.RetryPolicy,
    prompt: AnalystPrompt,
    provider_tools: Sequence[tools.ProviderTool],
    disclosures: disclosure.Disclosures,
    projection: ContextProjection,
    inherit: Inheritance,
    triage: contract.AgentResult | contract.AgentFailure | None = None,
    clock: Callable[[], float] = time.monotonic,
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> Analysis:
    """One analyst assessment: a bounded tool loop, then one verdict or one typed failure.

    Returns an `Analysis` and never raises for anything a model, an endpoint or a
    provider did — the two terminal outcomes are `concept/07`'s, and an exception
    escaping here would be a third one every caller has to remember to catch.

    Raises `AnalystError` for the things that are this code's fault: a request that
    is not an analyst request, a prompt version that is not the one the request
    records, a field set that offers the retrieval trace, a projection that is not
    the request's context, or two tools with one name.

    `policy` is the retry bound, the same argument `helena.triage.run` takes under
    the same name. The composition rule is **not** a parameter: it is loaded from
    the `policy_version` the request records, because a stored assessment is
    re-constrained against the rules it recorded and a caller that could pass a
    different one could score a run against a policy it never ran. It is imported
    here as `composition` so the two never read as one thing.

    `clock` and `now` are injectable for the reason `helena.budgets.RunBudget`'s
    is: a test has to be able to spend a wall clock without sleeping, and a
    retrieval time has to be assertable. `clock` is monotonic and bounds the run;
    `now` is a wall date and dates a record.
    """
    _check_runnable(request, prompt, projection, provider_tools)

    offered = classifications(request.versions.taxonomy_version)
    by_name = {tool.name: tool for tool in provider_tools}
    declarations = tuple(tool.declaration() for tool in provider_tools)
    observed = {
        (entity.entity_type, tools.normalize_indicator(entity.entity_type, entity.entity_value)): entity
        for entity in projection.entities
    }
    inherited = triage if inherit.inherit_triage_rationale else None

    # One ledger for the whole run, built here because for the analyst `run` **is**
    # the run: the tool dispatch and every model call charge the same object, which
    # is what makes the wall clock cover the provider waits (`helena.budgets`).
    budget = RunBudget.of(request, clock=clock)
    scope = tools.RunScope.of(request)

    retrievals: list[Retrieval] = []
    interrupted = _retrieve(
        request,
        prompt=prompt,
        client=client,
        offered=offered,
        declarations=declarations,
        by_name=by_name,
        observed=observed,
        scope=scope,
        budget=budget,
        disclosures=disclosures,
        inherited=inherited,
        retrievals=retrievals,
        now=now,
    )

    outcome = agents.assess(
        request,
        client=client,
        messages=prompt.messages(
            request,
            classifications=offered,
            retrievals=tuple(retrievals),
            inherited=inherited,
        ),
        policy=policy,
        budget=budget,
        disclosures=disclosures,
        propose=prompt.propose,
        vocabularies={CLASSIFICATION: offered},
    )
    outcome = _with_trace(outcome, tuple(retrievals))
    if interrupted is not None:
        outcome = _with_gap(outcome, interrupted)
    outcome = agents.with_truncation_gap(request, outcome)
    try:
        contract.check_exchange(request, outcome)
    except ContractError as refused:
        outcome = _refused_verdict(request, outcome, str(refused))
    unheld = _unheld(outcome)
    if unheld is not None:
        outcome = _refused_verdict(request, outcome, unheld)
    outcome = budgets.degraded(outcome, budget)

    gathered = tuple(retrievals)
    return Analysis(
        outcome=outcome,
        decision=_constrained(outcome, projection, gathered, observed),
        retrievals=gathered,
    )


# --- The loop -----------------------------------------------------------------


def _retrieve(
    request: contract.AgentRequest,
    *,
    prompt: AnalystPrompt,
    client: agents.ModelClient,
    offered: Sequence[str],
    declarations: tuple[dict[str, Any], ...],
    by_name: Mapping[str, tools.ProviderTool],
    observed: Mapping[tuple[str, str], ContextEntity],
    scope: tools.RunScope,
    budget: RunBudget,
    disclosures: disclosure.Disclosures,
    inherited: Any,
    retrievals: list[Retrieval],
    now: Callable[[], datetime],
) -> contract.Gap | None:
    """The bounded tool loop. Appends to `retrievals`; returns a gap where one is owed.

    **Termination is arithmetic, not a constant.** A turn that produces no tool
    call ends the loop, and a turn whose calls charged no step ends it too — so
    every turn that continues has strictly increased `budget.steps_spent`, which is
    bounded by `Budgets.steps`. There is no separate turn limit to keep consistent
    with the step budget, and no way for a model to buy another turn by asking for
    something that costs nothing.

    A model call that does not complete ends retrieval and is a `failed` gap on
    whatever the run goes on to produce: the answer call is attempted anyway,
    because `concept/07` wants a verdict on what was gathered, and the endpoint
    being unreachable will produce its own typed failure there if it still is.
    """
    if not declarations:
        # A loop with no tools is a loop with nothing to do, and a turn spent
        # discovering that costs the run tokens it could have answered with.
        return None
    turn = 0
    while True:
        turn += 1
        try:
            budget.check_tokens()
        except BudgetExhausted:
            return None
        # Deliberately not `budget.check_clock()`: a run out of clock at the model
        # path is `helena.contracts.v1.TIMED_OUT`, a failure reason and not a gap
        # (`helena.budgets.RunBudget.check_clock`), and recording it here would make
        # it both. `assess` is what turns it into the failure.
        if budget.remaining_seconds <= 0:
            return None
        messages = prompt.messages(
            request,
            classifications=offered,
            retrievals=tuple(retrievals),
            inherited=inherited,
        )
        disclosures.record_model_call(
            model=client.model_requested,
            disclosed_to=client.endpoint_host,
            prompt=agents.prompt_bytes(messages),
            messages=len(messages),
            at=now(),
        )
        try:
            completion = client.complete(
                messages,
                tools=declarations,
                max_tokens=budget.remaining_tokens,
                timeout=budget.remaining_seconds,
                attempt=turn,
            )
        except (agents.ModelTimedOut, agents.ModelUnavailable) as stopped:
            return contract.Gap(
                kind=contract.FAILED,
                detail=_bounded(
                    f"retrieval stopped after {turn - 1} completed turn(s): "
                    f"{type(stopped).__name__}: {stopped}"
                ),
            )
        budget.record_tokens(
            prompt=completion.prompt_tokens, completion=completion.completion_tokens
        )
        if not completion.tool_calls:
            return None
        spent = budget.steps_spent
        for invocation in completion.tool_calls:
            retrievals.append(
                _dispatch(
                    invocation,
                    by_name=by_name,
                    observed=observed,
                    scope=scope,
                    budget=budget,
                    disclosures=disclosures,
                    now=now,
                )
            )
        if budget.steps_spent == spent:
            # Every call this turn was refused for want of a step, so another turn
            # would produce the same refusals and spend tokens doing it.
            return None


def _dispatch(
    invocation: agents.ToolInvocation,
    *,
    by_name: Mapping[str, tools.ProviderTool],
    observed: Mapping[tuple[str, str], ContextEntity],
    scope: tools.RunScope,
    budget: RunBudget,
    disclosures: disclosure.Disclosures,
    now: Callable[[], datetime],
) -> Retrieval:
    """One requested tool call: dispatched, or refused with a reason of this layer's.

    **Exactly one step is charged per requested call**, whoever refuses it.
    `helena.tools.ProviderTool.lookup` charges its own — that is what bounds the
    loop, and it charges before it validates anything — so a call that reaches the
    tool is not charged here, and a call this function refuses is. Charging the
    step *before* announcing the refusal is what keeps the two layers' answers the
    same when the budget is what ran out: a run with no step left is
    `budget_exhausted` whether the tool it named existed or not.
    """
    refusal = _undispatchable(invocation, by_name, observed)
    if refusal is None:
        return Retrieval(
            tool=invocation.name,
            arguments=invocation.arguments,
            lookup=by_name[invocation.name].lookup(
                json.loads(invocation.arguments),
                scope=scope,
                budget=budget,
                disclosures=disclosures,
                now=now(),
            ),
            refusal=None,
        )
    reason, detail = refusal
    try:
        budget.charge_step()
    except BudgetExhausted as exhausted:
        reason, detail = BUDGET_EXHAUSTED, exhausted.detail
    return Retrieval(
        tool=invocation.name,
        arguments=invocation.arguments,
        lookup=None,
        refusal=LoopRefusal(
            tool=invocation.name, reason=reason, detail=_diagnostic(detail)
        ),
    )


def _undispatchable(
    invocation: agents.ToolInvocation,
    by_name: Mapping[str, tools.ProviderTool],
    observed: Mapping[tuple[str, str], ContextEntity],
) -> tuple[str, str] | None:
    """Why this call may not be dispatched, as `(reason, detail)`, or `None`.

    The malformed cases split in two on purpose. Arguments that are not a JSON
    object at all are this layer's `malformed_call`, because there is nothing for
    `helena.tools.ToolCall` to validate; arguments that *are* an object and do not
    validate are **dispatched anyway**, so that the refusal the model reads is the
    tool layer's own `malformed_arguments`, in the tool layer's wording. One fact,
    one spelling, produced by the layer that owns the vocabulary.

    The detail of a refusal names what was wrong and never the indicator: an
    `indicator_not_observed` refusal is agent-visible, and the value is exactly the
    thing this check decided must not travel — echoing it back would be a strange
    place to stop being careful about it.
    """
    if invocation.name not in by_name:
        return UNKNOWN_TOOL, (
            f"{invocation.name!r} is not a tool this run offers; the tools are "
            f"{sorted(by_name)}"
        )
    try:
        arguments = json.loads(invocation.arguments)
    except json.JSONDecodeError as malformed:
        return MALFORMED_CALL, f"the arguments are not JSON: {malformed}"
    if not isinstance(arguments, dict):
        return MALFORMED_CALL, (
            f"the arguments are a JSON {type(arguments).__name__}, and a tool call "
            f"is an object of named arguments"
        )
    try:
        call = tools.ToolCall.model_validate(arguments)
    except ValidationError:
        return None
    key = (
        call.entity_type,
        tools.normalize_indicator(call.entity_type, call.entity_value),
    )
    if key not in observed:
        return INDICATOR_NOT_OBSERVED, (
            f"this context never observed the {call.entity_type} asked about, so "
            f"asking a provider would disclose an indicator the monitored network "
            f"did not produce. The analyst answers about what this host did."
        )
    return None


# --- What the runner writes onto the outcome ----------------------------------


def _with_trace(
    outcome: contract.AgentResult | contract.AgentFailure,
    retrievals: Sequence[Retrieval],
) -> contract.AgentResult | contract.AgentFailure:
    """The retrieval trace, written by code, in the order the loop produced it.

    `concept/07`, "Caching": *"the retrieval trace records, per result, whether it
    was a cache hit or a live query, and the retrieval time of the underlying
    record. Two runs that differ only in cache state must be distinguishable
    afterwards."* Every one of those is measured by `helena.tools`, so this is the
    same kind of fact as the truncation gap: something the code knows and the model
    cannot see. `TRACE_FIELD` says why it is never asked for.

    A failure carries none — `AgentFailure` has no `retrieval_trace` field — and
    that is not a loss: the retrievals themselves are on the `Analysis`, and a run
    with no verdict has nothing for a citation to resolve against.

    Rebuilt through `model_validate` for the reason `agents.with_truncation_gap`
    gives: `model_copy` skips every rule in `model_post_init`.
    """
    steps = tuple(step for retrieval in retrievals for step in retrieval.steps)
    if not steps or isinstance(outcome, contract.AgentFailure):
        return outcome
    return type(outcome).model_validate({**dict(outcome), TRACE_FIELD: steps})


def _with_gap(
    outcome: contract.AgentResult | contract.AgentFailure, gap: contract.Gap
) -> contract.AgentResult | contract.AgentFailure:
    """One gap the runner measured, appended. Never a second of the same kind."""
    if any(existing.kind == gap.kind for existing in outcome.gaps):
        return outcome
    return type(outcome).model_validate(
        {**dict(outcome), "gaps": (*outcome.gaps, gap)}
    )


def _unheld(
    outcome: contract.AgentResult | contract.AgentFailure,
) -> str | None:
    """The two rules about an analyst verdict that the contract cannot state alone.

    Both are `concept/`'s and neither is expressible on `AgentResult`, because both
    are about the difference between two things the contract permits:

    1. **`unknown` is unassessable, not unsettled.** The contract requires gaps on
       `unknown`; it cannot require that one of them is a thing the run could not
       *see*, because `no_match` and `stale` are perfectly good gaps on a verdict
       that was settled. See `UNASSESSABLE_GAPS`.
    2. **A non-`normal` verdict's evidence package has to contain something.**
       `concept/02` makes it "assembled cited evidence: indicators, patterns,
       missing information, narrative"; the contract holds the two of those four
       that are not already `citations` and `gaps`, and permits both to be empty
       because `helena.budgets.degraded` attaches an empty package to a verdict the
       *code* rewrote. A package the **model** returned empty says nothing at all,
       and a verdict that assembled nothing has not answered *what is it*.

    Returns the reason a verdict does not hold, or `None`. The caller turns it into
    a typed failure, because `concept/02` makes a run that could not produce a
    verdict a typed failure and not a third label.
    """
    if isinstance(outcome, contract.AgentFailure):
        return None
    if outcome.root == contract.UNKNOWN and not any(
        gap.kind in UNASSESSABLE_GAPS for gap in outcome.gaps
    ):
        return (
            f"the verdict is {contract.UNKNOWN!r} and its gaps are "
            f"{sorted({gap.kind for gap in outcome.gaps})}, none of which is "
            f"something the run could not see ({list(UNASSESSABLE_GAPS)}). "
            f"`unknown` means the context was unassessable; a run that looked "
            f"things up and got answers it could not settle is `suspicious` "
            f"(`concept/02`)."
        )
    package = outcome.evidence_package
    if (
        outcome.root != contract.NORMAL
        and package is not None
        and not package.patterns
        and not package.narrative.strip()
    ):
        return (
            f"the verdict is {outcome.classification!r} and its evidence package "
            f"names no pattern and carries no narrative. An evidence package is "
            f"assembled cited evidence (`concept/02`), and an empty one is the "
            f"verdict without the assembly."
        )
    return None


def _refused_verdict(
    request: contract.AgentRequest,
    outcome: contract.AgentResult | contract.AgentFailure,
    detail: str,
) -> contract.AgentFailure:
    """A verdict that does not hold against its own run is a typed failure.

    `schema_invalid` — the reason that means *the model answered and the answer did
    not hold* — for the reason `helena.triage._unheld_exchange` gives, and with the
    same cost: it is **not** retried, because the retry loop is inside
    `helena.agents.assess` and feeds back what *validation* said. What would settle
    whether that is worth changing is a measured rate, which needs assessments to
    be stored (`prds/prd.json` task 43).

    The cost, the gaps and the reported model version are the run's own and travel
    with the failure: what the run spent is true whatever became of the answer.
    """
    if isinstance(outcome, contract.AgentFailure):  # pragma: no cover — see callers
        return outcome
    return contract.AgentFailure(
        emitter=request.emitter,
        reason=contract.SCHEMA_INVALID,
        detail=_bounded(f"the answer did not hold against its run: {detail}"),
        gaps=outcome.gaps,
        cost=outcome.cost,
        versions=request.versions,
        model_version=outcome.versions.model_version,
    )


def _constrained(
    outcome: contract.AgentResult | contract.AgentFailure,
    projection: ContextProjection,
    retrievals: Sequence[Retrieval],
    observed: Mapping[tuple[str, str], ContextEntity],
) -> Any:
    """The composition rule applied to the verdict, as a record beside it.

    The rules are the **request's own** `policy_version`, loaded by name, because
    a stored assessment is re-constrained against the rules it recorded
    (`concept/instruction.md` §2) and applying today's to it would score it against
    a policy it never ran.

    `None` for a typed failure: there is no verdict to constrain, and a `Decision`
    for a run that produced none would be a policy answering a question nobody
    asked.

    The analyst-tier claims are paired with the context entity each is about before
    they are handed over — see `helena.policy.supports_for` for why the join is the
    caller's — and the pairing cannot fail, because a claim only exists where the
    loop admitted the lookup and the loop admits only observed indicators.
    """
    if isinstance(outcome, contract.AgentFailure):
        return None
    rule = composition.version(outcome.versions.policy_version)
    pairs = tuple(
        (observed[(record.entity_type, record.entity_value)], record)
        for record in _retrieved(retrievals)
    )
    return rule.constrain(
        outcome, composition.supports_for(outcome, projection, retrieved=pairs)
    )


# --- Startup checks -----------------------------------------------------------


def _check_runnable(
    request: contract.AgentRequest,
    prompt: AnalystPrompt,
    projection: ContextProjection,
    provider_tools: Sequence[tools.ProviderTool],
) -> None:
    """Everything that is wrong before a call is made. Each is this code's fault.

    The projection check is the one that is easy to leave out and expensive to
    leave out: the composition rule and the observation check both read it, so a
    projection of another context would refuse the model's lookups and constrain
    its verdict against a host it never saw — and both would look like the model
    behaving oddly.
    """
    if request.emitter != EMITTER:
        raise AnalystError(
            f"this runner runs {EMITTER!r} and the request is for "
            f"{request.emitter!r}. The two agents differ in where their "
            f"information comes from, so running one's request through the "
            f"other's prompt is an assessment of neither."
        )
    if request.versions.prompt_version != prompt.version:
        raise AnalystError(
            f"the request records prompt_version "
            f"{request.versions.prompt_version!r} and the prompt is "
            f"{prompt.version!r}. What the analyst saw is pinned by the recorded "
            f"version, so two copies that can drift are worse than none "
            f"(`concept/instruction.md` §2)."
        )
    if TRACE_FIELD in prompt.propose:
        raise AnalystError(
            f"prompt {prompt.version!r} offers {TRACE_FIELD!r}, which is what the "
            f"tool layer measured and the model cannot see. A model that could "
            f"write the trace could authorise its own citations, because "
            f"`check_exchange` resolves them against it."
        )
    identity = (
        projection.tenant,
        projection.sensor,
        projection.context_id,
        projection.context_version,
    )
    asked = (
        request.tenant,
        request.sensor,
        request.context_id,
        request.context_version,
    )
    if identity != asked:
        raise AnalystError(
            f"the request is for {asked} and the projection is {identity}. The "
            f"projection is what says which indicators this host actually "
            f"contacted and what it did with them, so another context's is a run "
            f"scoped to a host it is not about."
        )
    names = [tool.name for tool in provider_tools]
    duplicated = sorted({name for name in names if names.count(name) > 1})
    if duplicated:
        raise AnalystError(
            f"two tools are called {duplicated}; a name is the only thing a model "
            f"addresses a tool by, so two sharing one is a tool it cannot reach"
        )


def _retrieved(retrievals: Sequence[Retrieval]) -> tuple[Any, ...]:
    """Every analyst-tier evidence row a run's retrievals produced, in order.

    `helena.enrichment.EnrichmentEvidence` rows, and only from calls that
    completed: a refusal produced none and a query that did not complete produced
    a typed error and no taxonomy object (`concept/05` rule 4), which is the
    distinction `helena.tools.ToolAnswer` already enforces one layer down.
    """
    return tuple(
        record
        for retrieval in retrievals
        if retrieval.lookup is not None and retrieval.lookup.answer is not None
        for record in retrieval.lookup.answer.evidence
    )


def _bounded(text: str, limit: int = contract.MAX_DETAIL) -> str:
    """A diagnostic is a sentence. Truncation is marked, never silent."""
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _diagnostic(text: str) -> str:
    """A refusal detail, bounded. It echoes text the model chose, so it is bounded."""
    return text[:MAX_FAILURE_DETAIL]


def _load(identifier: str) -> AnalystPrompt:
    """The prompt of one prompt version.

    Imported by name rather than held in a registry dict, so adding `v2` is adding
    a module and nothing else. The same loader `helena.taxonomy`,
    `helena.contracts`, `helena.hosts`, `helena.rendering`, `helena.triage` and
    `helena.policy` use.
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
            f"no analyst prompt {identifier!r}. An assessment that recorded it "
            f"cannot be reconstructed against this tree, so what the analyst was "
            f"asked is not reproducible here."
        ) from absent
    prompt = getattr(module, "PROMPT", None)
    if not isinstance(prompt, AnalystPrompt):
        raise UnknownVersion(
            f"{module.__name__} does not define an AnalystPrompt named PROMPT"
        )
    if prompt.version != identifier:
        raise UnknownVersion(
            f"{module.__name__} declares version {prompt.version!r}; a version "
            f"module and the version it declares must agree"
        )
    return prompt


#: Public name for the loader, so `version` reads as what a caller wants.
version = _load
