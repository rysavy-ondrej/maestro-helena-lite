"""Triage — one bounded rendering in, one of two labels out, and nothing else.

`concept/04-the-two-agents.md` makes the Triage Agent the asymmetric half of the
pipeline: its input is *"a bounded rendering, **and nothing else**"*, its tools
are *"none at all"*, its retrieval is *"none — no lookups, no waiting"*, and its
verdicts are `normal` or `suspicious`. `concept/02-concepts-and-taxonomy.md`
closes it: *"Triage emits `normal` or `suspicious` and nothing else. A context
triage could not assess is a **typed failure**, not a third label."*

This package holds the **runner**; `v1.py` holds the **prompt**. The split is
`docs/decisions/0008-version-registry.md`'s, in the words it uses of the
rendering: *"prompt and rendering versions follow the same shape: what triage saw
is pinned by the recorded version, not reconstructed from current code."* An
assessment records `prompt_version`, so the words the model was shown and the
field set it was offered are frozen the moment a row records one, and a reworded
instruction is a `v2` beside `v1` rather than an edit.

## What this adds over `helena.agents.assess`

`assess` is the model path — call, validate, retry bounded, or a typed failure.
It deliberately does four things not at all, and this is where all four happen:

| | Where it comes from |
| --- | --- |
| The prompt, with the rendering framed as data | `helena.triage.v1` |
| The schema narrowed to what triage may answer | `classifications`, a lookup in `helena.taxonomy` |
| The `truncated` gap on the outcome | `concept/instruction.md` §2, and it is a fact *code* knows |
| `helena.contracts.v1.check_exchange` | the rules that hold between a request and what it produced |

**Binding no tools is asserted at the call site**, not left to the contract.
`AgentRequest` already refuses a triage request that budgets a step or a live
query, and `AgentResult` already refuses one that reports having spent either —
but a runner that relied on that would be a runner whose own "triage has no
tools" is a comment. `run` checks the budgets it was handed and the field set it
is about to offer, and `tests/test_triage.py` asserts over the bytes the endpoint
receives that no tool definition is sent.

## Failing closed, and why that is safe

`escalates` is **one** of the two independent inputs that reach the analyst, and
it is deliberately not the interesting one. `concept/04`:

> **Triage returned `suspicious`.** / **The enrichment evidence escalates on its
> own** — a Tier A, or a high-confidence Tier B, malicious classification whose
> traffic characteristics support it — **regardless of the triage verdict**. An
> LLM returning `normal` may not bury a high-confidence match. ... **A triage
> failure does not escalate.** Failing closed is safe precisely because
> deterministic escalation is independent of whether triage ran at all; failing
> open would flood the expensive stage exactly when the model service is already
> failing.

So a typed failure escalates nothing here, and the safety of that is a property
of the *other* input, which is task 33's deterministic evaluator and does not
exist yet. Until it does, **this is a pipeline that fails closed with nothing
behind it**, and that is stated rather than implied:
`tests/test_triage.py::test_a_triage_failure_does_not_escalate` names the
dependency in its docstring and `docs/decisions/0021-the-triage-runner.md` §6
records it as the one thing this increment leaves genuinely unsafe.

Reads: `helena.agents` (the model path), `helena.taxonomy` (the closed root set),
`helena.contracts.v1` (the frozen request/result pair). Writes: nothing durable —
the structured log record is `helena.agents`'.

Maturity: experimental — exercised against a scripted endpoint and against the
real configured endpoint. No assessment has been stored, no verdict has been
evaluated against a label, and nothing routes on what this returns yet.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import ModuleType
from typing import Any

from helena import agents, budgets, disclosure, taxonomy
from helena.contracts import ContractError
from helena.contracts import v1 as contract

__all__ = [
    "CLASSIFICATION",
    "TOOL_SHAPED_FIELDS",
    "TriageError",
    "TriagePrompt",
    "UnknownVersion",
    "classifications",
    "escalates",
    "run",
    "version",
]

#: The emitter this package runs. One spelling, `helena.taxonomy`'s.
EMITTER = taxonomy.TRIAGE

#: The result property whose closed set is per emitter, and which
#: `helena.agents.CLOSED_VOCABULARIES` therefore cannot hold — see
#: `helena.agents.proposal_schema`.
CLASSIFICATION = "classification"

#: The three result fields `helena.contracts.v1.AgentResult` refuses from triage,
#: each because it is a thing only a stage with tools could have produced: an
#: assembled evidence package, a retrieval trace, a proposed claim. Named here so
#: that offering one in the prompt's field set is a startup failure rather than a
#: schema the model can only fail.
TOOL_SHAPED_FIELDS = ("evidence_package", "retrieval_trace", "proposed_claims")


class TriageError(Exception):
    """The triage runner was misconfigured or misused. Never a model's fault.

    A model that answered badly produces a `helena.contracts.v1.AgentFailure`;
    this is raised for the things that are wrong before a call is made, or that
    are wrong about this code rather than about an answer.
    """


class UnknownVersion(TriageError):
    """A prompt version was asked for that this package does not hold.

    Distinct for the reason `helena.rendering.UnknownVersion` is: a stored
    assessment recording a `prompt_version` whose module is absent is a replay
    that cannot be reconstructed, not a value that is invalid.
    """


@dataclass(frozen=True)
class TriagePrompt:
    """One prompt version: what it is called, what it asks for, and how it asks.

    A callable and two values rather than a class with one method, for the reason
    `helena.rendering.RenderingVersion` gives: a prompt is a function of a request
    and holds no state.

    `propose` is part of the version and not of the runner. It is *what the model
    was offered*, and a `v2` that offered a different field set would have shown
    the model a different question — `schema_version` would not record that,
    because the contract would not have changed.
    """

    version: str
    #: The `helena.contracts.v1.AgentResult` fields this version asks the model
    #: for. `helena.agents.proposal_schema` refuses anything the contract does
    #: not let a model propose.
    propose: tuple[str, ...]
    #: `(request, *, classifications) -> tuple[helena.agents.Message, ...]`.
    messages: Any


def classifications(taxonomy_version: str) -> tuple[str, ...]:
    """The verdicts triage may return, looked up rather than written down.

    `helena.taxonomy`'s `emitter_roots[triage]` is the one place the closed set
    lives, and it is closed *per taxonomy version* — so this resolves against the
    version the request records, not against current code. A tuple of literals
    here would be the second copy of a version-frozen vocabulary that
    `concept/instruction.md` §2 refuses.

    **The roots, not the paths under them.** The contract would accept
    `suspicious.low_reputation` from triage — `helena.taxonomy.for_emission`
    permits any path whose root is in the emitter's set — and this version does
    not offer one, because `concept/04`'s table gives triage two verdicts and its
    question is *is this worth analysing*, not *what is it*. The concrete cost of
    offering them is `normal.known_service`: a `normal` triage decision carries no
    citations at all, so a specific `normal` path would be an uncited claim that
    a service was identified. `docs/decisions/0021-the-triage-runner.md` §2 has
    the reasoning and what a model that answered a sub-path anyway would produce.

    Every offered value is put through `for_emission`, so a future version that
    marked a root unused fails here rather than offering the model a verdict the
    contract would then refuse.
    """
    vocabulary = taxonomy.version(taxonomy_version)
    offered = tuple(sorted(vocabulary.emitter_roots[EMITTER]))
    if not offered:
        raise TriageError(
            f"taxonomy {taxonomy_version} closes {EMITTER} over no roots at all, "
            f"so there is no verdict to ask for"
        )
    for path in offered:
        taxonomy.for_emission(
            path, level=taxonomy.CONTEXT, version=vocabulary, emitter=EMITTER
        )
    return offered


def run(
    request: contract.AgentRequest,
    *,
    client: agents.ModelClient,
    policy: agents.RetryPolicy,
    prompt: TriagePrompt,
    disclosures: disclosure.Disclosures,
) -> contract.AgentResult | contract.AgentFailure:
    """One triage assessment. A verdict or a typed failure, and never a third thing.

    Two terminal outcomes, the way `helena.agents.assess` has two, and for the
    same reason: an exception escaping here would be a third one every caller has
    to remember to catch. What this adds around `assess` is in the module
    docstring; the order below is the order it has to happen in, because the
    truncation gap has to be on the outcome *before* the exchange is checked.

    **The disclosure ledger is the caller's and the budget ledger is not**, and the
    asymmetry is the contract's rather than a preference. What the budget ledger
    becomes leaves on the result: `AgentResult.cost` is a contract field, so a
    ledger built here still reaches whoever stores the assessment. A disclosure
    row has no contract field to leave on — adding one is a change to the agent
    contract (`concept/instruction.md` §3) and `concept/07` puts the record on the
    *assessment* rather than in the agent's answer — so the ledger has to belong to
    the code that will store it. Triage discloses on every context it runs on,
    hosted inference being egress (`concept/03`), so this is not a formality.

    Raises `TriageError` for the things that are this code's fault — a request
    that is not a triage request, a prompt version that is not the one the
    request records, a field set that offers what triage may not carry. Those are
    startup failures, not assessments.
    """
    _check_binds_no_tools(request, prompt)
    if request.versions.prompt_version != prompt.version:
        raise TriageError(
            f"the request records prompt_version "
            f"{request.versions.prompt_version!r} and the prompt is "
            f"{prompt.version!r}. What triage saw is pinned by the recorded "
            f"version, so two copies that can drift are worse than none "
            f"(`concept/instruction.md` §2)."
        )

    offered = classifications(request.versions.taxonomy_version)
    # The ledger for this run, built here because for triage `run` **is** the
    # whole run: one model exchange, no tool loop, nothing to charge but the
    # tokens and the clock. The analyst's runner is where one ledger has to reach
    # two places (`helena.budgets`), and it is a later increment; building one
    # here would be the same object with a shorter life.
    budget = budgets.RunBudget.of(request)
    outcome = agents.assess(
        request,
        client=client,
        messages=prompt.messages(request, classifications=offered),
        policy=policy,
        budget=budget,
        disclosures=disclosures,
        propose=prompt.propose,
        vocabularies={CLASSIFICATION: offered},
    )
    outcome = agents.with_truncation_gap(request, outcome)
    try:
        contract.check_exchange(request, outcome)
    except ContractError as refused:
        return _unheld_exchange(request, outcome, refused)
    return outcome


def escalates(outcome: contract.AgentResult | contract.AgentFailure) -> bool:
    """Whether *this* outcome is the triage half of what reaches the analyst.

    `concept/04` gives the analyst two independent inputs and this is the first:
    *"Triage returned `suspicious`."* The second — enrichment evidence escalating
    on its own, regardless of the triage verdict — is evaluated by code that does
    not read this function at all, which is the whole point of it being
    independent, and it is task 33's.

    **A typed failure escalates nothing.** `concept/04`: *"A triage failure does
    not escalate. Failing closed is safe precisely because deterministic
    escalation is independent of whether triage ran at all; failing open would
    flood the expensive stage exactly when the model service is already
    failing."* There is nothing to read off a failure — it has no verdict field
    to read — and the check here is the type, so a future field could not change
    that by accident.

    The verdict test is *not `normal`* rather than *is `suspicious`*, and the
    difference matters in one direction only: a taxonomy version that gave triage
    a third root would escalate it rather than silently treat it as clean. The
    contract closes triage over `emitter_roots`, so under `v1` this is exactly
    `suspicious`, and `tests/test_triage.py` asserts that equivalence against the
    vocabulary rather than assuming it.
    """
    return (
        isinstance(outcome, contract.AgentResult) and outcome.root != contract.NORMAL
    )


def _check_binds_no_tools(request: contract.AgentRequest, prompt: TriagePrompt) -> None:
    """`concept/04`: tools "none at all", retrieval "none — no lookups, no waiting".

    Checked here as well as in the contract, because this is the call site and
    the claim is about what this code binds. The three checks are three different
    ways a tool could arrive: the wrong agent's request, a budget that permits a
    lookup, and a field set that asks the model for something only a tool loop
    could produce.
    """
    if request.emitter != EMITTER:
        raise TriageError(
            f"this runner runs {EMITTER!r} and the request is for "
            f"{request.emitter!r}. The two agents differ in where their "
            f"information comes from, so running one's request through the "
            f"other's prompt is an assessment of neither."
        )
    if request.budgets.steps or request.budgets.live_queries:
        raise TriageError(
            f"the request budgets {request.budgets.steps} steps and "
            f"{request.budgets.live_queries} live queries, and triage has no "
            f"tools at all. A budget that permits a lookup is a lookup nobody "
            f"has to justify."
        )
    offered = sorted(set(prompt.propose) & set(TOOL_SHAPED_FIELDS))
    if offered:
        raise TriageError(
            f"prompt {prompt.version!r} offers {offered}, which the contract "
            f"refuses from {EMITTER}: they are what a stage with tools produces. "
            f"Offering them would be offering the model a way to fail validation "
            f"and nothing else."
        )


def _unheld_exchange(
    request: contract.AgentRequest,
    outcome: contract.AgentResult | contract.AgentFailure,
    refused: ContractError,
) -> contract.AgentFailure:
    """A verdict that does not hold against its own request is a typed failure.

    `check_exchange` has four rules, and for an outcome this function produced,
    three of them cannot fail: the emitter is `request.emitter` because `assess`
    copies it there, the eight echoed versions are `request.versions` because
    `RequestVersions.completed_by` is the only thing that builds the result's
    version set, and the `truncated` gap was just written above. What is left is
    the rule that is about the **model's** answer: *every citation resolves to
    something the run was actually given.* A model citing an evidence id the
    rendering never showed has answered wrongly, so the run produced no verdict —
    which is `schema_invalid`, the reason that means the model answered and the
    answer did not hold.

    It is not retried, and that is a real cost rather than an oversight: the
    retry loop is inside `assess` and feeds back what *validation* said, and
    teaching it to feed back an exchange rule means handing it the request's
    rendering. Recorded in `docs/decisions/0021-the-triage-runner.md` §5 with
    what would settle whether it is worth doing — a measured rate of invented
    citations, which needs assessments to be stored.
    """
    if isinstance(outcome, contract.AgentFailure):  # pragma: no cover — see above
        raise refused
    return contract.AgentFailure(
        emitter=request.emitter,
        reason=contract.SCHEMA_INVALID,
        detail=_bounded(f"the answer did not hold against its request: {refused}"),
        gaps=outcome.gaps,
        cost=outcome.cost,
        versions=request.versions,
        model_version=outcome.versions.model_version,
    )


def _bounded(text: str, limit: int = contract.MAX_DETAIL) -> str:
    """A diagnostic is a sentence. Truncation is marked, never silent."""
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _load(identifier: str) -> TriagePrompt:
    """The prompt of one prompt version.

    Imported by name rather than held in a registry dict, so adding `v2` is
    adding a module and nothing else. The same loader `helena.taxonomy`,
    `helena.contracts`, `helena.hosts` and `helena.rendering` use.
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
            f"no triage prompt {identifier!r}. An assessment that recorded it "
            f"cannot be reconstructed against this tree, so what triage was asked "
            f"is not reproducible here."
        ) from absent
    prompt = getattr(module, "PROMPT", None)
    if not isinstance(prompt, TriagePrompt):
        raise UnknownVersion(
            f"{module.__name__} does not define a TriagePrompt named PROMPT"
        )
    if prompt.version != identifier:
        raise UnknownVersion(
            f"{module.__name__} declares version {prompt.version!r}; a version "
            f"module and the version it declares must agree"
        )
    return prompt


#: Public name for the loader, so `version` reads as what a caller wants.
version = _load
