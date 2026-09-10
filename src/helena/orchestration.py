"""Orchestration — the routing `if`, and the deterministic code around the agents.

`concept/03-architecture.md` writes this component's whole job as a sentence and
then as five lines of pseudocode:

> **Orchestration is deterministic project code.** Agents are invoked by it. No
> agent selects, invokes, sequences or terminates another, and **no model output
> determines control flow**. Routing is an `if`:
>
> ```text
> if evidence escalates independently (tier A, or tier B above threshold):
>     run_analyst(trigger="deterministic_signal")   # independent of triage
> elif triage.root == "suspicious":
>     run_analyst(trigger="triage_suspicious")
> else:
>     finish()
> ```

`route` below is that `if`, transcribed. It is three lines because it is three
lines: a router that needed a class, a state machine or a graph would be a router
whose branches were not the two `concept/04-the-two-agents.md` names.

## The order is the invariant, not a preference

`assess` computes the escalation **before** it calls triage, and the two are
computed from different objects: `helena.policy.supports_in` reads the
projection, and nothing that decides an escalation ever sees the triage outcome.
`concept/04`:

> **An LLM returning `normal` may not bury a high-confidence match.** That is why
> the deterministic escalation input exists and why it is evaluated by code
> rather than inside the prompt.

Two things enforce that here rather than intend it. The evaluator has no
parameter a verdict could arrive through (`helena.policy.v1.escalate`, asserted
by `tests/test_policy.py`), and this module records the escalation on the log
channel before the model client records the call it made — so the order is a
thing a test reads out of a stream rather than a thing a comment claims.

**A triage failure routes exactly as a `normal` does**, which is `concept/04`'s
*"a triage failure does not escalate"* and is safe for the reason that note
gives: the other input does not care whether triage ran at all.

## What the trigger is for

`concept/04` puts the trigger in the request — *"the trigger (scheduled triage,
triage-suspicious, or deterministic escalation)"* — and `helena.contracts.v1`
already refuses the pairings that would describe another pipeline. This module is
what sets it: `analyst_request` derives the escalated run's request from the
triage request it escalated, changing the emitter, the trigger, the prompt
version and the budgets and **nothing else**. Same context, same version, same
rendering, so the row task 43 stores says why analysis ran and over what.

## What is deliberately not here

- **Persistence.** Nothing durable is written; `Assessment` is the in-process
  shape task 43 stores. `concept/07` allows working memory to be ephemeral and
  requires the record to be a typed row, and there is no assessment table yet.
- **Rendering the request.** `concept/03` puts *"renders agent input"* in this
  component and `helena.rendering` is the versioned half of it, but nothing in
  the tree yet reads a context's feed-snapshot, normalization and aggregation
  versions out of the store, so a request built here would have to invent three
  recorded versions. The caller builds the triage request; this module derives
  the analyst's from it, which is the half that is a routing decision.
- **A second store, a checkpoint, a queue or a resumable graph.**
  `tests/test_orchestration.py` asserts the absence of every framework that would
  bring one; `docs/decisions/0032-deterministic-routing.md` §6 records what would
  reverse the choice.

Reads: `helena.policy` (the escalation evaluator and its thresholds),
`helena.triage` and `helena.analyst` (the two runners), `helena.budgets` (the
configured budgets), `helena.disclosure` (a ledger per run). Writes: nothing
durable — the structured log record is this module's, the rest is returned.

Maturity: experimental — the routing is exercised by the suite over a real
capture, a real feed extract and a scripted endpoint, and against the two
runners. No assessment has been stored, no verdict has been evaluated against a
label, and nothing consumes what this returns yet.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from helena import agents, analyst, budgets, disclosure, observability, policy, tools, triage
from helena.contracts import v1 as contract
from helena.rendering import ContextProjection

__all__ = [
    "ESCALATION_EVALUATED",
    "FINISHED",
    "ROUTED",
    "Assessment",
    "OrchestrationError",
    "analyst_request",
    "assess",
    "route",
]

#: The event names this module writes to the log channel. Two, because the two
#: things worth counting are different questions: how often the evidence
#: escalated on its own, and where each context ended up. `concept/07` asks for
#: the routing to be countable, and a single "routed" record would make
#: "escalated but triage also said suspicious" indistinguishable from
#: "escalated and triage said normal" — which is the case the whole input exists
#: for.
ESCALATION_EVALUATED = "orchestration.escalation_evaluated"
ROUTED = "orchestration.routed"

#: What `ROUTED` records where `concept/03`'s `else: finish()` applies. The
#: trigger field of an `Assessment` is `None` there — there is no analyst request
#: and therefore no trigger — and this is the word the log line uses so that a
#: count over the stream covers all three branches.
FINISHED = "finished"


class OrchestrationError(Exception):
    """The router was misconfigured or misused. Never a model's fault.

    The two runners already have this distinction and it is the same one: a model
    that answered badly produces a `helena.contracts.v1.AgentFailure`, and this is
    raised for what is wrong before a call is made. `assess` returns an
    `Assessment` for everything else, because an exception escaping a router is a
    third terminal outcome every caller has to remember to catch.
    """


@dataclass(frozen=True)
class Assessment:
    """One context, routed: what escalated, what triage said, and where it went.

    The in-process record of one pass through `concept/03`'s pipeline, and the
    shape task 43 turns into typed rows. Six things, none derivable from another:

    | | |
    | --- | --- |
    | `request` | the triage request the pass began with: the tenant, the host, the window, the context reference and its version, and the version set |
    | `escalation` | what the **evidence** escalates on its own, from the frozen `policy_version` the request recorded. Computed for every context, whether or not triage answered |
    | `triage` | what the **triage model** said, validated against the frozen contract |
    | `trigger` | which branch of the routing `if` ran. `None` is `finish()` |
    | `analyst_request` | the request the escalated run was made under. `None` exactly where `trigger` is |
    | `analysis` | what the analyst produced. `None` exactly where `trigger` is |

    The two disclosure ledgers are separate for the reason
    `helena.disclosure.Disclosures` gives: a ledger names the emitter it is the
    record of, so one shared between the two stages would file the analyst's
    disclosures under triage.
    """

    request: contract.AgentRequest
    escalation: Any
    triage: contract.AgentResult | contract.AgentFailure
    triage_disclosures: disclosure.Disclosures
    trigger: str | None
    analyst_request: contract.AgentRequest | None
    analysis: analyst.Analysis | None
    analyst_disclosures: disclosure.Disclosures | None

    def __post_init__(self) -> None:
        escalated = self.trigger is not None
        for name in ("analyst_request", "analysis", "analyst_disclosures"):
            if (getattr(self, name) is not None) != escalated:
                raise OrchestrationError(
                    f"trigger is {self.trigger!r} and {name} is "
                    f"{'set' if getattr(self, name) is not None else 'None'}. The "
                    f"trigger is what says analysis ran, so a record where the two "
                    f"disagree is an assessment nobody can tell apart from a "
                    f"finished one."
                )
        if escalated and self.analyst_request.trigger != self.trigger:
            raise OrchestrationError(
                f"the assessment routed on {self.trigger!r} and the analyst "
                f"request records {self.analyst_request.trigger!r}. The request is "
                f"what a stored assessment reads the reason off "
                f"(`concept/04`), so two copies that can drift are worse than none."
            )

    @property
    def terminal(self) -> contract.AgentResult | contract.AgentFailure:
        """The outcome this context is assessed as: the analyst's, or triage's.

        `concept/03`: *"Every assessed context is emitted, exactly once per
        terminal outcome ... A context that was escalated is emitted once,
        carrying the analyst's verdict and the triage decision that led to it."*
        Both are on this object; this is which one is the verdict. What emits it
        is D7's.
        """
        return self.triage if self.analysis is None else self.analysis.outcome


def route(
    escalation: Any, outcome: contract.AgentResult | contract.AgentFailure
) -> str | None:
    """`concept/03`'s routing `if`, transcribed. The trigger, or `None` to finish.

    ```text
    if evidence escalates independently (tier A, or tier B above threshold):
        run_analyst(trigger="deterministic_signal")   # independent of triage
    elif triage.root == "suspicious":
        run_analyst(trigger="triage_suspicious")
    else:
        finish()
    ```

    **The evidence branch is first and it is not an optimisation.** Both branches
    reach the same agent, so the order changes nothing about *what runs* — it
    changes what the stored trigger says about *why*, and `concept/04` makes the
    deterministic input the one that matters: a context that escalated on its own
    and whose triage also said `suspicious` is recorded as the escalation it was.

    `outcome` can only ever move this in one direction. Where the evidence
    escalates, no value of it reaches the second branch at all — which is
    `concept/instruction.md` §2's *"a `normal` from a model may not suppress a
    high-confidence match"* as a property of the control flow rather than of a
    prompt.

    The triage half is `helena.triage.escalates`, not a second reading of the
    verdict: that function already refuses to read anything off a typed failure,
    and a copy here would be a second opinion about which roots escalate.
    """
    if escalation.escalates:
        return contract.DETERMINISTIC_SIGNAL
    if triage.escalates(outcome):
        return contract.TRIAGE_SUSPICIOUS
    return None


def analyst_request(
    request: contract.AgentRequest,
    *,
    trigger: str,
    prompt_version: str,
    granted: contract.Budgets,
) -> contract.AgentRequest:
    """The escalated run's request, derived from the triage request that escalated.

    Four fields change and nothing else does. The emitter, because the two agents
    differ in where their information comes from; the trigger, because that is
    what `concept/04` puts in the request so a stored assessment says why analysis
    ran; the prompt version, because the analyst's prompt is its own frozen
    module; and the budgets, because `concept/07` makes those policy and the two
    agents are budgeted differently.

    **The context, its version and the rendering are the same objects.** That is
    the point of deriving rather than rebuilding: the analyst re-reads the context
    triage saw, at the version triage saw it at, so the two records join and a
    replay of either is a replay of one snapshot. `concept/04` gives the analyst
    *"the rendering, plus (when built) bounded cited case memory"* — the extra is
    the tool loop's, not a second rendering.

    Raises `OrchestrationError` for a trigger that is not one of the analyst's
    two. The contract refuses it as well; this raises first so the message names
    the router rather than a validation error on a field the caller never set.
    """
    if trigger not in (contract.TRIAGE_SUSPICIOUS, contract.DETERMINISTIC_SIGNAL):
        raise OrchestrationError(
            f"{trigger!r} is not one of the analyst's triggers "
            f"{[contract.TRIAGE_SUSPICIOUS, contract.DETERMINISTIC_SIGNAL]}; "
            f"{contract.SCHEDULED_TRIAGE!r} is how a triage run begins and is "
            f"never how the selective stage is reached"
        )
    # Rebuilt through the constructor rather than by `model_copy(update=...)`,
    # which does not re-validate: the pairing of the emitter and the trigger, and
    # the refusal of a triage budget that permits a lookup, are `AgentRequest`'s
    # own checks, and a derived request that skipped them would be the one request
    # in the system the contract never saw.
    recorded = {
        name: getattr(request.versions, name)
        for name in contract.RequestVersions.model_fields
    }
    recorded["prompt_version"] = prompt_version
    fields = {
        name: getattr(request, name) for name in contract.AgentRequest.model_fields
    }
    fields.update(
        emitter=analyst.EMITTER,
        trigger=trigger,
        budgets=granted,
        versions=contract.RequestVersions(**recorded),
    )
    return contract.AgentRequest(**fields)


def assess(
    request: contract.AgentRequest,
    *,
    projection: ContextProjection,
    triage_client: agents.ModelClient,
    analyst_client: agents.ModelClient,
    retry: agents.RetryPolicy,
    triage_prompt: triage.TriagePrompt,
    analyst_prompt: analyst.AnalystPrompt,
    provider_tools: Sequence[tools.ProviderTool],
    thresholds: policy.Thresholds,
    budget_policy: budgets.BudgetPolicy,
    send_policy: disclosure.SendPolicy,
    inherit: analyst.Inheritance,
    logger: observability.StructuredLogger,
) -> Assessment:
    """One context, from the triage request to the terminal outcome. Never raises for a model.

    The order below is `concept/03`'s and the first two steps may not be swapped:

    1. read every claim the context holds and evaluate the escalation — **before
       any model has been called**, from the frozen rules the request recorded;
    2. run triage;
    3. route (`route`);
    4. where the route is not `finish`, derive the analyst request and run it.

    `thresholds`, `budget_policy`, `send_policy`, `inherit` and `retry` are passed
    in rather than loaded here, for the reason `helena.analyst.run` gives of its
    own: a run scored against a policy it never ran under is a measurement of
    nothing, so the values a deployment loaded once are handed in. The **rules**
    are not among them — like the composition rule, they are loaded from the
    `policy_version` the request records, because a caller that could pass
    different ones could escalate a context under rules its row does not name.

    Raises `OrchestrationError` for what is this code's fault before a call is
    made: a request that is not a triage request. Everything the two runners
    refuse — a prompt version that is not the recorded one, a projection of
    another context, two tools with one name — is theirs to refuse, and their
    errors already name what is wrong.
    """
    if request.emitter != triage.EMITTER:
        raise OrchestrationError(
            f"routing begins with a {triage.EMITTER!r} request and this one is "
            f"for {request.emitter!r}. `concept/03` has one entry point: every "
            f"context is triaged, and analysis is what a branch reaches."
        )
    rules = policy.version(request.versions.policy_version)

    # Step 1, and it is first on purpose. `concept/04`: the enrichment evidence
    # escalates on its own "regardless of the triage verdict", so it is computed
    # from the projection before anything has an opinion to suppress it with.
    escalation = rules.escalate(policy.supports_in(projection), thresholds)
    logger.info(
        ESCALATION_EVALUATED,
        context_id=request.context_id,
        context_version=request.context_version,
        host=request.host,
        escalates=escalation.escalates,
        evidence_ids=list(escalation.evidence_ids),
        claims_read=escalation.claims_read,
        candidates=len(escalation.candidates),
        gaps=[gap.kind for gap in escalation.gaps],
        policy_version=escalation.policy_version,
        thresholds_version=escalation.thresholds_version,
    )

    triage_disclosures = disclosure.Disclosures.of(request, policy=send_policy)
    outcome = triage.run(
        request,
        client=triage_client,
        policy=retry,
        prompt=triage_prompt,
        disclosures=triage_disclosures,
    )

    trigger = route(escalation, outcome)
    logger.info(
        ROUTED,
        context_id=request.context_id,
        context_version=request.context_version,
        host=request.host,
        trigger=FINISHED if trigger is None else trigger,
        escalates=escalation.escalates,
        triage_outcome=_outcome_of(outcome),
    )
    if trigger is None:
        return Assessment(
            request=request,
            escalation=escalation,
            triage=outcome,
            triage_disclosures=triage_disclosures,
            trigger=None,
            analyst_request=None,
            analysis=None,
            analyst_disclosures=None,
        )

    escalated = analyst_request(
        request,
        trigger=trigger,
        prompt_version=analyst_prompt.version,
        granted=budget_policy.for_emitter(analyst.EMITTER),
    )
    analyst_disclosures = disclosure.Disclosures.of(escalated, policy=send_policy)
    analysis = analyst.run(
        escalated,
        client=analyst_client,
        policy=retry,
        prompt=analyst_prompt,
        provider_tools=provider_tools,
        disclosures=analyst_disclosures,
        projection=projection,
        inherit=inherit,
        triage=outcome,
    )
    return Assessment(
        request=request,
        escalation=escalation,
        triage=outcome,
        triage_disclosures=triage_disclosures,
        trigger=trigger,
        analyst_request=escalated,
        analysis=analysis,
        analyst_disclosures=analyst_disclosures,
    )


def _outcome_of(outcome: contract.AgentResult | contract.AgentFailure) -> str:
    """What triage produced, as one word for the log line.

    A root or a failure reason, and never a collapse of the two: a run that
    failed is not a run that said `normal` (`concept/instruction.md` §2), and a
    count over this field has to be able to tell them apart.
    """
    if isinstance(outcome, contract.AgentResult):
        return outcome.root
    return outcome.reason
