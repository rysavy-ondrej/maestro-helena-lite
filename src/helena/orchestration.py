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
rendering, so the stored row says why analysis ran and over what.

## Agents propose; code writes

`AssessmentStore` is the second half of this module and it is here rather than in
a module of its own because `concept/03` puts persistence in this component's row:
*"validates output, persists assessments including typed failures, and replays
from stored results."* It turns one `Assessment` into the typed rows of
`sql/migrations/0018_assessments.sql` — one row per **agent run**, citations as
`(assessment, evidence, role)` join rows, and a typed failure as a row carrying
the failure and no verdict. Nothing an agent produced reaches a column that the
frozen contract did not validate, and `store` re-runs
`helena.contracts.v1.check_exchange` before it writes.

## Working memory is the call, and a re-run is the whole of the recovery

`concept/03`: *"An assessment is one function call over one versioned context
snapshot. No checkpointing, no durable in-flight state anywhere outside the
engine; an interrupted run is simply re-run, because the versioned context
already makes that correct rather than a fallback."*

So `assess` is a function and everything it accumulates — the two disclosure
ledgers, the budget guard, the tool-loop transcript inside
`helena.analyst.run` — is constructed inside the call and unreachable after it
returns. This module holds no module-level mutable object at all, and nothing in
the package writes a file: there is no scratchpad, no transcript on disk, no
planning state and no framework virtual filesystem, because there is no framework
and no second place for state to live. `tests/test_orchestration.py` asserts both
by execution rather than by comment.

What that buys is that **re-run recovery needs no recovery machinery**. There is
no `resume`, no run id to look up and no checkpoint to reconcile: a run that was
interrupted is re-run by calling `assess` again over the same projection, and
`AssessmentStore.store` makes the result of doing so well-defined. Two things
make it so, and the second is this module's:

1. `assessment_id` is a digest over `(tenant, sensor, context reference, context
   version, emitter, trigger)`, so a re-run mints the identifier the first run
   did and rewrites its own row rather than adding a second copy.
2. **A pass supersedes every other run over its own context snapshot**
   (`RUNS_OF_A_PASS`). The identifier is the only thing that changes between a
   pass that escalated on the evidence, one that escalated on triage, and one
   that finished — so without this, a re-run that routed differently from the run
   it replaced would leave the earlier analyst row standing beside it as a second
   live opinion over one context version, and an interrupted run's orphaned child
   rows would never be collected at all.

A framework convenience is checked against those rules before it is switched on,
not after: `concept/03` says the ephemeral-state rule *"binds harder if a
framework is adopted, because such libraries make file-backed agent memory the
convenient default"*, and a checkpointer, a persistent scratchpad or a virtual
filesystem is a second store of uncited free text — which is a single-store
violation and a memory-poisoning channel at once.
`docs/decisions/0034-ephemeral-state-and-re-run.md` is the long form and the
three questions to ask of the next such flag.

## What is deliberately not here

- **The escalation record.** `Assessment.escalation` is computed on every pass and
  is not stored. It is recomputable from the projection under the recorded
  `policy_version`, but its `thresholds_version` is not on the request and is
  therefore not on any row yet — so a replay can reproduce the routing only for a
  deployment whose thresholds have not moved. **No remaining task lists it**;
  task 45 (assessment replay) is the first thing that cannot proceed without it,
  and what it needs is a typed row per pass with the candidates as join rows,
  which is a table this increment's step list does not name.
- **Proposed claims.** `AgentResult.proposed_claims` is written nowhere.
  `concept/07` makes a claim about infrastructure a proposal that deterministic
  code validates and writes, and where it is written is the findings table, which
  does not exist. Its citations are deliberately **not** folded into the
  assessment's citation rows — see `AssessmentStore._citations`.
- **The composition rule's decision.** `Analysis.decision` — what the cited
  evidence permits the verdict to be read as — is not stored either. It is a
  second record beside the verdict (`concept/07` keeps inference append-only) and
  it has its own findings list, which is the same shape and the same missing table
  as the proposals above.
- **Refused retrievals.** `Analysis.retrievals` holds the turns the tool layer
  refused, and `helena.contracts.v1.RETRIEVAL_OUTCOMES` has no value for one: a
  refusal is not a cache hit and not a live query. Turning it into a `Gap` is a
  decision somebody should make deliberately rather than discover, so the trace
  table holds `AgentResult.retrieval_trace` and nothing else.
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
configured budgets and the price table), `helena.disclosure` (a ledger per run).
Writes: `sql/migrations/0018_assessments.sql`'s six tables, through
`AssessmentStore`, plus the structured log record.

Maturity: experimental — the routing is exercised by the suite over a real
capture, a real feed extract and a scripted endpoint, and against the two
runners; the persistence by `tests/test_assessments.py` against a real engine,
including a run driven end to end through a scripted endpoint. No verdict has
been evaluated against a label, nothing has been replayed from a stored
assessment, and nothing consumes what these tables hold yet.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from helena import agents, analyst, budgets, disclosure, observability, policy, tools, triage
from helena.contracts import ContractError
from helena.contracts import v1 as contract
from helena.rendering import ContextProjection

__all__ = [
    "ASSESSMENT_TABLE",
    "CHILD_TABLES",
    "CITATION_TABLE",
    "DISCLOSURE_TABLE",
    "ESCALATION_EVALUATED",
    "FINISHED",
    "GAP_TABLE",
    "PATTERN_TABLE",
    "RETRIEVAL_TABLE",
    "ROUTED",
    "RUNS_OF_A_PASS",
    "Assessment",
    "AssessmentError",
    "AssessmentStore",
    "OrchestrationError",
    "analyst_request",
    "assess",
    "assessment_id",
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
    shape `AssessmentStore` turns into typed rows. Six things, none derivable from another:

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


# --- Persistence --------------------------------------------------------------
#
# `concept/03-architecture.md`: *"Agent output is stored as typed, queryable rows
# with citation joins, never as an opaque document."* The tables are
# `sql/migrations/0018_assessments.sql` and its head carries the shape argument;
# what is here is the code that writes them, because `concept/07-principles.md`
# makes that a rule rather than a convenience: *"an agent's claim about
# infrastructure is a **proposal**, validated against a schema and written by
# deterministic code."* Nothing below takes a value from an agent that the frozen
# contract did not already validate, and `store` re-runs the request/outcome
# rules before it writes a row.

#: The six tables one assessment is written into. Named here so the writer, the
#: delete-before-insert and `tests/test_assessments.py` agree on one spelling.
ASSESSMENT_TABLE = "helena_analytical_assessment"
CITATION_TABLE = "helena_analytical_assessment_citation"
GAP_TABLE = "helena_analytical_assessment_gap"
PATTERN_TABLE = "helena_analytical_assessment_pattern"
RETRIEVAL_TABLE = "helena_analytical_assessment_retrieval"
DISCLOSURE_TABLE = "helena_analytical_assessment_disclosure"

#: The five keyed by `assessment_id` alone, in the order they are emptied. The
#: assessment row is not among them: it is upserted rather than deleted, so a
#: re-run never leaves a window in which the context has no assessment at all.
CHILD_TABLES = (
    CITATION_TABLE,
    GAP_TABLE,
    PATTERN_TABLE,
    RETRIEVAL_TABLE,
    DISCLOSURE_TABLE,
)

#: Every `(emitter, trigger)` a pass over one context snapshot can produce a run
#: for — the three pairings `helena.contracts.v1.AgentRequest` accepts, and
#: `tests/test_orchestration.py` asserts these are exactly those rather than
#: leaving two copies to drift.
#:
#: The set is enumerable, and that is what makes a re-run's cleanup possible
#: without a read path: `assessment_id` is a pure function of the snapshot and
#: one of these pairs, so the **three identifiers one context version could ever
#: hold** are derivable from the request alone. A pass writes one or two of them
#: and supersedes the rest, which collects both the row a differently-routed
#: earlier run left standing and the child rows an interrupted one wrote before
#: it died — neither of which a query keyed on what is *present* would find.
RUNS_OF_A_PASS = (
    (triage.EMITTER, contract.SCHEDULED_TRIAGE),
    (analyst.EMITTER, contract.TRIAGE_SUSPICIOUS),
    (analyst.EMITTER, contract.DETERMINISTIC_SIGNAL),
)


class AssessmentError(Exception):
    """A row could not be written, and nothing was written for that run.

    Separate from `OrchestrationError` because the two are different failures at
    different times: that one refuses a request before any model is called, this
    one refuses an outcome the store cannot represent honestly — a verdict and a
    failure on one row, two endpoint hosts in one ledger, a citation to evidence
    the run was never given.
    """


def assessment_id(
    *,
    tenant: str,
    sensor: str,
    context_id: str,
    context_version: str,
    emitter: str,
    trigger: str,
) -> str:
    """The stable identifier for one agent run over one versioned context.

    A digest over what makes it that run, the same construction
    `helena.enrichment.evidence_id` uses and for the same reason: `concept/03`
    says *"an interrupted run is simply re-run, because the versioned context
    already makes that correct rather than a fallback"*, so a re-run has to mint
    the identifier the first run did and rewrite its own row. A RisingWave INSERT
    onto an existing primary key is a silent upsert, so idempotence comes from the
    key or it does not exist.

    **The outcome is not in it.** Two runs over one context version are the same
    assessment made twice; a verdict in the digest would leave the first run's row
    standing beside the second as a second live opinion.

    **Tenant and sensor are in it** for the reason the event id and the evidence
    id have them: two deployments assessing the same context reference would
    otherwise mint the same identifier in one store, and the upsert would be a
    cross-tenant overwrite that looks like it is working.
    """
    material = b"".join(
        _length_prefixed(part)
        for part in (tenant, sensor, context_id, context_version, emitter, trigger)
    )
    return hashlib.sha256(material).hexdigest()


def _length_prefixed(value: str) -> bytes:
    """`value` as its UTF-8 length, a colon, then its UTF-8 bytes.

    A third copy of `helena.normalizer`'s and `helena.enrichment`'s, kept private
    to each module the way those two are: a digest over concatenated fields with
    no lengths in it collides whenever two fields can borrow a character from each
    other, and the three identifiers are three contracts rather than one function.
    """
    encoded = value.encode("utf-8")
    return f"{len(encoded)}:".encode() + encoded


class AssessmentStore:
    """The write side of `concept/03`'s stored assessment. Deterministic code, one store.

    Holds a `psycopg.Connection` and the price table, and nothing else — no
    buffer, no in-process index, no queue. Every statement addresses
    `sql/migrations/0018_assessments.sql`'s tables in the same engine the rest of
    the system uses, which is what "one store" means here.

    `prices` is passed in rather than loaded, for the reason `assess` gives of the
    thresholds and the budgets: a row whose cost was derived from a price table
    the deployment did not run under is a figure nobody can check.
    """

    __slots__ = ("_connection", "_prices")

    def __init__(self, connection: Any, prices: budgets.PriceTable) -> None:
        if not isinstance(prices, budgets.PriceTable):
            raise AssessmentError(
                f"prices is a {type(prices).__name__}; the derived cost and the "
                f"`model_prices_version` beside it come from one table, so that "
                f"the figure and the revision that produced it cannot disagree"
            )
        self._connection = connection
        self._prices = prices

    def store(self, assessment: Assessment, *, at: datetime) -> tuple[str, ...]:
        """Write one routed pass: one row for triage, and one for the analyst if it ran.

        Returns the identifiers written, triage first. `at` is the wall time the
        assessment is recorded at — passed in rather than read from a clock here,
        so a test can assert it and so both rows of one pass carry the same value:
        they are one pass, and two timestamps a fraction apart would invite a
        reader to order them.

        Raises `AssessmentError` for anything the store cannot represent
        honestly, **before** it writes anything for that run. Everything a model
        did is already a typed outcome by the time it arrives here.

        **This is also the re-run path**, and it is the only one: `concept/03`
        has no resume, so storing a second pass over the same versioned snapshot
        is what recovering an interrupted one means. The rows this pass wrote
        stand, and every other run over that snapshot is superseded — after the
        writes rather than before them, so there is no instant at which the
        context has no assessment at all.
        """
        written = [self._one(assessment.request, assessment.triage,
                             assessment.triage_disclosures, at=at)]
        if assessment.analysis is not None:
            written.append(
                self._one(
                    assessment.analyst_request,
                    assessment.analysis.outcome,
                    assessment.analyst_disclosures,
                    at=at,
                )
            )
        self._supersede(assessment.request, keep=written)
        self._connection.execute("FLUSH")
        return tuple(written)

    def _supersede(self, request: contract.AgentRequest, *, keep: list[str]) -> None:
        """Remove every run over this context snapshot that this pass did not write.

        The three identifiers a snapshot could hold are derivable from the request
        (`RUNS_OF_A_PASS`), so this addresses them by key and never reads the
        store: a `DELETE` on a key nothing wrote is a no-op, which is why the
        child tables are emptied for a superseded identifier whether or not an
        assessment row was ever written under it. That case is not hypothetical —
        `_one` writes the children first, so a run killed between them and the
        assessment row leaves exactly that.

        `concept/03` allows the residue to exist at all only because it is *in the
        engine*: "no durable in-flight state anywhere outside the engine". What
        this method adds is that the re-run collects it, so what the store holds
        for one context version is what the last completed pass over it produced,
        and nothing else.
        """
        for emitter, trigger in RUNS_OF_A_PASS:
            identifier = assessment_id(
                tenant=request.tenant,
                sensor=request.sensor,
                context_id=request.context_id,
                context_version=request.context_version,
                emitter=emitter,
                trigger=trigger,
            )
            if identifier in keep:
                continue
            for table in CHILD_TABLES:
                self._connection.execute(
                    f"DELETE FROM {table} WHERE assessment_id = %s", (identifier,)
                )
            self._connection.execute(
                f"DELETE FROM {ASSESSMENT_TABLE} WHERE assessment_id = %s",
                (identifier,),
            )

    def _one(
        self,
        request: contract.AgentRequest,
        outcome: contract.AgentResult | contract.AgentFailure,
        disclosures: disclosure.Disclosures,
        *,
        at: datetime,
    ) -> str:
        """One agent run, as one assessment row and its children.

        The children go in first and the assessment row last, so a row that is
        visible is a row whose citations, gaps and trace are already there. The
        other order would make a reader's join silently short for as long as the
        writer took.
        """
        # The proposal is validated against the schema before anything is
        # written, which is `concept/07`'s "agents propose; code validates and
        # writes" at the point the writing happens. The two objects each
        # validated themselves at construction; what only this pair can check is
        # that the outcome answers *this* request — the emitter, the echoed
        # versions, and every citation resolving to evidence the run was given.
        try:
            contract.check_exchange(request, outcome)
        except ContractError as invalid:
            raise AssessmentError(
                f"the outcome does not answer the request it is stored against: "
                f"{invalid}. A row written anyway would be an assessment citing "
                f"evidence nobody showed it."
            ) from invalid

        # Read before anything is written, for the reason `store`'s docstring
        # gives: a refusal has to leave the store exactly as it was, and this one
        # is a refusal — two endpoints in one ledger is this project's own bug.
        endpoint_host = _endpoint_host(disclosures)
        identifier = assessment_id(
            tenant=request.tenant,
            sensor=request.sensor,
            context_id=request.context_id,
            context_version=request.context_version,
            emitter=request.emitter,
            trigger=request.trigger,
        )
        result = outcome if isinstance(outcome, contract.AgentResult) else None
        failure = outcome if isinstance(outcome, contract.AgentFailure) else None
        package = None if result is None else result.evidence_package

        for table in CHILD_TABLES:
            self._connection.execute(
                f"DELETE FROM {table} WHERE assessment_id = %s", (identifier,)
            )
        if result is not None:
            self._citations(identifier, result)
            self._retrievals(identifier, result)
            if package is not None:
                self._patterns(identifier, package)
        self._gaps(identifier, outcome)
        self._disclosures(identifier, disclosures)

        # The nine dimensions under `helena.versions.VersionSet`'s own field
        # names. A result carries the completed set; a failure carries the eight
        # known before the call plus an optional reported identity, and
        # `model_version` stays NULL exactly where nothing answered.
        recorded = {
            dimension: getattr(outcome.versions, dimension)
            for dimension in contract.REQUEST_VERSION_DIMENSIONS
        }
        model_version = (
            result.versions.model_version if result is not None else failure.model_version
        )
        price = self._prices.for_model(request.versions.model_requested)
        cost = outcome.cost
        self._connection.execute(
            f"INSERT INTO {ASSESSMENT_TABLE} (assessment_id, tenant, sensor, host, "
            f"context_id, context_version, window_start, window_end, emitter, "
            f"triggered_by, assessed_at, classification, confidence, narrative, "
            f"failure_reason, failure_detail, model_version, model_requested, "
            f"prompt_version, schema_version, rendering_version, taxonomy_version, "
            f"enrichment_snapshot_version, normalization_snapshot_version, "
            f"policy_version, aggregation_version, budget_steps, budget_tokens, "
            f"budget_wall_clock_seconds, budget_live_queries, prompt_tokens, "
            f"completion_tokens, steps, live_queries, cache_hits, retries, "
            f"wall_clock_seconds, model_cost, model_cost_currency, "
            f"model_prices_version, endpoint_host) "
            f"VALUES ({', '.join(['%s'] * 41)})",
            (
                identifier,
                request.tenant,
                request.sensor,
                request.host,
                request.context_id,
                request.context_version,
                request.window_start,
                request.window_end,
                request.emitter,
                request.trigger,
                at,
                None if result is None else result.classification,
                None if result is None else result.confidence,
                None if package is None or not package.narrative else package.narrative,
                None if failure is None else failure.reason,
                None if failure is None else failure.detail,
                model_version,
                request.versions.model_requested,
                recorded["prompt_version"],
                recorded["schema_version"],
                recorded["rendering_version"],
                recorded["taxonomy_version"],
                recorded["enrichment_snapshot_version"],
                recorded["normalization_snapshot_version"],
                recorded["policy_version"],
                recorded["aggregation_version"],
                request.budgets.steps,
                request.budgets.tokens,
                request.budgets.wall_clock_seconds,
                request.budgets.live_queries,
                cost.prompt_tokens,
                cost.completion_tokens,
                cost.steps,
                cost.live_queries,
                cost.cache_hits,
                cost.retries,
                cost.wall_clock_seconds,
                None if price is None else price.of(cost),
                None if price is None else price.currency,
                None if price is None else self._prices.version,
                endpoint_host,
            ),
        )
        return identifier

    def _citations(self, identifier: str, result: contract.AgentResult) -> None:
        """`concept/03`'s join rows: `(assessment, evidence, role)`.

        `result.citations` and not `result.evidence_ids` — the latter includes the
        citations a `ProposedClaim` carries, and those are a proposal's evidence
        rather than the assessment's. A proposal is written by the increment that
        writes findings; folding its citations in here would make the verdict look
        as though it cited them.
        """
        for citation in result.citations:
            self._connection.execute(
                f"INSERT INTO {CITATION_TABLE} (assessment_id, evidence_id, role) "
                f"VALUES (%s, %s, %s)",
                (identifier, citation.evidence_id, citation.stance),
            )

    def _gaps(
        self,
        identifier: str,
        outcome: contract.AgentResult | contract.AgentFailure,
    ) -> None:
        """The seven kinds, one row each, in the order the outcome recorded them.

        Both outcome kinds carry gaps: `concept/04` makes the gaps list the audit
        trail that keeps `unknown` falsifiable, and a typed failure may have found
        one before it fell over.
        """
        for ordinal, gap in enumerate(outcome.gaps):
            self._connection.execute(
                f"INSERT INTO {GAP_TABLE} (assessment_id, ordinal, kind, detail) "
                f"VALUES (%s, %s, %s, %s)",
                (identifier, ordinal, gap.kind, gap.detail),
            )

    def _patterns(self, identifier: str, package: contract.EvidencePackage) -> None:
        """The evidence package's patterns, as rows rather than as an array."""
        for ordinal, pattern in enumerate(package.patterns):
            self._connection.execute(
                f"INSERT INTO {PATTERN_TABLE} (assessment_id, ordinal, pattern) "
                f"VALUES (%s, %s, %s)",
                (identifier, ordinal, pattern),
            )

    def _retrievals(self, identifier: str, result: contract.AgentResult) -> None:
        """The retrieval trace: per result, cache hit or live query, and when.

        The step's `evidence_id` and its typed failure are exclusive on the row
        because they are exclusive on the step: a query that completed produced an
        evidence row and one that did not produced a typed error and no taxonomy
        object.
        """
        for ordinal, step in enumerate(result.retrieval_trace):
            self._connection.execute(
                f"INSERT INTO {RETRIEVAL_TABLE} (assessment_id, ordinal, source_id, "
                f"entity_type, entity_value, outcome, retrieved_at, evidence_id, "
                f"failure_reason, failure_detail) "
                f"VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (
                    identifier,
                    ordinal,
                    step.source_id,
                    step.entity_type,
                    step.entity_value,
                    step.outcome,
                    step.retrieved_at,
                    step.evidence_id,
                    None if step.failure is None else step.failure.reason,
                    None if step.failure is None else step.failure.detail,
                ),
            )

    def _disclosures(
        self, identifier: str, disclosures: disclosure.Disclosures
    ) -> None:
        """What left this network during the run, in the order it left.

        `concept/07`: *"what was disclosed is recorded on the assessment — source,
        query, cache hit or live, disclosed-to, and when."* The cache-hit half is
        the retrieval trace on the same assessment: a row exists here only where
        something was **sent**, which is what makes the two counts reconcile.
        """
        for ordinal, row in enumerate(disclosures.rows):
            self._connection.execute(
                f"INSERT INTO {DISCLOSURE_TABLE} (assessment_id, ordinal, channel, "
                f"source, disclosed_to, query, query_digest, disclosed_at, "
                f"send_policy_version) "
                f"VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (
                    identifier,
                    ordinal,
                    row.channel,
                    row.source,
                    row.disclosed_to,
                    row.query,
                    row.query_digest,
                    row.disclosed_at,
                    row.send_policy_version,
                ),
            )


def _endpoint_host(disclosures: disclosure.Disclosures) -> str | None:
    """The endpoint the prompt actually went to, off the run's own ledger.

    `concept/07`: *"because endpoints are configurable per agent, cross-wiring is
    possible, and recording endpoint and model per assessment is what makes it
    detectable."* Read from the disclosure record rather than from configuration
    for exactly that reason — configuration is what would be wrong in the case
    this column exists to catch, and the ledger is the record of where bytes went.

    `None` where no prompt ever left the process, which is a run that ended on the
    clock or the token budget before its first call. That is a different fact from
    a run that reached an endpoint and failed, and a configured host written in
    its place would erase the difference.

    Two hosts in one ledger is this project's own bug — one run has one client —
    and it is loud, because a row naming one of two endpoints is worse than none.
    """
    hosts = {
        row.disclosed_to
        for row in disclosures.rows
        if row.channel == disclosure.MODEL_INFERENCE
    }
    if not hosts:
        return None
    if len(hosts) > 1:
        raise AssessmentError(
            f"the run disclosed prompts to {sorted(hosts)}; one agent run has one "
            f"endpoint, and a column naming one of two is worse than an empty one"
        )
    return hosts.pop()
