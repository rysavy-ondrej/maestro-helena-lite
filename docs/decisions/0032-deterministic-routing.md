# 0032 — Deterministic routing, the escalation branch, and what would reverse it

**Status: accepted.** Task 42 (D6 Orchestration).
**Authority:** `concept/03-architecture.md` ("Orchestration", "The rules that
bound processing", "The store"), `concept/04-the-two-agents.md` ("What
escalates", "One contract for both"), `concept/07-principles.md`,
`concept/instruction.md` §1, §2 and §3, and
`docs/decisions/0023-deterministic-escalation.md`.

This increment adds `helena.orchestration.route`, `analyst_request` and `assess`,
and the `Assessment` they produce. It adds **no runtime dependency, no store, no
egress channel, no SQL, no config key and no contract field** — the trigger it
sets was already in `helena.contracts.v1.AgentRequest` and had no writer until
now.

---

## 1. The router is `concept/03`'s pseudocode, transcribed

```text
if evidence escalates independently (tier A, or tier B above threshold):
    run_analyst(trigger="deterministic_signal")   # independent of triage
elif triage.root == "suspicious":
    run_analyst(trigger="triage_suspicious")
else:
    finish()
```

`route(escalation, outcome)` is three statements and returns the trigger or
`None`. It is a **pure function of two already-computed values**, which is what
makes the routing table enumerable: three triage outcomes (the two roots the
contract closes triage over, and a typed failure) times two evidence states is
six rows, and `tests/test_orchestration.py::test_the_router_is_the_three_branches_concept_03_writes`
asserts every one of them.

Two things it deliberately does not do. It does not re-read the verdict — the
triage half is `helena.triage.escalates`, which already refuses to read anything
off a typed failure and already tests *not `normal`* rather than *is
`suspicious`* — and it reads exactly one attribute off the escalation, the
boolean. Both are asserted off `route`'s own AST, because the way this drifts is
a later increment adding "and the confidence was above x" to one of the branches,
which would be a second composition rule under one `policy_version`.

## 2. The evidence branch is first, and the order is about the record

Both branches reach the same agent, so swapping them changes nothing about *what
runs*. What it changes is the stored trigger for a context that escalated on its
own **and** whose triage also said `suspicious`: with the evidence branch first
that context is recorded as the escalation the evidence required, and with it
second it would be recorded as the model's opinion. `concept/04` makes the
deterministic input "the one that matters", so it is also the one that gets to
name the run.

## 3. Independence is enforced three ways, and one of them is a stream

`concept/instruction.md` §2: *"Deterministic escalation is independent of triage.
A `normal` from a model may not suppress a high-confidence match."*

| Where | What it establishes |
| --- | --- |
| `helena.policy.v1.escalate`'s signature and AST (ADR-0023 §2, task 33) | there is no parameter a verdict could arrive through |
| `assess`'s log records | the escalation is written to the channel **before** the first `agents.model.call` record — order read out of one shared stream rather than asserted about the source |
| `test_model_output_cannot_change_which_agent_runs_next` | the same escalating context triaged four ways (`normal`, `suspicious`, an unparseable answer, an endpoint that never answers) routes identically, and `test_the_escalation_is_identical_whatever_triage_said` compares the whole `Escalation` across three of them |

The second is the one worth keeping. "Computed before" is an ordering claim, and
an ordering claim asserted by reading the source is a claim about the source; the
log stream is the execution.

**A triage failure routes exactly as a `normal` does.** `concept/04`'s *"a triage
failure does not escalate"*, and it is safe only because the evidence branch does
not care whether triage ran — which ADR-0021 §6 recorded as the one genuinely
unsafe thing the triage stage shipped with, and which stops being true here
rather than in task 33: task 33 built the evaluator, and this is the first code
that calls it.

## 4. The trigger travels in the request, and four fields move with it

`analyst_request` derives the escalated run's request from the triage request
that escalated it. Four fields change — emitter, trigger, budgets, prompt version
— and the context reference, its version and the rendering are the **same
objects**. That is the point of deriving rather than rebuilding: the two records
join, and a replay of either is a replay of one snapshot.

It is rebuilt through the constructor rather than by `model_copy(update=...)`,
which does not re-validate in Pydantic v2. A derived request that skipped
validation would be the one request in the system the contract never saw, and the
checks it would skip are exactly the ones about this derivation: the pairing of
the emitter and the trigger, and the refusal of a triage budget that permits a
lookup.

**One measured surprise worth recording.** The two prompt versions are *both*
`v1`, because a prompt version is per-package and the two packages each start at
one — so today the derived request's `versions` compares **equal** to the triage
request's. What a stored row tells the two prompts apart by is the emitter, not
the prompt version alone. The test asserts a subset rather than an equality for
that reason, and says so.

## 5. Two ledgers, not one

`helena.disclosure.Disclosures` records the emitter it is the ledger of, so one
ledger shared across both stages would file the analyst's disclosures under
triage. `assess` builds one per run, from that run's own request, and returns
both on the `Assessment`. The budget ledgers stay where they are — inside each
runner, leaving on `AgentResult.cost` — for the asymmetry ADR-0026 records.

## 6. What would reverse this, and what would not

The task asks for this explicitly, and the honest answer has three entries and a
long list of things that are not on it.

**A measured need for resumability.** Today an interrupted assessment is re-run:
`concept/03` makes that correct rather than a fallback, because the context is
versioned and the same snapshot produces the same input. That stops being enough
when a *single* run becomes expensive enough that repeating it is a real cost —
a long analyst tool loop against a provider with a hard daily quota is the shape
of it. The number that would decide it is the one nobody has: the observed rate
of interrupted runs times the quota they burn. **Note what would *not* follow.**
Resumability would need a checkpoint, and `concept/instruction.md` §2 forbids a
checkpoint store; the compatible version is a checkpoint written as typed rows in
the single store, keyed by `(context reference, context version, trigger)`, which
is task 44's key and not a framework's. Adopting a graph framework *for its
checkpointer* would be adopting its backend, which is a second store.

**Human-in-the-loop interrupts.** The first version has no HTTP surface and no UI
by decision (`concept/03`, "The interfaces"), so there is nothing to interrupt
into. The deferred Investigation Agent is where a human enters, and it is
analyst-initiated and out of band — it appends a session to a finding rather than
suspending a pipeline run. An interrupt inside `assess` would need a durable
in-flight state for the run to wait in, which is the same forbidden thing as
above, plus a new surface (`concept/instruction.md` §3).

**A third agent whose routing is not a branch.** Two agents and one condition
each is an `if`. What would break it is not a *third agent* — a third branch is
still an `if` — but a third agent whose selection depends on something that is
not a value the code already has: a routing decision that is itself a judgement,
or a set of agents whose composition varies per context. That is the point where
a router becomes a planner, and the concept's answer is that a planner is a model
output determining control flow. If that is ever wanted, it is a change to
`concept/03`'s "the rules that bound processing", not an implementation choice.

**What would not reverse it:** the number of branches growing, the wiring getting
long (`assess` takes twelve keyword arguments and every one of them is a value a
deployment loaded once), wanting a diagram, wanting retries (bounded retries are
`helena.agents`'), wanting parallelism across contexts (an assessment is one
function call; running many is the caller's loop), or a framework offering
tracing (hosted tracing is a second egress channel, refused by
`tests/test_dependency_boundary.py`).

`tests/test_orchestration.py` holds the absence as three tests: no orchestration
framework or workflow engine declared or imported, no checkpoint store —
including the standard library's own file-backed ones, because a checkpoint
written with `shelve` is a second store exactly as one written with `redis` — and
none of them even importable from the environment, on the rule
`tests/test_dependency_boundary.py` applies to hosted tracing.

## 7. What is not claimed

- **Nothing is stored.** `Assessment` is in-process and the shape task 43 turns
  into typed rows; there is no assessment table, no citation join, no gaps table
  and no disclosure row. Every claim here about replay is a claim about a shape
  being ready.
- **Orchestration does not yet render agent input**, which `concept/03` also puts
  in this component. The caller builds the triage request, because nothing in the
  tree reads a context's feed-snapshot, normalization and aggregation versions
  out of the store, and a request built here would have to invent three recorded
  versions. `helena.rendering` is the versioned half and the tests here use it
  against a real projection; the assembly is D6's remaining work.
- **No verdict has been evaluated against a label.** The routing is exercised
  over a real capture, a real feed load and the committed thresholds; whether the
  threshold over- or under-alerts is ADR-0023 §7's open question and there is no
  corpus.
- **Re-run recovery is task 44.** What holds today is the half this module can
  claim: `helena.orchestration` has no mutable module-level object at all, so
  nothing of one context's run survives into the next.
