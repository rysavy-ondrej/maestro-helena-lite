# 0045 — What "the analyst is unsure" means, and who decides it

Status: accepted — 2026-09-12 (task 55, D9 Governance). Settles a question
`concept/05` says *"must be settled before the tool exists, because it decides
where the tool sits rather than how it is written."* No tool is built here; what
is recorded is which of the two answers the project took, and the machinery that
already implements it.

## The question this closes

`concept/08-open-questions.md`, blocking, the analyst and the provider tool:
**what "the analyst is unsure" means and who decides it.** `concept/05` gives the
reason it matters, and the reason is a scarce resource rather than a taxonomy
preference:

> A model that asks for the tool controls a scarce shared resource, and one
> verbose run can spend the day's quota for every other host; deterministic code
> deciding is inspectable and rate-limitable, at the cost of inferring
> uncertainty from outside. **Deterministic routing points at the second.**

The tool in question is the deferred multi-engine reputation lookup, whose free
tier is *"a few hundred lookups per day, shared across every host the pipeline
assesses"* — so routine use is use exhausted before noon.

## The answer, in three parts

**1. "Unsure" is not one thing, and the two senses have different deciders.**

| Sense | Who decides | Where |
| --- | --- | --- |
| *this context was **unassessable*** — a verdict | the model proposes `unknown`; **code validates it and can refuse it** | [0029](0029-the-analyst-runner.md), `helena.analyst` |
| *this run should spend a scarce shared quota* — a routing decision | **deterministic code only.** A model may not request it | this record, `helena.orchestration` |

Conflating them is what makes the question look unanswerable. A verdict is a
claim about a context and the agent is the right thing to make it; spending a
shared daily budget is a side effect, and `concept/instruction.md` §2 already
says an agent never performs one.

**2. `unknown` is validated, not asserted.** `concept/02` makes `unknown`
*"unassessable"* and *"deliberately distinct from `suspicious`, which means
analysis ran and could not settle it."* So the runner refuses an `unknown` whose
`gaps` are empty, and refuses one whose gaps name only things the run *got* —
`no_match` and `stale` are answers, not gaps. An `unknown` must name something
the run could not **see**: `missing`, `in_flight`, `failed`, `truncated` or
`budget_exhausted`. A refused `unknown` is recorded as a typed failure with no
verdict, never downgraded into a verdict nobody made.

This was measured twice rather than assumed: the real configured endpoint
answered `unknown` with no gaps at all, twice running, and the rule caught it
([0029](0029-the-analyst-runner.md) §what this changed).

**3. The routing answer is the deterministic one, and it is already the shape of
the code.** `helena.orchestration` routes on the triage *verdict*, by an `if`
([0032](0032-deterministic-routing.md)); `helena.policy` decides what a set of
claims supports; `RunBudget` is created once per run and charged at the boundary,
with no default and no negotiation ([0026](0026-the-budget-guard.md)). A
last-resort provider therefore enters as **a routing branch on stored state** —
the analyst run's recorded gaps, exhausted dimensions and verdict — and not as a
tool in the model's tool list.

The cost of that choice is stated in `concept/05` and is accepted here: code
infers uncertainty from outside, so it will sometimes spend a lookup on a run the
model would not have asked for, and sometimes withhold one it would. That is the
trade for inspectable and rate-limitable.

## What this does not settle, and is the re-entry condition

**There is no cross-run ledger, and a daily shared quota needs one.** `RunBudget`
is per run, in-process and thrown away with the run — which is exactly what
`concept/07`'s ephemeral-state rule requires. A "few hundred per day across every
host" limit is a fact about *all* runs, so enforcing it means a count that
outlives a run. **The one place that may live is the engine**, as typed rows, like
the emission counts ([0037](0037-at-least-once-emission.md)); a file, a Redis, or
a module-level counter is the second store `concept/instruction.md` §2 forbids.

So the deferred tool's re-entry test has two halves, both in
[`docs/deferred.md`](../deferred.md): a measured need for a second opinion the
tables and the primary provider cannot supply, **and** an engine-side daily
ledger. Neither exists. The credential does
([0004](0004-configuration-variables.md) records why it is required anyway), and
its quota is deliberately unspent.
