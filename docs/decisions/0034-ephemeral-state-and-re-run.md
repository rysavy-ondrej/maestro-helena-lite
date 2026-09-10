# 0034 — Ephemeral state, and re-run as the whole of recovery

**Status: accepted.** Task 44 (D6 Orchestration).
**Authority:** `concept/03-architecture.md` ("Orchestration", "The store"),
`concept/07-principles.md` (ephemeral state, agents propose / code writes),
`concept/instruction.md` §2 (one store) and §6 (the framework-convenience trap),
and `docs/decisions/0032-deterministic-routing.md` §6 and
`docs/decisions/0033-assessment-persistence.md` §2.

This increment adds `helena.orchestration.RUNS_OF_A_PASS` and the supersede step
inside `AssessmentStore.store`, and five tests. It adds **no runtime dependency,
no second store, no egress channel, no contract field and no table**.

---

## 1. There is no recovery machinery, and that is the design

`concept/03`:

> **An assessment is one function call over one versioned context snapshot.** No
> checkpointing, no durable in-flight state anywhere outside the engine; an
> interrupted run is simply re-run, because the versioned context already makes
> that correct rather than a fallback.

So this increment does not add a `resume`, a run registry, a lease, a retry queue
or a run id to look up. A run that was interrupted is recovered by calling
`helena.orchestration.assess` again over the same projection — which is the same
call the first one was — and storing the result.

The task's step list asks to *"implement re-run of an interrupted assessment
keyed by (context reference, context version, trigger)"*. What that turned out to
require was not a new entry point but the **two properties that make calling it
again well-defined**. The first already existed:
`docs/decisions/0033-assessment-persistence.md` §2 makes `assessment_id` a digest
over `(tenant, sensor, context reference, context version, emitter, trigger)`
with no outcome in it, so a re-run rewrites its own row instead of adding a second
copy. The second is §2 below, and it did not.

## 2. A pass supersedes every other run over its own snapshot

The identifier carries the trigger. That is correct — it is what says *why*
analysis ran — but it means a re-run that routed differently mints a **different**
analyst identifier from the run it replaced, and an upsert cannot remove a row it
is not addressing. Two cases, both reachable without any bug:

- The first pass escalated on triage's `suspicious` and the re-run's triage said
  `normal`, so the re-run finished. The first pass's analyst row stands, with a
  verdict, over a context version whose latest assessment did not escalate.
- The evidence branch fired on the re-run where triage's had fired before (or the
  reverse). Two analyst rows over one context version, each naming a different
  trigger, both live.

Neither is a second *assessment*: they are one assessment, made twice, and
`concept/03`'s "one function call over one versioned context snapshot" leaves no
reading under which both rows are current. So `store` now removes them:

> **A pass writes its one or two rows, then supersedes every other run over
> `(tenant, sensor, context_id, context_version)`.**

Three implementation notes, each load-bearing:

**The writes come first, the supersede second.** ADR-0033 §1 chose to upsert the
assessment row rather than delete-then-insert so that a re-run never opens a
window in which the context has no assessment at all. Superseding after the
writes keeps that: at every instant, the snapshot has at least the rows of one
completed pass.

**It addresses identifiers by key and never reads the store.** The pairings
`helena.contracts.v1.AgentRequest` accepts are three — triage/`scheduled_triage`,
analyst/`triage_suspicious`, analyst/`deterministic_signal` — so the three
identifiers one context version *could ever* hold are a pure function of the
request. `RUNS_OF_A_PASS` is that enumeration, and
`tests/test_orchestration.py::test_the_runs_of_a_pass_are_exactly_the_pairings_the_contract_accepts`
asserts it equals what the contract accepts, by construction, so a fourth pairing
cannot appear on one side alone. This is also why no read path is added — ADR-0033
deferred one deliberately, and it needs to be a versioned reader rather than a
`SELECT`.

**It collects what a query keyed on presence could not find.** `_one` writes the
child rows before the assessment row, so a run killed between them leaves
citations, gaps and disclosures whose parent row does not exist — orphans no join
would ever reach. Because the supersede addresses identifiers rather than rows it
found, it deletes those too.
`tests/test_assessments.py::test_a_re_run_collects_the_child_rows_an_interrupted_run_left`
produces that residue with a connection that stops mid-write the way a killed
process does, and asserts the re-run collects it.

**What is not claimed:** that a re-run reproduces the first run's *verdict*. The
model is not deterministic and this increment does not make it so. What is
well-defined is the record: after the re-run, what the store holds for that
context version is what the last completed pass produced, and nothing else.

## 3. Working memory is the call, and it is asserted by execution

`concept/07` lists **Ephemeral state** as a principle: *"In-process and framework
state is working memory for one assessment, never the durable record."* Three
tests hold it, and none of them reads a comment:

| Test | What it executes |
| --- | --- |
| `test_the_package_writes_no_file_anywhere` | Every module in `helena/` through the AST: no `open`, no `Path.write_*`/`mkdir`/`touch`, no `os` write call, no `tempfile` or `shutil`. `helena.observability` writes to a **stream its caller opened**, which is why `.write` is not on the list |
| `test_a_run_leaves_nothing_behind_in_any_helena_module` | A whole assessment — both agents, both ledgers, the budget guard, the analyst loop — between two snapshots of every `helena.*` module's `__dict__`, asserting no name was gained, lost or rebound. The first run is a warm-up, because the five frozen-version loaders import their module on first use and an import is not state |
| `test_a_killed_run_leaves_nothing_on_disk` | A child process running one assessment against an endpoint that never answers, `SIGKILL`ed inside its first model call, with `HOME`, `TMPDIR` and the working directory pointed at three empty directories. They are still empty, and the exit status is asserted to be the signal so that nothing had the chance to tidy up |

The killed-run test is the one worth keeping honest about: it proves the property
for *this* process, which currently has no framework in it. That is exactly why
§4 matters.

## 4. The rule for the next framework convenience

`concept/03` says the ephemeral-state rule *"binds harder if a framework is
adopted, because such libraries make file-backed agent memory the convenient
default — and an agent writing notes to a persistent backend has created a second
store of uncited free text, which is simultaneously a single-store violation and
a memory-poisoning channel."* `concept/instruction.md` §6 lists the trap as
*"adding a framework convenience because it is one flag away"*.

So: **a convenience is checked against three rules before it is switched on, not
after.** The three questions, in the order they eliminate things fastest:

1. **Single store.** Where does the state go when the process dies? If the answer
   is a file, a socket to another server, a vendor's service, or "the framework
   handles it", it is a second store. A checkpointer, a persistent scratchpad, a
   virtual filesystem, a vector memory and a run registry are all this answer.
   The compatible form of every one of them is typed rows in the engine, written
   by project code.
2. **Agents propose; code validates and writes.** Does the convenience let
   something a model produced reach a durable record without passing a schema?
   Auto-persisted memory, "save this note", tool results written straight to a
   store and free-text summaries of retrieved content are all this. A memory
   entry that is a sentence is a memory-poisoning channel; `concept/07` requires
   structured claims with provenance, confidence and expiry.
3. **Ephemeral state.** Does it survive the function call? If it does, it is
   working memory that became a durable record, and the versioned-context
   argument for "just re-run it" stops holding — because the second run would now
   inherit the first run's leftovers instead of starting from the snapshot.

A convenience that fails any one of them is an escalation
(`concept/instruction.md` §3), not a flag. **Being one flag away is not an
argument** — it is the reason the trap has a name.

Two things this is *not* an argument against, so the rule stays usable: bounded
in-process mutable objects that die with the call (`helena.budgets.RunBudget` and
`helena.disclosure.Disclosures` are both, deliberately — ADR-0026 §3 and ADR-0027),
and re-reading the engine, which is the store.

## 5. What would reverse this

**A measured need for resumability**, on the terms ADR-0032 §6 already set: the
observed rate of interrupted runs times the quota a repeat burns. Nothing has
been measured, and this increment does not change that — what it changes is that
the cost of a re-run is now *only* the repeated work, with no leftover rows to
reconcile. The compatible form of a checkpoint remains typed rows in the single
store keyed by `(context reference, context version, trigger)`, never a
framework's backend.

**A pass that legitimately writes more than one analyst row** — a second analyst
run over the same snapshot under the same trigger, or a third agent. The first
would need something in the identifier that distinguishes them, and that is a
decision about what an assessment *is*, not a fix. The second is a new pairing,
and `RUNS_OF_A_PASS`'s test is where it would surface.

**A retention or pruning policy.** `concept/08` still lists the retention horizon
as open. Superseding is not pruning: it removes the rows of a run that was
replaced, and it bounds nothing.

## 6. What is not claimed

- **No verdict has been evaluated against a label.** Unchanged, and unrelated.
- **The killed-run guarantee is about this package**, which imports no framework.
  It is a property of what is in the tree, re-asserted every run of the suite —
  not a proof about any library that might later be added.
- **Nothing replays a stored assessment.** Task 45's, and it still needs a
  versioned reader (ADR-0033) and the escalation record that no task owns.
- **A re-run is not idempotent in its verdict**, only in its record. See §2.
