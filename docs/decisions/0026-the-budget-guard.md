# 0026 — The budget guard: one ledger per run, charged at the boundary

**Status: accepted.** Task 36 (D5 Tools).
**Authority:** `concept/07-principles.md` ("Budgets", "Partial results and
failure", and the *must never happen* table),
`concept/03-architecture.md` (the component table, "The store"),
`concept/05-threat-intelligence.md` ("Credentials, rate limits and terms", the
MCP-tool rules), `concept/06-technology.md` ("Cost, measured"),
`concept/04-the-two-agents.md` (the asymmetry, `unknown`),
`concept/instruction.md` §1, §2 and §3, and
`docs/decisions/0020-the-model-client.md` §6.

This increment adds `src/helena/budgets.py`, a `[budgets]` and a `[rate_limits]`
table to `config/policy.toml`, and a required `budget` argument to
`helena.agents.assess` and `helena.tools.ProviderTool.lookup`. It adds **no
runtime dependency, no store, no egress channel, no source and no contract
field** — `helena.contracts.v1.Budgets` and `Cost` already carried the shape, from
task 26.

---

## 1. Four dimensions, one ledger, and the reason it is not four counters

`concept/07` gives the four dimensions and maps each to a real limit. What it does
**not** say is where the count lives, and the answer decides whether the wall
clock means anything:

> **The wall-clock budget and the live-query budget have to be set against each
> other**, not independently. … At a few lookups per minute, an analyst run
> checking six indicators spends over a minute waiting on the rate limit alone,
> before any inference.

A budget checked inside one model call cannot see the minute a lookup spent, so
`RunBudget` is created **once per agent run** and charged by everything in it. Two
ledgers would be two copies of a fact that can drift (`concept/instruction.md`
§2), and the drift is in the dangerous direction: an analyst turn that started its
own clock would be handed the full wall-clock budget again after every lookup,
which is the unbounded run the dimension exists to bound.

That is why `assess` and `lookup` both take it, keyword-only and with **no
default**. A default would be the silent configuration `concept/instruction.md` §6
names — invisible in exactly the deployment where the budget mattered. `assess`
also refuses a ledger whose limits are not the request's, because a run enforced
against numbers it was not given is a budget nobody set.

The ledger is mutable, in-process and thrown away with the run, which is what
`concept/07`'s "ephemeral state" requires: *working memory for one assessment,
never the durable record.* What is durable is the `Cost` that `cost()` returns.

## 2. Spent is not the same as truncated

`RunBudget.exhausted` records the dimensions the run **asked for more of and was
refused**, and deliberately not the ones whose remainder reached zero. The
difference is the whole of `concept/07`'s degrade rule:

| The run | Exhausted? |
| --- | --- |
| spent its last token on the answer it then returned | **no** — it finished |
| wanted another attempt, another lookup or another second and could not have one | **yes** — it was truncated |

Collapsing the two would degrade a perfectly good verdict to `unknown` for the
crime of using its budget efficiently, and `unknown` means *unassessable*.
`concept/07` refuses to collapse unassessable into assessed
("collapsing them inflates the escalation rate and corrupts evaluation labels"),
and this is the same collapse arriving from the accounting side.

So `record_tokens` reports spending and marks nothing; `check_tokens`,
`charge_step`, `charge_live_query` and `check_clock` are the guards, and each
records its own dimension when it refuses.

## 3. Enforced at the tool boundary, which means there is nothing to reason around

`concept/07` and `concept/05` both put the enforcement at the tool boundary "so an
agent cannot reason its way around them". Mechanically, in
`ProviderTool.lookup`:

| Charged | When | Why there |
| --- | --- | --- |
| a step | before anything else, on **every** accepted call, including one then refused as malformed | that is what bounds the loop; otherwise an unbounded loop can be bought with bad arguments |
| the wall clock | with the step, before the cache is read | the run is over; serving it a stored record would be work nobody can use |
| a live query | **after** the cache read | a hit sends nothing and discloses nothing (ADR-0025), so charging the quota first would spend it on a call that never left the process |
| tokens | never | a tool call spends none. `assess` charges those |

A spent dimension is a `ToolRefusal` carrying `budget_exhausted` — the same string
as the gap kind, imported rather than respelled. It is **not** a `QueryFailure`:
nothing was queried, so there is no provider to attribute an outage to, and a
refusal recorded as a provider failure would make the provider-failure count a
number nobody can act on. That is the same argument the two existing refusal
reasons carry, and `REFUSAL_REASONS` now has three.

**One thing this deliberately does not do.** When the live-query budget is spent
and the cache holds an *expired* record, the call is **refused** rather than
served the expired record explicitly `stale`. The stale fallback exists because
the provider did not answer and the record is then the best available evidence
(ADR-0025 §4); a run that is out of quota asked nothing, and letting a budget
decide what the evidence is would make two runs differing only in *budget* differ
in what they cite. If a later increment wants the other behaviour it should record
it as a change of this decision, not as an optimisation.

## 4. The values are policy, in the file the thresholds are already in

`concept/07`: *"budget values are **policy, not constants in a branch**; the same
applies to confidence thresholds."* One sentence, two things, so they are two
tables of one versioned policy file rather than two files. `helena.policy` owns
the path and now names both key sets, so neither loader refuses to start on a file
the other requires; each still refuses a key **nothing** reads.

`[budgets.triage]` states neither `steps` nor `retrieval_seconds`, and the loader
refuses a file that gives it either. `concept/04` gives triage "no tools at all"
and `AgentRequest` already refuses a triage request that budgets a step; a key
here that could be set to 1 would be a lookup nobody has to justify.

**There is no `budgets_version` yet, and that is deliberate.**
`thresholds_version` exists because an `Escalation` records it. Nothing records a
budget version — no assessment row exists (task 43) and `Budgets` has no version
field — so a key here would be a version nothing reads, which is what the rest of
this file refuses. The increment that stores an assessment adds it with the column
that reads it.

## 5. The live-query budget is derived and may not be written down

The two numbers `concept/07` requires to be set against each other are set against
each other by construction:

    live_queries = floor(retrieval_seconds x slowest [rate_limits] entry / 60)

and the loader refuses four ways the pair can contradict itself: a retrieval
allowance that does not fit inside the wall clock, one that buys no query at the
slowest configured rate, a step budget too small to reach the live queries it was
given, and an emitter with tools and no rate limit to derive from.

The **slowest** configured rate is the one that counts, because a run's queries
may all go to one source and the budget that survives is the one derived from the
source that answers slowest.

`[rate_limits]` is **the rate the tool layer holds itself to, and not a measured
provider limit.** `concept/05` makes rate limits "policy the tool layer enforces";
abuse.ch publishes fair-use terms rather than a number this project has verified,
and measuring one would mean deliberately exceeding it against a live service.
`concept/07`'s own "a few lookups per minute" is the shape 4 comes from, the file
says so, and it must be lowered the moment a provider states less.

**Nothing paces calls to that rate.** The rate is read for the derivation and no
throttle exists; the adapter that speaks to a live provider is what has to sleep,
and the wall-clock budget is what catches it when it does — provider waits are on
the same clock as the model calls, which §1 is about.

## 6. Degrade, in one direction only

`concept/07`: *budget exhausted mid-analysis → "a verdict on what was gathered,
with exhaustion and gaps explicit — but **never `normal`**; it degrades to
`unknown`"*, and in the *must never happen* table: *"a budget-truncated analyst
run returns `normal` — it established the absence of nothing."*

`degraded(outcome, budget)` is the one place code rewrites a classification:

| The run | What comes back |
| --- | --- |
| nothing refused | the outcome, unchanged and not even copied |
| truncated, verdict `normal` | `unknown`, with the gap |
| truncated, any other verdict | that verdict, with the gap |
| truncated, a typed failure | the failure, with the gap. There is no verdict to degrade |

Three details are decisions rather than mechanics:

- **It re-validates rather than `model_copy`ing.** `model_copy` skips
  `model_post_init`, and the rule that a `budget_exhausted` gap may not sit on a
  `normal` root lives there. A degrade that bypassed validation could produce
  exactly the outcome the concept forbids, which is why the test asserts the rule
  from both sides.
- **An empty evidence package is attached** when a `normal` analyst verdict
  degrades, because `concept/04` exempts only `normal` from carrying one. An empty
  package says the analyst named no patterns, which is true of the verdict it gave.
- **A truncated triage `normal` raises.** Triage has no `unknown` root:
  `concept/07` makes a context triage could not assess a *typed failure, not a
  third label*, and `assess` already produces that failure with this gap on it. So
  there is nothing to degrade a triage verdict *to*, and letting it stand would be
  the forbidden outcome under another emitter.

## 7. Monetary cost: derived, and the price table does not exist

Task 36's steps ask for "budgets consumed, latency, tokens and **derived monetary
cost** on the assessment". Three of the four are on `Cost` and are now measured by
the ledger. The fourth is **not built**, and this is the conflict recorded rather
than resolved:

- `concept/06`: monetary cost is "**derived** and recorded per assessment, not
  separately capped — capping it would double-count the enforced budget
  dimensions". Nothing here caps it, so that half holds.
- Deriving it needs a price table per model, and **no price table exists in this
  repository**. A currency figure computed from a guessed rate would be an
  invented external fact, which is the class of error this project has corrected
  three times (`concept/instruction.md` §0: check the artifact, not the page).
- A monetary field on `Cost` would also be a change to the **agent contract**,
  which `concept/instruction.md` §3 makes an escalation.

`Cost` already carries the two token counts the derivation consumes, and
"recorded per assessment" is a stored column. Both point at the same increment:
the one that stores an assessment (task 43) adds the column, the price table it
reads, and the version of that table it records. Until then the claim this
increment makes is the narrower true one — the tokens are measured; the money is
not.

## 8. Why `helena/budgets.py` and not `helena/orchestration.py`

`concept/03`'s component table has a row for **policy and budget guards**, and
`tests/test_package_layout.py` read that row as "the deterministic code in
`orchestration`". It cannot be, for a mechanical reason: the ledger is charged by
`helena.agents` **and** by `helena.tools`, and `orchestration` is the module that
will import both — so a ledger defined there is an import cycle. The policy half
of the same row is already outside `orchestration` too, in `helena.policy`, for a
different reason (a frozen rule version needs a versioned package).

So the row is two modules and `orchestration` keeps the rest of what
`concept/03` gives it: routing, output validation, persistence and replay. The
layout test's own comment now says this, because a rule enforced by a test whose
comment argues the opposite is a rule the next session will re-litigate.

## 9. What this increment does not demonstrate

- **No agent has ever been budgeted through a tool loop**, because no analyst tool
  loop exists (task 39). Every dimension is enforced and tested at the boundary it
  is enforced at; nothing has yet driven all four in one run of a real agent.
- **Nothing stores a `Cost`**, so "budgets consumed are recorded on the
  assessment" is a shape that is ready, not a property that holds.
- **Every number in `config/policy.toml`'s budget tables is a candidate.** No
  per-run token consumption has been measured, no provider latency distribution
  exists, and no provider rate limit has been verified. `concept/08` still lists
  the numeric budget values as open, and the file says so in the place a
  deployment would edit them.
