# 0033 — Assessment persistence: one row per agent run, citations as join rows

**Status: accepted.** Task 43 (D6 Orchestration).
**Authority:** `concept/03-architecture.md` ("Orchestration", "The store"),
`concept/02-concepts-and-taxonomy.md` (citation, evidence package, gap, typed
failure), `concept/06-technology.md` (derived monetary cost),
`concept/07-principles.md` (versions on every assessment, privacy and disclosure,
untrusted input, observability), `concept/instruction.md` §1 and §2, and
`docs/decisions/0017-the-agent-contract.md`.

This increment adds `sql/migrations/0018_assessments.sql` (six tables),
`helena.orchestration.AssessmentStore` and `assessment_id`, and
`helena.budgets.model_prices` with the `[model_prices]` table in
`config/policy.toml`. It adds **no runtime dependency, no second store, no egress
channel and no contract field**.

---

## 1. A row is one agent run, not one pass through the router

`concept/03` lists the typed columns an assessment carries: *"host, tenant,
context reference, window bounds, verdict and classification, confidence,
timestamps, model / prompt / contract / rendering versions, budgets consumed,
latency, tokens, cost, and cache-hit versus live-query counts."*

Every one of those is a property of **one agent run**. A pass through
`helena.orchestration.assess` reaches one or two agents with different models,
different prompts, different budgets, different costs and different verdicts, so
a row per pass would carry two of each or lose one. It is also how the same note
lists what the store holds: *"triage decisions, analyst assessments and evidence
packages"* — two kinds of record, not one.

So a finished pass writes one row and an escalated pass writes two, sharing
`(tenant, sensor, context_id, context_version)`. That tuple is what D7 joins on
for *"a context that was escalated is emitted once, carrying the analyst's
verdict and the triage decision that led to it."*

## 2. The identifier is the context version and the run, and nothing else

`assessment_id` is a sha256 over tenant, sensor, context reference, context
version, emitter and trigger — the construction `helena.enrichment.evidence_id`
uses. `concept/03`: *"an interrupted run is simply re-run, because the versioned
context already makes that correct rather than a fallback."* A RisingWave INSERT
onto an existing primary key is a silent upsert, so a re-run has to mint the
identifier the first run did or it doubles the row.

**The outcome is not in the digest**, deliberately: two runs over one context
version are the same assessment made twice, and a verdict in the identifier would
leave the first run's row standing beside the second as a second live opinion.

An upsert cannot remove a child row the second run no longer produces, so the
writer **deletes the run's children before it writes them**. The children go in
first and the assessment row last, so a visible assessment always has its whole
citation set.

## 3. There is no `verdict` column

The step list asked for "verdict and classification". The verdict is the root of
the classification; `helena.taxonomy` already refuses a path whose root is not its
first segment, so a stored column would be a second copy of a fact that cannot
disagree in the model and can in a table. This is the reading
`helena.enrichment.EnrichmentEvidence.verdict`,
`helena.contracts.v1.AgentResult.root` and
`sql/migrations/0017_analyst_lookup_cache.sql` already took. In SQL it is
`split_part(classification, '.', 1)`, asserted by execution in
`tests/test_assessments.py`.

## 4. The budgets granted are four numbers, not a version pointer

Task 36 deferred a `budgets_version` key to this increment. It is **not** added.
The row stores the four granted dimensions themselves — `budget_steps`,
`budget_tokens`, `budget_wall_clock_seconds`, `budget_live_queries` — because
those are what bounded the run, and a version string would be resolvable only
while `config/policy.toml` still held the entry it named. `concept/07`'s recorded
version set is nine dimensions and a budget version is not among them; adding a
tenth would be a change to `helena.versions.VersionSet`, which every stored row
carries.

`thresholds_version` is a different case and is **not** discharged here — see §7.

## 5. The derived cost, and why the price table ships empty

`concept/06`: *"monetary model cost is **derived** and recorded per assessment,
not separately capped — capping it would double-count the enforced budget
dimensions."* Task 36 escalated the absence of a price table and named this
increment as its owner.

`config/policy.toml` now has `[model_prices]` and `model_prices_version`, and
`helena.budgets.model_prices()` reads them. **The table has no entries**, because
a model's price is an external fact and this repository does not know what the
configured endpoint charges — `concept/instruction.md` §0's *check the artifact,
not the page*. A model with no entry stores NULL in `model_cost`,
`model_cost_currency` and `model_prices_version`.

NULL means **not priced**. It does not mean free, and reading it as free would be
the same collapse §2 of the instructions forbids between `missing` and
`no_match`. The alternative — a plausible rate — is the invented external fact
this project has been burned by repeatedly.

This is the one table in `config/policy.toml` whose absent entry is not a startup
error, and the asymmetry is deliberate: a threshold or a budget nobody chose is a
silent default that changes what the system *does*; a price nobody knows changes
only whether a column can be filled in. Half a price — a rate with no currency —
is still refused.

## 6. No free-text agent note is persisted as a record

`concept/07`: *"memory entries ... must be **structured claims with provenance,
confidence and expiry — never free-text summaries of retrieved content**. A
free-text note is precisely the persistence channel by which attacker-influenced
text reaches a future session's context."*

Three properties, each a different way that channel could open, and all three are
tests rather than assertions in prose:

1. **No table or column in the whole schema is named like a note.** A regex over
   `information_schema.columns`. `observation` is deliberately not in it — it is
   this project's word for *an entity was seen in traffic* — and the loose
   "observations" field the agent contract refuses is refused by `extra="forbid"`
   and by `tests/test_contracts.py`.
2. **The free-text columns are a declared six**, and every other string value
   stored by a real run is a closed-vocabulary token, an identifier, a digest or
   a version. Demonstrated by storing a run with every string field filled and
   checking each stored value.
3. **Nothing that builds a prompt can read a stored assessment.** The three
   modules `tests/test_untrusted.py` names as the only ones that construct a
   `helena.agents.Message` are read as ASTs and must not name an assessment table
   or the store. This is the property that matters: a bounded narrative that
   cannot be read back is not a memory-poisoning channel.

The narrative is `concept/03`'s own text column; the patterns are the rest of
`concept/02`'s evidence package and are rows rather than an array.

## 7. What is not stored, and who owes it

- **The escalation.** `Assessment.escalation` is computed on every pass and no
  table holds it. It is recomputable from the projection under the recorded
  `policy_version`, but its `thresholds_version` is on the `Escalation` and not on
  the request, so it reaches no row — which means a replay reproduces the routing
  only for a deployment whose thresholds have not moved. **No remaining task lists
  it.** Task 45 (assessment replay) is the first thing that cannot proceed without
  it, and the shape it needs is a typed row per pass with the candidates as join
  rows.
- **Proposed claims.** `AgentResult.proposed_claims` is written nowhere: where a
  proposal is written is the findings table, and there is none. Its citations are
  deliberately not folded into the assessment's citation rows, or the verdict
  would look as though it cited them.
- **The composition rule's decision.** `Analysis.decision` — what the cited
  evidence permits the verdict to be read as — is the same shape and the same
  missing table.
- **Refused retrievals.** `helena.contracts.v1.RETRIEVAL_OUTCOMES` has no value
  for a refusal, and task 41 recorded that turning one into a `Gap` is a decision
  somebody should make deliberately rather than discover. The trace table holds
  `AgentResult.retrieval_trace` and nothing else.
- **Pruning.** Nothing is evicted and nothing bounds the growth, exactly as
  `sql/migrations/0017` says of the evidence store.
  `concept/08-open-questions.md` still lists the retention horizon as open.

## 8. What would reverse this

- **A row per pass** becomes right if the two agents ever stop differing in model,
  budget, prompt and cost — that is, if the asymmetry `concept/04` calls
  deliberate is removed.
- **A verdict column** becomes right if something has to filter on the root at a
  volume where `split_part` is measurably the cost, and the measurement is what
  would justify it rather than the convenience.
- **The delete-before-insert** becomes wrong if re-run recovery (task 44) decides
  a completed prior run must not be rewritten at all. That is a decision about
  idempotence, and it belongs to that increment.

## 9. What is not claimed

Nothing has been replayed from a stored assessment; task 45 is the first thing
that would. No stored verdict has been compared against a label, because no
labelled corpus exists. The monetary column has never held a figure in this
repository, because nothing here knows a price — what is demonstrated is the
derivation, against a price table a test wrote.
