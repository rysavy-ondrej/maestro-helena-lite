# 07 — Principles

The rules an implementation may not break. Most of them are one idea applied at a
different seam: **absence of evidence is never presented as evidence of absence.**

## The agent boundary

| Rule | Statement |
| --- | --- |
| **Code owns side effects** | Deterministic project code owns schema validation, tenant isolation, budgets, escalation, persistence and **all side effects**. Agents may not change policy or perform remediation |
| **Deterministic orchestration** | No agent selects, invokes, sequences or terminates another, and **no model output determines control flow** |
| **Independent escalation** | Deterministic signals are independent escalation inputs. **A triage classification of `normal` cannot suppress a high-confidence match** |
| **Bounded retrieval** | Retrieval available to agents is read-only, tenant-scoped and budget-limited |
| **No direct provider access** | External providers are reached only through the approved tool layer. **Agents never hold keys or call providers directly** |
| **Agents propose; code writes** | An agent's claim about infrastructure is a proposal, validated against a schema and written by deterministic code |
| **Typed boundaries** | Nothing crosses an agent boundary except validated typed fields |
| **Ephemeral state** | In-process and framework state is working memory for one assessment, never the durable record |

## Partial results and failure

| Situation | Required behaviour |
| --- | --- |
| Feed not refreshed | `stale`, never `no_match` |
| Feed load failed | `failed` or `missing`, never a silently empty table |
| Lookup completed, indicator absent | `no_match` — a lookup outcome, never a statement of safety |
| Provider query failed | A typed error, no classification |
| Enrichment missing / stale / in-flight / failed | Each distinguishable in the enriched context **and** in the rendering |
| Rendering too large | Truncated **visibly** — silent truncation is a correctness bug |
| Budget exhausted mid-analysis | A verdict on what was gathered, with exhaustion and gaps explicit — but **never `normal`**; it degrades to `unknown` |
| Enrichment entirely failed | Analyst `unknown` (unassessable), with mandatory gaps |
| Analysis ran and could not settle it | `suspicious` — a valid outcome, **not** a failure |
| Triage could not assess the context | A **typed failure**, not a third label, and it does not escalate |
| Any terminal outcome | Emitted to the output topic, **including typed failures** |
| A missing configuration value | A **startup error naming the variable** — never a built-in default, never a silent fallback |

**Two distinctions the design refuses to collapse**, because collapsing either
corrupts the measurements the project exists to make:

- `unknown` (unassessable) versus `suspicious` (assessed, unsettled) — collapsing
  them inflates the escalation rate and corrupts evaluation labels.
- A typed failure versus a verdict — collapsing them makes the evaluation
  denominator *successes* rather than *contexts*, and hides a degrading model
  behind a stable-looking accuracy number.

**Schema-invalid model output is retried** with the validation error fed back, a
small bounded number of times, and then becomes a typed failure. Retries count
against the budget, and the retry count per model is itself a quality metric. **A
second-pass "repair" call is rejected**: it adds a model dependency inside one
assessment and can alter semantics rather than syntax, so the repaired verdict may
not be the verdict the model meant.

**An interrupted assessment is re-run, not resumed.** There is no checkpointing
and no durable in-flight state outside the engine; the versioned context snapshot
is what makes re-running the *correct* recovery rather than a fallback.

## Budgets

Four dimensions are enforced per agent run by orchestration code, each mapping to
a distinct real limit:

| Dimension | The real limit it maps to |
| --- | --- |
| Step / tool-call count | The unbounded tool loop |
| Token budget | Model service rate limits and quotas |
| Wall-clock timeout | Stream latency |
| Live external query count | Provider quotas |

**Budgets are enforced at the tool boundary**, so an agent cannot reason its way
around them. Budget values are **policy, not constants in a branch**; the same
applies to confidence thresholds.

**A budget that seems generous for a model call is not survivable for a handful of
provider lookups.** At a few lookups per minute, an analyst run checking six
indicators spends over a minute waiting on the rate limit alone, before any
inference. **The wall-clock budget and the live-query budget have to be set
against each other**, not independently.

## Caching

**Every provider tool is cache-first.** On each call it looks for a valid,
unexpired record for its source, endpoint and indicator, and returns it without
touching the network; it queries only on a miss or an expiry.

**The cache *is* the evidence store**, not a second store beside it. A separate
opaque cache was rejected because an assessment could then cite something the
cache had already evicted. **Retention is configured per source *and* per
endpoint**, because different data ages differently — multi-engine reputation moves
as engines rescan, a registration date never changes, and risk scores sit between.

Three consequences that are policy, not optimisation:

- **A cache hit discloses nothing.** The indicator was already disclosed when the
  entry was fetched, so caching is a **privacy control** as much as a cost control.
- **Replay reads stored responses and never re-queries.** A replay that calls the
  provider again is not a replay; it is a new investigation with a different
  answer. Under a few-hundred-per-day quota this stops being an efficiency property
  and becomes the enabling one: the first pass spends the quota, and every re-run
  is free because it replays.
- **The retrieval trace records, per result, whether it was a cache hit or a live
  query**, and the retrieval time of the underlying record. Two runs that differ
  only in cache state must be distinguishable afterwards.

**Static enrichment has no cache at all** — a join against a versioned reference
table has nothing to deduplicate.

## Retention and replay

**The broker retains nothing you can rely on:** consume-once, restart-volatile, a
topic never re-readable. **Replay reads retained source records, never broker
retention.** The durable record is the retained capture, replayed through the same
ingestion path as live traffic so replay exercises the real pipeline rather than a
parallel one.

**Engine-side retention is a temporal filter**, not a delete: a predicate on the
context views, declarative and engine-enforced. A context is *live* while its raw
window is inside the boundary and revises when a late record arrives, so its
version citation applies. **A context cited by a finding is copied out, never
evicted** — freezing before eviction is what makes a citation stable rather than
merely current. **The retention horizon is also the late-record tolerance**: one
parameter, not two, because a record arriving after its window's raw records are
gone cannot revise anything. And **the boundary must report what it drops**, so a
misconfigured horizon shows up as a rejection rate rather than as missing evidence
nobody knows is missing.

**No watermark on the flow source.** A record is admitted on arrival regardless of
its event time; context aggregates are incrementally maintained views, not closed
windows, and revision is a property of the engine rather than something the project
builds. **A revised context keeps its identity — the counters change in place and
the `context_id` does not.**

> **Decided 2026-09-04, and the earlier text was wrong.** This note used to say
> *"a revised context is a new version, never an edit in place"*, which no
> incrementally maintained view can honour, and which contradicted the assumption
> [08 — Open questions](08-open-questions.md) holds in force. Task 13 measured the
> real behaviour against the pinned engine: a late record folded into the existing
> row, taking window `21:30:00Z` from 59 flows to 60, with the `context_id`
> unchanged. Replaying a capture does not double a context either — the source
> rows are upserts and the aggregate follows them.
>
> The consequence is accepted rather than softened: **a finding may cite a context
> id whose numbers have since changed.** The answer is the one this note already
> gives — a context cited by a finding is **copied out, never evicted** — and
> `concept/08` keeps the trigger to revisit it when findings outlive a retention
> boundary.
>
> What still mints a *new* identity is a revision of the **aggregation itself**:
> the aggregation version is inside the `context_id` digest, so changing how a
> context is computed produces new ids rather than silently changing what an
> existing id means.

**Feed snapshots are part of the provenance.** Evidence cites the snapshot it
matched, and replaying a case must join the snapshot that was current then, not
today's — otherwise a replayed assessment silently scores against different data.

> **A correction worth carrying.** An earlier design made the ingestion layer a
> connector-backed table, reasoning from four measured eviction mechanisms and
> generalising past them in one sentence. Measured, that cost **740× the storage**
> for nothing. **Measuring the mechanisms you thought of does not bound the
> mechanisms that exist.**

## Versioning

| What | Rule |
| --- | --- |
| **Contract stability** | Once a contract exists, identity, provenance and relationship fields are stable; enrichment and feature blocks may extend within them |
| **New input format** | An adapter, not a contract change |
| **New enrichment source** | Must not change identity, provenance or assessment contracts, and adding one is a recorded decision |
| **Agent schemas** | Historical versions retained as frozen classes; replay validates a stored assessment against the version **that assessment recorded**, never against current code. Migrating old rows forward is rejected — a migration that reshapes a field changes what the assessment says the agent saw, so replay would reproduce the migration rather than the original run |
| **Taxonomy** | A revision is a new version module, never an edit |
| **Aggregation** | The aggregation version is bumped whenever the aggregation changes what a context *means*, recorded on every row, and the SQL and the code constant are asserted equal by a test — two copies of a version that can drift apart are worse than none |
| **Recorded on every assessment** | Model, prompt, schema, rendering, taxonomy, enrichment snapshot, **normalization snapshot**, policy and aggregation versions — nine. **A hosted endpoint can change beneath a stable API name, and an unrecorded change silently breaks replay.** The normalization snapshot is the Public Suffix List that decided a registrable domain, and is not the feed snapshot: normalization runs before enrichment and settles what the join key is (added 2026-09-04; this row previously named seven, omitting aggregation) |

## Privacy and disclosure

**Querying an external source discloses the indicator to that source.** Two
separate obligations follow: **what may be sent to which source is governed
policy**, and **what was disclosed is recorded on the assessment** — source, query,
cache hit or live, disclosed-to, and when.

| Path | Discloses |
| --- | --- |
| Static enrichment | **Nothing** — every prototype enrichment lookup is a local join. Conditional on holding local feed copies |
| Model inference | **Prompts, and therefore rendered context.** Hosted, not on-premises |
| Analyst provider lookups | The indicators the case suggests — and only for contexts that escalated, never for the whole stream |
| The output topic | Internal addresses, hostnames, retrieved external text. Local broker, so no redaction is performed — **and any consumer forwarding it off-site inherits the obligations** |

**"Local pipeline" means local inference and decisions, not zero network egress.**
The two must not be conflated in prose or in policy.

## Untrusted input

**External text and model-visible fields are data, never instructions**, and
**isolation is implemented and tested, not asserted.** The concrete surfaces:
advisory and report text, provider descriptions, engine names, category labels,
feed tags and comment fields, and **registration records, which in a malicious case
are written by the adversary**.

This is also why memory entries, if memory returns, must be **structured claims
with provenance, confidence and expiry — never free-text summaries of retrieved
content**. A free-text note is precisely the persistence channel by which
attacker-influenced text reaches a future session's context; the structured form
loses nothing except the part that must not be stored.

## Secrets and configuration

Configuration comes from the environment, from a file that is never committed,
with a committed example documenting every variable name with an empty value.
There are general model settings and per-agent overrides, provider credentials,
the ingestion identity, and the infrastructure addresses.

**Resolution order: agent-specific, then general, then fail.** A missing value is a
startup error naming the variable — never a built-in default endpoint, never an
empty token sent to a real service, never a silent fallback to another agent's
model. An empty or whitespace-only value counts as missing, because the example
ships every variable empty and a copied-but-unfilled file has to fail loudly.

**The failure this prevents is the expensive one:** a triage run that silently used
the analyst's model, or a run against an unintended endpoint, discovered only in
the cost or in the results. The same applies to the tenant — **a tenant that
silently defaults is a tenant-isolation failure that looks like it is working.**

**What is recorded on an assessment** is the endpoint host and the model identity
and version: enough to know what produced a result, with nothing that authenticates
as anyone. Because endpoints are configurable per agent, cross-wiring is possible,
and recording endpoint and model per assessment is what makes it detectable.

**Credentials live in the tool layer's configuration.** The tool layer holds
provider keys; the loader holds the feed key. **Agents never see a credential.**
The token type is a secret wrapper, absent from string conversion and any
serialization.

**Never logged, in any form:** tokens and credentials — in prompts, evidence, logs,
traces or source control. And specifically, **a key that travels in a URL path
must be redacted before anything is logged or stored**, including the fetch trace a
loader records for provenance.

## Observability

**Local structured logs only. No hosted tracing.** The reasoning is not ergonomic:
a hosted tracing service would be a **second egress channel** carrying prompts,
rendered context and retrieved provider text, needing its own send policy, its own
disclosure record, and a second vendor's data-handling terms verified alongside
the first.

**The audit record is the stored assessment**, not a trace UI. It already carries
the retrieval trace, the disclosure record, cost, latency and versions as
first-class typed columns — queryable in a way a trace UI is not.

**What must be observable:** latency, cost, staleness, error, escalation and
model-quality metrics; end-to-end provenance; record counts reconciled between
produced and materialised; the retention boundary's rejection rate; and emission
counted from the engine side.

## Behaviour that must be impossible

Each of these is a plausible implementation that would produce a pipeline which
**runs and lies**.

| Must never happen | Why |
| --- | --- |
| A feed that failed to refresh returns `no_match` | An unrefreshed table becomes a silent empty opinion |
| A timeout, quota exhaustion or auth failure becomes `no_match` | Execution state is not security meaning |
| A budget-truncated analyst run returns `normal` | It established the absence of nothing |
| Triage returning `normal` suppresses a Tier A match | Deterministic escalation is independent |
| An indicator's classification becomes the host verdict on its own | Scope before severity |
| Truncation happens without being visible | Silent truncation is a correctness bug, not a formatting choice |
| An agent writes a fact, a claim or a memory entry directly | Agents propose; code writes |
| Model output determines which agent runs next | Routing must be reproducible, or the escalation rate is a model output rather than a measured property |
| An agent holds a provider key or calls a provider directly | Budgets, credentials and disclosure would move inside the prompt |
| A replay re-queries a live provider | That is not a replay; it is a new investigation with a different answer |
| An assessment is stored as an opaque document | Citations are join rows; an array is where a query goes to die |
| A free-text agent note is persisted as a record | That is the channel by which attacker-influenced text reaches a future session |
| A per-invocation free-text task is added to the agent contract | It makes triage input non-uniform, assessments incomparable, and gives untrusted content a route into the instruction position |
| Retrieved external text is treated as instruction | Registration fields in a malicious case are written by the adversary |
| A token appears in a prompt, evidence row, log, trace or the repository | Including a key that travels in a URL path |
| Analyst-fetched provider data appears in a triage rendering | Triage input stops being uniform and past assessments stop being comparable |
| A stored assessment is validated against current code on replay | It must be validated against the version that assessment recorded |
| A cited context is evicted rather than frozen | A citation must be stable, not merely current |
| The pipeline is described as running models locally | Inference is hosted; prompts leave the network |
| "The prototype works" is read as "the verdicts are right" | The measurement that would establish that is blocked on the corpus |
