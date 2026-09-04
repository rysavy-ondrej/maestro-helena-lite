# 03 — Architecture

## The pipeline

```text
1 ingest    producers (JSONL) → broker (Kafka protocol) → Normalizer
2 context     └→ streaming engine: Context Builder → HostContext
                                                   + entity rows ─────────┐
3 enrich    feed → loader → reference table (snapshot-versioned)          │
                                                                          ↓
                              streaming engine: EnrichedHostContext view
                              (a join, not a dispatch)
4 triage      → TriageContext → Triage Agent  ──normal──────────────┐
                                     │                              │
                                suspicious, or deterministic        │
                                escalation on the evidence          │
                                     ↓                              │
5 analyse     → Analyst Agent ⇄ provider MCP tool ──verdict─────────┤
                                                                    ↓
6 emit                        streaming engine sink → output topic
```

## Components

| Component | Responsibility |
| --- | --- |
| **Normalizer** | Per-format adapters parsing flow records into validated events; **assigns tenant, sensor, schema version, event id and raw-record reference — none of which the input carries**; quarantines invalid input without stalling the stream |
| **Context Builder** | Streaming jobs and materialized views in three layers: windowed aggregation into a host context, entity extraction, and the enriched-context view. **The view definitions are project source**, versioned and tested |
| **Feed loaders** | Fetch each static feed on its schedule, parse it, map it to the taxonomy, and update its reference table with a snapshot version. **Load failures are recorded, never silent** |
| **Enrichment views** | SQL mapping and join views turning reference tables into enrichment evidence and the enriched context. **No runtime service** |
| **Orchestration** | Plain project-owned Python: renders agent input, routes on the triage result and on independently escalating evidence, enforces budgets, validates output, persists assessments including typed failures, and replays from stored results |
| **Agent contract** | Versioned request / result schemas shared by every agent, including the typed failure envelope. **The contract, not the library, is the architectural commitment** |
| **Triage Agent** | Small fast model. One rendering in, `normal` / `suspicious` out |
| **Analyst Agent** | Larger model with tools, autonomous. Deeper analysis over broader evidence |
| **Provider tools (MCP)** | Expose approved external providers as tools: credentials, send policy, budgets, disclosure recording, cache-first lookup |
| **Policy and budget guards** | Deterministic code enforcing the agent-boundary rules around every agent |
| **Sink** | A sink over a view joining the enriched context, the terminal verdict and the cited evidence |

## The rules that bound processing

**Orchestration is deterministic project code.** Agents are invoked by it. No
agent selects, invokes, sequences or terminates another, and **no model output
determines control flow**. Routing is an `if`:

```text
if evidence escalates independently (tier A, or tier B above threshold):
    run_analyst(trigger="deterministic_signal")   # independent of triage
elif triage.root == "suspicious":
    run_analyst(trigger="triage_suspicious")
else:
    finish()
```

**Agents propose; code writes.** An agent's observation about infrastructure is a
proposal, validated against a schema and written by deterministic code.

**An assessment is one function call over one versioned context snapshot.** No
checkpointing, no durable in-flight state anywhere outside the engine; an
interrupted run is simply re-run, because the versioned context already makes
that correct rather than a fallback.

**Framework and in-process state is ephemeral.** Scratchpads, tool-loop
transcripts, planning state and any framework's virtual files are working memory
for one assessment. Everything durable is written by deterministic code as typed
rows. This binds harder if a framework is adopted, because such libraries make
file-backed agent memory the convenient default — and an agent writing notes to a
persistent backend has created a second store of uncited free text, which is
simultaneously a single-store violation and a memory-poisoning channel.

## The store

**All data is maintained in one streaming engine. There is no second store.** It
holds contexts and entities, enrichment evidence, triage decisions, analyst
assessments and evidence packages, findings and their links, and provider-tool
cache entries as tiered evidence.

**Agent output is stored as typed, queryable rows with citation joins, never as an
opaque document.** The fields anyone would filter, join, group or aggregate on are
typed columns: host, tenant, context reference, window bounds, verdict and
classification, confidence, timestamps, model / prompt / contract / rendering
versions, budgets consumed, latency, tokens, cost, and cache-hit versus
live-query counts. Narrative stays a text column. **Evidence citations are join
rows** — `(assessment, evidence, role)` — not an array buried in JSON, because
citations are the thing most queries follow and an array is where a query goes to
die.

**What is *not* a store:**

- **The broker.** It is memory-first, single-node, consume-once and
  restart-volatile: a record read once is gone whatever retention says, and a
  restart discards what is queued. A topic is never re-readable — but **the
  reclaim is asynchronous, not instantaneous.** Measured on blink 0.2.0 (task 10):
  an immediate second drain can still return every record, and the topic empties a
  few seconds later, while a topic produced to and never read still holds its
  records after 30 s — so this is consume-once, not a short retention window.
  **A retry that assumes the topic has already emptied will occasionally
  double-ingest.** `docs/runbook.md` §3 and
  `docs/decisions/0014-the-ingest-topic-message.md` carry the measurement.
- **The output topic.** Egress only. Nothing may be recoverable only from it.
- **Framework state.**

The durable record for replay is the **retained source capture**, replayed through
the same ingestion path as live traffic so that replay exercises the real pipeline
rather than a parallel one.

### View layering

Three layers — **flatten → signal → analytical** — and an analytical view
references the signal layer, never the flatten layer and never the source
directly.

One measured rule sits beside the layering: **do not materialize an intermediate
that only feeds an aggregate** — it stores rows nothing reads. Every view declares
whether it is a view or a materialized view, and what reads it.

> **The size of the penalty is not a constant, and the earlier figure here was.**
> This note used to say a materialized intermediate cost **42 %** more disk. Task
> 17 measured it against the pinned engine on two workloads producing the same
> aggregate and got **+12 %** (142 064 → 159 194 bytes over the ten-record layer
> capture) and **+56 %** (119 154 → 186 236 bytes over 73 flow rows collapsing
> into 2 contexts). The penalty scales with the **aggregation factor** — how many
> rows the intermediate holds per row the aggregate emits — so 42 % was one
> workload's number and is not reproducible as a rate. **The direction is what
> holds and what the test asserts**; `make storage` reads the actual bytes off
> the engine rather than arguing from a figure.

## Providers

> **Static data is a table; live data is a tool.**

**Static — the enrichment tier.** Feeds are fetched by a small loader, parsed,
mapped to the taxonomy, and written to a snapshot-versioned reference table. The
enriched context joins the host context and its entities against those tables.
**No coordinator, no workers, no dispatch, no cache** — a join has nothing to
deduplicate. Consequences that must not be lost: snapshot versioning becomes the
whole provenance story; a table update is a system change and must be visible in
the record; and **a feed that failed to refresh is stale or missing, never
`no_match`**.

The join is **per entity**: arrays inside a window cannot be joined to evidence,
the rendering needs per-domain and per-address records, and the composition rule
needs the indicator correlated with the matching traffic.

**Live — the analyst tier.** Every API connector is exposed as a **cache-first MCP
tool**. The tool layer — deterministic project code, not the model — owns
credentials, tenant scoping, budget enforcement, what may be sent, disclosure
recording and response validation. **The agent sees a tool, never an HTTP client
and never a key.**

The cache **is** the evidence store, not a second store beside it; entries are
enrichment-evidence records with provenance and expiry. Evidence is tagged by
tier, and the triage rendering shows enrichment-tier evidence only — without that
tag, a report fetched during one investigation would appear in the *precomputed*
context of every later host that talked to the same address, and triage input
would stop being uniform.

## The interfaces

**The first version exposes no HTTP or REST API of its own.** That is a
consequence of the deferrals, not an oversight: the finding store's API and the
demonstration UI are both deferred, and the output topic replaced the UI as the
delivered surface.

| Surface | Direction | Contract |
| --- | --- | --- |
| **Ingest topic(s)** | in | One flow record per message, over the Kafka wire protocol |
| **Output topic** | out | One JSON message per assessed context, at-least-once |
| **Engine SQL** | out | The durable rows and views, over the PostgreSQL wire protocol |
| **Environment** | in | Model endpoints and tokens, provider credentials, tenant and sensor identity, engine and broker addresses |

**The broker is addressed only through the Kafka wire protocol.** No component
codes against a specific broker; replacing it must be a configuration change. That
rule holds on both ends, which is what keeps ingress and egress on the same terms.

Every assessed context is emitted, exactly once per terminal outcome — including
`normal` verdicts and **typed failures**. A context that was escalated is emitted
once, carrying the analyst's verdict and the triage decision that led to it. The
message carries context identity and version, host and window, the entity rows
with their traffic characteristics and enrichment evidence (with `no_match`,
`stale`, `failed` and `missing` distinguishable), the verdict and its path, the
citations, the retrieval and disclosure trace, and the full version set. Delivery
is at-least-once, so consumers deduplicate; exactly-once is not attempted.

**Emission must be observable from the engine side** — a count of rows the sink
view produced — because the broker discards its queue on restart, so a message
emitted with no consumer attached is simply gone and nothing counts it. Otherwise
"nothing arrived" cannot be told apart from "nothing was assessed".

## What stays external

| External | Relationship |
| --- | --- |
| **Telemetry producers / sensors** | Publish flow records; outside the boundary. The system never configures or queries them |
| **The broker and the streaming engine** | Third-party binaries the project **runs, not builds**, pinned for reproducibility. The engine's SQL and view definitions **are** project source |
| **The model service** | A hosted, OpenAI-compatible API. **Inference is hosted, not on-premises** |
| **Threat-intelligence publishers** | Fair-use terms bind both tiers; datasets stay out of the repository |
| **The evaluation corpus** | **Does not exist**, and gates every measurement |
| **The analyst workflow / SIEM** | A consumer of the output topic |
| **Detector generation and deployment** | A sibling project's responsibility, explicitly not HELENA's |

## Trust and egress boundaries

Three boundaries matter, and conflating them is a documented hazard.

**1. A local pipeline is not zero network egress.** "Local" means **decisions and
control stay local**, not that no packet leaves the network. Two things do leave:

- **Model prompts.** Inference in the prototype is hosted, so prompts leave the
  monitored network and the disclosure rule applies to model calls as much as to
  intelligence lookups. **No document may describe the pipeline as running models
  locally while it does not.**
- **Analyst-time provider queries.** Asking a provider about an address tells that
  provider the monitored network saw it.

Static enrichment, by contrast, is **zero-egress** — every prototype enrichment
lookup is a local join. That property is conditional on how each feed is obtained:
querying a public blocklist service instead of holding a local copy would silently
reverse it.

**2. The redaction gate has nothing to gate yet.** Everything crossing to the
cloud must pass one, and the only cloud component is the deferred Investigation
Agent. The sink writes to the *local* broker, so no redaction is performed — but
that is a property of the deployment, not of the message: the payload contains
internal addresses, hostnames and retrieved external text, and **any consumer that
forwards it off-site inherits the redaction, minimization and disclosure
obligations**. The pipeline cannot enforce that.

**3. External text is data, never instructions.** Advisories, provider
descriptions, category labels, engine names and **registration records** — which in
a malicious case are written by the adversary — arrive as text a model will read.
Isolation must be implemented and tested, not asserted.

**Tenant isolation is a seam, not yet enforcement.** Tenant and sensor are stamped
on every event and carried to the output, and every agent request is tenant-scoped
by contract. The isolation machinery — scoped retrieval, per-tenant policy,
isolation tests — is deferred. This is stated so the field's presence is not
mistaken for a guarantee.
