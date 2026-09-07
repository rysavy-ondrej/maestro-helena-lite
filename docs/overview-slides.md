---
marp: true
theme: default
paginate: true
size: 16:9
title: MAESTRO HELENA — prototype overview
---

<style>
section { font-size: 24px; }
section.lead h1 { font-size: 54px; }
table { font-size: 19px; }
pre { font-size: 18px; }
h1 { color: #14304a; }
h2 { color: #14304a; font-size: 32px; }
strong { color: #8a2b06; }
footer { font-size: 14px; color: #888; }
.small { font-size: 19px; }
section.dense { font-size: 21px; }
section.dense table { font-size: 16.5px; }
section.dense td, section.dense th { padding: 4px 8px; }
</style>

<!-- _class: lead -->
<!-- _paginate: false -->

# MAESTRO HELENA

### Host-context Enrichment and LLM-Enhanced Network Analysis

Turning network flow telemetry into **evidence-backed host contexts**,
enriched, triaged, analysed — and **inspectable**.

**Maturity: research prototype.** The skeleton exists and is under
construction. Nothing here claims the verdicts are right.

---

## The problem, and why naive automation is worse than nothing

An analyst investigating a suspicious host repeats the same work every time:
collect the traffic, enrich every indicator, compare against history, decide
whether to dig deeper. Repetitive, expensive, inconsistent.

But **a model that produces a confident verdict with no traceable evidence
cannot be audited, cannot be replayed, and cannot be improved.**

Two commitments follow — they are the project's reason for existing:

1. **Every verdict remains traceable to stored evidence.**
   Facts stay separate from inference; assessments cite stable evidence ids.
2. **Expensive reasoning is spent selectively.**
   Cheap triage decides what is worth analysing; deep analysis runs only on
   what triage — or the evidence itself — escalates.

<span class="small">Deployment posture: **read-only, analyst-supporting, non-blocking**. No autonomous blocking,
containment or remediation — rejected even as a future lane in a diagram.</span>

---

## The planned pipeline — six stages, and nothing beside them

```text
1 ingest    flow records (JSONL) → broker (Kafka protocol) → Normalizer
2 context     └→ streaming engine: host context + entity rows ───────────┐
3 enrich    feed → loader → reference table (snapshot-versioned)         │
                                                                        ↓
                            EnrichedHostContext view  (a join, not a dispatch)
4 triage      → rendering → Triage Agent ──normal──────────────────┐
                                 │                                 │
                            suspicious, or deterministic           │
                            escalation on the evidence             │
                                 ↓                                 │
5 analyse     → Analyst Agent ⇄ provider MCP tools ──verdict───────┤
                                                                   ↓
6 emit                       sink view → output topic (at-least-once)
```

- One host context per host per **5-minute tumbling window**.
- **All data lives in one streaming engine.** There is no second store.
- The broker is **not** a store: consume-once, restart-volatile. The durable
  record for replay is the **retained capture**, replayed through the same path.

---

<!-- _class: dense -->

## The processing components

| Component | Responsibility |
| --- | --- |
| **Normalizer** | Per-format adapters → validated events. Assigns tenant, sensor, schema version, event id, raw-record reference — **none of which the input carries**. Quarantines bad input without stalling |
| **Context Builder** | Streaming jobs and materialized views in three layers — *flatten → signal → analytical*. The **view definitions are project source**, versioned and tested |
| **Feed loaders** | Fetch each static feed, parse, map to the taxonomy, write a **snapshot-versioned** reference table. **A failure never empties a table** |
| **Enrichment views** | SQL mapping and join views producing enrichment evidence. **No runtime service** |
| **Orchestration** | Plain project-owned Python: renders agent input, routes, enforces budgets, validates output, persists assessments, replays |
| **Agent contract** | Versioned request/result schemas shared by every agent. **The contract, not the library, is the architectural commitment** |
| **Provider tools (MCP)** | Approved external providers as cache-first tools: credentials, send policy, budgets, disclosure recording |
| **Sink** | Egress of every assessed context — including `normal` and typed failures |

---

## Enrichment: static is a table, live is a tool

**The enrichment tier** — feeds loaded into snapshot-versioned reference tables,
joined **per entity** (`address`, `domain`, `fingerprint`, `url`).
Zero network egress: every lookup is a local join. First feed: **ThreatFox**.

**The analyst tier** — live APIs exposed as cache-first **MCP tools**, reachable
only from the Analyst Agent. The cache **is** the evidence store, not a second one.

Four states that must never collapse into each other:

| Field | Values | Meaning |
| --- | --- | --- |
| **status** | `ok` `stale` `failed` `missing` | what happened to the *lookup* |
| **classification** | `no_match` `normal` `suspicious` `malicious` `unknown` | what the source *said* |

> **A timeout, a quota exhaustion or an unrefreshed feed is never `no_match`.**
> Coverage is sparse — most entities hit nothing — so an enriched context is
> **mostly negative space**, and triage reading "no hit" as "clean" is the
> failure mode the whole design exists to prevent.

---

<!-- _class: dense -->

## The agentic module: two agents, asymmetric on purpose

| | **Triage Agent** | **Analyst Agent** |
| --- | --- | --- |
| Question | *Is this worth analysing?* | *What is it?* |
| Input | A bounded, versioned rendering — **and nothing else** | The rendering, plus (when built) bounded cited case memory |
| Tools | **None at all** | Budgeted tool loop over MCP provider tools |
| Retrieval | None — no lookups, no waiting | Live, on demand, case-driven |
| Verdicts | `normal` \| `suspicious` | `normal` \| `suspicious` \| `unknown` \| `malicious`, with a path |
| Evidence tier seen | `enrichment` only | `enrichment` **and** `analyst` |
| Writes | Nothing | Nothing — **it proposes** |
| Model | Smallest capable — the high-volume path | Larger, tool-calling, structured output with citations |

**The separation is not "the analyst gets more time".** The two differ in *where
their information comes from* — which is what makes enrichment affordable at
stream rates. **Agents differ by model, not by framework**; model choice is a
configuration value, never a code path.

---

## How an assessment actually runs

**Orchestration is deterministic project code. Routing is an `if`:**

```python
if evidence_escalates_independently(evidence):      # tier A, or tier B over threshold
    run_analyst(trigger="deterministic_signal")     # regardless of the triage verdict
elif triage.root == "suspicious":
    run_analyst(trigger="triage_suspicious")
else:
    finish()
```

- **An LLM returning `normal` may not bury a high-confidence match** — that is
  why deterministic escalation is evaluated by code, not inside a prompt.
- **A triage failure does not escalate.** Failing closed is safe *because*
  deterministic escalation is independent of whether triage ran at all.
- **The analyst does not inherit the triage rationale.** Its `normal` verdict is
  the direct measurement of triage precision — worthless if it was anchored.
- **One assessment = one function call over one versioned context snapshot.**
  An interrupted run is **re-run, not resumed**; there is no checkpoint state.
- **Four budgets** enforced *at the tool boundary*: steps, tokens, wall-clock,
  live queries — so an agent cannot reason its way around them.

---

<!-- _class: dense -->

## The rules the agents may not break

| Rule | Statement |
| --- | --- |
| **Code owns side effects** | Validation, tenant isolation, budgets, escalation, persistence. Agents may not change policy or remediate |
| **Deterministic orchestration** | No agent selects, invokes, sequences or terminates another. **No model output determines control flow** |
| **Agents propose; code writes** | An agent's claim is a proposal, schema-validated and written by deterministic code |
| **Typed boundaries** | Nothing crosses an agent boundary except validated typed fields — no free-text task, no free-text notes |
| **No direct provider access** | **Agents never hold keys or call providers directly** |
| **External text is data, never instruction** | Advisories, category labels, registration records — **written by the adversary in a malicious case** |
| **Ephemeral state** | Scratchpads and tool transcripts are working memory for one assessment, never the durable record |

**Scope before severity** — the most consequential rule: *an evidence-level
classification about a contacted indicator does not become the host verdict.*
A C2 hit with bidirectional traffic supports `malicious.c2`; the same hit with
one failed connection and no bytes does not. **Policy constrains what evidence
can support what verdict — the model only classifies.**

---

## The unplanned module — analyst UI, NL querying, investigation protocol

**Deferred, and deliberately underspecified** — what analysts need here depends
on what the local pipeline turns out to leave unanswered. Today the analyst is
served only indirectly, through the output topic.

The pieces it would bring together, each already named as deferred:

- **A demonstration UI** and a **finding store** — the *finding* is the record
  linking a context, its assessments and its evidence: the investigation protocol.
- **A query API / evidence graph** over the single store — the engine speaks the
  PostgreSQL wire protocol, so **natural-language questions map to SQL over typed
  rows and citation joins**, not over an opaque document.
- **The cloud Investigation Agent** — analyst-initiated: a human opens a case,
  works it interactively against a **redacted view** with a cloud model, and the
  session is **appended to the finding, never overwriting the local assessment**.
- **The analyst feedback loop** — a claim is never deleted; suppression is
  explicit policy, and a suppressed match is still recorded as having matched.

<span class="small">**Cost scales with analyst attention, not telemetry volume** — a different profile from the automatic pipeline.</span>

---

## What it inherits, and where it stands

**Constraints the unplanned module does not get to renegotiate**

- **The redaction gate has nothing to gate yet** — it is the *only* cloud
  component, and everything crossing to the cloud must pass one.
- Agent memory, if it returns, must be **structured claims with provenance,
  confidence and expiry — never free-text summaries** of retrieved content.
- A cited context is **frozen, never evicted**: a citation must be stable, not
  merely current.

**Built today:** ingest, context, enrichment through the enriched-context join
view and its acceptance gate. **Next:** rendering, the agent contract, triage.

**Claimable now:** verdicts cite stored evidence; outages, staleness and partial
context are visible; no autonomous remediation occurs.
**Not claimable:** accuracy, recall, escalation rate, latency, cost —
**the labelled evaluation corpus does not exist**, and it gates every measurement.

> A pipeline built without an evaluation harness can be demonstrably *running*
> and undemonstrably *correct*. **Inference is hosted, not on-premises** —
> prompts leave the monitored network.
