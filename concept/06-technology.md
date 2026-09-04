# 06 — Technology

## Platform and runtime

| Choice | Value |
| --- | --- |
| **Language** | **Python 3.12** for every software component — normalizer, feed loaders, MCP provider tools, agent runtimes, and (when they return) the evaluation harness and demonstration UI |
| **Packaging** | **uv**, with a committed lockfile. **One package**, modules per component |
| **Tests** | **One `pytest` suite** |
| **SQL** | The engine's view and model definitions are **project source in their own right**, versioned and tested by execution |
| **Migrations** | **Plain numbered `.sql` files applied in order**, tested by execution against a throwaway instance |
| **Broker** | **Blink**, a single Rust binary. A third-party binary the project **runs, not builds**, pinned to a commit |
| **Streaming engine** | **RisingWave**, pinned release binary. It speaks the PostgreSQL wire protocol, so any consumer is an ordinary PostgreSQL client |
| **OS** | Linux, single node at prototype scale |

**Why not a SQL transformation framework:** it would be a major dependency in the
data path, and the standing preference is against machinery ahead of a measured
need. Revisit if the model set outgrows plain migrations.

**A packaging hazard worth carrying:** the engine's released binary is dynamically
linked against a specific Python minor version's shared library. Distributions
shipping a different minor cannot satisfy that from their own repositories, and
**symlinking another minor onto that name fails silently** — the ABI differs.

## Technology in the assessment path

| Concern | Choice | Note |
| --- | --- | --- |
| Continuous processing, context, evidence, findings, knowledge | **RisingWave** | The single store |
| Orchestration, routing, budget enforcement, persistence | **Plain Python, project-owned** | Deterministic; no LLM supervisor |
| Model client, tool binding, structured output | **LangChain** over the OpenAI-compatible endpoint | Earns its place: tool binding and structured-output validation are needed on day one |
| Agent output schemas | **Pydantic**, versioned, historical versions retained as frozen classes | |
| Graph framework | **Not adopted** | At two agents with deterministic routing the graph is an `if` statement, and it would add a checkpoint store against the single-store rule |
| Higher-level agent frameworks | **Deferred** | Built on the graph framework, so adopting one means adopting both; unmeasured value over a plain tool loop |
| Workflow engine | **Rejected** | Operational weight out of proportion; the durability requirement here is per-assessment replay, which versioned inputs and stored results already deliver |
| Tracing / observability | **Local structured logs only** | A hosted tracer is a second egress channel for prompts and retrieved text |
| Second store — relational profile store, vector store, checkpoint store | **Rejected** | If semantic retrieval over notes later proves necessary it needs its own decision record, not an incidental dependency |

**Current dependencies are deliberately few:** Pydantic, a dotenv loader, a Kafka
client and a PostgreSQL driver, with pytest for development. **The model-client
library is deliberately absent until the first increment that actually calls a
model**, and a boundary test enforces that rule.

**What would reverse the orchestration choice:** a measured need for resumability,
human-in-the-loop interrupts, or a third agent whose routing is not expressible as
a branch. Because the *contract* is the architectural commitment and the *library*
is a technology-table entry, that reversal is orchestration wiring rather than an
agent rewrite.

## Models

Agents run against a hosted, OpenAI-compatible API. **Agents differ by model, not
by framework**, and **model choice stays a configuration value, never a code
path** — that is what keeps this cheap to redo.

| Agent | Profile |
| --- | --- |
| **Triage** | The smallest capable model. The high-volume path, where latency and cost per call dominate |
| **Analyst** | A larger model chosen for multi-step tool calling and structured output with citations. **Tool-call reliability matters more than raw context length** |
| **Investigation** | Deferred; a cloud model |

Candidates are settled by **measurement, not conclusion**. What settles them is
triage precision and recall against the deterministic signals, agreement with
analyst verdicts, schema-violation rate, and latency and cost per context — all of
which need the evaluation corpus.

**Two cautions that are design guidance, not model trivia:**

- **A very large context window is not a design goal.** If a case does not fit in a
  normal window, the retrieval and evidence packaging are wrong, not the model —
  the Analyst Agent is supposed to **select** evidence, not pour a database into a
  prompt. Reaching for a bigger window is a signal to look at the packaging first.
- **Quantization may matter more than parameter count for this workload.** Both
  agents must emit schema-valid structured output with stable evidence
  identifiers. Whether quantization shows up as schema violations or mis-copied
  identifiers is measurable and unmeasured.

**Multimodal capability is irrelevant throughout**: every input is text or
structured data, and no agent should be given a channel it has no use for.

## Deployment posture

- **Read-only, analyst-supporting, non-blocking.** No autonomous blocking,
  containment or remediation.
- **The automatic pipeline is local**, end to end, and terminates at a **local**
  broker topic. The only cloud component is the deferred Investigation Agent.
- **Inference is hosted, not on-premises.** Prompts leave the monitored network.
  Genuinely local inference remains the target for real telemetry; **no document
  may claim the prototype achieves it.**
- **Ingestion identity comes from deployment configuration.** The normalizer is
  configured per deployment with its tenant and sensor, which **does not scale to
  multiple sensors sharing one normalizer** — a known revisit.
- **Every view a deployment needs must exist before data flows.** The broker is
  consume-once, so a view added later starts empty rather than backfilling; adding
  one to a running deployment requires replay from the retained captures.

## Compatibility boundaries

| Boundary | Rule |
| --- | --- |
| **Broker** | Addressed **only** through the Kafka wire protocol. Replacing it must not require a code change beyond configuration — and the rule holds on both ends, so replacing the broker replaces ingress and egress at once |
| **Input format** | A second format later means writing an **adapter**, not changing the contracts. That is the boundary that must survive |
| **Enrichment sources** | A new source must not require a change to identity, provenance or assessment contracts |
| **Contracts** | Identity, provenance and relationship fields are stable; enrichment and feature blocks may extend within them |
| **Agent schemas** | Historical versions retained; replay validates against the recorded version, never against current code |

## Cost, measured

| Measurement | Value |
| --- | --- |
| Aggregate state | ~308 bytes per group, linear, and not watermark-dependent |
| Retention as a temporal filter | ~1.9 bytes per record |
| Retention as a connector-backed table | **740× more** — roughly 4 GB/day at a thousand hosts against 5.4 MB/day |
| Materializing an intermediate that only feeds an aggregate | **+42 % disk for nothing** |
| Steady state | 200 records/s for 35 minutes against a 2-minute boundary held flat |

Monetary model cost is **derived and recorded per assessment, not separately
capped** — capping it would double-count the enforced budget dimensions. Provider
quotas are a design constraint rather than an operational detail. And **emitting
`normal` verdicts means the output topic carries the full context volume**, not
just the interesting few: intended at prototype scale, and something that would
need revisiting at real rates.

## Performance

**There is no measured throughput or latency target, and none is asserted.** What
exists is the set of measured envelopes above, a shape for the budgets, and one
standing preference:

> **Streaming-first.** Where a choice exists between doing enrichment work in the
> engine and doing it in Python, **the engine wins unless measurement says
> otherwise.**

**Do not relitigate the language.** The original throughput risk was the per-flow
Python path in an enrichment coordinator; that component no longer exists, because
static enrichment is a join. If a throughput problem appears, measure it and move
that one component.

**One engine-specific habit to resist:** `CREATE MATERIALIZED VIEW` is the
habit-forming default, and each layer boundary is a chance to pay 42 % for nothing.
Materialize where something is queried or joined from; use a plain view where a
layer exists only to feed the one above it.

## Standing engineering preferences

- **Implement the smallest coherent capability that can validate the next
  important assumption**, and evaluate the result before committing to the next
  major step.
- **This applies to the increment *set*, not only to each increment.** A
  specification can be locally minimal at every step and globally unbuildable.
  Before adding an artifact, check what it makes *buildable*, not what it makes
  *complete*.
- **No speculative abstractions, frameworks, configuration systems or
  compatibility layers.** A registry for two agents is a speculative abstraction;
  what delivers the goal is the typed contract.
- **Keep experimental components behind simple interfaces**, so alternatives stay
  cheap to evaluate.
- **Preserve reproducibility**: fixed inputs, recorded versions, deterministic
  processing, useful logging.
- **Failed and inconclusive experiments are valid results.** Record why; never
  rewrite or hide them. And do not keep unsuccessful prototype code merely because
  effort was spent.
- **Important knowledge lives in the repository**, not only in conversation
  history.
- **Do not specify the whole system up front.** Keep unknowns explicit rather than
  inventing requirements to make a document look complete.

And the one this project learned the hard way, three times:

> **Check the artifact, not the page.** Every wrong source record here had the same
> shape — written from a documentation page or a guessed convention, then
> propagated before anyone fetched the thing it described. A feed was chosen as
> "narrowest" by a reasoning nobody had counted; a "regenerates every five minutes"
> claim was site boilerplate for a file frozen for years; two credential names were
> guessed and propagated across six documents each.
