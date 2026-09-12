# 0038 — Pipeline metrics and reconciliation, as views rather than a tracer

Status: accepted — 2026-09-11 (task 48, D7 Observability)

## Context

`concept/07-principles.md`, "Observability", is two statements. The first is a
refusal: **local structured logs only, no hosted tracing**, because a hosted
tracer is a second egress channel carrying prompts, rendered context and
retrieved provider text. `docs/decisions/0005-structured-logging-and-redaction.md`
built the channel that exists instead, and
`tests/test_dependency_boundary.py` keeps the tracing SDKs out by test.

The second statement is the positive half, and until this increment nothing
implemented it:

> **The audit record is the stored assessment**, not a trace UI. It already
> carries the retrieval trace, the disclosure record, cost, latency and versions
> as first-class typed columns — queryable in a way a trace UI is not.
>
> **What must be observable:** latency, cost, staleness, error, escalation and
> model-quality metrics; end-to-end provenance; record counts reconciled between
> produced and materialised; the retention boundary's rejection rate; and
> emission counted from the engine side.

Two of those seven were already built by the increments that needed them:
`helena_signal_retention_rejections` (`sql/migrations/0009`, task 12) and
`helena_analytical_emission_counts` (`sql/migrations/0020`, task 47).

## Decision

**Seven plain views in `sql/migrations/0021_pipeline_observability.sql`, a
reader module `helena.status`, and `uv run scripts/status.py` — and no metrics
store, no exporter, no scrape endpoint and no dashboard.**

| View | Layer | What it answers |
| --- | --- | --- |
| `helena_ingest_ledger` | source | normalized against quarantined, per capture |
| `helena_reference_feed_staleness` | reference | each source's snapshot age against its own schedule |
| `helena_analytical_run_metrics` | analytical | latency, cost, tokens, retries and cache state, per model |
| `helena_analytical_failure_counts` | analytical | the typed failures, one row per reason |
| `helena_analytical_escalation_counts` | analytical | escalation rate, and which trigger caused it |
| `helena_analytical_retrieval_metrics` | analytical | cache hit against live query per source, and typed retrieval failures |
| `helena_analytical_pipeline_reconciliation` | analytical | contexts, assessments and emittable messages per deployment |

Every one is a **plain view**: read as numbers by an operator or by
`helena status`, never streamed or joined from, so materializing any of them
would be disk for a count — the call `sql/migrations/0003`, `0004` and `0020`
already made for their counters. Two of them could not be materialized in any
case: `helena_reference_feed_staleness` computes `age_seconds` from `now()`
outside a `WHERE` clause, which a streaming query rejects
(`sql/migrations/0009`'s head has the measurement), and
`helena_analytical_pipeline_reconciliation` stands on
`helena_analytical_emission_counts`, which stands on a view that cannot be the
source of a streaming job at all (`sql/migrations/0019`'s head).

## 1. No hosted tracer is adopted, and this is what says so

Nothing in this increment sends anything anywhere. Adding a tracer, an OTLP
exporter, a Prometheus endpoint or a metrics push is an **egress decision** under
`concept/instruction.md` §3 — "an HTTP surface, a UI, or a second egress channel
(including hosted tracing)" — and not a configuration detail.

The property being kept is not "we avoided a dependency". It is that **an
operator with `psql` and no access to this project's source gets every number**:

```sql
SELECT * FROM helena_analytical_run_metrics;
SELECT * FROM helena_analytical_pipeline_reconciliation;
SELECT * FROM helena_signal_retention_rejections;
```

A trace UI cannot be asked "what did this model cost per assessed context last
week, grouped by the version of the prompt that ran", and this can, because the
assessment is already typed columns. That is the whole of `concept/07`'s
argument, and it is the reason the alternative was not weighed on ergonomics.

## 2. No rate is stored anywhere; a rate over nothing raises

Every view exposes a **numerator and a denominator and stops**. Every rate is a
property on a `helena.status` model, and every one of them raises when its
denominator is zero.

`helena.context.RetentionRejections.rate` (task 12) set the rule and gave the
reason: `0.0` would read as *"the boundary dropped nothing"* when the truth is
*"nothing was aggregated"*, and those are two different facts —
`concept/instruction.md` §2's "never collapse `stale` / `failed` / `missing` /
`no_match`" one level up. `helena.normalizer.QuarantineCounts.rate` made the same
call before it. The rates this increment adds behave identically:

| Rate | Raises when | Because `0.0` would read as |
| --- | --- | --- |
| `EscalationCounts.rate` | nothing triaged | "triage escalates nothing" |
| `RunMetrics.typed_failure_rate` | no runs | "this model never fails" |
| `RunMetrics.cache_hit_ratio` | no retrievals | "the cache never helped" — about triage, which has no tools |
| `RunMetrics.mean_cost` | no priced run | "this model is free" |
| `FeedStaleness.intervals_behind` | no schedule | "on time" — the SSLBL JA3 list is not late, it is finished |
| `IngestLedger.quarantine_rate` | nothing admitted | "nothing was refused" |
| `PipelineReconciliation.unaccounted` | no capture directory read | "nothing was lost" |

`helena.status.render` prints the refusal's own sentence where the number would
have been. Catching them and printing zeros is exactly what this would be
protecting against, so the renderer does not.

## 3. The reconciliation is two views and a join in Python, because of the
## layering invariant

`concept/instruction.md` §2 and `concept/03-architecture.md`: *"an analytical view
references the signal layer, never the flatten layer and never the source
directly."* The five terms `concept/07` asks to be reconciled are not in one
layer, and one of them is not in the engine at all:

| Term | Where it lives |
| --- | --- |
| capture record count | the retained **file** — `helena.normalizer.Capture.record_count` |
| normalized rows | source layer |
| quarantined rows | source layer |
| context rows | signal layer |
| emitted rows | analytical layer |

The PRD's step said "write a reconciliation view". **One view over all five would
read the source from the analytical layer**, which is the invariant, and
`helena.migrations.layering_violations` fails it. Two shapes were rejected before
this one:

* **Widening `MAY_READ["analytical"]` to include `source`.** That is an edit to
  the invariant to make one view convenient, and it would silently license every
  future analytical view to skip the signal layer.
* **A counter view in the `flatten` layer** (which may read `source`) for the
  signal layer to read and the analytical layer to read in turn. Formally legal
  and dishonest: the flatten layer is the flattening of nested observations
  (`docs/decisions/0015-the-flatten-layer.md`), and a row count is not that.
  Compliance dressed up.

So the source half is `helena_ingest_ledger` (source layer, over source
counters), the signal-and-analytical half is
`helena_analytical_pipeline_reconciliation`, and
`helena.status.PipelineReconciliation` is the one object that holds all five and
checks them against each other. **This is the shape
`helena.normalizer.IngestCounts` already has** for the ingest half, and it gave
the reason: *the four numbers deliberately come from four different places, and
that is what makes the check worth running.*

The conflict is recorded rather than resolved silently: the task's step is not
implementable as written without breaking a higher-authority document, and
`prds/reports/task-48.json` says so.

### What reconciles and what merely reports

Conflating these two lists would produce a check that fires on a healthy
pipeline.

**Refused** — `normalized + quarantined = admitted`; `admitted` no greater than
`capture_records` (more accounted for than the files hold means a capture was
ingested twice, which `IngestCounts` names — storing an event again is an upsert,
so it looks exactly like loss); `context_records` no greater than `normalized`;
`verdicts + typed_failures = runs`; `cache_hits + live_queries = steps`;
`answered + failures = steps`; escalations by trigger summing to escalations.

**Reported** — `unaggregated`, the normalized events that reached no context.
`helena_signal_host_context` tumbles `helena_flatten_flows` on `flow_start`
grouped by `src_address`, so an event with no `ip` layer or an unparseable `ts`
produces a flatten row the tumble drops. That is a fact about the input, and a
pipeline that refused to report it is one that cannot tell anybody the input
changed. Also reported: `emittable` against `assessments`, which differ whenever
a pass escalated — two runs, one message.

## 4. `emittable`, and why nothing counts what was emitted

`helena_analytical_emission_counts` counts what the store says is *emittable*,
which is the only thing the engine can honestly count. Nothing records that a
message was produced, deliberately:
`docs/decisions/0037-at-least-once-emission.md` §3 — delivery is at-least-once, a
re-run legitimately emits the same assessment again, and a ledger of what was
emitted would be a table whose only use is suppressing a duplicate the contract
says the consumer removes. The column is named for what it holds.

## 5. `helena.status` is a module, not an addition to `helena.observability`

Both are `concept/07`'s Observability section, so one module was the obvious
shape. It cannot be one: the metrics read `helena.enrichment`'s feed statuses so
that `ok` / `stale` / `missing` are not respelled, and `helena.enrichment`
imports `helena.observability` for the redactor. One module is an import cycle.

`tests/test_package_layout.py` therefore carries `status` in `SUPPORT_MODULES`
with that reasoning written down, beside `observability`'s. It is a support
module and not a component because it is not a stage: it reads every stage's
counters and owns none of them.

## 6. The command

`uv run scripts/status.py` — `helena status` — renders all of it, plus the two
counters earlier increments built, read through the modules that own them
(`helena.context.ContextStore.rejections`, `helena.sink.SinkStore.pending`). A
second copy of either would be a second number to disagree with the first.

`--captures DIR` supplies the capture record count. It is optional and its
absence is **said, never defaulted to 0**: how many records existed is a property
of the retained file and of nothing else, because the broker is consume-once and
restart-volatile, and `0` would report a deployment that had lost every record it
ever ingested.

It is **not a health check**. It prints numbers and does not decide which of them
is bad; `docs/runbook.md` §13 is where they are explained.

## 7. What is claimed

That each number `concept/07` names is derivable from the single store in plain
SQL, and that the rows are checked against themselves rather than trusted —
demonstrated by `tests/test_status.py` against the pinned engine, over
assessments written by the real writer, a capture ingested through the real path
and a snapshot loaded by the real loader.

**Not claimed:** that this is the right *set* of numbers. No deployment has been
watched with it, there are no thresholds, no alerting and no baseline, and
`concept/01-goal-and-scope.md`'s "is the assisted pipeline better than the
deterministic baseline in accuracy, escalation rate, latency and cost?" is a
question about an evaluation corpus that does not exist. What exists is the
measurement surface that question would be asked through.

## Alternatives rejected

* **A hosted tracer (Langfuse, LangSmith, OTLP to a vendor).** A second egress
  channel for prompts and retrieved provider text, needing its own send policy,
  its own disclosure record and a second vendor's data-handling terms
  (`concept/07`). Escalation under `concept/instruction.md` §3, and the note has
  already decided it.
* **A Prometheus endpoint.** A new HTTP surface (§3 again), and it would answer
  fewer questions than the SQL: a counter loses the version set, the model
  identity and the context reference, which are exactly what an audit needs.
* **Materializing the metric views.** Continuous state for numbers read
  occasionally. Measured direction, `docs/decisions/0016`.
* **Rate columns in SQL.** A view cannot refuse a division over an empty
  denominator; `0.0` would ship as a fact. §2.
* **A `metrics` table written by the pipeline.** A second store of derived
  numbers that can disagree with the rows they were derived from —
  `concept/instruction.md` §2, one store.
