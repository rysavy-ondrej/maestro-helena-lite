-- 0021  The pipeline's own numbers: metrics, staleness, and the reconciliation.
--
-- `concept/07-principles.md`, "Observability", lists what must be observable and
-- then says where it lives:
--
--   *"**The audit record is the stored assessment**, not a trace UI. It already
--   carries the retrieval trace, the disclosure record, cost, latency and
--   versions as first-class typed columns -- queryable in a way a trace UI is
--   not."*
--
--   *"**What must be observable:** latency, cost, staleness, error, escalation
--   and model-quality metrics; end-to-end provenance; record counts reconciled
--   between produced and materialised; the retention boundary's rejection rate;
--   and emission counted from the engine side."*
--
-- Two of those seven were already built and are deliberately not rebuilt here:
-- the retention boundary's rejection rate is `helena_signal_retention_rejections`
-- (sql/migrations/0009) and emission counted from the engine side is
-- `helena_analytical_emission_counts` (sql/migrations/0020). `helena status`
-- reads both beside the five this file adds, because an operator asking "is the
-- pipeline healthy" should not have to know which increment built which number.
--
-- **Nothing here is a new store and nothing here is a tracer.** Every view is a
-- `SELECT` over rows the pipeline already writes, and the whole of this file is
-- readable with `psql` by somebody who is running none of this project's code --
-- which is the property `concept/06-technology.md` chose over a hosted tracer,
-- and the property `docs/decisions/0038-pipeline-metrics-and-reconciliation.md`
-- §6 records as the reason no hosted tracer is adopted.
--
-- ## There is no rate column anywhere in this file
--
-- Every view here exposes a numerator and a denominator and stops. The division
-- belongs where "no rate over no records" can be refused --
-- `helena.context.RetentionRejections.rate` raises when nothing was aggregated,
-- because 0.0 would read as "the boundary dropped nothing" when the truth is
-- "nothing was aggregated", and `helena.normalizer.QuarantineCounts.rate` made
-- the same call before it. `helena.status` follows both: every rate on every
-- model in that module raises over an empty denominator rather than returning a
-- number that reads as good news.
--
-- ## The reconciliation is two views and a join in Python, and that is the
-- ## layering invariant, not an oversight
--
-- `concept/instruction.md` §2: *"View layering holds: flatten -> signal ->
-- analytical. An analytical view never reads the flatten layer or the source
-- directly."* The five terms the reconciliation compares do not sit in one
-- layer:
--
--   capture record count   the retained FILE. Not in the engine at all --
--                          sql/migrations/0004 stores no arrival time and the
--                          broker keeps nothing, so how many records existed is
--                          a property of the file and nothing else
--                          (`helena.normalizer.IngestCounts` says so first).
--   normalized rows        source layer
--   quarantined rows       source layer
--   context rows           signal layer
--   emitted rows           analytical layer
--
-- An analytical view spanning all five would read the source directly, which is
-- the invariant. So the source half is `helena_ingest_ledger` below -- a source
-- view over source counters -- the signal-and-analytical half is
-- `helena_analytical_pipeline_reconciliation`, and
-- `helena.status.PipelineReconciliation` is the one object that holds all five
-- and checks them against each other. The capture count reaches it from
-- `helena.normalizer.scan_captures`, or is absent and says so: a reconciliation
-- that silently used 0 for "no capture directory was given" would report a
-- deployment losing every record it ever ingested.
--
-- ## What reconciles, and what merely reports
--
-- `normalized + quarantined = admitted` is arithmetic over two counters of the
-- same capture and `helena_ingest_ledger` computes it. It reconciles or one of
-- the two stores lost a row.
--
-- `context_records` against `normalized` does **not** have to be equal, and a
-- view that asserted it would be wrong: `helena_signal_host_context` aggregates
-- `TUMBLE(helena_flatten_flows, flow_start, ...)` grouped by `src_address`, so a
-- normalized event with no `ip` layer or no parseable `ts` is a row the flatten
-- layer produces with nulls and the tumble drops. That gap is exactly the thing
-- worth seeing, so both numbers are reported and
-- `helena.status.PipelineReconciliation.unaggregated` is their difference --
-- named, not raised.
--
-- ## `emittable`, not `emitted`
--
-- `helena_analytical_emission_counts` counts what the store says is emittable,
-- which is the only thing the engine can honestly count: nothing records that a
-- message was produced, because delivery is at-least-once and a ledger of what
-- was emitted is the first step toward an exactly-once this project does not
-- attempt (`docs/decisions/0037-at-least-once-emission.md` §3). The column is
-- named for what it holds.
--
-- ## Every view here is plain
--
-- Not one of them is streamed from or joined from -- they are read as numbers by
-- an operator or by `helena status` -- so materializing any of them would be
-- disk for a count, the call sql/migrations/0003, 0004 and 0020 already made for
-- their counters. Two of them could not be materialized in any case:
-- `helena_reference_feed_staleness` computes `age_seconds` from `now()` outside
-- a WHERE clause, which a streaming query rejects (measured in
-- sql/migrations/0009's head), and
-- `helena_analytical_pipeline_reconciliation` reads
-- `helena_analytical_emission_counts`, which stands on a view that cannot be the
-- source of a streaming job at all (sql/migrations/0019's head).


-- helena_ingest_ledger: produced against materialized, per capture.
--
-- Layer:    source. A counter over the source layer's two counters, the way
--           helena_ingest_counts is a counter over helena_normalized_events.
--           It is here rather than in an analytical reconciliation view because
--           `concept/instruction.md` §2 does not let an analytical view read the
--           source; see the head of this file.
-- Object:   VIEW (plain). Read as three numbers; nothing streams or joins from
--           it.
-- Reads:    helena_ingest_counts, helena_ingest_quarantine_counts
-- Read by:  src/helena/status.py -- `StatusStore.ingest`, whose rows are the
--           source half of `PipelineReconciliation` -- and tests/test_status.py.
--
-- `admitted` is what ingestion accounted for: every record that became an event
-- plus every record it refused with a typed reason. `helena.normalizer`'s
-- `IngestCounts` already refuses a run whose `normalized + quarantined` does not
-- equal what it consumed; this is the same sum asked of the store afterwards, by
-- somebody who did not run the ingest and has no `consumed` to compare against.
--
-- The two counters are summed through a UNION ALL rather than joined, because a
-- capture may appear in either and not the other -- a capture every record of
-- which was quarantined has no row in helena_ingest_counts at all, and an inner
-- join would make that capture invisible instead of making it a row reading
-- `normalized = 0`.
CREATE VIEW helena_ingest_ledger AS
SELECT tenant,
       sensor,
       capture_sha256,
       sum(normalized)::BIGINT                    AS normalized,
       sum(quarantined)::BIGINT                   AS quarantined,
       (sum(normalized) + sum(quarantined))::BIGINT AS admitted
FROM (
    SELECT tenant,
           sensor,
           capture_sha256,
           normalized,
           0::BIGINT AS quarantined
    FROM helena_ingest_counts
    UNION ALL
    SELECT tenant,
           sensor,
           capture_sha256,
           0::BIGINT AS normalized,
           quarantined
    FROM helena_ingest_quarantine_counts
) counted
GROUP BY tenant, sensor, capture_sha256;


-- helena_reference_feed_staleness: per source, how old its snapshot is against
-- its own schedule.
--
-- Layer:    reference
-- Object:   VIEW (plain), and it could not be a materialized one: `age_seconds`
--           is `now()` outside a WHERE clause, which a streaming query rejects
--           (sql/migrations/0009's head has the measurement), and staleness is a
--           fact about the moment of reading rather than a row to keep -- the
--           same reason helena_reference_feed_snapshot_current gives.
-- Reads:    helena_reference_feed_snapshot, helena_reference_feed_snapshot_current
-- Read by:  src/helena/status.py -- `StatusStore.feeds` -- and
--           tests/test_status.py.
--
-- `helena_reference_feed_snapshot_current` already says `ok` or `stale`. Two
-- things this adds, and both are things an operator asked "why is enrichment
-- thin" needs:
--
-- 1. **`age_seconds` beside `refresh_interval_seconds`.** `stale` is a boolean
--    over a threshold; a source one minute past an hourly schedule and a source
--    three weeks past it are both `stale`, and only one of them is a feed nobody
--    is loading. The ratio is not computed here -- see the head; a source with
--    no schedule has no ratio, and `helena.status.FeedStaleness.intervals_behind`
--    is where that is refused rather than divided by null.
--
-- 2. **A row for a source whose loads are all failing.** The current view is an
--    inner join onto the newest attempt that produced a snapshot, so a source
--    that has never loaded has no row there at all and is invisible to anything
--    reading it -- `helena.enrichment.feed_status` has to turn "no row" into
--    `missing` in Python. This view starts from the attempt ledger instead, so
--    every source anything ever tried to load has exactly one row, and
--    `attempts`, `last_attempt_at` and `last_failure_at` say whether the silence
--    is "nobody has run the loader" or "the loader runs and fails".
--
-- **`missing`, `stale` and `ok` stay three things** (`concept/instruction.md`
-- §2, and `helena.enrichment.feed_status`'s own docstring on why the difference
-- is not academic). `missing` is no snapshot at all and is said here rather than
-- inferred from an absent row. A source with no `refresh_interval_seconds` reads
-- `ok` and not `stale`: there is nothing to be late against, and the current
-- view's CASE falls through to `stale` on a null interval because a null
-- comparison is not true -- which `helena.enrichment.feed_status` corrects in
-- Python and this corrects in the SQL, so that plain SQL and the module give an
-- operator the same answer.
--
-- `last_failure_at` is filtered on `snapshot_version IS NULL` rather than on
-- `outcome = 'failed'`, so there is no second copy of the outcome vocabulary
-- here to drift from `helena.enrichment.LOAD_STATUSES`. The snapshot table's own
-- rule makes the two identical: a failed load has no snapshot, and
-- `helena.enrichment.FeedSnapshot` refuses a row naming both.
CREATE VIEW helena_reference_feed_staleness AS
SELECT ledger.tenant,
       ledger.sensor,
       ledger.source_id,
       ledger.attempts,
       ledger.last_attempt_at,
       ledger.last_failure_at,
       current_snapshot.snapshot_version,
       current_snapshot.attempted_at              AS snapshot_at,
       current_snapshot.refresh_interval_seconds,
       CASE
           WHEN current_snapshot.attempted_at IS NULL THEN NULL
           ELSE extract(
               epoch FROM now() - current_snapshot.attempted_at
           )::DOUBLE PRECISION
       END                                        AS age_seconds,
       CASE
           WHEN current_snapshot.attempted_at IS NULL           THEN 'missing'
           WHEN current_snapshot.refresh_interval_seconds IS NULL THEN 'ok'
           ELSE current_snapshot.status
       END                                        AS status
FROM (
    SELECT tenant,
           sensor,
           source_id,
           count(*)::BIGINT  AS attempts,
           max(attempted_at) AS last_attempt_at,
           max(attempted_at) FILTER (
               WHERE snapshot_version IS NULL
           )                 AS last_failure_at
    FROM helena_reference_feed_snapshot
    GROUP BY tenant, sensor, source_id
) ledger
LEFT JOIN helena_reference_feed_snapshot_current current_snapshot
       ON current_snapshot.tenant = ledger.tenant
      AND current_snapshot.sensor = ledger.sensor
      AND current_snapshot.source_id = ledger.source_id;


-- helena_analytical_run_metrics: latency, cost, tokens, retries and cache state,
-- per model.
--
-- Layer:    analytical. It reads the assessment table, which is analytical --
--           the latitude sql/migrations/0019 recorded and
--           `docs/decisions/0036-the-output-message.md` §3 explains.
-- Object:   VIEW (plain). Read as numbers; nothing streams or joins from it.
-- Reads:    helena_analytical_assessment
-- Read by:  src/helena/status.py -- `StatusStore.runs` -- and
--           tests/test_status.py.
--
-- **The grain is the model, because the questions are about the model.**
-- `concept/06-technology.md`: *"analyst verdicts, schema-violation rate, and
-- latency and cost per context"*; `concept/07-principles.md`: *"the retry count
-- per model is itself a quality metric"*. So the group is (tenant, sensor,
-- emitter, model_requested, model_version) -- both model columns, because what
-- this deployment asked for is not what answered, and a silent substitution on
-- the provider's side is exactly the drift these numbers exist to make visible.
-- `model_version` is null on a `model_unavailable` failure, where nothing
-- answered at all, so those runs group together and are countable as such.
--
-- **No averages and no percentiles.** `latency_seconds_total` with `runs` beside
-- it is the mean, computed where a zero denominator can be refused; a percentile
-- would need the rows rather than the aggregate and this view is read by an
-- operator, not by a dashboard.
--
-- **`model_cost_total` is null when nothing had a price**, not 0. All three cost
-- columns on the assessment are null together where the model has no configured
-- price (sql/migrations/0018), and `coalesce(..., 0)` here would report a
-- deployment running for free. `runs_priced` and `runs_unpriced` are what say
-- which of the runs the total covers, and `currencies` is how a total summed
-- across two of them is refused rather than printed --
-- `helena.status.RunMetrics` raises on it, because a number that is 12 of one
-- currency and 5 of another is not a cost.
CREATE VIEW helena_analytical_run_metrics AS
SELECT tenant,
       sensor,
       emitter,
       model_requested,
       model_version,
       count(*)::BIGINT                                                 AS runs,
       count(*) FILTER (WHERE classification IS NOT NULL)::BIGINT       AS verdicts,
       count(*) FILTER (WHERE failure_reason IS NOT NULL)::BIGINT       AS typed_failures,
       count(*) FILTER (WHERE retries > 0)::BIGINT                      AS runs_with_retries,
       sum(retries)::BIGINT                                             AS retries,
       sum(prompt_tokens)::BIGINT                                       AS prompt_tokens,
       sum(completion_tokens)::BIGINT                                   AS completion_tokens,
       sum(cache_hits)::BIGINT                                          AS cache_hits,
       sum(live_queries)::BIGINT                                        AS live_queries,
       min(wall_clock_seconds)                                          AS latency_seconds_min,
       max(wall_clock_seconds)                                          AS latency_seconds_max,
       sum(wall_clock_seconds)                                          AS latency_seconds_total,
       count(*) FILTER (WHERE model_cost IS NOT NULL)::BIGINT           AS runs_priced,
       count(*) FILTER (WHERE model_cost IS NULL)::BIGINT               AS runs_unpriced,
       sum(model_cost)                                                  AS model_cost_total,
       count(DISTINCT model_cost_currency)::BIGINT                      AS currencies,
       max(model_cost_currency)                                         AS model_cost_currency,
       max(model_prices_version)                                        AS model_prices_version,
       max(assessed_at)                                                 AS most_recent
FROM helena_analytical_assessment
GROUP BY tenant, sensor, emitter, model_requested, model_version;


-- helena_analytical_failure_counts: the typed failures, one row per reason.
--
-- Layer:    analytical
-- Object:   VIEW (plain). Read as numbers; nothing streams or joins from it.
-- Reads:    helena_analytical_assessment
-- Read by:  src/helena/status.py -- `StatusStore.failures` -- and
--           tests/test_status.py.
--
-- `concept/07-principles.md`: *"A failed run is stored as a typed failure with no
-- verdict"*, and `concept/instruction.md` §7 requires every failure path to be
-- **countable**. This is where they are counted, and the reasons stay separate
-- rows rather than becoming columns: `helena.contracts.v1.FAILURE_REASONS` is a
-- closed set today and a fourth reason should appear here as a row nobody had to
-- add, not fail to appear because nobody edited a CASE.
--
-- The denominator is not here. `helena_analytical_run_metrics` above holds
-- `runs` and `typed_failures` per model, which is the failure rate's other half;
-- this view is the breakdown of the numerator, and joining the two is
-- `helena.status`'s job because that is where a rate over no runs is refused.
CREATE VIEW helena_analytical_failure_counts AS
SELECT tenant,
       sensor,
       emitter,
       failure_reason,
       count(*)::BIGINT  AS failures,
       max(assessed_at)  AS most_recent
FROM helena_analytical_assessment
WHERE failure_reason IS NOT NULL
GROUP BY tenant, sensor, emitter, failure_reason;


-- helena_analytical_escalation_counts: how many contexts went to the analyst,
-- and what sent them.
--
-- Layer:    analytical
-- Object:   VIEW (plain). Read as numbers; nothing streams or joins from it.
-- Reads:    helena_analytical_assessment
-- Read by:  src/helena/status.py -- `StatusStore.escalation` -- and
--           tests/test_status.py.
--
-- `concept/01-goal-and-scope.md` lists escalation rate among the four things the
-- system is to be measured on, and `concept/04-the-two-agents.md` makes the
-- analyst the expensive path -- so this is the number that says whether triage
-- is doing its job, and the number that moves first when a threshold is edited.
--
-- **Triage is the denominator.** Every pass writes a triage run
-- (`helena.orchestration`), and an escalated pass writes an analyst run beside
-- it, so `escalated / triaged` is the escalation rate and the division is in
-- `helena.status.EscalationCounts.rate`, which refuses it over no triage runs.
--
-- **The two triggers are counted apart**, because they are two mechanisms and
-- only one of them is the model's: `triage_suspicious` is triage asking for a
-- second opinion, and `deterministic_signal` is `concept/07`'s rule that *"a
-- `normal` from a model may not suppress a high-confidence match"* firing
-- independently of what triage said. A single escalation count would hide a
-- deployment whose deterministic escalations had stopped.
--
-- The four string literals are the second copy of
-- `helena.taxonomy.v1`'s emitters and `helena.contracts.v1.TRIGGERS`; the SQL
-- cannot import them, so tests/test_status.py asserts the two copies equal by
-- reading this file -- the same arrangement sql/migrations/0019 and
-- tests/test_sink.py have.
CREATE VIEW helena_analytical_escalation_counts AS
SELECT tenant,
       sensor,
       count(*) FILTER (WHERE emitter = 'triage')::BIGINT    AS triaged,
       count(*) FILTER (WHERE emitter = 'analyst')::BIGINT   AS escalated,
       count(*) FILTER (
           WHERE emitter = 'analyst' AND triggered_by = 'triage_suspicious'
       )::BIGINT                                             AS by_triage_suspicious,
       count(*) FILTER (
           WHERE emitter = 'analyst' AND triggered_by = 'deterministic_signal'
       )::BIGINT                                             AS by_deterministic_signal
FROM helena_analytical_assessment
GROUP BY tenant, sensor;


-- helena_analytical_retrieval_metrics: cache hit against live query, per source,
-- and what the live queries cost in failures.
--
-- Layer:    analytical
-- Object:   VIEW (plain). Read as numbers; nothing streams or joins from it.
-- Reads:    helena_analytical_assessment, helena_analytical_assessment_retrieval
-- Read by:  src/helena/status.py -- `StatusStore.retrievals` -- and
--           tests/test_status.py.
--
-- `concept/07-principles.md`, "Caching": *"the retrieval trace records, per
-- result, whether it was a cache hit or a live query, and the retrieval time of
-- the underlying record. Two runs that differ only in cache state must be
-- distinguishable afterwards."* `helena_analytical_run_metrics` already sums
-- both per model, which is the ratio `concept/07` asks for. This view is the
-- same trace cut by **source**, which is the cut an operator acts on: a cache
-- hit ratio is a property of a provider's traffic, not of a model's.
--
-- It also carries the two things the assessment row cannot: the **typed
-- retrieval failure** (`helena.enrichment.QUERY_FAILURE_REASONS`), which is a
-- query that did not complete and is never `no_match`, and `oldest_retrieved_at`
-- -- the age of the underlying record a cache hit served, which is the staleness
-- of the analyst tier the way `helena_reference_feed_staleness` is the staleness
-- of the enrichment tier.
--
-- `answered` counts steps that produced an evidence row. `answered` and
-- `failures` are exclusive and exhaustive by the contract
-- (`helena.contracts.v1.RetrievalStep`), and `helena.status.RetrievalMetrics`
-- refuses a row where they do not add up to `steps` rather than reporting a
-- third state nobody named.
--
-- The join to the assessment is what supplies tenant and sensor: the trace table
-- carries neither, because a child row's identity is its parent's.
CREATE VIEW helena_analytical_retrieval_metrics AS
SELECT run.tenant,
       run.sensor,
       run.emitter,
       step.source_id,
       count(*)::BIGINT                                              AS steps,
       count(*) FILTER (WHERE step.outcome = 'cache_hit')::BIGINT    AS cache_hits,
       count(*) FILTER (WHERE step.outcome = 'live_query')::BIGINT   AS live_queries,
       count(*) FILTER (WHERE step.evidence_id IS NOT NULL)::BIGINT  AS answered,
       count(*) FILTER (WHERE step.failure_reason IS NOT NULL)::BIGINT AS failures,
       min(step.retrieved_at)                                        AS oldest_retrieved_at,
       max(step.retrieved_at)                                        AS newest_retrieved_at
FROM helena_analytical_assessment_retrieval step
JOIN helena_analytical_assessment run
  ON run.assessment_id = step.assessment_id
GROUP BY run.tenant, run.sensor, run.emitter, step.source_id;


-- helena_analytical_pipeline_reconciliation: contexts, assessments and messages,
-- per deployment.
--
-- Layer:    analytical
-- Object:   VIEW (plain), and it could not be a materialized one: it reads
--           helena_analytical_emission_counts, which stands on
--           helena_analytical_sink, which cannot be the source of a streaming
--           job (sql/migrations/0019's head has the measurement and the reason).
-- Reads:    helena_signal_host_context, helena_analytical_assessment,
--           helena_analytical_emission_counts
-- Read by:  src/helena/status.py -- `StatusStore.pipeline`, which joins it
--           to helena_ingest_ledger and to the capture files to make the whole
--           chain one object -- and tests/test_status.py.
--
-- The signal-and-analytical half of the reconciliation
-- `concept/07-principles.md` asks for. The source half is `helena_ingest_ledger`
-- above and the capture count is not in the engine at all; the head of this file
-- says why the three cannot be one view, and `helena.status` is where they meet.
--
-- **`contexts` reads the unbounded aggregate, not the retained one**, which is
-- the same call `helena_signal_retention_rejections` makes and for the same
-- reason: a reconciliation over the retained view would silently stop counting
-- what the retention boundary took, and "records that went missing" would look
-- identical to "records that aged out". `helena_signal_retention_rejections` is
-- the view that says which of the two it was, and `helena status` prints them
-- next to each other.
--
-- **`context_records` is not expected to equal `normalized`.** It is the sum of
-- `flow_count`, so it counts normalized events that reached a context; an event
-- with no `ip` layer or an unparseable `ts` produces a flatten row the tumble
-- drops and is in neither. The head of this file has the case; the difference is
-- `helena.status.PipelineReconciliation.unaggregated` and it is reported rather
-- than raised.
--
-- The identity key is a UNION of both sides rather than a join from either, so a
-- deployment that has contexts and no assessments and one that has assessments
-- whose contexts have aged out both get a row. A missing row would read as a
-- deployment that does not exist.
CREATE VIEW helena_analytical_pipeline_reconciliation AS
SELECT deployment.tenant,
       deployment.sensor,
       coalesce(contexts.contexts, 0)::BIGINT         AS contexts,
       coalesce(contexts.context_records, 0)::BIGINT  AS context_records,
       coalesce(assessed.assessments, 0)::BIGINT      AS assessments,
       coalesce(assessed.assessed_contexts, 0)::BIGINT AS assessed_contexts,
       coalesce(emission.pending, 0)::BIGINT          AS emittable
FROM (
    SELECT tenant, sensor FROM helena_signal_host_context
    UNION
    SELECT tenant, sensor FROM helena_analytical_assessment
) deployment
LEFT JOIN (
    SELECT tenant,
           sensor,
           count(*)::BIGINT        AS contexts,
           sum(flow_count)::BIGINT AS context_records
    FROM helena_signal_host_context
    GROUP BY tenant, sensor
) contexts
       ON contexts.tenant = deployment.tenant
      AND contexts.sensor = deployment.sensor
LEFT JOIN (
    SELECT tenant,
           sensor,
           count(*)::BIGINT                   AS assessments,
           count(DISTINCT context_id)::BIGINT AS assessed_contexts
    FROM helena_analytical_assessment
    GROUP BY tenant, sensor
) assessed
       ON assessed.tenant = deployment.tenant
      AND assessed.sensor = deployment.sensor
LEFT JOIN helena_analytical_emission_counts emission
       ON emission.tenant = deployment.tenant
      AND emission.sensor = deployment.sensor;
