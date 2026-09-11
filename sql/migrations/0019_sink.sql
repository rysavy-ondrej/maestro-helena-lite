-- 0019  The sink view: the enriched context, the terminal verdict, the cited evidence.
--
-- `concept/03-architecture.md`, the Components table:
--
--   *"**Sink** | A sink over a view joining the enriched context, the terminal
--   verdict and the cited evidence"*
--
-- and, for what the view has to be able to supply, the Interfaces section:
--
--   *"The message carries context identity and version, host and window, the
--   entity rows with their traffic characteristics and enrichment evidence (with
--   `no_match`, `stale`, `failed` and `missing` distinguishable), the verdict and
--   its path, the citations, the retrieval and disclosure trace, and the full
--   version set."*
--
-- This file is the join. `src/helena/sink.py` is what assembles a message out of
-- it, and the four child tables of 0018 supply the lists that do not fan out per
-- entity (gaps, patterns, the retrieval trace, the disclosure ledger).
--
-- ## The grain is (terminal run x entity x source), and the left side is the run
--
-- One row per enrichment fact about one entity of the context one terminal run
-- assessed. Every join below it is a LEFT JOIN and the assessment row is the left
-- side, so a run whose context has no entities -- or whose context version the
-- store no longer holds -- still produces exactly one row. That is not a
-- convenience: `concept/03` requires **every** assessed context to be emitted,
-- *"including `normal` verdicts and typed failures"*, and an INNER JOIN anywhere
-- in this view would silently drop the runs with the least to say.
--
-- ## Which row of a pass is the terminal one
--
-- A pass over one context snapshot writes one triage row and, where it escalated,
-- a second analyst row (0018). `concept/03`: *"A context that was escalated is
-- emitted **once**, carrying the analyst's verdict and the triage decision that
-- led to it."* So the terminal run is the analyst's where one exists and triage's
-- otherwise, and the triage row is carried beside it under `triage_` names rather
-- than as a second emitted row.
--
-- The selection is the self LEFT JOIN `analyst_run` plus the predicate at the
-- bottom, which reads: keep the analyst row, or keep the triage row when there is
-- no analyst row over the same `(tenant, sensor, context_id, context_version)`.
-- Task 44's supersede is what makes that total -- after any completed store a
-- snapshot holds one triage row and at most one analyst row -- and it is also why
-- `helena.orchestration.RUNS_OF_A_PASS` is the enumeration this predicate is a
-- restatement of, in SQL, over rows rather than over identifiers.
--
-- ## The context is joined at the version the run recorded, or not at all
--
-- `context_version` is a digest over the context's own counters
-- (`sql/migrations/0009`), so a window that gained a late record has a different
-- version under the same `context_id`. Joining on the id alone would let a
-- message show a later version's entities beside an earlier version's verdict --
-- precisely the way this view, which duplicates state by construction, can come
-- to disagree with the rows it duplicates. So the join carries
-- `ctx.context_version = terminal.context_version`, and `context_resolved` says
-- which of the two happened: TRUE where the store still holds the exact snapshot
-- that was assessed, FALSE where it does not and the entity columns are therefore
-- all NULL. A consumer that cannot tell those apart would read "the host
-- contacted nothing" off a context that has simply moved on.
--
-- ## Four kinds of absence, and a fifth this view adds
--
-- `concept/instruction.md` §2: *"`stale`, `failed`, `missing` and `no_match` are
-- four different things, and a typed error is a fifth. Never collapse them, at
-- any layer, for any reason."* They arrive here as two independent columns off
-- `helena_analytical_enriched_context`, and nothing below merges them:
--
--   status                  ok / stale / failed / missing -- the state of the
--                           SOURCE for this window
--   evidence_classification the claim, or `no_match` where a snapshot was
--                           consulted and said nothing, or NULL where there was
--                           no snapshot to consult
--
-- The fifth is `status IS NULL`, which this view introduces and the enriched
-- context cannot: **no source has ever been asked at all**. The enriched context
-- CROSS JOINs the snapshot ledger, so on a deployment where no feed has ever
-- loaded it yields no rows whatever, and this view's LEFT JOIN turns that into an
-- entity row with no enrichment rather than into a context with no entities.
-- `missing` is a source that was asked for and has no snapshot valid at the
-- window; NULL is a deployment that has asked for none.
--
-- ## `cited_as`, and what it is not
--
-- The third thing `concept/03` names is *"the cited evidence"*, and it is the
-- LEFT JOIN onto 0018's `(assessment, evidence, role)` rows: `cited_as` is the
-- role the terminal outcome gave THIS evidence row, or NULL where it cited it
-- not at all. It is a denormalization of the citation table and not a second
-- record of it -- `helena.sink` reads the citation rows themselves for the
-- message's citation list, because a citation may resolve to analyst-tier
-- evidence (0017), which is not in the enriched context and therefore has no row
-- here to be marked on.
--
-- ## VIEW, and it could not be a SINK's direct source
--
-- Measured on the pinned engine, 2026-09-11: `CREATE MATERIALIZED VIEW ... AS
-- SELECT ... FROM helena_analytical_enriched_context` is rejected with *"Bind
-- error: failed to bind view helena_analytical_enriched_context"*, because that
-- view derives `status` from `now()` and a streaming query rejects `now()`
-- outside a WHERE clause (`sql/migrations/0009`, 3. in its head, measured the
-- same thing for `completeness`). Everything downstream of the enriched context
-- is therefore a batch read, this view included -- so emission (task 47) is
-- deterministic code reading this view and producing over the Kafka wire
-- protocol, not `CREATE SINK`. The engine-side count `concept/03` asks for
-- (*"a count of rows the sink view produced"*) is a batch `SELECT` over it.


-- helena_analytical_sink: one row per (terminal run, entity, source).
--
-- Layer:    analytical. It reads the analytical layer as well as the signal one,
--           which is new: the assessment rows and the enriched context are both
--           analytical, and there is nowhere else for a verdict-and-evidence join
--           to read them from. `concept/instruction.md` §2 states the invariant
--           as "an analytical view never reads the flatten layer or the source
--           directly" and says nothing against reading its own layer, which is
--           the same latitude `signal` and `reference` already have in
--           `helena.migrations.MAY_READ`.
--           `docs/decisions/0036-the-output-message.md` §3 records the change.
-- Object:   VIEW (plain), and it could not be a materialized one -- see the head.
--           It is read once per emitted message rather than joined from, and
--           materializing a join of every entity against every source against
--           every assessment would pay continuously for rows that are read once
--           and then leave the system.
-- Reads:    helena_analytical_assessment, helena_analytical_assessment_citation,
--           helena_analytical_enriched_context, helena_signal_host_context_live,
--           helena_signal_context_entities
-- Read by:  src/helena/sink.py -- `SinkStore.project`, which assembles the
--           emitted message out of it, and `SinkStore.pending`, which counts the
--           rows it produced -- and tests/test_sink.py.
CREATE VIEW helena_analytical_sink AS
SELECT
       -- --- The terminal run: what is emitted, and what identifies it ---------
       terminal.assessment_id,
       terminal.tenant,
       terminal.sensor,
       terminal.host,
       terminal.context_id,
       terminal.context_version,
       terminal.window_start,
       terminal.window_end,
       terminal.emitter,
       terminal.triggered_by,
       terminal.assessed_at,
       -- `concept/02`'s two terminal outcomes, as the word rather than as the
       -- absence of a column. `helena.orchestration.VERDICT` / `TYPED_FAILURE`.
       CASE WHEN terminal.classification IS NOT NULL THEN 'verdict'
            ELSE 'typed_failure' END                  AS outcome_kind,
       -- The verdict is the root of the path and is not stored as a column
       -- (0018's head): one fact, derived where it is read.
       split_part(terminal.classification, '.', 1)    AS verdict,
       terminal.classification,
       terminal.confidence,
       terminal.narrative,
       terminal.failure_reason,
       terminal.failure_detail,

       -- --- The full version set, plus what was asked for -------------------
       terminal.model_version,
       terminal.model_requested,
       terminal.prompt_version,
       terminal.schema_version,
       terminal.rendering_version,
       terminal.taxonomy_version,
       terminal.enrichment_snapshot_version,
       terminal.normalization_snapshot_version,
       terminal.policy_version,
       terminal.aggregation_version,

       -- --- The path: the triage decision that led to the terminal one -------
       -- NULL in every column when the terminal run IS the triage run, which is
       -- the ordinary case; a consumer reads `emitter` to tell the two apart
       -- rather than inferring it from a NULL.
       triage_run.assessment_id                       AS triage_assessment_id,
       triage_run.triggered_by                        AS triage_triggered_by,
       CASE WHEN triage_run.assessment_id IS NULL THEN NULL
            WHEN triage_run.classification IS NOT NULL THEN 'verdict'
            ELSE 'typed_failure' END                  AS triage_outcome_kind,
       split_part(triage_run.classification, '.', 1)  AS triage_verdict,
       triage_run.classification                      AS triage_classification,
       triage_run.confidence                          AS triage_confidence,
       triage_run.failure_reason                      AS triage_failure_reason,
       triage_run.failure_detail                      AS triage_failure_detail,
       triage_run.assessed_at                         AS triage_assessed_at,
       triage_run.model_version                       AS triage_model_version,
       triage_run.prompt_version                      AS triage_prompt_version,

       -- --- The context at the version that was assessed ---------------------
       ctx.context_id IS NOT NULL                     AS context_resolved,
       ctx.flow_count                                 AS context_flow_count,
       ctx.duration_seconds                           AS context_duration_seconds,
       ctx.bytes_sent                                 AS context_bytes_sent,
       ctx.bytes_received                             AS context_bytes_received,
       ctx.packets_sent                               AS context_packets_sent,
       ctx.packets_received                           AS context_packets_received,

       -- --- The entity and its traffic characteristics -----------------------
       -- From the signal layer and not from the enriched context, for the reason
       -- `src/helena/rendering/__init__.py` gives at length: the enriched
       -- context's entity list is gated on the snapshot ledger, so a message that
       -- took its entities from there would show a host that contacted nothing on
       -- a deployment whose only fault is that no feed has run yet.
       entity.entity_type,
       entity.entity_value,
       entity.observed_as_flow_destination,
       entity.observed_in_dns_query,
       entity.observed_in_dns_response,
       entity.observed_in_tls,
       entity.observed_in_http,
       entity.observed_flow_count,
       entity.observed_bytes_sent,
       entity.observed_bytes_received,
       entity.observed_packets_sent,
       entity.observed_packets_received,

       -- --- The enrichment evidence, with the four absences intact ------------
       enriched.source_id,
       enriched.evidence_id,
       enriched.source_tier,
       enriched.evidence_tier,
       enriched.snapshot_version,
       enriched.snapshot_loaded_at,
       enriched.status,
       enriched.classification                        AS evidence_classification,
       enriched.taxonomy_version                      AS evidence_taxonomy_version,
       enriched.confidence                            AS evidence_confidence,
       enriched.scope_type,
       enriched.scope_value,
       enriched.first_seen,
       enriched.last_seen,
       -- Retrieved external text, carried verbatim. See
       -- `docs/decisions/0036-the-output-message.md` §5: this is one of the three
       -- things that make the payload inherit a redaction obligation.
       enriched.native_evidence,
       enriched.port_matched,

       -- --- The cited evidence -----------------------------------------------
       cited.role                                     AS cited_as

FROM helena_analytical_assessment terminal
LEFT JOIN helena_analytical_assessment analyst_run
       ON analyst_run.tenant = terminal.tenant
      AND analyst_run.sensor = terminal.sensor
      AND analyst_run.context_id = terminal.context_id
      AND analyst_run.context_version = terminal.context_version
      AND analyst_run.emitter = 'analyst'
LEFT JOIN helena_analytical_assessment triage_run
       ON triage_run.tenant = terminal.tenant
      AND triage_run.sensor = terminal.sensor
      AND triage_run.context_id = terminal.context_id
      AND triage_run.context_version = terminal.context_version
      AND triage_run.emitter = 'triage'
      -- Only where the terminal run is the analyst's. Where triage IS the
      -- terminal run, the path columns would be a second copy of the columns
      -- beside them.
      AND terminal.emitter = 'analyst'
LEFT JOIN helena_signal_host_context_live ctx
       ON ctx.tenant = terminal.tenant
      AND ctx.sensor = terminal.sensor
      AND ctx.context_id = terminal.context_id
      AND ctx.context_version = terminal.context_version
LEFT JOIN helena_signal_context_entities entity
       ON entity.tenant = ctx.tenant
      AND entity.sensor = ctx.sensor
      AND entity.context_id = ctx.context_id
LEFT JOIN helena_analytical_enriched_context enriched
       ON enriched.tenant = entity.tenant
      AND enriched.sensor = entity.sensor
      AND enriched.context_id = entity.context_id
      AND enriched.entity_type = entity.entity_type
      AND enriched.entity_value = entity.entity_value
LEFT JOIN helena_analytical_assessment_citation cited
       ON cited.assessment_id = terminal.assessment_id
      AND cited.evidence_id = enriched.evidence_id
WHERE terminal.emitter = 'analyst'
   OR analyst_run.assessment_id IS NULL;
