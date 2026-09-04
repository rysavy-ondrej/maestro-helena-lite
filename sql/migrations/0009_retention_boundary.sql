-- 0009  The retention boundary, completeness, and the version a citation pins.
--
-- `concept/07-principles.md`, "Retention and replay", is the whole of what this
-- file implements, and it is four sentences:
--
--   * **Engine-side retention is a temporal filter**, not a delete: a predicate
--     on the context views, declarative and engine-enforced.
--   * **The retention horizon is also the late-record tolerance** -- one
--     parameter, not two, because a record arriving after its window's raw
--     records are gone cannot revise anything.
--   * **The boundary must report what it drops**, so a misconfigured horizon
--     shows up as a rejection rate rather than as missing evidence nobody knows
--     is missing.
--   * **A context cited by a finding is copied out, never evicted** -- freezing
--     before eviction is what makes a citation stable rather than merely
--     current.
--
-- and `concept/02-concepts-and-taxonomy.md` adds the fifth: **completeness is
-- `open` or `provisional`, and neither value is "final"** -- a context never
-- reaches a state where it cannot change while its raw records are retained.
--
-- ## One horizon, and what it costs
--
-- `helena_retention_horizon` declares it once and `INTERVAL '24 hours'` appears
-- a second time in the predicate of `helena_signal_host_context_retained`,
-- because a streaming query cannot read a view: `CROSS JOIN
-- helena_aggregation_version` is rejected as a "streaming nested-loop join"
-- (measured in sql/migrations/0002_aggregation_version.sql, and the same
-- refusal applies here). Two copies of a constant that can drift are worse than
-- none, so `tests/test_context.py` reads what the engine holds for **both** --
-- `helena_retention_horizon` and the definition RisingWave stored for the
-- retained view, out of `rw_catalog` -- and asserts them equal to each other and
-- to `helena.context.RETENTION_HORIZON`. Comparing against the catalogue rather
-- than against this file is deliberate: grepping the .sql would find the value in
-- the comment that explains it.
--
-- **24 hours is a candidate, not a decision.** `concept/08-open-questions.md`
-- records the horizon as unset and now empirical -- "a candidate can be observed
-- in the rejection counter before it is committed to" -- and that is exactly what
-- `helena_signal_retention_rejections` below is for. Changing it is a new
-- migration that drops and recreates every object here, never an edit to this
-- file: the runner refuses an applied file whose checksum changed
-- (docs/decisions/0007-sql-migrations.md).
--
-- **The consequence, said out loud: over this repository's fixtures the retained
-- views are empty.** Every record in `data/ingest/flow-sample.jsonl` and in
-- `tests/fixtures/captures/` is dated 2024-06-01, so its windows are far outside
-- any horizon a prototype would set, and the tests that exercise these views put
-- a real record through the real normalizer with its `ts` re-stamped -- the same
-- technique tasks 12-15 used for a case the sample cannot reach. The same
-- consequence holds for a deployment: **replaying an archived capture produces
-- contexts the boundary does not show.** They are in
-- `helena_signal_host_context` -- retention is a filter, not a delete, and
-- nothing here deletes a row -- and a replay validating a stored assessment
-- reads the frozen copy it cited, not the live view.
--
-- ## What was measured against RisingWave 3.0.3, and what it forced
--
-- Four measurements, all made before this file was written, all reproducible by
-- the tests that came with it:
--
--   1. **A temporal filter in a materialized view over the context aggregate is
--      accepted, and it really evicts.** A context whose `window_end` was 277.6 s
--      old, under a probe view with a 283-second horizon, was present at
--      creation and **gone 5 seconds after the horizon passed**, while the row
--      stayed in `helena_signal_host_context`. So the boundary is enforced by the
--      engine as the clock advances, not only at read time.
--      (`test_a_context_leaves_the_retained_view_when_its_window_passes_the_horizon`.)
--   2. **A late record inside the boundary still revises under a temporal
--      filter.** `concept/08-open-questions.md` lists this as untested and not to
--      be inferred; it is now measured rather than inferred. A second capture
--      observing the same window folded into the retained view's row exactly as
--      it folds into the base aggregate: 1 flow / 77 octets became 2 / 1380,
--      through the filter.
--      (`test_a_late_record_inside_the_boundary_still_revises_through_the_filter`.)
--   3. **`now()` is refused everywhere but `WHERE`, `HAVING`, `ON` and `FROM` in
--      a streaming query.** `CASE WHEN window_end > now() ...` in the select list
--      of a materialized view is rejected outright ("For streaming queries,
--      `NOW()` function is only allowed in ..."). That is why `completeness` is
--      on a plain view and cannot be on a materialized one -- it is not a
--      preference, it is the only place the engine allows it.
--   4. **A batch query over a plain view evaluates `now()` per read**, so the
--      completeness of a row is a property of when it was read, and the
--      rejection counter is a rate as of the moment it was asked.
--
-- ## Completeness: two values, and no way to write a third
--
--   `open`        the window has not closed yet -- `window_end > now()`. More
--                 records for it are expected in the ordinary course.
--   `provisional` the window has closed and the context is still inside the
--                 boundary, so a late record can still revise it.
--
-- There is no `final`, and there is nowhere to put one: the column is a two-branch
-- `CASE` in a view nothing writes to, so the domain is structural rather than a
-- constraint someone has to remember. A context does not become final; it leaves
-- the retained view. `tests/test_context.py` asserts the domain over rows in both
-- states and fails on any third value.
--
-- ## Two identities on the row, and what each one is for
--
-- `context_id` is the **identity**: tenant, sensor, host, window start and
-- aggregation version, and it does not change when a late record revises the
-- context. That was settled on 2026-09-04 against the engine's real behaviour
-- (`concept/07-principles.md`, and sql/migrations/0006_host_context.sql argues
-- it at length) -- an incrementally maintained view edits the counters in place.
--
-- `context_version` is the **version of the values**: a digest over the context
-- id and the six statistics. A revision leaves the id alone and mints a new
-- version, so "a revised context is a new version rather than an edit in place"
-- is true of the thing a citation records, while the identity stays stable. The
-- two together are what makes a citation resolvable: `(context_id,
-- context_version)` names a host and window *and* the numbers that were seen.
-- `tests/test_context.py` revises a context and asserts exactly that -- the id
-- unchanged, the version different.
--
-- The digest is the length-prefixed construction the event id and the context id
-- already use (docs/decisions/0011-event-identity-and-the-event-id.md): every
-- part is written as `<utf8 byte length>:<bytes>`, because a separator can occur
-- inside a value and two different rows must not hash to the same bytes.
-- `duration_seconds` goes in as the engine's rendering of a DOUBLE PRECISION,
-- which is the one part of this digest that is a property of the engine rather
-- than of the data; the test recomputes it from the same rendering, so what it
-- checks is the composition and the column set rather than float formatting.
--
-- `completeness` is deliberately **not** in the digest. It is a function of the
-- clock, not of the aggregation: the same numbers read a minute apart would
-- otherwise carry two versions and a citation would look revised when nothing
-- had changed.
--
-- ## What this file does not do
--
-- **Entity rows are bounded but not frozen.** `helena_signal_context_entities_
-- retained` follows the context boundary by construction (it joins it), so an
-- entity row cannot outlive the context it belongs to. There is no frozen copy
-- of an entity row, because what a finding cites is decided by the finding
-- contract and there is no finding contract yet (prd D4/D5). Deferred, and it
-- still says deferred.
--
-- **Nothing calls the freeze yet.** `helena_frozen_context` is written by
-- `helena.context.ContextStore.freeze`, and its caller -- the code that issues a
-- finding -- does not exist. What is demonstrated here is that a frozen copy
-- survives a revision of the context it was taken from, which is the property
-- the citation rule is about; that a finding takes one at the right moment is
-- not demonstrated by anything and is not claimed.


-- helena_retention_horizon: the declared retention horizon, once.
--
-- Layer:    reference. Not a view over data -- one constant, one row.
-- Object:   plain VIEW, for the reasons sql/migrations/0002_aggregation_version.sql
--           gives for the aggregation version: there is no state here, a table
--           would be state nobody maintains and an UPDATE could rewrite it under
--           rows that already recorded it, and a materialized view would be disk
--           for a literal.
-- Reads:    nothing.
-- Read by:  helena_signal_retention_rejections below (a batch view may read it;
--           a streaming one may not), helena.context.ContextStore.rejections
--           through that view, and tests/test_context.py, which asserts it
--           equals helena.context.RETENTION_HORIZON and equals the interval the
--           engine holds in the retained view's own definition.
CREATE VIEW helena_retention_horizon AS
SELECT INTERVAL '24 hours' AS retention_horizon;


-- helena_signal_host_context_retained: the contexts inside the retention boundary.
--
-- Layer:    signal. It reads the signal layer's own aggregate, the way
--           sql/migrations/0007_context_entities.sql joins it; the flatten layer
--           and the source stay behind helena_signal_host_context.
-- Object:   MATERIALIZED VIEW. This is the boundary itself: a temporal filter in
--           a materialized view is what makes the engine drop the row's state
--           when the horizon passes (measured -- see 1. above), and a plain view
--           would be a predicate that hides rows while the state behind it grew
--           forever. `concept/06-technology.md` costs the two shapes of retention
--           at ~1.9 bytes per record against 740x that for a connector-backed
--           table; this is the cheap one, and it is only cheap if the state
--           actually goes.
-- Reads:    helena_signal_host_context
-- Read by:  helena_signal_host_context_live, helena_signal_context_entities_retained,
--           and tests/test_context.py. The enriched-context view (D3) reads the
--           live view above it rather than this one.
--
-- The predicate is on `window_end` rather than `window_start`: the boundary is
-- about how old the *window* is, and a five-minute window whose start has just
-- passed the horizon still had records arriving into it a moment ago.
--
-- `INTERVAL '24 hours'` is the second copy of the horizon (see the head of this
-- file). It is a literal because a streaming query cannot read
-- helena_retention_horizon, and the two are asserted equal against the engine.
CREATE MATERIALIZED VIEW helena_signal_host_context_retained AS
SELECT context_id,
       tenant,
       sensor,
       host,
       window_start,
       window_end,
       flow_count,
       duration_seconds,
       bytes_sent,
       bytes_received,
       packets_sent,
       packets_received,
       aggregation_version
FROM helena_signal_host_context
WHERE window_end > now() - INTERVAL '24 hours';


-- helena_signal_host_context_live: the citable row -- a retained context, its
-- completeness as of this read, and the version of its values.
--
-- Layer:    signal
-- Object:   plain VIEW, and it could not be a materialized one: `now()` outside
--           a WHERE clause is rejected in a streaming query (measured -- 3. in
--           the head of this file), and `completeness` is a `CASE` over `now()`.
--           `context_version` sits here rather than on the retained view for a
--           reason of its own: one object defines what a citation pins, so the
--           version and the completeness a frozen copy records come from one
--           place.
-- Reads:    helena_signal_host_context_retained
-- Read by:  helena.context.ContextStore.freeze, which copies a row of it into
--           helena_frozen_context, and tests/test_context.py. The enriched-context
--           view (D3) is the next reader.
CREATE VIEW helena_signal_host_context_live AS
SELECT c.context_id,
       encode(
           sha256(
               convert_to(
                   octet_length(c.context_id)::VARCHAR || ':' || c.context_id
                   || octet_length(c.flow_count::VARCHAR)::VARCHAR
                   || ':' || c.flow_count::VARCHAR
                   || octet_length(c.duration_seconds::VARCHAR)::VARCHAR
                   || ':' || c.duration_seconds::VARCHAR
                   || octet_length(c.bytes_sent::VARCHAR)::VARCHAR
                   || ':' || c.bytes_sent::VARCHAR
                   || octet_length(c.bytes_received::VARCHAR)::VARCHAR
                   || ':' || c.bytes_received::VARCHAR
                   || octet_length(c.packets_sent::VARCHAR)::VARCHAR
                   || ':' || c.packets_sent::VARCHAR
                   || octet_length(c.packets_received::VARCHAR)::VARCHAR
                   || ':' || c.packets_received::VARCHAR,
                   'UTF8'
               )
           ),
           'hex'
       )                                                       AS context_version,
       CASE WHEN c.window_end > now() THEN 'open' ELSE 'provisional' END
                                                               AS completeness,
       c.tenant,
       c.sensor,
       c.host,
       c.window_start,
       c.window_end,
       c.flow_count,
       c.duration_seconds,
       c.bytes_sent,
       c.bytes_received,
       c.packets_sent,
       c.packets_received,
       c.aggregation_version
FROM helena_signal_host_context_retained c;


-- helena_signal_context_entities_retained: the entity rows of retained contexts.
--
-- Layer:    signal
-- Object:   MATERIALIZED VIEW, for the same reason as the retained context: an
--           entity row's state has to go when its context's does, and a plain
--           view would hide the rows while keeping them.
-- Reads:    helena_signal_context_entities, helena_signal_host_context_retained
-- Read by:  tests/test_context.py, and the enriched-context view (D3), which is
--           what the entity rows exist for.
--
-- The boundary is taken **by joining the retained context** rather than by
-- repeating the temporal predicate on the entity row's own `window_end`. That is
-- the lesson sql/migrations/0007_context_entities.sql already records about the
-- window interval: a second copy of the constant is a second thing to bump, and
-- a drifted copy produces plausible wrong rows. Here there is no second copy at
-- all -- an entity row is inside the boundary exactly when its context is, by
-- construction. The join is an equi-join on the whole context key, which
-- RisingWave plans (task 14 measured that an equi-join to this aggregate is
-- accepted where a cross join is not).
CREATE MATERIALIZED VIEW helena_signal_context_entities_retained AS
SELECT e.context_id,
       e.tenant,
       e.sensor,
       e.host,
       e.window_start,
       e.window_end,
       e.entity_type,
       e.entity_value,
       e.fingerprint_algorithm,
       e.observed_as_flow_destination,
       e.observed_in_dns_query,
       e.observed_in_dns_response,
       e.observed_in_tls,
       e.observed_in_http,
       e.observed_flow_count,
       e.observed_bytes_sent,
       e.observed_bytes_received,
       e.observed_packets_sent,
       e.observed_packets_received,
       e.aggregation_version
FROM helena_signal_context_entities e
JOIN helena_signal_host_context_retained r
  ON e.tenant = r.tenant
 AND e.sensor = r.sensor
 AND e.context_id = r.context_id;


-- helena_signal_retention_rejections: what the boundary drops, per identity.
--
-- Layer:    signal
-- Object:   plain VIEW. It reads `now()` in an aggregate filter, which a
--           streaming query refuses, and it is asked for a number rather than
--           joined from -- the same call helena_ingest_counts and
--           helena_ingest_quarantine_counts make.
-- Reads:    helena_signal_host_context, helena_retention_horizon
-- Read by:  helena.context.ContextStore.rejections, and tests/test_context.py.
--
-- **It reads the unbounded aggregate on purpose.** A counter over
-- helena_signal_host_context_retained could only ever report zero: the rows it
-- would have to count are the ones that view exists to remove. This is the one
-- place the base aggregate is read instead of the retained one, and that is what
-- makes "the boundary reports what it drops" possible at all.
--
-- **What "rejected" means here, exactly.** No record is refused at ingestion --
-- `concept/07-principles.md` has no watermark on the flow source, and a record is
-- admitted on arrival regardless of its event time. What the boundary drops is a
-- *context*: a window old enough that nothing downstream will see it, and the
-- records credited to that window with it. So the numerator is
-- `records_outside_boundary` -- flows credited to contexts outside the horizon --
-- and it is counted by the age of the window, not by when the record arrived.
-- There is no arrival time to count by: `sql/migrations/0004_normalized_events.sql`
-- deliberately stores none, because when a record arrived is a property of an
-- ingest run and would break replay idempotence. A record that arrives late into
-- a window that is still inside the boundary is not a rejection and is not
-- counted here -- it revises its context, which is measured
-- (`test_a_late_record_inside_the_boundary_still_revises_through_the_filter`).
--
-- `retention_horizon` is on the row so that a rejection rate carries the horizon
-- it was measured against; a rate without the parameter it measures is a number
-- nobody can act on.
--
-- There is no rate column. The division belongs where the "no rate over no
-- records" rule can be enforced -- `helena.context.RetentionRejections.rate`
-- raises when nothing was read, because 0.0 would read as "nothing was dropped"
-- when the truth is "nothing was aggregated". That is the same call
-- `QuarantineCounts.rate` makes (task 09), and the two behave the same way on
-- purpose.
CREATE VIEW helena_signal_retention_rejections AS
SELECT c.tenant,
       c.sensor,
       h.retention_horizon,
       count(*)::BIGINT                                        AS contexts,
       count(*) FILTER (
           WHERE c.window_end <= now() - h.retention_horizon
       )::BIGINT                                               AS contexts_outside_boundary,
       sum(c.flow_count)::BIGINT                               AS records,
       coalesce(
           sum(c.flow_count) FILTER (
               WHERE c.window_end <= now() - h.retention_horizon
           ),
           0
       )::BIGINT                                               AS records_outside_boundary
FROM helena_signal_host_context c
CROSS JOIN helena_retention_horizon h
GROUP BY c.tenant, c.sensor, h.retention_horizon;


-- helena_frozen_context: the copy-out. A cited context, kept as it was cited.
--
-- Layer:    signal (a stored row, not a view over one).
-- Object:   TABLE, in the one store. It is the only object here that holds a row
--           the engine would otherwise take away -- which is the point: "a
--           context cited by a finding is copied out, never evicted"
--           (`concept/07-principles.md`), and a copy that lived in a view would
--           evict with what it copied.
-- Written by: helena.context.ContextStore.freeze, as INSERT ... SELECT from
--           helena_signal_host_context_live -- the engine does the copy, and a
--           context that has already left the boundary inserts nothing, which
--           the writer turns into a typed refusal rather than a silent no-op.
-- Read by:  helena.context.ContextStore.frozen and tests/test_context.py. The
--           reader that matters is replay, which resolves a citation against the
--           frozen copy rather than against the live view.
--
-- **The key is (identity, context_id, context_version), and that is the whole
-- design.** Freezing the same unchanged context twice writes the same key and is
-- an upsert of an identical row, so a finding issued twice against an unrevised
-- context does not accumulate copies. Freezing after a revision writes a
-- *different* version and keeps both: the numbers the first citation saw stay
-- exactly as they were beside the numbers the second one saw. A revision
-- therefore produces a new version here rather than editing what an existing
-- citation resolves to.
--
-- **`completeness` is recorded and is never `final`.** A frozen copy is stable,
-- not complete: it says what the context was when it was cited, and the live
-- context may still revise. Recording it is what keeps a reader from mistaking a
-- frozen row for a closed one.
--
-- **There is no `frozen_at` column**, and its absence is the same decision
-- `sql/migrations/0003_ingest_quarantine.sql` made about `quarantined_at`. Every
-- column here is derived from the context, so freezing the same context under
-- the same identity twice produces a byte-identical row and replay reproduces it;
-- a timestamp would make the row a fact about a run rather than about a context,
-- and under an upsert it would silently come to mean "the last time this was
-- frozen". When a finding exists, *when* it was issued is a property of the
-- finding.
CREATE TABLE IF NOT EXISTS helena_frozen_context (
    tenant            VARCHAR,
    sensor            VARCHAR,
    context_id        VARCHAR,
    context_version   VARCHAR,
    completeness      VARCHAR          NOT NULL,
    host              VARCHAR          NOT NULL,
    window_start      TIMESTAMPTZ      NOT NULL,
    window_end        TIMESTAMPTZ      NOT NULL,
    flow_count        BIGINT           NOT NULL,
    duration_seconds  DOUBLE PRECISION NOT NULL,
    bytes_sent        BIGINT           NOT NULL,
    bytes_received    BIGINT           NOT NULL,
    packets_sent      BIGINT           NOT NULL,
    packets_received  BIGINT           NOT NULL,
    aggregation_version VARCHAR        NOT NULL,
    PRIMARY KEY (tenant, sensor, context_id, context_version)
);
