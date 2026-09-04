-- 0006  The signal layer: one host context per host per five-minute window.
--
-- `concept/03-architecture.md` gives the Context Builder three view layers --
-- flatten -> signal -> analytical -- and this file is the middle one. It reads
-- `helena_flatten_flows` (sql/migrations/0005_flatten_layer.sql) and nothing
-- else: the signal layer reads the flatten layer, and only the flatten layer is
-- allowed to read `helena_normalized_events`.
--
-- What it produces is the object the rest of the system is about.
-- `concept/02-concepts-and-taxonomy.md`: a **host context** is "what one host
-- did in one window: traffic statistics, behavioural features, provenance", and
-- it **carries no verdict**. Everything downstream -- entity extraction, the
-- enrichment join, the triage rendering, a finding's citation -- is about one of
-- these rows.
--
-- ## The window: five-minute tumbling, assigned by the flow's start
--
-- `concept/02-concepts-and-taxonomy.md` defines it: "5-minute tumbling; a flow
-- is assigned by its start time, so a long flow is credited entirely to the
-- window it began in". `TUMBLE(helena_flatten_flows, flow_start, INTERVAL '5
-- minutes')` is exactly that statement -- the window function is given the
-- flow's *start* and nothing else, so a flow of any duration contributes all of
-- its octets and packets to the one window it began in and none to the windows
-- it ran through.
--
-- **The accepted cost, said out loud.** The alternative -- apportioning a flow
-- across the windows it spans -- would make a long transfer visible in every
-- window it touched. Assignment by start time instead means:
--
--   * a long flow makes the window it started in look busier than the traffic
--     that actually crossed the wire in those five minutes, and the windows it
--     ran through look quieter;
--   * two flows a second apart on opposite sides of a boundary land in two
--     different contexts and are never seen together, which is the case
--     `concept/01-goal-and-scope.md`'s "several windows rather than a single
--     hit" is about;
--   * a tumbling window has no overlap, so no context has the whole of a
--     session that straddles a boundary.
--
-- `concept/08-open-questions.md` lists this as an assumption in force whose cost
-- "is measured and accepted", to be revisited "when window coherence can be
-- measured -- which needs the corpus". **That measurement cannot be made here
-- and is not claimed.** What the fixtures can show is only the mechanism, and
-- what they show is that the cost is invisible in them: measured over all 62
-- records of `data/ingest/flow-sample.jsonl`, the longest flow is 110.5 s
-- (`tcp.7`), every flow starts between 21:32:57.8Z and 21:35:08.6Z, and **no
-- sampled flow crosses a window boundary at all** -- so the sample cannot
-- exhibit the cost even in principle. `tests/test_context.py` demonstrates the
-- rule instead with a real record whose duration is lengthened past the
-- boundary, which shows the mechanism and measures nothing about how often it
-- matters. Window coherence stays **unmeasured**, blocked on the corpus
-- (`concept/08-open-questions.md`, the one that blocks everything).
--
-- ## The host key is the source address
--
-- `concept/02-concepts-and-taxonomy.md`: a host is "the subject of an
-- assessment, keyed provisionally by source address". So the group key is
-- `src_address`, and the consequence `concept/08-open-questions.md` records as
-- an accepted assumption falls straight out of it: **a host seen only as a
-- destination gets no context.** In the sample that is 16 of the 17 addresses
-- observed -- one source, sixteen destinations that are never a source -- and
-- exactly one host context per window. DHCP, NAT, roaming and multi-sensor
-- identity get no help from the input and none is invented here.
--
-- There is no `WHERE src_address IS NOT NULL` guard, because
-- `src/helena/normalizer.py::IpObservation` makes `ip.src` required: a record
-- without one is quarantined at ingestion and never becomes an event. A guard
-- here would silently drop a row whose absence is already impossible, which is
-- how a filter becomes the place a contract violation goes to hide.
--
-- ## The counters stay bidirectional
--
-- `concept/07-principles.md` keeps connection statistics bidirectional because
-- direction is signal, and the flatten layer already refuses to sum them. The
-- aggregate keeps the same four columns and adds no total: a host that sent
-- 10 904 octets and received 33 096 is a different thing from one that sent
-- 33 096 and received 10 904, and a `bytes_total` column is where that
-- difference stops being available to the layer above. There is no total column
-- here and there is not meant to be one.
--
-- `flow_count` and `duration_seconds` are the other two statistics: how many
-- flows were credited to this window, and the sum of their durations. The sums
-- are cast to BIGINT because RisingWave's `sum()` over a BIGINT column returns
-- NUMERIC, which reaches a client as a `Decimal` and would make an integral
-- counter arrive as a decimal (measured in task 09 on the quarantine counts).
--
-- ## The context carries no verdict
--
-- `concept/02-concepts-and-taxonomy.md` again: a host context "**carries no
-- verdict**", and `concept/07-principles.md` keeps facts and inference in
-- separate rows -- an inference is appended, never written onto the fact it is
-- about. There is no verdict, classification, confidence, severity or score
-- column below, and `tests/test_context.py` fails if one appears.
--
-- ## Identity, and what a revision does to it
--
-- `context_id` is a digest over the ingestion identity, the host, the window
-- start as epoch seconds, and the aggregation version:
--
--     context_id = sha256( len-prefixed( tenant, sensor, host,
--                                        window_start_epoch, aggregation_version ) )
--
-- The construction is the event id's, deliberately
-- (`docs/decisions/0011-event-identity-and-the-event-id.md`): the parts are
-- length-prefixed rather than joined by a separator, because a tenant is an
-- operator-supplied string and any delimiter can occur inside one, so
-- `tenant='a'/sensor='b:c'` must not hash to the same bytes as
-- `tenant='a:b'/sensor='c'`. Every part survives a replay -- nothing is drawn
-- from a clock, a counter or a `uuid4` -- so replaying a capture into the same
-- deployment reproduces every context id exactly.
--
-- The window start goes in as **epoch seconds**, not as its text rendering: the
-- text of a `timestamptz` depends on the session's `TimeZone` setting, and an
-- identity that changes with a client's session variable is not an identity.
--
-- **The aggregation version IS in the digest, and that is the opposite of the
-- event id, on purpose.** An event id identifies *which record* this is, which
-- does not change when the shape of an event changes, so
-- `EVENT_SCHEMA_VERSION` stays out of it. A context is not a record but a
-- *computation over* records, and the aggregation version is what says which
-- computation: the same host and the same window under a revised aggregation
-- are a different context with different numbers, and giving them one id would
-- make a citation resolve to numbers the cited run never produced. Putting the
-- version in the digest is what makes **a revision of the aggregation a new
-- version rather than an in-place edit** of what an existing id means.
--
-- That rule is structural on the SQL side rather than a convention. Bumping the
-- aggregation version is a NEW migration that drops and recreates this view
-- along with `helena_aggregation_version`; the runner refuses an applied file
-- whose checksum changed (`docs/decisions/0007-sql-migrations.md`), so editing
-- `'v1'` below in place is rejected by the tooling.
--
-- **The other kind of revision is an in-place edit, and this file does not
-- pretend otherwise.** A late record for a window that already has a context
-- makes the engine update that context's row: the counters change and the
-- context id does not. Measured, not inferred -- a second capture ingested
-- after this view existed took window 21:30:00Z from 59 flows / 100 847 octets
-- sent to 60 / 101 659, with the context id unchanged
-- (`tests/test_context.py::test_a_late_record_revises_a_context_in_place`).
-- Two concept notes describe that differently and the disagreement is recorded
-- rather than resolved here: `concept/07-principles.md` says "a revised context
-- is a new version, never an edit in place", while
-- `concept/08-open-questions.md` lists as an assumption in force that "context
-- identity is stable across revisions, so a finding may cite an id whose
-- numbers have changed", to be revisited when findings outlive a retention
-- boundary. This view implements the second, because it is the one that
-- describes what an incrementally maintained view actually does -- the same
-- note calls revision "a property of the engine rather than something the
-- project builds" -- and because freezing a cited context is
-- `concept/07-principles.md`'s own answer to it: "a context cited by a finding
-- is copied out, never evicted". Nothing cites a context yet, so nothing is
-- copied out yet; the increment that issues a finding is where the copy-out
-- belongs. See prds/reports/task-13.json.
--
-- The same upsert is what makes replay idempotent: re-ingesting a capture
-- rewrites byte-identical event rows, and the context is unchanged rather than
-- doubled. Also measured, and also a test.
--
-- ## What is NOT on the row yet
--
-- `completeness` (`open` / `provisional`, and neither of them "final") is a
-- property of the retention boundary and the late-record tolerance, which are
-- one unset parameter (`concept/07-principles.md`); it arrives with retention.
-- The behavioural features are the flow statistics the input supports and
-- nothing more -- `concept/08-open-questions.md` forbids specifying a TCP-state
-- or connection-failure feature, because the input cannot supply one. And there
-- is no capture reference: a window can span captures, so the flows behind a
-- context are found by its key against the flatten layer rather than by a
-- column that would be true only while one capture covers one window.


-- helena_signal_host_context: what one host did in one five-minute window.
--
-- Layer:    signal
-- Object:   MATERIALIZED VIEW. The measured rule beside the layering
--           (`concept/03-architecture.md`) is "do not materialize an
--           intermediate that only feeds an aggregate" -- 42 % more disk for
--           rows nothing reads. This is not that intermediate: it *is* the
--           aggregate, it is the layer's output, it is queried by host and
--           window on its own, and it is the row a finding will cite by
--           `context_id`. A citable row that exists only as a query plan is not
--           a stable evidence identifier.
-- Reads:    helena_flatten_flows
-- Read by:  tests/test_context.py today. It exists for entity extraction and
--           the enriched-context view (prd tasks 14 and D3), which join the
--           context to its entities and to the enrichment reference tables.
--
-- `'v1'` below is the literal copy of `helena.versions.AGGREGATION_VERSION`.
-- It is a literal because a streaming query cannot read
-- `helena_aggregation_version`: `CREATE MATERIALIZED VIEW ... CROSS JOIN
-- helena_aggregation_version` is rejected with "Not supported: streaming
-- nested-loop join", measured in sql/migrations/0002_aggregation_version.sql.
-- `tests/test_context.py` asserts the value on the rows this view produces
-- equals the Python constant and the engine's own copy, which is the only
-- comparison that can fail -- grepping this file would find it in a comment.
--
-- The aggregate is wrapped in a subquery and the digest is taken outside it so
-- that the version appears **once** in this statement. Written inline the
-- digest would need its own length-prefixed copy of the literal, and a version
-- bump that updated the column and forgot the digest would produce rows whose
-- id no longer matches what the row says produced it. The outer SELECT reads
-- `c.aggregation_version`, so there is nothing to keep in step.
CREATE MATERIALIZED VIEW helena_signal_host_context AS
SELECT encode(
           sha256(
               convert_to(
                   octet_length(c.tenant)::VARCHAR || ':' || c.tenant
                   || octet_length(c.sensor)::VARCHAR || ':' || c.sensor
                   || octet_length(c.host)::VARCHAR || ':' || c.host
                   || octet_length(c.window_start_epoch::VARCHAR)::VARCHAR
                   || ':' || c.window_start_epoch::VARCHAR
                   || octet_length(c.aggregation_version)::VARCHAR
                   || ':' || c.aggregation_version,
                   'UTF8'
               )
           ),
           'hex'
       )                        AS context_id,
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
FROM (
    SELECT f.tenant,
           f.sensor,
           f.src_address                                       AS host,
           f.window_start,
           f.window_end,
           extract(epoch FROM f.window_start)::BIGINT          AS window_start_epoch,
           count(*)::BIGINT                                    AS flow_count,
           sum(f.duration_seconds)                             AS duration_seconds,
           sum(f.bytes_sent)::BIGINT                           AS bytes_sent,
           sum(f.bytes_received)::BIGINT                       AS bytes_received,
           sum(f.packets_sent)::BIGINT                         AS packets_sent,
           sum(f.packets_received)::BIGINT                     AS packets_received,
           'v1'                                                AS aggregation_version
    FROM TUMBLE(helena_flatten_flows, flow_start, INTERVAL '5 minutes') f
    GROUP BY f.tenant, f.sensor, f.src_address, f.window_start, f.window_end
) c;
