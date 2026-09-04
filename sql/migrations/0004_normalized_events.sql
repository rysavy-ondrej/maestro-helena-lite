-- 0004  Normalized events: what ingestion accepted, and the counter over it.
--
-- concept/03-architecture.md gives the Normalizer the job of turning flow
-- records into "validated events" that assign "tenant, sensor, schema version,
-- event id and raw-record reference -- none of which the input carries". This
-- table is where those events land, and it is the first row in the store that
-- something downstream will read: concept/03-architecture.md's flatten layer is
-- built over it, and the three-layer rule (flatten -> signal -> analytical)
-- starts here, at the source.
--
-- A TABLE, not a view and not a materialized view. It is state with a writer:
-- src/helena/normalizer.py's `EventStore.record` INSERTs one row per accepted
-- record over the PostgreSQL wire protocol, from messages consumed off the
-- ingest topic. Read by that same class (`stored`), by the counter view below,
-- and -- next -- by the flatten-layer views.
--
-- ## The key is the ingestion identity plus the raw-record reference
--
-- The same key as helena_ingest_quarantine, for the same reasons
-- (sql/migrations/0003_ingest_quarantine.sql): a producer's own record `id` is
-- unique only within a capture, and tenant and sensor are in the key because an
-- INSERT onto an existing primary key in RisingWave is a silent UPSERT
-- (measured, task 04), so two deployments ingesting one file into one store
-- would overwrite each other's rows with no error at all.
--
-- The upsert is the property replay needs. The broker is consume-once, so a
-- re-run means replaying the retained capture through the same path; every
-- assigned field is derived from the capture, the offset and the configured
-- identity, so the second run rewrites byte-identical rows rather than doubling
-- them. tests/test_normalizer.py asserts that over the whole sample capture.
--
-- `event_id` is NOT the primary key even though it is unique: it is a digest
-- over exactly the four columns that are the key
-- (docs/decisions/0011-event-identity-and-the-event-id.md), so keying on it
-- would key on a hash of the key -- the same constraint, one indirection away,
-- and no longer readable in a WHERE clause.
--
-- ## The observation is JSONB, and it is the record exactly as supplied
--
-- The event's `observation` block is the flow record as the producer sent it,
-- and concept/instruction.md §2 requires the difference between *unobserved*
-- and *observed but empty* to survive: an unobserved layer is absent, an
-- observed-but-empty one is an empty array and is sent. Measured against
-- RisingWave 3.0.3 before this file was written, over all 62 records of
-- data/ingest/flow-sample.jsonl: every record round-trips through JSONB equal to
-- the JSON it was parsed from, `obs->'tls'->'alpn' = '[]'::jsonb` finds the one
-- record whose ALPN was observed and empty, and `NOT (obs ? 'dns')` finds the 32
-- with no DNS layer at all. Both halves of the rule are therefore representable,
-- and the flatten layer above can tell them apart.
--
-- Columns rather than JSONB was the alternative and it is the flatten layer's
-- job, not this one's: flattening here would mean the stored row is no longer
-- the record as read, and a producer field this contract has not seen would have
-- nowhere to go. The typed columns are what the layer above produces.
--
-- ## What the remaining columns are
--
-- `schema_version` is src/helena/normalizer.py::EVENT_SCHEMA_VERSION, the
-- version of the event contract that validated this record -- written as data
-- by the one Python constant rather than declared as a literal here, so there
-- is no second copy to drift. concept/07-principles.md: replay validates a
-- stored row against the version the row recorded, never against current code.
--
-- There is deliberately no ingestion timestamp, for the reason
-- docs/decisions/0011 gives: a wall clock would make a capture replayed twice
-- produce different rows from the run it replays. When a record arrived is a
-- property of an ingest run.
--
-- Layer:    source. This is *the* source the layering rule names: the flatten
--           layer reads it and nothing above the flatten layer may.
-- Object:   TABLE. The record as read, held so that every view above is a view
--           over one stored copy rather than over the topic, which is
--           consume-once.
-- Reads:    nothing.
-- Read by:  the flatten layer of sql/migrations/0005_flatten_layer.sql --
--           helena_flatten_flows, helena_flatten_dns, helena_flatten_dns_queries,
--           helena_flatten_dns_responses, helena_flatten_tls, helena_flatten_http,
--           helena_flatten_http_requests, helena_flatten_http_responses -- and
--           helena_ingest_counts below, src/helena/normalizer.py (EventStore) and
--           tests/test_normalizer.py.
CREATE TABLE IF NOT EXISTS helena_normalized_events (
    tenant         VARCHAR,
    sensor         VARCHAR,
    capture_sha256 VARCHAR,
    record_offset  BIGINT,
    schema_version VARCHAR NOT NULL,
    event_id       VARCHAR NOT NULL,
    observation    JSONB   NOT NULL,
    PRIMARY KEY (tenant, sensor, capture_sha256, record_offset)
);

-- The ingest counter: how many records of a capture became events, per
-- ingestion identity.
--
-- A plain VIEW, not a materialized view. It is a count over a table, read by
-- src/helena/normalizer.py::EventStore.normalized and by
-- tests/test_normalizer.py when a run reconciles; nothing streams or joins from
-- it, so materializing it would be disk for a number. The same call the
-- quarantine counter makes, for the same reason
-- (sql/migrations/0003_ingest_quarantine.sql).
--
-- This is the "normalized" half of the reconciliation
-- sql/migrations/0003_ingest_quarantine.sql said was the next increment. The
-- other three numbers come from elsewhere on purpose:
--
--   records     the retained capture file (`Capture.record_count`). The broker
--               is consume-once and restart-volatile -- measured against blink
--               0.2.0, a topic drained once is empty and its watermarks are back
--               to (0, 0) -- so "how many records were there" is a fact about
--               the file and can never be a fact about the topic.
--   consumed    the ingest run, counting messages off the topic.
--   quarantined helena_ingest_quarantine_counts.
--
-- src/helena/normalizer.py::ingest_counts brings all four together and refuses a
-- set that does not reconcile: normalized + quarantined must equal consumed, and
-- consumed may not exceed the records the capture holds.
--
-- Layer:    source. A counter over the source, like the quarantine counter.
-- Object:   VIEW (plain). A count over a table; nothing streams or joins from
--           it, so materializing it would be disk for a number.
-- Reads:    helena_normalized_events
-- Read by:  src/helena/normalizer.py (EventStore.normalized, ingest_counts) and
--           tests/test_normalizer.py.
CREATE VIEW helena_ingest_counts AS
SELECT tenant,
       sensor,
       capture_sha256,
       count(*) AS normalized
FROM helena_normalized_events
GROUP BY tenant, sensor, capture_sha256;
