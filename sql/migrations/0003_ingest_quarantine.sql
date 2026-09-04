-- 0003  Quarantine: the raw records ingestion refused, kept in the single store.
--
-- concept/03-architecture.md gives the Normalizer the job of quarantining
-- invalid input "without stalling the stream", and concept/instruction.md §6
-- says what that means in practice -- *quarantine with a typed reason and the
-- raw input exactly as read, and keep the stream running*. This table is where
-- those rows land, and putting them here closes the open question
-- concept/08-open-questions.md records as cross-cutting and urgent: *where
-- quarantined records live, given they currently land outside the store the
-- project says holds everything*. They live here. Everything durable is a typed
-- row in the streaming engine (concept/instruction.md §2, one store), and a
-- refused record is durable evidence about a producer -- the one thing that
-- says a field this project marked required is not required in the wild.
-- docs/decisions/0013-quarantine-in-the-single-store.md is the record.
--
-- A TABLE, not a view and not a materialized view. It is state with a writer:
-- src/helena/normalizer.py's `Quarantine.record` INSERTs one row per refused
-- record over the PostgreSQL wire protocol. Read by that same class
-- (`stored`, and `counts` through the view below) and by an operator asking
-- what a producer is sending; nothing streams from it yet.
--
-- ## The key is the ingestion identity plus the raw-record reference
--
-- Not the record's own `id`: that is the producer's label (`udp.0`, `tcp.17`),
-- unique only within a capture and scoped by protocol -- and a record that
-- failed to parse may not have a readable `id` at all. The pair that addresses
-- a raw record is the capture's sha256 and the record's zero-based offset in it
-- (src/helena/normalizer.py::RawRecordReference).
--
-- Tenant and sensor are in the key as well, for the reason
-- docs/decisions/0011-event-identity-and-the-event-id.md gives for putting them
-- in the event id: an INSERT onto an existing primary key in RisingWave is an
-- UPSERT that overwrites the row and raises nothing (measured, task 04), so two
-- deployments ingesting the same file into one store would silently overwrite
-- each other's quarantine rows -- a cross-tenant overwrite that looks like it
-- is working.
--
-- The upsert is what makes re-ingesting a capture idempotent rather than
-- duplicating: the same record refused twice for the same reason rewrites an
-- identical row. tests/test_normalizer.py asserts that.
--
-- ## There is deliberately no timestamp column
--
-- For the reason docs/decisions/0011 gives for keeping an ingestion timestamp
-- off the normalized event: a wall clock would make a capture replayed twice
-- produce a different row from the run it replays, and under the upsert above
-- the stored value would silently mean "the last time this was refused" rather
-- than "when it was first seen". When a record arrived is a property of an
-- ingest run, and nothing records runs yet.
--
-- ## The payload is BYTEA, and it is not truncated
--
-- *The raw input exactly as read.* A refused line is not necessarily valid
-- UTF-8 -- `b'{"id":"\xff"}'` is one of the cases the adapter reports as
-- malformed_json -- so a VARCHAR column would have to either reject the row or
-- decode it lossily, and a quarantine row that lost the bytes that caused it
-- cannot be diagnosed. Measured against RisingWave 3.0.3: BYTEA round-trips
-- those bytes unchanged.
--
-- Nothing truncates the payload. concept/instruction.md §2: *truncation is
-- visible or it is a bug*, and there is no visible-truncation marker here
-- because there is no truncation to mark.
--
-- ## What each of the remaining columns is
--
-- `schema_version` is src/helena/normalizer.py::EVENT_SCHEMA_VERSION -- the
-- version of the event contract that was in force when this record was
-- refused, so a quarantine backlog re-examined after a contract change says
-- which contract refused it rather than being read against whatever the code
-- says today. It is written as data by the one Python constant, not declared as
-- a literal here, so there is no second copy of it to drift.
--
-- `input_format`, `reason` and `detail` are src/helena/normalizer.py's
-- `ParseFailure`, stored flat. The three reasons -- malformed_json,
-- not_this_format, contract_violation -- mean different things and are never
-- collapsed into one (concept/instruction.md §2); the view below keeps them
-- apart in the counter too.
CREATE TABLE IF NOT EXISTS helena_ingest_quarantine (
    tenant         VARCHAR,
    sensor         VARCHAR,
    capture_sha256 VARCHAR,
    record_offset  BIGINT,
    schema_version VARCHAR NOT NULL,
    input_format   VARCHAR NOT NULL,
    reason         VARCHAR NOT NULL,
    detail         VARCHAR NOT NULL,
    payload        BYTEA   NOT NULL,
    PRIMARY KEY (tenant, sensor, capture_sha256, record_offset)
);

-- The quarantine counter, per ingestion identity, per capture, per reason.
--
-- A plain VIEW, not a materialized view. It is an aggregate over a table that
-- holds only the records ingestion refused -- at prototype scale a handful of
-- rows -- and nothing streams or joins from it, so materializing it would be
-- disk for a count. Read by src/helena/normalizer.py::Quarantine.counts and by
-- tests/test_normalizer.py.
--
-- The reason is in the GROUP BY rather than summed away: the numerator of the
-- quarantine rate is three numbers that mean three different things, and a
-- single total would collapse "the wrong adapter is configured" into "the
-- producer changed".
--
-- The DENOMINATOR is deliberately not here. The number of records a capture
-- holds is a property of the retained file (`Capture.record_count`), and the
-- broker is consume-once, so the store cannot supply it: `Quarantine.counts`
-- brings the two together and refuses a count that does not reconcile. The
-- ingest counters that make "consumed" and "normalized" engine-side facts are
-- the next increment.
CREATE VIEW helena_ingest_quarantine_counts AS
SELECT tenant,
       sensor,
       capture_sha256,
       input_format,
       reason,
       count(*) AS quarantined
FROM helena_ingest_quarantine
GROUP BY tenant, sensor, capture_sha256, input_format, reason;
