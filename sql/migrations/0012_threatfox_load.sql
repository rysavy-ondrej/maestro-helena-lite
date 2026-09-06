-- 0012  The ThreatFox load ledger: every attempt, including the ones that failed.
--
-- `concept/instruction.md`, the feed-loader rules: *never let a failure empty a
-- table* -- a fetch failure, a format change or an empty response leaves the
-- previous snapshot in place and **records the failure**, so the result is
-- `stale` or `missing`, never a silent empty opinion. This table is where that
-- record lives, and it is the same shape and the same argument as
-- `helena_reference_public_suffix_load` in 0008.
--
-- The claims themselves go in `helena_reference_enrichment_evidence` (0011),
-- which is shared by every source. This is per-load and per-source: what was
-- fetched, when, what came of it, and what did not.
--
-- ## The counts are the point, and they are four rather than one
--
-- `concept/instruction.md` §7 requires produced-versus-materialised counts to
-- reconcile. A loader that recorded only "5 000 rows written" would make the
-- interesting number invisible, so the row carries what it read, what it stored,
-- and the two reasons those differ:
--
--   entries_read        every entry in the export, after flattening the lists
--   claims_stored       the ones that became a claim
--   skipped_no_entity   file hashes. ThreatFox reports sha256/md5/sha1
--                       indicators and HELENA has no entity for a file digest --
--                       a `fingerprint` here is a TLS JA3/JA4, a property of a
--                       connection. 452 of 4 985 on 2026-09-06 (9.1 %). Counted
--                       rather than dropped, because a skip nobody counted is
--                       how a reconciliation stops being possible.
--   unseen_threat_types how many entries carried a `threat_type` the mapping
--                       has not seen. They still became claims, at the parent
--                       (`concept/02`: "emit the parent rather than guessing a
--                       child"), and this is what makes the source's vocabulary
--                       drifting visible instead of silent. `concept/05` warns
--                       the real vocabulary is larger than any sample.
--
-- entries_read = claims_stored + skipped_no_entity, and
-- `helena.enrichment.ThreatFoxLoad` refuses a row where it does not.
--
-- ## No credential, and the URL is still redacted
--
-- Measured 2026-09-06, and the second measurement rather than the first: the
-- bulk export returns 200 with no credential, and the API returns 401 without an
-- `Auth-Key` header. So `source_url` here holds no secret. It is still written
-- through the redactor, because `concept/07-principles.md`'s rule is about the
-- channel -- a stored URL leaks whatever was in it -- and not about this
-- provider, and because abuse.ch may change its auth on its own schedule.


-- helena_reference_threatfox_load: one row per load attempt.
--
-- Layer:    reference. The provenance of a snapshot in the reference layer,
--           beside the claims it produced.
-- Object:   TABLE. An attempt is a fact that happened; there is nothing to
--           derive it from.
-- Reads:    nothing.
-- Read by:  src/helena/enrichment.py (the loader writes it and reads back the
--           current snapshot) and tests/test_threatfox.py, plus
--           helena_reference_threatfox_load_counts below.
CREATE TABLE IF NOT EXISTS helena_reference_threatfox_load (
    attempted_at        TIMESTAMPTZ NOT NULL,
    -- Through Redactor.url before it is stored -- see the head.
    source_url          VARCHAR NOT NULL,
    -- `loaded`, `unchanged` or `failed`, the same three 0008 uses. `unchanged`
    -- is a successful fetch of bytes already held: the snapshot stands and
    -- nothing is rewritten.
    status              VARCHAR NOT NULL,
    -- The sha256 of the fetched bytes. NULL on a failure, because a failed load
    -- has no snapshot -- and a row naming both a snapshot and a failure reason
    -- is refused by the model rather than stored as something that reads as both.
    snapshot_version    VARCHAR,
    entries_read        BIGINT,
    claims_stored       BIGINT,
    skipped_no_entity   BIGINT,
    unseen_threat_types BIGINT,
    -- One of fetch_failed / malformed_export / empty_export. NULL on success.
    failure_reason      VARCHAR,
    failure_detail      VARCHAR,
    PRIMARY KEY (attempted_at, source_url)
);


-- helena_reference_threatfox_load_counts: attempts by status, for an operator.
--
-- Layer:    reference
-- Object:   VIEW (plain). A count over a table; nothing streams or joins from
--           it, so materializing it would be disk for a number -- the same call
--           helena_reference_public_suffix_load_counts and
--           helena_ingest_quarantine_counts make.
-- Reads:    helena_reference_threatfox_load
-- Read by:  tests/test_threatfox.py and whoever is asking why a snapshot is old.
--           `docs/runbook.md` is where that question gets answered.
CREATE VIEW helena_reference_threatfox_load_counts AS
SELECT status,
       failure_reason,
       count(*)::BIGINT           AS attempts,
       max(attempted_at)          AS most_recent
FROM helena_reference_threatfox_load
GROUP BY status, failure_reason;
