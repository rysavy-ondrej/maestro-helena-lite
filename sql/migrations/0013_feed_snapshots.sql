-- 0013  Snapshot versioning: one ledger for every feed, and history to replay from.
--
-- `concept/05-threat-intelligence.md`: *"write a snapshot version with every
-- load and **keep enough history for replay**."* `concept/02` says what that
-- history is for: *"Replay joins the snapshot current at event time, not
-- today's."*
--
-- Two things change here, and the second is a correction rather than an
-- addition.
--
-- ## One ledger, not one per feed
--
-- 0012 gave ThreatFox its own load table. That does not generalise: a second
-- feed would need a second table with the same columns, and "which feeds are
-- stale" would be a UNION somebody has to remember to extend. This file drops
-- 0012's two objects -- by name, and without recreating them, which is the
-- *removal* half of `Superseded by:` -- and puts one row per load attempt per
-- source in `helena_reference_feed_snapshot`.
--
-- The per-feed counts that were columns of 0012's table are now a JSONB
-- `counts` object, because they are not the same across feeds: ThreatFox counts
-- entries read, claims stored and skipped file hashes; a feed with no
-- unmappable indicator types would count two of those and not the third. A
-- column per feed's idea of a count is how a shared table stops being shared.
-- What every feed has in common -- when, what came of it, and which snapshot --
-- is columns.
--
-- ## Snapshot history is kept, and 0012's loader was wrong to delete it
--
-- The ThreatFox loader as written in task 22 replaced its claims insert-then-
-- delete, leaving exactly one snapshot: the same shape
-- `sql/migrations/0008_public_suffix_list.sql` uses for the Public Suffix List.
-- For the Public Suffix List that is right and deliberate -- it holds one
-- snapshot at a time on purpose, and the derivation GROUPs BY snapshot_version
-- so a second one fails loudly rather than being silently picked between.
--
-- **For a feed it is wrong**, and the reason is the sentence at the top of this
-- file: a claim records the snapshot it matched against, and replay has to join
-- *that* snapshot. Deleting it leaves a stored assessment citing a snapshot the
-- store no longer has, which is a replay that cannot be validated. So the
-- evidence table now keeps every snapshot it is given, and pruning is a
-- deliberate operation against the retention this file records rather than a
-- side effect of loading.
--
-- ## `stale` and `missing` are derived, never stored
--
-- `concept/02` lists four enrichment statuses and `concept/instruction.md`
-- forbids collapsing them. Two of them are properties of a *row* and two are
-- properties of *now*:
--
--   ok       the source answered. Stored on the claim, and true forever: it is
--            what happened when the query ran.
--   stale    the snapshot behind the claim is older than that feed's own refresh
--            schedule. A **function of the clock**, so storing it would be wrong
--            the moment time passed -- the same reason
--            `sql/migrations/0009_retention_boundary.sql` computes
--            `completeness` in a plain view over `now()` instead of writing it
--            down.
--   missing  there is no snapshot for that source at all. Not a property of any
--            row, because the rows do not exist: only a LEFT JOIN from the
--            entity side can say it, which is the enriched-context view's job.
--   failed   the query did not complete. Stored, with a typed error and no
--            taxonomy object.
--
-- So `helena_reference_feed_snapshot_current` below derives `ok` / `stale` per
-- source, and `missing` is what a reader concludes when a source it expected is
-- not in that view at all.
--
-- ## An indicator that disappears between snapshots
--
-- **A differ reads aged-out and retracted as one event, and it must not.**
-- ThreatFox's recent export is a rolling window rather than a cumulative
-- archive -- it regenerates every few minutes and carries only what is current
-- -- so an indicator present in snapshot N and absent from N+1 has either aged
-- out of the window or been retracted by the publisher, and the export says
-- which by saying nothing.
--
-- `concept/02` settles what may be concluded from that and it is very little:
-- *"Preserve the historical verdict when activity changes. An offline C2
-- endpoint remains historically malicious; delisting may reduce confidence, and
-- never rewrites the observation as normal. **Removal from a feed is not
-- exoneration.**"* Keeping the old snapshot is what makes that possible: the
-- claim stands, dated, against the snapshot that carried it. Nothing here
-- computes a disappearance, and a view that did would be asserting a difference
-- between two things the source does not distinguish.


-- helena_reference_feed_snapshot: one row per load attempt, for every feed.
--
-- Layer:    reference. The provenance of every snapshot in the reference layer,
--           beside the claims those snapshots produced.
-- Object:   TABLE. An attempt is a fact that happened; there is nothing to
--           derive it from.
-- Reads:    nothing.
-- Read by:  src/helena/enrichment.py (every loader writes it, and reads back
--           which snapshot is current), helena_reference_feed_snapshot_current
--           and helena_reference_feed_snapshot_counts below, and
--           tests/test_snapshots.py.
CREATE TABLE IF NOT EXISTS helena_reference_feed_snapshot (
    -- Identity, for the reason every other stored row carries it: an INSERT onto
    -- an existing key in RisingWave is a silent upsert, and two deployments
    -- loading the same feed must not overwrite each other's provenance.
    tenant           VARCHAR NOT NULL,
    sensor           VARCHAR NOT NULL,
    source_id        VARCHAR NOT NULL,
    attempted_at     TIMESTAMPTZ NOT NULL,
    -- Through Redactor.url before it is stored. The rule is about the channel --
    -- a stored URL leaks whatever was in it -- and not about any one provider.
    source_url       VARCHAR NOT NULL,
    -- `loaded`, `unchanged` or `failed`. `unchanged` is a successful fetch of
    -- bytes already held: the snapshot stands and nothing is rewritten.
    outcome          VARCHAR NOT NULL,
    -- The sha256 of the fetched bytes. NULL on a failure, because a failed load
    -- has no snapshot and a row naming both a snapshot and a failure reads as
    -- neither. `helena.enrichment.FeedSnapshot` refuses that row.
    snapshot_version VARCHAR,
    -- What this feed counted, as the feed counts it. JSONB rather than columns
    -- because the counts differ per feed -- see the head.
    counts           JSONB,
    failure_reason   VARCHAR,
    failure_detail   VARCHAR,
    PRIMARY KEY (tenant, sensor, source_id, attempted_at)
);


-- helena_reference_feed_snapshot_current: which snapshot each feed is on, and
-- whether it is stale as of this read.
--
-- Layer:    reference
-- Object:   VIEW (plain), and it could not be a materialized one for the reason
--           helena_signal_host_context_live gives: `now()` outside a WHERE
--           clause is rejected in a streaming query, and `status` here is a
--           comparison against it. It is also the right shape regardless --
--           staleness is a fact about the moment of reading, not a row to keep.
-- Reads:    helena_reference_feed_snapshot
-- Read by:  src/helena/enrichment.py (feed_status) and tests/test_snapshots.py.
--           The enriched-context view (a later D3 increment) is the reader this
--           exists for: it is what turns a claim's `ok` into `stale` without
--           rewriting the claim.
--
-- `refresh_interval_seconds` comes from the row rather than from a join against
-- a table of feeds, because the schedule is a property of the source that the
-- loader knows and the engine does not. It is written with every successful
-- load, so a feed whose schedule changes carries the new one from its next load
-- and the old rows still say what they were judged against.
CREATE VIEW helena_reference_feed_snapshot_current AS
SELECT s.tenant,
       s.sensor,
       s.source_id,
       s.snapshot_version,
       s.attempted_at,
       (s.counts ->> 'refresh_interval_seconds')::BIGINT AS refresh_interval_seconds,
       -- Two statuses and never a third: `missing` cannot be said here, because
       -- a source with no snapshot has no row to say it on.
       -- `INTERVAL '1 second' * n` rather than `make_interval(secs => n)`:
       -- RisingWave rejects named function arguments ("Invalid input syntax:
       -- named function arguments are not supported", measured 2026-09-06).
       CASE
           WHEN s.attempted_at
                > now() - INTERVAL '1 second'
                          * (s.counts ->> 'refresh_interval_seconds')::BIGINT
               THEN 'ok'
           ELSE 'stale'
       END                                               AS status
FROM helena_reference_feed_snapshot s
JOIN (
    -- The most recent attempt that actually produced a snapshot. A failed load
    -- is in the table and is deliberately not here: it left the previous
    -- snapshot in place, so what is current is still the one before it.
    SELECT tenant, sensor, source_id, max(attempted_at) AS attempted_at
    FROM helena_reference_feed_snapshot
    WHERE snapshot_version IS NOT NULL
    GROUP BY tenant, sensor, source_id
) latest
  ON latest.tenant = s.tenant
 AND latest.sensor = s.sensor
 AND latest.source_id = s.source_id
 AND latest.attempted_at = s.attempted_at;


DROP VIEW helena_reference_threatfox_load_counts;
DROP TABLE helena_reference_threatfox_load;


-- helena_reference_feed_snapshot_counts: attempts by source and outcome.
--
-- Layer:    reference
-- Object:   VIEW (plain). A count over a table; nothing streams or joins from
--           it, so materializing it would be disk for a number -- the same call
--           helena_reference_public_suffix_load_counts and
--           helena_ingest_quarantine_counts make.
-- Reads:    helena_reference_feed_snapshot
-- Read by:  tests/test_snapshots.py, scripts/load_threatfox.py --status, and
--           whoever is asking why a snapshot is old. `docs/runbook.md` is where
--           that question gets answered.
CREATE VIEW helena_reference_feed_snapshot_counts AS
SELECT source_id,
       outcome,
       failure_reason,
       count(*)::BIGINT  AS attempts,
       max(attempted_at) AS most_recent
FROM helena_reference_feed_snapshot
GROUP BY source_id, outcome, failure_reason;
