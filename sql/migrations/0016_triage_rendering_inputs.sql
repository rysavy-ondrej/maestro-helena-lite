-- 0016  The TLS parameters a host negotiated in a window: part four of the
--       triage rendering.
--
-- `concept/04-the-two-agents.md` gives the Triage Agent "a bounded, versioned
-- projection of the enriched host context, in five parts", and one of the five
-- is "**selected TLS parameters** -- a subset, not everything the record
-- carries". Four of the five already had a readable source in the engine. This
-- is the fifth.
--
-- The subset itself, and the criterion that chose it, are in
-- `docs/decisions/0018-the-triage-rendering.md` rather than in a comment here --
-- the task asked for a decision note precisely so that the next person can
-- disagree with the criterion instead of with a list.
--
-- The one thing worth saying in the file: **the fingerprints are not here.**
-- `client_ja3` and `client_ja4` are already `fingerprint` entities in
-- `helena_signal_context_entities`, which is what lets a fingerprint carry
-- enrichment and a stable evidence identifier; a second copy here would be a
-- value that can disagree with the one a claim attaches to.
--
-- Nothing else changes. No object is dropped and no definition is superseded:
-- the enriched context is exactly what `sql/migrations/0015_enriched_context.sql`
-- created, and the rendering takes the entity list and the observation flags
-- from `helena_signal_context_entities` and the claims from the enriched context
-- -- which is not a workaround, it is what those two views are each for. The
-- enriched context's source list is the snapshot ledger (0015's head says so and
-- states the consequence), so before any feed has ever loaded it yields no rows
-- at all; a rendering that took its entity list from there would show a host
-- that contacted nothing, which is worse than showing a host nobody could look
-- anything up about.


-- helena_signal_context_tls: the TLS parameters one host negotiated in one
-- window, one row per distinct parameter tuple.
--
-- Layer:    signal. It reads the flatten layer and the signal layer's own
--           aggregate, which is what helena_signal_context_entity_ports does and
--           for the same reason: the rendering may not reach into flatten, so
--           what it needs from there comes up through here.
-- Object:   VIEW (plain). One row per distinct tuple per context; the renderer
--           selects it by `context_id` and nothing joins from it, so there is no
--           state worth materializing
--           (docs/decisions/0016-view-layering-and-materialization-policy.md).
-- Reads:    helena_flatten_flows, helena_flatten_tls, helena_signal_host_context
-- Read by:  src/helena/rendering/__init__.py, which reads it for part four of
--           the triage rendering, and tests/test_rendering.py.
--
-- The window is taken over the flows, not over the TLS rows: `helena_flatten_tls`
-- carries no time column -- it is one row per event that observed TLS -- so the
-- flow it belongs to is what places it in a window. That is the same join
-- `helena_signal_entity_observations` makes, on the same four columns.
--
-- `handshake_count` counts the *flows* that negotiated this tuple, so a host
-- that opened forty identical TLS connections is one row saying forty rather
-- than forty rows. That is where most of part four's boundedness comes from for
-- free: the cardinality is the number of distinct (version, version, cipher)
-- tuples a host used, which is small even when the number of handshakes is not.
--
-- A flow that observed TLS with no handshake -- captured mid-connection, so no
-- versions and no cipher -- produces a row of three NULLs and a count, and that
-- is deliberate: it says TLS was observed and nothing was negotiable, which is
-- not the same as a window with no TLS in it at all and not the same as a
-- handshake whose parameters this file chose not to select.
CREATE VIEW helena_signal_context_tls AS
SELECT c.context_id,
       c.tenant,
       c.sensor,
       c.host,
       c.window_start,
       t.client_version,
       t.server_version,
       t.server_cipher,
       count(*)::BIGINT AS handshake_count
FROM TUMBLE(helena_flatten_flows, flow_start, INTERVAL '5 minutes') f
JOIN helena_flatten_tls t
  ON t.tenant = f.tenant
 AND t.sensor = f.sensor
 AND t.capture_sha256 = f.capture_sha256
 AND t.record_offset = f.record_offset
JOIN helena_signal_host_context c
  ON c.tenant = f.tenant
 AND c.sensor = f.sensor
 AND c.host = f.src_address
 AND c.window_start = f.window_start
GROUP BY c.context_id, c.tenant, c.sensor, c.host, c.window_start,
         t.client_version, t.server_version, t.server_cipher;
