-- 0015  The enriched context: a join, per entity, against the snapshot that was current.
--
-- `concept/03-architecture.md`: the enriched context is a **join**, not a
-- dispatch -- no runtime service, no coordinator, no workers and no cache,
-- because a join has nothing to deduplicate. This file is that join, and it is
-- the **first object in the analytical layer**: until now `MAY_READ`'s
-- `analytical` row was the invariant the layering test could describe and not
-- exercise.
--
-- ## Per entity, and why it could not be per context
--
-- `concept/03`: the join is **per entity**. That is not a preference. A host
-- context is one row with arrays inside it, and an array inside a window cannot
-- be joined to evidence; and the composition rule needs the indicator correlated
-- with **the traffic that reached it**, which means the entity row carrying that
-- traffic has to be the thing the claim attaches to.
--
-- ## The snapshot current at event time, not the latest one
--
-- `concept/02-concepts-and-taxonomy.md`: *"Replay joins the snapshot current at
-- event time, not today's."* A context from last Tuesday enriched against
-- today's feed would be a different assessment every time it was read, and a
-- stored one could never be reproduced.
--
-- `helena_reference_feed_snapshot_validity` turns the ledger into intervals --
-- each successful load is the current snapshot until the next successful one --
-- so the join is a range predicate on the context's `window_start` rather than a
-- correlated "latest" subquery. `lead()` over the ledger is what builds it, and
-- **failed attempts are excluded from that ordering on purpose**: a failure left
-- the previous snapshot in place, so it does not end that snapshot's validity.
--
-- A second view over **every** attempt answers the other question -- what was the
-- most recent attempt at that time, successful or not -- which is the difference
-- between `missing` and `failed` below.
--
-- ## The four statuses, distinguishable on the row
--
-- `concept/instruction.md` forbids collapsing them, and this is the layer where
-- they finally all become expressible. Two columns carry it, and they are
-- independent -- which is the whole reason `sql/migrations/0011` separated them:
--
--   status          what happened to the lookup
--   classification  what the source said, `no_match` included
--
--   ok       a snapshot covered this window and it is younger than the feed's
--            own refresh interval.
--   stale    a snapshot covered this window and the publisher has moved past it.
--            The claim stands: `concept/02` is explicit that removal from a feed
--            is not exoneration, and an aged snapshot is evidence with a date on
--            it rather than evidence withdrawn.
--   failed   no snapshot covered this window, and the most recent attempt at that
--            time had **failed**. We tried and could not.
--   missing  no snapshot covered this window and nothing had been tried. Never
--            asked, which is not the same as tried and failed, and neither is
--            the same as asked and told nothing.
--
-- And `no_match` is a **classification**, never a status: a source that ran and
-- found nothing. `concept/02` says why it matters more here than anywhere else
-- -- with sparse coverage most entities have no hit on anything, so an enriched
-- context is **mostly negative space**, and triage reading "no hit" as "clean" is
-- the failure mode the whole design exists to prevent. A LEFT JOIN is what makes
-- that a row rather than an absence.
--
-- ## The source list comes from the ledger, not from a second registry
--
-- To say `no_match` for a source there has to be a row for that source, so the
-- entities are joined against the sources rather than only against the claims.
-- The source list is `SELECT DISTINCT source_id FROM helena_reference_feed_snapshot`
-- -- every source that has ever been asked -- and **not** a table mirroring
-- `helena.enrichment.SOURCES`. A source's tier and declared subset are a governed
-- decision (`concept/05-threat-intelligence.md`), not a row somebody can UPDATE,
-- and a second copy of the registry in SQL is a second copy that can disagree.
--
-- The consequence is stated rather than hidden: a registered source that has
-- never attempted a load produces **no rows here at all**, not `missing` rows.
-- `helena.enrichment.feed_status` is what reports `missing` for it, because that
-- is a question about the source and not about any entity.
--
-- ## Port qualification
--
-- `concept/05`: *a C2 on one port matched against a host that contacted another
-- is a weaker claim.* The claim's scope carries the port -- a `scope_type` of
-- `address:port` means `scope_value` is `<address>:<port>` -- and until now
-- nothing on the other side of the join could be compared with it, because an
-- entity row is a value and its observation flags.
--
-- `helena_signal_context_entity_ports` is that other side: the ports a host
-- actually reached on an address, in that window, from the flatten layer. The
-- analytical layer may not read the flatten layer, which is exactly why this view
-- is in the signal layer and not inlined here.
--
-- `port_matched` is deliberately three-valued and is **not** a filter. NULL means
-- the claim is not port-scoped and the question does not arise; false means the
-- host reached that address on other ports only. A false row is kept, because
-- `concept/02` says what to do with it and it is not "drop it": that hit is
-- `suspicious` at most rather than nothing at all, and a view that filtered it
-- would be making the composition rule's decision on the rule's behalf.


-- helena_reference_feed_snapshot_validity: which snapshot was current, and when.
--
-- Layer:    reference
-- Object:   VIEW (plain). A window function over a ledger; nothing streams from
--           it and there is no state worth keeping.
-- Reads:    helena_reference_feed_snapshot
-- Read by:  helena_analytical_enriched_context below and tests/test_enriched.py.
--
-- `valid_to` is NULL for the newest snapshot, which is the one still current.
-- Only successful loads are ordered here: a failed attempt left the previous
-- snapshot in place, so it must not end that snapshot's validity.
CREATE VIEW helena_reference_feed_snapshot_validity AS
SELECT tenant,
       sensor,
       source_id,
       snapshot_version,
       attempted_at                                     AS valid_from,
       lead(attempted_at) OVER (
           PARTITION BY tenant, sensor, source_id ORDER BY attempted_at
       )                                                AS valid_to,
       (counts ->> 'refresh_interval_seconds')::BIGINT  AS refresh_interval_seconds
FROM helena_reference_feed_snapshot
WHERE snapshot_version IS NOT NULL;


-- helena_reference_feed_attempt_validity: what the most recent attempt was, and when.
--
-- Layer:    reference
-- Object:   VIEW (plain), for the same reason as the view above.
-- Reads:    helena_reference_feed_snapshot
-- Read by:  helena_analytical_enriched_context below and tests/test_enriched.py.
--
-- Every attempt, failures included -- which is the difference from the view
-- above and the whole point of having both. This one answers "had we tried, and
-- how did it go", and that is what tells `failed` from `missing`.
CREATE VIEW helena_reference_feed_attempt_validity AS
SELECT tenant,
       sensor,
       source_id,
       outcome,
       failure_reason,
       attempted_at AS valid_from,
       lead(attempted_at) OVER (
           PARTITION BY tenant, sensor, source_id ORDER BY attempted_at
       )            AS valid_to
FROM helena_reference_feed_snapshot;


-- helena_signal_context_entity_ports: the ports a host reached on an address.
--
-- Layer:    signal. It reads the flatten layer and the signal layer's own
--           aggregate, which is what `helena_signal_entity_observations` does and
--           for the same reason: the analytical layer may not read flatten, so
--           anything the enriched context needs from there comes up through here.
-- Object:   VIEW (plain). One row per port per address per context; the
--           enriched-context view joins it and nothing else does, so there is no
--           state worth materializing.
-- Reads:    helena_flatten_flows, helena_signal_host_context
-- Read by:  helena_analytical_enriched_context below and tests/test_enriched.py.
--
-- Destinations only. A port on the source side is the host's own ephemeral port
-- and says nothing about what it reached, and `concept/02` keys a host by its
-- source address -- so `dst_port` is the one that can be compared with a claim's
-- scope.
CREATE VIEW helena_signal_context_entity_ports AS
SELECT c.context_id,
       c.tenant,
       c.sensor,
       c.host,
       f.dst_address AS entity_value,
       f.dst_port    AS port
FROM TUMBLE(helena_flatten_flows, flow_start, INTERVAL '5 minutes') f
JOIN helena_signal_host_context c
  ON c.tenant = f.tenant
 AND c.sensor = f.sensor
 AND c.host = f.src_address
 AND c.window_start = f.window_start
WHERE f.dst_port IS NOT NULL
GROUP BY c.context_id, c.tenant, c.sensor, c.host, f.dst_address, f.dst_port;


-- helena_analytical_enriched_context: a context's entities, with what is known
-- about each of them.
--
-- Layer:    analytical. The first object in it. `MAY_READ` lets it read the
--           signal and reference layers and **not** the flatten layer or the
--           source -- the invariant `concept/instruction.md` §2 and
--           `concept/03-architecture.md` both state, and the one
--           tests/test_view_layering.py could describe but not exercise until now.
-- Object:   VIEW (plain), and deliberately not materialized. It is read when a
--           context is rendered rather than joined from, it carries `now()` in
--           its status derivation -- which a streaming query rejects outside a
--           WHERE clause -- and materializing a join of every entity against
--           every source would pay continuously for rows that are mostly
--           negative space. `docs/decisions/0016-view-layering-and-materialization-policy.md`
--           is the measured rule this follows.
-- Reads:    helena_signal_context_entities, helena_signal_context_entity_ports,
--           helena_reference_evidence, helena_reference_feed_snapshot,
--           helena_reference_feed_snapshot_validity,
--           helena_reference_feed_attempt_validity
-- Read by:  tests/test_enriched.py. The triage rendering (D4) is the reader this
--           exists for; nothing renders a context yet.
--
-- **This view carries no verdict and computes no severity.** It is the evidence a
-- verdict would be reasoned from, and `concept/02`'s composition rule -- "an
-- evidence-level classification about a contacted indicator does not become the
-- context verdict", the single most consequential rule in the taxonomy -- is
-- about what a *reader* may conclude from these rows. Putting a verdict here
-- would be making that decision in SQL, where none of the traffic correlation the
-- rule turns on has been weighed.
CREATE VIEW helena_analytical_enriched_context AS
SELECT e.context_id,
       e.tenant,
       e.sensor,
       e.host,
       e.window_start,
       e.entity_type,
       e.entity_value,
       -- The scope columns the composition rule reads: an address the host
       -- actually contacted is a stronger claim than one it only resolved.
       e.observed_as_flow_destination,
       e.observed_in_dns_query,
       e.observed_in_tls,
       e.observed_flow_count,
       e.observed_bytes_sent,
       e.observed_bytes_received,
       s.source_id,
       ev.evidence_id,
       ev.source_tier,
       ev.evidence_tier,
       -- The snapshot that was current when this window happened, which is not
       -- necessarily the one current now.
       v.snapshot_version,
       v.valid_from                       AS snapshot_loaded_at,
       -- ok / stale / failed / missing. See the head for what each one is not.
       CASE
           WHEN v.snapshot_version IS NULL AND a.outcome = 'failed' THEN 'failed'
           WHEN v.snapshot_version IS NULL THEN 'missing'
           WHEN v.refresh_interval_seconds IS NULL THEN 'ok'
           WHEN v.valid_from
                > now() - INTERVAL '1 second' * v.refresh_interval_seconds
               THEN 'ok'
           ELSE 'stale'
       END                                AS status,
       -- The claim, or `no_match` where a snapshot was consulted and said
       -- nothing, or NULL where there was no snapshot to consult. Three
       -- different facts, and `concept/instruction.md` forbids collapsing them.
       CASE
           WHEN ev.classification IS NOT NULL THEN ev.classification
           WHEN v.snapshot_version IS NOT NULL THEN 'no_match'
       END                                AS classification,
       ev.taxonomy_version,
       ev.confidence,
       ev.scope_type,
       ev.scope_value,
       ev.first_seen,
       ev.last_seen,
       ev.native_evidence,
       -- Three-valued and not a filter -- see the head. NULL where the claim is
       -- not port-scoped, false where the host reached this address on other
       -- ports only.
       CASE
           WHEN ev.scope_type <> 'address:port' THEN NULL
           WHEN p.port IS NOT NULL THEN TRUE
           ELSE FALSE
       END                                AS port_matched
FROM helena_signal_context_entities e
CROSS JOIN (
    -- Every source that has ever been asked. Not a mirror of
    -- helena.enrichment.SOURCES -- see the head for why a second registry in SQL
    -- would be a second registry that can disagree.
    SELECT DISTINCT tenant, sensor, source_id FROM helena_reference_feed_snapshot
) s
LEFT JOIN helena_reference_feed_snapshot_validity v
       ON v.tenant = e.tenant
      AND v.sensor = e.sensor
      AND v.source_id = s.source_id
      AND e.window_start >= v.valid_from
      AND (v.valid_to IS NULL OR e.window_start < v.valid_to)
LEFT JOIN helena_reference_feed_attempt_validity a
       ON a.tenant = e.tenant
      AND a.sensor = e.sensor
      AND a.source_id = s.source_id
      AND e.window_start >= a.valid_from
      AND (a.valid_to IS NULL OR e.window_start < a.valid_to)
LEFT JOIN helena_reference_evidence ev
       ON ev.tenant = e.tenant
      AND ev.sensor = e.sensor
      AND ev.source_id = s.source_id
      AND ev.snapshot_version = v.snapshot_version
      AND ev.entity_type = e.entity_type
      AND ev.entity_value = e.entity_value
LEFT JOIN helena_signal_context_entity_ports p
       ON ev.scope_type = 'address:port'
      AND p.context_id = e.context_id
      AND p.entity_value = e.entity_value
      -- The scope string is built from the port rather than the port parsed out
      -- of the scope, and that is not a style choice. `scope_value::INT` on the
      -- part after the last colon is evaluated for **every** row the join
      -- considers -- the `scope_type` predicate beside it does not short-circuit
      -- it -- so a domain scope like `106.137.52.in-addr.arpa` reaches the cast
      -- and the whole query fails with "integer invalid digit found in string".
      -- Measured, not reasoned about: it is what this join did on its first run.
      -- Comparing as text has the side benefit of being right for IPv6, where
      -- "after the last colon" is a guess about the address rather than a fact.
      AND ev.scope_value = e.entity_value || ':' || p.port::VARCHAR
WHERE e.tenant = s.tenant
  AND e.sensor = s.sensor;
