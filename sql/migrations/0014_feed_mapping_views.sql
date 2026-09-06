-- 0014  Enrichment views: reference tables in, evidence-level claims out.
--
-- `concept/03-architecture.md` names two components and this file is the second
-- of them:
--
--   Feed loaders    "Fetch each static feed on its schedule, parse it, map it to
--                    the taxonomy, and update **its reference table** with a
--                    snapshot version."
--   Enrichment views "**SQL mapping and join views** turning reference tables
--                    into enrichment evidence and the enriched context. **No
--                    runtime service**."
--
-- Until now there was one and not the other: the ThreatFox loader mapped in
-- Python and wrote the evidence rows itself, so "enrichment views" was a
-- component with nothing in it and `helena_reference_enrichment_evidence` was a
-- table somebody wrote rather than a shape derived from what a feed holds.
--
-- This file splits the two along the line those rows draw. The loader now writes
-- `helena_reference_threatfox` -- the native record, normalized but not
-- reshaped, with the taxonomy classification the loader mapped. The mapping view
-- turns that into the evidence shape, and `helena_reference_evidence` unions
-- the feeds. **No runtime service, no coordinator, no dispatch and no cache**,
-- because a join has nothing to deduplicate.
--
-- ## What the loader still does, and what moved
--
-- Both halves are mapping and the split is not arbitrary. The loader does what
-- needs the export in front of it: flattening the id-keyed lists, splitting
-- `ip:port`, splitting the delimited tags, reading `YYYY-MM-DD HH:MM:SS` into a
-- timestamp, and deciding a `threat_type` it has never seen emits the parent.
-- Those are decisions about *this publisher's format*, and a view that made them
-- would be a format parser written in SQL.
--
-- The view does what is the same for every feed: assembling the evidence shape,
-- deriving the identifier, setting the scope, and carrying the tier. Those are
-- decisions about *the evidence contract*, and a loader that made them would be
-- a second implementation of that contract per feed -- which is exactly how the
-- second feed's rows come out subtly different from the first's.
--
-- ## The evidence identifier, in two homes, asserted equal
--
-- `evidence_id` is a sha256 over identity, source, snapshot, entity,
-- classification, scope and **the native record** -- `concept/instruction.md`'s
-- requirement that a citation survive replay. The construction is the one
-- `sql/migrations/0006_host_context.sql` uses for `context_id`, length-prefixed
-- so that two fields cannot borrow a character from each other.
--
-- It has a second home in `helena.enrichment.evidence_id`, and
-- `tests/test_mapping.py` asserts the two produce the same digest for a real row
-- read out of the engine. Two copies that can drift are worse than none; these
-- two cannot, because a test asks the engine rather than reading this file.
--
-- **The native record is ThreatFox's own `indicator_id` plus the offset within
-- its list**, not a hash of the payload. The publisher's key is stable across
-- snapshots and is what the publisher means by "this record"; a digest of the
-- payload would mint a new identifier every time a field nobody reads changed.
-- The offset is there because the format is a list per id, and
-- `docs/decisions/0009-netify-application-identification.md` is the standing
-- reminder that N rows per entity is the point rather than an accident.
--
-- ## Contradictions are preserved, not resolved
--
-- Nothing here aggregates, deduplicates or picks between claims.
-- `concept/05-threat-intelligence.md` rule 6: *"Preserve contradictions. Never
-- collapse disagreement to a single verdict before the agent sees it."* Two
-- sources disagreeing about one address are two rows, and so are two rows of one
-- source -- `concept/02`: *"multiplicity is evidence for the agent to weigh,
-- never something to collapse before it is seen."*
--
-- ## The evidence tier
--
-- Every row carries `evidence_tier = 'enrichment'`. `concept/05` splits the
-- system's evidence in two: the **enrichment tier** is static feeds joined in
-- SQL, and the **analyst tier** is live providers queried through tools. It is
-- not the A-D source tier, which describes how strong a source is; this
-- describes how the evidence got here, and the two answer different questions
-- about the same row. A live-provider claim will carry `analyst` and the same
-- shape otherwise.


-- helena_reference_threatfox: the ThreatFox snapshot, as the loader read it.
--
-- Layer:    reference. A snapshot-versioned table a loader writes and the
--           mapping view below derives from -- the same place
--           helena_reference_public_suffix sits.
-- Object:   TABLE. The snapshot itself; there is nothing below it to derive it
--           from.
-- Reads:    nothing.
-- Read by:  helena_reference_evidence_threatfox below,
--           src/helena/enrichment.py (the loader) and tests/test_mapping.py.
--
-- The columns are the native record normalized and nothing more: `ioc_value` is
-- kept exactly as supplied beside the `entity_value` and `port` split out of it,
-- so the reference table can be checked against the export it came from.
CREATE TABLE IF NOT EXISTS helena_reference_threatfox (
    tenant           VARCHAR NOT NULL,
    sensor           VARCHAR NOT NULL,
    snapshot_version VARCHAR NOT NULL,
    -- ThreatFox's own key, and the offset within the list it keys. The format is
    -- an object keyed by indicator id whose values are LISTS; every list had
    -- length one on 2026-09-06 and that is a property of one snapshot rather
    -- than of the format.
    indicator_id     VARCHAR NOT NULL,
    record_offset    INT NOT NULL,
    -- As supplied, so this table can be checked against the export.
    ioc_type         VARCHAR NOT NULL,
    ioc_value        VARCHAR NOT NULL,
    -- Split out of `ioc_value`. `port` is NULL for anything but `ip:port`.
    entity_type      VARCHAR NOT NULL,
    entity_value     VARCHAR NOT NULL,
    port             INT,
    -- The publisher's threat type, and what the loader mapped it to.
    -- `threat_type_seen` is false where the mapping had not seen the type and
    -- emitted the parent -- `concept/02`'s "emit the parent rather than guessing
    -- a child" -- which is a counted event rather than a silent default.
    threat_type      VARCHAR NOT NULL,
    classification   VARCHAR NOT NULL,
    taxonomy_version VARCHAR NOT NULL,
    threat_type_seen BOOLEAN NOT NULL,
    -- 0-100 as the publisher sends it. The evidence view divides by 100; the
    -- reference table keeps the publisher's unit so it can be compared with the
    -- export.
    confidence_level INT NOT NULL,
    -- `concept/05`: common, not rare -- 16.5 % of the export. Native evidence
    -- and never the classification.
    is_compromised   BOOLEAN NOT NULL,
    -- Nullable and left that way: `last_seen` is absent on 19.3 % of entries and
    -- inventing it would make every stale claim look fresh.
    first_seen       TIMESTAMPTZ,
    last_seen        TIMESTAMPTZ,
    -- The delimited `tags` string, split. Absent on 8.9 % of entries, where this
    -- is an empty array rather than null: observed and empty is not unobserved.
    tags             JSONB,
    malware          VARCHAR,
    malware_printable VARCHAR,
    reporter         VARCHAR,
    reference        VARCHAR,
    PRIMARY KEY (tenant, sensor, snapshot_version, indicator_id, record_offset)
);


-- helena_reference_evidence_threatfox: ThreatFox's rows in the evidence shape.
--
-- Layer:    reference. It derives one reference table into the shape every feed
--           presents, and joins nothing outside the reference layer.
-- Object:   VIEW (plain). It is a projection with a digest in it: no aggregate,
--           no join, nothing to keep state for. Materializing it would pay for a
--           second copy of a table that is already stored -- the measured rule in
--           docs/decisions/0016-view-layering-and-materialization-policy.md.
-- Reads:    helena_reference_threatfox
-- Read by:  helena_reference_evidence below and tests/test_mapping.py.
CREATE VIEW helena_reference_evidence_threatfox AS
SELECT encode(
           sha256(
               convert_to(
                   octet_length(t.tenant)::VARCHAR || ':' || t.tenant
                   || octet_length(t.sensor)::VARCHAR || ':' || t.sensor
                   || octet_length('threatfox')::VARCHAR || ':' || 'threatfox'
                   || octet_length(t.snapshot_version)::VARCHAR
                   || ':' || t.snapshot_version
                   || octet_length(t.entity_type)::VARCHAR || ':' || t.entity_type
                   || octet_length(t.entity_value)::VARCHAR || ':' || t.entity_value
                   || octet_length(t.classification)::VARCHAR || ':' || t.classification
                   || octet_length(
                          CASE WHEN t.port IS NULL THEN t.entity_type
                               ELSE 'address:port' END
                      )::VARCHAR
                   || ':' || CASE WHEN t.port IS NULL THEN t.entity_type
                                  ELSE 'address:port' END
                   || octet_length(
                          CASE WHEN t.port IS NULL THEN t.entity_value
                               ELSE t.entity_value || ':' || t.port::VARCHAR END
                      )::VARCHAR
                   || ':' || CASE WHEN t.port IS NULL THEN t.entity_value
                                  ELSE t.entity_value || ':' || t.port::VARCHAR END
                   -- The native record: the publisher's key and the offset
                   -- within the list it keys, as ONE length-prefixed part.
                   -- `helena.enrichment.evidence_id` takes it as one string, so
                   -- prefixing the two halves separately would make two digests
                   -- that never agree -- which is the drift the test asserting
                   -- them equal exists to catch, caught here first.
                   || octet_length(
                          t.indicator_id || ':' || t.record_offset::VARCHAR
                      )::VARCHAR
                   || ':' || t.indicator_id || ':' || t.record_offset::VARCHAR,
                   'UTF8'
               )
           ),
           'hex'
       )                                        AS evidence_id,
       t.tenant,
       t.sensor,
       'threatfox'                              AS source_id,
       -- A-D, describing the SOURCE. Denormalized here rather than joined from a
       -- registry table because there is no registry table: the descriptor is
       -- Python (`helena.enrichment.SOURCES`) and a source's tier is a governed
       -- decision, not a row somebody can UPDATE.
       'B'                                      AS source_tier,
       -- How the evidence got here, which is not how strong it is. See the head.
       'enrichment'                             AS evidence_tier,
       t.snapshot_version,
       t.entity_type,
       t.entity_value,
       -- Every row of a loaded snapshot is a source that answered. `stale` is a
       -- property of the snapshot's age and `missing` of its absence, and
       -- neither can be a column here -- 0013's head has the argument.
       'ok'                                     AS status,
       t.classification,
       t.taxonomy_version,
       -- `concept/05`: the entry's confidence "must reach the claim rather than
       -- being flattened away". 0-100 there, 0.0-1.0 here: a change of unit and
       -- not of meaning.
       t.confidence_level::DOUBLE PRECISION / 100 AS confidence,
       -- What the claim is ABOUT, which is not always the entity it attaches to:
       -- for an `ip:port` indicator the claim is about the address on that port,
       -- and the entity is the address because that is what a context row joins
       -- on.
       CASE WHEN t.port IS NULL THEN t.entity_type ELSE 'address:port' END
                                                AS scope_type,
       CASE WHEN t.port IS NULL THEN t.entity_value
            ELSE t.entity_value || ':' || t.port::VARCHAR END
                                                AS scope_value,
       t.first_seen,
       t.last_seen,
       NULL::TIMESTAMPTZ                        AS valid_until,
       -- The minimal native fields that justify the mapping (`concept/05` rule
       -- 5). Minimal is the operative word: what justifies THIS mapping, not the
       -- publisher's whole response.
       jsonb_build_object(
           'threat_type', t.threat_type,
           'threat_type_seen_by_mapping', t.threat_type_seen,
           'is_compromised', t.is_compromised,
           'malware', t.malware,
           'malware_printable', t.malware_printable,
           'reporter', t.reporter,
           'reference', t.reference,
           'tags', t.tags,
           'indicator_id', t.indicator_id,
           'port', t.port
       )                                        AS native_evidence
FROM helena_reference_threatfox t;


-- helena_reference_evidence: every feed's claims, in one shape.
--
-- Layer:    reference
-- Object:   VIEW (plain). A UNION ALL of projections; there is nothing to keep
--           state for, and the enriched-context view above it is where
--           materialization is worth arguing about.
-- Reads:    helena_reference_evidence_threatfox
-- Read by:  src/helena/enrichment.py (reading claims back), tests/test_mapping.py
--           and tests/test_evidence.py. The enriched-context view (the next D3
--           increment) is the reader this exists for.
--
-- One feed today. `UNION ALL` and not `UNION`: two identical rows from two feeds
-- would be two claims, and deduplicating them is precisely the collapse
-- `concept/05` rule 6 forbids. Adding a feed is a mapping view and a line here.
CREATE VIEW helena_reference_evidence AS
SELECT * FROM helena_reference_evidence_threatfox;


-- 0011's table is superseded by the two views above: the evidence shape is
-- derived from what a feed holds rather than written by whoever loaded it, which
-- is what `concept/03-architecture.md` means by an enrichment *view*. Dropped
-- here and not recreated.
DROP TABLE helena_reference_enrichment_evidence;
