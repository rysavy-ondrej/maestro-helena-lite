-- 0011  Enrichment evidence: one claim, and the four ways there is no claim.
--
-- `concept/02-concepts-and-taxonomy.md` defines the row: *one claim about one
-- entity from one source: the classification, its confidence, its scope, its
-- snapshot, its tier, its status.* This is that row, and
-- `helena.enrichment.EnrichmentEvidence` is the same shape in Python. The two
-- are asserted equal by execution in tests/test_evidence.py, the way
-- FLATTEN_SHAPES and HOST_CONTEXT_SHAPE are: a column that stopped meaning what
-- it meant fails there rather than reaching a join.
--
-- ## The key is a digest, not (entity, source)
--
-- `concept/02`'s "one claim per (entity, source)" was once read as a cardinality
-- constraint, and `docs/decisions/0009-netify-application-identification.md`
-- settled that it is not: the schema carries **N rows per entity**, because
-- Netify alone puts up to **75 claims on a single address** and a loader keyed by
-- address silently discarded 124 653 rows in the first draft of that
-- measurement. So the primary key is `evidence_id`, a sha256 over what makes a
-- claim *that claim* -- identity, source, snapshot, entity, classification,
-- scope and the native evidence.
--
-- Two consequences, both deliberate. Re-running a load writes the **same** row
-- rather than a second copy, which matters here more than usual: RisingWave has
-- no transaction around DDL or DML and an INSERT onto an existing primary key is
-- a silent upsert, so idempotence has to come from the key. And two claims that
-- differ only in their native evidence are **two rows**, which is the
-- multiplicity `concept/02` calls "evidence for the agent to weigh, never
-- something to collapse before it is seen".
--
-- ## Status is not a classification, and `no_match` is not a status
--
-- `concept/instruction.md`: *"`stale`, `failed`, `missing` and `no_match` are
-- four different things, and a typed error is a fifth. Never collapse them, at
-- any layer, for any reason."* Two columns carry that here and they are not
-- interchangeable:
--
--   status          ok / stale / failed / missing -- what happened to the query
--   classification  a taxonomy path, `no_match` included -- what the source said
--
-- `classification` is NULL exactly when `status` is `failed` or `missing`, which
-- is `concept/05`'s rule 4: a query that did not complete emits a typed error and
-- **no taxonomy object**. A row with status `ok` and classification `no_match` is
-- a source that ran and found nothing, and that is a different fact from a source
-- that could not be asked. The constraint is enforced in Python at construction;
-- RisingWave has no CHECK constraints, so this comment and that check are where
-- it lives, and tests/test_evidence.py is what makes it fail.
--
-- ## There is no `verdict` column
--
-- `concept/02` lists `verdict` among the six fields a successful query normalizes
-- into. It is the root of the classification path, `helena.taxonomy` already
-- refuses a path whose root is not its first segment, and a column holding a copy
-- of the first segment is a column that can disagree with the one it came from.
-- `EnrichmentEvidence.verdict` derives it. The same argument
-- sql/migrations/0002_aggregation_version.sql makes about two homes for a
-- constant, one level down: two copies that can drift are worse than none, and
-- nothing here forces a second.
--
-- ## There is no `enriched_at`
--
-- Every column is a property of the claim or of the snapshot it came from, so a
-- load replayed against the same snapshot reproduces the row byte for byte -- the
-- same decision sql/migrations/0003_ingest_quarantine.sql made about
-- `quarantined_at` and 0009 made about `frozen_at`. When a snapshot was fetched
-- is a property of the load and belongs in that feed's load table. Under an
-- upsert, a timestamp here would quietly come to mean "the last time this claim
-- was re-observed", which is a different fact wearing the same name.


-- helena_reference_enrichment_evidence: every claim every source has made.
--
-- Layer:    reference. A snapshot-versioned table a loader writes and the signal
--           layer joins against, exactly like helena_reference_public_suffix --
--           not a view over observed traffic. The join to a context is per
--           entity (`concept/03-architecture.md`) and belongs to the enriched-
--           context view, which does not exist yet.
-- Object:   TABLE. The claims themselves; there is nothing below this to derive
--           them from, and a loader writes them.
-- Reads:    nothing.
-- Read by:  src/helena/enrichment.py (the writer and the shape) and
--           tests/test_evidence.py. The enriched-context view (a later D3
--           increment) is the reader this exists for; nothing joins it yet, and
--           a table -- unlike a materialized view -- costs nothing while it
--           waits.
-- Superseded by: 0014_feed_mapping_views.sql. That file drops this table and
--               does not recreate it: the evidence shape is now DERIVED from
--               each feed's reference table by a mapping view, which is what
--               concept/03-architecture.md means by an enrichment view. The
--               shape below is still the contract -- helena_reference_evidence
--               presents exactly these columns plus evidence_tier -- but this
--               CREATE is not what the engine holds.
CREATE TABLE IF NOT EXISTS helena_reference_enrichment_evidence (
    -- The ingestion identity, for the reason helena_normalized_events carries
    -- it: an INSERT onto an existing key in RisingWave is a silent upsert, and
    -- two deployments enriching the same entity must not overwrite each other.
    tenant             VARCHAR NOT NULL,
    sensor             VARCHAR NOT NULL,
    -- sha256 over identity, source, snapshot, entity, classification, scope and
    -- the native evidence. See helena.enrichment.evidence_id for what is in it
    -- and, more usefully, what is deliberately not: the status, because a claim
    -- that goes stale is the same claim.
    evidence_id        VARCHAR NOT NULL,
    source_id          VARCHAR NOT NULL,
    -- A-D, describing the SOURCE and never the entry
    -- (`concept/02-concepts-and-taxonomy.md`). It is denormalized onto the claim
    -- on purpose: a claim is replayed as it was made, and a source whose tier is
    -- re-rated later must not silently re-rate every claim it ever made.
    source_tier        VARCHAR NOT NULL,
    -- The feed snapshot this claim came from. Replay joins the snapshot current
    -- at event time, not today's.
    snapshot_version   VARCHAR NOT NULL,
    -- The join target: `address`, `domain`, `url` or `fingerprint`, matching
    -- what helena_signal_context_entities produces.
    entity_type        VARCHAR NOT NULL,
    entity_value       VARCHAR NOT NULL,
    -- ok / stale / failed / missing. Never `no_match`, which is a classification.
    status             VARCHAR NOT NULL,
    -- The taxonomy path, and the version it was drawn from. Both NULL exactly
    -- when the status is `failed` or `missing`.
    classification     VARCHAR,
    taxonomy_version   VARCHAR,
    -- Confidence in the MAPPING, not the probability the indicator is malicious
    -- (`concept/02`). A definitive negative answer can be `no_match` with 1.0,
    -- and a consumer that averaged this across sources as a threat score would
    -- be averaging the wrong quantity.
    confidence         DOUBLE PRECISION,
    -- `scope` as {type, value}, exactly normalized. Two columns rather than a
    -- blob because the composition rule reads them: a URL claim scopes to the
    -- URL and the host inherits only with host-level evidence, and a netblock
    -- claim scopes to a netblock and never to a host.
    scope_type         VARCHAR NOT NULL,
    scope_value        VARCHAR NOT NULL,
    -- Nullable and left that way. `concept/05` measured that references and
    -- last-seen dates are frequently absent, so first-seen plus the snapshot
    -- version is what dates a claim, and a last_seen defaulted to the load time
    -- would make every stale claim look fresh.
    first_seen         TIMESTAMPTZ,
    last_seen          TIMESTAMPTZ,
    valid_until        TIMESTAMPTZ,
    -- The minimal native fields that justify the mapping (`concept/05` rule 5).
    -- Minimal is the operative word: what justifies THIS mapping, not the
    -- provider's whole response.
    native_evidence    JSONB,
    PRIMARY KEY (tenant, sensor, evidence_id)
);
