-- 0017  The analyst-tier lookup cache, which is the evidence store.
--
-- `concept/07-principles.md`, "Caching": *"Every provider tool is cache-first.
-- On each call it looks for a valid, unexpired record for its source, endpoint
-- and indicator, and returns it without touching the network; it queries only on
-- a miss or an expiry."* And the structural half of the same paragraph: **"the
-- cache IS the evidence store, not a second store beside it. A separate opaque
-- cache was rejected because an assessment could then cite something the cache
-- had already evicted."**
--
-- So there is no cache here in the sense `concept/instruction.md` §3 forbids --
-- no Redis, no file, no in-process dictionary. There are two tables in the one
-- store, holding the same evidence shape 0011 defined and 0014 derives for the
-- feeds, plus the three columns a cache needs: the endpoint, the retrieval time
-- and the expiry.
--
-- ## Two tables, because a response and a claim are not the same object
--
--   helena_reference_analyst_response  one row per (cache key, response), the
--                                      provider's bytes exactly as they arrived
--   helena_reference_analyst_evidence  N rows per response, one per claim read
--                                      out of it
--
-- The response table exists because `concept/05-threat-intelligence.md` asks for
-- it in as many words: *"store the response before it is evaluated, cited by
-- stable identifier, or an assessment that depended on a live lookup cannot be
-- replayed because the provider's answer will have changed."* The identifier is
-- the sha256 of the bytes (`helena.tools.response_version`), and it is the same
-- value the claims carry as `snapshot_version` -- a live answer has no feed
-- snapshot, and what dates it is the response it came out of.
--
-- The response is written **before** the claims are validated, which is what
-- makes a `malformed_response` failure investigable: the bytes that would not
-- map are on disk, cited by their digest, and the absence of claims beside them
-- is exactly why a later lookup treats that key as a miss rather than serving
-- half an answer.
--
-- ## Nothing is evicted, and that is the point
--
-- `expires_at` bounds **validity**, never lifetime. An expired row is still
-- there, still citable, and still readable by a replay -- which is the property
-- the rejected opaque cache could not offer. Two consequences, both deliberate:
--
--   * an assessment that cited an evidence row can always resolve the citation,
--     however long ago the lookup happened;
--   * both tables grow without bound. Pruning is deferred and stays deferred:
--     `helena.enrichment.prune_snapshots` is the shape it would take, and what
--     it should keep is a function of how far back replay has to reach, which
--     `concept/08-open-questions.md` still lists as open.
--
-- ## There is no `status` column, for the reason `feed_status` has no table
--
-- `ok` and `stale` are properties of **now**, not of the row.
-- `helena.enrichment.feed_status` computes them from the snapshot ledger at read
-- time and its docstring gives the argument: *"a stored `stale` would be wrong
-- the moment time passed."* The same holds here, and harder -- a cached claim
-- crosses from `ok` to `stale` with no writer involved. So the row stores
-- `retrieved_at` and `expires_at`, and `helena.tools.CacheEntry.evidence`
-- derives the status against the clock the run was given. That is also why the
-- evidence identifier does not change when an entry expires:
-- `helena.enrichment.evidence_id` deliberately excludes the status, because a
-- claim that goes stale is the same claim.
--
-- `failed` and `missing` have no row here at all, and that is not an omission.
-- A query that did not complete produces a typed error and no taxonomy object
-- (`concept/05` rule 4), so there is nothing to store; and a cache **miss** is
-- not `missing` -- it is the reason to query. Recording a miss as `missing`
-- would be the collapse `concept/instruction.md` §2 forbids, dressed as an
-- optimisation.
--
-- ## What is deliberately not unioned into helena_reference_evidence
--
-- 0014's `helena_reference_evidence` is the enrichment tier: static feeds joined
-- per entity into `helena_analytical_enriched_context`, which is what triage is
-- rendered from. Analyst-tier rows are **not** added to it here. The tier tag
-- would keep them out of the triage rendering (`helena.rendering` allow-lists
-- `enrichment`), but they would still enter the enriched context of every later
-- host that talked to the same address -- and `concept/03-architecture.md` names
-- that outcome as the thing the tier tag exists to prevent, not as something the
-- tag makes safe. How an analyst-tier claim reaches a finding is the increment
-- that writes findings; the view below is where it would attach.


-- helena_reference_analyst_response: what a provider actually sent, retained.
--
-- Layer:    reference. A table a writer fills and a reader joins nothing to --
--           the same place helena_reference_threatfox sits. It is not the
--           `operational` layer that holds attempts and ledgers: this is the
--           evidence a claim was read out of, and replay reads it.
-- Object:   TABLE. The bytes themselves; there is nothing below this to derive
--           them from, and the tool layer writes them.
-- Reads:    nothing.
-- Read by:  src/helena/tools.py (the writer, and the cache read that rebuilds
--           the native response a lookup returns) and tests/test_tools.py.
--
-- The key is the cache key plus the response digest, so re-fetching an identical
-- answer rewrites the same row rather than adding a second copy -- RisingWave
-- has no transaction around DML and an INSERT onto an existing primary key is a
-- silent upsert, so idempotence has to come from the key. A *different* answer
-- for the same indicator is a different digest and therefore a new row, which is
-- what lets a replay see that the provider's answer changed.
CREATE TABLE IF NOT EXISTS helena_reference_analyst_response (
    tenant           VARCHAR NOT NULL,
    sensor           VARCHAR NOT NULL,
    source_id        VARCHAR NOT NULL,
    -- Which operation of the source this was. Part of the cache key because
    -- `concept/07` puts it there: two endpoints of one provider answer
    -- different questions about one indicator, and a key without it serves one
    -- answer for the other.
    endpoint         VARCHAR NOT NULL,
    entity_type      VARCHAR NOT NULL,
    -- The indicator **as the caller asked about it**: what was disclosed to the
    -- provider, spelling and all. Kept beside the normalized key for the reason
    -- 0008 keeps `observed_name` beside `normalized_name` -- so the two are
    -- never confused, and so the disclosure record has the literal string.
    entity_value     VARCHAR NOT NULL,
    -- The normalized indicator: what a lookup matches on. See
    -- helena.tools.normalize_indicator for what it folds and, more usefully,
    -- what it refuses to fold.
    entity_value_key VARCHAR NOT NULL,
    -- sha256 of `body`. The stable identifier `concept/05` rule 5 asks a stored
    -- response to be cited by, and the value the claims below carry as their
    -- snapshot_version.
    response_version VARCHAR NOT NULL,
    retrieved_at     TIMESTAMPTZ NOT NULL,
    -- Exactly as it arrived -- the rule quarantine follows. A payload normalized
    -- before it is stored is a payload no audit can compare against what the
    -- provider actually sent. BYTEA and not TEXT for the same reason: an
    -- encoding guess here would be a re-encoding nobody recorded.
    body             BYTEA NOT NULL,
    PRIMARY KEY (
        tenant, sensor, source_id, endpoint, entity_type, entity_value_key,
        response_version
    )
);


-- helena_reference_analyst_evidence: the claims read out of those responses.
--
-- Layer:    reference. The analyst-tier half of what helena_reference_evidence
--           is for the enrichment tier.
-- Object:   TABLE. A tool writes it; there is nothing below it to derive it
--           from, and unlike the feeds there is no native reference table to
--           map -- the native record is the response above, which is bytes.
-- Reads:    nothing.
-- Read by:  helena_reference_evidence_analyst below, src/helena/tools.py and
--           tests/test_tools.py.
--
-- The columns are 0011's evidence shape with three additions -- endpoint,
-- retrieved_at, expires_at -- and one removal, `status`, for the reason the head
-- of this file gives.
CREATE TABLE IF NOT EXISTS helena_reference_analyst_evidence (
    tenant           VARCHAR NOT NULL,
    sensor           VARCHAR NOT NULL,
    -- sha256 over identity, source, response digest, entity, classification,
    -- scope and the native record -- helena.enrichment.evidence_id, the same
    -- function sql/migrations/0014 has a second home for. The endpoint is NOT
    -- in it: the identifier is a contract shared with the enrichment tier and
    -- widening it would change every feed row's identity for a distinction
    -- feeds do not have. It is in the PRIMARY KEY below instead, and that is a
    -- measured correction rather than a precaution -- two endpoints of one
    -- source that return the same bytes about one indicator read the same claim
    -- out of them and therefore mint the same evidence_id, so a key without the
    -- endpoint made the second lookup upsert the first and hand it the *other*
    -- endpoint's retention. A citation by evidence_id then resolves to one row
    -- per endpoint that retrieved it: the same claim, retrieved twice, with two
    -- retrieval times, which is what happened.
    evidence_id      VARCHAR NOT NULL,
    source_id        VARCHAR NOT NULL,
    endpoint         VARCHAR NOT NULL,
    -- A-D, describing the SOURCE and never the entry, denormalized onto the
    -- claim for 0011's reason: a claim is replayed as it was made.
    source_tier      VARCHAR NOT NULL,
    -- The response digest. A live answer has no feed snapshot, so what dates a
    -- claim is the response it came out of -- and it joins this row to the bytes
    -- in helena_reference_analyst_response.
    snapshot_version VARCHAR NOT NULL,
    entity_type      VARCHAR NOT NULL,
    -- The **normalized** indicator, on both columns and for two different
    -- reasons. `entity_value` is the claim's subject, and a claim is about an
    -- address rather than about the spelling someone used to ask; that also
    -- makes what a cache hit serves identical to what the live query that filled
    -- it produced. `entity_value_key` is the lookup column. They are equal today
    -- and are two columns because the second is part of a key and the first is
    -- part of a contract, and merging them would make a normalization change a
    -- contract change.
    entity_value     VARCHAR NOT NULL,
    entity_value_key VARCHAR NOT NULL,
    -- Always present: every row here came out of a query that completed, and
    -- `no_match` is a classification and an answer. A query that did not
    -- complete writes nothing.
    classification   VARCHAR NOT NULL,
    taxonomy_version VARCHAR NOT NULL,
    -- Confidence in the MAPPING, not the probability the indicator is malicious.
    confidence       DOUBLE PRECISION,
    scope_type       VARCHAR NOT NULL,
    scope_value      VARCHAR NOT NULL,
    first_seen       TIMESTAMPTZ,
    last_seen        TIMESTAMPTZ,
    valid_until      TIMESTAMPTZ,
    native_evidence  JSONB,
    -- When the provider was asked. `RetrievalStep.retrieved_at` is documented as
    -- the UNDERLYING record's time rather than the step's, and this is that
    -- value: a cache hit carries the age of what it served, which is the number
    -- that says whether the answer was current.
    retrieved_at     TIMESTAMPTZ NOT NULL,
    -- retrieved_at + the retention configured for this source and endpoint. It
    -- bounds validity and not lifetime: see the head of this file.
    expires_at       TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant, sensor, endpoint, evidence_id)
);


-- helena_reference_evidence_analyst: those claims, tagged with their tier.
--
-- Layer:    reference. It projects one reference table and joins nothing.
-- Object:   VIEW (plain). A projection with one literal in it: no aggregate, no
--           join, nothing to keep state for, and materializing it would pay for
--           a second copy of a table that is already stored.
-- Reads:    helena_reference_analyst_evidence
-- Read by:  src/helena/tools.py -- the cache read goes through this view rather
--           than the table, so every hit is checked against the literal below --
--           and tests/test_tools.py.
--
-- The view exists for one reason: `evidence_tier` is a constant with two homes,
-- Python's `helena.enrichment.ANALYST_TIER` and this literal, and
-- `concept/instruction.md` §2 requires two copies of a version constant to be
-- asserted equal **by a test that asks the engine**. 0014 does exactly this for
-- `'enrichment'` and tests/test_rendering.py asserts it; tests/test_tools.py now
-- owes and pays the same for `'analyst'`. Without the view the literal would
-- exist only in Python, and the tier that keeps a live lookup out of the
-- precomputed triage path would be a value nothing could be wrong about.
CREATE VIEW helena_reference_evidence_analyst AS
SELECT e.evidence_id,
       e.tenant,
       e.sensor,
       e.source_id,
       e.source_tier,
       -- How the evidence got here, which is not how strong it is. The other
       -- value of this vocabulary is 0014's 'enrichment'.
       'analyst'                                AS evidence_tier,
       e.endpoint,
       e.snapshot_version,
       e.entity_type,
       e.entity_value,
       e.entity_value_key,
       e.classification,
       e.taxonomy_version,
       e.confidence,
       e.scope_type,
       e.scope_value,
       e.first_seen,
       e.last_seen,
       e.valid_until,
       e.native_evidence,
       e.retrieved_at,
       e.expires_at
FROM helena_reference_analyst_evidence e;
