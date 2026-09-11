-- 0018  The stored assessment: typed rows, and citations as join rows.
--
-- `concept/03-architecture.md`, "The store":
--
--   *"**Agent output is stored as typed, queryable rows with citation joins,
--   never as an opaque document.** The fields anyone would filter, join, group
--   or aggregate on are typed columns: host, tenant, context reference, window
--   bounds, verdict and classification, confidence, timestamps, model / prompt /
--   contract / rendering versions, budgets consumed, latency, tokens, cost, and
--   cache-hit versus live-query counts. Narrative stays a text column.
--   **Evidence citations are join rows** -- `(assessment, evidence, role)` -- not
--   an array buried in JSON, because citations are the thing most queries follow
--   and an array is where a query goes to die."*
--
-- Six tables, and the shape of the set is the point: one row per assessment and
-- one table per repeating thing, so every list an agent produced is rows a query
-- can filter and group rather than a document a query has to open.
--
-- ## A row is one AGENT RUN, not one pass through the router
--
-- `helena.orchestration.assess` routes one context and reaches one or two agents,
-- and every column the note lists above is a property of **one run**: the cost,
-- the latency, the nine versions, the model that answered, the endpoint it
-- answered from, the verdict and the confidence. A row per pass would have to
-- carry two of each or lose one. So a pass writes one row for triage and, where
-- it escalated, a second for the analyst -- which is also how `concept/03` lists
-- what the store holds: *"triage decisions, analyst assessments and evidence
-- packages"*.
--
-- The two rows of one pass share `(tenant, sensor, context_id, context_version)`,
-- which is what D7 joins them on for `concept/03`'s *"a context that was
-- escalated is emitted once, carrying the analyst's verdict and the triage
-- decision that led to it"*.
--
-- ## The identifier, and why a re-run rewrites rather than doubles
--
-- `assessment_id` is a sha256 over tenant, sensor, context reference, context
-- version, emitter and trigger -- `helena.orchestration.assessment_id`, the same
-- construction `helena.enrichment.evidence_id` uses and for the same reason.
-- `concept/03`: *"an interrupted run is simply re-run, because the versioned
-- context already makes that correct rather than a fallback."* A re-run of one
-- context version therefore mints the identifier the first run did, and a
-- RisingWave INSERT onto an existing primary key is a silent upsert -- so the
-- second run rewrites its own row instead of adding a second copy of it. The
-- child tables below are keyed by the same identifier and the writer deletes a
-- run's child rows before it writes them, because an upsert cannot remove a row
-- the second run no longer produces.
--
-- **The outcome is not in the digest.** Two runs over one context version are the
-- same assessment made twice, not two assessments; putting the verdict in the
-- identifier would make a re-run that answered differently a new row and leave
-- the old one standing as a second live opinion.
--
-- ## A typed failure is a row here, with no verdict in it
--
-- `concept/02`: *"**Typed failure** -- a run that could not produce a verdict,
-- stored as an assessment row carrying the failure and **no** verdict -- never a
-- verdict, never a silent drop."* So `classification`, `confidence` and
-- `narrative` are nullable and `failure_reason` / `failure_detail` are nullable,
-- and exactly one side of that pair is populated on any row. There is no CHECK
-- constraint because RisingWave has none; `helena.orchestration.AssessmentStore`
-- refuses to write a row with both or neither, and `tests/test_assessments.py`
-- asserts the property against rows read back out of the engine.
--
-- ## There is no `verdict` column, and that is deliberate
--
-- The step list this file was built from asks for "verdict and classification".
-- The verdict is the root of the classification and the taxonomy already refuses
-- a path whose root is not its first segment, so a stored column would be a
-- second copy of a fact that cannot disagree in the model and can in a table --
-- exactly the reading `helena.enrichment.EnrichmentEvidence.verdict` and
-- `helena.contracts.v1.AgentResult.root` already took, and the reason
-- `sql/migrations/0017`'s evidence table has no such column either. In SQL it is
-- `split_part(classification, '.', 1)`.
--
-- ## What the money columns are, and when they are NULL
--
-- `concept/06-technology.md`: *"monetary model cost is **derived** and recorded
-- per assessment, not separately capped."* Derived from the two token counts and
-- a price table, and **the price of a model is an external fact this repository
-- does not know**. So `config/policy.toml`'s `[model_prices]` is the table, it
-- ships with no entries, and a model with no entry stores NULL in all three
-- columns rather than a plausible number. NULL is "not priced" and is not zero:
-- collapsing the two would be the same mistake as collapsing `missing` into
-- `no_match`.


-- helena_analytical_assessment: one agent run, as the columns a query filters on.
--
-- Layer:    analytical. The top of the pipeline: what the signal and reference
--           layers were assessed into. It reads nothing -- deterministic code
--           writes it -- and it is `analytical` rather than `reference` because
--           the views that will read it (D7's sink, an evaluation) join it to
--           the signal layer's context and the reference layer's evidence, and
--           `helena.migrations.MAY_READ` lets only `analytical` read both.
-- Object:   TABLE. Agent output written by code; there is nothing below it to
--           derive it from.
-- Reads:    nothing.
-- Read by:  src/helena/orchestration.py (the writer),
--           helena_analytical_sink (sql/migrations/0019, which selects the
--           terminal run of a pass and the triage decision beside it) and
--           tests/test_assessments.py.
CREATE TABLE IF NOT EXISTS helena_analytical_assessment (
    -- sha256 over identity, context reference, context version, emitter and
    -- trigger. See the head of this file.
    assessment_id                  VARCHAR NOT NULL,
    tenant                         VARCHAR NOT NULL,
    sensor                         VARCHAR NOT NULL,
    host                           VARCHAR NOT NULL,
    -- The context reference and its version. `concept/04-the-two-agents.md`: the
    -- version "is what makes replay possible".
    context_id                     VARCHAR NOT NULL,
    context_version                VARCHAR NOT NULL,
    -- The window in EVENT time, copied from the request. Not the time the row
    -- was written: an assessment replayed later has to score the window that ran.
    window_start                   TIMESTAMPTZ NOT NULL,
    window_end                     TIMESTAMPTZ NOT NULL,
    emitter                        VARCHAR NOT NULL,
    -- `helena.contracts.v1.TRIGGERS`. Named `triggered_by` because `trigger` is
    -- a reserved word in this dialect; the contract field it carries is
    -- `AgentRequest.trigger`.
    triggered_by                   VARCHAR NOT NULL,
    -- When the row was written, in wall time. The event-time window above is the
    -- period assessed; this is when the assessment of it happened.
    assessed_at                    TIMESTAMPTZ NOT NULL,

    -- The verdict half. NULL on a typed failure, all three of them.
    classification                 VARCHAR,
    -- `concept/04`: "a number to measure, not a routing constant."
    confidence                     DOUBLE PRECISION,
    -- `concept/03`: "narrative stays a text column". The analyst's evidence
    -- package's narrative, bounded by the contract at 4 000 characters, and the
    -- only column in this schema that holds a sentence a model wrote. Nothing
    -- reads it back into a prompt -- see tests/test_assessments.py.
    narrative                      VARCHAR,

    -- The failure half. NULL on a verdict, both of them.
    -- `helena.contracts.v1.FAILURE_REASONS`.
    failure_reason                 VARCHAR,
    failure_detail                 VARCHAR,

    -- The nine version dimensions, under `helena.versions.VersionSet`'s own field
    -- names, plus the tenth thing a request records: what this deployment ASKED
    -- for, which is not what answered. `model_version` is the identity the
    -- response reported and is NULL exactly on a `model_unavailable` failure,
    -- where nothing answered at all.
    model_version                  VARCHAR,
    model_requested                VARCHAR NOT NULL,
    prompt_version                 VARCHAR NOT NULL,
    schema_version                 VARCHAR NOT NULL,
    rendering_version              VARCHAR NOT NULL,
    taxonomy_version               VARCHAR NOT NULL,
    enrichment_snapshot_version    VARCHAR NOT NULL,
    normalization_snapshot_version VARCHAR NOT NULL,
    policy_version                 VARCHAR NOT NULL,
    aggregation_version            VARCHAR NOT NULL,

    -- What the run was GRANTED, from `helena.contracts.v1.Budgets`. Stored as the
    -- four numbers rather than as a pointer to a revision of config/policy.toml:
    -- the numbers are what bounded the run, and a version string would only be
    -- resolvable while that file still held the entry it names.
    budget_steps                   INT NOT NULL,
    budget_tokens                  INT NOT NULL,
    budget_wall_clock_seconds      DOUBLE PRECISION NOT NULL,
    budget_live_queries            INT NOT NULL,

    -- What it SPENT, from `helena.contracts.v1.Cost`. `wall_clock_seconds` is the
    -- latency `concept/03` lists, and it is the whole run's.
    prompt_tokens                  INT NOT NULL,
    completion_tokens              INT NOT NULL,
    steps                          INT NOT NULL,
    -- `concept/07-principles.md`: two runs that differ only in cache state must
    -- be distinguishable afterwards. These two columns are how.
    live_queries                   INT NOT NULL,
    cache_hits                     INT NOT NULL,
    -- `concept/07`: "the retry count per model is itself a quality metric".
    retries                        INT NOT NULL,
    wall_clock_seconds             DOUBLE PRECISION NOT NULL,

    -- The derived monetary cost, its currency and the revision of the price table
    -- that derived it. All three NULL together where the model has no configured
    -- price -- see the head of this file.
    model_cost                     DOUBLE PRECISION,
    model_cost_currency            VARCHAR,
    model_prices_version           VARCHAR,

    -- Host and port of the endpoint the prompt actually went to, read off this
    -- run's own disclosure ledger rather than off configuration. `concept/07`:
    -- "because endpoints are configurable per agent, cross-wiring is possible,
    -- and recording endpoint and model per assessment is what makes it
    -- detectable." NULL where no prompt ever left the process, which is a
    -- different fact from a run that reached an endpoint and failed.
    endpoint_host                  VARCHAR,
    PRIMARY KEY (assessment_id)
);


-- helena_analytical_assessment_citation: `(assessment, evidence, role)`.
--
-- Layer:    analytical. The join `concept/03` asks for by name.
-- Object:   TABLE. Written by code from `AgentResult.citations`.
-- Reads:    nothing.
-- Read by:  src/helena/orchestration.py, helena_analytical_sink
--           (sql/migrations/0019, for `cited_as`) and
--           tests/test_assessments.py.
--
-- The primary key is `(assessment_id, evidence_id)` and not all three columns:
-- `helena.contracts.v1.AgentResult` already refuses a result that cites one
-- evidence id twice -- "one row cannot both support and contradict a verdict" --
-- and a key that admitted the same evidence under two roles would let the store
-- hold what the contract refuses.
CREATE TABLE IF NOT EXISTS helena_analytical_assessment_citation (
    assessment_id VARCHAR NOT NULL,
    -- `helena.enrichment.evidence_id`'s. It resolves into
    -- helena_reference_evidence (0014) or helena_reference_evidence_analyst
    -- (0017) -- one identifier across both tiers, which is what makes the join
    -- one join.
    evidence_id   VARCHAR NOT NULL,
    -- `helena.contracts.v1.STANCES`: supporting or contradicting.
    -- `concept/02-concepts-and-taxonomy.md` calls it the role.
    role          VARCHAR NOT NULL,
    PRIMARY KEY (assessment_id, evidence_id)
);


-- helena_analytical_assessment_gap: what the run could not see, one row per gap.
--
-- Layer:    analytical.
-- Object:   TABLE. Written by code from `AgentResult.gaps` / `AgentFailure.gaps`.
-- Reads:    nothing.
-- Read by:  src/helena/orchestration.py and tests/test_assessments.py.
--
-- `concept/02` names the seven kinds -- missing, stale, in-flight, failed,
-- found-nothing, truncated, budget-exhausted -- and `concept/instruction.md` §2
-- forbids collapsing any of them into another, so `kind` is one of
-- `helena.contracts.v1.GAP_KINDS` and there is no column that could merge two.
-- (`no_match` is the note's "found-nothing", spelled as
-- `helena.enrichment.NO_MATCH` spells it.)
--
-- The key carries an ordinal because two gaps of one kind with different details
-- are two gaps: a run can be missing two things.
CREATE TABLE IF NOT EXISTS helena_analytical_assessment_gap (
    assessment_id VARCHAR NOT NULL,
    -- Position in the outcome's gaps list, which is the order they were recorded.
    ordinal       INT NOT NULL,
    kind          VARCHAR NOT NULL,
    -- Required by the contract and bounded by it: a gap with no detail records
    -- that something was missing without recording what.
    detail        VARCHAR NOT NULL,
    PRIMARY KEY (assessment_id, ordinal)
);


-- helena_analytical_assessment_pattern: the evidence package's patterns.
--
-- Layer:    analytical.
-- Object:   TABLE. Written by code from `EvidencePackage.patterns`.
-- Reads:    nothing.
-- Read by:  src/helena/orchestration.py and tests/test_assessments.py.
--
-- `concept/02`: *"**Evidence package** -- assembled cited evidence: indicators,
-- patterns, missing information, narrative."* The indicators are the citation
-- rows above and the missing information is the gap rows; the narrative is a
-- column on the assessment; this is the fourth part. Rows rather than an array on
-- the assessment, for the reason the citations are rows.
--
-- A pattern is a bounded phrase the analyst named, not a note: the contract caps
-- it at `helena.contracts.v1.MAX_DETAIL` and nothing reads it back into a prompt.
CREATE TABLE IF NOT EXISTS helena_analytical_assessment_pattern (
    assessment_id VARCHAR NOT NULL,
    ordinal       INT NOT NULL,
    pattern       VARCHAR NOT NULL,
    PRIMARY KEY (assessment_id, ordinal)
);


-- helena_analytical_assessment_retrieval: the retrieval trace, one row per result.
--
-- Layer:    analytical.
-- Object:   TABLE. Written by code from `AgentResult.retrieval_trace`.
-- Reads:    nothing.
-- Read by:  src/helena/orchestration.py and tests/test_assessments.py.
--
-- `concept/07`, "Caching": *"the retrieval trace records, per result, **whether
-- it was a cache hit or a live query**, and the retrieval time of the underlying
-- record. Two runs that differ only in cache state must be distinguishable
-- afterwards."*
--
-- `evidence_id` and the two failure columns are exclusive, the way
-- `helena.contracts.v1.RetrievalStep` makes them exclusive: a query that
-- completed produced an evidence row -- `no_match` included, which is an answer
-- -- and one that did not produced a typed error and no taxonomy object
-- (`concept/05-threat-intelligence.md`, rule 4).
CREATE TABLE IF NOT EXISTS helena_analytical_assessment_retrieval (
    assessment_id  VARCHAR NOT NULL,
    -- Position in the trace: the order the loop retrieved in.
    ordinal        INT NOT NULL,
    source_id      VARCHAR NOT NULL,
    entity_type    VARCHAR NOT NULL,
    entity_value   VARCHAR NOT NULL,
    -- `helena.contracts.v1.RETRIEVAL_OUTCOMES`: cache_hit or live_query. Both are
    -- successful retrievals; a query that did not complete carries the failure
    -- columns below instead.
    outcome        VARCHAR NOT NULL,
    -- The UNDERLYING record's retrieval time, not the step's: a cache hit carries
    -- the age of what it served.
    retrieved_at   TIMESTAMPTZ NOT NULL,
    evidence_id    VARCHAR,
    -- `helena.enrichment.QUERY_FAILURE_REASONS`. Never `no_match`, which is a
    -- classification on a completed query and lives on an evidence row.
    failure_reason VARCHAR,
    failure_detail VARCHAR,
    PRIMARY KEY (assessment_id, ordinal)
);


-- helena_analytical_assessment_disclosure: what left, to whom, and when.
--
-- Layer:    analytical.
-- Object:   TABLE. Written by code from `helena.disclosure.Disclosures.rows`.
-- Reads:    nothing.
-- Read by:  src/helena/orchestration.py and tests/test_assessments.py.
--
-- `concept/07`, "Privacy and disclosure": *"what may be sent to which source is
-- governed policy, and **what was disclosed is recorded on the assessment** --
-- source, query, cache hit or live, disclosed-to, and when."* Four of those five
-- are columns here and the fifth is the retrieval trace above, on the same
-- assessment: a disclosure row exists only where something was SENT, so a cache
-- hit has a trace row and no disclosure row, which is what makes the two counts
-- reconcile.
--
-- Both channels are here. `concept/03` makes hosted inference egress too, so a
-- `model_inference` row is what says a prompt left this network -- and it is
-- where `helena_analytical_assessment.endpoint_host` is read from.
CREATE TABLE IF NOT EXISTS helena_analytical_assessment_disclosure (
    assessment_id       VARCHAR NOT NULL,
    -- Position in the ledger: the order the run disclosed in.
    ordinal             INT NOT NULL,
    -- `helena.disclosure.CHANNELS`: provider_lookup or model_inference.
    channel             VARCHAR NOT NULL,
    -- Who was told: a registered source id for a lookup, the model asked for a
    -- model call.
    source              VARCHAR NOT NULL,
    -- The host that received it. A host and never a URL -- `concept/07` requires
    -- a credential travelling in a URL to be redacted before anything is stored,
    -- and a column that holds no URL cannot hold one.
    disclosed_to        VARCHAR NOT NULL,
    -- What was disclosed, in words and bounded: the indicator for a lookup, the
    -- shape and size of the prompt for a model call and never its text.
    query               VARCHAR NOT NULL,
    -- sha256 of exactly the bytes that left, so the record can be checked against
    -- the rendering or the stored response without a second copy of either.
    query_digest        VARCHAR NOT NULL,
    disclosed_at        TIMESTAMPTZ NOT NULL,
    -- Which revision of config/policy.toml's send policy was in force.
    send_policy_version VARCHAR NOT NULL,
    PRIMARY KEY (assessment_id, ordinal)
);
