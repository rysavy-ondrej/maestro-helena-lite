-- 0008  The Public Suffix List: registrable-domain normalization, not enrichment.
--
-- `concept/05-threat-intelligence.md` puts the Public Suffix List in the source
-- catalogue with an empty "Maps to" cell and no tier, and says what it is for in
-- one line: **"Registrable-domain normalization -- needed for scope correctness,
-- not enrichment"**. That sentence is the whole design constraint of this file,
-- and it cuts two ways.
--
-- It is **normalization**, so the rows here answer one question -- where does the
-- registry-controlled part of a name end and the registrant-controlled part
-- begin -- and they answer it about the *name*, not about the *host*. The table
-- carries no threat type, no confidence, no first-seen, no compromised flag and
-- no tier, because there is nothing here to be confident about: a rule is not an
-- observation. **Nothing in this file produces a taxonomy claim**, nothing here
-- can escalate, and a name's registrable domain is not evidence of anything. A
-- match against a rule in `helena_reference_public_suffix` says only "these
-- labels are a public suffix", which is a fact about the DNS delegation
-- hierarchy and not about the traffic.
--
-- It is needed for **scope correctness**, which is why it is not optional. The
-- composition rule of `concept/02-concepts-and-taxonomy.md` weighs scope before
-- severity, and a scope comparison between a feed's domain and an observed name
-- is unreliable without it in both directions:
--
--   * too wide -- `example.co.uk` and `other.co.uk` share two trailing labels
--     and share nothing else. A comparison that stopped at "the last two labels
--     agree" would put every UK registrant in one scope.
--   * too narrow -- `a.b.example.com` and `c.example.com` are the same
--     registrant, and a comparison on the name alone cannot say so.
--
-- Both errors are invisible without a list of where the boundary actually is,
-- and the boundary is not derivable from the name: it is published, per suffix,
-- and it changes. Measured on the snapshot fetched 2026-09-03: 10 321 rules, of
-- which 287 are wildcards and 8 are exceptions, spread over 6 949 ICANN and
-- 3 372 private-section entries.
--
-- ## This does not change what a feed is matched on
--
-- `docs/decisions/0009-netify-application-identification.md` fixes the matching
-- rule for the one source the prototype has: match "on the name **as observed**
-- -- from DNS or TLS SNI -- and never on the registrable domain", because that
-- source's keys are not all registrable domains. Nothing here weakens that. The
-- entity value stays exactly as observed (0007 produces it and this file does
-- not touch it); the registrable domain arrives **beside** it as a new column,
-- for a comparison that asks a different question. A future join that matched on
-- the registrable domain would be a decision recorded where ADR-0009 is, not a
-- consequence of this table existing.
--
-- ## The algorithm, and why it is four objects rather than a function
--
-- The list's own algorithm (publicsuffix.org/list/, "Algorithm"): match the name
-- against every rule, where a rule's labels must equal the name's rightmost
-- labels and a leading `*` matches any single label; an exception rule (leading
-- `!`) that matches wins outright and the prevailing rule is that rule with its
-- leftmost label removed; otherwise the prevailing rule is the one with the most
-- labels; if none matches, the prevailing rule is `*`. The public suffix is the
-- matching labels, and the registrable domain is the public suffix plus one more
-- label to its left.
--
-- RisingWave has no user-defined function this could be written as -- embedded
-- Python UDFs are the thing `bin/README.md` records as an ABI hazard, and a
-- Python function on the stream path is what `concept/instruction.md` §1 gives
-- to the engine instead. So the algorithm is a join, and a join needs an
-- **equi-join**: `LIKE '%.' || suffix` would be a streaming nested-loop join,
-- which RisingWave refuses outright (measured here, and in 0002 before it). The
-- shape that works is to generate the name's candidate suffixes -- its rightmost
-- 0, 1, 2 ... labels -- and equi-join those against the rule's labels.
--
-- Three details make one join enough for all three rule kinds:
--
--   * a rule is stored with its `*.` or `!` marker **stripped** into `suffix`,
--     and the two booleans say which kind it was. A wildcard `*.ck` is stored as
--     `ck` and matches the candidate `ck` while asserting a suffix one label
--     *longer* than the candidate -- which is what `*` means -- so it is guarded
--     by `name_label_count > candidate_label_count`: there has to be a label for
--     the `*` to consume. That guard is also what keeps every slice below
--     well-formed: it is the only reason `suffix_label_count` can never exceed
--     `name_label_count`, and an out-of-range slice **clamps** in RisingWave
--     rather than raising, so without it a wrong answer would look like a right
--     one. Mutation-checked: removing the guard leaves all 77 published vectors
--     passing, which is why
--     tests/test_enrichment.py::test_a_wildcard_needs_a_label_to_consume exists
--     and asserts the suffix *length* rather than only the name.
--   * an exception `!www.ck` is stored as `www.ck` and asserts a suffix one
--     label *shorter* than the candidate, which is "the rule with its leftmost
--     label removed" said arithmetically.
--   * the algorithm's default rule `*` is stored as an actual row, with an empty
--     suffix, matching the zero-label candidate. That is not decoration: it
--     makes every valid name match at least one rule, so `snapshot_version`
--     reaches every derived row through the join, and a name with **no** match
--     means the table is empty rather than meaning "no rule applies". Those two
--     are `missing` and `no_match` and `concept/instruction.md` §2 forbids
--     collapsing them.
--
-- The candidate count per name is `generate_series(0, cardinality(labels))` --
-- bounded by the name's own label count, so no view here carries an arbitrary
-- depth limit that a future rule could outgrow silently. Measured on the
-- 2026-09-03 snapshot: the deepest stored suffix is 6 labels, so a name deeper
-- than that generates candidates that cannot match, which is correct and costs
-- one row each.
--
-- ## Normalization of the name, and what it does not reach
--
-- The name is lowercased and its trailing dots are removed before any of this,
-- and `normalized_name` is on the row beside `observed_name` so the two are
-- never confused. Two measured limits, stated rather than assumed:
--
--   * RisingWave 3.0.3's `lower()` is ASCII-only -- `lower('ÉX')` is `'Éx'`,
--     measured. A U-label observed in uppercase is therefore not folded. The
--     sample carries no non-ASCII name at all, so this is unexercised rather
--     than known-harmless.
--   * A rule whose labels are non-ASCII is loaded **twice**, once as published
--     and once punycoded, because a name may be observed in either form and the
--     join is on bytes. `公司.cn` and `xn--55qx5d.cn` are both keys of the same
--     rule; the loader does the punycoding (src/helena/enrichment.py) because
--     the engine has no IDNA function.
--
-- Two names are refused as not being domain names at all, and get
-- `registrable_domain_status = 'invalid_name'` rather than a plausible answer:
-- a name with an empty label (`.example.com`, `a..b`) and a name whose rightmost
-- label is all digits (`1.2.3.4` -- an address literal, which a URI host part
-- can be). A bracketed IPv6 literal is **not** detected; measured over
-- data/ingest/flow-sample.jsonl, no URI host is an address literal of either
-- kind, so the guard is exercised only by the tests.
--
-- ## What this file does not do
--
-- **It does not decide ICANN-only versus ICANN-plus-private.** Both sections are
-- loaded and both are used, which is the choice that makes shared infrastructure
-- separable: `user.github.io` and `other.github.io` are different registrants,
-- and so are two names under `*.workers.dev`, which is the shared-infrastructure
-- case `data/threatfox/domains_recent.json` actually contains. `section` is on
-- every rule row so an ICANN-only derivation can be added when something needs
-- one; nothing does yet, and a second derivation with no reader would be a view
-- with one caller and no way to be wrong.
--
-- **It does not derive a registrable domain for `url` entities.** A URL's host
-- part is already a `domain` entity of its own (0007), so the derivation reaches
-- it there.
--
-- **It has no schedule.** "Its own schedule" is `scripts/load_public_suffix_list.py`
-- run by whatever runs it; nothing in this repository schedules anything, and a
-- scheduler would be a second store of state.


-- helena_reference_public_suffix: the rules of one snapshot of the list.
--
-- A TABLE, not a view. It is state with a writer:
-- src/helena/enrichment.py::load_public_suffix_list INSERTs one row per rule
-- over the PostgreSQL wire protocol. Read by the derivation views below and by
-- tests/test_enrichment.py.
--
-- The grain is one row per **match key**, which is one row per rule except for
-- the 459 rules whose labels are not ASCII -- those get two, as the head
-- explains -- so the primary key is (rule, suffix) rather than either alone.
--
-- The table holds **exactly one snapshot at a time**, and `snapshot_version` is
-- on every row so a derived row can record which one decided it. The loader
-- writes the new snapshot's rows first and deletes the previous snapshot's
-- second, so a load that dies halfway leaves a superset rather than an empty
-- table; a failed *fetch* writes nothing here at all and leaves the previous
-- snapshot in place, which is what `concept/instruction.md` §6 requires of a
-- feed loader and is recorded in the load table below.
--
-- There is deliberately no `fetched_at` column here. When a snapshot was
-- fetched is a property of the load, not of a rule, and 10 322 copies of one
-- timestamp is a column that can disagree with itself.
CREATE TABLE helena_reference_public_suffix (
    -- The sha256 of the fetched bytes. Same content, same version: two fetches
    -- of an unchanged list are one snapshot, and the loader says `unchanged`
    -- rather than rewriting ten thousand identical rows.
    snapshot_version VARCHAR NOT NULL,
    -- The line as published, markers and all: `com`, `*.ck`, `!www.ck`, and `*`
    -- for the algorithm's default rule, which is not a line in the file.
    rule             VARCHAR,
    -- The match key: `rule` with `*.` or `!` removed, and punycoded when the
    -- published form is not ASCII. Empty for the default rule.
    suffix           VARCHAR,
    is_wildcard      BOOLEAN NOT NULL,
    is_exception     BOOLEAN NOT NULL,
    -- `icann`, `private`, or `default` for the algorithm's `*`. Kept because the
    -- section is what an ICANN-only derivation would filter on, and because a
    -- rule's section is the difference between "a registry sold this" and "a
    -- platform hands these out".
    section          VARCHAR NOT NULL,
    PRIMARY KEY (rule, suffix)
);


-- helena_reference_public_suffix_load: one row per load attempt, including the
-- ones that failed.
--
-- A TABLE, written by the same loader. Read by tests/test_enrichment.py and by
-- an operator asking when the list was last refreshed and whether it worked.
--
-- A failed fetch has to be visible or the previous snapshot silently becomes
-- current forever (`concept/instruction.md` §6: "a failed fetch leaving an empty
-- table" is the trap; leaving the previous snapshot in place is the fix, and
-- recording the failure is what stops the fix from becoming the same bug). The
-- three statuses are never collapsed:
--
--   loaded     the fetch worked, the list parsed, and these rules are now the
--              snapshot in the table above
--   unchanged  the fetch worked and the bytes hash to the snapshot already
--              loaded, so nothing was written
--   failed     nothing was written; `failure_reason` says which typed failure
--
-- `source_url` is stored through `helena.observability.Redactor` before it gets
-- here, for the reason `concept/instruction.md` §6 gives: a credential in a URL
-- path must be redacted before anything is logged, stored **or recorded as
-- provenance**. This list needs no credential; the rule is about the channel.
CREATE TABLE helena_reference_public_suffix_load (
    attempted_at     TIMESTAMPTZ,
    source_url       VARCHAR,
    status           VARCHAR NOT NULL,
    -- NULL when the fetch failed: there is no snapshot to name.
    snapshot_version VARCHAR,
    -- The number of rows this load wrote. NULL when it wrote none.
    rule_count       BIGINT,
    -- NULL unless `status` is `failed`, and then one of the typed reasons in
    -- src/helena/enrichment.py::FAILURE_REASONS.
    failure_reason   VARCHAR,
    failure_detail   VARCHAR,
    PRIMARY KEY (attempted_at, source_url)
);


-- The load counter, per source, per status, per reason.
--
-- A plain VIEW. An aggregate over a table that holds one row per load attempt --
-- a handful of rows at prototype scale -- and nothing streams or joins from it.
-- Read by tests/test_enrichment.py.
--
-- The reason is in the GROUP BY rather than summed away, for the reason
-- helena_ingest_quarantine_counts gives: a single total would collapse "the
-- network is down" into "the publisher changed the format".
CREATE VIEW helena_reference_public_suffix_load_counts AS
SELECT source_url,
       status,
       failure_reason,
       count(*) AS loads
FROM helena_reference_public_suffix_load
GROUP BY source_url, status, failure_reason;


-- helena_signal_domain_suffix_candidates: every candidate suffix of every domain
-- entity value, one row each.
--
-- Layer:    signal
-- Object:   VIEW (plain). The intermediate the 42 % rule is about
--           (`concept/03-architecture.md`): it exists so the label array is
--           built once and the candidates are generated once, and nothing reads
--           a single candidate.
-- Reads:    helena_signal_context_entities
-- Read by:  helena_signal_domain_public_suffix and
--           helena_signal_domain_registrable, below. tests/test_enrichment.py
--           reads it to check the candidate set of a name directly.
--
-- The `GROUP BY` is the distinct-name step: a name observed in fifty contexts is
-- normalized once. The row where `candidate_label_count = 0` is the anchor row
-- of a name -- exactly one per name, always present, carrying the label array --
-- which is what the derivation below joins on rather than taking a second
-- DISTINCT over an array column.
CREATE VIEW helena_signal_domain_suffix_candidates AS
SELECT observed_name,
       normalized_name,
       labels,
       name_label_count,
       name_is_valid,
       i AS candidate_label_count,
       array_to_string(labels[name_label_count - i + 1 : name_label_count], '.')
           AS candidate
FROM (
    SELECT observed_name,
           normalized_name,
           labels,
           cardinality(labels) AS name_label_count,
           -- Not a domain name: an empty label, or a rightmost label that is
           -- all digits. See the head for what this deliberately does not catch.
           array_position(labels, '') IS NULL
               AND NOT (labels[cardinality(labels)] ~ '^[0-9]+$')
               AS name_is_valid,
           generate_series(0, cardinality(labels)) AS i
    FROM (
        SELECT entity_value AS observed_name,
               regexp_replace(lower(entity_value), '\.+$', '') AS normalized_name,
               string_to_array(
                   regexp_replace(lower(entity_value), '\.+$', ''), '.'
               ) AS labels
        FROM helena_signal_context_entities
        WHERE entity_type = 'domain'
        GROUP BY 1, 2, 3
    ) n
) c;


-- helena_signal_domain_public_suffix: how many rightmost labels of a name are
-- its public suffix, and which snapshot said so.
--
-- Layer:    signal
-- Object:   VIEW (plain). Another intermediate: one row per name, feeding the
--           materialized view below and nothing else.
-- Reads:    helena_signal_domain_suffix_candidates, helena_reference_public_suffix
-- Read by:  helena_signal_domain_registrable, below.
--
-- This is the algorithm's steps 2 to 4 as one aggregate. The `CASE` on
-- `bool_or(is_exception)` is step 2's "an exception rule wins outright": where
-- one matched, the longest *exception* decides and the wildcard that also
-- matched is ignored, which is the only place in the algorithm where "the most
-- labels" is not the tie-break.
--
-- `snapshot_version` is in the GROUP BY rather than taken with `max()`. Two
-- snapshots in the table would then produce two rows for one name and break the
-- one-row-per-name assertion in tests/test_enrichment.py loudly, instead of one
-- row silently decided by whichever digest sorts higher.
CREATE VIEW helena_signal_domain_public_suffix AS
SELECT c.observed_name,
       r.snapshot_version,
       CASE
           WHEN bool_or(r.is_exception)
               THEN max(CASE WHEN r.is_exception
                             THEN c.candidate_label_count - 1 END)
           ELSE max(CASE WHEN r.is_wildcard
                         THEN c.candidate_label_count + 1
                         ELSE c.candidate_label_count END)
       END AS suffix_label_count
FROM helena_signal_domain_suffix_candidates c
JOIN helena_reference_public_suffix r
  ON r.suffix = c.candidate
WHERE c.name_is_valid
  -- A `*` needs a label to consume: `*.ck` is not a public suffix of `ck`.
  AND (NOT r.is_wildcard OR c.name_label_count > c.candidate_label_count)
GROUP BY c.observed_name, r.snapshot_version;


-- helena_signal_domain_registrable: one row per observed domain name, carrying
-- the name as observed, the name normalized, its public suffix and its
-- registrable domain.
--
-- Layer:    signal
-- Object:   MATERIALIZED VIEW. Not an intermediate: it is joined from
--           (helena_signal_context_domains, below) and it is the relation a
--           scope comparison queries by name. A join target that exists only as
--           a query plan is re-executed by every joiner -- and this one's plan
--           is a ten-thousand-row join under a set-returning function.
-- Reads:    helena_signal_domain_suffix_candidates,
--           helena_signal_domain_public_suffix
-- Read by:  helena_signal_context_domains, below, and tests/test_enrichment.py.
--
-- The join is a LEFT join and the four statuses are why. A name reaches this
-- view whatever happened to it, and `registrable_domain_status` says which of
-- four things it was -- they are four different states and
-- `concept/instruction.md` §2 forbids collapsing them into one NULL:
--
--   derived                  the name has a registrable domain, and it is here
--   name_is_a_public_suffix  the name **is** a public suffix (`co.uk`, `com`,
--                            an unlisted single-label name), so no registrable
--                            domain exists. Not a failure and not a missing
--                            value: there is nothing there to have
--   invalid_name             not a domain name (an empty label, or an address
--                            literal). The list was consulted and refused
--   list_not_loaded          no rule matched at all, not even the default `*`,
--                            which with a loaded snapshot cannot happen. It
--                            means helena_reference_public_suffix is empty:
--                            `missing`, never `no_match`
--
-- `public_suffix_snapshot_version` is NULL exactly when the status is one of the
-- last two, and a consumer that cites a registrable domain has to record it --
-- the list changes, and `bit.ly` was not always a public suffix.
CREATE MATERIALIZED VIEW helena_signal_domain_registrable AS
SELECT n.observed_name,
       n.normalized_name,
       n.name_label_count,
       s.suffix_label_count AS public_suffix_label_count,
       array_to_string(
           n.labels[n.name_label_count - s.suffix_label_count + 1
                    : n.name_label_count], '.'
       ) AS public_suffix,
       CASE WHEN n.name_label_count > s.suffix_label_count
            THEN array_to_string(
                     n.labels[n.name_label_count - s.suffix_label_count
                              : n.name_label_count], '.')
       END AS registrable_domain,
       CASE
           WHEN s.suffix_label_count IS NULL AND NOT n.name_is_valid
               THEN 'invalid_name'
           WHEN s.suffix_label_count IS NULL
               THEN 'list_not_loaded'
           WHEN n.name_label_count > s.suffix_label_count
               THEN 'derived'
           ELSE 'name_is_a_public_suffix'
       END AS registrable_domain_status,
       s.snapshot_version AS public_suffix_snapshot_version
FROM helena_signal_domain_suffix_candidates n
LEFT JOIN helena_signal_domain_public_suffix s
       ON s.observed_name = n.observed_name
WHERE n.candidate_label_count = 0;


-- helena_signal_context_domains: the domain entities of a host's window, each
-- with its registrable domain beside the name as observed.
--
-- Layer:    signal
-- Object:   VIEW (plain). An equi-join of two materialized views, adding five
--           columns and no aggregate; nothing joins from it yet, so
--           materializing it would be a second copy of rows that are already
--           stored twice over.
-- Reads:    helena_signal_context_entities, helena_signal_domain_registrable
-- Read by:  tests/test_enrichment.py today. It exists for the enrichment join
--           (D3), which needs the name as observed to match a feed and the
--           registrable domain to compare scope, and for the triage rendering,
--           which needs both for the same reason a reader does.
--
-- The join is an INNER join on the entity value, and it cannot drop a row:
-- helena_signal_domain_registrable is derived from these same values, one row
-- per distinct value.
-- tests/test_enrichment.py::test_every_domain_entity_row_keeps_its_registrable_domain
-- is what says so rather than this comment -- it counts both sides.
--
-- Every column of the entity row is carried through unchanged except
-- `fingerprint_algorithm`, which 0007 defines as NULL on every row that is not a
-- fingerprint -- so on a domain row it is NULL by construction and carrying it
-- would be a column that can only ever be one value. In particular
-- `entity_value` is still the name **as observed**: ADR-0009's matching rule is
-- about that column and this view does not touch it.
CREATE VIEW helena_signal_context_domains AS
SELECT e.context_id,
       e.tenant,
       e.sensor,
       e.host,
       e.window_start,
       e.window_end,
       e.entity_type,
       e.entity_value,
       e.observed_as_flow_destination,
       e.observed_in_dns_query,
       e.observed_in_dns_response,
       e.observed_in_tls,
       e.observed_in_http,
       e.observed_flow_count,
       e.observed_bytes_sent,
       e.observed_bytes_received,
       e.observed_packets_sent,
       e.observed_packets_received,
       d.normalized_name,
       d.public_suffix,
       d.registrable_domain,
       d.registrable_domain_status,
       d.public_suffix_snapshot_version,
       e.aggregation_version
FROM helena_signal_context_entities e
JOIN helena_signal_domain_registrable d
  ON d.observed_name = e.entity_value
WHERE e.entity_type = 'domain';
