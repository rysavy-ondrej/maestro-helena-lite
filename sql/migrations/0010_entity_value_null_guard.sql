-- 0010  An entity has a value, or it is not an entity.
--
-- Four branches of `helena_signal_entity_observations` read a column that the
-- flow-record contract used to guarantee and no longer does, and emit an entity
-- row with a null value when it is absent. This file adds the four guards. It
-- changes nothing else: every other line below is the definition 0007, 0008 and
-- 0009 already held, moved here because changing one view means recreating it
-- and everything standing on it.
--
-- ## What went wrong, and why it was not wrong before
--
-- `tls.sni`, `tls.ja3`, `tls.ja4` and `http.req[].uri` were **required** fields
-- of `FlowRecord` when 0007 was written, so `helena_flatten_tls.server_name` and
-- its neighbours could not be null and a guard would have been dead code. The
-- requiredness re-measurement over `data/demo/20250920` made all four optional
-- (`docs/decisions/0010-capture-identity.md`, addendum), and the reason is worth
-- stating because it is not a producer being sloppy: **a flow captured
-- mid-connection carries TLS records and no handshake.** There is no ClientHello
-- to read a name or a fingerprint out of. 36 % of that capture's TLS flows are
-- in that state, which is what a sensor that starts while connections are
-- already open looks like.
--
-- The consequence is worse than a null passing through, because
-- `helena_signal_context_entities` groups by `entity_value`: every
-- handshake-less flow in a context collapsed into **one** row, keyed on nothing,
-- accumulating their combined traffic. Measured over the whole day before this
-- file: 374 domain rows, 668 fingerprint rows and 1 url row, 1 043 in total.
-- Each is a join target that no enrichment feed can ever match, sitting beside
-- the real ones with real byte counts on it.
--
-- The `uri_host` branch already had `WHERE uri_host <> ''` and needed nothing.
-- That is the shape all five now have.
--
-- ## Why this file is 500 lines to add four predicates
--
-- RisingWave has no `CREATE OR REPLACE VIEW` -- measured, "Feature is not yet
-- implemented" -- so changing a view is dropping it and creating it again, and
-- dropping it means dropping everything that stands on it first. Seven objects
-- depend on `helena_signal_entity_observations` directly or through each other,
-- so seven are dropped and seven are recreated. Six of them come back byte for
-- byte; only the entity view's four branches differ.
--
-- **The drops are explicit and there is no CASCADE.** `DROP ... CASCADE` would
-- be one line and would take six objects this file never names, which is the
-- opposite of what the declaration blocks are for: a file whose effect is larger
-- than its text cannot be reviewed. `helena.migrations.declarations()` refuses a
-- CASCADE in a migration for that reason, and it refuses a drop whose readers
-- are still live, so the order below is checked rather than trusted.
--
-- ## What this cost in the runner
--
-- `declarations()` used to refuse *any* relation created twice across the whole
-- migration set, which made the recreate-to-change pattern impossible -- and
-- 0009's own head prescribes that pattern in as many words. It now walks the
-- `CREATE`s and `DROP`s in the order they run and refuses a create only when
-- something of that name is live at that point. The invariant is unchanged and
-- three new ones came with it: a drop of something nothing created, a drop of
-- something still read, and a CASCADE. See `helena.migrations.declarations`.
--
-- It also gained a fifth declared field, `Superseded by:`, and this file is why.
-- The seven `CREATE`s in 0007, 0008 and 0009 that this one replaces are now
-- definitions the engine does not hold: editing one of them to fix something
-- would change nothing anywhere, and nothing in those files said so. Each now
-- carries the field, naming this file, and the walk checks the claim in both
-- directions -- so adding it was an edit to three applied migrations and their
-- checksums moved. `docs/runbook.md` says what that does to a store that has
-- already migrated. That cost is the point: it is paid when the superseding file
-- is written, by the person who knows, instead of by whoever opens the dead
-- definition a year later.
--
-- ## What it does not do
--
-- Nothing backfills. A deployment that already stored the null-valued rows has
-- them in `helena_signal_context_entities`, which this file drops and rebuilds
-- from `helena_normalized_events` -- so they go, for the records the engine
-- still holds. Records outside the retention boundary are not re-aggregated and
-- a frozen context is not rewritten: a citation resolves to what it cited.



DROP MATERIALIZED VIEW helena_signal_context_entities_retained;
DROP VIEW helena_signal_context_domains;
DROP MATERIALIZED VIEW helena_signal_domain_registrable;
DROP VIEW helena_signal_domain_public_suffix;
DROP VIEW helena_signal_domain_suffix_candidates;
DROP MATERIALIZED VIEW helena_signal_context_entities;
DROP VIEW helena_signal_entity_observations;


-- helena_signal_entity_observations: one row per (flow, entity) observation.
--
-- Layer:    signal
-- Object:   VIEW (plain). `concept/03-architecture.md`'s measured rule -- do not
--           materialize an intermediate that only feeds an aggregate, it cost
--           42 % more disk for rows nothing reads -- and this is that
--           intermediate exactly: it exists so that the window is taken once,
--           over a named relation, and nothing queries a single observation.
-- Reads:    helena_flatten_flows, helena_flatten_dns_queries,
--           helena_flatten_dns_responses, helena_flatten_tls,
--           helena_flatten_http_requests
-- Read by:  helena_signal_context_entities, below. tests/test_context.py reads
--           it directly to check the extraction rules one branch at a time.
--
-- Each branch of the union names one place an entity value is observed and sets
-- the one flag that says so. The branch set is the table in
-- `concept/05-threat-intelligence.md`, one branch per cell.
--
-- **Four branches guard against a null and the rest do not**, and the split is
-- exactly the contract's. `ip.dst`, `dns.queries[].qn`, `dns.responses[].qn` and
-- `.rv` are still required by `FlowRecord` (src/helena/normalizer.py), so a
-- record missing one is quarantined at ingestion and never becomes an event; a
-- guard on those would be the place a contract violation goes to hide, which is
-- the argument 0006 makes for the host and it still holds.
--
-- `tls.sni`, `tls.ja3`, `tls.ja4` and a request's `uri` are **not** required any
-- more, and their absence is not a violation to surface: a flow captured
-- mid-connection has TLS records and no handshake, so there is no name and no
-- fingerprint to extract. Guarding those is not hiding a defect, it is declining
-- to invent an entity out of an observation that was never made. See this file's
-- head for what the missing guards produced.
--
-- The one filter about a *value* rather than a presence is still the URI host: a
-- relative URI has no host part, so it contributes a `url` row and no `domain`
-- row. Measured over `flow-sample.jsonl`: all 36 request URIs are absolute, so
-- that branch is exercised on every one of them.
--
-- The A/AAAA filter does not look at the record's section. An `A` record is an
-- address disclosure wherever it appears, and dropping one silently because it
-- arrived in the authority section is a worse failure than including it.
-- Measured over the sample: all 32 A records are in the answer section and the
-- 9 authority records are all SOA, so the choice is unexercised there.
CREATE VIEW helena_signal_entity_observations AS
SELECT f.tenant,
       f.sensor,
       f.capture_sha256,
       f.record_offset,
       f.flow_start,
       f.src_address AS host,
       f.bytes_sent,
       f.bytes_received,
       f.packets_sent,
       f.packets_received,
       o.entity_type,
       o.entity_value,
       o.fingerprint_algorithm,
       o.observed_as_flow_destination,
       o.observed_in_dns_query,
       o.observed_in_dns_response,
       o.observed_in_tls,
       o.observed_in_http
FROM helena_flatten_flows f
JOIN (
    -- address: the flow's destination.
    SELECT tenant,
           sensor,
           capture_sha256,
           record_offset,
           'address'                        AS entity_type,
           dst_address                      AS entity_value,
           NULL::VARCHAR                    AS fingerprint_algorithm,
           TRUE                             AS observed_as_flow_destination,
           FALSE                            AS observed_in_dns_query,
           FALSE                            AS observed_in_dns_response,
           FALSE                            AS observed_in_tls,
           FALSE                            AS observed_in_http
    FROM helena_flatten_flows
    UNION ALL
    -- address: the value of an A or AAAA resource record.
    SELECT tenant, sensor, capture_sha256, record_offset,
           'address', record_value, NULL::VARCHAR,
           FALSE, FALSE, TRUE, FALSE, FALSE
    FROM helena_flatten_dns_responses
    WHERE record_type IN ('A', 'AAAA')
    UNION ALL
    -- domain: a name the host asked about.
    SELECT tenant, sensor, capture_sha256, record_offset,
           'domain', query_name, NULL::VARCHAR,
           FALSE, TRUE, FALSE, FALSE, FALSE
    FROM helena_flatten_dns_queries
    UNION ALL
    -- domain: the name a resource record was about.
    SELECT tenant, sensor, capture_sha256, record_offset,
           'domain', response_name, NULL::VARCHAR,
           FALSE, FALSE, TRUE, FALSE, FALSE
    FROM helena_flatten_dns_responses
    UNION ALL
    -- domain: the name the client asked for in the TLS handshake, where there
    -- was a handshake. `server_name` is null on a flow captured mid-connection:
    -- TLS records were observed and no ClientHello was, so there is no name --
    -- which is not the same as a connection to no name. Without the guard that
    -- flow contributes an entity with a null value, and the grouping below keys
    -- on the value, so every handshake-less flow in a context collapses into one
    -- row accumulating their traffic under nothing.
    SELECT tenant, sensor, capture_sha256, record_offset,
           'domain', server_name, NULL::VARCHAR,
           FALSE, FALSE, FALSE, TRUE, FALSE
    FROM helena_flatten_tls
    WHERE server_name IS NOT NULL
    UNION ALL
    -- domain: the host part of a request URI -- no scheme, no userinfo, no
    -- port, no path, no query and no fragment, which is what
    -- `concept/instruction.md` §6 means by "the host part". The expression is
    -- written once, in the subquery, so the filter cannot drift from the value.
    -- Measured over the sample: no URI carries userinfo, a port, an IPv6
    -- literal host or a bare address, so those three steps are exercised by
    -- tests/test_context.py against a real record whose URI was changed in a
    -- way the contract permits, and by nothing else.
    SELECT tenant, sensor, capture_sha256, record_offset,
           'domain', uri_host, NULL::VARCHAR,
           FALSE, FALSE, FALSE, FALSE, TRUE
    FROM (
        SELECT tenant,
               sensor,
               capture_sha256,
               record_offset,
               regexp_replace(
                   CASE
                       WHEN position('@' IN authority) > 0
                           THEN substr(authority, position('@' IN authority) + 1)
                       ELSE authority
                   END,
                   ':[0-9]+$',
                   ''
               ) AS uri_host
        FROM (
            SELECT tenant,
                   sensor,
                   capture_sha256,
                   record_offset,
                   split_part(
                       split_part(
                           split_part(split_part(uri, '://', 2), '/', 1),
                           '?', 1
                       ),
                       '#', 1
                   ) AS authority
            FROM helena_flatten_http_requests
            WHERE uri LIKE '%://%'
        ) a
    ) h
    WHERE uri_host <> ''
    UNION ALL
    -- fingerprint: the client's JA3, where a handshake was observed to
    -- fingerprint. Same guard, same reason as the branch above.
    SELECT tenant, sensor, capture_sha256, record_offset,
           'fingerprint', client_ja3, 'ja3',
           FALSE, FALSE, FALSE, TRUE, FALSE
    FROM helena_flatten_tls
    WHERE client_ja3 IS NOT NULL
    UNION ALL
    -- fingerprint: the client's JA4. Nothing enriches it -- see 0007's head.
    SELECT tenant, sensor, capture_sha256, record_offset,
           'fingerprint', client_ja4, 'ja4',
           FALSE, FALSE, FALSE, TRUE, FALSE
    FROM helena_flatten_tls
    WHERE client_ja4 IS NOT NULL
    UNION ALL
    -- url: the request URI exactly as supplied, query string and all. HTTP/1
    -- and HTTP/2 are one view with a protocol column below this one, so both
    -- arrive here without a second branch.
    --
    -- `uri` is guarded for the same reason as the TLS branches above, and it is
    -- rarer: one request of the day capture's 3 689 carries a method and no URI.
    -- One row is still a join target keyed on nothing.
    SELECT tenant, sensor, capture_sha256, record_offset,
           'url', uri, NULL::VARCHAR,
           FALSE, FALSE, FALSE, FALSE, TRUE
    FROM helena_flatten_http_requests
    WHERE uri IS NOT NULL
) o
  ON o.tenant = f.tenant
 AND o.sensor = f.sensor
 AND o.capture_sha256 = f.capture_sha256
 AND o.record_offset = f.record_offset;


-- helena_signal_context_entities: the entities observed in one host's window,
-- one row each, with the traffic of the flows that observed them.
--
-- Layer:    signal
-- Object:   MATERIALIZED VIEW. Not the intermediate the 42 % rule is about:
--           this is the layer's second output, it is the **join target** for
--           the enrichment reference tables, and it is queried by context on
--           its own to render a context's entities. A join target that exists
--           only as a query plan is re-executed by every joiner.
-- Reads:    helena_signal_entity_observations, helena_signal_host_context
-- Read by:  helena_signal_context_entities_retained (the retention boundary),
--           helena_signal_domain_suffix_candidates and
--           helena_signal_context_domains (the registrable-domain derivation),
--           helena_analytical_enriched_context (sql/migrations/0015, the join
--           this exists for), and tests/test_context.py. The triage rendering
--           needs per-domain and per-address records rather than arrays, which
--           is the other half of why these rows are shaped this way.
--
-- Two levels of aggregation, and both are load-bearing:
--
--   inner   one row per (entity, flow): the flags OR'd together over the
--           several places one flow observed the same value, and the flow's
--           counters taken once with `max` -- they are constant within the
--           group, and `sum` here would multiply a flow's octets by the number
--           of times it mentioned the name.
--   outer   one row per (entity, context): the flags OR'd again across flows,
--           the flows counted, and the counters summed over distinct flows.
--
-- `aggregation_version` and `context_id` are both read off the host context
-- row rather than recomputed. That is deliberate: the digest construction and
-- the version literal exist once, in 0006, and an entity row cannot disagree
-- with the context it hangs off. The join is an inner one and cannot drop a
-- row -- every observation comes from a flow, and every flow produces a context
-- in the window it started in -- and the test named in the head is what says so
-- rather than this comment.
CREATE MATERIALIZED VIEW helena_signal_context_entities AS
SELECT c.context_id,
       e.tenant,
       e.sensor,
       e.host,
       e.window_start,
       e.window_end,
       e.entity_type,
       e.entity_value,
       e.fingerprint_algorithm,
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
       c.aggregation_version
FROM (
    SELECT p.tenant,
           p.sensor,
           p.host,
           p.window_start,
           p.window_end,
           p.entity_type,
           p.entity_value,
           p.fingerprint_algorithm,
           bool_or(p.observed_as_flow_destination) AS observed_as_flow_destination,
           bool_or(p.observed_in_dns_query)        AS observed_in_dns_query,
           bool_or(p.observed_in_dns_response)     AS observed_in_dns_response,
           bool_or(p.observed_in_tls)              AS observed_in_tls,
           bool_or(p.observed_in_http)             AS observed_in_http,
           count(*)::BIGINT                        AS observed_flow_count,
           sum(p.bytes_sent)::BIGINT               AS observed_bytes_sent,
           sum(p.bytes_received)::BIGINT           AS observed_bytes_received,
           sum(p.packets_sent)::BIGINT             AS observed_packets_sent,
           sum(p.packets_received)::BIGINT         AS observed_packets_received
    FROM (
        SELECT o.tenant,
               o.sensor,
               o.host,
               o.window_start,
               o.window_end,
               o.entity_type,
               o.entity_value,
               o.fingerprint_algorithm,
               o.capture_sha256,
               o.record_offset,
               bool_or(o.observed_as_flow_destination) AS observed_as_flow_destination,
               bool_or(o.observed_in_dns_query)        AS observed_in_dns_query,
               bool_or(o.observed_in_dns_response)     AS observed_in_dns_response,
               bool_or(o.observed_in_tls)              AS observed_in_tls,
               bool_or(o.observed_in_http)             AS observed_in_http,
               max(o.bytes_sent)                       AS bytes_sent,
               max(o.bytes_received)                   AS bytes_received,
               max(o.packets_sent)                     AS packets_sent,
               max(o.packets_received)                 AS packets_received
        FROM TUMBLE(
                 helena_signal_entity_observations, flow_start, INTERVAL '5 minutes'
             ) o
        GROUP BY o.tenant, o.sensor, o.host, o.window_start, o.window_end,
                 o.entity_type, o.entity_value, o.fingerprint_algorithm,
                 o.capture_sha256, o.record_offset
    ) p
    GROUP BY p.tenant, p.sensor, p.host, p.window_start, p.window_end,
             p.entity_type, p.entity_value, p.fingerprint_algorithm
) e
JOIN helena_signal_host_context c
  ON c.tenant = e.tenant
 AND c.sensor = e.sensor
 AND c.host = e.host
 AND c.window_start = e.window_start;


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


-- helena_signal_context_entities_retained: the entity rows of retained contexts.
--
-- Layer:    signal
-- Object:   MATERIALIZED VIEW, for the same reason as the retained context: an
--           entity row's state has to go when its context's does, and a plain
--           view would hide the rows while keeping them.
-- Reads:    helena_signal_context_entities, helena_signal_host_context_retained
-- Read by:  tests/test_context.py, and the enriched-context view (D3), which is
--           what the entity rows exist for.
--
-- The boundary is taken **by joining the retained context** rather than by
-- repeating the temporal predicate on the entity row's own `window_end`. That is
-- the lesson sql/migrations/0007_context_entities.sql already records about the
-- window interval: a second copy of the constant is a second thing to bump, and
-- a drifted copy produces plausible wrong rows. Here there is no second copy at
-- all -- an entity row is inside the boundary exactly when its context is, by
-- construction. The join is an equi-join on the whole context key, which
-- RisingWave plans (task 14 measured that an equi-join to this aggregate is
-- accepted where a cross join is not).
CREATE MATERIALIZED VIEW helena_signal_context_entities_retained AS
SELECT e.context_id,
       e.tenant,
       e.sensor,
       e.host,
       e.window_start,
       e.window_end,
       e.entity_type,
       e.entity_value,
       e.fingerprint_algorithm,
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
       e.aggregation_version
FROM helena_signal_context_entities e
JOIN helena_signal_host_context_retained r
  ON e.tenant = r.tenant
 AND e.sensor = r.sensor
 AND e.context_id = r.context_id;
