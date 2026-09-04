-- 0007  The signal layer, second object: the entity rows beside a host context.
--
-- `concept/01-goal-and-scope.md` describes stage 2 as "one host context per host
-- per 5-minute window, **with entity rows beside it**", and
-- `concept/02-concepts-and-taxonomy.md` says what an entity is: "the thing
-- enrichment is about and the join target -- a `domain`, an `address`, or a TLS
-- `fingerprint` observed in a host's window". `concept/05-threat-intelligence.md`
-- adds the fourth type, `url`, and fixes where each one comes from:
--
--   address      flow destinations; A / AAAA DNS answers
--   domain       DNS query names, DNS response names, TLS SNI, the host part of
--                HTTP URIs
--   fingerprint  TLS JA3 and JA4, client-side only
--   url          HTTP and HTTP/2 URIs
--
-- This file builds exactly those four, from the flatten layer
-- (sql/migrations/0005_flatten_layer.sql), and hangs them off the host context
-- (sql/migrations/0006_host_context.sql) by its `context_id`.
--
-- ## One row per entity per context, never an array
--
-- `concept/03-architecture.md`: "The join is **per entity**: arrays inside a
-- window cannot be joined to evidence, the rendering needs per-domain and
-- per-address records, and the composition rule needs the indicator correlated
-- with the matching traffic." So the grain here is (context, entity type, entity
-- value) and not a list of names on the context row. A domain seen in eleven
-- flows of one window is one row, and the flows behind it are found by joining
-- the flatten layer on the same key.
--
-- ## Observation-scoped traffic: named for what it is
--
-- `concept/02-concepts-and-taxonomy.md` defines the counts and names them
-- deliberately: "per-entity counts named for what they are: **the traffic of the
-- flows in which the entity was observed**". They are not the traffic *to* the
-- entity, and the `observed_` prefix on every one of them is there so that a
-- reader of a rendering cannot mistake them for it. The clearest case is an
-- address that only ever appeared as a DNS answer: its octets are the octets of
-- the DNS lookups that mentioned it, and nothing was ever sent to it.
--
-- The counters stay bidirectional and there is no total, for the reason
-- `concept/07-principles.md` gives and the two layers below already follow:
-- direction is signal, and a `bytes_total` column is where it stops being
-- available. The four columns are summed over the *distinct flows* in which the
-- entity was observed -- an entity observed twice on one flow (two HTTP requests
-- to the same host, a name in both a query and a response) must not count that
-- flow's octets twice, which is what the inner aggregation below is for.
--
-- Duration is not carried per entity: the task's traffic columns are flows,
-- packets and octets, and nothing above reads a per-entity duration.
--
-- ## The flags: which layer observed it, and the honest limitation
--
-- Five booleans say where the value was seen:
--
--   observed_as_flow_destination  the address was a flow's destination
--   observed_in_dns_query         the name was asked for
--   observed_in_dns_response      the name was answered for, or -- for an
--                                 address -- was the value of an A/AAAA record
--   observed_in_tls               the name was a TLS SNI, or the fingerprint
--                                 was the client's
--   observed_in_http              the name was the host part of a URI, or the
--                                 URL was requested
--
-- The first one is the flag `concept/02-concepts-and-taxonomy.md` asks for by
-- name: "a flag distinguishes an address seen as a flow destination from a name,
-- or an address seen only as a DNS answer". An address with
-- `observed_as_flow_destination = FALSE` and `observed_in_dns_response = TRUE`
-- was resolved and never contacted, and the composition rule
-- (`concept/02-concepts-and-taxonomy.md`, scope before severity) turns on
-- exactly that difference: a C2 hit on an address with bidirectional traffic
-- supports `malicious.c2` for the host, and the same hit on an address the host
-- only ever resolved does not. Measured on `data/ingest/flow-sample.jsonl`:
-- 16 of the 30 addresses that appear as A answers are never a flow destination.
--
-- The rest of the flags are the weaker substitute the same note records as an
-- **honest limitation**: "the scope test works on address entities and not on
-- domain ones, because a name carries the traffic of the flows that *mentioned*
-- it -- a DNS lookup -- not of the connection to the address it resolved to ...
-- What the rendering can still say is **which layers observed the name**: a name
-- in TLS SNI was connected to, where a name seen only in a DNS query may never
-- have been. Weaker than bytes, and not nothing." That is what these four
-- columns are, and nothing here claims they are the scope test.
--
-- A flag a type cannot reach is FALSE, not NULL: a fingerprint was genuinely not
-- observed in a DNS query, and there is no unobserved value to represent. Which
-- flags a type can reach is readable off `entity_type`.
--
-- ## Three coverage gaps, recorded here because this is where they bite
--
-- `concept/05-threat-intelligence.md` records them and this file is where the
-- rows they are about are produced:
--
--   * **JA4 has no public blocklist.** The flow record carries JA4 and JA4S and
--     this view emits JA4 fingerprint rows, and **nothing enriches them**. The
--     only fingerprint source in the catalogue is one JA3 list of under a
--     hundred entries, static since 2021. `fingerprint_algorithm` is on the row
--     so that the layer above can tell the two apart, because they are not the
--     same state: a JA4 with no source is `missing` and a JA3 that no source
--     matched is `no_match`, and `concept/instruction.md` §2 forbids collapsing
--     those. This view produces the rows; the distinction is the enrichment
--     join's to make, and it cannot make it without this column.
--   * **URL feeds have narrow reach on this input.** URIs exist only for
--     cleartext HTTP and HTTP/2; TLS yields an SNI, not a URL. Measured over the
--     62-record sample: 36 request URIs against 25 TLS handshakes, and every one
--     of the 11 URI hosts is also observed as a domain some other way. So the
--     matching value on this input is mostly domain, address and JA3, and a URL
--     feed's reach is bounded by how much cleartext HTTP the sensor sees.
--   * **Application identification identifies hosting as often as an
--     application**, which is why `service` is not an entity type at all: it
--     attaches to the address and domain rows this file already produces
--     (docs/decisions/0009-netify-application-identification.md).
--
-- ## What is deliberately not done here
--
-- **The value is the name as observed.** Nothing is lowercased, and no
-- registrable domain is derived: that is the Public Suffix List question (prd
-- task 15), and ADR-0009 already fixes the matching rule for one source -- match
-- "on the name **as observed** -- from DNS or TLS SNI -- and never on the
-- registrable domain". Measured over the sample: no DNS name, SNI or URI host
-- carries an uppercase character, so case folding would be unexercised guessing
-- today.
--
-- **A CNAME's target is not extracted as a domain of its own.** The concept
-- lists DNS *response names* and that is what is taken -- the `qn` of each
-- resource record. Measured over the sample: the 46 CNAME records carry 29
-- distinct targets and every one of them also appears as the name of another
-- resource record, so nothing is lost on this input; a chain ending in a CNAME
-- to a name no record is then about would lose that name, and that is stated
-- rather than guessed at.
--
-- **The server's fingerprints are not entities.** `concept/05` says JA3 and JA4
-- "client-side only", and `ja3s`/`ja4s` fingerprint the server's selection
-- rather than the client that made it. They stay in the flatten layer.
--
-- **The source address is not an entity.** It is the host -- the subject of the
-- assessment -- and enrichment is about what the host talked to.
--
-- **There is no entity id.** The natural key is (context_id, entity_type,
-- entity_value): it is unique, it is what a citation would carry, and a digest
-- over it would be a second identifier for the same three columns. The
-- increment that issues a citation is where an opaque id earns its place, if it
-- ever does.
--
-- ## The window interval is a second copy, and a test pins it
--
-- `INTERVAL '5 minutes'` appears here and in 0006, because `TUMBLE` takes a
-- named relation and the two views window different relations. Two copies that
-- can drift are what `concept/instruction.md` §2 forbids for a version constant,
-- so the drift is made to fail loudly rather than trusted: every entity row is
-- joined to its host context on the window start, and
-- `tests/test_context.py::test_the_entity_window_agrees_with_the_context_window`
-- asserts the ends agree too and that no entity row lost its context in the
-- join. A different interval in one of the two files breaks both.


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
-- There is no `IS NOT NULL` guard on any extracted value, and that is on
-- purpose: `ip.dst`, `dns.queries[].qn`, `dns.responses[].qn`, `.rv`, `tls.sni`,
-- `tls.ja3`, `tls.ja4` and a request's `uri` are all required by the contract
-- (src/helena/normalizer.py), so a record missing one is quarantined at
-- ingestion and never becomes an event. A guard here would be the place a
-- contract violation goes to hide -- the same argument 0006 makes for the host.
--
-- The one filter that is about a *value* rather than a presence is the URI host:
-- a relative URI has no host part, so it contributes a `url` row and no `domain`
-- row. Measured over the sample: all 36 request URIs are absolute, so that
-- branch is exercised on every one of them.
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
    -- domain: the name the client asked for in the TLS handshake.
    SELECT tenant, sensor, capture_sha256, record_offset,
           'domain', server_name, NULL::VARCHAR,
           FALSE, FALSE, FALSE, TRUE, FALSE
    FROM helena_flatten_tls
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
    -- fingerprint: the client's JA3.
    SELECT tenant, sensor, capture_sha256, record_offset,
           'fingerprint', client_ja3, 'ja3',
           FALSE, FALSE, FALSE, TRUE, FALSE
    FROM helena_flatten_tls
    UNION ALL
    -- fingerprint: the client's JA4. Nothing enriches it -- see the head.
    SELECT tenant, sensor, capture_sha256, record_offset,
           'fingerprint', client_ja4, 'ja4',
           FALSE, FALSE, FALSE, TRUE, FALSE
    FROM helena_flatten_tls
    UNION ALL
    -- url: the request URI exactly as supplied, query string and all. HTTP/1
    -- and HTTP/2 are one view with a protocol column below this one, so both
    -- arrive here without a second branch.
    SELECT tenant, sensor, capture_sha256, record_offset,
           'url', uri, NULL::VARCHAR,
           FALSE, FALSE, FALSE, FALSE, TRUE
    FROM helena_flatten_http_requests
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
-- Read by:  tests/test_context.py today. It exists for the enriched-context
--           view (D3), which joins these rows against the enrichment reference
--           tables, and for the triage rendering, which needs per-domain and
--           per-address records rather than arrays.
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
