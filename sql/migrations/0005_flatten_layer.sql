-- 0005  The flatten layer: typed, flat rows over the normalized events.
--
-- `concept/03-architecture.md` gives the Context Builder three view layers --
-- **flatten -> signal -> analytical** -- and one rule about how they may refer
-- to each other: an analytical view reads the signal layer, never the flatten
-- layer and never the source. This file is the bottom of that stack. Every
-- object here reads `helena_normalized_events` and nothing else, which is the
-- only place in the three layers where reading the source is allowed.
--
-- What it does is unpack. `helena_normalized_events.observation` is the flow
-- record as the producer sent it, held as JSONB so that nothing is lost and
-- nothing is invented (sql/migrations/0004_normalized_events.sql). Every layer
-- above wants columns: a window function over a start time, a join between a
-- domain and a feed's reference table, a count of packets in a direction. So
-- the flatten layer is where `observation->'ip'->>'bsent'` becomes
-- `bytes_sent BIGINT`, once, rather than in every view that needs it.
--
-- ## Every object here is a plain VIEW
--
-- `concept/instruction.md` §1 makes the plain view the default and
-- `concept/03-architecture.md` adds the measured rule beside it: **do not
-- materialize an intermediate that only feeds an aggregate** -- a materialized
-- intermediate cost 42 % more disk than the same query as a plain view, storing
-- rows nothing reads. Every object in this file is exactly that intermediate:
-- the signal layer above aggregates it (one host context per host per window)
-- and extracts entities from it, and nothing queries a flatten row on its own.
-- So all eight are plain views, and each declares it below.
--
-- Measured against RisingWave 3.0.3 before this file was written, because the
-- decision only holds if the layer above can actually be built on a plain view:
-- `CREATE MATERIALIZED VIEW ... AS SELECT ... FROM <a view using
-- jsonb_array_elements ... WITH ORDINALITY> GROUP BY ...` is accepted and
-- returns rows, and so is one over a view whose body is a `UNION ALL` of two
-- such branches. A set-returning function and a union both survive into a
-- streaming plan, so the signal layer does not need these materialized.
--
-- ## Absence is not emptiness, and the shape of this file is what keeps it
--
-- `concept/instruction.md` §2: an unobserved layer is absent and an
-- observed-but-empty one is an empty array, and a view that cannot tell those
-- apart cannot tell "no DNS traffic" from "DNS traffic with no answers". A
-- set-returning function collapses both to zero rows, so unpacking the arrays
-- alone would lose exactly that distinction.
--
-- Each layer family therefore has an **observation** object whose existence is
-- the statement that the layer was observed, and the per-item objects hang off
-- it:
--
--   observed and non-empty   a row in helena_flatten_dns, N rows in the queries
--   observed and empty       a row in helena_flatten_dns, 0 rows in the queries
--                            (and the row's own count column says 0)
--   not observed             no row in helena_flatten_dns at all
--
-- `helena_flatten_flows` is the flow's own row and exists for every event, so
-- the ip/tcp/udp layers need no separate observation object.
--
-- ## Identity travels into every row
--
-- Every flatten row carries the whole assigned identity -- tenant, sensor, the
-- raw-record reference (capture_sha256, record_offset), the event id and the
-- schema version that validated the record. A flatten row is what the layers
-- above aggregate and what an assessment will eventually cite, and an entity
-- row that could not name the tenant it belongs to would make the tenant seam
-- in `concept/03-architecture.md` stop at ingestion.
--
-- `schema_version` rides along for the reason `concept/instruction.md` §2 gives
-- for replay: the version that validated a row is a property of the row, and a
-- later reader has to be able to read it off the row rather than off current
-- code.
--
-- ## What is deliberately NOT unpacked
--
-- The TLS client offer (`cciphers`, `cexts`, `csigs`, `csvers`) and the server
-- extension list (`sexts`) stay in the JSONB. Nothing above reads them yet --
-- the entities the enrichment join needs are addresses, domains, fingerprints
-- and URLs -- and a view per unread array is structure ahead of the increment
-- that needs it. Same for the ALPN *values*: `alpn_count` is here because the
-- observed-but-empty case is real in the sample (`tcp.24` negotiated no
-- protocol), and the values themselves are one migration away when something
-- wants them. Nothing is lost either way: the record is whole in the source
-- table.
--
-- A URI is stored whole. `concept/instruction.md` §6 requires the **host part**
-- in a domain column, and that is what entity extraction does when it builds
-- domain rows; splitting here would make the flatten layer decide what a domain
-- is, which is a question about the Public Suffix List (prd task 15) and not
-- about unpacking.


-- helena_flatten_flows: one row per normalized event -- the flow itself.
--
-- Layer:    flatten
-- Object:   VIEW (plain). Nothing queries a flow row on its own; the signal
--           layer aggregates it into a host context.
-- Reads:    helena_normalized_events
-- Read by:  tests/test_context.py today. It exists for the windowed host-context
--           aggregation and for entity extraction (prd tasks 13 and 14), which
--           are the first non-test readers.
--
-- The counters stay in the two directions the input supplies.
-- `concept/07-principles.md` keeps connection statistics bidirectional because
-- direction is signal, and summing them here would be the first place it is
-- lost -- so there is no `bytes_total` column and there is not meant to be one.
--
-- `flow_start` is the flow's start as a timestamp, not the epoch float, because
-- a flow is credited to the window containing its start
-- (`concept/02-concepts-and-taxonomy.md`) and the window function above takes a
-- timestamp. `duration_seconds` stays a duration for the same reason: an end
-- time would be a derived value competing with the start.
--
-- `transport` says which of the two transport layers was observed, and the port
-- columns come from it. The contract allows both to be present -- no sampled
-- record has both, but that is a property of this producer -- so the both case
-- is given its own visible value rather than silently resolved: a row reading
-- 'tcp+udp' is countable, and its ports are TCP's.
CREATE VIEW helena_flatten_flows AS
SELECT e.tenant,
       e.sensor,
       e.capture_sha256,
       e.record_offset,
       e.event_id,
       e.schema_version,
       e.observation ->> 'id'                                    AS record_id,
       to_timestamp((e.observation ->> 'ts')::DOUBLE PRECISION)   AS flow_start,
       (e.observation ->> 'td')::DOUBLE PRECISION                 AS duration_seconds,
       e.observation -> 'ip' ->> 'proto'                          AS proto,
       e.observation -> 'ip' ->> 'src'                            AS src_address,
       e.observation -> 'ip' ->> 'dst'                            AS dst_address,
       (e.observation -> 'ip' ->> 'bsent')::BIGINT                AS bytes_sent,
       (e.observation -> 'ip' ->> 'brecv')::BIGINT                AS bytes_received,
       (e.observation -> 'ip' ->> 'psent')::BIGINT                AS packets_sent,
       (e.observation -> 'ip' ->> 'precv')::BIGINT                AS packets_received,
       CASE
           WHEN e.observation ? 'tcp' AND e.observation ? 'udp' THEN 'tcp+udp'
           WHEN e.observation ? 'tcp' THEN 'tcp'
           WHEN e.observation ? 'udp' THEN 'udp'
       END                                                        AS transport,
       coalesce(
           (e.observation -> 'tcp' ->> 'srcport')::INT,
           (e.observation -> 'udp' ->> 'srcport')::INT
       )                                                          AS src_port,
       coalesce(
           (e.observation -> 'tcp' ->> 'dstport')::INT,
           (e.observation -> 'udp' ->> 'dstport')::INT
       )                                                          AS dst_port
FROM helena_normalized_events e;


-- helena_flatten_dns: one row per event that observed DNS.
--
-- Layer:    flatten
-- Object:   VIEW (plain). It feeds the aggregate and the entity rows above it.
-- Reads:    helena_normalized_events
-- Read by:  tests/test_context.py today; the signal layer next (prd tasks 13-14).
--
-- The row's existence is the statement "this flow observed DNS". `rcode` is on
-- it because a lookup that resolved nothing is a different thing from a lookup
-- that was never made: `udp.7` in the sample answers rcode 3 with nine
-- authority records and no answer at all.
--
-- `query_count` and `response_count` are the array lengths as stored, so a
-- DNS observation with an empty array is a row saying 0 rather than an absent
-- row. They are also the reconciliation `concept/instruction.md` §7 asks for:
-- summed over a capture they must equal the row counts of the two views below,
-- and tests/test_context.py asserts exactly that.
CREATE VIEW helena_flatten_dns AS
SELECT e.tenant,
       e.sensor,
       e.capture_sha256,
       e.record_offset,
       e.event_id,
       e.schema_version,
       (e.observation -> 'dns' ->> 'rcode')::INT                     AS rcode,
       jsonb_array_length(e.observation -> 'dns' -> 'queries')       AS query_count,
       jsonb_array_length(e.observation -> 'dns' -> 'responses')     AS response_count
FROM helena_normalized_events e
WHERE e.observation ? 'dns';


-- helena_flatten_dns_queries: one row per question asked on the flow.
--
-- Layer:    flatten
-- Object:   VIEW (plain). Domain entities are extracted from it by the layer
--           above; nothing reads a query row on its own.
-- Reads:    helena_normalized_events
-- Read by:  tests/test_context.py today; entity extraction next (prd task 14).
--
-- `query_index` is the position in the array as stored. Order is meaningful in
-- DNS and the flatten layer is not entitled to lose it.
CREATE VIEW helena_flatten_dns_queries AS
SELECT e.tenant,
       e.sensor,
       e.capture_sha256,
       e.record_offset,
       e.event_id,
       e.schema_version,
       q.query_index,
       q.query ->> 'qn' AS query_name,
       q.query ->> 'qt' AS query_type
FROM helena_normalized_events e,
     jsonb_array_elements(e.observation -> 'dns' -> 'queries')
         WITH ORDINALITY AS q(query, query_index);


-- helena_flatten_dns_responses: one row per resource record answered on the flow.
--
-- Layer:    flatten
-- Object:   VIEW (plain). Address and domain entities are extracted from it.
-- Reads:    helena_normalized_events
-- Read by:  tests/test_context.py today; entity extraction next (prd task 14).
--
-- One row per record, never an index into the chain.
-- `concept/instruction.md` §6 lists reading `[0]` as a trap that has already
-- cost this project something: in the worked example the resolved address is at
-- index 2, and the sample's longest chain is twelve records. `response_index`
-- keeps the position so the chain can be reconstructed; `section` is the
-- record's own section ('answer' or 'authority' in the sample), which is what
-- separates "here is the address" from "here is who to ask".
CREATE VIEW helena_flatten_dns_responses AS
SELECT e.tenant,
       e.sensor,
       e.capture_sha256,
       e.record_offset,
       e.event_id,
       e.schema_version,
       r.response_index,
       r.response ->> 'rr'          AS section,
       r.response ->> 'qn'          AS response_name,
       r.response ->> 'rt'          AS record_type,
       (r.response ->> 'ttl')::BIGINT AS ttl_seconds,
       r.response ->> 'rv'          AS record_value
FROM helena_normalized_events e,
     jsonb_array_elements(e.observation -> 'dns' -> 'responses')
         WITH ORDINALITY AS r(response, response_index);


-- helena_flatten_tls: one row per event that observed TLS.
--
-- Layer:    flatten
-- Object:   VIEW (plain). Domain entities (from the SNI) and fingerprint
--           entities (from the client JA3/JA4) are extracted from it.
-- Reads:    helena_normalized_events
-- Read by:  tests/test_context.py today; entity extraction next (prd task 14).
--
-- `client_ja3`/`client_ja4` fingerprint the client and `server_ja3`/`server_ja4`
-- the server -- the input's `ja3`/`ja4` and `ja3s`/`ja4s`. The prefix is here
-- because "which side does this fingerprint" is the whole question a
-- fingerprint entity answers, and `ja3s` is one letter away from `ja3`.
--
-- `alpn_count` is the observed-but-empty case made visible: `tcp.24` in the
-- sample carries `alpn == []` -- TLS observed, no protocol negotiated -- which
-- is not the same thing as a flow with no TLS at all, and that flow has no row
-- here. `record_count` is the same for the TLS record sequence.
CREATE VIEW helena_flatten_tls AS
SELECT e.tenant,
       e.sensor,
       e.capture_sha256,
       e.record_offset,
       e.event_id,
       e.schema_version,
       e.observation -> 'tls' ->> 'sni'                        AS server_name,
       e.observation -> 'tls' ->> 'cver'                       AS client_version,
       e.observation -> 'tls' ->> 'sver'                       AS server_version,
       e.observation -> 'tls' ->> 'scipher'                    AS server_cipher,
       e.observation -> 'tls' ->> 'ja3'                        AS client_ja3,
       e.observation -> 'tls' ->> 'ja4'                        AS client_ja4,
       e.observation -> 'tls' ->> 'ja3s'                       AS server_ja3,
       e.observation -> 'tls' ->> 'ja4s'                       AS server_ja4,
       jsonb_array_length(e.observation -> 'tls' -> 'alpn')    AS alpn_count,
       jsonb_array_length(e.observation -> 'tls' -> 'recs')    AS record_count
FROM helena_normalized_events e
WHERE e.observation ? 'tls';


-- helena_flatten_http: one row per event that observed HTTP, per version.
--
-- Layer:    flatten
-- Object:   VIEW (plain). It feeds the aggregate and the entity rows above it.
-- Reads:    helena_normalized_events
-- Read by:  tests/test_context.py today; the signal layer next (prd tasks 13-14).
--
-- `protocol` is the observation key the row came from -- 'http' or 'http2' --
-- rather than a version string this file invents. A flow that observed both
-- gets two rows, which is what "one row per observed HTTP layer" means when a
-- flow can observe two of them (15 sampled flows observed HTTP/2 and 11
-- observed HTTP/1; none observed both, but the contract allows it).
--
-- Existence says the layer was observed; the counts say what was in it, so an
-- HTTP observation with no requests is a row reading 0 and not a missing row.
-- Summed over a capture the counts equal the row counts of the two views below.
CREATE VIEW helena_flatten_http AS
SELECT e.tenant,
       e.sensor,
       e.capture_sha256,
       e.record_offset,
       e.event_id,
       e.schema_version,
       'http'                                                    AS protocol,
       jsonb_array_length(e.observation -> 'http' -> 'req')       AS request_count,
       jsonb_array_length(e.observation -> 'http' -> 'res')       AS response_count
FROM helena_normalized_events e
WHERE e.observation ? 'http'
UNION ALL
SELECT e.tenant,
       e.sensor,
       e.capture_sha256,
       e.record_offset,
       e.event_id,
       e.schema_version,
       'http2',
       jsonb_array_length(e.observation -> 'http2' -> 'req'),
       jsonb_array_length(e.observation -> 'http2' -> 'res')
FROM helena_normalized_events e
WHERE e.observation ? 'http2';


-- helena_flatten_http_requests: one row per HTTP request observed on a flow.
--
-- Layer:    flatten
-- Object:   VIEW (plain). URL entities and the host part of a URI are taken
--           from it by the layer above.
-- Reads:    helena_normalized_events
-- Read by:  tests/test_context.py today; entity extraction next (prd task 14).
--
-- HTTP/1 and HTTP/2 requests arrive under different keys and are the same thing
-- to everything above -- a method, a URI and a user agent observed on this flow
-- -- so they are one view with a `protocol` column rather than two views every
-- reader would have to union itself.
--
-- `exchange_number` is the input's `num`, and it is NULL on every HTTP/2 row
-- because the HTTP/2 observation has no such field: measured over the sample,
-- `num` is present on all 15 HTTP/1 requests and on none of the 21 HTTP/2 ones.
-- That NULL is a property of the version, readable off the `protocol` column,
-- and not an unobserved value -- `content_type`, by contrast, is genuinely
-- optional on both versions.
--
-- `uri` is the URI exactly as supplied, query string and all. See the head of
-- this file for why it is not split here.
CREATE VIEW helena_flatten_http_requests AS
SELECT e.tenant,
       e.sensor,
       e.capture_sha256,
       e.record_offset,
       e.event_id,
       e.schema_version,
       'http'                              AS protocol,
       q.request_index,
       q.request ->> 'method'              AS method,
       q.request ->> 'uri'                 AS uri,
       q.request ->> 'agent'               AS user_agent,
       (q.request ->> 'num')::INT          AS exchange_number,
       q.request ->> 'content_type'        AS content_type,
       q.request ->> 'content_len'         AS content_length
FROM helena_normalized_events e,
     jsonb_array_elements(e.observation -> 'http' -> 'req')
         WITH ORDINALITY AS q(request, request_index)
UNION ALL
SELECT e.tenant,
       e.sensor,
       e.capture_sha256,
       e.record_offset,
       e.event_id,
       e.schema_version,
       'http2',
       q.request_index,
       q.request ->> 'method',
       q.request ->> 'uri',
       q.request ->> 'agent',
       NULL::INT,
       NULL::VARCHAR,
       NULL::VARCHAR
FROM helena_normalized_events e,
     jsonb_array_elements(e.observation -> 'http2' -> 'req')
         WITH ORDINALITY AS q(request, request_index);


-- helena_flatten_http_responses: one row per HTTP response observed on a flow.
--
-- Layer:    flatten
-- Object:   VIEW (plain). Read with the requests by the layer above.
-- Reads:    helena_normalized_events
-- Read by:  tests/test_context.py today; the signal layer next (prd tasks 13-14).
--
-- `status_code` and `content_length` are VARCHAR because that is how they
-- arrive: the input carries `code` and `content_len` as strings and the
-- contract keeps them as strings under strict mode
-- (src/helena/normalizer.py::HttpResponse), so casting here would be this layer
-- inventing a type the producer did not commit to. Anything that wants to
-- compare a status class casts it and finds out loudly when a producer sends
-- something that is not a number.
--
-- `exchange_number` and `content_length` are NULL on every HTTP/2 row for the
-- reason given on the requests view: the HTTP/2 observation has neither field.
-- `content_type` and `server` are optional on both versions and their NULL
-- means unobserved.
CREATE VIEW helena_flatten_http_responses AS
SELECT e.tenant,
       e.sensor,
       e.capture_sha256,
       e.record_offset,
       e.event_id,
       e.schema_version,
       'http'                              AS protocol,
       s.response_index,
       s.response ->> 'code'               AS status_code,
       (s.response ->> 'num')::INT         AS exchange_number,
       s.response ->> 'content_type'       AS content_type,
       s.response ->> 'content_len'        AS content_length,
       s.response ->> 'server'             AS server
FROM helena_normalized_events e,
     jsonb_array_elements(e.observation -> 'http' -> 'res')
         WITH ORDINALITY AS s(response, response_index)
UNION ALL
SELECT e.tenant,
       e.sensor,
       e.capture_sha256,
       e.record_offset,
       e.event_id,
       e.schema_version,
       'http2',
       s.response_index,
       s.response ->> 'code',
       NULL::INT,
       s.response ->> 'content_type',
       NULL::VARCHAR,
       s.response ->> 'server'
FROM helena_normalized_events e,
     jsonb_array_elements(e.observation -> 'http2' -> 'res')
         WITH ORDINALITY AS s(response, response_index);
