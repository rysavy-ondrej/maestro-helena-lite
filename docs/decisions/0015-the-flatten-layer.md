# 0015 — The flatten layer is eight plain views, and a layer's row is what says it was observed

**Status: accepted.** Task 12 (D2 Context).
**Authority:** `concept/03-architecture.md` (the three view layers, and *do not
materialize an intermediate that only feeds an aggregate*),
`concept/instruction.md` §1 (**plain view by default**; every view declares which
it is and what reads it), §2 (**view layering holds**; **absence is not
emptiness**) and §6 (never index `[0]`; a URI is not a domain).

## What was decided

`sql/migrations/0005_flatten_layer.sql` creates the bottom of the Context
Builder's three layers as **eight plain views over `helena_normalized_events`**:

| Object | One row per | Why it exists |
| --- | --- | --- |
| `helena_flatten_flows` | normalized event | the flow itself, typed |
| `helena_flatten_dns` | event that observed DNS | the layer was observed, and its rcode |
| `helena_flatten_dns_queries` | question asked | domain entities |
| `helena_flatten_dns_responses` | resource record answered | address and domain entities |
| `helena_flatten_tls` | event that observed TLS | SNI and the client fingerprints |
| `helena_flatten_http` | observed HTTP layer, per version | the layer was observed, and how much of it |
| `helena_flatten_http_requests` | request, either version | URL entities and the host part |
| `helena_flatten_http_responses` | response, either version | what came back |

Every row carries the whole assigned identity — tenant, sensor, capture sha256,
record offset, event id and schema version — because a row the layers above
aggregate is a row an assessment may end up citing, and an entity row that could
not name its tenant would end the tenant seam at ingestion.

## Three choices worth writing down

**Everything is a plain view.** `concept/03-architecture.md` measured a
materialized intermediate at 42 % more disk than the same query as a plain view,
and every object here is exactly that intermediate: the signal layer aggregates
it and nothing queries a flatten row on its own. The decision is only free if the
layer above can still be a streaming job over a plain view, so that was measured
against RisingWave 3.0.3 before the file was written and is asserted by
`tests/test_context.py`: a materialized view over a flatten view backfills and
returns rows, including over the two constructions this layer needs —
`jsonb_array_elements(...) WITH ORDINALITY`, and a `UNION ALL` of two such
branches. `TUMBLE(helena_flatten_flows, flow_start, INTERVAL '5 minutes')` is
accepted directly off the plain view, which is what task 13 needs.

**A layer-observation row is how absence stays distinct from emptiness.** A
set-returning function collapses "the array was empty" and "the layer was never
observed" into the same zero rows, so unpacking the arrays alone would lose the
distinction `concept/instruction.md` §2 refuses to lose. Each layer family
therefore has an observation object whose *existence* is the statement that the
layer was observed, with a count column saying what was in it:

```text
observed, non-empty   a row in helena_flatten_dns, N rows in the queries
observed, empty       a row in helena_flatten_dns, 0 rows, count column reads 0
not observed          no row in helena_flatten_dns at all
```

`tcp.24` in the sample is the real case: TLS observed, ALPN observed and empty.
It has a `helena_flatten_tls` row reading `alpn_count = 0`, while `udp.28` —
which observed no application layer at all — has no row in any of the seven.

**HTTP/1 and HTTP/2 are one view with a `protocol` column.** They are the same
thing to everything above — a method, a URI, an agent observed on this flow — and
two views would be a union every reader writes for itself. The consequence is
stated on the views: `exchange_number` and a response's `content_length` are NULL
on every HTTP/2 row because the HTTP/2 observation has no such field (measured
over the sample: `num` on all 15 HTTP/1 requests and none of the 21 HTTP/2 ones),
which is a property of the version and readable off the `protocol` column.
`content_type` and `server`, by contrast, are optional on both versions and their
NULL means unobserved.

## What this layer deliberately does not do

It does not split a URI. `concept/instruction.md` §6 wants the host part in a
domain column, and deciding what a domain is a question about the Public Suffix
List (prd task 15) rather than about unpacking; the flatten layer has no domain
column at all.

It does not unpack the TLS client offer (`cciphers`, `cexts`, `csigs`, `csvers`,
`sexts`) or the ALPN values. Nothing above reads them yet, and a view per unread
array is structure ahead of the increment that needs it. `alpn_count` is here
because the observed-but-empty case is real. Nothing is lost either way: the
record is whole in `helena_normalized_events.observation`.

It does not sum the two directions. `concept/07-principles.md` keeps connection
statistics bidirectional because direction is signal, and there is no
`bytes_total` column for the same reason there is no `packets_total` one.

## The coverage this rests on, and its one hole

Every assertion is over real records — the ten-record layer-coverage capture in
`tests/fixtures/captures/`, and all 62 records of `data/ingest/flow-sample.jsonl`
— put through the real normalizer and the real event store, then read back out of
the views on a throwaway engine.

Two branches real data cannot reach, and both are covered by taking a real record
and changing it in a way the contract permits, in a temporary capture that is
never committed as a fixture:

- **A flow that observed both `tcp` and `udp`.** No sampled record does, so the
  `transport` column's both-case is unreachable. It resolves to the visible value
  `'tcp+udp'` with TCP's ports, rather than silently picking one.
- **An HTTP/1 observation with unequal request and response counts.** All eleven
  in the sample hold as many responses as requests, so `request_count` reading
  the response array is invisible to every test over real HTTP/1 data. HTTP/2
  separates them by itself (`tcp.0`: one request, three responses).
