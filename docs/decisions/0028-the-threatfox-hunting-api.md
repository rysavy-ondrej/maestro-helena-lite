# 0028 — The ThreatFox hunting API: the source record for the first live provider

Status: **accepted**. Maturity: **experimental** — the surface below was measured
against the live service on **2026-09-10** and the adapter is exercised against
it, but no agent has yet driven a tool loop through it and no verdict has been
evaluated.

Supersedes nothing. Corrects one sentence of
[`concept/05-threat-intelligence.md`](../../concept/05-threat-intelligence.md)
and one sentence of `helena.tools.normalize_indicator`; §9 and §6 say which.

---

## 0. Why this document exists at all

`concept/05` records, emphatically, that *"the last three source records in this
project were each wrong for the same reason: written from a documentation page or
a guessed convention, then propagated before anyone fetched the thing it
described."* This file is the artifact-checked source record for the analyst
tier's one live provider, and **every table in it is a measurement**. Where a
number or a shape came from a page rather than from a response, it says so.

The probes were sent from this repository through `helena.config.Settings`'
credential, paced at the self-imposed four queries per minute in
`config/policy.toml`, and totalled **eighteen requests**. No credential value
appears here.

---

## 1. The confirmed query surface

| | Measured, 2026-09-10 |
| --- | --- |
| URL | `POST https://threatfox-api.abuse.ch/api/v1/` — one path for every operation |
| Body | JSON object; the operation is the `query` key. **Not** form-encoded, not a path or query-string parameter |
| Credential | HTTP header **`Auth-Key`**. Never in the path, never in the body |
| Response | `application/json`, always. `Content-Type` is set on 200 and **absent on 401/403** |
| Rate limit | **No published number and no rate-limit header on any response.** "Fair use principles" is what the terms say |

The documented operation set is ten: `get_iocs`, `ioc`, `search_ioc`,
`search_hash`, `taginfo`, `malwareinfo`, `submit_ioc`, `get_label`,
`malware_list`, `types`, `tag_list`. **`search_ioc` is the per-indicator lookup**
and is the only one this project uses; `submit_ioc` writes to the publisher's
dataset and is out of scope by `concept/instruction.md` §3 (nothing here moves
toward an outward-facing side effect).

### `search_ioc`, the operation the tool is

```json
{"query": "search_ioc", "search_term": "<indicator>", "exact_match": true}
```

`exact_match` defaults to **false**, and §3 is about what false actually does.

---

## 2. The envelope, and the trap in it

Every request that reached the application answered **HTTP 200**, including every
error. **The status code carries no information about the query**; `query_status`
does. Measured:

| What was asked | HTTP | `query_status` | type of `data` |
| --- | --- | --- | --- |
| a listed domain, `exact_match: true` | 200 | `ok` | list of records |
| an unlisted domain | 200 | `no_result` | **string** — `"Your search did not yield any results"` |
| `search_ioc` with no `search_term` | 200 | `missing_search_term` | string |
| `{"query": "helena_probe_not_a_query"}` | 200 | `unknown_operation` | string |
| a syntactically valid but wrong `Auth-Key` | **403** | `unknown_auth_key` | *absent* |
| no `Auth-Key` header at all | **401** | *absent* — the body is `{"error": "Unauthorized"}` | — |

**`data` changes type with `query_status`** — a list on `ok`, a string
otherwise — so a reader that indexes `data` without reading `query_status` first
crashes on the miss case, which is the common one. The adapter reads
`query_status` first and treats every other shape as `malformed_response`.

The two authentication failures are **two different shapes** and neither is a
`query_status` a reader could branch on uniformly: 401 has no `query_status` key,
403 has one and no `data`. Both map to the typed reason `auth_failed`.

---

## 3. `exact_match` cannot be used for an address, and the wildcard is not a substring search

This is the finding that shapes the adapter, and it follows from a fact
`concept/05` already records about the feed side: **ThreatFox indicators for
addresses are `ip:port`, never a bare address.** The `types` operation confirms
the closed `ioc_type` vocabulary contains no bare `ip`:

    body_from, domain, envelope_from, ip:port, md5_hash, sha1_hash,
    sha256_hash, sha3_384_hash, url

Measured against one address that the committed snapshot lists as
`45.192.105.203:8000`:

| Query | Result |
| --- | --- |
| `search_term: "45.192.105.203", exact_match: true` | **`no_result`** |
| `search_term: "45.192.105.203"` (wildcard) | `ok`, one record, `ioc = "45.192.105.203:8000"` |

So an **address lookup must use the wildcard**, and a domain or URL lookup may
use `exact_match: true` (both confirmed to return the exact record).

**What the wildcard actually does was measured rather than inferred**, because
"substring search" would have been a guess and it is wrong:

| Query | Records | What came back |
| --- | --- | --- |
| `45.192.105.20` — a strict prefix of the listed `ip:port` | `no_result` | a plain substring search would have matched |
| `72.255.59.61` — an address that appears **inside a listed URL** | 1 | `ioc_type: url`, `ioc = "http://72.255.59.61:50866/Mozi.7"` |
| `workers.dev` | **1 386** | 1 350 `domain` and 36 `url`, every one a different name under a shared suffix |

The mechanism is not documented and this project does not need to name it. The
**rule** it forces is:

> **A wildcard result is a set of candidates, not a set of matches.** Every
> record it returns is checked against the asked indicator and the asked entity
> type, and a record that is about something else is not a claim about what was
> asked.

Two of the three rows above are scope errors waiting to happen, and
`concept/02`'s scope-before-severity is what they would break: a URL listing on
an address is a claim about that URL, and reporting it as a claim about the
address would say the host was contacted at a listed location when it was not.
`workers.dev` is the shared-infrastructure case `concept/05` names, arriving
through the query surface rather than through the join.

**A dropped candidate is counted, never silently discarded.** Every claim the
adapter emits carries `records_returned` and `records_out_of_scope` in its native
evidence, and a response whose every record was out of scope is `no_match` — an
answer, with the count saying the provider was not silent. The whole response is
stored either way (`concept/05` rule 5), so nothing that arrived is lost.

---

## 4. The record shape, and how it differs from the bulk export

The API and the export are the same dataset in two spellings, and the spellings
differ in ways that would each have been a defect if assumed:

| Bulk export (`threatfox.abuse.ch/export/json/recent/`) | `search_ioc` |
| --- | --- |
| `ioc_value` | **`ioc`** |
| `first_seen_utc`, `last_seen_utc` | **`first_seen`, `last_seen`** — and the value carries a `" UTC"` suffix the export's does not |
| `tags` is a **comma-separated string** | `tags` is a **JSON array**, or `null` |
| the indicator id is the **object key** (the top level is an object of lists) | `id`, a field on the record, and the top level is a **flat list** |
| `anonymous` | absent |
| — | `sightings`, `threat_type_desc`, `ioc_type_desc`, `malware_malpedia`, `malware_samples` |

`is_compromised` is present on both, as a real boolean.

The adapter therefore **translates the API record into the export's own entry
shape** and pushes it through the loader's mapping functions —
`helena.enrichment.split_indicator` and `classify_threat_type` — rather than
writing a second mapping. That is what makes `concept/05`'s "evidence tiering
keeps the two comparable" true of the code and not only of the prose, and
`tests/test_providers.py` asserts a live claim and the enrichment view's claim
about one record agree field for field.

**`sightings` is the one field that is genuinely new information.** §7 is about
what that is worth.

---

## 5. Typed errors: down, rate-limited and slow

`concept/05` rule 4 — *"emit a typed error on failure, and no taxonomy object; a
timeout is never `no_match` and never `unknown`"* — over
`helena.enrichment.QUERY_FAILURE_REASONS`, which already existed and is reused
rather than extended:

| What happened | Reason |
| --- | --- |
| 401, or 403 with `unknown_auth_key` | `auth_failed` |
| 429 | `quota_exhausted` |
| any other HTTP status | `transport_error`, carrying the status and nothing from the body |
| the read timed out | `timeout` |
| the host did not resolve, refused, or the connection dropped | `transport_error` |
| 200 whose body is not JSON, whose `query_status` is absent or unknown, or whose `data` is the wrong type for its status | `malformed_response` |

None of them is `no_match` and none is a claim. `helena.tools.ProviderTool` turns
each into a `QueryFailure` on the retrieval step with no taxonomy object, and
serves an expired cached record explicitly `stale` beside it when one exists.

**Slow mid-analysis is two bounds and they are different.** The adapter's own
read timeout ends one request; the run's wall clock (`helena.budgets.RunBudget`,
charged on the same ledger as the model calls) ends the analysis. A request that
outlives the first is `timeout`; a run that outlives the second is a
`budget_exhausted` refusal and never a failure, because nothing was queried.

**The response body is never quoted into a failure detail.** It is text a
provider chose, and `concept/instruction.md` §6 makes retrieved provider text
data rather than diagnostics; the status and the exception class go into the
typed error, the bytes go to the store.

---

## 6. What is sent, in what spelling

The body carries the operation selector, the indicator, and — for a domain or a
URL — `exact_match`. Nothing else: no tenant, no sensor, no monitored host, no
window. That is `config/policy.toml`'s `[send_policy.threatfox] fields =
["entity_type", "entity_value"]` as a structural property, because the `ToolCall`
is the only object the adapter is handed.

**The adapter sends the normalized indicator**, through the same
`helena.tools.normalize_indicator` the cache key uses, and this is a correction
to a sentence in that function's docstring that predated any adapter
("normalization never changes what is sent"). The measurement that forced it:

| `search_term`, `exact_match: true` | Result |
| --- | --- |
| `fuwabo.workers.dev` | `ok` |
| `FUWABO.WORKERS.DEV` | `ok` — the match is case-insensitive |
| `fuwabo.workers.dev.` | **`no_result`** — the trailing root dot is not tolerated |

A fully-qualified name with the root dot is a spelling DNS traffic legitimately
produces. Sending it verbatim would have returned `no_result`, and the layer
would have **cached a `no_match` under the folded key** — a wrong claim with a
citation on it, which is the exact asymmetry `normalize_indicator`'s own
docstring argues against.

**The cost of the choice, recorded rather than glossed:** the disclosure ledger
records `entity_value` *as the model asked it* and the bytes that left carry the
folded spelling, so for a trailing-dot or upper-case indicator the two differ by
the fold. Both are recorded — `helena_reference_analyst_response` stores the
indicator as asked beside the normalized key — and the entity disclosed is the
same entity either way.

---

## 7. The retrieval confound, measured

`concept/05`: *"the same publisher feeds the enrichment tables and answers the
analyst's live questions … for any indicator already in the tables, the analyst
mostly re-confirms what triage saw."* That is now a measurement rather than an
expectation.

Three indicators — one `domain`, one `ip:port`, one `url` — present in the
committed snapshot were asked of the hunting API on 2026-09-10. For **all three**,
every field the two surfaces share was **identical**: same `id`, same
`threat_type`, same `malware`, same `confidence_level`, same `first_seen`, same
`is_compromised`, same `reporter`. The live lookup returned the same row the bulk
loader had already put in the tables.

**So an analyst-tier ThreatFox lookup about an indicator triage already saw adds
nothing to the classification, the confidence or the scope.** N = 3, and the
sample is small because each comparison costs a live query against a fair-use
service; what makes it more than three data points is that the export is a dump
of the same dataset, so agreement is the structural expectation and disagreement
would have been the finding.

What the live tool does add, and it is a short list:

1. **Freshness between snapshot loads.** The bulk snapshot is loaded on the
   feed's own schedule; an indicator added since is only reachable live.
2. **`sightings`** — a per-indicator count the export does not carry at all.
3. **Expiry, which cuts the other way.** The publisher expires IOCs older than
   six months and expired entries are exposed on **neither** the API nor the
   export, so the live tool cannot recover what a stale snapshot still holds.

**The consequence for anything reading these claims:** a ThreatFox analyst claim
corroborating a ThreatFox enrichment claim is **one source agreeing with itself**,
not two independent sources. `helena.enrichment.source_diversity` counts by
`source_id` and both tiers carry `threatfox`, so the arithmetic is already right;
this section is why it must stay right. `concept/05`'s concentration risk is the
same fact one level up.

---

## 8. The publisher's false-positive list: designed, and deferred for absence

`concept/05` asks for this and is right about why: a publisher-maintained FP list
is **evidence about evidence**, and it must enter *"by the same door as analyst
feedback — a claim is never deleted, suppression is explicit policy, and a
suppressed match is still recorded as having matched — not by quietly filtering
matches before anything sees them."*

**Measured 2026-09-10: ThreatFox publishes no false-positive list on either
surface this project can reach.** The documented operation set (§1) contains
none; three plausible operation names — `get_fp`, `fp_list`, `false_positives` —
each answered `unknown_operation`; and the export index offers JSON, CSV, MISP,
RPZ, host-file and Suricata formats and no FP feed. What the publisher does
instead is *expire* IOCs older than six months, "to avoid false positives", and an
expired IOC is simply **absent** from both surfaces — which is a deletion, and is
exactly the mechanism `concept/05` says a suppression must not be.

So the design is recorded and the code is not written, because writing it would
mean inventing the artifact it consumes — the failure mode this whole document
exists to avoid. **The shape, for the increment that finds a real FP source:**

| | |
| --- | --- |
| **A claim is never deleted** | the suppressed claim keeps its `evidence_id` and its row, and stays citable. Nothing in this project evicts evidence and this does not become the exception |
| **Suppression is a second claim** | the FP listing is its own evidence row about the *first* row's entity, from its own `source_id`, at its own tier, with its own `snapshot_version`. Not a column on the claim it suppresses |
| **Suppression is explicit policy** | what a suppressing claim *does* is a rule in a frozen `helena.policy.vN`, recorded on the decision as a named rule the way `constrain`'s rules already are — never a filter inside a loader or an adapter |
| **A suppressed match still matched** | the rendering and the assessment both show the claim and its suppression. Hiding it would make a context that was flagged and cleared indistinguishable from one nothing ever matched, and `concept/instruction.md` §2 forbids exactly that collapse |
| **The absence of an entry is not a clearance** | an indicator absent from an FP list is not thereby confirmed, the same way `no_match` is a lookup outcome and never a statement of safety |

The distinction that makes this non-trivial is that **expiry and suppression are
different facts** and the publisher's surface gives us neither: an indicator that
vanishes between two snapshots aged out **or** was retracted, and `concept/05`
already records that a loader diffing snapshots reads them as one event. An FP
list is what would separate them, and this provider does not have one.

---

## 9. The one place `concept/05` was wrong, and it is corrected in place

`concept/05` reads: *"No per-indicator lookup endpoint appears in the public
documentation, and asking about an indicator is the analyst tier's core
operation."*

**That is false as of 2026-09-10.** The public documentation at
`threatfox.abuse.ch/api/` documents `search_ioc` explicitly, with a request
table, a `curl` example and a sample response, and the live service answers it.
The note has been corrected in place with a dated correction block, in the shape
it already uses for the `Auth-Key` correction of 2026-09-03 — recorded rather
than overwritten, because the record of having been wrong is what stops the same
sentence being re-derived.

Whether the sentence was wrong when it was written or the publisher's
documentation changed since is not knowable from here, and this file does not
guess. What is recorded is what the artifact says today.

### A second thing found while checking, which is not this increment's to fix

The export index now documents a **new** bulk surface,
`https://threatfox-api.abuse.ch/v2/files/exports/YOUR-AUTH-KEY-HERE/full.csv.zip`
— **a credential in the URL path**, which is the shape `concept/05` once
wrongly attributed to the endpoint the loader uses and then corrected. Both
records are now true of different endpoints:

- `GET threatfox.abuse.ch/export/json/recent/` — **still 200 with no credential**,
  re-measured 2026-09-10, 3 774 281 bytes. This is the endpoint
  `helena.enrichment.fetch_threatfox` uses and it is unchanged.
- `threatfox-api.abuse.ch/v2/files/exports/<key>/…` — a newer surface, not used
  here, which puts the key in the path.

Nobody should "re-correct" the 2026-09-03 correction on the strength of the
second bullet. The redaction rule (`helena.observability.Redactor`) covers the
path case already and is why it is safe to have found this.

---

## 10. What this increment decided, in one list

1. The endpoint name is **`search_ioc`** — the provider's own operation name, so
   the tool the model is offered is `lookup_threatfox_search_ioc` and the cache
   key names an operation that exists.
2. The host comes from **`config/policy.toml`**, not from code:
   `helena.providers.threatfox_url(permit)` builds the URL from
   `SourcePermission.disclosed_to`, and the adapter **refuses a URL whose host is
   not the permitted one**. That closes the item ADR-0027 §6 deferred as "not
   checkable until a live adapter exists".
3. **Retention is derived, not invented**:
   `SourceDescriptor.refresh_interval_seconds` — the publisher's own fetch floor,
   3 600 s. A cached answer is valid for as long as this deployment would be
   willing to ask the source again. It is a **candidate**, on the same footing as
   `config/policy.toml`'s 0.80 and `config/agents.toml`'s 3: no hit-rate and no
   staleness cost has been measured, and `concept/08` still lists the retention
   horizon as open.
4. `exact_match` is **true for `domain` and `url`, false for `address`** (§3),
   and every wildcard candidate is filtered by entity type and indicator.
5. The adapter lives in **`helena/providers.py`**, not in `helena/tools.py`.
   `tests/test_tools.py` asserts off `tools.py`'s own AST that the boundary
   imports no HTTP machinery and holds no `://` literal, and that assertion is
   the structural half of "the agent sees a tool, never an HTTP client". Putting a
   URL in that module to save a file would have deleted the property.
