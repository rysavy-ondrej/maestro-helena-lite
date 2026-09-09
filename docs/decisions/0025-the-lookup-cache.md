# 0025 — The lookup cache, which is the evidence store

**Status: accepted.** Task 35 (D5 Tools).
**Authority:** `concept/07-principles.md` ("Caching", "Retention and replay"),
`concept/03-architecture.md` ("Live — the analyst tier"),
`concept/02-concepts-and-taxonomy.md` (the four statuses and `no_match`),
`concept/05-threat-intelligence.md` (rules 4 and 5),
`concept/08-open-questions.md` ("The analyst and the provider tool"),
`concept/instruction.md` §2 and §3, and
`docs/decisions/0024-provider-tools-and-the-mcp-boundary.md`.

This increment adds `sql/migrations/0017_analyst_lookup_cache.sql` — two tables
and one view — and the cache-first half of `helena.tools`. It adds **no runtime
dependency, no second store, no egress channel, no source and no contract
field.** It closes two of `concept/08`'s open questions and answers a third that
the task raised, and each of the three is a section below.

---

## 1. There is no cache. There is the evidence store, read first.

`concept/instruction.md` §3 requires an escalation before "adding a second store
of any kind, **including a cache**", and §2 forbids "a cache that is not itself
the evidence store". `concept/07` says why in one sentence:

> The cache **is** the evidence store, not a second store beside it. A separate
> opaque cache was rejected because an assessment could then cite something the
> cache had already evicted.

So nothing was escalated and nothing new was introduced: the two tables 0017 adds
are in the one streaming engine, in the evidence shape `sql/migrations/0011`
defined and `sql/migrations/0014` derives for the feeds, and `EvidenceCache` is a
reader and a writer over them holding a connection and no state at all. **There
is no in-process memoization in front of it**, deliberately — that would be the
second store, it would make two runs in one process differ from two runs in two,
and it would be invisible to a replay.

**Nothing is evicted.** `expires_at` bounds *validity*, never lifetime. An
expired row is still there, still citable and still readable, which is the
property the rejected opaque cache could not offer and the reason §4 below can
answer the way it does. The cost is honest and stated in the migration head: both
tables grow without bound, and pruning is deferred because what a prune may keep
is a function of how far back replay has to reach — still open in `concept/08`.

## 2. Cache-key normalization, and the asymmetry that makes it safe

`concept/08` lists it with the measurement attached: *"cache-key normalization,
because inconsistent keys quietly halve the hit rate."* The rule
`helena.tools.normalize_indicator` implements is stated before the folding,
because the folding is only defensible under it:

> **Fold only what the identifier's own specification makes equivalent, and when
> in doubt leave the value exactly as it is.**

A fold that is too timid costs one live query and one re-disclosure of an
indicator that was already disclosed. A fold that is too eager serves *one
indicator's evidence for a different indicator* — a wrong answer with a citation
on it. The two errors are not comparable, so every rule is a documented
equivalence:

| Type | Folded | Left alone |
| --- | --- | --- |
| `address` | the textual form, through `ipaddress` — `2001:0DB8::0001` and `2001:db8::1` are one address | anything that does not parse as an address |
| `domain` | ASCII case and trailing dots — the rule `sql/migrations/0008` already applies to an observed name | IDN forms: `xn--55qx5d.cn` and its U-label stay two keys |
| `url` | the scheme's case, the host's case, a default port, an empty path (RFC 3986 §6.2.2–6.2.3) | the path's case, the query, the fragment, anything not a hierarchical URI |
| `fingerprint` | case — a JA3 is a hex digest | everything else |

Three consequences worth having in writing:

* **Normalization never changes what is sent.** The adapter receives the
  `ToolCall` with the caller's own spelling. The normalized value is the key the
  store is searched by and the subject the claim is recorded against, and the
  spelling that was disclosed is kept on the stored response beside it.
* **IDN is not folded**, because the fold needs an IDNA implementation this
  project has no dependency for — and `sql/migrations/0008` records that the
  engine has no IDNA function either, which is why the public-suffix loader
  punycodes its rules instead.
* **The fragment is not dropped**, even though a server never sees one, because a
  threat-intelligence provider matches the literal string it was given.

One divergence is recorded rather than resolved: Python's `str.lower` is
Unicode-aware and RisingWave 3.0.3's is ASCII-only (measured, `sql/migrations/0008`),
so a non-ASCII U-label in uppercase folds here and does not in the engine's
`normalized_name`. Nothing joins the two today; the increment that joins an
analyst-tier claim to a context owes the reconciliation.

## 3. Are negative results cached? **Yes.**

`concept/08` frames this as the question that decides whether caching helps at
all — *"most lookups miss"*. Three reasons, in order of weight:

1. **A `no_match` is an answer**, not an absence. `concept/02`: "the source
   completed its query and returned no record — a lookup outcome, never a
   statement of safety." It is stored in the same shape a hit is, with a
   classification and a confidence, and there is no shape in which it could be
   "not cached" without inventing a fifth thing between an answer and a failure.
2. **The quota is the binding constraint.** Under a few-hundred-lookups-per-day
   budget, a cache that only holds hits is one that almost never helps, because
   almost every lookup misses.
3. **Not caching a miss re-discloses the indicator every run.** Caching is a
   privacy control (§5), and the negative case is where most of the disclosure
   would be.

**A failure is not cached**, and that is a different question with the opposite
answer. An outage is not a record of what a source said; caching one would let a
five-minute outage suppress every query for the retention window, which is
`failed` collapsing into an answer. A response that arrived and would not map is
in between and is handled precisely: **the bytes are stored** (§6) and **no claim
is**, so the operator can investigate what arrived and the next lookup treats the
key as a miss.

What is deliberately *not* done: a shorter retention for negatives than for hits.
The argument for one is real — an indicator that was unlisted may be listed
tomorrow, while a listing rarely disappears — and it is unmeasured, so it would be
a number chosen to look thoughtful. One retention per (source, endpoint), applied
to both.

## 4. Is an expired entry offered as explicitly stale when the provider is unreachable? **Yes.**

The other question `concept/08` leaves open, and the answer follows from §1: the
record was never evicted, so it is still there. `concept/02` defines `stale` as
exactly this case — *"there is a snapshot and the publisher has moved past it.
The claims still stand: removal from a feed is not exoneration, and an aged
snapshot is evidence with a date on it rather than evidence withdrawn."* Refusing
to serve it would leave the analyst with nothing when the store held something,
and would leave `stale` a status with no producer anywhere in the system.

**It is a fallback and never a substitute for a query.** The order is: valid
entry → serve; expired → query; query failed *and* an expired entry exists →
serve it `stale`.

The shape it takes is the part that needed care, because `concept/05` rule 4
forbids "a taxonomy object" on a failed query and `concept/instruction.md` §2
forbids collapsing `stale` and `failed`. Both hold, because **that answer
contains two retrievals and both are in the trace**:

| Step | Outcome | Carries |
| --- | --- | --- |
| the cache read | `cache_hit`, `retrieved_at` = the record's own time | one evidence row per claim, every one of them `stale` |
| the live query | `live_query`, `retrieved_at` = now | the `QueryFailure`, and no taxonomy object |

Rule 4 constrains a query's own result, and the failed query's step carries a
typed error and nothing else. The stale rows came from a query that completed
days earlier and say so. `ToolAnswer` was widened to permit exactly this — one
failure beside evidence that is entirely `stale` — and a failure beside an `ok`
row is still refused, which `tests/test_tools.py` asserts. Task 34's stricter
check was correct for a layer with no cache; this is the case it did not have.

The alternative — return the typed failure and let the analyst record a gap — was
rejected for the reason above, and it remains one line to reinstate: the branch is
named in `ProviderTool.lookup` and the decision is here rather than in a comment.

## 5. A cache hit discloses nothing, so caching is a privacy control

`concept/07` states it and this is where it becomes a property rather than a
remark. The indicator was disclosed once, when the entry was fetched; every later
run that reads it sends nothing at all. The measurement in the tests is not a
call counter — the adapter is the **only** thing in this layer that can reach a
provider (`helena.tools` imports no HTTP machinery at all, asserted off the
module's own AST), so an adapter that was not called is an indicator that was not
sent.

The log records it per call: `disclosed=true` on a live query, `false` on a hit,
and `true` on a stale fallback — which did reach the provider, and got no answer.
That field is a local log line and **not** the disclosure record `concept/03`
asks for; the send policy and the disclosure row are the next increment's, and
this decision does not pre-empt them.

> Landed since, in [0027](0027-disclosure-and-the-send-policy.md): the record is a
> row on the run's `helena.disclosure.Disclosures` ledger, one per outbound call
> and none for a hit, and it reconciles with `RunBudget.live_queries_spent`. The
> log field above is unchanged and is still the local line.

## 6. The response is stored before it is evaluated

`concept/05` rule 5: *"store the response before it is evaluated, cited by stable
identifier, or an assessment that depended on a live lookup cannot be replayed
because the provider's answer will have changed."* The identifier is the sha256
of the bytes (`helena.tools.response_version`), which is also what the claims
carry as `snapshot_version` — a live answer has no feed snapshot, and what dates
it is the response it came out of.

The **order** is the load-bearing part and the malformed case is what proves it: a
response that will not map into the declared subset is on disk under its digest
with no claims beside it, so the failure can be investigated against what
actually arrived and the key is still a miss. A cache hit rebuilds the
`NativeResponse` from those bytes, so a replay reads what the provider said
rather than what it would say today.

## 7. Retention per source *and* per endpoint, and what an endpoint is here

`concept/07` asks for both, and gives the reason as a spread: *"multi-engine
reputation moves as engines rescan, a registration date never changes, and risk
scores sit between."* So `retention_seconds` is a required per-tool value with no
default — a source-wide number would be one number too few, and a default would
be the silent configuration `concept/instruction.md` §6 names.

**One tool is one source and one endpoint.** The endpoint is a *logical name for
one operation*, validated against `^[a-z0-9][a-z0-9_]*$` — not a path and never a
URL, because it reaches the tool name the model is shown and `concept/03` is
explicit that the agent is offered a capability rather than a client. It is in
the cache key because `concept/07` puts it there, and the tension with
`concept/instruction.md` §1 ("no config key with one value") is recorded rather
than resolved by ignoring one of them: there is one endpoint today, the concept
names the dimension twice, and the concept is the higher authority.

A measured correction came out of this and is worth carrying: **the endpoint is
in the evidence table's primary key and not in `evidence_id`.** The identifier is
a contract shared with the enrichment tier, where there are no endpoints, so
widening it would change every feed row's identity. But two endpoints of one
source that return the same bytes about one indicator read the same claim out of
them and mint the same identifier — and with the endpoint out of the key, the
second lookup upserted the first and handed it the *other* endpoint's retention.
A test now holds that shut.

## 8. Why the analyst tier is not unioned into `helena_reference_evidence`

`helena_reference_evidence` is the enrichment tier: static feeds joined per entity
into `helena_analytical_enriched_context`, which is what triage is rendered from.
Adding analyst rows to it would be kept out of the *rendering* by the tier
allow-list — but they would still enter the enriched context of every later host
that talked to the same address, and `concept/03` names that outcome as the thing
the tier tag exists to prevent rather than something the tag makes safe.

`helena_reference_evidence_analyst` is where that union would attach when an
increment decides how an analyst-tier claim reaches a finding. Its purpose today
is narrower and concrete: it carries the `'analyst'` literal, so the constant has
a second home the engine can be asked about, and `tests/test_tools.py` asserts it
equal to `helena.enrichment.ANALYST_TIER` by execution — the duplicated-constant
debt `docs/decisions/0024`'s report recorded.

## 9. Status is derived, never stored

There is no `status` column. `ok` and `stale` are properties of *now*:
`helena.enrichment.feed_status` made the same decision for feeds and its docstring
gives the argument — *"a stored `stale` would be wrong the moment time passed"* —
and it is sharper here, because a cached claim crosses from `ok` to `stale` with
no writer involved. The row stores `retrieved_at` and `expires_at`;
`CacheEntry.evidence` derives the status against the clock the run was given, so
two records served in one answer cannot disagree about what time it is.

This is consistent with the identifier by construction:
`helena.enrichment.evidence_id` already excludes the status, because a claim that
goes stale is the same claim.

`failed` and `missing` have no row here at all. A query that did not complete
emits a typed error and no taxonomy object, so there is nothing to store; and a
cache **miss is not `missing`** — it is the reason to query. Recording a miss as
`missing` would be the collapse `concept/instruction.md` §2 forbids, dressed as
an optimisation.
