# 05 — Threat intelligence sources

> **Static data is a table; live data is a tool.**

A source published as files on a schedule becomes a snapshot-versioned reference
table, joined in SQL. A source answering per-indicator questions becomes a
cache-first MCP tool the Analyst Agent calls. Treating a bulk feed as a live API
puts per-entity network I/O on the stream path; treating a live API as a feed
loses the freshness it exists for.

**Adding a source is a governed decision, not a configuration convenience.**

## What can be enriched

What the input yields determines what enrichment is even possible:

| Entity type | Extracted from | Enrichable by |
| --- | --- | --- |
| `address` | Flow destinations; A / AAAA DNS answers | IP blocklists, C2 trackers, compromised-host lists, cloud and CDN ranges |
| `domain` | DNS query names, DNS response names, TLS SNI, the **host part** of HTTP URIs | Malware and phishing domain feeds |
| `fingerprint` | TLS JA3 and JA4, client-side only | **One JA3 blocklist, and nothing else** |
| `url` | HTTP and HTTP/2 URIs | URL blocklists |

**Three coverage gaps, recorded rather than glossed:**

- **JA4 has no public blacklist.** The flow record carries JA4 and JA4S; nothing
  enriches them.
- **URL feeds have narrow reach on this input.** URIs exist only for cleartext
  HTTP and HTTP/2; TLS yields SNI, not a URL. The matching value is mostly domain,
  address and JA3.
- **Service and application identification identifies *hosting* as often as it
  identifies applications.** Measured against the sample capture, 2026-09-03:
  every `*.trafficmanager.net` name resolves to `app.azure`/Hosting, while
  `config.edge.skype.com`, `ocsp.digicert.com` and `sls.update.microsoft.com`
  resolve to the actual service — and the same activity produces both answers
  depending on which observed name is joined. A cloud range still says only that
  the address is that provider's. So **affirmative `normal` is rarer than
  expected**, and it is why `service` is not an entity type at all: identification
  attaches to the `address` and `domain` entities that already exist. See
  [ADR-0009](../docs/decisions/0009-netify-application-identification.md).

## The enrichment tier — static feeds

**The first version loads exactly one feed: ThreatFox** (abuse.ch). That choice was
a correction made from a measurement rather than from reasoning: the narrowest feed
looked like the cheapest proof, but counted, it carries **five rows** — the join
would never fire against any traffic the project has.

ThreatFox is the better proof on three counts and not merely the larger one: it
carries thousands of address rows and hundreds of domain and URL rows; it produces
**both** address and domain entity rows, so the join is exercised on both types;
and its threat-type field requires real taxonomy mapping where a single-purpose
tracker maps everything to one path. The accepted cost is that it **regenerates
every few minutes**, which makes snapshot versioning a harder problem, not an
easier one.

### The catalogue

The first two rows are **accepted**. Everything below them is **deferred**, and
kept because it is where the next feed comes from.

| Feed | Indicators | Access | Maps to | Tier |
| --- | --- | --- | --- | --- |
| **ThreatFox** | address (`ip:port`), domain, URL | Bulk export **open, no credential**; API needs an `Auth-Key` **header** | C2 and malware delivery, by threat type | B |
| **Netify** | address, domain | Local snapshot in `data/netify/` (gitignored) | **Application identity and category — never a threat classification.** Context only; never escalates ([ADR-0009](../docs/decisions/0009-netify-application-identification.md)) | **D** |
| National CERT warning list | domain | Free, no auth | Phishing, often credential theft | A–B (manually verified) |
| URLhaus | URL; host / RPZ | Auth key | Malware delivery at exact-URL scope; the host inherits **only with host-level evidence** | A / B |
| Feodo Tracker | address | Auth key | Botnet C2 | A–B |
| SSLBL JA3 | JA3 fingerprint | Free, no auth | Malware, or a single low-confidence detection | **C** |
| Spamhaus DROP | netblock, ASN | Free; credit required; **fetch no more than hourly** | Malicious, role unknown — scope is a **netblock or ASN, never a host** | B |
| Emerging Threats compromised IPs | address | Free | Compromised host | C — aggregated, no per-entry evidence |
| Tor exit list | address | Free | Anonymization infrastructure | C–D |
| Cloud and CDN IP ranges | address range | Free, no auth | Cloud hosting | — |
| Public Suffix List | — | Free | **Registrable-domain normalization** — needed for scope correctness, not enrichment |
| Domain popularity list | domain | Free | A popularity prior, **not identity** |

Some sources are simply **not available**: several commercial-grade blocklists
need a datafeed or subscription agreement. Application-identification data is
commercial-only for production use, but a sample is on disk at `data/netify/` and
**the prototype may use it locally** — the decision, its measured coverage and the
two hazards it carries are in
[ADR-0009](../docs/decisions/0009-netify-application-identification.md).

**The JA3 caveat stands and does not improve.** The only JA3 source is a list of
under a hundred fingerprints, first seen years ago, **static since 2021**, carrying
the publisher's own statement that they are untested against known-good traffic and
may cause significant false positives. It is a historical artifact rather than a
feed; it cannot get better by being refreshed, because it is not being refreshed;
and holding a token does not make it Tier A. Whether it earns its place at all is
open, and the sharper half of that question is what a `no_match` against it may be
taken to mean.

### What the loader has to get right

Read from real downloads rather than from a documentation page, the primary feed
has five properties that change what the loader and the join must do:

| Property | Consequence |
| --- | --- |
| Indicators are `ip:port`, not addresses | The loader **splits the port into its own column** and **does not discard it**: a C2 listening on one port matched against a host that contacted another is a weaker claim than a port match — exactly the scope-before-severity distinction |
| A compromised flag separates victim from owner, and is **common, not rare** | A compromised legitimate host serving malware is a different claim about the contacted party than attacker-owned infrastructure, so **the taxonomy root cannot be assigned from the threat type alone** |
| Confidence is numeric and genuinely spread | It must **reach the claim** rather than being flattened away. Note this is confidence in the *entry*, where the A–D tier is about the *source* |
| The threat-type vocabulary is larger than any sample shows | The mapping needs defined behaviour for an unseen value: **emit the parent, never guess a child** |
| References and last-seen dates are frequently absent; tags are a delimited string, not an array | Per-entry evidence often does not exist, which bears on the tier rating; and recency cannot be read from last-seen alone, so **first-seen plus the snapshot version is what dates a claim** |

Two further shape traps: the export's top level is an **object keyed by indicator
id whose values are lists**, so a loader flattens rather than reading the first
element; and the full export is a **rolling window, not a cumulative archive**, so
an indicator's disappearance between two snapshots means *aged out* **or**
*retracted*, and a loader that diffs snapshots reads them as one event.

**Take the structured format, not the DNS-oriented ones.** RPZ and hosts-file
variants drop threat type, confidence and the compromised flag — exactly the set of
distinctions the composition rule needs. A feed that can only say "bad" costs the
ability to weigh scope against severity.

## The analyst tier — live providers

### The primary live provider

The same publisher's hunting API: POST, JSON or CSV per request, authenticated with
a **header**, not a credential in the path.

> **A gap that is not cosmetic.** No per-indicator lookup endpoint appears in the
> public documentation, and asking about an indicator is the analyst tier's core
> operation. **Confirm the query surface against the authenticated documentation
> before building the tool.** This is recorded emphatically because the last three
> source records in this project were each wrong for the same reason: written from
> a documentation page or a guessed convention, then propagated before anyone
> fetched the thing it described.

Its **false-positive list is more interesting than it looks**: a
publisher-maintained FP list is *evidence about evidence*. It should enter by the
same door as analyst feedback — a claim is never deleted, suppression is explicit
policy, and a suppressed match is still recorded as having matched — **not by
quietly filtering matches before anything sees them**.

### One organisation in both tiers, and the cost of that

The same publisher feeds the enrichment tables *and* answers the analyst's live
questions. Evidence tiering keeps the two comparable, **but it cannot manufacture
new information**: for any indicator already in the tables, the analyst mostly
re-confirms what triage saw. What it genuinely adds is freshness between snapshot
loads, indicators added since the last load, and per-indicator context the bulk
export omits.

**Concentration risk, recorded so it is not discovered later:** one provider
supplies most of the prototype's threat intelligence, so if its terms, availability
or coverage change, the evidence base changes with it. Acceptable for a prototype.

### Multi-engine reputation — deferred, with a narrow role

Not a routine second opinion. **A last step**, consulted when the analyst would
otherwise be unable to settle a context. Two lookups only — address and domain — and
no file, hash, relationship or graph queries, and no sample submission ever.

**Its free-tier quota is a design constraint, not an operational detail.** A few
hundred lookups per day is a **shared daily budget across every host the pipeline
assesses**, so routine use is use exhausted before noon. It is also a ceiling on a
whole evaluation rather than on one run, and must be sized against the evaluation
corpus *before the corpus is chosen*.

**Its response is contradictory by nature** — a handful of engines flagging an
address while most do not is normal, and **both sides are evidence**. The
assessment must not collapse it to a single verdict before the agent sees it. And
it is an aggregator, so it is never counted as many independent votes.

There is a real question underneath: what "the analyst is unsure" means, and **who
decides it**. A model that asks for the tool controls a scarce shared resource, and
one verbose run can spend the day's quota for every other host; deterministic code
deciding is inspectable and rate-limitable, at the cost of inferring uncertainty
from outside. Deterministic routing points at the second, and it must be settled
before the tool exists, because it decides *where the tool sits* rather than how it
is written.

### Registration and infrastructure history — deferred

Registration, hosting and DNS history for a domain. Complementary rather than
redundant with multi-engine reputation: **domain age and registration pattern are
often the discriminating evidence when reputation says nothing** — which is exactly
the `suspicious` residue that reaches analysis.

Its registration fields are **the sharpest instance of untrusted input in the
project**: registrant names, organization strings and free-text fields are supplied
by whoever registered the domain, which in a malicious case is the adversary.

## Credentials, rate limits and terms

- **The key is the API tier's, and it travels in a header.** Measured
  2026-09-03: `POST threatfox-api.abuse.ch/api/v1/` returns **401
  Unauthorized** with no `Auth-Key` header and **200** with one, and the bulk
  export `GET threatfox.abuse.ch/export/json/recent/` returns **200 with no
  credential at all**. So the tool layer holds the key and the bulk loader holds
  none.
- **Correction, recorded rather than overwritten.** Until 2026-09-03 this note
  said the bulk export carried the key **in the URL path** and that the secret had
  "two exposure profiles". Both were wrong — checked against the artifact, not the
  page. Do not build the loader around a key it does not need, and **re-measure
  before trusting either endpoint**: abuse.ch changes its auth on its own
  schedule, and a bulk export that is open today may not be tomorrow.
- **The redaction rule stands on its own and is not weakened by this.** It is not
  hypothetical — a live key reached a project conversation inside a pasted link —
  and it is not specific to this provider: an exception carrying a request URL
  leaks whatever was in that URL, whoever required it. See
  [07 — Principles](07-principles.md).
- **Fair-use terms bind both tiers**, and rate limits are **policy the tool layer
  enforces**, not an afterthought.
- Feed licensing attaches to stored evidence and to any derived dataset;
  **datasets stay out of the repository** — for size, and for terms that permit
  local use but not redistribution.

## What every source adapter must do

Feed loader or live tool, the same seven rules:

1. **Declare the subset it can emit**, publish it, version it, and test it.
   Complete taxonomy coverage is not required: a source that only identifies
   phishing maps a hit to phishing, an explicit absence to `no_match`, and nothing
   else.
2. **Map deterministically** from native fields to that subset. The mapping is a
   unit-testable deliverable, not prose.
3. **Emit the parent rather than guessing a child.**
4. **Emit a typed error on failure, and no taxonomy object.** A timeout is never
   `no_match` and never `unknown`.
5. **Retain the native payload for audit**; the compact normalized object is what
   downstream consumers compare across sources.
6. **Preserve contradictions.** Never collapse disagreement to a single verdict
   before the agent sees it.
7. **Retain the origin.** Evidence copied through an aggregator is not an
   independent vote.

**Feed loaders, additionally:** fetch on the feed's own schedule and respect
published fetch limits; **never let a failure empty a table** — a fetch failure, a
format change or an empty response leaves the previous snapshot in place and
records the failure, so the result is `stale` or `missing`, never a silent empty
opinion; write a snapshot version with every load and keep enough history for
replay; redact credentials that travel in a URL before logging, storing or tracing;
flatten nested containers rather than reading the first element; and normalize the
indicator to the entity's shape.

**MCP provider tools, additionally:** own the credential, so the agent sees a tool
and never an HTTP client or a key; be cache-first; enforce budgets at the tool
boundary so an agent cannot reason its way around them; record the disclosure;
**store the response before it is evaluated**, cited by stable identifier, or an
assessment that depended on a live lookup cannot be replayed because the provider's
answer will have changed; tag the evidence `analyst` so it never enters the
precomputed triage path; **on replay, read stored responses and never re-query**;
and validate the response, treating every string in it as data, never as
instruction.
