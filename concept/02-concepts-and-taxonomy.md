# 02 — Concepts and taxonomy

Getting the vocabulary right is not housekeeping here. **The single most
important idea is that a claim about an indicator and a verdict about a host are
not the same kind of statement**, and most of the failure modes the project
guards against are that conflation in some costume.

## The vocabulary

### Input and identity

| Term | Meaning |
| --- | --- |
| **Flow record** | The only input: one flat JSON object per observed flow, with inline DNS / TLS / HTTP observations. It carries **no** tenant, sensor, schema version or raw-record reference |
| **Capture** | A retained file of flow records, identified by the hash of the file. The captures are the project's durable record |
| **Tenant** / **Sensor** | Isolation scope and observing deployment. Assigned at ingestion from deployment configuration, **never read from the record** |
| **Host** | The subject of an assessment, keyed provisionally by source address |
| **Window** | 5-minute tumbling; a flow is assigned by its start time, so a long flow is credited entirely to the window it began in |
| **Completeness** | `open` or `provisional`. **Neither value is "final"** — a context never reaches a state where it cannot change while its raw records are retained |

### Facts

| Term | Meaning |
| --- | --- |
| **Fact** | An observation or an enrichment claim. Stored separately from inference |
| **Host context** | What one host did in one window: traffic statistics, behavioural features, provenance. **Carries no verdict** |
| **Entity** | The thing enrichment is about and the join target: a `domain`, an `address`, or a TLS `fingerprint` observed in a host's window |
| **Indicator** | An entity value as a *source* names it. What is disclosed when an external source is queried |
| **Observation-scoped traffic** | Per-entity counts named for what they are: the traffic of the flows in which the entity was *observed*. A flag distinguishes an address seen as a flow destination from a name, or an address seen only as a DNS answer |
| **Enrichment evidence** | One claim about one entity from one source: the classification, its confidence, its scope, its snapshot, its tier, its status. **An entity carries as many claims as its sources and their values produce** — multiplicity is evidence for the agent to weigh, never something to collapse before it is seen ([ADR-0009](../docs/decisions/0009-netify-application-identification.md)) |
| **Snapshot** | The version of a feed a claim matched against. Replay joins the snapshot current at event time, not today's |
| **Enrichment status** | `ok` / `stale` / `failed` / `missing` — each **distinct from `no_match`** |

### Inference

| Term | Meaning |
| --- | --- |
| **Inference** | A model conclusion or classifier score. Appended, never overwriting a fact |
| **Triage** | The cheap, high-volume decision: *is this worth analysing?* Binary, no tools, no lookups |
| **Analysis** | The expensive, selective decision: *what is it?* Live retrieval, budgets, an evidence package |
| **Classification path** | A dot-delimited, most-specific path in a closed vocabulary. The root must equal the first segment |
| **Citation** | A reference to a stable evidence identifier, marked `supporting` or `contradicting` |
| **Evidence package** | Assembled cited evidence: indicators, patterns, missing information, narrative |
| **Gap** | A recorded thing the run could not see: missing, stale, in-flight, failed, found-nothing, truncated, budget-exhausted |
| **Typed failure** | A run that could not produce a verdict, stored as an assessment row carrying the failure and **no** verdict — never a verdict, never a silent drop |
| **Disclosure** | The fact that querying a source told it the monitored network saw an indicator. Governed by policy, recorded on the assessment |
| **Finding** | The record linking a context, its assessments and its evidence |

### Structure

| Term | Meaning |
| --- | --- |
| **Reference table** | A static feed loaded into the streaming engine with a snapshot version. **Static data is a table; live data is a tool** |
| **Evidence tier (`enrichment` / `analyst`)** | *Where* a piece of evidence came from. The triage rendering shows enrichment-tier evidence only |
| **Source tier (A–D)** | *How strong* a source's evidence is — a different axis, see below |
| **Sink** | The terminal output topic. **Egress, not a store**: nothing may be recoverable only from it |

## Two levels of classification

Both levels share the syntax, the governance and the versioning. They classify
**different subjects**.

| | Evidence level | Context level |
| --- | --- | --- |
| Subject | An **indicator**: what a source says about an address, domain, URL or fingerprint | A **host context**: what this host did in this window |
| Emitted by | Feed mapping views and provider tools | Triage Agent and Analyst Agent |
| Roots | `no_match`, `normal`, `suspicious`, `malicious`, `unknown` | Triage: `normal`, `suspicious`. Analyst: `normal`, `suspicious`, `unknown`, `malicious` |

The evidence level is adopted essentially unchanged from an existing published
indicator taxonomy, so that HELENA's evidence stays comparable with other tools'
rather than re-deriving a vocabulary from the same providers. The context level
is HELENA's own, and is expected to be revised by evaluation.

### Shared syntax rules

- Dot-delimited, most-specific supported path; roots are closed.
- The parent is implied by the child. **Emit the parent rather than guessing a
  child** — a mapping with a threat type it has never seen emits `malicious`, not
  an invented `malicious.something`.
- `confidence` is confidence **in the mapping**, not the probability that the
  indicator is malicious. A definitive negative answer can be `no_match` with
  confidence `1.0`.
- The root must equal the first path segment — validated, not assumed.

## Evidence level

| Root | Meaning |
| --- | --- |
| `no_match` | The source completed its query and returned no record. **A lookup outcome, never a statement of safety** |
| `normal` | Affirmatively known to support harmless activity at that scope and time. Requires positive known-good evidence — a count of zero detections is not enough |
| `suspicious` | A material risk signal, but malicious purpose is not established |
| `malicious` | Known to have performed or supported malicious activity |
| `unknown` | A record exists, but the evidence cannot support another root |

`no_match` matters more here than in most systems: with sparse blocklist
coverage, **most entities have no hit on anything**, so an enriched context is
mostly negative space. Triage reading "no hit" as "clean" is the failure mode the
whole design exists to prevent.

Every source normalizes a successful query into the same six fields: `verdict`,
`classification`, `confidence`, `scope` (`{type, value}`, exactly normalized),
`time` (nullable first-seen / last-seen / valid-until — do not invent missing
precision), and `evidence` (the minimal native fields that justify the mapping).

**A failed query emits a typed error and no taxonomy object.** A timeout, quota
exhaustion or an auth failure never becomes `no_match`, and never becomes
`unknown` either — both of those are valid analysis results returned after a
*successful* query. The error object stays compact and never carries secrets,
authorization headers or full provider responses.

### Source tiers A–D

The tier describes the **source**, not the entry. It is what makes "deterministic
signals escalate independently" a testable rule rather than a judgement call.

| Tier | Evidence | Use |
| --- | --- | --- |
| **A** | Direct behaviour or authoritative curated role — confirmed payload delivery, C2, phishing page, validated malware configuration | May establish `malicious` by itself if scope and freshness are adequate. **Escalates independently of triage** |
| **B** | Explicit provider verdict or high-quality curated listing without full direct evidence | Usually malicious when high confidence. **High-confidence B escalates independently** |
| **C** | Aggregated reputation, predictive risk, community report, one scanner, heuristic anomaly | Normally `suspicious`; two independent sources may raise confidence |
| **D** | Passive DNS, certificate transparency, scan telemetry, co-occurrence | Context only |

Four normalization rules carry into the design:

1. **Scope before severity** — see below.
2. **Do not double-count correlated sources.** Evidence copied through an
   aggregator is not an independent vote; retain the origin and count source
   *diversity*. An aggregator is never counted as many votes.
3. **Preserve the historical verdict when activity changes.** An offline C2
   endpoint remains historically malicious; delisting may reduce confidence, and
   never rewrites the observation as normal. **Removal from a feed is not
   exoneration.**
4. **Compromise is evidence, not exoneration.** A legitimate site currently
   hosting phishing is malicious at that URL and time even though its owner is a
   victim. Keep the operational role as the classification and the compromised
   flag as native evidence.

## Context level

The vocabulary is frozen as a version. A revision is a new version module, never
an edit — replay validates against the version the assessment recorded.

- **Triage** emits `normal` or `suspicious` and nothing else. A context triage
  could not assess is a **typed failure, not a third label**.
- **Analyst** emits `normal`, `suspicious`, `unknown` or `malicious` with a path.

`unknown` means the context was **unassessable** — enrichment entirely failed, the
rendering was truncated past usefulness, or the budget ran out before evidence was
gathered. It is deliberately distinct from `suspicious`, which means **analysis
ran and could not settle it**. Collapsing the two inflates the escalation rate and
corrupts evaluation labels. **A budget-truncated run may return `unknown` but may
never return `normal`**: a run that stopped early has established the absence of
nothing. There are no `unknown.*` sub-paths — a child would claim a specificity
the run does not have, and the reason belongs in the gaps.

The malicious and suspicious families read as host-level statements, not
indicator-level ones: contacted C2, retrieved a payload, reached phishing
infrastructure (**a targeted user, not necessarily a compromised host**),
conducted hostile activity itself, sent spam, exfiltrated, or shows confirmed
compromise without a more specific role. `suspicious` covers low-reputation
contact, a single uncorroborated detection, disagreeing sources, anomalous DNS /
TLS / volume / periodicity, and materially new destinations. `normal` covers
identified legitimate service use, baseline consistency, and the host being
infrastructure behaving as such.

**Several paths the prototype cannot yet justify** — most anomaly and baseline
paths need history and behavioural features the first version does not build.
They are in the vocabulary because that is where evaluation is expected to push,
marked as unused rather than invented later.

## The composition rule — scope before severity

**An evidence-level classification about a contacted indicator does not become the
context verdict.** This is the boundary between the two levels, and the single
most consequential rule in the taxonomy.

- A C2 hit on a contacted address **with actual bidirectional traffic** supports
  `malicious.c2` for the host.
- **The same hit with one failed connection and no bytes returned does not.** That
  is `suspicious` at most, and possibly a host that resolved a name and gave up.
- A phishing domain contacted means the *user was targeted*, not that the host is
  compromised.
- A malicious indicator on **shared infrastructure** — a CDN, a cloud tenant, a
  resolver, a shared subdomain — transfers nothing to the host without
  corroboration.
- `normal` on contacted indicators **never** establishes `normal` for the context
  on its own: coverage is sparse, and absence of adverse evidence is not evidence
  of absence.

This is why per-entity traffic columns exist at all, and why they sit on the same
row as the verdict: a row carrying only a classification cannot tell those cases
apart.

**An honest limitation, recorded rather than hidden.** The scope test works on
**address** entities and not on **domain** ones, because a name carries the
traffic of the flows that *mentioned* it — a DNS lookup — not of the connection to
the address it resolved to. That bites precisely where it matters most, since the
feeds most likely to hit list domains. What the rendering can still say is **which
layers observed the name**: a name in TLS SNI was connected to, where a name seen
only in a DNS query may never have been. Weaker than bytes, and not nothing.

The composition rule should live as **explicit, testable policy** rather than in
the model's judgement: the model classifies, the policy constrains what evidence
can support what verdict. This is where over-alerting will come from if it is
wrong.
