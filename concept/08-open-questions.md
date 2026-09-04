# 08 — Open questions

What is genuinely unsettled. The point is not the count but the split: **which
unknowns block the first implementation, and which ride with a deferred capability
and block nothing today.**

## The one that blocks everything, and is outside the team's control

> **A labelled, multi-host, time-correct evaluation corpus containing genuine
> malicious and multi-stage activity does not exist.**

It gates **every measurement in the project**: the comparative research questions
entirely, the evaluation harness, model selection, threshold calibration, budget
values, window-coherence measurement, and the base-rate check that keeps a
sparse-coverage classifier from looking excellent while answering `normal` to
everything.

**It does not block building the pipeline.** What it blocks is the claim that the
pipeline is *right*.

One constraint it places on design: the live provider's daily quota must be sized
against the corpus **before the corpus is chosen**, or the comparison's arms stop
being contemporaneous.

## Blocking — must be answered inside the stage that needs them

**Enrichment.** How the enriched context represents enrichment that is missing,
stale, in flight or failed, so triage cannot read absence of evidence as evidence
of absence — this is the stage's central acceptance property. The loader's schedule
per feed and how fetch failures, format changes and empty responses are handled
without silently emptying a table. How the port qualifies an address match. How a
compromised flag is carried, given the taxonomy root cannot come from threat type
alone. The snapshot and versioning scheme, and how replay selects the snapshot
current at event time.

**Rendering and triage.** Which TLS parameters are selected, and by what criterion.
What bounds the rendering for a busy host, and how truncation is made visible. How
per-value citations and freshness are carried without bloating the rendering past
the budget it exists to respect. The per-source confidence thresholds that decide
when a Tier B match escalates independently. **Where the composition rule lives —
policy code, prompt, or both — and how it is tested; this is where over-alerting
will come from if it is wrong.** The numeric budget values and retry count. The
table design for evaluated contexts and their citation joins. And the first
instance of the truncation problem: the list of contributing events is unbounded
and nothing truncates it.

**The analyst and the provider tool.** **Confirm the live provider's query surface
against the authenticated documentation before building the tool** — no
per-indicator lookup endpoint appears in the public documentation, and that is the
tier's core operation. Which sources are approved for analyst-time querying and
what may be sent to each. How retrieved unstructured text is isolated from
instruction channels, and how that isolation is *tested* rather than asserted. What
happens when a source is down, rate-limited or slow mid-analysis. Cache retention
per source and endpoint; **whether negative results are cached, since most lookups
miss and this decides whether caching helps at all**; cache-key normalization,
because inconsistent keys quietly halve the hit rate; and whether an expired entry
is offered as explicitly stale when the provider is unreachable. Whether the MCP
servers are self-hosted wrappers per provider, and what their failure behaviour
looks like *as the agent sees it*. What "the analyst is unsure" means and **who
decides it**. Setting the wall-clock and live-query budgets against each other. And
how an upstream false-positive list enters — as evidence about evidence, not by
quietly filtering matches.

**The output.** The field-level shape of the emitted message, and making emission
countable from the engine side.

**Cross-cutting and urgent.** A record was silently lost once at a catch-up
boundary — **replayability is a goal rather than a claim while that stands**.
Durability and backup for the single store, now that findings and evidence exist
only there, which is a correctness concern rather than an ops detail. And where
quarantined records live, given they currently land outside the store the project
says holds everything.

## Not blocking — assumptions in force

| Assumption | Revisit when |
| --- | --- |
| The host key is the source address, so **a host seen only as a destination gets no context**; DHCP, NAT, roaming and multi-sensor resolution get no help from the input | Multiple sensors, or a case needing a destination-side host |
| Tenant and sensor come from deployment configuration, which does not scale to multiple sensors sharing one normalizer | The same trigger |
| A capture is identified by the hash of its retained file — provisional for live ingestion, where an open file has no final digest until it closes | Live ingestion |
| 5-minute tumbling windows, a flow assigned by its start. The cost is measured and accepted | Window coherence can be measured — which needs the corpus |
| The behavioural feature set is exactly what the input supports. **No TCP-state or connection-failure feature exists, and none may be specified** | A richer input format |
| The view-layering rule is enforced by convention plus boundary tests over the SQL | The view set grows |
| Topic layout, and what happens when the broker dies with data in flight, are unspecified | Multi-tenant or multi-format ingestion |
| The retained capture is the durable record; how a snapshot is versioned and how a finding addresses an exact source record remain open | The first real replay |
| A context is assessed against whichever feed snapshot was current, and a later snapshot changes what an identical context would say — a versioning and citation problem, not a race | With the snapshot scheme |
| The model service's data-handling terms, how model identity is pinned, and its rate limits are unconfirmed | **Check the terms before sending anything but a purpose-built replay dataset** |
| Provider credential names are inconsistent | **Settle by asking.** Both names that were guessed had propagated across six documents before being corrected |
| A local environment file is the secret source — a development convenience, not a deployment answer | First non-local deployment |
| The authorized source set is fixed; some feeds need an agreement or a licence | A second feed |
| Model assignments are candidates; a plain tool loop is the analyst baseline | Settled by measurement, which needs the corpus |
| **Settled 2026-09-04** — context identity is **stable across revisions** ([07 — Principles](07-principles.md)), so a revision edits the counters in place and the id does not change. What that means for a finding *already issued*, which may cite an id whose numbers have since changed, stays open | Findings outlive a retention boundary |
| The retention horizon is unset; the prototype runs on bounded fixtures. Now empirical — a candidate can be observed in the rejection counter before it is committed to | Retention is built |
| Untested, **and not to be inferred**: whether a late record inside the boundary still revises under a temporal filter | Retention is built |
| Unmeasured: how many entity rows a busy host produces. The fixture is one host for two minutes | With the rendering bounds |

## Known hazards, recorded rather than resolved

Not questions — accepted risks the concept must not be read as denying.

| Hazard | Statement |
| --- | --- |
| **The measurement gap** | A pipeline built without an evaluation harness can be demonstrably *running* and undemonstrably *correct* |
| **Silent record loss** | One record vanished at a catch-up boundary, and that class of silence has already been caught once on the same broker in the other direction |
| **The retrieval confound** | One organisation feeds both tiers, so analyst retrieval mostly re-confirms what triage saw. **Know what the experiment is measuring before it runs, not after it produces a number** |
| **Concentration risk** | One provider supplies most of the prototype's threat intelligence; if its terms, availability or coverage change, the evidence base changes with it |
| **The scope-test gap on domains** | The composition rule works on address entities and not on domain ones — and the feeds most likely to hit list domains |
| **The base rate** | Coverage is sparse; most contexts have no hit on anything. **A classifier that always answers `normal` will score well on accuracy and be worthless** |
| **The interface that hardens on first use** | The output payload becomes an interface the moment anything consumes it, and it duplicates state by construction — the same assessment exists as rows and as a message, so the two can disagree if the view is edited carelessly |
| **Framework defaults** | A model framework's conveniences must be checked against the single-store, agents-propose and ephemeral-state rules rather than enabled because they are one flag away |
| **Output volume** | Emitting `normal` verdicts means the topic carries the full context volume. Intended at prototype scale; it would need revisiting at real rates |
| **Deferred records outnumber code** | Every deferred component must stay labelled deferred, or the maturity labels start lying |
