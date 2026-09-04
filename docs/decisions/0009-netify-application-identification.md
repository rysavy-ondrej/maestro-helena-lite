# 0009 — Netify is admitted as an enrichment source, and what that does not mean

**Status: accepted.** Operator decision, 2026-09-03, taken outside a task session
and recorded here because the tension it settles had been carried forward untouched
by every session from task 0 to task 5.
**Authority:** `concept/05-threat-intelligence.md` (the source catalogue, the seven
rules every source adapter must obey, the feed-loader rules),
`concept/02-concepts-and-taxonomy.md` (entity, enrichment evidence, source tiers
A–D, scope before severity), `concept/instruction.md` §3 (adding an enrichment
source is an escalation — this record *is* that escalation, resolved).

## The tension this closes

`concept/05-threat-intelligence.md` said application-identification data is
**commercial-only** and listed it among sources that are "simply not available",
while `data/netify/` has been in the tree the whole time holding 965,967 address
rows, 11,144 domain rows and 1,500 application definitions. `prds/CONTEXT.md` §3
named the contradiction and correctly refused to resolve it inside a session.

## The decision, in four parts

1. **Netify may be used for this prototype.** It is a real enrichment source, not
   only a shape fixture.
2. **Netify supplies enrichment *information*, never a decision about the entity.**
   It produces evidence rows; it does not classify, does not contribute a verdict,
   and does not escalate. This is the part that constrains everything below.
3. **Domain matching is on the name as observed** — as extracted from a DNS query
   or answer, or from TLS SNI — so the match is preserved.
4. **The data schema is `host context 1 — n entity 1 — n enrichment`.** Multiple
   enrichment records on one entity are expected and **desired**: they give the
   triage agent more to decide on, not a conflict to resolve.

## Why "information, not a decision" is a structural constraint

Every other source in the catalogue answers *is this bad?*. Netify answers *what is
this?*. Those are different questions, and collapsing them would let an
identification become a verdict by accident.

So Netify's **declared emit subset** (rule 1) is disjoint from the threat taxonomy.
It emits an application identity and a category — `app.microsoft-authentication`,
`Business` — and it emits **no taxonomy classification at all**, not even
`no_match`, because `no_match` is an answer to a question Netify was never asked.
An address Netify does not know is `missing` from Netify, and that stays distinct
from `no_match` against ThreatFox, exactly as `concept/instruction.md` §2 requires.

It is therefore **Tier D — context only** (`concept/02` §"Source tiers A–D"). Tier D
may never establish a classification by itself and never escalates independently.
A Netify hit saying `app.windows-update` is context an analyst may weigh; it is not
an affirmative `normal`, and code may not treat it as one. The affirmative-benign
question stays open and is **not** settled by this record.

## Domain matching is on the observed name, not the registrable domain

This is the operator's third point and it is load-bearing, because the obvious
implementation is wrong.

Netify's domain keys are **not all registrable domains**. The file contains literal
keys such as `windowsupdate.com.edgesuite.net` and `live.com.akadns.net`. Task 15
introduces registrable-domain normalization via the Public Suffix List; if that
normalization ran **before** the Netify join, `windowsupdate.com.edgesuite.net`
would collapse to `edgesuite.net` and the match would be lost or silently degraded
to the CDN rather than the service.

**The join takes the domain as observed** — the name lifted from a DNS query, a DNS
answer, or TLS SNI — and walks its labels from most to least specific, stopping at
the first Netify key that matches. Registrable-domain normalization remains what it
is for, scope correctness, and does not sit in front of this join.

The measured consequence of getting the order right is total: **every one of the 42
real domains in `data/ingest/flow-sample.jsonl` matches** (3 exactly, 39 by suffix).

## What was measured

Joined against `data/ingest/flow-sample.jsonl` (62 records, one host, 130.8 s) on
2026-09-03. A count beats an adjective.

| | Result |
| --- | --- |
| Domains present, excluding reverse-DNS lookups | 42 |
| Domains matched | **42/42** — 3 exact, 39 by suffix |
| External addresses present | 31 (plus the host itself and one multicast address) |
| Addresses matched | **17/31** |

The categories returned are mixed, and the mixture is the point:
`app.skype`/VoIP, `app.office-365`/Business, `app.windows-update`/OS Updates,
`app.digicert`/Cybersecurity, `app.microsoft-authentication`/Business,
`app.bing`/Portal, `app.github`/Technology — but also `app.azure`/Hosting and
`app.azure-front-door`/CDN for every `*.trafficmanager.net` name.

**So `concept/05`'s claim that this data "identifies *hosting*, not applications" is
half right, and the half that is wrong is the useful half.** It identifies hosting
for cloud front-door names and genuine application identity for others. The note has
been corrected to say what was measured. Its architectural conclusion — that
`service` is not an entity type — **is unchanged and is reinforced** by this record:
Netify attaches to the `address` and `domain` entities that already exist.

## The data schema, and why multiplicity is the point

```text
HostContext ──1:n──> Entity ──1:n──> EnrichmentEvidence
  host, window        address          source, snapshot, tier, status,
                      domain           classification | application identity
                      fingerprint
```

**A host context has many entities; an entity has many enrichment records.** Two
claims about one address are two enrichment rows on that entity whether they came
from two sources or from two rows of one source — the shape is uniform, and nothing
downstream needs to tell those cases apart structurally.

This is deliberate rather than tolerated. The triage rendering is better off seeing
more of what is known about an entity than less, so multiple values are **evidence
to weigh, not a conflict to resolve before the agent sees it** — which is rule 6
arrived at from the other direction.

It also settles a question that would otherwise have landed in D3 task 20: the
evidence schema carries **N rows per entity**, not one row per (entity, source)
holding a collapsed set.

`concept/02-concepts-and-taxonomy.md` defined enrichment evidence as "one claim per
(entity, source)". As a cardinality constraint that is too narrow — Netify alone
puts up to 75 claims on a single address — so the line now describes the *unit* of a
claim rather than capping their number. `concept/03`'s "the join is **per entity**"
was already right and is unchanged.

## What the multiplicity looks like, and the one thing the loader must not do

**An address can carry many applications; a domain carries exactly one.** 83,575 of
the 841,314 distinct addresses appear on more than one row, up to **75 applications
for a single address**. `1.62.64.112` is both `app.qq`/Messaging and
`app.tencent-cloud-cdn`/CDN. `domains.csv` has no duplicate keys at all.

Expected, given the schema — but it still constrains the loader: **it must not
reduce an address to one application.** A dict keyed by address silently discards
124,653 rows, and the first draft of the measurement above did exactly that and had
to be redone.

The count is itself **information, not noise**: an address mapping to 75
applications identifies nothing, and one mapping to a single application identifies
something. That is a signal the rendering can use, and one more reason to preserve
the rows rather than truncate them.

## The hazard that remains: one service, two answers, depending on the name

`config.edge.skype.com` matches `app.skype`/VoIP, while
`config.edge.skype.com.trafficmanager.net` matches `app.azure`/Hosting. Both names
are observed in the same capture, for the same activity. This is the `*.workers.dev`
shared-infrastructure problem in a second costume, and it means a Netify claim must
record **which observed name produced it** — rule 7, retain the origin — so that a
hosting label and a service label are distinguishable rather than averaged.

## What the adapter still has to do

Netify is a **static local snapshot with no version of its own** and no upstream
fetch: the files were placed in the tree, not downloaded by this project. So the
loader writes a snapshot version at load time like any other feed, and a load
failure or an empty parse **leaves the previous snapshot in place and records the
failure** — `stale` or `missing`, never a silent empty opinion. `data/netify/` is
already in `.gitignore`, so the dataset stays out of the repository as
`concept/05` requires; the small extract committed as a test fixture must stay
small.

## What this record does NOT decide

- **The taxonomy is untouched.** Netify emits application identity and category,
  which are not taxonomy paths. If a later increment wants Netify to map into a
  classification vocabulary, that is a **new taxonomy version module**, never an
  edit (`docs/decisions/0008`), and a separate escalation.
- **Nothing about affirmative `normal`.** Tier D is context only. Whether an
  application identification can ever support a benign verdict is exactly the kind
  of claim that needs the evaluation corpus, which does not exist.
- **No ordering against ThreatFox.** ThreatFox remains the first and primary feed;
  the smallest coherent slice is still one feed working end to end. This record
  makes Netify buildable, not next.
- **Provenance and licence terms of this particular sample are not established
  here.** The decision is that the prototype may use it locally. Redistribution and
  any derived dataset remain out of scope, and the files remain gitignored.
