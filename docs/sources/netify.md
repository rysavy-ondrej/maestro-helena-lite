# Netify (application identification)

**Written from a fetched artifact — with one qualification, stated first.** The
data was **not fetched by this project**: the files were placed in the tree, not
downloaded. But they are the artifact, they were counted, and they were joined
against a real capture before anything was decided from them. **978 611 rows**
sit in `data/netify/` and every number below is from them, on 2026-09-03. No
sentence here comes from a documentation page.

| | |
| --- | --- |
| Tier | **D — context only** |
| Role | Application identity and category. **Never a threat classification, never a decision about an entity** |
| Entity types | `address`, `domain` (matched on the name **as observed**) |
| Declared emit subset | application identity and category. **No taxonomy classification at all — not even `no_match`** |
| Escalates independently | **no.** Tier D never does, and may never establish a classification by itself |
| Refresh interval | none. A **static local snapshot with no version of its own** |
| Loaded? | No loader exists. The decision and the measurement do |
| Record | [0009](../decisions/0009-netify-application-identification.md) — the operator decision, taken outside a task session |

## What is on disk

| File | Rows | Shape |
| --- | --- | --- |
| `data/netify/ips.csv` | **965 967** | `ip,app_id,tag,category` |
| `data/netify/domains.csv` | **11 144** | `domain,app_id,tag,category` |
| `data/netify/applications.csv` | **1 500** | `;`-delimited: `id;tag;short_name;full_name;description;url;category` |

Gitignored, and they stay out of the repository. Only a small extract is
committed as a test fixture.

## Why "information, not a decision" is structural

Every other source in the catalogue answers *is this bad?*. Netify answers *what
is this?*. Those are different questions, and collapsing them would let an
identification become a verdict by accident.

So its declared emit subset is **disjoint from the threat taxonomy**. An address
Netify does not know is `missing` **from Netify**, and that stays distinct from
`no_match` against ThreatFox — because `no_match` is an answer to a question
Netify was never asked. A hit saying `app.windows-update` is context an analyst
may weigh; **it is not an affirmative `normal`, and code may not treat it as
one.**

## The measurement, joined against `data/ingest/flow-sample.jsonl`

62 records, one host, 130.8 s, on 2026-09-03. A count beats an adjective.

| | Result |
| --- | --- |
| Domains present, excluding reverse-DNS lookups | 42 |
| Domains matched | **42/42** — 3 exact, 39 by suffix |
| External addresses present | 31 (plus the host itself and one multicast address) |
| Addresses matched | **17/31** |

## Matching is on the observed name, and the obvious implementation is wrong

Netify's domain keys are **not all registrable domains** — the file holds literal
keys like `windowsupdate.com.edgesuite.net` and `live.com.akadns.net`. If
registrable-domain normalization ran **before** this join,
`windowsupdate.com.edgesuite.net` would collapse to `edgesuite.net` and the match
would be lost or silently degraded to the CDN rather than the service.

**The join takes the name as observed** — from a DNS query, a DNS answer, or TLS
SNI — and walks its labels from most to least specific, stopping at the first
key that matches. The Public Suffix List stays what it is for: scope correctness,
not this join.

## Multiplicity, and the one thing a loader must not do

**An address can carry many applications; a domain carries exactly one.** 83 575
of 841 314 distinct addresses appear on more than one row, up to **75
applications for a single address**. `domains.csv` has no duplicate keys at all.

**A loader must not reduce an address to one application.** A dict keyed by
address silently discards **124 653 rows**, and the first draft of the
measurement above did exactly that and had to be redone. The count is itself
information: an address mapping to 75 applications identifies nothing, and one
mapping to a single application identifies something.

## Two hazards it carries

1. **One service, two answers, depending on the name.**
   `config.edge.skype.com` matches `app.skype`/VoIP;
   `config.edge.skype.com.trafficmanager.net` matches `app.azure`/Hosting. Both
   names are observed in the same capture for the same activity. So a claim must
   record **which observed name produced it**, or a hosting label and a service
   label become indistinguishable.
2. **It identifies hosting as often as applications** — every
   `*.trafficmanager.net` name resolves to `app.azure`/Hosting. `concept/05`'s
   original claim that this data identifies *hosting, not applications* is **half
   right, and the half that is wrong is the useful half**; the note was corrected
   to say what was measured. Its architectural conclusion is unchanged and
   reinforced: `service` is not an entity type, and identification attaches to the
   `address` and `domain` entities that already exist.

## What is still open

- **No loader, and it is not `SOURCES`-registered.** The decision makes Netify
  buildable, not next: the smallest coherent slice is still one feed working end
  to end.
- **The snapshot has no upstream version.** A loader would write a snapshot
  version at load time like any other feed, and a failed or empty parse would
  leave the previous snapshot in place and record the failure — `stale` or
  `missing`, never a silent empty opinion.
- **Provenance and licence terms of this particular sample are not established.**
  The decision is that the prototype may use it **locally**. Redistribution and
  any derived dataset are out of scope.
- **Whether an application identification can ever support an affirmative
  `normal`** is exactly the kind of claim that needs the corpus. Open.
