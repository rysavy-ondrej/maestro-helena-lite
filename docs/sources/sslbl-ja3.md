# SSLBL JA3 (abuse.ch)

**NOT written from a fetched artifact, and that is the most important line in
this record.** Nothing in this project has fetched the JA3 blacklist. Every
number and every property below is from `concept/05-threat-intelligence.md`,
which reports **the publisher's own statement** about its list — so this record
is *unverified*, in exactly the way `concept/instruction.md` §0 warns about:

> Every wrong source record in this project came from a documentation page or a
> guessed convention, propagated before anyone fetched the thing it described.

It is registered in `helena.enrichment.SOURCES` anyway, and §"Why it is
registered without an artifact" says why that is defensible.

| | |
| --- | --- |
| Tier | **C** — aggregated reputation and heuristics; normally `suspicious` |
| Entity types | `fingerprint` — **client-side JA3 only** |
| Declared emit subset | `{suspicious, no_match}`. **`malicious` is deliberately not in it** |
| Escalates independently | **no.** Tier C never does; two independent sources may raise confidence rather than one settling it |
| Refresh interval | **none**, and that is a decision — see below |
| Loaded? | **no.** No loader, no snapshot, no claim has ever been made |

## The caveat, which is the source record

`concept/05`: **the JA3 caveat stands and does not improve.**

> Under a hundred fingerprints, first seen years ago, **static since 2021**,
> carrying **the publisher's own statement that they are untested against
> known-good traffic and may cause significant false positives**. A historical
> artifact rather than a feed: it cannot get better by being refreshed, because
> it is not being refreshed. And holding a token does not make it Tier A.

Two consequences are already in the code rather than in a note:

- **`refresh_interval_seconds` is `None`.** A refresh interval would make it
  permanently `stale`, which would say something false: **it is not late, it is
  finished.** What is wrong with it is the caveat, not its age. This is also the
  one registered source that cannot go stale, which
  [0041](../decisions/0041-enrichment-status-representation.md) notes at the end.
- **`malicious` is not in the declared emit subset.** A list whose own publisher
  says it is untested against known-good traffic cannot establish that a
  fingerprint performed malicious activity. A hit is a material risk signal,
  which is what `suspicious` means.

## Why it is registered without an artifact

Because the registration is what carries the caveat, the tier and the *narrowed*
emit subset — and because it is the only non-ThreatFox entry in the registry, it
is what keeps `source_diversity`, the tier rules and the emit-subset check from
being written against a single source. `tests/test_sources.py` uses it for
exactly that: only A and B escalate independently, the caveat is on the
descriptor, and a claim outside a declared subset is an `UndeclaredClaim`.

**Nothing depends on its data, because it has none.** The rendering is explicit
about the consequence: `sslbl-ja3 status=missing` beside a domain would claim the
list was asked about something it does not cover, so the rendering does not print
it there ([0018](../decisions/0018-the-triage-rendering.md)).

## The coverage gap beside it, recorded rather than glossed

**JA4 has no public blacklist at all.** The flow record carries JA4 and JA4S and
nothing enriches them. Server-side fingerprints (`ja3s`, `ja4s`) are not
extracted as entities either: they describe the server, and what this project
says about a server is the address record.

## What would have to happen before it is used

1. **Fetch it and count it.** If it is under a hundred fingerprints and static
   since 2021, that is then a measurement rather than a quotation — and if it is
   not, this record was wrong and gets corrected in place beside the original
   ([0046](../decisions/0046-negative-results-are-kept.md)).
2. **Settle what a `no_match` against it may be taken to mean.** `concept/05`
   calls this the sharper half of the open question, and it is the half that
   matters: a `no_match` from a list of under a hundred entries is close to no
   information at all, and `concept/02` already forbids reading `no_match` as a
   statement of safety.
3. **Decide whether it earns its place.** That is open in `concept/05` and is not
   settled here.
