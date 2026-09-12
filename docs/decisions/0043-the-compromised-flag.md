# 0043 — The compromised flag is native evidence, and the taxonomy root is never read off a threat type

Status: accepted — 2026-09-12 (task 55, D9 Governance). **Recorded after the
fact.** The decision was taken in task 22 and lives in
`helena.providers.claim_from_entry`, `helena.enrichment`'s threat-type map,
`sql/migrations/0014` and `helena.policy.v1`. This record is where it becomes
findable.

## The question this closes

`concept/08-open-questions.md`, blocking, enrichment: **how a compromised flag is
carried, given the taxonomy root cannot come from threat type alone.**

`concept/05` is where the "cannot" comes from, and it is a measurement rather
than a worry:

> A compromised flag separates victim from owner, and is **common, not rare** —
> a compromised legitimate host serving malware is a different claim about the
> contacted party than attacker-owned infrastructure, so **the taxonomy root
> cannot be assigned from the threat type alone.**

Measured 2026-09-06 over 4 985 entries: `is_compromised` is set on **821
(16.5 %)**.

## The answer

**1. The flag is carried as native evidence on the claim, and never as the
classification.** `helena.providers` puts `is_compromised` into the claim's
native-evidence object beside `threat_type`, `malware`, `reporter`, `reference`,
`tags`, `indicator_id` and `port`; `sql/migrations/0014_feed_mapping_views.sql`
does the same in the mapping view, and the reference table carries
`is_compromised BOOLEAN NOT NULL` as supplied. It reaches the agent and it
reaches the emitted message. It decides nothing on its own.

**2. The horn of the dilemma the flag creates is removed by mapping every threat
type to the taxonomy *root*.** `concept/05`: *"the mapping needs defined
behaviour for an unseen value: emit the parent, never guess a child."* The
ThreatFox threat-type map does that for **every** value, seen or unseen, so the
question "does this threat type mean the contacted party is attacker-owned or a
victim?" is never answered by the mapping — because the mapping does not produce
a child path at all. The map's value is that it *names what has been seen*, so an
unseen type is a counted event rather than a silent one.

So the flag does not need to modify a classification, and nothing has to decide
between `malicious.c2` and `malicious.compromised` from a feed field. That is the
whole of why this is settleable at the evidence tier.

**3. The victim/owner distinction is made at the composition rule, from the
host's side.** `helena.policy.v1`'s `CONTACT_IS_NOT_COMPROMISE` is the sentence
`concept/02` writes: `malicious.phishing` is a *contact* path and survives,
because contacting phishing infrastructure makes the user targeted and not the
host compromised; `malicious.compromised` does not survive, because **no
enrichment-tier claim is about the host at all**. The contacted party's
compromised flag is evidence about the contacted party, in the rendering, for the
agent to weigh — exactly the multiplicity
[0009](0009-netify-application-identification.md) settled.

**4. The format choice follows from this.** `concept/05`: take the **structured**
export, not the RPZ or hosts-file variants, which *"drop exactly the distinctions
the composition rule needs"*. Neither carries a port, a confidence, a threat type
or the compromised flag. A feed that can only say "bad" costs the ability to
weigh scope against severity. `helena.enrichment` records that beside the export
URL, which is configuration rather than a constant, because **adding a source is
a governed decision, not a configuration convenience.**

## What this does not settle

- **Whether `malicious.compromised` can ever be reached.** Nothing in the
  prototype produces it: it would need a claim about the monitored host itself,
  and no registered source makes one. The path exists in `helena.taxonomy.v1`
  and is unreachable by construction, which is recorded here rather than in a
  gap somewhere.
- **A second source's version of the same flag.** Emerging Threats' compromised
  IP list is in `concept/05`'s catalogue as Tier C, aggregated, with no per-entry
  evidence — [`docs/deferred.md`](../deferred.md), *further feeds*. Two sources
  disagreeing about whether an address is compromised is two rows, not a
  conflict to resolve.
