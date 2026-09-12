# VirusTotal (multi-engine reputation) — deferred

**NOT written from a fetched artifact, deliberately.** No request has been sent
to this provider from this repository, and the quota is **unspent on purpose**.
The properties below are from `concept/05-threat-intelligence.md` and from the
provider's published free-tier terms, so this record is *unverified* and says so
— and the first thing to verify, if it is ever built, is the quota, because the
quota is a design constraint rather than an operational detail.

| | |
| --- | --- |
| Tier | not rated. It is an **aggregator**, so it is never counted as many independent votes |
| Role | **A last step**, not a routine second opinion — consulted when the analyst would otherwise be unable to settle a context |
| Entity types | `address` and `domain`. **Two lookups only** |
| Loaded? | no. No tool, no adapter, no request |
| Credential | `VIRUSTOTAL_AUTH_KEY` — **required configuration**, deliberately unused ([0004](../decisions/0004-configuration-variables.md)) |
| Register entry | [`../deferred.md`](../deferred.md) §13, *the second live provider* |
| Record | [0045](../decisions/0045-who-decides-the-analyst-is-unsure.md) |

## Hard limits on what it may ever be asked

`concept/05`, and these are scope rather than preferences:

- **Two lookups only** — address and domain.
- **No file, hash, relationship or graph queries.**
- **No sample submission ever.** Malware download and detonation are out of scope
  for the system entirely (`concept/01`), not deferred.

## The quota is the design constraint

A few hundred lookups per day is a **shared daily budget across every host the
pipeline assesses**, so routine use is use exhausted before noon. It is a ceiling
on a whole **evaluation** and not on one run, and `concept/08` places one
constraint on design because of it: **the daily quota must be sized against the
evaluation corpus before the corpus is chosen**, or the comparison's arms stop
being contemporaneous. `scripts/corpus_sizing.py` computes that ceiling from
`config/policy.toml`, and `docs/evaluation-corpus.md` §6 is where it lands.

`prds/CONTEXT.md` §3 records the documented free-tier numbers as **4/min,
500/day, shared across everything**. Not measured — measuring it would spend it.
`config/policy.toml`'s `[rate_limits]` has one entry, `threatfox = 4`, and gets a
second one on the day this provider does.

## Its answer is contradictory by nature

A handful of engines flagging an address while most do not is **normal**, and
**both sides are evidence**. An adapter must not collapse it to a single verdict
before the agent sees it — which is the same rule
[0009](../decisions/0009-netify-application-identification.md) arrived at from
the other direction: multiple claims on one entity are evidence to weigh, never a
conflict to resolve before it is seen. And because it is an aggregator, its
agreement with a feed is not corroboration by a second source.

## Who decides it is called

**Deterministic code, never the model.** That is
[0045](../decisions/0045-who-decides-the-analyst-is-unsure.md), and it is the
answer `concept/05` says must be settled *before the tool exists, because it
decides where the tool sits rather than how it is written*. A model that could
ask for this tool would control a scarce shared resource, and one verbose run
could spend the day's quota for every other host.

## Re-entry test

Both halves, from [`../deferred.md`](../deferred.md) §13:

1. a **measured need** — runs that could not settle with the tables and the
   primary provider and that a second opinion would have settled;
2. an **engine-side daily ledger**, because `RunBudget` is per-run and ephemeral
   by decision and a daily shared limit is a fact about all runs. A file or a
   module-level counter is the second store `concept/instruction.md` §2 forbids.

Neither exists. Until both do, the honest position is the current one: the
credential is configured, the provider is `deferred`, and **the quota is not
spent.**
