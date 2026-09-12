# ThreatFox (abuse.ch)

**Written from a fetched artifact.** The bulk export was fetched and counted on
2026-09-03 and 2026-09-06, and the credential profile re-measured on 2026-09-06
and 2026-09-12 (fourth time, unchanged). The hunting API was probed live on
2026-09-10 — eighteen requests, paced at the self-imposed four per minute,
including the three that corrected a sentence in `concept/05`. Nothing here is from a documentation page except where it says so.

| | |
| --- | --- |
| Tier | **B** — `concept/05`'s catalogue: explicit provider verdict or high-quality curated listing without full direct evidence |
| Role | The **first and primary** feed, and the **only** live provider |
| Entity types | `address`, `domain`, `url` |
| Declared emit subset | `{malicious, no_match}`, taxonomy `v1`, emit-subset `v1` |
| Escalates independently | yes, above the per-source threshold — Tier B, `config/policy.toml` |
| Refresh interval | 3 600 s (the descriptor's; the publisher regenerates every few minutes) |
| Aggregator | no |
| Records | [0028](../decisions/0028-the-threatfox-hunting-api.md) (the API), [0041](../decisions/0041-enrichment-status-representation.md)–[0044](../decisions/0044-the-snapshot-scheme.md) |

## Why it, and not something narrower

A correction made from a measurement rather than from reasoning: the narrowest
feed looked like the cheapest proof, but **counted, it carries five rows** — the
join would never have fired against any traffic this project has. ThreatFox is
the better proof on three counts and not merely the larger one: thousands of
address rows and hundreds of domain and URL rows; **both** address and domain
entity rows, so the join is exercised on both types; and a threat-type field that
requires real taxonomy mapping where a single-purpose tracker maps everything to
one path.

The accepted cost is that it **regenerates every few minutes**, which makes
snapshot versioning a harder problem, not an easier one
([0044](../decisions/0044-the-snapshot-scheme.md)).

## Credentials, measured four times

- **The bulk export needs none.** `GET threatfox.abuse.ch/export/json/recent/`
  returns 200 with no credential. Measured 2026-09-03, 2026-09-06 and again
  2026-09-12.
- **The API needs an `Auth-Key` HEADER**, not a credential in a URL path. The API
  returns **401** without the header and 200 with it. An earlier version of this
  project's own notes said the opposite and was wrong.
- **A credential in a URL path is redacted anyway**, before anything is logged,
  stored or recorded as provenance — the rule is about the exposure channel, not
  about this provider. A live key has already leaked into a project conversation
  by exactly that route.
- **Re-measure before building against either.** abuse.ch changes auth on its own
  schedule, and a bulk export that is open today may not be tomorrow. Probe with
  **status codes**, never by printing a key.

## The export's shape, measured 2026-09-06 over 4 985 entries

| Property | Measured | What it forces |
| --- | --- | --- |
| Top level is an object keyed by indicator id, values are **lists** | 4 985 keys, every list length 1 *in this snapshot* | **Flatten.** Reading `[0]` is the named trap, and "length 1 today" is not a schema |
| `ip:port` indicators | 3 139 (63 %), **596 distinct ports** | Split the port and keep it — [0042](../decisions/0042-port-qualification-of-an-address-match.md) |
| `is_compromised` | 821 (16.5 %) | Common, not rare. Native evidence, never the classification — [0043](../decisions/0043-the-compromised-flag.md) |
| `confidence_level` | genuinely spread: 49, 50, 75, 80, 90, 95, 100 | Let it reach the claim; flattening it discards the only per-entry signal there is |
| `reference` absent | 4 006 (80.4 %) | Per-entry evidence often does not exist — which bears on the tier rating |
| `last_seen_utc` absent | 961 (19.3 %); `first_seen_utc` absent **0** | **First-seen plus the snapshot version dates a claim** |
| `tags` | a comma-delimited **string**, absent on 443 (8.9 %) | Split it; it is not an array |
| File-hash indicators | 452 (9.1 %) | **Skipped and counted** — no entity type to attach to |
| `threat_type` | `botnet_cc` 4 084, `payload` 452, `payload_delivery` 447, `cc_skimming` a handful | Every one maps to the **root**; an unseen one is counted |

Confidence distribution over the `data/threatfox/` snapshot, 2026-09-09, which is
where the 0.80 threshold came from: the distribution is **bimodal**, and 0.75
carries two thirds of the address side on its own (2 254 of 3 375). See
`config/policy.toml`, which also says the threshold is **a candidate, not a
decision**.

**The export is a rolling window, not a cumulative archive.** An indicator
present in snapshot N and absent from N+1 has aged out **or** been retracted, and
the export says which by saying nothing — so nothing here diffs snapshots
([0044](../decisions/0044-the-snapshot-scheme.md) §5).

**Take the structured format.** The RPZ and hosts-file variants drop threat type,
confidence and the compromised flag — exactly the distinctions the composition
rule needs.

## The live surface

`POST threatfox-api.abuse.ch/api/v1/`, `search_ioc`, `Auth-Key` header.
[0028](../decisions/0028-the-threatfox-hunting-api.md) carries the whole surface,
the typed-error mapping and the probes. Three facts that are defects if assumed:

- **HTTP 200 answers every application error.** The status code says nothing;
  `query_status` does. `data` is a list on `ok` and a **string** on `no_result`.
- **`exact_match` cannot be used for an address** — ThreatFox has no bare-`ip`
  indicator type, only `ip:port` — so an address lookup uses the wildcard.
- **The wildcard is not a substring search and it crosses entity types.** It
  returned a `url` record for an address query and 1 386 records for
  `workers.dev`. A wildcard result is a set of **candidates**, and every one must
  be checked against the asked indicator before it is a claim.

**A correction kept rather than overwritten.** `concept/05` said no per-indicator
lookup endpoint appeared in the public documentation. Checked 2026-09-10: it is
**false**, `search_ioc` is documented and the live service answers it. Whether
the sentence was wrong when written or the documentation changed is not knowable
from here and is not guessed. The original sentence and its correction both stand
in `concept/05` — [0046](../decisions/0046-negative-results-are-kept.md).

## Two hazards this source carries

- **Concentration risk.** One organisation supplies most of the prototype's
  threat intelligence. [`../hazards.md`](../hazards.md) §4.
- **The retrieval confound.** The same organisation feeds both tiers. Measured
  2026-09-10: for three indicators, **every field the two surfaces share was
  identical**, so a ThreatFox analyst claim corroborating a ThreatFox enrichment
  claim is one source agreeing with itself. `source_diversity` counts by
  `source_id` and both tiers carry `threatfox`. [`../hazards.md`](../hazards.md) §3.

## Terms

Fair use binds both tiers; the datasets stay out of the repository
(`data/threatfox/` is gitignored, and only a small extract is committed as a test
fixture). **There is no false-positive feed to enter** — measured 2026-09-10, and
recorded in [`../deferred.md`](../deferred.md) §1 rather than designed around.
