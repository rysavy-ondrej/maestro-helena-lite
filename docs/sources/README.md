# Source records

One record per source this project holds, registers or has decided about.
`concept/05-threat-intelligence.md` is the catalogue and the authority; these are
the per-source records it implies, and they exist because of a specific failure
this project has already had:

> **Every wrong source record in this project came from a documentation page or a
> guessed convention, propagated before anyone fetched the thing it described.**
> `concept/instruction.md` §0: *check the artifact, not the page. A count beats an
> adjective: "narrowest" was a feed with five rows.*

So **every record here states, in its own words, whether it was written from a
fetched artifact.** Two of the five were not, and say so at the top rather than in
a footnote — a record written from a page is not worthless, it is *unverified*,
and the difference has to be visible where the record is read.

`tests/test_governance.py` enforces both halves: every source registered in
`helena.enrichment.SOURCES` has a record here, and every record states its
artifact provenance in a parseable line.

| Source | Tier | Record written from | Loaded? |
| --- | --- | --- | --- |
| [ThreatFox](threatfox.md) | **B** | a fetched artifact — the export, four times, plus eighteen live API requests | yes, both tiers |
| [Netify](netify.md) | **D** | a fetched artifact — 978 611 rows on disk, joined against a real capture | no loader; decided and measured |
| [Public Suffix List](public-suffix-list.md) | N/A — reference data, makes no claim | a fetched artifact — 10 781 rows | yes |
| [SSLBL JA3](sslbl-ja3.md) | **C** | **NOT fetched.** Registered from `concept/05`, which reports the publisher's own statement | no |
| [VirusTotal](virustotal.md) | — deferred | **NOT fetched.** Quota deliberately unspent | no |

Adding a source is a **governed decision, not a configuration convenience**
(`concept/05`) and an escalation (`concept/instruction.md` §3). A new source needs
a record here, a `SourceDescriptor` with its tier and declared emit subset, and —
if it is Tier B — a threshold in `config/policy.toml`, which has no default.
