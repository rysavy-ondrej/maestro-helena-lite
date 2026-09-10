# ThreatFox fixture

`export.json` — 11 entries under 10 indicator ids, taken byte for byte from the
real bulk export fetched on **2026-09-06** (`GET
threatfox.abuse.ch/export/json/recent/`, 200 with no credential, 4 985 entries).

Committed on the terms `.gitignore` already sets for this feed: *"Intelligence
snapshots stay out of the repository — fair-use terms bind them. A small extract
committed as a test fixture is fine; the full files are not."* Eleven entries of
4 985 is that extract. The full snapshot is not here and must not be.

## What each entry is here for

Picked to exercise every branch of the mapping rather than to be representative —
the ratios in the real export are recorded in `helena.enrichment`'s ThreatFox
section, measured over all 4 985 entries, and nothing should be inferred from the
ratios *here*.

| Property | Why it is in the fixture |
| --- | --- |
| one of every `ioc_type` — `ip:port`, `domain`, `url`, `sha256_hash`, `md5_hash`, `sha1_hash` | every branch of `THREATFOX_ENTITY_TYPES`, and the three that have no HELENA entity and are skipped and counted |
| an `is_compromised` entry | the flag is **native evidence, never the classification**: a legitimate site serving malware is malicious at that URL and its owner is a victim |
| a low-confidence entry (50) beside high ones | confidence is spread and must reach the claim rather than being flattened |
| an entry with no `last_seen_utc` | absent stays absent; **first-seen plus the snapshot version dates a claim** |
| an entry with no `tags` | `tags` is a delimited string, not an array, and an absent one is no tags rather than `[""]` |
| an entry with a `reference` | present on only 19.6 % of the real export, so the populated case needs pinning too |
| a `cc_skimming` entry | the rarest threat type in the snapshot (2 of 4 985) |

## The one entry that is not verbatim

**Indicator id `9999999` is constructed**, and it is the only thing here that
did not arrive that way: it carries **two** real entries under one id, because
the format is an object keyed by indicator id whose values are **lists** and
every list in the real snapshot had length one.

Length one is a property of one snapshot rather than of the format. Reading `[0]`
is in `concept/instruction.md` §6's list of traps that have already cost this
project something, and a fixture where every list has one element cannot tell a
loader that flattens from a loader that indexes. The two entries under it are
byte-for-byte copies of two real ones; only the grouping is made up, and it is
made up so that a test can fail.

---

# The hunting-API responses

`search_ioc_*.json` — five answers from `POST threatfox-api.abuse.ch/api/v1/`,
taken **byte for byte** from the live service on **2026-09-10** with the
`Auth-Key` header. They are the artifact `helena.providers` was written against,
and `docs/decisions/0028-the-threatfox-hunting-api.md` is the source record they
were captured for.

They are a different shape from `export.json` above, and the difference is the
point: the API spells the same records differently — `ioc` for `ioc_value`,
`first_seen`/`last_seen` with a `" UTC"` suffix for the `_utc` pair, `tags` as an
**array** rather than a comma-separated string, the indicator id as a field
rather than as the object key, and `sightings` and `malware_samples` that the
export does not carry at all. A fixture invented from the export's shape would
have hidden every one of those.

| File | What it is, and what it is here for |
| --- | --- |
| `search_ioc_domain_hit.json` | one `domain` record, `exact_match: true`. The straightforward hit, with a seven-element `tags` array and `is_compromised: true` |
| `search_ioc_address_hit.json` | the wildcard answer for a bare address. The record is `ip:port`, which is **the only address shape ThreatFox has** — so the claim is scoped `address:port` and the port is not discarded |
| `search_ioc_url_hit.json` | one `url` record, `exact_match: true`, and the only fixture with a populated `reference` |
| `search_ioc_no_result.json` | the miss, and the trap: `query_status` is `no_result` and **`data` is a string**, not the list an `ok` carries |
| `search_ioc_address_out_of_scope.json` | the wildcard answer for an address that appears **inside** a listed URL. One record, of type `url`. It is a claim about that URL and not about the address, and an adapter that reported it as one would say the host was contacted at a listed location when the evidence says no such thing |

Committed on the same terms as `export.json`: these are five answers about five
indicators, not a dataset, and the full export stays out of the repository.

**They are a snapshot and the indicators in them expire.** The publisher removes
IOCs older than six months from both the API and the export, so an indicator
listed here will eventually stop being listed live. Nothing in the suite asserts
that any of them is *currently* listed —
`tests/test_providers.py::test_the_hunting_api_still_answers_the_surface_this_adapter_was_written_against`
is the one live call and it asks about an indicator this project made up, so it
tests the surface rather than the feed's contents.
