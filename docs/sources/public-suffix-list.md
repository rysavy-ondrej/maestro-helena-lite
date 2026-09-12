# Public Suffix List

**Written from a fetched artifact.** The list is fetched by
`helena.enrichment.fetch_public_suffix_list` and loaded by
`load_public_suffix_list`; the 2026-09-03 snapshot parsed to **10 781 rows**, and
the write performance below was measured against RisingWave 3.0.3 on that
snapshot.

| | |
| --- | --- |
| Tier | **N/A**, and that is a value rather than an omission |
| Role | **Registrable-domain normalization**, for scope correctness. *Not* enrichment |
| Entity types | none. It attaches to no entity |
| Declared emit subset | **none. It makes no claim about anything** |
| Escalates independently | no — there is nothing to escalate |
| Loaded? | yes, `sql/migrations/0008_public_suffix_list.sql` |

## Why its tier is `N/A` and not unassigned

`concept/05` lists it as **built**, and separates it from the feeds by what it
produces: *"it produces no claims, never escalates, and its tier is therefore
N/A rather than unassigned."* It carries **no threat type, no confidence, no
first-seen and no compromised flag** — there is no per-entry evidence because
there are no entries about entities. A source record for it exists so that the
distinction is written down somewhere a reader will look, not because it needs
governing as an intelligence source.

## The shapes that matter

- **Two sections, and a rule outside both is a defect.** `ICANN DOMAINS` and
  `PRIVATE DOMAINS` are delimited by `// ===BEGIN …===` / `// ===END …===`
  markers; a rule outside both is **refused**, not guessed at.
- **The algorithm's default rule `*` is not a line in the published file** and is
  stored as a row anyway, so that **every valid name matches something**. That
  distinction is load-bearing rather than tidy — `sql/migrations/0008`'s head
  explains why a name matching nothing is a different bug from a name matching
  `*`.
- **One snapshot at a time, on purpose.** Unlike a feed, this table holds exactly
  one snapshot and the derivation `GROUP BY`s `snapshot_version`, so a second one
  **fails loudly** rather than being silently picked between. That is the
  opposite of the feed rule, and [0044](../decisions/0044-the-snapshot-scheme.md)
  §3 records why both are right.

## Typed failures, one per way a load ends with nothing written

| Reason | What happened |
| --- | --- |
| `fetch_failed` | the URL did not yield bytes — no network, a 404, a timeout |
| `malformed_rule` | a line is not a rule the algorithm can use |
| `empty_list` | the fetch worked and parsed to **no rules at all**, which would silently make every name its own public suffix |

A failed load **writes nothing and leaves the previous snapshot in place**.
`empty_list` exists because the dangerous outcome here is not an error, it is a
successful load of nothing.

## Two measurements worth keeping

- **Rows per INSERT: 500.** One statement per row through `executemany` took
  **15.9 s** on the 10 781-row snapshot; 500-row multi-row INSERTs took **1.2 s**.
  The round trip is the cost, not the write.
- **The fetch failure set includes `http.client.HTTPException`**, measured
  2026-09-12, and it had been missing. `http.client.InvalidURL` is a subclass of
  neither `OSError` nor `ValueError`, so it escaped both fetch functions untyped —
  and **its message quotes the whole request path**, so a URL holding a credential
  reached a traceback unredacted. Both fetch functions now raise their own typed
  error with a redacted message, and `from None` rather than `from failure`,
  because an exception chain is printed in full and a cause carrying the key
  would undo the redaction one line down.

## What this source does not do

It does **not** run in front of the Netify join
([netify.md](netify.md)): normalizing `windowsupdate.com.edgesuite.net` to
`edgesuite.net` before that join loses the match. Registrable-domain
normalization is for scope, and scope only.
