"""Enrichment — feed loaders and the snapshot-versioned reference tables.

Static data is a table, not a service: each feed is fetched on its schedule,
parsed, mapped to the taxonomy and written to a reference table carrying a
snapshot version. The enriched context is a SQL join against those tables, so
there is no runtime enrichment service, no dispatch and no cache.

A load failure leaves the previous snapshot in place and is recorded. A feed that
failed to refresh is `stale` or `missing` — never `no_match`.

Maturity: deferred — placeholder. Built by the D3 Enrichment increments.
"""
