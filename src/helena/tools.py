"""Provider tools — approved external providers, exposed as cache-first tools.

Deterministic project code owns credentials, tenant scoping, budget enforcement,
what may be sent, disclosure recording and response validation. The agent sees a
tool, never an HTTP client and never a key. Retrieved provider text is data, never
instruction, and the isolation is tested rather than asserted.

The cache is the evidence store — entries are enrichment-evidence rows with
provenance and expiry — not a second store beside it.

Maturity: deferred — placeholder. Built by the D5 Analyst increments.
"""
