# Public Suffix List fixtures

Two files, both used by `tests/test_enrichment.py`.

## `extract.dat`

A trimmed extract of the published list, in the list's own format, section
markers and all — the parser reads it exactly as it reads the real thing.

It holds every rule the committed tests need and nothing else: the rules the
official `checkPublicSuffix` vectors turn on, the rules that decide the names in
`data/ingest/flow-sample.jsonl`, and `github.io` / `workers.dev` /
`trafficmanager.net` for the shared-infrastructure case. 34 rules against the
snapshot's 10 321, which is why the suite can load it into a throwaway engine in
a fraction of a second.

`prds/CONTEXT.md` §3 asks for a small extract rather than the full file, and an
extract is only honest if it answers the same way the list does.
`test_the_extract_answers_as_the_published_list_does` is what says so: it fetches
the live list and asserts that, restricted to the candidate suffixes of every
name the suite tests, the two hold the same rules. That test failing means this
file is stale, not that the code is wrong — regenerate it from the current
snapshot.

## `checkpublicsuffix.txt`

The publisher's own test vectors, taken verbatim from
`tests/test_psl.txt` in the `publicsuffix/list` repository on 2026-09-03. CC0,
per the dedication in its first two lines.

77 `checkPublicSuffix(name, expected)` calls covering the cases a hand-written
test does not think of: mixed case, a leading dot, an unlisted TLD, a TLD with
only a wildcard rule, wildcards with exceptions, four-label US K12 names, and
IDN labels in both Unicode and punycode form. The suite runs every one of them
through the real ingestion path and the real views.

The commented-out `local` vectors and the `null` input are skipped: the first
because the list no longer carries those rules, the second because there is no
such thing as a domain entity with no value.
