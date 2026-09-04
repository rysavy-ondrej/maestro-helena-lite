"""Context Builder — windowed host context and entity extraction.

Streaming jobs and view definitions in three layers (flatten -> signal ->
analytical): windowed aggregation into a HostContext, extraction of the entity
rows the enrichment join needs, and the enriched-context view above them. The
SQL is project source in its own right, versioned and tested by execution.

An analytical view never reads the flatten layer or the source directly, and
every view declares whether it is a view or a materialized view and what reads it.

**This component's source is SQL, not Python.** There is nothing in this module
because there is nothing for Python to do here: `concept/instruction.md` §1 gives
the engine the work where a choice exists, and a layer of views is exactly that
case. The module stays because the component is one of the seven in
`concept/03-architecture.md` and `tests/test_package_layout.py` holds the package
to one module per component; when the Context Builder needs Python — a caller, a
typed row read back — it goes here.

What exists so far:

| Layer | Where | State |
| --- | --- | --- |
| flatten | `sql/migrations/0005_flatten_layer.sql` | eight plain views over `helena_normalized_events` |
| signal | `sql/migrations/0006_host_context.sql` | `helena_signal_host_context`, a materialized view: one host context per host per 5-minute window |
| signal | `sql/migrations/0007_context_entities.sql` | `helena_signal_entity_observations`, a plain view, and `helena_signal_context_entities`, a materialized view: one row per entity per context, with the traffic of the flows that observed it |
| signal | `sql/migrations/0008_public_suffix_list.sql` | the registrable-domain derivation: two plain candidate views, `helena_signal_domain_registrable` (materialized) and `helena_signal_context_domains` (plain). Its writer is `helena.enrichment`, not this module, because the reference table it joins is loaded rather than derived |
| analytical | — | deferred: the enriched-context view (D3) |

The flatten layer's shape and the three choices behind it are in
`docs/decisions/0015-the-flatten-layer.md`; the host context's window, host key,
identity and version are argued in the head of its own migration, including the
cost the window choice accepts and the one thing that cannot be measured without
the evaluation corpus. The entity rows' extraction rules, their
observation-scoped traffic and the three coverage gaps they inherit are argued
in the head of theirs. The registrable-domain derivation is argued in the head
of `sql/migrations/0008_public_suffix_list.sql` and tested by
`tests/test_enrichment.py`, because what it joins against is a reference table
with a loader — it is normalization for scope correctness and it produces no
taxonomy claim. `tests/test_context.py` is what exercises the flatten and
signal layers, against a real engine over real records.

Maturity: experimental — both layers exist and are exercised by execution over
the sample capture and the layer-coverage fixture. Nothing outside the test
suite reads a host context or an entity row yet, no context has been cited, no
entity has been enriched, and window coherence is unmeasured. The analytical
layer above is deferred and still says so.
"""
