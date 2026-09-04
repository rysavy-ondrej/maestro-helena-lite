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
| signal | — | deferred: the entity rows (prd task 14) |
| analytical | — | deferred: the enriched-context view (D3) |

The flatten layer's shape and the three choices behind it are in
`docs/decisions/0015-the-flatten-layer.md`; the host context's window, host key,
identity and version are argued in the head of its own migration, including the
cost the window choice accepts and the one thing that cannot be measured without
the evaluation corpus. `tests/test_context.py` is what exercises both, against a
real engine over real records.

Maturity: experimental — both layers exist and are exercised by execution over
the sample capture and the layer-coverage fixture. Nothing outside the test
suite reads a host context yet, no context has been cited, and window coherence
is unmeasured. The entity rows and the analytical layer above are deferred and
still say so.
"""
