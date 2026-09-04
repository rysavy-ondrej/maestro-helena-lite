"""Context Builder — windowed host context and entity extraction.

Streaming jobs and view definitions in three layers (flatten -> signal ->
analytical): windowed aggregation into a HostContext, extraction of the entity
rows the enrichment join needs, and the enriched-context view above them. The
SQL is project source in its own right, versioned and tested by execution.

An analytical view never reads the flatten layer or the source directly, and
every view declares whether it is a view or a materialized view and what reads it.

Maturity: deferred — placeholder. Built by the D2 Context increments.
"""
