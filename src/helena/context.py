"""Context Builder — windowed host context and entity extraction.

Streaming jobs and view definitions in three layers (flatten -> signal ->
analytical): windowed aggregation into a HostContext, extraction of the entity
rows the enrichment join needs, and the enriched-context view above them. The
SQL is project source in its own right, versioned and tested by execution.

An analytical view never reads the flatten layer or the source directly, and
every view declares whether it is a view or a materialized view and what reads it.

**Most of this component's source is SQL, not Python**, because
`concept/instruction.md` §1 gives the engine the work where a choice exists and a
layer of views is exactly that case. What is here in Python is what the engine
cannot do on its own: **the copy-out that freezes a cited context**, and **the
counter that reports what the retention boundary drops**.

Both belong to the retention boundary, and the boundary is one parameter.
`concept/07-principles.md`: engine-side retention is a temporal filter and not a
delete, *the retention horizon is also the late-record tolerance* — one
parameter, not two — the boundary must report what it drops, and a context cited
by a finding is copied out rather than evicted, because a citation has to be
stable rather than merely current. `RETENTION_HORIZON` is the Python copy of that
one parameter; `sql/migrations/0009_retention_boundary.sql` holds the engine's
two, and `tests/test_context.py` asserts all three equal by asking the engine —
including the interval RisingWave stored in the retained view's own definition.

What exists so far:

| Layer | Where | State |
| --- | --- | --- |
| flatten | `sql/migrations/0005_flatten_layer.sql` | eight plain views over `helena_normalized_events` |
| signal | `sql/migrations/0006_host_context.sql` | `helena_signal_host_context`, a materialized view: one host context per host per 5-minute window |
| signal | `sql/migrations/0007_context_entities.sql` | `helena_signal_entity_observations`, a plain view, and `helena_signal_context_entities`, a materialized view: one row per entity per context, with the traffic of the flows that observed it |
| signal | `sql/migrations/0008_public_suffix_list.sql` | the registrable-domain derivation: two plain candidate views, `helena_signal_domain_registrable` (materialized) and `helena_signal_context_domains` (plain). Its writer is `helena.enrichment`, not this module, because the reference table it joins is loaded rather than derived |
| signal | `sql/migrations/0009_retention_boundary.sql` | the retention boundary: `helena_retention_horizon` (plain), `helena_signal_host_context_retained` and `helena_signal_context_entities_retained` (materialized), `helena_signal_host_context_live` and `helena_signal_retention_rejections` (plain), and `helena_frozen_context`, the table this module writes |
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

The retention boundary is argued in the head of
`sql/migrations/0009_retention_boundary.sql`, including the four things measured
against the pinned engine before it was written and the two copies of the horizon
it is forced to carry.

Reads: `helena_signal_host_context_live` and `helena_signal_retention_rejections`.
Writes: `helena_frozen_context`, one row per frozen version of a cited context.

Maturity: experimental — the layers exist and are exercised by execution over the
sample capture and the layer-coverage fixture, and the boundary over real records
with a re-stamped `ts`, because every fixture in this repository is dated
2024-06-01 and no horizon a prototype would set reaches it. Nothing outside the
test suite reads a host context or an entity row yet, **nothing calls `freeze`**
— the code that issues a finding does not exist, so what is demonstrated is that
a frozen copy survives a revision, not that one is taken at the right moment —
no entity has been enriched, and window coherence is unmeasured. The horizon
itself is a candidate under observation rather than a decision
(`concept/08-open-questions.md`). The analytical layer above is deferred and
still says so.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal

import psycopg
from pydantic import BaseModel, ConfigDict, NonNegativeInt, model_validator

from helena.config import IngestionIdentity

__all__ = [
    "COMPLETENESS_VALUES",
    "FROZEN_CONTEXT_TABLE",
    "LIVE_HOST_CONTEXT_VIEW",
    "RETAINED_CONTEXT_ENTITIES_VIEW",
    "RETAINED_HOST_CONTEXT_VIEW",
    "RETENTION_HORIZON",
    "RETENTION_HORIZON_VIEW",
    "RETENTION_REJECTIONS_VIEW",
    "Completeness",
    "ContextOutsideRetention",
    "ContextStore",
    "FrozenContext",
    "RetentionRejections",
]

# The retention horizon, and it is also the late-record tolerance: one parameter,
# not two (`concept/07-principles.md`). This is the Python copy;
# `sql/migrations/0009_retention_boundary.sql` holds the engine's two — the
# `helena_retention_horizon` view and the literal in the retained view's
# predicate, which a streaming query cannot read from a view — and
# `tests/test_context.py` asserts all three equal by asking the engine.
#
# It is a candidate rather than a decision: `concept/08-open-questions.md` records
# the horizon as unset and now empirical, to be observed in the rejection counter
# before it is committed to. Changing it is a new migration, not an edit.
RETENTION_HORIZON = timedelta(hours=24)

# The five names migration 0009 creates, so this module names each of them once
# and a test can ask the engine what it actually holds.
RETENTION_HORIZON_VIEW = "helena_retention_horizon"
RETAINED_HOST_CONTEXT_VIEW = "helena_signal_host_context_retained"
LIVE_HOST_CONTEXT_VIEW = "helena_signal_host_context_live"
RETAINED_CONTEXT_ENTITIES_VIEW = "helena_signal_context_entities_retained"
RETENTION_REJECTIONS_VIEW = "helena_signal_retention_rejections"
FROZEN_CONTEXT_TABLE = "helena_frozen_context"

# `open` or `provisional`, and **neither value is "final"**
# (`concept/02-concepts-and-taxonomy.md`): a context never reaches a state where
# it cannot change while its raw records are retained. A context does not become
# final — it leaves the retained view. The SQL side cannot express a third value
# either: `completeness` is a two-branch CASE in a view nothing writes to.
Completeness = Literal["open", "provisional"]
COMPLETENESS_VALUES: tuple[str, ...] = ("open", "provisional")

# The columns of a frozen context, in the order the table declares them. Named
# once here so the SELECT that reads a live row and the INSERT that writes the
# copy cannot disagree about the column set.
_FROZEN_COLUMNS = (
    "tenant",
    "sensor",
    "context_id",
    "context_version",
    "completeness",
    "host",
    "window_start",
    "window_end",
    "flow_count",
    "duration_seconds",
    "bytes_sent",
    "bytes_received",
    "packets_sent",
    "packets_received",
    "aggregation_version",
)


class ContextOutsideRetention(LookupError):
    """A context was asked to be frozen and the boundary no longer shows it.

    Typed, and it is not the same thing as "no such context": the row may be
    sitting in `helena_signal_host_context` with its window long past the
    horizon. What this says is that the copy-out came too late —
    `concept/07-principles.md` requires freezing **before** eviction, and a
    freeze that quietly wrote nothing would leave a citation resolving to
    whatever the live view happens to say later, which is the failure the rule
    exists to prevent.
    """


class FrozenContext(BaseModel):
    """One frozen version of one context: what a citation resolves to.

    Frozen and extra-forbidding, like every stored contract in this package. The
    fields are the columns of `helena_frozen_context`, and `(tenant, sensor,
    context_id, context_version)` is its key: a revision mints a new version and
    keeps the old copy beside it, so a citation issued earlier still resolves to
    the numbers it was issued against.

    `completeness` is `open` or `provisional` here as well. A frozen copy is
    **stable, not complete** — it records what the context was when it was
    copied out, and the live context may still revise.
    """

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    tenant: str
    sensor: str
    context_id: str
    context_version: str
    completeness: Completeness
    host: str
    window_start: datetime
    window_end: datetime
    flow_count: NonNegativeInt
    duration_seconds: float
    bytes_sent: NonNegativeInt
    bytes_received: NonNegativeInt
    packets_sent: NonNegativeInt
    packets_received: NonNegativeInt
    aggregation_version: str


class RetentionRejections(BaseModel):
    """What the boundary drops under one identity: numerator, denominator, horizon.

    `concept/07-principles.md` requires the boundary to report what it drops, so
    that a misconfigured horizon shows up as a rejection rate rather than as
    missing evidence nobody knows is missing — and
    `concept/08-open-questions.md` makes this counter the way the horizon itself
    is chosen.

    The counts come from `helena_signal_retention_rejections`, which reads the
    **unbounded** aggregate on purpose: a counter over the retained view could
    only ever report zero. They are checked against each other on construction
    rather than trusted, the same call `QuarantineCounts` makes — more contexts
    outside the boundary than contexts is not a small mistake, it is a counter
    that has stopped meaning anything.

    `horizon` is carried because a rate without the parameter it measures is a
    number nobody can act on.
    """

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    tenant: str
    sensor: str
    horizon: timedelta
    contexts: NonNegativeInt
    contexts_outside_boundary: NonNegativeInt
    records: NonNegativeInt
    records_outside_boundary: NonNegativeInt

    @model_validator(mode="after")
    def _reconciles(self) -> RetentionRejections:
        if self.contexts_outside_boundary > self.contexts:
            raise ValueError(
                f"{self.contexts_outside_boundary} of {self.contexts} contexts "
                f"are outside the boundary; the counter does not reconcile"
            )
        if self.records_outside_boundary > self.records:
            raise ValueError(
                f"{self.records_outside_boundary} of {self.records} records are "
                f"outside the boundary; the counter does not reconcile"
            )
        return self

    @property
    def rate(self) -> float:
        """The rejection rate: records the boundary drops over records aggregated.

        No contexts means no rate. It raises rather than returning 0.0, which
        would read as "the boundary dropped nothing" when the truth is "nothing
        was aggregated" — the same distinction `QuarantineCounts.rate` refuses to
        collapse, and the same reason `stale` and `no_match` are never the same
        value anywhere in this project.
        """
        if self.records == 0:
            raise ValueError(
                "no records are aggregated under this identity, so there is no "
                "rejection rate; 0.0 would read as 'the boundary dropped nothing'"
            )
        return self.records_outside_boundary / self.records


@dataclass(frozen=True)
class ContextStore:
    """The context views and the frozen-context table, under one identity.

    The same shape as `EventStore` and `Quarantine` in `helena.normalizer`, and
    for the same reason: the identity is on the instance rather than passed per
    call, so a caller cannot read one deployment's contexts and write another's
    frozen copy.
    """

    connection: psycopg.Connection
    identity: IngestionIdentity

    def freeze(self, context_id: str) -> FrozenContext:
        """Copy a live context out, so a citation of it stays stable.

        `concept/07-principles.md`: a context cited by a finding is **copied out,
        never evicted**. This is that copy. It reads
        `helena_signal_host_context_live` — the retained context, its version and
        its completeness as of now — and writes the row it read into
        `helena_frozen_context`.

        Read-then-write rather than one `INSERT ... SELECT`, deliberately: an
        `INSERT ... SELECT` cannot tell the caller *which* version it wrote, and
        a freeze that cannot name what it froze is not a citation. What is
        written is exactly what was read, so the returned row and the stored row
        are the same row.

        Freezing twice writes the same key and is an upsert of an identical row.
        Freezing after a revision writes a different `context_version` and keeps
        both copies.

        A context that has already left the boundary raises
        `ContextOutsideRetention`, because there is nothing to copy and a silent
        no-op is how a citation ends up resolving to nothing.
        """
        self.connection.execute("FLUSH")
        columns = ", ".join(_FROZEN_COLUMNS)
        rows = self.connection.execute(
            f"SELECT {columns} FROM {LIVE_HOST_CONTEXT_VIEW} "
            f"WHERE tenant = %s AND sensor = %s AND context_id = %s",
            (self.identity.tenant, self.identity.sensor, context_id),
        ).fetchall()
        if not rows:
            raise ContextOutsideRetention(
                f"{LIVE_HOST_CONTEXT_VIEW} does not hold context {context_id!r} "
                f"for {self.identity.tenant!r} / {self.identity.sensor!r}: it is "
                f"outside the retention boundary of {RETENTION_HORIZON}, or it "
                f"was never aggregated. A context is copied out before it is "
                f"evicted, never after."
            )
        if len(rows) > 1:
            raise ValueError(
                f"{LIVE_HOST_CONTEXT_VIEW} holds {len(rows)} rows for context "
                f"{context_id!r}; a context id addresses one host in one window"
            )
        frozen = FrozenContext(**dict(zip(_FROZEN_COLUMNS, rows[0], strict=True)))
        self.connection.execute(
            f"INSERT INTO {FROZEN_CONTEXT_TABLE} ({columns}) "
            f"VALUES ({', '.join(['%s'] * len(_FROZEN_COLUMNS))})",
            tuple(getattr(frozen, column) for column in _FROZEN_COLUMNS),
        )
        self.connection.execute("FLUSH")
        return frozen

    def frozen(self, context_id: str) -> list[FrozenContext]:
        """Every frozen version of one context, oldest window first.

        More than one row is not a fault: a context frozen, revised and frozen
        again has two versions, and both are what some citation was issued
        against.
        """
        self.connection.execute("FLUSH")
        columns = ", ".join(_FROZEN_COLUMNS)
        rows = self.connection.execute(
            f"SELECT {columns} FROM {FROZEN_CONTEXT_TABLE} "
            f"WHERE tenant = %s AND sensor = %s AND context_id = %s "
            f"ORDER BY context_version",
            (self.identity.tenant, self.identity.sensor, context_id),
        ).fetchall()
        return [
            FrozenContext(**dict(zip(_FROZEN_COLUMNS, row, strict=True)))
            for row in rows
        ]

    def rejections(self) -> RetentionRejections:
        """What the boundary is dropping under this identity, as of now.

        A store with no contexts at all reports zeros rather than nothing: the
        counter exists to be watched, and a missing row is harder to graph than a
        zero. `RetentionRejections.rate` is what refuses to turn those zeros into
        a rate. Its horizon comes from `helena_retention_horizon` even then —
        from the engine, never from `RETENTION_HORIZON` here, because a counter
        that reported the horizon this process believes in would agree with
        itself about a store built by a different migration.
        """
        self.connection.execute("FLUSH")
        rows = self.connection.execute(
            f"SELECT retention_horizon, contexts, contexts_outside_boundary, "
            f"records, records_outside_boundary FROM {RETENTION_REJECTIONS_VIEW} "
            f"WHERE tenant = %s AND sensor = %s",
            (self.identity.tenant, self.identity.sensor),
        ).fetchall()
        if len(rows) > 1:
            raise ValueError(
                f"{RETENTION_REJECTIONS_VIEW} reports {len(rows)} rows for "
                f"{self.identity.tenant!r} / {self.identity.sensor!r}; it groups "
                f"by identity, so more than one is a broken counter"
            )
        if not rows:
            declared = self.connection.execute(
                f"SELECT retention_horizon FROM {RETENTION_HORIZON_VIEW}"
            ).fetchone()
            if declared is None:
                raise ValueError(
                    f"{RETENTION_HORIZON_VIEW} holds no row; the store declares "
                    f"no retention horizon, so there is no boundary to report on"
                )
            return RetentionRejections(
                tenant=self.identity.tenant,
                sensor=self.identity.sensor,
                horizon=declared[0],
                contexts=0,
                contexts_outside_boundary=0,
                records=0,
                records_outside_boundary=0,
            )
        horizon, contexts, outside, records, records_outside = rows[0]
        return RetentionRejections(
            tenant=self.identity.tenant,
            sensor=self.identity.sensor,
            horizon=horizon,
            contexts=contexts,
            contexts_outside_boundary=outside,
            records=records,
            records_outside_boundary=records_outside,
        )
