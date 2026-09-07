"""Rendering — the bounded, versioned projection an agent is given, read out of the store.

`concept/04-the-two-agents.md`, "What the Triage Agent sees": *a bounded,
versioned projection of the enriched host context, in five parts* — the host,
the domains contacted, the addresses contacted, selected TLS parameters, and
bidirectional connection statistics. The Triage Agent's input is *"a bounded
rendering, **and nothing else**"*, so this is not one channel among several: it
is the whole of what triage knows.

This package holds the **machinery** — the read-out from the engine — and a
version module holds the **rendering**. `v1.py` is the first, and
`helena.rendering.v1.render` is what turns a projection into a
`helena.contracts.v1.Rendering`.

## Why a version is a module

`docs/decisions/0008-version-registry.md` names this shape in advance: *"prompt
and rendering versions follow the same shape: what triage saw is pinned by the
recorded version, not reconstructed from current code."* An assessment records
`rendering_version`, and a `v2` that reorders a line or selects a different TLS
parameter must leave `v1` meaning what it meant. So a revision is `v2` beside
`v1`, never an edit — and the constants a version renders against (the line
grammar, the TLS subset, the entity types each section carries) live in the
version module and **not here**, for the reason `helena.contracts` gives: a
constant in this file is one every frozen version imports, and editing it would
edit `v1` through a side door.

## What is here, and the five queries it is

`RenderingStore.project(context_id)` reads one context out of the engine into a
`ContextProjection` — a plain, unformatted read-out. Five queries, because the
five parts do not come from one relation and a single join of all of them would
fan the connection statistics out across every entity row:

| Relation | What it supplies |
| --- | --- |
| `helena_signal_host_context_live` | the citable row: the context's version, its completeness and the bidirectional counters |
| `helena_signal_context_entities` | the entities themselves: the layers that observed each, and the traffic of the flows that did |
| `helena_analytical_enriched_context` | one row per (entity, source): the enrichment status and the claim |
| `helena_signal_context_entity_ports` | the destination ports the host reached on each address |
| `helena_signal_context_tls` | the TLS parameters negotiated in the window |

**The entity list is the signal layer's and the claims are the analytical
layer's, and that split is not a convenience.** The enriched context's source
list is the snapshot ledger — every source that has ever been *asked* — so
before any feed has ever loaded it yields **no rows at all**
(`sql/migrations/0015_enriched_context.sql` states the consequence). A rendering
that took its entity list from there would show a host that contacted nothing on
a deployment whose only fault is that no feed has run yet, which is a worse lie
than the one this whole stage exists to prevent. So the entities come from the
view that knows what a context observed, and what is *known* about them comes
from the view that knows that.

`helena_signal_host_context_live` and not `helena_signal_host_context`: the
request carries *"the context reference **and its version**, which is what makes
replay possible"* (`concept/04`), and the live view is the one object that
defines what a citation pins (`sql/migrations/0009_retention_boundary.sql`). A
context outside the retention boundary raises
`helena.context.ContextOutsideRetention` rather than rendering as an empty one.

## Evidence tier `enrichment`, and the trap in filtering for it

`concept/03-architecture.md`: *"the triage rendering shows enrichment-tier
evidence only — without that tag, a report fetched during one investigation would
appear in the *precomputed* context of every later host that talked to the same
address, and triage input would stop being uniform."* `concept/04` puts it in the
asymmetry table as one word: triage sees `enrichment`, the analyst sees
`enrichment` and `analyst`.

So the enrichment query filters on the tier — and it filters as an **allow-list with
a null arm**, `evidence_tier IS NULL OR evidence_tier = 'enrichment'`, which is
the whole reason this paragraph exists. The tier comes from a LEFT JOIN, so it is
NULL on exactly the rows that carry no claim: every `no_match`, every `missing`,
every `failed`. A plain `evidence_tier = 'enrichment'` would drop all of them and
leave a rendering of nothing but hits — the enriched context is *mostly negative
space*, and a triage input showing only the matches is the same misreading as one
showing none. `tests/test_rendering.py` asserts both arms.

## The four statuses survive the read

`concept/instruction.md` §2 and §7: `stale` / `failed` / `missing` / `no_match`
and a typed error stay distinct **"including in whatever is rendered to an
agent"**. Two independent fields carry it here exactly as they do in the view:
`EntityEnrichment.status` is what happened to the lookup and
`EntityEnrichment.classification` is what the source said, `no_match` included.
Neither is derived from the other and nothing here folds them together.

One status is minted here rather than read: a source in `helena.enrichment.SOURCES`
that has never attempted a load produces **no rows at all** in the enriched
context, because that view's source list is every source the ledger has ever seen
(`sql/migrations/0015_enriched_context.sql` states the consequence). A renderer
that showed only the rows it found would render a fingerprint nobody could look
up as a fingerprint with nothing against it. So every source whose declared
entity types cover an entity gets a record, and one with no row gets `missing` —
which is what `helena.enrichment.feed_status` reports for the same source, for
the same reason.

Reads: the five relations above. Writes: nothing.

Maturity: experimental — exercised by `tests/test_rendering.py` against a
migrated engine holding a real capture and a real ThreatFox extract. **No agent
has been given one of these renderings**, no model has read one, and nothing is
stored: what is demonstrated is that the five parts are built from the store and
keep the statuses apart, not that a model reasons better or worse from them. The
rendering is **not yet bounded** — the size budget and the truncation record are
the next increment's, and `helena.contracts.v1.Truncation` is the shape they
land in.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

import psycopg
from pydantic import BaseModel, ConfigDict, NonNegativeInt

from helena.config import IngestionIdentity
from helena.context import LIVE_HOST_CONTEXT_VIEW, Completeness, ContextOutsideRetention
from helena.enrichment import (
    ENRICHMENT_STATUSES,
    ENRICHMENT_TIER,
    ENTITY_TYPES,
    MISSING,
    SOURCES,
)

__all__ = [
    "CONTEXT_ENTITIES_VIEW",
    "CONTEXT_TLS_VIEW",
    "ENRICHED_CONTEXT_VIEW",
    "ENTITY_PORTS_VIEW",
    "OBSERVATION_LAYERS",
    "ConnectionStatistics",
    "ContextEntity",
    "ContextProjection",
    "EntityEnrichment",
    "RenderingError",
    "RenderingStore",
    "RenderingVersion",
    "TlsParameters",
    "UnknownVersion",
    "version",
]

#: The four relations this package selects from beside the live host context.
#: Named once here so a test can ask the engine what it holds rather than read a
#: string out of a query.
CONTEXT_ENTITIES_VIEW = "helena_signal_context_entities"
ENRICHED_CONTEXT_VIEW = "helena_analytical_enriched_context"
ENTITY_PORTS_VIEW = "helena_signal_context_entity_ports"
CONTEXT_TLS_VIEW = "helena_signal_context_tls"

#: The observation flag columns, in the order a rendering lists them, mapped to
#: the layer name a reader sees. The order is not alphabetical and is not
#: arbitrary: it runs from the weakest evidence of contact to the strongest, so
#: `dns_query` — *the host asked about this name and may never have gone there* —
#: reads before `flow_destination`, which is the host having actually sent
#: packets to it. `concept/04` is why the distinction is rendered at all.
#:
#: **All five, and that is the second reason the entity list comes from
#: `helena_signal_context_entities`.** The enriched context projects three of
#: them — the scope columns the composition rule reads — which is the right subset
#: for a rule about scope and the wrong one for a rendering about observation.
#: Measured on the layer-coverage capture, three names are observed only by one
#: of the two it leaves out: `ctldl.windowsupdate.com` and `ocsp.digicert.com` in
#: an HTTP request URI and nowhere else, and `106.137.52.in-addr.arpa` in a DNS
#: response and nowhere else. Read through those three flags they would have
#: rendered as observed by no layer at all, which `ContextEntity` now refuses to
#: build.
OBSERVATION_LAYERS: tuple[tuple[str, str], ...] = (
    ("observed_in_dns_query", "dns_query"),
    ("observed_in_dns_response", "dns_response"),
    ("observed_in_http", "http"),
    ("observed_in_tls", "tls"),
    ("observed_as_flow_destination", "flow_destination"),
)

# The columns each query selects, in one place, so the SELECT and the row
# unpacking cannot disagree about the column set. The same reason
# `helena.context._FROZEN_COLUMNS` exists.
_ENTITY_COLUMNS = (
    "entity_type",
    "entity_value",
    "fingerprint_algorithm",
    *(column for column, _ in OBSERVATION_LAYERS),
    "observed_flow_count",
    "observed_bytes_sent",
    "observed_bytes_received",
)

_ENRICHMENT_COLUMNS = (
    "entity_type",
    "entity_value",
    "source_id",
    "status",
    "classification",
    "confidence",
    "scope_type",
    "scope_value",
    "port_matched",
    "evidence_id",
    "snapshot_version",
    "snapshot_loaded_at",
    "first_seen",
    "last_seen",
)

_STATISTICS_COLUMNS = (
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
)

_TLS_COLUMNS = (
    "client_version",
    "server_version",
    "server_cipher",
    "handshake_count",
)

#: The enrichment query, exposed rather than inlined so that
#: `tests/test_rendering.py` can execute **this** text against a stand-in
#: relation carrying an `analyst`-tier row. The tier filter is the one predicate
#: here that cannot be exercised against the real store — nothing writes an
#: `analyst`-tier claim yet — and a test that read the string and looked for the
#: word `enrichment` would be finding the comment above it.
ENRICHMENT_QUERY = (
    f"SELECT {', '.join(_ENRICHMENT_COLUMNS)} FROM {ENRICHED_CONTEXT_VIEW} "
    f"WHERE tenant = %s AND sensor = %s AND context_id = %s "
    # The allow-list with its null arm. See the package docstring: the tier is
    # NULL on every row that carries no claim, and an equality test alone would
    # render a context of nothing but hits.
    f"AND (evidence_tier IS NULL OR evidence_tier = %s) "
    f"ORDER BY entity_type, entity_value, source_id, evidence_id"
)


class RenderingError(Exception):
    """The store did not yield a context a rendering can be built from.

    One exception type with a stated reason, the way
    `helena.hosts.HostAttributesError` is one: every case is the same refusal to
    render something whose shape would make the rendering say a thing that is not
    so, and a caller catching four of these would be enumerating the ways the
    engine might have surprised it.

    A context that has left the retention boundary is **not** this — that is
    `helena.context.ContextOutsideRetention`, which is a different fact and one a
    caller may reasonably act on by skipping the context.
    """


class UnknownVersion(RenderingError):
    """A rendering version was asked for that this package does not hold.

    Distinct, and it means a replay that cannot be reproduced rather than a store
    that surprised us: an assessment recorded a `rendering_version` whose module
    is not in this tree, so what triage saw cannot be rebuilt from it.
    """


class EntityEnrichment(BaseModel):
    """What one source has to say about one entity, and how the lookup went.

    Frozen. **`status` and `classification` are independent and stay that way** —
    `status` is what happened to the lookup (`ok` / `stale` / `failed` /
    `missing`) and `classification` is what the source said, `no_match` included.
    A stale snapshot holding no claim is `status='stale'` beside
    `classification='no_match'`, and both halves are true: the source completed
    its query, a while ago.

    Everything below `classification` is present only where there is a claim, and
    is `None` otherwise rather than zero or empty — a confidence of `0.0` on a
    lookup that found nothing would be a number nobody wrote.

    `source_tier` comes from `helena.enrichment.SOURCES` and never from the row:
    a source's A–D tier is a governed decision (`concept/05`) and the row's copy
    of it is NULL on exactly the rows that matter most here, the ones with no
    claim.
    """

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    source_id: str
    #: `A`, `B`, `C` or `D`, from the registry.
    source_tier: str
    status: str
    classification: str | None = None
    confidence: float | None = None
    scope_type: str | None = None
    scope_value: str | None = None
    #: Three-valued, and not a filter: `None` where the claim is not port-scoped,
    #: `False` where the host reached the address on other ports only. A `False`
    #: row is kept because `concept/02` says what to do with it and it is not
    #: "drop it" (`sql/migrations/0015_enriched_context.sql`).
    port_matched: bool | None = None
    #: The stable evidence identifier. Present exactly where there is a claim —
    #: `concept/04` requires one on every **enriched value**, and a lookup that
    #: found nothing produced no row to cite.
    evidence_id: str | None = None
    #: Freshness. The snapshot that was current when the window happened, and
    #: when it was loaded — `concept/05`: "first-seen plus the snapshot version
    #: is what dates a claim". Both `None` where no snapshot was consulted.
    snapshot_version: str | None = None
    snapshot_loaded_at: datetime | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    def model_post_init(self, _context: object) -> None:
        if self.status not in ENRICHMENT_STATUSES:
            raise ValueError(
                f"status {self.status!r} is not one of {ENRICHMENT_STATUSES}; "
                f"`no_match` is a classification and never a status"
            )
        if self.source_id not in SOURCES:
            raise ValueError(
                f"{self.source_id!r} is not a registered source. The rendering "
                f"names the sources `helena.enrichment.SOURCES` declares, so a "
                f"source that appeared in the store and not in the registry is a "
                f"claim nobody governs."
            )
        if (self.evidence_id is None) != (self.scope_type is None):
            raise ValueError(
                f"{self.source_id}: evidence id {self.evidence_id!r} beside scope "
                f"type {self.scope_type!r}. A claim carries both — the identifier "
                f"is what cites it and the scope is what it is about."
            )

    @property
    def has_claim(self) -> bool:
        """Whether this source made a positive claim about the entity.

        `no_match` is an answer and not a claim: `concept/02` calls it "a lookup
        outcome, never a statement of safety", and it carries no evidence row to
        cite.
        """
        return self.evidence_id is not None


class ContextEntity(BaseModel):
    """One entity the host touched in the window, with everything known about it.

    `concept/03`: the enrichment join is per entity, because "the rendering needs
    per-domain and per-address records" rather than arrays inside a window.

    `enrichment` carries **one record per source whose declared entity types
    cover this entity**, present or absent from the store — see the package
    docstring for the source that has never loaded.
    """

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    entity_type: str
    entity_value: str
    #: `ja3` or `ja4` for a fingerprint; `None` for every other type. Without it
    #: the two are indistinguishable except by the shape of a hex string.
    fingerprint_algorithm: str | None
    #: Which layers observed this value, in `OBSERVATION_LAYERS` order. Never
    #: empty: every entity row came from an observation.
    observed_layers: tuple[str, ...]
    observed_flow_count: NonNegativeInt
    observed_bytes_sent: NonNegativeInt
    observed_bytes_received: NonNegativeInt
    #: Destination ports the host reached on this address, ascending. Empty for
    #: every other entity type: a port qualifies an address and nothing else.
    ports: tuple[int, ...] = ()
    enrichment: tuple[EntityEnrichment, ...] = ()

    def model_post_init(self, _context: object) -> None:
        if self.entity_type not in ENTITY_TYPES:
            raise ValueError(
                f"entity type {self.entity_type!r} is not among {sorted(ENTITY_TYPES)}"
            )
        if not self.observed_layers:
            raise ValueError(
                f"{self.entity_type} {self.entity_value!r} was observed by no "
                f"layer. Every entity row comes from an observation, so an empty "
                f"list is a projection that lost the flag rather than an entity "
                f"nothing saw."
            )
        if self.ports and self.entity_type != "address":
            raise ValueError(
                f"a {self.entity_type} carries ports {list(self.ports)}; a "
                f"destination port qualifies an address and nothing else"
            )


class ConnectionStatistics(BaseModel):
    """The window's traffic, kept bidirectional.

    `concept/04`: "connection statistics — duration, packets and octets, kept
    **bidirectional**, because direction is signal." So there is no total and no
    ratio here, and none is rendered: a host that received a megabyte and a host
    that sent one are the same number once they are added up, and the difference
    is most of what an exfiltration looks like.

    `completeness` is `open` or `provisional` and **neither is "final"**
    (`helena.context`): a context does not become final while its records are
    retained, so a rendering says which it was rather than implying the numbers
    are settled.
    """

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    window_start: datetime
    window_end: datetime
    completeness: Completeness
    flow_count: NonNegativeInt
    duration_seconds: float
    bytes_sent: NonNegativeInt
    bytes_received: NonNegativeInt
    packets_sent: NonNegativeInt
    packets_received: NonNegativeInt


class TlsParameters(BaseModel):
    """One distinct tuple of negotiated TLS parameters, and how often it was used.

    The subset and the criterion that chose it are in
    `docs/decisions/0018-the-triage-rendering.md`; what is here is the shape
    `helena_signal_context_tls` produces.

    Every field is nullable because a flow captured mid-connection observed TLS
    records and no handshake — there was nothing to negotiate and nothing to
    read. That is not the same as a window with no TLS in it, which produces no
    row at all.
    """

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    client_version: str | None
    server_version: str | None
    server_cipher: str | None
    handshake_count: NonNegativeInt


class ContextProjection(BaseModel):
    """One context, read out of the store: everything a rendering is built from.

    Deliberately **unformatted**. This is what the engine holds; a rendering
    version decides what of it a model sees, in what order and in what words, and
    a `v2` that changes any of that must not have to change this.
    """

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    tenant: str
    sensor: str
    host: str
    context_id: str
    #: `concept/04`: the context reference **and its version** are what make
    #: replay possible. From `helena_signal_host_context_live`, which is the one
    #: object that defines what a citation pins.
    context_version: str
    statistics: ConnectionStatistics
    #: Every entity, ordered by (type, value). Neutral on purpose: an order that
    #: put the hits first would make a later truncation drop the negative space,
    #: and an enriched context that looks like nothing but threats is the same
    #: misreading as one that looks clean.
    entities: tuple[ContextEntity, ...]
    tls: tuple[TlsParameters, ...]

    def entities_of(self, *entity_types: str) -> tuple[ContextEntity, ...]:
        """The entities of the given types, in the projection's own order."""
        unknown = sorted(set(entity_types) - ENTITY_TYPES)
        if unknown:
            raise RenderingError(
                f"{unknown} is not among the entity types {sorted(ENTITY_TYPES)}"
            )
        return tuple(
            entity for entity in self.entities if entity.entity_type in entity_types
        )


@dataclass(frozen=True)
class RenderingVersion:
    """One version's renderer: the shape every version module supplies.

    A callable rather than a class, because a rendering is a function of a
    projection and a host attribute set and holds no state of its own — a class
    here would be an object with one method and a constructor that does nothing.
    """

    version: str
    #: `(projection, host_attributes) -> helena.contracts.v1.Rendering`.
    render: Any


@dataclass(frozen=True)
class RenderingStore:
    """The rendering's four relations, under one identity.

    The same shape as `helena.context.ContextStore`, and for the same reason: the
    identity is on the instance rather than passed per call, so a caller cannot
    render one deployment's context under another's tenant.
    """

    connection: psycopg.Connection
    identity: IngestionIdentity

    def project(self, context_id: str) -> ContextProjection:
        """Read one context out of the store, unformatted.

        Raises `helena.context.ContextOutsideRetention` for a context the live
        view no longer shows — there is nothing to render, and rendering an empty
        one would hand triage a host that did nothing.
        """
        self.connection.execute("FLUSH")
        statistics, host, context_version = self._statistics(context_id)
        return ContextProjection(
            tenant=self.identity.tenant,
            sensor=self.identity.sensor,
            host=host,
            context_id=context_id,
            context_version=context_version,
            statistics=statistics,
            entities=self._entities(context_id),
            tls=self._tls(context_id),
        )

    # --- the four queries ---------------------------------------------------

    def _statistics(
        self, context_id: str
    ) -> tuple[ConnectionStatistics, str, str]:
        rows = self.connection.execute(
            f"SELECT {', '.join(_STATISTICS_COLUMNS)} FROM {LIVE_HOST_CONTEXT_VIEW} "
            f"WHERE tenant = %s AND sensor = %s AND context_id = %s",
            (self.identity.tenant, self.identity.sensor, context_id),
        ).fetchall()
        if not rows:
            raise ContextOutsideRetention(
                f"{LIVE_HOST_CONTEXT_VIEW} does not hold context {context_id!r} "
                f"for {self.identity.tenant!r} / {self.identity.sensor!r}: it is "
                f"outside the retention boundary, or it was never aggregated. "
                f"There is nothing to render, and an empty rendering would say "
                f"the host did nothing."
            )
        if len(rows) > 1:
            raise RenderingError(
                f"{LIVE_HOST_CONTEXT_VIEW} holds {len(rows)} rows for context "
                f"{context_id!r}; a context id addresses one host in one window"
            )
        row = dict(zip(_STATISTICS_COLUMNS, rows[0], strict=True))
        host = row.pop("host")
        context_version = row.pop("context_version")
        return ConnectionStatistics(**row), host, context_version

    def _ports(self, context_id: str) -> dict[str, tuple[int, ...]]:
        """The destination ports reached on each address, ascending.

        Its own query rather than a join into either of the others: the enriched
        context has a row per (entity, source) and the ports would fan out across
        every one of them, so one port would arrive once per source.
        """
        rows = self.connection.execute(
            f"SELECT entity_value, port FROM {ENTITY_PORTS_VIEW} "
            f"WHERE tenant = %s AND sensor = %s AND context_id = %s "
            f"ORDER BY entity_value, port",
            (self.identity.tenant, self.identity.sensor, context_id),
        ).fetchall()
        ports: dict[str, list[int]] = {}
        for entity_value, port in rows:
            ports.setdefault(entity_value, []).append(port)
        return {value: tuple(found) for value, found in ports.items()}

    def _tls(self, context_id: str) -> tuple[TlsParameters, ...]:
        rows = self.connection.execute(
            f"SELECT {', '.join(_TLS_COLUMNS)} FROM {CONTEXT_TLS_VIEW} "
            f"WHERE tenant = %s AND sensor = %s AND context_id = %s "
            f"ORDER BY handshake_count DESC, client_version, server_version, "
            f"server_cipher",
            (self.identity.tenant, self.identity.sensor, context_id),
        ).fetchall()
        return tuple(
            TlsParameters(**dict(zip(_TLS_COLUMNS, row, strict=True))) for row in rows
        )

    def _entities(self, context_id: str) -> tuple[ContextEntity, ...]:
        entities = self.connection.execute(
            f"SELECT {', '.join(_ENTITY_COLUMNS)} FROM {CONTEXT_ENTITIES_VIEW} "
            f"WHERE tenant = %s AND sensor = %s AND context_id = %s "
            f"ORDER BY entity_type, entity_value",
            (self.identity.tenant, self.identity.sensor, context_id),
        ).fetchall()
        claims = self.connection.execute(
            ENRICHMENT_QUERY,
            (
                self.identity.tenant,
                self.identity.sensor,
                context_id,
                ENRICHMENT_TIER,
            ),
        ).fetchall()
        return _entities_from(entities, claims, self._ports(context_id))


def _entities_from(
    entities: list[tuple],
    claims: list[tuple],
    ports: dict[str, tuple[int, ...]],
) -> tuple[ContextEntity, ...]:
    """Join the entity rows to the claim rows, one record per entity.

    Separate from the queries so that the join — including the `missing` record
    minted for a source with no row at all — can be exercised over rows a test
    supplies, as well as over rows the engine did.

    An entity is keyed by `(entity_type, entity_value)`, which is what the
    enriched context joins on. A claim row naming a pair no entity row carries
    cannot happen — the enriched context reads the entity view — and is refused
    rather than dropped, because if it ever did happen it would be a claim about
    this host that nothing rendered.
    """
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in claims:
        record = dict(zip(_ENRICHMENT_COLUMNS, row, strict=True))
        grouped.setdefault((record["entity_type"], record["entity_value"]), []).append(
            record
        )
    found = [dict(zip(_ENTITY_COLUMNS, row, strict=True)) for row in entities]
    keys = {(row["entity_type"], row["entity_value"]) for row in found}
    orphaned = sorted(set(grouped) - keys)
    if orphaned:
        raise RenderingError(
            f"the enriched context carries claims about {orphaned}, which "
            f"{CONTEXT_ENTITIES_VIEW} does not list for this context. A claim "
            f"about an entity the rendering has no record for is a claim nothing "
            f"would show."
        )
    return tuple(
        _entity(
            row,
            grouped.get((row["entity_type"], row["entity_value"]), []),
            ports.get(row["entity_value"], ()),
        )
        for row in sorted(found, key=lambda row: (row["entity_type"], row["entity_value"]))
    )


def _entity(
    entity: dict[str, Any],
    claims: list[dict[str, Any]],
    ports: tuple[int, ...],
) -> ContextEntity:
    entity_type = entity["entity_type"]
    return ContextEntity(
        entity_type=entity_type,
        entity_value=entity["entity_value"],
        fingerprint_algorithm=entity["fingerprint_algorithm"],
        observed_layers=tuple(
            layer for column, layer in OBSERVATION_LAYERS if entity[column]
        ),
        observed_flow_count=entity["observed_flow_count"],
        observed_bytes_sent=entity["observed_bytes_sent"],
        observed_bytes_received=entity["observed_bytes_received"],
        ports=ports if entity_type == "address" else (),
        enrichment=_enrichment(entity_type, entity["entity_value"], claims),
    )


def _enrichment(
    entity_type: str, entity_value: str, rows: list[dict[str, Any]]
) -> tuple[EntityEnrichment, ...]:
    """One record per source that covers this entity type, ordered by source id.

    A source the store has rows for contributes them; a source it has none for
    contributes a `missing` record — see the package docstring. A source the
    registry does not declare as covering this entity type contributes nothing at
    all, which is not the same thing: `concept/05` puts the declared entity types
    on the descriptor because *"a JA3 list has nothing to say about a domain"*,
    and rendering `sslbl-ja3: missing` beside a domain would say the list was
    asked and could not answer.
    """
    by_source: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        by_source.setdefault(row["source_id"], []).append(row)
    unregistered = sorted(set(by_source) - set(SOURCES))
    if unregistered:
        raise RenderingError(
            f"{entity_type} {entity_value!r} carries claims from {unregistered}, "
            f"which `helena.enrichment.SOURCES` does not declare. A source in the "
            f"store and not in the registry has no tier and no declared subset, "
            f"so nothing can say what its claim is worth."
        )

    records: list[EntityEnrichment] = []
    for source_id, descriptor in sorted(SOURCES.items()):
        if entity_type not in descriptor.entity_types:
            continue
        found = by_source.get(source_id)
        if not found:
            records.append(
                EntityEnrichment(
                    source_id=source_id,
                    source_tier=descriptor.tier.value,
                    status=MISSING,
                )
            )
            continue
        _check_one_lookup(entity_type, entity_value, source_id, found)
        records.extend(
            EntityEnrichment(
                source_id=source_id,
                source_tier=descriptor.tier.value,
                status=row["status"],
                classification=row["classification"],
                confidence=row["confidence"],
                scope_type=row["scope_type"],
                scope_value=row["scope_value"],
                port_matched=row["port_matched"],
                evidence_id=row["evidence_id"],
                snapshot_version=row["snapshot_version"],
                snapshot_loaded_at=row["snapshot_loaded_at"],
                first_seen=row["first_seen"],
                last_seen=row["last_seen"],
            )
            for row in found
        )
    return tuple(records)


def _check_one_lookup(
    entity_type: str, entity_value: str, source_id: str, rows: list[dict[str, Any]]
) -> None:
    """Every row of one (entity, source) describes the same lookup.

    The status and the snapshot are properties of *(window, load history)* and
    not of an entity: every entity in one window sees the same status from the
    same source, and only the classification varies. Several rows appear when a
    source makes several claims about one entity, which `concept/05` rule 6
    requires to be preserved rather than collapsed — but they are several claims
    from **one** lookup, so a disagreement here means the projection is about to
    render one lookup as two, and the section header that states the freshness
    once would be stating one of them.
    """
    lookups = {
        (row["status"], row["snapshot_version"], row["snapshot_loaded_at"])
        for row in rows
    }
    if len(lookups) > 1:
        raise RenderingError(
            f"{entity_type} {entity_value!r} has {len(lookups)} different lookups "
            f"from {source_id!r} in one window: {sorted(map(str, lookups))}. The "
            f"status and the snapshot belong to the window and the load history, "
            f"not to the entity, so several claims from one source share one."
        )


def _load(identifier: str) -> RenderingVersion:
    """The renderer of one rendering version.

    Imported by name rather than held in a registry dict, so adding `v2` is
    adding a module and nothing else. The same loader `helena.contracts` and
    `helena.hosts` use.
    """
    from importlib import import_module  # noqa: PLC0415 — one call, at the edge

    if not identifier.isidentifier():
        raise UnknownVersion(
            f"{identifier!r} is not a version identifier; versions are module "
            f"names like 'v1'"
        )
    try:
        module = import_module(f"{__name__}.{identifier}")
    except ModuleNotFoundError as absent:
        raise UnknownVersion(
            f"no rendering version {identifier!r}. An assessment that recorded it "
            f"cannot be rebuilt against this tree, so what triage saw is not "
            f"reproducible here."
        ) from absent
    rendering = getattr(module, "RENDERING", None)
    if not isinstance(rendering, RenderingVersion):
        raise UnknownVersion(
            f"{module.__name__} does not define a RenderingVersion named RENDERING"
        )
    if rendering.version != identifier:
        raise UnknownVersion(
            f"{module.__name__} declares version {rendering.version!r}; a version "
            f"module and the version it declares must agree"
        )
    return rendering


#: Public name for the loader, so `version` reads as what a caller wants.
version = _load
