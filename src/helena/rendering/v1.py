"""Rendering v1 — the first frozen five-part projection. Never edited; superseded by a `v2`.

Everything here is read off `concept/04-the-two-agents.md` ("What the Triage
Agent sees"): the five parts, the four properties a rendering must have, and the
rule that the host attributes come from fixed configuration and nothing else.
`docs/decisions/0018-the-triage-rendering.md` carries the argument for the line
grammar, for the TLS parameter subset, and for the six things this rendering
deliberately does not carry — including the publisher's native payload, which is
an isolation decision rather than a formatting one.

**This file is frozen the moment an assessment records `rendering_version =
"v1"`.** `docs/decisions/0008-version-registry.md`: a revision is `v2` beside it,
with this left importable exactly as it was — because what a stored assessment
saw is pinned by the version it recorded, not reconstructed from current code.

## The line grammar, and why it is one line per record

Every record is one line of `kind value key=value ...`, and the enrichment of a
record is appended to that record's own line behind ` | `. Two properties come
out of that and both are load-bearing:

- **A claim can never be separated from the entity it is about.** The next
  increment bounds this rendering and drops records to fit; a shape where the
  claim sat on a continuation line would let a budget keep the entity and drop
  the claim, which is the quiet version of the failure `concept/07` calls
  "silent truncation is a correctness bug".
- **What was dropped is countable in lines.** `Truncation.kept` and
  `Truncation.total` are counts of records, and a record is a line.

Values are emitted through `token`, which percent-encodes anything that is not a
printable non-space ASCII character. A domain name comes from a DNS query and an
entity value is attacker-influenced text; a name carrying a newline would forge a
second line in a section, which is the same forgery `helena.hosts` refuses in a
configured attribute value, arriving from the other side.

## What the five parts are built from

| Part | Source | Cites |
| --- | --- | --- |
| `host` | `helena.hosts`, from fixed configuration | nothing — see below |
| `domains_contacted` | the `domain` entities of the projection | every domain claim |
| `addresses_contacted` | the `address` entities, and the ports reached on them | every address claim |
| `tls_parameters` | the negotiated parameter tuples, and the `fingerprint` entities | every fingerprint claim |
| `connection_statistics` | the context's own bidirectional counters | nothing |

The host section cites nothing **on purpose**: `concept/04` requires a stable
evidence identifier on every *enriched* value, and a configured attribute is not
one. A citation there would point at configuration as though a source had claimed
it. The connection statistics cite nothing for the same kind of reason — they are
measurements, not claims.

## The status and the classification are two tokens, always

`concept/instruction.md` §2 and §7: `stale` / `failed` / `missing` / `no_match`
and a typed error stay distinct *"including in whatever is rendered to an
agent"*. So every enrichment segment carries `status=` — what happened to the
lookup — and carries `classification=` only where the source answered.
`status=missing` with no classification and `status=ok classification=no_match`
are the two lines this whole stage exists to keep apart: the first is a name
nobody could look up, the second is a name that was looked up and is not listed.
A single collapsed token would make them one word apart at best.

Freshness is stated once per source in the section header, not once per record.
That is not a shortcut: the status and the snapshot are properties of *(window,
load history)* and not of an entity — every entity in one window sees the same
snapshot from the same source — and `helena.rendering` raises rather than
rendering a header for rows that disagree.

Maturity: experimental — exercised by `tests/test_rendering.py` against a
migrated engine holding a real capture and a real ThreatFox extract. No model has
been given one of these renderings, so what is demonstrated is that the five
parts are built and that the statuses stay apart in the text, not that the shape
reads well to a small model. It is **not yet bounded**: no section carries a
`Truncation` because nothing yet drops a record, and the size budget is the next
increment's.
"""

from __future__ import annotations

from datetime import datetime

from helena import hosts
from helena.contracts import v1 as contract
from helena.enrichment import ENTITY_TYPES
from helena.rendering import (
    ContextEntity,
    ContextProjection,
    EntityEnrichment,
    RenderingError,
    RenderingVersion,
    TlsParameters,
)

__all__ = [
    "ADDRESS",
    "DOMAIN",
    "EMPTY",
    "FINGERPRINT",
    "RENDERING",
    "RENDERING_VERSION",
    "SECTION_ENTITY_TYPES",
    "UNRENDERED_ENTITY_TYPES",
    "render",
    "token",
]

#: This module's own version, and the value an assessment records. `AgentRequest`
#: refuses a request whose `rendering.version` and `versions.rendering_version`
#: disagree, so the two copies of it on a request are asserted equal there.
RENDERING_VERSION = "v1"

DOMAIN = "domain"
ADDRESS = "address"
FINGERPRINT = "fingerprint"

#: Which entity types each of the three enriched sections carries.
#:
#: The fingerprints are in the TLS section and not in one of their own, because
#: `concept/04` closes the rendering at five parts and a JA3 *is* a TLS
#: parameter — a fingerprint of the ClientHello. It is the one entity type whose
#: section is not named after it, which is why it is written down here rather
#: than inferred from a name.
SECTION_ENTITY_TYPES: dict[str, tuple[str, ...]] = {
    contract.DOMAINS_CONTACTED: (DOMAIN,),
    contract.ADDRESSES_CONTACTED: (ADDRESS,),
    contract.TLS_PARAMETERS: (FINGERPRINT,),
}

#: The entity types this rendering version does not carry, named rather than
#: skipped.
#:
#: `url` is the only one, and the reason is `concept/04`'s own: the five parts
#: are "domains contacted" and "addresses contacted", and a URL record has no
#: part to go in. Folding one into the domain section would need the host-part
#: extraction re-implemented here, and that rule already has exactly one home
#: (`sql/migrations/0010_entity_value_null_guard.sql`); a second copy of it is
#: how two spellings of one name appear.
#:
#: **The cost is stated rather than hidden.** A URL-scoped claim is invisible to
#: triage — 287 of the 4 095 indicators in the ThreatFox snapshot are `url`-typed
#: — and what covers most of it is that the URL's host is already a `domain`
#: record in section two, carrying `http` among its observing layers. Measured on
#: the layer-coverage capture: six URL entities, 118 characters on average and
#: 254 at the longest, and every one of the five hosts they name is already a
#: domain record in the same context.
#: `docs/decisions/0018-the-triage-rendering.md` records what would close it.
UNRENDERED_ENTITY_TYPES: tuple[str, ...] = ("url",)

#: What a section with no records says. A blank body would make "this host
#: contacted no domains" and "the domain section was not rendered" the same thing
#: to an agent, which is the rule `concept/instruction.md` §2 states as *absence
#: is not emptiness* and which `helena.contracts.v1.Rendering` enforces one level
#: up by requiring all five sections to be present.
EMPTY = "none observed in this window"

# The characters a rendered token may carry unescaped: printable ASCII, no space
# and no `%`, which is the escape character itself. See the module docstring.
_SAFE = frozenset(chr(code) for code in range(0x21, 0x7F)) - {"%"}


def token(value: str) -> str:
    """One rendered value, with anything that could forge structure escaped.

    Percent-encoding of the UTF-8 bytes, so it is reversible and no value is
    silently changed into another. Real domain names and addresses are already
    inside the safe set, so this fires on the values that would otherwise be a
    problem and on nothing else.
    """
    return "".join(
        character
        if character in _SAFE
        else "".join(f"%{byte:02X}" for byte in character.encode())
        for character in value
    )


def _moment(when: datetime) -> str:
    return token(when.isoformat())


def render(
    projection: ContextProjection, attributes: hosts.HostAttributes
) -> contract.Rendering:
    """The five-part rendering of one context. The whole of what triage sees.

    `attributes` comes from `helena.hosts` — a closed, versioned field set from
    fixed configuration only — and must be the attributes of *this* projection's
    host. Rendering one host's configured attributes beside another's traffic
    would be an assessment about neither, and nothing downstream could tell.
    """
    if attributes.address != projection.host:
        raise RenderingError(
            f"the projection is of host {projection.host!r} and the attributes are "
            f"{attributes.address!r}'s. A rendering pairs one host's configured "
            f"attributes with that host's own traffic, and nothing downstream "
            f"could tell that it did not."
        )
    _check_every_entity_type_has_a_home()
    sections = (
        contract.RenderedSection(
            section=contract.HOST,
            body=hosts.render(attributes),
            evidence_ids=(),
        ),
        _entity_section(projection, contract.DOMAINS_CONTACTED),
        _entity_section(projection, contract.ADDRESSES_CONTACTED),
        _tls_section(projection),
        contract.RenderedSection(
            section=contract.CONNECTION_STATISTICS,
            body=_statistics(projection),
            evidence_ids=(),
        ),
    )
    return contract.Rendering(version=RENDERING_VERSION, sections=sections)


def _check_every_entity_type_has_a_home() -> None:
    """Every declared entity type is either rendered somewhere or named as not.

    `helena.enrichment.ENTITY_TYPES` is frozen by reference here, the way
    `helena.contracts.v1` freezes the taxonomy by reference and for the same
    reason: re-spelling the four types in every rendering version would be four
    vocabularies. What that costs is that adding a fifth changes what `v1` would
    do — so it fails here, loudly, at the first render, instead of producing a
    rendering that silently drops a kind of entity nobody decided about.
    """
    placed = {
        entity_type
        for types in SECTION_ENTITY_TYPES.values()
        for entity_type in types
    } | set(UNRENDERED_ENTITY_TYPES)
    homeless = sorted(ENTITY_TYPES - placed)
    if homeless:
        raise RenderingError(
            f"{homeless} is a declared entity type that rendering "
            f"{RENDERING_VERSION} neither renders nor names as unrendered. A "
            f"rendering version is frozen, so a new entity type is a decision for "
            f"a v2 rather than a kind of evidence that quietly stops being shown."
        )


# --- The three enriched sections --------------------------------------------


def _entity_section(
    projection: ContextProjection, section: str
) -> contract.RenderedSection:
    entities = projection.entities_of(*SECTION_ENTITY_TYPES[section])
    lines = [*_source_headers(entities), *(_entity_line(entity) for entity in entities)]
    return contract.RenderedSection(
        section=section,
        body="\n".join(lines) if lines else EMPTY,
        evidence_ids=_evidence_ids(entities),
    )


def _tls_section(projection: ContextProjection) -> contract.RenderedSection:
    """Part four: the selected parameters, then the client fingerprints.

    The parameters first because they describe every handshake in the window and
    the fingerprints describe the client that made them; and because the
    fingerprints are the part that carries enrichment, so a reader arrives at the
    claims having already seen what was negotiated.
    """
    entities = projection.entities_of(*SECTION_ENTITY_TYPES[contract.TLS_PARAMETERS])
    lines = [
        *(_tls_line(parameters) for parameters in projection.tls),
        *_source_headers(entities),
        *(_entity_line(entity) for entity in entities),
    ]
    return contract.RenderedSection(
        section=contract.TLS_PARAMETERS,
        body="\n".join(lines) if lines else EMPTY,
        evidence_ids=_evidence_ids(entities),
    )


def _source_headers(entities: tuple[ContextEntity, ...]) -> list[str]:
    """One line per source consulted for this section: tier, status, freshness.

    Written once because the status and the snapshot belong to the window and the
    load history rather than to an entity. Two entities disagreeing about either
    is a projection that would be rendered as one lookup and is refused here — it
    would make this line true of some of the records below it.
    """
    lookups: dict[str, EntityEnrichment] = {}
    for entity in entities:
        for record in entity.enrichment:
            seen = lookups.setdefault(record.source_id, record)
            if (seen.status, seen.snapshot_version, seen.snapshot_loaded_at) != (
                record.status,
                record.snapshot_version,
                record.snapshot_loaded_at,
            ):
                raise RenderingError(
                    f"{record.source_id!r} reports status {seen.status!r} for one "
                    f"entity in this window and {record.status!r} for another. "
                    f"The status and the snapshot are properties of the window "
                    f"and the load history, so one section states them once."
                )
    headers = []
    for source_id, record in sorted(lookups.items()):
        line = [
            "source",
            token(source_id),
            f"tier={token(record.source_tier)}",
            f"status={token(record.status)}",
        ]
        if record.snapshot_version is not None:
            line.append(f"snapshot={token(record.snapshot_version)}")
        if record.snapshot_loaded_at is not None:
            line.append(f"loaded={_moment(record.snapshot_loaded_at)}")
        headers.append(" ".join(line))
    return headers


def _entity_line(entity: ContextEntity) -> str:
    """One record: what it is, how it was observed, and what each source said."""
    line = [token(entity.entity_type), token(entity.entity_value)]
    if entity.fingerprint_algorithm is not None:
        line.append(f"algorithm={token(entity.fingerprint_algorithm)}")
    if entity.ports:
        line.append("ports=" + ",".join(str(port) for port in entity.ports))
    line.extend(
        (
            "layers=" + ",".join(entity.observed_layers),
            f"flows={entity.observed_flow_count}",
            f"bytes_sent={entity.observed_bytes_sent}",
            f"bytes_received={entity.observed_bytes_received}",
        )
    )
    return " ".join(line) + "".join(
        " | " + _enrichment_segment(record) for record in entity.enrichment
    )


def _enrichment_segment(record: EntityEnrichment) -> str:
    """What one source said about one entity, on that entity's own line.

    `classification=` appears only where the source answered. A `missing` or
    `failed` lookup produced no taxonomy object at all (`concept/05` rule 4), and
    writing one there — even the word `none` — would be a fifth value standing
    for something `status` already says.
    """
    segment = [token(record.source_id), f"status={token(record.status)}"]
    if record.classification is not None:
        segment.append(f"classification={token(record.classification)}")
    if not record.has_claim:
        return " ".join(segment)
    if record.confidence is not None:
        segment.append(f"confidence={record.confidence:.2f}")
    segment.append(f"scope_type={token(str(record.scope_type))}")
    segment.append(f"scope={token(str(record.scope_value))}")
    if record.port_matched is not None:
        segment.append(f"port_matched={'true' if record.port_matched else 'false'}")
    if record.first_seen is not None:
        segment.append(f"first_seen={_moment(record.first_seen)}")
    if record.last_seen is not None:
        segment.append(f"last_seen={_moment(record.last_seen)}")
    # Last on the line because it is the longest token and the one a reader
    # copies rather than reads.
    segment.append(f"evidence={token(str(record.evidence_id))}")
    return " ".join(segment)


def _evidence_ids(entities: tuple[ContextEntity, ...]) -> tuple[str, ...]:
    """The stable identifiers this section rendered, in the order it rendered them.

    Ordered and unique: `RenderedSection` refuses a repeated identifier, because
    the same claim rendered twice is one claim and a duplicate would count as two
    in anything reading the list.
    """
    found: dict[str, None] = {}
    for entity in entities:
        for record in entity.enrichment:
            if record.evidence_id is not None:
                found[record.evidence_id] = None
    return tuple(found)


# --- The two sections with nothing to cite ----------------------------------


def _tls_line(parameters: TlsParameters) -> str:
    """One negotiated parameter tuple, and how many flows used it.

    A parameter the record did not carry is **not rendered**: a flow captured
    mid-connection observed TLS records and no handshake, so there was nothing to
    negotiate. `tls handshakes=3` on its own is that case, and it is not the same
    as a window with no TLS in it — which produces no line at all.
    """
    line = ["tls"]
    for field in ("client_version", "server_version", "server_cipher"):
        value = getattr(parameters, field)
        if value is not None:
            line.append(f"{field}={token(value)}")
    line.append(f"handshakes={parameters.handshake_count}")
    return " ".join(line)


def _statistics(projection: ContextProjection) -> str:
    """Part five, kept bidirectional.

    `concept/04`: "duration, packets and octets, kept **bidirectional**, because
    direction is signal." There is no total and no ratio here and none is
    derived: a host that received a megabyte and a host that sent one are the
    same number once they are added together, and the difference is most of what
    an exfiltration looks like.
    """
    statistics = projection.statistics
    return "\n".join(
        (
            " ".join(
                (
                    f"window_start={_moment(statistics.window_start)}",
                    f"window_end={_moment(statistics.window_end)}",
                    # `open` or `provisional`, and neither is "final": a context
                    # does not stop revising while its records are retained.
                    f"completeness={token(statistics.completeness)}",
                )
            ),
            f"flows={statistics.flow_count} "
            f"duration_seconds={statistics.duration_seconds:.3f}",
            f"bytes_sent={statistics.bytes_sent} "
            f"bytes_received={statistics.bytes_received}",
            f"packets_sent={statistics.packets_sent} "
            f"packets_received={statistics.packets_received}",
        )
    )


RENDERING = RenderingVersion(version=RENDERING_VERSION, render=render)
