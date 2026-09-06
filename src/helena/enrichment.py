"""Enrichment — feed loaders and the snapshot-versioned reference tables.

Static data is a table, not a service: each feed is fetched on its schedule,
parsed, mapped to the taxonomy and written to a reference table carrying a
snapshot version. The enriched context is a SQL join against those tables, so
there is no runtime enrichment service, no dispatch and no cache.

A load failure leaves the previous snapshot in place and is recorded. A feed that
failed to refresh is `stale` or `missing` — never `no_match`.

**What exists here is not a feed.** The first loader in this module is the
Public Suffix List, and `concept/05-threat-intelligence.md` puts it in the
catalogue with an empty "Maps to" cell and no tier because it is
**normalization, needed for scope correctness, not enrichment**. It maps to
nothing in the taxonomy, it produces no claim about an entity, and a name's
registrable domain can neither escalate nor suppress anything. It lives in this
module because the *mechanism* is the one this module is about — fetch on a
schedule, parse, write a snapshot-versioned reference table, join in SQL — and a
second module for one function that shares every rule with this one would be a
component that does not exist. `sql/migrations/0008_public_suffix_list.sql`
carries the argument and the derivation; this file is the writer.

The enrichment tier proper — ThreatFox first, per `concept/05` — is still
deferred, and so is every part of this module that *maps* anything to the
taxonomy.

**What does exist is the registry**: which sources this deployment knows, what
tier each one is, and the taxonomy subset each may emit. `concept/05`'s first
rule for every source adapter is *declare the subset it can emit, publish it,
version it, and test it*, and a declaration is worth having before the mapping
that has to satisfy it — the loader is then written against a published subset
rather than the subset being read back off whatever the loader happened to
produce. `SOURCES` is that declaration, `check_claim` is the test rule 1 asks
for, and `source_diversity` is normalization rule 2: an aggregator is never
counted as many votes.

**And the evidence row itself.** `EnrichmentEvidence` is one claim about one
entity from one source, and `helena_reference_enrichment_evidence` is the same
shape in the engine. Its key is a digest of the claim rather than
`(entity, source)`, because `docs/decisions/0009-netify-application-identification.md`
settled that the schema carries **N rows per entity** — Netify alone puts up to
75 claims on one address. `QueryFailure` is what a query that did not complete
produces instead: typed, bounded, and with nowhere to put a classification.

Reads: an HTTP(S) or `file:` URL supplied by the caller, through the standard
library. Writes: `helena_reference_public_suffix`,
`helena_reference_public_suffix_load` and — when a loader exists —
`helena_reference_enrichment_evidence`.

Maturity: experimental — the Public Suffix List loader and its failure paths are
exercised by `tests/test_enrichment.py`, against a real engine and against the
live list; the source registry and the diversity count by `tests/test_sources.py`;
the evidence row, its statuses and its identifier by `tests/test_evidence.py`,
including a round trip through the engine. Nothing has been enriched, no feed
loader exists, no claim has been made by anything, and no snapshot version has
reached an assessment.
"""

from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.request
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any

import psycopg
from pydantic import BaseModel, ConfigDict, Field

from helena import taxonomy
from helena.observability import Redactor

__all__ = [
    "DEFAULT_RULE",
    "DEFAULT_SECTION",
    "FAILURE_REASONS",
    "ICANN_SECTION",
    "LOAD_STATUSES",
    "PRIVATE_SECTION",
    "PUBLIC_SUFFIX_LOAD_TABLE",
    "PUBLIC_SUFFIX_TABLE",
    "PublicSuffixListError",
    "ENRICHMENT_EVIDENCE_TABLE",
    "ENRICHMENT_STATUSES",
    "ENTITY_TYPES",
    "MAX_FAILURE_DETAIL",
    "MISSING",
    "NO_MATCH",
    "OK",
    "QUERY_FAILED",
    "QUERY_FAILURE_REASONS",
    "STALE",
    "SOURCES",
    "Claim",
    "EnrichmentEvidence",
    "PublicSuffixLoad",
    "PublicSuffixRule",
    "QueryFailure",
    "SourceDescriptor",
    "SourceError",
    "Tier",
    "UndeclaredClaim",
    "check_claim",
    "evidence_id",
    "fetch_public_suffix_list",
    "load_public_suffix_list",
    "origins",
    "parse_public_suffix_list",
    "source",
    "source_diversity",
]

# The two tables migration 0008 creates. Named here so the loader and the tests
# say them once; the migration is the other copy and applying it is what proves
# the two agree.
PUBLIC_SUFFIX_TABLE = "helena_reference_public_suffix"
PUBLIC_SUFFIX_LOAD_TABLE = "helena_reference_public_suffix_load"

# The list's own section markers. Everything between BEGIN and END belongs to
# that section; a rule outside both is a defect in the file and is refused.
_BEGIN = {
    "// ===BEGIN ICANN DOMAINS===": "icann",
    "// ===BEGIN PRIVATE DOMAINS===": "private",
}
_END = {"// ===END ICANN DOMAINS===", "// ===END PRIVATE DOMAINS==="}

ICANN_SECTION = "icann"
PRIVATE_SECTION = "private"

# The algorithm's default rule, which is not a line in the published file:
# "If no rules match, the prevailing rule is '*'". It is stored as a row so that
# every valid name matches something — see the head of migration 0008 for why
# that distinction is load-bearing rather than tidy.
DEFAULT_RULE = "*"
DEFAULT_SECTION = "default"

# What a load attempt can end as. Never collapsed: `unchanged` is a successful
# fetch of a list that already is the current snapshot, and `failed` wrote
# nothing at all and left the previous snapshot in place.
LOADED = "loaded"
UNCHANGED = "unchanged"
FAILED = "failed"
LOAD_STATUSES = (LOADED, UNCHANGED, FAILED)

# The typed failures, one per way a load can end with nothing written.
#
#   fetch_failed    the URL did not yield bytes — no network, a 404, a timeout
#   malformed_rule  a line is not a rule the algorithm can use
#   empty_list      the fetch worked and parsed to no rules at all, which would
#                   silently make every name its own public suffix
FETCH_FAILED = "fetch_failed"
MALFORMED_RULE = "malformed_rule"
EMPTY_LIST = "empty_list"
FAILURE_REASONS = (FETCH_FAILED, MALFORMED_RULE, EMPTY_LIST)

# How long a fetch is given. A loader that hangs forever is a loader that never
# records a failure, and the failure is the point.
FETCH_TIMEOUT_SECONDS = 60.0

# Rows per INSERT. Measured against RisingWave 3.0.3 on the 2026-09-03 snapshot
# (10 781 rows): one statement per row through `executemany` took 15.9 s, and
# 500-row multi-row INSERTs took 1.2 s. The round trip is the cost, not the
# write.
INSERT_CHUNK_ROWS = 500


class PublicSuffixListError(ValueError):
    """A fetched list is not one this loader can use. Carries a typed reason.

    Raised by the parser and turned into a `failed` load row by
    `load_public_suffix_list`, which is the only caller that has a table to
    record it in.
    """

    def __init__(self, message: str, *, reason: str) -> None:
        if reason not in FAILURE_REASONS:
            raise ValueError(f"{reason!r} is not one of {FAILURE_REASONS}")
        super().__init__(message)
        self.reason = reason


@dataclass(frozen=True)
class PublicSuffixRule:
    """One match key of one rule.

    `rule` is the published line, markers and all. `suffix` is what the join in
    migration 0008 compares against a name's candidate labels: the same line
    with `*.` or `!` removed, and punycoded when the published form is not
    ASCII. A rule with non-ASCII labels therefore produces two of these, sharing
    a `rule` and differing in `suffix`, because a name may be observed in either
    form and the join is on bytes.
    """

    rule: str
    suffix: str
    is_wildcard: bool
    is_exception: bool
    section: str


class PublicSuffixLoad(BaseModel):
    """One row of `helena_reference_public_suffix_load`, as it was written.

    Frozen: it describes an attempt that has already happened. The model
    validates the invariants the table's columns only document — a failure names
    a reason and no snapshot, a success names a snapshot and no reason — so a
    loader that got them the wrong way round fails here rather than storing a row
    that reads as both.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    attempted_at: datetime
    source_url: str
    status: str
    snapshot_version: str | None
    rule_count: int | None
    failure_reason: str | None
    failure_detail: str | None

    def model_post_init(self, _context: object) -> None:
        if self.status not in LOAD_STATUSES:
            raise ValueError(f"status {self.status!r} is not one of {LOAD_STATUSES}")
        if self.status == FAILED:
            if self.failure_reason not in FAILURE_REASONS:
                raise ValueError(
                    f"a failed load names one of {FAILURE_REASONS}, "
                    f"not {self.failure_reason!r}"
                )
            if self.snapshot_version is not None:
                raise ValueError(
                    "a failed load wrote nothing, so it names no snapshot version"
                )
        else:
            if self.failure_reason is not None or self.failure_detail is not None:
                raise ValueError(
                    f"a {self.status} load carries no failure reason or detail"
                )
            if not self.snapshot_version:
                raise ValueError(f"a {self.status} load names the snapshot it read")


def fetch_public_suffix_list(url: str, *, timeout: float = FETCH_TIMEOUT_SECONDS) -> bytes:
    """The bytes at `url`, or a `PublicSuffixListError` with `fetch_failed`.

    Every transport failure becomes the same typed reason on purpose: from the
    loader's side, a 404, a DNS failure and a timeout are one thing — no bytes,
    so the previous snapshot stays. Which one it was is in the detail.

    `urllib` rather than an HTTP client library: `docs/decisions/0002-dependency-set.md`
    keeps `requests` and `httpx` deliberately absent, and one GET does not earn a
    dependency.
    """
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            return response.read()
    except (urllib.error.URLError, OSError, ValueError) as failure:
        raise PublicSuffixListError(
            f"{type(failure).__name__}: {failure}", reason=FETCH_FAILED
        ) from failure


def parse_public_suffix_list(raw: bytes) -> tuple[PublicSuffixRule, ...]:
    """The rules of a published list, plus the algorithm's default rule.

    Refuses rather than skips. A line this cannot read is a change in the
    publisher's format, which is exactly the thing a loader must surface —
    `concept/instruction.md` §2, "unknown fields are quarantined, not coerced" —
    and skipping it would quietly narrow the list until a name that should have
    been a public suffix no longer is.
    """
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as failure:
        raise PublicSuffixListError(
            f"the list is not UTF-8: {failure}", reason=MALFORMED_RULE
        ) from failure

    rules: list[PublicSuffixRule] = []
    section: str | None = None
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith("//"):
            if stripped in _BEGIN:
                section = _BEGIN[stripped]
            elif stripped in _END:
                section = None
            continue
        if not stripped:
            continue
        if section is None:
            raise PublicSuffixListError(
                f"line {number} is a rule outside both sections: {stripped!r}. "
                f"The section markers say which registry a rule belongs to, and "
                f"a rule with no section cannot be recorded as having one",
                reason=MALFORMED_RULE,
            )
        rules.extend(_rule(stripped, section, number))

    if not rules:
        raise PublicSuffixListError(
            "the list holds no rules; loading it would make every name its own "
            "public suffix",
            reason=EMPTY_LIST,
        )

    rules.append(
        PublicSuffixRule(
            rule=DEFAULT_RULE,
            suffix="",
            is_wildcard=True,
            is_exception=False,
            section=DEFAULT_SECTION,
        )
    )
    return tuple(rules)


def load_public_suffix_list(
    connection: psycopg.Connection,
    *,
    source_url: str,
    redactor: Redactor,
    now: datetime | None = None,
) -> PublicSuffixLoad:
    """Fetch the list, replace the snapshot, and record the attempt either way.

    Returns the load row it wrote. The row is written in every case, including
    the failures — a load that left no trace is a snapshot that silently ages.

    The order is: fetch, parse **completely**, then write. A parse failure
    therefore leaves the previous snapshot untouched rather than half-replaced,
    which is the whole reason parsing happens before the first INSERT.

    The replacement itself is insert-then-delete rather than delete-then-insert.
    RisingWave has no transaction around a write either (measured, task 04:
    an INSERT onto an existing key is a silent upsert), so one of the two orders
    has to be chosen for what its half-done state looks like: a superset of the
    rules for a moment, or an empty list for a moment. A superset makes a name's
    public suffix at worst a stale-but-real one; an empty list makes every name
    its own public suffix.

    `redactor` is not optional. `source_url` is recorded as provenance and
    `concept/instruction.md` §6 requires a credential in a URL to be redacted
    before anything is *stored*, not only before anything is logged.
    """
    attempted_at = now or datetime.now(timezone.utc)
    recorded_url = redactor.url(source_url)

    try:
        raw = fetch_public_suffix_list(source_url)
        rules = parse_public_suffix_list(raw)
    except PublicSuffixListError as failure:
        return _record(
            connection,
            PublicSuffixLoad(
                attempted_at=attempted_at,
                source_url=recorded_url,
                status=FAILED,
                snapshot_version=None,
                rule_count=None,
                failure_reason=failure.reason,
                failure_detail=redactor.text(str(failure)),
            ),
        )

    snapshot_version = hashlib.sha256(raw).hexdigest()
    if snapshot_version in _loaded_snapshots(connection):
        return _record(
            connection,
            PublicSuffixLoad(
                attempted_at=attempted_at,
                source_url=recorded_url,
                status=UNCHANGED,
                snapshot_version=snapshot_version,
                rule_count=None,
                failure_reason=None,
                failure_detail=None,
            ),
        )

    values = [
        (
            snapshot_version,
            rule.rule,
            rule.suffix,
            rule.is_wildcard,
            rule.is_exception,
            rule.section,
        )
        for rule in rules
    ]
    with connection.cursor() as cursor:
        for start in range(0, len(values), INSERT_CHUNK_ROWS):
            chunk = values[start : start + INSERT_CHUNK_ROWS]
            placeholders = ", ".join(["(%s, %s, %s, %s, %s, %s)"] * len(chunk))
            cursor.execute(
                f"INSERT INTO {PUBLIC_SUFFIX_TABLE} "
                f"(snapshot_version, rule, suffix, is_wildcard, is_exception, "
                f"section) VALUES {placeholders}",
                [value for row in chunk for value in row],
            )
        # Measured, and not optional: without it the DELETE below scans a state
        # the INSERTs have not reached and removes every row, new snapshot
        # included, leaving an empty table and no error. A rule present in both
        # snapshots is upserted onto its own key and so carries the new version
        # by the time the DELETE runs, which is what makes deleting by version
        # the right way to drop the rules that left.
        cursor.execute("FLUSH")
        cursor.execute(
            f"DELETE FROM {PUBLIC_SUFFIX_TABLE} WHERE snapshot_version <> %s",
            (snapshot_version,),
        )
    return _record(
        connection,
        PublicSuffixLoad(
            attempted_at=attempted_at,
            source_url=recorded_url,
            status=LOADED,
            snapshot_version=snapshot_version,
            rule_count=len(rules),
            failure_reason=None,
            failure_detail=None,
        ),
    )


def _rule(line: str, section: str, number: int) -> Iterator[PublicSuffixRule]:
    """One published line as the one or two match keys it matches by."""
    is_exception = line.startswith("!")
    body = line[1:] if is_exception else line
    is_wildcard = body.startswith("*.")
    suffix = body[2:] if is_wildcard else body

    if not suffix or any(label == "" for label in suffix.split(".")):
        raise PublicSuffixListError(
            f"line {number} has an empty label: {line!r}", reason=MALFORMED_RULE
        )
    if "*" in suffix or "!" in suffix or any(c.isspace() for c in suffix):
        raise PublicSuffixListError(
            f"line {number} is not a rule this loader understands: {line!r}. "
            f"A `*` is only ever the leftmost label and a `!` only ever the "
            f"first character",
            reason=MALFORMED_RULE,
        )
    if suffix != suffix.lower():
        raise PublicSuffixListError(
            f"line {number} is not lowercase: {line!r}. The join is on bytes and "
            f"the engine's lower() is ASCII-only, so a rule that is not already "
            f"folded would never match",
            reason=MALFORMED_RULE,
        )

    for key in _match_keys(suffix, line, number):
        yield PublicSuffixRule(
            rule=line,
            suffix=key,
            is_wildcard=is_wildcard,
            is_exception=is_exception,
            section=section,
        )


def _match_keys(suffix: str, line: str, number: int) -> tuple[str, ...]:
    """The forms a name may be observed in: as published, and punycoded.

    An all-ASCII rule has one key. A rule with a U-label has two, because a
    resolver, a TLS SNI and a URI host may each carry either form and the engine
    has no IDNA function to normalize them with.
    """
    if suffix.isascii():
        return (suffix,)
    try:
        encoded = ".".join(
            label
            if label.isascii()
            else "xn--" + label.encode("punycode").decode("ascii")
            for label in suffix.split(".")
        )
    except UnicodeError as failure:
        raise PublicSuffixListError(
            f"line {number} has a label that does not punycode: {line!r} "
            f"({failure})",
            reason=MALFORMED_RULE,
        ) from failure
    return (suffix, encoded)


def _loaded_snapshots(connection: psycopg.Connection) -> set[str]:
    """The snapshot versions the rules table currently holds.

    Normally one, and `tests/test_enrichment.py` asserts that. More than one
    means a load died between its INSERTs and its DELETE, and the next load
    replaces the lot.
    """
    connection.execute("FLUSH")
    return {
        row[0]
        for row in connection.execute(
            f"SELECT DISTINCT snapshot_version FROM {PUBLIC_SUFFIX_TABLE}"
        ).fetchall()
    }


def _record(
    connection: psycopg.Connection, load: PublicSuffixLoad
) -> PublicSuffixLoad:
    connection.execute(
        f"INSERT INTO {PUBLIC_SUFFIX_LOAD_TABLE} "
        f"(attempted_at, source_url, status, snapshot_version, rule_count, "
        f"failure_reason, failure_detail) VALUES (%s, %s, %s, %s, %s, %s, %s)",
        _columns(load),
    )
    connection.execute("FLUSH")
    return load


def _columns(load: PublicSuffixLoad) -> Sequence[object]:
    return (
        load.attempted_at,
        load.source_url,
        load.status,
        load.snapshot_version,
        load.rule_count,
        load.failure_reason,
        load.failure_detail,
    )


# --- The source registry: what a source is, and what it may say --------------
#
# `concept/02-concepts-and-taxonomy.md`: **the tier describes the source, not the
# entry.** It is what makes "deterministic signals escalate independently" a
# testable rule rather than a judgement call -- an escalation path that read a
# per-entry confidence would be a judgement about one row, and this is a standing
# statement about where the evidence comes from.
#
# `concept/05-threat-intelligence.md` §"What every source adapter must do" is the
# other half, and rule 1 is what this section implements: **declare the subset it
# can emit, publish it, version it, and test it.** Complete taxonomy coverage is
# explicitly not required -- "a source that only identifies phishing maps a hit to
# phishing, an explicit absence to `no_match`, and nothing else."
#
# **The Public Suffix List is deliberately not registered here**, and its absence
# is a statement rather than an omission. `concept/05` gives it an empty "Maps to"
# cell and a tier of **N/A rather than unassigned**: it is normalization needed for
# scope correctness, it makes no claim about any entity, and it can neither
# escalate nor suppress. A registry of claim-emitting sources is exactly what it is
# not in. The loader for it is in this module because the *mechanism* is shared;
# the registry is about claims, and it makes none.


class Tier(str, Enum):
    """Source tiers A-D, from `concept/02-concepts-and-taxonomy.md`.

    A `str` enum because a tier is written onto rows and read back out of them,
    and a second spelling of the same value is the drift the version rules exist
    to prevent.
    """

    #: "Direct behaviour or authoritative curated role -- confirmed payload
    #: delivery, C2, phishing page, validated malware configuration." May
    #: establish `malicious` by itself if scope and freshness are adequate, and
    #: **escalates independently of triage**.
    A = "A"
    #: "Explicit provider verdict or high-quality curated listing without full
    #: direct evidence." Usually malicious when high confidence, and
    #: **high-confidence B escalates independently**.
    B = "B"
    #: "Aggregated reputation, predictive risk, community report, one scanner,
    #: heuristic anomaly." Normally `suspicious`; two independent sources may
    #: raise confidence -- which is what `source_diversity` below counts.
    C = "C"
    #: "Passive DNS, certificate transparency, scan telemetry, co-occurrence."
    #: Context only: never escalates on its own.
    D = "D"

    @property
    def escalates_independently(self) -> bool:
        """Whether a claim from this tier may escalate without triage agreeing.

        `concept/instruction.md`: "Deterministic escalation is independent of
        triage. A `normal` from a model may not suppress a high-confidence
        match." The tier is what decides which claims that applies to, and it is
        a property here rather than a table elsewhere so the rule has one home.

        B is included and the condition on it -- *high* confidence -- is not
        expressible on a descriptor, because confidence belongs to the entry and
        the tier belongs to the source. The caller applies it; this says which
        tiers can reach the question at all.
        """
        return self in (Tier.A, Tier.B)


# The entity types an indicator can be about, from
# `concept/02-concepts-and-taxonomy.md` and matching the `entity_type` values
# `helena_signal_context_entities` produces -- a descriptor that named a fifth
# would declare coverage of something no context row can join to.
ENTITY_TYPES = frozenset({"address", "domain", "url", "fingerprint"})

# `concept/02`: "The source completed its query and returned no record. A lookup
# outcome, never a statement of safety." Named once, because every declared
# subset is required to contain it and two functions below compare against it.
NO_MATCH = "no_match"


class SourceError(Exception):
    """A source descriptor or a claim is not what the catalogue says one is."""


class UndeclaredClaim(SourceError):
    """A source emitted a path outside its declared subset.

    Its own error, because it means the mapping and the declaration have drifted
    apart -- not that the path is invalid. `concept/05` rule 1 requires the
    subset to be published, versioned and **tested**, and this is what a test has
    to be able to catch.
    """


@dataclass(frozen=True)
class SourceDescriptor:
    """One source: its tier, what it is about, and the subset it may emit.

    Frozen and validated on construction, so a descriptor that claims a taxonomy
    path its version does not have fails where it is written rather than where
    something tries to emit it.
    """

    source_id: str
    tier: Tier
    #: Which kinds of indicator this source is about. A claim about anything else
    #: is refused: a JA3 list has nothing to say about a domain.
    entity_types: frozenset[str]
    #: The evidence-level taxonomy paths this source may emit. `no_match` belongs
    #: in every subset -- `concept/05` rule 1 makes an explicit absence part of
    #: what a source reports, and `concept/02` is emphatic that `no_match` is a
    #: lookup outcome and never a statement of safety.
    emits: frozenset[str]
    #: The taxonomy version `emits` is drawn from. A subset is only meaningful
    #: against the vocabulary it was declared against.
    taxonomy_version: str
    #: The version of this declaration. It moves when the subset moves, so a
    #: stored claim can be read against the subset that was declared when it was
    #: made -- the same rule as every other version in this project.
    emit_subset_version: str
    #: True where this source republishes other sources' evidence.
    #: `concept/02`: "Evidence copied through an aggregator is not an independent
    #: vote; retain the origin and count source diversity. An aggregator is never
    #: counted as many votes."
    aggregator: bool = False
    #: What a reader has to know before trusting this source, recorded on the
    #: descriptor rather than in prose somewhere else. Empty where there is none.
    caveat: str = ""

    def __post_init__(self) -> None:
        if not self.source_id or self.source_id != self.source_id.strip():
            raise SourceError(f"{self.source_id!r} is not a source id")
        outside = self.entity_types - ENTITY_TYPES
        if outside:
            raise SourceError(
                f"{self.source_id}: entity types {sorted(outside)} are not among "
                f"{sorted(ENTITY_TYPES)}"
            )
        if not self.entity_types:
            raise SourceError(f"{self.source_id}: declares no entity types")
        if not self.emit_subset_version.strip():
            raise SourceError(f"{self.source_id}: the emit subset has no version")
        # Every declared path has to exist in the taxonomy version it names. This
        # is the join between `concept/05` rule 1 and `helena.taxonomy`: a
        # published subset that named a path the vocabulary does not have would
        # be a claim nothing could ever validate.
        for path in sorted(self.emits):
            taxonomy.resolve(path, level=taxonomy.EVIDENCE, version=self.taxonomy_version)
        if NO_MATCH not in self.emits:
            raise SourceError(
                f"{self.source_id}: {NO_MATCH!r} is not in the declared subset. "
                f"A source reports an explicit absence as well as a hit "
                f"(concept/05, 'What every source adapter must do', rule 1)."
            )

    def declares(self, path: str) -> bool:
        return path in self.emits


# The registry. Two entries, and both are in `concept/05`'s catalogue with the
# tier written there rather than chosen here.
SOURCES: dict[str, SourceDescriptor] = {
    "threatfox": SourceDescriptor(
        source_id="threatfox",
        tier=Tier.B,
        entity_types=frozenset({"address", "domain", "url"}),
        # `concept/05`: "C2 and malware delivery, by threat type". **By threat
        # type** is the part v1 cannot express: the evidence level is roots-only
        # there, because `concept/02` adopts it from a published indicator
        # taxonomy it neither names nor reproduces (see `helena/taxonomy/v1.py`).
        # So the declared subset is the root, which is a supported and true
        # answer, and the threat-type children arrive with the loader that can
        # say what they are -- in a taxonomy v2 and a new subset version here.
        emits=frozenset({"malicious", NO_MATCH}),
        taxonomy_version="v1",
        emit_subset_version="v1",
        aggregator=False,
    ),
    "sslbl-ja3": SourceDescriptor(
        source_id="sslbl-ja3",
        tier=Tier.C,
        entity_types=frozenset({"fingerprint"}),
        # `concept/05` maps it to "Malware, or a single low-confidence
        # detection", and tier C is "normally `suspicious`". `malicious` is not
        # in the subset and the caveat below is why: a list that its own
        # publisher says is untested against known-good traffic cannot establish
        # that a fingerprint performed malicious activity. A hit is a material
        # risk signal, which is what `suspicious` means.
        emits=frozenset({"suspicious", NO_MATCH}),
        taxonomy_version="v1",
        emit_subset_version="v1",
        aggregator=False,
        caveat=(
            "Under a hundred fingerprints, first seen years ago and static since "
            "2021, carrying the publisher's own statement that they are untested "
            "against known-good traffic and may cause significant false "
            "positives. A historical artifact rather than a feed: it cannot "
            "improve by being refreshed, because it is not being refreshed. "
            "Whether it earns its place is open, and the sharper half of that "
            "question is what a no_match against it may be taken to mean "
            "(concept/05-threat-intelligence.md)."
        ),
    ),
}


def source(source_id: str) -> SourceDescriptor:
    """The descriptor for `source_id`, or a `SourceError` naming what is registered."""
    try:
        return SOURCES[source_id]
    except KeyError:
        raise SourceError(
            f"no source {source_id!r} is registered; the catalogue holds "
            f"{sorted(SOURCES)}. Adding one is a governed decision "
            f"(concept/05-threat-intelligence.md), not a configuration change."
        ) from None


@dataclass(frozen=True)
class Claim:
    """One source's statement about one indicator, with its origin retained.

    `origin` is `concept/05` rule 7 and `concept/02` normalization rule 2: where
    the evidence actually came from, when this source is republishing somebody
    else's. `None` means the source is speaking for itself, which is the only
    thing a non-aggregator may do.
    """

    source_id: str
    entity_type: str
    entity_value: str
    path: str
    origin: str | None = None

    @property
    def attributed_to(self) -> str:
        """Who this claim is evidence *from* -- the origin where there is one.

        The one place the aggregator rule turns into a value. Two claims that
        resolve to the same name are one vote however many sources carried them.
        """
        return self.origin or self.source_id


def check_claim(claim: Claim) -> Claim:
    """Refuse a claim a source did not declare it could make. Returns the claim.

    The check `concept/05` rule 1 means by "test it": a mapping that starts
    emitting a path outside the published subset is a drift between the mapping
    and its declaration, and it is caught here rather than downstream where it
    would look like a taxonomy question.
    """
    descriptor = source(claim.source_id)
    if claim.entity_type not in descriptor.entity_types:
        raise UndeclaredClaim(
            f"{claim.source_id} claims about a {claim.entity_type!r} and declares "
            f"{sorted(descriptor.entity_types)}"
        )
    # Valid in the taxonomy first, so an invalid path is a taxonomy error and a
    # valid-but-undeclared one is a source error. Two facts, two errors.
    taxonomy.resolve(
        claim.path, level=taxonomy.EVIDENCE, version=descriptor.taxonomy_version
    )
    if not descriptor.declares(claim.path):
        raise UndeclaredClaim(
            f"{claim.source_id} emitted {claim.path!r}, which is outside its "
            f"declared subset {sorted(descriptor.emits)} "
            f"(subset {descriptor.emit_subset_version})"
        )
    if claim.origin is not None and not descriptor.aggregator:
        raise UndeclaredClaim(
            f"{claim.source_id} is not an aggregator and carries evidence "
            f"attributed to {claim.origin!r}; a source that republishes another's "
            f"evidence is declared as an aggregator or it is misattributing"
        )
    return claim


def source_diversity(claims: Sequence[Claim]) -> int:
    """How many independent sources these claims represent.

    `concept/02` normalization rule 2: *"Do not double-count correlated sources.
    Evidence copied through an aggregator is not an independent vote; retain the
    origin and count source diversity. An aggregator is never counted as many
    votes."*

    So the count is over `attributed_to` and not over `source_id`, and three
    consequences fall out of that rather than needing rules of their own:

    * one source making forty claims is **one**;
    * an aggregator republishing forty entries with no origin retained is
      **one** -- it is one source's opinion however many rows it has;
    * the same origin reaching us directly *and* through an aggregator is
      **one**, which is the correlated-source case the rule is actually about.

    This is the number tier C's "two independent sources may raise confidence"
    is counted with. It is deliberately not a confidence, a score or a verdict:
    it is a count, and what to do with it belongs to whatever is escalating.
    """
    return len({claim.attributed_to for claim in claims})


def origins(claims: Sequence[Claim]) -> dict[str, list[Claim]]:
    """The claims grouped by who they are evidence from, origin retained.

    `source_diversity` is the count; this is what it counted, because a number
    with no way to see what went into it cannot be argued with -- and
    `concept/05` rule 6 requires contradictions to survive to the agent rather
    than being collapsed on the way.
    """
    grouped: dict[str, list[Claim]] = {}
    for claim in claims:
        grouped.setdefault(claim.attributed_to, []).append(claim)
    return grouped


# --- Enrichment evidence: one claim, and the four ways there is no claim ------
#
# `concept/02-concepts-and-taxonomy.md` defines the row: *"One claim about one
# entity from one source: the classification, its confidence, its scope, its
# snapshot, its tier, its status."* And it defines what a successful query
# normalizes into -- *"`verdict`, `classification`, `confidence`, `scope`
# (`{type, value}`, exactly normalized), `time` (nullable first-seen / last-seen
# / valid-until -- do not invent missing precision), and `evidence` (the minimal
# native fields that justify the mapping)."*
#
# **The key is not `(entity, source)`, and that is a correction rather than a
# choice.** `concept/02`'s line was once read as a cardinality constraint, and
# `docs/decisions/0009-netify-application-identification.md` settled that it is
# not: *"the evidence schema carries N rows per entity, not one row per (entity,
# source) holding a collapsed set"*, because Netify alone puts **up to 75 claims
# on a single address**, and a loader keyed by address silently discarded 124 653
# rows in a first draft of that measurement. `concept/02` now says so directly:
# *"An entity carries as many claims as its sources and their values produce --
# multiplicity is evidence for the agent to weigh, never something to collapse
# before it is seen."* So the row is keyed by a digest of the claim, and two
# genuinely different claims from one source about one entity are two rows.
#
# **`verdict` is derived and not stored.** It is the root of the classification
# path, `helena.taxonomy` already refuses a path whose root is not its first
# segment, and a second column holding the same fact is a column that can
# disagree with the one it was copied from. The six-field contract is satisfied
# at the object -- `EnrichmentEvidence.verdict` is there -- without a stored
# duplicate that nothing keeps in step.


#: `concept/02`: "`ok` / `stale` / `failed` / `missing` -- each **distinct from
#: `no_match`**." `concept/instruction.md` makes that five things that may never
#: be collapsed, at any layer, for any reason: a typed error is the fifth.
#:
#:   ok       the source was queried and answered, and there is a claim. The
#:            claim may be `no_match`, which is an answer and not an absence.
#:   stale    the snapshot is older than this source's own refresh window. The
#:            claim stands and its age is now part of what it is worth.
#:   failed   the query ran and did not complete. There is a typed error and no
#:            taxonomy object.
#:   missing  no snapshot exists to query at all -- the feed has never loaded,
#:            or its table is empty. Not a source that found nothing.
OK = "ok"
STALE = "stale"
QUERY_FAILED = "failed"
MISSING = "missing"
ENRICHMENT_STATUSES = (OK, STALE, QUERY_FAILED, MISSING)

#: Why a query did not complete. Typed, because `concept/05` rule 4 turns on the
#: distinction: *"Emit a typed error on failure, and no taxonomy object. A
#: timeout is never `no_match` and never `unknown`."* Both of those are analysis
#: results returned after a **successful** query.
TIMEOUT = "timeout"
QUOTA_EXHAUSTED = "quota_exhausted"
AUTH_FAILED = "auth_failed"
TRANSPORT_ERROR = "transport_error"
MALFORMED_RESPONSE = "malformed_response"
QUERY_FAILURE_REASONS = (
    TIMEOUT,
    QUOTA_EXHAUSTED,
    AUTH_FAILED,
    TRANSPORT_ERROR,
    MALFORMED_RESPONSE,
)

ENRICHMENT_EVIDENCE_TABLE = "helena_reference_enrichment_evidence"

#: How long a `detail` may be. Bounded because an unbounded diagnostic string is
#: where a provider response ends up: somebody pastes `str(response)` in, and the
#: row now holds the body `QueryFailure` exists to keep out.
MAX_FAILURE_DETAIL = 500


class QueryFailure(BaseModel):
    """A query that did not complete. Compact, typed, and carrying no payload.

    `concept/05` rule 4 and `concept/02`: a timeout, quota exhaustion or an auth
    failure **never becomes `no_match`** and never becomes `unknown` -- both of
    those are valid analysis results returned after a *successful* query -- and
    *"the error object stays compact and never carries secrets, authorization
    headers or full provider responses."*

    That last rule is enforced by the shape rather than by review. There is no
    field a response body can go in: `reason` is one of five typed values,
    `detail` is bounded, and `extra="forbid"` means a caller cannot add
    `response` or `headers` to the object at all. `tests/test_evidence.py`
    asserts the field set, so adding one is a deliberate act with a test to
    change rather than a field that appears.

    It has **no classification and no confidence**, and that is the point: an
    object that could carry either would be a taxonomy object emitted on failure,
    which is exactly what rule 4 forbids.
    """

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    source_id: str
    entity_type: str
    entity_value: str
    reason: str
    #: What went wrong, in words, for an operator. Never a provider response,
    #: never a header, never a credential -- see the class docstring.
    detail: str = ""

    def model_post_init(self, _context: object) -> None:
        if self.reason not in QUERY_FAILURE_REASONS:
            raise ValueError(
                f"reason {self.reason!r} is not one of {QUERY_FAILURE_REASONS}"
            )
        if len(self.detail) > MAX_FAILURE_DETAIL:
            raise ValueError(
                f"detail is {len(self.detail)} characters and the limit is "
                f"{MAX_FAILURE_DETAIL}; a diagnostic is a sentence, and an "
                f"unbounded one is where a provider response ends up"
            )
        if self.entity_type not in ENTITY_TYPES:
            raise ValueError(
                f"entity type {self.entity_type!r} is not among {sorted(ENTITY_TYPES)}"
            )


class EnrichmentEvidence(BaseModel):
    """One claim about one entity from one source, as a source normalized it.

    Frozen: a claim describes a query that has already happened.

    **`confidence` is confidence in the mapping, not the probability that the
    indicator is malicious.** `concept/02` says so in as many words and gives the
    consequence that makes it checkable: *"A definitive negative answer can be
    `no_match` with confidence `1.0`."* A field read as P(malicious) would make
    that combination nonsense, and a consumer that averaged it across sources
    would be averaging two different quantities. It is also **not** the tier: the
    tier is about the *source* and this is about *this mapping of this entry*.

    **The time fields are nullable and stay that way.** `concept/05` measured
    that references and last-seen dates are frequently absent, so *"first-seen
    plus the snapshot version is what dates a claim"* and missing precision is
    never invented -- a `last_seen` defaulted to the load time would make every
    stale claim look fresh, which is the failure the `stale` status exists to
    make visible.

    **A bad classification raises `TaxonomyError`, not `ValidationError`.** Every
    other refusal below raises `ValueError` and Pydantic turns it into a
    validation error about a field; a path the vocabulary does not have is not a
    malformed field but a taxonomy fact, and `helena.taxonomy` already tells "not
    in the vocabulary" apart from "declared but unused". Flattening both into one
    field error would lose that at the first caller, which is
    `concept/instruction.md` §2's rule about two facts and one value.
    """

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    #: The stable identifier: a digest of the claim, so replaying a load writes
    #: the same row and two genuinely different claims are two rows. See
    #: `evidence_id`.
    evidence_id: str
    source_id: str
    source_tier: Tier
    #: The feed snapshot this claim came from. `concept/02`: replay joins the
    #: snapshot current at event time, not today's.
    snapshot_version: str
    entity_type: str
    entity_value: str
    status: str
    #: The taxonomy path, present only when the source answered. `None` for every
    #: other status, because `concept/05` rule 4 forbids a taxonomy object where
    #: there was no successful query -- and because `stale` carries its claim on
    #: a row of its own rather than by reusing this one.
    classification: str | None = None
    taxonomy_version: str | None = None
    confidence: float | None = None
    #: `scope` -- `{type, value}`, exactly normalized. What the claim is *about*,
    #: which is not always the entity it attaches to: a URL claim scopes to the
    #: URL and `concept/05` says the host inherits "only with host-level
    #: evidence", and a Spamhaus DROP claim scopes to a netblock or an ASN and
    #: "never a host". Two columns rather than a JSON blob, because the scope is
    #: what the composition rule reads.
    scope_type: str
    scope_value: str
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    valid_until: datetime | None = None
    #: The minimal native fields that justify the mapping -- `concept/05` rule 5,
    #: "retain the native payload for audit". Minimal is the operative word: it
    #: is what justifies *this* mapping, not the provider's whole response.
    native_evidence: dict[str, Any] = Field(default_factory=dict)

    def model_post_init(self, _context: object) -> None:
        if self.status not in ENRICHMENT_STATUSES:
            raise ValueError(
                f"status {self.status!r} is not one of {ENRICHMENT_STATUSES}. "
                f"`no_match` is a classification and never a status."
            )
        if self.entity_type not in ENTITY_TYPES:
            raise ValueError(
                f"entity type {self.entity_type!r} is not among {sorted(ENTITY_TYPES)}"
            )
        has_claim = self.classification is not None
        if self.status in (OK, STALE) and not has_claim:
            raise ValueError(
                f"status {self.status!r} means the source answered, and there is "
                f"no classification. An answer of 'nothing listed' is the "
                f"classification 'no_match', not an absent one."
            )
        if self.status in (QUERY_FAILED, MISSING) and has_claim:
            raise ValueError(
                f"status {self.status!r} carries classification "
                f"{self.classification!r}; a query that did not complete emits a "
                f"typed error and no taxonomy object (concept/05, rule 4)"
            )
        if has_claim:
            if self.taxonomy_version is None:
                raise ValueError(
                    "a classification without a taxonomy version cannot be "
                    "replayed: nothing says which vocabulary it was drawn from"
                )
            taxonomy.resolve(
                self.classification,
                level=taxonomy.EVIDENCE,
                version=self.taxonomy_version,
            )
        if self.confidence is not None and not 0.0 <= self.confidence <= 1.0:
            raise ValueError(
                f"confidence {self.confidence} is outside 0.0-1.0"
            )
        if not self.scope_type.strip() or not self.scope_value.strip():
            raise ValueError(
                "scope is {type, value} and both are required: what a claim is "
                "about is what the composition rule reads"
            )

    @property
    def verdict(self) -> str | None:
        """The root of the classification -- derived, never stored.

        `concept/02` lists `verdict` among the six normalized fields, and the
        taxonomy already refuses a path whose root is not its first segment. A
        stored column would be a second copy of a fact that cannot disagree in
        the model and can in a table.
        """
        return None if self.classification is None else self.classification.split(".")[0]

    @property
    def dated_by(self) -> str:
        """What dates this claim: `concept/05`'s rule, as a value.

        *"Recency cannot be read from last-seen alone, so first-seen plus the
        snapshot version is what dates a claim."* Returned as text because it is
        for a reader and an operator, not for arithmetic.
        """
        seen = "unknown first-seen" if self.first_seen is None else self.first_seen.isoformat()
        return f"{seen} in snapshot {self.snapshot_version}"


def evidence_id(
    *,
    tenant: str,
    sensor: str,
    source_id: str,
    snapshot_version: str,
    entity_type: str,
    entity_value: str,
    classification: str | None,
    scope_type: str,
    scope_value: str,
    native_evidence: Mapping[str, Any],
) -> str:
    """The stable identifier for one claim: a digest over what makes it that claim.

    Deterministic and drawn from nothing that changes on a replay, for the reason
    `helena.normalizer._event_id` gives: re-running a load has to write the same
    row rather than a second copy of it, and a RisingWave INSERT onto an existing
    key is a silent upsert.

    **The native evidence is in the digest**, and it has to be. Netify puts up to
    75 claims on one address, and they differ *only* in the application they
    name; a digest over source, snapshot and entity alone would make those 75 one
    row and silently keep the last. That is the exact discard
    `docs/decisions/0009-netify-application-identification.md` measured.

    **Tenant and sensor are in it** for the reason the event id has them: two
    deployments enriching the same entity would otherwise mint the same id in one
    store, and the upsert would be a cross-tenant overwrite that looks like it is
    working.

    **The status is not in it.** A claim that goes stale is the same claim; its
    status is what this deployment currently thinks of it, not part of which
    claim it is. Putting it in the digest would mint a new row every time a
    snapshot aged.
    """
    material = b"".join(
        _length_prefixed(part)
        for part in (
            tenant,
            sensor,
            source_id,
            snapshot_version,
            entity_type,
            entity_value,
            "" if classification is None else classification,
            scope_type,
            scope_value,
            # Canonical: sorted keys, no incidental whitespace, so two equal
            # payloads written by two loaders hash the same.
            json.dumps(native_evidence, sort_keys=True, separators=(",", ":")),
        )
    )
    return hashlib.sha256(material).hexdigest()


def _length_prefixed(value: str) -> bytes:
    """`value` as its UTF-8 length, a colon, then its UTF-8 bytes.

    The same construction `helena.normalizer` uses, and for the same reason: a
    digest over concatenated fields with no lengths in it collides whenever two
    fields can borrow a character from each other.
    """
    encoded = value.encode("utf-8")
    return f"{len(encoded)}:".encode() + encoded
