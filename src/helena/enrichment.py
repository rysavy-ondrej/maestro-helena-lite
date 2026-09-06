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

**ThreatFox is loaded.** `concept/05`'s "the first version loads exactly one
feed" is `load_threatfox` below: fetch the structured export, flatten it, map it
to claims and replace the snapshot, with every attempt — including the failures —
recorded in `helena_reference_threatfox_load`. Its section head carries what was
measured against the real export and when, because the ratios that shape the
loader are properties of a feed that will move.

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
entity from one source. It is a **derived** shape, not a stored one: each feed's
loader writes its own reference table and a mapping view in
`sql/migrations/0014_feed_mapping_views.sql` turns that into
`helena_reference_evidence` — `concept/03-architecture.md`'s "SQL mapping and
join views turning reference tables into enrichment evidence. **No runtime
service.**" A loader that assembled the evidence shape itself would be a second
implementation of the contract per feed, which is how the second feed's rows come
out subtly different from the first's.

Its identifier is a digest of the claim rather than `(entity, source)`, because
`docs/decisions/0009-netify-application-identification.md` settled that the schema
carries **N rows per entity** — Netify alone puts up to 75 claims on one address.
`QueryFailure` is what a query that did not complete produces instead: typed,
bounded, and with nowhere to put a classification.

**Snapshot versioning is the provenance story for the static tier.** Every load
attempt of every feed writes a row to `helena_reference_feed_snapshot` —
including the failures, because a fetch failure, a format change or an empty
response leaves the previous snapshot in place and is *recorded*, never a silent
empty opinion. Loading does not delete the snapshot before it: a claim records
the snapshot it matched against and replay joins *that* one, so `prune_snapshots`
is a deliberate call rather than a side effect. `feed_status` derives `ok` /
`stale` / `missing`, which are three different things and none of them is
`no_match`.

Reads: an HTTP(S) or `file:` URL supplied by the caller, through the standard
library. Writes: `helena_reference_public_suffix`,
`helena_reference_public_suffix_load`, `helena_reference_enrichment_evidence` and
`helena_reference_feed_snapshot`.

Maturity: experimental — the Public Suffix List loader and its failure paths are
exercised by `tests/test_enrichment.py`, against a real engine and against the
live list; the source registry and the diversity count by `tests/test_sources.py`;
the evidence row, its statuses and its identifier by `tests/test_evidence.py`,
including a round trip through the engine; the ThreatFox loader by
`tests/test_threatfox.py`, against a real engine and a committed extract of a
real export; snapshot versioning, the three failure modes and the derived
statuses by `tests/test_snapshots.py`; the mapping views, the identifier's two
homes and the tiers by `tests/test_mapping.py`, every one of them against a real
engine. What has NOT happened: no context has been
enriched — the join is a view that does not exist yet — and no snapshot version
has reached an assessment.
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
from psycopg.types.json import Jsonb
from pydantic import BaseModel, ConfigDict, Field

from helena import taxonomy
from helena.observability import Redactor

__all__ = [
    "Claim",
    "DEFAULT_RULE",
    "DEFAULT_SECTION",
    "EMPTY_EXPORT",
    "ENRICHMENT_EVIDENCE_VIEW",
    "ENRICHMENT_STATUSES",
    "ENTITY_TYPES",
    "EnrichmentEvidence",
    "FAILURE_REASONS",
    "FEED_REFERENCE_TABLES",
    "FEED_SNAPSHOT_CURRENT_VIEW",
    "FEED_SNAPSHOT_TABLE",
    "FeedSnapshot",
    "FeedStatus",
    "ICANN_SECTION",
    "LOAD_STATUSES",
    "MALFORMED_EXPORT",
    "MAX_FAILURE_DETAIL",
    "MISSING",
    "NO_MATCH",
    "OK",
    "PRIVATE_SECTION",
    "PUBLIC_SUFFIX_LOAD_TABLE",
    "PUBLIC_SUFFIX_TABLE",
    "PublicSuffixListError",
    "PublicSuffixLoad",
    "PublicSuffixRule",
    "QUERY_FAILED",
    "QUERY_FAILURE_REASONS",
    "QueryFailure",
    "SNAPSHOTS_KEPT",
    "SOURCES",
    "STALE",
    "SourceDescriptor",
    "SourceError",
    "THREATFOX_ENTITY_TYPES",
    "THREATFOX_FAILURE_REASONS",
    "THREATFOX_MIN_FETCH_INTERVAL_SECONDS",
    "THREATFOX_REFERENCE_TABLE",
    "THREATFOX_SOURCE",
    "THREATFOX_THREAT_TYPES",
    "THREATFOX_UNSEEN_THREAT_TYPE",
    "ThreatFoxEntry",
    "ThreatFoxError",
    "ThreatFoxRow",
    "ThreatFoxSnapshot",
    "Tier",
    "UndeclaredClaim",
    "check_claim",
    "classify_threat_type",
    "evidence_id",
    "feed_status",
    "fetch_public_suffix_list",
    "fetch_threatfox",
    "load_public_suffix_list",
    "load_threatfox",
    "origins",
    "parse_public_suffix_list",
    "parse_threatfox",
    "prune_snapshots",
    "source",
    "source_diversity",
    "split_indicator",
    "threatfox_rows",
    "threatfox_snapshot_version",
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

# `concept/05` puts fetch limits under "policy the tool layer enforces, not an
# afterthought", and the recent export is a rolling window rather than a
# firehose. Hourly is the floor a scheduler is expected to respect; nothing here
# schedules anything, and a scheduler with its own state would be a second store.
# It sits with the registry rather than in the ThreatFox section below because
# the descriptor is what carries a source's schedule -- see `refresh_interval_seconds`.
THREATFOX_MIN_FETCH_INTERVAL_SECONDS = 3600


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
    #: How often this feed publishes, in seconds -- the feed's OWN schedule and
    #: not a polling preference. `concept/05` puts fetch limits under "policy the
    #: tool layer enforces, not an afterthought", and it is also what `stale` is
    #: measured against: a snapshot older than the interval is one the source has
    #: already replaced. `None` for a source with no schedule to be late against.
    refresh_interval_seconds: int | None = None
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
        # The recent export "regenerates every few minutes and is a rolling
        # window, not a cumulative archive". An hour is the floor `concept/05`'s
        # fair-use terms imply for fetching, and a snapshot older than that is
        # one the publisher has already moved past.
        refresh_interval_seconds=THREATFOX_MIN_FETCH_INTERVAL_SECONDS,
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
        # No schedule: `concept/05` records that this list has been **static
        # since 2021**. A refresh interval would make it permanently stale and
        # say something false -- it is not late, it is finished. What is wrong
        # with it is in the caveat, not in its age.
        refresh_interval_seconds=None,
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

# The evidence shape is a VIEW over each feed's reference table, not a table a
# loader writes -- `sql/migrations/0014_feed_mapping_views.sql` and
# `concept/03-architecture.md`'s "Enrichment views" row. What a loader writes is
# its own reference table.
ENRICHMENT_EVIDENCE_VIEW = "helena_reference_evidence"
THREATFOX_REFERENCE_TABLE = "helena_reference_threatfox"

# Which table a source's snapshots live in, so pruning does not need a branch per
# feed. A source with no entry here has no loader yet.
FEED_REFERENCE_TABLES = {"threatfox": THREATFOX_REFERENCE_TABLE}
FEED_SNAPSHOT_TABLE = "helena_reference_feed_snapshot"
FEED_SNAPSHOT_CURRENT_VIEW = "helena_reference_feed_snapshot_current"

# How many snapshots of one source to keep when `prune_snapshots` is called.
# More than one, because replay joins the snapshot a claim recorded rather than
# today's (`concept/02`); a number rather than "all", because the recent export
# is thousands of claims every hour. Three is a candidate and not a decision --
# what it should be is a function of how far back replay has to reach, which is
# an open question (`concept/08-open-questions.md`) rather than a value anyone
# has measured.
SNAPSHOTS_KEPT = 3

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
    native_record: str,
) -> str:
    """The stable identifier for one claim: a digest over what makes it that claim.

    Deterministic and drawn from nothing that changes on a replay, for the reason
    `helena.normalizer._event_id` gives: re-running a load has to write the same
    row rather than a second copy of it, and a RisingWave INSERT onto an existing
    key is a silent upsert.

    **The native record is in the digest**, and it has to be. Netify puts up to
    75 claims on one address, and they differ *only* in the application they
    name; a digest over source, snapshot and entity alone would make those 75 one
    row and silently keep the last. That is the exact discard
    `docs/decisions/0009-netify-application-identification.md` measured.

    `native_record` is the **publisher's own identifier** for the record -- for
    ThreatFox, its `indicator_id` and the offset within the list that id keys.
    Not a digest of the payload: the publisher's key is stable across snapshots
    and is what the publisher means by "this record", where a payload digest
    would mint a new identifier every time a field nobody reads changed.

    This is the second home of the construction in
    `sql/migrations/0014_feed_mapping_views.sql`, which is what actually produces
    the identifier. `tests/test_mapping.py` asserts the two agree on a row read
    out of the engine, rather than either being believed.

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
            native_record,
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


# --- ThreatFox: the first feed ----------------------------------------------
#
# `concept/05-threat-intelligence.md`: *"The first version loads exactly one
# feed: ThreatFox."* Everything below was measured against the real export
# rather than read off a documentation page, and the measurements are dated
# because the feed is not ours and will move.
#
# **The loader holds no credential.** Measured 2026-09-06, and the second time
# this has been measured rather than assumed: `GET
# threatfox.abuse.ch/export/json/recent/` returns **200 with no credential at
# all**, while `POST threatfox-api.abuse.ch/api/v1/` returns **401** without an
# `Auth-Key` header. Until 2026-09-03 the concept note said the bulk export
# carried a key **in the URL path**; it was wrong, it is corrected there, and
# building a loader around a key this endpoint does not want would have created
# the exact leak the redaction rule exists to prevent. The redactor is still
# applied to the recorded URL, because that rule is about the channel -- an
# exception carrying a request URL leaks whatever was in it -- and not about this
# provider.
#
# **Re-measure before trusting this.** abuse.ch changes its auth on its own
# schedule, and a bulk export that is open today may not be tomorrow. Probe with
# status codes; never by printing a key.
#
# ## What the real export looks like, measured 2026-09-06 over 4 985 entries
#
# | Property | Measured | What it forces |
# | --- | --- | --- |
# | Top level is an object keyed by indicator id, values are **lists** | 4 985 keys, every list length 1 *in this snapshot* | Flatten. Reading `[0]` is `concept/instruction.md` §6's named trap, and "length 1 today" is not a schema |
# | `ip:port` indicators | 3 139 of 4 985 (63 %), **596 distinct ports** | Split and keep the port -- a C2 on one port matched against a host that contacted another is a weaker claim |
# | `is_compromised` | 821 (16.5 %) | Common, not rare. Native evidence, never the classification |
# | `confidence_level` | genuinely spread: 49, 50, 75, 80, 90, 95, 100 | Let it reach the claim; flattening it discards the only per-entry signal there is |
# | `reference` absent | 4 006 (80.4 %) | Per-entry evidence often does not exist |
# | `last_seen_utc` absent | 961 (19.3 %); `first_seen_utc` absent 0 | **first-seen plus the snapshot version dates a claim** |
# | `tags` | a comma-delimited string, absent on 443 (8.9 %) | Split it; it is not an array |
# | File-hash indicators | 452 (9.1 %) -- `sha256_hash`, `md5_hash`, `sha1_hash` | **Skipped and counted.** See below |
#
# ## File hashes have no entity here, and are counted rather than dropped
#
# ThreatFox reports file hashes. HELENA's entity types are `address`, `domain`,
# `url` and `fingerprint`, and a `fingerprint` is a TLS JA3/JA4 -- a property of
# a connection -- not a file digest. There is nothing in a host context for a
# file hash to attach to, so those entries cannot become claims.
#
# They are **skipped and counted**, never silently discarded: the count is on the
# load row, so "the loader stored 4 533 of 4 985 entries" is a fact an operator
# can see rather than a discrepancy somebody notices later. `concept/instruction.md`
# §7 requires produced-versus-materialised counts to reconcile, and a skip nobody
# counted is exactly how that stops being possible.
#
# ## Every threat type maps to `malicious`, and that is not laziness
#
# `concept/05` adopts the evidence level "essentially unchanged from an existing
# published indicator taxonomy, **so that HELENA's evidence stays comparable with
# other tools' rather than re-deriving a vocabulary from the same providers**."
#
# Deriving `malicious.c2` from ThreatFox's `botnet_cc` would be re-deriving a
# vocabulary from a provider -- the precise thing that sentence exists to
# prevent. So the mapping table below emits the **root**, which
# `concept/02-concepts-and-taxonomy.md` calls the right answer for a type the
# vocabulary cannot express: *"emit the parent rather than guessing a child."*
# The threat type itself is retained as native evidence, so nothing is lost and
# an agent can read it.
#
# The table is still worth having explicitly and still worth unit-testing, for
# three reasons that have nothing to do with its current values: it records which
# threat types have been **seen and considered**, an unseen one is **counted** so
# the source's vocabulary drifting surfaces instead of passing silently, and it
# is where children attach on the day the published taxonomy is in this
# repository and a `v2` can carry them.

THREATFOX_SOURCE = "threatfox"

# **The export URL is not in this package**, and that is enforced rather than
# remembered: `tests/test_broker.py::test_no_module_in_the_package_holds_a_broker_address`
# refuses an address-shaped literal anywhere under `helena/`. It lives in
# `scripts/load_threatfox.py` and nowhere else, for the reason
# `concept/05-threat-intelligence.md` opens with -- *"adding a source is a
# governed decision, not a configuration convenience"* -- and a URL in the
# package or in the environment is exactly that convenience.
#
# Which export it must be is a decision rather than a detail, and it belongs
# beside the URL: take the **structured** export and not the RPZ or hosts-file
# variants, "which drop exactly the distinctions the composition rule needs".
# Neither of those carries a port, a confidence, a threat type or the compromised
# flag, and the port is the difference between a C2 claim that matches a host's
# traffic and one that does not.

#: ThreatFox `ioc_type` -> the HELENA entity type it becomes. A type absent from
#: this map has no entity to attach to and is skipped and counted -- see above.
THREATFOX_ENTITY_TYPES = {
    "ip:port": "address",
    "domain": "domain",
    "url": "url",
}

#: ThreatFox `threat_type` -> an evidence-level taxonomy path. Every known type
#: maps to the root, for the reason above. The value of the table is that it
#: names what has been seen, so an unseen type is a counted event rather than a
#: silent default.
#:
#: Measured 2026-09-06: `botnet_cc` 4 084, `payload` 452, `payload_delivery` 447,
#: `cc_skimming` 2. `concept/05` warns the real vocabulary is larger than any
#: sample, which is why the unseen case is a rule and not an oversight.
THREATFOX_THREAT_TYPES = {
    "botnet_cc": "malicious",
    "payload": "malicious",
    "payload_delivery": "malicious",
    "cc_skimming": "malicious",
}

#: What an unseen threat type emits. `concept/02`: *"a mapping with a threat type
#: it has never seen emits `malicious`, not an invented `malicious.something`."*
THREATFOX_UNSEEN_THREAT_TYPE = "malicious"



MALFORMED_EXPORT = "malformed_export"
EMPTY_EXPORT = "empty_export"
THREATFOX_FAILURE_REASONS = (FETCH_FAILED, MALFORMED_EXPORT, EMPTY_EXPORT)


class ThreatFoxError(Exception):
    """The export could not be fetched or could not be read.

    Carries one of `THREATFOX_FAILURE_REASONS`. The same shape as
    `PublicSuffixListError` and for the same reason: a loader that raised a bare
    exception would leave the caller deciding whether the previous snapshot
    survives, and that decision is `concept/instruction.md`'s, not the caller's.
    """

    def __init__(self, message: str, *, reason: str) -> None:
        super().__init__(message)
        if reason not in THREATFOX_FAILURE_REASONS:
            raise ValueError(
                f"reason {reason!r} is not one of {THREATFOX_FAILURE_REASONS}"
            )
        self.reason = reason


@dataclass(frozen=True)
class ThreatFoxEntry:
    """One entry of the export, flattened out of its list and read as it arrived.

    A dataclass rather than a dict so that a field the publisher renames is an
    error at parse time. Only the fields the mapping or the evidence needs are
    lifted; the rest of the entry travels in `native` for audit.
    """

    indicator_id: str
    record_offset: int
    ioc_type: str
    ioc_value: str
    threat_type: str
    confidence_level: int
    is_compromised: bool
    first_seen_utc: str | None
    last_seen_utc: str | None
    tags: tuple[str, ...]
    native: Mapping[str, Any]


def fetch_threatfox(url: str, *, timeout: float = FETCH_TIMEOUT_SECONDS) -> bytes:
    """The bytes at `url`, or a `ThreatFoxError` with `fetch_failed`.

    No credential is attached, and that is measured rather than assumed -- see
    the section head. A caller that needs the authenticated API is using the tool
    layer, which is a different thing with a different rule about keys.
    """
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            return response.read()
    except (urllib.error.URLError, OSError, ValueError) as failure:
        raise ThreatFoxError(
            f"{type(failure).__name__}: {failure}", reason=FETCH_FAILED
        ) from failure


def parse_threatfox(raw: bytes) -> tuple[ThreatFoxEntry, ...]:
    """Every entry of the export, flattened, in the order the file gives them.

    **Flattened, not indexed.** The top level is an object keyed by indicator id
    whose values are lists. Every list was length 1 on 2026-09-06, and that is a
    property of one snapshot rather than of the format -- `concept/instruction.md`
    §6 lists reading `[0]` of a nested array among the traps that have already
    cost this project something, and this is the second place it would have.

    Refuses rather than skips a malformed entry, the way
    `parse_public_suffix_list` does: a field the publisher renamed is a format
    change, and skipping it would quietly narrow the snapshot. A *skip* here means
    something else entirely -- an entry this project has no entity for -- and that
    is `threatfox_claims`' job, with a count.
    """
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as failure:
        raise ThreatFoxError(
            f"{type(failure).__name__}: {failure}", reason=MALFORMED_EXPORT
        ) from failure
    if not isinstance(document, dict):
        raise ThreatFoxError(
            f"the export is a {type(document).__name__} and not an object keyed "
            f"by indicator id",
            reason=MALFORMED_EXPORT,
        )
    if not document:
        raise ThreatFoxError(
            "the export is empty; the previous snapshot stays", reason=EMPTY_EXPORT
        )
    entries: list[ThreatFoxEntry] = []
    for indicator_id, value in document.items():
        if not isinstance(value, list):
            raise ThreatFoxError(
                f"{indicator_id}: the value is a {type(value).__name__} and the "
                f"format is a list per indicator id",
                reason=MALFORMED_EXPORT,
            )
        for offset, entry in enumerate(value):
            if not isinstance(entry, dict):
                raise ThreatFoxError(
                    f"{indicator_id}[{offset}] is a {type(entry).__name__}",
                    reason=MALFORMED_EXPORT,
                )
            entries.append(_threatfox_entry(indicator_id, offset, entry))
    return tuple(entries)


def _threatfox_entry(
    indicator_id: str, offset: int, entry: Mapping[str, Any]
) -> ThreatFoxEntry:
    where = f"{indicator_id}[{offset}]"
    try:
        ioc_type = entry["ioc_type"]
        ioc_value = entry["ioc_value"]
        threat_type = entry["threat_type"]
        confidence = entry["confidence_level"]
    except KeyError as missing:
        raise ThreatFoxError(
            f"{where}: no {missing.args[0]!r}; the publisher's format has changed",
            reason=MALFORMED_EXPORT,
        ) from missing
    if not isinstance(confidence, int) or isinstance(confidence, bool):
        raise ThreatFoxError(
            f"{where}: confidence_level is {confidence!r}", reason=MALFORMED_EXPORT
        )
    # `tags` is a delimited string and not an array -- measured, and absent on
    # 8.9 % of entries. Splitting an absent one gives no tags rather than [""].
    raw_tags = entry.get("tags")
    tags = tuple(t for t in (raw_tags or "").split(",") if t) if raw_tags else ()
    return ThreatFoxEntry(
        indicator_id=str(indicator_id),
        record_offset=offset,
        ioc_type=str(ioc_type),
        ioc_value=str(ioc_value),
        threat_type=str(threat_type),
        confidence_level=confidence,
        is_compromised=bool(entry.get("is_compromised")),
        first_seen_utc=entry.get("first_seen_utc") or None,
        last_seen_utc=entry.get("last_seen_utc") or None,
        tags=tags,
        native=dict(entry),
    )


def split_indicator(entry: ThreatFoxEntry) -> tuple[str, str, int | None]:
    """`(entity_type, entity_value, port)` for one entry.

    **The port is kept**, and `concept/05` says why it has to be: a C2 on one port
    matched against a host that contacted a different port on the same address is
    a weaker claim, and an address column that swallowed the port could not tell
    those apart. 3 139 of 4 985 entries carried one on 2026-09-06, across 596
    distinct ports.

    Raises `KeyError` for an `ioc_type` with no entity -- the caller counts those
    rather than this refusing the whole snapshot over them.
    """
    entity_type = THREATFOX_ENTITY_TYPES[entry.ioc_type]
    if entry.ioc_type != "ip:port":
        return entity_type, entry.ioc_value, None
    address, _, port = entry.ioc_value.rpartition(":")
    if not address or not port.isdigit():
        raise ThreatFoxError(
            f"{entry.indicator_id}: ioc_type is 'ip:port' and ioc_value is "
            f"{entry.ioc_value!r}",
            reason=MALFORMED_EXPORT,
        )
    return entity_type, address, int(port)


def classify_threat_type(threat_type: str) -> tuple[str, bool]:
    """`(taxonomy path, whether the type was one this mapping has seen)`.

    Deterministic and total: every input has an answer, and the second value says
    whether that answer came from the table or from the parent rule. A caller
    counts the unseen ones -- a source's vocabulary growing is a fact worth
    surfacing, and `concept/05` warns the real vocabulary is larger than any
    sample.
    """
    mapped = THREATFOX_THREAT_TYPES.get(threat_type)
    if mapped is None:
        return THREATFOX_UNSEEN_THREAT_TYPE, False
    return mapped, True


@dataclass(frozen=True)
class ThreatFoxRow:
    """One entry of the export, normalized into the reference table's shape.

    Not the evidence shape: that is what the mapping view derives, and a loader
    that assembled it would be a second implementation of the evidence contract
    per feed. This is the native record with the publisher's format read out of
    it -- the list flattened, `ip:port` split, the delimited tags split, the
    timestamps parsed -- plus the taxonomy classification, which
    `concept/03-architecture.md` makes the loader's job.
    """

    snapshot_version: str
    indicator_id: str
    record_offset: int
    ioc_type: str
    ioc_value: str
    entity_type: str
    entity_value: str
    port: int | None
    threat_type: str
    classification: str
    taxonomy_version: str
    threat_type_seen: bool
    confidence_level: int
    is_compromised: bool
    first_seen: datetime | None
    last_seen: datetime | None
    tags: tuple[str, ...]
    malware: str | None
    malware_printable: str | None
    reporter: str | None
    reference: str | None


@dataclass(frozen=True)
class ThreatFoxSnapshot:
    """What one parse produced: the claims, and what did not become one.

    The counts are the point. `concept/instruction.md` §7 requires
    produced-versus-materialised counts to reconcile, and a loader that returned
    only its rows would make "4 533 claims from 4 985 entries" a discrepancy
    somebody notices later rather than a number the load row carries.
    """

    snapshot_version: str
    rows: tuple[ThreatFoxRow, ...]
    #: Entries whose `ioc_type` has no HELENA entity -- file hashes. Skipped and
    #: counted, never silently dropped.
    skipped_no_entity: int
    #: Entries whose `threat_type` this mapping has not seen. They still became
    #: claims, at the parent; the count is what makes the source's vocabulary
    #: drifting visible instead of silent.
    unseen_threat_types: tuple[str, ...]

    @property
    def entries_read(self) -> int:
        return len(self.rows) + self.skipped_no_entity


def threatfox_snapshot_version(raw: bytes) -> str:
    """The sha256 of the fetched bytes.

    The same identity rule the Public Suffix List uses: same content, same
    version, so two fetches of an unchanged export are one snapshot rather than a
    second copy of five thousand identical rows.
    """
    return hashlib.sha256(raw).hexdigest()


def threatfox_rows(raw: bytes) -> ThreatFoxSnapshot:
    """Parse an export into reference rows, counting what did not become one.

    The half of the mapping `concept/05` rule 2 calls "a unit-testable
    deliverable, not prose" that needs the publisher's format in front of it:
    bytes in, reference rows out, no engine and no clock. Turning these into the
    evidence shape is `helena_reference_evidence_threatfox`'s job, because that
    shape is the same for every feed and a loader that assembled it would be a
    second implementation of it per feed.
    """
    entries = parse_threatfox(raw)
    version = threatfox_snapshot_version(raw)
    rows: list[ThreatFoxRow] = []
    skipped = 0
    unseen: list[str] = []
    for entry in entries:
        if entry.ioc_type not in THREATFOX_ENTITY_TYPES:
            skipped += 1
            continue
        entity_type, entity_value, port = split_indicator(entry)
        classification, seen = classify_threat_type(entry.threat_type)
        if not seen:
            unseen.append(entry.threat_type)
        rows.append(
            ThreatFoxRow(
                snapshot_version=version,
                indicator_id=entry.indicator_id,
                record_offset=entry.record_offset,
                ioc_type=entry.ioc_type,
                ioc_value=entry.ioc_value,
                entity_type=entity_type,
                entity_value=entity_value,
                port=port,
                threat_type=entry.threat_type,
                classification=classification,
                taxonomy_version=SOURCES[THREATFOX_SOURCE].taxonomy_version,
                threat_type_seen=seen,
                confidence_level=entry.confidence_level,
                is_compromised=entry.is_compromised,
                first_seen=_threatfox_time(entry.first_seen_utc),
                last_seen=_threatfox_time(entry.last_seen_utc),
                tags=entry.tags,
                malware=entry.native.get("malware"),
                malware_printable=entry.native.get("malware_printable"),
                reporter=entry.native.get("reporter"),
                reference=entry.native.get("reference"),
            )
        )
    return ThreatFoxSnapshot(
        snapshot_version=version,
        rows=tuple(rows),
        skipped_no_entity=skipped,
        unseen_threat_types=tuple(sorted(set(unseen))),
    )


def _threatfox_time(value: str | None) -> datetime | None:
    """`YYYY-MM-DD HH:MM:SS` in UTC, or None. Never a guess.

    Absent stays absent: `last_seen_utc` is missing on 19.3 % of entries, and
    `concept/05` is explicit that missing precision is not invented -- a
    `last_seen` defaulted to now would make every stale claim look fresh. A value
    this cannot read is also None rather than a raise, because one unparseable
    timestamp is not a reason to refuse a snapshot; the raw string survives in
    the native evidence either way.
    """
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


class FeedSnapshot(BaseModel):
    """One row of `helena_reference_feed_snapshot`: one load attempt of one feed.

    Frozen: it describes an attempt that has already happened. The invariants the
    columns only document are validated here -- a failure naming a snapshot, a
    success naming a reason -- so a loader that got them the wrong way round
    fails before storing a row that reads as both.

    `counts` is whatever that feed counts, because feeds do not count the same
    things: ThreatFox has entries read, claims stored and skipped file hashes,
    and a feed with no unmappable indicator type would have two of those. What is
    checked here is what every feed shares -- see `reconciles`.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    source_id: str
    attempted_at: datetime
    source_url: str
    outcome: str
    snapshot_version: str | None
    counts: dict[str, Any] = Field(default_factory=dict)
    failure_reason: str | None = None
    failure_detail: str | None = None

    def model_post_init(self, _context: object) -> None:
        if self.outcome not in LOAD_STATUSES:
            raise ValueError(f"outcome {self.outcome!r} is not one of {LOAD_STATUSES}")
        if self.outcome == FAILED:
            if not self.failure_reason:
                raise ValueError("a failed load names a reason")
            if self.snapshot_version is not None:
                raise ValueError(
                    "a failed load has no snapshot: the previous one stands, and "
                    "a row naming both reads as neither"
                )
            return
        if self.failure_reason is not None:
            raise ValueError(
                f"a {self.outcome} load names failure reason "
                f"{self.failure_reason!r}"
            )
        if self.snapshot_version is None:
            raise ValueError(f"a {self.outcome} load names no snapshot")
        self.reconciles()

    def reconciles(self) -> None:
        """`entries_read == stored + skipped`, where the feed reports all three.

        `concept/instruction.md` §7 requires produced-versus-materialised counts
        to reconcile. A feed that does not report these three is not exempt from
        the rule -- it has nothing here to check, and whatever it does count is
        checked wherever it is produced.
        """
        read = self.counts.get("entries_read")
        stored = self.counts.get("claims_stored")
        skipped = self.counts.get("skipped_no_entity")
        if None in (read, stored, skipped):
            return
        if read != stored + skipped:
            raise ValueError(
                f"{read} entries read, {stored} stored and {skipped} skipped; "
                f"the counters do not reconcile (concept/instruction.md §7)"
            )


def load_threatfox(
    connection: psycopg.Connection,
    *,
    tenant: str,
    sensor: str,
    source_url: str,
    redactor: Redactor,
    raw: bytes | None = None,
    now: datetime | None = None,
) -> FeedSnapshot:
    """Fetch, map completely, then write. Returns the load row it wrote.

    The order is the one `load_public_suffix_list` uses and for the same reason:
    **fetch, parse completely, then write.** A format change therefore leaves the
    previous snapshot untouched rather than half-replaced, which is why parsing
    happens before the first INSERT rather than row by row.

    The replacement is insert-then-delete, again as 0008 argues: RisingWave has no
    transaction around a write, so one of the two orders has to be chosen for what
    its half-done state looks like. A superset of the claims for a moment is a
    reader seeing an old claim beside a new one; an empty table for a moment is a
    reader seeing `no_match` where there is a hit, which is the failure mode
    `concept/02` says the whole design exists to prevent.

    `raw` is for a test or a replay that already holds the bytes. Left unset, the
    export is fetched.

    `redactor` is not optional, for the reason `load_public_suffix_list` gives:
    `concept/instruction.md` §6 requires a credential in a URL to be redacted
    before anything is **stored**, not only before anything is logged. This
    endpoint needs no credential -- measured -- and the rule is about the channel.
    """
    attempted_at = now or datetime.now(timezone.utc)
    recorded_url = redactor.url(source_url)
    try:
        payload = fetch_threatfox(source_url) if raw is None else raw
        snapshot = threatfox_rows(payload)
    except ThreatFoxError as failure:
        # The previous snapshot is untouched: nothing has been written, and the
        # claims still join. `concept/instruction.md`: never let a failure empty
        # a table -- the result is `stale`, never a silent empty opinion.
        return _record_snapshot(
            connection,
            FeedSnapshot(
                source_id=THREATFOX_SOURCE,
                attempted_at=attempted_at,
                source_url=recorded_url,
                outcome=FAILED,
                snapshot_version=None,
                failure_reason=failure.reason,
                failure_detail=str(failure)[:MAX_FAILURE_DETAIL],
            ),
            tenant=tenant,
            sensor=sensor,
        )

    counts = {
        "entries_read": snapshot.entries_read,
        "claims_stored": len(snapshot.rows),
        "skipped_no_entity": snapshot.skipped_no_entity,
        "unseen_threat_types": len(snapshot.unseen_threat_types),
        # Written with the load rather than joined from a table of feeds: the
        # schedule is what the loader knows and the engine does not, and a row
        # judged against one interval keeps saying which interval that was.
        "refresh_interval_seconds": SOURCES[THREATFOX_SOURCE].refresh_interval_seconds,
    }
    outcome = UNCHANGED if _holds_snapshot(
        connection,
        tenant=tenant,
        sensor=sensor,
        source_id=THREATFOX_SOURCE,
        snapshot_version=snapshot.snapshot_version,
    ) else LOADED
    if outcome == LOADED:
        # Written, never replaced. The old snapshot stays: a claim records the
        # snapshot it matched against and replay joins *that* one
        # (`concept/02`), so deleting it would leave a stored assessment citing a
        # snapshot the store no longer has. Pruning is `prune_snapshots`, a
        # deliberate operation against a retention, not a side effect of loading.
        for row in snapshot.rows:
            _insert_threatfox_row(connection, row, tenant=tenant, sensor=sensor)
        connection.execute("FLUSH")
    return _record_snapshot(
        connection,
        FeedSnapshot(
            source_id=THREATFOX_SOURCE,
            attempted_at=attempted_at,
            source_url=recorded_url,
            outcome=outcome,
            snapshot_version=snapshot.snapshot_version,
            counts=counts,
        ),
        tenant=tenant,
        sensor=sensor,
    )


def _holds_snapshot(
    connection: psycopg.Connection,
    *,
    tenant: str,
    sensor: str,
    source_id: str,
    snapshot_version: str,
) -> bool:
    """Whether the evidence table already holds this snapshot's claims.

    Read from the claims rather than from the snapshot ledger, because the claims
    are what a join sees: a ledger saying `loaded` over an empty table would be a
    second store disagreeing with the first.

    Several snapshots coexisting is the normal state now and not an error -- that
    is what replay joins against.
    """
    connection.execute("FLUSH")
    rows = connection.execute(
        f"SELECT 1 FROM {ENRICHMENT_EVIDENCE_VIEW} WHERE tenant = %s AND "
        f"sensor = %s AND source_id = %s AND snapshot_version = %s LIMIT 1",
        (tenant, sensor, source_id, snapshot_version),
    ).fetchall()
    return bool(rows)


def _insert_threatfox_row(
    connection: psycopg.Connection,
    row: ThreatFoxRow,
    *,
    tenant: str,
    sensor: str,
) -> None:
    """Write one reference row. The only writer of the ThreatFox snapshot table.

    Nothing here assembles an evidence row: that is the mapping view's job, and
    the evidence shape has exactly one implementation because of it.
    """
    connection.execute(
        f"INSERT INTO {THREATFOX_REFERENCE_TABLE} (tenant, sensor, "
        f"snapshot_version, indicator_id, record_offset, ioc_type, ioc_value, "
        f"entity_type, entity_value, port, threat_type, classification, "
        f"taxonomy_version, threat_type_seen, confidence_level, is_compromised, "
        f"first_seen, last_seen, tags, malware, malware_printable, reporter, "
        f"reference) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, "
        f"%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
        (
            tenant,
            sensor,
            row.snapshot_version,
            row.indicator_id,
            row.record_offset,
            row.ioc_type,
            row.ioc_value,
            row.entity_type,
            row.entity_value,
            row.port,
            row.threat_type,
            row.classification,
            row.taxonomy_version,
            row.threat_type_seen,
            row.confidence_level,
            row.is_compromised,
            row.first_seen,
            row.last_seen,
            Jsonb(list(row.tags)),
            row.malware,
            row.malware_printable,
            row.reporter,
            row.reference,
        ),
    )


def _record_snapshot(
    connection: psycopg.Connection,
    snapshot: FeedSnapshot,
    *,
    tenant: str,
    sensor: str,
) -> FeedSnapshot:
    """Write the snapshot row and return it. Every attempt, failures included."""
    connection.execute(
        f"INSERT INTO {FEED_SNAPSHOT_TABLE} (tenant, sensor, source_id, "
        f"attempted_at, source_url, outcome, snapshot_version, counts, "
        f"failure_reason, failure_detail) "
        f"VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
        (
            tenant,
            sensor,
            snapshot.source_id,
            snapshot.attempted_at,
            snapshot.source_url,
            snapshot.outcome,
            snapshot.snapshot_version,
            Jsonb(snapshot.counts),
            snapshot.failure_reason,
            snapshot.failure_detail,
        ),
    )
    connection.execute("FLUSH")
    return snapshot


# --- Snapshot status, and what it is not ------------------------------------


@dataclass(frozen=True)
class FeedStatus:
    """What a source's snapshot is worth as of one read.

    `ok` and `stale` come from the engine's own view of the snapshot ledger;
    `missing` is the absence of a row there. They are computed rather than stored
    because two of the four enrichment statuses are properties of *now*:
    `helena_signal_host_context_live` computes `completeness` over `now()` for
    exactly this reason, and a stored `stale` would be wrong the moment time
    passed.
    """

    source_id: str
    status: str
    snapshot_version: str | None
    attempted_at: datetime | None
    refresh_interval_seconds: int | None

    @property
    def has_snapshot(self) -> bool:
        return self.snapshot_version is not None


def feed_status(
    connection: psycopg.Connection, *, tenant: str, sensor: str, source_id: str
) -> FeedStatus:
    """`ok`, `stale` or `missing` for one source, as of this read.

    The three that a *reader* of the reference layer can be in.
    `concept/instruction.md` forbids collapsing them and the difference is not
    academic:

    * `ok` -- the snapshot is younger than the feed's own refresh interval, so it
      is what the publisher currently says.
    * `stale` -- there is a snapshot and the publisher has moved past it. The
      claims still stand: `concept/02` is explicit that removal from a feed is
      not exoneration, and an aged snapshot is evidence with a date on it rather
      than evidence withdrawn.
    * `missing` -- **no snapshot at all**. Never `no_match`, and that is the
      distinction the whole design turns on: `no_match` is a source that ran and
      found nothing, and `missing` is a source that was never asked. Reading the
      second as the first is triage reading "no hit" as "clean".

    A source with no `refresh_interval_seconds` can never be `stale` -- the SSLBL
    JA3 list has been static since 2021, so it is not late, it is finished, and
    what is wrong with it is in its caveat rather than in its age.
    """
    connection.execute("FLUSH")
    rows = connection.execute(
        f"SELECT status, snapshot_version, attempted_at, refresh_interval_seconds "
        f"FROM {FEED_SNAPSHOT_CURRENT_VIEW} "
        f"WHERE tenant = %s AND sensor = %s AND source_id = %s",
        (tenant, sensor, source_id),
    ).fetchall()
    if not rows:
        return FeedStatus(
            source_id=source_id,
            status=MISSING,
            snapshot_version=None,
            attempted_at=None,
            refresh_interval_seconds=None,
        )
    status, version, attempted_at, interval = rows[0]
    if interval is None:
        # Nothing to be late against. The view has to say something, and `stale`
        # against no schedule would be a claim about a feed that has none.
        status = OK
    return FeedStatus(
        source_id=source_id,
        status=status,
        snapshot_version=version,
        attempted_at=attempted_at,
        refresh_interval_seconds=interval,
    )


def prune_snapshots(
    connection: psycopg.Connection,
    *,
    tenant: str,
    sensor: str,
    source_id: str,
    keep: int = SNAPSHOTS_KEPT,
) -> int:
    """Drop all but the newest `keep` snapshots of one source. Returns how many went.

    **A deliberate operation, never a side effect of loading**, and that is the
    correction this increment makes to the ThreatFox loader as task 22 shipped
    it: that one replaced its claims insert-then-delete and kept exactly one
    snapshot, which is right for the Public Suffix List and wrong for a feed. A
    claim records the snapshot it matched against and `concept/02` requires
    replay to join *that* snapshot, so deleting it on the next load leaves a
    stored assessment citing a snapshot the store no longer has.

    Pruning still has to exist -- the recent export is thousands of claims every
    hour -- so it is here, with a number, called when somebody decides to call
    it. Nothing calls it automatically, for the reason nothing here schedules a
    fetch: that decision has an operator behind it.
    """
    connection.execute("FLUSH")
    versions = [
        row[0]
        for row in connection.execute(
            f"SELECT snapshot_version FROM {FEED_SNAPSHOT_TABLE} "
            f"WHERE tenant = %s AND sensor = %s AND source_id = %s "
            f"AND snapshot_version IS NOT NULL "
            f"ORDER BY attempted_at DESC",
            (tenant, sensor, source_id),
        ).fetchall()
    ]
    # Newest first, de-duplicated: an `unchanged` load writes a second row for a
    # snapshot already held, and that is one snapshot rather than two.
    ordered: list[str] = []
    for version in versions:
        if version not in ordered:
            ordered.append(version)
    doomed = ordered[keep:]
    if not doomed:
        return 0
    table = FEED_REFERENCE_TABLES[source_id]
    for version in doomed:
        connection.execute(
            f"DELETE FROM {table} WHERE tenant = %s AND sensor = %s "
            f"AND snapshot_version = %s",
            (tenant, sensor, version),
        )
    connection.execute("FLUSH")
    return len(doomed)
