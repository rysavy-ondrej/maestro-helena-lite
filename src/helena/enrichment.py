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
deferred, and so is every part of this module that maps anything to the taxonomy.

Reads: an HTTP(S) or `file:` URL supplied by the caller, through the standard
library. Writes: `helena_reference_public_suffix` and
`helena_reference_public_suffix_load`.

Maturity: experimental — the Public Suffix List loader and its failure paths are
exercised by `tests/test_enrichment.py`, against a real engine and against the
live list. Nothing has been enriched, no feed loader exists, and no snapshot
version has reached an assessment.
"""

from __future__ import annotations

import hashlib
import urllib.error
import urllib.request
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone

import psycopg
from pydantic import BaseModel, ConfigDict

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
    "PublicSuffixLoad",
    "PublicSuffixRule",
    "fetch_public_suffix_list",
    "load_public_suffix_list",
    "parse_public_suffix_list",
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
