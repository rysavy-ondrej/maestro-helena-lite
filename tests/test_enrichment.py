"""Tests for helena.enrichment. Mirrors src/helena/enrichment.py.

Half of this component's source is SQL — `sql/migrations/0008_public_suffix_list.sql`
— so it is tested the way the rest of the engine's source is: by applying the
migrations to a throwaway engine, loading a real list through the real loader,
putting real records through the real ingestion path, and asking the views what
they hold. Nothing here asserts on SQL text.

The correctness argument for the derivation is not this file's own reasoning. It
is the publisher's own `checkPublicSuffix` vectors, committed verbatim under
`tests/fixtures/public-suffix-list/`, run through the whole path: a name becomes
a DNS query in a capture, the capture becomes normalized events, the events
become a domain entity row, and the entity row becomes a registrable domain. A
test that agreed with the SQL about what a public suffix is would find the
comment.
"""

from __future__ import annotations

import hashlib
import json
import re
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import psycopg
import pytest

import helena.enrichment
from helena.config import Settings
from helena.enrichment import (
    DEFAULT_RULE,
    DEFAULT_SECTION,
    EMPTY_LIST,
    ENRICHMENT_EVIDENCE_VIEW,
    FAILED,
    FETCH_FAILED,
    ICANN_SECTION,
    LOADED,
    MALFORMED_RULE,
    PRIVATE_SECTION,
    PUBLIC_SUFFIX_LOAD_TABLE,
    PUBLIC_SUFFIX_TABLE,
    FEED_SNAPSHOT_TABLE,
    UNCHANGED,
    PublicSuffixListError,
    PublicSuffixLoad,
    load_public_suffix_list,
    parse_public_suffix_list,
)
from helena.normalizer import (
    Capture,
    EventStore,
    NormalizedEvent,
    Normalizer,
    describe_capture,
)
from helena.observability import Redactor

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SAMPLE = PROJECT_ROOT / "data" / "ingest" / "flow-sample.jsonl"
FIXTURE_CAPTURES = Path(__file__).resolve().parent / "fixtures" / "captures"
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "public-suffix-list"
EXTRACT = FIXTURES / "extract.dat"
VECTORS = FIXTURES / "checkpublicsuffix.txt"

# The published list. The one copy in the package's own code is deliberately
# absent — the URL lives in scripts/load_public_suffix_list.py, which is where a
# source is chosen — so the test that fetches it reads it from there.
LIVE_LIST_SCRIPT = PROJECT_ROOT / "scripts" / "load_public_suffix_list.py"

# The layer-coverage capture, as tests/test_context.py uses it. Its first record
# (`udp.0`) is a real DNS lookup, and replacing its query list with names of a
# test's own is the technique tasks 12 to 14 established: a real record changed
# only in a way the contract permits, in a tmp_path capture, through the real
# normalizer. Never a hand-written record, and never committed as a fixture.
LAYERS_CAPTURE = "ace6ca33f7bf8aa949f79124abf33fc115cfd0909e9dea798f4762cf87af8318"

# The same environment shape tests/test_context.py uses, and for the same reason:
# values that are obviously not credentials, so a leak into a pytest failure
# message would be a nuisance rather than an incident.
ENVIRONMENT = {
    "LLM_URL": "http://model.invalid/v1",
    "LLM_TOKEN": "token-under-test",
    "LLM_MODEL": "model-under-test",
    "HELENA_TENANT": "tenant-under-test",
    "HELENA_SENSOR": "sensor-under-test",
    "HELENA_INPUT_FORMAT": "flow-json",
    "ABUSECH_AUTH_KEY": "abusech-key-under-test",
    "VIRUSTOTAL_AUTH_KEY": "virustotal-key-under-test",
    "RISINGWAVE_DSN": "postgresql://root@localhost:4566/dev",
    "KAFKA_BOOTSTRAP_SERVERS": "localhost:9092",
    "HELENA_INGEST_TOPIC": "helena.ingest",
}

REFERENCE_TABLE_SHAPE = (
    ("snapshot_version", "character varying"),
    ("rule", "character varying"),
    ("suffix", "character varying"),
    ("is_wildcard", "boolean"),
    ("is_exception", "boolean"),
    ("section", "character varying"),
)

LOAD_TABLE_SHAPE = (
    ("attempted_at", "timestamp with time zone"),
    ("source_url", "character varying"),
    ("status", "character varying"),
    ("snapshot_version", "character varying"),
    ("rule_count", "bigint"),
    ("failure_reason", "character varying"),
    ("failure_detail", "character varying"),
)

# The derivation's interface, as sql/migrations/0008_public_suffix_list.sql
# declares it. The second copy — the file is the first — asserted equal by asking
# the engine, which is the only comparison that can fail.
REGISTRABLE = "helena_signal_domain_registrable"
CONTEXT_DOMAINS = "helena_signal_context_domains"
SUFFIX_CANDIDATES = "helena_signal_domain_suffix_candidates"

REGISTRABLE_SHAPE = (
    ("observed_name", "character varying"),
    ("normalized_name", "character varying"),
    ("name_label_count", "integer"),
    ("public_suffix_label_count", "integer"),
    ("public_suffix", "character varying"),
    ("registrable_domain", "character varying"),
    ("registrable_domain_status", "character varying"),
    ("public_suffix_snapshot_version", "character varying"),
)

# The four states of `registrable_domain_status`, which the migration head keeps
# apart on purpose. Named here so a test can say which one it means.
DERIVED = "derived"
IS_A_PUBLIC_SUFFIX = "name_is_a_public_suffix"
INVALID_NAME = "invalid_name"
LIST_NOT_LOADED = "list_not_loaded"


def test_module_imports():
    assert helena.enrichment.__doc__


# --- Reading the published format ------------------------------------------


def test_the_extract_parses_to_the_rules_it_holds():
    """Sections, markers and the three rule kinds, off the committed extract."""
    rules = parse_public_suffix_list(EXTRACT.read_bytes())
    by_rule = {}
    for rule in rules:
        by_rule.setdefault(rule.rule, []).append(rule)

    assert by_rule["com"][0].section == ICANN_SECTION
    assert by_rule["github.io"][0].section == PRIVATE_SECTION

    (wildcard,) = by_rule["*.ck"]
    assert (wildcard.suffix, wildcard.is_wildcard, wildcard.is_exception) == (
        "ck",
        True,
        False,
    )
    (exception,) = by_rule["!www.ck"]
    assert (exception.suffix, exception.is_wildcard, exception.is_exception) == (
        "www.ck",
        False,
        True,
    )
    (plain,) = by_rule["co.uk"]
    assert (plain.suffix, plain.is_wildcard, plain.is_exception) == (
        "co.uk",
        False,
        False,
    )


def test_a_rule_with_non_ascii_labels_is_loaded_in_both_forms():
    """A name may be observed as a U-label or punycoded; the join is on bytes."""
    rules = parse_public_suffix_list(EXTRACT.read_bytes())
    keys = {rule.suffix for rule in rules if rule.rule == "公司.cn"}
    assert keys == {"公司.cn", "xn--55qx5d.cn"}
    assert {rule.suffix for rule in rules if rule.rule == "中国"} == {
        "中国",
        "xn--fiqs8s",
    }
    # An all-ASCII rule gets exactly one key, so the two forms are not a habit.
    assert len([rule for rule in rules if rule.rule == "com"]) == 1


def test_the_algorithms_default_rule_is_a_row():
    """`*` is not a line in the file, and every valid name has to match it."""
    rules = parse_public_suffix_list(EXTRACT.read_bytes())
    (default,) = [rule for rule in rules if rule.rule == DEFAULT_RULE]
    assert (default.suffix, default.is_wildcard, default.section) == (
        "",
        True,
        DEFAULT_SECTION,
    )


@pytest.mark.parametrize(
    ("body", "reason"),
    [
        (b"com\n", MALFORMED_RULE),  # outside both section markers
        (b"// ===BEGIN ICANN DOMAINS===\nex..ample\n", MALFORMED_RULE),
        (b"// ===BEGIN ICANN DOMAINS===\na.*.b\n", MALFORMED_RULE),
        (b"// ===BEGIN ICANN DOMAINS===\nCOM\n", MALFORMED_RULE),
        (b"// ===BEGIN ICANN DOMAINS===\nc\xffm\n", MALFORMED_RULE),
        (b"// a comment and nothing else\n", EMPTY_LIST),
        (b"", EMPTY_LIST),
    ],
)
def test_a_list_this_cannot_read_is_refused_with_a_typed_reason(
    body: bytes, reason: str
):
    """Refused, not skipped.

    A line the parser cannot read is the publisher changing format, which is the
    one thing a loader must surface. Skipping it would quietly narrow the list
    until a name that should have been a public suffix no longer is — and
    nothing downstream could tell that from the name simply not being one.
    """
    with pytest.raises(PublicSuffixListError) as raised:
        parse_public_suffix_list(body)
    assert raised.value.reason == reason


def test_a_refusal_names_the_line_it_refused():
    with pytest.raises(PublicSuffixListError) as raised:
        parse_public_suffix_list(b"// ===BEGIN ICANN DOMAINS===\ncom\nex..ample\n")
    assert "line 3" in str(raised.value)
    assert "ex..ample" in str(raised.value)


# --- The load row keeps its states apart -----------------------------------


def _load(**overrides: object) -> PublicSuffixLoad:
    fields: dict[str, object] = {
        "attempted_at": datetime(2026, 9, 3, tzinfo=timezone.utc),
        "source_url": "file:///list.dat",
        "status": LOADED,
        "snapshot_version": "a" * 64,
        "rule_count": 3,
        "failure_reason": None,
        "failure_detail": None,
    }
    return PublicSuffixLoad(**{**fields, **overrides})


def test_a_failed_load_names_a_typed_reason_and_no_snapshot():
    failed = _load(
        status=FAILED,
        snapshot_version=None,
        rule_count=None,
        failure_reason=FETCH_FAILED,
        failure_detail="URLError: unreachable",
    )
    assert failed.failure_reason == FETCH_FAILED

    with pytest.raises(ValueError, match="names no snapshot version"):
        _load(status=FAILED, failure_reason=FETCH_FAILED)
    with pytest.raises(ValueError, match="names one of"):
        _load(status=FAILED, snapshot_version=None, failure_reason="something else")


def test_a_successful_load_carries_no_failure_and_names_its_snapshot():
    with pytest.raises(ValueError, match="carries no failure reason"):
        _load(failure_reason=FETCH_FAILED)
    with pytest.raises(ValueError, match="names the snapshot it read"):
        _load(snapshot_version=None)
    with pytest.raises(ValueError, match="is not one of"):
        _load(status="ok")


# --- Putting real records and a real list into a throwaway engine ----------


def settings(**overrides: str) -> Settings:
    return Settings.load(environ={**ENVIRONMENT, **overrides}, env_file=None)


def redactor() -> Redactor:
    return Redactor.from_settings(settings())


def store_capture(connection: psycopg.Connection, capture: Capture) -> None:
    """Normalize every record of `capture` and store it, through the real path."""
    configured = settings()
    normalizer = Normalizer.from_settings(configured)
    store = EventStore(connection=connection, identity=configured.identity)
    for result in normalizer.normalize_capture(capture):
        assert isinstance(result, NormalizedEvent), result
        store.record(result)
    connection.execute("FLUSH")


def rows(connection: psycopg.Connection, sql: str, *args: object) -> list[tuple]:
    # `args or None`: psycopg reads the query for placeholders as soon as any
    # parameter sequence is passed, and a bare `%` is then a malformed one.
    return connection.execute(sql, args or None).fetchall()


def one(connection: psycopg.Connection, sql: str, *args: object) -> object:
    result = rows(connection, sql, *args)
    assert len(result) == 1, f"expected one row, got {len(result)}"
    return result[0][0]


def load(
    connection: psycopg.Connection, path: Path, **kwargs: object
) -> PublicSuffixLoad:
    """The real loader, over a `file:` URL, so no test needs the network."""
    return load_public_suffix_list(
        connection, source_url=path.as_uri(), redactor=redactor(), **kwargs
    )


def capture_of_names(tmp_path: Path, names: list[str], stem: str) -> Capture:
    """A real DNS record whose query list is `names`, as a one-record capture.

    `udp.0` of the layer-coverage capture with its `queries` replaced. The query
    type comes from the record it replaces, so nothing here is invented except
    the names — which are the input under test.
    """
    record = json.loads(
        (FIXTURE_CAPTURES / f"{LAYERS_CAPTURE}.jsonl").read_bytes().splitlines()[0]
    )
    assert record["id"] == "udp.0"
    # The rest of the observation is left exactly as the producer emitted it —
    # `rcode` is required by the contract, and a record rebuilt from the fields
    # a test happens to care about is quarantined rather than normalized.
    query_type = record["dns"]["queries"][0]["qt"]
    record["dns"] = {
        **record["dns"],
        "queries": [{"qn": name, "qt": query_type} for name in names],
        # Answered with nothing, which the contract permits and which keeps the
        # real record's own three answers out of the names under test.
        "responses": [],
    }
    path = tmp_path / f"{stem}.jsonl"
    path.write_bytes(json.dumps(record).encode() + b"\n")
    return describe_capture(path)


def vectors() -> list[tuple[str, str | None]]:
    """The publisher's `checkPublicSuffix` vectors, as (name, expected) pairs.

    `null` input is skipped: there is no domain entity with no value. Lines that
    are commented out in the published file are skipped by the pattern, which
    only matches a line that starts with the call.
    """
    pattern = re.compile(r"^checkPublicSuffix\('([^']*)', (?:'([^']*)'|null)\);$")
    found = []
    for line in VECTORS.read_text(encoding="utf-8").splitlines():
        match = pattern.match(line.strip())
        if match:
            found.append((match.group(1), match.group(2)))
    return found


@pytest.fixture
def loaded(migrated_engine: psycopg.Connection) -> psycopg.Connection:
    """A migrated engine holding the committed extract as its snapshot."""
    result = load(migrated_engine, EXTRACT)
    assert result.status == LOADED, result
    return migrated_engine


# --- What the migration creates --------------------------------------------


@pytest.mark.integration
def test_the_reference_objects_are_what_they_declare(
    migrated_engine: psycopg.Connection,
):
    """Every object in the reference layer, named.

    A prefix query rather than a list of things to check, so adding a reference
    object means editing this dict -- the same deliberate friction
    `tests/test_context.py` applies to the signal layer. A table that appeared
    without anybody deciding it should is what this catches.
    """
    assert dict(
        rows(
            migrated_engine,
            "SELECT table_name, table_type FROM information_schema.tables "
            "WHERE table_schema = current_schema() "
            "AND table_name LIKE 'helena_reference_%'",
        )
    ) == {
        PUBLIC_SUFFIX_TABLE: "BASE TABLE",
        PUBLIC_SUFFIX_LOAD_TABLE: "BASE TABLE",
        "helena_reference_public_suffix_load_counts": "VIEW",
        # ThreatFox's snapshot and the two views that map it into the evidence
        # shape (0014). 0011's evidence TABLE is dropped there: the shape is
        # derived now, not written. Their columns are asserted in
        # tests/test_mapping.py, beside the model they have to agree with.
        "helena_reference_threatfox": "BASE TABLE",
        "helena_reference_evidence_threatfox": "VIEW",
        ENRICHMENT_EVIDENCE_VIEW: "VIEW",
        # One snapshot ledger for every feed, and its two views (0013). 0012's
        # per-feed table is dropped there and does not appear.
        FEED_SNAPSHOT_TABLE: "BASE TABLE",
        "helena_reference_feed_snapshot_current": "VIEW",
        "helena_reference_feed_snapshot_counts": "VIEW",
        # sql/migrations/0015: the ledger as intervals, so the enriched context
        # can join the snapshot that was current at a window's event time rather
        # than the newest one. Two views because they answer two questions —
        # which snapshot was current, and what the most recent attempt was.
        "helena_reference_feed_snapshot_validity": "VIEW",
        "helena_reference_feed_attempt_validity": "VIEW",
    }


@pytest.mark.integration
@pytest.mark.parametrize(
    ("table", "shape"),
    [
        (PUBLIC_SUFFIX_TABLE, REFERENCE_TABLE_SHAPE),
        (PUBLIC_SUFFIX_LOAD_TABLE, LOAD_TABLE_SHAPE),
        (REGISTRABLE, REGISTRABLE_SHAPE),
    ],
)
def test_an_object_has_the_shape_it_declares(
    migrated_engine: psycopg.Connection, table: str, shape: tuple
):
    assert (
        tuple(
            rows(
                migrated_engine,
                "SELECT column_name, data_type FROM information_schema.columns "
                "WHERE table_schema = current_schema() AND table_name = %s "
                "ORDER BY ordinal_position",
                table,
            )
        )
        == shape
    )


@pytest.mark.integration
def test_the_reference_table_makes_no_claim_about_anything(
    migrated_engine: psycopg.Connection,
):
    """`concept/05-threat-intelligence.md`: normalization, not enrichment.

    The list maps to nothing in the taxonomy, so there is nothing here to be
    confident about and nothing here that can escalate. Checked by column name
    rather than by reading the migration's comment, because the failure this
    catches is someone adding the column.
    """
    forbidden = (
        "threat",
        "malware",
        "verdict",
        "classification",
        "confidence",
        "severity",
        "score",
        "taxonomy",
        "tier",
    )
    for table in (PUBLIC_SUFFIX_TABLE, REGISTRABLE, CONTEXT_DOMAINS):
        columns = [
            name
            for (name,) in rows(
                migrated_engine,
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_schema = current_schema() AND table_name = %s",
                table,
            )
        ]
        assert columns, table
        assert [
            name for name in columns if any(word in name for word in forbidden)
        ] == [], table


# --- Loading, and the failure paths ----------------------------------------


@pytest.mark.integration
def test_a_load_writes_the_snapshot_it_names(migrated_engine: psycopg.Connection):
    """The rule count on the load row reconciles with the rows in the table."""
    result = load(migrated_engine, EXTRACT)
    assert result.status == LOADED
    assert result.snapshot_version == hashlib.sha256(EXTRACT.read_bytes()).hexdigest()

    migrated_engine.execute("FLUSH")
    held = one(migrated_engine, f"SELECT count(*) FROM {PUBLIC_SUFFIX_TABLE}")
    assert held == result.rule_count
    assert (
        one(
            migrated_engine,
            f"SELECT count(DISTINCT snapshot_version) FROM {PUBLIC_SUFFIX_TABLE}",
        )
        == 1
    )
    assert rows(
        migrated_engine,
        f"SELECT status, snapshot_version, rule_count, failure_reason "
        f"FROM {PUBLIC_SUFFIX_LOAD_TABLE}",
    ) == [(LOADED, result.snapshot_version, result.rule_count, None)]


@pytest.mark.integration
def test_loading_the_same_list_twice_is_recorded_as_unchanged(
    migrated_engine: psycopg.Connection,
):
    """Same bytes, same snapshot. Nothing is rewritten and the fact is stored."""
    first = load(migrated_engine, EXTRACT)
    second = load(migrated_engine, EXTRACT, now=datetime.now(timezone.utc))
    assert (second.status, second.snapshot_version) == (
        UNCHANGED,
        first.snapshot_version,
    )
    assert second.rule_count is None

    migrated_engine.execute("FLUSH")
    assert (
        one(migrated_engine, f"SELECT count(*) FROM {PUBLIC_SUFFIX_TABLE}")
        == first.rule_count
    )
    assert sorted(
        rows(
            migrated_engine,
            "SELECT status, loads FROM helena_reference_public_suffix_load_counts",
        )
    ) == [(LOADED, 1), (UNCHANGED, 1)]


@pytest.mark.integration
def test_a_new_snapshot_replaces_the_previous_one(
    migrated_engine: psycopg.Connection, tmp_path: Path
):
    """One snapshot at a time, and the rules that left are gone from the table."""
    load(migrated_engine, EXTRACT)
    trimmed = tmp_path / "trimmed.dat"
    trimmed.write_bytes(b"// ===BEGIN ICANN DOMAINS===\ncom\nnet\n")
    second = load(migrated_engine, trimmed)

    assert second.status == LOADED
    migrated_engine.execute("FLUSH")
    assert sorted(
        rows(migrated_engine, f"SELECT rule FROM {PUBLIC_SUFFIX_TABLE}")
    ) == [("*",), ("com",), ("net",)]
    assert (
        one(
            migrated_engine,
            f"SELECT count(DISTINCT snapshot_version) FROM {PUBLIC_SUFFIX_TABLE}",
        )
        == 1
    )


@pytest.mark.integration
def test_a_fetch_that_failed_leaves_the_previous_snapshot_in_place(
    migrated_engine: psycopg.Connection, tmp_path: Path
):
    """`concept/instruction.md` §6: not an empty table, and not a silent one."""
    first = load(migrated_engine, EXTRACT)
    failed = load(migrated_engine, tmp_path / "there-is-no-such-file.dat")

    assert (failed.status, failed.failure_reason) == (FAILED, FETCH_FAILED)
    assert failed.snapshot_version is None and failed.rule_count is None
    assert failed.failure_detail

    migrated_engine.execute("FLUSH")
    assert rows(
        migrated_engine,
        f"SELECT DISTINCT snapshot_version FROM {PUBLIC_SUFFIX_TABLE}",
    ) == [(first.snapshot_version,)]
    assert rows(
        migrated_engine,
        "SELECT status, failure_reason, loads "
        "FROM helena_reference_public_suffix_load_counts WHERE status = %s",
        FAILED,
    ) == [(FAILED, FETCH_FAILED, 1)]


@pytest.mark.integration
def test_a_list_that_did_not_parse_leaves_the_previous_snapshot_in_place(
    migrated_engine: psycopg.Connection, tmp_path: Path
):
    """Parsing happens before the first INSERT, which is the whole point of it."""
    first = load(migrated_engine, EXTRACT)
    broken = tmp_path / "broken.dat"
    broken.write_bytes(b"// ===BEGIN ICANN DOMAINS===\ncom\nex..ample\n")
    failed = load(migrated_engine, broken)

    assert (failed.status, failed.failure_reason) == (FAILED, MALFORMED_RULE)
    migrated_engine.execute("FLUSH")
    assert rows(
        migrated_engine,
        f"SELECT DISTINCT snapshot_version FROM {PUBLIC_SUFFIX_TABLE}",
    ) == [(first.snapshot_version,)]


@pytest.mark.integration
def test_the_stored_source_url_went_through_the_redactor(
    migrated_engine: psycopg.Connection, tmp_path: Path
):
    """A credential in a URL is redacted before it is *stored*, not only logged.

    This list needs no credential — the rule is about the channel, and the
    provenance column is one of the places `concept/instruction.md` §6 names.
    """
    secret = settings().providers.abusech_auth_key.reveal()
    missing = tmp_path / f"{secret}" / "list.dat"
    result = load(migrated_engine, missing)

    assert result.status == FAILED
    migrated_engine.execute("FLUSH")
    stored = rows(
        migrated_engine,
        f"SELECT source_url, failure_detail FROM {PUBLIC_SUFFIX_LOAD_TABLE}",
    )
    assert stored and all(
        secret not in column for row in stored for column in row if column
    ), stored


# --- The derivation, against the publisher's own vectors -------------------


@pytest.mark.integration
def test_the_published_check_public_suffix_vectors_all_agree(
    loaded: psycopg.Connection, tmp_path: Path
):
    """Every vector, through the whole path: capture, events, entity, derivation.

    77 cases the suite would not have thought of on its own — mixed case, a
    leading dot, an unlisted TLD, a TLD whose only rule is a wildcard, wildcards
    with exceptions, four-label US K12 names, and IDN labels in both forms.
    """
    expected = vectors()
    assert len(expected) == 77, "the committed vector file changed"

    names = sorted({name for name, _ in expected})
    store_capture(loaded, capture_of_names(tmp_path, names, "vectors"))

    derived = {
        name: registrable
        for name, registrable in rows(
            loaded,
            f"SELECT observed_name, registrable_domain FROM {REGISTRABLE}",
        )
    }
    assert set(names) <= set(derived), sorted(set(names) - set(derived))
    disagreed = [
        (name, want, derived[name]) for name, want in expected if derived[name] != want
    ]
    assert disagreed == []


@pytest.mark.integration
def test_the_four_states_of_a_name_stay_apart(
    loaded: psycopg.Connection, tmp_path: Path
):
    """`derived`, `name_is_a_public_suffix` and `invalid_name` are three things.

    The fourth, `list_not_loaded`, is the test below — it needs an engine with
    no snapshot, which this fixture is the opposite of.
    """
    names = ["www.example.co.uk", "co.uk", "example", ".leading.com", "1.2.3.4"]
    store_capture(loaded, capture_of_names(tmp_path, names, "states"))

    assert dict(
        rows(
            loaded,
            f"SELECT observed_name, registrable_domain_status FROM {REGISTRABLE} "
            f"WHERE observed_name = ANY(%s)",
            names,
        )
    ) == {
        "www.example.co.uk": DERIVED,
        "co.uk": IS_A_PUBLIC_SUFFIX,
        # An unlisted single-label name is a public suffix by the default rule,
        # not an error and not a registrable domain.
        "example": IS_A_PUBLIC_SUFFIX,
        ".leading.com": INVALID_NAME,
        "1.2.3.4": INVALID_NAME,
    }
    assert dict(
        rows(
            loaded,
            f"SELECT observed_name, public_suffix FROM {REGISTRABLE} "
            f"WHERE observed_name = ANY(%s)",
            names,
        )
    ) == {
        "www.example.co.uk": "co.uk",
        "co.uk": "co.uk",
        "example": "example",
        ".leading.com": None,
        "1.2.3.4": None,
    }


@pytest.mark.integration
def test_a_name_with_no_list_loaded_says_so_rather_than_no_match(
    migrated_engine: psycopg.Connection, tmp_path: Path
):
    """`missing` and `no_match` are two things, and this is the seam between them.

    With a snapshot loaded, every valid name matches at least the default rule,
    so no match at all can only mean the reference table is empty. A row that
    said `name_is_a_public_suffix` here would be the collapse
    `concept/instruction.md` §2 forbids: it would read as "this name has no
    registrant part" when what happened is that nobody ever loaded the list.
    """
    store_capture(
        migrated_engine, capture_of_names(tmp_path, ["www.example.com"], "unloaded")
    )
    assert rows(
        migrated_engine,
        f"SELECT registrable_domain_status, registrable_domain, "
        f"public_suffix_snapshot_version FROM {REGISTRABLE}",
    ) == [(LIST_NOT_LOADED, None, None)]


@pytest.mark.integration
def test_loading_the_list_afterwards_fills_the_derivation_in(
    migrated_engine: psycopg.Connection, tmp_path: Path
):
    """The reference table is a table, so the join updates when it is written.

    Worth asserting rather than assuming: the derivation is a materialized view
    created by the migration, which is before any rule exists, and the whole
    design depends on rules arriving afterwards being picked up.
    """
    store_capture(
        migrated_engine, capture_of_names(tmp_path, ["www.example.com"], "later")
    )
    assert (
        one(
            migrated_engine,
            f"SELECT registrable_domain_status FROM {REGISTRABLE}",
        )
        == LIST_NOT_LOADED
    )

    result = load(migrated_engine, EXTRACT)
    migrated_engine.execute("FLUSH")
    assert rows(
        migrated_engine,
        f"SELECT registrable_domain_status, registrable_domain, "
        f"public_suffix_snapshot_version FROM {REGISTRABLE}",
    ) == [(DERIVED, "example.com", result.snapshot_version)]


@pytest.mark.integration
def test_the_candidate_suffixes_of_a_name_are_all_of_them(
    loaded: psycopg.Connection, tmp_path: Path
):
    """No depth limit: the candidates are bounded by the name's own labels.

    A deep name is the case a fixed limit would get wrong silently — the rule it
    should have matched is simply never offered to the join — so the count is
    asserted against the name rather than against a constant.
    """
    deep = "a.b.c.d.e.f.g.h.i.j.example.com"
    store_capture(loaded, capture_of_names(tmp_path, [deep], "deep"))

    candidates = rows(
        loaded,
        f"SELECT candidate_label_count, candidate FROM {SUFFIX_CANDIDATES} "
        f"WHERE observed_name = %s ORDER BY candidate_label_count",
        deep,
    )
    labels = deep.split(".")
    assert candidates == [
        (i, ".".join(labels[len(labels) - i :]) if i else "")
        for i in range(len(labels) + 1)
    ]
    assert one(
        loaded,
        f"SELECT registrable_domain FROM {REGISTRABLE} WHERE observed_name = %s",
        deep,
    ) == "example.com"


@pytest.mark.integration
def test_a_wildcard_needs_a_label_to_consume(loaded: psycopg.Connection, tmp_path: Path):
    """`*.ck` is not a public suffix of `ck`, and `*.kobe.jp` is not one of `kobe.jp`.

    The guard this discriminates is the one that keeps a wildcard rule from
    asserting a suffix longer than the name it matched. Mutation-checked: with
    the guard removed, the publisher's 77 vectors *all still pass* — none of
    them is a name equal to a wildcard rule's parent — while `kobe.jp` flips
    from a two-label registrable domain to no registrable domain at all, and
    `ck`'s public suffix is silently claimed to be two labels long inside a
    one-label name.

    That length is also what keeps the slice arithmetic in the derivation
    well-formed: `suffix_label_count <= name_label_count` holds only because of
    this guard, and an out-of-range slice clamps in RisingWave rather than
    raising, so the wrong answer would look like a right one.
    """
    names = ["ck", "kobe.jp", "b.c.mm"]
    store_capture(loaded, capture_of_names(tmp_path, names, "wildcards"))

    assert dict(
        rows(
            loaded,
            f"SELECT observed_name, public_suffix_label_count FROM {REGISTRABLE} "
            f"WHERE observed_name = ANY(%s)",
            names,
        )
    ) == {"ck": 1, "kobe.jp": 1, "b.c.mm": 2}
    assert dict(
        rows(
            loaded,
            f"SELECT observed_name, registrable_domain FROM {REGISTRABLE} "
            f"WHERE observed_name = ANY(%s)",
            names,
        )
    ) == {"ck": None, "kobe.jp": "kobe.jp", "b.c.mm": "b.c.mm"}


@pytest.mark.integration
def test_the_private_section_separates_shared_infrastructure(
    loaded: psycopg.Connection, tmp_path: Path
):
    """Two tenants of one platform are two registrants, and both sections say so.

    `data/threatfox/domains_recent.json` carries `*.workers.dev` names, which is
    the case this is about: an indicator on one tenant's name is not an
    indicator on another's, and an ICANN-only derivation would put both under
    `workers.dev` and lose the distinction entirely.
    """
    names = ["one.workers.dev", "two.workers.dev", "user.github.io"]
    store_capture(loaded, capture_of_names(tmp_path, names, "shared"))

    assert dict(
        rows(
            loaded,
            f"SELECT observed_name, registrable_domain FROM {REGISTRABLE} "
            f"WHERE observed_name = ANY(%s)",
            names,
        )
    ) == {
        "one.workers.dev": "one.workers.dev",
        "two.workers.dev": "two.workers.dev",
        "user.github.io": "user.github.io",
    }


@pytest.mark.integration
def test_the_name_as_observed_is_not_rewritten(
    loaded: psycopg.Connection, tmp_path: Path
):
    """ADR-0009's matching rule is about `entity_value`, and nothing touches it.

    Normalization happens beside the observed name, never onto it: the feed the
    prototype has matches on the name as observed, so a view that lowercased the
    entity value would silently change what that source is joined on.

    The sample carries no uppercase name at all — measured in 0007 — so the
    uppercase case is a real record with its query name recased, which the
    contract permits and this producer never emitted.
    """
    observed = "WwW.Example.COM."
    store_capture(loaded, capture_of_names(tmp_path, [observed], "cased"))

    assert rows(
        loaded,
        f"SELECT entity_value, normalized_name, registrable_domain "
        f"FROM {CONTEXT_DOMAINS} WHERE entity_value = %s",
        observed,
    ) == [(observed, "www.example.com", "example.com")]


# --- Over the real capture -------------------------------------------------


@pytest.mark.integration
def test_every_domain_entity_row_keeps_its_registrable_domain(
    loaded: psycopg.Connection,
):
    """The join in helena_signal_context_domains cannot drop or duplicate a row.

    Over the whole 62-record sample, so the count is the real one. A join key
    that silently matched nothing is exactly what this counts both sides of.
    """
    store_capture(loaded, describe_capture(SAMPLE))

    entities = one(
        loaded,
        "SELECT count(*) FROM helena_signal_context_entities "
        "WHERE entity_type = 'domain'",
    )
    assert entities > 0
    assert one(loaded, f"SELECT count(*) FROM {CONTEXT_DOMAINS}") == entities
    assert (
        one(
            loaded,
            f"SELECT count(*) FROM {CONTEXT_DOMAINS} "
            f"WHERE registrable_domain_status <> %s",
            DERIVED,
        )
        == 0
    )


@pytest.mark.integration
def test_the_real_names_resolve_to_the_registrable_domains_they_should(
    loaded: psycopg.Connection,
):
    """Real names from the sample, including the two that are not two labels.

    `in-addr.arpa` is a two-label public suffix in the ICANN section, and
    `trafficmanager.net` is one in the private section — the second is the
    hosting case ADR-0009 measured, where every name under it is a different
    Azure customer.
    """
    store_capture(loaded, describe_capture(SAMPLE))
    expected = {
        "ocsp.digicert.com": "digicert.com",
        "config.edge.skype.com": "skype.com",
        "217.106.137.52.in-addr.arpa": "52.in-addr.arpa",
    }
    assert dict(
        rows(
            loaded,
            f"SELECT observed_name, registrable_domain FROM {REGISTRABLE} "
            f"WHERE observed_name = ANY(%s)",
            sorted(expected),
        )
    ) == expected

    trafficmanager = rows(
        loaded,
        f"SELECT observed_name, registrable_domain, public_suffix FROM {REGISTRABLE} "
        f"WHERE observed_name LIKE %s",
        "%.trafficmanager.net",
    )
    assert trafficmanager
    for observed, registrable, suffix in trafficmanager:
        assert suffix == "trafficmanager.net"
        assert registrable == ".".join(observed.split(".")[-3:])


# --- The list itself, fetched -----------------------------------------------


def _live_list() -> bytes:
    """The published list, or a skip saying the machine cannot reach it.

    The URL is read out of `scripts/load_public_suffix_list.py` rather than
    written here, because that script is the one place a source is chosen and a
    second copy would be a second source.
    """
    url = re.search(
        r'^PUBLIC_SUFFIX_LIST_URL = "([^"]+)"$',
        LIVE_LIST_SCRIPT.read_text(),
        re.MULTILINE,
    )
    assert url, "scripts/load_public_suffix_list.py no longer names the list"
    try:
        with urllib.request.urlopen(url.group(1), timeout=60) as response:
            return response.read()
    except (urllib.error.URLError, OSError) as unreachable:
        pytest.skip(f"cannot reach the published list: {unreachable}")


@pytest.mark.integration
def test_the_published_list_is_still_the_format_this_parses():
    """The artifact, not the page. It changes on the publisher's schedule."""
    rules = parse_public_suffix_list(_live_list())
    sections = {rule.section for rule in rules}
    assert sections == {ICANN_SECTION, PRIVATE_SECTION, DEFAULT_SECTION}
    assert len(rules) > 5000, len(rules)
    assert any(rule.is_wildcard and rule.rule != DEFAULT_RULE for rule in rules)
    assert any(rule.is_exception for rule in rules)


@pytest.mark.integration
def test_the_extract_answers_as_the_published_list_does():
    """The committed extract is a subset, so it has to be a *sufficient* one.

    Sufficiency is a property of the inputs, not of the derivation: for every
    name the suite tests, the two lists have to offer the join the same rules.
    Restricted to those names' candidate suffixes, they do — or this file is
    stale and needs regenerating from the current snapshot, which is what a
    failure here means.
    """
    live = parse_public_suffix_list(_live_list())
    extract = parse_public_suffix_list(EXTRACT.read_bytes())

    names = {name for name, _ in vectors()} | _sample_names() | {
        "one.workers.dev",
        "two.workers.dev",
        "user.github.io",
        "a.b.c.d.e.f.g.h.i.j.example.com",
        "WwW.Example.COM.",
        "www.example.co.uk",
        "co.uk",
        "example",
        ".leading.com",
        "1.2.3.4",
    }
    candidates = set()
    for name in names:
        labels = name.lower().rstrip(".").split(".")
        for depth in range(len(labels) + 1):
            candidates.add(".".join(labels[len(labels) - depth :]) if depth else "")

    def offered(rules) -> set[tuple]:
        return {
            (rule.rule, rule.suffix, rule.is_wildcard, rule.is_exception)
            for rule in rules
            if rule.suffix in candidates
        }

    assert offered(extract) == offered(live)


def _sample_names() -> set[str]:
    """Every domain name `data/ingest/flow-sample.jsonl` carries."""
    from urllib.parse import urlsplit

    found: set[str] = set()
    for line in SAMPLE.read_bytes().splitlines():
        record = json.loads(line)
        dns = record.get("dns") or {}
        found.update(query["qn"] for query in dns.get("queries") or [])
        found.update(response["qn"] for response in dns.get("responses") or [])
        server_name = (record.get("tls") or {}).get("sni")
        if server_name:
            found.add(server_name)
        for layer in ("http", "http2"):
            for request in (record.get(layer) or {}).get("req") or []:
                host = urlsplit(request.get("uri", "")).hostname
                if host:
                    found.add(host)
    return found
