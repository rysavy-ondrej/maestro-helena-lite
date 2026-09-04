"""The version registry, and the one constant that has two copies.

The point of the integration half is the last invariant of
`concept/instruction.md` §2: *two copies of a version constant must be asserted
equal by a test — the SQL and the Python*. It is asserted the only way that
means anything, by applying the migrations to a throwaway engine and asking the
engine what it now returns. Reading the `.sql` file would find the value in the
comment that explains it.

The engine tests also pin one measured limitation rather than an assumed one: a
streaming query cannot read the constant view, so a D2 aggregation view has to
carry the literal itself. That is a fact about RisingWave 3.0.3, and a test is
how a later engine version lifting it becomes news instead of folklore.
"""

from __future__ import annotations

import io
import json

import psycopg
import pytest

from helena.observability import Redactor, StructuredLogger
from helena.versions import (
    AGGREGATION_VERSION,
    AGGREGATION_VERSION_VIEW,
    VERSION_COLUMNS,
    VersionSet,
)

# The dimensions concept/07-principles.md names, spelled out here on purpose:
# deriving them from the model would make a dropped dimension invisible.
DIMENSIONS = (
    "model_version",
    "prompt_version",
    "schema_version",
    "rendering_version",
    "taxonomy_version",
    "enrichment_snapshot_version",
    "policy_version",
    "aggregation_version",
)


def a_version_set(**overrides: str) -> VersionSet:
    """A full version set with recognisable values, for the cases that need one."""
    values = {dimension: f"{dimension}-under-test" for dimension in DIMENSIONS}
    values["aggregation_version"] = AGGREGATION_VERSION
    return VersionSet(**{**values, **overrides})


# --- The dimensions ----------------------------------------------------------


def test_a_version_set_records_every_dimension_the_principles_name():
    assert VERSION_COLUMNS == DIMENSIONS


def test_a_missing_dimension_is_refused_and_named():
    values = {dimension: "v1" for dimension in DIMENSIONS}
    del values["rendering_version"]

    with pytest.raises(ValueError, match="rendering_version"):
        VersionSet(**values)


def test_a_dimension_that_is_not_one_is_refused():
    with pytest.raises(ValueError, match="feed_version"):
        a_version_set(feed_version="v1")


@pytest.mark.parametrize("value", ["", " ", "\t", "v1 and v2", "v1\n"])
def test_a_version_that_is_not_an_identifier_is_refused(value: str):
    with pytest.raises(ValueError, match="prompt_version"):
        a_version_set(prompt_version=value)


def test_a_model_version_shaped_like_a_hosted_model_id_is_accepted():
    """The value is whatever the endpoint calls itself; it is not reformatted."""
    reported = "vendor/Model-Name-70B-Instruct:2026-05-01"
    assert a_version_set(model_version=reported).model_version == reported


def test_a_rejected_value_is_not_echoed_in_the_error():
    """A wrong value in a version field must not land in a traceback.

    Task 01 measured the leak this closes: Pydantic echoes the rejected input
    unless `hide_input_in_errors` is set, so a credential passed to the wrong
    field reaches whoever reads the error.
    """
    wrong = "not a version but it could have been a token"

    with pytest.raises(ValueError) as raised:
        a_version_set(policy_version=wrong)

    echoed = wrong in str(raised.value)
    assert not echoed, "the rejected value was echoed in the ValidationError"


def test_a_version_set_is_frozen():
    versions = a_version_set()
    with pytest.raises(ValueError):
        versions.taxonomy_version = "v2"


# --- Stamping a row ----------------------------------------------------------


def test_stamping_adds_the_version_columns_and_leaves_the_row_alone():
    row = {"assessment_id": "a-1", "verdict": "normal"}

    stamped = a_version_set().stamp(row)

    assert row == {"assessment_id": "a-1", "verdict": "normal"}
    assert set(stamped) == set(row) | set(DIMENSIONS)
    assert stamped["assessment_id"] == "a-1"
    assert stamped["aggregation_version"] == AGGREGATION_VERSION


def test_stamping_a_row_that_already_carries_a_version_is_refused():
    stamped = a_version_set().stamp({"assessment_id": "a-1"})

    with pytest.raises(ValueError, match="already carries"):
        a_version_set(taxonomy_version="v2").stamp(stamped)


def test_a_stamped_row_round_trips_back_into_the_set_that_stamped_it():
    versions = a_version_set()

    assert VersionSet.from_row(versions.stamp({"assessment_id": "a-1"})) == versions


def test_a_row_that_records_no_version_is_refused_by_name():
    row = a_version_set().stamp({"assessment_id": "a-1"})
    del row["enrichment_snapshot_version"]

    with pytest.raises(ValueError, match="enrichment_snapshot_version"):
        VersionSet.from_row(row)


def test_the_columns_are_the_field_names():
    """One name per dimension, so a written row and a read row cannot disagree."""
    assert a_version_set().as_columns().keys() == set(DIMENSIONS)


# --- What carries the set ----------------------------------------------------


def test_a_version_set_goes_into_a_log_record_whole():
    """`versions` on a log record is this set, not a subset of it.

    The emitter refuses an empty version set; this is the other half — what it
    is handed is the full set, and every dimension survives serialization.
    """
    stream = io.StringIO()
    log = StructuredLogger(
        component="orchestration",
        tenant="tenant-under-test",
        sensor="sensor-under-test",
        # Not a credential, and nothing here is one — a Redactor refuses to be
        # built with nothing registered, because one that redacts nothing looks
        # exactly like one that works.
        redactor=Redactor(["fake-auth-key-0123456789abcdef"]),
        stream=stream,
    )

    log.info("assessment.stored", versions=a_version_set().as_columns())

    record = json.loads(stream.getvalue())
    assert record["versions"] == a_version_set().as_columns()


# --- The SQL copy, by execution ----------------------------------------------


@pytest.mark.integration
def test_the_aggregation_version_in_the_engine_equals_the_python_constant(
    migrated_engine: psycopg.Connection,
):
    """The two copies of the aggregation version, asked of the engine.

    This is the invariant that makes the duplication acceptable at all: the
    version is in `sql/migrations/0002_aggregation_version.sql` and in
    `helena.versions`, and a drift between them is a failing test.
    """
    row = migrated_engine.execute(
        f"SELECT aggregation_version FROM {AGGREGATION_VERSION_VIEW}"
    ).fetchall()

    assert row == [(AGGREGATION_VERSION,)]


@pytest.mark.integration
def test_the_aggregation_version_is_a_plain_view(migrated_engine: psycopg.Connection):
    """Declared a view, not a materialized view — and the engine agrees.

    One constant with no writer is not worth a table's state or an MV's disk.
    """
    row = migrated_engine.execute(
        "SELECT table_type FROM information_schema.tables "
        "WHERE table_schema = current_schema() AND table_name = %s",
        (AGGREGATION_VERSION_VIEW,),
    ).fetchall()

    assert row == [("VIEW",)]


@pytest.mark.integration
def test_a_streaming_view_cannot_read_the_aggregation_version(
    migrated_engine: psycopg.Connection,
):
    """Measured, not assumed: this is why a D2 aggregation view carries the literal.

    RisingWave 3.0.3 plans the join against a one-row constant view as a
    nested-loop join and refuses it in a streaming query. A batch SELECT over
    the same view is fine — the two tests above are exactly that. If this ever
    stops raising, the aggregation views can take the version from one place and
    this test is the notification.
    """
    with pytest.raises(psycopg.Error, match="nested-loop join"):
        migrated_engine.execute(
            f"CREATE MATERIALIZED VIEW versioned_ledger AS "
            f"SELECT l.version, v.aggregation_version "
            f"FROM helena_schema_migrations l "
            f"CROSS JOIN {AGGREGATION_VERSION_VIEW} v"
        )
