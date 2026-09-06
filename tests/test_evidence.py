"""Enrichment evidence: the five things that may never be collapsed into one.

`concept/instruction.md`: *"`stale`, `failed`, `missing` and `no_match` are four
different things, and a typed error is a fifth. Never collapse them, at any
layer, for any reason."* Most of this file is that sentence, made to fail.

The engine table and the Python model are asserted equal by execution rather than
by reading, the way `tests/test_context.py` treats the flatten shapes: a column
that stopped meaning what it meant fails here instead of reaching a join.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import psycopg
import pytest
from psycopg.types.json import Jsonb
from pydantic import ValidationError

from helena import taxonomy
from helena.enrichment import (
    ENRICHMENT_EVIDENCE_VIEW,
    ENRICHMENT_STATUSES,
    MAX_FAILURE_DETAIL,
    MISSING,
    NO_MATCH,
    OK,
    QUERY_FAILED,
    QUERY_FAILURE_REASONS,
    STALE,
    TIMEOUT,
    EnrichmentEvidence,
    QueryFailure,
    Tier,
    evidence_id,
)

# The engine's column set, held here as the second copy of the interface — the
# same deliberate friction FLATTEN_SHAPES and REGISTRABLE_SHAPE are. A migration
# that adds or renames a column fails here until somebody decides it should.
EVIDENCE_SHAPE = {
    "tenant",
    "sensor",
    "evidence_id",
    "source_id",
    "source_tier",
    "snapshot_version",
    "entity_type",
    "entity_value",
    "status",
    "classification",
    "taxonomy_version",
    "confidence",
    "scope_type",
    "scope_value",
    "first_seen",
    "last_seen",
    "valid_until",
    "native_evidence",
}


def claim(**overrides: Any) -> EnrichmentEvidence:
    """A well-formed `ok` claim, for a test to break one field of."""
    fields: dict[str, Any] = {
        "evidence_id": "0" * 64,
        "source_id": "threatfox",
        "source_tier": Tier.B,
        "snapshot_version": "snapshot-1",
        "entity_type": "domain",
        "entity_value": "bad.test",
        "status": OK,
        "classification": "malicious",
        "taxonomy_version": "v1",
        "confidence": 0.9,
        "scope_type": "domain",
        "scope_value": "bad.test",
    }
    fields.update(overrides)
    return EnrichmentEvidence(**fields)


# --- The statuses, and what each one is not ---------------------------------


def test_the_four_statuses_are_the_ones_the_concept_note_names():
    assert ENRICHMENT_STATUSES == ("ok", "stale", "failed", "missing")


def test_no_match_is_a_classification_and_never_a_status():
    """The distinction the whole row is shaped around.

    A source that ran and found nothing is `ok` + `no_match`. A source that could
    not be asked is `missing`. Reading the second as the first is
    `concept/02`'s named failure mode — "triage reading 'no hit' as 'clean'" —
    with the ambiguity moved one layer down.
    """
    assert NO_MATCH not in ENRICHMENT_STATUSES
    with pytest.raises(ValidationError, match="never a status"):
        claim(status=NO_MATCH)


def test_a_status_that_answered_must_carry_a_classification():
    """`ok` with nothing said is the collapse this refuses.

    An answer of "nothing listed" is the classification `no_match`, not an absent
    classification — otherwise a null would mean both "found nothing" and "was
    never asked".
    """
    with pytest.raises(ValidationError, match="not an absent one"):
        claim(status=OK, classification=None, taxonomy_version=None)
    with pytest.raises(ValidationError, match="not an absent one"):
        claim(status=STALE, classification=None, taxonomy_version=None)


@pytest.mark.parametrize("status", [QUERY_FAILED, MISSING])
def test_a_status_that_did_not_answer_may_not_carry_a_classification(status: str):
    """`concept/05` rule 4: a typed error and **no taxonomy object**."""
    with pytest.raises(ValidationError, match="no taxonomy object"):
        claim(status=status)


@pytest.mark.parametrize("status", [QUERY_FAILED, MISSING])
def test_a_row_that_did_not_answer_is_well_formed_without_one(status: str):
    row = claim(status=status, classification=None, taxonomy_version=None, confidence=None)
    assert row.classification is None
    assert row.verdict is None


def test_stale_is_a_claim_that_stands_and_missing_is_not_a_claim_at_all():
    """Two of the four, and the difference is whether anything was said.

    A stale snapshot still holds what it held; its age is part of what it is
    worth. `missing` is no snapshot to consult, which is not a source finding
    nothing.
    """
    stale = claim(status=STALE)
    assert stale.classification == "malicious"
    missing = claim(status=MISSING, classification=None, taxonomy_version=None, confidence=None)
    assert missing.classification is None
    assert stale.status != missing.status


# --- A failed query is a typed error, never a verdict -----------------------


def test_a_timeout_is_a_typed_error_and_not_no_match_or_unknown():
    """`concept/02`: both of those are analysis results returned after a
    **successful** query.

    The strongest available statement of that is structural: `QueryFailure` has
    no field a classification could go in, so a timeout cannot become one by
    accident. The reason is typed, so the four failure kinds stay apart too.
    """
    failure = QueryFailure(
        source_id="threatfox",
        entity_type="domain",
        entity_value="bad.test",
        reason=TIMEOUT,
        detail="no response within the request deadline",
    )
    assert failure.reason == TIMEOUT
    assert "classification" not in QueryFailure.model_fields
    assert "confidence" not in QueryFailure.model_fields
    assert TIMEOUT not in ENRICHMENT_STATUSES
    for absent in (NO_MATCH, "unknown"):
        assert absent not in QUERY_FAILURE_REASONS


def test_the_failure_reasons_are_typed():
    with pytest.raises(ValidationError, match="is not one of"):
        QueryFailure(
            source_id="threatfox",
            entity_type="domain",
            entity_value="bad.test",
            reason="something went wrong",
        )


def test_a_failure_object_has_nowhere_to_put_a_provider_response():
    """`concept/02`: "never carries secrets, authorization headers or full
    provider responses."

    Enforced by the shape rather than by review: the field set is exactly five,
    and `extra="forbid"` means a caller cannot add one. A test on the field set
    makes adding one a deliberate act with a test to change.
    """
    assert set(QueryFailure.model_fields) == {
        "source_id",
        "entity_type",
        "entity_value",
        "reason",
        "detail",
    }
    for forbidden in ("response", "headers", "authorization", "body", "payload"):
        with pytest.raises(ValidationError):
            QueryFailure(
                source_id="threatfox",
                entity_type="domain",
                entity_value="bad.test",
                reason=TIMEOUT,
                **{forbidden: "..."},
            )


def test_the_detail_is_bounded_so_a_response_body_cannot_be_pasted_in():
    """An unbounded diagnostic is where `str(response)` ends up."""
    QueryFailure(
        source_id="threatfox",
        entity_type="domain",
        entity_value="bad.test",
        reason=TIMEOUT,
        detail="x" * MAX_FAILURE_DETAIL,
    )
    with pytest.raises(ValidationError, match="the limit is"):
        QueryFailure(
            source_id="threatfox",
            entity_type="domain",
            entity_value="bad.test",
            reason=TIMEOUT,
            detail="x" * (MAX_FAILURE_DETAIL + 1),
        )


# --- Confidence is in the mapping ------------------------------------------


def test_no_match_with_confidence_one_is_representable():
    """`concept/02`, in as many words: "A definitive negative answer can be
    `no_match` with confidence `1.0`."

    This is the test that says `confidence` is not P(malicious). Under that
    reading the row below is nonsense — certainty that a thing is malicious,
    labelled as not listed — and under the right one it is a source saying "I
    looked, it is definitively not in my data, and I am sure of the lookup".
    """
    row = claim(classification=NO_MATCH, confidence=1.0)
    assert row.classification == NO_MATCH
    assert row.confidence == 1.0
    assert row.verdict == NO_MATCH
    assert row.status == OK


def test_confidence_is_optional_and_bounded():
    assert claim(confidence=None).confidence is None
    for outside in (-0.1, 1.1):
        with pytest.raises(ValidationError, match="outside"):
            claim(confidence=outside)


def test_confidence_is_not_the_tier():
    """The tier is about the source; this is about this mapping of this entry.

    A tier-C source can be certain of a lookup, and a tier-A source can map an
    entry it is unsure about.
    """
    low = claim(source_tier=Tier.A, confidence=0.1)
    high = claim(source_tier=Tier.C, confidence=1.0)
    assert low.source_tier is Tier.A and low.confidence == 0.1
    assert high.source_tier is Tier.C and high.confidence == 1.0


# --- Time: nullable, and never invented -------------------------------------


def test_the_time_fields_default_to_absent_rather_than_to_now():
    """`concept/05`: do not invent missing precision.

    A `last_seen` defaulted to the load time would make every stale claim look
    fresh, which is the fact the `stale` status exists to make visible.
    """
    row = claim()
    assert (row.first_seen, row.last_seen, row.valid_until) == (None, None, None)


def test_what_dates_a_claim_is_first_seen_plus_the_snapshot():
    """`concept/05`: "recency cannot be read from last-seen alone"."""
    seen = datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert claim(first_seen=seen).dated_by == f"{seen.isoformat()} in snapshot snapshot-1"
    assert "unknown first-seen" in claim().dated_by


# --- The verdict is derived --------------------------------------------------


def test_the_verdict_is_the_root_of_the_classification_and_is_not_stored():
    assert claim(classification="malicious").verdict == "malicious"
    assert claim(classification=NO_MATCH).verdict == NO_MATCH
    assert "verdict" not in EnrichmentEvidence.model_fields
    assert "verdict" not in EVIDENCE_SHAPE


def test_a_classification_outside_the_taxonomy_is_a_taxonomy_error():
    """And not a `ValidationError`, deliberately.

    Every other refusal here raises `ValueError`, which Pydantic turns into a
    `ValidationError` about a field. A path the vocabulary does not have is not a
    malformed field — it is a taxonomy fact — and `helena.taxonomy` already
    distinguishes "not in the vocabulary" from "declared but unused". Flattening
    it into a field error would throw that away at the first caller, which is
    `concept/instruction.md` §2's rule about two facts and one value.
    """
    with pytest.raises(taxonomy.TaxonomyError, match="Emit the parent"):
        claim(classification="malicious.ransomware")
    # And the ordinary field failures are still ordinary field failures.
    with pytest.raises(ValidationError):
        claim(confidence=2.0)


def test_a_classification_without_a_taxonomy_version_cannot_be_replayed():
    with pytest.raises(ValidationError, match="which vocabulary"):
        claim(taxonomy_version=None)


# --- The identifier: stable, and not (entity, source) -----------------------


def _id(**overrides: Any) -> str:
    fields: dict[str, Any] = {
        "tenant": "acme",
        "sensor": "sensor-1",
        "source_id": "netify",
        "snapshot_version": "snapshot-1",
        "entity_type": "address",
        "entity_value": "1.62.64.112",
        "classification": "normal",
        "scope_type": "address",
        "scope_value": "1.62.64.112",
        "native_record": "netify-row-1",
    }
    fields.update(overrides)
    return evidence_id(**fields)


def test_the_same_claim_twice_is_the_same_row():
    """Replaying a load must write the same row, not a second copy.

    An INSERT onto an existing key in RisingWave is a silent upsert, so
    idempotence has to come from the key rather than from anybody remembering.
    """
    assert _id() == _id()


def test_two_claims_from_one_source_about_one_entity_are_two_rows():
    """`docs/decisions/0009`: the schema carries N rows per entity.

    Netify puts up to 75 applications on one address, differing only in the
    application they name. A digest over source, snapshot and entity alone would
    make those 75 one row and silently keep the last — the exact discard ADR-0009
    measured at 124 653 rows.
    """
    assert _id(native_record="netify-row-1") != _id(native_record="netify-row-2")


def test_the_native_record_is_the_publishers_key_and_not_a_payload_digest():
    """A payload digest would mint a new identifier whenever a field nobody reads
    changed; the publisher's key is what the publisher means by "this record".

    `sql/migrations/0014_feed_mapping_views.sql` is what produces the identifier
    in practice, and `tests/test_mapping.py` asserts it agrees with this.
    """
    assert _id(native_record="1901959:0") != _id(native_record="1901959:1")
    assert _id(native_record="1901959:0") == _id(native_record="1901959:0")


def test_two_deployments_do_not_mint_the_same_id():
    """The reason `helena.normalizer._event_id` carries the identity too."""
    assert _id(tenant="acme") != _id(tenant="other")
    assert _id(sensor="sensor-1") != _id(sensor="sensor-2")


def test_a_claim_that_goes_stale_keeps_its_identity():
    """The status is deliberately not in the digest.

    A claim that ages is the same claim; its status is what this deployment
    currently thinks of it. In the digest, every snapshot that aged would mint a
    new row for a claim nobody re-made.
    """
    identifier = _id()
    aged = claim(evidence_id=identifier, status=STALE)
    fresh = claim(evidence_id=identifier, status=OK)
    assert aged.evidence_id == fresh.evidence_id


def test_the_snapshot_is_in_the_digest():
    """A claim from a later snapshot is a different claim, and both are kept.

    `concept/02`: replay joins the snapshot current at event time, not today's,
    which is only possible if both rows exist.
    """
    assert _id(snapshot_version="snapshot-1") != _id(snapshot_version="snapshot-2")


# --- Where the rest of this went -------------------------------------------
#
# The engine-facing tests -- the column shape, the round trip, a stored
# classification resolving against the version beside it -- are in
# `tests/test_mapping.py` now. `sql/migrations/0014_feed_mapping_views.sql`
# made the evidence shape a VIEW derived from each feed's reference table rather
# than a table a loader writes, so the thing to assert against the model is what
# the view produces, and the file that asserts it is the one that also checks the
# mapping produced it correctly.
#
# What stays here is the model: the statuses, the four ways there is no claim,
# the typed failure, and the identifier's construction. None of those need an
# engine, and they are the contract the view has to satisfy.
