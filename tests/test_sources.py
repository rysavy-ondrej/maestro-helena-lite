"""The source registry: tiers, declared subsets, and not counting one source twice.

`concept/02-concepts-and-taxonomy.md` gives the tier table and the normalization
rules; `concept/05-threat-intelligence.md` gives the catalogue and the seven rules
every source adapter must follow. The tests here are the ones that can fail:
rule 1 says a declared subset must be *tested*, and rules 2 and 7 about
aggregators are the reason `source_diversity` is a function rather than a `len()`
at a call site.

Nothing emits a claim yet — no feed loader exists — so what is exercised is the
declaration and the counting, not a mapping. `tests/test_enrichment.py` holds the
one loader that does exist, which registers nothing because it makes no claims.
"""

from __future__ import annotations

import pytest

from helena import taxonomy
from helena.enrichment import (
    NO_MATCH,
    SOURCES,
    Claim,
    SourceDescriptor,
    SourceError,
    Tier,
    UndeclaredClaim,
    check_claim,
    origins,
    source,
    source_diversity,
)


# --- Tiers describe the source, not the entry -------------------------------


def test_the_tiers_are_the_four_the_concept_note_defines():
    assert [tier.value for tier in Tier] == ["A", "B", "C", "D"]


def test_only_a_and_b_escalate_independently():
    """`concept/instruction.md`: a `normal` from a model may not suppress a
    high-confidence match — and the tier is what decides which matches those are.

    C and D cannot: C is aggregated reputation and heuristics, where
    `concept/02` says two independent sources may raise confidence rather than
    one settling it, and D is context only.
    """
    assert [tier for tier in Tier if tier.escalates_independently] == [Tier.A, Tier.B]


def test_the_registered_sources_carry_the_tier_the_catalogue_gives_them():
    """`concept/05`'s catalogue table, not a choice made here."""
    assert source("threatfox").tier is Tier.B
    assert source("sslbl-ja3").tier is Tier.C


def test_the_ja3_caveat_is_on_the_descriptor():
    """`concept/05`: "The JA3 caveat stands and does not improve."

    Recorded where a consumer reads the source rather than in prose it may never
    open. The specific facts are asserted because a caveat that softened into
    "some limitations apply" would pass a test for its mere presence.
    """
    caveat = source("sslbl-ja3").caveat
    assert "static since" in caveat
    assert "untested against known-good traffic" in caveat
    assert "false positives" in caveat
    assert source("threatfox").caveat == ""


def test_an_unregistered_source_names_what_is_registered():
    """Adding a source is a governed decision, so the refusal says so."""
    with pytest.raises(SourceError, match="governed decision"):
        source("virustotal")


# --- The declared subset, and testing it ------------------------------------


def test_every_declared_path_exists_in_the_taxonomy_version_it_names():
    """The join between `concept/05` rule 1 and `helena.taxonomy`.

    A published subset naming a path the vocabulary does not have would be a
    claim nothing could ever validate. Checked here over the real registry as
    well as on construction, so the registry itself is covered.
    """
    for descriptor in SOURCES.values():
        for path in sorted(descriptor.emits):
            resolved = taxonomy.resolve(
                path, level=taxonomy.EVIDENCE, version=descriptor.taxonomy_version
            )
            assert resolved.path == path


def test_every_subset_contains_no_match():
    """`concept/05` rule 1: a hit maps to the path, "an explicit absence to
    `no_match`, and nothing else".

    `concept/02` is emphatic about why it matters: with sparse coverage most
    entities have no hit on anything, and triage reading "no hit" as "clean" is
    the failure mode the whole design exists to prevent. A source that could not
    say `no_match` would leave that silence unlabelled.
    """
    for descriptor in SOURCES.values():
        assert NO_MATCH in descriptor.emits


def test_a_subset_without_no_match_is_refused():
    with pytest.raises(SourceError, match="explicit absence"):
        SourceDescriptor(
            source_id="probe",
            tier=Tier.C,
            entity_types=frozenset({"domain"}),
            emits=frozenset({"suspicious"}),
            taxonomy_version="v1",
            emit_subset_version="v1",
        )


def test_a_subset_naming_a_path_the_taxonomy_lacks_is_refused():
    with pytest.raises(taxonomy.TaxonomyError):
        SourceDescriptor(
            source_id="probe",
            tier=Tier.B,
            entity_types=frozenset({"domain"}),
            emits=frozenset({"malicious.ransomware", NO_MATCH}),
            taxonomy_version="v1",
            emit_subset_version="v1",
        )


def test_a_descriptor_naming_an_entity_type_no_context_row_has_is_refused():
    """A source declaring coverage of something nothing can join to."""
    with pytest.raises(SourceError, match="are not among"):
        SourceDescriptor(
            source_id="probe",
            tier=Tier.C,
            entity_types=frozenset({"asn"}),
            emits=frozenset({NO_MATCH}),
            taxonomy_version="v1",
            emit_subset_version="v1",
        )


def test_the_subset_is_versioned():
    for descriptor in SOURCES.values():
        assert descriptor.emit_subset_version.strip()
    with pytest.raises(SourceError, match="no version"):
        SourceDescriptor(
            source_id="probe",
            tier=Tier.C,
            entity_types=frozenset({"domain"}),
            emits=frozenset({NO_MATCH}),
            taxonomy_version="v1",
            emit_subset_version="  ",
        )


# --- Every claim a source emits is inside its declared subset ---------------


def test_a_claim_inside_the_declared_subset_is_accepted():
    claim = Claim(
        source_id="threatfox",
        entity_type="domain",
        entity_value="example.test",
        path="malicious",
    )
    assert check_claim(claim) is claim


def test_a_claim_outside_the_declared_subset_is_refused():
    """`concept/05` rule 1 requires the subset to be tested; this is the test.

    `sslbl-ja3` is tier C with a caveat saying its entries are untested against
    known-good traffic, so `malicious` is not in its subset — a hit is a material
    risk signal and not an established fact about behaviour.
    """
    with pytest.raises(UndeclaredClaim, match="outside its declared subset"):
        check_claim(
            Claim(
                source_id="sslbl-ja3",
                entity_type="fingerprint",
                entity_value="28a2c9bd18a11de089ef85a160da29e4",
                path="malicious",
            )
        )


def test_an_invalid_path_is_a_taxonomy_error_and_not_a_source_error():
    """Two facts, two errors — `concept/instruction.md` §2.

    "Not in the vocabulary" is a different failure from "valid, and this source
    did not declare it": the first is a bug in the mapping's vocabulary, the
    second is drift between a mapping and its published subset.
    """
    with pytest.raises(taxonomy.TaxonomyError) as raised:
        check_claim(
            Claim(
                source_id="threatfox",
                entity_type="domain",
                entity_value="example.test",
                path="malicious.invented",
            )
        )
    assert not isinstance(raised.value, UndeclaredClaim)


def test_a_claim_about_an_entity_type_the_source_does_not_cover_is_refused():
    """A JA3 list has nothing to say about a domain."""
    with pytest.raises(UndeclaredClaim, match="declares"):
        check_claim(
            Claim(
                source_id="sslbl-ja3",
                entity_type="domain",
                entity_value="example.test",
                path="suspicious",
            )
        )


# --- Aggregators, and not counting one source many times --------------------


AGGREGATOR = SourceDescriptor(
    source_id="probe-aggregator",
    tier=Tier.C,
    entity_types=frozenset({"address"}),
    emits=frozenset({"suspicious", NO_MATCH}),
    taxonomy_version="v1",
    emit_subset_version="v1",
    aggregator=True,
)


@pytest.fixture
def registered_aggregator():
    """An aggregator in the registry for the length of one test.

    The real catalogue has none — `concept/05` accepts ThreatFox and Netify, and
    neither republishes another source — so the rule is exercised against a
    descriptor built here rather than left untested until one arrives.
    """
    SOURCES[AGGREGATOR.source_id] = AGGREGATOR
    try:
        yield AGGREGATOR
    finally:
        del SOURCES[AGGREGATOR.source_id]


def _claim(source_id: str, value: str, origin: str | None = None) -> Claim:
    return Claim(
        source_id=source_id,
        entity_type="address",
        entity_value=value,
        path="suspicious",
        origin=origin,
    )


def test_a_source_that_is_not_an_aggregator_may_not_attribute_evidence_elsewhere():
    """`concept/05` rule 7: retain the origin — and only a republisher has one.

    A non-aggregator carrying somebody else's attribution is either
    misattributing or is an aggregator nobody declared, and both are worth
    stopping.
    """
    with pytest.raises(UndeclaredClaim, match="not an aggregator"):
        check_claim(
            Claim(
                source_id="sslbl-ja3",
                entity_type="fingerprint",
                entity_value="28a2c9bd18a11de089ef85a160da29e4",
                path="suspicious",
                origin="somebody-else",
            )
        )


def test_one_source_making_many_claims_is_one_source():
    claims = [_claim("sslbl-ja3", f"10.0.0.{n}") for n in range(40)]
    assert source_diversity(claims) == 1


def test_an_aggregator_with_no_origin_retained_is_one_vote(registered_aggregator):
    """`concept/02`: "An aggregator is never counted as many votes."

    Forty rows republished with nothing saying where they came from are one
    source's opinion forty times, not forty sources agreeing.
    """
    claims = [_claim(registered_aggregator.source_id, f"10.0.0.{n}") for n in range(40)]
    for claim in claims:
        check_claim(claim)
    assert source_diversity(claims) == 1


def test_an_aggregator_that_retains_origins_counts_them(registered_aggregator):
    claims = [
        _claim(registered_aggregator.source_id, "10.0.0.1", origin="feed-p"),
        _claim(registered_aggregator.source_id, "10.0.0.2", origin="feed-q"),
    ]
    for claim in claims:
        check_claim(claim)
    assert source_diversity(claims) == 2


def test_the_same_origin_direct_and_through_an_aggregator_is_one(registered_aggregator):
    """The correlated-source case the rule is actually about.

    `concept/02` normalization rule 2: do not double-count correlated sources.
    Evidence that reached us twice — once from its origin and once copied — is
    one source, and a diversity count that said two would be the double-count
    the rule names.
    """
    claims = [
        _claim("sslbl-ja3", "10.0.0.1"),
        _claim(registered_aggregator.source_id, "10.0.0.1", origin="sslbl-ja3"),
    ]
    assert source_diversity(claims) == 1


def test_diversity_is_counted_over_origins_and_the_grouping_shows_what_it_counted(
    registered_aggregator,
):
    """A count with no way to see what went into it cannot be argued with.

    `concept/05` rule 6 also requires contradictions to survive to the agent, so
    the claims are grouped rather than reduced.
    """
    claims = [
        _claim("sslbl-ja3", "10.0.0.1"),
        _claim(registered_aggregator.source_id, "10.0.0.1", origin="sslbl-ja3"),
        _claim(registered_aggregator.source_id, "10.0.0.2", origin="feed-q"),
    ]
    grouped = origins(claims)
    assert sorted(grouped) == ["feed-q", "sslbl-ja3"]
    assert len(grouped["sslbl-ja3"]) == 2
    assert source_diversity(claims) == len(grouped)


def test_no_claims_is_no_diversity():
    """Zero, and not an error: nothing said anything, which is a real answer.

    Distinct from `no_match`, which is a source that ran and found nothing.
    """
    assert source_diversity([]) == 0
    assert origins([]) == {}


# --- The Public Suffix List is deliberately not a source --------------------


def test_the_public_suffix_list_is_not_in_the_registry():
    """`concept/05` gives it tier **N/A rather than unassigned**.

    It is normalization needed for scope correctness, it makes no claim about any
    entity, and it can neither escalate nor suppress. Its absence from a registry
    of claim-emitting sources is the statement; this is what makes it one rather
    than an oversight.
    """
    assert "public-suffix-list" not in SOURCES
    assert not [key for key in SOURCES if "suffix" in key]
