"""The taxonomy: the rules `concept/02-concepts-and-taxonomy.md` states, made to fail.

Every rule the note calls "validated, not assumed" gets a test that fails when it
is not. The vocabulary itself is asserted only where the note names something —
`malicious.c2` is the one path written out in `concept/02`, and the closed root
sets are given there in full. The rest of `v1`'s paths are a derivation from
prose and are checked for *shape* rather than pinned name by name: a test listing
them would pass for a `v2` nobody reviewed, because whoever wrote `v2` would edit
the list too.
"""

from __future__ import annotations

import pytest

from helena import taxonomy
from helena.taxonomy import v1


# --- The version module, and what a version is ------------------------------


def test_the_version_module_declares_the_version_it_is():
    assert v1.TAXONOMY_VERSION == "v1"
    assert taxonomy.version("v1") is v1.TAXONOMY


def test_a_version_that_does_not_exist_is_its_own_error():
    """Distinct from an invalid path, because it means replay cannot proceed.

    A stored assessment recording `v9` is not a bad value; it is a row this tree
    cannot validate, and `concept/07-principles.md` requires replay to validate
    against the version the assessment recorded rather than current code.
    """
    with pytest.raises(taxonomy.UnknownVersion, match="no taxonomy version 'v9'"):
        taxonomy.version("v9")


def test_a_version_identifier_is_a_module_name():
    with pytest.raises(taxonomy.UnknownVersion, match="not a version identifier"):
        taxonomy.version("../v1")


# --- Roots are closed, per level and per emitter ----------------------------


def test_the_roots_are_the_ones_the_concept_note_closes_over():
    """The one thing worth pinning by name: `concept/02` gives these in full."""
    assert v1.TAXONOMY.roots[taxonomy.EVIDENCE] == frozenset(
        {"no_match", "normal", "suspicious", "malicious", "unknown"}
    )
    assert v1.TAXONOMY.roots[taxonomy.CONTEXT] == frozenset(
        {"normal", "suspicious", "unknown", "malicious"}
    )
    assert v1.TAXONOMY.emitter_roots[taxonomy.TRIAGE] == frozenset(
        {"normal", "suspicious"}
    )
    assert v1.TAXONOMY.emitter_roots[taxonomy.ANALYST] == frozenset(
        {"normal", "suspicious", "unknown", "malicious"}
    )


def test_an_invalid_root_is_refused():
    with pytest.raises(taxonomy.TaxonomyError, match="does not close over"):
        taxonomy.resolve(
            "dangerous", level=taxonomy.CONTEXT, version="v1", emitter=taxonomy.ANALYST
        )


def test_triage_may_not_emit_a_root_the_analyst_has():
    """`concept/02`: triage emits `normal` or `suspicious` **and nothing else**.

    The roots are closed per emitter, not only per level, and this is the case
    that shows the difference: `malicious.c2` is a valid context path and triage
    still may not produce it.
    """
    assert taxonomy.resolve(
        "malicious.c2", level=taxonomy.CONTEXT, version="v1", emitter=taxonomy.ANALYST
    ).root == "malicious"
    with pytest.raises(taxonomy.TaxonomyError, match="context/triage does not close"):
        taxonomy.resolve(
            "malicious.c2",
            level=taxonomy.CONTEXT,
            version="v1",
            emitter=taxonomy.TRIAGE,
        )


def test_a_context_triage_that_could_not_assess_has_no_label_to_reach_for():
    """The other half of the same rule: triage has no `unknown` either.

    `concept/02` calls that a typed failure rather than a third label, so the
    absence here is the design and not an oversight.
    """
    with pytest.raises(taxonomy.TaxonomyError):
        taxonomy.resolve(
            "unknown", level=taxonomy.CONTEXT, version="v1", emitter=taxonomy.TRIAGE
        )


def test_an_evidence_root_is_not_a_context_root():
    """`no_match` is a lookup outcome about an indicator, not a verdict on a host."""
    assert taxonomy.resolve("no_match", level=taxonomy.EVIDENCE, version="v1").is_root
    with pytest.raises(taxonomy.TaxonomyError, match="does not close over"):
        taxonomy.resolve(
            "no_match", level=taxonomy.CONTEXT, version="v1", emitter=taxonomy.ANALYST
        )


# --- The root equals the first segment --------------------------------------


def test_the_root_is_the_first_segment_and_a_mismatch_is_refused():
    """`concept/02`: "The root must equal the first path segment — validated, not assumed."

    A path whose first segment is a legal root but which is not in the vocabulary
    is the near-miss this catches; a path whose first segment is not a root at all
    is caught one check earlier.
    """
    resolved = taxonomy.resolve(
        "malicious.c2", level=taxonomy.CONTEXT, version="v1", emitter=taxonomy.ANALYST
    )
    assert resolved.root == resolved.segments[0] == "malicious"
    with pytest.raises(taxonomy.TaxonomyError, match="does not close over"):
        taxonomy.resolve(
            "c2.malicious",
            level=taxonomy.CONTEXT,
            version="v1",
            emitter=taxonomy.ANALYST,
        )


@pytest.mark.parametrize("path", ["", " ", "malicious.", ".c2", "malicious..c2", " malicious"])
def test_a_malformed_path_is_refused(path: str):
    with pytest.raises(taxonomy.TaxonomyError):
        taxonomy.resolve(
            path, level=taxonomy.CONTEXT, version="v1", emitter=taxonomy.ANALYST
        )


# --- Most-specific supported path, and emitting the parent ------------------


def test_an_invented_child_is_refused_and_the_parent_is_offered():
    """`concept/02`: emit `malicious`, not an invented `malicious.something`.

    The refusal names the parent, because a mapping that hit this needs to know
    what it may emit instead — an error that only said "no" would be answered by
    guessing again.
    """
    with pytest.raises(taxonomy.TaxonomyError, match="Emit the parent"):
        taxonomy.resolve(
            "malicious.ransomware",
            level=taxonomy.CONTEXT,
            version="v1",
            emitter=taxonomy.ANALYST,
        )


def test_every_root_is_itself_an_emittable_path():
    """"Emit the parent" means nothing unless the parent is a legal answer."""
    for root in sorted(v1.TAXONOMY.roots[taxonomy.EVIDENCE]):
        assert taxonomy.for_emission(root, level=taxonomy.EVIDENCE, version="v1").is_root
    for root in sorted(v1.TAXONOMY.emitter_roots[taxonomy.ANALYST]):
        assert taxonomy.for_emission(
            root, level=taxonomy.CONTEXT, version="v1", emitter=taxonomy.ANALYST
        ).is_root


# --- No `unknown.*` sub-paths -----------------------------------------------


def test_unknown_has_no_children():
    """`concept/02`: a child would claim a specificity the run does not have.

    Enforced structurally — `unknown` is a root with nothing under it, so a child
    fails the supported-path rule with no special case to forget in `v2`. The
    vocabulary is asserted directly as well, so a `v2` that added one fails here
    rather than only where something tried to emit it.
    """
    assert not [
        path
        for path in v1.TAXONOMY.paths[taxonomy.CONTEXT]
        if path.startswith("unknown.")
    ]
    with pytest.raises(taxonomy.TaxonomyError):
        taxonomy.resolve(
            "unknown.budget_exhausted",
            level=taxonomy.CONTEXT,
            version="v1",
            emitter=taxonomy.ANALYST,
        )


# --- Declared and unused ----------------------------------------------------


def test_an_unused_path_resolves_and_says_it_is_unused():
    """The lookup that tells a declared-but-unjustified path from a typo."""
    resolved = taxonomy.resolve(
        "suspicious.anomalous_dns",
        level=taxonomy.CONTEXT,
        version="v1",
        emitter=taxonomy.ANALYST,
    )
    assert resolved.unused
    assert "one host in one five-minute window" in resolved.unused_reason


def test_an_unused_path_may_not_be_emitted():
    with pytest.raises(taxonomy.UnusablePath, match="declared in v1 and unused"):
        taxonomy.for_emission(
            "suspicious.anomalous_dns",
            level=taxonomy.CONTEXT,
            version="v1",
            emitter=taxonomy.ANALYST,
        )


def test_unusable_is_not_the_same_error_as_invalid():
    """`concept/instruction.md` §2: two different facts are never one value.

    `UnusablePath` is a `TaxonomyError`, so a caller that does not care catches
    one thing; a caller that does care can fall back to the parent for an unused
    path and fail for an invalid one.
    """
    assert issubclass(taxonomy.UnusablePath, taxonomy.TaxonomyError)
    with pytest.raises(taxonomy.TaxonomyError) as invalid:
        taxonomy.for_emission(
            "suspicious.invented",
            level=taxonomy.CONTEXT,
            version="v1",
            emitter=taxonomy.ANALYST,
        )
    assert not isinstance(invalid.value, taxonomy.UnusablePath)


def test_every_unused_path_needs_history_and_says_which_kind():
    """`concept/02` says *which* paths the prototype cannot justify: anomaly and baseline.

    So the unused set is checked against that description rather than listed: any
    path marked unused must be an anomaly, a baseline or a novelty one, and every
    anomaly and baseline path must be marked unused. A `v2` that marks something
    else unused, or that quietly starts emitting an anomaly path without building
    history, fails here.
    """
    context_paths = v1.TAXONOMY.paths[taxonomy.CONTEXT]
    needs_history = {
        path
        for path in context_paths
        if any(k in path for k in ("anomalous", "baseline", "new_"))
    }
    assert set(v1.TAXONOMY.unused) == needs_history
    assert needs_history, "the vocabulary declares no path evaluation is expected to reach"
    for reason in v1.TAXONOMY.unused.values():
        assert reason.strip(), "an unused path records why"


def test_the_usable_context_paths_are_the_ones_that_need_no_history():
    """What is emittable today, stated as a consequence rather than a list."""
    usable = {
        path
        for path in v1.TAXONOMY.paths[taxonomy.CONTEXT]
        if path not in v1.TAXONOMY.unused
    }
    for path in sorted(usable):
        assert taxonomy.for_emission(
            path, level=taxonomy.CONTEXT, version="v1", emitter=taxonomy.ANALYST
        ).path == path


# --- The evidence level is roots-only, deliberately -------------------------


def test_the_evidence_level_declares_roots_and_no_children():
    """Not an unfinished list — see `helena/taxonomy/v1.py`'s docstring.

    `concept/02` adopts the evidence level "essentially unchanged from an existing
    published indicator taxonomy" and neither names it nor reproduces it, so there
    is nothing here to adopt sub-paths from and inventing them is the exact thing
    the note's own rule forbids. They arrive with the first feed that needs them,
    which is a `v2`.
    """
    assert v1.TAXONOMY.paths[taxonomy.EVIDENCE] == v1.TAXONOMY.roots[taxonomy.EVIDENCE]
    with pytest.raises(taxonomy.TaxonomyError, match="Emit the parent"):
        taxonomy.resolve("malicious.c2", level=taxonomy.EVIDENCE, version="v1")


def test_the_evidence_level_takes_no_emitter_and_the_context_level_requires_one():
    with pytest.raises(taxonomy.TaxonomyError, match="no emitter distinction"):
        taxonomy.resolve(
            "malicious", level=taxonomy.EVIDENCE, version="v1", emitter=taxonomy.ANALYST
        )
    with pytest.raises(taxonomy.TaxonomyError, match="an emitter is required"):
        taxonomy.resolve("malicious", level=taxonomy.CONTEXT, version="v1")


def test_an_unknown_level_is_refused():
    with pytest.raises(taxonomy.TaxonomyError, match="is not one of"):
        taxonomy.resolve("malicious", level="indicator", version="v1")


# --- The vocabulary cannot disagree with itself -----------------------------


@pytest.mark.parametrize(
    ("broken", "message"),
    [
        (
            {"roots": {taxonomy.EVIDENCE: frozenset({"normal"})}},
            "and the levels are",
        ),
        (
            {"paths": {taxonomy.EVIDENCE: frozenset({"nope"}), taxonomy.CONTEXT: frozenset()}},
            "which is not one of",
        ),
        (
            {"unused": {"normal.not_a_path": "because"}},
            "are marked unused and are not in the vocabulary",
        ),
        (
            {"unused": {"normal.baseline": "  "}},
            "marked unused with no reason",
        ),
    ],
    ids=["missing-level", "path-outside-roots", "unused-not-declared", "unused-no-reason"],
)
def test_a_version_module_that_disagrees_with_itself_fails_at_import(
    broken: dict, message: str
):
    """The checks run in `__post_init__`, so a bad vocabulary fails where it is written.

    A version module is data, and data with no validation is the place a typo
    lives until something tries to emit it.
    """
    fields = {
        "version": "vtest",
        "roots": dict(v1.TAXONOMY.roots),
        "emitter_roots": dict(v1.TAXONOMY.emitter_roots),
        "paths": dict(v1.TAXONOMY.paths),
        "unused": dict(v1.TAXONOMY.unused),
        **broken,
    }
    with pytest.raises(taxonomy.TaxonomyError, match=message):
        taxonomy.TaxonomyVersion(**fields)


def test_a_root_that_is_not_a_path_is_refused():
    """A closed root with no path is a parent that could never be emitted."""
    with pytest.raises(taxonomy.TaxonomyError, match="could not be emitted"):
        taxonomy.TaxonomyVersion(
            version="vtest",
            roots={taxonomy.EVIDENCE: frozenset({"normal"}), taxonomy.CONTEXT: frozenset()},
            emitter_roots={taxonomy.TRIAGE: frozenset(), taxonomy.ANALYST: frozenset()},
            paths={taxonomy.EVIDENCE: frozenset(), taxonomy.CONTEXT: frozenset()},
            unused={},
        )
