"""The governance registers, and the one thing about them that can fail silently.

Three registers were written in task 55 and each is a copy of something the
concept notes already say: `docs/decisions/README.md` maps every blocking
question in `concept/08-open-questions.md` to the record that settled it,
`docs/deferred.md` holds every deferred capability from
`concept/01-goal-and-scope.md` with its re-entry test, and `docs/hazards.md`
holds the accepted risks from `concept/08`'s hazards table.

A copy that can drift from its source is the thing `concept/instruction.md` §2
says is worse than none, so what is asserted here is the drift and not the
prose: a hazard added to the note, a deferral added to the note, a blocking
section renamed, a record the index names and nobody wrote, a source registered
in `helena.enrichment.SOURCES` with no record in `docs/sources/`.

The other half is the maturity label. `tests/test_package_layout.py` already
requires every module to declare exactly one, and
`concept/instruction.md` §5 says what the `deferred` one costs when it lapses:
*"a deferred component that loses its label makes every other label a lie."*
**No module is labelled `deferred` today**, so the parametrized check over the
package is vacuous by construction, and a vacuous check is one that passes after
it stops working. `test_the_register_check_rejects_a_deferred_module_with_no_key`
is what keeps it honest: it runs the same function this file uses over a
synthetic docstring and requires it to fail.
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path

import pytest

from helena.enrichment import SOURCES

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PACKAGE_ROOT = PROJECT_ROOT / "src" / "helena"
DOCS = PROJECT_ROOT / "docs"
DECISIONS = DOCS / "decisions"
SOURCE_RECORDS = DOCS / "sources"
DEFERRED = DOCS / "deferred.md"
HAZARDS = DOCS / "hazards.md"
INDEX = DECISIONS / "README.md"
GOAL_NOTE = PROJECT_ROOT / "concept" / "01-goal-and-scope.md"
OPEN_QUESTIONS = PROJECT_ROOT / "concept" / "08-open-questions.md"
INSTRUCTIONS = PROJECT_ROOT / "concept" / "instruction.md"
REPORTS = PROJECT_ROOT / "prds" / "reports"

# What `concept/01-goal-and-scope.md`'s "Deferred — not cancelled" list says,
# mapped to the register keys that carry it. One bullet can carry four
# capabilities -- "a demonstration UI, a finding store, an evidence graph and a
# query API" is one line and four entries -- which is exactly why this is a
# table and not a string comparison.
#
# The keys are the register's; the phrases are the note's, verbatim enough to
# fail if the note is reworded. A bullet added to the note and not to this table
# fails `test_every_deferral_the_note_lists_is_in_the_register`, which is the
# drift this file exists to catch.
NOTE_DEFERRALS = {
    "the analyst feedback loop, and agent memory": (
        "analyst-feedback-loop",
        "agent-memory",
    ),
    "a demonstration UI, a finding store, an evidence graph and a query API": (
        "demonstration-ui",
        "finding-store",
        "evidence-graph",
        "query-api",
    ),
    "the evaluation harness": ("evaluation-harness",),
    "a detection tier of rules and classifiers": ("detection-tier",),
    "threat-intelligence feeds beyond the first": ("further-feeds",),
    "context retention and freezing": ("retention-and-freezing",),
    "the cloud Investigation Agent and its redaction gate": (
        "investigation-agent",
    ),
    "multi-tenancy *enforcement*": ("multi-tenancy-enforcement",),
}

#: The blocking-question sections of `concept/08`, which are the headings the
#: closure map has to have. `concept/08` writes them as bold run-in headings.
BLOCKING_SECTIONS = (
    "Enrichment",
    "Rendering and triage",
    "The analyst and the provider tool",
    "The output",
    "Cross-cutting and urgent",
)

MATURITY = re.compile(r"Maturity: (\w+)")


def _flat(text: str) -> str:
    """One line, single-spaced. A wrapped sentence is the same sentence."""
    return re.sub(r"\s+", " ", text)


def register_keys() -> tuple[str, ...]:
    """The keys `docs/deferred.md` declares, in the order it declares them."""
    return tuple(re.findall(r"^Key: `([a-z0-9-]+)`$", DEFERRED.read_text(), re.M))


def missing_register_key(docstring: str, keys: tuple[str, ...]) -> bool:
    """Whether a module docstring labelled `deferred` fails to name a register key.

    A function rather than an inline condition because no module is labelled
    `deferred` yet, so the only way to exercise it is to call it directly --
    see this module's docstring.
    """
    label = MATURITY.search(docstring)
    if label is None or label.group(1) != "deferred":
        return False
    return not any(f"`{key}`" in docstring or key in docstring for key in keys)


def _module_paths() -> list[Path]:
    return sorted(PACKAGE_ROOT.rglob("*.py"))


# --- The deferred register --------------------------------------------------


def test_the_register_declares_a_unique_key_for_every_entry():
    keys = register_keys()
    assert keys, "the register declares no keys at all"
    assert len(set(keys)) == len(keys), f"a key is declared twice in {keys}"


@pytest.mark.parametrize("key", register_keys())
def test_every_register_entry_carries_a_re_entry_test(key: str):
    """`concept/01`: *the test for re-entry is the test that governs entry.*

    An entry without one is a capability nobody has to justify coming back, which
    is the register failing at the only job it has.
    """
    document = DEFERRED.read_text()
    start = document.index(f"Key: `{key}`")
    following = [
        match.start()
        for match in re.finditer(r"^Key: `", document[start + 1 :], re.M)
    ]
    end = start + 1 + following[0] if following else len(document)
    entry = document[start:end]
    assert "Re-entry test" in entry, f"{key} has no re-entry test"


@pytest.mark.parametrize("phrase,keys", sorted(NOTE_DEFERRALS.items()))
def test_every_deferral_the_note_lists_is_in_the_register(
    phrase: str, keys: tuple[str, ...]
):
    assert phrase in _flat(GOAL_NOTE.read_text()), (
        f"`concept/01` no longer says {phrase!r}; NOTE_DEFERRALS is stale"
    )
    declared = register_keys()
    for key in keys:
        assert key in declared, f"{phrase!r} is deferred in the note and {key} is not in the register"


def test_the_note_lists_no_deferral_the_table_above_does_not_cover():
    """A ninth bullet in `concept/01` fails here rather than going unregistered.

    The bullets are the lines between "Deferred -- not cancelled" and "Out of
    scope for the system entirely", which is the boundary that matters: moving
    something across it is a change to the concept.
    """
    text = GOAL_NOTE.read_text()
    start = text.index("**Deferred — not cancelled.**")
    end = text.index("**Out of scope for the system entirely:**")
    bullets = [_flat(bullet) for bullet in text[start:end].split("\n- ")[1:]]
    uncovered = [
        bullet
        for bullet in bullets
        if not any(phrase in bullet for phrase in NOTE_DEFERRALS)
    ]
    assert uncovered == [], (
        f"`concept/01` defers {uncovered} and docs/deferred.md does not carry it"
    )


def test_the_register_does_not_promote_anything_out_of_scope():
    """`concept/01`'s out-of-scope list is not deferred, and the register says so.

    A "Response Agent" performing containment is rejected *even as a future lane
    in a diagram*; a register entry for one would be that lane.
    """
    document = DEFERRED.read_text()
    assert "must not be listed as if it were" in document
    for rejected in (
        "blocking, containment or remediation",
        "detonation",
        "hosted tracing",
    ):
        assert rejected in document, f"{rejected!r} is not named as out of scope"
    assert not re.search(r"^Key: `response-agent`", document, re.M)


# --- The maturity label the register exists for -----------------------------


@pytest.mark.parametrize("path", _module_paths(), ids=lambda p: p.name)
def test_a_module_marked_deferred_names_a_register_entry(path: Path):
    """`concept/instruction.md` §5, the sentence this whole file is about.

    Vacuous today, and deliberately kept rather than skipped: the moment a
    module is labelled `deferred`, this is the test that asks where its record
    is.
    """
    docstring = ast.get_docstring(ast.parse(path.read_text())) or ""
    assert not missing_register_key(docstring, register_keys()), (
        f"{path.name} declares Maturity: deferred and names no key from "
        f"docs/deferred.md"
    )


def test_the_register_check_rejects_a_deferred_module_with_no_key():
    """The check above, exercised on input that must fail it."""
    keys = register_keys()
    assert missing_register_key("Maturity: deferred — nothing built.", keys)
    assert not missing_register_key(
        "Maturity: deferred — see `evaluation-harness`.", keys
    )
    assert not missing_register_key("Maturity: experimental — built.", keys)
    assert not missing_register_key("no label at all", keys)


def test_no_module_is_labelled_deferred_yet_and_that_is_the_current_fact():
    """Recorded as an assertion so it is a measurement rather than a memory.

    If this goes red, a module became deferred -- which is fine, and the test
    above is then the one that matters. Update this one to the new fact.
    """
    deferred = [
        path.name
        for path in _module_paths()
        if (ast.get_docstring(ast.parse(path.read_text())) or "").find(
            "Maturity: deferred"
        )
        != -1
    ]
    assert deferred == []


# --- The hazards register ---------------------------------------------------


def note_hazards() -> tuple[str, ...]:
    """The hazard names from `concept/08`'s "Known hazards" table."""
    text = OPEN_QUESTIONS.read_text()
    table = text[text.index("## Known hazards, recorded rather than resolved") :]
    return tuple(re.findall(r"^\| \*\*(.+?)\*\* \|", table, re.M))


@pytest.mark.parametrize("hazard", note_hazards())
def test_every_hazard_the_note_records_has_a_section(hazard: str):
    """A hazard added to `concept/08` and not here is a risk the register denies."""
    headings = re.findall(r"^## \d+\. (.+)$", HAZARDS.read_text(), re.M)
    assert hazard in headings, (
        f"`concept/08` records the hazard {hazard!r} and docs/hazards.md has "
        f"sections {headings}"
    )


def test_the_register_records_no_hazard_the_note_does_not():
    """The other direction: a section here that `concept/08` dropped.

    `docs/hazards.md` says an entry leaves when it stops being true, and a
    hazard the authority no longer records is one to investigate rather than to
    keep quietly -- `concept/instruction.md` §4, a discrepancy between two
    records is investigated, never papered over.
    """
    headings = re.findall(r"^## \d+\. (.+)$", HAZARDS.read_text(), re.M)
    assert sorted(headings) == sorted(note_hazards())


def test_every_hazard_section_says_what_is_done_about_it():
    """An accepted risk with no disposition is a risk nobody accepted."""
    document = HAZARDS.read_text()
    sections = re.split(r"^## \d+\. ", document, flags=re.M)[1:]
    for section in sections:
        name = section.split("\n", 1)[0]
        assert "*What is done" in section or "*What is deliberately not done" in section, (
            f"hazard {name!r} records no disposition"
        )


# --- The decision records and the closure map -------------------------------


def decision_records() -> tuple[Path, ...]:
    return tuple(sorted(DECISIONS.glob("0*.md")))


def test_the_record_numbers_are_contiguous_and_never_reused():
    """`concept/instruction.md` §4: *identifiers are never reused.*"""
    numbers = [int(path.name[:4]) for path in decision_records()]
    assert numbers == sorted(set(numbers)), "a record number is duplicated"
    assert numbers == list(range(1, len(numbers) + 1)), (
        f"the numbering has a hole or a reuse: {numbers}"
    )


@pytest.mark.parametrize("path", decision_records(), ids=lambda p: p.name[:4])
def test_every_record_declares_a_status_and_a_number_matching_its_filename(path: Path):
    text = path.read_text()
    heading = text.split("\n", 1)[0]
    assert heading.startswith(f"# {path.name[:4]} — "), (
        f"{path.name} opens with {heading!r}"
    )
    assert "Status:" in text, f"{path.name} declares no status"


@pytest.mark.parametrize("path", decision_records(), ids=lambda p: p.name[:4])
def test_every_record_is_in_the_index(path: Path):
    assert f"]({path.name})" in INDEX.read_text(), (
        f"{path.name} exists and docs/decisions/README.md does not list it"
    )


def test_the_index_names_no_record_that_does_not_exist():
    named = set(re.findall(r"\]\((0\d{3}-[a-z0-9-]+\.md)\)", INDEX.read_text()))
    missing = sorted(name for name in named if not (DECISIONS / name).exists())
    assert missing == [], f"the index names {missing}"


@pytest.mark.parametrize("section", BLOCKING_SECTIONS)
def test_the_closure_map_covers_every_blocking_section(section: str):
    """`concept/08`'s blocking sections, each with a table in the map.

    A renamed section fails here, which is the point: the map is only worth
    keeping while it is a map of the question list that exists.
    """
    assert f"**{section}.**" in OPEN_QUESTIONS.read_text(), (
        f"`concept/08` no longer has a {section!r} section"
    )
    assert f"### {section}" in INDEX.read_text(), (
        f"the closure map has no {section!r} table"
    )


def test_the_closure_map_marks_the_one_thing_that_is_still_open():
    """The silent-record-loss row. A map with no open row would be the tell.

    `concept/08` ties it to a claim ceiling -- *replayability is a goal rather
    than a claim while that stands* -- so a map that quietly closed it would be
    licensing a claim nobody earned.
    """
    index = _flat(INDEX.read_text())
    assert "STILL OPEN" in index
    assert "A row that says STILL OPEN is not a defect in this table." in index


@pytest.mark.parametrize(
    "record",
    [
        "0041-enrichment-status-representation.md",
        "0042-port-qualification-of-an-address-match.md",
        "0043-the-compromised-flag.md",
        "0044-the-snapshot-scheme.md",
        "0045-who-decides-the-analyst-is-unsure.md",
    ],
)
def test_the_records_written_for_the_enrichment_questions_exist(record: str):
    """Named rather than globbed: these five are what task 55 added, and a later
    session renaming one should have to say so here."""
    assert (DECISIONS / record).exists()


# --- The source records -----------------------------------------------------


def source_records() -> tuple[Path, ...]:
    return tuple(sorted(SOURCE_RECORDS.glob("*.md")))


@pytest.mark.parametrize("source_id", sorted(SOURCES))
def test_every_registered_source_has_a_record(source_id: str):
    """`concept/05`: *adding a source is a governed decision.* The record is the
    governing."""
    assert (SOURCE_RECORDS / f"{source_id}.md").exists(), (
        f"{source_id} is in helena.enrichment.SOURCES with no docs/sources record"
    )


@pytest.mark.parametrize(
    "path",
    [path for path in source_records() if path.name != "README.md"],
    ids=lambda p: p.stem,
)
def test_every_source_record_states_its_artifact_provenance(path: Path):
    """The one sentence every source record in this project has to carry.

    `concept/instruction.md` §0: *check the artifact, not the page* -- and
    `concept/05` records that the last three source records here were each wrong
    for the same reason. A record written from a page is not worthless, it is
    **unverified**, and the difference has to be visible where the record is
    read rather than inferred from what it omits.
    """
    opening = _flat(path.read_text()[:600])
    fetched = "**Written from a fetched artifact" in opening
    not_fetched = "**NOT written from a fetched artifact" in opening
    assert fetched != not_fetched, (
        f"docs/sources/{path.name} does not open by stating whether it was "
        f"written from a fetched artifact"
    )


def test_the_records_that_were_not_fetched_are_the_two_that_were_not():
    """Named, so that a record quietly upgrading its own provenance fails.

    Both are honest-unverified rather than wrong: `sslbl-ja3` is registered from
    the publisher's own statement about a list static since 2021, and VirusTotal's
    quota is deliberately unspent.
    """
    unfetched = {
        path.stem
        for path in source_records()
        if path.name != "README.md"
        and "**NOT written from a fetched artifact" in _flat(path.read_text()[:600])
    }
    assert unfetched == {"sslbl-ja3", "virustotal"}


# --- Negative results are kept ----------------------------------------------


def test_the_instruction_still_says_a_failed_experiment_is_a_result():
    """[0046] rests on this sentence; a rewrite that dropped it would silently
    license deleting one."""
    instructions = _flat(INSTRUCTIONS.read_text())
    assert "Failed and inconclusive experiments are valid results." in instructions
    assert "Never rewrite or delete one." in instructions


@pytest.mark.parametrize(
    "path", sorted(REPORTS.glob("task-*.json")), ids=lambda p: p.stem
)
def test_every_report_carries_the_fields_that_hold_a_negative_result(path: Path):
    """The shape, not the content. A report may have nothing to put in these --
    but it may not omit the place it would go, because then "we tried nothing"
    and "we recorded nothing" read the same.
    """
    report = json.loads(path.read_text())
    for field in ("failed_approaches", "deferred", "lessons"):
        assert field in report, f"{path.name} has no {field}"
        assert isinstance(report[field], list), f"{path.name}'s {field} is not a list"


def test_the_record_says_where_a_negative_result_lives():
    document = _flat((DECISIONS / "0046-negative-results-are-kept.md").read_text())
    assert "failed_approaches" in document
    assert "Alternatives rejected" in document
    assert "corrected in place beside the original" in document
    # The honest limit: a test cannot see a file that is gone.
    assert "A test cannot see a file that is gone; `git` can" in document
