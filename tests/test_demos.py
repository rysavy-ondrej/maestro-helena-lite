"""The demo index, held equal to what is on disk and to what `run-demo` offers.

`docs/demos.md` §3 is the index. Three copies of a list exist — the table, the
`demo/` directory and `run-demo`'s `DEMOS` array — and the ways they rot are the
ways every register in this repository rots: a demo added to the directory and
not the table, a table row naming a script nobody wrote, and a runner offering a
number the index does not describe.

The same device `tests/test_conformance.py` uses for the must-never-happen table
and `tests/test_governance.py` uses for the deferred register: parse the document
on every run rather than copy it, so a reworded row is red instead of silently
leaving a test asserting a sentence nobody wrote.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
DEMOS = ROOT / "demo"
INDEX = ROOT / "docs" / "demos.md"
RUNNER = DEMOS / "run-demo"


def index_rows() -> list[tuple[int, str, bool]]:
    """`(number, script, shipped)` per row of the index table.

    A row is *proposed* rather than shipped when its tier cell says so, which is
    the one place that fact is written down.
    """
    rows: list[tuple[int, str, bool]] = []
    for line in INDEX.read_text().splitlines():
        found = re.match(r"^\| (\d+) \| `([a-z0-9_]+\.py)` \| ([^|]+)\|", line)
        if found:
            number, script, tier = found.groups()
            rows.append((int(number), script, "proposed" not in tier))
    return rows


def demo_scripts() -> list[str]:
    """The demo scripts, which is not every `.py` in the directory.

    `_common.py` is a helper the demos share, not a demo: it opens no schema of
    its own and demonstrates nothing. One definition here rather than an
    underscore check repeated per test, which is how the maturity test came to
    demand a label from a module that has no reader to declare one to.
    """
    return sorted(
        path.name for path in DEMOS.glob("*.py") if not path.name.startswith("_")
    )


def shipped() -> list[str]:
    return [script for _, script, is_shipped in index_rows() if is_shipped]


def runner_list() -> list[str]:
    """`DEMOS=(...)` from `run-demo`, as a list of script stems."""
    found = re.search(r"^DEMOS=\(([^)]*)\)", RUNNER.read_text(), re.M)
    assert found, "run-demo no longer declares a DEMOS array"
    return found.group(1).split()


def test_the_index_is_numbered_from_one_without_gaps():
    numbers = [number for number, _, _ in index_rows()]
    assert numbers == list(range(1, len(numbers) + 1)), (
        f"the index numbers are {numbers}. They are the demo's stable name in "
        f"three documents, so a gap is a citation that no longer resolves."
    )


def test_every_shipped_demo_exists_on_disk():
    missing = [script for script in shipped() if not (DEMOS / script).exists()]
    assert missing == [], (
        f"the index lists {missing} as shipped and demo/ does not hold them. A "
        f"row is marked proposed until the script exists."
    )


def test_every_script_in_the_directory_is_in_the_index():
    """A demo nobody indexed is a demo nobody runs."""
    on_disk = demo_scripts()
    listed = sorted(script for _, script, _ in index_rows())
    assert on_disk == [name for name in listed if name in on_disk], (
        f"demo/ holds {sorted(set(on_disk) - set(listed))} which docs/demos.md "
        f"does not list"
    )
    assert not set(on_disk) - set(listed)


def test_the_runner_offers_exactly_the_shipped_demos_in_index_order():
    """`run-demo 3` and *"demo 3"* in the index have to be the same thing."""
    assert [f"{stem}.py" for stem in runner_list()] == shipped()


@pytest.mark.parametrize("script", demo_scripts())
def test_every_demo_declares_its_maturity(script: str):
    """`concept/instruction.md` §5: a label that goes missing makes the others lie."""
    text = (DEMOS / script).read_text()
    assert "Maturity:" in text, f"{script} declares no maturity label"


@pytest.mark.parametrize("script", demo_scripts())
def test_every_demo_says_what_it_does_not_show(script: str):
    """The half a demo is most tempting to leave out.

    Every shipped demo states its own limits -- demo 1 and 2 that they reach no
    assessment, demo 3 that it says nothing about whether the verdicts are right.
    A demo without that paragraph is the one somebody quotes as evidence.
    """
    text = (DEMOS / script).read_text().lower()
    assert "does not show" in text or "not claimable" in text, (
        f"{script} never says what it does not show"
    )


def test_the_index_states_the_data_each_demo_needs():
    """Two demos need a capture that is not in this repository, and that has to be
    findable from the index rather than discovered by running one."""
    text = INDEX.read_text()
    assert "not committed" in text, (
        "the index no longer marks which demos need the uncommitted capture"
    )
