"""The corpus requirements, the quota ceiling, and the gates that keep both true.

Two halves, and they fail for different reasons.

**The arithmetic** is `scripts/corpus_sizing.py`, executed here against the real
`config/policy.toml`. The per-run live-query ceiling it sizes with is the one
`helena.budgets` derives and `helena.tools` enforces, so a budget change moves the
ceiling in this file rather than leaving `docs/evaluation-corpus.md` quietly
describing a system that no longer exists.

**The document** is `docs/evaluation-corpus.md`, and what is asserted about it is
what a document rots by: a research question added to
`concept/01-goal-and-scope.md` and not carried across, a hazard reworded in
`concept/08-open-questions.md`, a table of ceilings copied once and never
recomputed. Those are parsed out of the notes on every run, the way
`tests/test_end_to_end.py` parses the claims and `tests/test_conformance.py`
parses the must-never-happen table.

What is deliberately **not** here is a test of the evaluation harness, which does
not exist and stays deferred. `test_the_harness_is_still_deferred` is what keeps
that honest.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from datetime import date
from pathlib import Path

import pytest

from helena import budgets, taxonomy

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

import corpus_sizing  # noqa: E402 — needs the path above

DOCUMENT = PROJECT_ROOT / "docs" / "evaluation-corpus.md"
GOAL_NOTE = PROJECT_ROOT / "concept" / "01-goal-and-scope.md"
OPEN_QUESTIONS = PROJECT_ROOT / "concept" / "08-open-questions.md"
SOURCE = "threatfox"


@pytest.fixture(scope="module")
def policy() -> budgets.BudgetPolicy:
    """The shipped policy file, loaded the way the pipeline loads it."""
    return budgets.load()


def _flat(text: str) -> str:
    """Markdown flattened to one line: no blockquote markers, no bold, one space.

    A sentence in a markdown file is wrapped across lines and quoted with `>` in
    one file and not in another; a test that required a particular wrapping would
    be a formatting rule rather than a check that the sentence is there.
    """
    unquoted = "\n".join(
        line.lstrip().removeprefix(">").strip() for line in text.splitlines()
    )
    return " ".join(unquoted.replace("**", "").split())


def _number(cell: str) -> float:
    """A table cell's number, with the thousands space this repository writes."""
    found = re.search(r"[\d][\d .]*", cell.replace(" ", " "))
    assert found, f"{cell!r} holds no number"
    return float(found.group(0).replace(" ", ""))


def _table(document: str, heading: str) -> list[list[str]]:
    """The markdown table whose header row begins `heading`, cells stripped."""
    rows = []
    for line in document.splitlines():
        if line.startswith(f"| {heading} |"):
            rows = [line]
        elif rows and line.startswith("|"):
            rows.append(line)
        elif rows:
            break
    assert rows, f"docs/evaluation-corpus.md has no table headed {heading!r}"
    cells = [[cell.strip() for cell in row.strip("|").split("|")] for row in rows]
    return [cells[0], *cells[2:]]  # the separator row carries nothing


# --- The arithmetic ----------------------------------------------------------


def test_the_per_run_ceiling_is_the_one_the_tool_layer_enforces(
    policy: budgets.BudgetPolicy,
):
    """Read from the ledger's own derivation, not re-derived beside it.

    `helena.budgets.load` computes the live-query count from the retrieval seconds
    and the slowest rate limit, because `concept/07` refuses to let the two be set
    independently. The sizing instrument sizes against *that* number: a second
    derivation here would be a copy that drifts from the one the dispatch refuses
    calls with, and the drift would be invisible until an evaluation overran a
    provider.
    """
    slowest = min(policy.rate_limits.values())
    derived = int(policy.retrieval_seconds[taxonomy.ANALYST] * slowest / 60)
    assert corpus_sizing.per_run_live_queries(policy) == derived
    assert derived > 0


def test_the_sustained_ceiling_is_the_rate_the_tools_keep(policy: budgets.BudgetPolicy):
    """And it is ours, not the provider's — `config/policy.toml` says so."""
    assert corpus_sizing.sustained_daily_ceiling(policy, SOURCE) == (
        policy.rate_limits[SOURCE] * corpus_sizing.MINUTES_PER_DAY
    )


def test_a_source_nothing_queries_live_gets_no_rate_and_no_default(
    policy: budgets.BudgetPolicy,
):
    """The silent configuration default, refused where it would be cheapest."""
    with pytest.raises(corpus_sizing.SizingError, match="no rate limit is configured"):
        corpus_sizing.queries_a_minute(policy, "sslbl-ja3")


def test_the_envelope_is_the_runs_times_the_per_run_ceiling():
    """And a fraction of an analyst run is a whole one."""
    line = corpus_sizing.envelope(
        contexts=1000,
        escalation_rate=0.0105,  # 10.5 runs
        per_run=8,
        daily_quota=5760,
        queries_per_minute=4,
    )
    assert line.analyst_runs == 11
    assert line.live_queries == 88
    assert line.retrieval_minutes == 22.0
    assert line.days_of_quota == 88 / 5760
    assert line.fits_in_a_day
    assert not line.capped_by_distinct


def test_the_cache_is_the_other_bound_and_it_is_the_lower_one():
    """A corpus cannot spend more live queries than it has distinct indicators.

    `docs/decisions/0025-the-lookup-cache.md` §3 caches negative results, which is
    what makes this true on a sparse corpus: the second run to ask about an
    indicator nobody lists pays nothing. The cap is reported rather than applied
    silently — an envelope that quietly became smaller would look like a budget
    that had been lowered.
    """
    without = corpus_sizing.envelope(
        contexts=12089,
        escalation_rate=0.10,
        per_run=8,
        daily_quota=5760,
        queries_per_minute=4,
    )
    with_cache = corpus_sizing.envelope(
        contexts=12089,
        escalation_rate=0.10,
        per_run=8,
        daily_quota=5760,
        queries_per_minute=4,
        distinct_indicators=2490,  # the measured day's distinct names
    )
    assert with_cache.live_queries == 2490
    assert with_cache.capped_by_distinct
    assert with_cache.live_queries < without.live_queries
    assert with_cache.analyst_runs == without.analyst_runs

    roomy = corpus_sizing.envelope(
        contexts=12089,
        escalation_rate=0.10,
        per_run=8,
        daily_quota=5760,
        queries_per_minute=4,
        distinct_indicators=1_000_000,
    )
    assert roomy.live_queries == without.live_queries
    assert not roomy.capped_by_distinct


def test_more_escalation_never_costs_less():
    """The monotonicity the ceiling table is read off."""
    spent = [
        corpus_sizing.envelope(
            contexts=12089,
            escalation_rate=rate,
            per_run=8,
            daily_quota=5760,
            queries_per_minute=4,
        ).live_queries
        for rate in corpus_sizing.DEFAULT_ESCALATION_RATES
    ]
    assert spent == sorted(spent)
    assert len(set(spent)) == len(spent)


def test_the_ceiling_is_the_corpus_that_just_fits(policy: budgets.BudgetPolicy):
    """`max_contexts_a_day` and `envelope` are two views of one division.

    Stated as the property rather than as a number: a corpus of exactly the
    ceiling's size spends no more than the quota in a day, and one escalation's
    worth more spends more than the quota.
    """
    per_run = corpus_sizing.per_run_live_queries(policy)
    quota = corpus_sizing.sustained_daily_ceiling(policy, SOURCE)
    for rate in corpus_sizing.DEFAULT_ESCALATION_RATES:
        ceiling = corpus_sizing.max_contexts_a_day(
            daily_quota=quota, per_run=per_run, escalation_rate=rate
        )
        fits = corpus_sizing.envelope(
            contexts=ceiling,
            escalation_rate=rate,
            per_run=per_run,
            daily_quota=quota,
            queries_per_minute=policy.rate_limits[SOURCE],
        )
        assert fits.fits_in_a_day, rate
        over = corpus_sizing.envelope(
            contexts=ceiling + int(1 / rate) + 1,
            escalation_rate=rate,
            per_run=per_run,
            daily_quota=quota,
            queries_per_minute=policy.rate_limits[SOURCE],
        )
        assert not over.fits_in_a_day, rate


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        ({"contexts": 0}, "a corpus of none"),
        ({"escalation_rate": 0.0}, "fraction of the contexts"),
        ({"escalation_rate": 1.5}, "fraction of the contexts"),
        ({"per_run": 0}, "spends no quota"),
        ({"daily_quota": 0}, "never a default"),
        ({"queries_per_minute": 0}, "it is a rate"),
        ({"distinct_indicators": 0}, "nothing to look up"),
    ],
)
def test_the_envelope_refuses_an_input_rather_than_sizing_against_it(
    arguments: dict[str, object], message: str
):
    """Every refusal names the parameter and why it cannot be that.

    A zero quota that sized to infinity, or a zero rate that divided by nothing,
    would produce a number an evaluation could be planned against.
    """
    valid: dict[str, object] = {
        "contexts": 12089,
        "escalation_rate": 0.1,
        "per_run": 8,
        "daily_quota": 5760,
        "queries_per_minute": 4,
    }
    with pytest.raises(corpus_sizing.SizingError, match=message):
        corpus_sizing.envelope(**{**valid, **arguments})  # type: ignore[arg-type]


def test_halving_the_interval_quadruples_the_positives():
    """The property the corpus is sized by, not the number it comes to.

    `n = z^2 p (1 - p) / h^2`, so the width is the expensive dimension: the
    difference between a claim to a tenth and a claim to a twentieth is four times
    the labelling.
    """
    wide = corpus_sizing.positives_for_interval(proportion=0.8, half_width=0.10)
    narrow = corpus_sizing.positives_for_interval(proportion=0.8, half_width=0.05)
    assert narrow == pytest.approx(4 * wide, abs=2)
    # Hardest at a half, which is the uninformative case.
    assert corpus_sizing.positives_for_interval(
        proportion=0.5, half_width=0.10
    ) > corpus_sizing.positives_for_interval(proportion=0.9, half_width=0.10)


def test_the_corpus_size_is_the_positives_over_the_base_rate():
    """And a rarer positive costs proportionally more corpus."""
    assert corpus_sizing.contexts_for_positives(positives=62, base_rate=0.01) == 6200
    assert corpus_sizing.contexts_for_positives(
        positives=62, base_rate=0.001
    ) == 10 * corpus_sizing.contexts_for_positives(positives=62, base_rate=0.01)


@pytest.mark.parametrize(
    ("call", "arguments", "message"),
    [
        ("positives_for_interval", {"proportion": 0.0, "half_width": 0.1}, "a rate in"),
        ("positives_for_interval", {"proportion": 1.0, "half_width": 0.1}, "a rate in"),
        ("positives_for_interval", {"proportion": 0.8, "half_width": 0.0}, "a width in"),
        ("contexts_for_positives", {"positives": 0, "base_rate": 0.1}, "it is a count"),
        ("contexts_for_positives", {"positives": 1, "base_rate": 0.0}, "a fraction in"),
    ],
)
def test_the_corpus_sizing_refuses_an_input_too(
    call: str, arguments: dict[str, object], message: str
):
    with pytest.raises(corpus_sizing.SizingError, match=message):
        getattr(corpus_sizing, call)(**arguments)


# --- The feed snapshot's coverage window -------------------------------------


def _export(directory: Path, records: list[dict[str, object]]) -> Path:
    """An export in the shape the publisher writes: id -> list of records."""
    import json

    payload = {str(1_000_000 + index): [record] for index, record in enumerate(records)}
    path = directory / "export.json"
    path.write_text(json.dumps(payload))
    return path


def test_the_snapshot_window_is_the_activity_the_export_carries(tmp_path: Path):
    """Last activity, not first seen — and the difference is most of the export.

    An indicator first seen a year ago is in a *recent* export because it was seen
    again, so reading `first_seen_utc` alone would report a window that spans a
    year and claim the snapshot can enrich traffic it says nothing about.
    """
    _export(
        tmp_path,
        [
            {"first_seen_utc": "2026-08-31 04:00:00", "last_seen_utc": None},
            {"first_seen_utc": "2024-01-16 10:00:00", "last_seen_utc": "2026-09-02 08:00:00"},
            {"first_seen_utc": "2026-09-01 12:00:00", "last_seen_utc": "2026-09-01 13:00:00"},
        ],
    )
    window = corpus_sizing.snapshot_window(tmp_path)
    assert window.entries == 3
    assert window.earliest_activity == date(2026, 8, 31)
    assert window.latest_activity == date(2026, 9, 2)
    assert window.span_days == 2
    assert window.first_seen_before_window == 1


def test_the_snapshot_window_flattens_and_never_reads_index_zero(tmp_path: Path):
    """The shape permits several records under one id (`prds/CONTEXT.md` §3)."""
    import json

    (tmp_path / "export.json").write_text(
        json.dumps(
            {
                "1894170": [
                    {"first_seen_utc": "2026-09-01 00:00:00", "last_seen_utc": None},
                    {"first_seen_utc": "2026-09-04 00:00:00", "last_seen_utc": None},
                ]
            }
        )
    )
    window = corpus_sizing.snapshot_window(tmp_path)
    assert window.entries == 2
    assert window.latest_activity == date(2026, 9, 4)


def test_the_committed_fixture_export_reads_as_one_window(tmp_path: Path):
    """The export fixture the enrichment tests load, read as a snapshot window.

    Copied out of `tests/fixtures/threatfox/` because that directory holds the
    hunting API's *responses* beside the export, and those are the next test.
    """
    fixture = PROJECT_ROOT / "tests" / "fixtures" / "threatfox" / "export.json"
    (tmp_path / "export.json").write_text(fixture.read_text())
    window = corpus_sizing.snapshot_window(tmp_path)
    assert window.entries > 0
    assert window.earliest_activity <= window.latest_activity
    assert window.first_seen_before_window <= window.entries


def test_an_api_response_is_not_a_snapshot_and_is_refused(tmp_path: Path):
    """The two surfaces have different shapes, and one window is not the other.

    `docs/decisions/0028-the-threatfox-hunting-api.md` §7 is the reason to be
    careful here: the export and the API are the same dataset, so a reader that
    silently accepted a response would produce a plausible window over a handful
    of hand-picked indicators.
    """
    response = (
        PROJECT_ROOT / "tests" / "fixtures" / "threatfox" / "search_ioc_address_hit.json"
    )
    (tmp_path / "response.json").write_text(response.read_text())
    with pytest.raises(corpus_sizing.SizingError, match="not a bulk export"):
        corpus_sizing.snapshot_window(tmp_path)


def test_an_absent_snapshot_is_a_missing_artifact_and_says_so(tmp_path: Path):
    """Not an empty feed. `concept/instruction.md` §2 keeps those apart."""
    with pytest.raises(corpus_sizing.SizingError, match="missing"):
        corpus_sizing.snapshot_window(tmp_path)


# --- The command an operator runs --------------------------------------------


def _command(*arguments: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["uv", "run", "scripts/corpus_sizing.py", *arguments],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        timeout=300,
        env=os.environ.copy(),
    )


def test_the_command_has_no_default_daily_quota():
    """The one number nobody may invent, refused at the argument parser.

    abuse.ch publishes fair-use terms and no daily number. A default here would be
    a fabricated figure inside the calculation that exists to stop an evaluation
    overrunning a provider.
    """
    result = _command()
    assert result.returncode == 2
    assert "--daily-quota" in result.stderr


def test_the_command_prints_the_ceiling(policy: budgets.BudgetPolicy):
    """And the ceiling it prints is the one this module computes."""
    result = _command("--daily-quota", "self-imposed")
    assert result.returncode == 0, result.stderr
    runs = corpus_sizing.max_analyst_runs_a_day(
        daily_quota=corpus_sizing.sustained_daily_ceiling(policy, SOURCE),
        per_run=corpus_sizing.per_run_live_queries(policy),
    )
    assert f"ceiling: {runs} analyst runs a day" in result.stdout
    assert "not a provider quota" in result.stdout.lower()


def test_the_command_refuses_a_quota_it_cannot_read():
    result = _command("--daily-quota", "plenty")
    assert result.returncode == 1
    assert "FAILED" in result.stderr


# --- The document ------------------------------------------------------------


def _research_questions() -> tuple[str, ...]:
    """The bullets under `## The research questions`, as they are written."""
    note = GOAL_NOTE.read_text()
    section = note.split("## The research questions", 1)[1].split("\n## ", 1)[0]
    bullets = re.findall(r"^- (.+?)(?=\n[-*\n])", section, re.DOTALL | re.MULTILINE)
    assert bullets, "concept/01-goal-and-scope.md no longer lists research questions"
    return tuple(" ".join(bullet.split()) for bullet in bullets)


def _hazard(name: str) -> str:
    """A row of `concept/08-open-questions.md`'s known-hazards table."""
    note = OPEN_QUESTIONS.read_text()
    found = re.search(rf"^\| \*\*{re.escape(name)}\*\* \| (.+?) \|$", note, re.MULTILINE)
    assert found, f"concept/08-open-questions.md no longer has a {name!r} hazard"
    return _flat(found.group(1))


def test_the_document_exists_and_states_what_it_is_not():
    assert DOCUMENT.exists(), f"{DOCUMENT} is the corpus requirement task 54 writes"
    document = _flat(DOCUMENT.read_text())
    assert "It is not the evaluation harness." in document


def test_every_research_question_has_a_measurement_and_a_blocker():
    """The note's questions, parsed on every run.

    The three ways this rots are the ones `tests/test_end_to_end.py` closes for
    the claims: a question added to the note appears nowhere here and is red, a
    question reworded no longer matches and is red, and a question that is here
    with no measurement or no blocker beside it is a heading pretending to be an
    answer.
    """
    document = _flat(DOCUMENT.read_text())
    questions = _research_questions()
    assert len(questions) == 8, questions
    for index, question in enumerate(questions, start=1):
        assert question in document, f"the document does not state RQ{index}: {question}"
        identifier = f"RQ{index} — "
        assert identifier in document, f"the document does not number RQ{index}"
        section = document.split(identifier, 1)[1].split(" RQ", 1)[0]
        assert question in section, f"RQ{index} is numbered for a different question"
        assert "Measurement:" in section, f"RQ{index} states no measurement"
        assert "Blocker:" in section, f"RQ{index} states no blocker"


def test_the_two_hazards_the_corpus_gates_are_stated_in_full():
    """Both, verbatim from the note, because both are ways to misread a result."""
    document = _flat(DOCUMENT.read_text())
    for name in ("The base rate", "The retrieval confound"):
        statement = _hazard(name)
        assert statement in document, f"the document does not state {name!r}: {statement}"


def test_the_envelope_table_is_recomputed_rather_than_quoted(
    policy: budgets.BudgetPolicy,
):
    """Every cell of §5's first table, computed from `config/policy.toml`.

    Two copies of a derived number that can drift are worse than none
    (`concept/instruction.md` §2). This is the SQL-and-Python version-constant
    rule applied to a table in a document.
    """
    document = DOCUMENT.read_text()
    header, *rows = _table(document, "Escalation")
    quotas = [_number(cell) for cell in header[-2:]]
    assert quotas[0] == corpus_sizing.sustained_daily_ceiling(policy, SOURCE)
    per_run = corpus_sizing.per_run_live_queries(policy)
    per_minute = policy.rate_limits[SOURCE]
    assert rows, "§5's envelope table has no rows"
    for row in rows:
        rate = _number(row[0]) / 100
        for column, quota in enumerate(quotas, start=4):
            line = corpus_sizing.envelope(
                contexts=corpus_sizing.MEASURED_DAY_CONTEXTS,
                escalation_rate=rate,
                per_run=per_run,
                daily_quota=int(quota),
                queries_per_minute=per_minute,
            )
            assert _number(row[1]) == line.analyst_runs, row
            assert _number(row[2]) == line.live_queries, row
            assert _number(row[3]) == round(line.retrieval_minutes / 60, 1), row
            assert _number(row[column]) == round(line.days_of_quota, 2), row


def test_the_ceiling_table_is_recomputed_too(policy: budgets.BudgetPolicy):
    """§5's second table: the ceiling the quota places on any evaluation."""
    document = DOCUMENT.read_text()
    header, *rows = _table(document, "Daily quota")
    rates = [_number(cell) / 100 for cell in header[2:]]
    assert rates, "the ceiling table names no escalation rates"
    per_run = corpus_sizing.per_run_live_queries(policy)
    assert rows, "§5's ceiling table has no rows"
    for row in rows:
        quota = int(_number(row[0]))
        assert _number(row[1]) == corpus_sizing.max_analyst_runs_a_day(
            daily_quota=quota, per_run=per_run
        ), row
        for column, rate in enumerate(rates, start=2):
            assert _number(row[column]) == corpus_sizing.max_contexts_a_day(
                daily_quota=quota, per_run=per_run, escalation_rate=rate
            ), row
    assert int(_number(rows[0][0])) == corpus_sizing.sustained_daily_ceiling(
        policy, SOURCE
    ), "the first ceiling row is the one config/policy.toml implies"


def test_the_corpus_size_the_document_quotes_is_the_computed_one():
    """§6's positives and the contexts they imply, recomputed."""
    document = _flat(DOCUMENT.read_text())
    wide = corpus_sizing.positives_for_interval(proportion=0.8, half_width=0.10)
    narrow = corpus_sizing.positives_for_interval(proportion=0.8, half_width=0.05)
    assert f"{wide} labelled positives" in document
    assert f"{narrow} for ±5 %" in document
    spaced = f"{corpus_sizing.contexts_for_positives(positives=wide, base_rate=0.001):,}"
    assert spaced.replace(",", " ") + " contexts" in document


def test_the_harness_is_still_deferred():
    """The label that makes every other label mean something.

    `concept/01-goal-and-scope.md` defers the evaluation harness; this file is its
    requirement and not its beginning. So: the note still defers it, the document
    still says so, and no module has appeared under `helena/` that is one by
    another name.
    """
    assert "the evaluation harness" in _flat(GOAL_NOTE.read_text())
    document = _flat(DOCUMENT.read_text())
    assert "The harness is deferred" in document
    assert "stays deferred" in document
    strays = [
        path.name
        for path in (PROJECT_ROOT / "src" / "helena").rglob("*.py")
        if re.search(r"eval|harness|corpus|score", path.stem)
    ]
    assert strays == [], f"the harness is deferred and {strays} is inside the package"
