"""The budget guard: four dimensions, one ledger per run, and the degrade rule.

Three properties this module is about, and each is a sentence of `concept/07`:

* **The four dimensions are enforced, each against the limit it maps to.** A
  dimension is *exhausted* when the run asked for more and was refused — not when
  it merely spent the last of something, because a run that spent its last token
  on the answer it returned finished rather than got truncated.
* **The wall clock and the live-query budget are set against each other.** The
  live-query count is not configured at all: it is derived from the retrieval
  allowance and the slowest configured provider rate, and the loader refuses a
  pair that contradicts itself.
* **A budget-truncated run may return `unknown` and may never return `normal`.**
  Asserted from both sides: `degraded` never produces one, and the contract
  refuses one built by hand.

No engine and no endpoint: the ledger is arithmetic over an injected clock. The
tool boundary's half is `tests/test_tools.py`, which has the engine the cache
needs, and the model loop's half is `tests/test_agents.py`.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from helena import budgets, policy, taxonomy
from helena.budgets import (
    DIMENSIONS,
    LIVE_QUERIES,
    STEPS,
    TOKENS,
    WALL_CLOCK,
    BudgetError,
    BudgetExhausted,
    RunBudget,
    degraded,
)
from helena.contracts.v1 import (
    BUDGET_EXHAUSTED,
    CONTRACT_VERSION,
    MODEL_UNAVAILABLE,
    SCHEMA_INVALID,
    SECTIONS,
    TRIAGE_SUSPICIOUS,
    SCHEDULED_TRIAGE,
    AgentFailure,
    AgentRequest,
    AgentResult,
    Budgets,
    Citation,
    Cost,
    EvidencePackage,
    Gap,
    RenderedSection,
    Rendering,
    RequestVersions,
)
from helena.taxonomy import ANALYST, TRIAGE

PROJECT_ROOT = Path(__file__).resolve().parent.parent

WINDOW_START = datetime(2026, 9, 9, 12, 0, tzinfo=timezone.utc)
CITED = "evidence-1"

ANALYST_BUDGETS = Budgets(steps=4, tokens=8000, wall_clock_seconds=20.0, live_queries=2)
TRIAGE_BUDGETS = Budgets(steps=0, tokens=8000, wall_clock_seconds=20.0, live_queries=0)


class Clock:
    """A monotonic source a test drives, so nothing sleeps to spend a budget."""

    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def versions(**overrides: str) -> RequestVersions:
    return RequestVersions(
        **{
            "prompt_version": "p1",
            "schema_version": CONTRACT_VERSION,
            "rendering_version": "r1",
            "taxonomy_version": "v1",
            "enrichment_snapshot_version": "2026-09-09T00:00:00Z",
            "normalization_snapshot_version": "psl-2026-09-09",
            "policy_version": "v1",
            "aggregation_version": "v1",
            "model_requested": "stub-model",
            **overrides,
        }
    )


def request(emitter: str = ANALYST, **overrides: object) -> AgentRequest:
    return AgentRequest(
        **{
            "tenant": "acme",
            "sensor": "sensor-1",
            "emitter": emitter,
            "host": "10.127.0.100",
            "window_start": WINDOW_START,
            "window_end": WINDOW_START + timedelta(minutes=5),
            "context_id": "ctx-1",
            "context_version": "ctx-1/3",
            "trigger": TRIAGE_SUSPICIOUS if emitter == ANALYST else SCHEDULED_TRIAGE,
            "rendering": Rendering(
                version="r1",
                sections=tuple(
                    RenderedSection(section=name, body=f"<{name}>", evidence_ids=())
                    for name in SECTIONS
                ),
            ),
            "budgets": ANALYST_BUDGETS if emitter == ANALYST else TRIAGE_BUDGETS,
            "versions": versions(),
            **overrides,
        }
    )


def cost(**overrides: object) -> Cost:
    return Cost(
        **{
            "prompt_tokens": 100,
            "completion_tokens": 20,
            "steps": 0,
            "live_queries": 0,
            "cache_hits": 0,
            "retries": 0,
            "wall_clock_seconds": 1.5,
            **overrides,
        }
    )


def result(
    classification: str = "normal",
    *,
    emitter: str = ANALYST,
    gaps: tuple[Gap, ...] = (),
    package: EvidencePackage | None = None,
) -> AgentResult:
    """A verdict. Citations where the contract requires them and not otherwise."""
    cited = () if emitter == TRIAGE and classification == "normal" else (
        Citation(evidence_id=CITED, stance="supporting"),
    )
    # An analyst verdict that is not `normal` carries an evidence package
    # (`concept/04`), and only a `normal` one may omit it.
    if package is None and emitter == ANALYST and classification != "normal":
        package = EvidencePackage(patterns=("beaconing",), narrative="what was seen")
    return AgentResult(
        emitter=emitter,
        classification=classification,
        confidence=0.9,
        citations=cited,
        evidence_package=package,
        gaps=gaps,
        cost=cost(steps=2 if emitter == ANALYST else 0),
        versions=versions().completed_by("stub-model-2026-05"),
    )


def failure(reason: str = SCHEMA_INVALID, **overrides: object) -> AgentFailure:
    return AgentFailure(
        **{
            "emitter": ANALYST,
            "reason": reason,
            "detail": "nothing validated",
            "cost": cost(steps=2),
            "versions": versions(),
            "model_version": None if reason == MODEL_UNAVAILABLE else "stub-model-2026-05",
            **overrides,
        }
    )


# --- One vocabulary for the four dimensions ----------------------------------


def test_the_dimensions_are_the_contracts_own_field_names():
    """Two copies of a vocabulary that can drift are worse than none.

    A dimension name reaches a `BudgetExhausted`, a gap detail and a refusal, so a
    fifth spelling of "wall clock" here would be a budget nothing enforces under a
    name nothing reads.
    """
    assert set(DIMENSIONS) == set(Budgets.model_fields)
    assert DIMENSIONS == (STEPS, TOKENS, WALL_CLOCK, LIVE_QUERIES)


def test_an_unknown_dimension_cannot_be_reported_as_exhausted():
    with pytest.raises(BudgetError):
        BudgetExhausted("money", "no price table exists")


def test_the_ledger_takes_the_budgets_the_request_carried():
    given = request()
    assert RunBudget.of(given).limits == given.budgets
    with pytest.raises(BudgetError):
        RunBudget({"steps": 1})  # type: ignore[arg-type]


# --- Steps: the unbounded tool loop ------------------------------------------


def test_every_step_is_charged_and_the_loop_ends_where_the_budget_does():
    budget = RunBudget(ANALYST_BUDGETS)
    for spent in range(ANALYST_BUDGETS.steps):
        budget.charge_step()
        assert budget.steps_spent == spent + 1
    assert budget.remaining_steps == 0
    with pytest.raises(BudgetExhausted) as refused:
        budget.charge_step()
    assert refused.value.dimension == STEPS
    assert budget.exhausted == (STEPS,)
    # The refusal did not spend the step it refused.
    assert budget.steps_spent == ANALYST_BUDGETS.steps


def test_a_triage_ledger_refuses_the_first_step_because_triage_has_no_tools():
    """`concept/04`: triage's tools are "none at all", expressed as policy.

    The contract already refuses a triage request that budgets a step; this is the
    same rule arriving at the boundary, so a triage runner that grew a tool loop
    would be refused by the ledger rather than by a comment.
    """
    budget = RunBudget.of(request(TRIAGE))
    with pytest.raises(BudgetExhausted) as refused:
        budget.charge_step()
    assert refused.value.dimension == STEPS


# --- Live queries: the provider quota ----------------------------------------


def test_live_queries_are_charged_separately_from_steps():
    budget = RunBudget(ANALYST_BUDGETS)
    budget.charge_step()
    budget.charge_live_query()
    assert (budget.steps_spent, budget.live_queries_spent) == (1, 1)
    budget.charge_step()
    budget.charge_live_query()
    with pytest.raises(BudgetExhausted) as refused:
        budget.charge_live_query()
    assert refused.value.dimension == LIVE_QUERIES
    assert budget.exhausted == (LIVE_QUERIES,)
    # Two steps are left, and they are what a cache hit spends.
    assert budget.remaining_steps == 2


def test_a_cache_hit_is_counted_and_charges_nothing():
    """`concept/03` records "cache-hit versus live-query counts"; only one is a quota."""
    budget = RunBudget(ANALYST_BUDGETS)
    budget.charge_step()
    budget.record_cache_hit()
    assert budget.cache_hits == 1
    assert budget.remaining_live_queries == ANALYST_BUDGETS.live_queries


# --- The wall clock, which covers the whole run ------------------------------


def test_the_clock_starts_with_the_ledger_and_not_with_the_call():
    """A provider wait shortens the time left to reason, which is the point.

    `concept/07`: "at a few lookups per minute, an analyst run checking six
    indicators spends over a minute waiting on the rate limit alone, before any
    inference." Nothing here sleeps: the clock is injected and driven.
    """
    clock = Clock()
    budget = RunBudget(ANALYST_BUDGETS, clock=clock)
    assert budget.remaining_seconds == ANALYST_BUDGETS.wall_clock_seconds
    budget.check_clock()

    clock.advance(15.0)
    assert budget.elapsed_seconds == 15.0
    assert budget.remaining_seconds == 5.0
    budget.check_clock()

    clock.advance(5.0)
    with pytest.raises(BudgetExhausted) as refused:
        budget.check_clock()
    assert refused.value.dimension == WALL_CLOCK
    assert budget.exhausted == (WALL_CLOCK,)
    # The number the model loop passes as its request timeout goes with it.
    assert budget.remaining_seconds <= 0


# --- Tokens: spent is not the same as truncated ------------------------------


def test_tokens_are_recorded_as_spent_and_refused_only_when_asked_for_more():
    budget = RunBudget(ANALYST_BUDGETS)
    budget.record_tokens(prompt=6000, completion=2000)
    assert budget.tokens_spent == 8000
    assert budget.remaining_tokens == 0
    # Spending the last token is not a truncation: the answer that spent it is
    # still an answer. Only asking for another attempt is.
    assert budget.exhausted == ()
    assert budget.gap() is None
    with pytest.raises(BudgetExhausted) as refused:
        budget.check_tokens()
    assert refused.value.dimension == TOKENS
    assert budget.exhausted == (TOKENS,)


def test_a_negative_token_count_is_a_client_bug_and_is_not_recorded():
    budget = RunBudget(ANALYST_BUDGETS)
    with pytest.raises(BudgetError):
        budget.record_tokens(prompt=-1, completion=0)
    assert budget.tokens_spent == 0


# --- What the ledger becomes ---------------------------------------------------


def test_the_cost_is_what_the_run_spent_including_latency():
    """`concept/03`'s typed columns: budgets consumed, latency, tokens, and the two counts."""
    clock = Clock()
    budget = RunBudget(ANALYST_BUDGETS, clock=clock)
    budget.charge_step()
    budget.charge_live_query()
    budget.charge_step()
    budget.record_cache_hit()
    budget.record_tokens(prompt=300, completion=90)
    clock.advance(2.5)

    spent = budget.cost(retries=1)
    assert spent == Cost(
        prompt_tokens=300,
        completion_tokens=90,
        steps=2,
        live_queries=1,
        cache_hits=1,
        retries=1,
        wall_clock_seconds=2.5,
    )
    # `concept/06`: monetary cost is derived per assessment and not capped here,
    # and no price table exists in this repository to derive it from.
    assert "cost" not in Cost.model_fields
    assert not any("monetar" in name or name == "money" for name in Cost.model_fields)


def test_a_negative_retry_count_is_refused():
    with pytest.raises(BudgetError):
        RunBudget(ANALYST_BUDGETS).cost(retries=-1)


def test_the_gap_names_every_dimension_the_run_was_refused_in_order():
    clock = Clock()
    budget = RunBudget(ANALYST_BUDGETS, clock=clock)
    assert budget.gap() is None

    for _ in range(ANALYST_BUDGETS.live_queries):
        budget.charge_step()
        budget.charge_live_query()
    with pytest.raises(BudgetExhausted):
        budget.charge_live_query()
    clock.advance(ANALYST_BUDGETS.wall_clock_seconds + 1)
    with pytest.raises(BudgetExhausted):
        budget.check_clock()

    gap = budget.gap()
    assert gap is not None
    assert gap.kind == BUDGET_EXHAUSTED
    assert gap.detail.index("live queries") < gap.detail.index("wall clock")
    assert "2 of 2 live queries" in gap.detail


# --- The degrade rule ----------------------------------------------------------


def spent(dimension: str = LIVE_QUERIES) -> RunBudget:
    """A ledger that was refused one thing, so `gap()` has something to say."""
    budget = RunBudget(Budgets(steps=1, tokens=1, wall_clock_seconds=20.0, live_queries=0))
    if dimension == LIVE_QUERIES:
        with pytest.raises(BudgetExhausted):
            budget.charge_live_query()
    elif dimension == TOKENS:
        budget.record_tokens(prompt=1, completion=0)
        with pytest.raises(BudgetExhausted):
            budget.check_tokens()
    else:  # pragma: no cover - the two above are what the tests use
        raise AssertionError(dimension)
    return budget


def test_a_run_that_exhausted_nothing_is_returned_untouched():
    verdict = result()
    assert degraded(verdict, RunBudget(ANALYST_BUDGETS)) is verdict


def test_a_truncated_normal_analyst_verdict_degrades_to_unknown():
    """`concept/07`: "a budget-truncated analyst run returns `normal`" must never happen.

    It established the absence of nothing, so the verdict becomes `unknown` —
    unassessable — and the exhaustion is explicit beside it. The citations it did
    make stay: they are what it saw before the budget ran out.
    """
    verdict = degraded(result("normal"), spent())
    assert isinstance(verdict, AgentResult)
    assert verdict.root == "unknown"
    assert [gap.kind for gap in verdict.gaps] == [BUDGET_EXHAUSTED]
    assert verdict.citations == (Citation(evidence_id=CITED, stance="supporting"),)
    # `unknown` is not `normal` and it is not `suspicious` either: `concept/07`
    # refuses to collapse unassessable into assessed-and-unsettled.
    assert verdict.classification != "suspicious"
    # A `normal` analyst verdict may omit the evidence package and `unknown` may
    # not, so the degrade attaches an empty one: the analyst named no patterns.
    assert verdict.evidence_package == EvidencePackage()


@pytest.mark.parametrize("classification", ["suspicious", "malicious.c2", "unknown"])
def test_a_truncated_verdict_that_is_not_normal_keeps_its_verdict(classification: str):
    """"A verdict on what was gathered, with exhaustion and gaps explicit."

    Only `normal` is the claim a truncated run cannot make. Everything else is a
    verdict on what it did see, and rewriting it would throw away the analysis
    that had already happened.
    """
    package = EvidencePackage(patterns=("beaconing",), narrative="seen so far")
    before = result(
        classification,
        gaps=(Gap(kind="stale", detail="one feed was a day old"),),
        package=package,
    )
    after = degraded(before, spent())
    assert isinstance(after, AgentResult)
    assert after.classification == classification
    assert [gap.kind for gap in after.gaps] == ["stale", BUDGET_EXHAUSTED]
    assert after.evidence_package == package


def test_a_typed_failure_gets_the_gap_and_stays_a_typed_failure():
    """There is no verdict to degrade, and a failure may not acquire one.

    `concept/02`: a typed failure is "stored as an assessment row carrying the
    failure and **no** verdict — never a verdict, never a silent drop".
    """
    after = degraded(failure(), spent())
    assert isinstance(after, AgentFailure)
    assert after.reason == SCHEMA_INVALID
    assert [gap.kind for gap in after.gaps] == [BUDGET_EXHAUSTED]
    assert not hasattr(after, "classification")


def test_the_gap_is_not_recorded_twice():
    """One fact once. The gaps list is what makes `unknown` falsifiable."""
    already = result(
        "suspicious", gaps=(Gap(kind=BUDGET_EXHAUSTED, detail="the loop ran out"),)
    )
    assert degraded(already, spent()) is already


def test_a_truncated_triage_verdict_has_nowhere_to_degrade_to():
    """Triage has no `unknown` root: the outcome is a typed failure, not a third label.

    `concept/07`: "triage could not assess the context → a typed failure, not a
    third label." `helena.agents.assess` produces exactly that, with this gap on
    it, so a truncated triage `normal` reaching here is a bug in a caller rather
    than an outcome to rewrite.
    """
    with pytest.raises(BudgetError) as refused:
        degraded(result("normal", emitter=TRIAGE), spent())
    assert "unknown" in str(refused.value)
    assert "unknown" not in taxonomy.version("v1").emitter_roots[TRIAGE]


@pytest.mark.parametrize("classification", ["normal", "suspicious", "malicious.c2"])
def test_a_budget_truncated_run_can_return_unknown_and_can_never_return_normal(
    classification: str,
):
    """The rule from both sides, because one side alone would not hold it.

    `concept/07`, under *must never happen*: "a budget-truncated analyst run
    returns `normal` — it established the absence of nothing."

    From above: whatever the model answered, a truncated run's verdict is not
    `normal` once the exhaustion is recorded. From below: the contract itself
    refuses a result carrying a `budget_exhausted` gap on a `normal` root, so
    there is no way to assemble the forbidden outcome by hand either — including
    the way that would look most innocent, a `degraded` implemented with
    `model_copy`, which skips validation entirely.
    """
    verdict = degraded(result(classification), spent())
    assert isinstance(verdict, AgentResult)
    assert verdict.root != "normal"
    assert any(gap.kind == BUDGET_EXHAUSTED for gap in verdict.gaps)

    with pytest.raises(ValueError) as refused:
        result("normal", gaps=(Gap(kind=BUDGET_EXHAUSTED, detail="spent"),))
    assert "never return `normal`" in str(refused.value)


# --- The values are policy, and the fourth dimension is derived ---------------


def write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "policy.toml"
    path.write_text(text)
    return path


A_FILE = """
[budgets.triage]
tokens = 8000
wall_clock_seconds = 30.0

[budgets.analyst]
steps = 12
tokens = 60000
wall_clock_seconds = 300.0
retrieval_seconds = 120.0

[rate_limits]
threatfox = 4
"""


def test_the_committed_policy_file_is_what_a_run_is_bounded_by():
    """The file a deployment actually edits, read as the loader reads it.

    A suite that read a temporary copy would pass with the committed file saying
    anything at all — including nothing.
    """
    loaded = budgets.load()
    assert set(loaded.by_emitter) == set(taxonomy.EMITTERS)
    for emitter, bounded in loaded.by_emitter.items():
        assert bounded == loaded.for_emitter(emitter)
    triage = loaded.for_emitter(TRIAGE)
    assert (triage.steps, triage.live_queries) == (0, 0)
    assert loaded.for_emitter(ANALYST).steps > 0
    with pytest.raises(BudgetError) as refused:
        loaded.for_emitter("some-agent-nobody-configured")
    assert "policy" in str(refused.value)


def test_the_live_query_budget_is_derived_from_the_clock_and_the_rate():
    """`concept/07`: the two "have to be set against each other", not independently.

    Recomputed here from the two inputs the loader kept, rather than compared with
    a number written down twice.
    """
    loaded = budgets.load()
    analyst = loaded.for_emitter(ANALYST)
    allowance = loaded.retrieval_seconds[ANALYST]
    slowest = min(loaded.rate_limits.values())
    assert analyst.live_queries == int(allowance * slowest // 60)
    # The pair is survivable: spending the whole live-query budget at the slowest
    # configured rate fits inside the wall clock, with time left to reason.
    assert analyst.live_queries / slowest * 60 <= allowance < analyst.wall_clock_seconds
    # And the step budget can actually reach it.
    assert analyst.steps >= analyst.live_queries
    # Triage gets no retrieval allowance at all, because it has no tools.
    assert TRIAGE not in loaded.retrieval_seconds


def test_the_slowest_configured_provider_is_the_one_the_budget_is_derived_from(tmp_path):
    """A run's queries may all go to one source, so the survivable budget is the slow one."""
    path = write(
        tmp_path,
        A_FILE.replace("threatfox = 4", "threatfox = 4\n'sslbl-ja3' = 60"),
    )
    loaded = budgets.load(path)
    assert loaded.rate_limits == {"threatfox": 4, "sslbl-ja3": 60}
    assert loaded.for_emitter(ANALYST).live_queries == int(120.0 * 4 // 60)


def test_a_budget_file_that_is_absent_is_a_startup_failure(tmp_path):
    with pytest.raises(BudgetError) as refused:
        budgets.load(tmp_path / "nothing.toml")
    assert "never an unbounded run" in str(refused.value)


def test_an_unreadable_file_is_a_startup_failure(tmp_path):
    with pytest.raises(BudgetError):
        budgets.load(write(tmp_path, "[budgets.triage\n"))


@pytest.mark.parametrize(
    "edit, expected",
    [
        # A key nothing reads is a policy somebody set and nothing applies.
        (lambda text: text + "\n[quotas]\ndaily = 500\n", "quotas"),
        # No budget at all for an agent that runs.
        (
            lambda text: text.replace(
                "[budgets.triage]\ntokens = 8000\nwall_clock_seconds = 30.0\n", ""
            ),
            "triage",
        ),
        # A budget for something that is not an agent.
        (lambda text: text + "\n[budgets.hunter]\ntokens = 1\n", "hunter"),
        # Triage may not be given a step budget: it has no tools at all.
        (
            lambda text: text.replace(
                "[budgets.triage]\ntokens", "[budgets.triage]\nsteps = 3\ntokens"
            ),
            "no tools at all",
        ),
        # The live-query count is derived and may never be written down.
        (
            lambda text: text.replace(
                "retrieval_seconds = 120.0", "retrieval_seconds = 120.0\nlive_queries = 9"
            ),
            "derived",
        ),
        # A dimension with no value has no default.
        (lambda text: text.replace("tokens = 60000\n", ""), "tokens"),
        # Retrieval that does not fit inside the wall clock leaves nothing to reason with.
        (
            lambda text: text.replace("retrieval_seconds = 120.0", "retrieval_seconds = 400.0"),
            "no time to reason",
        ),
        # An allowance that buys no query at the slowest rate.
        (
            lambda text: text.replace("retrieval_seconds = 120.0", "retrieval_seconds = 10.0"),
            "could never reach one",
        ),
        # A step budget the derived live-query budget cannot fit inside.
        (lambda text: text.replace("steps = 12", "steps = 3"), "never applies"),
        # Tools and no rate limit to derive the quota from.
        (lambda text: text.replace("threatfox = 4", ""), "nothing to derive"),
        # A rate limit for a source nobody registered.
        (
            lambda text: text.replace("threatfox = 4", "'some-api' = 4\nthreatfox = 4"),
            "governed decision",
        ),
        # A rate of zero is a source nothing may ever ask.
        (lambda text: text.replace("threatfox = 4", "threatfox = 0"), "positive"),
        # A budget of zero on a dimension a run cannot work without.
        (lambda text: text.replace("tokens = 8000", "tokens = 0"), "positive"),
        (
            lambda text: text.replace(
                "wall_clock_seconds = 30.0", "wall_clock_seconds = 0"
            ),
            "positive",
        ),
    ],
)
def test_a_budget_file_that_contradicts_itself_is_refused(tmp_path, edit, expected):
    """Every one of these is a way the four dimensions can be inconsistent.

    `concept/instruction.md` §6: a silent configuration default is a named trap,
    and every failure here names the file and what is wrong with it.
    """
    with pytest.raises(BudgetError) as refused:
        budgets.load(write(tmp_path, edit(A_FILE)))
    assert expected in str(refused.value)


def test_both_loaders_read_the_same_file_and_neither_rejects_the_others_keys():
    """One policy file, two tables. `concept/07` puts budgets and thresholds in one sentence.

    Asserted over the committed file rather than over the constants, because the
    failure this prevents is one loader refusing to start on a file the other one
    requires.
    """
    assert budgets.POLICY_FILE == policy.POLICY_FILE
    assert budgets.POLICY_FILE == PROJECT_ROOT / "config" / "policy.toml"
    assert policy.BUDGET_KEYS.isdisjoint(policy.THRESHOLD_KEYS)
    assert budgets.load(policy.POLICY_FILE).by_emitter
    assert policy.thresholds(budgets.POLICY_FILE).by_source


# --- The price table ----------------------------------------------------------
#
# `concept/06-technology.md`: "monetary model cost is **derived** and recorded per
# assessment, not separately capped". `helena.orchestration.AssessmentStore` is
# what multiplies these numbers by a run's tokens; what is asserted here is that
# the table is loaded from the policy file and that an unpriced model is a `None`
# rather than a guess.

PRICED = """
model_prices_version = "2026-09-10"

[model_prices."vendor/some-model"]
prompt_per_million = 3.0
completion_per_million = 15.0
currency = "USD"
"""


def test_the_committed_policy_file_prices_nothing_and_that_is_the_correct_state():
    """An empty price table, and it is empty because the price is an external fact.

    `config/policy.toml` argues it: this repository does not know what the
    endpoint in `.env` charges, and `concept/instruction.md` §0's *check the
    artifact, not the page* makes an invented rate worse than an absent one. So
    the version is there — every derived figure records one — and the table is
    not, and an unpriced model derives `None`.
    """
    table = budgets.model_prices()
    assert table.version
    assert table.prices == {}
    assert table.for_model("model-under-test") is None


def test_a_configured_price_derives_the_cost_from_the_two_token_counts(tmp_path):
    """Per million, in the currency the entry states."""
    table = budgets.model_prices(write(tmp_path, PRICED))
    price = table.for_model("vendor/some-model")
    assert price is not None
    assert price.currency == "USD"
    spent = Cost(
        prompt_tokens=1_000_000,
        completion_tokens=2_000_000,
        steps=0,
        live_queries=0,
        cache_hits=0,
        retries=0,
        wall_clock_seconds=1.0,
    )
    assert price.of(spent) == pytest.approx(3.0 + 30.0)


def test_a_price_table_that_cannot_say_which_revision_it_is_is_refused(tmp_path):
    """A stored cost records the revision that derived it, or it cannot be checked."""
    without = PRICED.replace('model_prices_version = "2026-09-10"\n', "")
    with pytest.raises(budgets.BudgetError) as refused:
        budgets.model_prices(write(tmp_path, without))
    assert "model_prices_version" in str(refused.value)


@pytest.mark.parametrize(
    "dropped",
    ["prompt_per_million = 3.0\n", "completion_per_million = 15.0\n", 'currency = "USD"\n'],
)
def test_half_a_price_is_refused_rather_than_defaulted(tmp_path, dropped):
    """There is no default for a rate and none for a currency.

    Unlike a *missing model*, which is a `None` — the asymmetry is the point.
    A model the table is silent about is a price nobody knows; an entry stating
    two of three keys is a price somebody wrote down wrong.
    """
    with pytest.raises(budgets.BudgetError) as refused:
        budgets.model_prices(write(tmp_path, PRICED.replace(dropped, "")))
    assert "price entry states" in str(refused.value)
