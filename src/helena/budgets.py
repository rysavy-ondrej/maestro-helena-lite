"""Budget guards — the four dimensions of one agent run, enforced where they are spent.

`concept/03-architecture.md` lists **policy and budget guards** as "deterministic
code enforcing the agent-boundary rules around every agent", and `concept/07`
gives the four dimensions and the one rule about where they are checked:

| Dimension | The real limit it maps to | Enforced in |
| --- | --- | --- |
| Step / tool-call count | the unbounded tool loop | `helena.tools.ProviderTool.lookup` |
| Token budget | model service rate limits and quotas | `helena.agents.assess` |
| Wall-clock timeout | stream latency | both, off one clock |
| Live external query count | provider quotas | `helena.tools.ProviderTool.lookup` |

**Budgets are enforced at the tool boundary, so an agent cannot reason its way
around them** (`concept/07`, `concept/05`'s tool rules). Nothing in a prompt says
how many lookups are left, and nothing needs to: the dispatch refuses the call.
A model that asks anyway gets a typed, agent-visible `ToolRefusal` and the run
carries on with one fewer step.

## One ledger per run, and why it is not four numbers in a loop

`RunBudget` is the ledger and it is created **once per agent run**, from
`AgentRequest.budgets`. Both the model loop and the tool dispatch charge the same
object, which is what makes the wall clock cover *the whole run including provider
waits* rather than one model call at a time. Two ledgers — one in `assess`, one
around the tools — would be two copies of a fact that can drift
(`concept/instruction.md` §2), and the drift is in the dangerous direction: an
analyst turn that started its own clock would get the full wall-clock budget again
after every lookup, which is the unbounded loop the dimension exists to bound.

It is mutable and in-process, which `concept/07`'s "ephemeral state" allows and
requires: it is working memory for one assessment and never the durable record.
What is durable is `helena.contracts.v1.Cost` — `cost()` is how the ledger becomes
one — and the assessment row that stores it is `prds/prd.json` task 43's.

## Where this module is, and why it is not `orchestration`

`concept/03`'s component table has a row for the guards and
`tests/test_package_layout.py` used to read that row as "the deterministic code in
`orchestration`". It cannot be, and the reason is mechanical: orchestration is the
code that will import `helena.agents` **and** `helena.tools`, and both of those
have to charge the ledger, so a ledger defined in `orchestration` is an import
cycle. `docs/decisions/0026-the-budget-guard.md` records the decision.

## Budget values are policy

`concept/07`: "budget values are **policy, not constants in a branch**; the same
applies to confidence thresholds." So `load()` reads them from
`config/policy.toml` — the same versioned policy file `helena.policy.thresholds`
reads — and there is no default anywhere in this module. A missing file, a missing
emitter or a missing rate limit is a startup failure naming what is absent.

**The wall-clock and live-query budgets are set against each other**, which is the
part `concept/07` is emphatic about: "at a few lookups per minute, an analyst run
checking six indicators spends over a minute waiting on the rate limit alone". So
the live-query count is **not configured**. It is derived from two numbers that
are — the seconds of the run's wall clock that may be spent waiting on providers,
and the slowest configured provider rate — and `config/policy.toml` argues both.

Maturity: experimental — the ledger, the derivation and the degradation are
exercised by `tests/test_budgets.py`, the tool-boundary enforcement by
`tests/test_tools.py` and the model-loop half by `tests/test_agents.py`. **No
analyst tool loop calls this yet** (task 39), and nothing stores a `Cost`
(task 43), so "budgets consumed are recorded on the assessment" is a shape that is
ready and not a property that holds.
"""

from __future__ import annotations

import json
import time
import tomllib
from collections.abc import Callable
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from helena import taxonomy
from helena.contracts import v1 as contract
from helena.policy import BUDGET_KEYS, POLICY_FILE, THRESHOLD_KEYS

__all__ = [
    "BUDGET_KEYS",
    "DIMENSIONS",
    "LIVE_QUERIES",
    "POLICY_FILE",
    "STEPS",
    "TOKENS",
    "WALL_CLOCK",
    "BudgetError",
    "BudgetExhausted",
    "BudgetPolicy",
    "RunBudget",
    "degraded",
    "load",
]

# The four dimensions, spelled exactly as `helena.contracts.v1.Budgets` spells
# them. One vocabulary: a dimension name reaches a gap detail, a log line and a
# `BudgetExhausted`, and a second spelling of "wall clock" in any of them is the
# drift the version rules exist to prevent. `tests/test_budgets.py` asserts these
# are the contract's own field names rather than a list that looks like them.
STEPS = "steps"
TOKENS = "tokens"
WALL_CLOCK = "wall_clock_seconds"
LIVE_QUERIES = "live_queries"
DIMENSIONS = (STEPS, TOKENS, WALL_CLOCK, LIVE_QUERIES)


class BudgetError(RuntimeError):
    """The budget policy or the ledger was misconfigured or misused.

    Never a model's fault and never a provider's: every case is this deployment's
    configuration or this project's code. A model that spent its budget gets a
    `BudgetExhausted`, which is a different class for exactly that reason.
    """


class BudgetExhausted(Exception):
    """A dimension has nothing left, raised where the spending was about to happen.

    Carries the dimension, from `DIMENSIONS`, so an operator can count which
    budget is the one that keeps binding — `concept/07` makes the retry count per
    model a quality metric on the same grounds.

    It is an exception rather than a returned `False` because the call it refuses
    must not proceed by accident: a caller that forgets to check a boolean gets a
    lookup, and a caller that forgets to catch this gets a loud failure. The tool
    boundary catches it and returns a typed `ToolRefusal`; nothing else may
    swallow it.
    """

    def __init__(self, dimension: str, detail: str) -> None:
        if dimension not in DIMENSIONS:
            raise BudgetError(
                f"dimension {dimension!r} is not one of {list(DIMENSIONS)}"
            )
        super().__init__(detail)
        self.dimension = dimension
        self.detail = detail


class RunBudget:
    """One agent run's four limits and what it has spent. Mutable, in-process, ephemeral.

    Built by `of(request)` from the request's `Budgets`, which is where the values
    the policy file supplied arrive. The limits are read-only; the consumption is
    what changes.

    **The clock starts when the ledger is built**, not when a model call or a
    lookup begins, which is the whole point: `remaining_seconds` shrinks while a
    provider is being waited on, so a run that spent four minutes on rate-limited
    lookups has four minutes less to reason with. `clock` is injectable so a test
    can drive it without sleeping; it is a monotonic source, never a wall date,
    because a clock adjustment mid-run must not extend or truncate a budget.

    Two shapes of question, and they are not interchangeable:

    | | |
    | --- | --- |
    | `remaining_tokens`, `remaining_seconds` | the model loop needs the *number*: it passes the remainder to the endpoint as `max_tokens` and as the request timeout |
    | `charge_step`, `charge_live_query`, `check_clock` | the tool dispatch needs the *decision*, and a refused one raises rather than returning a value a caller could ignore |
    """

    __slots__ = (
        "_limits",
        "_clock",
        "_started",
        "_prompt_tokens",
        "_completion_tokens",
        "_steps",
        "_live_queries",
        "_cache_hits",
        "_exhausted",
    )

    def __init__(
        self,
        limits: contract.Budgets,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not isinstance(limits, contract.Budgets):
            raise BudgetError(
                f"the limits are a {type(limits).__name__}; a run is bounded by "
                f"the four dimensions the contract carries, so that the budget a "
                f"request was given and the budget that was enforced cannot be "
                f"two different things"
            )
        self._limits = limits
        self._clock = clock
        self._started = clock()
        self._prompt_tokens = 0
        self._completion_tokens = 0
        self._steps = 0
        self._live_queries = 0
        self._cache_hits = 0
        # Insertion-ordered, so the gap detail names dimensions in the order the
        # run hit them. A dict rather than a set for that reason alone.
        self._exhausted: dict[str, None] = {}

    @classmethod
    def of(
        cls,
        request: contract.AgentRequest,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> RunBudget:
        """The ledger for one request. The only constructor orchestration should use.

        Symmetric with `helena.tools.RunScope.of`, and for the same reason: what
        bounds a run is deterministic code's to decide and the request is where it
        was written down, so a ledger assembled from loose numbers beside a
        request is a run enforced against a budget nobody handed it.
        """
        return cls(request.budgets, clock=clock)

    def __repr__(self) -> str:
        return (
            f"RunBudget(steps={self._steps}/{self._limits.steps}, "
            f"tokens={self.tokens_spent}/{self._limits.tokens}, "
            f"live_queries={self._live_queries}/{self._limits.live_queries}, "
            f"elapsed={self.elapsed_seconds:.3f}/"
            f"{self._limits.wall_clock_seconds}s)"
        )

    # --- What it was given ---------------------------------------------------

    @property
    def limits(self) -> contract.Budgets:
        """The four dimensions as the request carried them. Frozen; never adjusted."""
        return self._limits

    # --- What it has spent ---------------------------------------------------

    @property
    def steps_spent(self) -> int:
        return self._steps

    @property
    def live_queries_spent(self) -> int:
        return self._live_queries

    @property
    def cache_hits(self) -> int:
        return self._cache_hits

    @property
    def tokens_spent(self) -> int:
        return self._prompt_tokens + self._completion_tokens

    @property
    def elapsed_seconds(self) -> float:
        return self._clock() - self._started

    @property
    def remaining_steps(self) -> int:
        return self._limits.steps - self._steps

    @property
    def remaining_live_queries(self) -> int:
        return self._limits.live_queries - self._live_queries

    @property
    def remaining_tokens(self) -> int:
        return self._limits.tokens - self.tokens_spent

    @property
    def remaining_seconds(self) -> float:
        return self._limits.wall_clock_seconds - self.elapsed_seconds

    @property
    def exhausted(self) -> tuple[str, ...]:
        """The dimensions this run **asked for more of and was refused**, in order.

        A record of refusals and deliberately not a computation over the
        remainders, because the two answer different questions and only one of
        them is what `concept/07` degrades a verdict for. A run that spent its
        last token on the answer it then returned was not truncated: it finished.
        A run that wanted another lookup, or another attempt, and could not have
        one **was** truncated, and that is the run that "established the absence
        of nothing".

        So every `charge_*` and `check_*` that refuses records its dimension here,
        and `record_tokens` — which reports spending that already happened —
        records nothing.
        """
        return tuple(self._exhausted)

    # --- Spending it ---------------------------------------------------------

    def charge_step(self) -> None:
        """One tool call. Raises `BudgetExhausted` when the loop has no step left.

        Charged for **every** call the dispatch accepts, including one it then
        refuses as malformed and one a cache hit answers: `concept/07`'s dimension
        is the step count, and a malformed call the model has to be told about is a
        turn of the loop whatever came of it. That is what bounds the loop.
        """
        if self.remaining_steps <= 0:
            self._exhausted[STEPS] = None
            raise BudgetExhausted(
                STEPS,
                f"the step budget of {self._limits.steps} is spent; a tool loop "
                f"is bounded by orchestration and not by the model deciding it "
                f"has asked enough",
            )
        self._steps += 1

    def charge_live_query(self) -> None:
        """One request that will reach a provider. Raises when the quota is spent.

        Charged **after** the cache has been consulted, never before, because a
        cache hit sends nothing: "a hit discloses nothing and costs no live query"
        is the property `docs/decisions/0025-the-lookup-cache.md` argues, and
        charging the quota before the read would spend it on a call that never
        left the process.
        """
        if self.remaining_live_queries <= 0:
            self._exhausted[LIVE_QUERIES] = None
            raise BudgetExhausted(
                LIVE_QUERIES,
                f"the live-query budget of {self._limits.live_queries} is spent; "
                f"a provider quota is shared across every host the pipeline "
                f"assesses (`concept/05`)",
            )
        self._live_queries += 1

    def record_cache_hit(self) -> None:
        """One call a stored record answered. Counted, never charged.

        `concept/03` puts "cache-hit versus live-query counts" on the assessment
        and `concept/07` requires two runs differing only in cache state to be
        distinguishable afterwards. Both are counted per **call**, not per record:
        the unit a provider quota is spent in is the request, so a hit has to be
        counted in the same unit or the two numbers are not comparable.
        """
        self._cache_hits += 1

    def record_tokens(self, *, prompt: int, completion: int) -> None:
        """What a model call actually spent. Recorded, never refused.

        The tokens are already gone by the time the response says how many there
        were, so this cannot raise, and it does not mark the dimension either: the
        guard is `check_tokens`, and a run that spent its last token on an answer
        that validated finished rather than got truncated. See `exhausted`.
        """
        if prompt < 0 or completion < 0:
            raise BudgetError(
                f"a model call reported {prompt} prompt and {completion} "
                f"completion tokens; a negative count is a client bug, and "
                f"recording it would make the budget arithmetic silently wrong"
            )
        self._prompt_tokens += prompt
        self._completion_tokens += completion

    def check_tokens(self) -> None:
        """Whether another model call may be made at all. Raises when it may not.

        The model loop's guard, called before an attempt rather than after one.
        `concept/07`: "retries count against the budget", so a run whose retries
        spent the token budget ends here, and the dimension is recorded as
        refused because a run that wanted another attempt and could not have one
        is exactly the truncation `budget_exhausted` names.
        """
        if self.remaining_tokens <= 0:
            self._exhausted[TOKENS] = None
            raise BudgetExhausted(
                TOKENS,
                f"the token budget of {self._limits.tokens} is spent, "
                f"{self.tokens_spent} of it on this run; the retries a "
                f"schema-invalid answer costs are spent against it "
                f"(`concept/07`)",
            )

    def check_clock(self) -> None:
        """The whole run's clock, including every provider wait. Raises when it is spent.

        The tool boundary's check. The model loop deliberately does not call it:
        it needs `remaining_seconds` as the request timeout anyway, and a run that
        ran out of clock *there* is `helena.contracts.v1.TIMED_OUT` — a **failure
        reason** and not a gap, which is `docs/decisions/0020-the-model-client.md`
        §6's recorded shape and would be one fact twice if it were both. At the
        tool boundary the run is still alive and only the call is refused, so the
        exhaustion is a gap on whatever verdict the run ends up producing.
        """
        if self.remaining_seconds <= 0:
            self._exhausted[WALL_CLOCK] = None
            raise BudgetExhausted(
                WALL_CLOCK,
                f"the wall-clock budget of {self._limits.wall_clock_seconds}s is "
                f"spent, {self.elapsed_seconds:.1f}s of it on this run; provider "
                f"waits are on the same clock as the model calls",
            )

    # --- What it becomes -----------------------------------------------------

    def cost(self, *, retries: int) -> contract.Cost:
        """What the run spent, as the record an assessment stores.

        `concept/03`'s typed columns: "budgets consumed, latency, tokens, cost,
        and cache-hit versus live-query counts". Latency is `wall_clock_seconds`
        and it is the **whole run's**, which is the number a stream operator would
        act on. There is no monetary field: `concept/06` derives money from the
        token counts and a price table, no price table exists here, and
        `helena.contracts.v1.Cost` says so at length.

        `retries` is a parameter rather than a counter here because it is a fact
        about one model exchange — `attempts - 1` — and this ledger deliberately
        does not know how many model calls a run made.
        """
        if retries < 0:
            raise BudgetError(f"a run cannot have spent {retries} retries")
        return contract.Cost(
            prompt_tokens=self._prompt_tokens,
            completion_tokens=self._completion_tokens,
            steps=self._steps,
            live_queries=self._live_queries,
            cache_hits=self._cache_hits,
            retries=retries,
            wall_clock_seconds=self.elapsed_seconds,
        )

    def gap(self) -> contract.Gap | None:
        """The `budget_exhausted` gap, or `None` when nothing was exhausted.

        `concept/02` makes budget exhaustion one of the seven gap kinds and
        `concept/07` requires the exhaustion to be **explicit** on the verdict.
        The detail names the dimensions and what each was, because "the budget ran
        out" without saying which one is a gap that records that something was
        missing without recording what.
        """
        if not self._exhausted:
            return None
        spent = {
            STEPS: f"{self._steps} of {self._limits.steps} steps",
            TOKENS: f"{self.tokens_spent} of {self._limits.tokens} tokens",
            WALL_CLOCK: (
                f"{self.elapsed_seconds:.1f}s of "
                f"{self._limits.wall_clock_seconds}s wall clock"
            ),
            LIVE_QUERIES: (
                f"{self._live_queries} of {self._limits.live_queries} live queries"
            ),
        }
        hit = ", ".join(spent[dimension] for dimension in self._exhausted)
        return contract.Gap(
            kind=contract.BUDGET_EXHAUSTED,
            detail=f"the run exhausted {hit}"[: contract.MAX_DETAIL],
        )


def degraded(
    outcome: contract.AgentResult | contract.AgentFailure,
    budget: RunBudget,
) -> contract.AgentResult | contract.AgentFailure:
    """The outcome with the exhaustion made explicit, degraded rather than aborted.

    `concept/07`, "Partial results and failure": *budget exhausted mid-analysis →
    "a verdict on what was gathered, with exhaustion and gaps explicit — but
    **never `normal`**; it degrades to `unknown`"*. And in the list of things that
    must never happen: *"a budget-truncated analyst run returns `normal` — it
    established the absence of nothing."*

    So this is the one place a classification is rewritten by code, and it rewrites
    in exactly one direction:

    | The run | What comes back |
    | --- | --- |
    | nothing exhausted | the outcome, unchanged and not copied |
    | exhausted, verdict `normal` | `unknown`, with the gap. The absence it claimed to establish was never established |
    | exhausted, any other verdict | that verdict, with the gap. It is a verdict on what was gathered |
    | exhausted, a typed failure | the failure, with the gap. There is no verdict to degrade |

    Nothing else moves: the citations, the retrieval trace, the proposed claims
    and the cost are the run's own. A `normal` **analyst** verdict carries no
    evidence package (`concept/04` exempts only that one), and `unknown` requires
    one, so the degrade attaches an empty package — the analyst named no patterns,
    which is what an empty one says.

    Raises `BudgetError` for a truncated **triage** result, because triage has no
    `unknown` root: `concept/07` makes "triage could not assess the context" a
    typed failure and not a third label, so there is nothing to degrade a triage
    verdict *to*. `helena.agents.assess` already produces that typed failure with
    this gap on it.
    """
    gap = budget.gap()
    if gap is None:
        return outcome
    if any(existing.kind == contract.BUDGET_EXHAUSTED for existing in outcome.gaps):
        # Already explicit. A second gap of the same kind would be one fact
        # recorded twice, and the gaps list is what makes `unknown` falsifiable.
        return outcome
    gaps = [
        *(existing.model_dump(mode="json") for existing in outcome.gaps),
        gap.model_dump(mode="json"),
    ]
    if isinstance(outcome, contract.AgentFailure) or outcome.root != contract.NORMAL:
        return _revalidated(outcome, gaps=gaps)
    if outcome.emitter == taxonomy.TRIAGE:
        raise BudgetError(
            f"a triage run exhausted {list(budget.exhausted)} and returned "
            f"{outcome.classification!r}. Triage has no `unknown` root — "
            f"`concept/07` makes a context triage could not assess a typed "
            f"failure and not a third label — so there is nothing to degrade "
            f"this to, and it may not stand as a verdict either."
        )
    return _revalidated(
        outcome,
        gaps=gaps,
        classification=contract.UNKNOWN,
        evidence_package=(
            outcome.evidence_package or contract.EvidencePackage()
        ).model_dump(mode="json"),
    )


def _revalidated(
    outcome: contract.AgentResult | contract.AgentFailure, **updates: object
) -> contract.AgentResult | contract.AgentFailure:
    """The outcome with fields replaced, **through the contract's own validation**.

    `model_copy` would be shorter and would skip every rule in
    `model_post_init`, which is the one thing this function may not do: the rule
    that a `budget_exhausted` gap may not sit on a `normal` verdict lives there,
    and a degrade that bypassed it could produce exactly the outcome
    `concept/07` forbids. Validated as JSON for the reason
    `helena.agents.assess` gives: the contract is `strict=True`, and python mode
    would refuse the `list` a dump produces where a `tuple` is declared.
    """
    merged = {**outcome.model_dump(mode="json"), **updates}
    return type(outcome).model_validate_json(json.dumps(merged))


class BudgetPolicy(BaseModel):
    """The budget values one deployment configured, as loaded. Frozen.

    `by_emitter` is what a run is given and the only thing orchestration needs;
    the other two fields are the inputs the fourth dimension was **derived** from,
    kept because a derived number whose inputs are not recorded cannot be argued
    with. `tests/test_budgets.py` recomputes the derivation from them.
    """

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    #: `triage` / `analyst` -> the four dimensions. One entry per
    #: `helena.taxonomy.EMITTERS`, checked by the loader.
    by_emitter: dict[str, contract.Budgets]
    #: `source_id` -> queries per minute the tool layer holds itself to. Not a
    #: measured provider limit — see `config/policy.toml`.
    rate_limits: dict[str, int]
    #: emitter -> how many of its wall-clock seconds may be spent waiting on
    #: providers. Only the emitter with tools has one.
    retrieval_seconds: dict[str, float]

    def for_emitter(self, emitter: str) -> contract.Budgets:
        """This emitter's four dimensions, or a `BudgetError` naming what is loaded.

        Never a default. A run whose budget nobody configured is the run that
        discovers what unbounded costs, and it would discover it in exactly the
        deployment where the budget mattered.
        """
        try:
            return self.by_emitter[emitter]
        except KeyError:
            raise BudgetError(
                f"no budget is configured for {emitter!r}; "
                f"{sorted(self.by_emitter)} are. Budget values are policy "
                f"(`concept/07`), so an agent the policy file is silent about "
                f"runs against no budget at all."
            ) from None


#: The dimensions `config/policy.toml` states directly, per emitter. `live_queries`
#: is deliberately not among them — it is derived (see `load`) — and `steps` and
#: `retrieval_seconds` are only the tool-using emitter's.
_STATED = {TOKENS, WALL_CLOCK}
_TOOL_STATED = _STATED | {STEPS, "retrieval_seconds"}
_SECONDS_IN_A_MINUTE = 60


def load(path: Path | str = POLICY_FILE) -> BudgetPolicy:
    """Read the budget values, or fail naming what is wrong with the file.

    The same file and the same reader `helena.policy.thresholds` uses — `concept/07`
    puts budgets and confidence thresholds in one sentence as the two things that
    are policy rather than constants in a branch, so they are two tables of one
    policy file rather than two files.

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

    **The live-query budget is derived and may not be written down.**
    `concept/07`: "the wall-clock budget and the live-query budget have to be set
    against each other, not independently", because "at a few lookups per minute,
    an analyst run checking six indicators spends over a minute waiting on the
    rate limit alone". So:

        live_queries = floor(retrieval_seconds x slowest rate / 60)

    and the slowest configured rate is the one that counts, because the run's
    queries may all go to one source and the budget that survives is the one
    derived from the source that answers slowest. Four checks make the pair
    consistent rather than merely present, and each is a way the two numbers can
    contradict each other: a retrieval allowance that does not fit inside the wall
    clock, one that buys no query at all, a step budget too small to reach the
    live queries it was given, and an emitter with tools and no rate limit to
    derive from.

    `triage` states neither `steps` nor `retrieval_seconds` and is given zero of
    both: `concept/04` gives triage "no tools at all", and
    `helena.contracts.v1.AgentRequest` refuses a triage request that budgets a
    step. A configurable one would be a lookup nobody has to justify.
    """
    path = Path(path)
    try:
        raw = path.read_bytes()
    except FileNotFoundError as absent:
        raise BudgetError(
            f"no budget policy at {path}. `concept/07` makes budget values policy "
            f"and not constants in this package, so an absent file is a startup "
            f"failure and never an unbounded run."
        ) from absent
    try:
        document = tomllib.loads(raw.decode())
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as malformed:
        raise BudgetError(f"{path} is not readable TOML: {malformed}") from malformed

    unexpected = sorted(set(document) - BUDGET_KEYS - THRESHOLD_KEYS)
    if unexpected:
        raise BudgetError(
            f"{path} has top-level keys {unexpected}; the budget tables are "
            f"{sorted(BUDGET_KEYS)} and the threshold half of the file is "
            f"{sorted(THRESHOLD_KEYS)}. A key nothing reads is a policy somebody "
            f"set and nothing applies."
        )

    rates = _rate_limits(path, document)
    tables = document.get("budgets")
    if not isinstance(tables, dict):
        raise BudgetError(
            f"{path} has no [budgets] table. Every agent run is bounded on four "
            f"dimensions (`concept/07`) and the values are this file's, so a "
            f"file that omits them is a run with no budget at all."
        )
    missing = sorted(set(taxonomy.EMITTERS) - set(tables))
    if missing:
        raise BudgetError(
            f"{path} configures no budget for {missing}. Every agent is bounded, "
            f"and an agent the file is silent about is the one that runs unbounded."
        )
    unknown = sorted(set(tables) - set(taxonomy.EMITTERS))
    if unknown:
        raise BudgetError(
            f"{path} configures budgets for {unknown}, which are not agents "
            f"({sorted(taxonomy.EMITTERS)}). A budget for an emitter that does "
            f"not exist is a number nothing enforces."
        )

    by_emitter: dict[str, contract.Budgets] = {}
    retrieval: dict[str, float] = {}
    for emitter in sorted(taxonomy.EMITTERS):
        table = tables[emitter]
        if not isinstance(table, dict):
            raise BudgetError(
                f"{path}: [budgets.{emitter}] is {type(table).__name__}, and a "
                f"budget is a table of dimension -> value"
            )
        tools_permitted = emitter != taxonomy.TRIAGE
        expected = _TOOL_STATED if tools_permitted else _STATED
        wrong = sorted(set(table) - expected)
        if wrong:
            raise BudgetError(
                f"{path}: [budgets.{emitter}] sets {wrong}. It states "
                f"{sorted(expected)}"
                + (
                    ""
                    if tools_permitted
                    else " — `concept/04` gives triage no tools at all, so a "
                    "configurable step or live-query budget for it would be a "
                    "lookup nobody has to justify"
                )
                + f", and {LIVE_QUERIES!r} is never written down: it is derived "
                f"from the retrieval allowance and the slowest rate limit."
            )
        absent = sorted(expected - set(table))
        if absent:
            raise BudgetError(
                f"{path}: [budgets.{emitter}] sets no {absent}. There is no "
                f"default for a budget dimension — a defaulted one is invisible "
                f"in exactly the deployment where it mattered."
            )
        tokens = _positive_int(path, emitter, TOKENS, table[TOKENS])
        wall_clock = _positive_number(path, emitter, WALL_CLOCK, table[WALL_CLOCK])
        if not tools_permitted:
            by_emitter[emitter] = contract.Budgets(
                steps=0, tokens=tokens, wall_clock_seconds=wall_clock, live_queries=0
            )
            continue

        steps = _positive_int(path, emitter, STEPS, table[STEPS])
        allowance = _positive_number(
            path, emitter, "retrieval_seconds", table["retrieval_seconds"]
        )
        if allowance >= wall_clock:
            raise BudgetError(
                f"{path}: [budgets.{emitter}] may spend {allowance}s of a "
                f"{wall_clock}s wall clock waiting on providers, which leaves no "
                f"time to reason with what came back. `concept/07` sets the two "
                f"against each other; this sets one over the other."
            )
        if not rates:
            raise BudgetError(
                f"{path} has no [rate_limits] entry, and [budgets.{emitter}] has "
                f"tools. The live-query budget is derived from the slowest "
                f"configured rate (`concept/07`), so there is nothing to derive "
                f"it from and no number to enforce."
            )
        slowest = min(rates.values())
        live_queries = int(allowance * slowest // _SECONDS_IN_A_MINUTE)
        if live_queries < 1:
            raise BudgetError(
                f"{path}: {allowance}s of retrieval at {slowest} queries per "
                f"minute buys {live_queries} live queries, so the emitter with "
                f"tools could never reach one. Raise the allowance or the rate, "
                f"or say the agent has no tools."
            )
        if steps < live_queries:
            raise BudgetError(
                f"{path}: [budgets.{emitter}] allows {steps} steps and the "
                f"derived live-query budget is {live_queries}. Every live query "
                f"is a step, so the step budget would bind first and the "
                f"live-query budget would be a number that never applies."
            )
        by_emitter[emitter] = contract.Budgets(
            steps=steps,
            tokens=tokens,
            wall_clock_seconds=wall_clock,
            live_queries=live_queries,
        )
        retrieval[emitter] = allowance

    return BudgetPolicy(
        by_emitter=by_emitter, rate_limits=rates, retrieval_seconds=retrieval
    )


def _rate_limits(path: Path, document: dict[str, object]) -> dict[str, int]:
    """The rate the tool layer holds itself to, per source. Registered sources only.

    `concept/05`: "rate limits are **policy the tool layer enforces**, not an
    afterthought". The coverage rule is the opposite of `[thresholds]`': every
    entry must name a registered source, and a registered source needs one only if
    something queries it live — a feed loader has a fetch interval on its
    descriptor instead, and a rate limit for it would be a key nothing reads.
    """
    # Imported here, not at module scope, because this is the only thing in the
    # module that needs the source registry and `helena.enrichment` pulls the
    # whole evidence layer in with it.
    from helena.enrichment import SOURCES

    table = document.get("rate_limits", {})
    if not isinstance(table, dict):
        raise BudgetError(
            f"{path}: [rate_limits] is {type(table).__name__}, and it is a table "
            f"of source id -> queries per minute"
        )
    rates: dict[str, int] = {}
    for source_id, value in table.items():
        if source_id not in SOURCES:
            raise BudgetError(
                f"{path} sets a rate limit for {source_id!r}, which is not a "
                f"registered source ({sorted(SOURCES)}). Adding a source is a "
                f"governed decision (`concept/05`), not a line in this file."
            )
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise BudgetError(
                f"{path}: rate_limits.{source_id} is {value!r}; it is a positive "
                f"whole number of queries per minute, and a zero or negative one "
                f"is a source nothing may ever ask"
            )
        rates[source_id] = value
    return rates


def _positive_int(path: Path, emitter: str, name: str, value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise BudgetError(
            f"{path}: budgets.{emitter}.{name} is {value!r}; it is a positive "
            f"whole number, and a run given none of a dimension can only ever "
            f"produce a failure"
        )
    return value


def _positive_number(path: Path, emitter: str, name: str, value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        raise BudgetError(
            f"{path}: budgets.{emitter}.{name} is {value!r}; it is a positive "
            f"number of seconds, and a run given none of a dimension can only "
            f"ever produce a failure"
        )
    return float(value)
