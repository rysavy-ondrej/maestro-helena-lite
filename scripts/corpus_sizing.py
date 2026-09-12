#!/usr/bin/env python3
"""Size an evaluation corpus against the provider quota, before the corpus is chosen.

    uv run scripts/corpus_sizing.py --daily-quota self-imposed
    uv run scripts/corpus_sizing.py --daily-quota 500
    uv run scripts/corpus_sizing.py --daily-quota self-imposed --snapshot data/threatfox
    make corpus-sizing

`concept/08-open-questions.md` states the constraint this instrument exists for:
*"the live provider's daily quota must be sized against the corpus **before the
corpus is chosen**, or the comparison's arms stop being contemporaneous."* So the
arithmetic is here, run against `config/policy.toml` rather than written into a
document, and `docs/evaluation-corpus.md` cites what it prints.

Three reports, and none of them scores anything:

1. **The live-query envelope.** What a corpus of N contexts would spend against a
   daily quota at a given escalation rate, and how long the provider's own rate
   limit makes that take. The per-run ceiling is read from
   `helena.budgets.load()` — it is *derived* there from the retrieval seconds and
   the slowest rate limit, and re-deriving it here would be the second copy of a
   number that `concept/instruction.md` §2 forbids.
2. **The corpus size the base rate demands.** How many labelled positives a
   confidence interval of a given width needs, and how many contexts that is at a
   base rate. The base rate is **unmeasured** — see `docs/evaluation-corpus.md` §6
   — so it is swept rather than assumed.
3. **A feed snapshot's coverage window**, when `--snapshot` is given: the span of
   activity the export actually carries, which is the range of event times a
   corpus enriched with it could be time-correct over.

**There is no default daily quota.** abuse.ch publishes fair-use terms and no
number, and inventing one would put a fabricated figure in the one calculation
that exists to stop an evaluation overrunning a provider. `--daily-quota
self-imposed` uses the sustained ceiling derived from `[rate_limits]` in
`config/policy.toml`, which is this project's own ceiling and not the provider's.

**This is not the evaluation harness**, which `concept/01-goal-and-scope.md`
lists as deferred and which stays deferred: nothing here reads a label, scores a
verdict or runs the pipeline. It computes what an evaluation would cost.

Exit status is 0 when every report was produced, 1 when an input was refused.

Maturity: experimental — an instrument, not part of the pipeline. The per-run
ceiling and the rate limit come from `helena.budgets`, so it sizes against the
budget the prototype actually enforces rather than a copy of it.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path

from helena import budgets, taxonomy
from helena.budgets import BudgetError, BudgetPolicy

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SNAPSHOT = PROJECT_ROOT / "data" / "threatfox"

#: Minutes in a day. The rate limit is per minute and the quota is per day, so
#: this is the only unit conversion between them.
MINUTES_PER_DAY = 24 * 60

#: The contexts one measured day of one network produced — 143 captures,
#: 239 850 records, 3 199 source addresses, 23.97 hours, 12 089 contexts over
#: 287 five-minute windows (`demo/README.md`, `demo/context_over_a_day.py`). It
#: is the only multi-host number this repository has measured, so it is the
#: anchor the envelope is reported against and not a target corpus size.
MEASURED_DAY_CONTEXTS = 12089

#: The escalation rates the report sweeps. **Not measurements** — nothing has run
#: against labelled outcomes, so the fraction of contexts triage sends to the
#: analyst is unknown and the report shows what each would cost rather than
#: picking one.
DEFAULT_ESCALATION_RATES = (0.01, 0.05, 0.10, 1.00)

#: The base rates the corpus-size report sweeps, for the same reason.
DEFAULT_BASE_RATES = (0.001, 0.01, 0.10)

#: The two-sided normal deviate for a 95 % interval.
Z_95 = 1.96


class SizingError(ValueError):
    """An input the arithmetic refuses, naming which one and why."""


@dataclass(frozen=True)
class Envelope:
    """What one corpus would spend, against one daily quota."""

    contexts: int
    escalation_rate: float
    #: Contexts the router would send to the analyst, rounded up: a fraction of a
    #: run is a run.
    analyst_runs: int
    #: The upper bound. Every analyst run spending its whole live-query budget.
    live_queries: int
    #: True when `live_queries` is the distinct-indicator count rather than
    #: `analyst_runs x per_run` — the cache is what makes the two differ.
    capped_by_distinct: bool
    #: Minutes of pure waiting, at the rate the tool layer holds itself to.
    retrieval_minutes: float
    #: The quota this many queries consumes, in days of it.
    days_of_quota: float

    @property
    def fits_in_a_day(self) -> bool:
        return self.days_of_quota <= 1.0


@dataclass(frozen=True)
class SnapshotWindow:
    """The span of activity a feed export carries, read off the export."""

    entries: int
    #: The oldest and newest *last activity* in the export — for an entry with no
    #: `last_seen_utc`, its `first_seen_utc`.
    earliest_activity: date
    latest_activity: date
    #: Entries whose `first_seen_utc` is older than the activity window, i.e. long
    #: -lived indicators the export carries because they were seen again.
    first_seen_before_window: int

    @property
    def span_days(self) -> int:
        return (self.latest_activity - self.earliest_activity).days


def per_run_live_queries(policy: BudgetPolicy) -> int:
    """The analyst's live-query ceiling, as `helena.budgets` derived it.

    Read rather than recomputed. `load()` derives it from the retrieval seconds
    and the slowest configured rate limit and refuses a pair that contradicts
    itself; a second derivation here would be a copy that can drift from the one
    the tool layer actually enforces.
    """
    return policy.for_emitter(taxonomy.ANALYST).live_queries


def queries_a_minute(policy: BudgetPolicy, source: str) -> int:
    """The rate the tool layer holds itself to for a source, or a refusal.

    Never a default. A source queried live at a rate nobody chose is the silent
    configuration default `concept/instruction.md` §6 lists by name, and it would
    be invisible in exactly the evaluation where it mattered.
    """
    try:
        return policy.rate_limits[source]
    except KeyError:
        raise SizingError(
            f"no rate limit is configured for {source!r}; "
            f"{sorted(policy.rate_limits)} are. A source nothing queries live has "
            f"none — see config/policy.toml's [rate_limits]."
        ) from None


def sustained_daily_ceiling(policy: BudgetPolicy, source: str) -> int:
    """Queries a day at the rate the tool layer holds itself to, run flat out.

    **Not a provider quota.** `config/policy.toml` says what `[rate_limits]` is:
    a self-imposed ceiling under fair-use terms that publish no number. Running
    flat out for 24 hours against a fair-use service is not a thing to do; this
    is the ceiling that rate places on an evaluation, which is a different claim.
    """
    return queries_a_minute(policy, source) * MINUTES_PER_DAY


def envelope(
    *,
    contexts: int,
    escalation_rate: float,
    per_run: int,
    daily_quota: int,
    queries_per_minute: int,
    distinct_indicators: int | None = None,
) -> Envelope:
    """What a corpus of `contexts` would spend, and how long the rate makes it take.

    `distinct_indicators` is the other bound and it is the one the lookup cache
    creates: a hit costs no quota and a negative result is cached
    (`docs/decisions/0025-the-lookup-cache.md` §3), so an evaluation cannot spend
    more live queries than the corpus has distinct indicators, however many runs
    ask about them. It is optional because the count is unmeasured.
    """
    if contexts <= 0:
        raise SizingError(f"contexts is {contexts}; a corpus of none sizes nothing")
    if not 0.0 < escalation_rate <= 1.0:
        raise SizingError(
            f"escalation_rate is {escalation_rate}; it is a fraction of the "
            f"contexts in (0, 1]"
        )
    if per_run <= 0:
        raise SizingError(
            f"per_run is {per_run}; an analyst run that may make no live query "
            f"spends no quota and sizes nothing"
        )
    if daily_quota <= 0:
        raise SizingError(
            f"daily_quota is {daily_quota}; the quota is the provider's published "
            f"number or the ceiling `[rate_limits]` implies, never zero and never "
            f"a default"
        )
    if queries_per_minute <= 0:
        raise SizingError(f"queries_per_minute is {queries_per_minute}; it is a rate")
    if distinct_indicators is not None and distinct_indicators <= 0:
        raise SizingError(
            f"distinct_indicators is {distinct_indicators}; a corpus with no "
            f"indicator in it has nothing to look up"
        )

    analyst_runs = math.ceil(contexts * escalation_rate)
    live_queries = analyst_runs * per_run
    capped = distinct_indicators is not None and distinct_indicators < live_queries
    if capped:
        assert distinct_indicators is not None  # narrowed by `capped`
        live_queries = distinct_indicators
    return Envelope(
        contexts=contexts,
        escalation_rate=escalation_rate,
        analyst_runs=analyst_runs,
        live_queries=live_queries,
        capped_by_distinct=capped,
        retrieval_minutes=live_queries / queries_per_minute,
        days_of_quota=live_queries / daily_quota,
    )


def max_analyst_runs_a_day(*, daily_quota: int, per_run: int) -> int:
    """The ceiling the quota places on an evaluation: analyst runs a day."""
    if daily_quota <= 0 or per_run <= 0:
        raise SizingError(
            f"daily_quota={daily_quota} per_run={per_run}; both are positive counts"
        )
    return daily_quota // per_run


def max_contexts_a_day(*, daily_quota: int, per_run: int, escalation_rate: float) -> int:
    """... and the contexts that is, at an escalation rate."""
    if not 0.0 < escalation_rate <= 1.0:
        raise SizingError(
            f"escalation_rate is {escalation_rate}; it is a fraction in (0, 1]"
        )
    return int(max_analyst_runs_a_day(daily_quota=daily_quota, per_run=per_run) / escalation_rate)


def positives_for_interval(*, proportion: float, half_width: float, z: float = Z_95) -> int:
    """Labelled positives needed for an interval of that half-width on a rate.

    The normal approximation, `n = z^2 p (1 - p) / h^2`. It is the crude one on
    purpose: what it is here to show is the order of magnitude — that tens of
    positives measure nothing about recall — and a better interval would not
    change that.
    """
    if not 0.0 < proportion < 1.0:
        raise SizingError(f"proportion is {proportion}; it is a rate in (0, 1)")
    if not 0.0 < half_width < 1.0:
        raise SizingError(f"half_width is {half_width}; it is a width in (0, 1)")
    return math.ceil(z * z * proportion * (1.0 - proportion) / (half_width * half_width))


def contexts_for_positives(*, positives: int, base_rate: float) -> int:
    """The contexts a corpus needs to hold that many positives, at a base rate."""
    if positives <= 0:
        raise SizingError(f"positives is {positives}; it is a count")
    if not 0.0 < base_rate <= 1.0:
        raise SizingError(f"base_rate is {base_rate}; it is a fraction in (0, 1]")
    return math.ceil(positives / base_rate)


def _activity(record: dict[str, object]) -> date:
    """The most recent date an export record reports, first or last seen."""
    stamps = [str(record["first_seen_utc"])]
    last = record.get("last_seen_utc")
    if last:
        stamps.append(str(last))
    return max(datetime.fromisoformat(stamp).date() for stamp in stamps)


def _export_records(export: Path, payload: object) -> list[list[dict[str, object]]]:
    """The record lists of one export, or a refusal naming the file.

    A bulk export is an object keyed by IOC id whose values are lists. An API
    response is not, and a reader that accepted both would report a window over
    whatever it managed to parse — `concept/instruction.md` §6's "catching an
    exception and continuing", one layer up.
    """
    if not isinstance(payload, dict) or not payload:
        raise SizingError(f"{export} is not a bulk export: its top level is not an object")
    lists = []
    for key, records in payload.items():
        if not isinstance(records, list) or not all(
            isinstance(record, dict) and "first_seen_utc" in record for record in records
        ):
            raise SizingError(
                f"{export} is not a bulk export: {key!r} does not hold a list of "
                f"records with a first_seen_utc. An API response is a different "
                f"shape and carries a different window."
            )
        lists.append(records)
    return lists


def snapshot_window(directory: Path) -> SnapshotWindow:
    """The activity span of every export in a directory, flattened.

    The export's top level is an object keyed by IOC id whose values are *lists*;
    this flattens them and never reads `[0]` (`concept/instruction.md` §6).
    """
    exports = sorted(directory.glob("*.json"))
    if not exports:
        raise SizingError(
            f"{directory} holds no *.json export. The snapshots are gitignored "
            f"(`prds/CONTEXT.md` §3), so an absent directory is a missing "
            f"artifact rather than an empty feed."
        )
    activity: list[date] = []
    first_seen: list[date] = []
    for export in exports:
        payload = json.loads(export.read_text())
        for records in _export_records(export, payload):
            for record in records:
                activity.append(_activity(record))
                first_seen.append(
                    datetime.fromisoformat(str(record["first_seen_utc"])).date()
                )
    if not activity:
        raise SizingError(f"{directory} holds exports with no records in them")
    earliest = min(activity)
    return SnapshotWindow(
        entries=len(activity),
        earliest_activity=earliest,
        latest_activity=max(activity),
        first_seen_before_window=sum(1 for seen in first_seen if seen < earliest),
    )


def _quota(argument: str, policy: BudgetPolicy, source: str) -> tuple[int, str]:
    """The daily quota to size against, and what it is."""
    if argument == "self-imposed":
        ceiling = sustained_daily_ceiling(policy, source)
        return ceiling, (
            f"{ceiling}/day — this project's own [rate_limits] ceiling for "
            f"{source}, run flat out for 24 h. Not a provider quota: abuse.ch "
            f"publishes fair-use terms and no number."
        )
    try:
        stated = int(argument)
    except ValueError:
        raise SizingError(
            f"--daily-quota {argument!r} is neither an integer nor 'self-imposed'"
        ) from None
    return stated, f"{stated}/day — stated on the command line."


def _report_envelope(
    policy: BudgetPolicy,
    *,
    contexts: int,
    rates: tuple[float, ...],
    daily_quota: int,
    quota_says: str,
    source: str,
    distinct: int | None,
) -> None:
    per_run = per_run_live_queries(policy)
    per_minute = queries_a_minute(policy, source)
    print("1. The live-query envelope")
    print(f"   per analyst run      {per_run} live queries (derived, config/policy.toml)")
    print(f"   rate the tools keep  {per_minute}/minute for {source}")
    print(f"   daily quota          {quota_says}")
    print(f"   corpus               {contexts} contexts")
    if distinct is not None:
        print(f"   distinct indicators  {distinct}")
    print()
    print("   escalation   analyst runs   live queries   retrieval   days of quota")
    for rate in rates:
        line = envelope(
            contexts=contexts,
            escalation_rate=rate,
            per_run=per_run,
            daily_quota=daily_quota,
            queries_per_minute=per_minute,
            distinct_indicators=distinct,
        )
        marker = " (capped by distinct)" if line.capped_by_distinct else ""
        print(
            f"   {rate:>9.0%}   {line.analyst_runs:>12}   {line.live_queries:>12}   "
            f"{line.retrieval_minutes / 60:>7.1f} h   {line.days_of_quota:>13.2f}{marker}"
        )
    print()
    print(
        f"   ceiling: {max_analyst_runs_a_day(daily_quota=daily_quota, per_run=per_run)} "
        f"analyst runs a day, which is"
    )
    for rate in rates:
        print(
            f"            {max_contexts_a_day(daily_quota=daily_quota, per_run=per_run, escalation_rate=rate):>9} "
            f"contexts a day at {rate:.0%} escalation"
        )
    print()


def _report_corpus_size(
    *, recall: float, half_width: float, base_rates: tuple[float, ...]
) -> None:
    positives = positives_for_interval(proportion=recall, half_width=half_width)
    print("2. The corpus size the base rate demands")
    print(
        f"   {positives} labelled positives for a 95 % interval of "
        f"+/-{half_width:.0%} on a rate of {recall:.0%}"
    )
    print("   base rate    contexts needed   measured network days of them")
    for base_rate in base_rates:
        needed = contexts_for_positives(positives=positives, base_rate=base_rate)
        print(
            f"   {base_rate:>9.1%}   {needed:>15}   {needed / MEASURED_DAY_CONTEXTS:>29.1f}"
        )
    print("   the base rate is unmeasured — docs/evaluation-corpus.md section 6")
    print()


def _report_snapshot(directory: Path) -> None:
    window = snapshot_window(directory)
    print("3. The feed snapshot's coverage window")
    print(f"   {directory}: {window.entries} entries")
    print(
        f"   last activity between {window.earliest_activity} and "
        f"{window.latest_activity} — a {window.span_days}-day span"
    )
    print(
        f"   {window.first_seen_before_window} of them were first seen before that "
        f"window and are in the export because they were seen again"
    )
    print(
        "   a corpus this snapshot can enrich time-correctly is one captured "
        "inside that span"
    )
    print()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--daily-quota",
        required=True,
        help=(
            "the provider's published daily query quota, or 'self-imposed' for "
            "the ceiling config/policy.toml's [rate_limits] implies. There is no "
            "default: abuse.ch publishes fair-use terms and no number"
        ),
    )
    parser.add_argument(
        "--source",
        default="threatfox",
        help="the source whose rate limit paces the evaluation (default: threatfox)",
    )
    parser.add_argument(
        "--contexts",
        type=int,
        default=MEASURED_DAY_CONTEXTS,
        help=(
            f"contexts in the corpus (default: {MEASURED_DAY_CONTEXTS}, what one "
            f"measured day of one network produced — demo/README.md)"
        ),
    )
    parser.add_argument(
        "--escalation-rate",
        type=float,
        action="append",
        dest="escalation_rates",
        help="a rate to report, repeatable (default: 1 %%, 5 %%, 10 %%, 100 %%)",
    )
    parser.add_argument(
        "--distinct-indicators",
        type=int,
        default=None,
        help="distinct indicators in the corpus, if known — the cache's own bound",
    )
    parser.add_argument(
        "--recall",
        type=float,
        default=0.80,
        help="the rate the interval in report 2 is around (default: 0.80)",
    )
    parser.add_argument(
        "--half-width",
        type=float,
        default=0.10,
        help="the interval half-width report 2 sizes for (default: 0.10)",
    )
    parser.add_argument(
        "--snapshot",
        type=Path,
        nargs="?",
        const=DEFAULT_SNAPSHOT,
        default=None,
        help=f"also report a feed export's coverage window (default: {DEFAULT_SNAPSHOT})",
    )
    arguments = parser.parse_args(argv)

    try:
        policy = budgets.load()
        daily_quota, quota_says = _quota(arguments.daily_quota, policy, arguments.source)
        rates = tuple(arguments.escalation_rates or DEFAULT_ESCALATION_RATES)
        _report_envelope(
            policy,
            contexts=arguments.contexts,
            rates=rates,
            daily_quota=daily_quota,
            quota_says=quota_says,
            source=arguments.source,
            distinct=arguments.distinct_indicators,
        )
        _report_corpus_size(
            recall=arguments.recall,
            half_width=arguments.half_width,
            base_rates=DEFAULT_BASE_RATES,
        )
        if arguments.snapshot is not None:
            _report_snapshot(arguments.snapshot)
    except (SizingError, BudgetError) as error:
        print(f"FAILED: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
