"""Status — the pipeline's own numbers, read out of the engine as plain SQL.

`concept/07-principles.md`, "Observability", is two statements and this module is
the second one.

The first is about what is *not* here: **local structured logs only, no hosted
tracing**, because a hosted tracer is a second egress channel carrying prompts,
rendered context and retrieved provider text. `helena.observability` is the
channel that exists instead and `tests/test_dependency_boundary.py` keeps the
tracing SDKs out by test.

The second is what takes its place:

    *"**The audit record is the stored assessment**, not a trace UI. It already
    carries the retrieval trace, the disclosure record, cost, latency and
    versions as first-class typed columns — queryable in a way a trace UI is
    not."*

    *"**What must be observable:** latency, cost, staleness, error, escalation
    and model-quality metrics; end-to-end provenance; record counts reconciled
    between produced and materialised; the retention boundary's rejection rate;
    and emission counted from the engine side."*

So there is no metrics store, no exporter, no scrape endpoint and no dashboard.
There are seven views in `sql/migrations/0021_pipeline_observability.sql`, two
counters earlier increments already built, and this module — which reads them,
checks each row against itself, and refuses the divisions that would lie. Every
number `helena status` prints can be got with `psql` by somebody running none of
this code, which is the property the note chose over a trace UI.

## Where each number comes from

| Question | Relation | Read by |
| --- | --- | --- |
| latency, cost, tokens, retries, cache state per model | `helena_analytical_run_metrics` | `StatusStore.runs` |
| which typed failures, how many, how recent | `helena_analytical_failure_counts` | `StatusStore.failures` |
| escalation rate, and which trigger caused it | `helena_analytical_escalation_counts` | `StatusStore.escalation` |
| cache hit against live query per source, and typed retrieval failures | `helena_analytical_retrieval_metrics` | `StatusStore.retrievals` |
| how old each feed's snapshot is against its own schedule | `helena_reference_feed_staleness` | `StatusStore.feeds` |
| normalized against quarantined, per capture | `helena_ingest_ledger` | `StatusStore.ingest` |
| contexts, assessments and messages per deployment | `helena_analytical_pipeline_reconciliation` | `StatusStore.pipeline` |
| what the retention boundary is dropping | `helena_signal_retention_rejections` (0009) | `helena.context.ContextStore.rejections` |
| how many messages there are to emit | `helena_analytical_emission_counts` (0020) | `helena.sink.SinkStore.pending` |

The last two are **not rebuilt here**. They were built by the increments that
needed them, they are the right shape, and a second copy of a counter is a second
number to disagree with the first. `report()` reads them through the modules that
own them.

## No rate is stored, and a rate over nothing raises

Every view exposes a numerator and a denominator and stops; every rate in this
module is a property that raises when its denominator is zero.
`helena.context.RetentionRejections.rate` set the rule and said why: `0.0` would
read as *"the boundary dropped nothing"* when the truth is *"nothing was
aggregated"*, and those are two different facts — the same reason `stale`,
`failed`, `missing` and `no_match` are never the same value anywhere in this
project (`concept/instruction.md` §2). `helena.normalizer.QuarantineCounts.rate`
made the same call before it.

The models refuse more than that. A row whose parts do not add up to its own
total is a counter that has stopped meaning anything, so `verdicts +
typed_failures = runs`, `cache_hits + live_queries = steps` and `answered +
failures = steps` are checked on construction rather than assumed — and a cost
summed across two currencies is refused rather than printed, because a number
that is twelve of one and five of another is not a cost.

## The reconciliation spans three layers, so it is not one view

`concept/instruction.md` §2: *"View layering holds: flatten → signal →
analytical. An analytical view never reads the flatten layer or the source
directly."* The five terms `concept/07` asks to be reconciled are in three
different layers and one of them is not in the engine at all:

    capture record count   the retained FILE — `helena.normalizer.Capture`
    normalized rows        source layer
    quarantined rows       source layer
    context rows           signal layer
    emitted rows           analytical layer

One view over all five would read the source from the analytical layer, which is
the invariant. So the source half is `helena_ingest_ledger`, the rest is
`helena_analytical_pipeline_reconciliation`, and `PipelineReconciliation` below
is the one object that holds all five and checks them against each other. This is
the same shape `helena.normalizer.IngestCounts` already has for the ingest half,
and for the same reason it gives: *the four numbers deliberately come from four
different places, and that is what makes the check worth running.*

**The capture count is optional and its absence is said, never defaulted.**
`helena status` takes a `--captures` directory; without one, `capture_records` is
`None` and `unaccounted` raises instead of returning a number. A reconciliation
that used `0` for "nobody told me where the captures are" would report a
deployment that had lost every record it ever ingested.

Reads: the engine, through a `psycopg` connection the caller owns. Writes:
nothing — not a row, not a file. This module is a reader.

Maturity: experimental — every view it reads is exercised by execution against
the pinned engine in `tests/test_status.py`, over assessments written by the real
writer and a capture ingested through the real path. No deployment has been
watched with it, so nothing here is claimed to be the right *set* of numbers;
what is demonstrated is that each one is derivable from the store in plain SQL.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta

import psycopg
from pydantic import BaseModel, ConfigDict, NonNegativeInt, model_validator

from helena.config import IngestionIdentity
from helena.context import ContextStore, RetentionRejections
from helena.enrichment import MISSING, OK, STALE
from helena.normalizer import Capture
from helena.sink import SinkStore

__all__ = [
    "ESCALATION_COUNTS_VIEW",
    "FAILURE_COUNTS_VIEW",
    "FEED_STALENESS_VIEW",
    "FEED_STATUSES",
    "INGEST_LEDGER_VIEW",
    "PIPELINE_RECONCILIATION_VIEW",
    "RETRIEVAL_METRICS_VIEW",
    "RUN_METRICS_VIEW",
    "EscalationCounts",
    "FailureCounts",
    "FeedStaleness",
    "IngestLedger",
    "PipelineReconciliation",
    "RetrievalMetrics",
    "RunMetrics",
    "Status",
    "StatusStore",
    "render",
    "report",
]

# The seven relations sql/migrations/0021 adds. The two this module also reads --
# helena_signal_retention_rejections and helena_analytical_emission_counts -- are
# named by the modules that own them (`helena.context`, `helena.sink`) and are
# deliberately not re-declared here.
INGEST_LEDGER_VIEW = "helena_ingest_ledger"
FEED_STALENESS_VIEW = "helena_reference_feed_staleness"
RUN_METRICS_VIEW = "helena_analytical_run_metrics"
FAILURE_COUNTS_VIEW = "helena_analytical_failure_counts"
ESCALATION_COUNTS_VIEW = "helena_analytical_escalation_counts"
RETRIEVAL_METRICS_VIEW = "helena_analytical_retrieval_metrics"
PIPELINE_RECONCILIATION_VIEW = "helena_analytical_pipeline_reconciliation"

#: What `helena_reference_feed_staleness.status` may say, and the three
#: `helena.enrichment.feed_status` says. Imported rather than spelled again: a
#: fourth name for `missing` is the drift the vocabulary rules exist to stop.
FEED_STATUSES = (OK, STALE, MISSING)

# Every read is `SELECT <these columns> FROM <that view>`, and the row is zipped
# onto the names positionally, so these tuples are a second copy of each view's
# shape. `tests/test_status.py::test_every_view_is_the_column_list_this_module_
# holds` asserts each equal to what the engine holds, in order -- the same
# arrangement `helena.sink.SINK_COLUMNS` and
# `helena.orchestration.ASSESSMENT_COLUMNS` have.
INGEST_LEDGER_COLUMNS = (
    "tenant",
    "sensor",
    "capture_sha256",
    "normalized",
    "quarantined",
    "admitted",
)
FEED_STALENESS_COLUMNS = (
    "tenant",
    "sensor",
    "source_id",
    "attempts",
    "last_attempt_at",
    "last_failure_at",
    "snapshot_version",
    "snapshot_at",
    "refresh_interval_seconds",
    "age_seconds",
    "status",
)
RUN_METRICS_COLUMNS = (
    "tenant",
    "sensor",
    "emitter",
    "model_requested",
    "model_version",
    "runs",
    "verdicts",
    "typed_failures",
    "runs_with_retries",
    "retries",
    "prompt_tokens",
    "completion_tokens",
    "cache_hits",
    "live_queries",
    "latency_seconds_min",
    "latency_seconds_max",
    "latency_seconds_total",
    "runs_priced",
    "runs_unpriced",
    "model_cost_total",
    "currencies",
    "model_cost_currency",
    "model_prices_version",
    "most_recent",
)
FAILURE_COUNTS_COLUMNS = (
    "tenant",
    "sensor",
    "emitter",
    "failure_reason",
    "failures",
    "most_recent",
)
ESCALATION_COUNTS_COLUMNS = (
    "tenant",
    "sensor",
    "triaged",
    "escalated",
    "by_triage_suspicious",
    "by_deterministic_signal",
)
RETRIEVAL_METRICS_COLUMNS = (
    "tenant",
    "sensor",
    "emitter",
    "source_id",
    "steps",
    "cache_hits",
    "live_queries",
    "answered",
    "failures",
    "oldest_retrieved_at",
    "newest_retrieved_at",
)
PIPELINE_RECONCILIATION_COLUMNS = (
    "tenant",
    "sensor",
    "contexts",
    "context_records",
    "assessments",
    "assessed_contexts",
    "emittable",
)


class Measured(BaseModel):
    """Shared configuration for every counter in this module.

    The three `helena.normalizer.Observed` takes, for the reasons it gives:
    unknown fields refused rather than coerced, no type coerced either, and a row
    that cannot be edited after it was read. A counter that could be edited after
    it was read is a counter whose number is not the store's.
    """

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class IngestLedger(Measured):
    """One capture's produced-against-materialized, asked of the store.

    `admitted` is on the row rather than derived here because it is the engine's
    own sum: a total that disagreed with its parts would be a view that has
    stopped adding up, and that is worth catching rather than hiding behind a
    Python `+`.
    """

    tenant: str
    sensor: str
    capture_sha256: str
    normalized: NonNegativeInt
    quarantined: NonNegativeInt
    admitted: NonNegativeInt

    @model_validator(mode="after")
    def _reconciles(self) -> IngestLedger:
        if self.normalized + self.quarantined != self.admitted:
            raise ValueError(
                f"{self.normalized} normalized + {self.quarantined} quarantined "
                f"is not the {self.admitted} the ledger reports admitted for "
                f"capture {self.capture_sha256}; the counter does not reconcile"
            )
        return self

    @property
    def quarantine_rate(self) -> float:
        """Refused records over records ingestion accounted for.

        No admitted records means no rate, for the reason
        `helena.normalizer.QuarantineCounts.rate` gives: `0.0` would read as
        "nothing was refused" when the truth is "nothing was ingested".
        """
        if self.admitted == 0:
            raise ValueError(
                f"capture {self.capture_sha256} has no admitted records, so "
                f"there is no quarantine rate; 0.0 would read as 'nothing was "
                f"refused'"
            )
        return self.quarantined / self.admitted


class FeedStaleness(Measured):
    """One source's snapshot age against its own schedule, as of this read.

    `status` is the engine's, not this module's: the view corrects the null
    interval the way `helena.enrichment.feed_status` corrects it in Python, so
    plain SQL and this module give an operator the same answer.

    `missing`, `stale` and `ok` stay three things. `missing` is *no snapshot at
    all*, and it is exactly the rows where `snapshot_at` is null — checked here,
    because a `stale` on a source that never loaded would be a claim about the
    age of something that does not exist.
    """

    tenant: str
    sensor: str
    source_id: str
    attempts: NonNegativeInt
    last_attempt_at: datetime
    last_failure_at: datetime | None
    snapshot_version: str | None
    snapshot_at: datetime | None
    refresh_interval_seconds: int | None
    age_seconds: float | None
    status: str

    @model_validator(mode="after")
    def _says_one_of_the_three(self) -> FeedStaleness:
        if self.status not in FEED_STATUSES:
            raise ValueError(
                f"{FEED_STALENESS_VIEW} reports status {self.status!r} for "
                f"{self.source_id}; the three a reader can be in are "
                f"{', '.join(FEED_STATUSES)}"
            )
        if (self.status == MISSING) != (self.snapshot_at is None):
            raise ValueError(
                f"{self.source_id} is reported {self.status!r} with "
                f"snapshot_at={self.snapshot_at!r}; `missing` is no snapshot at "
                f"all and nothing else is"
            )
        if (self.snapshot_at is None) != (self.age_seconds is None):
            raise ValueError(
                f"{self.source_id} has snapshot_at={self.snapshot_at!r} and "
                f"age_seconds={self.age_seconds!r}; a snapshot has an age and "
                f"an absent one has none"
            )
        return self

    @property
    def age(self) -> timedelta:
        """How old the current snapshot is. Raises when there is none."""
        if self.age_seconds is None:
            raise ValueError(
                f"{self.source_id} has no snapshot, so it has no age — it is "
                f"{MISSING}, which is not the same thing as old"
            )
        return timedelta(seconds=self.age_seconds)

    @property
    def intervals_behind(self) -> float:
        """Snapshot age in units of the feed's own refresh interval.

        The number `stale` cannot give: one minute past an hourly schedule and
        three weeks past it are both `stale`, and only one of them is a feed
        nobody is loading.

        A source with no schedule has no ratio and this raises, rather than
        dividing by a null. `helena.enrichment.feed_status` says why such a
        source is `ok` and not `stale`: the SSLBL JA3 list has been static since
        2021, so it is not late, it is finished.
        """
        if self.refresh_interval_seconds is None:
            raise ValueError(
                f"{self.source_id} declares no refresh interval, so there is "
                f"nothing for it to be behind; it is not late, and a ratio here "
                f"would invent a schedule it does not have"
            )
        if self.refresh_interval_seconds == 0:
            raise ValueError(
                f"{self.source_id} declares a refresh interval of 0 seconds, "
                f"which is not a schedule"
            )
        return self.age.total_seconds() / self.refresh_interval_seconds


class RunMetrics(Measured):
    """Latency, cost, tokens, retries and cache state for one model's runs.

    The grain is (tenant, sensor, emitter, model asked for, model that answered),
    because what this deployment asked for is not what answered and a
    substitution on the provider's side is one of the things these numbers exist
    to make visible. `model_version` is null exactly on a `model_unavailable`
    failure, where nothing answered at all.
    """

    tenant: str
    sensor: str
    emitter: str
    model_requested: str
    model_version: str | None
    runs: NonNegativeInt
    verdicts: NonNegativeInt
    typed_failures: NonNegativeInt
    runs_with_retries: NonNegativeInt
    retries: NonNegativeInt
    prompt_tokens: NonNegativeInt
    completion_tokens: NonNegativeInt
    cache_hits: NonNegativeInt
    live_queries: NonNegativeInt
    latency_seconds_min: float
    latency_seconds_max: float
    latency_seconds_total: float
    runs_priced: NonNegativeInt
    runs_unpriced: NonNegativeInt
    model_cost_total: float | None
    currencies: NonNegativeInt
    model_cost_currency: str | None
    model_prices_version: str | None
    most_recent: datetime

    @model_validator(mode="after")
    def _reconciles(self) -> RunMetrics:
        if self.verdicts + self.typed_failures != self.runs:
            raise ValueError(
                f"{self.emitter} has {self.runs} run(s) of which "
                f"{self.verdicts} carry a verdict and {self.typed_failures} a "
                f"typed failure; a stored run is one or the other "
                f"(`concept/07-principles.md`), so the rest are rows claiming "
                f"neither"
            )
        if self.runs_priced + self.runs_unpriced != self.runs:
            raise ValueError(
                f"{self.runs_priced} priced + {self.runs_unpriced} unpriced is "
                f"not the {self.runs} run(s) counted; the cost columns are null "
                f"together or set together and this row is neither"
            )
        if self.runs_with_retries > self.runs:
            raise ValueError(
                f"{self.runs_with_retries} of {self.runs} run(s) retried; the "
                f"counter does not reconcile"
            )
        if self.currencies > 1:
            raise ValueError(
                f"{self.emitter}'s runs on {self.model_requested!r} are priced "
                f"in {self.currencies} currencies, so their total is not a "
                f"cost. Price one model in one currency, or read the "
                f"assessments"
            )
        if (self.model_cost_total is None) != (self.runs_priced == 0):
            raise ValueError(
                f"{self.runs_priced} run(s) are priced and the total is "
                f"{self.model_cost_total!r}; a priced run has a cost and an "
                f"unpriced one contributes none"
            )
        return self

    @property
    def mean_latency_seconds(self) -> float:
        """The run's whole wall clock, averaged. Raises over no runs."""
        return self.latency_seconds_total / self._over("a mean latency")

    @property
    def typed_failure_rate(self) -> float:
        """Runs that ended as a typed failure, over runs."""
        return self.typed_failures / self._over("a failure rate")

    @property
    def schema_retry_rate(self) -> float:
        """Runs that needed at least one bounded retry, over runs.

        `concept/07-principles.md`: *"the retry count per model is itself a
        quality metric"*. This is the count as a share of runs;
        `retries_per_run` below is the count itself, and they differ whenever one
        run spent more than one retry — which is the case worth seeing, because
        the retries are bounded and a run at the bound is a run about to become a
        typed failure.
        """
        return self.runs_with_retries / self._over("a retry rate")

    @property
    def retries_per_run(self) -> float:
        """Bounded schema retries spent, over runs."""
        return self.retries / self._over("a retry count per run")

    @property
    def cache_hit_ratio(self) -> float:
        """Cache hits over retrievals.

        Raises where the runs made no retrievals at all, which is every triage
        run: `concept/04-the-two-agents.md` gives triage no tools, so `0.0` here
        would read as "the cache never helped" about an agent that never asked.
        """
        retrievals = self.cache_hits + self.live_queries
        if retrievals == 0:
            raise ValueError(
                f"{self.emitter}'s runs on {self.model_requested!r} retrieved "
                f"nothing, so there is no cache-hit ratio; 0.0 would read as "
                f"'the cache never helped' about runs that never asked"
            )
        return self.cache_hits / retrievals

    @property
    def mean_cost(self) -> float:
        """Derived monetary cost over the runs that had a price.

        The denominator is `runs_priced` and not `runs`: dividing a priced
        subset's total by every run reports a cost per run that no run cost.
        """
        if self.runs_priced == 0 or self.model_cost_total is None:
            raise ValueError(
                f"no run of {self.model_requested!r} has a configured price, so "
                f"there is no cost; 0.0 would read as 'this model is free'"
            )
        return self.model_cost_total / self.runs_priced

    def _over(self, what: str) -> int:
        if self.runs == 0:
            raise ValueError(
                f"no runs are counted for {self.emitter} on "
                f"{self.model_requested!r}, so there is no {what}"
            )
        return self.runs


class FailureCounts(Measured):
    """One typed failure reason, counted.

    `concept/instruction.md` §7 requires every failure path to be typed, stored
    and countable. The reason stays a value rather than becoming a column, so a
    reason nobody has added to a `CASE` still appears.
    """

    tenant: str
    sensor: str
    emitter: str
    failure_reason: str
    failures: NonNegativeInt
    most_recent: datetime


class EscalationCounts(Measured):
    """How many contexts triage sent to the analyst, and what sent them.

    Every pass writes a triage run and an escalated one writes an analyst run
    beside it, so `triaged` is the denominator. The two triggers are counted
    apart because they are two mechanisms: `triage_suspicious` is triage asking
    for a second opinion, and `deterministic_signal` is `concept/07`'s rule that
    a `normal` from a model may not suppress a high-confidence match, firing
    independently of what triage said.
    """

    tenant: str
    sensor: str
    triaged: NonNegativeInt
    escalated: NonNegativeInt
    by_triage_suspicious: NonNegativeInt
    by_deterministic_signal: NonNegativeInt

    @model_validator(mode="after")
    def _reconciles(self) -> EscalationCounts:
        by_trigger = self.by_triage_suspicious + self.by_deterministic_signal
        if by_trigger != self.escalated:
            raise ValueError(
                f"{self.escalated} analyst run(s) are counted and "
                f"{by_trigger} carry one of the two escalation triggers; an "
                f"analyst run reached the store under a trigger that does not "
                f"escalate to one"
            )
        if self.escalated > self.triaged:
            raise ValueError(
                f"{self.escalated} of {self.triaged} pass(es) escalated; every "
                f"pass writes a triage run, so more analyst runs than triage "
                f"runs is a store missing the triage half of a pass"
            )
        return self

    @property
    def rate(self) -> float:
        """Escalated passes over triaged passes.

        `concept/01-goal-and-scope.md` lists escalation rate among the four
        things the system is to be measured on. No triaged passes means no rate:
        `0.0` would read as "triage escalates nothing" about a deployment that
        has assessed nothing.
        """
        if self.triaged == 0:
            raise ValueError(
                "no context has been triaged under this identity, so there is "
                "no escalation rate; 0.0 would read as 'triage escalates "
                "nothing'"
            )
        return self.escalated / self.triaged


class RetrievalMetrics(Measured):
    """One source's retrieval trace: cache against live, answered against failed.

    `concept/07-principles.md`, "Caching": *"two runs that differ only in cache
    state must be distinguishable afterwards."* `RunMetrics` sums both per model,
    which is that ratio; this is the same trace cut by source, which is the cut
    an operator acts on.

    `answered` and `failures` are exclusive and exhaustive by the contract
    (`helena.contracts.v1.RetrievalStep`): a query that completed produced an
    evidence row — `no_match` included, which is an answer — and one that did not
    produced a typed error and no taxonomy object. A row where they do not add up
    is refused rather than reported as a third state nobody named.
    """

    tenant: str
    sensor: str
    emitter: str
    source_id: str
    steps: NonNegativeInt
    cache_hits: NonNegativeInt
    live_queries: NonNegativeInt
    answered: NonNegativeInt
    failures: NonNegativeInt
    oldest_retrieved_at: datetime
    newest_retrieved_at: datetime

    @model_validator(mode="after")
    def _reconciles(self) -> RetrievalMetrics:
        if self.cache_hits + self.live_queries != self.steps:
            raise ValueError(
                f"{self.source_id}: {self.cache_hits} cache hit(s) + "
                f"{self.live_queries} live quer(ies) is not the {self.steps} "
                f"step(s) counted; a retrieval is one or the other "
                f"(`helena.contracts.v1.RETRIEVAL_OUTCOMES`)"
            )
        if self.answered + self.failures != self.steps:
            raise ValueError(
                f"{self.source_id}: {self.answered} answered + {self.failures} "
                f"failed is not the {self.steps} step(s) counted; a step "
                f"produced evidence or a typed error, and never both or neither"
            )
        return self

    @property
    def cache_hit_ratio(self) -> float:
        """Cache hits over retrievals against this source."""
        if self.steps == 0:
            raise ValueError(
                f"nothing was retrieved from {self.source_id}, so there is no "
                f"cache-hit ratio"
            )
        return self.cache_hits / self.steps

    @property
    def failure_rate(self) -> float:
        """Queries that did not complete, over queries made.

        Never `no_match`: that is an answer and is counted in `answered`
        (`concept/05-threat-intelligence.md`, rule 4).
        """
        if self.steps == 0:
            raise ValueError(
                f"nothing was retrieved from {self.source_id}, so there is no "
                f"failure rate"
            )
        return self.failures / self.steps


class PipelineReconciliation(Measured):
    """The whole chain's counts, from the capture file to the emittable message.

    `concept/07-principles.md` asks for *"record counts reconciled between
    produced and materialised"* end to end. The terms come from three engine
    layers and from the file system, for the reason the module docstring gives,
    and this is where they meet and are checked against each other.

    **What must reconcile and what merely reports** are two different lists, and
    conflating them would produce a check that fires on a healthy pipeline:

    * `admitted` may not exceed `capture_records`. More records accounted for
      than the files hold means a capture was ingested twice — the case
      `helena.normalizer.IngestCounts` names, where storing an event again is an
      upsert and looks exactly like loss.
    * `context_records` may not exceed `normalized`, because a context's
      `flow_count` counts normalized events.
    * `context_records` **need not equal** `normalized`.
      `helena_signal_host_context` tumbles `helena_flatten_flows` on `flow_start`
      grouped by `src_address`, so an event with no `ip` layer or an unparseable
      `ts` produces a flatten row the tumble drops. That is `unaggregated`, and
      it is reported rather than raised: it is a fact about the input, and a
      pipeline that refused to report it would be one that could not tell anybody
      the input had changed.
    * `emittable` **need not equal** `assessments`. A pass that escalated stores
      two runs and emits one message, so `emittable` tracks terminal outcomes
      (`sql/migrations/0019`), not rows.
    """

    tenant: str
    sensor: str
    #: How many captures on disk the ingest ledger has a row for, and how many
    #: records they hold. `None` when no capture directory was given — never 0,
    #: which would report a deployment that had lost everything.
    captures: NonNegativeInt | None
    capture_records: NonNegativeInt | None
    #: Ledger rows whose capture file was not in the directory. Their records are
    #: not in `capture_records`, so `unaccounted` refuses to be computed.
    captures_absent: NonNegativeInt | None
    normalized: NonNegativeInt
    quarantined: NonNegativeInt
    contexts: NonNegativeInt
    context_records: NonNegativeInt
    assessments: NonNegativeInt
    assessed_contexts: NonNegativeInt
    emittable: NonNegativeInt

    @model_validator(mode="after")
    def _reconciles(self) -> PipelineReconciliation:
        supplied = (self.captures, self.capture_records, self.captures_absent)
        if len({term is None for term in supplied}) != 1:
            raise ValueError(
                "the capture terms are supplied together or not at all; "
                f"got captures={self.captures!r}, "
                f"capture_records={self.capture_records!r}, "
                f"captures_absent={self.captures_absent!r}"
            )
        if (
            self.capture_records is not None
            and self.captures_absent == 0
            and self.admitted > self.capture_records
        ):
            raise ValueError(
                f"{self.admitted} record(s) are accounted for and the captures "
                f"hold {self.capture_records}; at least one record was ingested "
                f"more than once — storing an event again is an upsert, so it "
                f"looks exactly like loss"
            )
        if self.context_records > self.normalized:
            raise ValueError(
                f"{self.context_records} record(s) reached a context and "
                f"{self.normalized} were normalized; a context counts normalized "
                f"events, so this counter does not reconcile"
            )
        if self.assessed_contexts > self.assessments:
            raise ValueError(
                f"{self.assessed_contexts} context(s) were assessed by "
                f"{self.assessments} run(s); a run assesses one context"
            )
        return self

    @property
    def admitted(self) -> int:
        """Records ingestion accounted for: normalized plus quarantined."""
        return self.normalized + self.quarantined

    @property
    def unaccounted(self) -> int:
        """Capture records that reached neither store.

        The number the broker makes possible: it is consume-once and
        restart-volatile, so a record that went missing between the topic and the
        store is gone and nothing else counts it.

        Raises rather than guessing when the capture directory was not given, or
        when the ledger names a capture that was not in it — both are "the
        denominator is incomplete", and a number computed over an incomplete
        denominator is worse than no number.
        """
        if self.capture_records is None:
            raise ValueError(
                "no capture directory was read, so how many records existed is "
                "unknown; `helena status --captures DIR` is what supplies it, "
                "and the file is the only place that number lives"
            )
        if self.captures_absent:
            raise ValueError(
                f"{self.captures_absent} capture(s) the ingest ledger names were "
                f"not in the directory read, so the record count is incomplete "
                f"and the difference would not be loss"
            )
        return self.capture_records - self.admitted

    @property
    def unaggregated(self) -> int:
        """Normalized events that reached no context. Reported, never raised."""
        return self.normalized - self.context_records


class Status(Measured):
    """Everything `helena status` prints, for one identity, as of one read.

    Assembled by `report()` and rendered by `render()`. It is a model rather than
    a bag of prints so that the numbers can be asserted on by a test and used by
    something other than the command — and so that a future reader of the report
    gets the same refusals a reader of the individual counters gets.
    """

    tenant: str
    sensor: str
    read_at: datetime
    ingest: tuple[IngestLedger, ...]
    feeds: tuple[FeedStaleness, ...]
    runs: tuple[RunMetrics, ...]
    failures: tuple[FailureCounts, ...]
    escalation: EscalationCounts | None
    retrievals: tuple[RetrievalMetrics, ...]
    pipeline: PipelineReconciliation | None
    rejections: RetentionRejections
    emittable: NonNegativeInt


@dataclass(frozen=True)
class StatusStore:
    """The observability views, under one identity.

    The same shape as `helena.sink.SinkStore` and `helena.context.ContextStore`,
    and for the same reason: the identity is on the instance rather than passed
    per call, so a caller cannot read one deployment's numbers and print them
    under another's tenant. `concept/instruction.md` §6 — *"a defaulted tenant is
    an isolation failure that looks like it is working"*.

    Every method is a `SELECT` and nothing here writes.
    """

    connection: psycopg.Connection
    identity: IngestionIdentity

    def ingest(self) -> tuple[IngestLedger, ...]:
        """One row per capture this identity has ingested anything of."""
        return tuple(
            IngestLedger(**row)
            for row in self._read(
                INGEST_LEDGER_VIEW, INGEST_LEDGER_COLUMNS, order="capture_sha256"
            )
        )

    def feeds(self) -> tuple[FeedStaleness, ...]:
        """One row per source anything has ever tried to load."""
        return tuple(
            FeedStaleness(**row)
            for row in self._read(
                FEED_STALENESS_VIEW, FEED_STALENESS_COLUMNS, order="source_id"
            )
        )

    def runs(self) -> tuple[RunMetrics, ...]:
        """One row per (emitter, model asked for, model that answered)."""
        return tuple(
            RunMetrics(**row)
            for row in self._read(
                RUN_METRICS_VIEW,
                RUN_METRICS_COLUMNS,
                order="emitter, model_requested, model_version",
            )
        )

    def failures(self) -> tuple[FailureCounts, ...]:
        """One row per (emitter, typed failure reason) that has happened."""
        return tuple(
            FailureCounts(**row)
            for row in self._read(
                FAILURE_COUNTS_VIEW,
                FAILURE_COUNTS_COLUMNS,
                order="emitter, failure_reason",
            )
        )

    def escalation(self) -> EscalationCounts | None:
        """The escalation counter, or `None` where nothing has been assessed.

        `None` rather than a row of zeros, and the difference matters: a row of
        zeros is a deployment whose triage escalates nothing, and this is a
        deployment whose triage has not run. `EscalationCounts.rate` refuses the
        first; this refuses the second one level up.
        """
        rows = self._read(ESCALATION_COUNTS_VIEW, ESCALATION_COUNTS_COLUMNS)
        return EscalationCounts(**rows[0]) if rows else None

    def retrievals(self) -> tuple[RetrievalMetrics, ...]:
        """One row per (emitter, source) the analyst tier has retrieved from."""
        return tuple(
            RetrievalMetrics(**row)
            for row in self._read(
                RETRIEVAL_METRICS_VIEW,
                RETRIEVAL_METRICS_COLUMNS,
                order="emitter, source_id",
            )
        )

    def pipeline(
        self, *, captures: Mapping[str, Capture] | None = None
    ) -> PipelineReconciliation | None:
        """The whole chain's counts, or `None` where the store holds nothing.

        `captures` is `helena.normalizer.scan_captures`'s result for the retained
        capture directory. Without it the capture terms are `None` and
        `PipelineReconciliation.unaccounted` raises; see the module docstring on
        why they are not defaulted to 0.

        Only the captures the **ingest ledger names** are counted, because the
        question is "did every record of what was ingested arrive", not "how many
        records are on this disk". A ledger row whose file is not in the
        directory is counted in `captures_absent` rather than silently ignored.
        """
        rows = self._read(
            PIPELINE_RECONCILIATION_VIEW, PIPELINE_RECONCILIATION_COLUMNS
        )
        if not rows:
            return None
        ledger = self.ingest()
        counted = self._captures(ledger, captures)
        return PipelineReconciliation(
            **rows[0],
            **counted,
            normalized=sum(entry.normalized for entry in ledger),
            quarantined=sum(entry.quarantined for entry in ledger),
        )

    @staticmethod
    def _captures(
        ledger: Sequence[IngestLedger], captures: Mapping[str, Capture] | None
    ) -> dict[str, int | None]:
        if captures is None:
            return {"captures": None, "capture_records": None, "captures_absent": None}
        present = [entry for entry in ledger if entry.capture_sha256 in captures]
        return {
            "captures": len(present),
            "capture_records": sum(
                captures[entry.capture_sha256].record_count for entry in present
            ),
            "captures_absent": len(ledger) - len(present),
        }

    def _read(
        self, view: str, columns: Sequence[str], *, order: str = ""
    ) -> list[dict[str, object]]:
        self.connection.execute("FLUSH")
        rows = self.connection.execute(
            f"SELECT {', '.join(columns)} FROM {view} "
            f"WHERE tenant = %s AND sensor = %s"
            + (f" ORDER BY {order}" if order else ""),
            (self.identity.tenant, self.identity.sensor),
        ).fetchall()
        return [dict(zip(columns, row, strict=True)) for row in rows]


def report(
    connection: psycopg.Connection,
    identity: IngestionIdentity,
    *,
    read_at: datetime,
    captures: Mapping[str, Capture] | None = None,
) -> Status:
    """Every counter this deployment has, read in one pass.

    The retention rejections and the emittable count come from the modules that
    own those views rather than from a second query here — `concept/07`'s
    rejection rate is `helena.context.ContextStore.rejections` and the engine-side
    emission count is `helena.sink.SinkStore.pending`. A second copy of either
    would be a second number to disagree with the first.

    `read_at` is passed in rather than taken here because every staleness number
    in the result is relative to a moment, and a report that stamped itself would
    stamp a different moment than the `now()` the engine used.
    """
    store = StatusStore(connection=connection, identity=identity)
    return Status(
        tenant=identity.tenant,
        sensor=identity.sensor,
        read_at=read_at,
        ingest=store.ingest(),
        feeds=store.feeds(),
        runs=store.runs(),
        failures=store.failures(),
        escalation=store.escalation(),
        retrievals=store.retrievals(),
        pipeline=store.pipeline(captures=captures),
        rejections=ContextStore(connection, identity).rejections(),
        emittable=SinkStore(connection=connection, identity=identity).pending(),
    )


def render(status: Status) -> str:
    """The report as lines of plain text, for a terminal.

    Deliberately not a table library and not JSON: the audience is an operator
    reading a terminal, and the numbers are already available as SQL to anything
    that wants to parse them. Where a rate cannot be computed the reason is
    printed instead of the number — that is the whole point of the refusals
    above, and swallowing them here would put the zeros back.
    """
    lines = [
        f"helena status — {status.tenant} / {status.sensor}",
        f"read at {status.read_at.isoformat()}",
        "",
        "PIPELINE",
    ]
    lines += _pipeline(status)
    lines += ["", "RETENTION BOUNDARY"]
    lines += _rejections(status.rejections)
    lines += ["", "FEEDS"]
    lines += _feeds(status.feeds)
    lines += ["", "RUNS"]
    lines += _runs(status.runs)
    lines += ["", "TYPED FAILURES"]
    lines += _failures(status.failures)
    lines += ["", "ESCALATION"]
    lines += _escalation(status.escalation)
    lines += ["", "RETRIEVAL"]
    lines += _retrievals(status.retrievals)
    return "\n".join(lines) + "\n"


def _shown(compute, specification: str) -> str:
    """A number, or the sentence saying why there is none.

    Every refusal in this module is a `ValueError` carrying a sentence written
    for exactly this moment, so the message *is* the rendering. Catching it here
    and printing the number is what would put the misleading zeros back.
    """
    try:
        return format(compute(), specification)
    except ValueError as refused:
        return f"— ({refused})"


def _rate(compute) -> str:
    return _shown(compute, ".3f")


def _count(compute) -> str:
    """A whole number of records. `.3f` on a count reads as a measurement."""
    return _shown(compute, "d")


def _cost(compute) -> str:
    """Money, at six places: one triage call is fractions of a cent."""
    return _shown(compute, ".6f")


def _pipeline(status: Status) -> list[str]:
    reconciliation = status.pipeline
    if reconciliation is None:
        return ["  nothing ingested and nothing assessed under this identity"]
    if reconciliation.capture_records is None:
        held = "capture records   not read (pass --captures DIR)"
    else:
        held = (
            f"capture records   {reconciliation.capture_records} "
            f"in {reconciliation.captures} capture(s)"
        )
    lines = [
        f"  {held}",
        f"  normalized        {reconciliation.normalized}",
        f"  quarantined       {reconciliation.quarantined}",
        f"  admitted          {reconciliation.admitted}",
        f"  unaccounted       {_count(lambda: reconciliation.unaccounted)}",
        f"  context records   {reconciliation.context_records} "
        f"in {reconciliation.contexts} context(s)",
        f"  unaggregated      {reconciliation.unaggregated}",
        f"  assessments       {reconciliation.assessments} "
        f"over {reconciliation.assessed_contexts} context(s)",
        f"  emittable         {reconciliation.emittable} message(s)",
    ]
    if reconciliation.emittable != status.emittable:
        lines.append(
            f"  WARNING: the reconciliation view reports "
            f"{reconciliation.emittable} emittable message(s) and the emission "
            f"counter {status.emittable}; the two read the same view and "
            f"disagree"
        )
    return lines


def _rejections(rejections: RetentionRejections) -> list[str]:
    return [
        f"  horizon           {rejections.horizon}",
        f"  contexts          {rejections.contexts_outside_boundary} of "
        f"{rejections.contexts} outside the boundary",
        f"  records           {rejections.records_outside_boundary} of "
        f"{rejections.records} outside the boundary",
        f"  rejection rate    {_rate(lambda: rejections.rate)}",
    ]


def _feeds(feeds: Sequence[FeedStaleness]) -> list[str]:
    if not feeds:
        return ["  no source has ever been loaded under this identity"]
    lines = []
    for feed in feeds:
        behind = _rate(lambda feed=feed: feed.intervals_behind)
        lines.append(
            f"  {feed.source_id:<24} {feed.status:<8} "
            f"{feed.attempts} attempt(s), {behind} interval(s) behind"
        )
        if feed.last_failure_at is not None:
            lines.append(
                f"  {'':<24} last failed attempt "
                f"{feed.last_failure_at.isoformat()}"
            )
    return lines


def _runs(runs: Sequence[RunMetrics]) -> list[str]:
    if not runs:
        return ["  nothing has been assessed under this identity"]
    lines = []
    for run in runs:
        answered = run.model_version or "— (nothing answered)"
        lines.append(f"  {run.emitter} asked {run.model_requested}, got {answered}")
        lines.append(
            f"    runs {run.runs}  verdicts {run.verdicts}  "
            f"typed failures {run.typed_failures} "
            f"(rate {_rate(lambda run=run: run.typed_failure_rate)})"
        )
        lines.append(
            f"    latency  mean {_rate(lambda run=run: run.mean_latency_seconds)}s"
            f"  min {run.latency_seconds_min:.3f}s"
            f"  max {run.latency_seconds_max:.3f}s"
        )
        lines.append(
            f"    tokens   prompt {run.prompt_tokens}  "
            f"completion {run.completion_tokens}"
        )
        lines.append(
            f"    cost     mean {_cost(lambda run=run: run.mean_cost)} "
            f"{run.model_cost_currency or ''}".rstrip()
            + f"  priced {run.runs_priced}/{run.runs}"
            + (
                f"  prices {run.model_prices_version}"
                if run.model_prices_version
                else ""
            )
        )
        lines.append(
            f"    retries  {run.retries} over {run.runs} run(s), "
            f"rate {_rate(lambda run=run: run.schema_retry_rate)}"
        )
        lines.append(
            f"    cache    {run.cache_hits} hit(s) / {run.live_queries} live, "
            f"ratio {_rate(lambda run=run: run.cache_hit_ratio)}"
        )
    return lines


def _failures(failures: Sequence[FailureCounts]) -> list[str]:
    if not failures:
        return ["  none stored"]
    return [
        f"  {failure.emitter:<10} {failure.failure_reason:<20} "
        f"{failure.failures}  most recent {failure.most_recent.isoformat()}"
        for failure in failures
    ]


def _escalation(escalation: EscalationCounts | None) -> list[str]:
    if escalation is None:
        return ["  nothing has been triaged under this identity"]
    return [
        f"  triaged           {escalation.triaged}",
        f"  escalated         {escalation.escalated} "
        f"(rate {_rate(lambda: escalation.rate)})",
        f"    by triage       {escalation.by_triage_suspicious}",
        f"    by rule         {escalation.by_deterministic_signal}",
    ]


def _retrievals(retrievals: Sequence[RetrievalMetrics]) -> list[str]:
    if not retrievals:
        return ["  no provider has been queried under this identity"]
    lines = []
    for retrieval in retrievals:
        lines.append(
            f"  {retrieval.emitter} / {retrieval.source_id:<20} "
            f"{retrieval.steps} step(s), "
            f"cache {_rate(lambda r=retrieval: r.cache_hit_ratio)}, "
            f"failed {_rate(lambda r=retrieval: r.failure_rate)}"
        )
        lines.append(
            f"    oldest record served {retrieval.oldest_retrieved_at.isoformat()}"
        )
    return lines
