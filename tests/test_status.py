"""The pipeline's own numbers, executed against the engine that holds them.

`concept/07-principles.md` lists what must be observable — latency, cost,
staleness, error, escalation and model-quality metrics; record counts reconciled
between produced and materialised; the retention boundary's rejection rate; and
emission counted from the engine side — and says where it lives: *"the audit
record is the stored assessment, not a trace UI ... queryable in a way a trace UI
is not."*

So every test here runs SQL. The views in
`sql/migrations/0021_pipeline_observability.sql` are applied by the migration
runner into the shared migrated schema, rows are written by the **real writers**
— the normalizer over a real capture, the ThreatFox loader over the committed
extract, `helena.orchestration.AssessmentStore` over contract objects — and the
numbers are read back through `helena.status`. A test that asserted on the text
of a `CREATE VIEW` would find the comment arguing for a thing's absence; these
ask the engine.

The unit tests at the top are the ones that cannot be executed against a store:
the two copies of a constant the SQL cannot import, and the refusals that fire
before a number is printed.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg
import pytest

from helena import analyst, budgets, disclosure, migrations, orchestration, status, triage
from helena.config import IngestionIdentity, Settings
from helena.contracts.v1 import (
    CACHE_HIT,
    CONTRACT_VERSION,
    FAILURE_REASONS,
    LIVE_QUERY,
    MODEL_UNAVAILABLE,
    SCHEMA_INVALID,
    SECTIONS,
    SUPPORTING,
    TRIGGERS,
    AgentFailure,
    AgentRequest,
    AgentResult,
    Citation,
    Cost,
    EvidencePackage,
    Gap,
    QueryFailure,
    RenderedSection,
    Rendering,
    RequestVersions,
    RetrievalStep,
)
from helena.enrichment import (
    FEED_SNAPSHOT_TABLE,
    MISSING,
    OK,
    STALE,
    THREATFOX_MIN_FETCH_INTERVAL_SECONDS,
    load_threatfox,
)
from helena.normalizer import (
    EventStore,
    Normalizer,
    Quarantine,
    describe_capture,
    scan_captures,
)
from helena.observability import Redactor
from helena.policy import v1 as rule

PROJECT_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures"
FIXTURE_CAPTURES = FIXTURES / "captures"
LAYERS_CAPTURE = "ace6ca33f7bf8aa949f79124abf33fc115cfd0909e9dea798f4762cf87af8318"
THREATFOX_FIXTURE = FIXTURES / "threatfox" / "export.json"
RAW = THREATFOX_FIXTURE.read_bytes()
FEED_URL = "https://threatfox.abuse.ch/export/json/recent/"

TENANT = "tenant-under-test"
SENSOR = "sensor-under-test"
WINDOW_SECONDS = 300

# Obviously not credentials, and every variable `Settings.load` requires.
ENVIRONMENT = {
    "LLM_URL": "http://model.invalid/v1",
    "LLM_TOKEN": "token-under-test",
    "LLM_MODEL": "model-under-test",
    "HELENA_TENANT": TENANT,
    "HELENA_SENSOR": SENSOR,
    "HELENA_INPUT_FORMAT": "flow-json",
    "ABUSECH_AUTH_KEY": "abusech-key-under-test",
    "VIRUSTOTAL_AUTH_KEY": "virustotal-key-under-test",
    "RISINGWAVE_DSN": "postgresql://root@localhost:4566/dev",
    "KAFKA_BOOTSTRAP_SERVERS": "localhost:9092",
    "HELENA_INGEST_TOPIC": "helena.ingest",
    "HELENA_OUTPUT_TOPIC": "helena.output",
}

TRIAGE = triage.EMITTER
ANALYST = analyst.EMITTER
TRIAGE_PROMPT = triage.version("v1")
ANALYST_PROMPT = analyst.version("v1")
BUDGET_POLICY = budgets.load()
SEND_POLICY = disclosure.send_policy()
NO_PRICES = budgets.model_prices()
#: A price table with an entry for the model under test, so the derived-cost
#: columns are filled in and `RunMetrics.mean_cost` has something to divide.
#: Built here rather than read from `config/policy.toml`, which is deliberately
#: silent about the endpoint this repository does not know the price of.
PRICED = budgets.PriceTable(
    version="prices-under-test",
    prices={
        "model-under-test": budgets.ModelPrice(
            prompt_per_million=3.0, completion_per_million=15.0, currency="USD"
        )
    },
)
ENDPOINT = "model.invalid:8443"
ASSESSED_AT = datetime(2026, 9, 11, 12, 0, tzinfo=timezone.utc)
RETRIEVED = "f" * 64
MIGRATION = migrations.MIGRATIONS_DIR / "0021_pipeline_observability.sql"

#: Every view this increment adds, with the column list `helena.status` reads it
#: through. The pairs drive `test_every_view_is_the_column_list_this_module_holds`.
VIEWS = {
    status.INGEST_LEDGER_VIEW: status.INGEST_LEDGER_COLUMNS,
    status.FEED_STALENESS_VIEW: status.FEED_STALENESS_COLUMNS,
    status.RUN_METRICS_VIEW: status.RUN_METRICS_COLUMNS,
    status.FAILURE_COUNTS_VIEW: status.FAILURE_COUNTS_COLUMNS,
    status.ESCALATION_COUNTS_VIEW: status.ESCALATION_COUNTS_COLUMNS,
    status.RETRIEVAL_METRICS_VIEW: status.RETRIEVAL_METRICS_COLUMNS,
    status.PIPELINE_RECONCILIATION_VIEW: status.PIPELINE_RECONCILIATION_COLUMNS,
}


def settings() -> Settings:
    return Settings.load(environ=ENVIRONMENT, env_file=None)


def identity(tenant: str = TENANT) -> IngestionIdentity:
    return IngestionIdentity(tenant=tenant, sensor=SENSOR)


def a_store(connection: psycopg.Connection, tenant: str = TENANT) -> status.StatusStore:
    return status.StatusStore(connection=connection, identity=identity(tenant))


# --- The two copies of a constant the SQL cannot import ----------------------


def statement(view: str) -> str:
    """One view's `CREATE`, from its name to the semicolon that ends it.

    Sliced per view rather than over the whole file, because the file's prose
    quotes the literals it argues against -- the staleness view's head explains
    why it does *not* filter on `outcome = 'failed'` -- and a search over the
    whole text would read the argument as a second copy of the constant.
    """
    text = MIGRATION.read_text()
    start = text.index(f"CREATE VIEW {view} AS")
    return text[start : text.index(";", start)]


def test_the_emitter_literals_in_the_escalation_view_are_the_taxonomy_s():
    """`concept/instruction.md` §2: two copies of a constant are asserted equal.

    The escalation counter branches on `'triage'` and `'analyst'` as string
    literals because SQL cannot import `helena.taxonomy`; this is where the two
    copies meet, exactly as `tests/test_sink.py` does it for
    `sql/migrations/0019`.
    """
    assert set(
        re.findall(r"emitter = '([a-z_]+)'", statement(status.ESCALATION_COUNTS_VIEW))
    ) == {TRIAGE, ANALYST}


def test_the_trigger_literals_in_the_escalation_view_are_the_contract_s():
    """The two triggers that escalate, and never the one that does not.

    `scheduled_triage` is how a pass *starts*, so counting it as an escalation
    would report every assessed context as escalated.
    """
    found = set(
        re.findall(
            r"triggered_by = '([a-z_]+)'", statement(status.ESCALATION_COUNTS_VIEW)
        )
    )
    assert found < set(TRIGGERS)
    assert found == {"triage_suspicious", "deterministic_signal"}


def test_the_retrieval_outcome_literals_in_the_view_are_the_contract_s():
    assert set(
        re.findall(
            r"outcome = '([a-z_]+)'", statement(status.RETRIEVAL_METRICS_VIEW)
        )
    ) == {CACHE_HIT, LIVE_QUERY}


def test_the_feed_statuses_this_module_holds_are_enrichment_s_three():
    """`helena.status.FEED_STATUSES` is imported, not respelled.

    A fourth name for `missing` is the drift `concept/instruction.md` §2's
    "never collapse `stale` / `failed` / `missing` / `no_match`" exists to stop,
    and the cheapest way to get one is a second spelling in a second module.
    """
    assert status.FEED_STATUSES == (OK, STALE, MISSING)
    assert set(
        re.findall(r"THEN '([a-z_]+)'", statement(status.FEED_STALENESS_VIEW))
    ) <= set(status.FEED_STATUSES)


def test_every_view_the_migration_adds_is_declared_plain_and_in_its_own_layer():
    """The layering rule over the declarations, and the materialization call.

    `concept/instruction.md` §2 puts the source layer out of an analytical
    view's reach, which is why the reconciliation is two views: the ingest ledger
    is `source` and reads only source counters.
    """
    declared = migrations.declarations()
    layers = {name: declared[name].layer for name in VIEWS}
    assert layers == {
        status.INGEST_LEDGER_VIEW: "source",
        status.FEED_STALENESS_VIEW: "reference",
        status.RUN_METRICS_VIEW: "analytical",
        status.FAILURE_COUNTS_VIEW: "analytical",
        status.ESCALATION_COUNTS_VIEW: "analytical",
        status.RETRIEVAL_METRICS_VIEW: "analytical",
        status.PIPELINE_RECONCILIATION_VIEW: "analytical",
    }
    assert all(declared[name].kind == "VIEW" for name in VIEWS)
    assert migrations.layering_violations(declared) == []


# --- The refusals, which fire before a number is printed ---------------------


def a_run(**overrides) -> status.RunMetrics:
    return status.RunMetrics(
        **{
            "tenant": TENANT,
            "sensor": SENSOR,
            "emitter": TRIAGE,
            "model_requested": "model-under-test",
            "model_version": "model-under-test-2026-05",
            "runs": 2,
            "verdicts": 2,
            "typed_failures": 0,
            "runs_with_retries": 1,
            "retries": 3,
            "prompt_tokens": 80,
            "completion_tokens": 40,
            "cache_hits": 0,
            "live_queries": 0,
            "latency_seconds_min": 0.5,
            "latency_seconds_max": 1.5,
            "latency_seconds_total": 2.0,
            "runs_priced": 0,
            "runs_unpriced": 2,
            "model_cost_total": None,
            "currencies": 0,
            "model_cost_currency": None,
            "model_prices_version": None,
            "most_recent": ASSESSED_AT,
            **overrides,
        }
    )


def test_a_run_row_whose_verdicts_and_failures_do_not_add_up_is_refused():
    """A stored run carries a verdict or a typed failure, and never neither.

    `concept/07-principles.md`: *"a failed run is stored as a typed failure with
    no verdict"*. A row that is neither is a row claiming nothing, and it would
    quietly deflate every rate computed over `runs`.
    """
    with pytest.raises(ValueError, match="claiming neither"):
        a_run(runs=3, verdicts=2, typed_failures=0)


def test_a_cost_summed_across_two_currencies_is_refused_rather_than_printed():
    with pytest.raises(ValueError, match="not a"):
        a_run(runs_priced=2, runs_unpriced=0, model_cost_total=17.0, currencies=2)


def test_a_cost_total_without_a_priced_run_is_refused():
    with pytest.raises(ValueError, match="priced"):
        a_run(model_cost_total=17.0)


def test_no_rate_is_computed_over_an_empty_denominator():
    """Every rate raises rather than returning 0.0, and says why.

    `helena.context.RetentionRejections.rate` set the rule: 0.0 would read as
    "nothing was dropped" when the truth is "nothing was aggregated", and the two
    are different facts. `helena.status.render` prints the sentence in place of
    the number, so the refusal reaches the operator rather than being swallowed.
    """
    empty = a_run(
        runs=0,
        verdicts=0,
        typed_failures=0,
        runs_with_retries=0,
        retries=0,
        prompt_tokens=0,
        completion_tokens=0,
        latency_seconds_min=0.0,
        latency_seconds_max=0.0,
        latency_seconds_total=0.0,
        runs_priced=0,
        runs_unpriced=0,
    )
    for rate in (
        "mean_latency_seconds",
        "typed_failure_rate",
        "schema_retry_rate",
        "retries_per_run",
    ):
        with pytest.raises(ValueError, match="no runs are counted"):
            getattr(empty, rate)


def test_a_triage_run_has_no_cache_hit_ratio_because_it_never_retrieved():
    """`concept/04-the-two-agents.md` gives triage no tools.

    0.0 here would read as "the cache never helped" about an agent that never
    asked — the same collapse the whole module refuses.
    """
    with pytest.raises(ValueError, match="never asked"):
        a_run().cache_hit_ratio


def test_an_unpriced_model_has_no_cost_rather_than_a_cost_of_zero():
    with pytest.raises(ValueError, match="free"):
        a_run().mean_cost


def test_the_escalation_rate_refuses_a_store_with_more_analyst_runs_than_triage():
    with pytest.raises(ValueError, match="missing the triage half"):
        status.EscalationCounts(
            tenant=TENANT,
            sensor=SENSOR,
            triaged=1,
            escalated=2,
            by_triage_suspicious=2,
            by_deterministic_signal=0,
        )


def test_a_retrieval_row_that_is_neither_answered_nor_failed_is_refused():
    """`concept/05-threat-intelligence.md` rule 4, as a counter.

    A query that completed produced an evidence row — `no_match` included, which
    is an answer — and one that did not produced a typed error. There is no third
    state, so a row that implies one is a broken counter rather than a discovery.
    """
    with pytest.raises(ValueError, match="never both or neither"):
        status.RetrievalMetrics(
            tenant=TENANT,
            sensor=SENSOR,
            emitter=ANALYST,
            source_id="threatfox",
            steps=2,
            cache_hits=1,
            live_queries=1,
            answered=1,
            failures=0,
            oldest_retrieved_at=ASSESSED_AT,
            newest_retrieved_at=ASSESSED_AT,
        )


def a_reconciliation(**overrides) -> status.PipelineReconciliation:
    return status.PipelineReconciliation(
        **{
            "tenant": TENANT,
            "sensor": SENSOR,
            "captures": None,
            "capture_records": None,
            "captures_absent": None,
            "normalized": 10,
            "quarantined": 0,
            "contexts": 1,
            "context_records": 10,
            "assessments": 1,
            "assessed_contexts": 1,
            "emittable": 1,
            **overrides,
        }
    )


def test_the_capture_terms_are_supplied_together_or_not_at_all():
    with pytest.raises(ValueError, match="together or not at all"):
        a_reconciliation(captures=1)


def test_an_unread_capture_directory_refuses_a_number_rather_than_assuming_zero():
    """The reason `--captures` is optional and its absence is not `0`.

    How many records existed is a property of the retained file and of nothing
    else: the broker is consume-once and restart-volatile. Defaulting it to 0
    would report a deployment that had lost every record it ever ingested.
    """
    with pytest.raises(ValueError, match="no capture directory was read"):
        a_reconciliation().unaccounted


def test_a_ledger_naming_a_capture_that_is_not_on_disk_refuses_the_difference():
    with pytest.raises(ValueError, match="record count is incomplete"):
        a_reconciliation(
            captures=1, capture_records=10, captures_absent=1
        ).unaccounted


def test_more_records_accounted_for_than_the_captures_hold_is_refused():
    """Storing an event a second time is an upsert, so it looks exactly like loss.

    `helena.normalizer.IngestCounts` names the case and this is the same refusal
    asked of the store afterwards, by somebody who has no `consumed` to compare
    against.
    """
    with pytest.raises(ValueError, match="ingested\nmore than once|more than once"):
        a_reconciliation(captures=1, capture_records=8, captures_absent=0)


def test_a_normalized_event_can_reach_no_context_and_that_is_reported():
    """`unaggregated` is a fact about the input, not a broken counter.

    `helena_signal_host_context` tumbles on `flow_start` grouped by
    `src_address`, so an event with no `ip` layer produces a flatten row the
    tumble drops. Reported, never raised.
    """
    assert a_reconciliation(context_records=7).unaggregated == 3


def test_a_feed_with_no_schedule_is_not_late_and_has_no_ratio():
    """`helena.enrichment.feed_status`'s rule, one level up.

    The SSLBL JA3 list has been static since 2021: it is not late, it is
    finished, and a ratio here would invent a schedule it does not have.
    """
    static = status.FeedStaleness(
        tenant=TENANT,
        sensor=SENSOR,
        source_id="sslbl-ja3",
        attempts=1,
        last_attempt_at=ASSESSED_AT,
        last_failure_at=None,
        snapshot_version="a" * 64,
        snapshot_at=ASSESSED_AT,
        refresh_interval_seconds=None,
        age_seconds=86400.0,
        status=OK,
    )
    assert static.age == timedelta(days=1)
    with pytest.raises(ValueError, match="nothing for it to be behind"):
        static.intervals_behind


def test_a_source_with_no_snapshot_is_missing_and_has_no_age():
    absent = status.FeedStaleness(
        tenant=TENANT,
        sensor=SENSOR,
        source_id="threatfox",
        attempts=2,
        last_attempt_at=ASSESSED_AT,
        last_failure_at=ASSESSED_AT,
        snapshot_version=None,
        snapshot_at=None,
        refresh_interval_seconds=None,
        age_seconds=None,
        status=MISSING,
    )
    with pytest.raises(ValueError, match="not the same thing as old"):
        absent.age


# --- What the engine actually holds ------------------------------------------


@pytest.mark.integration
@pytest.mark.parametrize("view", sorted(VIEWS), ids=lambda name: name)
def test_every_view_is_the_column_list_this_module_holds(
    migrated_engine: psycopg.Connection, view: str
):
    """Two copies of a relation's shape, asserted equal by execution.

    In order, because `StatusStore._read` zips the names onto the values
    positionally — the same reason `helena.sink.SINK_COLUMNS` has this test.
    """
    held = migrated_engine.execute(
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_schema = current_schema() AND table_name = %s "
        "ORDER BY ordinal_position",
        (view,),
    ).fetchall()
    assert [name for (name,) in held] == list(VIEWS[view])


# --- Ingest: produced against materialized -----------------------------------


def restamped(directory: Path, *, extra: bytes = b"") -> Path:
    """The layer capture, moved into the window `now` falls in, named by its hash.

    The committed capture is dated 2024-06-01 and the retention boundary is 24
    hours, so its contexts are outside it and the retention counter would report
    every record as rejected. `tests/test_sink.py` re-stamps for the same reason.

    `extra` is appended verbatim, which is how a record the adapter refuses gets
    into the capture: the quarantine terms of the reconciliation need one.

    The file is named `<sha256>.jsonl` because `helena.normalizer.scan_captures`
    refuses anything else -- *"addressed by its file hash"* is checkable rather
    than a convention -- and the reconciliation reads the capture count through
    it.
    """
    records = [
        json.loads(line)
        for line in (FIXTURE_CAPTURES / f"{LAYERS_CAPTURE}.jsonl")
        .read_bytes()
        .splitlines()
    ]
    window = float(int(time.time() // WINDOW_SECONDS) * WINDOW_SECONDS)
    body = (
        b"".join(
            json.dumps({**record, "ts": window + 1}).encode() + b"\n"
            for record in records
        )
        + extra
    )
    path = directory / f"{hashlib.sha256(body).hexdigest()}.jsonl"
    path.write_bytes(body)
    return path


def ingest(connection: psycopg.Connection, path: Path) -> int:
    """The capture through the real ingestion path. Returns its record count."""
    configured = settings()
    normalizer = Normalizer.from_settings(configured)
    quarantine = Quarantine(connection=connection, identity=configured.identity)
    capture = describe_capture(path)
    store = EventStore(connection=connection, identity=configured.identity)
    for event in normalizer.ingest_capture(capture, quarantine):
        store.record(event)
    connection.execute("FLUSH")
    return capture.record_count


@pytest.mark.integration
def test_the_ingest_ledger_counts_normalized_against_quarantined_per_capture(
    migrated_engine: psycopg.Connection, tmp_path: Path
):
    """One capture, one refused record, one row that adds up.

    `concept/instruction.md` §7: *"produced-versus-materialised counts
    reconcile"*. The refused line is a real refusal through the real adapter —
    nothing is inserted into the quarantine table by hand — so what is counted is
    what ingestion actually did.
    """
    path = restamped(tmp_path, extra=b"{not json at all}\n")
    records = ingest(migrated_engine, path)

    (ledger,) = a_store(migrated_engine).ingest()
    assert ledger.capture_sha256 == describe_capture(path).sha256
    assert ledger.quarantined == 1
    assert ledger.normalized == records - 1
    assert ledger.admitted == records
    assert ledger.quarantine_rate == pytest.approx(1 / records)


@pytest.mark.integration
def test_another_deployment_s_capture_is_not_in_this_identity_s_ledger(
    migrated_engine: psycopg.Connection, tmp_path: Path
):
    """A defaulted or borrowed tenant is an isolation failure that looks fine."""
    path = restamped(tmp_path)
    ingest(migrated_engine, path)
    assert a_store(migrated_engine, tenant="somebody-else").ingest() == ()


# --- Assessments: latency, cost, retries, escalation, retrieval --------------


def versions(**overrides: str) -> RequestVersions:
    return RequestVersions(
        **{
            "prompt_version": TRIAGE_PROMPT.version,
            "schema_version": CONTRACT_VERSION,
            "rendering_version": "r1",
            "taxonomy_version": "v1",
            "enrichment_snapshot_version": "2026-09-01T00:00:00Z",
            "normalization_snapshot_version": "psl-2026-09-01",
            "policy_version": rule.POLICY_VERSION,
            "aggregation_version": "v1",
            "model_requested": "model-under-test",
            **overrides,
        }
    )


def a_rendering() -> Rendering:
    """A rendering that showed one evidence row, so a citation of it resolves.

    `helena.contracts.v1.check_exchange` refuses an outcome citing evidence the
    run was never given, and `AssessmentStore` runs that check before it writes.
    `RETRIEVED` is therefore in a section's `evidence_ids` here rather than only
    in the citation.
    """
    return Rendering(
        version="r1",
        sections=tuple(
            RenderedSection(
                section=name,
                body=(
                    f"domain example.invalid | threatfox=malicious "
                    f"evidence={RETRIEVED}"
                    if name == "domains_contacted"
                    else f"<{name}>"
                ),
                evidence_ids=(RETRIEVED,) if name == "domains_contacted" else (),
            )
            for name in SECTIONS
        ),
    )


def a_request(context: str, **overrides) -> AgentRequest:
    """A triage request over a synthetic context.

    The metric views read the assessment tables and nothing else, so the context
    does not have to exist in the store for them — which is the point of keeping
    these tests off the ingest path: what is under test is the aggregate, and a
    real context would only make the fixture slower and the failure harder to
    read. The reconciliation test below uses a real one, because there the join
    to the context is the thing being checked.
    """
    return AgentRequest(
        **{
            "tenant": TENANT,
            "sensor": SENSOR,
            "emitter": TRIAGE,
            "host": "10.127.0.100",
            "window_start": ASSESSED_AT - timedelta(minutes=5),
            "window_end": ASSESSED_AT,
            "context_id": context,
            "context_version": "c" * 64,
            "trigger": "scheduled_triage",
            "rendering": a_rendering(),
            "budgets": BUDGET_POLICY.for_emitter(TRIAGE),
            "versions": versions(),
            **overrides,
        }
    )


def a_cost(**overrides) -> Cost:
    return Cost(
        **{
            "prompt_tokens": 40,
            "completion_tokens": 20,
            "steps": 0,
            "live_queries": 0,
            "cache_hits": 0,
            "retries": 0,
            "wall_clock_seconds": 0.5,
            **overrides,
        }
    )


def a_result(emitter: str, **overrides) -> AgentResult:
    fields: dict[str, object] = {
        "emitter": emitter,
        "classification": "suspicious",
        "confidence": 0.7,
        "citations": (Citation(evidence_id=RETRIEVED, stance=SUPPORTING),),
        "cost": a_cost(),
        "versions": versions().completed_by("model-under-test-2026-05"),
        **overrides,
    }
    if emitter == ANALYST and "evidence_package" not in fields:
        fields["evidence_package"] = EvidencePackage(
            patterns=("beaconing on a fixed interval",),
            narrative="the traffic went both ways",
        )
    return AgentResult(**fields)


def a_failure(emitter: str = TRIAGE, **overrides) -> AgentFailure:
    return AgentFailure(
        **{
            "emitter": emitter,
            "reason": MODEL_UNAVAILABLE,
            "detail": "the endpoint did not answer",
            "gaps": (Gap(kind="missing", detail="no answer, so no assessment"),),
            "cost": a_cost(prompt_tokens=0, completion_tokens=0),
            "versions": versions(),
            **overrides,
        }
    )


def ledger_of(asked: AgentRequest) -> disclosure.Disclosures:
    rows = disclosure.Disclosures.of(asked, policy=SEND_POLICY)
    rows.record_model_call(
        model="model-under-test",
        disclosed_to=ENDPOINT,
        prompt=b'{"messages": []}',
        messages=2,
        at=ASSESSED_AT,
    )
    return rows


def store_pass(
    connection: psycopg.Connection,
    context: str,
    *,
    prices: budgets.PriceTable = NO_PRICES,
    triage_outcome: AgentResult | AgentFailure | None = None,
    analysis: AgentResult | AgentFailure | None = None,
    trigger: str = "triage_suspicious",
    retrievals: tuple[RetrievalStep, ...] = (),
) -> tuple[str, ...]:
    """One pass over one synthetic context, written by the real writer."""
    asked = a_request(context)
    outcome = a_result(TRIAGE) if triage_outcome is None else triage_outcome
    if analysis is None:
        assessment = orchestration.Assessment(
            request=asked,
            escalation=None,
            triage=outcome,
            triage_disclosures=ledger_of(asked),
            trigger=None,
            analyst_request=None,
            analysis=None,
            analyst_disclosures=None,
        )
    else:
        escalated = orchestration.analyst_request(
            asked,
            trigger=trigger,
            prompt_version=ANALYST_PROMPT.version,
            granted=BUDGET_POLICY.for_emitter(ANALYST),
        )
        assessment = orchestration.Assessment(
            request=asked,
            escalation=None,
            triage=outcome,
            triage_disclosures=ledger_of(asked),
            trigger=escalated.trigger,
            analyst_request=escalated,
            analysis=analyst.Analysis(
                outcome=analysis, decision=None, retrievals=retrievals
            ),
            analyst_disclosures=ledger_of(escalated),
        )
    written = orchestration.AssessmentStore(connection, prices=prices).store(
        assessment, at=ASSESSED_AT
    )
    connection.execute("FLUSH")
    return written


@pytest.mark.integration
def test_the_run_metrics_carry_latency_tokens_retries_and_cost_per_model(
    migrated_engine: psycopg.Connection,
):
    """`concept/06-technology.md`: latency and cost per context, per model.

    Two triage runs on one model, one of which spent two bounded retries. The
    grain is the model, so both land on one row, and the price table is the one
    the runs were stored under — `AssessmentStore` derives the figure and records
    the revision that derived it.
    """
    store_pass(migrated_engine, "1" * 64, prices=PRICED)
    store_pass(
        migrated_engine,
        "2" * 64,
        prices=PRICED,
        triage_outcome=a_result(TRIAGE, cost=a_cost(retries=2, wall_clock_seconds=1.5)),
    )

    (run,) = a_store(migrated_engine).runs()
    assert (run.emitter, run.model_requested) == (TRIAGE, "model-under-test")
    assert run.model_version == "model-under-test-2026-05"
    assert (run.runs, run.verdicts, run.typed_failures) == (2, 2, 0)
    assert run.latency_seconds_total == pytest.approx(2.0)
    assert run.mean_latency_seconds == pytest.approx(1.0)
    assert (run.latency_seconds_min, run.latency_seconds_max) == (0.5, 1.5)
    assert (run.prompt_tokens, run.completion_tokens) == (80, 40)
    assert (run.retries, run.runs_with_retries) == (2, 1)
    assert run.schema_retry_rate == pytest.approx(0.5)
    assert run.retries_per_run == pytest.approx(1.0)
    assert run.runs_priced == 2
    assert run.model_cost_currency == "USD"
    assert run.model_prices_version == PRICED.version
    assert run.mean_cost > 0.0


@pytest.mark.integration
def test_an_unpriced_model_reports_no_cost_and_never_a_cost_of_zero(
    migrated_engine: psycopg.Connection,
):
    """`config/policy.toml` is silent about this endpoint's price, on purpose.

    `helena.budgets.PriceTable` says why: an invented figure is worse than an
    absent one. The three money columns are null together and the metric has to
    carry that through rather than summing nulls into a zero.
    """
    store_pass(migrated_engine, "1" * 64)
    (run,) = a_store(migrated_engine).runs()
    assert run.model_cost_total is None
    assert (run.runs_priced, run.runs_unpriced) == (0, 1)
    with pytest.raises(ValueError, match="free"):
        run.mean_cost


@pytest.mark.integration
def test_a_typed_failure_is_counted_as_one_and_carries_no_verdict(
    migrated_engine: psycopg.Connection,
):
    """`concept/instruction.md` §7: every failure path typed, stored and countable.

    Two failures of two different reasons stay two rows: the reasons are values
    rather than columns, so a reason nobody added to a `CASE` still appears.
    """
    store_pass(migrated_engine, "1" * 64, triage_outcome=a_failure())
    store_pass(
        migrated_engine,
        "2" * 64,
        triage_outcome=a_failure(
            reason=SCHEMA_INVALID,
            detail="the answer never validated",
            # `schema_invalid` means the model answered and the answer never
            # validated, so the identity that answered is known and the contract
            # requires it. `model_unavailable` above is the one where nothing
            # answered at all.
            model_version="model-under-test-2026-05",
            cost=a_cost(retries=3, prompt_tokens=0, completion_tokens=0),
        ),
    )

    store = a_store(migrated_engine)
    failures = {row.failure_reason: row.failures for row in store.failures()}
    assert failures == {MODEL_UNAVAILABLE: 1, SCHEMA_INVALID: 1}
    assert set(failures) <= set(FAILURE_REASONS)

    # `model_version` is null exactly where nothing answered, so the two failures
    # group apart: one row for the model that answered badly, one for the model
    # that did not answer. That split is the point of having both model columns.
    silent, answered = sorted(store.runs(), key=lambda run: run.model_version or "")
    assert silent.model_version is None
    assert (silent.runs, silent.verdicts, silent.typed_failures) == (1, 0, 1)
    assert answered.model_version == "model-under-test-2026-05"
    assert (answered.runs, answered.verdicts, answered.typed_failures) == (1, 0, 1)
    assert answered.retries == 3
    assert answered.typed_failure_rate == pytest.approx(1.0)


@pytest.mark.integration
def test_the_escalation_counter_is_analyst_runs_over_triage_runs(
    migrated_engine: psycopg.Connection,
):
    """`concept/01-goal-and-scope.md` measures the system on escalation rate.

    Three passes, two escalated, and the two triggers counted apart:
    `triage_suspicious` is triage asking for a second opinion and
    `deterministic_signal` is the rule firing independently of what triage said
    (`concept/07-principles.md`). One number would hide a deployment whose
    deterministic escalations had stopped.
    """
    store_pass(migrated_engine, "1" * 64)
    store_pass(migrated_engine, "2" * 64, analysis=a_result(ANALYST))
    store_pass(
        migrated_engine,
        "3" * 64,
        analysis=a_result(ANALYST),
        trigger="deterministic_signal",
    )

    escalation = a_store(migrated_engine).escalation()
    assert escalation is not None
    assert (escalation.triaged, escalation.escalated) == (3, 2)
    assert escalation.by_triage_suspicious == 1
    assert escalation.by_deterministic_signal == 1
    assert escalation.rate == pytest.approx(2 / 3)


@pytest.mark.integration
def test_nothing_assessed_is_no_escalation_counter_rather_than_a_rate_of_zero(
    migrated_engine: psycopg.Connection,
):
    assert a_store(migrated_engine).escalation() is None


@pytest.mark.integration
def test_the_retrieval_metrics_keep_cache_hits_live_queries_and_failures_apart(
    migrated_engine: psycopg.Connection,
):
    """`concept/07-principles.md`: two runs differing only in cache state must be
    distinguishable afterwards — and a typed error is never `no_match`.

    One trace with one of each: a cache hit that produced evidence, and a live
    query that produced a typed error and no taxonomy object.
    """
    store_pass(
        migrated_engine,
        "1" * 64,
        analysis=a_result(
            ANALYST,
            cost=a_cost(live_queries=1, cache_hits=1),
            retrieval_trace=(
                RetrievalStep(
                    source_id="threatfox",
                    entity_type="domain",
                    entity_value="example.invalid",
                    outcome=CACHE_HIT,
                    retrieved_at=ASSESSED_AT - timedelta(hours=2),
                    evidence_id=RETRIEVED,
                ),
                RetrievalStep(
                    source_id="threatfox",
                    entity_type="domain",
                    entity_value="example.invalid",
                    outcome=LIVE_QUERY,
                    retrieved_at=ASSESSED_AT,
                    failure=QueryFailure(
                        source_id="threatfox",
                        entity_type="domain",
                        entity_value="example.invalid",
                        reason="timeout",
                        detail="the provider did not answer",
                    ),
                ),
            ),
        ),
    )

    store = a_store(migrated_engine)
    (retrieval,) = store.retrievals()
    assert (retrieval.emitter, retrieval.source_id) == (ANALYST, "threatfox")
    assert (retrieval.steps, retrieval.cache_hits, retrieval.live_queries) == (2, 1, 1)
    assert (retrieval.answered, retrieval.failures) == (1, 1)
    assert retrieval.cache_hit_ratio == pytest.approx(0.5)
    assert retrieval.failure_rate == pytest.approx(0.5)
    assert retrieval.oldest_retrieved_at == ASSESSED_AT - timedelta(hours=2)

    # The same two facts one level up, off the assessment's own columns.
    analyst_run = next(run for run in store.runs() if run.emitter == ANALYST)
    assert (analyst_run.cache_hits, analyst_run.live_queries) == (1, 1)
    assert analyst_run.cache_hit_ratio == pytest.approx(0.5)


# --- Staleness ---------------------------------------------------------------


@pytest.mark.integration
def test_a_snapshot_past_its_schedule_reports_its_age_and_how_far_behind(
    migrated_engine: psycopg.Connection,
):
    """`stale` is a boolean over a threshold; the age is the number to act on.

    The extract is loaded through the real loader with an `attempted_at` three
    refresh intervals in the past, so the snapshot is genuinely old rather than
    edited to look old.
    """
    loaded_at = datetime.now(timezone.utc) - timedelta(
        seconds=3 * THREATFOX_MIN_FETCH_INTERVAL_SECONDS
    )
    load_threatfox(
        migrated_engine,
        tenant=TENANT,
        sensor=SENSOR,
        source_url=FEED_URL,
        redactor=Redactor.from_settings(settings()),
        raw=RAW,
        now=loaded_at,
    )
    migrated_engine.execute("FLUSH")

    (feed,) = a_store(migrated_engine).feeds()
    assert feed.source_id == "threatfox"
    assert feed.status == STALE
    assert feed.attempts == 1
    assert feed.last_failure_at is None
    assert feed.snapshot_version is not None
    assert feed.refresh_interval_seconds == THREATFOX_MIN_FETCH_INTERVAL_SECONDS
    assert feed.age_seconds == pytest.approx(
        3 * THREATFOX_MIN_FETCH_INTERVAL_SECONDS, rel=0.05
    )
    assert feed.intervals_behind == pytest.approx(3.0, rel=0.05)


@pytest.mark.integration
def test_a_source_whose_every_load_failed_is_missing_and_says_when_it_last_tried(
    migrated_engine: psycopg.Connection,
):
    """The row `helena_reference_feed_snapshot_current` cannot produce.

    That view inner-joins onto the newest attempt that produced a snapshot, so a
    source that has never loaded has no row there at all and is invisible to
    anything reading it. `missing` is not `stale` and not `failed`
    (`concept/instruction.md` §2), and "the loader runs and fails" is not
    "nobody has run the loader" — `attempts` and `last_failure_at` are what tell
    them apart.
    """
    for minutes in (30, 10):
        migrated_engine.execute(
            f"INSERT INTO {FEED_SNAPSHOT_TABLE} (tenant, sensor, source_id, "
            f"attempted_at, source_url, outcome, snapshot_version, counts, "
            f"failure_reason, failure_detail) "
            f"VALUES (%s, %s, %s, %s, %s, 'failed', NULL, NULL, %s, %s)",
            (
                TENANT,
                SENSOR,
                "threatfox",
                datetime.now(timezone.utc) - timedelta(minutes=minutes),
                FEED_URL,
                "fetch_failed",
                "the endpoint did not answer",
            ),
        )
    migrated_engine.execute("FLUSH")

    (feed,) = a_store(migrated_engine).feeds()
    assert feed.status == MISSING
    assert feed.attempts == 2
    assert feed.snapshot_version is None
    assert feed.snapshot_at is None
    assert feed.age_seconds is None
    assert feed.last_failure_at == feed.last_attempt_at
    with pytest.raises(ValueError, match="not the same thing as old"):
        feed.age


# --- The whole chain ---------------------------------------------------------


@pytest.mark.integration
def test_the_reconciliation_compares_the_capture_the_store_and_the_sink(
    migrated_engine: psycopg.Connection, tmp_path: Path
):
    """`concept/07-principles.md`: record counts reconciled, produced to materialised.

    The whole chain in one object, and the terms really do come from three
    engine layers and from the file system: the capture count is read off the
    retained file, the ingest terms off the source layer, the contexts off the
    signal layer and the emittable message off the analytical one.
    """
    path = restamped(tmp_path, extra=b"{not json at all}\n")
    records = ingest(migrated_engine, path)
    captures = scan_captures(tmp_path)

    context = migrated_engine.execute(
        "SELECT context_id, context_version FROM helena_signal_host_context_live "
        "WHERE tenant = %s AND sensor = %s ORDER BY window_start LIMIT 1",
        (TENANT, SENSOR),
    ).fetchone()
    assert context, "the capture produced no live context"
    store_pass(migrated_engine, context[0])

    reconciliation = a_store(migrated_engine).pipeline(captures=captures)
    assert reconciliation is not None
    assert reconciliation.captures == 1
    assert reconciliation.captures_absent == 0
    assert reconciliation.capture_records == records
    assert reconciliation.quarantined == 1
    assert reconciliation.normalized == records - 1
    assert reconciliation.admitted == records
    assert reconciliation.unaccounted == 0
    assert reconciliation.contexts >= 1
    assert reconciliation.context_records <= reconciliation.normalized
    assert reconciliation.unaggregated == (
        reconciliation.normalized - reconciliation.context_records
    )
    assert (reconciliation.assessments, reconciliation.assessed_contexts) == (1, 1)


@pytest.mark.integration
def test_the_reconciliation_without_a_capture_directory_says_so(
    migrated_engine: psycopg.Connection, tmp_path: Path
):
    path = restamped(tmp_path)
    ingest(migrated_engine, path)

    reconciliation = a_store(migrated_engine).pipeline()
    assert reconciliation is not None
    assert reconciliation.capture_records is None
    with pytest.raises(ValueError, match="no capture directory was read"):
        reconciliation.unaccounted


@pytest.mark.integration
def test_an_empty_store_has_no_reconciliation_row_at_all(
    migrated_engine: psycopg.Connection,
):
    """A deployment that has ingested nothing is not a deployment reading zero.

    The counter is over contexts and assessments; with neither, there is no row,
    and `helena status` prints the sentence rather than a screen of zeros.
    """
    assert a_store(migrated_engine).pipeline() is None


# --- The report and the command ----------------------------------------------


@pytest.mark.integration
def test_the_report_carries_the_retention_rejection_rate_and_the_emission_count(
    migrated_engine: psycopg.Connection, tmp_path: Path
):
    """Two of `concept/07`'s seven were already built, and are read, not rebuilt.

    The rejection rate is `helena_signal_retention_rejections` through
    `helena.context.ContextStore.rejections`, and the engine-side emission count
    is `helena_analytical_emission_counts` through `helena.sink.SinkStore.pending`.
    A second copy of either would be a second number to disagree with the first.
    """
    path = restamped(tmp_path)
    ingest(migrated_engine, path)

    report = status.report(
        migrated_engine,
        identity(),
        read_at=datetime.now(timezone.utc),
        captures=scan_captures(tmp_path),
    )
    assert report.rejections.records > 0
    # The capture was re-stamped into the current window, so nothing is outside
    # the boundary and the rate is a real 0.0 rather than a refusal.
    assert report.rejections.rate == 0.0
    assert report.rejections.horizon == timedelta(hours=24)
    assert report.emittable == 0
    assert report.pipeline is not None
    assert report.pipeline.emittable == report.emittable


@pytest.mark.integration
def test_the_rendered_report_prints_the_refusal_where_a_rate_cannot_be_computed(
    migrated_engine: psycopg.Connection,
):
    """An empty store renders, and says what is empty rather than printing zeros.

    This is the whole argument for the refusals: a report that swallowed them
    would print `0.000` for the escalation rate of a deployment that has never
    triaged anything, and nobody reading it would know.
    """
    rendered = status.render(
        status.report(
            migrated_engine, identity(), read_at=datetime.now(timezone.utc)
        )
    )
    for heading in (
        "PIPELINE",
        "RETENTION BOUNDARY",
        "FEEDS",
        "RUNS",
        "TYPED FAILURES",
        "ESCALATION",
        "RETRIEVAL",
    ):
        assert heading in rendered
    assert "nothing ingested and nothing assessed" in rendered
    assert "nothing has been triaged" in rendered
    assert "0.000" not in rendered.split("RETENTION BOUNDARY")[1].split("FEEDS")[0]


@pytest.mark.integration
def test_the_rendered_report_carries_every_number_of_a_live_deployment(
    migrated_engine: psycopg.Connection, tmp_path: Path
):
    path = restamped(tmp_path, extra=b"{not json at all}\n")
    ingest(migrated_engine, path)
    store_pass(
        migrated_engine,
        "1" * 64,
        prices=PRICED,
        analysis=a_result(
            ANALYST,
            cost=a_cost(live_queries=1, cache_hits=1),
            retrieval_trace=(
                RetrievalStep(
                    source_id="threatfox",
                    entity_type="domain",
                    entity_value="example.invalid",
                    outcome=CACHE_HIT,
                    retrieved_at=ASSESSED_AT,
                    evidence_id=RETRIEVED,
                ),
            ),
        ),
    )

    rendered = status.render(
        status.report(
            migrated_engine,
            identity(),
            read_at=datetime.now(timezone.utc),
            captures=scan_captures(tmp_path),
        )
    )
    assert "quarantined       1" in rendered
    assert f"{TENANT} / {SENSOR}" in rendered
    assert "escalated         1" in rendered
    assert "threatfox" in rendered


def test_the_status_command_is_runnable_and_takes_a_capture_directory():
    """The command exists, imports and parses its arguments.

    `--help` returns before `Settings.load`, so this needs no environment and no
    engine — what it proves is that `scripts/status.py` is importable and that
    the one flag the reconciliation depends on is really there. What the command
    prints is `helena.status.render`, which the two tests above execute.
    """
    finished = subprocess.run(
        [sys.executable, str(PROJECT_ROOT / "scripts" / "status.py"), "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert finished.returncode == 0, finished.stderr
    assert "--captures" in finished.stdout
