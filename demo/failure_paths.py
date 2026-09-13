#!/usr/bin/env python3
"""Four things going wrong, and not one of them becoming a verdict.

    demo/run-demo 6
    uv run demo/failure_paths.py

The failure modes this project exists to prevent are the quiet ones: a record
that vanishes, an outage that reads as a clean result, a model that fails its
schema and gets a `normal` written for it anyway. Each of the four below is made
to happen on purpose, and what is printed is **what the pipeline did with it**.

  | # | What goes wrong | What must happen |
  | --- | --- | --- |
  | 1 | a record the input contract refuses | quarantined with a typed reason, **and the stream keeps running** |
  | 2 | the feed is unreachable | a typed `failed` status — never `no_match`, and the previous snapshot is left alone |
  | 3 | the model answers something the schema refuses, three times | a typed failure with **no verdict**, emitted rather than dropped |
  | 4 | the rendering does not fit its budget | truncation that is **visible** in what the agent was shown |

`concept/07-principles.md` has all four as must-never-happen rows, and
`tests/test_conformance.py` asserts them. This is the same four run where a
reader can watch them.

## What it does not show

**Nothing about verdict quality**, and in run 3 nothing about model behaviour
either: the endpoint is scripted, so the invalid answer is an input to this demo
rather than something a model happened to do.

Maturity: experimental — a demonstration, not a tested component. All four are
covered by `tests/test_conformance.py` (MNH-01, MNH-02, MNH-06 and the
quarantine rows) and by `tests/test_normalizer.py`; this script is exercised by
running it.
"""

from __future__ import annotations

import io
import json
import sys
import tempfile
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from _common import (  # noqa: E402
    BOLD,
    DIM,
    GREEN,
    RED,
    RESET,
    YELLOW,
    answered,
    banner,
    current_window,
    enrichment_rows,
    ingest,
    live_contexts,
    load_feed,
    load_suffixes,
    note,
    print_states,
    rule,
    said,
    sample_records,
    schema,
    Scripted,
    settings_for,
    stage,
    stage_capture,
    utc,
)

from helena import (  # noqa: E402
    agents,
    analyst,
    budgets,
    disclosure,
    enrichment,
    observability,
    orchestration,
    policy,
    rendering,
    sink,
    triage,
)
from helena.agents import ModelClient  # noqa: E402
from helena.contracts.v1 import (  # noqa: E402
    CONTRACT_VERSION,
    SCHEDULED_TRIAGE,
    AgentRequest,
    RequestVersions,
)
from helena.observability import Redactor  # noqa: E402
from helena.policy import v1 as policy_v1  # noqa: E402
from helena.rendering import v1 as rendering_v1  # noqa: E402
from helena.taxonomy import TRIAGE  # noqa: E402
from helena import hosts  # noqa: E402

#: Small enough that the sample's own entity list cannot fit, so truncation is a
#: property of the budget rather than of a capture chosen to overflow one.
TIGHT_BUDGET = rendering.RenderingBudget(characters=1200)


def main() -> int:
    print(f"{BOLD}MAESTRO HELENA — four failures, and what became of each{RESET}")
    rule()
    window = current_window()
    records = sample_records()

    # Run 3 needs three invalid answers: `config/agents.toml` allows three
    # attempts, and the run has to end on a typed failure rather than mid-retry.
    script = [answered(said(verdict="probably fine", note="not the schema")) for _ in range(3)]
    with Scripted(script) as endpoint:
        settings = settings_for(model_url=endpoint.url)
        with schema(settings) as (connection, name):
            suffixes = load_suffixes(
                connection, settings, when=utc(window) - timedelta(minutes=5)
            )

            # --- 1. a record the contract refuses -------------------------
            stage(1, "A malformed record — quarantined, and the stream keeps running")
            broken = json.loads(json.dumps(records[0]))
            broken["id"] = "malformed.1"
            broken["not_a_field_the_contract_knows"] = "surprise"
            with tempfile.TemporaryDirectory(prefix="helena-demo-") as staging:
                capture = stage_capture(
                    [*records, broken], Path(staging), window=window
                )
                counts = ingest(settings, connection, capture)
            print(f"  records in the capture   {counts.records}")
            print(f"  normalized into events   {counts.normalized}")
            print(f"  {YELLOW}quarantined{RESET}              "
                  f"{counts.quarantine.quarantined}")
            rows = connection.execute(
                "SELECT reason, count(*) FROM helena_ingest_quarantine "
                "GROUP BY reason ORDER BY reason"
            ).fetchall()
            for reason, count in rows:
                print(f"    {YELLOW}{reason}{RESET}  x{count}")
            print(f"  {GREEN}the other {counts.normalized} records reached the store{RESET}")
            note("input drift surfaces as a typed row; it is never coerced away")

            # --- 2. the feed is unreachable --------------------------------
            stage(2, "The feed is unreachable — `failed`, which is not `no_match`")
            load = load_feed(
                connection,
                settings,
                when=utc(window) - timedelta(minutes=2),
                url="https://threatfox.invalid/export/json/recent/",
            )
            print(f"  outcome      {RED}{load.outcome}{RESET}: {load.failure_reason}")
            connection.execute("FLUSH")
            live_contexts(connection)
            note("every entity's enrichment status, with the feed down:")
            print_states(enrichment_rows(connection))
            note("`failed` — an outage is execution state, never security meaning")

            # A real snapshot now, so runs 3 and 4 have something to render.
            good = load_feed(connection, settings, when=utc(window) - timedelta(minutes=1))
            if good.outcome == enrichment.FAILED:
                raise SystemExit(f"the live feed did not load: {good.failure_reason}")
            connection.execute("FLUSH")
            (snapshot,) = connection.execute(
                "SELECT snapshot_version FROM helena_reference_feed_snapshot_validity "
                "WHERE tenant = %s AND sensor = %s AND valid_from <= %s "
                "AND (valid_to IS NULL OR valid_to > %s)",
                (settings.identity.tenant, settings.identity.sensor,
                 utc(window), utc(window)),
            ).fetchone()

            contexts = live_contexts(connection)
            store = rendering.RenderingStore(connection=connection, identity=settings.identity)
            projection = store.project(contexts[0])

            # --- 4. truncation, shown before the run that uses it ----------
            stage(3, "A rendering that does not fit — truncation is visible or it is a bug")
            full = rendering_v1.render(
                projection, hosts.load().attributes_for(projection.host), rendering.budget()
            )
            tight = rendering_v1.render(
                projection, hosts.load().attributes_for(projection.host), TIGHT_BUDGET
            )
            for label, rendered, budget in (
                ("configured", full, rendering.budget().characters),
                ("tightened", tight, TIGHT_BUDGET.characters),
            ):
                size = sum(len(section.body) for section in rendered.sections)
                print(f"  {label:<11} {size:>6} chars against a budget of {budget}")
            marks = [
                line
                for section in tight.sections
                for line in section.body.splitlines()
                if "truncat" in line.lower()
            ]
            if marks:
                print(f"  {GREEN}the agent is told, in the rendering it was given:{RESET}")
                for line in marks[:3]:
                    print(f"    {YELLOW}{line.strip()[:70]}{RESET}")
            else:
                print(f"  {DIM}the tightened rendering still fit; nothing was cut{RESET}")

            # --- 3. the model fails its schema -----------------------------
            stage(4, "The model answers something the schema refuses, three times")
            (aggregation,) = connection.execute(
                "SELECT aggregation_version FROM helena_signal_host_context_live "
                "WHERE tenant = %s AND sensor = %s AND context_id = %s",
                (projection.tenant, projection.sensor, projection.context_id),
            ).fetchone()
            budget_policy = budgets.load()
            triage_prompt, analyst_prompt = triage.version("v1"), analyst.version("v1")
            asked = AgentRequest(
                tenant=projection.tenant,
                sensor=projection.sensor,
                emitter=TRIAGE,
                host=projection.host,
                window_start=projection.statistics.window_start,
                window_end=projection.statistics.window_end,
                context_id=projection.context_id,
                context_version=projection.context_version,
                trigger=SCHEDULED_TRIAGE,
                rendering=full,
                budgets=budget_policy.for_emitter(TRIAGE),
                versions=RequestVersions(
                    prompt_version=triage_prompt.version,
                    schema_version=CONTRACT_VERSION,
                    rendering_version=rendering_v1.RENDERING_VERSION,
                    taxonomy_version="v1",
                    enrichment_snapshot_version=snapshot,
                    normalization_snapshot_version=suffixes.snapshot_version,
                    policy_version=policy_v1.POLICY_VERSION,
                    aggregation_version=aggregation,
                    model_requested=settings.triage.model,
                ),
            )
            # Disabled: this context holds no claim, so the configured gate would
            # clear it and no model would ever be asked -- and the failure this
            # demo is about is one only a model can produce. The gate has its own
            # demo (5); mixing the two would show neither.
            gate = policy.TriageGate(
                policy_version=policy_v1.POLICY_VERSION,
                triage_gate_version="demo-disabled",
                min_suspicious_indicators=0,
            )
            logger = observability.StructuredLogger(
                component="demo",
                tenant=settings.identity.tenant,
                sensor=settings.identity.sensor,
                redactor=Redactor.from_settings(settings),
                stream=io.StringIO(),
            )
            assessment = orchestration.assess(
                asked,
                projection=projection,
                triage_client=ModelClient.for_agent(settings, "triage"),
                analyst_client=ModelClient.for_agent(settings, "analyst"),
                retry=agents.RetryPolicy(attempts=3),
                triage_prompt=triage_prompt,
                analyst_prompt=analyst_prompt,
                provider_tools=(),
                thresholds=policy.thresholds(),
                budget_policy=budget_policy,
                send_policy=disclosure.send_policy(),
                inherit=analyst.Inheritance(inherit_triage_rationale=False),
                logger=logger,
                triage_gate=gate,
            )
            outcome = assessment.triage
            reason = getattr(outcome, "reason", None)
            print(f"  attempts     {endpoint.calls} (the model was asked "
                  f"{endpoint.calls} time(s))")
            if reason is None:
                raise SystemExit(
                    "triage did not produce a typed failure, so there is nothing "
                    "here to show. This demo refuses to print its conclusions "
                    "over a run that did not produce them."
                )
            print(f"  triage       {RED}typed failure{RESET}: {reason}")
            print(f"  verdict      {BOLD}none{RESET} — a failed run is never given one")

            stage(5, "It is emitted anyway — a failure a consumer never sees is a drop")
            assessments = orchestration.AssessmentStore(
                connection=connection, prices=budgets.model_prices()
            )
            from datetime import datetime, timezone

            assessments.store(assessment, at=datetime.now(timezone.utc))
            connection.execute("FLUSH")
            # `pending` is a COUNT asked of the engine and `terminal` is the
            # identifiers, which is the seam `concept/03` wants: emission is
            # observable from the engine side rather than from the broker.
            sink_store = sink.SinkStore(connection=connection, identity=settings.identity)
            print(f"  pending      {sink_store.pending()} message(s) to emit")
            for identifier in sink_store.terminal()[:1]:
                message = sink_store.project(identifier)
                print(f"  outcome_kind {BOLD}{message.outcome_kind}{RESET}")
                print(f"  verdict      {message.verdict if message.verdict else '—'}")
                print(f"  failure      {RED}{message.failure_reason}{RESET}")
                print(f"  caveat       {DIM}{message.caveat[:64]}…{RESET}")

            banner("WHAT THE FOUR SHOW")
            # Every number below is read off this run. A closing paragraph that
            # restated the intended story would keep asserting it after the code
            # stopped producing it -- which is what happened here on the first
            # run, when the gate cleared the context and the text still claimed a
            # typed failure.
            emitted = sink_store.project(sink_store.terminal()[0])
            print(
                f"\n{DIM}  {counts.quarantine.quarantined} record(s) quarantined with a typed reason, and the other\n"
                f"  {counts.normalized} kept flowing.\n\n"
                f"  An unreachable feed produced `{load.outcome}` and not `no_match` —\n"
                f"  execution state is not security meaning.\n\n"
                f"  A rendering of {sum(len(s.body) for s in full.sections)} characters cut to "
                f"{sum(len(s.body) for s in tight.sections)} said so in the\n"
                f"  text the agent was given, on {len(marks)} line(s).\n\n"
                f"  A model asked {endpoint.calls} time(s) failed the schema every time and\n"
                f"  produced `{emitted.outcome_kind}` / `{emitted.failure_reason}` with\n"
                f"  verdict `{emitted.verdict}` — which still left through the sink.\n\n"
                f"  Every one of those is a row in concept/07's must-never-happen table,\n"
                f"  and tests/test_conformance.py is where they are asserted rather than\n"
                f"  demonstrated.{RESET}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
