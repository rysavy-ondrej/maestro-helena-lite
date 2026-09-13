#!/usr/bin/env python3
"""A stored assessment read back against the versions it recorded — not today's.

    demo/run-demo 7
    uv run demo/replay_an_assessment.py

`concept/instruction.md` §2: **replay validates against the version the
assessment recorded, never against current code.** Historical schema classes are
retained frozen, and migrating old rows forward is forbidden.

This assesses one context, stores it, and then reads it back three ways:

  1. **`read_assessment`** — the row and its children, validated against the
     contract version the row names. Nothing is called.
  2. **`reconstruct`** — the request rebuilt by re-rendering the recorded context
     version under the recorded rendering version, then paired with the stored
     outcome under *that* version's `check_exchange`. Still nothing is called.
  3. **`rerun`** — the same request asked again, with the recorded prompt, and
     **no live provider lookup**: a replay that re-queried a provider would be a
     new investigation with a different answer.

Then `compare` says which dimensions moved. **A difference is a measurement, not
a failure.** The model is not deterministic, which is why `concept/01` puts
*"that identical inputs replay identically"* on the not-claimable list — and why
this demo scripts the endpoint, so the one thing that varies is chosen rather
than stumbled into.

## What it does not show

**Not that replay is bit-identical**, which is not claimable. **Nothing about
verdict quality.** The refusals replay makes on a row it cannot honour — an
unknown `schema_version`, a projection at another `context_version`, a citation
the rebuilt rendering no longer shows — are `tests/test_replay.py`'s, which
induces each; this shows the path that succeeds and names the four.

Maturity: experimental — a demonstration, not a tested component. The four
refusals and the comparison are covered by `tests/test_replay.py`; this script is
exercised by running it.
"""

from __future__ import annotations

import io
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from _common import (  # noqa: E402
    BOLD,
    DIM,
    GREEN,
    RESET,
    YELLOW,
    answered,
    banner,
    current_window,
    ingest,
    live_contexts,
    load_feed,
    load_suffixes,
    note,
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
    hosts,
    observability,
    orchestration,
    policy,
    rendering,
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

#: What the scripted model says, twice: once for the run and once for the replay.
#: Identical on purpose — so that `compare` reporting "nothing moved" is a fact
#: about this run rather than a property of replay that nobody may claim.
ANSWER = said(classification="normal", confidence=0.87)


def main() -> int:
    print(f"{BOLD}MAESTRO HELENA — replaying a stored assessment{RESET}")
    rule()
    window = current_window()

    with Scripted([answered(ANSWER), answered(ANSWER)]) as endpoint:
        settings = settings_for(model_url=endpoint.url)
        with schema(settings) as (connection, name):
            stage(1, "Assess one context and store it")
            suffixes = load_suffixes(
                connection, settings, when=utc(window) - timedelta(minutes=5)
            )
            with tempfile.TemporaryDirectory(prefix="helena-demo-") as staging:
                capture = stage_capture(sample_records(), Path(staging), window=window)
                ingest(settings, connection, capture)
            load = load_feed(connection, settings, when=utc(window) - timedelta(minutes=1))
            if load.outcome == enrichment.FAILED:
                raise SystemExit(f"the feed did not load: {load.failure_reason}")
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
                rendering=rendering_v1.render(
                    projection,
                    hosts.load().attributes_for(projection.host),
                    rendering.budget(),
                ),
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
                # Disabled: this demo is about replay, and a gated context has no
                # model answer to replay. `docs/decisions/0047` is the gate.
                triage_gate=policy.TriageGate(
                    policy_version=policy_v1.POLICY_VERSION,
                    triage_gate_version="demo-disabled",
                    min_suspicious_indicators=0,
                ),
            )
            assessments = orchestration.AssessmentStore(
                connection=connection, prices=budgets.model_prices()
            )
            written = assessments.store(assessment, at=datetime.now(timezone.utc))
            connection.execute("FLUSH")
            identifier = written[0] if isinstance(written, (list, tuple)) else written
            print(f"  context      {projection.context_id[:24]}…")
            print(f"  assessment   {str(identifier)[:24]}…")
            print(f"  model calls  {endpoint.calls}")

            stage(2, "Read it back — nothing is called")
            stored = orchestration.read_assessment(connection, str(identifier))
            recorded = stored.versions if hasattr(stored, "versions") else None
            print(f"  {GREEN}validated against the contract version the ROW names{RESET}")
            if recorded is not None:
                for field in (
                    "schema_version", "prompt_version", "rendering_version",
                    "taxonomy_version", "policy_version", "aggregation_version",
                ):
                    value = getattr(recorded, field, None)
                    if value is not None:
                        print(f"    {field:<28} {value}")
            note("not today's constants — the row's own, which is the whole rule")

            stage(3, "Rebuild the request from the versions the row recorded")
            rebuilt = orchestration.reconstruct(
                stored,
                projection=projection,
                attributes=hosts.load().attributes_for(projection.host),
                budget=rendering.budget(),
            )
            print(f"  {GREEN}the rendering was re-rendered, not stored{RESET}")
            note("the context reference and its version are what make replay possible")
            print(f"  sections     {len(rebuilt.rendering.sections)}")

            stage(4, "Ask it again — the recorded prompt, and no live lookup")
            replayed = orchestration.rerun(
                stored,
                rebuilt,
                client=ModelClient.for_agent(settings, "triage"),
                retry=agents.RetryPolicy(attempts=3),
                send_policy=disclosure.send_policy(),
                projection=projection,
                provider_tools=(),
            )
            print(f"  model calls  {endpoint.calls} total "
                  f"({endpoint.calls - 1} for the original run)")
            note("provider_tools=() — a replay that re-queried a provider would be")
            note("a new investigation with a different answer, not a replay")

            stage(5, "Compare")
            # `compare` takes the two OUTCOMES, not the two containers: it reads
            # `classification` and `reason` off them and refuses an object that
            # is neither kind, which is how it keeps a verdict and a typed
            # failure from being diffed into each other.
            differences = orchestration.compare(stored.outcome, replayed.outcome)
            if not differences:
                print(f"  {GREEN}nothing moved{RESET} across the compared dimensions")
                note("which is a fact about THIS run against a scripted endpoint —")
                note("`identical inputs replay identically` is NOT claimable")
            else:
                for difference in differences:
                    print(f"  {YELLOW}{difference}{RESET}")

            banner("WHAT REPLAY REFUSES")
            print(
                f"\n{DIM}  Four refusals, none of them softened into a best effort, and each\n"
                f"  induced in tests/test_replay.py rather than described there:\n\n"
                f"    a `schema_version` this tree does not hold   -> UnknownVersion\n"
                f"    a row that does not fit the version it names -> ReplayError\n"
                f"    a projection at another `context_version`    -> ReplayError\n"
                f"    a citation the rebuilt rendering lost        -> ReplayError\n\n"
                f"  Nothing is migrated forward. A stored assessment validated against\n"
                f"  today's code would be scored under rules it never ran.{RESET}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
