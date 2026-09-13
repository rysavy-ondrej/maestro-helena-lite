#!/usr/bin/env python3
"""What survives, what rebuilds itself, and what a capture replay does not bring back.

    demo/run-demo 8
    uv run demo/backup_and_restore.py

Findings and evidence exist only in the streaming engine, which makes durability
a **correctness** concern rather than an ops detail. This builds a pipeline state,
backs it up, restores it into a second schema, and compares the two — then does
the thing that is easy to assume works and does not.

**The measurement worth watching is the negative one.** The retained captures
back up the store's *input*, not the store. Replaying a capture into an empty
schema reconstructs the events and **no assessment, no snapshot and no evidence
row** — which is exactly why the engine has to be backed up at all, and is the
half an operator is most likely to discover during a recovery rather than before
one.

Three things are shown:

  1. a backup taken from a live schema and **verified** — the trailer carries the
     body digest, so a truncated file is detectable rather than merely short;
  2. a restore into a separately migrated schema, with every relation compared;
  3. a capture replay on its own, into a third schema, and what is missing.

`docs/decisions/0040-durability-and-backup.md` is the model and
`docs/runbook.md` §15 is the procedure. The broker and the output topic are
**excluded** from the durability model by decision: the broker retains nothing
that can be relied on, and the output topic is egress.

## What it does not show

**Not a restore at production scale.** The recovery time here is a fixture's and
is dominated by applying the migrations rather than by moving data, so it does
not extrapolate. **Nothing about verdict quality.**

Maturity: experimental — a demonstration, not a tested component. The rehearsal
it performs is covered by `tests/test_durability.py`, which asserts every
relation; this script is exercised by running it.
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
    durability,
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

def build_state(settings, connection, window: float, endpoint) -> str:
    """One assessed context, so the backup has something worth restoring."""
    suffixes = load_suffixes(connection, settings, when=utc(window) - timedelta(minutes=5))
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
        (settings.identity.tenant, settings.identity.sensor, utc(window), utc(window)),
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
            projection, hosts.load().attributes_for(projection.host), rendering.budget()
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
        logger=observability.StructuredLogger(
            component="demo",
            tenant=settings.identity.tenant,
            sensor=settings.identity.sensor,
            redactor=Redactor.from_settings(settings),
            stream=io.StringIO(),
        ),
        # Disabled: a gated context stores no model answer, and this demo is
        # about what survives a restore rather than about the gate.
        triage_gate=policy.TriageGate(
            policy_version=policy_v1.POLICY_VERSION,
            triage_gate_version="demo-disabled",
            min_suspicious_indicators=0,
        ),
    )
    orchestration.AssessmentStore(
        connection=connection, prices=budgets.model_prices()
    ).store(assessment, at=datetime.now(timezone.utc))
    connection.execute("FLUSH")
    return projection.context_id


def counts(connection) -> dict[str, int]:
    """Row counts for the four relations this demo talks about."""
    found: dict[str, int] = {}
    for relation in (
        # The input half, which a capture replay DOES bring back -- printing
        # only the relations it does not would show half the point.
        "helena_normalized_events",
        "helena_analytical_assessment",
        "helena_reference_feed_snapshot",
        "helena_reference_evidence",
    ):
        try:
            (count,) = connection.execute(f"SELECT count(*) FROM {relation}").fetchone()
        except Exception:  # noqa: BLE001 — a relation this build does not have
            continue
        found[relation] = count
    return found


def main() -> int:
    print(f"{BOLD}MAESTRO HELENA — what survives, and what a replay does not bring back{RESET}")
    rule()
    window = current_window()

    with Scripted([answered(said(classification="normal", confidence=0.9))]) as endpoint:
        settings = settings_for(model_url=endpoint.url)

        with schema(settings) as (source, source_name):
            stage(1, "Build a pipeline state worth restoring")
            context_id = build_state(settings, source, window, endpoint)
            before = counts(source)
            print(f"  schema       {source_name}")
            for relation, count in before.items():
                print(f"    {relation:<34} {count}")

            stage(2, "Back it up, and verify what was written")
            started = datetime.now(timezone.utc)
            lines = list(durability.back_up(source, taken_at=started))
            header = durability.verify(lines)
            size = sum(len(line) for line in lines)
            print(f"  lines        {len(lines)} (header, rows, trailer)")
            print(f"  bytes        {size:,}")
            print(f"  relations    {len(header.relations)} declared")
            print(f"  {GREEN}verified{RESET} — the trailer's digest covers the body")
            note("the digest is at the END, which is what makes truncation visible")

            stage(3, "Restore into a separately migrated schema")
            with schema(settings) as (target, target_name):
                result = durability.restore(target, lines)
                seconds = (datetime.now(timezone.utc) - started).total_seconds()
                after = counts(target)
                print(f"  schema       {target_name}")
                print(f"  restored     {sum(result.rows.values())} row(s) into "
                      f"{len(result.rows)} relation(s)")
                print(f"  recovery     {seconds:.1f}s, dominated by the migrations")
                rule()
                print(f"  {'relation':<34} {'source':>8} {'restored':>9}")
                for relation, count in before.items():
                    back = after.get(relation, 0)
                    mark = GREEN if back == count else YELLOW
                    print(f"  {relation:<34} {count:>8} {mark}{back:>9}{RESET}")
                note("materialized views are NOT in the backup — they rebuilt")
                note("themselves from the tables the migrations created")

            stage(4, "Now replay the capture alone, into a third schema")
            with schema(settings) as (replayed, replayed_name):
                load_suffixes(
                    replayed, settings, when=utc(window) - timedelta(minutes=5)
                )
                with tempfile.TemporaryDirectory(prefix="helena-demo-") as staging:
                    capture = stage_capture(
                        sample_records(), Path(staging), window=window
                    )
                    ingest(settings, replayed, capture)
                live_contexts(replayed)
                alone = counts(replayed)
                print(f"  schema       {replayed_name}")
                rule()
                print(f"  {'relation':<34} {'source':>8} {'replay only':>12}")
                for relation, count in before.items():
                    back = alone.get(relation, 0)
                    mark = GREEN if back == count else YELLOW
                    print(f"  {relation:<34} {count:>8} {mark}{back:>12}{RESET}")

                missing = [
                    relation
                    for relation, count in before.items()
                    if count and not alone.get(relation)
                ]
                banner("THE MEASUREMENT THAT MATTERS IS THE NEGATIVE ONE")
                print()
                if missing:
                    print(f"  A capture replay reconstructed the input and "
                          f"{BOLD}not{RESET}:")
                    for relation in missing:
                        print(f"    {YELLOW}{relation}{RESET}")
                print(
                    f"\n{DIM}  The retained captures back up the store's INPUT, not the store.\n"
                    f"  That difference is the whole reason the engine has to be backed\n"
                    f"  up at all, and it is the half an operator tends to discover\n"
                    f"  during a recovery rather than before one.\n\n"
                    f"  The durable record is two halves and both are needed: the\n"
                    f"  engine's tables, and the retained captures. The broker and the\n"
                    f"  output topic are excluded by decision — ADR-0040.{RESET}"
                )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
