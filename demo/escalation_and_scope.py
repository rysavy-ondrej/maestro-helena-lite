#!/usr/bin/env python3
"""Three hosts, one indicator: what escalates, what does not, and what is never read.

    demo/run-demo 5
    uv run demo/escalation_and_scope.py

The same listed indicator reaches three hosts in three different ways, in **one
window and one schema**, so the three outcomes sit beside each other rather than
in three runs a reader has to hold in their head:

  | Host | What it did with the indicator | Expected |
  | --- | --- | --- |
  | `10.0.0.1` | **contacted** it — it is the flow destination | escalates on the evidence alone, before any model runs |
  | `10.0.0.2` | **resolved** it and never contacted it | does **not** escalate — scope before severity |
  | `10.0.0.3` | never saw it; ordinary traffic | no claim at all, so the pre-triage gate clears it without a model |

Three facts are on display and each has a rule behind it.

**1. Deterministic escalation is computed before any model is called, and no
model output can suppress it.** `concept/07-principles.md` makes *"Triage
returning `normal` suppresses a Tier A match"* a must-never-happen row. The
scripted model below answers `normal` for every host on purpose, so what
escalates does so over the model's objection.

**2. Scope before severity.** An indicator's classification is not the host's
verdict. `10.0.0.2` resolved a listed address and never sent it a packet; the
claim is real and the composition rule refuses to escalate on it.

**3. The gate is subordinate to the escalation.** `10.0.0.3` holds no claim and
is cleared without inference (`docs/decisions/0047-the-pre-triage-gate.md`).
`10.0.0.1` holds one and escalates — and would escalate at **any** threshold,
because the gate is checked after the escalation and never before it.

## How the three hosts are made

`data/ingest/flow-sample.jsonl` is one host's traffic. It is copied three times
with `ip.src` rewritten, which makes three contexts in one window — a context is
one host in one window. The indicator is then planted into two of the copies, the
way `scripts/plant_indicators.py` does it for a corpus. **The indicator is
planted and the output says so.** Real traffic does not intersect a two-day
sighting window; `demo/assess_a_slice.py` pass A is 131 entities and every one is
`no_match`.

## What it does not show

**Nothing about verdict quality.** The model is scripted, so its answers are an
input to this demo rather than an output of it, and the escalations shown are the
deterministic layer's — not a claim that the traffic is malicious. It is a benign
flow with a rewritten destination.

Maturity: experimental — a demonstration, not a tested component. The rules it
shows are covered by `tests/test_escalation.py`, `tests/test_composition.py` and
`tests/test_orchestration.py`; this script is exercised by running it.
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
sys.path.insert(0, str(ROOT.parent / "scripts"))

from _common import (  # noqa: E402
    BOLD,
    THREATFOX_EXPORT_URL,
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
from plant_indicators import Indicator, indicators, plant_address, plant_resolved_only  # noqa: E402

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
    triage,
)
from helena.agents import ModelClient  # noqa: E402
from helena.observability import Redactor  # noqa: E402
from helena.contracts.v1 import (  # noqa: E402
    CONTRACT_VERSION,
    SCHEDULED_TRIAGE,
    AgentRequest,
    RequestVersions,
)
from helena.policy import v1 as policy_v1  # noqa: E402
from helena.rendering import v1 as rendering_v1  # noqa: E402
from helena.taxonomy import TRIAGE  # noqa: E402
from helena import hosts  # noqa: E402

CONTACTED, RESOLVED_ONLY, UNTOUCHED = "10.0.0.1", "10.0.0.2", "10.0.0.3"
EXPORT = ROOT.parent / "data" / "threatfox"


def strongest(pool: list[Indicator]) -> Indicator:
    """A listed `ip:port` at full confidence, so the threshold is not the variable."""
    listed = [item for item in pool if item.ioc_type == "ip:port" and item.confidence >= 1.0]
    if not listed:
        raise SystemExit(
            "the export holds no ip:port indicator at confidence 1.0; this demo "
            "varies the SCOPE and needs the confidence held constant"
        )
    return listed[0]


def three_hosts(records: list[dict], indicator: Indicator) -> list[dict]:
    """One host's traffic, three times, with the indicator reaching two of them."""
    built: list[dict] = []
    for source, how in ((CONTACTED, "contacted"), (RESOLVED_ONLY, "resolved"), (UNTOUCHED, None)):
        for index, record in enumerate(records):
            copy = json.loads(json.dumps(record))
            copy["ip"]["src"] = source
            copy["id"] = f"{source}-{index}"
            built.append(copy)
        if how is None:
            continue
        # Plant into the FIRST record of this host that can carry it, using the
        # same two functions the corpus generator uses -- one definition of what
        # "contacted" and "resolved only" mean as data.
        mine = [item for item in built if item["ip"]["src"] == source]
        if how == "contacted":
            target = next(item for item in mine if isinstance(item.get("tcp"), dict))
            planted = plant_address(target, indicator, port=None)
        else:
            target = next(
                item
                for item in mine
                if isinstance(item.get("dns"), dict) and item["dns"].get("responses")
            )
            planted = plant_resolved_only(target, indicator)
        built[built.index(target)] = planted
    return built


def request_for(projection, *, connection, settings, snapshot, normalization, budget_policy, prompt):
    """The triage request. Nothing in `src/helena` builds one — `docs/deployment.md` §1."""
    (aggregation,) = connection.execute(
        "SELECT aggregation_version FROM helena_signal_host_context_live "
        "WHERE tenant = %s AND sensor = %s AND context_id = %s",
        (projection.tenant, projection.sensor, projection.context_id),
    ).fetchone()
    return AgentRequest(
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
            prompt_version=prompt.version,
            schema_version=CONTRACT_VERSION,
            rendering_version=rendering_v1.RENDERING_VERSION,
            taxonomy_version="v1",
            enrichment_snapshot_version=snapshot,
            normalization_snapshot_version=normalization,
            policy_version=policy_v1.POLICY_VERSION,
            aggregation_version=aggregation,
            model_requested=settings.triage.model,
        ),
    )


def main() -> int:
    print(f"{BOLD}MAESTRO HELENA — escalation, scope, and the gate{RESET}")
    rule()

    # Fetched once, and BOTH the indicator and the snapshot come from these
    # bytes. Picking from `data/threatfox/` while loading the live export
    # compares two different snapshots taken weeks apart, and every plant misses
    # -- silently, because a missed plant looks exactly like ordinary traffic.
    export = enrichment.fetch_threatfox(
        THREATFOX_EXPORT_URL, redactor=Redactor.from_settings(settings_for())
    )
    with tempfile.NamedTemporaryFile("wb", suffix=".json", delete=False) as handle:
        handle.write(export)
        export_path = Path(handle.name)
    indicator = strongest(indicators(export_path))
    address, port = indicator.address
    print(f"  indicator    {BOLD}{indicator.value}{RESET}  "
          f"confidence {indicator.confidence:.2f}  ({indicator.malware or 'unnamed'})")
    print(f"  {YELLOW}PLANTED{RESET} into two of three hosts — real traffic does not "
          f"intersect a two-day sighting window")

    window = current_window()
    records = three_hosts(sample_records(), indicator)

    # Every host gets `normal` from the model, so whatever escalates does so over
    # the model's objection rather than because of it.
    script = [answered(said(classification="normal", confidence=0.9)) for _ in range(6)]
    with Scripted(script) as endpoint:
        settings = settings_for(model_url=endpoint.url)
        with schema(settings) as (connection, name):
            stage(1, "Ingest three hosts into one window")
            suffixes = load_suffixes(
                connection, settings, when=utc(window) - timedelta(minutes=5)
            )
            with tempfile.TemporaryDirectory(prefix="helena-demo-") as staging:
                capture = stage_capture(records, Path(staging), window=window)
                counts = ingest(settings, connection, capture)
            print(f"  schema       {name}")
            print(f"  normalized   {counts.normalized}")

            stage(2, "Load the snapshot the indicator is listed in")
            load = load_feed(
                connection, settings, when=utc(window) - timedelta(minutes=1), raw=export
            )
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
            print(f"  snapshot     {snapshot[:16]}…")

            stage(3, "What each host is claimed to have done")
            contexts = live_contexts(connection)
            store = rendering.RenderingStore(connection=connection, identity=settings.identity)
            projections = {}
            for context_id in contexts:
                projection = store.project(context_id)
                projections[projection.host] = projection
            for host in (CONTACTED, RESOLVED_ONLY, UNTOUCHED):
                projection = projections.get(host)
                if projection is None:
                    print(f"  {host:<10} {DIM}no context{RESET}")
                    continue
                claims = policy.supports_in(projection)
                matched = [
                    entity.entity_value
                    for entity in projection.entities
                    for row in entity.enrichment
                    if row.classification not in (None, "no_match")
                ]
                print(f"  {host:<10} {len(claims)} claim(s)"
                      f"{'  ← ' + ', '.join(sorted(set(matched))) if matched else ''}")

            stage(4, "The deterministic escalation — computed before any model runs")
            rules = policy.version(policy_v1.POLICY_VERSION)
            thresholds = policy.thresholds()
            gate = policy.triage_gate()
            escalations = {}
            for host, projection in projections.items():
                escalation = rules.escalate(policy.supports_in(projection), thresholds)
                escalations[host] = escalation
                decision = policy.gate(
                    escalation,
                    minimum=gate.min_suspicious_indicators,
                    triage_gate_version=gate.triage_gate_version,
                )
                mark = GREEN if escalation.escalates else DIM
                print(f"  {host:<10} escalates={mark}{str(escalation.escalates):<5}{RESET}"
                      f"  claims_read={escalation.claims_read}"
                      f"  gate={'CLEARS' if decision.cleared else decision.reason}")

            contacted_claims = len(
                policy.supports_in(projections[CONTACTED])
            ) if CONTACTED in projections else 0
            if not contacted_claims:
                raise SystemExit(
                    f"the plant produced no claim on {CONTACTED}: the indicator "
                    f"{indicator.value} is not in the snapshot that was loaded, so "
                    f"there is nothing here to escalate on and nothing to show. "
                    f"This demo refuses to print its conclusions over data that "
                    f"does not support them."
                )

            stage(5, "Assess each host — the model answers `normal` for all three")
            budget_policy = budgets.load()
            triage_prompt, analyst_prompt = triage.version("v1"), analyst.version("v1")
            # The run's structured log goes to a buffer rather than the terminal:
            # what this demo is about is the three outcomes, and the log is a
            # different demo's subject.
            logger = observability.StructuredLogger(
                component="demo",
                tenant=settings.identity.tenant,
                sensor=settings.identity.sensor,
                redactor=Redactor.from_settings(settings),
                stream=io.StringIO(),
            )
            outcomes = {}
            for host in (CONTACTED, RESOLVED_ONLY, UNTOUCHED):
                projection = projections.get(host)
                if projection is None:
                    continue
                asked = request_for(
                    projection, connection=connection, settings=settings,
                    snapshot=snapshot,
                    normalization=suffixes.snapshot_version,
                    budget_policy=budget_policy, prompt=triage_prompt,
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
                    thresholds=thresholds,
                    budget_policy=budget_policy,
                    send_policy=disclosure.send_policy(),
                    inherit=analyst.Inheritance(inherit_triage_rationale=False),
                    logger=logger,
                    triage_gate=gate,
                )
                outcomes[host] = assessment

            banner("WHAT THE THREE HOSTS SHOW")
            print(f"\n  {'host':<11} {'claims':<7} {'escalates':<10} {'triage':<14} outcome")
            rule()
            for host in (CONTACTED, RESOLVED_ONLY, UNTOUCHED):
                assessment = outcomes.get(host)
                if assessment is None:
                    continue
                escalation = escalations[host]
                gated = isinstance(assessment.triage, policy.GateDecision)
                ran = "NOT RUN (gated)" if gated else "answered `normal`"
                outcome = (
                    f"{GREEN}analyst reached{RESET}" if assessment.trigger
                    else ("cleared without a model" if gated else "finished at triage")
                )
                print(f"  {host:<11} {escalation.claims_read:<7} "
                      f"{str(escalation.escalates):<10} {ran:<14} {outcome}")

            # Read off the run rather than written down: a demo whose closing
            # paragraph is a constant will keep asserting its conclusion after
            # the code stops producing it, which is the one thing a demo must
            # never do.
            contacted, resolved, untouched = (
                escalations.get(CONTACTED), escalations.get(RESOLVED_ONLY),
                escalations.get(UNTOUCHED),
            )
            print()
            if contacted and contacted.escalates and resolved and not resolved.escalates:
                print(
                    f"{DIM}  {CONTACTED} escalated on {contacted.claims_read} claim(s) although the\n"
                    f"  model said `normal` — the evidence escalates on its own and no\n"
                    f"  model output can suppress it.\n\n"
                    f"  {RESOLVED_ONLY} read {resolved.claims_read} claim(s) about the SAME indicator and did\n"
                    f"  not escalate: it resolved the address and never sent it a packet.\n"
                    f"  Scope before severity.{RESET}"
                )
            else:
                print(
                    f"{YELLOW}  The two planted hosts did not separate as intended:{RESET}\n"
                    f"    {CONTACTED}: escalates={contacted.escalates if contacted else '—'}\n"
                    f"    {RESOLVED_ONLY}: escalates={resolved.escalates if resolved else '—'}\n"
                    f"  Nothing is concluded from a run that did not produce the contrast."
                )
            if untouched is not None and untouched.claims_read == 0:
                print(
                    f"\n{DIM}  {UNTOUCHED} held no claim and no model ever read it — the gate\n"
                    f"  cleared it, which is the trade docs/hazards.md §11 records.{RESET}"
                )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
