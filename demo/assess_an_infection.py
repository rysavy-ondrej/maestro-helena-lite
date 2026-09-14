#!/usr/bin/env python3
"""A real infected host, its real C2 chain, and what the pipeline makes of it.

    demo/run-demo 9
    uv run demo/assess_an_infection.py
    uv run demo/assess_an_infection.py --exercise 2026-08-09

Every other demo here runs either benign traffic or traffic this repository
rewrote. This one runs **a real malware infection**: one
[Malware-Traffic-Analysis.net](https://www.malware-traffic-analysis.net/training-exercises.html)
exercise from `data/connections/malware-traffic/`, a single Windows-AD client
that was actually compromised, with its actual C2 chain in the DNS queries and
TLS SNI.

The default is `2026-09-11`, *"Kongtuke Rebuke!"*: 320 connections over 21
minutes from `10.9.11.135`, whose infection chain reaches `winrun2915.com`,
`logincrypt8338.com`, `opscast3707.net` and `know.mom-nower.com`.

## The two things this demo changes, and it says so every run

**1. The timestamps are moved.** A snapshot's validity interval begins when it
was fetched, so a capture from days ago is covered by no snapshot fetchable
today and would produce no enrichment at all
(`docs/evaluation-corpus.md` §4). The records are re-stamped so the capture
*ends now*, which is `scripts/rebase_capture.py`'s operation and is permitted:
`ts` is a field of the input contract.

**2. The feed is told about the C2 domains, because it does not know them.**
Measured 2026-09-14: the **current ThreatFox export shares nothing** with any of
the ten exercises — not one address, not one domain, including the exercise
captured three days earlier. So the chain is added to the snapshot the demo
loads, and every screen that shows a match says `ADDED`.

That second point is the demo's most useful result and it is a negative one.
This is not a pipeline failure and not a feed failure: the recent export is a
rolling two-day sighting window of a few thousand indicators, and a specific
intrusion is simply not in it. **A pipeline that only knows what a feed lists
would have said `normal` about a live infection**, which is what
`docs/hazards.md` §6 and §11 are about, now measured against real malware
traffic rather than against benign browsing.

## What is real here

The connections, the hosts, the DNS chain, the TLS parameters, the byte and
packet counts, and the order and timing of the infection. The host really did
contact those domains, in that sequence.

## What it does not show

**Nothing about verdict quality.** There is no labelled corpus and there is no
answer key in this tree — the exercise's answer pages stay upstream — so what a
model says here is not scored against anything. **Not detection either**: the
match happens because the demo told the feed what to look for.

Maturity: experimental — a demonstration, not a tested component. The stages it
drives are covered by `tests/test_end_to_end.py`; this script is exercised by
running it.
"""

from __future__ import annotations

import argparse
import io
import json
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
    RED,
    RESET,
    THREATFOX_EXPORT_URL,
    YELLOW,
    banner,
    ingest,
    live_contexts,
    load_feed,
    load_suffixes,
    note,
    rule,
    schema,
    settings_for,
    stage,
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

CORPUS = ROOT.parent / "data" / "connections" / "malware-traffic"
DEFAULT_EXERCISE = "2026-09-11"

#: What each exercise's traffic really reached, by the entity type the enrichment
#: join matches on. Read off the capture's own DNS, HTTP and flows -- these are
#: things the host actually contacted, not a guess about which were malicious.
#: The upstream answer keys are not in this tree, so this is *"the chain the
#: traffic shows"* and deliberately not *"the indicators of compromise"*.
#:
#: **All three types ThreatFox covers are here on purpose.** A domain-only chain
#: is what the first version of this demo planted, and it produced five claims
#: and no deterministic escalation at all -- because the composition rule's scope
#: test does not reach domain entities (`docs/hazards.md` §5). Adding the
#: addresses and the URL the same traffic carried is what makes the enrichment
#: join, and the rules on top of it, visible as more than one outcome.
CHAINS = {
    "2026-09-11": (
        # --- domains: queried, and three of them offered as a TLS server name
        ("know.mom-nower.com", "domain"),
        ("winrun2915.com", "domain"),
        ("logincrypt8338.com", "domain"),
        ("opscast3707.net", "domain"),
        ("aatthews.cfd", "domain"),
        # --- an address on its own infrastructure. The host sent it 4.77 MB
        # over 73 flows of plain HTTP and got 107 KB back: contacted, heavily,
        # both ways, on the port the indicator names.
        ("86.106.87.134:80", "ip:port"),
        # --- an address behind a CDN, reached for winrun2915.com. Contacted
        # just as really, and the rules should treat it differently: one
        # address shared by everything is not evidence about this host.
        ("104.21.91.138:443", "ip:port"),
        # --- a URL the host actually requested, from the same C2
        (
            "http://know.mom-nower.com/zgzly/e2fkf6&"
            "4a0fd955c05d43841a9a8d921ceec63b0dc5b431a9fb54b33ad7848707bc16e9/o3m8xrq0rab",
            "url",
        ),
    ),
}


def records_of(exercise: str) -> list[dict]:
    path = CORPUS / "conn" / f"{exercise}.jsonl"
    if not path.exists():
        raise SystemExit(
            f"{path} is not here. The malware corpus is not committed -- it is "
            f"records derived from third-party captures and this project holds "
            f"no redistribution clearance for them. "
            f"{CORPUS / 'README.md'} says where it comes from."
        )
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def infected_host(records: list[dict]) -> str:
    """The client the exercise is about: the one that did the talking.

    Each exercise is one LAN segment with exactly one infected client
    (`UPSTREAM-AGENTS.md`), and it is the overwhelming majority of the traffic --
    316 of 320 records in the default exercise. Derived rather than configured,
    so pointing this at another exercise needs no table entry.
    """
    counts: dict[str, int] = {}
    for record in records:
        counts[record["ip"]["src"]] = counts.get(record["ip"]["src"], 0) + 1
    return max(counts, key=counts.get)


def listed(export: bytes, chain: tuple[tuple[str, str], ...]) -> bytes:
    """The live export with the chain added, as entries the loader will map.

    Added rather than substituted: everything ThreatFox really published is still
    there, so the `no_match` rows in the output are real answers about real
    indicators and only the chain is this demo's doing.

    `ioc_type` is carried per entry rather than assumed, because the whole point
    of planting three types is that the join and the rules treat them
    differently -- an `ip:port` is split into address and port by
    `sql/migrations/0014_feed_mapping_views.sql`, and the port then qualifies
    the match instead of filtering it.
    """
    document = json.loads(export)
    base = max((int(key) for key in document if key.isdigit()), default=0) + 1
    for offset, (value, kind) in enumerate(chain):
        document[str(base + offset)] = [
            {
                "ioc_value": value,
                "ioc_type": kind,
                "threat_type": "botnet_cc",
                "malware": "win.unknown",
                "malware_alias": None,
                "malware_printable": "Unknown",
                "first_seen_utc": "2026-09-11 20:05:55",
                "last_seen_utc": None,
                # Above `config/policy.toml`'s threshold on purpose: what this
                # demo is about is the path a match takes, not the threshold,
                # which `demo/escalation_and_scope.py` varies instead.
                "confidence_level": 100,
                "is_compromised": False,
                "reference": "demo/assess_an_infection.py -- ADDED, not published",
                "tags": "demo-added",
                "anonymous": 0,
                "reporter": "demo",
            }
        ]
    return json.dumps(document).encode()


def overlap(export: bytes, records: list[dict]) -> set[str]:
    """What the capture and the REAL export already share, before anything is added."""
    document = json.loads(export)
    addresses, domains = set(), set()
    for entries in document.values():
        for entry in entries:
            value, kind = entry.get("ioc_value"), entry.get("ioc_type")
            if kind == "ip:port":
                addresses.add(value.rsplit(":", 1)[0])
            elif kind == "domain":
                domains.add(value)
    found = set()
    for record in records:
        if record["ip"]["dst"] in addresses:
            found.add(record["ip"]["dst"])
        for query in (record.get("dns") or {}).get("queries") or []:
            if query.get("qn") in domains:
                found.add(query["qn"])
        name = (record.get("tls") or {}).get("sni")
        if name in domains:
            found.add(name)
    return found


def staged(records: list[dict], directory: Path):
    """The records as a capture file, addressed by its own sha256.

    Written as they stand, spacing intact — a capture is traffic and traffic is
    the intervals between its records.
    """
    from helena.normalizer import CAPTURE_SUFFIX, describe_capture

    path = directory / "capture.jsonl"
    path.write_bytes(b"".join(json.dumps(r).encode() + b"\n" for r in records))
    described = describe_capture(path)
    final = path.with_name(f"{described.sha256}{CAPTURE_SUFFIX}")
    path.replace(final)
    return describe_capture(final)


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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--exercise", default=DEFAULT_EXERCISE)
    parser.add_argument(
        "--domains-only",
        action="store_true",
        help="plant only the domain indicators, which is what docs/hazards.md §5 "
             "was measured with: the scope test does not reach domain entities, so "
             "nothing escalates deterministically however high the confidence.",
    )
    parser.add_argument(
        "--windows",
        type=int,
        default=3,
        help="assess the first N windows in time order (0 = all). Every context "
             "holding a claim escalates, and one analyst run is minutes.",
    )
    arguments = parser.parse_args(argv)

    print(f"{BOLD}MAESTRO HELENA — one real infection, end to end{RESET}")
    rule()
    records = records_of(arguments.exercise)
    host = infected_host(records)
    chain = CHAINS.get(arguments.exercise, ())
    source_first = min(record["ts"] for record in records)
    source_last = max(record["ts"] for record in records)
    print(f"  exercise     {BOLD}{arguments.exercise}{RESET}  "
          f"({len(records)} connections)")
    print(f"  infected     {BOLD}{host}{RESET}  "
          f"{sum(1 for r in records if r['ip']['src'] == host)} of {len(records)} records")
    print(f"  captured     {utc(source_first):%Y-%m-%d %H:%M} → {utc(source_last):%H:%M} UTC")
    note("real traffic: the hosts, the DNS chain, the TLS parameters and the timing")

    settings = settings_for()
    redactor = Redactor.from_settings(settings)

    stage(1, "What the live feed already knows about this capture")
    export = enrichment.fetch_threatfox(THREATFOX_EXPORT_URL, redactor=redactor)
    shared = overlap(export, records)
    print(f"  fetched      {len(export):,} bytes from ThreatFox")
    if shared:
        print(f"  {GREEN}already listed{RESET}  {sorted(shared)}")
        note("a real match — nothing needs adding for those")
    else:
        print(f"  {YELLOW}overlap: none{RESET}")
        note("not one address and not one domain of this capture is in the current")
        note("export. The recent feed is a rolling two-day sighting window; a")
        note("specific intrusion is not in it. THAT IS THIS DEMO'S REAL RESULT:")
        note("a pipeline that only knew what a feed lists would call this normal.")

    if arguments.domains_only:
        chain = tuple((value, kind) for value, kind in chain if kind == "domain")
        print(f"\n  {YELLOW}--domains-only{RESET}: planting the domains and nothing else,")
        note("which is how docs/hazards.md §5 was measured")
    if not chain:
        raise SystemExit(
            f"no chain is recorded for {arguments.exercise!r}, so this demo has "
            f"nothing to tell the feed about. CHAINS in this file is read off "
            f"each capture's own DNS and TLS; add the exercise there first."
        )
    print(f"\n  {YELLOW}ADDED to the snapshot{RESET}, because the feed does not list them:")
    for value, kind in chain:
        print(f"    {YELLOW}{kind:<8}{RESET} {value[:64]}")
    if arguments.domains_only:
        note("domains only — the scope test does not reach a domain entity, so")
        note("this is the run where nothing escalates however high the confidence")
    else:
        note("all three types the source covers, so the join can be seen matching")
        note("more than one")
    note("these are things the host really reached; the LISTING is the demo's")

    # The capture ends now, so every window has closed and can be assessed. A
    # capture rebased to START now spans into the future and its windows never
    # close. `scripts/rebase_capture.py` is the same operation for a corpus.
    delta = datetime.now(timezone.utc).timestamp() - source_last - 60.0
    moved = [{**record, "ts": record["ts"] + delta} for record in records]
    window_start = utc(source_first + delta)

    with schema(settings) as (connection, name):
        stage(2, "Ingest the capture, re-stamped so its windows have closed")
        suffixes = load_suffixes(connection, settings, when=window_start - timedelta(minutes=10))
        with tempfile.TemporaryDirectory(prefix="helena-demo-") as staging:
            # Staged here rather than through `_common.stage_capture`, which
            # collapses a capture into ONE window: this one keeps its own 21
            # minutes, because the point is a host moving through the infection
            # over several windows rather than a single context.
            capture = staged(moved, Path(staging))
            counts = ingest(settings, connection, capture)
        print(f"  schema       {name}")
        print(f"  shifted      {delta / 86400:+.1f} days, so the capture ends a minute ago")
        print(f"  normalized   {counts.normalized}, quarantined "
              f"{counts.quarantine.quarantined}")
        if not counts.complete:
            print(f"  {RED}counters do not reconcile{RESET}")

        stage(3, "Load the snapshot: what ThreatFox published, plus the chain")
        load = load_feed(
            connection, settings, when=window_start - timedelta(minutes=5),
            raw=listed(export, chain),
        )
        if load.outcome == enrichment.FAILED:
            raise SystemExit(f"the feed did not load: {load.failure_reason}")
        connection.execute("FLUSH")
        (snapshot,) = connection.execute(
            "SELECT snapshot_version FROM helena_reference_feed_snapshot_validity "
            "WHERE tenant = %s AND sensor = %s AND valid_from <= %s "
            "AND (valid_to IS NULL OR valid_to > %s)",
            (settings.identity.tenant, settings.identity.sensor, window_start, window_start),
        ).fetchone()
        print(f"  snapshot     {snapshot[:16]}…  "
              f"{(load.counts or {}).get('claims_stored', 0)} claims")

        stage(4, "What the enrichment join matched, by entity type")
        matched = connection.execute(
            "SELECT entity_type, status, "
            "       coalesce(classification, '(no snapshot consulted)'), "
            "       count(*), count(DISTINCT entity_value) "
            "FROM helena_analytical_enriched_context "
            "GROUP BY 1, 2, 3 ORDER BY 1, 3 DESC, 2"
        ).fetchall()
        print(f"  {'entity type':<13} {'status':<8} {'what the snapshot said':<26} "
              f"{'rows':>5} {'distinct':>9}")
        rule()
        for entity_type, status, classification, rows, distinct in matched:
            hit = classification not in ("no_match", "(no snapshot consulted)")
            colour = (GREEN + BOLD) if hit else DIM
            print(f"  {entity_type:<13} {status:<8} {colour}{classification:<26}{RESET}"
                  f" {rows:>5} {distinct:>9}")
        note("`no_match` is a snapshot consulted and saying nothing about that entity —")
        note("a real answer about a real indicator, and not a statement of safety")
        hits = connection.execute(
            "SELECT entity_type, entity_value, source_id, confidence, port_matched "
            "FROM helena_analytical_enriched_context "
            "WHERE classification NOT IN ('no_match') AND classification IS NOT NULL "
            "GROUP BY 1,2,3,4,5 ORDER BY 1, 2"
        ).fetchall()
        if hits:
            print(f"\n  {GREEN}the entities a claim was made about{RESET}:")
            for entity_type, value, source, confidence, port_matched in hits:
                port = "" if port_matched is None else f"  port_matched={port_matched}"
                print(f"    {entity_type:<9} {value[:46]:<46} {source} "
                      f"{confidence}{port}")
            note("port_matched qualifies an address match, it does not filter it (ADR-0042)")

        stage(5, "The contexts the engine computed, and what was claimed about them")
        contexts = live_contexts(connection)
        store = rendering.RenderingStore(connection=connection, identity=settings.identity)
        projections = [store.project(context_id) for context_id in contexts]
        projections.sort(key=lambda p: p.statistics.window_start)
        rules = policy.version(policy_v1.POLICY_VERSION)
        thresholds = policy.thresholds()
        gate = policy.triage_gate()
        print(f"  contexts     {len(projections)} "
              f"({len(set(p.host for p in projections))} host(s) x 5-minute windows)")
        rule()
        print(f"  {'window':<8} {'host':<15} {'entities':<9} {'claims':<7} escalates")
        escalations = {}
        held: set[tuple[str, str]] = set()
        for projection in projections:
            escalation = rules.escalate(policy.supports_in(projection), thresholds)
            escalations[projection.context_id] = escalation
            mark = GREEN if escalation.escalates else DIM
            print(f"  {projection.statistics.window_start:%H:%M}    "
                  f"{projection.host:<15} {len(projection.entities):<9} "
                  f"{escalation.claims_read:<7} {mark}{escalation.escalates}{RESET}")
            if escalation.claims_read and not escalation.escalates:
                held.update(
                    (candidate.entity_type, rule)
                    for candidate in escalation.candidates
                    for rule in candidate.rules
                )
                shown = [c for c in escalation.candidates if not c.escalates][:2]
                for candidate in shown:
                    print(f"    {DIM}{candidate.entity_type} {candidate.entity_value[:30]}"
                          f"  supports={candidate.supports}  held by {list(candidate.rules)}{RESET}")

        stage(6, "Assess the contexts against the configured model")
        print(f"  {DIM}triage {settings.triage.model} / analyst {settings.analyst.model}; "
              f"gate min_suspicious_indicators={gate.min_suspicious_indicators}{RESET}")
        budget_policy = budgets.load()
        triage_prompt, analyst_prompt = triage.version("v1"), analyst.version("v1")
        # One buffer for the demo's own log AND the two agents': every
        # `ModelClient` builds a logger, and one without a stream writes to the
        # terminal. Nineteen JSON lines over the top of the output is how that
        # was found.
        log = io.StringIO()
        logger = observability.StructuredLogger(
            component="demo", tenant=settings.identity.tenant,
            sensor=settings.identity.sensor, redactor=redactor, stream=log,
        )
        assessments = orchestration.AssessmentStore(
            connection=connection, prices=budgets.model_prices()
        )
        # The INFECTED HOST's windows, in time order. Not a cherry-pick of
        # results: the host is chosen before any assessment runs, by traffic
        # volume, and this demo is about it -- the other two "hosts" in this
        # capture are a broadcast address and a gateway with one record each.
        # A prefix over every context instead put the two of those first and
        # assessed nothing that mattered. `--windows 0` runs all of the host's.
        mine = [p for p in projections if p.host == host]
        assessed = mine if arguments.windows == 0 else mine[: arguments.windows]
        if len(assessed) < len(projections):
            print(f"  {YELLOW}first {len(assessed)} of {len(mine)} windows for {host}{RESET} "
                  f"{DIM}(--windows 0 for all){RESET}")
        outcomes = []
        for projection in assessed:
            asked = request_for(
                projection, connection=connection, settings=settings,
                snapshot=snapshot, normalization=suffixes.snapshot_version,
                budget_policy=budget_policy, prompt=triage_prompt,
            )
            assessment = orchestration.assess(
                asked,
                projection=projection,
                triage_client=ModelClient.for_agent(settings, "triage", stream=log),
                analyst_client=ModelClient.for_agent(settings, "analyst", stream=log),
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
            assessments.store(assessment, at=datetime.now(timezone.utc))
            outcomes.append((projection, assessment))
            gated = isinstance(assessment.triage, policy.GateDecision)
            reached = "gated" if gated else ("analyst" if assessment.trigger else "triage")
            print(f"  {projection.statistics.window_start:%H:%M}    reached {reached}",
                  flush=True)
        connection.execute("FLUSH")

        stage(7, "What a consumer reads off the output topic")
        sink_store = sink.SinkStore(connection=connection, identity=settings.identity)
        print(f"  pending      {sink_store.pending()} message(s)")
        cited = 0
        for identifier in sink_store.terminal():
            message = sink_store.project(identifier)
            hits = [
                (entity.entity_value, evidence.classification)
                for entity in message.entities
                for evidence in entity.evidence
                if evidence.classification not in (None, "no_match")
            ]
            cited += len(message.citations)
            mark = GREEN if message.verdict and message.verdict != "normal" else DIM
            print(f"  {message.window_start:%H:%M}    "
                  f"{message.outcome_kind:<13} "
                  f"{mark}{str(message.verdict or message.failure_reason):<12}{RESET}"
                  f" {len(message.citations)} citation(s)"
                  f"{'  ← ' + ', '.join(v for v, _ in hits[:2]) if hits else ''}")

        banner("WHAT THIS RUN SHOWED")
        escalated = sum(1 for _, a in outcomes if a.trigger)
        gated_count = sum(
            1 for _, a in outcomes if isinstance(a.triage, policy.GateDecision)
        )
        print(f"\n  {len(assessed)} of {len(mine)} window(s) of {host} assessed, "
              f"out of {len(projections)} contexts in the capture")
        print(f"  {escalated} reached the analyst, {gated_count} cleared by the gate")
        print(f"  {cited} citation(s) to stored evidence on the topic")
        print(
            f"\n{DIM}  The connections were real: this host really contacted that chain,\n"
            f"  in that order. Two things were not. The timestamps were moved so a\n"
            f"  loadable snapshot could cover the windows, and the feed was told\n"
            f"  about the chain — because it does not know it. Nothing here is\n"
            f"  evidence that the pipeline would have FOUND this infection; it is\n"
            f"  what the pipeline does with an infection once something lists it.\n\n"
            f"  The gap between those two sentences is the one docs/hazards.md §11\n"
            f"  records, and it is why the pre-triage gate's cost is unmeasured.{RESET}"
        )

        if held:
            banner("A HIGH-CONFIDENCE MATCH THAT DID NOT ESCALATE")
            print()
            for entity_type, rule_name in sorted(held):
                print(f"  {YELLOW}{entity_type:<12}{RESET} held by {BOLD}{rule_name}{RESET}")
            print(
                f"\n{DIM}  Those claims are confidence 1.0 on a host that really was\n"
                f"  compromised, and the deterministic escalation did not fire. The rule\n"
                f"  that held each one back is named above, read off the run rather than\n"
                f"  argued here. If the entity type is `domain`, this is the scope-test\n"
                f"  gap docs/hazards.md §5 records -- 'the composition rule works on\n"
                f"  address entities and not on domain ones, and the feeds most likely to\n"
                f"  hit list domains' -- happening on real malware traffic rather than in\n"
                f"  a paragraph.{RESET}"
            )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
