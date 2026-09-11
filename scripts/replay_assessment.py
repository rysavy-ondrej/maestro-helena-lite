#!/usr/bin/env python3
"""Replay one stored assessment against the versions it recorded.

    uv run scripts/replay_assessment.py <assessment_id>
    uv run scripts/replay_assessment.py <assessment_id> --rerun

Without `--rerun` this **calls nothing**: it reads the assessment row and its
children, validates them against the contract version the row recorded, rebuilds
the request by re-rendering the recorded context version under the recorded
rendering version, and pairs the two under that version's own rules. That is the
half a replay can do offline, and it is the half that says whether the inputs the
assessment recorded still reconstruct.

`--rerun` then asks the reconstructed request again — the recorded prompt
version, the same budgets, and provider tools that may only be replays — and
prints a structured diff across verdict, path, confidence and citations.

Two things `--rerun` costs, said before it is used rather than after:

- **the model is called.** Hosted inference is egress (`concept/03`), so a rerun
  discloses the rendering to the configured endpoint and spends that quota, the
  way the original run did. The provider half is offline: every lookup resolves
  from the stored response and `helena.network.no_network` refuses any new
  outbound connection underneath it, so no feed is queried and no credential is
  revealed;
- **the answer will not be the same answer.** The model is not deterministic and
  nothing here makes it so. A difference is a measurement of how far a re-ask
  moved, never a failure — what would be a failure is a reconstruction that could
  not be validated, and that stops the command before the model is called.

Exit status is 0 only when the assessment was read, validated and reconstructed —
and, with `--rerun`, re-asked. A difference between the two outcomes is reported
and does not change the status.

Maturity: experimental — `helena.orchestration`'s replay underneath it is
exercised by tests/test_assessment_replay.py against a real engine, a real
capture and a scripted endpoint; this wrapper's read path is run there through
`uv run` in a subprocess, and its `--rerun` path is not (it would call a model
from the suite). See prds/reports/task-45.json.
"""

from __future__ import annotations

import argparse
import sys

import psycopg

from helena import analyst, budgets, disclosure, hosts, observability
from helena import orchestration as routing
from helena import providers, rendering, tools, triage
from helena.agents import AgentError, ModelClient, retry_policy
from helena.config import ConfigurationError, Settings
from helena.context import ContextOutsideRetention
from helena.contracts import ContractError
from helena.rendering import RenderingError, RenderingStore
from helena.taxonomy import TaxonomyError

#: The timeout one provider call is given. Unused in a replay — the adapter is
#: never reached — and passed anyway because the factory builds one either way;
#: see `helena.providers.threatfox_tool`.
PROVIDER_TIMEOUT_SECONDS = 30.0


def _describe(stored: routing.StoredAssessment) -> None:
    """What the store holds for this identifier, before anything is rebuilt."""
    print(f"assessment  {stored.assessment_id}")
    print(f"  run       {stored.emitter} / {stored.trigger}, assessed {stored.assessed_at}")
    print(f"  context   {stored.context_id} at {stored.context_version}")
    print(f"  host      {stored.tenant}/{stored.sensor} {stored.host}")
    print(f"  window    {stored.window_start} .. {stored.window_end}")
    print(f"  outcome   {_outcome_line(stored.outcome)}")
    print("  versions")
    for dimension, value in sorted(stored.versions.items()):
        print(f"    {dimension:<32} {value}")
    print(f"    {'model_version':<32} {stored.model_version}")


def _outcome_line(outcome: object) -> str:
    """One line for either terminal outcome, and never one shape for both.

    A typed failure has no verdict (`concept/02`), so it is printed as the
    failure it is rather than as a row with empty verdict columns.
    """
    classification = getattr(outcome, "classification", None)
    if classification is None:
        return f"typed failure: {outcome.reason} — {outcome.detail}"
    return (
        f"{classification} at confidence {outcome.confidence}, "
        f"{len(outcome.citations)} citation(s), {len(outcome.gaps)} gap(s)"
    )


def _replay_tools(
    settings: Settings, connection: psycopg.Connection
) -> list[tools.ProviderTool]:
    """The analyst's tools, every one of them a replay.

    `replay=True` is passed here rather than defaulted anywhere: it is the
    caller's statement about which run this is, and this command is the caller
    that knows. In this mode the adapter is built and never called, so the
    credential below is never revealed (`helena.tools`, "Replay").
    """
    return [
        providers.threatfox_tool(
            credential=settings.providers.abusech_auth_key,
            cache=tools.EvidenceCache(connection),
            send_policy=disclosure.send_policy(),
            replay=True,
            logger=observability.logger("providers", settings, stream=sys.stderr),
            redactor=observability.Redactor.from_settings(settings),
            timeout_seconds=PROVIDER_TIMEOUT_SECONDS,
        )
    ]


def _rerun(
    settings: Settings,
    connection: psycopg.Connection,
    stored: routing.StoredAssessment,
    request: object,
    projection: rendering.ContextProjection,
) -> routing.ReplayedRun:
    """Ask the reconstructed request again, under this deployment's endpoint."""
    agent = triage.EMITTER if stored.emitter == triage.EMITTER else analyst.EMITTER
    return routing.rerun(
        stored,
        request,
        client=ModelClient.for_agent(settings, agent, stream=sys.stderr),
        retry=retry_policy(),
        send_policy=disclosure.send_policy(),
        projection=projection,
        provider_tools=(
            () if agent == triage.EMITTER else _replay_tools(settings, connection)
        ),
        inherit=None if agent == triage.EMITTER else analyst.inheritance(),
    )


def _report(replayed: routing.ReplayedRun, stored: routing.StoredAssessment) -> None:
    """The diff, and what the replay spent and disclosed getting it."""
    cost = replayed.outcome.cost
    print(f"replayed    {_outcome_line(replayed.outcome)}")
    print(
        f"  spent     {cost.steps} step(s), {cost.live_queries} live "
        f"quer(y|ies), {cost.cache_hits} cache hit(s), {cost.retries} retr(y|ies)"
    )
    lookups = [
        row
        for row in replayed.disclosures.rows
        if row.channel == disclosure.PROVIDER_LOOKUP
    ]
    print(
        f"  disclosed {len(replayed.disclosures.rows)} record(s), "
        f"{len(lookups)} of them to a provider"
    )
    differences = routing.compare(stored.outcome, replayed.outcome)
    if not differences:
        print("  diff      the replay agrees on every dimension")
        return
    print("  diff      stored -> replayed")
    for difference in differences:
        print(
            f"    {difference.dimension:<16} {difference.original!r} -> "
            f"{difference.replayed!r}"
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="replay-assessment", description=__doc__.splitlines()[0]
    )
    parser.add_argument(
        "assessment",
        metavar="<id>",
        help=(
            "the stored assessment, by the identifier the store minted for it "
            "(`helena.orchestration.assessment_id`)"
        ),
    )
    parser.add_argument(
        "--rerun",
        action="store_true",
        help=(
            "also ask the reconstructed request again and print the diff. This "
            "calls the configured model endpoint and spends its quota; no "
            "provider is queried either way"
        ),
    )
    arguments = parser.parse_args(argv)

    try:
        settings = Settings.load()
    except ConfigurationError as refused:
        print(f"FAILED: {refused}", file=sys.stderr)
        return 1

    try:
        with psycopg.connect(
            settings.infrastructure.risingwave_dsn, autocommit=True, connect_timeout=5
        ) as connection:
            stored = routing.read_assessment(connection, arguments.assessment)
            _describe(stored)
            projection = RenderingStore(
                connection=connection, identity=settings.identity
            ).project(stored.context_id)
            request = routing.reconstruct(
                stored,
                projection=projection,
                attributes=hosts.load().attributes_for(stored.host),
                budget=rendering.budget(),
            )
            print(
                f"reconstructed the request: rendering "
                f"{request.rendering.version}, "
                f"{len(request.rendering.evidence_ids)} evidence id(s), "
                f"{len(request.rendering.truncations)} truncation(s)"
            )
            if not arguments.rerun:
                print("nothing was called; pass --rerun to ask the model again")
                return 0
            replayed = _rerun(settings, connection, stored, request, projection)
    except (
        routing.ReplayError,
        ContextOutsideRetention,
        ContractError,
        TaxonomyError,
        RenderingError,
        hosts.HostAttributesError,
        budgets.BudgetError,
        AgentError,
        ConfigurationError,
    ) as refused:
        print(f"FAILED: {refused}", file=sys.stderr)
        return 1
    except psycopg.Error as error:
        print(f"FAILED: the engine did not answer: {error}", file=sys.stderr)
        return 1

    _report(replayed, stored)
    return 0


if __name__ == "__main__":
    sys.exit(main())
