"""The router: three branches, and no model output reaching any of them.

Mirrors `src/helena/orchestration.py`. The sentences under test are
`concept/03-architecture.md`'s and `concept/04-the-two-agents.md`'s:

- *"Orchestration is deterministic project code. ... No agent selects, invokes,
  sequences or terminates another, and **no model output determines control
  flow**. Routing is an `if`."*
- *"if evidence escalates independently ... elif triage.root == 'suspicious' ...
  else: finish()"* — with the evidence branch **first**.
- *"The enrichment evidence escalates on its own ... **regardless of the triage
  verdict**. An LLM returning `normal` may not bury a high-confidence match."*
- *"A triage failure does not escalate."*
- *"The request carries ... the trigger (scheduled triage, triage-suspicious, or
  deterministic escalation)."*

**The endpoint is a real HTTP server** on the loopback interface, scripted per
test, for the reason `tests/test_triage.py` and `tests/test_analyst.py` give: the
transport and the bytes are what is exercised. Most tests here bind **no provider
tool**, because what is under test is which agent runs and not what it retrieves
— a loop with no tools makes exactly one call (`helena.analyst._retrieve`), which
keeps a routing test a routing test.

The three tests at the end run against a real engine: a real capture, a real
ThreatFox extract loaded through the real feed loader, and the routing decision
the store's own numbers produce.
"""

from __future__ import annotations

import ast
import importlib.util
import io
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import tomllib
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import psycopg
import pytest

from helena import (
    agents,
    analyst,
    budgets,
    disclosure,
    hosts,
    observability,
    orchestration,
    policy,
    rendering,
    triage,
)
from helena.agents import ModelClient, RetryPolicy
from helena.config import ModelSettings, Secret, Settings
from helena.contracts.v1 import (
    CONTRACT_VERSION,
    DETERMINISTIC_SIGNAL,
    MODEL_UNAVAILABLE,
    SCHEDULED_TRIAGE,
    SECTIONS,
    SUPPORTING,
    TRIAGE_SUSPICIOUS,
    TRIGGERS,
    AgentFailure,
    AgentRequest,
    AgentResult,
    Citation,
    Cost,
    RenderedSection,
    Rendering,
    RequestVersions,
)
from helena.enrichment import load_threatfox
from helena.normalizer import EventStore, Normalizer, describe_capture
from helena.observability import Redactor
from helena.policy import supports_in
from helena.policy import v1 as rule
from helena.rendering import ContextEntity, ContextProjection, EntityEnrichment
from helena.rendering import v1 as rendering_v1
from helena.taxonomy import ANALYST, TRIAGE

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PACKAGE_ROOT = PROJECT_ROOT / "src" / "helena"
FIXTURE_CAPTURES = PROJECT_ROOT / "tests" / "fixtures" / "captures"
LAYERS_CAPTURE = "ace6ca33f7bf8aa949f79124abf33fc115cfd0909e9dea798f4762cf87af8318"
THREATFOX_FIXTURE = PROJECT_ROOT / "tests" / "fixtures" / "threatfox" / "export.json"
RAW = THREATFOX_FIXTURE.read_bytes()

TENANT, SENSOR = "tenant-under-test", "sensor-under-test"
URL = "https://threatfox.invalid/export/json/recent/"
HOST = "10.127.0.100"
ADDRESS = "203.0.113.10"
DOMAIN = "c2.example.invalid"
WINDOW_START = datetime(2024, 6, 1, 12, 0, tzinfo=timezone.utc)
WINDOW_END = WINDOW_START + timedelta(minutes=5)
WINDOW_SECONDS = 300

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
}

#: The evidence id the synthetic rendering shows and the synthetic projection
#: carries. Real ones are a 64-character sha256; what matters here is that the
#: rendering and the projection agree, because a citation is resolved against
#: both.
SHOWN = "e" * 64

TRIAGE_PROMPT = triage.version("v1")
ANALYST_PROMPT = analyst.version("v1")
THREE_ATTEMPTS = RetryPolicy(attempts=3)
OFF = analyst.Inheritance(inherit_triage_rationale=False)

#: The project's own configuration, read from the committed files. Passed in
#: rather than loaded inside `assess`, which is the module's own rule.
THRESHOLDS = policy.thresholds()
BUDGET_POLICY = budgets.load()
SEND_POLICY = disclosure.send_policy()


# --- Builders ----------------------------------------------------------------


def versions(**overrides: str) -> RequestVersions:
    return RequestVersions(
        **{
            "prompt_version": TRIAGE_PROMPT.version,
            "schema_version": CONTRACT_VERSION,
            "rendering_version": "r1",
            "taxonomy_version": "v1",
            "enrichment_snapshot_version": "2024-06-01T00:00:00Z",
            "normalization_snapshot_version": "psl-2024-06-01",
            "policy_version": rule.POLICY_VERSION,
            "aggregation_version": "v1",
            "model_requested": "model-under-test",
            **overrides,
        }
    )


def a_rendering() -> Rendering:
    body = (
        f"address {ADDRESS} ports=443 bytes_sent=4200 bytes_received=51000 | "
        f"threatfox=malicious evidence={SHOWN}"
    )
    return Rendering(
        version="r1",
        sections=tuple(
            RenderedSection(
                section=name,
                body=body if name == "addresses_contacted" else f"<{name}> {DOMAIN}",
                evidence_ids=(SHOWN,) if name == "addresses_contacted" else (),
                truncation=None,
            )
            for name in SECTIONS
        ),
    )


def request(**overrides: object) -> AgentRequest:
    """The triage request, which is where routing begins."""
    return AgentRequest(
        **{
            "tenant": TENANT,
            "sensor": SENSOR,
            "emitter": TRIAGE,
            "host": HOST,
            "window_start": WINDOW_START,
            "window_end": WINDOW_END,
            "context_id": "ctx-1",
            "context_version": "ctx-1/3",
            "trigger": SCHEDULED_TRIAGE,
            "rendering": a_rendering(),
            "budgets": BUDGET_POLICY.for_emitter(TRIAGE),
            "versions": versions(),
            **overrides,
        }
    )


def a_projection(*, confidence: float = 1.0, **overrides: object) -> ContextProjection:
    """One context the store would produce: one address the host talked to, one claim.

    `confidence` is the dial the escalation turns on — `config/policy.toml` asks
    for 0.80, so 1.0 escalates and 0.5 does not, and every other property of the
    claim is held constant between the two.
    """
    return ContextProjection(
        **{
            "tenant": TENANT,
            "sensor": SENSOR,
            "host": HOST,
            "context_id": "ctx-1",
            "context_version": "ctx-1/3",
            "statistics": rendering.ConnectionStatistics(
                window_start=WINDOW_START,
                window_end=WINDOW_END,
                completeness="open",
                flow_count=3,
                duration_seconds=42.0,
                bytes_sent=4200,
                bytes_received=51_000,
                packets_sent=30,
                packets_received=60,
            ),
            "entities": (
                ContextEntity(
                    entity_type="address",
                    entity_value=ADDRESS,
                    fingerprint_algorithm=None,
                    observed_layers=("flow_destination",),
                    observed_flow_count=3,
                    observed_bytes_sent=4200,
                    observed_bytes_received=51_000,
                    ports=(443,),
                    enrichment=(
                        EntityEnrichment(
                            source_id="threatfox",
                            source_tier="B",
                            status="ok",
                            classification="malicious",
                            confidence=confidence,
                            scope_type="address",
                            scope_value=ADDRESS,
                            port_matched=None,
                            evidence_id=SHOWN,
                            snapshot_version="2024-06-01T00:00:00Z",
                        ),
                    ),
                ),
            ),
            "tls": (),
            **overrides,
        }
    )


def model_settings(url: str, *, agent: str) -> ModelSettings:
    return ModelSettings(
        agent=agent,
        endpoint_url=url,
        token=Secret("token-under-test"),
        model="model-under-test",
        source={"LLM_URL": "LLM_URL", "LLM_TOKEN": "LLM_TOKEN", "LLM_MODEL": "LLM_MODEL"},
    )


def logger(stream: io.StringIO, *, component: str) -> observability.StructuredLogger:
    return observability.StructuredLogger(
        component=component,
        tenant=TENANT,
        sensor=SENSOR,
        redactor=observability.Redactor(["token-under-test"]),
        stream=stream,
    )


# --- The scripted endpoint ---------------------------------------------------


class _Endpoint:
    """A real OpenAI-compatible endpoint on the loopback interface, scripted.

    A smaller copy of `tests/test_triage.py`'s, deliberately: a test module here
    is self-contained, and this one serves both agents from one script — which is
    also what makes the call order assertable.
    """

    def __init__(self, script: list[Any]) -> None:
        self.script = list(script)
        self.received: list[dict[str, Any]] = []
        endpoint = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self) -> None:  # noqa: N802 — the stdlib's name
                length = int(self.headers.get("Content-Length", 0))
                endpoint.received.append(json.loads(self.rfile.read(length)))
                assert endpoint.script, "the endpoint was called more times than scripted"
                nxt = endpoint.script.pop(0)
                if isinstance(nxt, int):
                    self.send_error(nxt)
                    return
                body = json.dumps(nxt).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args: object) -> None:
                """The stdlib handler logs to stderr; the suite has its own channel."""

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> _Endpoint:
        self.thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_port}/v1/"

    def client(self, agent: str, stream: io.StringIO) -> ModelClient:
        return model_client(self.url, agent, stream)


def model_client(url: str, agent: str, stream: io.StringIO) -> ModelClient:
    return ModelClient(
        model_settings(url, agent=agent),
        logger=logger(stream, component=f"agents.{agent}"),
    )


class _Elsewhere:
    """`_Endpoint`'s client half with no server: an address in another process.

    What `assess_at` points at. The killed-run test keeps the endpoint in the
    parent, because a child process that has to be killed mid-call cannot also be
    the thing that decides when the call hangs.
    """

    def __init__(self, url: str) -> None:
        self.url = url

    def client(self, agent: str, stream: io.StringIO) -> ModelClient:
        return model_client(self.url, agent, stream)


def answered(content: str, *, prompt: int = 40, completion: int = 20):
    return {
        "id": "cmpl-1",
        "model": "model-under-test-2026-05",
        "choices": [
            {
                "index": 0,
                "finish_reason": "stop",
                "message": {"role": "assistant", "content": content},
            }
        ],
        "usage": {"prompt_tokens": prompt, "completion_tokens": completion},
    }


def said(**fields: Any) -> str:
    return json.dumps(fields)


TRIAGE_NORMAL = said(classification="normal", confidence=0.9)
TRIAGE_SUSPICIOUS_ANSWER = said(
    classification="suspicious",
    confidence=0.6,
    citations=[{"evidence_id": SHOWN, "stance": SUPPORTING}],
)
#: The analyst's answer. Bounded to what a run with no tools can support: the
#: claim the enrichment tier already carries, cited, with the package
#: `concept/04` requires of a non-`normal` analyst verdict.
ANALYST_ANSWER = said(
    classification="suspicious.low_reputation",
    confidence=0.5,
    citations=[{"evidence_id": SHOWN, "stance": SUPPORTING}],
    evidence_package={
        "patterns": ["beaconing"],
        "narrative": "the address answered and the traffic went both ways",
    },
)


def assess(
    endpoint: _Endpoint,
    *,
    projection: ContextProjection | None = None,
    asked: AgentRequest | None = None,
    stream: io.StringIO | None = None,
    provider_tools: Any = (),
) -> orchestration.Assessment:
    stream = io.StringIO() if stream is None else stream
    asked = request() if asked is None else asked
    return orchestration.assess(
        asked,
        projection=a_projection() if projection is None else projection,
        triage_client=endpoint.client(TRIAGE, stream),
        analyst_client=endpoint.client(ANALYST, stream),
        retry=THREE_ATTEMPTS,
        triage_prompt=TRIAGE_PROMPT,
        analyst_prompt=ANALYST_PROMPT,
        provider_tools=provider_tools,
        thresholds=THRESHOLDS,
        budget_policy=BUDGET_POLICY,
        send_policy=SEND_POLICY,
        inherit=OFF,
        logger=logger(stream, component="orchestration"),
    )


def assess_at(url: str) -> orchestration.Assessment:
    """One assessment against an endpoint in another process.

    The entry point `test_a_killed_run_leaves_nothing_on_disk`'s child process
    calls, module-level so the child can reach it with one import.
    """
    return assess(_Elsewhere(url))


def escalation_of(projection: ContextProjection):
    """The escalation, computed the way `assess` computes it. No model anywhere."""
    return rule.escalate(supports_in(projection), THRESHOLDS)


def records(stream: io.StringIO) -> list[dict[str, Any]]:
    return [json.loads(line) for line in stream.getvalue().splitlines()]


def events(stream: io.StringIO) -> list[str]:
    return [record["event"] for record in records(stream)]


def one(stream: io.StringIO, event: str) -> dict[str, Any]:
    """The fields of the one record with this event name.

    `helena.observability` lifts `context_id` and the versions out of the fields
    and leaves the rest under `fields`; this is that shape, unwrapped once, so a
    test asserts on what was recorded rather than on where the logger puts it.
    """
    found = [record for record in records(stream) if record["event"] == event]
    assert len(found) == 1, f"{len(found)} {event!r} records"
    return {"context_id": found[0]["context_id"], **found[0]["fields"]}


# --- The routing `if` itself --------------------------------------------------


def a_cost() -> Cost:
    return Cost(
        prompt_tokens=40,
        completion_tokens=20,
        wall_clock_seconds=0.1,
        retries=0,
        live_queries=0,
        cache_hits=0,
        steps=0,
    )


def a_result(classification: str) -> AgentResult:
    return AgentResult(
        emitter=TRIAGE,
        classification=classification,
        confidence=0.7,
        citations=()
        if classification == "normal"
        else (Citation(evidence_id=SHOWN, stance=SUPPORTING),),
        gaps=(),
        cost=a_cost(),
        versions=versions().completed_by("model-under-test-2026-05"),
    )


def a_failure() -> AgentFailure:
    return AgentFailure(
        emitter=TRIAGE,
        reason=MODEL_UNAVAILABLE,
        detail="the endpoint did not answer",
        cost=a_cost(),
        versions=versions(),
    )


@pytest.mark.parametrize(
    ("escalates", "outcome", "expected"),
    [
        (True, a_result("normal"), DETERMINISTIC_SIGNAL),
        (True, a_result("suspicious"), DETERMINISTIC_SIGNAL),
        (True, a_failure(), DETERMINISTIC_SIGNAL),
        (False, a_result("normal"), None),
        (False, a_result("suspicious"), TRIAGE_SUSPICIOUS),
        (False, a_failure(), None),
    ],
)
def test_the_router_is_the_three_branches_concept_03_writes(
    escalates: bool, outcome: Any, expected: str | None
):
    """Every cell of the table `concept/03`'s pseudocode defines, enumerated.

    Three triage outcomes are all there are — the two roots the contract closes
    triage over, and a typed failure — so this is exhaustive rather than
    representative. The evidence branch wins in all three of its rows, which is
    the shape of *"regardless of the triage verdict"*.
    """
    projection = a_projection(confidence=1.0 if escalates else 0.5)
    escalation = escalation_of(projection)
    assert escalation.escalates is escalates
    assert orchestration.route(escalation, outcome) == expected


def test_a_triage_failure_does_not_escalate_on_its_own():
    """`concept/04`: *"A triage failure does not escalate."*

    Routed exactly as a `normal` is, and for the reason that note gives — the
    other input does not care whether triage ran at all — so failing closed is
    only safe because the evidence branch is there. That is one assertion here
    and not two sentences: the same failure routes to `finish` under quiet
    evidence and to the analyst under escalating evidence.
    """
    failure = a_failure()
    assert orchestration.route(escalation_of(a_projection(confidence=0.5)), failure) is None
    assert (
        orchestration.route(escalation_of(a_projection(confidence=1.0)), failure)
        == DETERMINISTIC_SIGNAL
    )


def test_the_evidence_branch_is_first_and_says_so_in_the_trigger():
    """Both branches reach the same agent, so the order is about the record.

    A context that escalated on its own **and** whose triage said `suspicious`
    is recorded as `deterministic_signal`. Reversing the two would store the
    model's opinion as the reason for a run the evidence had already required.
    """
    assert (
        orchestration.route(
            escalation_of(a_projection(confidence=1.0)), a_result("suspicious")
        )
        == DETERMINISTIC_SIGNAL
    )


def test_the_triage_half_of_the_router_is_the_runner_s_own_reading():
    """One definition of "triage escalates", not two.

    `helena.triage.escalates` is what refuses to read a verdict off a typed
    failure and what tests *not `normal`* rather than *is `suspicious`*; a second
    copy in the router would be a second opinion about which roots escalate.
    """
    source = ast.parse((PACKAGE_ROOT / "orchestration.py").read_text())
    router = next(
        node
        for node in ast.walk(source)
        if isinstance(node, ast.FunctionDef) and node.name == "route"
    )
    calls = [
        ast.unparse(node.func)
        for node in ast.walk(router)
        if isinstance(node, ast.Call)
    ]
    assert calls == ["triage.escalates"]
    # And the only attribute it reads off the escalation is the boolean.
    read = {
        node.attr
        for node in ast.walk(router)
        if isinstance(node, ast.Attribute) and ast.unparse(node.value) == "escalation"
    }
    assert read == {"escalates"}


# --- No model output determines control flow ---------------------------------


def test_model_output_cannot_change_which_agent_runs_next():
    """`concept/instruction.md` §2, as an executed property rather than a comment.

    The same escalating context is triaged four ways — `normal`, `suspicious`, a
    schema-invalid answer that becomes a typed failure, and an endpoint that
    never answers — and every one of them runs the analyst under
    `deterministic_signal`. Whatever the model said, the next agent and the
    reason recorded for it are the same.
    """
    scripts = {
        "normal": [answered(TRIAGE_NORMAL), answered(ANALYST_ANSWER)],
        "suspicious": [answered(TRIAGE_SUSPICIOUS_ANSWER), answered(ANALYST_ANSWER)],
        "unparseable": [answered("not json"), answered("not json"), answered("not json"), answered(ANALYST_ANSWER)],
        "unreachable": [503, 503, 503, answered(ANALYST_ANSWER)],
    }
    routed = {}
    for name, script in scripts.items():
        with _Endpoint(script) as endpoint:
            assessment = assess(endpoint)
        routed[name] = (
            assessment.trigger,
            assessment.analyst_request.emitter,
            assessment.escalation.evidence_ids,
        )
    assert set(routed.values()) == {(DETERMINISTIC_SIGNAL, ANALYST, (SHOWN,))}


def test_a_normal_verdict_cannot_bury_a_high_confidence_match():
    """`concept/04`'s sentence, over the whole runner rather than the evaluator.

    The model says `normal` with high confidence and the analyst runs anyway,
    under the trigger that names the evidence and not the verdict.
    """
    with _Endpoint([answered(TRIAGE_NORMAL), answered(ANALYST_ANSWER)]) as endpoint:
        assessment = assess(endpoint)
    assert isinstance(assessment.triage, AgentResult)
    assert assessment.triage.root == "normal"
    assert assessment.trigger == DETERMINISTIC_SIGNAL
    assert assessment.analysis is not None
    assert assessment.terminal is assessment.analysis.outcome


def test_the_escalation_is_identical_whatever_triage_said():
    """Independence, asserted over the record rather than over the signature.

    `tests/test_policy.py` asserts that the evaluator has no parameter a verdict
    could arrive through. This asserts the consequence: the escalation the runner
    produced is the same object for a `normal`, a `suspicious` and a failure, down
    to its candidates and its gaps.
    """
    produced = []
    for script in (
        [answered(TRIAGE_NORMAL), answered(ANALYST_ANSWER)],
        [answered(TRIAGE_SUSPICIOUS_ANSWER), answered(ANALYST_ANSWER)],
        [503, 503, 503, answered(ANALYST_ANSWER)],
    ):
        with _Endpoint(script) as endpoint:
            produced.append(assess(endpoint).escalation)
    assert produced[0] == produced[1] == produced[2]
    assert produced[0] == escalation_of(a_projection())


def test_the_escalation_is_recorded_before_the_model_is_called():
    """*Before* is read out of a stream, not asserted about the source.

    The router and both model clients write to one log channel, so the order of
    the lines is the order the code ran in. The escalation record is first, which
    is what makes *"computed before and independently of the triage call"* a thing
    this suite observed.
    """
    stream = io.StringIO()
    with _Endpoint([answered(TRIAGE_NORMAL), answered(ANALYST_ANSWER)]) as endpoint:
        assess(endpoint, stream=stream)
    written = events(stream)
    assert written[0] == orchestration.ESCALATION_EVALUATED
    assert orchestration.ROUTED in written
    # Every model call happened after the escalation was already decided, and
    # the analyst's calls happened after the route was recorded.
    calls = [
        index
        for index, event in enumerate(written)
        if event == "agents.model.call"
    ]
    assert len(calls) == 2, written
    assert min(calls) > written.index(orchestration.ESCALATION_EVALUATED)
    assert max(calls) > written.index(orchestration.ROUTED)


def test_the_routing_decision_is_countable_on_the_log_channel():
    """`concept/07` wants the routing countable, and the two questions differ.

    "How often did the evidence escalate" and "where did this context end up"
    are separate records, so a context that escalated *and* whose triage said
    `suspicious` is not indistinguishable from one that only escalated.
    """
    stream = io.StringIO()
    with _Endpoint(
        [answered(TRIAGE_SUSPICIOUS_ANSWER), answered(ANALYST_ANSWER)]
    ) as endpoint:
        assess(endpoint, stream=stream)
    routed = one(stream, orchestration.ROUTED)
    assert routed["trigger"] == DETERMINISTIC_SIGNAL
    assert routed["escalates"] is True
    assert routed["triage_outcome"] == "suspicious"
    assert routed["context_id"] == "ctx-1"
    evaluated = one(stream, orchestration.ESCALATION_EVALUATED)
    assert evaluated["evidence_ids"] == [SHOWN]
    assert evaluated["policy_version"] == rule.POLICY_VERSION
    assert evaluated["thresholds_version"] == THRESHOLDS.thresholds_version


def test_a_failed_triage_run_is_recorded_as_a_failure_and_never_as_normal():
    """`concept/instruction.md` §2 keeps a typed failure distinct from a verdict.

    The log line a routing count reads has to keep them apart too, or "the model
    was down" becomes "the context was clean" in the one place anybody would
    notice it.
    """
    stream = io.StringIO()
    with _Endpoint([503, 503, 503]) as endpoint:
        assessment = assess(endpoint, projection=a_projection(confidence=0.5), stream=stream)
    assert isinstance(assessment.triage, AgentFailure)
    assert assessment.trigger is None
    routed = one(stream, orchestration.ROUTED)
    assert routed["triage_outcome"] == MODEL_UNAVAILABLE
    assert routed["trigger"] == orchestration.FINISHED


def test_quiet_evidence_and_a_normal_verdict_finish_without_the_analyst():
    """The third branch. One model call in the whole assessment, and no analysis."""
    with _Endpoint([answered(TRIAGE_NORMAL)]) as endpoint:
        assessment = assess(endpoint, projection=a_projection(confidence=0.5))
        assert endpoint.received and not endpoint.script
    assert assessment.trigger is None
    assert assessment.analysis is None and assessment.analyst_request is None
    assert assessment.terminal is assessment.triage


def test_quiet_evidence_and_a_suspicious_verdict_reach_the_analyst():
    """The second branch, and the only one a model can reach."""
    with _Endpoint(
        [answered(TRIAGE_SUSPICIOUS_ANSWER), answered(ANALYST_ANSWER)]
    ) as endpoint:
        assessment = assess(endpoint, projection=a_projection(confidence=0.5))
    assert assessment.trigger == TRIAGE_SUSPICIOUS
    assert assessment.analyst_request.trigger == TRIAGE_SUSPICIOUS
    assert assessment.analysis is not None


# --- The trigger travels in the request --------------------------------------


def test_the_derived_request_changes_four_fields_and_nothing_else():
    """`concept/04`: the request carries the trigger, and it is what says why.

    The context reference, its version and the rendering are the same objects, so
    the two records join and a replay of either is a replay of one snapshot.
    """
    triage_request = request()
    escalated = orchestration.analyst_request(
        triage_request,
        trigger=DETERMINISTIC_SIGNAL,
        prompt_version=ANALYST_PROMPT.version,
        granted=BUDGET_POLICY.for_emitter(ANALYST),
    )
    changed = {
        name
        for name in AgentRequest.model_fields
        if getattr(escalated, name) != getattr(triage_request, name)
    }
    # A subset rather than an equality, and the reason is worth writing down: the
    # two prompt versions are **both** `v1` today, because a prompt version is
    # per-package and the two packages each start at one. So `versions` compares
    # equal here and would not once either agent ships a `v2`. What a stored row
    # tells the two apart by is the emitter, not the prompt version alone.
    assert changed <= {"emitter", "trigger", "budgets", "versions"}
    assert {"emitter", "trigger", "budgets"} <= changed
    assert escalated.emitter == ANALYST
    assert escalated.trigger == DETERMINISTIC_SIGNAL
    assert escalated.budgets == BUDGET_POLICY.for_emitter(ANALYST)
    assert escalated.rendering is triage_request.rendering
    assert (escalated.context_id, escalated.context_version) == (
        triage_request.context_id,
        triage_request.context_version,
    )
    # The only version dimension that moves is the prompt: a different agent's
    # frozen words, over the same taxonomy, policy, rendering and snapshots.
    moved = {
        name
        for name in RequestVersions.model_fields
        if getattr(escalated.versions, name) != getattr(triage_request.versions, name)
    }
    assert moved <= {"prompt_version"}
    assert escalated.versions.prompt_version == ANALYST_PROMPT.version


def test_the_derived_request_is_revalidated_by_the_contract():
    """A request built by a copy that skipped validation is the one nothing checked.

    `AgentRequest` refuses `scheduled_triage` paired with the analyst; the router
    refuses it first so the message names the router, and the contract would
    refuse it anyway.
    """
    with pytest.raises(orchestration.OrchestrationError, match="not one of the analyst"):
        orchestration.analyst_request(
            request(),
            trigger=SCHEDULED_TRIAGE,
            prompt_version=ANALYST_PROMPT.version,
            granted=BUDGET_POLICY.for_emitter(ANALYST),
        )


def test_the_analyst_is_budgeted_by_the_policy_file():
    """`concept/07`: budget values are policy, not constants in a branch.

    The triage request carries triage's budget — no steps, no live queries, which
    the contract enforces — and the escalated request carries the analyst's,
    read from `config/policy.toml` rather than from the request that escalated.
    """
    with _Endpoint([answered(TRIAGE_NORMAL), answered(ANALYST_ANSWER)]) as endpoint:
        assessment = assess(endpoint)
    granted = assessment.analyst_request.budgets
    assert granted == BUDGET_POLICY.for_emitter(ANALYST)
    assert granted.steps > 0 and granted.live_queries > 0
    assert assessment.request.budgets.steps == 0


def test_each_stage_gets_its_own_disclosure_ledger():
    """A ledger names the emitter it is the record of (`helena.disclosure`).

    One shared between the two stages would file the analyst's disclosures under
    triage, which is the one field an auditor reading a disclosure row needs.
    """
    with _Endpoint([answered(TRIAGE_NORMAL), answered(ANALYST_ANSWER)]) as endpoint:
        assessment = assess(endpoint)
    assert assessment.triage_disclosures.emitter == TRIAGE
    assert assessment.analyst_disclosures.emitter == ANALYST
    assert assessment.triage_disclosures is not assessment.analyst_disclosures
    # Hosted inference is egress (`concept/03`), so both ledgers hold a row.
    assert assessment.triage_disclosures.rows and assessment.analyst_disclosures.rows


# --- What the router refuses --------------------------------------------------


def test_routing_begins_with_a_triage_request():
    with _Endpoint([]) as endpoint:
        with pytest.raises(orchestration.OrchestrationError, match="one entry point"):
            assess(
                endpoint,
                asked=orchestration.analyst_request(
                    request(),
                    trigger=DETERMINISTIC_SIGNAL,
                    prompt_version=ANALYST_PROMPT.version,
                    granted=BUDGET_POLICY.for_emitter(ANALYST),
                ),
            )


def test_an_assessment_whose_trigger_and_analysis_disagree_is_refused():
    """The trigger is what says analysis ran; a record where the two differ is unreadable."""
    with _Endpoint([answered(TRIAGE_NORMAL), answered(ANALYST_ANSWER)]) as endpoint:
        assessment = assess(endpoint)
    with pytest.raises(orchestration.OrchestrationError, match="analysis is"):
        orchestration.Assessment(
            request=assessment.request,
            escalation=assessment.escalation,
            triage=assessment.triage,
            triage_disclosures=assessment.triage_disclosures,
            trigger=None,
            analyst_request=None,
            analysis=assessment.analysis,
            analyst_disclosures=None,
        )


def test_an_assessment_cannot_record_a_trigger_its_request_does_not():
    with _Endpoint([answered(TRIAGE_NORMAL), answered(ANALYST_ANSWER)]) as endpoint:
        assessment = assess(endpoint)
    with pytest.raises(orchestration.OrchestrationError, match="two copies"):
        orchestration.Assessment(
            request=assessment.request,
            escalation=assessment.escalation,
            triage=assessment.triage,
            triage_disclosures=assessment.triage_disclosures,
            trigger=TRIAGE_SUSPICIOUS,
            analyst_request=assessment.analyst_request,
            analysis=assessment.analysis,
            analyst_disclosures=assessment.analyst_disclosures,
        )


def test_the_rules_are_loaded_from_the_version_the_request_records():
    """Not a parameter, for the reason the composition rule is not one.

    A caller that could pass different rules could escalate a context under rules
    its stored row does not name.
    """
    with _Endpoint([]) as endpoint:
        with pytest.raises(policy.UnknownVersion, match="no policy version 'v9'"):
            assess(endpoint, asked=request(versions=versions(policy_version="v9")))


# --- No graph framework, workflow engine or checkpoint store ------------------

# Distribution name -> the top-level module it installs. `concept/03` makes
# orchestration "plain project-owned Python" and `concept/instruction.md` §2
# forbids a checkpoint store outright; both are how a graph framework arrives, so
# the two lists are one test. `tests/test_dependency_boundary.py` owns the
# approved set and already refuses `langgraph`; this refuses the category, so a
# second one arriving is a failing test rather than a pull request nobody reads.
ORCHESTRATION_FRAMEWORKS = {
    "langgraph": "langgraph",
    "langgraph-checkpoint": "langgraph",
    "llama-index": "llama_index",
    "autogen": "autogen",
    "pyautogen": "autogen",
    "crewai": "crewai",
    "haystack-ai": "haystack",
    "semantic-kernel": "semantic_kernel",
    "smolagents": "smolagents",
    "dspy": "dspy",
    "burr": "burr",
    "controlflow": "controlflow",
    "prefect": "prefect",
    "dagster": "dagster",
    "apache-airflow": "airflow",
    "luigi": "luigi",
    "metaflow": "metaflow",
    "kedro": "kedro",
    "flytekit": "flytekit",
    "temporalio": "temporalio",
    "celery": "celery",
    "dramatiq": "dramatiq",
    "rq": "rq",
    "ray": "ray",
}

# Durable stores a checkpoint would go to. `concept/instruction.md` §2: "no second
# database, no vector store, no checkpoint store, no file-backed agent memory, no
# cache that is not itself the evidence store."
CHECKPOINT_STORES = {
    "redis": "redis",
    "diskcache": "diskcache",
    "joblib": "joblib",
    "tinydb": "tinydb",
    "lmdb": "lmdb",
    "plyvel": "plyvel",
    "duckdb": "duckdb",
    "sqlalchemy": "sqlalchemy",
    "chromadb": "chromadb",
    "faiss-cpu": "faiss",
    "qdrant-client": "qdrant_client",
}

#: The standard library's own file-backed stores. Importable everywhere, so what
#: is asserted is that the **package** does not reach for one — a checkpoint
#: written with `shelve` is a second store exactly as one written with `redis`.
STDLIB_PERSISTENCE = ("pickle", "shelve", "dbm", "sqlite3", "marshal")

_REQUIREMENT_NAME = re.compile(r"^[A-Za-z0-9._-]+")


def _declared() -> set[str]:
    document = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text())
    requirements = list(document["project"]["dependencies"]) + list(
        document["dependency-groups"]["dev"]
    )
    return {
        _REQUIREMENT_NAME.match(requirement).group(0).lower().replace("_", "-")
        for requirement in requirements
    }


def _package_imports() -> set[str]:
    imported: set[str] = set()
    for module in sorted(PACKAGE_ROOT.rglob("*.py")):
        for node in ast.walk(ast.parse(module.read_text(), filename=str(module))):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                imported.add(node.module.split(".")[0])
    return imported


def test_no_graph_framework_or_workflow_engine_is_declared_or_imported():
    """`concept/03`: orchestration is "plain project-owned Python".

    Routing is an `if`, so a graph is a runtime that would own the control flow
    the concept gives to this module — and every one of these brings a checkpoint
    backend with it, which `concept/instruction.md` §2 forbids separately.
    """
    declared = _declared()
    assert not declared.intersection(ORCHESTRATION_FRAMEWORKS)
    imported = _package_imports()
    assert not imported.intersection(ORCHESTRATION_FRAMEWORKS.values())


def test_no_checkpoint_store_is_declared_or_imported():
    """One store. A resumable graph's state has nowhere in this system to live."""
    declared = _declared()
    assert not declared.intersection(CHECKPOINT_STORES)
    imported = _package_imports()
    assert not imported.intersection(CHECKPOINT_STORES.values())
    assert not imported.intersection(STDLIB_PERSISTENCE), (
        "the package reaches for a standard-library file-backed store. A "
        "checkpoint written with `shelve` is a second store exactly as one "
        "written with `redis` (`concept/instruction.md` §2)."
    )


def test_no_orchestration_framework_is_even_importable_from_the_environment():
    """Not declared is not enough: a transitive install would still be one line away.

    The same rule `tests/test_dependency_boundary.py` applies to hosted tracing,
    and for the same reason — the thing that makes an invariant hold is that
    breaking it is hard, not that nobody has.
    """
    resolvable = sorted(
        {
            module
            for module in set(ORCHESTRATION_FRAMEWORKS.values())
            | set(CHECKPOINT_STORES.values())
            if importlib.util.find_spec(module) is not None
        }
    )
    assert not resolvable, (
        f"an orchestration framework or checkpoint store is installed: "
        f"{resolvable}. It arrived transitively; find which, and record the "
        f"decision before leaving it there."
    )


def test_the_router_holds_no_state_between_assessments():
    """An assessment is one function call (`concept/03`).

    `helena.orchestration` has no module-level mutable object at all, so there is
    nothing for one context's run to leave behind for the next — which is what
    makes "an interrupted run is simply re-run" a property rather than a plan.
    Task 44 is where re-run recovery is built; this is the half that is true now.
    """
    module = ast.parse((PACKAGE_ROOT / "orchestration.py").read_text())
    assigned = {
        target.id: node.value
        for node in module.body
        if isinstance(node, ast.Assign)
        for target in node.targets
        if isinstance(target, ast.Name)
    }
    # `__all__` is the export list every module here has and is not state.
    held = {
        name: value for name, value in assigned.items() if not name.startswith("__")
    }
    assert held, "the module-level constants were not found; has the file moved?"
    # Checked off the shape of the expression rather than by evaluating it:
    # `CHILD_TABLES` is a tuple of the table-name constants above it, which is
    # immutable and is not a literal. What makes something state is that it is a
    # container that can be mutated or an object that was constructed — a dict, a
    # list, a set, a comprehension or a call.
    STATEFUL = (
        ast.Dict,
        ast.List,
        ast.Set,
        ast.DictComp,
        ast.ListComp,
        ast.SetComp,
        ast.GeneratorExp,
        ast.Call,
    )
    for name, value in held.items():
        for node in ast.walk(value):
            assert not isinstance(node, STATEFUL), (
                f"{name} is a mutable or constructed module-level object: "
                f"{ast.unparse(value)}"
            )


# --- Ephemeral state: the working memory is the call --------------------------
#
# `concept/03`: *"An assessment is one function call over one versioned context
# snapshot. No checkpointing, no durable in-flight state anywhere outside the
# engine ... **Framework and in-process state is ephemeral.** Scratchpads,
# tool-loop transcripts, planning state and any framework's virtual files are
# working memory for one assessment."*
#
# The tests above assert the absence of the frameworks that would bring a durable
# backend. These assert the property that absence is for: what a run accumulates
# is reachable only from the call, and a run that is killed leaves nothing.

#: The standard library's ways of writing a file, and the two modules whose whole
#: job is producing one. A scratchpad, a tool-loop transcript or a framework's
#: virtual filesystem arrives as one of these, so the package calling none of them
#: is what makes "working memory for one assessment" a property rather than an
#: intention. `helena.observability` writes to a **stream** its caller opened,
#: which is why `.write` is not among them.
FILE_WRITING_METHODS = (
    "write_text",
    "write_bytes",
    "touch",
    "mkdir",
    "makedirs",
    "unlink",
    "symlink_to",
    "hardlink_to",
)
FILE_WRITING_OS_CALLS = (
    "open",
    "remove",
    "unlink",
    "mkdir",
    "makedirs",
    "rename",
    "replace",
    "rmdir",
    "write",
)
FILE_PRODUCING_MODULES = ("tempfile", "shutil")


def test_the_package_writes_no_file_anywhere():
    """No scratchpad, no transcript on disk, no virtual filesystem.

    There is no framework here to disable the feature on, so what is asserted is
    the property directly: nothing in `helena` opens a file for writing, creates a
    directory or reaches for `tempfile`. The single store is the engine, and a run's
    working memory is the objects the call holds.
    """
    offenders: list[str] = []
    for module in sorted(PACKAGE_ROOT.rglob("*.py")):
        where = module.relative_to(PACKAGE_ROOT)
        for node in ast.walk(ast.parse(module.read_text(), filename=str(module))):
            if isinstance(node, ast.Import):
                offenders += [
                    f"{where}: import {alias.name}"
                    for alias in node.names
                    if alias.name.split(".")[0] in FILE_PRODUCING_MODULES
                ]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                if node.module.split(".")[0] in FILE_PRODUCING_MODULES:
                    offenders.append(f"{where}: from {node.module} import …")
            elif isinstance(node, ast.Call):
                called = node.func
                if isinstance(called, ast.Name) and called.id == "open":
                    offenders.append(f"{where}:{node.lineno}: open(…)")
                elif isinstance(called, ast.Attribute):
                    on_os = (
                        isinstance(called.value, ast.Name) and called.value.id == "os"
                    )
                    if called.attr in FILE_WRITING_METHODS or (
                        on_os and called.attr in FILE_WRITING_OS_CALLS
                    ):
                        offenders.append(f"{where}:{node.lineno}: .{called.attr}(…)")
    assert not offenders, (
        f"the package writes to the filesystem: {offenders}. Durable state is "
        f"typed rows in the engine (`concept/instruction.md` §2); a file is a "
        f"second store, and an agent's notes in one are a second store of "
        f"uncited free text."
    )


def test_the_runs_of_a_pass_are_exactly_the_pairings_the_contract_accepts():
    """Two copies of the enumeration, asserted equal by construction.

    `orchestration.RUNS_OF_A_PASS` is what a re-run addresses to supersede the
    runs it replaced, so a fourth pairing the contract began to accept and this
    list did not would be a row nothing ever collects.
    """
    accepted = set()
    for emitter in (TRIAGE, ANALYST):
        for trigger in TRIGGERS:
            try:
                request(
                    emitter=emitter,
                    trigger=trigger,
                    budgets=BUDGET_POLICY.for_emitter(emitter),
                )
            except ValueError:
                continue  # pydantic's ValidationError is one
            accepted.add((emitter, trigger))
    assert set(orchestration.RUNS_OF_A_PASS) == accepted
    assert len(orchestration.RUNS_OF_A_PASS) == len(set(orchestration.RUNS_OF_A_PASS))


def _helena_modules() -> dict[str, dict[str, Any]]:
    return {
        name: dict(vars(module))
        for name, module in sorted(sys.modules.items())
        if name == "helena" or name.startswith("helena.")
    }


def test_a_run_leaves_nothing_behind_in_any_helena_module():
    """Asserted by execution, not off the source: run one, then compare.

    `test_the_router_holds_no_state_between_assessments` reads `orchestration.py`
    for a module-level container. This runs a whole assessment — both agents, both
    disclosure ledgers, the budget guard, the analyst's tool loop — and asserts
    that no module in the package gained, lost or rebound a single name while it
    happened. The first run is the warm-up: `helena.policy.version` and its four
    siblings import their frozen version module on first use, and an import is
    exactly the once-per-process event this must not confuse for state.
    """
    with _Endpoint([answered(TRIAGE_NORMAL), answered(ANALYST_ANSWER)]) as endpoint:
        first = assess(endpoint)
    before = _helena_modules()

    with _Endpoint([answered(TRIAGE_NORMAL), answered(ANALYST_ANSWER)]) as endpoint:
        second = assess(endpoint)
    after = _helena_modules()

    assert set(after) == set(before), "a helena module was imported by the run"
    for name in before:
        assert set(after[name]) == set(before[name]), f"{name} gained or lost a name"
        for attribute, value in before[name].items():
            assert after[name][attribute] is value, f"{name}.{attribute} was rebound"

    # And the two runs share no working memory: each ledger is the record of one
    # run, and the first one is exactly what it was when its run returned.
    assert first.triage_disclosures is not second.triage_disclosures
    assert first.analyst_disclosures is not second.analyst_disclosures
    assert len(first.triage_disclosures.rows) == len(second.triage_disclosures.rows)


def test_a_killed_run_leaves_nothing_on_disk():
    """`SIGKILL` mid-assessment, and the process's whole writable world is empty.

    A child process runs one assessment against an endpoint here that accepts the
    prompt and never answers, so it is killed inside the first model call — with
    no cleanup, no `finally` and no `atexit`, which is the point: what is being
    asserted is that there was nothing to clean up. Its home, its temporary
    directory and its working directory are three empty directories under
    `tmp_path`, and after the kill they still are.

    Bytecode caching is turned off in the child rather than tolerated: a `.pyc`
    the interpreter wrote is not this system's state, and a test that allowed one
    exception would have to allow the next.
    """
    hangs = _Hangs()
    work = Path(tempfile.mkdtemp(prefix="killed-run-"))
    try:
        home, temporary, working = (work / "home", work / "tmp", work / "cwd")
        for directory in (home, temporary, working):
            directory.mkdir()
        child = working / "run.py"
        child.write_text(
            "import sys\n"
            f"sys.path.insert(0, {str(PROJECT_ROOT / 'tests')!r})\n"
            "import test_orchestration\n"
            "test_orchestration.assess_at(sys.argv[1])\n"
        )
        before = set(work.rglob("*"))

        with hangs:
            running = subprocess.Popen(
                [sys.executable, str(child), hangs.url],
                cwd=working,
                env={
                    "PATH": os.environ["PATH"],
                    "HOME": str(home),
                    "TMPDIR": str(temporary),
                    "XDG_CACHE_HOME": str(home / "cache"),
                    "PYTHONDONTWRITEBYTECODE": "1",
                    "PYTHONPATH": str(PROJECT_ROOT / "src"),
                },
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                assert hangs.called.wait(timeout=120), (
                    f"the child never reached the endpoint: "
                    f"{running.communicate(timeout=30)[1].decode()}"
                )
                running.kill()
                running.communicate(timeout=60)
            finally:
                if running.poll() is None:  # pragma: no cover — the kill worked
                    running.kill()
                    running.communicate(timeout=60)

        assert running.returncode == -signal.SIGKILL, (
            f"the child exited {running.returncode} rather than being killed, so "
            f"it had the chance to tidy up and this proves nothing"
        )
        assert set(work.rglob("*")) - before == set(), (
            "a killed run left a file behind. `concept/03` allows no durable "
            "in-flight state anywhere outside the engine."
        )
    finally:
        hangs.close()
        shutil.rmtree(work, ignore_errors=True)


class _Hangs:
    """An endpoint that accepts a prompt and never answers.

    What holds the child inside its first model call while it is killed, so what
    the test observes is an assessment that was interrupted rather than one that
    finished and tidied up. Threading, because the parent has to keep serving
    while it kills the caller.
    """

    def __init__(self) -> None:
        self.called = threading.Event()
        self.release = threading.Event()
        endpoint = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self) -> None:  # noqa: N802 — the stdlib's name
                self.rfile.read(int(self.headers.get("Content-Length", 0)))
                endpoint.called.set()
                endpoint.release.wait(timeout=120)

            def log_message(self, *args: object) -> None:
                """The stdlib handler logs to stderr; the suite has its own channel."""

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> _Hangs:
        self.thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.release.set()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_port}/v1/"

    def close(self) -> None:
        self.release.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


# --- Against a real engine ----------------------------------------------------


def settings() -> Settings:
    return Settings.load(environ=ENVIRONMENT, env_file=None)


def current_window() -> float:
    return float(int(time.time() // WINDOW_SECONDS) * WINDOW_SECONDS)


def targeted(raw: bytes, entity_value: str, ioc_type: str) -> bytes:
    """The committed extract with one entry repointed at an entity the capture has."""
    document = json.loads(raw)
    key = sorted(document)[0]
    document[key][0]["ioc_type"] = ioc_type
    document[key][0]["ioc_value"] = entity_value
    return json.dumps(document).encode()


@pytest.fixture
def live(migrated_engine: psycopg.Connection, tmp_path: Path) -> psycopg.Connection:
    """The layer-coverage capture, re-stamped into the window `now` falls in.

    The same fixture `tests/test_policy.py` and `tests/test_analyst.py` use: the
    projection reads `helena_signal_host_context_live`, which is inside the
    retention boundary.
    """
    path = tmp_path / "restamped.jsonl"
    records_in = [
        {**json.loads(line), "ts": current_window() + 1}
        for line in (FIXTURE_CAPTURES / f"{LAYERS_CAPTURE}.jsonl").read_bytes().splitlines()
    ]
    path.write_bytes(
        b"".join(json.dumps(record).encode() + b"\n" for record in records_in)
    )
    configured = settings()
    normalizer = Normalizer.from_settings(configured)
    events_store = EventStore(connection=migrated_engine, identity=configured.identity)
    for outcome in normalizer.normalize_capture(describe_capture(path)):
        events_store.record(outcome)
    migrated_engine.execute("FLUSH")
    return migrated_engine


def load_extract(connection: psycopg.Connection, raw: bytes) -> None:
    load_threatfox(
        connection,
        tenant=TENANT,
        sensor=SENSOR,
        source_url=URL,
        redactor=Redactor.from_settings(settings()),
        raw=raw,
        now=datetime.fromtimestamp(current_window(), tz=timezone.utc),
    )


def a_live_projection(connection: psycopg.Connection) -> ContextProjection:
    found = connection.execute(
        "SELECT context_id FROM helena_signal_host_context_live"
    ).fetchall()
    assert len(found) == 1, f"expected one live context, got {len(found)}"
    store = rendering.RenderingStore(
        connection=connection, identity=settings().identity
    )
    return store.project(found[0][0])


def a_live_request(projection: ContextProjection) -> AgentRequest:
    produced = rendering_v1.render(
        projection,
        hosts.load().attributes_for(projection.host),
        rendering.budget(),
    )
    return request(
        host=projection.host,
        context_id=projection.context_id,
        context_version=projection.context_version,
        window_start=projection.statistics.window_start,
        window_end=projection.statistics.window_end,
        rendering=produced,
        versions=versions(rendering_version=produced.version),
    )


def a_contacted_port(connection: psycopg.Connection) -> tuple[str, int]:
    reached = connection.execute(
        "SELECT entity_value, port FROM helena_signal_context_entity_ports "
        "ORDER BY entity_value, port LIMIT 1"
    ).fetchone()
    assert reached, "the capture produced no contacted port"
    return reached[0], reached[1]


def live_evidence_id(projection: ContextProjection, address: str) -> str:
    """The evidence id the store minted for the claim about this address."""
    return next(
        record.evidence_id
        for entity in projection.entities
        if entity.entity_value == address
        for record in entity.enrichment
        if record.evidence_id is not None
    )


def live_answer(projection: ContextProjection, address: str) -> str:
    """The analyst's answer over a real projection, citing the claim the store made."""
    evidence_id = live_evidence_id(projection, address)
    return said(
        classification="suspicious.low_reputation",
        confidence=0.5,
        citations=[{"evidence_id": evidence_id, "stance": SUPPORTING}],
        evidence_package={
            "patterns": ["beaconing"],
            "narrative": "the address answered and the traffic went both ways",
        },
    )


@pytest.mark.integration
def test_a_real_high_confidence_hit_routes_past_a_normal_verdict(
    live: psycopg.Connection,
):
    """The whole branch, over a real capture and a real feed load.

    A capture, the feed loader, the mapping view's own `port_matched` and
    `confidence`, the committed thresholds, and a model saying `normal` — and the
    analyst runs anyway, under the trigger that names the evidence. Nothing in
    this path is a fixture except the words the model said.
    """
    address, port = a_contacted_port(live)
    load_extract(live, targeted(RAW, f"{address}:{port}", "ip:port"))
    projection = a_live_projection(live)
    asked = a_live_request(projection)

    with _Endpoint(
        [answered(TRIAGE_NORMAL), answered(live_answer(projection, address))]
    ) as endpoint:
        assessment = assess(endpoint, projection=projection, asked=asked)

    assert isinstance(assessment.triage, AgentResult)
    assert assessment.triage.root == "normal"
    assert assessment.trigger == DETERMINISTIC_SIGNAL
    assert assessment.escalation.escalates is True
    assert assessment.analyst_request.trigger == DETERMINISTIC_SIGNAL
    assert assessment.analyst_request.context_version == projection.context_version
    assert assessment.analysis is not None


@pytest.mark.integration
def test_a_real_context_with_no_hits_finishes_on_a_normal_verdict(
    live: psycopg.Connection,
):
    """The `else: finish()` branch, over a real context whose lookups all missed.

    `claims_read` is what keeps *"nothing escalated"* and *"there was nothing to
    read"* apart, and the routing record carries both.
    """
    load_extract(live, RAW)
    projection = a_live_projection(live)
    asked = a_live_request(projection)

    stream = io.StringIO()
    with _Endpoint([answered(TRIAGE_NORMAL)]) as endpoint:
        assessment = assess(
            endpoint, projection=projection, asked=asked, stream=stream
        )
        assert not endpoint.script

    assert assessment.trigger is None
    assert assessment.escalation.escalates is False
    assert assessment.escalation.claims_read == 0
    assert assessment.terminal is assessment.triage
    routed = one(stream, orchestration.ROUTED)
    assert routed["trigger"] == orchestration.FINISHED


@pytest.mark.integration
def test_a_real_hit_below_the_threshold_leaves_the_route_to_triage(
    live: psycopg.Connection,
):
    """The same real hit, under the number `config/policy.toml` carries.

    Below the threshold the evidence branch does not fire, so the model's answer
    is what decides — which is the only direction a model may move this.
    """
    address, port = a_contacted_port(live)
    document = json.loads(targeted(RAW, f"{address}:{port}", "ip:port"))
    document[sorted(document)[0]][0]["confidence_level"] = 50
    load_extract(live, json.dumps(document).encode())
    projection = a_live_projection(live)
    asked = a_live_request(projection)

    with _Endpoint([answered(TRIAGE_NORMAL)]) as endpoint:
        finished = assess(endpoint, projection=projection, asked=asked)
    assert finished.escalation.escalates is False
    assert finished.escalation.claims_read >= 1
    assert finished.trigger is None

    cited = live_evidence_id(projection, address)
    with _Endpoint(
        [
            answered(
                said(
                    classification="suspicious",
                    confidence=0.6,
                    citations=[{"evidence_id": cited, "stance": SUPPORTING}],
                )
            ),
            answered(live_answer(projection, address)),
        ]
    ) as endpoint:
        escalated = assess(endpoint, projection=projection, asked=asked)
    assert escalated.trigger == TRIAGE_SUSPICIOUS
    assert escalated.escalation.escalates is False
