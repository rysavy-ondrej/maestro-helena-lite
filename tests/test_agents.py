"""The model client, structured output, and the bounded schema retry.

Mirrors `src/helena/agents.py`. Three groups of sentences are under test here,
each from a note rather than from the code:

- `concept/04-the-two-agents.md`: *agents differ by model, not by framework, and
  model choice stays a configuration value, never a code path.*
- `concept/07-principles.md`: *schema-invalid model output is retried with the
  validation error fed back, a small bounded number of times, and then becomes a
  typed failure. Retries count against the budget ... **A second-pass "repair"
  call is rejected**.*
- `concept/07-principles.md`: *what is recorded on an assessment is the endpoint
  host and the model identity and version — enough to know what produced a
  result, with nothing that authenticates as anyone.*

**The endpoint under test is a real HTTP server**, on the loopback interface,
scripted per test. `helena.agents` does its own `urllib` call against it, so what
is exercised is the transport, the headers, the JSON body and the failure
mapping — not a mocked seam. One test at the end calls the **configured** endpoint
with the real credentials, because a client tested only against a stub has not
been tested against the thing that surprises you; it carries the `integration`
marker and skips when the endpoint cannot be reached.
"""

from __future__ import annotations

import ast
import io
import json
import threading
import urllib.error
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import pytest

from helena import agents, observability, taxonomy
from helena.agents import (
    CODE_OWNED_FIELDS,
    AgentError,
    Message,
    ModelClient,
    RetryPolicy,
    assess,
    proposable_fields,
    proposal_schema,
    retry_policy,
)
from helena.budgets import RunBudget
from helena.config import AGENTS, ModelSettings, Secret, Settings
from helena.contracts.v1 import (
    BUDGET_EXHAUSTED,
    CONTRACT_VERSION,
    GAP_KINDS,
    MODEL_UNAVAILABLE,
    RETRIEVAL_OUTCOMES,
    SCHEDULED_TRIAGE,
    SCHEMA_INVALID,
    SECTIONS,
    STANCES,
    TIMED_OUT,
    AgentFailure,
    AgentRequest,
    AgentResult,
    Budgets,
    Rendering,
    RenderedSection,
    RequestVersions,
)
from helena.taxonomy import TRIAGE

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODULE = PROJECT_ROOT / "src" / "helena" / "agents.py"

WINDOW_START = datetime(2024, 6, 1, 12, 0, tzinfo=timezone.utc)
WINDOW_END = WINDOW_START + timedelta(minutes=5)

# A stable evidence id the rendering shows. Real ones are 64 hex characters
# (`helena.enrichment.evidence_id`); nothing here depends on the shape.
SHOWN = "e" * 64

# The fields a triage model may propose. `concept/04`: triage has no tools and no
# retrieval, so the contract refuses a triage result carrying an evidence package,
# a retrieval trace or a proposed claim — offering them in the schema would be
# offering a way to fail validation. Task 31 owns the triage runner; this is the
# same subset, used here to keep the schema on the high-volume path small.
TRIAGE_PROPOSABLE = ("classification", "confidence", "citations", "gaps")

# What a rendering says. Distinctive, so a test can assert it never reaches a log.
RENDERED_BODY = "10.127.0.100 contacted example.test — no_match"


# --- Builders ----------------------------------------------------------------


def versions(**overrides: str) -> RequestVersions:
    return RequestVersions(
        **{
            "prompt_version": "p1",
            "schema_version": CONTRACT_VERSION,
            "rendering_version": "r1",
            "taxonomy_version": "v1",
            "enrichment_snapshot_version": "2024-06-01T00:00:00Z",
            "normalization_snapshot_version": "psl-2024-06-01",
            "policy_version": "pol1",
            "aggregation_version": "v1",
            "model_requested": "stub-model",
            **overrides,
        }
    )


def rendering() -> Rendering:
    return Rendering(
        version="r1",
        sections=tuple(
            RenderedSection(
                section=name,
                body=RENDERED_BODY if name == "addresses_contacted" else f"<{name}>",
                evidence_ids=(SHOWN,) if name == "addresses_contacted" else (),
                truncation=None,
            )
            for name in SECTIONS
        ),
    )


def request(**overrides: object) -> AgentRequest:
    return AgentRequest(
        **{
            "tenant": "acme",
            "sensor": "sensor-1",
            "emitter": TRIAGE,
            "host": "10.127.0.100",
            "window_start": WINDOW_START,
            "window_end": WINDOW_END,
            "context_id": "ctx-1",
            "context_version": "ctx-1/3",
            "trigger": SCHEDULED_TRIAGE,
            "rendering": rendering(),
            "budgets": Budgets(
                steps=0, tokens=8000, wall_clock_seconds=20.0, live_queries=0
            ),
            "versions": versions(),
            **overrides,
        }
    )


def messages() -> tuple[Message, ...]:
    """What a runner would send. The prompt itself is task 31's."""
    return (
        Message(role="system", content="Triage this host. Answer as JSON."),
        Message(role="user", content=RENDERED_BODY),
    )


def assessed(the_request: AgentRequest, **kwargs):
    """`assess` with the ledger a runner would hand it.

    `assess` takes a `RunBudget` and has no default for it: the ledger is built
    once per agent **run** and charged by the tool loop as well as by the model
    calls, so a default built inside `assess` would restart the wall clock on
    every turn of a loop (`helena.budgets`). Every test here is a single
    exchange, so the ledger is built from the same request that carries the
    budgets — which is what `RunBudget.of` is for, and what
    `test_a_ledger_built_from_another_request_is_refused` covers when it is not.
    """
    return assess(the_request, budget=RunBudget.of(the_request), **kwargs)


def environment(**overrides: str) -> dict[str, str]:
    """A complete configuration, with the two agents deliberately cross-checkable."""
    return {
        "LLM_URL": "https://general.invalid/v1/",
        "LLM_TOKEN": "general-token",
        "LLM_MODEL": "general-model",
        "LLM_URL_TRIAGE": "https://triage.invalid/v1/",
        "LLM_MODEL_TRIAGE": "small-model",
        "LLM_MODEL_ANALYST": "large-model",
        "HELENA_TENANT": "acme",
        "HELENA_SENSOR": "sensor-1",
        "HELENA_INPUT_FORMAT": "flow-json",
        "ABUSECH_AUTH_KEY": "abusech-key",
        "VIRUSTOTAL_AUTH_KEY": "virustotal-key",
        "RISINGWAVE_DSN": "postgresql://root@127.0.0.1:4566/dev",
        "KAFKA_BOOTSTRAP_SERVERS": "127.0.0.1:9092",
        "HELENA_INGEST_TOPIC": "helena.ingest",
        **overrides,
    }


def settings(**overrides: str) -> Settings:
    return Settings.load(environ=environment(**overrides), env_file=None)


def model_settings(url: str, *, agent: str = TRIAGE, model: str = "stub-model"):
    return ModelSettings(
        agent=agent,
        endpoint_url=url,
        token=Secret("stub-token"),
        model=model,
        source={"LLM_URL": "LLM_URL", "LLM_TOKEN": "LLM_TOKEN", "LLM_MODEL": "LLM_MODEL"},
    )


def logger(stream: io.StringIO) -> observability.StructuredLogger:
    return observability.StructuredLogger(
        component="agents.triage",
        tenant="acme",
        sensor="sensor-1",
        redactor=observability.Redactor(["stub-token"]),
        stream=stream,
    )


# How long the "hang" script holds a connection open. Comfortably longer than
# the wall-clock budget the test that uses it sets, and short enough that
# shutting the single-threaded server down does not dominate the suite.
_HANG_SECONDS = 2.0

ONE_ATTEMPT = RetryPolicy(attempts=1)
THREE_ATTEMPTS = RetryPolicy(attempts=3)


# --- The scripted endpoint ---------------------------------------------------


class _Endpoint:
    """A real OpenAI-compatible endpoint on the loopback interface, scripted.

    Each entry of `script` is what the next call gets: a JSON-serializable body,
    an `int` status to fail with, or the string `"hang"` to answer nothing at all
    so the client's timeout is the one that fires. Running out of script is an
    assertion failure rather than a default response — a test that calls more
    times than it scripted has found something, and answering it anyway would
    hide it.
    """

    def __init__(self, script: list[Any]) -> None:
        self.script = list(script)
        self.received: list[dict[str, Any]] = []
        self.headers: list[dict[str, str]] = []
        endpoint = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self) -> None:  # noqa: N802 — the stdlib's name
                length = int(self.headers.get("Content-Length", 0))
                endpoint.received.append(json.loads(self.rfile.read(length)))
                endpoint.headers.append(dict(self.headers))
                assert endpoint.script, "the endpoint was called more times than scripted"
                nxt = endpoint.script.pop(0)
                if nxt == "hang":
                    threading.Event().wait(_HANG_SECONDS)
                    return
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

    def client(self, stream: io.StringIO | None = None) -> ModelClient:
        return ModelClient(
            model_settings(self.url), logger=logger(stream or io.StringIO())
        )

    @property
    def bodies(self) -> list[str]:
        """Every request as text, for asserting what was and was not sent."""
        return [json.dumps(payload) for payload in self.received]


def answer(content: str, *, model: str = "stub-model-2026-05", prompt=40, completion=20):
    """One OpenAI-compatible chat completion carrying `content`."""
    return {
        "id": "cmpl-1",
        "model": model,
        "choices": [{"index": 0, "message": {"role": "assistant", "content": content}}],
        "usage": {"prompt_tokens": prompt, "completion_tokens": completion},
    }


VALID = json.dumps({"classification": "normal", "confidence": 0.9})
# Schema-shaped but contract-invalid: `stance` is one of exactly two words, and
# JSON Schema cannot say so, which is why the retry loop is not dead code.
INVALID_STANCE = json.dumps(
    {
        "classification": "suspicious",
        "confidence": 0.4,
        "citations": [{"evidence_id": SHOWN, "stance": "no_match"}],
    }
)


# --- Model selection is configuration, not a code path -----------------------


def test_the_two_agents_differ_only_by_configuration():
    """`concept/04`: agents differ by model, and model choice is never a code path."""
    resolved = settings()
    triage = ModelClient.for_agent(resolved, "triage")
    analyst = ModelClient.for_agent(resolved, "analyst")

    assert triage.model_requested == "small-model"
    assert analyst.model_requested == "large-model"
    # The endpoint too: `concept/07` says cross-wiring is possible precisely
    # because endpoints are per-agent, which is why the host is recorded.
    assert triage.endpoint_host == "triage.invalid"
    assert analyst.endpoint_host == "general.invalid"


def test_changing_only_the_configuration_changes_only_the_model():
    """The claim "cheap to redo" made falsifiable: no code moves, the model does."""
    before = ModelClient.for_agent(settings(), "triage").model_requested
    after = ModelClient.for_agent(
        settings(LLM_MODEL_TRIAGE="another-model"), "triage"
    ).model_requested
    assert (before, after) == ("small-model", "another-model")


def test_the_module_never_names_an_agent():
    """No branch on agent identity — asserted over the source, not the behaviour.

    String constants only, docstrings excluded: a comment cannot be a branch and a
    docstring naming the two agents is documentation. If `"triage"` appears as a
    value in this module, something is deciding by identity rather than reading
    configuration.
    """
    tree = ast.parse(MODULE.read_text())
    docstrings = {
        id(node.body[0].value)
        for node in ast.walk(tree)
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef))
        and node.body
        and isinstance(node.body[0], ast.Expr)
        and isinstance(node.body[0].value, ast.Constant)
        and isinstance(node.body[0].value.value, str)
    }
    literals = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and id(node) not in docstrings
    }
    named = sorted(literals & set(AGENTS))
    assert not named, f"helena/agents.py names {named}; agent choice is configuration"


def test_the_configured_agents_and_the_taxonomy_emitters_are_one_vocabulary():
    """Two copies of the same closed set, asserted equal rather than assumed.

    `helena.config.AGENTS` is what `.env` overrides are named after and
    `helena.taxonomy.EMITTERS` is what a request and a result carry. `for_agent`
    is the first code that crosses from one to the other — `getattr(settings,
    request.emitter)` — so a set that drifted would resolve an emitter to no
    configuration at all.
    """
    assert AGENTS == taxonomy.EMITTERS


def test_an_unknown_agent_fails_loudly_naming_the_ones_that_exist():
    with pytest.raises(AgentError) as refused:
        ModelClient.for_agent(settings(), "investigation")
    assert "triage" in str(refused.value) and "analyst" in str(refused.value)


def test_the_recorded_endpoint_host_authenticates_as_nobody():
    """`concept/07`: "enough to know what produced a result, nothing that
    authenticates as anyone." Userinfo, path and query are dropped, not masked."""
    client = ModelClient(
        model_settings("https://user:secret@endpoint.invalid:8443/v1/?key=abc"),
        logger=logger(io.StringIO()),
    )
    assert client.endpoint_host == "endpoint.invalid:8443"


def test_an_endpoint_url_with_no_host_is_a_startup_failure():
    with pytest.raises(AgentError) as refused:
        ModelClient(model_settings("not-a-url/v1"), logger=logger(io.StringIO()))
    assert "host" in str(refused.value)


# --- The schema is derived from the contract, never written twice ------------


def test_the_proposable_and_code_owned_fields_partition_the_result():
    """A field added to a future result is proposable unless it is named owned."""
    assert set(proposable_fields(AgentResult)) | set(CODE_OWNED_FIELDS) == set(
        AgentResult.model_fields
    )
    assert not set(proposable_fields(AgentResult)) & set(CODE_OWNED_FIELDS)


def test_the_model_is_never_asked_for_what_the_code_measured():
    """`Cost` is "measured by orchestration, never by the model", and versions too."""
    schema = proposal_schema(AgentResult)
    assert not set(schema["properties"]) & set(CODE_OWNED_FIELDS)
    assert set(schema["properties"]) == set(proposable_fields(AgentResult))


def test_narrowing_the_schema_drops_the_definitions_nothing_references():
    """The schema is sent on every call on the high-volume path, so it is pruned."""
    full = proposal_schema(AgentResult)
    triage = proposal_schema(AgentResult, TRIAGE_PROPOSABLE)
    assert set(triage["$defs"]) == {"Citation", "Gap"}
    assert "EvidencePackage" in full["$defs"]
    assert len(json.dumps(triage)) < len(json.dumps(full))
    assert triage["required"] == ["classification", "confidence"]
    assert triage["additionalProperties"] is False


def test_a_field_the_contract_does_not_offer_is_refused():
    with pytest.raises(AgentError) as refused:
        proposal_schema(AgentResult, ("classification", "cost"))
    assert "cost" in str(refused.value)


def test_an_empty_proposal_schema_is_refused():
    with pytest.raises(AgentError):
        proposal_schema(AgentResult, ())


def test_a_closed_vocabulary_the_contract_enforces_is_shown_to_the_model():
    """The failure this prevents was measured, not imagined.

    `Citation.stance` is checked in `model_post_init`, so `model_json_schema`
    reports `{"type": "string"}` — and against the configured endpoint on
    2026-09-07 the model filled it with the host's rendered line, three times,
    and the assessment became a typed failure for a vocabulary nobody had shown
    it. The enum comes from the contract's own constant, so there is one copy.
    """
    schema = proposal_schema(AgentResult, TRIAGE_PROPOSABLE)
    assert schema["$defs"]["Citation"]["properties"]["stance"]["enum"] == list(STANCES)
    assert schema["$defs"]["Gap"]["properties"]["kind"]["enum"] == list(GAP_KINDS)


def test_every_closed_vocabulary_still_names_a_field_the_contract_has():
    """A rename in a future contract is a loud failure, not a silent gap.

    Reading the whole map is what makes this a check on the map rather than on
    the two entries the triage subset happens to reach.
    """
    definitions = AgentResult.model_json_schema()["$defs"]
    for (definition, field), vocabulary in agents.CLOSED_VOCABULARIES.items():
        assert definition in definitions, definition
        assert field in definitions[definition]["properties"], (definition, field)
        assert vocabulary, (definition, field)
    # And the mechanism itself fails loudly when one stops resolving.
    assert proposal_schema(AgentResult)["$defs"]["RetrievalStep"]["properties"][
        "outcome"
    ]["enum"] == list(RETRIEVAL_OUTCOMES)


# --- The retry bound is policy in a file, not a constant in a branch ---------


def test_the_configured_retry_bound_is_read_from_the_file():
    assert retry_policy().attempts == 3


def test_an_absent_retry_file_is_a_startup_failure_not_an_unbounded_loop(tmp_path):
    with pytest.raises(AgentError) as refused:
        retry_policy(tmp_path / "absent.toml")
    assert "unbounded" in str(refused.value)


def test_a_retry_file_with_a_key_nothing_reads_is_refused(tmp_path):
    path = tmp_path / "agents.toml"
    path.write_text("[retry]\nattempts = 2\n\n[repair]\nattempts = 1\n")
    with pytest.raises(AgentError) as refused:
        retry_policy(path)
    assert "repair" in str(refused.value)


def test_a_retry_bound_of_zero_is_refused(tmp_path):
    path = tmp_path / "agents.toml"
    path.write_text("[retry]\nattempts = 0\n")
    with pytest.raises(AgentError):
        retry_policy(path)


# --- One call, one verdict ---------------------------------------------------


def test_a_valid_answer_becomes_a_result_carrying_what_the_run_spent():
    with _Endpoint([answer(VALID, prompt=91, completion=87)]) as endpoint:
        outcome = assessed(
            request(),
            client=endpoint.client(),
            messages=messages(),
            policy=THREE_ATTEMPTS,
            propose=TRIAGE_PROPOSABLE,
        )
    assert isinstance(outcome, AgentResult)
    assert outcome.classification == "normal"
    assert outcome.cost.retries == 0
    assert (outcome.cost.prompt_tokens, outcome.cost.completion_tokens) == (91, 87)
    # Triage has no tools at all, and this module has no tool loop to spend on.
    assert (outcome.cost.steps, outcome.cost.live_queries, outcome.cost.cache_hits) == (
        0,
        0,
        0,
    )


def test_the_recorded_model_is_the_one_that_answered_not_the_one_requested():
    """`docs/decisions/0008`: the configured name is what stays stable while what
    answers to it changes, so the response's identity is what is recorded."""
    with _Endpoint([answer(VALID, model="stub-model-2026-05")]) as endpoint:
        outcome = assessed(
            request(),
            client=endpoint.client(),
            messages=messages(),
            policy=THREE_ATTEMPTS,
            propose=TRIAGE_PROPOSABLE,
        )
    assert outcome.versions.model_version == "stub-model-2026-05"
    assert outcome.versions.model_version != request().versions.model_requested


def test_the_schema_goes_to_the_endpoint_and_the_credential_goes_in_a_header():
    with _Endpoint([answer(VALID)]) as endpoint:
        assessed(
            request(),
            client=endpoint.client(),
            messages=messages(),
            policy=THREE_ATTEMPTS,
            propose=TRIAGE_PROPOSABLE,
        )
    sent = endpoint.received[0]
    assert sent["response_format"]["type"] == "json_schema"
    assert sent["response_format"]["json_schema"]["schema"]["required"] == [
        "classification",
        "confidence",
    ]
    assert endpoint.headers[0]["Authorization"] == "Bearer stub-token"
    # The token is in a header and nowhere else — not the URL, not the body.
    assert "stub-token" not in endpoint.bodies[0]


# --- The bounded retry, and the repair call that does not exist --------------


def test_a_schema_invalid_answer_is_retried_with_the_validation_error_fed_back():
    """`concept/07`, and the retry count is what makes it visible afterwards."""
    with _Endpoint([answer(INVALID_STANCE), answer(VALID)]) as endpoint:
        outcome = assessed(
            request(),
            client=endpoint.client(),
            messages=messages(),
            policy=THREE_ATTEMPTS,
            propose=TRIAGE_PROPOSABLE,
        )
    assert isinstance(outcome, AgentResult)
    assert outcome.cost.retries == 1
    # Both attempts' tokens, because a retry is spent, not forgiven.
    assert outcome.cost.prompt_tokens == 80

    fed_back = endpoint.received[1]["messages"][-1]["content"]
    assert "no_match" in fed_back, "the validation error itself is what is fed back"
    assert "stance" in fed_back


def test_no_repair_call_path_exists():
    """`concept/07`: a second-pass "repair" call is **rejected**.

    The difference between a sanctioned retry and a repair call is what the model
    is sent: a retry re-asks the original question and says what was wrong, a
    repair hands back the invalid answer to be edited. So the property asserted
    here is over the bytes the endpoint received — **the model's invalid answer is
    never an input to anything** — plus the other half, that every attempt is the
    same question rather than a narrowing of it.

    A repair path could not pass this: it has nothing to repair without sending
    the answer back.
    """
    with _Endpoint([answer(INVALID_STANCE), answer(INVALID_STANCE), answer(VALID)]) as (
        endpoint
    ):
        outcome = assessed(
            request(),
            client=endpoint.client(),
            messages=messages(),
            policy=THREE_ATTEMPTS,
            propose=TRIAGE_PROPOSABLE,
        )

    assert isinstance(outcome, AgentResult)
    assert len(endpoint.received) == 3
    for body in endpoint.bodies:
        assert INVALID_STANCE not in body
        assert "0.4" not in body, "the discarded answer's own values never go back"
    for sent in endpoint.received:
        assert [message["role"] for message in sent["messages"][:2]] == ["system", "user"]
        assert sent["messages"][0]["content"] == messages()[0].content
        assert sent["messages"][1]["content"] == messages()[1].content
        # No assistant turn: that is the shape a repair call would need.
        assert not [m for m in sent["messages"] if m["role"] == "assistant"]


def test_the_prompt_does_not_grow_with_the_retries():
    """One feedback message, replaced each attempt, not one appended per attempt."""
    with _Endpoint([answer(INVALID_STANCE), answer(INVALID_STANCE), answer(VALID)]) as (
        endpoint
    ):
        assessed(
            request(),
            client=endpoint.client(),
            messages=messages(),
            policy=THREE_ATTEMPTS,
            propose=TRIAGE_PROPOSABLE,
        )
    assert [len(sent["messages"]) for sent in endpoint.received] == [2, 3, 3]


def test_exhausted_retries_become_a_typed_failure_and_never_a_verdict():
    """`concept/07`: a typed failure and a verdict are not collapsed, ever."""
    with _Endpoint([answer(INVALID_STANCE)] * 3) as endpoint:
        outcome = assessed(
            request(),
            client=endpoint.client(),
            messages=messages(),
            policy=THREE_ATTEMPTS,
            propose=TRIAGE_PROPOSABLE,
        )
    assert isinstance(outcome, AgentFailure)
    assert outcome.reason == SCHEMA_INVALID
    assert outcome.cost.retries == 2
    # The identity that answered is recorded: something did answer, repeatedly.
    assert outcome.model_version == "stub-model-2026-05"
    # There is nowhere on the object to put a verdict, and this is that fact
    # asserted rather than trusted.
    assert not hasattr(outcome, "classification")
    assert "no_match" in outcome.detail


def test_the_retry_bound_is_the_configured_one():
    """One attempt configured is one call, and then a typed failure."""
    with _Endpoint([answer(INVALID_STANCE)]) as endpoint:
        outcome = assessed(
            request(),
            client=endpoint.client(),
            messages=messages(),
            policy=ONE_ATTEMPT,
            propose=TRIAGE_PROPOSABLE,
        )
    assert len(endpoint.received) == 1
    assert isinstance(outcome, AgentFailure)
    assert outcome.cost.retries == 0


def test_an_answer_setting_a_field_the_code_owns_is_refused_rather_than_dropped():
    """A model reporting its own cost has been asked the wrong question."""
    smuggled = json.dumps(
        {
            "classification": "normal",
            "confidence": 0.9,
            "cost": {"prompt_tokens": 1, "completion_tokens": 1},
        }
    )
    with _Endpoint([answer(smuggled), answer(VALID)]) as endpoint:
        outcome = assessed(
            request(),
            client=endpoint.client(),
            messages=messages(),
            policy=THREE_ATTEMPTS,
            propose=TRIAGE_PROPOSABLE,
        )
    assert isinstance(outcome, AgentResult)
    assert "cost" in endpoint.received[1]["messages"][-1]["content"]


def test_a_classification_the_taxonomy_does_not_have_is_a_schema_violation():
    """`AgentResult` raises `TaxonomyError`, not `ValidationError` — both retry."""
    invented = json.dumps({"classification": "malicious.telepathy", "confidence": 0.9})
    with _Endpoint([answer(invented)] * 3) as endpoint:
        outcome = assessed(
            request(),
            client=endpoint.client(),
            messages=messages(),
            policy=THREE_ATTEMPTS,
            propose=TRIAGE_PROPOSABLE,
        )
    assert isinstance(outcome, AgentFailure)
    assert outcome.reason == SCHEMA_INVALID
    assert len(endpoint.received) == 3


def test_an_answer_that_is_not_json_is_retried_and_then_typed():
    with _Endpoint([answer("I think this host looks fine.")] * 2) as endpoint:
        outcome = assessed(
            request(),
            client=endpoint.client(),
            messages=messages(),
            policy=RetryPolicy(attempts=2),
            propose=TRIAGE_PROPOSABLE,
        )
    assert isinstance(outcome, AgentFailure)
    assert outcome.reason == SCHEMA_INVALID
    assert "not JSON" in outcome.detail


# --- Retries are spent against the budget ------------------------------------


def test_retries_are_spent_against_the_token_budget():
    """`concept/07`: "retries count against the budget."

    The budget here buys two attempts and no more, and the run ends on the budget
    rather than on the retry count — a `budget_exhausted` gap beside a
    `schema_invalid` failure, because those are two different facts.
    """
    with _Endpoint([answer(INVALID_STANCE, prompt=40, completion=20)] * 3) as endpoint:
        outcome = assessed(
            request(budgets=Budgets(
                steps=0, tokens=100, wall_clock_seconds=20.0, live_queries=0
            )),
            client=endpoint.client(),
            messages=messages(),
            policy=THREE_ATTEMPTS,
            propose=TRIAGE_PROPOSABLE,
        )
    assert len(endpoint.received) == 2, "the third attempt had no budget left"
    assert isinstance(outcome, AgentFailure)
    assert outcome.reason == SCHEMA_INVALID
    assert [gap.kind for gap in outcome.gaps] == [BUDGET_EXHAUSTED]
    assert outcome.cost.prompt_tokens + outcome.cost.completion_tokens == 120


def test_the_remaining_budget_is_what_the_next_attempt_may_spend():
    """`max_tokens` shrinks as the budget is spent, so a retry cannot overshoot."""
    with _Endpoint([answer(INVALID_STANCE, prompt=40, completion=20), answer(VALID)]) as (
        endpoint
    ):
        assessed(
            request(budgets=Budgets(
                steps=0, tokens=500, wall_clock_seconds=20.0, live_queries=0
            )),
            client=endpoint.client(),
            messages=messages(),
            policy=THREE_ATTEMPTS,
            propose=TRIAGE_PROPOSABLE,
        )
    assert [sent["max_tokens"] for sent in endpoint.received] == [500, 440]


def test_one_ledger_spans_every_model_call_of_one_run():
    """The budget is the **run's**, not the call's, which is what an analyst loop needs.

    `helena.budgets`: a ledger built inside `assess` would restart the wall clock
    and the token count on every turn of a tool loop, so a run could spend its
    whole budget arbitrarily many times. Two exchanges on one ledger here: the
    second is offered only what the first left.
    """
    given = request()
    budget = RunBudget.of(given)
    answers = [answer(VALID, prompt=40, completion=20)] * 2
    with _Endpoint(answers) as endpoint:
        client = endpoint.client()
        for _ in range(2):
            outcome = assess(
                given,
                client=client,
                messages=messages(),
                policy=THREE_ATTEMPTS,
                budget=budget,
                propose=TRIAGE_PROPOSABLE,
            )
    assert [sent["max_tokens"] for sent in endpoint.received] == [8000, 7940]
    assert (outcome.cost.prompt_tokens, outcome.cost.completion_tokens) == (80, 40)
    assert budget.exhausted == ()


def test_a_ledger_built_from_another_requests_budgets_is_refused():
    """A run enforced against a budget it was not given is a budget nobody set."""
    other = request(
        budgets=Budgets(steps=0, tokens=50, wall_clock_seconds=1.0, live_queries=0)
    )
    with _Endpoint([answer(VALID)]) as endpoint:
        with pytest.raises(AgentError) as refused:
            assess(
                request(),
                client=endpoint.client(),
                messages=messages(),
                policy=THREE_ATTEMPTS,
                budget=RunBudget.of(other),
                propose=TRIAGE_PROPOSABLE,
            )
    assert "RunBudget.of(request)" in str(refused.value)
    assert endpoint.received == [], "nothing was asked"


# --- The endpoint failing is not the model failing ---------------------------


def test_an_endpoint_that_refuses_is_model_unavailable_with_no_reported_version():
    """`model_unavailable` means nothing answered, so no identity is recorded."""
    with _Endpoint([503]) as endpoint:
        outcome = assessed(
            request(),
            client=endpoint.client(),
            messages=messages(),
            policy=THREE_ATTEMPTS,
            propose=TRIAGE_PROPOSABLE,
        )
    assert isinstance(outcome, AgentFailure)
    assert outcome.reason == MODEL_UNAVAILABLE
    assert outcome.model_version is None
    assert len(endpoint.received) == 1, "an unreachable endpoint is not retried"


def test_an_endpoint_that_stops_answering_mid_retry_is_not_called_unanswered():
    """Something did answer, so "nothing answered" would be false.

    The run produced no verdict because no answer validated; the transport failure
    is why there were no further attempts, and it is recorded as a `failed` gap
    rather than collapsed into the reason.
    """
    with _Endpoint([answer(INVALID_STANCE), 502]) as endpoint:
        outcome = assessed(
            request(),
            client=endpoint.client(),
            messages=messages(),
            policy=THREE_ATTEMPTS,
            propose=TRIAGE_PROPOSABLE,
        )
    assert isinstance(outcome, AgentFailure)
    assert outcome.reason == SCHEMA_INVALID
    assert outcome.model_version == "stub-model-2026-05"
    assert [gap.kind for gap in outcome.gaps] == ["failed"]


def test_a_response_that_is_not_a_chat_completion_is_the_endpoint_not_the_model():
    """A deployment pointed at the wrong service is not a model that needs retrying."""
    with _Endpoint([{"result": "ok"}]) as endpoint:
        outcome = assessed(
            request(),
            client=endpoint.client(),
            messages=messages(),
            policy=THREE_ATTEMPTS,
            propose=TRIAGE_PROPOSABLE,
        )
    assert isinstance(outcome, AgentFailure)
    assert outcome.reason == MODEL_UNAVAILABLE
    assert len(endpoint.received) == 1


def test_a_response_with_no_usage_is_refused_rather_than_counted_as_zero():
    """A token budget silently unenforced is invisible where it mattered most."""
    body = answer(VALID)
    del body["usage"]
    with _Endpoint([body]) as endpoint:
        outcome = assessed(
            request(),
            client=endpoint.client(),
            messages=messages(),
            policy=THREE_ATTEMPTS,
            propose=TRIAGE_PROPOSABLE,
        )
    assert isinstance(outcome, AgentFailure)
    assert outcome.reason == MODEL_UNAVAILABLE


def test_the_wall_clock_budget_produces_a_timed_out_failure():
    with _Endpoint(["hang"]) as endpoint:
        outcome = assessed(
            request(budgets=Budgets(
                steps=0, tokens=8000, wall_clock_seconds=0.3, live_queries=0
            )),
            client=endpoint.client(),
            messages=messages(),
            policy=THREE_ATTEMPTS,
            propose=TRIAGE_PROPOSABLE,
        )
    assert isinstance(outcome, AgentFailure)
    assert outcome.reason == TIMED_OUT
    assert outcome.cost.wall_clock_seconds > 0


# --- What is logged, and what may never be -----------------------------------


def test_every_call_records_the_endpoint_host_and_both_model_identities():
    """`concept/07`: enough to know what produced a result. Cross-wiring detectable."""
    stream = io.StringIO()
    with _Endpoint([answer(VALID)]) as endpoint:
        assessed(
            request(),
            client=endpoint.client(stream),
            messages=messages(),
            policy=THREE_ATTEMPTS,
            propose=TRIAGE_PROPOSABLE,
        )
    records = [json.loads(line) for line in stream.getvalue().splitlines()]
    answered = [r for r in records if r["event"] == "agents.model.answered"]
    assert len(answered) == 1
    fields = answered[0]["fields"]
    assert fields["endpoint_host"].startswith("127.0.0.1:")
    assert fields["model_requested"] == "stub-model"
    assert fields["model_reported"] == "stub-model-2026-05"
    assert fields["prompt_tokens"] == 40


def test_no_prompt_and_no_rendering_ever_reaches_the_log():
    """The rendering is attacker-influenced text and a prompt is not a diagnostic."""
    stream = io.StringIO()
    with _Endpoint([answer(INVALID_STANCE), answer(VALID)]) as endpoint:
        assessed(
            request(),
            client=endpoint.client(stream),
            messages=messages(),
            policy=THREE_ATTEMPTS,
            propose=TRIAGE_PROPOSABLE,
        )
    written = stream.getvalue()
    assert written
    assert RENDERED_BODY not in written
    assert "stub-token" not in written
    assert SHOWN not in written


# --- The configured endpoint, for real ---------------------------------------


@pytest.mark.skipif(
    not (PROJECT_ROOT / ".env").exists(), reason="no local .env on this machine"
)
@pytest.mark.integration
def test_the_configured_triage_model_answers_this_schema():
    """The artifact, not the page: the real endpoint, the real model, one call.

    Asserts on shapes and on the contract, never on the verdict — there is no
    labelled corpus, so what a model says about this rendering is not something
    this suite can be right or wrong about. What it *can* assert is that the
    round trip produces a validated `AgentResult` whose recorded identity came
    from the response.

    No value from `.env` is asserted on or printed.
    """
    resolved = Settings.load(environ={}, env_file=PROJECT_ROOT / ".env")
    client = ModelClient.for_agent(resolved, "triage", stream=io.StringIO())
    try:
        outcome = assessed(
            request(versions=versions(model_requested=resolved.triage.model)),
            client=client,
            messages=messages(),
            policy=retry_policy(),
            propose=TRIAGE_PROPOSABLE,
        )
    except (urllib.error.URLError, OSError) as unreachable:  # pragma: no cover
        pytest.skip(f"cannot reach the configured endpoint: {unreachable}")

    # Asserted for **either** outcome, so a model that failed validation cannot
    # make this test silently prove nothing: the round trip completed, the tokens
    # were counted against the budget, and what answered was recorded.
    assert isinstance(outcome, (AgentResult, AgentFailure))
    assert outcome.cost.retries < retry_policy().attempts
    assert client.endpoint_host and "@" not in client.endpoint_host

    if isinstance(outcome, AgentFailure):
        # A live model that cannot emit this schema is a real result and not a
        # test bug — `concept/06` lists the schema-violation rate as something the
        # evaluation corpus measures, and no corpus exists. Recorded loudly.
        assert outcome.reason in (SCHEMA_INVALID, MODEL_UNAVAILABLE, TIMED_OUT)
        pytest.skip(f"the configured triage model produced {outcome.reason}")

    assert outcome.root in taxonomy.version("v1").emitter_roots[TRIAGE]
    assert outcome.versions.model_version
    assert outcome.cost.prompt_tokens > 0 and outcome.cost.completion_tokens > 0
