"""Agents — the model client, structured output, and the bounded schema retry.

Two agents differing by **model, not by framework** (`concept/04-the-two-agents.md`).
**The contract they exchange is not here**: it is `helena.contracts`, a versioned
package holding one frozen request/result pair per version. This module is what
*calls* a model with a `helena.contracts.v1.AgentRequest` and turns what comes
back into an `AgentResult` or an `AgentFailure`.

Nothing crosses the agent boundary except validated typed fields. An agent
proposes; deterministic code validates and writes. An agent never performs a side
effect, never holds a credential and never calls a provider directly.

## What the model is allowed to propose

`AgentResult` has ten fields and the model supplies seven of them.
`CODE_OWNED_FIELDS` — `emitter`, `cost` and `versions` — are **measured by the
code that ran the assessment**, never asked for: `Cost` is "what the run actually
spent. Measured by orchestration, never by the model", and a model that reported
its own token count or its own schema version would be recording a version that
was assumed rather than observed.

So there is **no second schema**. The JSON schema the endpoint is given is derived
from the frozen contract class by dropping those three fields
(`proposal_schema`), and what the model returns is validated by constructing that
same frozen class. A `v2` contract changes both at once because both are derived
from one place, and `tests/test_agents.py` asserts the partition is exhaustive so
a field added to a future result cannot quietly become unproposable.

## The bounded retry, and the repair call that is not here

`concept/07-principles.md`: *schema-invalid model output is retried with the
validation error fed back, a small bounded number of times, and then becomes a
typed failure. Retries count against the budget, and the retry count per model is
itself a quality metric. A second-pass "repair" call is rejected: it adds a model
dependency inside one assessment and can alter semantics rather than syntax, so
the repaired verdict may not be the verdict the model meant.*

The difference between the two is **what is sent back**, and it is enforced by
construction rather than by a comment:

| | Retry (this module) | Repair (rejected) |
| --- | --- | --- |
| What the model is sent | the original question, plus what was wrong | its own invalid answer, to fix |
| What comes back | a fresh answer to the original question | an edit of the previous one |

`_attempt_messages` rebuilds the message list from the **original** messages plus
one feedback message every time, so an invalid answer is discarded and is never
an input to anything. `tests/test_agents.py::test_no_repair_call_path_exists`
asserts exactly that over the bytes the endpoint receives.

The bound is `config/agents.toml`, not a constant here: `concept/07` makes budget
values "policy, not constants in a branch", and the retry count is spent against
the token budget the same way a tool call is.

## What is recorded, and what is not

`concept/07`, "Secrets and configuration": *what is recorded on an assessment is
the **endpoint host** and the **model identity and version** — enough to know what
produced a result, with nothing that authenticates as anyone. Because endpoints
are configurable per agent, cross-wiring is possible, and recording endpoint and
model per assessment is what makes it detectable.*

- **Model identity** is on the contract already: `versions.model_requested` is
  what this deployment asked for and `VersionSet.model_version` is what the
  response said answered. `RequestVersions.completed_by` is the bridge, and it is
  given the *reported* value, never the configured one.
- **The endpoint host** has no field on the frozen contract, and adding one is an
  escalation (`concept/instruction.md` §3), not an increment. It is
  `ModelClient.endpoint_host` — host and port, with userinfo, path, query and
  credential stripped — so the code that stores an assessment has it without the
  contract growing a field. Every call also logs it through
  `helena.observability`, which is the only record that exists until D5 builds
  the assessment table. **The storage increment owes that column.**

**No message content is ever logged.** The rendering is attacker-influenced text
and the prompt is not a diagnostic; what the log carries is the host, the two
model identities, the token counts and the attempt number.

## Why `urllib` and not LangChain

`concept/06-technology.md` puts LangChain in the technology table for exactly this
increment, and it is **not** what this module uses. Measured on 2026-09-07 rather
than argued: `langchain-openai` resolves to **37 distributions**, and one of them
is `langsmith`, a hard dependency of `langchain-core`. `concept/06` and
`concept/07` both settle hosted tracing as *rejected, not deferred* — a second
egress channel for prompts and retrieved provider text — and
`tests/test_dependency_boundary.py::test_no_hosted_tracing_sdk_is_even_importable_from_the_environment`
enforces that by asserting the module does not resolve at all. Adopting LangChain
here would have meant weakening that test in the session that introduced the
thing it guards against.

So the two documents disagree, the conflict is recorded rather than resolved by a
session (`docs/decisions/0020-the-model-client.md`, and the report for task 30),
and what this module does is what the project already does for the feed loaders:
one POST does not earn a dependency. The endpoint is an ordinary
OpenAI-compatible HTTP API and `urllib` speaks it. Structured output is validated
by Pydantic, which is approved and is the contract's own validator; **tool
binding, which is the half of LangChain's justification this module does not
supply, has no caller yet** — triage binds no tools at all, and the analyst's tool
loop is a later increment. That increment is where the question has to be
answered, and it will still be the operator's to answer.

## Inference is hosted, so a model call is a disclosure

`concept/03-architecture.md`: *"Inference in the prototype is hosted, so prompts
leave the monitored network and the disclosure rule applies to model calls as much
as to intelligence lookups."* So `assess` takes the run's
`helena.disclosure.Disclosures` ledger on the same terms it takes the budget —
keyword-only, no default — and records one row **before each attempt**, because a
retry sends the prompt a second time. The row names the model, the endpoint host
and the size and digest of what left; it does not copy the prompt, which is the
rendered context the request already carries under a recorded
`rendering_version`.

Reads: `helena.config.ModelSettings` (one agent's endpoint, token and model).
Writes: nothing durable — one structured log record per call, to stderr, and one
disclosure row per attempt on the ledger it was handed.

Maturity: experimental — exercised against a local stub endpoint and against the
real configured endpoint. No assessment has been stored, and no evaluation has
measured a schema-violation rate for any model.
"""

from __future__ import annotations

import json
import tomllib
import urllib.error
import urllib.request
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, NonNegativeInt, PositiveInt, ValidationError

from helena import observability, taxonomy
from helena.budgets import BudgetExhausted, RunBudget
from helena.config import AGENTS, ModelSettings, Settings
from helena.disclosure import Disclosures
from helena.contracts import v1 as contract
from helena.enrichment import ENTITY_TYPES, QUERY_FAILURE_REASONS

__all__ = [
    "CLOSED_VOCABULARIES",
    "CODE_OWNED_FIELDS",
    "COMPLETIONS_PATH",
    "RETRY_FILE",
    "ROLES",
    "AgentError",
    "Completion",
    "Message",
    "ModelClient",
    "ModelTimedOut",
    "ModelUnavailable",
    "RetryPolicy",
    "assess",
    "proposable_fields",
    "proposal_schema",
    "retry_policy",
]

PROJECT_ROOT = Path(__file__).resolve().parents[2]

#: The retry bound. Policy, not a constant in this package — see `retry_policy`.
RETRY_FILE = PROJECT_ROOT / "config" / "agents.toml"

#: Appended to the configured endpoint. The OpenAI-compatible chat completions
#: path; the configured URL carries the API root, including its version segment.
COMPLETIONS_PATH = "chat/completions"

#: The three roles the endpoint takes. `assistant` is here because the wire
#: protocol has it, and deliberately not used: an assistant turn is how an
#: invalid answer would re-enter the conversation, which is the repair call.
ROLES = ("system", "user", "assistant")

#: The fields of a result that deterministic code measures and the model is never
#: asked for. `emitter` is which agent ran, `cost` is what the run spent and
#: `versions` is what produced it — three facts the caller knows and the model
#: would only be guessing at.
CODE_OWNED_FIELDS = ("emitter", "cost", "versions")

#: The closed vocabularies the contract enforces **after** generation, keyed by
#: the definition and property they belong to.
#:
#: `model_json_schema()` cannot see any of them. Every one is checked in a
#: `model_post_init` — a validator is code, not a type — so the generated schema
#: says `{"type": "string"}` for a field that accepts exactly two words. Measured
#: against the configured endpoint on 2026-09-07: with `stance` left as a bare
#: string the model filled it with the host's rendered line, three times, and the
#: assessment became a typed failure for a vocabulary nobody had shown it.
#:
#: So the enum is injected from **the contract's own constant**, read at
#: schema-build time. That is one copy and not two: there is no literal here to
#: drift from `STANCES`, and `tests/test_agents.py` asserts every entry still
#: names a class and a field the contract has.
CLOSED_VOCABULARIES: dict[tuple[str, str], tuple[str, ...]] = {
    ("Citation", "stance"): contract.STANCES,
    ("Gap", "kind"): contract.GAP_KINDS,
    ("RetrievalStep", "outcome"): contract.RETRIEVAL_OUTCOMES,
    ("RetrievalStep", "entity_type"): tuple(sorted(ENTITY_TYPES)),
    ("ProposedClaim", "subject_type"): tuple(sorted(ENTITY_TYPES)),
    ("QueryFailure", "reason"): tuple(QUERY_FAILURE_REASONS),
}

#: Bound on the validation error fed back to the model, and on a failure detail.
#: The same bound `helena.enrichment.QueryFailure` uses, for the reason it gives:
#: a diagnostic is a sentence, and an unbounded one is where a provider response
#: ends up.
MAX_FEEDBACK = contract.MAX_DETAIL

#: The one sampling parameter this module sets. Zero because `concept/06` asks
#: for reproducibility — fixed inputs, recorded versions, deterministic
#: processing. It is not a claim that the endpoint is deterministic; a hosted
#: endpoint is not, which is why the model identity is recorded per assessment.
TEMPERATURE = 0


class AgentError(RuntimeError):
    """The agent layer was misconfigured or misused. Never a model's fault."""


class ModelUnavailable(AgentError):
    """No usable response at all — refused, errored, or unreachable.

    Becomes `contract.MODEL_UNAVAILABLE`, which carries **no** reported model
    version, because nothing answered.
    """


class ModelTimedOut(AgentError):
    """The wall-clock budget was spent before an answer arrived."""


class Message(BaseModel):
    """One turn of the request. Content is never logged and never truncated here.

    The rendering it carries is bounded by `helena.rendering.budget()` already,
    and a second bound in this module would silently re-truncate what the
    rendering recorded truncating.
    """

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    role: str
    content: str

    def model_post_init(self, _context: object) -> None:
        if self.role not in ROLES:
            raise ValueError(f"role {self.role!r} is not one of {list(ROLES)}")
        if not self.content.strip():
            raise ValueError("a blank message is a turn that says nothing")


def _version_shaped(name: str, value: str) -> None:
    """What `helena.versions.Version` accepts, checked where it can still be typed.

    A reported model identity that cannot be recorded as a version is an
    **endpoint** problem, and catching it here makes it `model_unavailable` with a
    message naming the field, rather than a `ValidationError` escaping from
    `completed_by` three frames later where it would read as the model's fault.
    """
    if not value or value.split() != [value]:
        raise ValueError(
            f"{name} is {value!r}; a recorded version is one non-empty token with "
            f"no whitespace"
        )


class RetryPolicy(BaseModel):
    """How many times one assessment may ask the model. Read from configuration.

    `attempts` counts **calls**, not retries: one attempt is a run with no retry
    at all, and `Cost.retries` is `attempts spent - 1`. Counting calls is what
    makes the exhaustion condition readable at the loop head rather than
    off-by-one at the bottom.
    """

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    attempts: PositiveInt


class Completion(BaseModel):
    """One answer from the endpoint, and what it cost.

    `model_reported` is what the **response** said answered, which is the only
    value `RequestVersions.completed_by` accepts. `docs/decisions/0008-version-registry.md`:
    the configured name "is the thing that stays stable while what answers to it
    changes".
    """

    model_config = ConfigDict(
        strict=True, extra="forbid", frozen=True, protected_namespaces=()
    )

    text: str
    model_reported: str
    prompt_tokens: NonNegativeInt
    completion_tokens: NonNegativeInt

    def model_post_init(self, _context: object) -> None:
        _version_shaped("the reported model identity", self.model_reported)


def retry_policy(path: Path | str = RETRY_FILE) -> RetryPolicy:
    """Read the configured retry bound, or fail naming what is wrong with the file.

    TOML, so the file is `tomllib` and no dependency — the same reader
    `helena.rendering.budget` and `helena.hosts.load` use:

        [retry]
        attempts = 3

    There is no fallback value. A retry bound nobody chose is the silent default
    `concept/instruction.md` §6 lists by name, and the shape it would take here is
    the worst one: an assessment quietly spending three times its token budget on
    a model that cannot emit the schema.
    """
    path = Path(path)
    try:
        raw = path.read_bytes()
    except FileNotFoundError as absent:
        raise AgentError(
            f"no retry configuration at {path}. The bound on schema retries is "
            f"policy and not a constant in this package, so an absent file is a "
            f"startup failure and never an unbounded retry loop."
        ) from absent
    try:
        document = tomllib.loads(raw.decode())
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as malformed:
        raise AgentError(f"{path} is not readable TOML: {malformed}") from malformed
    unexpected = sorted(set(document) - {"retry"})
    if unexpected:
        raise AgentError(
            f"{path} has top-level keys {unexpected}; the file is one [retry] "
            f"table. A key nothing reads is a policy somebody set and nothing "
            f"applies."
        )
    table = document.get("retry")
    if not isinstance(table, dict):
        raise AgentError(
            f"{path} has no [retry] table; the bound is the whole of what this "
            f"file says."
        )
    try:
        return RetryPolicy(**table)
    except ValidationError as refused:
        raise AgentError(f"{path}: {refused}") from refused


def proposable_fields(result_type: type[BaseModel]) -> tuple[str, ...]:
    """The result fields a model may propose: every field code does not own.

    Derived rather than listed, so a contract version that adds a field makes it
    proposable by default and a field that must not be proposed is added to
    `CODE_OWNED_FIELDS` deliberately.
    """
    missing = [name for name in CODE_OWNED_FIELDS if name not in result_type.model_fields]
    if missing:
        raise AgentError(
            f"{result_type.__name__} has no {missing} field, so this module cannot "
            f"tell what the code that ran the assessment owns from what the model "
            f"proposes"
        )
    return tuple(
        name for name in result_type.model_fields if name not in CODE_OWNED_FIELDS
    )


def proposal_schema(
    result_type: type[BaseModel],
    fields: Sequence[str] | None = None,
    *,
    vocabularies: Mapping[str, Sequence[str]] | None = None,
) -> dict[str, Any]:
    """The JSON schema for what the model may propose, derived from the contract.

    One schema, one source. `fields` narrows it — the contract already refuses a
    triage result carrying an evidence package, a retrieval trace or a proposed
    claim, so offering a triage model those fields would be offering it a way to
    fail validation and nothing else. `None` means every proposable field.

    `vocabularies` closes a **top-level** property the same way
    `CLOSED_VOCABULARIES` closes a nested one, and it is a parameter rather than
    another entry in that map because the one field that needs it —
    `classification` — has a different closed set per emitter and per taxonomy
    version. A constant here would be a second copy of `helena.taxonomy`'s
    `emitter_roots`, and this module may not name an agent to choose between
    them. The caller passes the set it looked up; `tests/test_triage.py` is what
    asserts the looked-up set is the taxonomy's.

    `$defs` are pruned to what the kept properties actually reference, because the
    schema is sent on **every** call on the high-volume path: measured against the
    configured endpoint on 2026-09-07, the triage subset is 2 195 bytes and the
    full set 13 309.
    """
    allowed = proposable_fields(result_type)
    selected = tuple(allowed if fields is None else fields)
    if not selected:
        raise AgentError(
            "a proposal schema with no fields would ask the model for nothing and "
            "refuse whatever it said"
        )
    unknown = sorted(set(selected) - set(allowed))
    if unknown:
        raise AgentError(
            f"{unknown} is not something {result_type.__name__} lets a model "
            f"propose; the proposable fields are {list(allowed)}"
        )

    full = result_type.model_json_schema()
    properties = {name: full["properties"][name] for name in selected}
    for name, vocabulary in (vocabularies or {}).items():
        if name not in properties:
            raise AgentError(
                f"a vocabulary was given for {name!r}, which this schema does not "
                f"offer; the properties are {list(properties)}. A closed set on a "
                f"field the model is never asked for is a constraint nothing applies."
            )
        if not vocabulary:
            raise AgentError(
                f"the vocabulary for {name!r} is empty, which would ask the model "
                f"for a value and permit none"
            )
        properties[name] = {**properties[name], "enum": list(vocabulary)}
    definitions = _with_vocabularies(full.get("$defs", {}))
    return {
        "type": "object",
        "properties": properties,
        "required": [name for name in full.get("required", ()) if name in selected],
        "$defs": _reachable(properties, definitions),
        # The endpoint's strict mode and the contract's `extra="forbid"` refuse
        # the same thing, one before generation and one after. Neither alone is
        # enough: a server that ignores the schema still meets the contract.
        "additionalProperties": False,
    }


def _with_vocabularies(definitions: dict[str, Any]) -> dict[str, Any]:
    """The definitions, with every closed vocabulary the contract enforces made visible.

    Fails loudly rather than silently skipping: a definition or a field this map
    names and the contract no longer has is a rename that would leave the model
    guessing at a vocabulary again, and the guess costs a whole assessment.
    """
    for (definition, field), vocabulary in CLOSED_VOCABULARIES.items():
        if definition not in definitions:
            raise AgentError(
                f"the contract has no {definition!r}, and CLOSED_VOCABULARIES "
                f"names it. A vocabulary this module cannot show the model is one "
                f"the model will invent a value for."
            )
        properties = definitions[definition].get("properties", {})
        if field not in properties:
            raise AgentError(
                f"{definition} has no {field!r} field, and CLOSED_VOCABULARIES "
                f"names it"
            )
        properties[field] = {**properties[field], "enum": list(vocabulary)}
    return definitions


def _reachable(
    properties: dict[str, Any], definitions: dict[str, Any]
) -> dict[str, Any]:
    """The `$defs` the kept properties reference, transitively.

    Serialized-and-searched rather than walked node by node: a `$ref` is a string
    with one spelling, and a walker would be a second traversal of Pydantic's
    schema shape that has to be kept correct as that shape changes.
    """
    keep: set[str] = set()
    pending = [json.dumps(properties)]
    while pending:
        blob = pending.pop()
        for name, definition in definitions.items():
            if f'"#/$defs/{name}"' in blob and name not in keep:
                keep.add(name)
                pending.append(json.dumps(definition))
    return {name: definitions[name] for name in sorted(keep)}


class ModelClient:
    """One agent's endpoint, token and model. Differs from the other by configuration.

    There is no branch on which agent this is, anywhere in this module: the agent
    name indexes `Settings`, and everything after that is the same code against
    different values. `concept/04`: "agents differ by model, not by framework, and
    model choice stays a configuration value, never a code path."
    """

    __slots__ = ("_settings", "_logger", "_url")

    def __init__(
        self, settings: ModelSettings, *, logger: observability.StructuredLogger
    ) -> None:
        self._settings = settings
        self._logger = logger
        self._url = f"{settings.endpoint_url.rstrip('/')}/{COMPLETIONS_PATH}"
        if not self.endpoint_host:
            raise AgentError(
                f"the endpoint configured for {settings.agent!r} names no host. "
                f"Resolution is agent-specific, then general, then fail — a "
                f"request to a hostless URL is a run against an unintended "
                f"endpoint that looks like a transport error."
            )

    @classmethod
    def for_agent(
        cls, settings: Settings, agent: str, *, stream: Any = None
    ) -> ModelClient:
        """The client for one agent, resolved purely from configuration.

        `getattr` rather than a branch, and the name is checked against
        `helena.config.AGENTS` first so a typo is a startup error naming the
        agents that exist rather than an `AttributeError` from inside Pydantic.
        """
        if agent not in AGENTS:
            raise AgentError(f"agent {agent!r} is not one of {list(AGENTS)}")
        return cls(
            getattr(settings, agent),
            logger=observability.logger(f"agents.{agent}", settings, stream=stream),
        )

    @property
    def endpoint_host(self) -> str:
        """Host and port. What is recorded on an assessment, per `concept/07`.

        Userinfo, path and query are dropped rather than redacted: this value is
        recorded and logged, and "enough to know what produced a result, nothing
        that authenticates as anyone" is a rule about what is *kept*, not about
        what is masked afterwards.
        """
        parts = urlsplit(self._settings.endpoint_url)
        host = parts.hostname or ""
        try:
            port = parts.port
        except ValueError:  # a non-numeric port in the configured URL
            raise AgentError(
                f"the endpoint configured for {self._settings.agent!r} has an "
                f"unparseable port"
            ) from None
        return f"{host}:{port}" if port else host

    @property
    def model_requested(self) -> str:
        """The configured model name. Never what answered — that is on the response."""
        return self._settings.model

    def complete(
        self,
        messages: Sequence[Message],
        *,
        schema: dict[str, Any],
        max_tokens: int,
        timeout: float,
        attempt: int,
    ) -> Completion:
        """One call. Raises `ModelUnavailable` or `ModelTimedOut`, never returns a partial.

        The schema goes to the endpoint's `response_format` rather than into the
        prompt, and that is a cost decision with a measurement behind it: against
        the configured endpoint on 2026-09-07 the same triage question cost **122
        prompt tokens** with the schema in `response_format` and **694** with the
        schema written into a system message. The high-volume path pays that
        difference on every context.

        It does not make the retry loop dead code. Strict mode constrains the
        *shape*; the contract's rules — a stance that is not one of two words, a
        classification the taxonomy does not have, a confidence outside 0..1 —
        are not expressible in JSON Schema and are exactly what fails.
        """
        payload = {
            "model": self._settings.model,
            "messages": [
                {"role": message.role, "content": message.content}
                for message in messages
            ],
            "max_tokens": max_tokens,
            "temperature": TEMPERATURE,
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "agent_result",
                    "strict": True,
                    "schema": schema,
                },
            },
        }
        request = urllib.request.Request(
            self._url,
            data=json.dumps(payload).encode(),
            headers={
                # The one place this token is revealed. It goes in a header, never
                # in the URL: `concept/05` and task 01 both record what a
                # credential in a path costs once anything logs the request.
                "Authorization": f"Bearer {self._settings.token.reveal()}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )
        # No message content here, ever. The rendering is attacker-influenced text
        # and a prompt is not a diagnostic.
        self._logger.outbound_request(
            "agents.model.call",
            method="POST",
            url=self._url,
            endpoint_host=self.endpoint_host,
            model_requested=self._settings.model,
            attempt=attempt,
            max_tokens=max_tokens,
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                raw = response.read()
        except urllib.error.HTTPError as refused:
            # The status and nothing else. A response body may echo the request,
            # and the request carries the rendering and an Authorization header.
            self._logger.exception(
                "agents.model.refused", refused, endpoint_host=self.endpoint_host
            )
            raise ModelUnavailable(
                f"the endpoint answered HTTP {refused.code}"
            ) from refused
        except (TimeoutError, urllib.error.URLError, OSError) as unreachable:
            self._logger.exception(
                "agents.model.unreachable",
                unreachable,
                endpoint_host=self.endpoint_host,
            )
            if _is_timeout(unreachable):
                raise ModelTimedOut(
                    f"{type(unreachable).__name__}: {unreachable}"
                ) from unreachable
            raise ModelUnavailable(
                f"{type(unreachable).__name__}: {unreachable}"
            ) from unreachable

        completion = _completion(raw)
        self._logger.info(
            "agents.model.answered",
            endpoint_host=self.endpoint_host,
            model_requested=self._settings.model,
            model_reported=completion.model_reported,
            attempt=attempt,
            prompt_tokens=completion.prompt_tokens,
            completion_tokens=completion.completion_tokens,
        )
        return completion


def _is_timeout(failure: BaseException) -> bool:
    """A read timeout, whichever of the two shapes `urllib` raises it in."""
    if isinstance(failure, TimeoutError):
        return True
    reason = getattr(failure, "reason", None)
    return isinstance(reason, TimeoutError)


def _completion(raw: bytes) -> Completion:
    """The response body as a `Completion`, or `ModelUnavailable` naming the field.

    A body this cannot read is the **endpoint** failing to be OpenAI-compatible,
    which is a different thing from the model failing to emit the schema — one is
    a deployment pointed at the wrong service and the other is a model that needs
    retrying, and collapsing them would retry three times against a service that
    was never going to answer.

    `usage` is required rather than defaulted to zero. A token budget silently
    unenforced is the failure this project keeps writing down: it is invisible in
    exactly the deployment where the budget mattered.
    """
    try:
        body = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as malformed:
        raise ModelUnavailable(
            f"the endpoint's response is not JSON: {type(malformed).__name__}"
        ) from malformed
    try:
        choice = body["choices"][0]["message"]["content"]
        usage = body["usage"]
        return Completion(
            text=choice,
            model_reported=body["model"],
            prompt_tokens=usage["prompt_tokens"],
            completion_tokens=usage["completion_tokens"],
        )
    except (KeyError, IndexError, TypeError) as missing:
        raise ModelUnavailable(
            f"the endpoint's response is not an OpenAI-compatible chat completion: "
            f"{type(missing).__name__} {missing}"
        ) from missing
    except ValidationError as refused:
        raise ModelUnavailable(
            f"the endpoint's response has a field of the wrong type: {refused}"
        ) from refused


def _attempt_messages(
    messages: Sequence[Message], validation_error: str | None
) -> tuple[Message, ...]:
    """The original question, plus at most one message saying what was wrong.

    **This is where the repair call is refused.** The list is rebuilt from
    `messages` every attempt, so the model's invalid answer is discarded and never
    sent anywhere: what it is told is that an answer failed and what the failure
    said, not what it wrote. One feedback message, not one per attempt, so the
    prompt does not grow with the retries.
    """
    if validation_error is None:
        return tuple(messages)
    return (
        *messages,
        Message(
            role="user",
            content=(
                "The previous answer did not validate and has been discarded. "
                "Answer the original question again, in full, as JSON matching "
                "the schema. Do not refer to the previous answer. The validation "
                f"error was:\n{validation_error}"
            ),
        ),
    )


def _bound(text: str, limit: int = MAX_FEEDBACK) -> str:
    """A diagnostic is a sentence. Truncation is marked, never silent."""
    return text if len(text) <= limit else text[: limit - 1] + "…"


def assess(
    request: contract.AgentRequest,
    *,
    client: ModelClient,
    messages: Sequence[Message],
    policy: RetryPolicy,
    budget: RunBudget,
    disclosures: Disclosures,
    propose: Sequence[str] | None = None,
    vocabularies: Mapping[str, Sequence[str]] | None = None,
) -> contract.AgentResult | contract.AgentFailure:
    """One assessment: call, validate, retry bounded, or a typed failure.

    Returns an `AgentResult` **or** an `AgentFailure` and never raises for
    anything the model or the endpoint did — `concept/07` makes the typed failure
    and the verdict the two terminal outcomes, and an exception escaping here
    would be a third one that the caller would have to remember to catch.

    `policy` has no default for the reason `helena.rendering.v1.render`'s budget
    has none: a caller that could forget it would run unbounded.

    **`budget` is the run's ledger, not this call's**, and it has no default for a
    sharper version of the same reason. `helena.budgets.RunBudget` is built once
    per agent run and charged by everything in it — the model calls here and every
    provider lookup — so the wall clock covers *the whole run including provider
    waits* and the token budget covers every attempt of it. A ledger built inside
    this function would restart the clock on every turn of an analyst's tool loop,
    which is the unbounded run the dimension exists to bound. It is checked
    against `request.budgets` on the way in, because a ledger built from another
    request's numbers would enforce a budget nobody handed this run.

    Two dimensions are charged here and two are not: tokens and the wall clock are
    this module's, and steps and live queries are `helena.tools`' — a model call
    spends neither.

    **`disclosures` is the run's disclosure ledger** and has no default for the
    third version of the same reason. `concept/03`: inference is hosted, so a
    prompt leaves the monitored network and *"the disclosure rule applies to model
    calls as much as to intelligence lookups"*. One row per attempt, recorded
    before the request is made — a retry discloses the rendering a second time,
    and a call that timed out disclosed it too. It is checked against the request
    on the way in, because a ledger built from another request's scope would
    record this run's disclosures against a context nobody can resolve.

    **What this does not do**, and what the runner around it owes:

    - It does not call `contract.check_exchange`. That is where the truncation
      rule lives — a rendering that truncated requires a `truncated` gap on the
      outcome — and the gap is a fact *code* knows, so the runner emits it and
      then checks the exchange. Doing it here would mean this module writing a
      gap into a verdict it did not produce.
    - It does not choose the prompt, the model or the field set. Those are the
      caller's, from configuration and from a versioned prompt file. `propose`
      and `vocabularies` are what the caller narrows the schema with; this
      module cannot look either up, because looking them up means knowing which
      agent is running.
    """
    if (disclosures.tenant, disclosures.sensor, disclosures.context_id) != (
        request.tenant,
        request.sensor,
        request.context_id,
    ):
        raise AgentError(
            f"the request is {request.tenant}/{request.sensor} context "
            f"{request.context_id!r} and the disclosure ledger records "
            f"{disclosures.tenant}/{disclosures.sensor} context "
            f"{disclosures.context_id!r}. "
            f"`helena.disclosure.Disclosures.of(request, policy=...)` is what "
            f"builds one, because a disclosure recorded against another run's "
            f"context is a record nobody can resolve."
        )
    if budget.limits != request.budgets:
        raise AgentError(
            f"the request budgets {request.budgets} and the ledger enforces "
            f"{budget.limits}. `helena.budgets.RunBudget.of(request)` is what "
            f"builds one, because a run enforced against a budget it was not "
            f"given is a budget nobody set (`concept/instruction.md` §2)."
        )
    result_type = contract.AgentResult
    schema = proposal_schema(result_type, propose, vocabularies=vocabularies)

    attempts = 0
    reported: str | None = None
    validation_error: str | None = None

    def failure(reason: str, detail: str, *, gap: contract.Gap | None) -> contract.AgentFailure:
        return contract.AgentFailure(
            emitter=request.emitter,
            reason=reason,
            detail=_bound(detail),
            gaps=() if gap is None else (gap,),
            cost=budget.cost(retries=max(attempts - 1, 0)),
            versions=request.versions,
            # `model_unavailable` means nothing answered, and the contract
            # refuses a reported version there. Every other reason carries what
            # answered, when something did.
            model_version=None if reason == contract.MODEL_UNAVAILABLE else reported,
        )

    while attempts < policy.attempts:
        try:
            # The ledger's own guard, so that "the run wanted another attempt and
            # could not have one" is recorded where it happened and reaches the
            # `budget_exhausted` gap below. `concept/07`: the retries a
            # schema-invalid answer costs are spent against this budget, so a run
            # can end here before it ends on `policy.attempts`.
            budget.check_tokens()
        except BudgetExhausted:
            break
        remaining_tokens = budget.remaining_tokens
        remaining_seconds = budget.remaining_seconds
        if remaining_seconds <= 0:
            return failure(
                contract.TIMED_OUT,
                f"the wall-clock budget of {request.budgets.wall_clock_seconds}s "
                f"was spent over {attempts} attempt(s)",
                gap=None,
            )

        attempts += 1
        attempted = _attempt_messages(messages, validation_error)
        # Before the call, not after. The prompt is on the wire either way, and a
        # request that reached the endpoint and then timed out disclosed the
        # rendering just as much as one that answered. `concept/03`: inference is
        # hosted, so this is egress and the disclosure rule applies to it.
        disclosures.record_model_call(
            model=client.model_requested,
            disclosed_to=client.endpoint_host,
            prompt=_prompt_bytes(attempted),
            messages=len(attempted),
            at=datetime.now(timezone.utc),
        )
        try:
            completion = client.complete(
                attempted,
                schema=schema,
                max_tokens=remaining_tokens,
                timeout=remaining_seconds,
                attempt=attempts,
            )
        except ModelTimedOut as expired:
            return failure(contract.TIMED_OUT, str(expired), gap=None)
        except ModelUnavailable as unreachable:
            if reported is None:
                return failure(contract.MODEL_UNAVAILABLE, str(unreachable), gap=None)
            # Something did answer earlier, so "nothing answered" would be false.
            # The run produced no verdict because no answer validated, and the
            # transport failure is why there were no more attempts.
            return failure(
                contract.SCHEMA_INVALID,
                f"no answer validated, and the retry ended early: {unreachable}",
                gap=contract.Gap(
                    kind=contract.FAILED,
                    detail=f"the endpoint stopped answering mid-retry: {unreachable}",
                ),
            )

        budget.record_tokens(
            prompt=completion.prompt_tokens, completion=completion.completion_tokens
        )
        reported = completion.model_reported

        # Built outside the `try` on purpose: these are what the *code* measured,
        # and a failure here is this module's bug, not an answer worth retrying.
        spent = budget.cost(retries=max(attempts - 1, 0))
        versions = request.versions.completed_by(completion.model_reported)

        try:
            merged = {
                **_proposed(completion.text),
                "emitter": request.emitter,
                "cost": spent.model_dump(mode="json"),
                "versions": versions.model_dump(mode="json"),
            }
            # **Validated in JSON mode, which is the mode the answer arrived in.**
            # The contract is `strict=True`, and in *python* mode that refuses a
            # `list` where a `tuple` is declared and an `int` where a `float` is —
            # so `{"citations": [...]}` and `{"confidence": 1}` would be permanent
            # schema violations no model could ever get past, and the bounded retry
            # would burn three attempts on a difference between JSON and Python
            # rather than on anything the model did. JSON mode keeps every
            # strictness that is about the *data* — a string where a number is
            # declared is still refused — and drops the one that is about the host
            # language's type vocabulary.
            return result_type.model_validate_json(json.dumps(merged))
        except (ValidationError, ValueError, taxonomy.TaxonomyError) as invalid:
            # `ValidationError` is Pydantic's, `TaxonomyError` is what
            # `AgentResult` raises for a path the vocabulary does not have, and
            # `ValueError` covers `_proposed`. All three are the model's answer
            # being wrong, which is what a retry is for.
            validation_error = _bound(str(invalid))

    if reported is None:
        # Unreachable while every budget dimension is strictly positive, which
        # `Budgets` enforces — but `schema_invalid` requires a reported model
        # version, so leaving it to chance would make this function raise from
        # the one place that promises it never does.
        return failure(
            contract.MODEL_UNAVAILABLE,
            f"no attempt was made in {attempts} attempt(s); the run had no budget",
            gap=budget.gap(),
        )
    return failure(
        contract.SCHEMA_INVALID,
        f"no answer validated in {attempts} attempt(s). The last error was: "
        f"{validation_error}",
        gap=budget.gap(),
    )


def _prompt_bytes(messages: Sequence[Message]) -> bytes:
    """Exactly what the rendered context amounts to on the wire, for a digest.

    The messages and nothing else: the schema, the model name and the sampling
    parameter also travel, and they are this project's own rather than anything
    the monitored network produced. Serialized the way the request body serializes
    them, so the digest is over the bytes that left and not over a paraphrase of
    them. The value is never stored — `helena.disclosure.Disclosure` keeps its
    digest, and the text stays in the rendering the request already carries.
    """
    return json.dumps(
        [message.model_dump(mode="json") for message in messages],
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def _proposed(text: str) -> dict[str, Any]:
    """The model's answer as the fields it is allowed to propose.

    Raises `ValueError` for anything wrong, because everything wrong here is the
    model's answer being wrong and the loop feeds that back. A key the code owns
    is refused by name rather than silently dropped: a model that reported its own
    cost is a model that has been asked the wrong question, and dropping it would
    hide that.
    """
    try:
        proposed = json.loads(text)
    except json.JSONDecodeError as malformed:
        raise ValueError(f"the answer is not JSON: {malformed}") from malformed
    if not isinstance(proposed, dict):
        raise ValueError(
            f"the answer is a JSON {type(proposed).__name__}, and a result is an object"
        )
    owned = sorted(set(proposed) & set(CODE_OWNED_FIELDS))
    if owned:
        raise ValueError(
            f"the answer sets {owned}, which the code that ran the assessment "
            f"records and never asks for"
        )
    return proposed
