"""Configuration — the environment read once, fail-loud, with secrets wrapped.

Configuration comes from the process environment and from an uncommitted `.env`;
`.env.example` documents every variable name with an empty value, and
`tests/test_config.py` holds the two files to the same set. Resolution for
anything an agent uses is **agent-specific, then general, then fail**: a missing
value is a startup error naming the variable — never a built-in default
endpoint, never a silent fallback to another agent's model, never a defaulted
tenant. An empty or whitespace-only value counts as missing, because the example
ships every variable empty and a copied-but-unfilled file has to fail loudly.

The failure this prevents is the expensive one: a triage run that silently used
the analyst's model, or a run against an unintended endpoint, discovered only in
the cost or in the results (`concept/07-principles.md`).

Tokens and provider keys are `Secret` — absent from `str`, `repr` and every
Pydantic serialization. `reveal()` is the only way out of one, and it belongs at
the point of use, never at the point of logging.

Reads: `os.environ`, layered over an uncommitted `.env`. Writes: nothing.

Maturity: experimental — exercised by the test suite against the real `.env`,
but no deployment has run against it.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import Annotated

from dotenv import dotenv_values
from pydantic import BaseModel, ConfigDict, PlainSerializer

__all__ = [
    "AGENTS",
    "HELENA_INGEST_TOPIC",
    "REDACTED",
    "VARIABLES",
    "ConfigurationError",
    "Infrastructure",
    "IngestionIdentity",
    "ModelSettings",
    "ProviderCredentials",
    "Secret",
    "Settings",
]

# What a secret renders as, everywhere a value would otherwise appear. One
# constant so that a test can assert the absence of the value by asserting the
# presence of this.
REDACTED = "***redacted***"

# The two agents of concept/04-the-two-agents.md. Investigation is deferred and
# is deliberately not here: it would be a third set of variables for an agent
# that does not exist.
AGENTS = ("triage", "analyst")

# The general model settings. Each has a per-agent override, resolved first.
LLM_URL = "LLM_URL"
LLM_TOKEN = "LLM_TOKEN"
LLM_MODEL = "LLM_MODEL"
MODEL_VARIABLES = (LLM_URL, LLM_TOKEN, LLM_MODEL)

# Ingestion identity. Prefixed, because a bare `TENANT` in a shared environment
# is the kind of name another process sets by accident, and a wrong tenant is an
# isolation failure that looks like it is working.
HELENA_TENANT = "HELENA_TENANT"
HELENA_SENSOR = "HELENA_SENSOR"

# Which input format this deployment consumes, naming one of the adapters
# registered in `helena.normalizer`. A second input format is an adapter and a
# change to this variable, never a change to a contract
# (`concept/06-technology.md`, compatibility boundaries). It has no default for
# the same reason nothing else here does: a deployment silently reading its
# traffic through the wrong parser would quarantine every record and look like a
# producer problem. The registered names live with the adapters, so this module
# does not validate the value — `helena.normalizer.adapter_for` refuses an
# unknown one naming this variable.
HELENA_INPUT_FORMAT = "HELENA_INPUT_FORMAT"

ABUSECH_AUTH_KEY = "ABUSECH_AUTH_KEY"
VIRUSTOTAL_AUTH_KEY = "VIRUSTOTAL_AUTH_KEY"

RISINGWAVE_DSN = "RISINGWAVE_DSN"
KAFKA_BOOTSTRAP_SERVERS = "KAFKA_BOOTSTRAP_SERVERS"

# The topic flow records arrive on. A name, not an address: it sits beside the
# bootstrap servers because both are what "replacing the broker is a
# configuration change" means in practice, and a topic name compiled into the
# consumer would be exactly as wrong as an address compiled into it
# (`concept/03-architecture.md`). No default, for the reason nothing here has
# one: a deployment reading an empty or misspelled topic waits forever on a
# topic nobody produces to, which looks identical to a producer that has
# stopped.
#
# The **output** topic is deliberately absent. It enters with the sink that
# writes to it; a configuration key nothing reads is a key with one value and no
# way to be wrong (`concept/instruction.md` §1).
HELENA_INGEST_TOPIC = "HELENA_INGEST_TOPIC"

# Every one of these must be present and non-blank, or startup fails naming it.
REQUIRED_VARIABLES = (
    *MODEL_VARIABLES,
    HELENA_TENANT,
    HELENA_SENSOR,
    HELENA_INPUT_FORMAT,
    ABUSECH_AUTH_KEY,
    VIRUSTOTAL_AUTH_KEY,
    RISINGWAVE_DSN,
    KAFKA_BOOTSTRAP_SERVERS,
    HELENA_INGEST_TOPIC,
)

# Optional by design: absent means "use the general value". That is the whole of
# the agent-specific → general half of the resolution order.
AGENT_OVERRIDE_VARIABLES = tuple(
    f"{variable}_{agent.upper()}" for agent in AGENTS for variable in MODEL_VARIABLES
)

# The loader's variable set. `.env.example` lists exactly these, all empty.
VARIABLES = REQUIRED_VARIABLES + AGENT_OVERRIDE_VARIABLES


class ConfigurationError(RuntimeError):
    """Startup failed because configuration is missing. Names every variable."""


class Secret:
    """A value that must not reach a log, a row, a prompt or a trace.

    `str` and `repr` render `REDACTED`, and the Pydantic serializer below
    substitutes it in both `model_dump` and `model_dump_json`. `reveal()` is the
    single deliberate way out; grepping for it finds every place a credential is
    used.
    """

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        if not isinstance(value, str):
            raise TypeError(f"Secret takes a str, not {type(value).__name__}")
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __str__(self) -> str:
        return REDACTED

    def __repr__(self) -> str:
        return f"Secret({REDACTED})"


def _redact(_secret: Secret) -> str:
    return REDACTED


# A Secret in a Pydantic model. `arbitrary_types_allowed` validates it by
# isinstance — a bare str is not silently promoted, so a credential cannot enter
# a settings object without passing through the wrapper.
SecretField = Annotated[Secret, PlainSerializer(_redact, return_type=str)]

# `hide_input_in_errors` because a validation error otherwise echoes the input:
# a bare credential string passed where a `Secret` belongs would be a leak into
# a traceback, which is one of the places a credential may never appear.
_SETTINGS_MODEL_CONFIG = ConfigDict(
    frozen=True,
    arbitrary_types_allowed=True,
    extra="forbid",
    hide_input_in_errors=True,
)


class ModelSettings(BaseModel):
    """One agent's resolved model settings, and the variables they came from.

    `source` is what makes cross-wiring detectable rather than merely possible:
    it records whether this agent's model came from its own override or from the
    general value.
    """

    model_config = _SETTINGS_MODEL_CONFIG

    agent: str
    endpoint_url: str
    token: SecretField
    model: str
    source: Mapping[str, str]


class IngestionIdentity(BaseModel):
    """Tenant and sensor. Assigned at ingestion, never read from the record."""

    model_config = _SETTINGS_MODEL_CONFIG

    tenant: str
    sensor: str


class ProviderCredentials(BaseModel):
    """The keys the loader and the tool layer hold. Agents never see one."""

    model_config = _SETTINGS_MODEL_CONFIG

    abusech_auth_key: SecretField
    virustotal_auth_key: SecretField


class Infrastructure(BaseModel):
    """Where the engine and the broker are, and which topic ingress reads.

    Addresses and a topic name, no credentials. The topic is here rather than in
    a section of its own because it is the same kind of fact as the bootstrap
    address: what this deployment was pointed at.
    """

    model_config = _SETTINGS_MODEL_CONFIG

    risingwave_dsn: str
    kafka_bootstrap_servers: str
    ingest_topic: str


class Settings(BaseModel):
    """The whole configuration, resolved at startup or not at all."""

    model_config = _SETTINGS_MODEL_CONFIG

    identity: IngestionIdentity
    # The adapter this deployment reads its input through, by name. Resolved to
    # an adapter by `helena.normalizer.adapter_for`, which is where the
    # registered names are — configuration says which format arrives, and the
    # normalizer says which formats exist.
    input_format: str
    providers: ProviderCredentials
    infrastructure: Infrastructure
    triage: ModelSettings
    analyst: ModelSettings

    @classmethod
    def load(
        cls,
        *,
        environ: Mapping[str, str] | None = None,
        env_file: str | Path | None = ".env",
    ) -> Settings:
        """Resolve every variable, or raise naming all the ones that are missing.

        The process environment wins over `.env`; a blank value is absent in
        both layers, so an exported-but-empty variable does not shadow a real
        one in the file.
        """
        values = _layered(
            dotenv_values(env_file) if env_file is not None else {},
            os.environ if environ is None else environ,
        )
        missing: list[str] = []

        def required(name: str) -> str:
            value = values.get(name)
            if value is None:
                missing.append(name)
                return ""
            return value

        identity = {
            "tenant": required(HELENA_TENANT),
            "sensor": required(HELENA_SENSOR),
        }
        input_format = required(HELENA_INPUT_FORMAT)
        providers = {
            "abusech_auth_key": required(ABUSECH_AUTH_KEY),
            "virustotal_auth_key": required(VIRUSTOTAL_AUTH_KEY),
        }
        infrastructure = {
            "risingwave_dsn": required(RISINGWAVE_DSN),
            "kafka_bootstrap_servers": required(KAFKA_BOOTSTRAP_SERVERS),
            "ingest_topic": required(HELENA_INGEST_TOPIC),
        }
        agents = {
            agent: _resolve_agent(agent, values, missing) for agent in AGENTS
        }

        if missing:
            raise ConfigurationError(
                "missing configuration: "
                + ", ".join(sorted(set(missing)))
                + ". Set each one in the environment or in an uncommitted .env "
                "(see .env.example). An empty or whitespace-only value counts "
                "as missing."
            )

        return cls(
            identity=IngestionIdentity(**identity),
            input_format=input_format,
            providers=ProviderCredentials(
                abusech_auth_key=Secret(providers["abusech_auth_key"]),
                virustotal_auth_key=Secret(providers["virustotal_auth_key"]),
            ),
            infrastructure=Infrastructure(**infrastructure),
            triage=agents["triage"],
            analyst=agents["analyst"],
        )


def _present(value: str | None) -> str | None:
    """The value with surrounding whitespace removed, or None if it is blank.

    Empty and whitespace-only are missing — the example ships every variable
    empty, so a copied-but-unfilled file has to fail rather than send an empty
    token to a real service.
    """
    if value is None:
        return None
    return value.strip() or None


def _layered(*layers: Mapping[str, str | None]) -> dict[str, str]:
    """Later layers win, but only where they actually carry a value."""
    values: dict[str, str] = {}
    for layer in layers:
        for name, raw in layer.items():
            value = _present(raw)
            if value is not None:
                values[name] = value
    return values


def _resolve_agent(
    agent: str, values: Mapping[str, str], missing: list[str]
) -> ModelSettings:
    """Agent-specific, then general, then fail — for all three model settings.

    Failure is recorded rather than raised so that one startup error can name
    every missing variable instead of one per run.
    """
    resolved: dict[str, str] = {}
    source: dict[str, str] = {}
    for variable in MODEL_VARIABLES:
        override = f"{variable}_{agent.upper()}"
        for name in (override, variable):
            if (value := values.get(name)) is not None:
                resolved[variable] = value
                source[variable] = name
                break
        else:
            # The general variable is the one that must be set; the override is
            # optional, so naming it here would send the operator to the wrong
            # place.
            missing.append(variable)
            resolved[variable] = ""
            source[variable] = variable

    return ModelSettings(
        agent=agent,
        endpoint_url=resolved[LLM_URL],
        token=Secret(resolved[LLM_TOKEN]),
        model=resolved[LLM_MODEL],
        source=dict(source),
    )
