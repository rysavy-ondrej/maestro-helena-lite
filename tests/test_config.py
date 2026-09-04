"""Tests for helena.config. Mirrors src/helena/config.py.

Every test that resolves settings passes an explicit environment and
`env_file=None`, so the suite never reads the real `.env` except in the one test
that is about reading the real `.env` — and that one asserts on shapes, never on
values.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest
from pydantic import BaseModel, ValidationError

from helena.config import (
    AGENTS,
    REDACTED,
    VARIABLES,
    ConfigurationError,
    ProviderCredentials,
    Secret,
    Settings,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ENV_EXAMPLE = PROJECT_ROOT / ".env.example"
CONFIG_SOURCE = PROJECT_ROOT / "src" / "helena" / "config.py"

# Values that are obviously not credentials, so that a leak in a failure message
# is a nuisance and not an incident.
COMPLETE_ENVIRONMENT = {
    "LLM_URL": "http://model.invalid/v1",
    "LLM_TOKEN": "token-general",
    "LLM_MODEL": "model-general",
    "HELENA_TENANT": "tenant-under-test",
    "HELENA_SENSOR": "sensor-under-test",
    "HELENA_INPUT_FORMAT": "flow-json",
    "ABUSECH_AUTH_KEY": "abusech-key",
    "VIRUSTOTAL_AUTH_KEY": "virustotal-key",
    "RISINGWAVE_DSN": "postgresql://root@localhost:4566/dev",
    "KAFKA_BOOTSTRAP_SERVERS": "localhost:9092",
    "HELENA_INGEST_TOPIC": "helena.ingest",
}

BLANK = ("", " ", "\t", "\n", "  \t\n ")


def environment(**overrides: str) -> dict[str, str]:
    """A complete environment with the overrides applied; None removes a name."""
    values = dict(COMPLETE_ENVIRONMENT)
    for name, value in overrides.items():
        if value is None:
            values.pop(name, None)
        else:
            values[name] = value
    return values


def load(**overrides: str) -> Settings:
    return Settings.load(environ=environment(**overrides), env_file=None)


# --- The Secret wrapper ------------------------------------------------------


def test_a_secret_is_absent_from_str_and_repr():
    secret = Secret("s3cret-value")
    assert str(secret) == REDACTED
    assert repr(secret) == f"Secret({REDACTED})"
    assert f"{secret}" == REDACTED
    assert "s3cret-value" not in f"{secret!r} {secret!s} {secret}"


def test_a_secret_reveals_its_value_only_when_asked():
    assert Secret("s3cret-value").reveal() == "s3cret-value"


def test_a_secret_is_absent_from_pydantic_serialization():
    credentials = ProviderCredentials(
        abusech_auth_key=Secret("abusech-value"),
        virustotal_auth_key=Secret("virustotal-value"),
    )
    dumped = credentials.model_dump()
    assert dumped == {
        "abusech_auth_key": REDACTED,
        "virustotal_auth_key": REDACTED,
    }
    assert json.loads(credentials.model_dump_json()) == dumped
    leaked = "abusech-value" in credentials.model_dump_json()
    assert not leaked


def test_a_secret_is_absent_from_the_settings_repr():
    settings = load()
    rendered = f"{settings!r} {settings.model_dump()} {settings.model_dump_json()}"
    leaked = [
        name
        for name, value in COMPLETE_ENVIRONMENT.items()
        if name.endswith(("TOKEN", "AUTH_KEY")) and value in rendered
    ]
    assert leaked == []


def test_a_bare_string_cannot_be_used_where_a_secret_is_expected():
    """A credential reaches a settings object through the wrapper or not at all."""
    with pytest.raises(ValidationError) as raised:
        ProviderCredentials(
            abusech_auth_key="abusech-value", virustotal_auth_key=Secret("v")
        )
    message = str(raised.value)
    assert "abusech_auth_key" in message
    leaked = "abusech-value" in message
    assert not leaked


# --- Resolution: agent-specific, then general, then fail ---------------------


def test_a_missing_per_agent_model_falls_back_to_the_general_one():
    settings = load()
    assert settings.triage.model == "model-general"
    assert settings.analyst.model == "model-general"
    assert settings.triage.source["LLM_MODEL"] == "LLM_MODEL"


def test_a_per_agent_override_wins_over_the_general_value():
    settings = load(LLM_MODEL_TRIAGE="model-triage", LLM_MODEL_ANALYST="model-analyst")
    assert settings.triage.model == "model-triage"
    assert settings.analyst.model == "model-analyst"
    assert settings.triage.source["LLM_MODEL"] == "LLM_MODEL_TRIAGE"


def test_one_agents_override_never_becomes_another_agents_model():
    """The expensive failure: a triage run that silently used the analyst model."""
    settings = load(LLM_MODEL_ANALYST="model-analyst")
    assert settings.analyst.model == "model-analyst"
    assert settings.triage.model == "model-general"


def test_the_endpoint_and_token_resolve_per_agent_the_same_way():
    settings = load(LLM_URL_ANALYST="http://analyst.invalid/v1")
    assert settings.analyst.endpoint_url == "http://analyst.invalid/v1"
    assert settings.triage.endpoint_url == COMPLETE_ENVIRONMENT["LLM_URL"]
    assert settings.analyst.token.reveal() == "token-general"


def test_a_missing_general_model_fails_naming_the_variable():
    with pytest.raises(ConfigurationError) as raised:
        load(LLM_MODEL=None)
    assert "LLM_MODEL" in str(raised.value)


def test_a_per_agent_override_does_not_satisfy_the_general_requirement():
    """Both agents resolve, but the error still names the variable to set."""
    with pytest.raises(ConfigurationError) as raised:
        load(LLM_MODEL=None, LLM_MODEL_TRIAGE="model-triage")
    assert "LLM_MODEL" in str(raised.value)


def test_a_missing_tenant_fails_naming_the_variable():
    with pytest.raises(ConfigurationError) as raised:
        load(HELENA_TENANT=None)
    message = str(raised.value)
    assert "HELENA_TENANT" in message
    assert "tenant-under-test" not in message


@pytest.mark.parametrize("variable", sorted(COMPLETE_ENVIRONMENT))
def test_every_general_variable_is_required(variable: str):
    with pytest.raises(ConfigurationError) as raised:
        load(**{variable: None})
    assert variable in str(raised.value)


@pytest.mark.parametrize("blank", BLANK, ids=repr)
def test_an_empty_or_whitespace_only_value_counts_as_missing(blank: str):
    with pytest.raises(ConfigurationError) as raised:
        load(HELENA_SENSOR=blank)
    assert "HELENA_SENSOR" in str(raised.value)


@pytest.mark.parametrize("blank", BLANK, ids=repr)
def test_a_blank_per_agent_override_falls_back_rather_than_failing(blank: str):
    settings = load(LLM_MODEL_TRIAGE=blank)
    assert settings.triage.model == "model-general"


def test_the_error_names_every_missing_variable_at_once():
    with pytest.raises(ConfigurationError) as raised:
        load(HELENA_TENANT=None, LLM_URL=None, RISINGWAVE_DSN=None)
    message = str(raised.value)
    assert all(
        name in message for name in ("HELENA_TENANT", "LLM_URL", "RISINGWAVE_DSN")
    )


def test_surrounding_whitespace_is_stripped_from_a_value():
    settings = load(HELENA_TENANT="  tenant-under-test\n")
    assert settings.identity.tenant == "tenant-under-test"


# --- No defaults -------------------------------------------------------------


def test_no_settings_field_has_a_default():
    """A field with a default is a silent configuration default by another name."""
    # `Settings` itself and the models it groups. A scalar field (`input_format`
    # names an adapter, it does not group anything) is checked on `Settings`.
    models = [
        Settings,
        *(
            field.annotation
            for field in Settings.model_fields.values()
            if isinstance(field.annotation, type)
            and issubclass(field.annotation, BaseModel)
        ),
    ]
    optional = {
        f"{model.__name__}.{name}"
        for model in models
        for name, field in model.model_fields.items()
        if not field.is_required()
    }
    assert optional == set()


def test_the_module_contains_no_endpoint_literal():
    """No built-in default endpoint — not even as an unused constant."""
    literals = [
        node.value
        for node in ast.walk(ast.parse(CONFIG_SOURCE.read_text()))
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    ]
    assert [literal for literal in literals if "://" in literal] == []


def test_loading_with_an_empty_environment_fails_rather_than_defaulting():
    with pytest.raises(ConfigurationError) as raised:
        Settings.load(environ={}, env_file=None)
    message = str(raised.value)
    assert all(name in message for name in COMPLETE_ENVIRONMENT)


# --- The example file --------------------------------------------------------


def _example_variables() -> list[str]:
    names = []
    for line in ENV_EXAMPLE.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name, separator, value = line.partition("=")
        assert separator == "=", f"{line!r} is not NAME=VALUE"
        assert value == "", f"{name} carries a value; the example ships every one empty"
        names.append(name)
    return names


def test_the_example_lists_exactly_the_loaders_variables():
    assert sorted(_example_variables()) == sorted(VARIABLES)


def test_the_example_lists_each_variable_once():
    names = _example_variables()
    assert len(names) == len(set(names))


def test_a_copied_but_unfilled_example_fails_naming_every_variable():
    """The reason blank counts as missing: this is the file operators copy."""
    with pytest.raises(ConfigurationError) as raised:
        Settings.load(environ={}, env_file=ENV_EXAMPLE)
    message = str(raised.value)
    assert all(name in message for name in COMPLETE_ENVIRONMENT)


def test_the_variable_set_covers_every_agent():
    for agent in AGENTS:
        assert f"LLM_MODEL_{agent.upper()}" in VARIABLES


# --- The real file -----------------------------------------------------------


@pytest.mark.skipif(
    not (PROJECT_ROOT / ".env").exists(), reason="no local .env on this machine"
)
def test_the_real_env_file_resolves_to_complete_settings():
    """The loader against the file an operator actually fills in.

    Asserts on shapes only. A value is never asserted on, printed or compared to
    a literal — the point is that resolution works, not what it resolved to.
    """
    settings = Settings.load(environ={}, env_file=PROJECT_ROOT / ".env")
    assert settings.identity.tenant
    assert settings.identity.sensor
    assert settings.triage.model and settings.analyst.model
    assert settings.triage.token.reveal()
    assert settings.providers.abusech_auth_key.reveal()

    rendered = f"{settings!r} {settings.model_dump_json()}"
    leaked = any(
        secret.reveal() in rendered
        for secret in (
            settings.triage.token,
            settings.analyst.token,
            settings.providers.abusech_auth_key,
            settings.providers.virustotal_auth_key,
        )
    )
    assert not leaked


@pytest.mark.skipif(
    not (PROJECT_ROOT / ".env").exists(), reason="no local .env on this machine"
)
def test_the_process_environment_wins_over_the_file():
    settings = Settings.load(
        environ={"HELENA_TENANT": "tenant-from-environ"},
        env_file=PROJECT_ROOT / ".env",
    )
    assert settings.identity.tenant == "tenant-from-environ"


@pytest.mark.skipif(
    not (PROJECT_ROOT / ".env").exists(), reason="no local .env on this machine"
)
def test_a_blank_process_variable_does_not_shadow_the_file():
    settings = Settings.load(
        environ={"HELENA_TENANT": "   "}, env_file=PROJECT_ROOT / ".env"
    )
    assert settings.identity.tenant.strip() == settings.identity.tenant
    assert settings.identity.tenant
