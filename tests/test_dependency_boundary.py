"""The dependency boundary.

Two copies of the approved set would drift, so this test derives one from the
other: the distributions declared in `pyproject.toml` are the source of truth,
and every top-level import in `helena/` must resolve to one of them, to the
standard library, or to `helena` itself.

The rule this enforces is from `concept/06-technology.md`: current dependencies
are deliberately few — Pydantic, a dotenv loader, a Kafka client and a PostgreSQL
driver, with pytest for development — and *the model-client library is
deliberately absent until the first increment that actually calls a model*.
"""

from __future__ import annotations

import ast
import re
import sys
import tomllib
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PACKAGE_ROOT = PROJECT_ROOT / "src" / "helena"

# Distribution name -> the top-level module name it installs. A distribution that
# is not in this map is not approved, whatever `pyproject.toml` says: adding one
# is a recorded decision (docs/decisions/0002-dependency-set.md), not an edit.
APPROVED_RUNTIME_DISTRIBUTIONS = {
    "pydantic": "pydantic",
    "python-dotenv": "dotenv",
    "confluent-kafka": "confluent_kafka",
    "psycopg": "psycopg",
}

APPROVED_DEV_DISTRIBUTIONS = {"pytest": "pytest"}

# Absent by decision, not by accident. The model client enters in the increment
# that first *calls* a model, not the one that first mentions one.
DELIBERATELY_ABSENT = (
    "langchain",
    "langchain_core",
    "langchain_openai",
    "langgraph",
    "openai",
    "anthropic",
    "requests",
    "httpx",
    "sqlalchemy",
    "kafka",  # kafka-python: a second Kafka client is still a new dependency
)

# Hosted tracing and telemetry SDKs. Absent for a different reason from the
# above: not "not yet", but "not at all". `concept/06-technology.md` and
# `concept/07-principles.md` both settle it — observability is **local
# structured logs only**, because a hosted tracer is a second egress channel
# carrying prompts, rendered context and retrieved provider text, and it would
# need its own send policy, its own disclosure record and a second vendor's
# data-handling terms. `concept/instruction.md` §3 makes adding one an
# escalation, not an edit. `helena.observability` is what exists instead.
#
# Distribution name -> the top-level module it installs.
HOSTED_TELEMETRY_DISTRIBUTIONS = {
    "langsmith": "langsmith",
    "langfuse": "langfuse",
    "opentelemetry-sdk": "opentelemetry",
    "opentelemetry-api": "opentelemetry",
    "sentry-sdk": "sentry_sdk",
    "ddtrace": "ddtrace",
    "datadog": "datadog",
    "newrelic": "newrelic",
    "elastic-apm": "elasticapm",
    "logfire": "logfire",
    "libhoney": "libhoney",
    "openinference-instrumentation": "openinference",
    "arize-phoenix": "phoenix",
    "braintrust": "braintrust",
    "wandb": "wandb",
    "mlflow": "mlflow",
    "helicone": "helicone",
}

_REQUIREMENT_NAME = re.compile(r"^[A-Za-z0-9._-]+")


def _declared(key: str, table: dict) -> set[str]:
    return {
        _REQUIREMENT_NAME.match(requirement).group(0).lower().replace("_", "-")
        for requirement in table.get(key, [])
    }


def _pyproject() -> dict:
    return tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text())


def _package_modules() -> list[Path]:
    return sorted(PACKAGE_ROOT.rglob("*.py"))


def _top_level_imports(source: Path) -> set[str]:
    """Top-level module names imported absolutely by one file.

    Relative imports (`from . import x`) carry no top-level name and are skipped.
    """
    imported: set[str] = set()
    for node in ast.walk(ast.parse(source.read_text(), filename=str(source))):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            imported.add(node.module.split(".")[0])
    return imported


def test_declared_runtime_dependencies_are_exactly_the_approved_set():
    declared = _declared("dependencies", _pyproject()["project"])
    assert declared == set(APPROVED_RUNTIME_DISTRIBUTIONS), (
        "pyproject.toml declares a runtime dependency set that does not match the "
        "approved one. Adding a dependency is an escalation, not an edit: record "
        "the decision in docs/decisions/ and update APPROVED_RUNTIME_DISTRIBUTIONS."
    )


def test_declared_dev_dependencies_are_exactly_the_approved_set():
    declared = _declared("dev", _pyproject()["dependency-groups"])
    assert declared == set(APPROVED_DEV_DISTRIBUTIONS), (
        "The dev dependency group does not match the approved one. Lint and "
        "typecheck tooling is pending a decision — see "
        "docs/decisions/0003-lint-and-typecheck-tooling.md."
    )


def test_package_imports_nothing_unapproved():
    approved = (
        set(APPROVED_RUNTIME_DISTRIBUTIONS.values())
        | set(sys.stdlib_module_names)
        | {"helena"}
    )
    offenders: dict[str, set[str]] = {}
    for module in _package_modules():
        unapproved = _top_level_imports(module) - approved
        if unapproved:
            offenders[str(module.relative_to(PROJECT_ROOT))] = unapproved
    assert not offenders, f"unapproved top-level imports in the package: {offenders}"


def test_the_model_client_is_still_absent():
    """The absence is enforced, so that it stays a decision and not an oversight."""
    declared = _declared("dependencies", _pyproject()["project"]) | _declared(
        "dev", _pyproject()["dependency-groups"]
    )
    for name in DELIBERATELY_ABSENT:
        assert name.replace("_", "-") not in declared, (
            f"{name} is declared but is deliberately absent by decision"
        )

    imported: set[str] = set()
    for module in _package_modules():
        imported |= _top_level_imports(module)
    assert not imported.intersection(DELIBERATELY_ABSENT), (
        f"the package imports a deliberately absent module: "
        f"{sorted(imported.intersection(DELIBERATELY_ABSENT))}"
    )


def test_no_hosted_tracing_sdk_is_declared_or_imported():
    """The second egress channel stays impossible, not merely unbuilt."""
    declared = _declared("dependencies", _pyproject()["project"]) | _declared(
        "dev", _pyproject()["dependency-groups"]
    )
    assert not declared.intersection(HOSTED_TELEMETRY_DISTRIBUTIONS), (
        "a hosted tracing or telemetry SDK is declared. Observability is local "
        "structured logs only (helena.observability); adding a tracer is an "
        "escalation — see docs/decisions/0005-structured-logging-and-redaction.md."
    )

    imported: set[str] = set()
    for module in _package_modules():
        imported |= _top_level_imports(module)
    assert not imported.intersection(HOSTED_TELEMETRY_DISTRIBUTIONS.values()), (
        f"the package imports a hosted telemetry SDK: "
        f"{sorted(imported.intersection(HOSTED_TELEMETRY_DISTRIBUTIONS.values()))}"
    )


def test_no_hosted_tracing_sdk_is_even_importable_from_the_environment():
    """Not declared is not enough: a transitive install would still be reachable.

    `import langsmith` succeeding anywhere in this environment means one `import`
    line in one module is all that separates prompts and retrieved provider text
    from a vendor's servers. This asserts the module does not resolve at all.
    """
    import importlib.util

    resolvable = sorted(
        {
            module_name
            for module_name in HOSTED_TELEMETRY_DISTRIBUTIONS.values()
            if importlib.util.find_spec(module_name) is not None
        }
    )
    assert not resolvable, (
        f"a hosted telemetry SDK is installed in the environment: {resolvable}. "
        "It arrived as a transitive dependency of something approved; find which, "
        "and record the decision before leaving it there."
    )


def test_the_approved_runtime_distributions_are_actually_importable():
    """The lockfile is the contract; this is the environment honouring it."""
    import importlib

    for distribution, module_name in APPROVED_RUNTIME_DISTRIBUTIONS.items():
        assert importlib.import_module(module_name), distribution
