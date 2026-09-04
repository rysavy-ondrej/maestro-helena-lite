"""The package skeleton: one module per architecture component, all labelled.

`concept/instruction.md` §5 requires a maturity label on anything added and
requires it to stay current; this test is what makes an unlabelled module a test
failure rather than a thing nobody notices.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PACKAGE_ROOT = PROJECT_ROOT / "src" / "helena"

# The components of concept/03-architecture.md. Enrichment views and the policy
# and budget guards are not modules of their own: the views are SQL, and the
# guards are the deterministic code in `orchestration`.
COMPONENT_MODULES = {
    "normalizer",
    "context",
    "enrichment",
    "agents",
    "tools",
    "orchestration",
    "sink",
}

# Not architecture components: cross-cutting modules every component uses.
# `config` is the fail-loud environment loader — `concept/03-architecture.md`
# lists the environment as an interface, not as a component, and configuration
# belongs to no single stage. `observability` is the local structured log and its
# redactor: `concept/07-principles.md` gives observability its own section rather
# than a place in the pipeline, and every component logs. Adding one here is a
# smaller decision than adding a component, but it is still a deliberate edit
# rather than a new file appearing unnoticed.
# `migrations` is here for the same kind of reason: `concept/03-architecture.md`
# makes the engine's view and model definitions project source, and applying
# them is not any one stage's job — the schema exists before any stage runs.
# `versions` is here on the same terms: `concept/07-principles.md` requires the
# version set on every citable row, so every stage stamps one and none of them
# owns it.
# `broker` is here on the same terms, and the reasoning is
# `concept/03-architecture.md`'s own: the broker is an *interface*, not a
# component — "ingest topic(s)" and "output topic" are two rows of the interface
# table, and the rule about them ("the broker is addressed only through the Kafka
# wire protocol ... that rule holds on both ends") is one rule over both ends
# rather than one for the Normalizer and another for the Sink. A Kafka client in
# each of those modules would be two places the rule can be broken;
# `tests/test_broker.py` asserts there is exactly one.
SUPPORT_MODULES = {
    "config",
    "observability",
    "migrations",
    "versions",
    "broker",
}

MATURITY_LABELS = ("stable", "experimental", "hypothesis", "deferred", "deprecated")


def _module_paths() -> list[Path]:
    return sorted(PACKAGE_ROOT.rglob("*.py"))


def test_the_package_has_exactly_one_module_per_component():
    found = {path.stem for path in _module_paths()} - {"__init__"} - SUPPORT_MODULES
    assert found == COMPONENT_MODULES


@pytest.mark.parametrize("path", _module_paths(), ids=lambda p: p.name)
def test_every_module_declares_a_maturity_label(path: Path):
    docstring = ast.get_docstring(ast.parse(path.read_text()))
    assert docstring, f"{path.name} has no docstring"
    labels = [
        label for label in MATURITY_LABELS if f"Maturity: {label}" in docstring
    ]
    assert len(labels) == 1, (
        f"{path.name} must declare exactly one 'Maturity: <label>' line, "
        f"found {labels}"
    )
