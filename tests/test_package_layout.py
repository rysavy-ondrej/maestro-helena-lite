"""The package skeleton: one module per architecture component, all labelled.

`concept/instruction.md` §5 requires a maturity label on anything added and
requires it to stay current; this test is what makes an unlabelled module a test
failure rather than a thing nobody notices.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PACKAGE_ROOT = PROJECT_ROOT / "src" / "helena"

# The components of concept/03-architecture.md. Enrichment views are not a module
# of their own: they are SQL.
#
# `disclosure` is the send-policy-and-disclosure-recording half of the note's
# "Provider tools (MCP)" row -- "credentials, send policy, budgets, disclosure
# recording, cache-first lookup" -- split out of `tools` for the reason `budgets`
# was split out of `orchestration`: `concept/03-architecture.md` makes hosted
# inference egress, so `helena.agents` records a disclosure too, and a ledger
# defined in `tools` would make the model client import the provider tool layer to
# find it. One ledger per run, charged by both, is `docs/decisions/0026`'s shape
# and `docs/decisions/0027-disclosure-and-the-send-policy.md` records this one.
#
# `budgets` is the note's "policy and budget guards" row, and it is a module
# because it could not be the one this comment used to name. Until task 36 the
# guards were "the deterministic code in `orchestration`", which is where
# concept/03 puts budget enforcement -- but the ledger has to be charged by
# `helena.agents` *and* by `helena.tools`, and `orchestration` is the module that
# will import both, so a ledger defined there is an import cycle. The policy half
# of that row stayed in `helena.policy` for its own reason (a frozen rule version
# needs a versioned package); `docs/decisions/0026-the-budget-guard.md` records
# both. `orchestration` keeps the rest of the row: routing, validation,
# persistence and replay.
#
# `providers` is the other half of the same row and is split out of `tools` for a
# reason that is machine-checked rather than aesthetic: `tests/test_tools.py`
# reads `tools.py`'s own AST and fails if it imports HTTP machinery or holds a
# `://` literal, which is what makes "the agent sees a tool, never an HTTP client
# and never a key" a property of the code. The adapter that speaks a provider's
# protocol has to hold both, so it cannot live there without deleting the
# property. `helena.tools.ProviderTool` takes it as one injected callable --
# `ask(call, credential) -> ProviderAnswer` --  and
# `docs/decisions/0028-the-threatfox-hunting-api.md` §10 records the decision.
COMPONENT_MODULES = {
    "normalizer",
    "context",
    "enrichment",
    "agents",
    "budgets",
    "disclosure",
    "tools",
    "providers",
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
# `untrusted` is here on the same terms and for a reason `concept/07` states
# directly: *Untrusted input* is a section of the principles rather than a stage
# of the pipeline, and every surface that shows a model a string uses it -- the
# two prompt versions, the rendering's escaper, the tool layer's serializer and
# the model client's retry feedback. Putting the frame in any one of them would
# make the other three import that one, and putting a copy in each is the second
# spelling of a delimiter that `helena.untrusted`'s docstring refuses. It is not a
# component because it is not a stage, and it is not a versioned package because
# what it holds is a mechanism rather than something an assessment records:
# `docs/decisions/0030-untrusted-text-isolation.md` records the one thing that
# costs -- a frozen `vN` prompt now imports a file that can be edited -- and the
# pin that pays for it.
# `network` is here for a reason that is machine-checked rather than aesthetic,
# and it is the mirror image of `providers`'. The tool layer's replay mode has to
# arm a guard that makes an outbound connection raise, and the guard has to
# import `socket` -- which `helena.tools` may not, because the AST test in
# `tests/test_tools.py` fails if it imports `urllib`, `http`, `socket` or `ssl`.
# `helena.providers` owns the protocol and would be the obvious home, and it
# cannot be one: it imports `helena.tools`. So the guard is a module holding one
# context manager, no URL and no client -- the opposite of a component. It is not
# named `replay`, because `concept/03-architecture.md` puts "replays from stored
# results" inside Orchestration and that runner does not exist yet; this is the
# guard, not the replay.
# `status` is here on the same terms as `observability`, and it is the other half
# of the same section: `concept/07-principles.md` gives Observability a section of
# the principles rather than a place in the pipeline, and says what belongs in
# each half -- *"local structured logs only, no hosted tracing"*, which is
# `observability`, and *"the audit record is the stored assessment ... queryable
# in a way a trace UI is not"* with the list of what must be observable, which is
# this. It reads every stage's counters and owns none of them, so it is a
# component of nothing.
#
# It is not folded into `observability` for a reason that is mechanical rather
# than aesthetic: the metrics have to read `helena.enrichment`'s feed statuses so
# that `missing`, `stale` and `ok` are not respelled, and `helena.enrichment`
# imports `helena.observability` for the redactor. One module would be an import
# cycle. `docs/decisions/0038-pipeline-metrics-and-reconciliation.md` §5 records
# it.
# `durability` is here on the same terms as `migrations`, and for a reason the
# concept notes give rather than one this file invents: `concept/08-open-questions.md`
# files durability and backup under *cross-cutting and urgent* -- "now that
# findings and evidence exist only there, which is a correctness concern rather
# than an ops detail". It is not a stage, and it is not one stage's property: the
# durable record is the retained captures plus every durable table, so a module
# living inside `normalizer` would own half of it and a module inside
# `orchestration` the other half. It reads `helena.migrations` for the schema
# identity a restore compares and `helena.normalizer` for the capture store, owns
# no relation of its own, and adds no store -- the bytes of a backup live in
# `scripts/backup.py`, so the package still writes to no file.
SUPPORT_MODULES = {
    "config",
    "durability",
    "observability",
    "status",
    "migrations",
    "versions",
    "broker",
    "untrusted",
    "network",
}

# Subpackages, and the only kind there is one of. A versioned package holds
# frozen version modules -- `v1.py`, `v2.py` -- rather than a component or a
# support module, because `docs/decisions/0008-version-registry.md` makes a
# revision "a new version module, never an edit": `v1` stays importable exactly
# as it was, so the modules accumulate and a flat package would fill with
# `taxonomy_v1`, `taxonomy_v2`, `schema_v1` and so on. ADR-0008 promises the same
# shape for agent output schemas, prompts and renderings, so this is a category
# rather than one exception.
#
# `taxonomy` is here rather than in COMPONENT_MODULES for the reason `versions`
# is in SUPPORT_MODULES: `concept/02-concepts-and-taxonomy.md` has both agents
# and the feed mapping views emitting classifications, so no single stage owns
# the vocabulary.
#
# Adding one is a deliberate edit here, exactly as adding a support module is.
# `contracts` is here for the same reason `taxonomy` is, and ADR-0008 named it in
# advance: "agent output schemas are the same [as the taxonomy]: historical
# versions are retained as frozen Pydantic classes, and replay validates against
# the recorded one." It is not in COMPONENT_MODULES because it is not a stage --
# `helena.agents` is the component `concept/03-architecture.md` names, and the
# request/result pair it exchanges is the thing that has to stay frozen once a
# row records a `schema_version`. A frozen class inside `agents.py` would be a
# version that could be edited every time the runner around it changed.
#
# `hosts` is the third, and it is versioned for the reason the other two are:
# `concept/04-the-two-agents.md` makes triage's host knowledge "a closed,
# **versioned** field set from fixed configuration only", and a rendering records
# which set produced it. A `v2` that adds or retires a field must leave `v1`
# meaning what it meant, so the field set is a frozen module and the loader,
# the configuration reader and the renderer are the machinery beside it.
#
# `rendering` is the fourth, and ADR-0008 named it in the same breath as the
# other two: "prompt and rendering versions follow the same shape: what triage
# saw is pinned by the recorded version, not reconstructed from current code."
# An assessment records `rendering_version`, so a `v2` that reorders a line or
# selects a different TLS parameter must leave `v1` meaning what it meant. It is
# not in COMPONENT_MODULES because `concept/03-architecture.md` puts rendering
# inside Orchestration -- "renders agent input" -- and the thing that has to stay
# frozen is the projection, not the code that calls it.
#
# `triage` is the fifth, and it is the other half of the sentence ADR-0008 uses
# of the rendering: "**prompt** and rendering versions follow the same shape".
# An assessment records `prompt_version`, so the words the model was shown and
# the result fields it was offered are frozen the moment a row records one, and a
# reworded instruction is a `v2` rather than an edit to what every historical row
# claims to have been asked. It is not in COMPONENT_MODULES for the reason
# `rendering` is not: `concept/03-architecture.md` puts routing on the triage
# result inside Orchestration, and what has to stay frozen is the prompt, not the
# code that sends it.
#
# `policy` is the sixth, and it is the dimension `helena.versions` left without
# an owner: every citable row records `policy_version`, and
# `concept/02-concepts-and-taxonomy.md` requires the composition rule to live as
# "explicit, testable policy rather than in the model's judgement". A stored
# assessment is entitled to have the rule that constrained it stay exactly as it
# was, so the rules are a frozen module and the read that assembles their input is
# the machinery beside them. It is not in COMPONENT_MODULES for the reason the
# comment at the head of this file gives: `concept/03-architecture.md` puts the
# policy guard inside Orchestration rather than making it a stage.
#
# `analyst` is the seventh, and it is `triage`'s counterpart for the same sentence
# of ADR-0008. An analyst assessment records a `prompt_version` too, and the
# analyst's prompt carries more that a later reader would want pinned than
# triage's does: the field set it was offered, the framing of the retrieved
# provider text, and which fields of a triage outcome were shown when the
# inheritance arm was on. All three are what the model was *asked*, so a reworded
# instruction is a `v2` beside `v1` and never an edit. It is not in
# COMPONENT_MODULES for the reason `triage` is not.
VERSIONED_PACKAGES = {
    "taxonomy",
    "contracts",
    "hosts",
    "rendering",
    "triage",
    "policy",
    "analyst",
}

# What a file inside a versioned package may be called. Anything else -- a
# helper, a shared base, a `common.py` -- is the thing that would let a later
# edit reach a frozen version, so it is refused rather than reviewed.
VERSION_MODULE = re.compile(r"^v[0-9]+$")

MATURITY_LABELS = ("stable", "experimental", "hypothesis", "deferred", "deprecated")


def _module_paths() -> list[Path]:
    return sorted(PACKAGE_ROOT.rglob("*.py"))


def _top_level_paths() -> list[Path]:
    return sorted(PACKAGE_ROOT.glob("*.py"))


def test_the_package_has_exactly_one_module_per_component():
    found = {path.stem for path in _top_level_paths()} - {"__init__"} - SUPPORT_MODULES
    assert found == COMPONENT_MODULES


def test_every_subpackage_is_a_declared_versioned_package():
    """A subpackage cannot appear unnoticed either.

    The component test above reads only the top level, so without this a new
    directory under `helena/` would be invisible to it -- which is how the
    package skeleton stops being a skeleton.
    """
    found = {
        path.parent.name
        for path in _module_paths()
        if path.parent != PACKAGE_ROOT
    }
    assert found == VERSIONED_PACKAGES


@pytest.mark.parametrize("package", sorted(VERSIONED_PACKAGES))
def test_a_versioned_package_holds_only_version_modules(package: str):
    """`__init__.py` and `vN.py`, and nothing else.

    A shared helper inside one of these is a file every frozen version imports,
    so editing it edits `v1` -- the in-place revision
    `docs/decisions/0008-version-registry.md` forbids, arriving through a side
    door. The machinery belongs in `__init__.py`, where the package docstring has
    to say what happens if a future version needs different machinery.
    """
    stems = sorted(
        path.stem for path in (PACKAGE_ROOT / package).glob("*.py")
    )
    offending = [
        stem for stem in stems
        if stem != "__init__" and not VERSION_MODULE.match(stem)
    ]
    assert offending == [], (
        f"helena/{package}/ holds {offending}, and a versioned package holds "
        f"only __init__.py and vN.py"
    )
    assert any(VERSION_MODULE.match(stem) for stem in stems), (
        f"helena/{package}/ holds no version module"
    )


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
