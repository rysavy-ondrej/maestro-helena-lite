"""Contracts — the versioned agent request/result pair, frozen one version at a time.

`concept/04-the-two-agents.md`, "One contract for both": *one versioned typed
request / result pair covers every agent. Agents never exchange free-form
natural-language messages, and nothing crosses an agent boundary except validated
typed fields.* The two agents differ by **model**, not by framework and not by
schema, so there is one request class and one result class and no per-agent
subclass — the asymmetry between Triage and Analyst is enforced as **rules on the
one contract**, not as a second shape.

This package holds the **machinery**; a version module holds the **contract**.
`v1.py` is the first, and `helena.contracts.v1` is what a caller imports.

## Why a version is a module, and why nothing here may be edited later

`docs/decisions/0008-version-registry.md` promises this shape in as many words:
*agent output schemas are the same [as the taxonomy]: historical versions are
retained as frozen Pydantic classes, and replay validates against the recorded
one. A migration that reshapes a stored field is rejected outright.*

So **a revision is `v2` beside `v1`, never an edit to `v1`.** A stored assessment
records `schema_version`, and replay validates it against the module that version
names — against the classes that ran, not against current code. Editing `v1` in
place would silently change what every historical assessment claims to have been
validated as, which is the one failure the version registry exists to prevent.
Adding anything to the agent contract is an escalation, not an increment
(`concept/instruction.md` §3).

**What that costs, said out loud:** the constants a version validates against —
the triggers, the section names, the gap kinds, the stances, the failure reasons
— live in the version module and **not here**, because a constant in this file is
one every frozen version imports, and editing it would edit `v1` through a side
door. `tests/test_package_layout.py` refuses any file in this package that is not
`__init__.py` or `vN.py` for the same reason.

The unavoidable exceptions are the shapes `v1` imports from the rest of the
package — `helena.versions.VersionSet`, `helena.taxonomy`'s syntax and
`helena.enrichment.QueryFailure` — and they are named in
`docs/decisions/0017-the-agent-contract.md` as frozen by reference: changing one
of them changes what `v1` validates. Re-implementing them inside `v1` was the
alternative, and it would be a second spelling of the typed failure and of the
taxonomy per contract version, which is worse.

## What is here

`version("v1")` returns a `ContractVersion` — the three classes that version
holds, addressed by name so that replay can do

    contracts.version(row["schema_version"]).result.model_validate_json(stored)

without importing a version module directly and without a registry dict, which
would be a second place a version has to be listed and the one that gets
forgotten. It is the same loader `helena.taxonomy` uses, for the same reason.

Reads: nothing. Writes: nothing.

Maturity: experimental — exercised by `tests/test_contracts.py`. The classes have
carried nothing: no model has been called, no assessment has been stored or
emitted, and no result has been replayed against a recorded `schema_version`. What
is demonstrated is that the shapes refuse what `concept/04` and
`concept/07-principles.md` say they must refuse, not that they fit a real model's
output.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import ModuleType

from pydantic import BaseModel

__all__ = [
    "ContractError",
    "ContractVersion",
    "UnknownVersion",
    "version",
]


class ContractError(Exception):
    """An object, or a pair of them, is not what the agent contract says one is.

    One exception type with a stated reason, for the reason
    `helena.taxonomy.TaxonomyError` gives: every case is the same refusal to let
    something cross the agent boundary, and a caller enumerating four of these
    would be listing the ways it might be wrong instead of not being wrong.

    A field that is malformed on its own raises Pydantic's `ValidationError`; this
    is for the rules that hold **between** fields or **between** a request and its
    outcome, which is where the concept's asymmetries live.
    """


class UnknownVersion(ContractError):
    """A contract version was asked for that this package does not hold.

    Distinct from an invalid field, and it means something quite different: a
    stored assessment recorded a `schema_version` whose module is not here, which
    is a replay that cannot be validated rather than a value that is wrong.
    """


@dataclass(frozen=True)
class ContractVersion:
    """One version's three classes: the shape every version module supplies.

    `request` is what deterministic code hands an agent, `result` is a verdict and
    `failure` is a run that produced none. There is no fourth: `concept/07` makes
    a typed failure and a verdict the two terminal outcomes and refuses to
    collapse them, so a version module that offered one object covering both would
    be making the denominator *successes* rather than *contexts*.
    """

    version: str
    request: type[BaseModel]
    result: type[BaseModel]
    failure: type[BaseModel]


def _load(identifier: str) -> ContractVersion:
    """The three frozen classes of one contract version.

    Imported by name rather than held in a registry dict, so adding `v2` is
    adding a module and nothing else.
    """
    from importlib import import_module  # noqa: PLC0415 — one call, at the edge

    if not identifier.isidentifier():
        raise UnknownVersion(
            f"{identifier!r} is not a version identifier; versions are module "
            f"names like 'v1'"
        )
    try:
        module: ModuleType = import_module(f"{__name__}.{identifier}")
    except ModuleNotFoundError as absent:
        raise UnknownVersion(
            f"no contract version {identifier!r}. A stored assessment that "
            f"recorded it cannot be validated against this tree."
        ) from absent
    contract = getattr(module, "CONTRACT", None)
    if not isinstance(contract, ContractVersion):
        raise UnknownVersion(
            f"{module.__name__} does not define a ContractVersion named CONTRACT"
        )
    if contract.version != identifier:
        raise UnknownVersion(
            f"{module.__name__} declares version {contract.version!r}; a version "
            f"module and the version it declares must agree"
        )
    return contract


#: Public name for the loader, so `version` reads as what a caller wants.
version = _load
