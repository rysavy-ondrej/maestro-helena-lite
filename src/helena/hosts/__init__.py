"""Hosts — the closed, versioned host attribute set, from fixed configuration only.

`concept/04-the-two-agents.md` gives the Triage Agent exactly one kind of host
knowledge: *"a closed, versioned field set from **fixed configuration only**"*,
rendered as part one of the five-part projection — *"the host — address and
device type, from a closed versioned attribute set sourced from fixed
configuration only. **When unknown it is rendered as unknown — never omitted,
never guessed.**"* And the reason, in the note's own words:

> Because the host attribute set comes from fixed configuration and nothing else,
> triage input stays **independent of any prior agent output** — which is what
> keeps assessments comparable across hosts and across time.

That independence is a structural property of this package, not a convention it
follows. **Nothing here imports anything else in `helena`**, so there is no code
path from an assessment, a proposal, an enrichment row or the store into a host
attribute — the package's whole input is a file path and an address, and
`tests/test_hosts.py` asserts that by reading the imports rather than by trusting
this paragraph.

## Why a versioned package

`docs/decisions/0008-version-registry.md`: *a revision is a new version module,
never an edit*. A rendering records which attribute set it was built from, and a
stored assessment that recorded `v1` has to keep meaning what it meant — so `v2`
arrives beside `v1` (a field added, a field retired) and `v1` stays importable
exactly as it was. The machinery is here; a version module holds only the closed
field set. If a future version ever needed different *machinery*, that would be a
change to this file and therefore a change to how `v1` behaves, which is the
thing the rule forbids; the field set would have to move into the version modules
and this would become a dispatcher. Recorded because it is the one way this
layout can go wrong — the same note `helena.taxonomy` carries.

## Closed means closed in both directions

A field the set does not declare is refused when the configuration file offers it
— a typo'd `devicetype` that was silently ignored would render as `unknown` and
look exactly like an unconfigured host. And a field the set *does* declare is
always rendered, with `UNKNOWN` where configuration is silent, because an omitted
key would make "this host's device type was never recorded" and "this host has no
device type" the same thing to an agent. That is `concept/instruction.md` §2's
*absence is not emptiness*, one layer up.

A host absent from the configuration file entirely is not an error and not an
empty rendering: it is every field `UNKNOWN` but the address. The alternative —
refusing to render — would make triage skip exactly the hosts nobody has
inventoried, which are not the ones worth skipping.

## What is deliberately not here

**No fallback source.** Not the store, not DNS, not a prior assessment, not an
inference from the traffic. `concept/04` is a closed list of two attributes and
the fields are what configuration supplies; a guessed device type is the *guess*
the note forbids by name, and it would be indistinguishable from a recorded one
afterwards.

**No rendering-version knowledge, and no contract import.** `render` returns the
body of the host section as text; the renderer (the increment that builds the
five-part projection) is what wraps it into a `helena.contracts.v1.RenderedSection`
and owns `rendering_version`. The attribute set carries its **own** version and
`render` writes it into the body, which is how "record its version on the
rendering" survives a rendering version being bumped for an unrelated reason.

Reads: one configuration file, `config/hosts.toml` by default. Writes: nothing.

Maturity: experimental — exercised by `tests/test_hosts.py`, including against a
migrated engine holding evidence about the very host being rendered. No agent has
been given a rendering built from it, and no operator has filled the file in for
a real fleet.
"""

from __future__ import annotations

import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType, ModuleType

__all__ = [
    "ADDRESS",
    "ATTRIBUTES_FILE",
    "UNKNOWN",
    "VERSION_LINE",
    "HostAttributeConfiguration",
    "HostAttributeSet",
    "HostAttributes",
    "HostAttributesError",
    "UnknownVersion",
    "load",
    "render",
    "version",
]

PROJECT_ROOT = Path(__file__).resolve().parents[3]

#: The fixed configuration. A path, not a value read from the environment: a
#: location is what `helena.migrations.MIGRATIONS_DIR` is, and a deployment that
#: keeps its inventory elsewhere passes the path to `load`. A missing file is a
#: loud failure naming it, never an empty fleet.
ATTRIBUTES_FILE = PROJECT_ROOT / "config" / "hosts.toml"

#: What an attribute configuration does not supply renders as. `concept/04`:
#: "when unknown it is rendered as unknown -- never omitted, never guessed".
#:
#: It is the same word as the taxonomy's `unknown` root and it is a different
#: fact: that one is a verdict about a context the analyst could not assess, this
#: one is a host attribute nobody recorded. They never appear in the same place
#: -- a verdict is a classification path in a result, this is a value in the host
#: section of a rendering -- and the note spells both the same way, so spelling
#: this one differently would be inventing a vocabulary the concept does not have.
UNKNOWN = "unknown"

#: The first line of a rendered host section: which attribute set produced it.
#: Written into the body because `helena.contracts.v1.RenderedSection` has no
#: field for it and is frozen -- and because the version belongs with the values
#: it explains, so a body pasted into a bug report still says what it is.
VERSION_LINE = "attribute_set_version"

#: The field every version is keyed by. Machinery rather than vocabulary: the
#: address is the host's identity in the store, in `helena_signal_host_context`
#: and in `AgentRequest.host`, so it is not a field a version may drop or rename
#: -- what a version chooses is the fields *beside* it.
ADDRESS = "address"

# A configured value is operator-supplied text that ends up in a model prompt,
# one line per field. Bounded and single-line for both reasons: a newline would
# let `device_type = "laptop\naddress: 10.0.0.1"` forge a second attribute line
# in the body, and an unbounded value is how the host section eats the budget the
# other four sections were sized against.
VALUE_LIMIT = 120


class HostAttributesError(Exception):
    """The attribute set, or the configuration offered for it, is not what it must be.

    One exception type with a stated reason, for the reason
    `helena.taxonomy.TaxonomyError` gives: every case is the same refusal to let
    a host attribute exist that configuration did not put there, and a caller
    catching four of these would be enumerating the ways it might be wrong.
    """


class UnknownVersion(HostAttributesError):
    """An attribute set version was asked for that this package does not hold.

    Distinct, and it means something different from a bad field: a rendering that
    recorded it cannot be reproduced against this tree, which is a replay
    failure rather than a configuration mistake.
    """


@dataclass(frozen=True)
class HostAttributeSet:
    """One version's closed field set: the shape every version module supplies.

    `fields` is ordered — it is the order a host section renders in, and two
    renderings of the same host must not differ by it. `ADDRESS` comes first
    because it is the identity the rest of the section is about.
    """

    version: str
    #: field name -> what the field means, for the operator filling the file in
    #: and for the error raised when they misspell one.
    fields: Mapping[str, str]

    def __post_init__(self) -> None:
        # The invariants a version module could get wrong, checked at import
        # rather than at the first render: a field set that disagrees with itself
        # should fail where it is written.
        names = list(self.fields)
        if not names or names[0] != ADDRESS:
            raise HostAttributesError(
                f"{self.version}: the fields are {names} and the first must be "
                f"{ADDRESS!r}; the address is the host's identity, not a field a "
                f"version may drop or reorder"
            )
        if VERSION_LINE in self.fields:
            raise HostAttributesError(
                f"{self.version}: a field is named {VERSION_LINE!r}, which is the "
                f"line a rendered section uses for the attribute set version; a "
                f"reader could not tell the two apart"
            )
        for name, meaning in self.fields.items():
            if not name.isidentifier() or name != name.lower():
                raise HostAttributesError(
                    f"{self.version}: {name!r} is not a field name; a field is a "
                    f"lower-case identifier, because it is a key in a TOML table "
                    f"and a label in a rendering"
                )
            if not meaning.strip():
                raise HostAttributesError(
                    f"{self.version}: {name!r} is declared with no meaning. A "
                    f"field an operator cannot be told the meaning of is a field "
                    f"they will fill in with something else."
                )

    @property
    def configured(self) -> tuple[str, ...]:
        """The fields a configuration file may supply — every one but the address.

        The address is the key of the host's table, so a table that also carried
        it would have two spellings of one fact and no rule for which wins.
        """
        return tuple(name for name in self.fields if name != ADDRESS)

    def _unknown_for(self, address: str) -> HostAttributes:
        """Every field `UNKNOWN`, for a host the configuration does not mention.

        Not an error, and not an empty section — see the package docstring.
        """
        return self._attributes(address, {})

    def _attributes(self, address: str, configured: Mapping[str, str]) -> HostAttributes:
        """One host's attributes: the configured values, `UNKNOWN` for the rest.

        **Private on purpose.** This is the only function in the package that
        turns a value into a host attribute, and it is reachable from `load` and
        from nowhere else — so the package's whole public surface takes a file
        path and an address, and there is no exported call an assessment, a
        proposal or an enrichment row could be handed to.
        `tests/test_hosts.py` asserts that nothing outside this package reaches
        it.

        Refuses a field the set does not declare, so a misspelling fails here
        rather than rendering as `unknown` and looking like an unconfigured host.
        """
        _check_address(address)
        if ADDRESS in configured:
            raise HostAttributesError(
                f"{address}: the table carries an {ADDRESS!r} field. The address "
                f"is the key of the host's table, never a value inside it — two "
                f"spellings of one fact with no rule for which wins."
            )
        offered = sorted(set(configured) - set(self.configured))
        if offered:
            raise HostAttributesError(
                f"{address}: {offered} is not in the {self.version} attribute "
                f"set, which supplies {list(self.configured)}. The set is closed "
                f"— a field it does not declare cannot be rendered, and silently "
                f"ignoring it would be indistinguishable from an unconfigured host."
            )
        values = {ADDRESS: address}
        for name in self.configured:
            value = configured.get(name)
            if value is None:
                values[name] = UNKNOWN
                continue
            _check_value(address, name, value)
            values[name] = value
        return HostAttributes(version=self.version, values=MappingProxyType(values))


@dataclass(frozen=True)
class HostAttributes:
    """One host's attribute values: every field of the set, and the set's version.

    Never a subset. `__post_init__` is what makes "never omitted" a property of
    the object rather than of the renderer, so a value that goes missing fails
    where it is built instead of rendering as a shorter section.
    """

    version: str
    #: field -> value, in the set's order, `UNKNOWN` where configuration was
    #: silent. Read-only: a mapping a caller could write to is a host attribute
    #: an agent's output could reach after all.
    values: Mapping[str, str]

    def __post_init__(self) -> None:
        declared = version(self.version).fields
        if list(self.values) != list(declared):
            raise HostAttributesError(
                f"the attributes are {list(self.values)} and {self.version} "
                f"declares {list(declared)}, in that order. An absent attribute "
                f"is rendered as {UNKNOWN!r}, never omitted."
            )
        if not isinstance(self.values, MappingProxyType):
            raise HostAttributesError(
                "the values must be read-only; build them with "
                "HostAttributeSet.attributes rather than by hand"
            )

    @property
    def address(self) -> str:
        return self.values[ADDRESS]


@dataclass(frozen=True)
class HostAttributeConfiguration:
    """One configuration file, read: the attribute set it declares and its hosts.

    Frozen and read once. There is no reload and no watch — *fixed* configuration
    is what `concept/04` says the source is, and a set of host attributes that
    changed under a running triage stage would make two assessments of the same
    host incomparable for a reason neither of them records.
    """

    path: Path
    attribute_set: HostAttributeSet
    #: address -> that host's attributes. Every host the file names; a host it
    #: does not name is not absent from `attributes_for`, only from here.
    hosts: Mapping[str, HostAttributes]

    @property
    def version(self) -> str:
        return self.attribute_set.version

    def attributes_for(self, address: str) -> HostAttributes:
        """This host's attributes — from this file, or every field `UNKNOWN`.

        The only way to obtain a `HostAttributes` for rendering, and it takes an
        address and nothing else. There is no overload taking an assessment, a
        proposal, an enrichment row or a connection, which is what makes
        `concept/04`'s independence checkable rather than aspirational.
        """
        _check_address(address)
        configured = self.hosts.get(address)
        if configured is not None:
            return configured
        return self.attribute_set._unknown_for(address)


def _check_address(address: str) -> None:
    if not isinstance(address, str):
        raise HostAttributesError(
            f"a host address is a string, not {type(address).__name__}"
        )
    if not address.strip() or address != address.strip():
        raise HostAttributesError(
            f"{address!r} is not a host address: it is blank or padded"
        )
    if len(address) > VALUE_LIMIT or not address.isprintable():
        raise HostAttributesError(
            f"{address!r} is not a host address: it is over {VALUE_LIMIT} "
            f"characters or carries a control character"
        )


def _check_value(address: str, field: str, value: str) -> None:
    if not isinstance(value, str):
        raise HostAttributesError(
            f"{address}.{field} is {type(value).__name__}; a host attribute is a "
            f"string, and a number or a list would render as its Python repr"
        )
    if not value.strip():
        raise HostAttributesError(
            f"{address}.{field} is blank. A field with nothing in it is "
            f"{UNKNOWN!r} — leave it out of the file and say so, rather than "
            f"recording an empty answer that reads as a recorded one."
        )
    if value == UNKNOWN:
        raise HostAttributesError(
            f"{address}.{field} is {UNKNOWN!r}, which is what an *unrecorded* "
            f"attribute renders as. Leave it out of the file: a configured "
            f"{UNKNOWN!r} and an absent one would be one value carrying two facts."
        )
    if not value.isprintable() or len(value) > VALUE_LIMIT:
        raise HostAttributesError(
            f"{address}.{field} is over {VALUE_LIMIT} characters or carries a "
            f"newline or control character. A host section is one line per "
            f"field, and a value with a newline in it forges a second line."
        )


def _load(identifier: str) -> HostAttributeSet:
    """The closed field set of one attribute set version.

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
            f"no host attribute set {identifier!r}. A rendering that recorded it "
            f"cannot be reproduced against this tree."
        ) from absent
    attributes = getattr(module, "ATTRIBUTES", None)
    if not isinstance(attributes, HostAttributeSet):
        raise UnknownVersion(
            f"{module.__name__} does not define a HostAttributeSet named ATTRIBUTES"
        )
    if attributes.version != identifier:
        raise UnknownVersion(
            f"{module.__name__} declares version {attributes.version!r}; a version "
            f"module and the version it declares must agree"
        )
    return attributes


#: Public name for the loader, so `version` reads as what a caller wants.
version = _load


def load(path: Path | str = ATTRIBUTES_FILE) -> HostAttributeConfiguration:
    """Read the fixed host attribute configuration, or fail naming what is wrong.

    TOML, so the file is `tomllib` and no dependency:

        version = "v1"

        [hosts."10.127.0.100"]
        device_type = "workstation"

    The file declares which attribute set it was written against, and this
    refuses a version this tree does not hold rather than reading the tables
    against the current set — a file written for a `v2` that renamed a field
    would otherwise load silently and render every host's value as `unknown`.
    """
    path = Path(path)
    try:
        raw = path.read_bytes()
    except FileNotFoundError as absent:
        raise HostAttributesError(
            f"no host attribute configuration at {path}. Triage's host knowledge "
            f"comes from fixed configuration and from nothing else, so an absent "
            f"file is a startup failure and never an empty fleet."
        ) from absent
    try:
        document = tomllib.loads(raw.decode())
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as malformed:
        raise HostAttributesError(f"{path} is not readable TOML: {malformed}") from malformed

    unexpected = sorted(set(document) - {"version", "hosts"})
    if unexpected:
        raise HostAttributesError(
            f"{path} has top-level keys {unexpected}; the file is a version and a "
            f"[hosts] table. A key nothing reads is a fact somebody recorded and "
            f"nothing renders."
        )
    declared = document.get("version")
    if not isinstance(declared, str) or not declared:
        raise HostAttributesError(
            f"{path} declares no attribute set version. A file that did not say "
            f"which set it was written against could not be checked against one."
        )
    attribute_set = _load(declared)

    hosts = document.get("hosts", {})
    if not isinstance(hosts, dict):
        raise HostAttributesError(
            f"{path}: [hosts] is {type(hosts).__name__}, and it is a table of "
            f"address -> attributes"
        )
    resolved: dict[str, HostAttributes] = {}
    for address, table in hosts.items():
        if not isinstance(table, dict):
            raise HostAttributesError(
                f"{path}: hosts.{address!r} is {type(table).__name__}; each host "
                f"is a table of the attributes configuration supplies for it"
            )
        resolved[address] = attribute_set._attributes(address, table)
    return HostAttributeConfiguration(
        path=path, attribute_set=attribute_set, hosts=MappingProxyType(resolved)
    )


def render(attributes: HostAttributes) -> str:
    """The body of the host section: the set's version, then every field.

    One line per field, in the set's order, `UNKNOWN` where configuration was
    silent. The caller wraps this in a `RenderedSection` — this package holds no
    contract version, so a contract `v2` does not reach back into the attribute
    set (see the package docstring).

    Nothing is dropped, so there is no `Truncation` to record: the section is a
    closed field set of bounded values and is the one part of the rendering whose
    size does not depend on what the host did.
    """
    if not isinstance(attributes, HostAttributes):
        raise HostAttributesError(
            f"render takes HostAttributes, not {type(attributes).__name__}. The "
            f"host section is built from configuration and from nothing else."
        )
    lines = [f"{VERSION_LINE}: {attributes.version}"]
    lines.extend(f"{field}: {value}" for field, value in attributes.values.items())
    return "\n".join(lines)
