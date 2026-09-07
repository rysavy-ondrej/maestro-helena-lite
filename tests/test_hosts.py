"""The host attribute set: closed, versioned, and sourced from configuration alone.

`concept/04-the-two-agents.md` gives triage "a closed, versioned field set from
**fixed configuration only**", rendered so that "when unknown it is rendered as
unknown — never omitted, never guessed", and gives the reason: it is what keeps
triage input independent of any prior agent output, and therefore what keeps
assessments comparable across hosts and across time.

Three of those words are properties something can be made to fail, and each has
tests below: **closed** (a field the set does not declare is refused, and a field
it does declare is always rendered), **versioned** (the set says which version it
is and the rendering records it), and **fixed configuration only** — which is the
one that cannot be tested by writing a bad value, because it is about code paths
that must not exist. That one is tested three ways: by reading the package's
imports, by reading the rest of `src/helena` for anything that mints a host
attribute, and by putting a plausible device type for the host *into the store*
and rendering the host anyway.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path
from types import MappingProxyType

import psycopg
import pytest

from helena import hosts
from helena.contracts import v1 as contract
from helena.hosts import v1

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PACKAGE = PROJECT_ROOT / "src" / "helena" / "hosts"

# The host in `data/ingest/flow-sample.jsonl` — the 62 real flow records the
# ingest path is built against, and the one entry the committed configuration
# carries.
FIXTURE_HOST = "10.127.0.100"


def write(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "hosts.toml"
    path.write_text(body)
    return path


# --- The version module, and what a version is ------------------------------


def test_the_version_module_declares_the_version_it_is():
    assert v1.ATTRIBUTES.version == "v1"
    assert hosts.version("v1") is v1.ATTRIBUTES


def test_a_version_that_does_not_exist_is_its_own_error():
    """A rendering recording `v9` cannot be reproduced here; that is not a bad value."""
    with pytest.raises(hosts.UnknownVersion, match="no host attribute set 'v9'"):
        hosts.version("v9")


def test_a_version_identifier_is_a_module_name():
    with pytest.raises(hosts.UnknownVersion, match="not a version identifier"):
        hosts.version("../v1")


def test_the_set_is_the_two_fields_the_concept_note_names():
    """`concept/04`: "address and device type". Pinned, because the note is explicit.

    The set is closed, so an extra field is not a harmless addition: it renders as
    `unknown` on every host in every rendering until something populates it.
    """
    assert tuple(v1.ATTRIBUTES.fields) == ("address", "device_type")
    assert v1.ATTRIBUTES.configured == ("device_type",)


def test_a_field_set_that_is_not_keyed_by_the_address_is_refused():
    with pytest.raises(hosts.HostAttributesError, match="the address is the host's identity"):
        hosts.HostAttributeSet(version="v9", fields={"device_type": "what it is"})


def test_a_field_declared_with_no_meaning_is_refused():
    """An operator who is not told what a field means fills it in with something else."""
    with pytest.raises(hosts.HostAttributesError, match="declared with no meaning"):
        hosts.HostAttributeSet(
            version="v9", fields={"address": "the host", "device_type": "  "}
        )


def test_a_field_cannot_be_named_after_the_version_line():
    with pytest.raises(hosts.HostAttributesError, match="could not tell the two apart"):
        hosts.HostAttributeSet(
            version="v9",
            fields={"address": "the host", hosts.VERSION_LINE: "not a field"},
        )


# --- Closed, in both directions ---------------------------------------------


def test_an_absent_attribute_renders_as_unknown_and_is_never_omitted(tmp_path: Path):
    """`concept/04`: "never omitted, never guessed"."""
    path = write(tmp_path, 'version = "v1"\n\n[hosts."10.0.0.1"]\n')
    attributes = hosts.load(path).attributes_for("10.0.0.1")

    assert attributes.values["device_type"] == hosts.UNKNOWN
    assert hosts.render(attributes).splitlines() == [
        "attribute_set_version: v1",
        "address: 10.0.0.1",
        "device_type: unknown",
    ]


def test_a_host_the_configuration_does_not_mention_still_renders(tmp_path: Path):
    """Refusing would make triage skip exactly the hosts nobody has inventoried."""
    path = write(tmp_path, 'version = "v1"\n')
    attributes = hosts.load(path).attributes_for("192.0.2.7")

    assert attributes.address == "192.0.2.7"
    assert set(attributes.values) == set(v1.ATTRIBUTES.fields)
    assert attributes.values["device_type"] == hosts.UNKNOWN


def test_a_field_the_set_does_not_declare_is_refused(tmp_path: Path):
    """A typo silently ignored would render as `unknown` and look unconfigured."""
    path = write(
        tmp_path,
        'version = "v1"\n\n[hosts."10.0.0.1"]\ndevicetype = "workstation"\n',
    )
    with pytest.raises(hosts.HostAttributesError, match=r"\['devicetype'\] is not in the v1"):
        hosts.load(path)


def test_the_address_is_the_key_and_never_a_field_inside_the_table(tmp_path: Path):
    path = write(
        tmp_path,
        'version = "v1"\n\n[hosts."10.0.0.1"]\naddress = "10.0.0.2"\n',
    )
    with pytest.raises(hosts.HostAttributesError, match="never a value inside it"):
        hosts.load(path)


def test_the_word_unknown_cannot_be_configured(tmp_path: Path):
    """One value would otherwise carry two facts: unrecorded, and recorded as unknown."""
    path = write(
        tmp_path, 'version = "v1"\n\n[hosts."10.0.0.1"]\ndevice_type = "unknown"\n'
    )
    with pytest.raises(hosts.HostAttributesError, match="Leave it out of the file"):
        hosts.load(path)


def test_a_blank_attribute_is_refused(tmp_path: Path):
    path = write(tmp_path, 'version = "v1"\n\n[hosts."10.0.0.1"]\ndevice_type = "  "\n')
    with pytest.raises(hosts.HostAttributesError, match="is blank"):
        hosts.load(path)


def test_a_configured_value_cannot_forge_a_second_attribute_line(tmp_path: Path):
    """The body is one line per field, so a newline in a value is a forged field."""
    path = write(
        tmp_path,
        'version = "v1"\n\n[hosts."10.0.0.1"]\n'
        'device_type = "laptop\\naddress: 198.51.100.4"\n',
    )
    with pytest.raises(hosts.HostAttributesError, match="forges a second line"):
        hosts.load(path)


def test_an_attribute_that_is_not_a_string_is_refused(tmp_path: Path):
    """A number would render as its Python repr and read as a recorded value."""
    path = write(tmp_path, 'version = "v1"\n\n[hosts."10.0.0.1"]\ndevice_type = 7\n')
    with pytest.raises(hosts.HostAttributesError, match="a host attribute is a string"):
        hosts.load(path)


def test_attributes_cannot_be_built_short_of_the_set():
    """"Never omitted" is a property of the object, not of the renderer."""
    with pytest.raises(hosts.HostAttributesError, match="never omitted"):
        hosts.HostAttributes(
            version="v1", values=MappingProxyType({"address": "10.0.0.1"})
        )


def test_the_values_of_a_rendered_host_cannot_be_written_to(tmp_path: Path):
    """A mapping a caller could write to is a host attribute an agent could reach."""
    path = write(tmp_path, 'version = "v1"\n')
    attributes = hosts.load(path).attributes_for("10.0.0.1")
    with pytest.raises(TypeError):
        attributes.values["device_type"] = "server"  # type: ignore[index]


# --- The configuration file --------------------------------------------------


def test_a_missing_configuration_file_is_a_startup_failure_and_not_an_empty_fleet(
    tmp_path: Path,
):
    with pytest.raises(hosts.HostAttributesError, match="never an empty fleet"):
        hosts.load(tmp_path / "absent.toml")


def test_a_file_written_for_a_version_this_tree_does_not_hold_is_refused(tmp_path: Path):
    """Reading it against the current set would render every value as `unknown`."""
    path = write(tmp_path, 'version = "v9"\n\n[hosts."10.0.0.1"]\ndevice_type = "x"\n')
    with pytest.raises(hosts.UnknownVersion, match="no host attribute set 'v9'"):
        hosts.load(path)


def test_a_file_that_declares_no_version_is_refused(tmp_path: Path):
    path = write(tmp_path, '[hosts."10.0.0.1"]\ndevice_type = "x"\n')
    with pytest.raises(hosts.HostAttributesError, match="declares no attribute set version"):
        hosts.load(path)


def test_a_top_level_key_nothing_reads_is_refused(tmp_path: Path):
    """A key nothing renders is a fact somebody recorded and nobody will see."""
    path = write(tmp_path, 'version = "v1"\nowner = "someone"\n')
    with pytest.raises(hosts.HostAttributesError, match=r"top-level keys \['owner'\]"):
        hosts.load(path)


def test_a_file_that_is_not_toml_is_refused(tmp_path: Path):
    path = write(tmp_path, "version: v1\n")
    with pytest.raises(hosts.HostAttributesError, match="not readable TOML"):
        hosts.load(path)


def test_the_committed_configuration_loads_and_covers_the_ingest_fixture_host():
    """The default path is real, and the entry in it is the fixture's own host.

    Not a placeholder address: `data/ingest/flow-sample.jsonl` is one host and
    this is it, so the rendering path has a real address with a recorded
    attribute behind it.
    """
    configuration = hosts.load()

    assert configuration.path == hosts.ATTRIBUTES_FILE
    assert configuration.version == "v1"
    assert set(configuration.hosts) == {FIXTURE_HOST}
    assert configuration.attributes_for(FIXTURE_HOST).values["device_type"] != hosts.UNKNOWN


def test_the_configured_host_is_the_host_the_ingest_fixture_carries():
    """Read off the fixture rather than asserted twice — the two must not drift."""
    import json

    sources = {
        json.loads(line)["ip"]["src"]
        for line in (PROJECT_ROOT / "data" / "ingest" / "flow-sample.jsonl")
        .read_text()
        .splitlines()
        if line.strip()
    }
    assert sources == {FIXTURE_HOST}


# --- Fixed configuration ONLY ------------------------------------------------
#
# The property `concept/04` hangs triage's comparability on, and the one that
# cannot be checked by feeding something a bad value: what must not exist is a
# code path. Three tests, each closing a different route.

# What the package may import. Everything else -- the store driver, any other
# helena module -- would be a route from an assessment, a proposal or an
# enrichment row into a host attribute.
PERMITTED_IMPORTS = frozenset(
    {
        "__future__",
        "collections.abc",
        "dataclasses",
        "importlib",
        "pathlib",
        "tomllib",
        "types",
        "helena.hosts",
    }
)


def _imported_modules(path: Path) -> set[str]:
    module = ast.parse(path.read_text())
    imported: set[str] = set()
    for node in ast.walk(module):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            # Relative imports resolve inside this package by construction.
            imported.add(node.module if node.level == 0 else "helena.hosts")
    return imported


@pytest.mark.parametrize(
    "path", sorted(PACKAGE.glob("*.py")), ids=lambda p: p.name
)
def test_the_package_imports_nothing_that_could_reach_an_agent_or_the_store(path: Path):
    """Route one: the package itself.

    With no import of `helena.enrichment`, `helena.contracts`, `helena.context`
    or a database driver, there is no expression inside this package that could
    evaluate to an assessment, a proposal or an enrichment row. That is what
    makes "fixed configuration only" structural rather than a convention.
    """
    offending = sorted(_imported_modules(path) - PERMITTED_IMPORTS)
    assert offending == [], (
        f"{path.name} imports {offending}. Triage's host knowledge comes from "
        f"fixed configuration and nothing else; an import of the store, the "
        f"enrichment layer or the agent contract is the route by which a prior "
        f"agent output reaches a host attribute."
    )


def test_nothing_outside_the_package_mints_a_host_attribute():
    """Route two: the rest of the tree.

    `_attributes` is the one function that turns a value into a host attribute
    and it is private, so the package's public surface takes a **path and an
    address** and nothing else. This asserts nobody reached around it: the
    renderer that arrives next calls `load(...).attributes_for(address)`, which
    needs neither of these names.
    """
    minting = {"HostAttributes", "HostAttributeSet", "_attributes", "_unknown_for"}
    offending: list[str] = []
    for path in sorted((PROJECT_ROOT / "src" / "helena").rglob("*.py")):
        if path.parent == PACKAGE:
            continue
        module = ast.parse(path.read_text())
        for node in ast.walk(module):
            if isinstance(node, ast.alias) and node.name.split(".")[-1] in minting:
                offending.append(f"{path.name} imports {node.name}")
            elif isinstance(node, ast.Name) and node.id in minting:
                offending.append(f"{path.name}:{node.lineno} {node.id}")
            elif isinstance(node, ast.Attribute) and node.attr in minting:
                offending.append(f"{path.name}:{node.lineno} .{node.attr}")
    assert offending == [], (
        f"{offending} builds a host attribute outside helena/hosts/. A second "
        f"producer is a second source, and the point of the set is that there "
        f"is one."
    )


def test_the_public_surface_takes_a_path_and_an_address(tmp_path: Path):
    """Route three: the signatures. Nothing exported accepts an attribute value.

    Read off the objects rather than asserted in prose, so adding a parameter
    that took an assessment, a proposal or an enrichment row fails here.
    """
    reading = {
        "load": hosts.load,
        "version": hosts.version,
        "attributes_for": hosts.HostAttributeConfiguration.attributes_for,
        "render": hosts.render,
    }
    parameters = {
        name: [
            parameter.name
            for parameter in inspect.signature(function).parameters.values()
            if parameter.name != "self"
        ]
        for name, function in reading.items()
    }
    assert parameters == {
        "load": ["path"],
        "version": ["identifier"],
        "attributes_for": ["address"],
        "render": ["attributes"],
    }

    # And `render` refuses anything that is not a checked set of attributes, so a
    # row read out of the store cannot be handed to it as a mapping.
    with pytest.raises(hosts.HostAttributesError, match="from configuration and from nothing else"):
        hosts.render({"address": "10.0.0.1", "device_type": "server"})  # type: ignore[arg-type]


@pytest.mark.integration
def test_evidence_in_the_store_about_this_host_does_not_reach_its_attributes(
    migrated_engine: psycopg.Connection, tmp_path: Path
):
    """The behavioural half of the same property, against a real engine.

    The store is given a real enrichment claim about the very host being
    rendered, and its tags are `workstation` and `desktop` — ThreatFox tags are
    free-form publisher text, so a row whose tags read like a device type is a
    shape the real feed can produce. If anything ever wired the store into the
    attribute set, this is the row it would find.

    The assertion is deliberately general: **nothing the store says about this
    host appears in its rendering**, except the address, which is the key the
    rendering was requested for.
    """
    migrated_engine.execute(
        """
        INSERT INTO helena_reference_threatfox (
            tenant, sensor, snapshot_version, indicator_id, record_offset,
            ioc_type, ioc_value, entity_type, entity_value, port,
            threat_type, classification, taxonomy_version, threat_type_seen,
            confidence_level, is_compromised, first_seen, last_seen,
            tags, malware, malware_printable, reporter, reference
        ) VALUES (
            'acme', 'sensor-1', 'snapshot-1', '1000001', 0,
            'ip:port', %s, 'address', %s, 8000,
            'botnet_cc', 'malicious', 'v1', true,
            100, false, '2026-09-01T00:00:00Z', '2026-09-02T00:00:00Z',
            '["workstation", "desktop"]', 'win.example', 'Example', 'someone',
            'https://example.invalid/1'
        )
        """,
        (f"{FIXTURE_HOST}:8000", FIXTURE_HOST),
    )
    migrated_engine.execute("FLUSH")
    claims = migrated_engine.execute(
        "SELECT entity_value, classification, native_evidence "
        "FROM helena_reference_evidence WHERE entity_value = %s",
        (FIXTURE_HOST,),
    ).fetchall()
    assert len(claims) == 1, (
        "the store holds no claim about this host, so the test below would pass "
        "for the wrong reason"
    )

    path = write(tmp_path, 'version = "v1"\n')
    body = hosts.render(hosts.load(path).attributes_for(FIXTURE_HOST))

    assert body.splitlines()[-1] == f"device_type: {hosts.UNKNOWN}"
    for value in ("workstation", "desktop", "win.example", "Example", "malicious"):
        assert value not in body, f"{value!r} reached the host section from the store"


# --- The version, recorded on the rendering ----------------------------------


def test_the_rendering_records_the_attribute_set_version(tmp_path: Path):
    """`concept/04`: the rendering is versioned, so what triage saw is pinned.

    The version goes in the **body**, because `RenderedSection` is frozen and has
    no field for it — and because the attribute set's version is not the
    rendering's: a rendering version bumped for the TLS subset must not be read
    as a change to what the host section's fields mean.
    """
    path = write(tmp_path, f'version = "v1"\n\n[hosts."{FIXTURE_HOST}"]\ndevice_type = "kiosk"\n')
    attributes = hosts.load(path).attributes_for(FIXTURE_HOST)

    section = contract.RenderedSection(
        section=contract.HOST,
        body=hosts.render(attributes),
        # Empty on purpose: `concept/04` requires a stable evidence identifier on
        # every *enriched* value, and a configured attribute is not one. A
        # citation here would point at configuration as though a source had
        # claimed it.
        evidence_ids=(),
    )

    assert section.body.startswith(f"{hosts.VERSION_LINE}: v1")
    assert f"{hosts.VERSION_LINE}: {attributes.version}" in section.body
    assert section.evidence_ids == ()
    # The host section drops nothing, so there is nothing to record as dropped.
    assert section.truncation is None


def test_two_renderings_of_the_same_host_are_the_same_body(tmp_path: Path):
    """Comparability across time is the reason the set is fixed; order is part of it."""
    path = write(tmp_path, f'version = "v1"\n\n[hosts."{FIXTURE_HOST}"]\ndevice_type = "kiosk"\n')
    first = hosts.render(hosts.load(path).attributes_for(FIXTURE_HOST))
    second = hosts.render(hosts.load(path).attributes_for(FIXTURE_HOST))

    assert first == second
