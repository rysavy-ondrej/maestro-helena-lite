"""What may be sent, and the record of what was.

Mirrors `src/helena/disclosure.py`. The sentences under test are
`concept/07-principles.md`'s:

> **Querying an external source discloses the indicator to that source.** Two
> separate obligations follow: **what may be sent to which source is governed
> policy**, and **what was disclosed is recorded on the assessment** — source,
> query, cache hit or live, disclosed-to, and when.

and `concept/03-architecture.md`'s: *"Inference in the prototype is hosted, so
prompts leave the monitored network and the disclosure rule applies to model calls
as much as to intelligence lookups."*

The enforcement half of this lives at the tool boundary and is tested there
(`tests/test_tools.py`), against a real engine and the real ThreatFox extract.
What is here is the policy the boundary reads, the record it writes, and the two
places the vocabulary could drift: the sendable fields against the outbound
request's own fields, and the loader against the source registry.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from helena import budgets, enrichment, policy, tools
from helena.contracts.v1 import (
    CONTRACT_VERSION,
    MAX_DETAIL,
    SCHEDULED_TRIAGE,
    SECTIONS,
    AgentRequest,
    Budgets,
    RenderedSection,
    Rendering,
    RequestVersions,
)
from helena.disclosure import (
    CHANNELS,
    MODEL_INFERENCE,
    PROVIDER_LOOKUP,
    SENDABLE_FIELDS,
    Disclosure,
    DisclosureError,
    Disclosures,
    SendPolicy,
    SourcePermission,
    digest,
    send_policy,
)
from helena.taxonomy import TRIAGE

PROJECT_ROOT = Path(__file__).resolve().parent.parent
NOW = datetime(2026, 9, 9, 12, 0, tzinfo=timezone.utc)
SOURCE = enrichment.THREATFOX_SOURCE


# --- Builders -----------------------------------------------------------------


def written(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "policy.toml"
    path.write_text(body)
    return path


def entry(**overrides: str) -> str:
    """One `[send_policy.threatfox]` table, as the file writes it."""
    fields = {
        "disclosed_to": '"threatfox-api.abuse.ch"',
        "entity_types": '["address", "domain", "url"]',
        "fields": '["entity_type", "entity_value"]',
        **overrides,
    }
    lines = "\n".join(f"{name} = {value}" for name, value in fields.items())
    return f'send_policy_version = "t1"\n\n[send_policy.{SOURCE}]\n{lines}\n'


def permission(**overrides: object) -> SourcePermission:
    return SourcePermission(
        **{
            "source_id": SOURCE,
            "disclosed_to": "provider.invalid",
            "entity_types": ("address", "domain", "url"),
            "fields": SENDABLE_FIELDS,
            "send_policy_version": "t1",
            **overrides,
        }
    )


def policy_holding(permit: SourcePermission, version: str = "t1") -> SendPolicy:
    return SendPolicy(version=version, by_source={permit.source_id: permit})


def request(**overrides: object) -> AgentRequest:
    return AgentRequest(
        **{
            "tenant": "acme",
            "sensor": "sensor-1",
            "emitter": TRIAGE,
            "host": "10.127.0.100",
            "window_start": NOW,
            "window_end": datetime(2026, 9, 9, 12, 5, tzinfo=timezone.utc),
            "context_id": "ctx-1",
            "context_version": "ctx-1/3",
            "trigger": SCHEDULED_TRIAGE,
            "rendering": Rendering(
                version="r1",
                sections=tuple(
                    RenderedSection(section=name, body=f"<{name}>", evidence_ids=())
                    for name in SECTIONS
                ),
            ),
            "budgets": Budgets(
                steps=0, tokens=8000, wall_clock_seconds=20.0, live_queries=0
            ),
            "versions": RequestVersions(
                prompt_version="p1",
                schema_version=CONTRACT_VERSION,
                rendering_version="r1",
                taxonomy_version="v1",
                enrichment_snapshot_version="2026-09-06T00:00:00Z",
                normalization_snapshot_version="psl-2026-09-06",
                policy_version="pol1",
                aggregation_version="agg1",
                model_requested="stub-model",
            ),
            **overrides,
        }
    )


def ledger(permit: SourcePermission | None = None, **overrides: object) -> Disclosures:
    return Disclosures.of(
        request(**overrides), policy=policy_holding(permit or permission())
    )


# --- The shipped policy, and the three loaders of one file --------------------


def test_the_projects_own_send_policy_permits_the_one_source_that_is_queried_live():
    """`config/policy.toml` is the file, and this is what it currently says.

    An entry means a source may be **queried live**, which is the condition
    `[rate_limits]` states of itself: `sslbl-ja3` is a feed the loader copies
    locally, a local join discloses nothing (`concept/03`), and an entry for it
    would permit a disclosure nothing makes.
    """
    permitted = send_policy()
    assert sorted(permitted.by_source) == [SOURCE]
    threatfox = permitted.permit(SOURCE)
    assert threatfox.disclosed_to == "threatfox-api.abuse.ch"
    assert set(threatfox.entity_types) == enrichment.source(SOURCE).entity_types
    assert threatfox.fields == SENDABLE_FIELDS
    assert threatfox.send_policy_version == permitted.version


def test_all_three_loaders_read_the_one_policy_file_without_refusing_each_others_keys():
    """Three tables of one file, and no loader refuses a key another requires.

    `helena.policy` owns the path and names all three key sets for exactly this
    reason; the failure it prevents is a loader added later rejecting the file the
    other two need.
    """
    assert send_policy(policy.POLICY_FILE).version
    assert budgets.load(policy.POLICY_FILE).by_emitter
    assert policy.thresholds(policy.POLICY_FILE).by_source
    assert (
        policy.DISCLOSURE_KEYS & (policy.THRESHOLD_KEYS | policy.BUDGET_KEYS)
    ) == frozenset()


def test_a_top_level_key_no_loader_reads_is_refused_by_this_one_too(tmp_path: Path):
    path = written(tmp_path, 'invented = "yes"\n' + entry())
    with pytest.raises(DisclosureError, match="nothing reads"):
        send_policy(path)


# --- The vocabulary cannot drift from the request it governs ------------------


def test_the_sendable_fields_are_exactly_the_outbound_requests_own_fields():
    """Two copies of a vocabulary, asserted equal (`concept/instruction.md` §2).

    `helena.tools.ToolCall` is the object the adapter is handed and the only thing
    the layer gives it to build a body from, so a field added to it must be
    declarable here before anything can populate it. If this fails, the new field
    is sendable and no policy has ever permitted it.
    """
    assert set(SENDABLE_FIELDS) == set(tools.ToolCall.model_fields)


def test_a_field_that_is_not_part_of_an_outbound_request_is_refused(tmp_path: Path):
    path = written(tmp_path, entry(fields='["entity_type", "tenant"]'))
    with pytest.raises(DisclosureError, match="tenant"):
        send_policy(path)


# --- The loader's coverage rules ----------------------------------------------


def test_a_send_policy_for_an_unregistered_source_is_refused(tmp_path: Path):
    """Adding a source is a governed decision, not a line in this file."""
    path = written(tmp_path, entry().replace(f"send_policy.{SOURCE}", "send_policy.acme"))
    with pytest.raises(DisclosureError, match="not a registered source"):
        send_policy(path)


def test_a_permission_wider_than_the_sources_capability_is_refused(tmp_path: Path):
    """A permission cannot exceed the capability it is a permission for.

    ThreatFox answers about addresses, names and URLs and not about fingerprints,
    so permitting a fingerprint to be disclosed to it is a line nothing reads.
    """
    path = written(tmp_path, entry(entity_types='["domain", "fingerprint"]'))
    with pytest.raises(DisclosureError, match="does not answer about"):
        send_policy(path)


def test_permitting_no_entity_type_is_refused_rather_than_permitting_nothing(
    tmp_path: Path,
):
    path = written(tmp_path, entry(entity_types="[]"))
    with pytest.raises(DisclosureError, match="permits no entity type"):
        send_policy(path)


@pytest.mark.parametrize(
    "host",
    [
        '"https://threatfox-api.abuse.ch/api/v1/"',
        '"threatfox-api.abuse.ch/api/v1/"',
        '"key@threatfox-api.abuse.ch"',
        '""',
    ],
)
def test_disclosed_to_is_a_bare_host_and_never_a_url(tmp_path: Path, host: str):
    """`concept/07`: a credential travelling in a URL is redacted before anything
    is logged or stored. A policy file that holds no URL cannot leak one, and the
    tool layer holds none either."""
    path = written(tmp_path, entry(disclosed_to=host))
    with pytest.raises(DisclosureError):
        send_policy(path)


@pytest.mark.parametrize("absent", ["disclosed_to", "entity_types", "fields"])
def test_every_key_of_an_entry_is_required(tmp_path: Path, absent: str):
    """There is no default for what may be sent — a defaulted one is a disclosure
    nobody decided to make."""
    lines = [
        line
        for line in entry().splitlines()
        if not line.startswith(f"{absent} =")
    ]
    with pytest.raises(DisclosureError, match=absent):
        send_policy(written(tmp_path, "\n".join(lines)))


def test_an_entry_key_nothing_reads_is_refused(tmp_path: Path):
    path = written(tmp_path, entry() + "\nrate = 4\n")
    with pytest.raises(DisclosureError, match="rate"):
        send_policy(path)


def test_a_file_with_no_version_is_refused(tmp_path: Path):
    """Every disclosure records which revision of the file permitted it."""
    path = written(tmp_path, entry().replace('send_policy_version = "t1"', ""))
    with pytest.raises(DisclosureError, match="send_policy_version"):
        send_policy(path)


def test_an_absent_file_is_a_startup_failure_and_never_a_permission(tmp_path: Path):
    with pytest.raises(DisclosureError, match="never a permission"):
        send_policy(tmp_path / "absent.toml")


def test_a_file_with_no_entries_permits_nothing(tmp_path: Path):
    """The whitelist's own answer, which is the safe direction."""
    permitted = send_policy(written(tmp_path, 'send_policy_version = "t1"\n'))
    with pytest.raises(DisclosureError, match="no send policy permits"):
        permitted.permit(SOURCE)


# --- The record ---------------------------------------------------------------


def test_a_provider_lookup_records_the_source_the_host_the_query_and_when():
    """`concept/07`'s own field list, minus the one the retrieval trace carries."""
    recorded = ledger()
    row = recorded.record_lookup(
        permit=permission(),
        entity_type="domain",
        entity_value="Evil.Example.",
        at=NOW,
    )
    assert row.channel == PROVIDER_LOOKUP
    assert row.source == SOURCE
    assert row.disclosed_to == "provider.invalid"
    # The literal spelling that was disclosed, not the normalized cache key: what
    # the provider was told is what it was told.
    assert row.query == "domain Evil.Example."
    assert row.query_digest == digest(b"Evil.Example.")
    assert row.disclosed_at == NOW
    assert row.send_policy_version == "t1"
    assert recorded.rows == (row,)


def test_a_model_call_records_the_model_the_host_and_the_shape_of_the_prompt():
    """`concept/03`: hosted inference is egress, on the same footing as a lookup."""
    recorded = ledger()
    row = recorded.record_model_call(
        model="model-under-test",
        disclosed_to="model.invalid:443",
        prompt=b'[{"role":"user","content":"the host contacted 10.0.0.1"}]',
        messages=2,
        at=NOW,
    )
    assert row.channel == MODEL_INFERENCE
    assert row.source == "model-under-test"
    assert row.disclosed_to == "model.invalid:443"
    assert row.query == "prompt of 2 message(s), 57 bytes, for context ctx-1"
    assert row.query_digest == digest(
        b'[{"role":"user","content":"the host contacted 10.0.0.1"}]'
    )


def test_the_prompt_itself_is_not_copied_into_the_record():
    """What it contains is the rendered context, which the request already carries
    under a recorded `rendering_version`. A second copy here would put internal
    addresses somewhere nothing else governs."""
    recorded = ledger()
    row = recorded.record_model_call(
        model="model-under-test",
        disclosed_to="model.invalid",
        prompt=b"the host 10.127.0.100 contacted brightmorningday.top",
        messages=1,
        at=NOW,
    )
    serialized = row.model_dump_json()
    assert "10.127.0.100" not in serialized
    assert "brightmorningday.top" not in serialized


def test_the_two_channels_are_counted_apart():
    recorded = ledger()
    recorded.record_lookup(
        permit=permission(), entity_type="domain", entity_value="a.invalid", at=NOW
    )
    recorded.record_model_call(
        model="m", disclosed_to="h", prompt=b"x", messages=1, at=NOW
    )
    assert len(recorded.to_channel(PROVIDER_LOOKUP)) == 1
    assert len(recorded.to_channel(MODEL_INFERENCE)) == 1
    assert [row.channel for row in recorded.rows] == list(CHANNELS)
    with pytest.raises(DisclosureError, match="not one of"):
        recorded.to_channel("email")


def test_the_ledger_records_the_run_it_is_the_record_of():
    asked = request()
    recorded = Disclosures.of(asked, policy=policy_holding(permission()))
    assert (recorded.tenant, recorded.sensor, recorded.context_id) == (
        asked.tenant,
        asked.sensor,
        asked.context_id,
    )
    assert recorded.emitter == asked.emitter


def test_a_ledger_with_a_blank_tenant_does_not_construct():
    """A defaulted tenant is an isolation failure that looks like it is working."""
    with pytest.raises(DisclosureError, match="tenant is blank"):
        Disclosures(
            tenant=" ",
            sensor="sensor-1",
            context_id="ctx-1",
            emitter=TRIAGE,
            policy=policy_holding(permission()),
        )


def test_recording_under_a_permission_the_policy_does_not_hold_is_refused():
    """Enforcement and recording read one policy, or the record means nothing.

    The case this catches is a tool built against one revision of
    `config/policy.toml` recording onto a ledger built from another.
    """
    recorded = ledger()
    with pytest.raises(DisclosureError, match="Enforcement and recording"):
        recorded.record_lookup(
            permit=permission(send_policy_version="t2"),
            entity_type="domain",
            entity_value="a.invalid",
            at=NOW,
        )


def test_recording_a_disclosure_the_permission_forbids_is_refused():
    """The boundary should have refused it; this is the second door on the same
    room, because a recorded disclosure the policy did not permit is either a leak
    or a bypass and both are worse than a stopped run."""
    permit = permission(entity_types=("address",))
    recorded = ledger(permit)
    with pytest.raises(DisclosureError, match="does not permit disclosing"):
        recorded.record_lookup(
            permit=permit, entity_type="domain", entity_value="a.invalid", at=NOW
        )


def test_a_lookup_recording_an_unregistered_source_is_refused():
    """Two vocabularies in one field is a record nobody can group by."""
    with pytest.raises(ValueError, match="not one of"):
        Disclosure(
            channel=PROVIDER_LOOKUP,
            source="not-a-source",
            disclosed_to="provider.invalid",
            query="domain a.invalid",
            query_digest=digest(b"a.invalid"),
            disclosed_at=NOW,
            send_policy_version="t1",
        )


def test_a_model_call_naming_a_registered_source_is_refused():
    with pytest.raises(ValueError, match="two"):
        Disclosure(
            channel=MODEL_INFERENCE,
            source=SOURCE,
            disclosed_to="model.invalid",
            query="prompt",
            query_digest=digest(b""),
            disclosed_at=NOW,
            send_policy_version="t1",
        )


@pytest.mark.parametrize(
    "override, message",
    [
        ({"channel": "carrier-pigeon"}, "channel"),
        ({"disclosed_to": " "}, "blank"),
        ({"query": " "}, "blank"),
        ({"query_digest": "abc"}, "SHA-256"),
        ({"disclosed_at": datetime(2026, 9, 9, 12, 0)}, "timezone"),
        ({"query": "x" * (MAX_DETAIL + 1)}, "limit"),
    ],
)
def test_a_record_that_records_nothing_useful_is_refused(
    override: dict[str, object], message: str
):
    fields = {
        "channel": MODEL_INFERENCE,
        "source": "model-under-test",
        "disclosed_to": "model.invalid",
        "query": "prompt of 1 message(s), 1 bytes, for context ctx-1",
        "query_digest": digest(b"x"),
        "disclosed_at": NOW,
        "send_policy_version": "t1",
        **override,
    }
    with pytest.raises(ValueError, match=message):
        Disclosure(**fields)


def test_a_query_longer_than_the_bound_is_truncated_rather_than_refused_by_the_ledger():
    """The bound is on the record; the ledger truncates rather than raising,
    because an over-long indicator is the model's doing and a refused *record*
    would lose the fact that something was sent."""
    long_value = "a" * (MAX_DETAIL + 100)
    row = ledger().record_lookup(
        permit=permission(), entity_type="domain", entity_value=long_value, at=NOW
    )
    assert len(row.query) == MAX_DETAIL
    # The digest is over what was sent, not over what the record could hold.
    assert row.query_digest == digest(long_value.encode())


def test_the_disclosure_module_holds_no_url_and_no_http_client():
    """The policy names hosts and this module reads them; neither speaks to one.

    The same assertion `tests/test_tools.py` makes of the tool layer, for the same
    reason: a module that cannot reach a provider cannot disclose to one by
    accident, so the record and the sending stay in different places.
    """
    source_text = (PROJECT_ROOT / "src" / "helena" / "disclosure.py").read_text()
    code = "\n".join(
        line for line in source_text.splitlines() if not line.strip().startswith("#")
    )
    for forbidden in ("urllib", "http.client", "requests", "socket"):
        assert f"import {forbidden}" not in code
