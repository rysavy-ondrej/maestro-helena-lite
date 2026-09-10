"""Disclosure — what may leave, and the record of what did.

`concept/07-principles.md`, "Privacy and disclosure":

> **Querying an external source discloses the indicator to that source.** Two
> separate obligations follow: **what may be sent to which source is governed
> policy**, and **what was disclosed is recorded on the assessment** — source,
> query, cache hit or live, disclosed-to, and when.

Two obligations, two halves of this module. `SendPolicy` is the first: a per-source
declaration of which entity types and which fields may be sent, loaded from the
same versioned policy file the thresholds and the budgets come from. `Disclosures`
is the second: one ledger per agent run, holding one `Disclosure` per outbound
call.

## Both channels, on one footing

`concept/03-architecture.md` is explicit that a local pipeline is not zero egress:
*"Inference in the prototype is hosted, so prompts leave the monitored network and
the disclosure rule applies to model calls as much as to intelligence lookups."*
So the ledger has two producers and they record through the same object:

| Channel | Who records it | What leaves |
| --- | --- | --- |
| `provider_lookup` | `helena.tools.ProviderTool.lookup`, before the adapter is called | the indicator the analyst asked about |
| `model_inference` | `helena.agents.assess`, before each attempt | the rendered context, as the prompt |

That is the same shape `helena.budgets.RunBudget` has and it is the same reason:
one object per run, charged by everything in the run, so the run's total is a fact
rather than a sum somebody has to remember to compute. A second ledger in either
module would be two copies of one fact (`concept/instruction.md` §2).

## A cache hit records nothing, and that is the point

`concept/07`: *"A cache hit discloses nothing. The indicator was already disclosed
when the entry was fetched."* So a hit adds no row — caching is a privacy control,
and a ledger that recorded a hit as a disclosure would say the run told a provider
something it did not.

**Where "cache hit or live" is recorded** is therefore
`helena.contracts.v1.RetrievalStep.outcome`, on the same assessment, one step per
record served; `docs/decisions/0017-the-agent-contract.md` already said the
disclosure record would be derived from it. The two reconcile by construction and
`tests/test_tools.py` asserts it: **the number of provider disclosures in a run
equals `RunBudget.live_queries_spent`**, and `RunBudget.cache_hits` is how many
calls disclosed nothing. The one call that appears in both is the stale fallback —
it reached the provider, which disclosed, and then served stored rows.

## Refusing rather than trimming

The policy is a whitelist and the tool layer applies it *before any request
leaves*. What it does when a call does not fit is refuse it, typed and countable
(`helena.tools.SEND_POLICY_FORBIDS`), and never send an altered one: a query with
the forbidden part removed is a query the deployment did not authorise and an
answer to a question nobody asked. Two things can fail:

- the **entity type** is not one this source may be told about, which is not the
  same refusal as `entity_type_not_covered`: that one is the source's capability
  (a JA3 list has nothing to say about a domain) and this one is the deployment's
  permission. A source that could answer and may not be asked is a different fact
  from a source that cannot answer;
- a **field** of the outbound request is not permitted, so the request cannot be
  assembled at all. `SENDABLE_FIELDS` is the vocabulary and it is exactly the
  field set of `helena.tools.ToolCall` — the object that reaches the adapter —
  which is what makes "a policy-forbidden field cannot reach a request body" a
  property of the code rather than of an adapter's discipline. A field added to
  that object later has to be declared here and permitted in the file before
  anything can populate it.

The check runs **before the cache is read**, not after. A permission that has been
revoked stops the source being consulted at all: nothing here evicts, so the
stored records are still there and a re-permitted source finds them again, but a
run must not keep answering from a cache filled while the permission was in force.

## What is not here

- **No `disclosure` table.** `concept/02` and `concept/07` put the record *on the
  assessment*, and no assessment is stored yet (`prds/prd.json` task 43). This is
  the standing `helena.budgets.RunBudget` has for `Cost`, deliberately: a table
  here would be a second home for a fact the assessment is going to carry.
- **Nothing governs the model channel per field.** What of a context reaches a
  prompt is the rendering's decision, recorded as `rendering_version` on every
  request, and a second field list here would be a second opinion about it. What
  this module adds for that channel is the *record*: which host, when, over what,
  and under which send policy.
- **No verification that an adapter honours `disclosed_to`.** The host is the one
  the deployment approved for a source and is what the record names; the adapter
  is the code that has to speak to it, and `helena.tools` holds no URL at all
  (asserted off its own AST) so the layer could not check the request even in
  principle.

Reads: `config/policy.toml` and `helena.enrichment.SOURCES`. Writes: nothing.

Maturity: experimental — the loader, the ledger and both channels are exercised by
`tests/test_disclosure.py`, the tool-boundary enforcement by `tests/test_tools.py`
against a real migrated engine and the real ThreatFox extract, and the model
channel by `tests/test_agents.py` against a scripted endpoint and the configured
one. **No live provider has been queried through the layer** (task 38), and
nothing stores a ledger yet (task 43), so "recorded on the assessment" is a ready
shape and not a property that holds.
"""

from __future__ import annotations

import hashlib
import tomllib
from datetime import datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from helena.contracts import v1 as contract
from helena.policy import (
    BUDGET_KEYS,
    DISCLOSURE_KEYS,
    POLICY_FILE,
    PRICE_KEYS,
    THRESHOLD_KEYS,
)

__all__ = [
    "CHANNELS",
    "DISCLOSURE_KEYS",
    "MODEL_INFERENCE",
    "POLICY_FILE",
    "PROVIDER_LOOKUP",
    "SENDABLE_FIELDS",
    "Disclosure",
    "DisclosureError",
    "Disclosures",
    "SendPolicy",
    "SourcePermission",
    "digest",
    "send_policy",
]

#: The two ways this pipeline tells an outside party something. `concept/07`'s
#: disclosure table has four rows; the other two are not this module's. Static
#: enrichment discloses **nothing** — every prototype enrichment lookup is a local
#: join — and the output topic is a local broker whose consumers inherit the
#: obligation, which is a property of a deployment rather than of a call this code
#: makes.
PROVIDER_LOOKUP = "provider_lookup"
MODEL_INFERENCE = "model_inference"
CHANNELS = (PROVIDER_LOOKUP, MODEL_INFERENCE)

#: Which fields of an outbound provider request a send policy may permit. It is
#: the field set of `helena.tools.ToolCall` — the object the adapter is handed and
#: the only thing this layer gives it to build a body from — spelled here because
#: `helena.tools` imports this module and not the other way round.
#: `tests/test_disclosure.py` asserts the two are the same set, which is what
#: keeps a field added to the request from being sendable before it is declared.
SENDABLE_FIELDS = ("entity_type", "entity_value")


class DisclosureError(RuntimeError):
    """The send policy or the ledger was misconfigured or misused.

    Never a model's fault and never a provider's. A call the policy forbids is not
    an error at all — it is a typed `helena.tools.ToolRefusal` the agent can read,
    because refusing is the normal working of a whitelist.
    """


def digest(payload: bytes) -> str:
    """A digest of exactly what left, so a record can be checked without a copy.

    The same construction `helena.tools.response_version` uses on the way back:
    what was disclosed is a fact an audit has to be able to verify, and copying
    the prompt into a second place would put the rendered context — internal
    addresses, hostnames, retrieved text — somewhere the rendering already is.
    """
    return hashlib.sha256(payload).hexdigest()


class SourcePermission(BaseModel):
    """What one source may be told, and where it lives. Frozen, and never a default.

    `concept/08-open-questions.md` lists *"which sources are approved for
    analyst-time querying and what may be sent to each"* as open; this is the shape
    the answer is written in, and `config/policy.toml` carries the argument for the
    values that are in it.
    """

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    source_id: str
    #: The host this source's requests go to — what the record names as
    #: disclosed-to. A **host**, never a URL: `concept/07` requires a credential
    #: travelling in a URL to be redacted before anything is logged or stored, and
    #: the safest version of that rule is that no URL is in the policy at all.
    disclosed_to: str
    #: Which kinds of indicator this deployment permits being disclosed to this
    #: source. A subset of what the source *covers*: permission cannot exceed
    #: capability, and a permission to send something the source cannot answer
    #: about would be a line nothing reads.
    entity_types: tuple[str, ...]
    #: Which fields of the outbound request may be populated, from
    #: `SENDABLE_FIELDS`. A call needing anything else is refused, never trimmed.
    fields: tuple[str, ...]
    #: The version of the file these came out of, carried so the tool that
    #: enforces them and the ledger that records them can be asserted equal rather
    #: than assumed so.
    send_policy_version: str

    def permits(self, entity_type: str) -> bool:
        return entity_type in self.entity_types

    def withholds(self, wanted: tuple[str, ...]) -> tuple[str, ...]:
        """The fields of an outbound request this policy does not permit, in order."""
        return tuple(name for name in wanted if name not in self.fields)


class SendPolicy(BaseModel):
    """What every approved source may be told, as loaded. Frozen.

    A source absent from here may not be queried at all — `permit` fails naming
    the file — which is the whitelist direction. `concept/05-threat-intelligence.md`
    already makes registering a source a governed decision; this is the second
    gate, and it is a different question: the registry says a source exists and
    what it answers about, and this says whether this deployment may talk to it.
    """

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    version: str
    by_source: dict[str, SourcePermission]

    def permit(self, source_id: str) -> SourcePermission:
        """This source's permission, or a `DisclosureError` naming what is permitted.

        Never a default and never a permissive fallback. A source nobody wrote a
        send policy for is one nobody decided may be told anything, and answering
        with "everything" would make the whitelist a formality in exactly the
        deployment where it mattered.
        """
        try:
            return self.by_source[source_id]
        except KeyError:
            raise DisclosureError(
                f"no send policy permits querying {source_id!r}; "
                f"{sorted(self.by_source)} are permitted. Querying a source "
                f"discloses the indicator to it (`concept/07`), so what may be "
                f"sent to which source is a decision in `config/policy.toml` and "
                f"never an absence of one."
            ) from None


def send_policy(path: Path | str = POLICY_FILE) -> SendPolicy:
    """Read the send policy, or fail naming what is wrong with the file.

    The same file and the same reader `helena.policy.thresholds` and
    `helena.budgets.load` use — one sentence of `concept/07` makes budgets and
    thresholds policy rather than constants, and what may be sent is policy in the
    same sense and by the same note.

        send_policy_version = "2026-09-09"

        [send_policy.threatfox]
        disclosed_to = "threatfox-api.abuse.ch"
        entity_types = ["address", "domain", "url"]
        fields = ["entity_type", "entity_value"]

    Every failure is loud and names the path. The coverage rules are the point of
    the loader and each is a way an entry can be a decision nobody can act on: an
    unregistered source, an entity type the source does not cover, a field that is
    not a field of the outbound request, and a `disclosed_to` that is a URL rather
    than a host.

    A file with no `[send_policy]` table loads: it is a deployment that permits no
    live querying, and every `permit` then fails naming the file. That is the
    whitelist's own answer rather than an error, and it is the safe direction.
    """
    path = Path(path)
    try:
        raw = path.read_bytes()
    except FileNotFoundError as absent:
        raise DisclosureError(
            f"no send policy at {path}. What may be sent to which source is "
            f"governed policy (`concept/07`), so an absent file is a startup "
            f"failure and never a permission to send anything."
        ) from absent
    try:
        document = tomllib.loads(raw.decode())
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as malformed:
        raise DisclosureError(f"{path} is not readable TOML: {malformed}") from malformed

    unexpected = sorted(
        set(document) - DISCLOSURE_KEYS - THRESHOLD_KEYS - BUDGET_KEYS - PRICE_KEYS
    )
    if unexpected:
        raise DisclosureError(
            f"{path} has top-level keys {unexpected}; this loader reads "
            f"{sorted(DISCLOSURE_KEYS)}, `helena.policy.thresholds` reads "
            f"{sorted(THRESHOLD_KEYS)} and `helena.budgets.load` reads "
            f"{sorted(BUDGET_KEYS | PRICE_KEYS)}. A key nothing reads is a policy "
            f"somebody set "
            f"and nothing applies."
        )
    version = document.get("send_policy_version")
    if not isinstance(version, str) or not version.strip():
        raise DisclosureError(
            f"{path} declares no send_policy_version. Every disclosure records "
            f"which revision of this file permitted it, so a file without one "
            f"produces records that cannot be replayed against the policy that "
            f"allowed them."
        )

    table = document.get("send_policy", {})
    if not isinstance(table, dict):
        raise DisclosureError(
            f"{path}: [send_policy] is {type(table).__name__}, and it is a table "
            f"of source id -> what that source may be told"
        )
    by_source = {
        source_id: _permission(path, source_id, entry, version)
        for source_id, entry in table.items()
    }
    return SendPolicy(version=version, by_source=by_source)


_ENTRY_KEYS = frozenset({"disclosed_to", "entity_types", "fields"})


def _permission(
    path: Path, source_id: str, entry: object, version: str
) -> SourcePermission:
    """One `[send_policy.<source>]` entry, checked against the registry."""
    # Imported here rather than at module scope for the reason
    # `helena.budgets._rate_limits` gives: this is the only thing in the module
    # that needs the source registry, and `helena.enrichment` pulls the whole
    # evidence layer in with it.
    from helena.enrichment import SOURCES  # noqa: PLC0415

    if source_id not in SOURCES:
        raise DisclosureError(
            f"{path} writes a send policy for {source_id!r}, which is not a "
            f"registered source ({sorted(SOURCES)}). Adding a source is a governed "
            f"decision (`concept/05`), not a line in this file."
        )
    if not isinstance(entry, dict):
        raise DisclosureError(
            f"{path}: [send_policy.{source_id}] is {type(entry).__name__}, and it "
            f"is a table of {sorted(_ENTRY_KEYS)}"
        )
    wrong = sorted(set(entry) - _ENTRY_KEYS)
    if wrong:
        raise DisclosureError(
            f"{path}: [send_policy.{source_id}] sets {wrong}; it states "
            f"{sorted(_ENTRY_KEYS)}"
        )
    absent = sorted(_ENTRY_KEYS - set(entry))
    if absent:
        raise DisclosureError(
            f"{path}: [send_policy.{source_id}] sets no {absent}. There is no "
            f"default for what may be sent to a source — a defaulted one is a "
            f"disclosure nobody decided to make."
        )

    host = entry["disclosed_to"]
    if not isinstance(host, str) or not host.strip():
        raise DisclosureError(
            f"{path}: send_policy.{source_id}.disclosed_to is {host!r}; it is the "
            f"host this source's requests go to, and a record that cannot say who "
            f"was told is not a disclosure record"
        )
    if any(character in host for character in "/@?# ") or "://" in host:
        raise DisclosureError(
            f"{path}: send_policy.{source_id}.disclosed_to is {host!r}, which is "
            f"not a bare host. `concept/07` requires a credential travelling in a "
            f"URL to be redacted before anything is logged or stored; a policy "
            f"file that holds no URL cannot leak one, and the tool layer holds no "
            f"URL either."
        )

    covered = SOURCES[source_id].entity_types
    permitted = _strings(path, source_id, "entity_types", entry["entity_types"])
    if not permitted:
        raise DisclosureError(
            f"{path}: send_policy.{source_id} permits no entity type, so nothing "
            f"could ever be asked of it. Remove the entry to say the source may "
            f"not be queried; an entry that permits nothing says the same thing "
            f"twice and differently."
        )
    outside = sorted(set(permitted) - covered)
    if outside:
        raise DisclosureError(
            f"{path}: send_policy.{source_id} permits disclosing {outside}, which "
            f"{source_id} does not answer about ({sorted(covered)}). A permission "
            f"cannot exceed the capability it is a permission for."
        )

    fields = _strings(path, source_id, "fields", entry["fields"])
    unknown = sorted(set(fields) - set(SENDABLE_FIELDS))
    if unknown:
        raise DisclosureError(
            f"{path}: send_policy.{source_id} permits sending {unknown}, which is "
            f"not part of an outbound request ({list(SENDABLE_FIELDS)}). A field "
            f"nothing can populate is a permission nothing reads."
        )
    return SourcePermission(
        source_id=source_id,
        disclosed_to=host.strip(),
        entity_types=permitted,
        fields=fields,
        send_policy_version=version,
    )


def _strings(path: Path, source_id: str, name: str, value: object) -> tuple[str, ...]:
    """A list of non-blank strings, in the order the file wrote them."""
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item.strip() for item in value
    ):
        raise DisclosureError(
            f"{path}: send_policy.{source_id}.{name} is {value!r}; it is a list of "
            f"names, and a blank one is a decision that says nothing"
        )
    return tuple(value)


class Disclosure(BaseModel):
    """One act of telling an outside party something. Frozen, typed, countable.

    `concept/07`'s list is the field list: **source, query, cache hit or live,
    disclosed-to, and when**. Four of the five are here; the fifth is
    `helena.contracts.v1.RetrievalStep.outcome` on the same assessment, because a
    row exists here **only** where something was sent — see the module docstring.

    The tenant, the sensor and the context are on the `Disclosures` ledger rather
    than on every row, for the reason `helena.contracts.v1.Cost` carries none: one
    ledger is one run, and a scope repeated per row is a scope that can disagree
    with itself.
    """

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    #: `provider_lookup` or `model_inference`.
    channel: str
    #: Who was told. A registered source id for a lookup — checked, so the field
    #: cannot quietly become a second vocabulary — and the model asked for a model
    #: call, which is what `concept/07` records on an assessment beside the
    #: endpoint host.
    source: str
    #: The host that received it. `concept/07`: enough to know what produced a
    #: result, with nothing that authenticates as anyone.
    disclosed_to: str
    #: What was disclosed, in words and bounded. The indicator itself for a
    #: lookup — `sql/migrations/0017` keeps the literal string for this reason —
    #: and the shape and size of the prompt for a model call, never its text.
    query: str
    #: A digest of exactly what left, so the record can be checked against the
    #: rendering or the stored response without holding a second copy of either.
    query_digest: str
    disclosed_at: datetime
    #: Which revision of `config/policy.toml`'s send policy was in force.
    send_policy_version: str

    def model_post_init(self, _context: object) -> None:
        from helena.enrichment import SOURCES  # noqa: PLC0415

        if self.channel not in CHANNELS:
            raise ValueError(f"channel {self.channel!r} is not one of {list(CHANNELS)}")
        for name in ("source", "disclosed_to", "query", "send_policy_version"):
            if not getattr(self, name).strip():
                raise ValueError(
                    f"{name} is blank; a disclosure record that cannot say what "
                    f"left, or who was told, records nothing"
                )
        if self.channel == PROVIDER_LOOKUP and self.source not in SOURCES:
            raise ValueError(
                f"a {PROVIDER_LOOKUP} names the registered source that was told, "
                f"and {self.source!r} is not one of {sorted(SOURCES)}"
            )
        if self.channel == MODEL_INFERENCE and self.source in SOURCES:
            raise ValueError(
                f"a {MODEL_INFERENCE} names the model that was asked, and "
                f"{self.source!r} is a registered enrichment source; two "
                f"vocabularies in one field is a record nobody can group by"
            )
        if len(self.query) > contract.MAX_DETAIL:
            raise ValueError(
                f"the query is {len(self.query)} characters and the limit is "
                f"{contract.MAX_DETAIL}; an unbounded one is where a payload ends up"
            )
        if len(self.query_digest) != 64 or not all(
            character in "0123456789abcdef" for character in self.query_digest
        ):
            raise ValueError(
                f"query_digest {self.query_digest!r} is not a SHA-256 digest of "
                f"what was sent"
            )
        if self.disclosed_at.tzinfo is None:
            raise ValueError("disclosed_at has no timezone; when is a moment in UTC")


class Disclosures:
    """Every act of disclosure one agent run made. One ledger per run, in order.

    Built by `of(request)`, exactly as `helena.budgets.RunBudget.of` is and for the
    same reason: what a run is permitted to disclose and what it did disclose are
    deterministic code's to decide, and the request is where the tenant, the sensor
    and the context reference were written down. A ledger assembled from loose
    values beside a request is a run whose disclosures name a context nobody can
    resolve.

    Mutable, in-process and ephemeral, which is what `concept/07` allows of working
    memory. What is durable is the assessment it becomes part of, and that row does
    not exist yet (task 43).
    """

    __slots__ = ("_tenant", "_sensor", "_context_id", "_emitter", "_policy", "_rows")

    def __init__(
        self,
        *,
        tenant: str,
        sensor: str,
        context_id: str,
        emitter: str,
        policy: SendPolicy,
    ) -> None:
        for name, value in (
            ("tenant", tenant),
            ("sensor", sensor),
            ("context_id", context_id),
            ("emitter", emitter),
        ):
            if not value.strip():
                raise DisclosureError(
                    f"{name} is blank. A disclosure ledger names the run it is "
                    f"the record of, and a defaulted tenant is an isolation "
                    f"failure that looks like it is working "
                    f"(`concept/instruction.md` §6)."
                )
        if not isinstance(policy, SendPolicy):
            raise DisclosureError(
                f"the policy is a {type(policy).__name__}; a ledger records under "
                f"the send policy that permitted the calls, so that enforcement "
                f"and recording cannot read two different files"
            )
        self._tenant = tenant
        self._sensor = sensor
        self._context_id = context_id
        self._emitter = emitter
        self._policy = policy
        self._rows: list[Disclosure] = []

    @classmethod
    def of(cls, request: contract.AgentRequest, *, policy: SendPolicy) -> Disclosures:
        return cls(
            tenant=request.tenant,
            sensor=request.sensor,
            context_id=request.context_id,
            emitter=request.emitter,
            policy=policy,
        )

    def __repr__(self) -> str:
        return (
            f"Disclosures({self._context_id!r}, {len(self._rows)} row(s), "
            f"policy {self._policy.version!r})"
        )

    # --- What it is the record of --------------------------------------------

    @property
    def tenant(self) -> str:
        return self._tenant

    @property
    def sensor(self) -> str:
        return self._sensor

    @property
    def context_id(self) -> str:
        return self._context_id

    @property
    def emitter(self) -> str:
        return self._emitter

    @property
    def policy(self) -> SendPolicy:
        """The send policy in force. What the tool layer enforced, read back."""
        return self._policy

    # --- What it holds --------------------------------------------------------

    @property
    def rows(self) -> tuple[Disclosure, ...]:
        """Every disclosure this run made, in the order it made them."""
        return tuple(self._rows)

    def to_channel(self, channel: str) -> tuple[Disclosure, ...]:
        """The rows of one channel, so the two can be counted apart."""
        if channel not in CHANNELS:
            raise DisclosureError(f"channel {channel!r} is not one of {list(CHANNELS)}")
        return tuple(row for row in self._rows if row.channel == channel)

    # --- Recording ------------------------------------------------------------

    def record_lookup(
        self,
        *,
        permit: SourcePermission,
        entity_type: str,
        entity_value: str,
        at: datetime,
    ) -> Disclosure:
        """One provider query, recorded **before** it is sent.

        Before rather than after, and the asymmetry is deliberate: a request that
        reached the provider and then timed out disclosed the indicator anyway, so
        recording on success would under-record exactly the case an operator most
        needs to see. The cost is a row for a call that failed before it left the
        process, which over-records in the safe direction.

        The permission is the one the tool enforced, passed in rather than looked
        up here, so the check and the record cannot read two different entries. It
        is verified against the policy this ledger holds — a mismatch is this
        project's own bug and is loud, because a disclosure that the policy in
        force did not permit is either a leak or a bypass and both are worse than
        a stopped run.
        """
        held = self._policy.permit(permit.source_id)
        if held != permit:
            raise DisclosureError(
                f"the tool enforced {permit} and this ledger records under "
                f"{held}. Enforcement and recording read one policy, or a "
                f"disclosure is recorded under rules that did not permit it."
            )
        if not permit.permits(entity_type):
            raise DisclosureError(
                f"the send policy does not permit disclosing a {entity_type} to "
                f"{permit.source_id} ({list(permit.entity_types)}), so this call "
                f"should have been refused before it reached the record"
            )
        return self._record(
            Disclosure(
                channel=PROVIDER_LOOKUP,
                source=permit.source_id,
                disclosed_to=permit.disclosed_to,
                query=f"{entity_type} {entity_value}"[: contract.MAX_DETAIL],
                query_digest=digest(entity_value.encode()),
                disclosed_at=at,
                send_policy_version=permit.send_policy_version,
            )
        )

    def record_model_call(
        self,
        *,
        model: str,
        disclosed_to: str,
        prompt: bytes,
        messages: int,
        at: datetime,
    ) -> Disclosure:
        """One model call, recorded before the prompt leaves. `concept/03`'s own rule.

        *"Inference in the prototype is hosted, so prompts leave the monitored
        network and the disclosure rule applies to model calls as much as to
        intelligence lookups."* A retry is a second call and a second row: the
        prompt left twice.

        **The prompt is not copied into the record.** What it contains is the
        rendered context — internal addresses, hostnames and retrieved external
        text — which the request already carries under a recorded
        `rendering_version`; a second copy here would put it in a place nothing
        else governs. What is recorded is its shape, its size and a digest of
        exactly the bytes that left, which is what an audit needs to tie a
        disclosure to a rendering it can read.
        """
        return self._record(
            Disclosure(
                channel=MODEL_INFERENCE,
                source=model,
                disclosed_to=disclosed_to,
                query=(
                    f"prompt of {messages} message(s), {len(prompt)} bytes, for "
                    f"context {self._context_id}"
                )[: contract.MAX_DETAIL],
                query_digest=digest(prompt),
                disclosed_at=at,
                send_policy_version=self._policy.version,
            )
        )

    def _record(self, row: Disclosure) -> Disclosure:
        self._rows.append(row)
        return row
