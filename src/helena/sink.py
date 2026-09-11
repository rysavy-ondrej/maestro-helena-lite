"""Sink — the emitted message, field by field, and the view it is read out of.

`concept/03-architecture.md`, the Components table: *"**Sink** | A sink over a
view joining the enriched context, the terminal verdict and the cited
evidence."* The view is `sql/migrations/0019_sink.sql`; this module is the shape
of what goes on the wire and the read that assembles it.

The message `concept/03` specifies, in its own words:

    *"The message carries context identity and version, host and window, the
    entity rows with their traffic characteristics and enrichment evidence (with
    `no_match`, `stale`, `failed` and `missing` distinguishable), the verdict and
    its path, the citations, the retrieval and disclosure trace, and the full
    version set."*

Those eight things are `OutputMessage`'s eight groups of fields, in that order.

## Egress, not storage — and what that means for a field

*"The output topic. Egress only. **Nothing may be recoverable only from it.**"*
(`concept/03`, and `concept/instruction.md` §2.) Every field below is a
projection of a row in the single store, and
`tests/test_sink.py::test_every_field_of_the_message_is_recoverable_from_the_engine`
executes a recovery query per field group and compares. The one exception is
`message_version`, which is a constant of the emitter rather than state: it
records which shape the bytes are in, and there is nothing to recover it from
because nothing stored it.

That rule is what makes the duplication safe rather than merely unavoidable. The
same assessment exists twice — as the rows 0018 wrote and as the bytes that go on
the topic — and two copies of a fact can disagree. Here they cannot be
*independently* wrong: the message is derived on every read, so a disagreement is
a defect in one query rather than a stale second record.

## The message shape is an interface, and it is versioned as one

`MESSAGE_VERSION` is on every message and is `"v1"`. Nothing in the engine records
it — no assessment row has a `message_version` column and replay never validates
against one — so this is **not** a frozen version module in the sense of
`docs/decisions/0008-version-registry.md`. It is an interface version for the
consumers `concept/03` names (*"the analyst workflow / SIEM"*), and the rule is
stated rather than structural:

    A change to the field set, to a field's meaning, or to its type is an
    interface change. It bumps `MESSAGE_VERSION` and it comes with a decision
    record.

`tests/fixtures/sink/message-v1.json` pins the JSON Schema of `OutputMessage`
without its prose — the field set, the types and which fields are required — and
`tests/test_sink.py` compares against it byte for byte, so a silent edit is a
failing test rather than a consumer discovering it. The fixture's README says what
to do when it fails. `docs/decisions/0036-the-output-message.md` is the record.

## Redaction is inherited, and this deployment performs none

`concept/03`, "Trust and egress boundaries", 2.:

    *"The sink writes to the **local** broker, so no redaction is performed — but
    that is a property of the deployment, not of the message: the payload
    contains internal addresses, hostnames and retrieved external text, and **any
    consumer that forwards it off-site inherits the redaction, minimization and
    disclosure obligations**. The pipeline cannot enforce that."*

All three are here and are named so nobody has to find them: `host` and
`EmittedEntity.entity_value` (internal addresses and the names the host looked
up), and `EmittedEvidence.native_evidence` (the publisher's own text, retrieved).
`EmittedDisclosure.query` adds a fourth kind — a record of which indicators this
network told an external provider about, which is itself disclosive. The module
carries no redactor, because redacting here would make the local consumer's copy
differ from the stored rows for no benefit; what it carries is the statement of
the obligation, in `docs/decisions/0036-the-output-message.md` §5 and in
`MESSAGE_CAVEAT`, which is on every message.

## Delivery is at-least-once, and the consumer deduplicates

`emit` produces one message per terminal outcome and then reconciles what it
produced against `SinkStore.pending`. It does **not** remember what it emitted
last time, so a second run puts the same messages on the topic again — which is
what `concept/03`'s *"delivery is at-least-once, so consumers deduplicate;
exactly-once is not attempted"* means in code rather than in prose.

**The deduplication key is `OutputMessage.assessment_id`**, and it also travels
in the `helena-assessment-id` header so a consumer can discard a repeat without
parsing the value. It is a digest over
`(tenant, sensor, context_id, context_version, emitter, trigger)`
(`sql/migrations/0018`) with no outcome and no timestamp in it, so two emissions
of one terminal run carry one key and deduplicating on it is correct rather than
lossy. `docs/decisions/0037-at-least-once-emission.md` §2 is the contract a
consumer implements against.

## Emission is not recorded, and the count is of what there is to emit

Nothing here writes a row saying a message was produced. The engine-side number
`concept/03` asks for is `helena_analytical_emission_counts`
(`sql/migrations/0020`) — how many messages the store holds, not how many left —
and that is the number that answers the question the note poses: a consumer that
sees nothing asks the engine, and gets `0` for *"nothing was assessed"* or `12`
for *"twelve existed and are gone"*. A ledger of what was emitted would be the
first step toward the exactly-once this project does not attempt, and would make
the sink write to the store it exists to read from. ADR-0037 §3.

Reads: helena_analytical_sink, helena_analytical_emission_counts,
helena_analytical_assessment_citation, helena_analytical_assessment_gap,
helena_analytical_assessment_pattern, helena_analytical_assessment_retrieval,
helena_analytical_assessment_disclosure. Writes: the output topic, through
`helena.broker` and no other way. Nothing durable — a sink is egress.

Maturity: experimental — `tests/test_sink.py` executes the view, the read and the
emission against the pinned engine and the pinned broker, over rows a real
`AssessmentStore` wrote: an escalated pass, a typed failure, a context whose
version has moved on and a deployment with no feed loaded, drained back off the
topic and compared to what the store projects. No consumer outside this project
has read one, so the interface is exercised by these tests and by nothing else.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

import psycopg
from pydantic import BaseModel, ConfigDict

from helena import orchestration
from helena.broker import BrokerProducer
from helena.config import ConfigurationError, IngestionIdentity
from helena.versions import VERSION_COLUMNS

__all__ = [
    "CITED_ROLES",
    "EMISSION_COUNTS_VIEW",
    "EmissionCounts",
    "EmittedCitation",
    "EmittedDisclosure",
    "EmittedEntity",
    "EmittedEvidence",
    "EmittedGap",
    "EmittedRetrieval",
    "EmittedVersions",
    "MESSAGE_CAVEAT",
    "MESSAGE_VERSION",
    "OUTPUT_HEADERS",
    "OUTPUT_HEADER_ASSESSMENT",
    "OUTPUT_HEADER_MESSAGE_VERSION",
    "OutputMessage",
    "SINK_COLUMNS",
    "SINK_VIEW",
    "SinkError",
    "SinkStore",
    "TriageDecision",
    "emit",
]

#: The shape of the bytes on the topic. See the head: an interface version, not a
#: recorded one, and a change to it is a decision record.
MESSAGE_VERSION = "v1"

#: What every message says about itself. One sentence, because a consumer that
#: forwards the payload off-site inherits an obligation the pipeline cannot
#: enforce (`concept/03`, "Trust and egress boundaries") and the payload is the
#: only place that obligation can travel with the data.
MESSAGE_CAVEAT = (
    "Unredacted: contains internal addresses, hostnames and retrieved external "
    "text. A consumer that forwards this off-site inherits the redaction, "
    "minimization and disclosure obligations."
)

#: The view this module reads. `sql/migrations/0019_sink.sql`.
SINK_VIEW = "helena_analytical_sink"

#: The engine-side count of messages there are to emit.
#: `sql/migrations/0020_emission_counts.sql`.
EMISSION_COUNTS_VIEW = "helena_analytical_emission_counts"

# What a message says about itself in its headers, so that a consumer can act on
# both without parsing the value. `helena.broker` carries header bytes and knows
# nothing of what they mean; this is the only place that does, exactly as
# `helena.normalizer.INGEST_HEADERS` is on the ingress side.
#
# Two headers and no more. The identifier is here because deduplication is the
# consumer's obligation under an at-least-once contract and making it parse a
# few hundred kilobytes of JSON to learn a key it may be about to discard is a
# cost the header removes. The version is here because a consumer that does not
# understand a shape should be able to route the message aside rather than fail
# parsing it. Everything else about the message is in the message.
OUTPUT_HEADER_ASSESSMENT = "helena-assessment-id"
OUTPUT_HEADER_MESSAGE_VERSION = "helena-message-version"
OUTPUT_HEADERS = (OUTPUT_HEADER_ASSESSMENT, OUTPUT_HEADER_MESSAGE_VERSION)

#: Every column of `SINK_VIEW`, in the order the migration declares them. Named
#: once for the reason `helena.orchestration.ASSESSMENT_COLUMNS` is: the read
#: below and `tests/test_sink.py` would otherwise be two copies of the view's
#: shape, and the one that goes stale is the reader.
SINK_COLUMNS = (
    "assessment_id",
    "tenant",
    "sensor",
    "host",
    "context_id",
    "context_version",
    "window_start",
    "window_end",
    "emitter",
    "triggered_by",
    "assessed_at",
    "outcome_kind",
    "verdict",
    "classification",
    "confidence",
    "narrative",
    "failure_reason",
    "failure_detail",
    "model_version",
    "model_requested",
    "prompt_version",
    "schema_version",
    "rendering_version",
    "taxonomy_version",
    "enrichment_snapshot_version",
    "normalization_snapshot_version",
    "policy_version",
    "aggregation_version",
    "triage_assessment_id",
    "triage_triggered_by",
    "triage_outcome_kind",
    "triage_verdict",
    "triage_classification",
    "triage_confidence",
    "triage_failure_reason",
    "triage_failure_detail",
    "triage_assessed_at",
    "triage_model_version",
    "triage_prompt_version",
    "context_resolved",
    "context_flow_count",
    "context_duration_seconds",
    "context_bytes_sent",
    "context_bytes_received",
    "context_packets_sent",
    "context_packets_received",
    "entity_type",
    "entity_value",
    "observed_as_flow_destination",
    "observed_in_dns_query",
    "observed_in_dns_response",
    "observed_in_tls",
    "observed_in_http",
    "observed_flow_count",
    "observed_bytes_sent",
    "observed_bytes_received",
    "observed_packets_sent",
    "observed_packets_received",
    "source_id",
    "evidence_id",
    "source_tier",
    "evidence_tier",
    "snapshot_version",
    "snapshot_loaded_at",
    "status",
    "evidence_classification",
    "evidence_taxonomy_version",
    "evidence_confidence",
    "scope_type",
    "scope_value",
    "first_seen",
    "last_seen",
    "native_evidence",
    "port_matched",
    "cited_as",
)

#: The columns of the sink view that describe the terminal run rather than one
#: entity of it. Every row of one message carries the same values in these, which
#: is what makes the grouping below a grouping rather than a choice.
_RUN_COLUMNS = SINK_COLUMNS[: SINK_COLUMNS.index("entity_type")]

#: The entity and its traffic characteristics.
_ENTITY_COLUMNS = SINK_COLUMNS[
    SINK_COLUMNS.index("entity_type") : SINK_COLUMNS.index("source_id")
]

#: One source's answer about one entity, plus the role the verdict gave it.
_EVIDENCE_COLUMNS = SINK_COLUMNS[SINK_COLUMNS.index("source_id") :]

#: `helena.contracts.v1.STANCES`, as the sink view spells them back. Named here
#: so the message's own vocabulary is readable without opening the contract; the
#: equality is asserted in `tests/test_sink.py` rather than left to drift.
CITED_ROLES = ("supporting", "contradicting")

#: The version columns of the assessment row, in `EmittedVersions`' own order.
#: Derived from the registry so a dimension cannot be dropped on the way out.
_VERSION_FIELDS = (*VERSION_COLUMNS, "model_requested")

_MESSAGE_MODEL_CONFIG = ConfigDict(
    # A message describes a run that has already happened, and nothing downstream
    # of `project` may edit one into something the rows do not say.
    frozen=True,
    extra="forbid",
    hide_input_in_errors=True,
    protected_namespaces=(),
)


class SinkError(Exception):
    """A message cannot be assembled honestly, so it is not assembled.

    Every case is the same refusal: the rows the view produced do not describe
    one terminal run of one pass. An assessment id this deployment does not hold,
    an identity that is not this sink's, rows that disagree about the run they
    belong to. Emitting anyway would put bytes on the topic that no query can
    reproduce, which is the one property egress may not lose.
    """


class EmittedEvidence(BaseModel):
    """What one source had to say about one entity, and whether the verdict cited it.

    `concept/instruction.md` §2 — *"`stale`, `failed`, `missing` and `no_match`
    are four different things, and a typed error is a fifth. Never collapse
    them"* — is the reason `status` and `classification` are two fields and
    neither has a default:

    | `status` | `classification` | what happened |
    | --- | --- | --- |
    | `ok` | a path | the source answered and made a claim |
    | `ok` | `no_match` | the source answered and said nothing about this entity |
    | `stale` | a path or `no_match` | the same, from a snapshot past its refresh window |
    | `failed` | `None` | the load did not complete; there is no claim to have |
    | `missing` | `None` | no snapshot exists to consult at this window |

    A consumer that maps any two of those five rows onto one value has undone the
    distinction on the way out of the system. There is a **sixth** case and it is
    not a row here: an entity whose `evidence` tuple is empty, which is a
    deployment that has never asked any source at all. `missing` is a source that
    was asked for and had nothing to look in; an empty tuple is nobody to ask.
    `sql/migrations/0019_sink.sql` has the argument.
    """

    model_config = _MESSAGE_MODEL_CONFIG

    source_id: str
    #: `ok` / `stale` / `failed` / `missing` — `helena.enrichment.ENRICHMENT_STATUSES`,
    #: and never absent. The enriched context's `CASE` is total, so a NULL here
    #: would be the join producing a row about a source it could not name, and
    #: validation refuses it rather than emitting an evidence row with no state.
    status: str
    #: The claim, or `no_match`, or `None`. See the table above.
    classification: str | None
    #: `helena.enrichment.evidence_id`'s, and the identifier a citation resolves
    #: to. `None` where there is no claim to identify.
    evidence_id: str | None
    #: A-D. How strong the source is, which is not how it got here.
    source_tier: str | None
    #: `enrichment` or `analyst`. How it got here.
    evidence_tier: str | None
    snapshot_version: str | None
    snapshot_loaded_at: datetime | None
    taxonomy_version: str | None
    confidence: float | None
    scope_type: str | None
    scope_value: str | None
    first_seen: datetime | None
    last_seen: datetime | None
    #: The publisher's own record, verbatim. Retrieved external text: it is data
    #: and never instruction (`concept/07`), and it is one of the three things
    #: that make this payload inherit a redaction obligation.
    native_evidence: Any | None
    #: Three-valued, and not a filter. `None` where the claim is not port-scoped,
    #: `False` where the host reached this address on other ports only.
    port_matched: bool | None
    #: The role the terminal outcome gave this evidence row, or `None` where it
    #: cited it not at all. A denormalization of `OutputMessage.citations`, which
    #: is the authoritative list because a citation may resolve to analyst-tier
    #: evidence that has no row here.
    cited_as: str | None


class EmittedEntity(BaseModel):
    """One entity of the context, what the host did with it, and what is known about it.

    `concept/03`: *"the entity rows with their traffic characteristics and
    enrichment evidence"*. The observation flags are `concept/instruction.md`
    §2's *"absence is not emptiness"* at the entity level: an address the host
    contacted is a different fact from one it only resolved, and the composition
    rule turns on which.

    `evidence` is empty where no source has ever been asked. That is not the same
    as `no_match` and is not the same as `missing`; the six rows of
    `EmittedEvidence`'s table say which is which.
    """

    model_config = _MESSAGE_MODEL_CONFIG

    entity_type: str
    entity_value: str
    observed_as_flow_destination: bool
    observed_in_dns_query: bool
    observed_in_dns_response: bool
    observed_in_tls: bool
    observed_in_http: bool
    observed_flow_count: int
    observed_bytes_sent: int
    observed_bytes_received: int
    observed_packets_sent: int
    observed_packets_received: int
    evidence: tuple[EmittedEvidence, ...]


class EmittedCitation(BaseModel):
    """`(evidence, role)` — a join row of 0018, as the message spells it.

    The assessment identifier is not repeated here: the message is one
    assessment's, and `OutputMessage.assessment_id` is what these belong to.
    """

    model_config = _MESSAGE_MODEL_CONFIG

    evidence_id: str
    #: `helena.contracts.v1.STANCES`. See `CITED_ROLES`.
    role: str


class EmittedGap(BaseModel):
    """What the run could not see. `concept/02`'s seven kinds, never collapsed."""

    model_config = _MESSAGE_MODEL_CONFIG

    kind: str
    detail: str


class EmittedRetrieval(BaseModel):
    """One step of the retrieval trace, tagged with the run that took it.

    `concept/07`, "Caching": *"the retrieval trace records, per result, whether it
    was a cache hit or a live query, and the retrieval time of the underlying
    record."* `retrieved_at` is the **underlying record's**, so a cache hit
    carries the age of what it served rather than the time it was served.

    `emitter` is here because the trace is the pass's rather than the terminal
    run's: a triage run cannot retrieve at all (`concept/04`), so a triage-tagged
    step would be a contract violation a consumer can see.
    """

    model_config = _MESSAGE_MODEL_CONFIG

    emitter: str
    source_id: str
    entity_type: str
    entity_value: str
    #: `cache_hit` or `live_query`. Both are completed retrievals.
    outcome: str
    retrieved_at: datetime
    evidence_id: str | None
    #: `helena.enrichment.QUERY_FAILURE_REASONS`. Never `no_match`.
    failure_reason: str | None
    failure_detail: str | None


class EmittedDisclosure(BaseModel):
    """What left this network, to whom, and when. Both channels.

    `concept/07`, "Privacy and disclosure". The pass's ledger rather than the
    terminal run's, for the same reason the retrieval trace is: a triage run
    calls a hosted model, and `concept/03` makes that egress too, so a message
    that showed only the analyst's disclosures would under-report what the
    assessment of this context sent off-site.

    `query` is what was disclosed in words and never the text of a prompt;
    `disclosed_to` is a host and never a URL, so a credential in a path cannot
    reach this field.
    """

    model_config = _MESSAGE_MODEL_CONFIG

    emitter: str
    #: `helena.disclosure.CHANNELS`: `provider_lookup` or `model_inference`.
    channel: str
    source: str
    disclosed_to: str
    query: str
    #: sha256 of exactly the bytes that left.
    query_digest: str
    disclosed_at: datetime
    send_policy_version: str


class EmittedVersions(BaseModel):
    """The nine dimensions a citable row records, plus what was asked for.

    Not `helena.versions.VersionSet`, and the difference is one field:
    `model_version` is NULL exactly on a `model_unavailable` failure, where
    nothing answered at all, and `VersionSet` requires all nine to be present
    because it describes a run that reached a model. A message has to carry the
    runs that did not.

    The field names are `VERSION_COLUMNS` plus `model_requested`, and
    `tests/test_sink.py` asserts that equality against the registry rather than
    leaving two spellings of nine dimensions to drift — `concept/instruction.md`
    §2: *"two copies of a version constant must be asserted equal by a test"*.
    """

    model_config = _MESSAGE_MODEL_CONFIG

    #: What answered, as the endpoint reported itself. `None` exactly where
    #: nothing did.
    model_version: str | None
    prompt_version: str
    schema_version: str
    rendering_version: str
    taxonomy_version: str
    enrichment_snapshot_version: str
    normalization_snapshot_version: str
    policy_version: str
    aggregation_version: str
    #: The tenth thing a run records: what this deployment *asked* for, which is
    #: not what answered.
    model_requested: str


class TriageDecision(BaseModel):
    """The triage decision that led to an analyst verdict. `concept/03`'s "path".

    Present exactly where the terminal run is the analyst's — *"a context that
    was escalated is emitted once, carrying the analyst's verdict **and the
    triage decision that led to it**"*. Where triage is itself the terminal run
    this is `None` and the message's own verdict fields are triage's.

    Deliberately narrow. Everything else about the triage run — its citations,
    its gaps, its budgets, its cost — is in the store under
    `assessment_id`, which is in this object, so carrying it twice would grow the
    payload without adding a fact. What is here is what a reader needs to see the
    path without a second query: whether triage agreed, and what it was.
    """

    model_config = _MESSAGE_MODEL_CONFIG

    assessment_id: str
    trigger: str
    #: `verdict` or `typed_failure`.
    outcome_kind: str
    verdict: str | None
    classification: str | None
    confidence: float | None
    failure_reason: str | None
    failure_detail: str | None
    assessed_at: datetime
    model_version: str | None
    prompt_version: str


class OutputMessage(BaseModel):
    """One JSON message per assessed context. `concept/03`'s output-topic contract.

    Field order is the order `concept/03` lists what the message carries: context
    identity and version, host and window, the entity rows, the verdict and its
    path, the citations, the retrieval and disclosure trace, and the full version
    set.

    **`assessment_id` is the deduplication key.** Delivery is at-least-once, so a
    consumer may see this message more than once; the identifier is a digest over
    `(tenant, sensor, context_id, context_version, emitter, trigger)` and is
    stable across a re-run of the same snapshot, so discarding a repeat is
    correct. It is not a message id: two emissions of the same assessment are the
    same assessment, which is what makes deduplicating on it right rather than
    lossy.
    """

    model_config = _MESSAGE_MODEL_CONFIG

    #: The shape of these bytes. See the module head — an interface version.
    message_version: str
    #: The obligation that travels with the payload. See the module head.
    caveat: str

    # --- context identity and version, host and window ----------------------
    assessment_id: str
    tenant: str
    sensor: str
    host: str
    context_id: str
    context_version: str
    window_start: datetime
    window_end: datetime
    assessed_at: datetime
    #: Whether the store still holds the exact context snapshot that was
    #: assessed. `False` means the window has since gained records and `entities`
    #: is empty for that reason rather than because the host contacted nothing.
    context_resolved: bool
    #: The context's own counters — the six values `context_version` is a digest
    #: over, so they cannot disagree with it. `None` where `context_resolved` is
    #: `False`.
    flow_count: int | None
    duration_seconds: float | None
    bytes_sent: int | None
    bytes_received: int | None
    packets_sent: int | None
    packets_received: int | None

    # --- the entity rows ----------------------------------------------------
    entities: tuple[EmittedEntity, ...]

    # --- the verdict and its path -------------------------------------------
    #: `triage` or `analyst`: which agent produced the terminal outcome.
    emitter: str
    trigger: str
    #: `verdict` or `typed_failure`. `concept/02`'s two terminal outcomes, and
    #: `concept/instruction.md` §2 requires both to be emitted.
    outcome_kind: str
    #: The root of `classification`. `None` on a typed failure.
    verdict: str | None
    classification: str | None
    confidence: float | None
    narrative: str | None
    failure_reason: str | None
    failure_detail: str | None
    #: The triage decision that led here, or `None` where triage is the terminal
    #: run.
    triage: TriageDecision | None

    # --- the citations ------------------------------------------------------
    citations: tuple[EmittedCitation, ...]
    gaps: tuple[EmittedGap, ...]
    patterns: tuple[str, ...]

    # --- the retrieval and disclosure trace ---------------------------------
    retrievals: tuple[EmittedRetrieval, ...]
    disclosures: tuple[EmittedDisclosure, ...]

    # --- the full version set -----------------------------------------------
    #: The nine dimensions `concept/07` requires on a citable row, plus what was
    #: asked for.
    versions: EmittedVersions


@dataclass(frozen=True)
class SinkStore:
    """The sink view and the four child tables, under one identity.

    The same shape as `helena.rendering.RenderingStore` and for the same reason:
    the identity is on the instance rather than passed per call, so a caller
    cannot emit one deployment's assessment under another's tenant.
    `concept/instruction.md` §6 — *"a defaulted tenant is an isolation failure
    that looks like it is working"*.
    """

    connection: psycopg.Connection
    identity: IngestionIdentity

    def pending(self) -> int:
        """How many messages this identity has to emit, asked of the engine.

        `concept/03`: *"Emission must be observable from the engine side — a count
        of rows the sink view produced — because the broker discards its queue on
        restart, so a message emitted with no consumer attached is simply gone.
        Otherwise 'nothing arrived' cannot be told apart from 'nothing was
        assessed'."*

        The count lives in `sql/migrations/0020` rather than in this query, so
        that an operator who is not running the emitter can ask the engine the
        same question and get the same number (`docs/runbook.md` §12). It is at
        message grain — the view's own grain is one row per
        (terminal run x entity x source) — and the reason is in that migration.

        No row for this identity means nothing has been assessed, which is a real
        answer and not a missing one; the ingest counter reads the same way.
        """
        self.connection.execute("FLUSH")
        rows = self.connection.execute(
            f"SELECT pending FROM {EMISSION_COUNTS_VIEW} "
            f"WHERE tenant = %s AND sensor = %s",
            (self.identity.tenant, self.identity.sensor),
        ).fetchall()
        return int(rows[0][0]) if rows else 0

    def terminal(self) -> tuple[str, ...]:
        """Every terminal run this identity holds, oldest first.

        One identifier per message `concept/03` requires to be emitted — *"every
        assessed context is emitted, exactly once per terminal outcome"* — and it
        is the view's own selection rather than a second reading of it, so a pass
        that escalated appears once and under the analyst's identifier.
        """
        self.connection.execute("FLUSH")
        rows = self.connection.execute(
            f"SELECT DISTINCT assessment_id, assessed_at FROM {SINK_VIEW} "
            f"WHERE tenant = %s AND sensor = %s ORDER BY assessed_at, assessment_id",
            (self.identity.tenant, self.identity.sensor),
        ).fetchall()
        return tuple(identifier for identifier, _ in rows)

    def project(self, assessment_id: str) -> OutputMessage:
        """The message for one terminal run, assembled out of the store.

        Raises `SinkError` for an identifier the sink view does not hold under
        this identity — which is an assessment of another deployment, an
        assessment that is not terminal (the triage half of a pass that
        escalated), or no assessment at all. All three are the same refusal:
        there is nothing here to emit, and emitting an empty message would put a
        context on the topic that the store does not describe.
        """
        self.connection.execute("FLUSH")
        rows = self.connection.execute(
            f"SELECT {', '.join(SINK_COLUMNS)} FROM {SINK_VIEW} "
            f"WHERE tenant = %s AND sensor = %s AND assessment_id = %s "
            f"ORDER BY entity_type, entity_value, source_id",
            (self.identity.tenant, self.identity.sensor, assessment_id),
        ).fetchall()
        if not rows:
            raise SinkError(
                f"{SINK_VIEW} holds no terminal run {assessment_id!r} for "
                f"{self.identity.tenant!r} / {self.identity.sensor!r}. It is "
                f"another deployment's, it is the triage half of a pass that "
                f"escalated, or it was never stored — and none of the three is a "
                f"message."
            )
        dicts = [dict(zip(SINK_COLUMNS, row, strict=True)) for row in rows]
        run = _one_run(dicts, assessment_id)
        triage_id = run["triage_assessment_id"]
        of_the_pass = (
            ((triage_id, "triage"), (assessment_id, run["emitter"]))
            if triage_id
            else ((assessment_id, run["emitter"]),)
        )
        return OutputMessage(
            message_version=MESSAGE_VERSION,
            caveat=MESSAGE_CAVEAT,
            assessment_id=run["assessment_id"],
            tenant=run["tenant"],
            sensor=run["sensor"],
            host=run["host"],
            context_id=run["context_id"],
            context_version=run["context_version"],
            window_start=run["window_start"],
            window_end=run["window_end"],
            assessed_at=run["assessed_at"],
            context_resolved=run["context_resolved"],
            flow_count=run["context_flow_count"],
            duration_seconds=run["context_duration_seconds"],
            bytes_sent=run["context_bytes_sent"],
            bytes_received=run["context_bytes_received"],
            packets_sent=run["context_packets_sent"],
            packets_received=run["context_packets_received"],
            entities=_entities(dicts),
            emitter=run["emitter"],
            trigger=run["triggered_by"],
            outcome_kind=run["outcome_kind"],
            verdict=run["verdict"],
            classification=run["classification"],
            confidence=run["confidence"],
            narrative=run["narrative"],
            failure_reason=run["failure_reason"],
            failure_detail=run["failure_detail"],
            triage=_triage(run),
            citations=self._citations(assessment_id),
            gaps=self._gaps(assessment_id),
            patterns=self._patterns(assessment_id),
            retrievals=self._retrievals(of_the_pass),
            disclosures=self._disclosures(of_the_pass),
            versions=EmittedVersions(
                **{column: run[column] for column in _VERSION_FIELDS}
            ),
        )

    # --- the five child reads -----------------------------------------------

    def _citations(self, identifier: str) -> tuple[EmittedCitation, ...]:
        """The terminal outcome's citations, whichever tier they resolve to.

        Read from the join table rather than off the sink view's `cited_as`: a
        citation may resolve to analyst-tier evidence (`sql/migrations/0017`),
        which is not in the enriched context and therefore has no row in the view
        to be marked on. The view's column is the denormalization; this is the
        list.
        """
        rows = self.connection.execute(
            f"SELECT evidence_id, role FROM {orchestration.CITATION_TABLE} "
            f"WHERE assessment_id = %s ORDER BY evidence_id",
            (identifier,),
        ).fetchall()
        return tuple(
            EmittedCitation(evidence_id=evidence_id, role=role)
            for evidence_id, role in rows
        )

    def _gaps(self, identifier: str) -> tuple[EmittedGap, ...]:
        rows = self.connection.execute(
            f"SELECT kind, detail FROM {orchestration.GAP_TABLE} "
            f"WHERE assessment_id = %s ORDER BY ordinal",
            (identifier,),
        ).fetchall()
        return tuple(EmittedGap(kind=kind, detail=detail) for kind, detail in rows)

    def _patterns(self, identifier: str) -> tuple[str, ...]:
        rows = self.connection.execute(
            f"SELECT pattern FROM {orchestration.PATTERN_TABLE} "
            f"WHERE assessment_id = %s ORDER BY ordinal",
            (identifier,),
        ).fetchall()
        return tuple(pattern for (pattern,) in rows)

    def _retrievals(
        self, of_the_pass: tuple[tuple[str, str], ...]
    ) -> tuple[EmittedRetrieval, ...]:
        """The pass's retrieval trace, each step tagged with the run that took it."""
        steps: list[EmittedRetrieval] = []
        for identifier, emitter in of_the_pass:
            rows = self.connection.execute(
                f"SELECT source_id, entity_type, entity_value, outcome, "
                f"retrieved_at, evidence_id, failure_reason, failure_detail "
                f"FROM {orchestration.RETRIEVAL_TABLE} "
                f"WHERE assessment_id = %s ORDER BY ordinal",
                (identifier,),
            ).fetchall()
            steps.extend(
                EmittedRetrieval(
                    emitter=emitter,
                    source_id=source_id,
                    entity_type=entity_type,
                    entity_value=entity_value,
                    outcome=outcome,
                    retrieved_at=retrieved_at,
                    evidence_id=evidence_id,
                    failure_reason=failure_reason,
                    failure_detail=failure_detail,
                )
                for (
                    source_id,
                    entity_type,
                    entity_value,
                    outcome,
                    retrieved_at,
                    evidence_id,
                    failure_reason,
                    failure_detail,
                ) in rows
            )
        return tuple(steps)

    def _disclosures(
        self, of_the_pass: tuple[tuple[str, str], ...]
    ) -> tuple[EmittedDisclosure, ...]:
        """The pass's disclosure ledger, each row tagged with the run that sent it."""
        ledger: list[EmittedDisclosure] = []
        for identifier, emitter in of_the_pass:
            rows = self.connection.execute(
                f"SELECT channel, source, disclosed_to, query, query_digest, "
                f"disclosed_at, send_policy_version "
                f"FROM {orchestration.DISCLOSURE_TABLE} "
                f"WHERE assessment_id = %s ORDER BY ordinal",
                (identifier,),
            ).fetchall()
            ledger.extend(
                EmittedDisclosure(
                    emitter=emitter,
                    channel=channel,
                    source=source,
                    disclosed_to=disclosed_to,
                    query=query,
                    query_digest=query_digest,
                    disclosed_at=disclosed_at,
                    send_policy_version=send_policy_version,
                )
                for (
                    channel,
                    source,
                    disclosed_to,
                    query,
                    query_digest,
                    disclosed_at,
                    send_policy_version,
                ) in rows
            )
        return tuple(ledger)


@dataclass(frozen=True)
class EmissionCounts:
    """One emission run's two numbers: what the store held, and what was produced.

    `concept/instruction.md` §7 requires produced-versus-materialised counts to
    reconcile, and the two here deliberately come from different sides of the
    wire:

    - `pending` from `helena_analytical_emission_counts` in the engine, read as
      the run started;
    - `emitted` from the run, counting messages the broker acknowledged — `flush`
      raises for anything it did not, so this is deliveries and not attempts.

    `emitted > pending` is refused rather than reported. It cannot happen in a
    run that emits `SinkStore.terminal()` once each, so it means a message was
    produced twice inside one run — which is the producer's half of *"exactly
    once per terminal outcome"* failing, and the one duplicate the at-least-once
    contract does not cover, because a consumer deduplicating across runs would
    not be looking within one.

    `emitted < pending` is reported and not raised, through `complete`. It is a
    real and ordinary state: a pass that landed after `terminal()` was read is a
    message this run did not emit and the next one will.
    """

    pending: int
    emitted: int

    def __post_init__(self) -> None:
        if self.emitted > self.pending:
            raise SinkError(
                f"{self.emitted} message(s) were emitted and the engine held "
                f"{self.pending}; a run emits each terminal outcome once, so a "
                f"number larger than the store's is a message produced twice "
                f"within one run rather than the repeat a consumer deduplicates"
            )

    @property
    def complete(self) -> bool:
        """Whether every message the store held reached the broker."""
        return self.emitted == self.pending


def emit(
    *, store: SinkStore, producer: BrokerProducer, topic: str
) -> EmissionCounts:
    """Emit every terminal outcome this identity holds. At-least-once.

    `concept/03`: *"Every assessed context is emitted, exactly once per terminal
    outcome — including `normal` verdicts and typed failures. A context that was
    escalated is emitted once, carrying the analyst's verdict and the triage
    decision that led to it. Delivery is at-least-once, so consumers
    deduplicate; exactly-once is not attempted."*

    The three halves of that sentence are three different mechanisms and only one
    of them is here. *One per terminal outcome* is `SINK_VIEW`'s own selection,
    read through `SinkStore.terminal`: the analyst row where a pass escalated and
    the triage row otherwise, so a `normal`, a `suspicious` and a typed failure
    are each one message and an escalated context is one message under the
    analyst's identifier. *Carrying the triage decision* is `project`, which puts
    it in the `triage` object. What is here is the loop, the topic and the count.

    **`topic` is a parameter and there is no default.** It comes from
    `HELENA_OUTPUT_TOPIC` through `helena.config`, the way the address does, so
    that "replacing the broker is a configuration change" stays true of egress as
    well as ingress. Nothing in this module names a topic.

    **The topic is created before anything is published**, because the pinned
    broker accepts a publish to a topic that does not exist and then keeps the
    message in the local queue with no error at all (`helena.broker`,
    `docs/runbook.md` §3). Every message is then flushed before this returns, so
    a count it reports is a count the broker acknowledged.

    **Re-running emits the same messages again, and that is the contract.**
    Nothing is recorded about what was emitted (see the module head), so a second
    run produces every terminal outcome the store still holds. The consumer
    discards the repeat by `assessment_id`, which is stable across runs.

    Raises `BrokerError` if the broker refused anything, and `SinkError` if a
    message could not be assembled — neither is swallowed, because a message that
    did not go is a record the broker keeps nothing of.
    """
    if not topic:
        raise ConfigurationError(
            "the output topic is empty. It comes from HELENA_OUTPUT_TOPIC "
            "through helena.config and has no default; emitting to an unnamed "
            "topic is a run that publishes nothing and says it published."
        )
    # The list first and the count second, and the order is load-bearing. Both
    # are reads of a store that is still being written to, and a pass that lands
    # between them has to fall on the side the counters can describe: read this
    # way it raises `pending`, which `complete` reports as a message this run did
    # not emit. Read the other way round it would raise `emitted` above `pending`
    # and be refused as a double-emission that never happened.
    terminal = store.terminal()
    pending = store.pending()
    producer.create_topic(topic)
    for assessment_id in terminal:
        message = store.project(assessment_id)
        producer.publish(
            topic,
            message.model_dump_json().encode("utf-8"),
            {
                OUTPUT_HEADER_ASSESSMENT: assessment_id.encode("utf-8"),
                OUTPUT_HEADER_MESSAGE_VERSION: MESSAGE_VERSION.encode("utf-8"),
            },
        )
    producer.flush()
    return EmissionCounts(pending=pending, emitted=len(terminal))


def _one_run(rows: list[dict[str, Any]], identifier: str) -> dict[str, Any]:
    """The run columns, asserted identical across every row of the message.

    The view's grain is one row per entity per source, so the run columns repeat.
    Checking rather than taking the first is the cheap half of the duplication
    hazard this whole module is about: if the join ever fans a message across two
    runs, this is where it stops instead of on a consumer's desk.
    """
    first = {column: rows[0][column] for column in _RUN_COLUMNS}
    for row in rows[1:]:
        differing = sorted(
            column for column in _RUN_COLUMNS if row[column] != first[column]
        )
        if differing:
            raise SinkError(
                f"{SINK_VIEW} produced rows for {identifier!r} that disagree "
                f"about {differing}; one message is one terminal run, and a join "
                f"that fans it across two is a defect in the view rather than "
                f"something to emit"
            )
    return first


def _entities(rows: list[dict[str, Any]]) -> tuple[EmittedEntity, ...]:
    """The rows grouped into entities, each carrying its sources' answers.

    A row whose `entity_value` is NULL is the LEFT JOIN's own: the context holds
    no entities, or its version has moved on. It produces no entity rather than
    an entity with no name — `sql/migrations/0010` spent a whole migration on the
    difference and `context_resolved` is what says which of the two it was.
    """
    entities: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in rows:
        if row["entity_value"] is None:
            continue
        entities.setdefault((row["entity_type"], row["entity_value"]), []).append(row)
    return tuple(
        EmittedEntity(
            **{column: group[0][column] for column in _ENTITY_COLUMNS},
            evidence=tuple(
                EmittedEvidence(
                    source_id=row["source_id"],
                    status=row["status"],
                    classification=row["evidence_classification"],
                    evidence_id=row["evidence_id"],
                    source_tier=row["source_tier"],
                    evidence_tier=row["evidence_tier"],
                    snapshot_version=row["snapshot_version"],
                    snapshot_loaded_at=row["snapshot_loaded_at"],
                    taxonomy_version=row["evidence_taxonomy_version"],
                    confidence=row["evidence_confidence"],
                    scope_type=row["scope_type"],
                    scope_value=row["scope_value"],
                    first_seen=row["first_seen"],
                    last_seen=row["last_seen"],
                    native_evidence=row["native_evidence"],
                    port_matched=row["port_matched"],
                    cited_as=row["cited_as"],
                )
                for row in group
                if row["source_id"] is not None
            ),
        )
        for group in entities.values()
    )


def _triage(run: dict[str, Any]) -> TriageDecision | None:
    """The path, where there is one. `None` where triage is the terminal run."""
    if run["triage_assessment_id"] is None:
        return None
    return TriageDecision(
        assessment_id=run["triage_assessment_id"],
        trigger=run["triage_triggered_by"],
        outcome_kind=run["triage_outcome_kind"],
        verdict=run["triage_verdict"],
        classification=run["triage_classification"],
        confidence=run["triage_confidence"],
        failure_reason=run["triage_failure_reason"],
        failure_detail=run["triage_failure_detail"],
        assessed_at=run["triage_assessed_at"],
        model_version=run["triage_model_version"],
        prompt_version=run["triage_prompt_version"],
    )
