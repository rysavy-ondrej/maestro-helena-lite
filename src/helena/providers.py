"""Provider adapters — the half of a tool that speaks a provider's protocol.

`helena.tools.ProviderTool` owns everything that is the same for every provider:
the credential, the tenant scope, the budget, the send policy, the disclosure
record, the cache and the validation against the declared subset. What it does
not own is the wire, and this module is the wire. The seam between them is one
callable:

    ask(call: ToolCall, credential: Secret) -> ProviderAnswer

## Why this is not inside `helena/tools.py`

Because the boundary's structural guarantee is asserted off that module's own
AST: `tests/test_tools.py` reads `tools.py` and fails if it imports HTTP
machinery or holds a `://` literal, which is the machine-checkable half of *"the
agent sees a tool, never an HTTP client and never a key"*. A URL in that file to
save this one would have deleted the property rather than kept the code together.
`docs/decisions/0028-the-threatfox-hunting-api.md` §10 records the decision.

## The one provider here, and what was measured about it

ThreatFox's hunting API — `POST https://threatfox-api.abuse.ch/api/v1/`, JSON in
and JSON out, authenticated with an `Auth-Key` **header**. ADR-0028 is the source
record and every shape below is measured against the live service on 2026-09-10
rather than read off the documentation page. Four of those measurements are
load-bearing enough to repeat here, because each is a defect if assumed:

| | |
| --- | --- |
| **HTTP 200 for every application error** | the status says nothing; `query_status` does. `data` is a **list** on `ok` and a **string** on `no_result`, so a reader that indexes it without branching crashes on the common case |
| **`exact_match` cannot be used for an address** | ThreatFox stores `ip:port` and has no bare-`ip` indicator type at all, so `exact_match: true` on an address is always `no_result`. The address path uses the wildcard |
| **the wildcard is not a substring search, and it crosses entity types** | it returned a `url` record for an address query and 1 386 records for `workers.dev`, while a strict prefix of a listed `ip:port` matched nothing. So **a wildcard result is a set of candidates, not a set of matches**, and every one is checked against the asked indicator and entity type before it becomes a claim |
| **the exact match is case-insensitive but rejects a trailing root dot** | `fuwabo.workers.dev.` is `no_result`. That is a spelling DNS traffic legitimately produces, so what is sent is the **normalized** indicator — otherwise the layer caches a `no_match` that is simply wrong |

## What a dropped candidate costs, and where it is visible

A record the wildcard returned that is about something else is **not** discarded
silently. Every claim carries `records_returned` and `records_out_of_scope` in its
native evidence, and a response whose every record was out of scope answers
`no_match` — an answer, with the count saying the provider was not silent. The
whole response is stored by the tool layer before it is evaluated (`concept/05`
rule 5), so nothing that arrived is lost.

The reason to drop them at all is `concept/02`'s scope-before-severity: a URL
listing on an address is a claim about that URL, and reporting it as a claim about
the address would say the host was contacted at a listed location when it was not.

## The mapping is the loader's, not a second one

An API record is translated into the export's own `helena.enrichment.ThreatFoxEntry`
shape and pushed through the *same* `split_indicator` and `classify_threat_type`
the bulk loader uses. `concept/05` puts one publisher in both tiers and says
evidence tiering "keeps the two comparable"; one mapping is what makes that true
of the code. The field names differ between the two surfaces in five ways
(ADR-0028 §4) and the translation is where that lives.

## Typed errors, and the two different kinds of slow

`concept/05` rule 4: a failure is a typed error and no taxonomy object. Every
branch below raises `helena.tools.ProviderQueryFailed` carrying one of
`helena.enrichment.QUERY_FAILURE_REASONS`, and none of them is `no_match`.

The adapter's read timeout ends one **request**; `helena.budgets.RunBudget`'s
wall clock ends the **run**, charged on the same ledger as the model calls. A
request that outlives the first is `timeout`; a run that outlives the second is a
`budget_exhausted` refusal at the tool boundary and never a failure here, because
nothing was queried.

**A provider's response body never reaches a failure detail.** It is text the
provider chose, and `concept/instruction.md` §6 makes retrieved provider text
data rather than diagnostics: the status and the exception class go into the
typed error, the bytes go to the store.

## Deliberately not here

- **Pacing.** `config/policy.toml`'s `[rate_limits] threatfox = 4` is read to
  derive the live-query budget and nothing sleeps between calls. This module is
  the only thing that knows a request left the process, so a throttle belongs
  here when one is built; until then the wall-clock budget charges the wait.
- **The publisher's false-positive list.** Measured absent from both the API and
  the export (ADR-0028 §8). The design for how one would enter — a claim is never
  deleted, suppression is a second claim under explicit policy, and a suppressed
  match is still recorded as having matched — is written down there and the code
  is not, because writing it would mean inventing the artifact it consumes.
- **A second provider.** VirusTotal is deferred by `concept/05` with a narrow
  role and a shared daily quota, and an adapter for it would be an abstraction
  with one user today.

Reads: `helena.disclosure.SourcePermission` (the host, from policy),
`helena.enrichment` (the registry and the loader's mapping), `helena.tools` (the
seam and the indicator fold). Writes: nothing — the tool layer stores.

Maturity: experimental — the surface is confirmed against the live service and
the adapter is exercised against it, but no agent has driven a tool loop through
it and no verdict from it has been evaluated.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from helena.config import Secret
from helena.disclosure import SendPolicy, SourcePermission
from helena.enrichment import (
    AUTH_FAILED,
    MALFORMED_RESPONSE,
    NO_MATCH,
    QUOTA_EXHAUSTED,
    THREATFOX_SOURCE,
    TIMEOUT,
    TRANSPORT_ERROR,
    ThreatFoxEntry,
    ThreatFoxError,
    classify_threat_type,
    source,
    split_indicator,
)
from helena.observability import Redactor, StructuredLogger
from helena.tools import (
    EvidenceCache,
    ProviderAnswer,
    ProviderClaim,
    ProviderQueryFailed,
    ProviderTool,
    ToolCall,
    normalize_indicator,
)

__all__ = [
    "API_PATH",
    "AUTH_HEADER",
    "EXACT_MATCH_ENTITY_TYPES",
    "NO_RESULT",
    "QUERY_OK",
    "SEARCH_IOC",
    "ThreatFoxHuntingAPI",
    "threatfox_tool",
    "threatfox_url",
]

#: The endpoint name, and it is the **provider's own operation name** rather than
#: a label this project invented. It reaches two places that outlive this module:
#: the tool the model is offered (`lookup_threatfox_search_ioc`) and the cache
#: key, which is per source *and* per endpoint because "two operations of one
#: provider answer different questions about one indicator". A logical name for
#: an operation that does not exist would make both of those lie.
SEARCH_IOC = "search_ioc"

#: The only scheme this project talks to a provider over. Not configurable: the
#: one wrong setting sends a credential in clear text, and a policy file that
#: could express it would be a policy file that could get it wrong.
SCHEME = "https"

#: The one path every operation goes to. Not a per-operation path: the operation
#: is the `query` key of the JSON body, which is why the tool's `endpoint` above
#: is a name and not a route.
API_PATH = "/api/v1/"

#: Where the credential travels. `concept/05` and the 2026-09-03 correction it
#: carries: a header, never the path. Measured again on 2026-09-10 — 401 without
#: it, 200 with it.
AUTH_HEADER = "Auth-Key"

#: The two `query_status` values that are answers. Everything else is a typed
#: failure; `helena.enrichment`'s five reasons are the vocabulary.
QUERY_OK = "ok"
NO_RESULT = "no_result"

#: `query_status` values that mean the credential, not the query. 401 carries no
#: `query_status` at all and 403 carries `unknown_auth_key` with no `data`, so
#: both shapes are handled and both mean `auth_failed`.
AUTH_STATUSES = frozenset({"unknown_auth_key", "illegal_auth_key"})

#: Which entity types may be asked with `exact_match: true`.
#:
#: **`address` is absent and that is a measurement, not an omission.** ThreatFox
#: has no bare-`ip` indicator type — `{"query": "types"}` returns `ip:port`,
#: `domain`, `url` and four hash types and nothing else — so an exact match on an
#: address can never hit, and it did not: `45.192.105.203` with `exact_match:
#: true` answered `no_result` while the same term without it returned
#: `45.192.105.203:8000`. The wildcard is what an address lookup has, and
#: `_in_scope` below is the price of using it.
EXACT_MATCH_ENTITY_TYPES = frozenset({"domain", "url"})

#: The `ioc_type` a record must carry to be a claim about each asked entity type.
#: The address row is the `ip:port` fact again, from the other direction, and it
#: is what keeps a URL record that merely *contains* the address out of the
#: address's claims (ADR-0028 §3).
IOC_TYPE_FOR_ENTITY = {"address": "ip:port", "domain": "domain", "url": "url"}

#: How the API spells a timestamp. The bulk export's `first_seen_utc` is
#: `"2026-09-02 06:10:15"`; the API's `first_seen` is the same instant with a
#: `" UTC"` suffix, which `datetime.fromisoformat` will not read.
UTC_SUFFIX = " UTC"


class ProviderConfigurationError(RuntimeError):
    """This deployment wired an adapter wrong. Never a provider's fault.

    Its own class rather than a `ProviderQueryFailed`: a URL pointing somewhere
    the send policy does not permit is a misconfiguration that must stop the
    process, and dressing it as a transport failure would record an outage that
    did not happen and let the run continue talking to the wrong host.
    """


def threatfox_url(permit: SourcePermission) -> str:
    """The URL this deployment's ThreatFox requests go to, built from policy.

    **The host is `config/policy.toml`'s and the path is this module's.**
    `concept/07` requires a credential travelling in a URL to be redacted before
    anything is logged or stored, and the safest version of that rule is that the
    policy file holds no URL at all — so it holds a bare host, the tool layer
    holds none, and the one place a URL is assembled is here.

    `https` is not configurable. A scheme in the policy file would be a knob whose
    only wrong setting sends a credential in clear text.

    Composed with `urlunsplit` rather than by formatting, and that is not a style
    choice: `tests/test_broker.py` sweeps every module in the package for an
    address-shaped literal, a scheme-and-slashes pattern among them, because such
    a literal is the fallback that makes "replacing the broker is a configuration
    change" quietly false. The rule is worth keeping whole, and a URL assembled
    from its parts does not need an exception to it.
    """
    if permit.source_id != THREATFOX_SOURCE:
        raise ProviderConfigurationError(
            f"this URL is ThreatFox's and the permission is "
            f"{permit.source_id!r}'s; a source's host is not another source's"
        )
    return urlunsplit((SCHEME, permit.disclosed_to, API_PATH, "", ""))


class ThreatFoxHuntingAPI:
    """One `search_ioc` call: the request this project may send, and the mapping back.

    Constructed with the URL rather than with the host, so that the check below is
    possible at all: the adapter **refuses to be built pointing anywhere the send
    policy does not permit**. `docs/decisions/0027-disclosure-and-the-send-policy.md`
    §6 deferred exactly this — "verifying that an adapter speaks to `disclosed_to`
    … becomes checkable when a live adapter exists" — and this is the check.

    `timeout_seconds` has no default. It bounds one request and the run's wall
    clock bounds the analysis (see the module docstring); a defaulted request
    timeout is the silent configuration `concept/instruction.md` §6 names, and it
    would be invisible in exactly the deployment where a provider went slow.
    """

    __slots__ = ("_url", "_permit", "_logger", "_timeout")

    def __init__(
        self,
        *,
        url: str,
        permit: SourcePermission,
        logger: StructuredLogger,
        timeout_seconds: float,
    ) -> None:
        if permit.source_id != THREATFOX_SOURCE:
            raise ProviderConfigurationError(
                f"this adapter is ThreatFox's and the permission is "
                f"{permit.source_id!r}'s"
            )
        host = urlsplit(url).hostname
        if host != permit.disclosed_to:
            raise ProviderConfigurationError(
                f"the send policy permits disclosing to "
                f"{permit.disclosed_to!r} and this adapter is pointed at "
                f"{host!r}; the record of what was disclosed would name a host "
                f"nothing was sent to"
            )
        if not isinstance(timeout_seconds, (int, float)) or timeout_seconds <= 0:
            raise ProviderConfigurationError(
                f"the request timeout is {timeout_seconds!r}; it bounds one "
                f"request and has no default"
            )
        self._url = url
        self._permit = permit
        self._logger = logger
        self._timeout = float(timeout_seconds)

    def __repr__(self) -> str:
        return f"ThreatFoxHuntingAPI({self._permit.disclosed_to!r})"

    @property
    def host(self) -> str:
        """The host this adapter speaks to. What the disclosure record names."""
        return self._permit.disclosed_to

    def __call__(self, call: ToolCall, credential: Secret) -> ProviderAnswer:
        """Ask about one indicator. A `ProviderAnswer`, or a `ProviderQueryFailed`.

        Never returns an empty answer: a provider that lists nothing has answered,
        and the answer is a `no_match` claim (`concept/02`). `ProviderAnswer`
        refuses the empty tuple, which is that rule enforced rather than
        remembered.
        """
        indicator = normalize_indicator(call.entity_type, call.entity_value)
        body = self._request_body(call.entity_type, indicator)
        raw = self._post(body, credential, call)
        document = self._document(raw)
        status = document.get("query_status")
        if status in AUTH_STATUSES:
            raise ProviderQueryFailed(AUTH_FAILED, f"query_status {status}")
        if status == NO_RESULT:
            return ProviderAnswer(
                body=raw, claims=(self._absent(call, indicator, returned=0, dropped=0),)
            )
        if status != QUERY_OK:
            # `missing_search_term`, `unknown_operation`, and anything the
            # publisher adds later. The value is a closed vocabulary this project
            # does not own, so an unrecognised one is the response failing to be
            # what this adapter was written against -- not a claim, and not an
            # absence.
            raise ProviderQueryFailed(
                MALFORMED_RESPONSE, f"query_status {status!r}"
            )
        records = document.get("data")
        if not isinstance(records, list):
            raise ProviderQueryFailed(
                MALFORMED_RESPONSE,
                f"query_status is {QUERY_OK!r} and data is a "
                f"{type(records).__name__}, not a list",
            )
        return self._answer(call, indicator, raw, records)

    # --- The request ----------------------------------------------------------

    def _request_body(self, entity_type: str, indicator: str) -> dict[str, Any]:
        """The JSON body. The indicator, the operation, and nothing about the case.

        No tenant, no sensor, no monitored host, no window — which is
        `config/policy.toml`'s `fields = ["entity_type", "entity_value"]` as a
        structural property rather than a promise, because the `ToolCall` is the
        only object this adapter is given.

        `exact_match` is set for the entity types it can work for and omitted for
        `address`; `EXACT_MATCH_ENTITY_TYPES` carries the measurement.
        """
        body: dict[str, Any] = {"query": SEARCH_IOC, "search_term": indicator}
        if entity_type in EXACT_MATCH_ENTITY_TYPES:
            body["exact_match"] = True
        return body

    def _post(self, body: Mapping[str, Any], credential: Secret, call: ToolCall) -> bytes:
        """The request, and every way it can fail, as one of five typed reasons."""
        request = urllib.request.Request(
            self._url,
            data=json.dumps(body).encode(),
            headers={
                # The one place this key is revealed, and it is a header. A
                # credential in the path is what `concept/05`'s 2026-09-03
                # correction is about, and what the export's newer `/v2/files/`
                # surface still does -- see ADR-0028 §9.
                AUTH_HEADER: credential.reveal(),
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )
        # The indicator is not logged. It is the thing the disclosure ledger
        # records under policy, and a local log line is not that record.
        self._logger.outbound_request(
            "providers.threatfox.query",
            method="POST",
            url=self._url,
            source_id=THREATFOX_SOURCE,
            endpoint=SEARCH_IOC,
            entity_type=call.entity_type,
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:
                return response.read()
        except urllib.error.HTTPError as refused:
            self._logger.exception(
                "providers.threatfox.refused", refused, source_id=THREATFOX_SOURCE
            )
            status = refused.code
            # An `HTTPError` is also an open response, and it stays open for as
            # long as the exception it is chained to. Closing it here rather than
            # leaving it to the collector keeps a failing provider from leaking a
            # socket per call -- which is the failure mode a run full of
            # `transport_error`s would produce.
            refused.close()
            raise ProviderQueryFailed(
                self._reason_for(status), f"HTTP {status}"
            ) from refused
        except (TimeoutError, urllib.error.URLError, OSError) as unreachable:
            self._logger.exception(
                "providers.threatfox.unreachable",
                unreachable,
                source_id=THREATFOX_SOURCE,
            )
            reason = TIMEOUT if _is_timeout(unreachable) else TRANSPORT_ERROR
            raise ProviderQueryFailed(
                reason, type(unreachable).__name__
            ) from unreachable

    @staticmethod
    def _reason_for(status: int) -> str:
        """An HTTP status as one of the five typed reasons.

        401 and 403 are the two authentication shapes measured (ADR-0028 §2) and
        they are `auth_failed` rather than `transport_error`: a key that stopped
        working is not an outage, and a deployment that cannot tell them apart
        retries against a service that will never answer.
        """
        if status in (401, 403):
            return AUTH_FAILED
        if status == 429:
            return QUOTA_EXHAUSTED
        return TRANSPORT_ERROR

    @staticmethod
    def _document(raw: bytes) -> Mapping[str, Any]:
        """The body as an object, or `malformed_response` naming the shape.

        Not the exception's text and not the body's: a decoder error carries the
        offending bytes, and those are the provider's text.
        """
        try:
            document = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as unreadable:
            raise ProviderQueryFailed(
                MALFORMED_RESPONSE, f"the response is not JSON: "
                f"{type(unreadable).__name__}"
            ) from unreadable
        if not isinstance(document, dict):
            raise ProviderQueryFailed(
                MALFORMED_RESPONSE,
                f"the response is a {type(document).__name__} and the envelope "
                f"is an object with a query_status",
            )
        return document

    # --- The mapping ----------------------------------------------------------

    def _answer(
        self,
        call: ToolCall,
        indicator: str,
        raw: bytes,
        records: Sequence[Any],
    ) -> ProviderAnswer:
        """The records that are about what was asked, as claims. The rest, as a count.

        `concept/05` rules 2 and 3 -- map deterministically, emit the parent
        rather than guessing a child -- are `classify_threat_type`'s and are not
        re-implemented here.
        """
        selected: list[ThreatFoxEntry] = []
        for record in records:
            if not isinstance(record, dict):
                raise ProviderQueryFailed(
                    MALFORMED_RESPONSE,
                    f"a data entry is a {type(record).__name__}, not an object",
                )
            entry = _entry(record)
            if self._in_scope(call.entity_type, indicator, entry):
                selected.append(entry)
        # Counted before any claim is built, so every claim of one answer carries
        # the same two numbers and a reader can tell what a claim was selected out
        # of without holding the response.
        returned, dropped = len(records), len(records) - len(selected)
        if not selected:
            # Every candidate was about something else. That is an answer and not
            # an absence of one -- the provider was not silent -- so the count
            # travels on the `no_match` claim rather than being lost with the
            # records.
            return ProviderAnswer(
                body=raw,
                claims=(
                    self._absent(call, indicator, returned=returned, dropped=dropped),
                ),
            )
        return ProviderAnswer(
            body=raw,
            claims=tuple(
                self._claim(entry, returned=returned, dropped=dropped)
                for entry in selected
            ),
        )

    @staticmethod
    def _in_scope(entity_type: str, indicator: str, entry: ThreatFoxEntry) -> bool:
        """Whether this record is a claim about the indicator that was asked.

        Two conditions and both are needed. The `ioc_type` must be the one that
        carries this entity type -- a `url` record is not an `address` claim -- and
        the record's own indicator, split the way the loader splits it, must be
        the value that was asked. The wildcard returns neighbours (ADR-0028 §3)
        and a neighbour is a different entity.
        """
        if entry.ioc_type != IOC_TYPE_FOR_ENTITY.get(entity_type):
            return False
        try:
            _, value, _port = split_indicator(entry)
        except (KeyError, ThreatFoxError):
            # An `ip:port` whose value does not split, or an `ioc_type` with no
            # HELENA entity. Neither is a claim about what was asked; the record
            # is still in the stored response.
            return False
        return normalize_indicator(entity_type, value) == indicator

    @staticmethod
    def _claim(
        entry: ThreatFoxEntry, *, returned: int, dropped: int
    ) -> ProviderClaim:
        """One record as one claim, through the loader's own mapping.

        The scope is `sql/migrations/0014_feed_mapping_views.sql`'s rule and not a
        second one: for an `ip:port` indicator the claim is about the address **on
        that port**, so `scope_type` is `address:port` and the entity it attaches
        to is still the address. `concept/05`: the port qualifies the match and is
        not discarded.
        """
        entity_type, value, port = split_indicator(entry)
        path, seen = classify_threat_type(entry.threat_type)
        scope_type = "address:port" if port is not None else entity_type
        scope_value = f"{value}:{port}" if port is not None else value
        evidence: dict[str, Any] = {
            "threat_type": entry.threat_type,
            "threat_type_seen_by_mapping": seen,
            # `concept/05`: a compromised legitimate host is a different claim
            # about the contacted party than attacker-owned infrastructure, so the
            # flag is native evidence and never the classification.
            "is_compromised": entry.is_compromised,
            "malware": entry.native.get("malware"),
            "malware_printable": entry.native.get("malware_printable"),
            "reporter": entry.native.get("reporter"),
            "reference": entry.native.get("reference"),
            "tags": list(entry.tags),
            "indicator_id": entry.indicator_id,
            "port": port,
            # The two fields the enrichment tier has no equivalent of. The first
            # is the only genuinely new information this surface carries
            # (ADR-0028 §7); the second is how many candidates the wildcard
            # returned, so a claim says what it was selected out of.
            "sightings": entry.native.get("sightings"),
            "records_returned": returned,
            "records_out_of_scope": dropped,
        }
        return ProviderClaim(
            path=path,
            scope_type=scope_type,
            scope_value=scope_value,
            native_record=entry.indicator_id,
            # 0-100 there, 0.0-1.0 here: a change of unit and not of meaning, and
            # the same one migration 0014 applies. `concept/05`: confidence "must
            # reach the claim rather than being flattened away".
            confidence=entry.confidence_level / 100,
            first_seen=_moment(entry.first_seen_utc),
            last_seen=_moment(entry.last_seen_utc),
            native_evidence=evidence,
        )

    @staticmethod
    def _absent(
        call: ToolCall, indicator: str, *, returned: int, dropped: int
    ) -> ProviderClaim:
        """The provider answered and lists nothing about this indicator.

        `concept/02`: *"a lookup outcome, never a statement of safety."* The two
        counts distinguish the two ways it happens -- the provider returned
        nothing, or it returned only records about other entities -- which the
        classification alone cannot.
        """
        return ProviderClaim(
            path=NO_MATCH,
            scope_type=call.entity_type,
            scope_value=indicator,
            # A stable native record for a record that does not exist. The
            # evidence digest needs one and there is no publisher identifier to
            # use, so it names the operation that produced the absence.
            native_record=f"{SEARCH_IOC}:{NO_MATCH}",
            native_evidence={
                "records_returned": returned,
                "records_out_of_scope": dropped,
            },
        )


def threatfox_tool(
    *,
    credential: Secret,
    cache: EvidenceCache,
    send_policy: SendPolicy,
    logger: StructuredLogger,
    redactor: Redactor,
    timeout_seconds: float,
) -> ProviderTool:
    """The live ThreatFox lookup tool, wired from the registry and the send policy.

    Everything provider-specific is derived rather than passed:

    | | |
    | --- | --- |
    | the host | `send_policy.permit('threatfox').disclosed_to`, and the adapter refuses any other |
    | the endpoint | `search_ioc`, the provider's own operation name |
    | the retention | `SourceDescriptor.refresh_interval_seconds` — the publisher's own fetch floor, 3 600 s |

    **The retention is derived and it is a candidate.** An answer stays valid for
    as long as this deployment would be willing to ask the source again, which is
    a rule rather than a number somebody picked; but no hit rate and no staleness
    cost has been measured, `concept/08` still lists the retention horizon as
    open, and ADR-0028 §10 records it on the same footing as `config/policy.toml`'s
    0.80.
    """
    descriptor = source(THREATFOX_SOURCE)
    permit = send_policy.permit(THREATFOX_SOURCE)
    retention = descriptor.refresh_interval_seconds
    if retention is None:  # pragma: no cover — the descriptor states 3 600 s
        raise ProviderConfigurationError(
            f"{THREATFOX_SOURCE} has no refresh interval to derive a cache "
            f"retention from, and a default here would be one nobody chose"
        )
    return ProviderTool(
        source_id=THREATFOX_SOURCE,
        endpoint=SEARCH_IOC,
        credential=credential,
        ask=ThreatFoxHuntingAPI(
            url=threatfox_url(permit),
            permit=permit,
            logger=logger,
            timeout_seconds=timeout_seconds,
        ),
        cache=cache,
        retention_seconds=retention,
        send_policy=send_policy,
        logger=logger,
        redactor=redactor,
    )


def _entry(record: Mapping[str, Any]) -> ThreatFoxEntry:
    """One API record in the bulk export's own entry shape.

    The translation is the whole of what differs between the two surfaces, and it
    is five renames rather than a second mapping (ADR-0028 §4): `ioc` for
    `ioc_value`, `first_seen`/`last_seen` for the `_utc` pair and with a `" UTC"`
    suffix to strip, `tags` as an **array** rather than a comma-separated string,
    and the indicator id as a field rather than as the object key the export
    groups by.

    `record_offset` is 0 because the API's `data` is a flat list: there is no
    per-id grouping to be an offset within, and the id is unique in it.
    """
    try:
        ioc = record["ioc"]
        ioc_type = record["ioc_type"]
        threat_type = record["threat_type"]
        confidence = record["confidence_level"]
        indicator_id = record["id"]
    except KeyError as missing:
        raise ProviderQueryFailed(
            MALFORMED_RESPONSE,
            f"a record has no {missing.args[0]!r}; the publisher's format has "
            f"changed",
        ) from missing
    if not isinstance(confidence, int) or isinstance(confidence, bool):
        raise ProviderQueryFailed(
            MALFORMED_RESPONSE,
            f"confidence_level is a {type(confidence).__name__}, not an integer",
        )
    tags = record.get("tags")
    if tags is not None and not isinstance(tags, list):
        raise ProviderQueryFailed(
            MALFORMED_RESPONSE,
            f"tags is a {type(tags).__name__}; on this surface it is an array "
            f"or null, and the comma-separated string is the bulk export's",
        )
    return ThreatFoxEntry(
        indicator_id=str(indicator_id),
        record_offset=0,
        ioc_type=str(ioc_type),
        ioc_value=str(ioc),
        threat_type=str(threat_type),
        confidence_level=confidence,
        is_compromised=bool(record.get("is_compromised")),
        first_seen_utc=_without_suffix(record.get("first_seen")),
        last_seen_utc=_without_suffix(record.get("last_seen")),
        tags=tuple(str(tag) for tag in (tags or ())),
        native=dict(record),
    )


def _without_suffix(value: Any) -> str | None:
    """`"2026-09-02 06:10:15 UTC"` as the export spells it, or `None`.

    Absent stays absent -- `concept/05`: do not invent missing precision, and
    `last_seen` is null on most of this feed.
    """
    if not value:
        return None
    return str(value).removesuffix(UTC_SUFFIX).strip() or None


def _moment(value: str | None) -> datetime | None:
    """A feed timestamp as an aware UTC datetime, or `None` if it is absent.

    A value that will not parse is `malformed_response` rather than a silently
    dropped time: `concept/05` makes first-seen plus the snapshot version what
    dates a claim, so a claim with a first-seen the adapter could not read is a
    claim whose age nothing knows.
    """
    if value is None:
        return None
    try:
        return datetime.fromisoformat(value).replace(tzinfo=timezone.utc)
    except ValueError as unreadable:
        raise ProviderQueryFailed(
            MALFORMED_RESPONSE, f"a timestamp will not parse: {unreadable}"
        ) from unreadable


def _is_timeout(failure: BaseException) -> bool:
    """A read timeout, whichever of the two shapes `urllib` raises it in.

    The same two shapes `helena.agents` handles, and for the same reason: a
    timeout arrives either directly or wrapped in a `URLError`, and collapsing it
    into `transport_error` would lose the distinction `concept/05` rule 4 is
    about.
    """
    if isinstance(failure, TimeoutError):
        return True
    return isinstance(getattr(failure, "reason", None), TimeoutError)
