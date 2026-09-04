"""Observability — local structured logs, with credential redaction on the way out.

**Local structured logs only. No hosted tracing.** The reason is not ergonomic:
a hosted tracer is a *second egress channel* carrying prompts, rendered context
and retrieved provider text, and it would need its own send policy, its own
disclosure record and a second vendor's data-handling terms
(`concept/07-principles.md`, "Observability"). The audit record is the stored
assessment, not a trace UI. `tests/test_dependency_boundary.py` keeps the tracing
SDKs out by test rather than by good intentions.

Every record is one JSON object on one line of **stderr** — stdout carries data,
so it may not carry logs — with the same ten top-level keys every time
(`STRUCTURED_LOG_FIELDS`), and anything the caller adds nested under `fields` so
that the stable set cannot be shadowed. `tenant` and `sensor` come from
`Settings`; there is no default and no logger without an identity, because a
defaulted tenant is an isolation failure that looks like it is working.

**Redaction happens at the emitter, not at the call site.** A call site that
remembers to redact is a call site that will one day forget, so:

1. every string a caller passes is redacted before it is serialized — registered
   secret values are replaced, and any URL embedded in the string is stripped
   structurally;
2. `outbound_request` and `exception` route the request URL through
   `Redactor.url` explicitly, because a credential that reaches a URL reaches
   proxy logs, shell history and *exceptions carrying the request URL*. This is
   a rule about the exposure channel, not about one provider: the abuse.ch key
   travels in an `Auth-Key` header and its bulk export needs no credential at all
   (measured 2026-09-03, `concept/05-threat-intelligence.md`);
3. the serialized line is swept for registered secret values one last time before
   it is written, so a value that arrived by a route none of the above covers
   still does not reach the stream.

Verified rather than assumed: `urllib.error.HTTPError.url` carries the full
request URL including a path-embedded key, while `str(exception)` does not. An
exception logged by its attributes leaks; one logged by its message does not.
Both are redacted here.

`Redactor.url` is not only for logs. A loader records the URL it fetched as
provenance, and that row goes through the same helper before it is stored.

Reads: `Settings` (for the identity and the secret values it must never emit).
Writes: `sys.stderr`, one JSON object per line.

Maturity: experimental — exercised by the test suite, including against a real
`urllib` exception from a real HTTP request. No deployment has run against it,
and no pipeline stage logs through it yet: this increment builds the channel, the
stages that use it come later.
"""

from __future__ import annotations

import json
import re
import sys
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from typing import Any, TextIO
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit, urlunsplit

from pydantic import BaseModel

from helena.config import REDACTED, Secret, Settings

__all__ = [
    "CREDENTIAL_QUERY_PARAMETERS",
    "LEVELS",
    "STRUCTURED_LOG_FIELDS",
    "Redactor",
    "StructuredLogger",
    "logger",
]

# The top-level keys of every record, in order. A caller's own fields go under
# `fields`, so this set is fixed and a caller cannot shadow `tenant`.
#
#   event       what happened, a dotted name from the emitting component
#   event_id    the normalizer-assigned identity of a flow event, when the record
#               is about one — not the same thing as `event`
#   context_id  the identity of a host context, when the record is about one
#   versions    the version set of whatever is being reported, or null
STRUCTURED_LOG_FIELDS = (
    "timestamp",
    "level",
    "component",
    "event",
    "tenant",
    "sensor",
    "event_id",
    "context_id",
    "versions",
    "fields",
)

LEVELS = ("info", "warning", "error")

# Query parameter names whose value is redacted whatever it is. Over-redacting a
# query parameter costs a diagnostic; under-redacting one costs a credential.
CREDENTIAL_QUERY_PARAMETERS = frozenset(
    {
        "access-token",
        "access_token",
        "api-key",
        "api_key",
        "apikey",
        "auth",
        "auth-key",
        "auth_key",
        "authkey",
        "authorization",
        "key",
        "passwd",
        "password",
        "pwd",
        "secret",
        "sig",
        "signature",
        "token",
    }
)

# A URL embedded in a longer string — an exception message, a caller's note. The
# character class stops at whitespace and at the quoting characters a URL cannot
# carry unescaped, so a match is the URL and not the sentence around it.
_EMBEDDED_URL = re.compile(r"[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s\"'<>\\)\]}]+")

# Attributes an exception uses to carry the URL of the request that failed.
# `urllib.error.HTTPError` sets both; a bare `URLError` sets neither, which is
# why the message is redacted as well.
_URL_ATTRIBUTES = ("url", "filename")


class Redactor:
    """Removes credentials from a string, a URL, or a whole serialized record.

    Two mechanisms, because neither alone is enough. **Registered values** —
    every `Secret` in `Settings` — are replaced wherever they appear, which is
    what covers a key travelling in a URL *path*, where nothing about the segment
    marks it as a credential. **Structural rules** strip URL userinfo and the
    values of credential-named query parameters, which is what covers a
    credential nobody registered.

    What it deliberately does not do is guess: a path segment that merely *looks*
    like a key is left alone. This project fetches URLs whose path segments are
    file hashes, and redacting one of those would destroy the provenance the
    fetch exists to record.
    """

    __slots__ = ("_values",)

    def __init__(self, secrets: Iterable[str]) -> None:
        values: set[str] = set()
        for secret in secrets:
            if not secret or not secret.strip():
                raise ValueError("a blank secret cannot be redacted; it matches everything")
            values.add(secret)
            values.add(quote(secret, safe=""))
        if not values:
            raise ValueError(
                "a Redactor with no registered secrets would silently redact "
                "nothing; build it with Redactor.from_settings(settings)"
            )
        # Longest first, so a secret that contains another is replaced whole.
        self._values = tuple(sorted(values, key=len, reverse=True))

    @classmethod
    def from_settings(cls, settings: Settings) -> Redactor:
        """Register every `Secret` the configuration holds.

        This is the one place in the package that calls `Secret.reveal()` for a
        reason other than using the credential: the values go into the redactor
        and never come out of it.
        """
        return cls(sorted(_secret_values(settings)))

    def text(self, value: str) -> str:
        """A string that may contain a secret, a URL, or both."""
        return self.sweep(_EMBEDDED_URL.sub(lambda match: self.url(match.group()), value))

    def url(self, url: str) -> str:
        """A string that is a URL: userinfo, credential query values, key paths.

        An unparseable URL is redacted whole rather than passed through — the
        result is visibly `***redacted***`, never a quietly leaked original.
        """
        try:
            parts = urlsplit(url)
        except ValueError:
            return REDACTED

        netloc = parts.netloc
        if "@" in netloc:
            netloc = f"{REDACTED}@{netloc.rsplit('@', 1)[1]}"

        path = "/".join(self._path_segment(segment) for segment in parts.path.split("/"))

        query = parts.query
        if query:
            query = urlencode(
                [
                    (name, self._query_value(name, value))
                    for name, value in parse_qsl(query, keep_blank_values=True)
                ],
                # `*` stays literal so the marker reads as `***redacted***` in a
                # log line rather than as three percent escapes.
                safe="*",
            )

        return self.sweep(urlunsplit((parts.scheme, netloc, path, query, parts.fragment)))

    def _path_segment(self, segment: str) -> str:
        """A path segment is redacted when it *is* a registered secret.

        The percent-decoded form is compared too, so a key that was quoted into
        the path is caught by structure rather than only by the literal sweep.
        """
        if segment and (segment in self._values or unquote(segment) in self._values):
            return REDACTED
        return segment

    def _query_value(self, name: str, value: str) -> str:
        return REDACTED if name.lower() in CREDENTIAL_QUERY_PARAMETERS else value

    def sweep(self, value: str) -> str:
        """Replace every registered secret value, and nothing else.

        Structure-blind on purpose, so it is safe to run over an already
        serialized record — which is where the emitter uses it, as the last
        thing that happens before a line reaches the stream.
        """
        for secret in self._values:
            value = value.replace(secret, REDACTED)
        return value


class StructuredLogger:
    """One component's log channel. One JSON object per line, redacted on write.

    Built by `logger()`; constructing one directly means supplying the identity
    and the redactor yourself, which is what the tests do.
    """

    __slots__ = ("_component", "_tenant", "_sensor", "_redactor", "_stream")

    def __init__(
        self,
        *,
        component: str,
        tenant: str,
        sensor: str,
        redactor: Redactor,
        stream: TextIO | None = None,
    ) -> None:
        self._component = _required("component", component)
        self._tenant = _required("tenant", tenant)
        self._sensor = _required("sensor", sensor)
        self._redactor = redactor
        self._stream = stream

    def info(self, event: str, **fields: Any) -> None:
        self._emit("info", event, fields)

    def warning(self, event: str, **fields: Any) -> None:
        self._emit("warning", event, fields)

    def error(self, event: str, **fields: Any) -> None:
        self._emit("error", event, fields)

    def outbound_request(self, event: str, *, method: str, url: str, **fields: Any) -> None:
        """The only way an outbound request is logged.

        The URL is redacted structurally here rather than by the caller, because
        the caller is the one holding the credential it just put in the path.
        """
        self._emit("info", event, {"method": method, "url": self._redactor.url(url), **fields})

    def exception(self, event: str, exception: BaseException, **fields: Any) -> None:
        """A failure, recorded as a typed row: what class, what message, what URL.

        The URL an exception carries is on an attribute, not in the message —
        `urllib.error.HTTPError.url` holds the whole request URL — so it is read
        out and redacted rather than left for whoever formats the traceback.
        """
        request_url = _request_url(exception)
        self._emit(
            "error",
            event,
            {
                "error_type": type(exception).__name__,
                "error": self._redactor.text(str(exception)),
                "error_url": None if request_url is None else self._redactor.url(request_url),
                **fields,
            },
        )

    def _emit(self, level: str, event: str, fields: Mapping[str, Any]) -> None:
        if level not in LEVELS:
            raise ValueError(f"level must be one of {LEVELS}, not {level!r}")

        extra = dict(fields)
        versions = extra.pop("versions", None)
        if versions is not None and not versions:
            raise ValueError(
                f"{event}: an empty version set is not a version set. Pass the "
                "versions the record cites, or omit the argument"
            )

        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": level,
            "component": self._component,
            "event": _required("event", event),
            "tenant": self._tenant,
            "sensor": self._sensor,
            "event_id": extra.pop("event_id", None),
            "context_id": extra.pop("context_id", None),
            "versions": None if versions is None else dict(versions),
            "fields": extra,
        }

        # Redact the values, then serialize, then sweep the line: the first pass
        # is structural and needs the values apart, the last one is the guarantee
        # that nothing reached the stream by a route the first pass did not know
        # about. A value that will not serialize raises here, before anything is
        # written — a repr'd object is exactly how something unredactable would
        # arrive in a log line.
        line = json.dumps(
            {key: self._redact(value) for key, value in record.items()},
            separators=(",", ":"),
            default=_unserializable,
        )
        stream = sys.stderr if self._stream is None else self._stream
        stream.write(self._redactor.sweep(line) + "\n")
        stream.flush()

    def _redact(self, value: Any) -> Any:
        if isinstance(value, Secret):
            return REDACTED
        if isinstance(value, str):
            return self._redactor.text(value)
        if isinstance(value, Mapping):
            return {self._redact(key): self._redact(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [self._redact(item) for item in value]
        return value


def logger(component: str, settings: Settings, *, stream: TextIO | None = None) -> StructuredLogger:
    """The logger for one component, carrying the deployment's identity."""
    return StructuredLogger(
        component=component,
        tenant=settings.identity.tenant,
        sensor=settings.identity.sensor,
        redactor=Redactor.from_settings(settings),
        stream=stream,
    )


def _required(name: str, value: str) -> str:
    """No blank identity anywhere in a record — the tenant least of all."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-blank string, not {value!r}")
    return value


def _secret_values(model: BaseModel) -> set[str]:
    """Every `Secret` in a settings tree, revealed once, for the redactor only."""
    values: set[str] = set()
    for name in type(model).model_fields:
        field = getattr(model, name)
        if isinstance(field, Secret):
            values.add(field.reveal())
        elif isinstance(field, BaseModel):
            values |= _secret_values(field)
    return values


def _request_url(exception: BaseException) -> str | None:
    for attribute in _URL_ATTRIBUTES:
        value = getattr(exception, attribute, None)
        if isinstance(value, str) and "://" in value:
            return value
    return None


def _unserializable(value: Any) -> Any:
    raise TypeError(
        f"a log field of type {type(value).__name__} is not JSON-serializable. "
        "Convert it at the call site; falling back to repr() is how an "
        "unredactable object reaches a log line"
    )
