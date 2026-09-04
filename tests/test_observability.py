"""Tests for helena.observability. Mirrors src/helena/observability.py.

Most of these use a fake key that is obviously not a credential, so that a
failure message is a nuisance and not an incident. Two tests use the real
`ABUSECH_AUTH_KEY` from the local `.env`, because a redactor that covers a
made-up value and not the configured one is a redactor that has not been tested.
Those two never assert on the value: they compute a boolean first and assert the
boolean with a fixed message, so pytest's assertion rewriting has no operand to
print.

The exception path is exercised against a real `urllib` request to a real HTTP
server on the loopback interface. `urllib.error.HTTPError` carries the request
URL on an attribute, which is the leak this module exists to close; a hand-built
exception would not prove that.
"""

from __future__ import annotations

import ast
import io
import json
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from helena.config import REDACTED, Secret, Settings
from helena.observability import (
    CREDENTIAL_QUERY_PARAMETERS,
    STRUCTURED_LOG_FIELDS,
    Redactor,
    StructuredLogger,
    logger,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PACKAGE_ROOT = PROJECT_ROOT / "src" / "helena"

# Not a credential. Long enough to be recognisable in an assertion message, and
# shaped like the abuse.ch key it stands in for: an opaque path segment.
FAKE_KEY = "fake-auth-key-0123456789abcdef"

# The shape the abuse.ch bulk export takes when the key travels in the path.
FEED_URL = f"https://threatfox.abuse.ch/export/{FAKE_KEY}/json/recent/"


@pytest.fixture
def stream() -> io.StringIO:
    return io.StringIO()


@pytest.fixture
def log(stream: io.StringIO) -> StructuredLogger:
    return StructuredLogger(
        component="enrichment",
        tenant="tenant-under-test",
        sensor="sensor-under-test",
        redactor=Redactor([FAKE_KEY]),
        stream=stream,
    )


def records(stream: io.StringIO) -> list[dict]:
    return [json.loads(line) for line in stream.getvalue().splitlines()]


def only(stream: io.StringIO) -> dict:
    written = records(stream)
    assert len(written) == 1, f"expected one record, got {len(written)}"
    return written[0]


# --- The record shape --------------------------------------------------------


def test_every_record_carries_exactly_the_stable_fields(log, stream):
    log.info("feed.fetch.started")
    assert tuple(only(stream)) == STRUCTURED_LOG_FIELDS


def test_the_stable_fields_carry_the_component_and_the_identity(log, stream):
    log.info("feed.fetch.started")
    record = only(stream)
    assert record["component"] == "enrichment"
    assert record["tenant"] == "tenant-under-test"
    assert record["sensor"] == "sensor-under-test"
    assert record["level"] == "info"
    assert record["event"] == "feed.fetch.started"


def test_a_callers_own_fields_are_nested_and_cannot_shadow_the_stable_ones(log, stream):
    log.info("feed.fetch.finished", tenant="not-the-tenant", rows=3375)
    record = only(stream)
    assert record["tenant"] == "tenant-under-test"
    assert record["fields"] == {"tenant": "not-the-tenant", "rows": 3375}


def test_the_pipeline_identities_are_null_when_the_record_is_not_about_one(log, stream):
    log.info("feed.fetch.started")
    record = only(stream)
    assert record["event_id"] is None
    assert record["context_id"] is None
    assert record["versions"] is None


def test_the_pipeline_identities_are_recorded_when_they_are_given(log, stream):
    log.info(
        "context.assessed",
        event_id="event-1",
        context_id="context-1",
        versions={"taxonomy": "1"},
    )
    record = only(stream)
    assert record["event_id"] == "event-1"
    assert record["context_id"] == "context-1"
    assert record["versions"] == {"taxonomy": "1"}
    assert record["fields"] == {}


def test_an_empty_version_set_is_refused_rather_than_recorded_as_one(log, stream):
    with pytest.raises(ValueError, match="not a version set"):
        log.info("context.assessed", versions={})
    assert stream.getvalue() == ""


def test_each_record_is_one_json_object_on_one_line(log, stream):
    log.info("feed.fetch.started")
    log.warning("feed.fetch.slow", seconds=31)
    log.error("feed.fetch.failed", status=503)
    assert [record["level"] for record in records(stream)] == ["info", "warning", "error"]


def test_the_timestamp_is_utc_and_parseable(log, stream):
    from datetime import datetime, timezone

    log.info("feed.fetch.started")
    parsed = datetime.fromisoformat(only(stream)["timestamp"])
    assert parsed.tzinfo is not None
    assert parsed.utcoffset() == timezone.utc.utcoffset(None)


# --- Fail loud ---------------------------------------------------------------


@pytest.mark.parametrize("blank", ["", " ", "\t\n"])
def test_a_logger_refuses_a_blank_identity(blank: str):
    with pytest.raises(ValueError, match="tenant"):
        StructuredLogger(
            component="enrichment",
            tenant=blank,
            sensor="sensor-under-test",
            redactor=Redactor([FAKE_KEY]),
        )


def test_a_record_refuses_a_blank_event_name(log, stream):
    with pytest.raises(ValueError, match="event"):
        log.info("  ")
    assert stream.getvalue() == ""


def test_a_redactor_with_no_secrets_is_refused(log):
    with pytest.raises(ValueError, match="no registered secrets"):
        Redactor([])


def test_a_blank_secret_is_refused_because_it_would_match_everything():
    with pytest.raises(ValueError, match="blank secret"):
        Redactor([FAKE_KEY, "  "])


def test_a_field_that_cannot_be_serialized_raises_instead_of_being_repred(log, stream):
    with pytest.raises(TypeError, match="not JSON-serializable"):
        log.info("feed.fetch.started", when=object())
    assert stream.getvalue() == ""


# --- Redaction: the known value ----------------------------------------------


def test_a_registered_secret_never_survives_a_field(log, stream):
    log.info("feed.fetch.started", note=f"fetching with key {FAKE_KEY} now")
    written = stream.getvalue()
    assert FAKE_KEY not in written
    assert REDACTED in written


def test_a_registered_secret_never_survives_a_nested_field(log, stream):
    log.info("feed.fetch.started", detail={"headers": [f"Auth-Key: {FAKE_KEY}"]})
    written = stream.getvalue()
    assert FAKE_KEY not in written
    assert only(stream)["fields"]["detail"]["headers"] == [f"Auth-Key: {REDACTED}"]


def test_a_secret_object_reaching_a_field_is_redacted_not_serialized(log, stream):
    log.info("feed.fetch.started", token=Secret(FAKE_KEY))
    assert FAKE_KEY not in stream.getvalue()
    assert only(stream)["fields"]["token"] == REDACTED


def test_a_registered_secret_never_survives_a_field_name(log, stream):
    log.info("feed.fetch.started", **{"detail": {FAKE_KEY: 1}})
    assert FAKE_KEY not in stream.getvalue()


# --- Redaction: URLs ---------------------------------------------------------


def test_a_key_in_a_path_segment_is_redacted_and_the_rest_of_the_url_survives():
    redacted = Redactor([FAKE_KEY]).url(FEED_URL)
    assert FAKE_KEY not in redacted
    assert redacted == f"https://threatfox.abuse.ch/export/{REDACTED}/json/recent/"


def test_a_percent_encoded_key_in_a_path_segment_is_redacted():
    key = "fake/auth+key with spaces"
    from urllib.parse import quote

    redacted = Redactor([key]).url(f"https://example.invalid/export/{quote(key, safe='')}/json")
    assert key not in redacted
    assert quote(key, safe="") not in redacted
    assert redacted == f"https://example.invalid/export/{REDACTED}/json"


def test_a_key_embedded_in_a_larger_path_segment_is_still_redacted():
    redacted = Redactor([FAKE_KEY]).url(f"https://example.invalid/export_{FAKE_KEY}.json")
    assert FAKE_KEY not in redacted
    assert REDACTED in redacted


def test_url_userinfo_is_stripped_even_when_the_credential_is_unknown():
    redacted = Redactor([FAKE_KEY]).url("https://someone:hunter2@example.invalid/feed")
    assert "hunter2" not in redacted
    assert "someone" not in redacted
    assert redacted == f"https://{REDACTED}@example.invalid/feed"


@pytest.mark.parametrize("parameter", sorted(CREDENTIAL_QUERY_PARAMETERS))
def test_a_credential_named_query_parameter_is_redacted_whatever_its_value(parameter: str):
    redacted = Redactor([FAKE_KEY]).url(f"https://example.invalid/feed?{parameter}=hunter2")
    assert "hunter2" not in redacted
    assert redacted == f"https://example.invalid/feed?{parameter}={REDACTED}"


def test_an_ordinary_query_parameter_survives():
    redacted = Redactor([FAKE_KEY]).url("https://example.invalid/feed?format=json&limit=100")
    assert redacted == "https://example.invalid/feed?format=json&limit=100"


def test_a_path_segment_that_merely_looks_like_a_key_is_left_alone():
    """A file hash in a path is provenance, not a credential. Guessing loses it."""
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    url = f"https://mb-api.abuse.ch/downloads/{sha256}/"
    assert Redactor([FAKE_KEY]).url(url) == url


def test_an_unparseable_url_is_redacted_whole_rather_than_passed_through():
    assert Redactor([FAKE_KEY]).url("https://exam[ple.invalid:99999/feed") == REDACTED


def test_a_url_embedded_in_a_message_is_redacted_structurally():
    message = f"could not reach https://someone:hunter2@example.invalid/feed?token=t after 3 tries"
    redacted = Redactor([FAKE_KEY]).text(message)
    assert "hunter2" not in redacted
    assert redacted.startswith("could not reach ")
    assert redacted.endswith(" after 3 tries")


def test_an_outbound_request_log_redacts_the_url_without_the_caller_doing_it(log, stream):
    log.outbound_request("feed.fetch.started", method="GET", url=FEED_URL)
    written = stream.getvalue()
    assert FAKE_KEY not in written
    record = only(stream)
    assert record["fields"]["method"] == "GET"
    assert record["fields"]["url"] == f"https://threatfox.abuse.ch/export/{REDACTED}/json/recent/"


# --- Redaction: the exception path, against a real HTTP failure --------------


class _NotFound(BaseHTTPRequestHandler):
    """Answers everything with 404, so urllib raises a real HTTPError."""

    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802 — the stdlib's name
        self.send_error(404)

    def log_message(self, *args: object) -> None:
        """The stdlib handler logs to stderr; the suite has its own log channel."""


@pytest.fixture
def failing_server():
    """A real HTTP server on the loopback interface. No egress, no quota spend."""
    server = HTTPServer(("127.0.0.1", 0), _NotFound)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def fetch(url: str) -> urllib.error.HTTPError:
    """The fetch a feed loader makes, against a server that always fails."""
    with pytest.raises(urllib.error.HTTPError) as raised:
        with urllib.request.urlopen(url, timeout=10):
            pass
    error = raised.value
    # An HTTPError *is* the response, and it holds the connection open. The
    # suite runs with `filterwarnings = ["error"]`, so leaking it fails a later
    # test rather than this one.
    error.close()
    return error


def test_a_urllib_exception_really_does_carry_the_key_in_the_url(failing_server):
    """The premise. If this ever stops holding, the redaction below proves less."""
    error = fetch(f"{failing_server}/export/{FAKE_KEY}/json/recent/")
    assert FAKE_KEY in error.url
    assert FAKE_KEY not in str(error)


def test_a_loader_fetch_and_its_failure_never_put_the_key_in_the_log(
    failing_server, log, stream
):
    url = f"{failing_server}/export/{FAKE_KEY}/json/recent/"
    log.outbound_request("feed.fetch.started", method="GET", url=url)
    error = fetch(url)
    log.exception("feed.fetch.failed", error, status=error.code)

    written = stream.getvalue()
    assert FAKE_KEY not in written
    started, failed = records(stream)
    assert started["fields"]["url"].endswith(f"/export/{REDACTED}/json/recent/")
    assert failed["level"] == "error"
    assert failed["fields"]["error_type"] == "HTTPError"
    assert failed["fields"]["error_url"].endswith(f"/export/{REDACTED}/json/recent/")
    assert failed["fields"]["status"] == 404


def test_an_exception_carrying_the_url_only_in_its_message_is_redacted(log, stream):
    """`urllib.error.URLError` sets no url attribute; the message is all there is."""
    error = urllib.error.URLError(f"cannot connect to {FEED_URL}")
    log.exception("feed.fetch.failed", error)
    written = stream.getvalue()
    assert FAKE_KEY not in written
    record = only(stream)
    assert record["fields"]["error_url"] is None
    assert REDACTED in record["fields"]["error"]


# --- The real key, from the real .env ----------------------------------------
#
# These assert on a boolean, never on the value: a failing `assert key not in
# output` prints both operands, which would be the leak the test is about.


def real_settings() -> Settings:
    return Settings.load(environ={}, env_file=PROJECT_ROOT / ".env")


def test_the_redactor_covers_every_credential_the_configuration_holds():
    settings = real_settings()
    redactor = Redactor.from_settings(settings)
    configured = [
        settings.providers.abusech_auth_key,
        settings.providers.virustotal_auth_key,
        settings.triage.token,
        settings.analyst.token,
    ]
    for secret in configured:
        survived = redactor.text(f"value={secret.reveal()}") != f"value={REDACTED}"
        assert not survived, "a configured credential survived the redactor"


def test_the_real_feed_key_never_reaches_the_log_from_a_url_or_an_exception(stream):
    settings = real_settings()
    log = logger("enrichment", settings, stream=stream)
    key = settings.providers.abusech_auth_key.reveal()
    url = f"https://threatfox.abuse.ch/export/{key}/json/recent/"

    log.outbound_request("feed.fetch.started", method="GET", url=url)
    log.exception("feed.fetch.failed", urllib.error.URLError(f"cannot reach {url}"))

    written = stream.getvalue()
    leaked = key in written
    assert not leaked, "the real abuse.ch key reached the log output"
    assert written.count(REDACTED) >= 2


def test_the_logger_takes_its_identity_from_settings_and_defaults_nothing(stream):
    settings = real_settings()
    logger("enrichment", settings, stream=stream).info("feed.fetch.started")
    record = only(stream)
    assert record["tenant"] == settings.identity.tenant
    assert record["sensor"] == settings.identity.sensor


# --- One logging path --------------------------------------------------------


def _package_modules() -> list[Path]:
    return sorted(PACKAGE_ROOT.rglob("*.py"))


def test_the_package_has_no_second_logging_path():
    """One channel, so "redacted on the way out" is a property and not a habit.

    `print()` and the standard library's `logging` both write unredacted strings
    to a stream nobody swept. Neither is a second *egress* channel in the hosted
    sense, but both are a way for a credential to reach a file.
    """
    offenders: dict[str, set[str]] = {}
    for module in _package_modules():
        found: set[str] = set()
        tree = ast.parse(module.read_text(), filename=str(module))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id == "print":
                    found.add("print()")
            elif isinstance(node, ast.Import):
                found |= {f"import {a.name}" for a in node.names if a.name == "logging"}
            elif isinstance(node, ast.ImportFrom) and node.module == "logging":
                found.add("from logging import ...")
        if found:
            offenders[module.name] = found
    assert not offenders, (
        f"the package writes log output outside helena.observability: {offenders}"
    )
