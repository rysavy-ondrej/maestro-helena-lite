"""Secrets hygiene: the wrapper, the two exposure profiles, and the five channels.

`concept/07-principles.md`, "Secrets and configuration":

    *"**Never logged, in any form:** tokens and credentials — in prompts,
    evidence, logs, traces or source control. And specifically, **a key that
    travels in a URL path must be redacted before anything is logged or stored**,
    including the fetch trace a loader records for provenance."*

**The same provider secret has two exposure profiles, and only one of them needs
the URL rule.** Measured against abuse.ch on 2026-09-12, the fourth time this has
been measured rather than read off a page (`docs/runbook.md` §14 has the dates and
the commands):

| Profile | Where the key travels | What it reaches |
| --- | --- | --- |
| The hunting API, `POST threatfox-api.abuse.ch/api/v1/` | an `Auth-Key` **header** | the request body and the TLS session. Not a proxy log, not shell history, not `HTTPError.url`, not a pasted link |
| The v2 export, `GET threatfox-api.abuse.ch/v2/files/exports/<AUTH-KEY>/full.csv.zip` | the **URL path** | all four of those, and anything that records the URL as provenance |

The bulk export this repository actually fetches —
`GET threatfox.abuse.ch/export/json/recent/` — needs **no credential at all**, so
it has neither profile; the redactor is applied to its recorded URL anyway,
because the rule is about the exposure channel and not about one provider's
current auth. That asymmetry is the thing this module exists to keep true: it is
the reason `helena.providers` puts the key in a header, and the reason the stored
fetch trace is redacted regardless.

**It is not hypothetical.** A live key reached a project conversation inside a
pasted link, which is why the repository scan below is over committed bytes rather
than over intentions.

## What this module owns, and what it does not

The five channels `concept/07` names already had owners for three of them, and a
second definition of one property is worse than none:

| Channel | Owned by |
| --- | --- |
| the log, and an exception carrying a request URL | `tests/test_observability.py`, against the live key |
| the agent-visible tool surface | `tests/test_tools.py`, against the live key |
| the prompt bytes and the disclosure record | `tests/test_conformance.py`'s MNH-15 |
| the Public Suffix loader's stored URL | `tests/test_enrichment.py` |
| the feed loader's recorded URL, query-parameter form | `tests/test_threatfox.py` |

What had no owner, and is here: the **path** form of the feed loader's trace, the
loader's stored **failure detail** (where a fetch exception's own message carries
the URL it was fetching), the wrapper as a property of the package rather than of
one model, **source control**, and the two downstream surfaces MNH-15 left —
a stored evidence row and an emitted message.

**Two channels were open when this module was written and it found both**, which
is the argument for writing it over the live key rather than over a placeholder:
the feed loader stored its fetch diagnostic unredacted (the Public Suffix loader
beside it did not), and `http.client.InvalidURL` — a subclass of neither `OSError`
nor `ValueError` — escaped both fetch functions untyped and printed the request
path into the traceback of the very first run here. `docs/runbook.md` §14 records
both, and the second is the reason both fetch functions now take a redactor.

**Every assertion over a live value is computed as a boolean first.** pytest
rewrites assertions and prints both operands, so `assert key not in text` would
print the key at the exact moment the redaction failed. That is not a theoretical
risk: it is how the escaping `InvalidURL` above was found.
"""

from __future__ import annotations

import ast
import io
import json
import re
import subprocess
from datetime import timedelta
from pathlib import Path

import psycopg
import pytest

from helena import hosts, rendering, sink
from helena.config import REDACTED, Secret, Settings
from helena.enrichment import (
    FAILED,
    FEED_SNAPSHOT_TABLE,
    FETCH_FAILED,
    MAX_FAILURE_DETAIL,
    THREATFOX_REFERENCE_TABLE,
    PublicSuffixListError,
    ThreatFoxError,
    fetch_public_suffix_list,
    fetch_threatfox,
    load_threatfox,
)
from helena.observability import Redactor, logger
from helena.rendering import v1 as rendering_v1
from helena.triage import v1 as triage_v1
from test_sink import (  # noqa: E402 — the suite's own cross-module idiom
    RAW,
    Snapshot,
    a_sink,
    an_entity,
    request,
    settings,
    store_capture,
    store_pass,
    targeted,
    versions,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PACKAGE_ROOT = PROJECT_ROOT / "src" / "helena"
SCRIPTS_ROOT = PROJECT_ROOT / "scripts"
ENV_FILE = PROJECT_ROOT / ".env"

#: Not a credential, and shaped like the one it stands in for: an opaque path
#: segment. The fake is what failure messages are allowed to print.
FAKE_KEY = "fake-auth-key-0123456789abcdef"


def keyed_url(key: str) -> str:
    """The v2 export's shape: the one abuse.ch surface with a key in the path.

    Nothing in this repository fetches it, and nothing here does either — every
    test below either passes `raw=` or uses a host that does not resolve. The real
    host is written out because the shape is the point.
    """
    return f"https://threatfox-api.abuse.ch/v2/files/exports/{key}/full.csv.zip"


def unfetchable_keyed_url(key: str) -> str:
    """The same URL with a space in the segment after the key.

    `http.client` refuses it in `putrequest`, which is **before** the connection
    is opened — measured 2026-09-12, 4 ms against a host that does not resolve —
    so this reaches no network and the exception it raises quotes the whole path.
    """
    return f"https://feed.invalid/v2/files/exports/{key}/ full.csv.zip"


def live_settings() -> Settings:
    return Settings.load(environ={}, env_file=ENV_FILE)


def live_values() -> tuple[str, ...]:
    """Every credential the local configuration holds, from the real file."""
    configured = live_settings()
    return tuple(
        secret.reveal()
        for secret in (
            configured.triage.token,
            configured.analyst.token,
            configured.providers.abusech_auth_key,
            configured.providers.virustotal_auth_key,
        )
    )


requires_env = pytest.mark.skipif(
    not ENV_FILE.exists(), reason="no local .env on this machine"
)


# --- The wrapper -------------------------------------------------------------
#
# `tests/test_config.py` owns the wrapper's behaviour on one model. What is here
# is the wrapper as a property of the *package*: that no model anywhere can hold a
# credential without the redacting serializer, and that the one way out is called
# in three declared places.


def test_the_wrapper_yields_its_value_through_reveal_and_no_other_surface():
    """`str`, `repr`, both f-string conversions, `%`, `format`, and a dump."""
    secret = Secret("s3cret-value-0123456789")
    surfaces = [
        str(secret),
        repr(secret),
        f"{secret}",
        f"{secret!s}",
        f"{secret!r}",
        "%s" % (secret,),
        "{}".format(secret),
        "{0!r}".format(secret),
        " ".join([str(secret), repr(secret)]),
    ]
    for rendered in surfaces:
        leaked = "s3cret-value-0123456789" in rendered
        assert not leaked, "the wrapper rendered its value"
        assert REDACTED in rendered
    assert secret.reveal() == "s3cret-value-0123456789", (
        "the value is still there; it is every rendering of it that is redacted"
    )


def test_the_standard_json_encoder_refuses_a_secret_rather_than_rendering_it():
    """A refusal, not a string.

    `json.dumps` falling back to `str()` would have been the quiet version of
    this: a credential serialized as `***redacted***` is safe, but a credential
    serialized by *anything that happens to call str* is a habit rather than a
    property. The encoder raises, so a path that tries to serialize a `Secret`
    outside a Pydantic model fails loudly instead.
    """
    with pytest.raises(TypeError):
        json.dumps({"token": Secret("s3cret-value")})


def _models(tree: ast.Module) -> list[ast.ClassDef]:
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef)
        and any(
            ast.unparse(base).endswith("BaseModel") or ast.unparse(base) == "BaseModel"
            for base in node.bases
        )
    ]


def _annotated_fields(model: ast.ClassDef) -> list[tuple[str, str]]:
    return [
        (node.target.id, ast.unparse(node.annotation))
        for node in model.body
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
    ]


def _package_modules() -> list[Path]:
    return sorted(PACKAGE_ROOT.rglob("*.py")) + sorted(SCRIPTS_ROOT.rglob("*.py"))


def test_every_model_field_that_holds_a_secret_carries_the_redacting_serializer():
    """`SecretField`, never a bare `Secret`, anywhere in the package.

    A field annotated `Secret` validates the same way and serializes the value
    verbatim, because the `PlainSerializer` is what substitutes `REDACTED` in
    `model_dump` and `model_dump_json`. The two annotations look
    interchangeable at the call site and are not, which is exactly the kind of
    difference that survives review.
    """
    offenders: list[str] = []
    for module in _package_modules():
        tree = ast.parse(module.read_text(), filename=str(module))
        for model in _models(tree):
            for name, annotation in _annotated_fields(model):
                if "Secret" not in annotation:
                    continue
                if "SecretField" not in annotation:
                    offenders.append(f"{module.name}:{model.name}.{name}: {annotation}")
    assert offenders == [], (
        "a model field holds a credential without the redacting serializer; "
        f"annotate it `SecretField` (helena.config): {offenders}"
    )


def _configs_hiding_input(tree: ast.Module) -> set[str]:
    """Module-level `ConfigDict(...)` names whose `hide_input_in_errors` is true."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Call):
            continue
        if not ast.unparse(node.value.func).endswith("ConfigDict"):
            continue
        if not any(
            keyword.arg == "hide_input_in_errors"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is True
            for keyword in node.value.keywords
        ):
            continue
        names |= {
            target.id for target in node.targets if isinstance(target, ast.Name)
        }
    return names


def test_every_model_that_can_hold_a_secret_hides_the_input_in_its_errors():
    """Pydantic echoes the rejected input into a `ValidationError` otherwise.

    Measured when the settings models were written: a bare credential string
    passed where a `Secret` belongs arrives in the error as `input_value=...`,
    which puts it in a traceback — one of the places `concept/07` says a
    credential may never appear. The flag is per model, so a *new* model holding
    a `SecretField` has to set it too, and this is what says so.
    """
    offenders: list[str] = []
    for module in _package_modules():
        tree = ast.parse(module.read_text(), filename=str(module))
        hiding = _configs_hiding_input(tree)
        for model in _models(tree):
            if not any(
                "SecretField" in annotation
                for _, annotation in _annotated_fields(model)
            ):
                continue
            configured = [
                ast.unparse(node.value)
                for node in model.body
                if isinstance(node, ast.Assign)
                and any(
                    isinstance(target, ast.Name) and target.id == "model_config"
                    for target in node.targets
                )
            ]
            if not configured:
                offenders.append(f"{module.name}:{model.name} sets no model_config")
                continue
            if not any(
                setting in hiding or "hide_input_in_errors=True" in setting
                for setting in configured
            ):
                offenders.append(f"{module.name}:{model.name} -> {configured}")
    assert offenders == [], (
        "a model holding a credential does not set hide_input_in_errors=True, so "
        f"a validation error would echo the value into a traceback: {offenders}"
    )


#: Where `Secret.reveal()` may be called, and what each call is for. A fourth
#: entry is a fourth place a credential is used, which `concept/instruction.md`
#: §3 makes a decision rather than an edit — the credential's *travel* is the
#: thing under review, not the line that reads it.
REVEALED_IN = {
    "src/helena/providers.py": "the provider's `Auth-Key` request header",
    "src/helena/agents.py": "the model endpoint's `Authorization: Bearer` header",
    "src/helena/observability.py": "registering the values with the redactor, "
    "which is the one call that is not a use of the credential",
}


def test_reveal_is_called_in_three_declared_places_and_nowhere_else():
    """The single deliberate way out of the wrapper stays greppable and small.

    Read as an AST rather than grepped, because `helena.config` and
    `helena.tools` both *discuss* `reveal()` in prose and a text search finds the
    sentence arguing for the thing's absence (the same lesson
    `tests/test_conformance.py` records for `_names`). `scripts/` is scanned too:
    a script that reveals a key is the shell-history exposure channel, which is
    one of the two this module's header table is about.
    """
    callers: dict[str, int] = {}
    for module in _package_modules():
        tree = ast.parse(module.read_text(), filename=str(module))
        calls = sum(
            1
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "reveal"
        )
        if calls:
            callers[str(module.relative_to(PROJECT_ROOT))] = calls
    assert set(callers) == set(REVEALED_IN), (
        "the set of modules that reveal a credential changed. Each one is a "
        f"place a key travels; declared: {REVEALED_IN}, found: {callers}"
    )


# --- The key-in-URL profile, through the loader's stored trace ----------------


@pytest.mark.integration
def test_the_stored_fetch_trace_of_a_feed_load_carries_no_key_from_the_path(
    migrated_engine: psycopg.Connection,
):
    """The path form of the exposure profile, which had no test.

    `tests/test_threatfox.py` covers the query-parameter form, where the
    parameter's *name* is what marks the value. A key in a path segment carries
    no such marker — which is why the redactor replaces registered values and
    deliberately does not guess at segments (a segment that merely looks opaque
    is a file hash in this project, and redacting one would destroy the
    provenance the fetch exists to record).
    """
    load_threatfox(
        migrated_engine,
        tenant="tenant-under-test",
        sensor="sensor-under-test",
        source_url=keyed_url(FAKE_KEY),
        redactor=Redactor([FAKE_KEY]),
        raw=RAW,
    )
    migrated_engine.execute("FLUSH")
    stored = migrated_engine.execute(
        f"SELECT source_url, outcome, failure_detail FROM {FEED_SNAPSHOT_TABLE}"
    ).fetchall()
    assert len(stored) == 1
    (url, outcome, detail) = stored[0]
    assert FAKE_KEY not in url, url
    assert url == keyed_url(REDACTED), url
    assert (outcome, detail) == ("loaded", None)


@pytest.mark.integration
def test_a_fetch_exception_carrying_the_request_url_is_redacted_before_it_is_stored(
    migrated_engine: psycopg.Connection,
):
    """The stored diagnostic is the second column the rule covers, not only the URL.

    The exception is a real one from the real fetch path: a URL whose path holds
    the key and whose next segment holds a space is refused by `http.client` in
    `putrequest`, **before** the connection is opened, and the message it raises
    quotes the whole path.

    This case is the reason `helena.enrichment._FETCH_FAILURES` names
    `http.client.HTTPException` explicitly. `InvalidURL` is a subclass of neither
    `OSError` nor `ValueError`, so before this test it escaped `fetch_threatfox`
    untyped and printed the path — key included — into whatever printed the
    traceback. That is the one exposure channel the logger cannot cover, because
    nothing had logged anything.

    Redaction happens before the bound and not after: truncating first would
    leave a half-credential the redactor no longer recognizes.
    """
    result = load_threatfox(
        migrated_engine,
        tenant="tenant-under-test",
        sensor="sensor-under-test",
        source_url=unfetchable_keyed_url(FAKE_KEY),
        redactor=Redactor([FAKE_KEY]),
    )
    assert (result.outcome, result.failure_reason) == (FAILED, FETCH_FAILED)
    assert FAKE_KEY not in result.failure_detail, result.failure_detail
    assert REDACTED in result.failure_detail, (
        "the exception message quoted the request path, so the redacted marker "
        "has to be in what was stored"
    )

    migrated_engine.execute("FLUSH")
    (url, detail) = migrated_engine.execute(
        f"SELECT source_url, failure_detail FROM {FEED_SNAPSHOT_TABLE}"
    ).fetchone()
    assert FAKE_KEY not in url and FAKE_KEY not in detail
    assert len(detail) <= MAX_FAILURE_DETAIL


@pytest.mark.parametrize(
    ("fetch", "error"),
    (
        (fetch_threatfox, ThreatFoxError),
        (fetch_public_suffix_list, PublicSuffixListError),
    ),
)
def test_an_exception_raised_during_a_fetch_carries_a_redacted_url_and_no_cause(
    fetch, error
):
    """Redacted at the raise, not only at the row, and the chain is suppressed.

    The loader's stored row is one surface; the exception in flight is another,
    and it is the one that reaches a terminal, a CI log and a pasted traceback —
    none of which the logger sees. So both fetch functions require a redactor and
    build their own message through it.

    `from None` rather than `from failure`, and that is the load-bearing half: a
    traceback printer prints the whole `__cause__` chain, so a redacted message
    with an unredacted cause one line below it is not redacted. What survives is
    the original's type name and message, inside the typed error.
    """
    with pytest.raises(error) as raised:
        fetch(unfetchable_keyed_url(FAKE_KEY), redactor=Redactor([FAKE_KEY]))
    message = str(raised.value)
    assert FAKE_KEY not in message, message
    assert REDACTED in message and "InvalidURL" in message
    assert raised.value.reason == FETCH_FAILED
    assert raised.value.__cause__ is None and raised.value.__suppress_context__, (
        "the original exception is still chained, so a traceback prints its "
        "unredacted message under this one"
    )


@pytest.mark.parametrize(
    "fetch", (fetch_threatfox, fetch_public_suffix_list)
)
def test_a_fetch_cannot_be_called_without_a_redactor(fetch):
    """Keyword-only and required, so no call site can forget it."""
    with pytest.raises(TypeError):
        fetch(keyed_url(FAKE_KEY))


@pytest.mark.integration
def test_a_long_diagnostic_is_redacted_before_it_is_bounded(
    migrated_engine: psycopg.Connection,
):
    """The ordering, demonstrated rather than asserted in a comment.

    A key far enough into the message that the bound would cut through it. Redact
    first and the whole value is gone; bound first and the prefix survives into
    the stored row, which is a credential fragment nobody will ever grep for.
    """
    padding = "p" * (MAX_FAILURE_DETAIL * 2)
    result = load_threatfox(
        migrated_engine,
        tenant="tenant-under-test",
        sensor="sensor-under-test",
        source_url=unfetchable_keyed_url(f"{padding}{FAKE_KEY}"),
        redactor=Redactor([f"{padding}{FAKE_KEY}"]),
    )
    assert result.outcome == FAILED
    assert len(result.failure_detail) <= MAX_FAILURE_DETAIL
    assert FAKE_KEY not in result.failure_detail
    assert REDACTED in result.failure_detail


@requires_env
@pytest.mark.integration
def test_the_live_key_in_a_url_path_reaches_neither_the_stored_trace_nor_the_log(
    migrated_engine: psycopg.Connection,
):
    """The same two paths with the real key from `.env`, and a log beside them.

    A redactor that covers a made-up value and not the configured one is a
    redactor that has not been tested. Asserted on booleans with fixed messages,
    for the reason the module header gives.
    """
    configured = live_settings()
    key = configured.providers.abusech_auth_key.reveal()
    redactor = Redactor.from_settings(configured)
    stream = io.StringIO()
    log = logger("enrichment", configured, stream=stream)

    log.outbound_request("feed.fetch.started", method="GET", url=keyed_url(key))
    loaded = load_threatfox(
        migrated_engine,
        tenant="tenant-under-test",
        sensor="sensor-under-test",
        source_url=keyed_url(key),
        redactor=redactor,
        raw=RAW,
    )
    failed = load_threatfox(
        migrated_engine,
        tenant="tenant-under-test",
        sensor="sensor-under-test",
        source_url=unfetchable_keyed_url(key),
        redactor=redactor,
    )
    migrated_engine.execute("FLUSH")
    rows = migrated_engine.execute(
        f"SELECT source_url, failure_detail FROM {FEED_SNAPSHOT_TABLE}"
    ).fetchall()

    assert loaded.outcome == "loaded" and failed.outcome == FAILED
    assert len(rows) == 2
    surfaces = [
        value for row in rows for value in row if value is not None
    ] + [stream.getvalue()]
    for surface in surfaces:
        leaked = key in surface
        assert not leaked, "the live abuse.ch key reached a stored row or the log"
    assert all(REDACTED in surface for surface in surfaces)


# --- Source control ----------------------------------------------------------


def _tracked_files() -> list[Path]:
    listed = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        check=True,
    ).stdout
    paths = [PROJECT_ROOT / name for name in listed.decode().split("\0") if name]
    return [path for path in paths if path.is_file()]


#: A credential-named key assigned an opaque value. Deliberately not an entropy
#: or length heuristic over everything — `tests/test_observability.py` records
#: why that approach is wrong for path segments, and the same reasoning applies
#: here: this fires on the *name beside the value*, which is what a pasted
#: configuration line has and a file hash does not.
_CREDENTIAL_NAME = (
    r"(?:auth[-_]?key|api[-_]?key|apikey|access[-_]?token|bearer|secret|"
    r"password|passwd|pwd|token|credential)"
)
_ASSIGNED = re.compile(
    rf"(?i){_CREDENTIAL_NAME}['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9][\w\-./+=]{{15,}})"
)

#: A URL carrying userinfo: `scheme://user:pass@host`. The one
#: credential-in-a-URL shape that needs no judgement about the value —
#: `helena.policy` already refuses it in configuration for the same reason. The
#: host is captured because the redaction tests legitimately feed such URLs in,
#: and what makes those acceptable is the same thing that makes a placeholder
#: acceptable: the host says it is not real.
_USERINFO = re.compile(
    r"[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s/\"'<>]*:[^\s/\"'<>]*@([^\s/\"'<>]*)"
)

#: What a committed credential-shaped value must say about itself. A test
#: placeholder names itself in this project (`abusech-key-under-test`), so the
#: rule is the convention rather than a list of accepted values that somebody has
#: to remember to extend.
NOT_REAL = (
    "under-test",
    "conformance",
    "fake",
    "example",
    "placeholder",
    "redacted",
    "invalid",
    "sample",
    "dummy",
)


def _candidates(text: str) -> list[str]:
    """Credential-shaped values, minus the two things that merely look like one."""
    found = []
    for value in (match.group(1) for match in _ASSIGNED.finditer(text)):
        if re.search(r"\.[A-Za-z_]", value):
            continue  # a dotted expression: `settings.providers.abusech_auth_key`
        if value.isupper() and "_" in value:
            continue  # a variable name: `VIRUSTOTAL_AUTH_KEY`
        found.append(value)
    return found


@requires_env
def test_no_committed_file_carries_a_configured_credential():
    """Source control is one of the five channels, and this is the live check.

    Over the bytes `git` tracks, which is what "committed" means — the values are
    the real ones from `.env`, so this is the exact test for the channel that
    produced the incident behind the rule: a key inside a pasted link. Fixtures
    are in it by construction (`git ls-files` does not care what a file is for)
    and the count below is asserted, so a scan that silently reached none of them
    fails rather than passes.
    """
    values = live_values()
    tracked = _tracked_files()
    offenders = sorted(
        str(path.relative_to(PROJECT_ROOT))
        for path in tracked
        if any(value.encode() in path.read_bytes() for value in values)
    )
    assert offenders == [], (
        f"{len(offenders)} committed file(s) carry a live credential. Rotate the "
        f"key first, then rewrite the history: {offenders}"
    )
    fixtures = [
        path for path in tracked if "tests/fixtures/" in path.as_posix()
    ]
    assert len(tracked) > 200 and len(fixtures) > 5, (
        f"the scan covered {len(tracked)} tracked files and {len(fixtures)} "
        f"fixtures, which is too few to have read the repository"
    )


def test_every_credential_shaped_value_in_a_committed_file_says_it_is_not_real():
    """The second line, for a value this deployment's `.env` does not hold.

    The live scan above cannot see a *colleague's* key, so this one reads the
    shape: a credential-named key assigned an opaque value, or a URL carrying
    userinfo. What it requires is the convention the suite already follows —
    a test credential names itself `-under-test` — so a pasted real value is red
    on arrival and a new placeholder costs one word.

    It is not exhaustive and is not claimed to be: a key pasted into prose with
    no name beside it is invisible here, and what covers that case is the live
    scan above plus `.gitignore`.
    """
    unexplained: dict[str, list[str]] = {}
    userinfo: list[str] = []
    for path in _tracked_files():
        try:
            text = path.read_text()
        except (UnicodeDecodeError, ValueError):
            continue  # a binary fixture holds no assignment to read
        name = str(path.relative_to(PROJECT_ROOT))
        if name == str(Path(__file__).relative_to(PROJECT_ROOT)):
            continue  # this module declares the patterns it looks for
        offending = [
            value
            for value in _candidates(text)
            if not any(marker in value.lower() for marker in NOT_REAL)
        ]
        if offending:
            unexplained[name] = sorted(set(offending))
        # The host only. A message naming the whole match would print the
        # userinfo, which is the thing the assertion is about.
        userinfo += [
            f"{name} -> {host}"
            for host in _USERINFO.findall(text)
            if not any(marker in host.lower() for marker in NOT_REAL)
        ]
    assert unexplained == {}, (
        "a credential-shaped value in a committed file does not say it is not "
        f"real. A test value names itself — one of {NOT_REAL}: {unexplained}"
    )
    assert userinfo == [], f"a committed URL carries userinfo: {userinfo}"


def test_the_environment_file_is_ignored_and_untracked():
    """`.gitignore` is the first line of the repository channel, so assert it.

    Both halves, because they fail separately: a file `git` already tracks stays
    tracked however the ignore rules change.
    """
    tracked = {path.relative_to(PROJECT_ROOT).as_posix() for path in _tracked_files()}
    assert ".env" not in tracked
    assert not any(name.startswith("secrets/") for name in tracked)
    ignored = subprocess.run(
        ["git", "check-ignore", ".env", "secrets/"],
        cwd=PROJECT_ROOT,
        capture_output=True,
    )
    assert ignored.returncode == 0
    assert set(ignored.stdout.decode().split()) == {".env", "secrets/"}


# --- The three downstream surfaces -------------------------------------------


TENANT, SENSOR = "tenant-under-test", "sensor-under-test"
UNBOUNDED = rendering.RenderingBudget(characters=1_000_000)


@pytest.fixture
def keyed_context(
    migrated_engine: psycopg.Connection, tmp_path: Path
) -> tuple[psycopg.Connection, Snapshot, str, str]:
    """A real context, enriched by a load whose URL carried the key in its path.

    The capture goes through the real normalizer and the committed ThreatFox
    extract through the real loader, exactly as `tests/test_sink.py` builds its
    own — the one difference is the URL, which is the channel under test. One
    entry is repointed at a domain the capture really contains, so there is a
    claim to cite and an evidence identifier to put in a rendering.
    """
    key = (
        live_settings().providers.abusech_auth_key.reveal()
        if ENV_FILE.exists()
        else FAKE_KEY
    )
    store_capture(migrated_engine, tmp_path / "restamped.jsonl")
    matched = an_entity(migrated_engine)
    snapshot = Snapshot(migrated_engine)
    load_threatfox(
        migrated_engine,
        tenant=TENANT,
        sensor=SENSOR,
        source_url=keyed_url(key),
        redactor=Redactor([key]),
        raw=targeted(RAW, matched),
        now=snapshot.window_start - timedelta(seconds=60),
    )
    migrated_engine.execute("FLUSH")
    return migrated_engine, snapshot, matched, key


def _strings(value: object) -> list[str]:
    """Every string anywhere in a JSON-shaped value, keys included."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [
            text
            for key, item in value.items()
            for text in (_strings(key) + _strings(item))
        ]
    if isinstance(value, (list, tuple)):
        return [text for item in value for text in _strings(item)]
    return []


def _rows(connection: psycopg.Connection, table: str) -> list[tuple]:
    return connection.execute(f"SELECT * FROM {table}").fetchall()


def _property_names(schema: dict, definitions: dict | None = None) -> set[str]:
    """Every field name in a model's JSON Schema, following its `$defs`."""
    definitions = definitions if definitions is not None else schema.get("$defs", {})
    names: set[str] = set()
    for name, child in (schema.get("properties") or {}).items():
        names.add(name)
        names |= _property_names(child, definitions)
    for key in ("items", "prefixItems", "additionalProperties"):
        child = schema.get(key)
        for part in child if isinstance(child, list) else [child]:
            if isinstance(part, dict):
                names |= _property_names(part, definitions)
    for part in schema.get("anyOf", []) + schema.get("allOf", []):
        names |= _property_names(part, definitions)
    reference = schema.get("$ref")
    if reference:
        names |= _property_names(definitions[reference.split("/")[-1]], definitions)
    return names


#: A field name that would hold a URL. The message carries none, which is what
#: makes "a credential in a path cannot reach a consumer" structural rather than
#: a property of today's values: `EmittedDisclosure.disclosed_to` is a host.
URL_SHAPED = {"url", "uri", "href", "source_url", "endpoint", "endpoint_url", "link"}


@pytest.mark.integration
def test_no_prompt_evidence_row_or_emitted_message_can_carry_a_credential(
    keyed_context: tuple[psycopg.Connection, Snapshot, str, str],
):
    """The two surfaces MNH-15 left, plus a real prompt over real rows.

    MNH-15 checks the prompt bytes and the disclosure record against a synthetic
    request. This runs the same question through the whole width of the pipeline
    the credential actually entered: a feed load whose URL carried the key, the
    claims it stored, the enriched context that joins them, a rendering built by
    the real renderer over those rows, the triage prompt built from it, and the
    message the sink projects out of the stored assessment.

    The structural half is the one that survives a change of values: the emitted
    message has no URL-shaped field at all, so there is no column for a key in a
    path to arrive in.
    """
    connection, snapshot, matched, key = keyed_context
    shown = snapshot.evidence_id(matched)

    store = rendering.RenderingStore(
        connection=connection, identity=settings().identity
    )
    projection = store.project(snapshot.context_id)
    rendered = rendering_v1.render(
        projection, hosts.load().attributes_for(projection.host), UNBOUNDED
    )
    asked = request(
        snapshot,
        shown,
        matched,
        rendering=rendered,
        # Two copies of a version constant: `AgentRequest` refuses a request
        # whose rendering and version set disagree, and this rendering is the
        # real renderer's rather than the stand-in `tests/test_sink.py` builds.
        versions=versions(rendering_version=rendering_v1.RENDERING_VERSION),
    )
    prompt = "\n".join(
        turn.content
        for turn in triage_v1.PROMPT.messages(
            asked, classifications=("normal", "suspicious")
        )
    )

    evidence = [
        text
        for table in (
            rendering.ENRICHED_CONTEXT_VIEW,
            THREATFOX_REFERENCE_TABLE,
            FEED_SNAPSHOT_TABLE,
        )
        for row in _rows(connection, table)
        for text in _strings([str(value) for value in row])
    ]
    assert evidence, "nothing was stored, so this test would pass on an empty store"

    written = store_pass(connection, snapshot, shown, matched)
    message = a_sink(connection).project(written[0])
    emitted = message.model_dump_json()
    assert any(entity.evidence for entity in message.entities), (
        "the message carries no evidence at all, so it is not the surface this "
        "test claims to have checked"
    )

    for surface in [prompt, *evidence, emitted]:
        leaked = key in surface
        assert not leaked, "a credential reached a prompt, an evidence row or a message"

    names = _property_names(sink.OutputMessage.model_json_schema())
    assert {"assessment_id", "caveat", "native_evidence", "disclosed_to"} <= names, (
        f"the schema walk found {len(names)} field names and not the ones the "
        f"message is known to have, so the next assertion would pass vacuously"
    )
    assert URL_SHAPED.isdisjoint(names), (
        "the emitted message grew a URL-shaped field; a key in a path now has a home"
    )
