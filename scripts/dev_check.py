#!/usr/bin/env python3
"""Check the pinned binaries and that both endpoints answer.

Two jobs, on purpose in one place: `scripts/dev-up` runs this before it starts
anything and again once it has, and `tests/test_infrastructure.py` imports it —
so "the endpoint answers" has one definition rather than one per caller.

The pins come from `docs/versions.md`. Nothing else in the repository holds a
checksum or a version string for these binaries.

Run it directly:

    uv run scripts/dev_check.py                 # pins, then both endpoints
    uv run scripts/dev_check.py --binaries-only # pins only, nothing has to run
    uv run scripts/dev_check.py --wait 120      # retry the endpoints until up
    uv run scripts/dev_check.py --addresses     # shell assignments for dev-up

Maturity: experimental — exercised by tests/test_infrastructure.py and by
scripts/dev-up on every start, and the measurements behind it are recorded in
docs/runbook.md, but it has run against exactly one machine and one pair of
binaries.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shlex
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

PROJECT_ROOT = Path(__file__).resolve().parent.parent
VERSIONS_MD = PROJECT_ROOT / "docs" / "versions.md"

# The SONAME `bin/risingwave` is linked against. `bin/lib/` is where the pinned
# copy lives, and `bin/env.sh` is the shell-side way of putting it on the path;
# `engine_env()` below is the same thing for a subprocess started from Python.
LIBPYTHON_SONAME = "libpython3.12.so.1.0"
LIBPYTHON_DIR = PROJECT_ROOT / "bin" / "lib"

_PIN_BLOCK = re.compile(r"^```pins$(.*?)^```$", re.MULTILINE | re.DOTALL)
_PIN_LINE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9./_-]*)\s*=\s*(\S.*?)\s*$")


class CheckFailed(Exception):
    """A pin did not match, or an endpoint did not answer.

    The message names the file or the address, and says what to do about it —
    these are read by whoever is trying to get a local pipeline running.
    """


def pins() -> dict[str, str]:
    """The `pins` block of docs/versions.md, as a flat mapping."""
    if not VERSIONS_MD.exists():
        raise CheckFailed(f"{VERSIONS_MD} is missing; it holds the pins")
    block = _PIN_BLOCK.search(VERSIONS_MD.read_text())
    if block is None:
        raise CheckFailed(f"{VERSIONS_MD} has no ```pins block")
    found: dict[str, str] = {}
    for number, line in enumerate(block.group(1).splitlines(), start=1):
        if not line.strip():
            continue
        match = _PIN_LINE.match(line)
        if match is None:
            raise CheckFailed(
                f"{VERSIONS_MD}: line {number} of the pins block is not "
                f"`key = value`: {line!r}"
            )
        found[match.group(1)] = match.group(2)
    if not found:
        raise CheckFailed(f"{VERSIONS_MD}: the pins block is empty")
    return found


def engine_env() -> dict[str, str]:
    """The environment `bin/risingwave` needs, whatever it inherited.

    Prepending `bin/lib` is idempotent, so this behaves the same whether or not
    `bin/env.sh` was sourced first.
    """
    env = dict(os.environ)
    inherited = env.get("LD_LIBRARY_PATH", "")
    env["LD_LIBRARY_PATH"] = (
        f"{LIBPYTHON_DIR}:{inherited}" if inherited else str(LIBPYTHON_DIR)
    )
    return env


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def check_checksums(recorded: dict[str, str]) -> list[str]:
    """Every `sha256.<path>` pin, against the file on disk."""
    reported = []
    for key, expected in sorted(recorded.items()):
        if not key.startswith("sha256."):
            continue
        relative = key[len("sha256.") :]
        path = PROJECT_ROOT / relative
        if not path.exists():
            raise CheckFailed(
                f"{relative} is missing. It is a third-party binary the project "
                f"runs, not builds — see docs/versions.md for the pin and "
                f"bin/README.md for where it comes from."
            )
        actual = _sha256(path)
        if actual != expected:
            raise CheckFailed(
                f"{relative} is not the pinned artifact: sha256 {actual}, "
                f"expected {expected} (docs/versions.md). Whatever this file "
                f"is, no recorded result was produced against it."
            )
        reported.append(f"{relative} matches its pinned sha256")
    return reported


def linked_libpython() -> Path:
    """Where the dynamic linker resolves the engine's libpython to.

    This is the only check that catches a wrong Python minor. The engine starts,
    serves SQL and reports the right version against a mismatched library — see
    docs/runbook.md.
    """
    risingwave = PROJECT_ROOT / "bin" / "risingwave"
    result = subprocess.run(
        ["ldd", str(risingwave)],
        env=engine_env(),
        capture_output=True,
        text=True,
        check=False,
    )
    for line in result.stdout.splitlines():
        if LIBPYTHON_SONAME not in line:
            continue
        if "not found" in line:
            raise CheckFailed(
                f"{LIBPYTHON_SONAME} does not resolve. `source bin/env.sh` "
                f"before running the engine, or put the pinned copy in "
                f"bin/lib/."
            )
        _, _, resolved = line.partition("=>")
        return Path(resolved.strip().rsplit(" ", 1)[0]).resolve()
    raise CheckFailed(
        f"ldd does not report {LIBPYTHON_SONAME} for bin/risingwave. The binary "
        f"is not the pinned one, or ldd is unavailable."
    )


def check_linked_libpython(recorded: dict[str, str]) -> list[str]:
    """The library the engine will actually load is the pinned one."""
    key = f"sha256.bin/lib/{LIBPYTHON_SONAME}"
    expected = recorded[key]
    resolved = linked_libpython()
    actual = _sha256(resolved)
    if actual != expected:
        raise CheckFailed(
            f"bin/risingwave resolves {LIBPYTHON_SONAME} to {resolved}, whose "
            f"sha256 is {actual}, not the pinned {expected}. A different Python "
            f"minor version under this name is an ABI mismatch that produces no "
            f"error at all — read the hazard section of docs/runbook.md before "
            f"doing anything else."
        )
    return [f"{LIBPYTHON_SONAME} resolves to the pinned library"]


def check_binary_versions(recorded: dict[str, str]) -> list[str]:
    """Every `version.bin/<name>` pin, against what `--version` prints."""
    reported = []
    for key, expected in sorted(recorded.items()):
        if not key.startswith("version.bin/"):
            continue
        relative = key[len("version.") :]
        result = subprocess.run(
            [str(PROJECT_ROOT / relative), "--version"],
            env=engine_env(),
            capture_output=True,
            text=True,
            check=False,
        )
        actual = result.stdout.strip()
        if actual != expected:
            raise CheckFailed(
                f"{relative} --version printed {actual!r}, expected "
                f"{expected!r} (docs/versions.md)"
            )
        reported.append(f"{relative} reports {actual}")
    return reported


def check_binaries(recorded: dict[str, str] | None = None) -> list[str]:
    """Everything that can be checked without a process running."""
    recorded = recorded if recorded is not None else pins()
    return (
        check_checksums(recorded)
        + check_linked_libpython(recorded)
        + check_binary_versions(recorded)
    )


def check_engine(dsn: str, recorded: dict[str, str]) -> list[str]:
    """The engine answers the PostgreSQL wire protocol, and is the pinned one."""
    import psycopg

    expected = recorded["version.engine-wire"]
    try:
        with psycopg.connect(dsn, autocommit=True, connect_timeout=5) as connection:
            row = connection.execute("SELECT version()").fetchone()
    except psycopg.Error as error:
        raise CheckFailed(f"the engine did not answer: {error}") from error
    actual = row[0] if row else None
    if actual != expected:
        raise CheckFailed(
            f"the engine reports {actual!r} over the wire, expected {expected!r} "
            f"(docs/versions.md)"
        )
    return [f"engine answers the PostgreSQL wire protocol: {actual}"]


def check_broker(bootstrap: str) -> list[str]:
    """The broker answers the Kafka wire protocol.

    Metadata only. `concept/06-technology.md` makes the Kafka wire protocol the
    only way the broker is addressed, so its REST port is not touched here even
    though it would be an easier health check.
    """
    from confluent_kafka.admin import AdminClient

    admin = AdminClient({"bootstrap.servers": bootstrap})
    try:
        metadata = admin.list_topics(timeout=5)
    except Exception as error:  # confluent_kafka.KafkaException and friends
        raise CheckFailed(f"the broker did not answer: {error}") from error
    if not metadata.brokers:
        raise CheckFailed(
            f"the broker answered at {bootstrap} but advertised no brokers"
        )
    advertised = ", ".join(
        f"{broker.host}:{broker.port}" for broker in metadata.brokers.values()
    )
    return [f"broker answers the Kafka wire protocol, advertising {advertised}"]


def addresses() -> dict[str, str]:
    """The engine and broker addresses, resolved the way the package does.

    Read through `helena.config` rather than the environment so `dev-up` binds
    exactly what the pipeline will later connect to, and fails the same way when
    a variable is missing.
    """
    from helena.config import Settings

    infrastructure = Settings.load().infrastructure
    dsn = urlsplit(infrastructure.risingwave_dsn)
    if not dsn.hostname or not dsn.port:
        raise CheckFailed(
            "RISINGWAVE_DSN has no host and port; the engine needs a listen "
            "address to bind"
        )
    first_broker = infrastructure.kafka_bootstrap_servers.split(",")[0].strip()
    host, _, port = first_broker.rpartition(":")
    if not host or not port.isdigit():
        raise CheckFailed(
            f"KAFKA_BOOTSTRAP_SERVERS does not start with host:port: "
            f"{first_broker!r}"
        )
    return {
        "RISINGWAVE_DSN": infrastructure.risingwave_dsn,
        "RW_LISTEN_ADDR": f"{dsn.hostname}:{dsn.port}",
        "KAFKA_BOOTSTRAP_SERVERS": infrastructure.kafka_bootstrap_servers,
        "BLINK_BROKER_PORTS": port,
        "BLINK_KAFKA_HOSTNAME": host,
    }


def _wait_for_endpoints(deadline: float, recorded: dict[str, str]) -> list[str]:
    resolved = addresses()
    while True:
        try:
            return check_engine(resolved["RISINGWAVE_DSN"], recorded) + check_broker(
                resolved["KAFKA_BOOTSTRAP_SERVERS"]
            )
        except CheckFailed:
            if time.monotonic() >= deadline:
                raise
            time.sleep(1.0)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--binaries-only",
        action="store_true",
        help="check the pins only; nothing has to be running",
    )
    parser.add_argument(
        "--wait",
        type=float,
        default=0.0,
        metavar="SECONDS",
        help="retry the endpoint checks for up to SECONDS before failing",
    )
    parser.add_argument(
        "--addresses",
        action="store_true",
        help="print the resolved addresses as shell assignments and exit",
    )
    arguments = parser.parse_args(argv)

    try:
        if arguments.addresses:
            resolved = addresses()
            # Only what `dev-up` needs to bind. The DSN and the bootstrap list
            # are resolved again inside this module when the endpoints are
            # checked, so neither has to travel through a shell.
            for name in ("RW_LISTEN_ADDR", "BLINK_BROKER_PORTS", "BLINK_KAFKA_HOSTNAME"):
                print(f"{name}={shlex.quote(resolved[name])}")
            return 0
        recorded = pins()
        reported = check_binaries(recorded)
        if not arguments.binaries_only:
            reported += _wait_for_endpoints(
                time.monotonic() + arguments.wait, recorded
            )
    except CheckFailed as failure:
        print(f"FAILED: {failure}", file=sys.stderr)
        return 1
    for line in reported:
        print(f"ok: {line}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
