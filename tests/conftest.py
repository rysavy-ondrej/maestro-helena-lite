"""Fixtures for the tests that need the pinned engine and broker running.

`scripts/dev_check.py` holds the definition of "the endpoint answers"; this file
holds the definition of "there is one to ask". A fixture starts the pinned binary
itself when nothing is listening, so the suite needs no infrastructure to have
been brought up first — but it uses an instance that `scripts/dev-up` already
started when there is one, because a second RisingWave cannot run alongside the
first (`--listen-addr` moves the PostgreSQL port, the meta and compute services
still bind 5690 and 5688).

The readiness wait lives in the fixtures rather than in a test, so no test can
address an endpoint before the endpoint has answered.
"""

from __future__ import annotations

import subprocess
import sys
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4

import psycopg
import pytest

from helena import migrations

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

import dev_check  # noqa: E402  (needs the path above)

# The infrastructure smoke test. Everything that needs an engine or a broker
# runs after it, so a failure reads as "the endpoints are down" once rather than
# as every integration test failing separately.
SMOKE_MODULE = "test_infrastructure"

STARTUP_TIMEOUT_SECONDS = 180.0


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Unit tests, then the smoke test, then the rest of the integration tests.

    `list.sort` is stable, so nothing is reordered within a group.
    """

    def group(item: pytest.Item) -> int:
        if "integration" not in item.keywords:
            return 0
        return 1 if item.module.__name__ == SMOKE_MODULE else 2

    items.sort(key=group)


@pytest.fixture(scope="session")
def pins() -> dict[str, str]:
    return dev_check.pins()


@pytest.fixture(scope="session")
def pinned_binaries(pins: dict[str, str]) -> None:
    """Skip rather than fail when bin/ is empty.

    `bin/` is not committed, so a fresh checkout has no binaries at all. That is
    a missing artifact, not a broken project — `scripts/dev-up` is what fails
    loud about it, naming docs/versions.md.
    """
    for key in pins:
        if not key.startswith("sha256.bin/"):
            continue
        relative = key[len("sha256.") :]
        if not (PROJECT_ROOT / relative).exists():
            pytest.skip(f"{relative} is not on disk; see docs/versions.md")


@pytest.fixture(scope="session")
def addresses(pinned_binaries: None) -> dict[str, str]:
    return dev_check.addresses()


def _answers(check: Callable[[], object]) -> bool:
    try:
        check()
    except dev_check.CheckFailed:
        return False
    return True


def _tail(log: Path, lines: int = 15) -> str:
    if not log.exists():
        return "(no log)"
    return "\n".join(log.read_text(errors="replace").splitlines()[-lines:])


@contextmanager
def _serve(
    name: str,
    argv: list[str],
    cwd: Path,
    env: dict[str, str],
    answers: Callable[[], object],
    log: Path,
) -> Iterator[None]:
    """Start a binary if nothing is answering, and stop only what was started."""
    if _answers(answers):
        yield
        return
    cwd.mkdir(parents=True, exist_ok=True)
    with log.open("wb") as handle:
        process = subprocess.Popen(argv, cwd=cwd, env=env, stdout=handle, stderr=handle)
    try:
        deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
        while not _answers(answers):
            if process.poll() is not None:
                raise RuntimeError(
                    f"{name} exited with {process.returncode} before it "
                    f"answered; last of {log}:\n{_tail(log)}"
                )
            if time.monotonic() >= deadline:
                raise RuntimeError(
                    f"{name} did not answer within {STARTUP_TIMEOUT_SECONDS:.0f}s; "
                    f"last of {log}:\n{_tail(log)}"
                )
            time.sleep(1.0)
        yield
    finally:
        process.terminate()
        try:
            process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=30)


@pytest.fixture(scope="session")
def engine_dsn(
    addresses: dict[str, str],
    pins: dict[str, str],
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[str]:
    """A RisingWave answering the PostgreSQL wire protocol on the configured DSN.

    In-memory when this fixture starts it, so a test run leaves no store behind.
    The working directory is a temporary one because the engine writes its
    temp-secret directory relative to where it was started.
    """
    dsn = addresses["RISINGWAVE_DSN"]
    workdir = tmp_path_factory.mktemp("engine")
    with _serve(
        name="risingwave",
        argv=[
            str(PROJECT_ROOT / "bin" / "risingwave"),
            "single_node",
            "--in-memory",
            "--listen-addr",
            addresses["RW_LISTEN_ADDR"],
            "--config-path",
            str(PROJECT_ROOT / "scripts" / "risingwave.toml"),
        ],
        cwd=workdir,
        env=dev_check.engine_env(),
        answers=lambda: dev_check.check_engine(dsn, pins),
        log=workdir / "risingwave.log",
    ):
        yield dsn


@pytest.fixture(scope="session")
def broker_bootstrap(
    addresses: dict[str, str], tmp_path_factory: pytest.TempPathFactory
) -> Iterator[str]:
    """A Blink answering the Kafka wire protocol on the configured bootstrap."""
    bootstrap = addresses["KAFKA_BOOTSTRAP_SERVERS"]
    workdir = tmp_path_factory.mktemp("broker")
    env = dev_check.engine_env()
    env["BROKER_PORTS"] = addresses["BLINK_BROKER_PORTS"]
    env["KAFKA_HOSTNAME"] = addresses["BLINK_KAFKA_HOSTNAME"]
    with _serve(
        name="blink",
        argv=[
            str(PROJECT_ROOT / "bin" / "blink"),
            "--settings",
            str(PROJECT_ROOT / "scripts" / "blink.yaml"),
        ],
        cwd=workdir,
        env=env,
        answers=lambda: dev_check.check_broker(bootstrap),
        log=workdir / "blink.log",
    ):
        yield bootstrap


@pytest.fixture
def engine_schema(engine_dsn: str) -> Iterator[psycopg.Connection]:
    """A connection whose `search_path` is a schema of its own, dropped after.

    The throwaway unit is a **schema**, not a process. `single_node` binds fixed
    meta and compute ports, so a second engine cannot run beside the first (see
    docs/runbook.md) — but an unqualified `CREATE TABLE` lands in `search_path`,
    so a schema gives each test an empty store that `DROP SCHEMA ... CASCADE`
    takes away again, on the throwaway in-memory engine `engine_dsn` provides.

    Autocommit because RisingWave DDL inside an open transaction is not visible
    to the statements that follow it.
    """
    schema = f"helena_test_{uuid4().hex}"
    with psycopg.connect(engine_dsn, autocommit=True, connect_timeout=5) as connection:
        connection.execute(f"CREATE SCHEMA {schema}")
        try:
            connection.execute(f"SET search_path TO {schema}")
            yield connection
        finally:
            connection.execute("SET search_path TO public")
            connection.execute(f"DROP SCHEMA {schema} CASCADE")


@pytest.fixture
def migrated_engine(engine_schema: psycopg.Connection) -> psycopg.Connection:
    """`engine_schema` with every migration in `sql/migrations/` applied.

    This is what anything needing the engine's schema should take: the views a
    test queries are the ones a deployment gets, from the same files, applied by
    the same runner.
    """
    migrations.apply(engine_schema)
    return engine_schema
