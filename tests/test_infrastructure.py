"""The pinned binaries are the pinned binaries, and both endpoints answer.

This is the smoke test `prds/prd.json` task 3 asks for. `conftest.py` orders it
ahead of every other test that carries the `integration` marker, so a dead
engine or broker is reported once here rather than as a wall of unrelated
failures.

The four checks that do not need anything running come first, because one of
them — the libpython one — is the only thing that catches a wrong Python minor
at all. See docs/runbook.md.
"""

from __future__ import annotations

import subprocess
import sys
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import dev_check  # noqa: E402  (needs the path above)

from conftest import pytest_collection_modifyitems  # noqa: E402


def test_the_pinned_binaries_match_their_recorded_checksums(
    pinned_binaries: None, pins: dict[str, str]
):
    assert dev_check.check_checksums(pins)


def test_the_engine_resolves_the_pinned_libpython(
    pinned_binaries: None, pins: dict[str, str]
):
    assert dev_check.check_linked_libpython(pins)


def test_a_different_python_minor_under_that_name_is_rejected(
    pinned_binaries: None, pins: dict[str, str], tmp_path: Path, monkeypatch
):
    """The hazard, reproduced: the SONAME satisfied by the wrong minor version.

    Nothing about running the engine detects this — it starts, serves SQL and
    reports the right version — so the check has to be structural, and this is
    the test that proves the structural check works.
    """
    others = [
        candidate
        for candidate in Path("/usr/lib").glob("*/libpython3.*.so.1.0")
        if candidate.name != dev_check.LIBPYTHON_SONAME
    ]
    if not others:
        pytest.skip("no other libpython minor on this machine to mis-link against")
    (tmp_path / dev_check.LIBPYTHON_SONAME).symlink_to(others[0])
    monkeypatch.setattr(dev_check, "LIBPYTHON_DIR", tmp_path)

    with pytest.raises(dev_check.CheckFailed) as caught:
        dev_check.check_linked_libpython(pins)
    assert "ABI mismatch" in str(caught.value)


def test_the_binaries_report_the_recorded_versions(
    pinned_binaries: None, pins: dict[str, str]
):
    assert dev_check.check_binary_versions(pins)


def test_the_smoke_test_is_ordered_before_the_other_integration_tests():
    """The ordering `conftest.pytest_collection_modifyitems` is there to impose."""

    def item(name, module, integration):
        return SimpleNamespace(
            name=name,
            module=SimpleNamespace(**{"__name__": module}),
            keywords={"integration"} if integration else set(),
        )

    items = [
        item("other-integration", "test_migrations", True),
        item("unit", "test_config", False),
        item("smoke", "test_infrastructure", True),
    ]
    pytest_collection_modifyitems(items)
    assert [item.name for item in items] == ["unit", "smoke", "other-integration"]


@pytest.mark.integration
def test_the_engine_answers_the_postgresql_wire_protocol(
    engine_dsn: str, pins: dict[str, str]
):
    """A plain psycopg client, and the running engine is the pinned version.

    `check_engine` compares `SELECT version()` against `version.engine-wire` in
    docs/versions.md — the second copy of the version constant, asserted equal
    to what the process actually reports.
    """
    import psycopg

    assert dev_check.check_engine(engine_dsn, pins)
    with psycopg.connect(engine_dsn, autocommit=True) as connection:
        assert connection.execute("SELECT 1").fetchone() == (1,)


@pytest.mark.integration
def test_the_broker_answers_the_kafka_wire_protocol(broker_bootstrap: str):
    assert dev_check.check_broker(broker_bootstrap)


@pytest.mark.integration
def test_a_record_survives_a_round_trip_through_the_broker(broker_bootstrap: str):
    """Ingress and egress in one: the broker is addressed only over Kafka.

    Consumption is by explicit assignment, not by subscription — see the
    consumer-group section of docs/runbook.md.
    """
    from confluent_kafka import OFFSET_BEGINNING, Consumer, Producer, TopicPartition
    from confluent_kafka.admin import AdminClient, NewTopic

    topic = f"helena-smoke-{uuid.uuid4().hex[:12]}"
    admin = AdminClient({"bootstrap.servers": broker_bootstrap})
    for created in admin.create_topics(
        [NewTopic(topic, num_partitions=1, replication_factor=1)]
    ).values():
        created.result(timeout=15)

    payload = topic.encode()
    producer = Producer({"bootstrap.servers": broker_bootstrap})
    producer.produce(topic, payload)
    assert producer.flush(15) == 0, "the broker did not accept the record"

    consumer = Consumer(
        {
            "bootstrap.servers": broker_bootstrap,
            "group.id": topic,
            "enable.auto.commit": False,
        }
    )
    try:
        consumer.assign([TopicPartition(topic, 0, OFFSET_BEGINNING)])
        received = None
        for _ in range(20):
            message = consumer.poll(1.0)
            if message is None:
                continue
            assert not message.error(), message.error()
            received = message.value()
            break
    finally:
        consumer.close()
    assert received == payload


def test_dev_up_and_dev_down_are_executable():
    for script in ("dev-up", "dev-down"):
        path = Path(__file__).resolve().parent.parent / "scripts" / script
        assert path.exists(), f"scripts/{script} is missing"
        result = subprocess.run(
            ["bash", "-n", str(path)], capture_output=True, text=True
        )
        assert result.returncode == 0, result.stderr
