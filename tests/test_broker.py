"""The broker boundary: one wire protocol, one client, an address from configuration.

Two halves, and they check different kinds of thing.

The **boundary** tests are structural. `concept/03-architecture.md` requires the
broker to be addressed only through the Kafka wire protocol, on both ends, so
that replacing it is a configuration change — and the way that rule is broken is
never a decision anybody records. It is one import of a broker's own admin SDK,
or one health check against blink's REST port on 30004 because it is easier than
metadata, or one `bootstrap.servers` typed into a module. These tests fail on
each of those.

The **round-trip** tests are behavioural, against the pinned broker, because a
structural test cannot tell whether the wrapper actually carries a record and its
headers — and the headers are where the raw-record reference travels
(`docs/decisions/0014-the-ingest-topic-message.md`).
"""

from __future__ import annotations

import ast
import re
import time
import uuid
from pathlib import Path

import pytest

from helena.broker import BrokerConsumer, BrokerError, BrokerProducer
from helena.config import Settings

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PACKAGE_ROOT = PROJECT_ROOT / "src" / "helena"
BROKER_MODULE = PACKAGE_ROOT / "broker.py"

# The Kafka client, and the only names of it this package may bind. Every one is
# a wire-protocol client or a protocol-level constant:
#
#   Producer / Consumer          Produce and Fetch
#   AdminClient / NewTopic       CreateTopics — a Kafka protocol API (key 19),
#                                which is why it is here and blink's REST port
#                                is not
#   TopicPartition               an assignment, since the pinned broker has no
#                                working consumer coordinator
#   OFFSET_BEGINNING             the only offset a consume-once topic has
#   KafkaError / KafkaException  the protocol's own errors
#
# Anything else — a broker vendor's SDK, a management client, a schema registry —
# is outside the protocol and a decision, not an import.
KAFKA_CLIENT = "confluent_kafka"
WIRE_PROTOCOL_NAMES = {
    "AdminClient",
    "Consumer",
    "KafkaError",
    "KafkaException",
    "NewTopic",
    "OFFSET_BEGINNING",
    "Producer",
    "TopicPartition",
}

# What talking to a broker any other way looks like. `helena.broker` may not
# reach the network except through the Kafka client, so an HTTP or socket client
# in it is the REST port one line away.
NETWORK_MODULES = {"http", "urllib", "socket", "ssl", "ftplib", "telnetlib", "xmlrpc"}

# How long a drained topic is given to become unreadable. Measured against blink
# 0.2.0: between 0 and about 6 seconds, and it is a background reclaim rather
# than a step of the read, so this is a deadline and not a duration to assert.
RECLAIM_DEADLINE_SECONDS = 45.0

# A literal address, in any of the forms one gets written in. The address comes
# from KAFKA_BOOTSTRAP_SERVERS through `helena.config` and from nowhere else; a
# literal here is the fallback that makes "replacing the broker is a
# configuration change" false without anybody noticing.
ADDRESS_LITERAL = re.compile(
    r"(\d{1,3}(?:\.\d{1,3}){3}:\d+|localhost:\d+|\w+://|:\d{4,5}\b)"
)


def _module_paths() -> list[Path]:
    return sorted(PACKAGE_ROOT.rglob("*.py"))


def _imports(source: Path) -> dict[str, set[str]]:
    """Top-level module name -> the names bound from it, for one file."""
    found: dict[str, set[str]] = {}
    for node in ast.walk(ast.parse(source.read_text(), filename=str(source))):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.setdefault(alias.name.split(".")[0], set()).add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            found.setdefault(node.module.split(".")[0], set()).update(
                alias.name for alias in node.names
            )
    return found


def _string_constants(source: Path) -> list[str]:
    """Every string literal in a file except the docstrings.

    Docstrings are excluded deliberately: this module's own docstring quotes the
    measured facts about the pinned broker, including its REST port, and a test
    that could not tell a documented measurement from a hardcoded address would
    push the measurement out of the repository — which is the opposite of what
    `concept/instruction.md` §5 asks for.
    """
    tree = ast.parse(source.read_text(), filename=str(source))
    docstrings = {
        ast.get_docstring(node, clean=False)
        for node in ast.walk(tree)
        if isinstance(
            node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef
        )
    }
    return [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value not in docstrings
    ]


def test_only_the_broker_module_imports_a_kafka_client():
    """One place a broker client is constructed, so there is one place to check."""
    importers = sorted(
        path.name
        for path in _module_paths()
        if KAFKA_CLIENT in _imports(path)
    )
    assert importers == ["broker.py"], (
        f"{KAFKA_CLIENT} is imported by {importers}. The broker is addressed "
        f"through helena.broker and nothing else, so that 'replacing the broker "
        f"is a configuration change' has one place it can be true or false."
    )


def test_the_broker_module_binds_only_wire_protocol_names():
    bound = _imports(BROKER_MODULE)[KAFKA_CLIENT]
    beyond = sorted(bound - WIRE_PROTOCOL_NAMES)
    assert not beyond, (
        f"helena/broker.py binds {beyond} from {KAFKA_CLIENT}, which is not one "
        f"of the wire-protocol names this project has approved. A client API "
        f"beyond the protocol is a decision, not an import."
    )


def test_the_broker_module_reaches_the_network_no_other_way():
    """No HTTP and no raw socket — so the broker's REST port is unreachable."""
    reachable = sorted(set(_imports(BROKER_MODULE)) & NETWORK_MODULES)
    assert not reachable, (
        f"helena/broker.py imports {reachable}. The pinned broker has a REST "
        f"port and it is deliberately never touched (docs/runbook.md §3); an "
        f"HTTP client in this module is that health check one line away."
    )


def test_no_module_in_the_package_holds_a_broker_address():
    offenders = {
        path.name: sorted(
            {
                literal
                for literal in _string_constants(path)
                if ADDRESS_LITERAL.search(literal)
            }
        )
        for path in _module_paths()
    }
    offenders = {name: found for name, found in offenders.items() if found}
    assert not offenders, (
        f"address-shaped literals in the package: {offenders}. Addresses come "
        f"from helena.config (RISINGWAVE_DSN, KAFKA_BOOTSTRAP_SERVERS) and "
        f"topic names from HELENA_INGEST_TOPIC; a literal is a default, and "
        f"there are no defaults."
    )


def test_the_producer_and_consumer_take_the_configured_address():
    """`from_settings` resolves the address, and resolves it from one variable."""
    settings = Settings.load(
        environ={
            "LLM_URL": "u",
            "LLM_TOKEN": "t",
            "LLM_MODEL": "m",
            "HELENA_TENANT": "acme",
            "HELENA_SENSOR": "sensor-1",
            "HELENA_INPUT_FORMAT": "flow-json",
            "ABUSECH_AUTH_KEY": "k",
            "VIRUSTOTAL_AUTH_KEY": "k",
            "RISINGWAVE_DSN": "postgresql://root@127.0.0.1:4566/dev",
            "KAFKA_BOOTSTRAP_SERVERS": "192.0.2.7:9092",
            "HELENA_INGEST_TOPIC": "helena.ingest",
        },
        env_file=None,
    )
    with BrokerProducer.from_settings(settings) as producer:
        assert producer.bootstrap_servers == "192.0.2.7:9092"
    with BrokerConsumer.from_settings(settings) as consumer:
        assert consumer.bootstrap_servers == "192.0.2.7:9092"


@pytest.mark.integration
def test_a_message_and_its_headers_survive_the_round_trip(broker_bootstrap: str):
    """The wrapper carries the bytes and the headers, unchanged.

    The headers matter as much as the value here: the raw-record reference
    travels in them, so a wrapper that dropped them would produce events with no
    way back to the record they came from.
    """
    topic = f"helena-test-{uuid.uuid4().hex[:12]}"
    headers = {"helena-capture-sha256": b"a" * 64, "helena-record-offset": b"41"}
    with BrokerProducer(broker_bootstrap) as producer:
        assert producer.create_topic(topic) is True
        assert producer.create_topic(topic) is False, "the second call created it again"
        producer.publish(topic, b'{"id":"udp.0"}', headers)

    with BrokerConsumer(broker_bootstrap) as consumer:
        received = list(consumer.consume(topic, idle_timeout=2.0))

    assert len(received) == 1
    assert received[0].value == b'{"id":"udp.0"}'
    assert received[0].headers == headers
    assert received[0].topic == topic


@pytest.mark.integration
def test_a_record_that_has_been_read_is_reclaimed_and_one_that_has_not_is_kept(
    broker_bootstrap: str,
):
    """The broker is not a store, measured — including the part the note omits.

    `concept/03-architecture.md`: *memory-first, single-node, consume-once and
    restart-volatile: a record read once is gone whatever retention says. A topic
    is never re-readable.* Measured against blink 0.2.0 (2026-09-03), that is
    true in substance and **not instantaneous**: a second drain started
    immediately after the first can still return every record, and the reclaim
    lands a few seconds later. Both halves are asserted here, because a retry
    written against the note alone would look correct and would occasionally
    double-ingest a capture.

    The second topic is the control that makes this a statement about *reading*
    rather than about a short retention window: produced at the same moment,
    never read, and still holding its records when the drained one has been
    emptied. Without it, "the records went away" would be equally explained by
    a retention timer.
    """
    drained, untouched = (
        f"helena-test-{uuid.uuid4().hex[:12]}" for _ in range(2)
    )
    with BrokerProducer(broker_bootstrap) as producer:
        for topic in (drained, untouched):
            producer.create_topic(topic)
            for index in range(3):
                producer.publish(topic, f"record-{index}".encode(), {})

    def drain(topic: str) -> list[bytes]:
        with BrokerConsumer(broker_bootstrap) as consumer:
            return [
                message.value for message in consumer.consume(topic, idle_timeout=1.0)
            ]

    assert drain(drained) == [b"record-0", b"record-1", b"record-2"]

    deadline = time.monotonic() + RECLAIM_DEADLINE_SECONDS
    while drain(drained) and time.monotonic() < deadline:
        pass
    assert drain(drained) == [], (
        f"the topic was still re-readable {RECLAIM_DEADLINE_SECONDS:.0f}s after "
        f"being drained. Everything downstream assumes a record read once is "
        f"gone: replay reads the retained capture, and the ingest counters treat "
        f"a consumed record as unrecoverable."
    )
    assert drain(untouched) == [b"record-0", b"record-1", b"record-2"], (
        "a topic nobody read lost its records too, so this is a retention "
        "window rather than consume-once, and the measurement above says "
        "something different from what it claims."
    )


@pytest.mark.integration
def test_producing_to_a_topic_that_does_not_exist_is_an_error_not_a_silence(
    broker_bootstrap: str,
):
    """The measured failure mode of the pinned broker, turned into an exception.

    `docs/runbook.md` §3: producing to a topic that was never created leaves the
    message in the local queue with no error at all. `flush` is what makes that
    countable — without it, a whole capture can be "published" to nowhere.
    """
    topic = f"helena-absent-{uuid.uuid4().hex[:12]}"
    producer = BrokerProducer(broker_bootstrap)
    producer.publish(topic, b"never-arrives", {})
    with pytest.raises(BrokerError) as caught:
        producer.flush(timeout=5.0)
    assert "still queued" in str(caught.value)
