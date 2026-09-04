"""Broker — the Kafka wire protocol, and nothing else.

`concept/03-architecture.md` states the rule twice, once as an interface and
once as a constraint:

> **The broker is addressed only through the Kafka wire protocol.** No component
> codes against a specific broker; replacing it must be a configuration change.
> That rule holds on both ends, which is what keeps ingress and egress on the
> same terms.

This module is the whole of "both ends". It is the only place in the package
that imports a Kafka client, the only place that constructs one, and it holds no
knowledge of HELENA's contracts: a `Message` is an offset, some bytes and some
header bytes. What those bytes mean belongs to `helena.normalizer`
(`IngestMessage`), so this file could be pointed at a different broker — or at a
different message — without either of them knowing.

Two things follow from that split and both are deliberate:

- **The address is a parameter, never a literal.** `from_settings` reads
  `KAFKA_BOOTSTRAP_SERVERS` through `helena.config` and there is no default and
  no fallback. `tests/test_broker.py` asserts this module contains no address.
- **Topic names are not here either.** They are configuration
  (`HELENA_INGEST_TOPIC`), passed in per call, because a topic name compiled
  into the client is the same mistake as an address compiled into it.

## The broker is not a store

`concept/03-architecture.md` puts the broker under *what is not a store*:
memory-first, single-node, consume-once and restart-volatile. Measured against
the pinned blink 0.2.0 rather than taken from the note (2026-09-03): three
records produced to a topic, drained once from `OFFSET_BEGINNING`, and a second
drain from `OFFSET_BEGINNING` returns **nothing** — the watermarks are back to
`(0, 0)`. A topic really is never re-readable, whatever retention says.

So nothing here retries by re-reading, no offset is stored anywhere, and
`consume` reads from the beginning because there is nothing else to read from.
The durable record is the retained capture; see `docs/runbook.md` §3.

## Consumer groups do not work against the pinned broker

Blink 0.2.0 closes the TCP connection on `FindCoordinatorRequest v2`, so
`subscribe()` waits forever and raises nothing (measured in task 03,
`docs/runbook.md`). `consume` therefore uses `assign()` on an explicit
partition. That is a property of this broker, not of the protocol — assignment
is Kafka, and swapping in a broker with working coordinators would not change a
line of this module.

Reads: the broker, over the Kafka wire protocol. Writes: the broker, the same
way.

Maturity: experimental — exercised by `tests/test_broker.py` against the pinned
blink, including the round trip with headers and the consume-once measurement
above. It has never run against any other broker, so "replacing the broker is a
configuration change" is a property of the code's shape here, not something that
has been demonstrated by doing it.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from types import TracebackType

from confluent_kafka import (
    OFFSET_BEGINNING,
    Consumer,
    KafkaError,
    KafkaException,
    Producer,
    TopicPartition,
)
from confluent_kafka.admin import AdminClient, NewTopic

from helena.config import Settings

__all__ = [
    "DEFAULT_IDLE_TIMEOUT_SECONDS",
    "DEFAULT_PARTITION",
    "BrokerConsumer",
    "BrokerError",
    "BrokerProducer",
    "Message",
]

# How long `consume` waits for a message before deciding the topic has gone
# quiet. A drain has to end somewhere and the broker cannot say "that was the
# last one": there is no end-of-stream in the protocol, and with consume-once
# semantics a message that arrives after the drain ended is simply gone. The
# caller reconciles what it consumed against the capture (see
# `helena.normalizer.ingest_counts`), which is what turns "the topic went quiet"
# into a countable fact rather than an assumption.
DEFAULT_IDLE_TIMEOUT_SECONDS = 5.0

# The broker runs one partition per topic (`KAFKA_CFG_NUM_PARTITIONS=1`,
# `docs/runbook.md` §3). The number is a parameter rather than an assumption
# baked into the loop, but there is exactly one value in use and no code that
# fans out across partitions — that would be ordering machinery for a case that
# does not exist.
DEFAULT_PARTITION = 0

# How long to wait for the broker on a blocking call: topic creation, and the
# final flush. Long enough that a slow local broker is not a failure, short
# enough that a dead one is reported rather than waited on.
_BROKER_TIMEOUT_SECONDS = 30.0


class BrokerError(RuntimeError):
    """The broker did not do what the Kafka protocol says it would.

    Raised rather than returned, and never swallowed. A message the broker did
    not accept is a message that is gone — the broker keeps nothing — so a
    producer that carried on would lose records with nothing to count.
    """


@dataclass(frozen=True)
class Message:
    """One message on a topic, as the wire carries it.

    Deliberately not a HELENA contract: an offset, the value bytes exactly as
    they were produced, and the headers as bytes. `helena.normalizer` is what
    reads a raw-record reference out of the headers, and it is the only thing
    that knows there is one.

    `offset` is the broker's own offset in the partition, not the record's
    offset in a capture. The two are different numbers with the same name in
    different places, which is why nothing here calls it "offset" alone.
    """

    topic: str
    partition: int
    offset: int
    value: bytes
    headers: Mapping[str, bytes]


class BrokerProducer:
    """Publishes to a topic over the Kafka wire protocol.

    A thin wrapper. It exists for three reasons, not to hide the client:

    - to make `helena.broker` the one place a Kafka client is constructed, so
      the boundary test in `tests/test_broker.py` has something to assert;
    - because a delivery failure in librdkafka is asynchronous — `produce`
      returns before the broker has seen anything, and without a delivery
      callback a rejected message is a silent loss. `flush` here raises;
    - because producing to a topic that does not exist leaves the message in the
      queue with no error at all (measured, `docs/runbook.md` §3), so
      `create_topic` is a step a caller must not be able to forget.
    """

    def __init__(self, bootstrap_servers: str) -> None:
        self.bootstrap_servers = bootstrap_servers
        self._producer = Producer({"bootstrap.servers": bootstrap_servers})
        self._admin = AdminClient({"bootstrap.servers": bootstrap_servers})
        self._failures: list[str] = []

    @classmethod
    def from_settings(cls, settings: Settings) -> BrokerProducer:
        """The producer this deployment is configured to be."""
        return cls(settings.infrastructure.kafka_bootstrap_servers)

    def create_topic(self, topic: str) -> bool:
        """Create `topic` if metadata does not already show it. True if created.

        Both calls are Kafka protocol APIs — `Metadata` and `CreateTopics`.
        `concept/03-architecture.md`'s rule is about the protocol, not about
        which of its request types are used; the broker's own REST surface is
        what is never touched, and `tests/test_broker.py` asserts this module
        cannot reach it.

        **Metadata first, rather than create-and-catch**, and that is a
        measurement rather than a preference. Measured against blink 0.2.0
        (2026-09-03): `CreateTopics` for a topic that already exists does *not*
        come back as `TOPIC_ALREADY_EXISTS`. The broker sends a response
        librdkafka cannot parse at all — `_BAD_MSG`, "CreateTopics response
        protocol parse failure", with a second line saying the broker returned a
        topic that was not in the request — so the "already exists" case is
        indistinguishable by error code from a broker that is genuinely
        misbehaving. Asking metadata is the only way to tell them apart.

        The race between the check and the create is real and is not worth
        machinery here: one producer publishes a capture, the broker is
        single-node, and a lost race surfaces as the parse failure below rather
        than as a silently missing topic.
        """
        if topic in self._admin.list_topics(timeout=_BROKER_TIMEOUT_SECONDS).topics:
            return False
        request = NewTopic(topic, num_partitions=1, replication_factor=1)
        for created in self._admin.create_topics([request]).values():
            try:
                created.result(timeout=_BROKER_TIMEOUT_SECONDS)
            except KafkaException as error:
                raise BrokerError(
                    f"could not create topic {topic!r} on "
                    f"{self.bootstrap_servers}: {error}. A parse failure here "
                    f"is what the pinned broker answers when the topic already "
                    f"exists, so metadata and this call disagree — something "
                    f"else created it in between."
                ) from error
        return True

    def publish(
        self, topic: str, value: bytes, headers: Mapping[str, bytes]
    ) -> None:
        """Queue one message. Delivery is confirmed by `flush`, not by this.

        Nothing has reached the broker when this returns — librdkafka batches —
        which is why every caller must flush before it believes anything was
        sent.
        """
        try:
            self._producer.produce(
                topic,
                value=value,
                headers=list(headers.items()),
                on_delivery=self._delivered,
            )
        except BufferError as error:
            # The local queue is full because the broker is not keeping up.
            # Draining it here would hide a broker that has stopped accepting
            # records behind a slow producer.
            raise BrokerError(
                f"the local produce queue for {topic!r} is full: {error}"
            ) from error
        self._producer.poll(0)

    def flush(self, timeout: float = _BROKER_TIMEOUT_SECONDS) -> None:
        """Wait for every queued message, and raise if any did not arrive.

        Two separate failures, kept apart: messages still outstanding when the
        timeout expired, and messages the broker refused. Both mean records were
        lost, and neither is a return value a caller can ignore.
        """
        outstanding = self._producer.flush(timeout)
        if outstanding:
            raise BrokerError(
                f"{outstanding} message(s) were still queued for "
                f"{self.bootstrap_servers} after {timeout:.0f}s. A topic that "
                f"does not exist is the usual cause — create it first."
            )
        if self._failures:
            failures = "; ".join(self._failures)
            self._failures.clear()
            raise BrokerError(f"the broker refused {failures}")

    def _delivered(self, error: KafkaError | None, message: object) -> None:
        if error is not None:
            self._failures.append(str(error))

    def __enter__(self) -> BrokerProducer:
        return self

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        # Flush on the way out only when the block succeeded. Flushing while an
        # exception is propagating would raise a second one over the first.
        if exception_type is None:
            self.flush()


class BrokerConsumer:
    """Reads a topic over the Kafka wire protocol, once.

    By explicit assignment rather than subscription, because the pinned broker's
    coordinator disconnects (see the module docstring). No offset is committed
    and none is stored: the topic is consume-once, so there is no second read to
    resume.
    """

    def __init__(self, bootstrap_servers: str) -> None:
        self.bootstrap_servers = bootstrap_servers
        self._consumer = Consumer(
            {
                "bootstrap.servers": bootstrap_servers,
                # librdkafka requires a group id even for an assignment-only
                # consumer. Nothing joins a group — see the module docstring —
                # so this names the client rather than coordinating anything.
                "group.id": "helena",
                "enable.auto.commit": False,
            }
        )

    @classmethod
    def from_settings(cls, settings: Settings) -> BrokerConsumer:
        """The consumer this deployment is configured to be."""
        return cls(settings.infrastructure.kafka_bootstrap_servers)

    def consume(
        self,
        topic: str,
        *,
        partition: int = DEFAULT_PARTITION,
        idle_timeout: float = DEFAULT_IDLE_TIMEOUT_SECONDS,
    ) -> Iterator[Message]:
        """Every message on `topic`, in offset order, until it goes quiet.

        Ends after `idle_timeout` seconds with nothing arriving. It cannot end
        any other way: the protocol has no end-of-stream, and a bounded run that
        waited for one would never return.

        A broker-side error on a message is raised, not skipped. A message that
        could not be read is not a record this deployment can quarantine — there
        is nothing to quarantine — and continuing past it would lose a record
        with nothing counting it.
        """
        self._consumer.assign([TopicPartition(topic, partition, OFFSET_BEGINNING)])
        while True:
            message = self._consumer.poll(idle_timeout)
            if message is None:
                return
            if message.error() is not None:
                raise BrokerError(
                    f"the broker returned an error for {topic!r} partition "
                    f"{partition}: {message.error()}"
                )
            yield Message(
                topic=message.topic(),
                partition=message.partition(),
                offset=message.offset(),
                value=message.value(),
                headers=dict(message.headers() or []),
            )

    def close(self) -> None:
        self._consumer.close()

    def __enter__(self) -> BrokerConsumer:
        return self

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()
