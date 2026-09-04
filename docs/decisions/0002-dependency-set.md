# 0002 — The dependency set, and what is deliberately absent

**Status: accepted.** Task 0 (D0 Foundations).
**Authority:** `concept/06-technology.md`, `concept/instruction.md` §3.

Adding a runtime dependency is an escalation, not an edit. This file is the
record of the ones that are here and why, and `tests/test_dependency_boundary.py`
is what makes the record enforceable: it derives the approved set from
`pyproject.toml`, and fails if a module in `helena/` imports anything outside it.

## Runtime

| Distribution | Import name | Why it is here |
| --- | --- | --- |
| `pydantic` | `pydantic` | Agent request/result schemas and the normalizer's validated events. `concept/06-technology.md` names it: versioned schemas with historical versions retained as frozen classes, which is validation plus a stable class identity, not a serialisation helper |
| `python-dotenv` | `dotenv` | Configuration arrives through the environment; local development keeps it in `.env`. Loading it through one project path is what lets the fail-loud rule be implemented in one place rather than at every read site |
| `confluent-kafka` | `confluent_kafka` | Ingress and egress, over the Kafka wire protocol on both ends — see below |
| `psycopg[binary]` | `psycopg` | The engine speaks the PostgreSQL wire protocol, so the store is reached with an ordinary PostgreSQL client. `[binary]` because the wheel carries libpq and the node has no system libpq to link against |

## Development

| Distribution | Why |
| --- | --- |
| `pytest` | The one test suite |

## Why `confluent-kafka` and not another Kafka client

The requirement is the *protocol*, not a broker: `concept/03-architecture.md`
requires the broker to be addressed only through the Kafka wire protocol, on both
ends, so that replacing it is a configuration change.

The choice was **checked against the artifact, not a page** — against the pinned
`bin/blink` 0.2.0 binary, on 2026-09-03:

- metadata and `AdminClient.create_topics` worked;
- produce with delivery confirmation worked **after the topic was created**;
- consume worked via **manual `assign()`** with `OFFSET_BEGINNING`;
- consume via **`subscribe()` returned nothing** in the same probe — consumer
  group coordination against this broker is unverified and is a question for the
  increment that wires the broker, not an assumed capability.

`kafka-python` was not tried: it is a second implementation of the same protocol
with a weaker maintenance record, and choosing it would still have needed the
same probe. The boundary test lists `kafka` among the deliberately absent
top-level modules so that a second client cannot arrive by accident.

`psycopg` was checked the same way against `bin/risingwave` 3.0.3 in
`playground` mode: connect, `CREATE TABLE`, insert, `FLUSH`, select, `CREATE
VIEW`, select from the view, drop. It reported
`PostgreSQL 13.14.0-RisingWave-3.0.3`.

## Deliberately absent

| Absent | Until |
| --- | --- |
| **The model client library** (LangChain and anything like it) | **The increment that first *calls* a model** — not the one that first mentions one. `concept/06-technology.md` places LangChain in the technology table and states the absence rule in the same paragraph; `tests/test_dependency_boundary.py::test_the_model_client_is_still_absent` enforces it |
| An HTTP client (`requests`, `httpx`) | The increment that first fetches a feed or calls a provider. Feed loaders will need one; nothing does yet |
| A SQL toolkit or transformation framework | Not planned. Migrations are numbered `.sql` files applied in order, and a framework in the data path is machinery ahead of a measured need |
| A graph or agent framework | Rejected, not deferred: two agents with deterministic routing is an `if`, and the checkpoint store such a framework brings is a second store |

Removing something from the absent list means editing both this file and the
test — which is the point.
