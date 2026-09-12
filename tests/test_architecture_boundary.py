"""The architectural rejections, as tests rather than as prose.

`concept/06-technology.md`'s table does not only say what HELENA uses. Five of
its rows say what it **does not**, and those rows are commitments rather than
preferences:

| Concern | Choice |
| --- | --- |
| Graph framework | **Not adopted** |
| Higher-level agent frameworks | **Deferred** |
| Workflow engine | **Rejected** |
| Tracing / observability | **Local structured logs only** |
| Second store — relational profile store, vector store, checkpoint store | **Rejected** |

Each is one `uv add` away from being reversed by accident, which is exactly the
trap `concept/instruction.md` §6 names: *"adding a framework convenience because
it is one flag away"*. A rejection that lives only in a table is reversed by
whoever wanted the convenience; a rejection with a test is reversed by whoever is
willing to delete the test, and deleting a test is visible in a diff.

**Reversing any of these takes a decision record.** The note says so itself for
the second store — *"it needs its own decision record, not an incidental
dependency"* — and `docs/decisions/0039-architectural-boundaries.md` is where
that argument goes, for all five.
`test_reversing_a_rejection_requires_a_decision_record` keeps that file present
and keeps it naming every rejection it governs.

### What this module checks that the others do not

The boundary is already partly held, and duplicating a check would give it two
definitions that can disagree:

- `tests/test_dependency_boundary.py` owns the **approved set**: the declared
  distributions, the package's top-level imports, and the hosted-telemetry SDKs
  (declared, imported, and resolvable from the environment). This module reuses
  its helpers and its telemetry table rather than restating either.
- `tests/test_broker.py` owns the **broker-specific API**: only `helena.broker`
  imports a Kafka client, it binds only wire-protocol names, it reaches the
  network no other way, and no module holds a broker address.

What had no owner, and is here:

1. A second store is not merely undeclared — it is **not installed**, so no
   module can reach one by importing it (`find_spec`).
2. The **standard library's** stores. `sqlite3`, `shelve` and `dbm` are stdlib,
   so the approved-set test passes them by construction: it allows everything in
   `sys.stdlib_module_names`. A checkpoint store does not need a dependency.
3. Graph frameworks, workflow engines and higher-level agent frameworks, which
   were never enumerated anywhere.
4. **The filesystem.** `concept/03-architecture.md` requires that there be *"no
   durable in-flight state anywhere outside the engine"* and calls file-backed
   agent memory the convenient default a framework brings. A file is a second
   store whether or not a library was installed to write it.
5. The persistence targets themselves: the engine driver, the Kafka client, and
   **two** topic names — checked in the engine's own catalogue as well as in the
   package, because `CREATE SINK` and `CREATE SOURCE` are persistence targets
   that no Python import would reveal.
6. A broker *vendor's* client or CLI, which is the one broker-specific route
   `tests/test_broker.py` cannot see: it reads `helena/broker.py`, and an `rpk`
   subprocess or a second Kafka client would be in some other module.

### Adding a rejection to the table means adding a test

Enforced the way `tests/test_conformance.py` enforces the must-never-happen
table: `REJECTIONS` holds each row's Concern and its Choice **verbatim**,
`_technology_table()` re-parses the note on every run, and the two meta-tests
fail when a row is added, removed, reworded or reversed without this module
following.

Maturity: experimental. These are structural tests over the package's source and
its declared dependencies, plus one executed query against the migrated schema —
so what they demonstrate is that the boundary is not crossed *in this tree*,
which is what a guardrail can demonstrate. They do not demonstrate that crossing
it would be wrong; `concept/06-technology.md` argues that, and this module
executes it.
"""

from __future__ import annotations

import ast
import importlib.util
from pathlib import Path

import psycopg
import pytest

from helena.config import VARIABLES, Infrastructure

# One source of truth for the approved set and for how a module's imports are
# read. `tests/` is on `sys.path` under pytest's default import mode, and
# `tests/test_infrastructure.py` already imports `conftest` and `scripts/` the
# same way.
from test_dependency_boundary import (
    APPROVED_RUNTIME_DISTRIBUTIONS,
    HOSTED_TELEMETRY_DISTRIBUTIONS,
    _declared,
    _package_modules,
    _pyproject,
    _top_level_imports,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PACKAGE_ROOT = PROJECT_ROOT / "src" / "helena"
TECHNOLOGY_NOTE = PROJECT_ROOT / "concept" / "06-technology.md"
DECISION_RECORD = PROJECT_ROOT / "docs" / "decisions" / "0039-architectural-boundaries.md"

# The rows of `concept/06-technology.md`'s table that are rejections, each with
# the Choice cell verbatim and the test here that executes it. The meta-tests at
# the bottom check both directions: a row whose wording or choice changed, and a
# rejection the note added that nothing here carries.
REJECTIONS: dict[str, tuple[str, str]] = {
    "Graph framework": (
        "Not adopted",
        "test_no_graph_framework_workflow_engine_or_tracer_is_reachable",
    ),
    "Higher-level agent frameworks": (
        "Deferred",
        "test_no_graph_framework_workflow_engine_or_tracer_is_reachable",
    ),
    "Workflow engine": (
        "Rejected",
        "test_no_graph_framework_workflow_engine_or_tracer_is_reachable",
    ),
    "Tracing / observability": (
        "Local structured logs only",
        "test_no_graph_framework_workflow_engine_or_tracer_is_reachable",
    ),
    "Second store — relational profile store, vector store, checkpoint store": (
        "Rejected",
        "test_no_second_store_client_is_declared_imported_or_installed",
    ),
}

# A Choice cell that is a refusal. Used by the meta-test to find a rejection row
# `REJECTIONS` does not carry.
REFUSALS = {"Not adopted", "Rejected", "Deferred"}

# Distribution -> the top-level module it installs, for the three kinds of second
# store the note names. Grouped by which of the three it is, because "a second
# store" is the rule and these are the shapes it arrives in.
SECOND_STORE_DISTRIBUTIONS = {
    # Relational profile store — an ORM or a second driver is the store, whatever
    # it is pointed at. `psycopg` against the engine is the one connection there
    # is; a second one is a second store even if the address is the same.
    "sqlalchemy": "sqlalchemy",
    "alembic": "alembic",
    "django": "django",
    "peewee": "peewee",
    "tortoise-orm": "tortoise",
    "sqlmodel": "sqlmodel",
    "pony": "pony",
    "asyncpg": "asyncpg",
    "psycopg2": "psycopg2",
    "pymysql": "pymysql",
    "duckdb": "duckdb",
    # Vector store — the row the note wrote the "needs its own decision record"
    # sentence for, because semantic retrieval over analyst notes is the thing
    # somebody will reach for first.
    "chromadb": "chromadb",
    "qdrant-client": "qdrant_client",
    "pinecone-client": "pinecone",
    "weaviate-client": "weaviate",
    "lancedb": "lancedb",
    "pymilvus": "pymilvus",
    "faiss-cpu": "faiss",
    "annoy": "annoy",
    "hnswlib": "hnswlib",
    "usearch": "usearch",
    "txtai": "txtai",
    "pgvector": "pgvector",
    "sentence-transformers": "sentence_transformers",
    # Checkpoint store, cache and key-value state. `concept/instruction.md` §3
    # makes a cache a second store explicitly — *"including a cache, a queue or a
    # file"* — and `docs/decisions/0025-the-lookup-cache.md` is why the lookup
    # cache is engine rows instead.
    "langgraph-checkpoint": "langgraph",
    "redis": "redis",
    "pymongo": "pymongo",
    "diskcache": "diskcache",
    "sqlitedict": "sqlitedict",
    "tinydb": "tinydb",
    "lmdb": "lmdb",
    "plyvel": "plyvel",
    "rocksdict": "rocksdict",
    "zodb": "ZODB",
    "joblib": "joblib",
    "cachetools": "cachetools",
    "filelock": "filelock",
}

# The standard library's stores. No dependency is needed for any of these, so the
# approved-set test cannot see them: it allows every name in
# `sys.stdlib_module_names`. A checkpoint store is three lines of `shelve`.
#
# `pickle` and `marshal` are here as the serialization half of the same thing —
# neither has a use in this package that is not writing state somewhere to be
# read back, and `concept/03-architecture.md` puts durable state in the engine as
# **typed rows**, which is the opposite of an opaque blob.
STDLIB_STORE_MODULES = {
    "sqlite3",
    "shelve",
    "dbm",
    "pickle",
    "marshal",
}

# Graph frameworks and higher-level agent frameworks. The note rejects the first
# and defers the second, and gives one reason for both: an agent framework is
# *"built on the graph framework, so adopting one means adopting both"*.
GRAPH_AND_AGENT_FRAMEWORK_DISTRIBUTIONS = {
    "langgraph": "langgraph",
    "llama-index": "llama_index",
    "crewai": "crewai",
    "pyautogen": "autogen",
    "autogen-agentchat": "autogen_agentchat",
    "semantic-kernel": "semantic_kernel",
    "haystack-ai": "haystack",
    "dspy-ai": "dspy",
    "smolagents": "smolagents",
    "pydantic-ai": "pydantic_ai",
    "agno": "agno",
    "atomic-agents": "atomic_agents",
    "griptape": "griptape",
}

# Workflow engines. *"Operational weight out of proportion; the durability
# requirement here is per-assessment replay, which versioned inputs and stored
# results already deliver"* — and every one of these brings a metadata database,
# which is the second store arriving by the other door.
WORKFLOW_ENGINE_DISTRIBUTIONS = {
    "apache-airflow": "airflow",
    "prefect": "prefect",
    "dagster": "dagster",
    "luigi": "luigi",
    "temporalio": "temporalio",
    "celery": "celery",
    "ray": "ray",
    "dask": "dask",
    "metaflow": "metaflow",
    "kedro": "kedro",
    "flytekit": "flytekit",
    "apache-beam": "apache_beam",
}

# A broker vendor's own client or SDK. `tests/test_broker.py` holds the rule
# inside `helena/broker.py`; this is the half it cannot see, because a second
# Kafka client or a vendor SDK would be imported by some *other* module — and
# `test_only_the_broker_module_imports_a_kafka_client` looks for
# `confluent_kafka` by name, so a different client is invisible to it.
BROKER_CLIENT_DISTRIBUTIONS = {
    "kafka-python": "kafka",
    "aiokafka": "aiokafka",
    "pykafka": "pykafka",
    "quixstreams": "quixstreams",
    "faust-streaming": "faust",
    "confluent-kafka-rest": "confluent_kafka_rest",
    "redpanda": "redpanda",
    "rptest": "rptest",
    "kafkit": "kafkit",
}

# Standard-library modules that mutate the filesystem or start a process. None
# has a use on this side of the boundary: the package reads files (migrations,
# the pinned SQL, a capture) and writes only to the engine, the broker and a log
# stream. `subprocess` is here because an `rpk` or a `psql` invocation is a
# persistence target and a broker-specific API at once, and it needs no import
# that any of the tables above would catch.
FILESYSTEM_AND_PROCESS_MODULES = {
    "shutil",
    "tempfile",
    "subprocess",
    "multiprocessing",
    "fcntl",
    "mmap",
}

# Unambiguous filesystem-write method names. Deliberately not `write`, `remove`,
# `rename` or `replace`: `helena.observability` writes a log line to a `TextIO`,
# and `str.replace` and `dataclasses.replace` are all over the package, so a scan
# for those names would find prose-equivalent false positives and get widened
# into uselessness. These six have no second meaning.
FILESYSTEM_WRITE_METHODS = {
    "write_text",
    "write_bytes",
    "touch",
    "mkdir",
    "makedirs",
    "symlink_to",
}

# The characters that make `open()` a write. `open(path)` and `open(path, "rb")`
# are reads and are allowed; nothing in the package uses either today, but a
# migration file read is a legitimate thing for one to do later.
WRITE_MODE_CHARACTERS = set("wax+")


def _technology_table() -> dict[str, str]:
    """Concern -> Choice, read from the note itself on every run.

    Parsed rather than copied, for the reason `tests/test_conformance.py` parses
    `concept/07-principles.md`: a copy goes stale silently, and the failure mode
    is a test that passes while checking a sentence nobody wrote any more.
    """
    rows: dict[str, str] = {}
    in_table = False
    for line in TECHNOLOGY_NOTE.read_text().splitlines():
        if line.startswith("| Concern | Choice |"):
            in_table = True
            continue
        if in_table:
            if not line.startswith("|"):
                break
            cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
            if len(cells) != 3 or set(cells[0]) <= {"-"}:
                continue
            rows[cells[0]] = cells[1].strip("*")
    assert rows, f"no technology table found in {TECHNOLOGY_NOTE}"
    return rows


def _test_names() -> set[str]:
    """Every test function defined in this module, by name."""
    tree = ast.parse(Path(__file__).read_text(), filename=__file__)
    return {
        node.name
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name.startswith("test_")
    }


def _package_imports() -> set[str]:
    imported: set[str] = set()
    for module in _package_modules():
        imported |= _top_level_imports(module)
    return imported


def _all_declared() -> set[str]:
    pyproject = _pyproject()
    return _declared("dependencies", pyproject["project"]) | _declared(
        "dev", pyproject["dependency-groups"]
    )


def _installed(modules: set[str]) -> list[str]:
    """Those of `modules` that resolve to something in this environment."""
    resolvable = []
    for name in sorted(modules):
        try:
            found = importlib.util.find_spec(name) is not None
        except (ImportError, ValueError):
            # A package whose parent is absent, or a name that is not a valid
            # module path. Either way it does not resolve.
            found = False
        if found:
            resolvable.append(name)
    return resolvable


def _rejected(table: dict[str, str]) -> tuple[set[str], set[str]]:
    """(declared distributions, imported modules) that fall in one table."""
    declared = _all_declared() & {name.lower() for name in table}
    imported = _package_imports() & set(table.values())
    return declared, imported


def test_no_second_store_client_is_declared_imported_or_installed():
    """*"There is no second store"* — relational, vector or checkpoint.

    Three assertions, because three different things go wrong. Declared is the
    deliberate reversal; imported is the reversal that skipped the lockfile;
    **installed** is the one neither of the others sees — a store client that
    arrived as somebody else's transitive dependency is one `import` line away
    from being used, and nothing in `pyproject.toml` mentions it.
    """
    declared, imported = _rejected(SECOND_STORE_DISTRIBUTIONS)
    assert not declared, (
        f"a second-store client is declared: {sorted(declared)}. "
        f"concept/06-technology.md rejects the relational profile store, the "
        f"vector store and the checkpoint store together, and says what it takes "
        f"to reverse that: 'its own decision record, not an incidental "
        f"dependency'. See {DECISION_RECORD.name}."
    )
    assert not imported, (
        f"the package imports a second-store client: {sorted(imported)}. "
        f"Everything durable is typed rows in the streaming engine "
        f"(concept/03-architecture.md, 'The store')."
    )
    assert not _installed(set(SECOND_STORE_DISTRIBUTIONS.values())), (
        f"a second-store client is installed in this environment: "
        f"{_installed(set(SECOND_STORE_DISTRIBUTIONS.values()))}. It arrived as a "
        f"transitive dependency of something approved; find which, and record the "
        f"decision before leaving it there."
    )


def test_no_stdlib_store_module_is_imported_by_the_package():
    """The gap the approved-set test cannot close: a store that needs no package.

    `tests/test_dependency_boundary.py` allows every name in
    `sys.stdlib_module_names`, which it has to — the package is mostly standard
    library. So `import sqlite3` passes it, and a checkpoint store is three lines
    of `shelve`. This is the assertion that makes the single-store rule about
    *stores* rather than about *dependencies*.
    """
    offenders: dict[str, set[str]] = {}
    for module in _package_modules():
        found = _top_level_imports(module) & STDLIB_STORE_MODULES
        if found:
            offenders[str(module.relative_to(PROJECT_ROOT))] = found
    assert not offenders, (
        f"the package imports a standard-library store: {offenders}. A second "
        f"store does not need a dependency — concept/instruction.md §2 rules out "
        f"'no second database, no vector store, no checkpoint store, no "
        f"file-backed agent memory, no cache that is not itself the evidence "
        f"store', and none of those requires an install."
    )


def test_no_graph_framework_workflow_engine_or_tracer_is_reachable():
    """Three rejections that fail the same way: one convenience, one flag away.

    The hosted-tracing half reuses `tests/test_dependency_boundary.py`'s table
    rather than restating it — that module owns the declared, imported and
    installed assertions for telemetry, and two copies of the list would drift.
    What is added here is the graph framework, the workflow engine and the
    higher-level agent framework, which had no table anywhere.
    """
    frameworks = (
        GRAPH_AND_AGENT_FRAMEWORK_DISTRIBUTIONS | WORKFLOW_ENGINE_DISTRIBUTIONS
    )
    declared, imported = _rejected(frameworks)
    assert not declared, (
        f"a graph framework, agent framework or workflow engine is declared: "
        f"{sorted(declared)}. The graph framework is not adopted (the routing is "
        f"an `if` in helena.orchestration), the agent frameworks are deferred "
        f"because they are built on it, and the workflow engine is rejected "
        f"because per-assessment replay is the durability requirement and "
        f"versioned inputs already deliver it. See {DECISION_RECORD.name}."
    )
    assert not imported, (
        f"the package imports a graph framework, agent framework or workflow "
        f"engine: {sorted(imported)}."
    )
    assert not _installed(set(frameworks.values())), (
        f"one is installed in this environment: "
        f"{_installed(set(frameworks.values()))}. Each of these brings a "
        f"checkpoint or metadata store, which is the second store arriving by "
        f"the other door."
    )

    # The tracing row of the same table. Import-side only: the declaration and
    # the environment are `tests/test_dependency_boundary.py`'s
    # `test_no_hosted_tracing_sdk_is_declared_or_imported` and
    # `test_no_hosted_tracing_sdk_is_even_importable_from_the_environment`.
    traced = _package_imports() & set(HOSTED_TELEMETRY_DISTRIBUTIONS.values())
    assert not traced, (
        f"the package imports a hosted tracing SDK: {sorted(traced)}. "
        f"Observability is local structured logs only (helena.observability); a "
        f"hosted tracer is a second egress channel for prompts and retrieved "
        f"provider text."
    )


def test_the_package_writes_to_no_file_and_starts_no_process():
    """A file is a second store, whether or not a library was installed for it.

    `concept/03-architecture.md` is explicit that this binds harder once a
    framework is in play, *"because such libraries make file-backed agent memory
    the convenient default — and an agent writing notes to a persistent backend
    has created a second store of uncited free text"*. The framework is not here,
    so the file-backed default has to be ruled out on its own terms.

    Reads are allowed and unchecked: `helena.migrations` reads `sql/migrations/`,
    `helena.versions` reads `pyproject.toml`, `helena.normalizer` reads a
    capture. Writing is what makes a path a store.
    """
    offenders: dict[str, set[str]] = {}

    def note(path: Path, what: str) -> None:
        offenders.setdefault(str(path.relative_to(PROJECT_ROOT)), set()).add(what)

    for module in _package_modules():
        for imported in _top_level_imports(module) & FILESYSTEM_AND_PROCESS_MODULES:
            note(module, f"import {imported}")
        tree = ast.parse(module.read_text(), filename=str(module))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            function = node.func
            if isinstance(function, ast.Attribute):
                if function.attr in FILESYSTEM_WRITE_METHODS:
                    note(module, f".{function.attr}()")
            elif isinstance(function, ast.Name) and function.id == "open":
                mode = _open_mode(node)
                if mode is None or set(mode) & WRITE_MODE_CHARACTERS:
                    note(module, f"open(mode={mode!r})")

    assert not offenders, (
        f"the package writes to the filesystem or starts a process: {offenders}. "
        f"concept/03-architecture.md: 'No checkpointing, no durable in-flight "
        f"state anywhere outside the engine; an interrupted run is simply "
        f"re-run.' Everything durable is typed rows in the engine; a log line "
        f"goes to a stream (helena.observability), never to a path."
    )


def _open_mode(call: ast.Call) -> str | None:
    """The `mode` argument of an `open()` call, or None if it is not a literal.

    A non-literal mode is treated as a write by the caller, because a mode this
    test cannot read is a mode it cannot clear.
    """
    argument: ast.expr | None = None
    if len(call.args) > 1:
        argument = call.args[1]
    for keyword in call.keywords:
        if keyword.arg == "mode":
            argument = keyword.value
    if argument is None:
        return "r"
    if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
        return argument.value
    return None


def test_the_only_external_clients_are_the_engine_driver_and_the_kafka_client():
    """Two ways out of this process that persist anything, and they are named.

    The approved set is four distributions, and two of them are libraries rather
    than clients: `pydantic` validates and `dotenv` reads a file at startup.
    What remains is the engine over the PostgreSQL wire protocol and the broker
    over the Kafka wire protocol — `concept/03-architecture.md`'s interface table
    exactly, minus the environment.
    """
    clients = {"psycopg", "confluent_kafka"}
    imported = _package_imports()
    third_party = imported & set(APPROVED_RUNTIME_DISTRIBUTIONS.values())

    assert third_party - {"pydantic", "dotenv"} == clients, (
        f"the package's third-party clients are "
        f"{sorted(third_party - {'pydantic', 'dotenv'})}, not {sorted(clients)}. "
        f"Adding one is a dependency decision and a persistence decision at once."
    )
    for client in clients:
        assert client in imported, (
            f"{client} is no longer imported by the package. If a persistence "
            f"target was removed, this test should be the thing that says so."
        )


def test_the_deployment_names_exactly_two_topics():
    """The two topics of the interface table, and no third.

    One in, one out. A third topic name in configuration would be a second egress
    channel or a second ingress, both of which `concept/instruction.md` §3 makes
    an escalation — and `helena.config` is where one would be added, because the
    broker module holds no topic name at all (`tests/test_broker.py`).
    """
    topics = {name for name in Infrastructure.model_fields if name.endswith("_topic")}
    assert topics == {"ingest_topic", "output_topic"}, (
        f"Infrastructure names {sorted(topics)}. The interface is one ingest "
        f"topic and one output topic (concept/03-architecture.md, 'The "
        f"interfaces'); a third is a second egress channel or a second ingress."
    )

    variables = {name for name in VARIABLES if "TOPIC" in name}
    assert variables == {"HELENA_INGEST_TOPIC", "HELENA_OUTPUT_TOPIC"}, (
        f"the required configuration names {sorted(variables)} as topics."
    )


def test_no_broker_specific_client_is_declared_imported_or_installed():
    """The half of the broker rule that `tests/test_broker.py` cannot see.

    That module reads `helena/broker.py`: it proves the *broker module* binds
    only wire-protocol names and reaches the network no other way. It looks for
    `confluent_kafka` by name, so a **second** client — `kafka-python`,
    `aiokafka`, a vendor SDK — imported by any other module would pass every one
    of its assertions.

    `concept/03-architecture.md`: *"No component codes against a specific broker;
    replacing it must be a configuration change."* A vendor SDK is that rule
    broken in a way that still speaks Kafka most of the time.
    """
    declared, imported = _rejected(BROKER_CLIENT_DISTRIBUTIONS)
    assert not declared, (
        f"a broker-specific or second Kafka client is declared: {sorted(declared)}."
    )
    assert not imported, (
        f"the package imports {sorted(imported)}. The broker is addressed through "
        f"helena.broker over the Kafka wire protocol and no other way."
    )
    assert not _installed(set(BROKER_CLIENT_DISTRIBUTIONS.values())), (
        f"a broker-specific client is installed: "
        f"{_installed(set(BROKER_CLIENT_DISTRIBUTIONS.values()))}."
    )


@pytest.mark.integration
def test_the_migrated_schema_defines_no_source_sink_connection_or_secret(
    migrated_engine: psycopg.Connection,
):
    """The persistence targets the Python boundary tests cannot see.

    `CREATE SINK ... WITH (connector = 'kafka', ...)` is an egress channel with
    its own credentials, defined in SQL, invisible to every import scan in this
    file. `CREATE SOURCE` with an S3 or Iceberg connector is a second store the
    same way, and `CREATE SECRET` is a credential living somewhere other than the
    environment.

    The project has none, by decision rather than by omission:
    `sql/migrations/0019_sink.sql` records that the sink is a **plain view** read
    by deterministic code producing over the Kafka wire protocol, *"not `CREATE
    SINK`"* — measured, because the enriched context derives `status` from
    `now()` and a streaming query rejects that. So emission stays on the same
    terms as ingestion, which is what `concept/03-architecture.md` means by the
    rule holding on both ends.
    """
    schema = migrated_engine.execute("SELECT current_schema()").fetchone()[0]
    schema_id = migrated_engine.execute(
        "SELECT id FROM rw_catalog.rw_schemas WHERE name = %s", (schema,)
    ).fetchone()
    assert schema_id is not None, f"the migrated schema {schema!r} is not in rw_schemas"

    for relation in ("rw_sources", "rw_sinks", "rw_connections", "rw_secrets"):
        rows = migrated_engine.execute(
            f"SELECT name FROM rw_catalog.{relation} WHERE schema_id = %s",
            (schema_id[0],),
        ).fetchall()
        assert not rows, (
            f"the migrated schema defines {relation} {[name for (name,) in rows]}. "
            f"The engine's only external wiring is none: ingestion and emission "
            f"are the package's own Kafka client (helena.broker), and a "
            f"connector-backed source or sink is a persistence target with its "
            f"own credentials that no import scan would reveal."
        )


def test_the_technology_table_still_records_each_rejection():
    """A rejection reversed in the note is red here, not silently followed.

    `concept/` is the authority (`prds/CONTEXT.md` §1), so this test does not
    forbid the note from changing — it makes the change land in the same commit
    as the decision record and the tests that implement it.
    """
    table = _technology_table()
    for concern, (choice, _) in REJECTIONS.items():
        assert concern in table, (
            f"concept/06-technology.md no longer has a row for {concern!r}. If "
            f"the rejection was withdrawn, {DECISION_RECORD.name} and the test "
            f"for it change in the same commit."
        )
        assert table[concern] == choice, (
            f"the Choice for {concern!r} is now {table[concern]!r}, not "
            f"{choice!r}. A reversal is a decision record, not an edit."
        )


def test_every_rejection_in_the_technology_table_has_a_test_here():
    """Adding a rejection to the note means adding a test, and this is the gate.

    The other direction of the test above. A row the note adds with a refusing
    Choice — 'Not adopted', 'Rejected', 'Deferred' — has no test until somebody
    writes one, and a prose rejection is the thing this module exists to stop.
    """
    table = _technology_table()
    uncovered = {
        concern
        for concern, choice in table.items()
        if choice in REFUSALS and concern not in REJECTIONS
    }
    assert not uncovered, (
        f"concept/06-technology.md rejects {sorted(uncovered)} and nothing here "
        f"carries it. Add the row to REJECTIONS with the test that executes it."
    )

    defined = _test_names()
    missing = {
        name for _, name in REJECTIONS.values() if name not in defined
    }
    assert not missing, (
        f"REJECTIONS names tests that do not exist in this module: {sorted(missing)}."
    )


def test_reversing_a_rejection_requires_a_decision_record():
    """The step the task asks for, made a test rather than a paragraph.

    The note already says it for the second store — *"it needs its own decision
    record, not an incidental dependency"* — and the same is true of the other
    four. The record has to exist and has to name each rejection it governs, so
    that somebody reversing one finds the argument rather than an empty file.
    """
    assert DECISION_RECORD.exists(), (
        f"{DECISION_RECORD.relative_to(PROJECT_ROOT)} is missing. It is what "
        f"'a decision record, not an incidental dependency' points at."
    )
    text = DECISION_RECORD.read_text()
    unnamed = sorted(
        concern for concern in REJECTIONS if concern.split(" —")[0] not in text
    )
    assert not unnamed, (
        f"{DECISION_RECORD.name} does not name {unnamed}. Each rejection this "
        f"module enforces needs its argument written down where a reversal will "
        f"look for it."
    )
