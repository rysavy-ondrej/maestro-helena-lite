# 0039 — The architectural rejections are tests, and reversing one is a decision record

Status: accepted — 2026-09-12 (task 50, D8 Guardrails)

## Context

`concept/06-technology.md`'s table has nine rows. Four of them say what HELENA
uses; five say what it does not:

| Concern | Choice | The note's reason |
| --- | --- | --- |
| Graph framework | **Not adopted** | at two agents with deterministic routing the graph is an `if`, and it would add a checkpoint store against the single-store rule |
| Higher-level agent frameworks | **Deferred** | built on the graph framework, so adopting one means adopting both; unmeasured value over a plain tool loop |
| Workflow engine | **Rejected** | operational weight out of proportion; the durability requirement is per-assessment replay, which versioned inputs and stored results already deliver |
| Tracing / observability | **Local structured logs only** | a hosted tracer is a second egress channel for prompts and retrieved text |
| Second store — relational profile store, vector store, checkpoint store | **Rejected** | *"If semantic retrieval over notes later proves necessary it needs its own decision record, not an incidental dependency"* |

Those are architectural commitments, not preferences — each of them is load
bearing for a rule somewhere else. The graph framework carries a checkpoint
store, so adopting it deletes the single-store invariant as a side effect. A
hosted tracer carries prompts and retrieved provider text off the machine, so
adopting it creates a second egress channel with no send policy and no
disclosure record. A workflow engine carries a metadata database, which is the
second store arriving by a door nobody was watching.

And every one of them is reversed the same way. Not by a decision — by a
convenience. `concept/instruction.md` §6 lists it as a recurring trap in its own
right: *"Adding a framework convenience because it is one flag away — check it
against the single-store, agents-propose and ephemeral-state rules first."* The
check it asks for is a check a person has to remember to perform, against rules
in a file they may not have opened, at the moment they are trying to get
something working.

Two of the five were already held by tests before this increment.
`tests/test_dependency_boundary.py` (task 0, extended by task 30) asserts the
declared distribution set is exactly the approved one, that the package's
top-level imports resolve to it, and that no hosted telemetry SDK is declared,
imported, or even *resolvable* from the environment.
`tests/test_broker.py` (task 3) asserts that only `helena/broker.py` imports a
Kafka client, that it binds only wire-protocol names, and that no module holds a
broker address.

The other three were prose.

## Decision

**`tests/test_architecture_boundary.py`: one test per rejection, plus two
meta-tests that make adding a rejection to the note mean adding a test, plus
this record — which is what "a decision record, not an incidental dependency"
points at, and which a test requires to exist and to name every rejection it
governs.**

Nothing in `src/` changed. This increment adds no capability; it makes five
existing commitments fail loudly instead of quietly.

### What is new, and what was deliberately not duplicated

The boundary was already partly held, and a second copy of a check is two
definitions of one property that can disagree. So the new module reuses
`tests/test_dependency_boundary.py`'s helpers and its telemetry table by
importing them, and names `tests/test_broker.py` as the owner of the in-module
broker rule rather than restating it. What it adds is the six things neither
covered:

| # | The gap | Why it was a gap |
| --- | --- | --- |
| 1 | A second-store client is not **installed**, not merely undeclared | A store client that arrived transitively is one `import` line from being used, and `pyproject.toml` never mentions it |
| 2 | The **standard library's** stores — `sqlite3`, `shelve`, `dbm`, `pickle`, `marshal` | The approved-set test allows everything in `sys.stdlib_module_names`, which it must; a checkpoint store is three lines of `shelve` and needs no dependency at all |
| 3 | Graph frameworks, agent frameworks and workflow engines | Enumerated nowhere. `langgraph` was one entry in a list about the model client |
| 4 | The **filesystem** — write-mode `open()`, `write_text`, `mkdir`, `shutil`, `tempfile`, `subprocess` | A file is a second store whether or not a library was installed to write it |
| 5 | The engine's **own catalogue**: no source, sink, connection or secret in the migrated schema | `CREATE SINK ... WITH (connector = 'kafka', ...)` is an egress channel with its own credentials, defined in SQL, invisible to every import scan |
| 6 | A **second** Kafka client or a broker vendor's SDK | `tests/test_broker.py` reads `helena/broker.py` and looks for `confluent_kafka` by name, so `aiokafka` imported by some other module passes all of it |

### 1. Installed, not just declared

`test_no_second_store_client_is_declared_imported_or_installed` makes three
assertions because three different things go wrong, and they fail at different
times. *Declared* is the deliberate reversal, and it is the one that would be
noticed anyway. *Imported* is the reversal that skipped the lockfile — a
`pip install` in a session, which `prds/CONTEXT.md` §3 already forbids for a
different reason. *Installed* is the one neither of the others sees.

This is the shape task 30 arrived at for hosted telemetry and the reasoning
carries across unchanged: `langchain-core` has `langsmith` as a hard dependency,
so `langchain-openai` would have put a tracing client in the environment without
a single line of anybody's intent. The same is true of every vector store that
ships an embedded client, and of `langgraph-checkpoint`.

### 2. The stores that need no dependency

The single-store rule in `concept/instruction.md` §2 is about *stores*:

> **One store.** Everything durable goes to the streaming engine as typed rows.
> No second database, no vector store, no checkpoint store, no file-backed agent
> memory, no cache that is not itself the evidence store.

None of the four things it names requires an install. `sqlite3`, `dbm` and
`shelve` are standard library, and the approved-set test allows every name in
`sys.stdlib_module_names` — which it has to, because the package is mostly
standard library. So the dependency boundary passes `import sqlite3` by
construction, and the rule it was thought to be enforcing was never the rule
that was written down.

`pickle` and `marshal` are in the same table as the serialization half of the
same thing. Neither has a use in this package that is not writing state
somewhere to be read back, and `concept/03-architecture.md` puts durable state
in the engine as **typed rows** — which is the opposite of an opaque blob, and
is the same argument `docs/decisions/0033-assessment-persistence.md` makes for
storing an assessment as columns rather than as a JSON document.

### 3. The filesystem, checked as a store

`concept/03-architecture.md` states the rule and then says where it will be
broken from:

> **An assessment is one function call over one versioned context snapshot.** No
> checkpointing, no durable in-flight state anywhere outside the engine; an
> interrupted run is simply re-run […]
>
> **Framework and in-process state is ephemeral.** […] This binds harder if a
> framework is adopted, because such libraries make file-backed agent memory the
> convenient default — and an agent writing notes to a persistent backend has
> created a second store of uncited free text, which is simultaneously a
> single-store violation and a memory-poisoning channel.

The framework is not here, so the file-backed default has to be ruled out on its
own terms rather than by ruling out the framework.

**Reads are allowed and unchecked.** `helena.migrations` reads
`sql/migrations/`, `helena.versions` reads `pyproject.toml`,
`helena.normalizer` reads a capture. Writing is what makes a path a store.

Two things about the scan are deliberate and both are about false positives.
The write-method list is six names — `write_text`, `write_bytes`, `touch`,
`mkdir`, `makedirs`, `symlink_to` — and does **not** include `write`, `remove`,
`rename` or `replace`. `helena.observability` writes a log line to a `TextIO`
(`stream.write(...)`, defaulting to `sys.stderr`), and `str.replace` and
`dataclasses.replace` are used throughout; a scan for those names finds
prose-equivalent false positives and gets widened until it checks nothing. This
is the same lesson task 49 recorded about reading source with `ast` rather than
`re`: a check that fires on the thing it is not about gets disabled, not fixed.

And `open()` is judged by its mode, not by its presence. `open(path)` and
`open(path, "rb")` are reads. A mode containing `w`, `a`, `x` or `+` is a write,
and a mode this test cannot read as a literal is treated as a write, because a
mode it cannot clear is a mode it cannot clear.

`subprocess` is in the table with `shutil` and `tempfile` for a reason that
spans two rejections at once: an `rpk` or a `psql` invocation is a persistence
target *and* a broker-specific API, and it needs no import that any of the
distribution tables would catch.

### 4. The engine's catalogue is part of the boundary

Every other check in this module reads Python. The persistence target that is
not written in Python is a connector defined in SQL:

- `CREATE SINK ... WITH (connector = 'kafka', ...)` is a second egress channel
  with credentials of its own, and it is what someone reaches for the first time
  emission feels slow.
- `CREATE SOURCE` with an S3, Iceberg or JDBC connector is a second store.
- `CREATE SECRET` is a credential living somewhere other than the environment,
  which `docs/decisions/0004-configuration-variables.md` rules out.

`test_the_migrated_schema_defines_no_source_sink_connection_or_secret` queries
`rw_catalog.rw_sources`, `rw_sinks`, `rw_connections` and `rw_secrets`, scoped by
`schema_id` to the schema the migrations were applied to, and requires all four
to be empty. Measured against the pinned engine 3.0.3 on 2026-09-12: all four
are empty for the migrated schema, and cluster-wide. The query was also shown to
catch what it is for rather than assumed to — a throwaway schema with one
`CREATE SOURCE ... WITH (connector = 'datagen', ...)` in it comes back
`rw_sources [('probe_source',)]` from the same statement, scoped by the same
`schema_id`.

That the sink is a plain view rather than a `CREATE SINK` is not an omission —
`sql/migrations/0019_sink.sql` records the measurement behind it. The enriched
context derives `status` from `now()`, a streaming query rejects `now()` outside
a `WHERE` clause, and everything downstream of it is therefore a batch read. So
emission is deterministic code reading a view and producing over the Kafka wire
protocol, which is also what keeps the rule *"the broker is addressed only
through the Kafka wire protocol"* true on both ends.

### 5. Adding a rejection to the table means adding a test

`REJECTIONS` maps each concern to its Choice cell **verbatim** and to the test
that executes it, and `_technology_table()` re-parses
`concept/06-technology.md` on every run. Two meta-tests close it in both
directions:

    a rejection is withdrawn or reworded in the note  -> the Choice no longer matches, red
    a rejection is added to the note                  -> nothing carries it, red
    a test named by REJECTIONS is renamed or deleted  -> the name does not resolve, red

This is task 49's pattern (`tests/test_conformance.py` over
`concept/07-principles.md`'s must-never-happen table) applied to the technology
table, for the same reason: a gate that copies the document it guards passes
while checking a sentence nobody wrote any more.

The meta-test does **not** forbid the note from changing. `concept/` is the
authority (`prds/CONTEXT.md` §1). What it forbids is the note changing *quietly*
— the reversal, this record and the test that implements it land in one commit
or not at all.

### 6. This record is required by a test

`test_reversing_a_rejection_requires_a_decision_record` asserts that this file
exists and that it names every rejection in `REJECTIONS`. The note already says
what reversing the second store takes — *"its own decision record, not an
incidental dependency"* — and the same is true of the other four. Requiring the
record to exist and to name the rejection means somebody reversing one finds the
argument rather than an empty file with a number on it.

## What reversing one of these takes

Concretely, for any of the five:

1. **A new record in `docs/decisions/`** — not an edit to this one — stating
   what was measured that the note's reason did not anticipate. The note gives a
   reason per row, and each is falsifiable: *"at two agents"*, *"unmeasured
   value over a plain tool loop"*, *"the durability requirement here is
   per-assessment replay"*, *"a second egress channel"*, *"if semantic retrieval
   over notes later proves necessary"*. A reversal answers the reason it is
   reversing.
2. **The corresponding row in `concept/06-technology.md`**, which is an
   escalation to the operator: `prds/CONTEXT.md` §1 puts `concept/` above every
   implementation session, and §6 makes a framework, a dependency and a second
   store escalations in their own right.
3. **The test here**, changed in the same commit — and with it, whichever of the
   invariants the rejection was holding up. A graph framework means answering
   what happens to the single-store rule its checkpointer breaks. A hosted
   tracer means a send policy and a disclosure record for a second egress
   channel (`docs/decisions/0027-disclosure-and-the-send-policy.md` is the shape
   the first one took).

The point of the ordering is that step 3 cannot be reached by accident. A test
is deleted deliberately or not at all, and a deleted test is visible in a diff
in a way that a new line in `pyproject.toml` is not.

## What is claimed

That the boundary is not crossed **in this tree**, and that crossing it now
fails a test rather than passing unnoticed. That is what a guardrail can
demonstrate.

Not claimed: that the rejections are right. `concept/06-technology.md` argues
that, and two of the five are explicitly provisional — the agent frameworks are
*deferred* rather than rejected, and the model-client question is an open
escalation recorded in `docs/decisions/0020-the-model-client.md` §1. Also not
claimed: that the lists are exhaustive. A vector store nobody has heard of is
not in `SECOND_STORE_DISTRIBUTIONS`, and it would be caught by
`tests/test_dependency_boundary.py`'s approved-set assertion instead — which is
exhaustive by construction, because it is an equality against four names rather
than a blocklist. The tables here are the second line, and their value is the
error message: they say *which rule* is being broken, and where the argument is.

## Alternatives rejected

**A blocklist only, with no approved-set equality.** This is the shape a
dependency guard usually takes, and it is unbounded: it fails on the packages
somebody thought of. `tests/test_dependency_boundary.py`'s equality against the
four approved distributions is what actually closes the set; the tables here
name the shapes so that the failure says why. Both, or the blocklist is
security theatre.

**Asserting on text — grepping `src/` for `sqlite3` or `import langgraph`.**
Task 49 measured what this costs: three checks written as text searches were all
wrong in the same way, because a module's own docstring quoting the rule matches
the search for a violation of it. This module reads imports and calls with
`ast`, and the two places it does read prose — the technology table and this
record — are reading documents rather than source, which is the case where text
is the artifact.

**Putting these tests in `tests/test_dependency_boundary.py`.** Tempting, since
they share helpers. But that module's subject is *the approved set*: what this
project depends on, and whether the declaration, the imports and the environment
agree. This module's subject is *five rejections in a concept note*, which is a
different thing to keep current — it is parsed from `concept/06-technology.md`
on every run, and it goes red when the **note** changes. Keeping them apart is
what lets the meta-tests be about the note rather than about `pyproject.toml`.

**A `guardrails` pytest marker, like `conformance`.** Not added. The
`conformance` marker exists because "do the guarantees still hold" is a question
an operator asks directly, and `make conformance` answers it in 30 s. These
tests are 11 tests and 27 s, ten of which need nothing running; splitting them
out would create a second thing to remember to run without making anything
answerable that is not already. They are collected by `uv run pytest -q` and
therefore by `make check`, which is what makes them required.
