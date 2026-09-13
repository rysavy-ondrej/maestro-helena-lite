# Deploying and operating HELENA

Maturity: `experimental`. Every command here has been run against the pinned
binaries on one machine. Nothing here has been run as a service, on more than one
host, or for longer than a working session.

**This is the path, not the reference.** [`runbook.md`](runbook.md) owns each
operation in detail and is organised by topic; this file is the order you do them
in, and links rather than restates. Where the two disagree the runbook is right
and the difference is a defect — one copy of a procedure, or it drifts.

---

## 1. What ships, and the one thing that does not

**HELENA is a library plus operator scripts. There are no daemons.** Nothing here
is a service you start and leave running: the engine and the broker are
long-lived, and everything HELENA does is a command you run against them. That is
deliberate for a prototype, and it is the first thing to understand before
planning a deployment around it.

The consequence, stated plainly because it is the gap that matters most:

> **There is no assessment runner.** You can ingest, contextualise, enrich, emit,
> replay, monitor and back up from the command line. **You cannot run the triage
> and analyst stages from the command line**, because nothing in `src/helena`
> turns a live context into an agent request. `helena.orchestration.assess` is
> *entered* with a request; the scheduler that would build one is not part of the
> first version (`concept/01`: the analyst is served indirectly, through the
> output topic).

So the six stages are operable like this:

| Stage | How you run it | Status |
| --- | --- | --- |
| 1 Ingest | `scripts/replay_capture.py`, or your own publisher onto the ingest topic | operable |
| 2 Context | the engine, continuously, from the migrations | automatic |
| 3 Enrich | `scripts/load_threatfox.py`, `scripts/load_public_suffix_list.py` | operable |
| 4 Triage | — | **you must write the caller** |
| 5 Analyse | — | **you must write the caller** |
| 6 Emit | `scripts/emit.py` | operable |

Two things build a request today, and both are worth reading before you write a
third: [`demo/assess_a_slice.py`](../demo/assess_a_slice.py) stage 7, and
`tests/test_end_to_end.py::triage_request`. They are deliberately similar. Before
copying either, read [`acceptance.md`](acceptance.md) finding 1 — with **two**
enrichment sources, `RequestVersions.enrichment_snapshot_version` has no single
value to record and the question is unsettled. One source avoids it.

**To see all six stages run, use the demo:** `demo/run-demo 3`. That is currently
the only end-to-end path that produces a fresh assessment outside the test suite.

---

## 2. Before you start

| | |
| --- | --- |
| Python | 3.12, through `uv` only. Never `pip`, never a second virtualenv |
| Binaries | `bin/risingwave` 3.0.3 and `bin/blink` 0.2.0, already built. `dev-up` **downloads nothing** and refuses to start anything whose version does not match [`versions.md`](versions.md) |
| A model endpoint | OpenAI-compatible. Required — there is no offline mode |
| Network | `threatfox.abuse.ch` and `publicsuffix.org` for reference data |

**One engine per machine.** `single_node --listen-addr` moves the PostgreSQL port
only; meta and compute bind fixed ports, so a second RisingWave cannot run beside
the first — [runbook §2](runbook.md#2-up-and-down) has the panic it produces.

```bash
uv sync          # the locked environment; uv.lock is the reproducibility contract
make check       # lockfile in sync, sources compile, the whole suite passes
```

Run `make check` before deploying rather than after. It is ~15 minutes and it is
the only thing that tells you the tree you are deploying is the tree that works.

---

## 3. First deployment, in order

The order matters in one place and it is step 4 — read its note before skipping
ahead.

### 1. Configure

```bash
cp .env.example .env    # then fill it in; .env is never committed
```

**Every variable is required and none has a default.** An empty or
whitespace-only value counts as *missing* and fails at startup naming the
variable, rather than sending an empty token to a real service. `HELENA_TENANT`
and `HELENA_SENSOR` are deliberately undefaulted: a tenant that silently defaults
is an isolation failure that looks like it is working.

The per-agent `LLM_*_TRIAGE` / `LLM_*_ANALYST` variables are optional overrides.
Resolution is agent-specific, then general, then fail — **never** a fallback to
the other agent's model.

Credentials: [runbook §14](runbook.md#14-credentials-two-exposure-profiles-and-only-one-needs-the-url-rule)
is required reading, not background. The same provider secret has two exposure
profiles and only one needs the URL-redaction rule.

### 2. Start the engine and the broker

```bash
make dev-up      # verifies the pins, starts both, waits until both answer
make dev-down    # stops them; leaves .rwdata/ alone
```

Logs land in `.run/`, engine state in `.rwdata/`. Neither is committed.

### 3. Apply the schema

```bash
make migrate
```

### 4. Apply it **before** anything is ingested

This is the ordering constraint. **The broker is consume-once, so a view created
later starts empty.** A materialized view added after records have already been
consumed does not backfill from them — it sees only what arrives next. If you
ingest first and migrate second, the context layer will be silently short, and
nothing will fail loudly to tell you.

[runbook §5](runbook.md#5-migrations) is the migration runner, the ledger and
what a checksum mismatch means.

### 5. Load the reference data

```bash
uv run scripts/load_public_suffix_list.py    # registrable-domain derivation
uv run scripts/load_threatfox.py             # the enrichment snapshot
uv run scripts/load_threatfox.py --status    # what is loaded, and recent attempts
```

Both must be loaded **before** the window you want enriched. A snapshot's
validity interval begins when it was fetched, and the enrichment join matches the
snapshot whose interval covers the context's window — so a snapshot loaded after
the traffic does not enrich it. This is the same rule that makes retroactive
enrichment of an archived capture impossible;
[`evaluation-corpus.md`](evaluation-corpus.md) §4 has the measurement.

A failed load leaves the previous snapshot in place and records the failure. It
never empties the table.

### 6. Get records in

```bash
uv run scripts/replay_capture.py --captures <dir> <sha256> --ingest
```

The capture is addressed by its own sha256, which is what the file is named.
`--ingest` also runs the ingestion side in this process and reports the counters.
For live traffic, publish onto `HELENA_INGEST_TOPIC` in the same wire form — the
broker is addressed only through the Kafka wire protocol, on both ends.

[runbook §7](runbook.md#7-ingest-the-topic-the-events-and-the-counters) has the
counters and what they reconcile against;
[§6](runbook.md#6-quarantine-what-ingestion-refused) has quarantine, which is
where unknown fields go rather than being coerced.

### 7. Assess

There is no command. See §1 — this is the gap. `demo/run-demo 3` is the working
example.

### 8. Emit

```bash
uv run scripts/emit.py --count    # what is pending, without emitting
uv run scripts/emit.py            # drain every terminal outcome to the topic
```

Every assessed context leaves once per terminal outcome — `normal` verdicts,
`suspicious` ones and **typed failures alike**. A failed run is emitted as a
typed failure with no verdict; it is never dropped and never given a verdict.

The topic and broker are not flags, deliberately: a topic typed on a command line
is a topic that can differ between two runs of the same deployment.

**The output topic is egress, not storage.** Nothing is recoverable only from it,
and anything forwarding it off-site inherits the disclosure obligations —
[runbook §11](runbook.md#11-egress-what-the-output-topic-carries-and-what-you-inherit-by-forwarding-it).

---

## 4. The operating loop

| Cadence | Command | Why |
| --- | --- | --- |
| Continuous | your publisher → ingest topic | the engine contextualises as records land |
| Hourly at most | `scripts/load_threatfox.py` | the export regenerates every few minutes; an hour is the floor the fair-use terms imply |
| After each assessment batch | `scripts/emit.py` | drains terminal outcomes to egress |
| Daily, or when something looks wrong | `make status` | below |
| Daily | `make backup` | below |

### Watching it

```bash
make status                                            # the pipeline's own numbers
uv run scripts/status.py --captures <dir>              # ... including records retained
```

`--captures` takes **the directory your deployment retains captures in**, and
there is no default, deliberately. A capture store is a directory of files each
named `<sha256>.jsonl` — `data/ingest/` is *not* one: it holds a sample under a
human name, and both this file and the `Makefile` used it as the example until
2026-09-12. A path that is not a readable capture store is a named failure
(`CaptureStoreUnreachable`) rather than a report of zero records, because a
mistyped directory reading as *"this deployment retained nothing"* is the same
error in a more expensive place.

**It is not a health check.** It prints numbers and does not decide which are
bad — latency, cost, staleness, escalation, typed failures and the end-to-end
record reconciliation, every one a plain SELECT over the single store.
[runbook §13](runbook.md#13-status-what-the-pipelines-own-numbers-say) explains
what each number is and what it is not.

Every rate refuses an empty denominator rather than printing `0.0`, because
`0.0` would ship as the fact *"the boundary dropped nothing"* when what happened
is that nothing was measured.

### Backing it up

```bash
make backup                                              # → .backups/
uv run scripts/backup.py --verify .backups/<file>
uv run scripts/backup.py --restore .backups/<file> --schema <throwaway>
uv run scripts/dev_check.py --captures <dir>             # the other half
```

**The durable record is two halves and you need both**: the engine's tables, and
the retained captures. The captures back up the *input*, not the store — a
capture replay alone reconstructs the events and **no** assessment, snapshot or
evidence row. The broker and the output topic are excluded from the durability
model by decision.

Restore refuses into a schema that already holds rows, and every refusal fires
before the first INSERT, because the engine has no transaction to roll a
half-restore back. [runbook §15](runbook.md#15-durability-what-survives-what-is-backed-up-and-how-long-recovery-takes)
and [ADR-0040](decisions/0040-durability-and-backup.md) are the model, the
residual risks and the measured recovery time.

### Explaining a stored assessment

```bash
uv run scripts/replay_assessment.py <assessment_id>           # calls nothing
uv run scripts/replay_assessment.py <assessment_id> --rerun
```

Without `--rerun` this calls no model and no provider: it validates the stored
rows against **the contract version the row recorded**, never against current
code, and rebuilds the request under the recorded rendering and context versions.
Replay reads stored responses and never re-queries a live provider.

---

## 5. Limits you will hit

Not caveats — each one is a thing that will surprise an operator who has not read
it, and each is recorded elsewhere with its reasoning.

- **No assessment runner.** §1. The largest one.
- **One engine per machine.** Fixed meta and compute ports.
- **No daemons**, so no restart semantics, no supervision, no health endpoint.
  Adding an HTTP surface is a decision, not a convenience —
  [ADR-0039](decisions/0039-architectural-boundaries.md).
- **One enrichment source in practice.** Two current snapshots have no single
  value for `enrichment_snapshot_version` — [`acceptance.md`](acceptance.md)
  finding 1, still open.
- **Enrichment must be contemporaneous.** A snapshot loaded after the traffic
  does not enrich it, and an archived capture cannot be enriched at all.
- **Coverage is sparse and that is normal.** The recent export is a two-day
  sighting window of a few thousand indicators. Ordinary traffic matches nothing,
  and `no_match` is a lookup outcome, never a statement of safety.
- **Multi-tenancy is not enforced.** Identity is stamped and carried; isolation
  between tenants is not implemented — [`deferred.md`](deferred.md).
- **What you may not claim.** Accuracy, recall, false-positive rate, escalation
  rate, latency, cost and identical replay are **not** claimable, because the
  labelled corpus that would measure them does not exist.
  [`acceptance.md`](acceptance.md) is the list, and it is short on purpose.

---

## 6. Where everything else lives

| You want | Read |
| --- | --- |
| One operation in detail | [`runbook.md`](runbook.md), §1–15 |
| What the prototype may and may not claim | [`acceptance.md`](acceptance.md) |
| Why something is built the way it is | [`decisions/`](decisions/) and its README |
| What is deliberately not built | [`deferred.md`](deferred.md) |
| Accepted risks | [`hazards.md`](hazards.md) |
| The architecture and each component | [`../README.md`](../README.md) |
| What the system is *for* | [`../concept/`](../concept/) — the authority |
| Seeing it work | `demo/run-demo 3`; [`demos.md`](demos.md) is which demo shows what |
| Building a corpus to run it over | [`synthetic-corpus.md`](synthetic-corpus.md), `scripts/rebase_capture.py`, `scripts/plant_indicators.py` |
