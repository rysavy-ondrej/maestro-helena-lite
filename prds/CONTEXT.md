# CONTEXT — the implementation agent's operating guide

You are Claude Code, running **one PRD task in one fresh session**. This file is
your entry point. Read it, then the task, then only what the task needs.

You are not building HELENA in this session. You are building **one task's worth
of it**, well enough that the next session can build on it without reading yours.

---

## 1. Authority order

When two sources disagree, the higher one wins — and **say that they disagreed**
in your report rather than quietly picking one.

1. **`../concept/`** — what HELENA is. The intent and the invariants.
2. **`../concept/instruction.md`** — how it may be built. **Binding rules.**
3. **`prd.json`** — the task list. *What* to build next, not permission to break 1 or 2.
4. **This file** — how to run a session efficiently.

If a task's steps would break an invariant in `instruction.md`, **do not do it**.
Implement what is compatible, and record the conflict in your report. A task
description is a plan written earlier; the invariants are the project.

---

## 2. Repository map

```
concept/         The concept notes. Authoritative. Read what you need, not all of it.
  README.md              index + the six-stage shape
  01-goal-and-scope.md   the problem, scope, what may not be claimed
  02-concepts-…          vocabulary, taxonomy, scope-before-severity
  03-architecture.md     stages, components, single store, boundaries
  04-the-two-agents.md   Triage vs Analyst
  05-threat-intelligence.md  sources, tiers, loader/tool rules
  06-technology.md       Python 3.12, uv, RisingWave, Blink, LangChain, Pydantic
  07-principles.md       the rules an implementation may not break
  08-open-questions.md   what is unsettled, and what it blocks
  instruction.md         BINDING build rules + the definition of done

prds/            This folder. Task list and progress tracking.
  prd.json               56 tasks. THE SCRIPT OWNS THIS FILE — do not edit it.
  CONTEXT.md             this file
  instructions.md        a copy of concept/instruction.md (stale links; prefer the original)
  reports/task-NN.json   YOUR OUTPUT. One per task. See §7.
  logs/                  raw session envelopes, written by the script
  progress.txt           append-only human log, written by the script
  session.json           runner state, written by the script
  session-memory.json    lessons carried between sessions. Read it. Script writes it.
  .usage-cache.json      the runner's budget cache. Ignore it.

.venv/           The Python environment. Already created (uv venv, 3.12.14), no
                 packages installed yet. Use it; do not create another. See §3.

implement.sh     The runner that gave you this task. Owned by the operator —
                 do not edit it, do not run it from inside a session.

bin/             Third-party binaries the project RUNS, not builds.
  risingwave             streaming engine, pinned v3.0.3
  blink                  Kafka-protocol broker, pinned commit
  env.sh                 `source bin/env.sh` before running risingwave (LD_LIBRARY_PATH)
  README.md              pins and the libpython ABI hazard — read before touching bin/

data/            Fixtures. Real data, not evaluation data.
  ingest/flow-sample.jsonl   62 records, one host, 2.2 minutes, straddles a window boundary
  threatfox/*.json           feed format reference (gitignored, may be absent)
  netify/*.csv               application-identification sample

.env             Local secrets — populated and live. NEVER read its values into a
                 report, a log, a test fixture, or a commit. Names are fine. See §3.
```

Do not assume a file exists because a note mentions it, and do not rebuild what
§3 says is already here. The package, `pyproject.toml` and `uv.lock` were created
by task 0, and the tree **is** a git repository whose default branch is `main`.
**Development is linear: one task in flight, `main` always the whole of what is
done.** A finished task is committed and merged (§4, *Land*); an unfinished one
blocks the next from starting.

---

## 3. What is already here — use it, don't rebuild it

Three sets of working artifacts are already in the tree. They exist so that
structural decisions are made against **real shapes and real behaviour** rather
than against a documentation page, and so modules can be tested for real. The
project's own rule applies: *check the artifact, not the page.*

### `bin/` — the binaries, already built and runnable

Do **not** build these, download them, containerise them, or add them as
dependencies. They are third-party binaries the project *runs*.

| Binary | Version (verified) | What it is |
| --- | --- | --- |
| `bin/risingwave` | `3.0.3 (ec07f2eb75)` | The streaming engine — the single store. Speaks the PostgreSQL wire protocol |
| `bin/blink` | `0.2.0` | The Kafka-protocol broker, for ingress and egress |
| `bin/lib/libpython3.12.so.1.0` | CPython 3.12.14 | RisingWave links this. `bin/env.sh` puts it on `LD_LIBRARY_PATH` |

```bash
source bin/env.sh                                    # required before risingwave
./bin/risingwave single_node --store-directory ./.rwdata
./bin/risingwave playground                          # in-memory, for a throwaway test instance
./bin/blink --settings <path>                        # blink needs a settings YAML
```

**Never symlink another Python minor onto `libpython3.12.so.1.0`** — the ABI
differs and the failure is silent. `bin/README.md` has the pins and the hazard.

Tests that need an engine should start a throwaway instance (`playground` is
in-memory) and execute the SQL against it. **A test that asserts on SQL text
instead of running it is not a test** — it finds the comment arguing for a
thing's absence.

### `data/` — real samples, for shape decisions and for tests

Real data, verified on disk. **Not evaluation data** — there are no labels, and
the labelled corpus does not exist.

| Path | What it actually contains | What it is good for |
| --- | --- | --- |
| `data/ingest/flow-sample.jsonl` | **62 records**, one host (`10.127.0.100`), **130.8 s** — so it straddles a 5-minute boundary. Layers present: `dns` 30, `tls` 25, `http2` 15, `http` 11, plus `ip`/`tcp`/`udp` | The input contract, the normalizer, windowing, entity extraction, the whole ingest→context path. Cleared for the repository |
| `data/threatfox/ip_port_recent.json` | **3 375** records, `ioc_type: ip:port` (e.g. `45.192.105.203:8000`) | The address side of the enrichment join, and the port-split rule |
| `data/threatfox/domains_recent.json` | **433** records, `ioc_type: domain` (including `*.workers.dev` shared infrastructure) | The domain side of the join, and the shared-infrastructure case |
| `data/threatfox/urls_recent.json` | **287** records, `ioc_type: url` | URL scope, and host-part extraction |
| `data/netify/ips.csv` | **965 967** rows: `ip,app_id,tag,category` | See the note below — read before using |
| `data/netify/domains.csv` | **11 144** rows: `domain,app_id,tag,category` | ditto |
| `data/netify/applications.csv` | **1 500** rows, `;`-delimited: `id;tag;short_name;full_name;description;url;category` | ditto |

**The ThreatFox files carry all fourteen documented fields** — `ioc_value`,
`ioc_type`, `threat_type`, `malware`, `malware_alias`, `malware_printable`,
`first_seen_utc`, `last_seen_utc`, `confidence_level`, `is_compromised`,
`reference`, `tags`, `anonymous`, `reporter`. Two shape facts to verify for
yourself rather than take from here: the top level is an **object keyed by IOC id
whose values are lists** (every list in this snapshot has one element, but the
shape permits more — **flatten, never read `[0]`**), and `tags` is a
**comma-separated string**, not an array.

These snapshots are a **format reference**, not a live feed — ThreatFox
regenerates every few minutes, so treat these as one snapshot with one version.
Commit a small extract as a test fixture; do not commit the full files.

> **Settled on 2026-09-03 — do not escalate this again.** An earlier reading of
> `concept/05-threat-intelligence.md` had Netify as commercial-only and out of
> scope, which contradicted the million rows sitting in `data/netify/`. The
> operator decided: the prototype **may use it locally**, as a **Tier D** source
> that supplies application identity and category and **never a threat
> classification or a decision about an entity**. Domains match on the name **as
> observed** — from DNS or TLS SNI — and never on the registrable domain, because
> Netify's keys are not all registrable domains. The decision, its measured
> coverage and the two hazards it carries are in
> [`../docs/decisions/0009-netify-application-identification.md`](../docs/decisions/0009-netify-application-identification.md).
> Reports from tasks 0–10 list this as open; they predate the decision.

### `.venv/` — the environment, installed and locked

A virtualenv exists at the project root, created with `uv venv`:

| | |
| --- | --- |
| Path | `.venv/` (project root) |
| Python | **3.12.14**, uv-managed CPython — matches the 3.12 the engine binary links against |
| Packages installed | the locked set — `uv sync` rebuilds it from `uv.lock` |
| uv | 0.12.7 |

`pyproject.toml` and `uv.lock` were created by task 0. `uv.lock` is committed and
is the reproducibility contract; the environment is disposable and rebuilt from it.

- **Use the venv that is here.** Do not run `uv venv` again, do not create a
  second environment, do not use `virtualenv`, `conda`, or a system interpreter.
  `uv` finds `.venv/` at the project root automatically.
- **Add dependencies with `uv add`**, so they land in `pyproject.toml` *and* the
  lockfile in one step. **Never `pip install`** — a package installed outside the
  lockfile is invisible to the next session and to every later run.
- **Run everything through `uv run`** — `uv run pytest -q`, `uv run python -m …`.
  Never call `.venv/bin/python` directly in a committed script or a test command,
  and never the system `python3`.
- **Commit `uv.lock`.** It is the reproducibility contract; the environment is
  disposable and can be rebuilt from it with `uv sync`.

**The baseline dependency set is already decided** by task 0 and does not need an
escalation: Pydantic, `python-dotenv`, a Kafka client, a PostgreSQL driver, and
pytest for development. **Anything beyond that set is an escalation** (§6) — in
particular LangChain, which the concept notes place in the technology table but
which is **deliberately absent until the first increment that actually calls a
model**, with a boundary test enforcing its absence until then. Adding a package
in the increment that first *mentions* it, rather than the one that first *calls*
it, is the mistake this rule exists to prevent.

### `.env` — live credentials, for testing against real services

Populated and working. Load it through the project's own configuration path
(`python-dotenv`), never by parsing it ad hoc.

| Variable | Populated | For |
| --- | --- | --- |
| `LLM_URL`, `LLM_TOKEN`, `LLM_MODEL` | yes | The OpenAI-compatible model endpoint, for every agent |
| `LLM_MODEL_TRIAGE`, `LLM_MODEL_ANALYST` | yes | Per-agent model overrides. URL and token fall back to the general values |
| `ABUSECH_AUTH_KEY` | yes | The live hunting API (`Auth-Key` header). The bulk export needs no credential — see below |
| `VIRUSTOTAL_AUTH_KEY` | yes | Deferred provider — **do not spend the quota**: 4/min, 500/day, shared across everything |
| `RISINGWAVE_DSN`, `KAFKA_BOOTSTRAP_SERVERS` | yes | Local infrastructure |

**You may use these to verify a module really works** — call the model endpoint,
fetch a feed, connect to the engine. That is what they are for, and a module
tested only against a mock has not been tested against the thing that surprises
you.

**The rules around them are absolute:**

- **Never print a value** — not to stdout, a log, a report, a commit message, or
  a test fixture. Variable *names* are fine everywhere.
- **The abuse.ch key travels in an `Auth-Key` HEADER, not in a URL path.**
  Measured 2026-09-03: the API returns 401 without the header and 200 with it;
  the bulk export at `threatfox.abuse.ch/export/json/recent/` returns 200 with no
  credential at all. An earlier version of this file said the opposite — it was
  wrong. Re-measure before building against either; abuse.ch changes auth on its
  own schedule.
- **Redact a credential in a URL path anyway**, before anything is logged, stored
  or recorded as provenance. A live key has already leaked into a project
  conversation by exactly that route, and the rule is about the exposure channel,
  not about this one provider.
- **Resolution is agent-specific, then general, then fail.** A missing value is a
  startup error naming the variable — never a default, never a fallback to
  another agent's model. Empty and whitespace count as missing.
- **Do not commit `.env`**, and do not copy values into `.env.example`.
- **Respect the quotas.** Fair-use terms bind the feeds; VirusTotal's daily
  budget is shared with every future run and every future evaluation.

## 4. The session loop

### Check the tree is clear — before anything else

**The history is linear and exactly one task is ever in flight.** A task may not
start while the previous one is unfinished or unmerged. There are never two
branches at different stages of development, and `main` is always the whole of
what is done.

Run this first. If any of the three is non-empty, **stop**: write
`prds/reports/task-NN.json` with `"status": "blocked"` naming what is
outstanding, change nothing else, and let the operator resolve it.

```bash
git status --porcelain          # uncommitted work from an earlier task
git branch --list 'task-*'      # a task branch that was never merged
git worktree list               # a workspace that was never released
```

This is a hard precondition, not a preference. An unmerged branch is a task
someone stopped in the middle of; starting a second task on top of it is how a
repository ends up with two half-finished stages and no way to tell which one
`main` should believe. **Resolving it is the operator's call, never a session's**
— do not merge, rebase, delete or stash another session's work to clear your way.

### Orient — cheaply

1. Read `session-memory.json`. Past sessions recorded lessons and failed
   approaches there; repeating one is the most expensive mistake available.
2. Read your task from `prd.json` (the runner also pastes it into your prompt).
3. Read **only the concept notes the task touches** — plus `instruction.md` §2
   (invariants) and §7 (definition of done), always.
4. Look at what already exists before writing: `ls`, `Glob`, `Grep`. Earlier
   tasks built things; the previous session's report says what. **§3 lists what
   shipped with the project** — binaries, sample data, the venv, live
   credentials. Reaching for a mock, a fixture generator, or a download when one
   of those already covers it is wasted work and a worse test.

**Do not read all of `concept/` "for context".** It is ~1,500 lines. Read the
index, then the two or three notes that matter. Reading the rest costs you the
context budget you need for the actual code.

### Plan

Put the task's `steps` into **TodoWrite** as your working list, adjusted for what
you find. One in progress at a time. This is what makes a long task recoverable
if you run out of room.

If the task is large or ambiguous, spend one thinking pass on the shape before
touching files — but do not write a design document. The concept notes are the
design document.

### Implement

Follow `instruction.md`. The rules that bite most often, in practice:

- **Smallest coherent slice.** No base class with one subclass, no interface with
  one implementation, no config key with one value, no registry for two things.
- **Add a dependency in the increment that first *calls* it**, never the one that
  first mentions it. If you need a new dependency, that is an **escalation**, not
  a decision.
- **Streaming-first.** If it can be a view, it is a view. Plain view unless
  something queries or joins from it; every definition states which and what reads it.
- **Fail loud.** No silent default, no swallowed exception, no defaulted tenant.
- **Never collapse** `stale` / `failed` / `missing` / `no_match` / typed error.

### Verify — actually run it

A task is not done because the code looks right.

- `uv run pytest -q` for the whole suite; `uv run pytest -q -k <pattern>` while
  iterating. Run the **full suite** at least once before reporting.
- **`migrated_engine` shares one migrated schema across the run** and empties the
  data tables before each test. Do not "fix" it back to migrating per test: each
  materialized view starts a streaming job, so per-test migration made the suite
  scale with (views x tests) and cost 1 135 s for one module where it now costs
  42. If you need a genuinely pristine schema, take `engine_schema` and apply
  what you want — that is what the migration runner's own tests do.
- If the task touches SQL, the test must **execute** it against a throwaway
  engine instance, not assert on its text. (A test that greps SQL text finds the
  comment arguing for a thing's absence — assert against what the engine receives,
  with comments stripped.)
- Use the **real artifacts** (§3): `data/ingest/flow-sample.jsonl` for the ingest
  path, `data/threatfox/*.json` for the enrichment join, a `./bin/risingwave
  playground` instance for SQL, and the live credentials in `.env` to prove a
  connector actually connects. A module tested only against a mock has not been
  tested against the thing that surprises you.
- If the task touches the binaries: `source bin/env.sh` first.
- If a verification fails and you cannot fix it inside the task's scope, that is a
  **`blocked`** report, not a `completed` one with a caveat.

### Report

Write `prds/reports/task-NN.json` (§7). **This is the deliverable the next
session reads.** A task with working code and no report is an incomplete task.

### Land — commit, merge, release the workspace

A task may be implemented in its own workspace, and when it is finished it is
**committed, merged to `main`, and the workspace released.** Working directly on
`main` is fine for a small task: the rule is not "always branch", it is *do not
leave finished work uncommitted*.

**A workspace here buys a clean revert point for one task, never parallelism.**
Development is linear (§4, first block), so at most one task branch exists at any
moment and it is released before the next task starts. Two task branches alive at
once is the state this workflow exists to prevent.

```bash
git worktree add -b task-NN ../helena-task-NN
```

**A fresh worktree does not carry what a session needs** — measured, not assumed.
Everything gitignored is absent: `.env`, `bin/blink`, `bin/risingwave`,
`bin/lib/`, `data/netify/`, `data/threatfox/` and `.venv/`, and `Settings.load()`
fails there naming every variable. Link them in first:

```bash
cd ../helena-task-NN
for p in .env bin/blink bin/risingwave bin/lib data/netify data/threatfox; do
  ln -s "/root/maestro-helena-lite/$p" "$p"
done
uv sync          # this worktree's OWN .venv - see the warning below
```

**`uv sync` in the worktree is required, and is not the second environment §3
forbids.** The main `.venv` carries `helena.pth` holding the absolute path
`/root/maestro-helena-lite/src`, so a shared or symlinked venv makes `import
helena` load the **main tree's** source: you would edit the worktree, test the
other tree, and get a green suite that proves nothing. A worktree venv built by
`uv sync` from the committed `uv.lock` is the same locked set and it is released
with the worktree.

Then, once the suite passes and the report is written:

```bash
git add -A && git commit          # the report is part of the commit
cd /root/maestro-helena-lite
git merge --no-ff task-NN
git worktree remove ../helena-task-NN && git branch -d task-NN
```

Four rules around it:

- **Check `git status` before committing** rather than trusting `.gitignore`.
  `.env`, `secrets/`, the `bin/` binaries and `data/netify` / `data/threatfox`
  are never committed; `uv.lock` always is.
- **A credential never enters a commit message**, exactly as it never enters a
  log line or a report.
- **Merge only a green suite** — and understand what not merging costs. If the
  task ends `blocked`, `partial` or `failed`, commit what exists, say so in the
  report, and **leave the branch unmerged** for the operator. That branch then
  **halts the pipeline**: by the precondition at the top of §4, the next task
  cannot start until the operator resolves it. That is the intended behaviour —
  a red or half-finished `main` costs every later session more than a stopped
  queue does.
- **Only one engine runs per machine** (task 3: meta and compute bind fixed
  ports), so a worktree does not get its own RisingWave. Run the suite in one
  workspace at a time.

---

## 5. Using Claude Code efficiently here

The point of these is to leave context for the work, and to avoid paying twice
for the same information.

**Searching and reading**

- `Grep`/`Glob` to locate; `Read` with `offset`/`limit` for anything large. Do not
  `cat` a directory tree to "get oriented".
- Batch independent reads and searches **into one tool block** — they run in
  parallel.
- **Never re-read a file to verify an edit landed.** `Edit` errors if it did not.
- `prd.json` is 68 KB. Read your task out of it with `jq` or `python3 -c`, not by
  reading the file.

**Subagents**

- Use the **Explore** subagent when the answer requires sweeping many files and
  you only want the conclusion (e.g. "where is the version constant duplicated
  between SQL and Python?"). It keeps the file dumps out of your context.
- **Do not** spawn a subagent for a lookup you can do in one `Grep`. Do not spawn
  a general-purpose agent to write the task's code — this session is the agent.

**Editing**

- `Edit` for existing files, `Write` only for new ones. Read before you edit.
- Match the surrounding code's idiom, naming and comment density. There is no
  house style document; the existing code is the style document.

**Shell**

- `uv run …` for anything Python, `uv add` for a dependency. Never a system
  `python3`, never `pip install`, never a second virtualenv — `.venv/` is already
  there (§3).
- Start a throwaway engine with `source bin/env.sh && ./bin/risingwave playground`
  rather than mocking SQL you could execute.
- Long-running things (an engine, a broker) go in the background; do not block a
  turn on a `sleep`.
- Keep a failing command's real output. Do not summarise an error you did not read.

**Context discipline**

- One task, one session. **Do not start the next task** because it looks small.
  The runner will give it a fresh session with a fresh budget.
- If you are running low on room, stop, write the report with
  `"status": "partial"` and precise notes on what remains. A truthful partial is
  worth more than a rushed finish — and the next session inherits your report,
  not your context.

**Do not**

- edit `prd.json`, `session.json`, `progress.txt` or `session-memory.json` — the
  runner owns them, and your channel to them is the report;
- leave a finished task uncommitted, or merged nowhere — see §4, *Land*;
- add a `docs/` sprawl. If a decision was made, record it where the task says;
  otherwise it goes in the report.

---

## 6. Escalate rather than guess

Stop and record an escalation in your report — do **not** improvise — for:

- a new **runtime dependency** or a framework;
- a **second store** of any kind, including a cache, a queue, or a state file;
- adding or changing an **enrichment source**;
- changing a **contract's** identity, provenance or relationship fields, or
  adding anything to the **agent contract**;
- **editing the taxonomy** (a revision is a new version module, never an edit);
- anything moving toward **blocking, containment or remediation**;
- a new **HTTP surface**, UI, or second egress channel including hosted tracing;
- a **conflict between the task and an invariant**, or between two documents.

An escalation is a normal, successful outcome for a session. Implement everything
around it, report the block precisely, and stop. **Guessing an external fact is
the one thing this project has been burned by repeatedly** — check the artifact,
not the documentation page, and if you cannot check it, escalate.

---

## 7. The report contract

Write exactly one file, `prds/reports/task-NN.json`, where `NN` is the
zero-padded task index the runner gave you. The runner reads it to update the
tracking files, so the shape matters.

```json
{
  "task_index": 7,
  "title": "[D1 Ingest] Normalizer core with identity stamping from configuration",
  "status": "completed",
  "summary": "One or two sentences. What now exists that did not before.",
  "assumption_validated": "What this increment let us learn, or 'none — infrastructure'.",
  "makes_buildable": "What the next task can now be built on.",
  "files_changed": ["src/helena/normalizer/core.py", "tests/test_normalizer.py"],
  "verification": {
    "command": "uv run pytest -q",
    "passed": true,
    "detail": "34 passed. SQL migrations executed against a throwaway instance."
  },
  "escalations": [
    {"kind": "dependency", "detail": "…", "blocking": false}
  ],
  "invariant_conflicts": [],
  "deferred": ["What the task listed that was deliberately not done, and why."],
  "lessons": ["Durable facts worth carrying to later sessions."],
  "failed_approaches": ["What was tried and did not work, so nobody retries it."],
  "next_session_should_know": "Free text. The handover."
}
```

`status` is one of:

| Value | Meaning |
| --- | --- |
| `completed` | Every step done, verification ran and passed, definition of done holds |
| `partial` | Real progress, verified as far as it goes, remainder stated precisely |
| `blocked` | Cannot proceed without a decision or an external fact. `escalations` says what |
| `failed` | Attempted and did not work. `failed_approaches` says what was tried |

**Report honestly.** `completed` with a failing test is the one outcome that
poisons every session after yours. The project's own rule applies to you: *never
claim more than was demonstrated.*

---

## 8. Definition of done

From `concept/instruction.md` §7 — all of these, or the status is not `completed`:

- [ ] The assumption the increment validates is stated, and the result recorded —
      including if it was negative or inconclusive.
- [ ] Exercised by the one pytest suite, including its SQL, **by execution**.
- [ ] Every new view declares view vs materialized view, and what reads it.
- [ ] Every new failure path is typed, stored and countable; counts reconcile.
- [ ] `stale` / `failed` / `missing` / `no_match` / typed error stay distinct end to end.
- [ ] Versions recorded on every citable row; duplicated constants asserted equal.
- [ ] No dependency, store, egress channel or contract field added without a decision.
- [ ] Maturity labels present and accurate; deferred things still say deferred.
- [ ] No credential in a prompt, row, log, trace, test fixture or the repository.
- [ ] The claim made is no stronger than what was demonstrated.

**And one item this file adds**, which is repository workflow rather than a build
rule, so it is deliberately *not* in `concept/instruction.md` §7 and does not make
the copy above drift:

- [ ] The work is **committed, and merged to `main`**, and any workspace opened
      for it is released (§4, *Land*). A `blocked`, `partial` or `failed` task
      commits but does **not** merge — and its unmerged branch **stops the next
      task from starting** until the operator resolves it (§4, first block).
