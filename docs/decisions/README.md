# Decision records

One record per settled question. **Identifiers are never reused**
(`concept/instruction.md` §4): the next record is `0047`, and a superseded record
keeps its number and says what superseded it.

A record here is not a design document — `concept/` is the design document. A
record exists when a question was **settled**, and its job is to say what was
decided, what was measured, what was rejected and what the decision does **not**
cover. `concept/instruction.md` §5: *important knowledge goes in the repository,
not only in the conversation that produced it.*

Two registers sit beside this directory and are part of the same governance:
[`../deferred.md`](../deferred.md), every deferred capability with its re-entry
test, and [`../hazards.md`](../hazards.md), the accepted risks. Per-source
records are in [`../sources/`](../sources/).

---

## The index

| # | Title |
| --- | --- |
| [0001](0001-repository-layout-and-toolchain.md) | One package, one test suite, one environment |
| [0002](0002-dependency-set.md) | The dependency set, and what is deliberately absent |
| [0003](0003-lint-and-typecheck-tooling.md) | Lint and typecheck tooling: escalated, not chosen |
| [0004](0004-configuration-variables.md) | The configuration variables, and what has no default |
| [0005](0005-structured-logging-and-redaction.md) | Local structured logging, and where credentials are redacted |
| [0006](0006-running-the-pinned-binaries.md) | Running the pinned binaries: verify, do not fetch |
| [0007](0007-sql-migrations.md) | The engine schema is numbered `.sql` files, applied by a small runner |
| [0008](0008-version-registry.md) | The version registry, and why a revision is never an edit |
| [0009](0009-netify-application-identification.md) | Netify is admitted as an enrichment source, and what that does not mean |
| [0010](0010-capture-identity.md) | The flow record contract, and what capture identity rests on |
| [0011](0011-event-identity-and-the-event-id.md) | The identity the Normalizer stamps, and how an event id is made |
| [0012](0012-input-format-adapters.md) | Per-format input adapters, and the registration point |
| [0013](0013-quarantine-in-the-single-store.md) | Quarantined records live in the single store |
| [0014](0014-the-ingest-topic-message.md) | The ingest topic message: the record in the value, its reference in the headers |
| [0015](0015-the-flatten-layer.md) | The flatten layer is eight plain views, and a layer's row is what says it was observed |
| [0016](0016-view-layering-and-materialization-policy.md) | The view-layering rule and the materialization policy are enforced by declaration and by execution |
| [0017](0017-the-agent-contract.md) | The agent contract: one versioned pair, and the four things it says that `concept/04` does not |
| [0018](0018-the-triage-rendering.md) | The triage rendering: the five parts, the line grammar, and the TLS subset |
| [0019](0019-the-rendering-size-budget.md) | The rendering size budget, and what a truncated section says |
| [0020](0020-the-model-client.md) | The model client, structured output, and the bounded schema retry |
| [0021](0021-the-triage-runner.md) | The triage runner, and the prompt as a frozen version |
| [0022](0022-the-composition-rule.md) | The composition rule, and where it runs relative to the prompt |
| [0023](0023-deterministic-escalation.md) | Deterministic escalation, and the thresholds that are not in the code |
| [0024](0024-provider-tools-and-the-mcp-boundary.md) | Provider tools: what the layer owns, and what "MCP" means here |
| [0025](0025-the-lookup-cache.md) | The lookup cache, which is the evidence store |
| [0026](0026-the-budget-guard.md) | The budget guard: one ledger per run, charged at the boundary |
| [0027](0027-disclosure-and-the-send-policy.md) | Disclosure recording and the send policy |
| [0028](0028-the-threatfox-hunting-api.md) | The ThreatFox hunting API: the source record for the first live provider |
| [0029](0029-the-analyst-runner.md) | The analyst runner: two phases, one ledger, and a downgrade that is recorded |
| [0030](0030-untrusted-text-isolation.md) | Untrusted-text isolation: one wrapper, one escaper, and a pin on the frozen prompts |
| [0031](0031-replay-at-the-tool-boundary.md) | Replay at the tool boundary, and the guard that makes it one |
| [0032](0032-deterministic-routing.md) | Deterministic routing, the escalation branch, and what would reverse it |
| [0033](0033-assessment-persistence.md) | Assessment persistence: one row per agent run, citations as join rows |
| [0034](0034-ephemeral-state-and-re-run.md) | Ephemeral state, and re-run as the whole of recovery |
| [0035](0035-assessment-replay.md) | Assessment replay from the stored versioned inputs |
| [0036](0036-the-output-message.md) | The sink view and the emitted message |
| [0037](0037-at-least-once-emission.md) | At-least-once emission, and the count that outlives the broker |
| [0038](0038-pipeline-metrics-and-reconciliation.md) | Pipeline metrics and reconciliation, as views rather than a tracer |
| [0039](0039-architectural-boundaries.md) | The architectural rejections are tests, and reversing one is a decision record |
| [0040](0040-durability-and-backup.md) | Durability: the two halves of the record, and a logical backup of the tables |
| [0041](0041-enrichment-status-representation.md) | Enrichment status: six states, four names, and the two that are derived |
| [0042](0042-port-qualification-of-an-address-match.md) | How a port qualifies an address match: a scope, a three-valued flag, and a policy rule |
| [0043](0043-the-compromised-flag.md) | The compromised flag is native evidence, and the taxonomy root is never read off a threat type |
| [0044](0044-the-snapshot-scheme.md) | The snapshot scheme: one ledger, intervals, and history that is not deleted |
| [0045](0045-who-decides-the-analyst-is-unsure.md) | What "the analyst is unsure" means, and who decides it |
| [0046](0046-negative-results-are-kept.md) | Failed and inconclusive experiments are results, and they are kept where they happened |

---

## Open-question closure

`concept/08-open-questions.md` splits its unknowns into *the one that blocks
everything*, *blocking — must be answered inside the stage that needs them*, and
*not blocking — assumptions in force*. **The blocking ones are answered inside
the stage that needs them, so their answers are beside the code that settled
them.** This table is the map from the question to that place, and
`tests/test_governance.py` keeps it honest: every heading of the blocking section
is represented here, and every record this table names exists.

**A row that says STILL OPEN is not a defect in this table.** It is the answer.

### Enrichment

| Question, as `concept/08` asks it | Settled by |
| --- | --- |
| How the enriched context represents enrichment that is **missing, stale, in flight or failed** | [0041](0041-enrichment-status-representation.md) — four names for six states; `ok` stored, `stale` and `missing` derived, `in_flight` deliberately not a status |
| The **loader's schedule per feed**, and how fetch failures, format changes and empty responses are handled without silently emptying a table | [0044](0044-the-snapshot-scheme.md) — the schedule is `SourceDescriptor.refresh_interval_seconds`, a failed load writes nothing and does not end the previous snapshot's validity; the typed failure sets are in [`../sources/`](../sources/) |
| How the **port qualifies** an address match | [0042](0042-port-qualification-of-an-address-match.md) — `address:port` scope, a three-valued `port_matched` that is not a filter, and one policy rule |
| How a **compromised flag** is carried, given the taxonomy root cannot come from threat type alone | [0043](0043-the-compromised-flag.md) — native evidence, never the classification; the mapping emits the root for every threat type, so nothing reads a root off one |
| The **snapshot and versioning scheme**, and how replay selects the snapshot current at event time | [0044](0044-the-snapshot-scheme.md) — one ledger, `lead()` intervals, a range predicate on `window_start` |

### Rendering and triage

| Question | Settled by |
| --- | --- |
| Which **TLS parameters** are selected, and by what criterion | [0018 §3](0018-the-triage-rendering.md) |
| What **bounds the rendering** for a busy host, and how truncation is made visible | [0019](0019-the-rendering-size-budget.md) — one measured number, four selection rules, and a visible `truncated` line. §6 says what it deliberately does not do |
| How **per-value citations and freshness** are carried without bloating the rendering | [0018 §5](0018-the-triage-rendering.md) — status and classification as two tokens, freshness as one line |
| The **per-source confidence thresholds** that decide when a Tier B match escalates independently | [0023 §4](0023-deterministic-escalation.md) and `config/policy.toml`, which states of itself that 0.80 is **a candidate, not a decision**, and why |
| **Where the composition rule lives** — policy code, prompt, or both — and how it is tested | [0022](0022-the-composition-rule.md) — policy code, after the prompt, as a frozen versioned package; seven rules, each the sentence of `concept/02` it is |
| The numeric **budget values and retry count** | [0026](0026-the-budget-guard.md) (four dimensions, one ledger per run) and [0020 §5](0020-the-model-client.md) (the bounded retry, and why a repair call is forbidden). Both candidates, and both say so |
| The **table design for evaluated contexts** and their citation joins | [0033](0033-assessment-persistence.md) |
| The list of **contributing events is unbounded** and nothing truncates it | [0019](0019-the-rendering-size-budget.md), which quotes this question as the reason it exists |

### The analyst and the provider tool

| Question | Settled by |
| --- | --- |
| **Confirm the live provider's query surface** against the authenticated documentation before building the tool | [0028](0028-the-threatfox-hunting-api.md) — eighteen live requests, and it **corrected** `concept/05`: the per-indicator lookup exists |
| Which sources are approved for **analyst-time querying** and what may be sent to each | [0027 §1](0027-disclosure-and-the-send-policy.md) — a whitelist in the versioned policy file, refusing rather than trimming |
| How retrieved **unstructured text is isolated** from instruction channels, and how that isolation is *tested* | [0030](0030-untrusted-text-isolation.md) |
| What happens when a source is **down, rate-limited or slow** mid-analysis | [0024 §2](0024-provider-tools-and-the-mcp-boundary.md) — four things the agent sees, **and none of them is `no_match`** |
| **Cache retention** per source and endpoint | [0025 §7](0025-the-lookup-cache.md) |
| **Whether negative results are cached**, since most lookups miss | [0025 §3](0025-the-lookup-cache.md) — **yes** |
| **Cache-key normalization** | [0025 §2](0025-the-lookup-cache.md) |
| Whether an **expired entry is offered as explicitly stale** when the provider is unreachable | [0025 §4](0025-the-lookup-cache.md) — **yes** |
| Whether the **MCP servers** are self-hosted wrappers per provider, and their failure behaviour *as the agent sees it* | [0024 §1](0024-provider-tools-and-the-mcp-boundary.md) |
| What **"the analyst is unsure"** means and **who decides it** | [0045](0045-who-decides-the-analyst-is-unsure.md) — two senses, two deciders; the routing one is deterministic code and never a tool in the model's list |
| Setting the **wall-clock and live-query budgets against each other** | [0026 §1](0026-the-budget-guard.md) — one ledger per run, which is what makes the wall clock mean anything |
| How an upstream **false-positive list** enters — as evidence about evidence, not a quiet filter | The design stands and is unchanged; **measured 2026-09-10, there is no such list to enter.** [0028 §8](0028-the-threatfox-hunting-api.md) and [`../deferred.md`](../deferred.md) §1 |

### The output

| Question | Settled by |
| --- | --- |
| The **field-level shape** of the emitted message | [0036](0036-the-output-message.md) |
| Making **emission countable from the engine side** | [0037](0037-at-least-once-emission.md), [0038](0038-pipeline-metrics-and-reconciliation.md) |

### Cross-cutting and urgent

| Question | Settled by |
| --- | --- |
| A record was silently lost at a catch-up boundary — **replayability is a goal rather than a claim while that stands** | **STILL OPEN.** Nothing reproduces the loss. Recorded as an accepted hazard, [`../hazards.md`](../hazards.md) §2, and it is why `concept/01` puts *"identical inputs replay identically"* on the not-claimable list |
| **Durability and backup** for the single store | [0040](0040-durability-and-backup.md) — and it closes the single store's half **only**, which it says explicitly |
| Where **quarantined records** live | [0013](0013-quarantine-in-the-single-store.md) |

### The one that blocks everything

**A labelled, multi-host, time-correct evaluation corpus does not exist.** Not
closed and not closeable from inside this repository. `docs/evaluation-corpus.md`
is the written requirement, the harness stays `deferred`
([`../deferred.md`](../deferred.md) §7), and every artifact depending on a
measurement says *unmeasured*.

### Not blocking — assumptions in force

`concept/08`'s last table is **not** reproduced here. Those are assumptions with
a *revisit-when*, not questions with an answer, and copying them would create a
second copy that drifts from the one that is maintained. Five of its rows have
since become measurements and were updated in place there, which is the argument
for having one home rather than two.
