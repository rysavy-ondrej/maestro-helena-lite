# 0031 — Replay at the tool boundary, and the guard that makes it one

**Status: accepted.** Task 41 (D5 Tools).
**Authority:** `concept/07-principles.md` ("Caching", "Retention and replay"),
`concept/05-threat-intelligence.md` (the MCP provider tool rules),
`concept/03-architecture.md` (Orchestration "replays from stored results"),
`concept/02-concepts-and-taxonomy.md` (the four statuses and `no_match`),
`concept/instruction.md` §2 and §3, and
`docs/decisions/0025-the-lookup-cache.md`.

This increment adds a replay mode to `helena.tools.ProviderTool`, one refusal
reason, and `helena.network` — a module holding one context manager. It adds **no
runtime dependency, no second store, no egress channel, no source, no config key
and no contract field**, and it changes no stored shape: replay reads exactly
what `sql/migrations/0017` already stores.

---

## 1. Replay is a mode of the run, not an argument of the call

`replay` is a constructor keyword on `ProviderTool` with **no default**, so every
construction site says which of the two a run is. Three alternatives were
considered and rejected:

- **A per-`lookup` argument.** A mode a caller can vary per call is a mode a tool
  loop can vary per turn, and a run half of which re-queried is not a replay of
  anything.
- **A field on `RunScope`.** It is the right *scope* — one run, and not the
  model's to choose — and the wrong object: `RunScope` is the tenant and the
  sensor, and its whole argument is about isolation. A mode on it would travel
  through the cache key's neighbourhood for no reason.
- **A key in `config/policy.toml`.** A deployment does not have a replay setting.
  Whether *this run* replays is the caller's statement about this run.

Defaulting it to `False` was rejected too, and the direction matters: forgetting
to say `replay=True` when replaying is the exact failure this task exists to
prevent, and a default is what lets it be forgotten. The cost is four
construction sites, all in this repository.

## 2. A replay miss is a refusal, and it could not have been anything else

`no_stored_response` joins `helena.tools.REFUSAL_REASONS`. It is not a
`QueryFailure`, for the reason the other four refusals are not: nothing was
queried, so there is no provider to attribute an outage to, and recording a
`transport_error` for a request nobody made would be an outage that did not
happen.

It also **could not** have been a retrieval step. `helena.contracts.v1`'s
`RETRIEVAL_OUTCOMES` is `cache_hit` and `live_query`; a replay miss is neither,
and widening a frozen contract to record the absence of a row is a change
`concept/instruction.md` §3 requires a decision for and this increment does not
need. What the model sees is a typed, agent-visible refusal naming the source,
the endpoint and the entity type — and never the value, for the reason
`_forbidden`'s detail names fields and never values.

And it is not a `no_match`. `concept/02` calls `no_match` "a lookup outcome,
never a statement of safety" — the provider said it lists nothing. `no_stored_response`
is nobody having asked. `stale`, `failed`, `missing`, `no_match` and a typed
error stay five things, and this is a fifth kind of absence that collapses into
none of them.

## 3. An expired record is served in a replay, not refused

Nothing is ever evicted (ADR-0025 §1), so an expired record is still there and
still citable, and `concept/02` defines `stale` as exactly that: the claim
stands and its age is part of what it is worth. Refusing anything past its
retention would make a replay of a three-week-old assessment return nothing,
which is the opposite of what replay is for.

**No failure step travels beside it.** The live path's stale fallback carries one
because a provider was reached and did not answer; a replay reached nothing, and
reporting a timeout nobody experienced would be inventing an outage to explain an
age. The difference between the two runs is therefore visible in the trace — one
has a `live_query` step with a `QueryFailure`, the other has only `cache_hit`
steps — which is `concept/07`'s "distinguishable afterwards" holding for the
awkward case as well as the easy one.

One consequence found while writing it: `_served` derived its **log line's**
status from whether a failure was passed, which was right for both live callers
and wrong the moment a replay could serve an expired record with no outage. It
now derives it from the same expiry the evidence rows are dated against.

## 4. The guard, and the precise bound on what it claims

`helena.network.no_network()` arms a refusal in front of `socket.socket.connect`,
`connect_ex` and `socket.getaddrinfo`, and `ProviderTool.lookup` wraps the whole
dispatch in it whenever the tool is a replay. A `NetworkAttempted` propagates: it
is not a typed result the model can read and argue with, because a mode that
promises to send nothing has either sent nothing or has a bug.

**It blocks new outbound connections. It does not block reads and writes on a
connection that was already open**, and that is deliberate rather than a gap left
unnoticed: a replay resolves every lookup out of the streaming engine over a
`psycopg` connection opened before the guard is armed, and a guard that stopped
the store being read would stop a replay being a replay. `tests/test_replay.py`
pins that bound by executing a real query against the real engine inside the
guard.

So the claim the project may make is: **nothing new leaves the process while a
replay lookup is running**, and it is no stronger than that. An adapter holding a
pooled connection open from a live phase would slip through; none does, because
`helena.providers` opens a socket per call. A UDP `sendto` on an unconnected
socket would slip through; nothing here sends one. Blocking every method of every
socket would make this a sandbox, which it is not.

The structural guarantee is separate and is the stronger of the two: in replay no
branch of the dispatch reaches `self._ask` at all. The guard exists because a
guarantee about which branches run is a claim about code, and this task asked for
one about behaviour.

## 5. Why `helena.network` is a module

`helena.tools` may not import `socket`: `tests/test_tools.py` reads its AST and
fails if it imports `urllib`, `http`, `socket` or `ssl`, which is what makes "the
agent sees a tool, never an HTTP client and never a key" a property of the code
(task 34). `helena.providers` owns the protocol and would be the obvious home,
and cannot be one — it imports `helena.tools`, so the tool layer would import its
own adapter.

The module therefore holds one context manager, one exception, no URL, no
credential and no client. It is named for the guard and **not** `replay`, because
`concept/03-architecture.md` puts "replays from stored results" inside
Orchestration and that runner does not exist yet.

## 6. What this does not make replayable

A replayed **lookup**, not a replayed **assessment**. A whole run still calls the
model — hosted inference is a different quota, a different disclosure channel and
a different record — and the stored assessment a full replay would be reconstructed
from is not written by any increment yet. `concept/03`'s Orchestration row is
where that lands.

Two smaller ones, named so a green suite does not read as more than it is: what
is replayed is the **claims** stored beside the response, re-validated against the
`taxonomy_version` the row recorded (`concept/instruction.md` §2 — never today's
declared subset), with the native bytes travelling alongside on `Lookup.native`.
Re-deriving the claims from the stored bytes on each replay would run today's
mapping over an old answer, which is the migration-forward that invariant
forbids. And nothing prunes the store, so how far back a replay can reach is
still bounded only by disk — `concept/08` lists the retention horizon as open and
this increment does not close it.
