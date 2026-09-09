# 0027 — Disclosure recording and the send policy

**Status:** accepted, 2026-09-09. Supersedes nothing; extends
[0024](0024-provider-tools-and-the-mcp-boundary.md),
[0025](0025-the-lookup-cache.md) and [0026](0026-the-budget-guard.md), each of
which named this increment as the one that owed the disclosure record.

`concept/07-principles.md`, "Privacy and disclosure":

> **Querying an external source discloses the indicator to that source.** Two
> separate obligations follow: **what may be sent to which source is governed
> policy**, and **what was disclosed is recorded on the assessment** — source,
> query, cache hit or live, disclosed-to, and when.

Two obligations, and this decision is about where each of them lives.

## 1. The send policy is a whitelist in the versioned policy file

`config/policy.toml` already holds the two things `concept/07` calls "policy, not
constants in a branch" — the confidence thresholds and the budget values. What may
be sent is policy in the same sense and by the same note, so it is a third table of
the one file rather than a second file, and it is read by
`helena.disclosure.send_policy` the way the other two are read by
`helena.policy.thresholds` and `helena.budgets.load`.

Three keys per source and each is required, because there is no default for what
may be sent:

| Key | What it is | The rule the loader enforces |
| --- | --- | --- |
| `disclosed_to` | the host this source's requests go to | a **bare host**, never a URL — `concept/07` requires a credential in a URL to be redacted before anything is logged or stored, and a file with no URL cannot leak one |
| `entity_types` | what this deployment permits being disclosed to it | a subset of what the source *covers*: a permission cannot exceed the capability it is a permission for |
| `fields` | which fields of the outbound request may be populated | out of `helena.disclosure.SENDABLE_FIELDS`, which **is** the field set of `helena.tools.ToolCall` |

**An entry means a source may be queried live**, which is the same condition
`[rate_limits]` states of itself. `sslbl-ja3` gets none: it is a feed the loader
copies locally and a local join discloses nothing (`concept/03`), so an entry
would permit a disclosure nothing makes. A tool for a source with no entry cannot
be constructed at all — `ProviderTool.__init__` resolves the permission the way it
already resolves the descriptor, so registration and permission are two gates on
one line each.

**`threatfox-api.abuse.ch` is measured, not read off a page.** `POST
https://threatfox-api.abuse.ch/api/v1/` with no `Auth-Key` header answered `401
{"error": "Unauthorized"}` on 2026-09-09, which is the same result
`src/helena/enrichment.py` recorded on 2026-09-06, and the bulk export the loader
uses is a different host that needs no credential. The probe sent no credential and
no indicator. **The query surface behind that host is still unconfirmed** and
confirming it is task 38's; what is settled here is *where an analyst-tier query
would go*, which is what a disclosure record has to name.

## 2. Refusing rather than trimming, and before the cache rather than after

The enforcement is in `ProviderTool.lookup`, and a call the policy cannot admit is
a typed `ToolRefusal` carrying `send_policy_forbids`. It is a **fourth refusal
reason** rather than a variant of `entity_type_not_covered`, because the two are
different facts with different remedies: that one is the source's capability ("a
JA3 list has nothing to say about a domain") and is fixed by asking a different
source, and this one is the deployment's permission and is fixed by editing this
file. An operator who saw one count could act on neither.

**Nothing is trimmed.** A query with the forbidden part removed is a question the
deployment did not authorise and an answer to nothing, so a request that cannot be
assembled is not sent in a reduced form. The mechanism is that
`SENDABLE_FIELDS` is the `ToolCall`'s own field set: the adapter is handed that
object and nothing else, so a field the policy withholds is a request that cannot
exist, and a field added to the call later has to be declared and permitted before
anything can populate it. `tests/test_disclosure.py` asserts the two sets are equal
so they cannot drift.

**The check runs before the cache read.** The alternative — serving a stored
answer for an entity type the policy no longer permits — would let a revoked
permission keep producing claims from records fetched while it was in force.
Nothing evicts, so the records stay and a re-permitted source finds them again;
what changes is that a run under the new policy consults the source not at all.

## 3. A cache hit records nothing, which is where "cache hit or live" went

`concept/07`: *"A cache hit discloses nothing. The indicator was already disclosed
when the entry was fetched."* So the ledger records **one row per outbound call**
and a hit adds none. That is deliberately not the same as a row saying "cache hit":
a record that a run told a provider something it did not tell it is worse than no
record.

Where the fifth element of `concept/07`'s list lives is therefore
`helena.contracts.v1.RetrievalStep.outcome`, one step per record served, on the
same assessment — which is what
[0017](0017-the-agent-contract.md) already said the disclosure record would be
derived from. The two reconcile by construction and the suite asserts it:

    len(disclosures.to_channel(PROVIDER_LOOKUP)) == budget.live_queries_spent

with `budget.cache_hits` counting the calls that disclosed nothing. The stale
fallback is the one call in both: it reached the provider, which disclosed, and
then served stored rows.

**Recorded before the send, not after.** A request that reached the provider and
then timed out disclosed the indicator anyway, so recording on success would
under-record exactly the case an operator needs to see. The cost is a row for a
call that failed before it left the process, which over-records in the direction an
audit can live with.

## 4. Model inference is on the same footing, because it is egress

`concept/03`: *"Inference in the prototype is hosted, so prompts leave the
monitored network and the disclosure rule applies to model calls as much as to
intelligence lookups."* So `helena.agents.assess` records one row **per attempt** —
a retry sends the rendering a second time — naming the model, the endpoint host,
the size of what left and a digest of it.

**The prompt is not copied into the record.** What it contains is the rendered
context — internal addresses, hostnames and retrieved external text — which the
request already carries under a recorded `rendering_version`; a second copy would
put it somewhere nothing else governs. The digest is over exactly the bytes that
left, so an audit can tie a disclosure to a rendering it can read without holding
two copies of either.

**Nothing governs the model channel per field**, and that is not an oversight: what
of a context reaches a prompt is the rendering's decision, recorded as
`rendering_version`, and a second field list here would be a second opinion about
it. What this adds for that channel is the record.

## 5. One ledger per run, and the caller owns it

`Disclosures` is built once per agent run from the request, exactly as
`helena.budgets.RunBudget` is, and both the tool dispatch and the model loop record
onto the same object. A second ledger in either place would be two copies of one
fact.

The module is `helena/disclosure.py` and not part of `helena/tools.py` for the
mechanical reason ADR-0026 gives for `helena/budgets.py`: `helena.agents` records a
disclosure too, and a ledger defined in `tools` would make the model client import
the provider tool layer to find it. `tests/test_package_layout.py` carries the
same note.

**The ledger is passed in and not built inside `helena.triage.run`, while the
budget ledger is built there** — an asymmetry that is the contract's rather than a
preference. What the budget ledger becomes leaves on the result: `AgentResult.cost`
is a contract field, so a ledger built inside still reaches whoever stores the
assessment. A disclosure row has **no contract field to leave on**, and adding one
is a change to the agent contract (`concept/instruction.md` §3) which `concept/07`
does not ask for — it puts the record on the *assessment*, not in the agent's
answer. So the ledger belongs to the code that will store it.

## 6. What is not decided here

- **Where a disclosure row is stored.** Nowhere yet. `concept/02` and `concept/07`
  put the record on the assessment and no assessment is stored (task 43), so the
  ledger is in-process and ephemeral — the standing `Cost` has, for the same reason
  and until the same increment. A table now would be a second home for a fact the
  assessment is going to carry.
- **Whether an indicator the model invented may be sent at all.** The policy
  governs *what kinds of thing* and *which fields*; it does not ask where the value
  came from, so a hallucinated indicator is disclosed as readily as an observed
  one. Closing that needs the context beside the tool, which is the analyst
  runner's shape rather than this layer's. It is the sharpest gap the tool layer
  still leaves and it is named in `helena.tools`' own docstring.
- **Whether an adapter honours `disclosed_to`.** The host is what the deployment
  approved and what the record names; `helena.tools` holds no URL at all (asserted
  off its own AST) so the layer could not check the request even in principle. The
  live adapter is where that becomes checkable, and it is task 38's.
- **Retention or minimization of what is disclosed.** `concept/07`'s redaction gate
  "has nothing to gate yet" and the only egress paths are these two; a consumer of
  the output topic that forwards it off-site inherits obligations this pipeline
  cannot enforce.
