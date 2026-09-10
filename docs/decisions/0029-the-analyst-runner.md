# 0029 — The analyst runner: two phases, one ledger, and a downgrade that is recorded

**Status:** accepted, 2026-09-10. Extends
[0017](0017-the-agent-contract.md) (the request/result pair),
[0020](0020-the-model-client.md) (the model path and the LangChain question),
[0021](0021-the-triage-runner.md) (the shape a runner has),
[0022](0022-the-composition-rule.md) (what the rule produces),
[0024](0024-provider-tools-and-the-mcp-boundary.md) through
[0028](0028-the-threatfox-hunting-api.md) (the tool layer it drives). Supersedes
nothing.

`concept/04-the-two-agents.md` gives the Analyst Agent a *"budgeted tool loop over
MCP provider tools"*, live retrieval, four roots *"with a classification path"*,
and one instruction about what it may be told: *"the analyst does not inherit the
triage rationale by default."* This is the decision record for the six choices
that made that runnable.

---

## 1. The retrieval phase and the answer phase are two calls, because they have to be

**Measured against the configured analyst endpoint, 2026-09-10.** One function
tool bound, one user turn saying *"the host contacted 45.192.105.203 on port 8000.
Look it up."*:

| Sent | `finish_reason` | What came back |
| --- | --- | --- |
| `tools` alone | `tool_calls` | one `tool_calls` entry, arguments chosen by the model |
| `tools` **and** `response_format` `json_schema` `strict: true` | `stop` | `{"classification":"malicious","confidence":100}` — **no tool call at all** |

The schema compiles to a grammar the model cannot leave, so binding both turns the
tool loop off silently. A loop written that way passes every test that does not
watch the wire: it "works", it never retrieves, and its verdicts look like
verdicts.

So `helena.agents.ModelClient.complete` takes **either** a schema or a tool list
and refuses both, and the analyst runs two phases: bounded turns with tools and no
schema, then one structured answer with the schema and no tools.

**What it costs, stated rather than hidden.** The loop cannot know a turn was the
last one until the model declines to call anything, so every run that binds tools
pays one model call to discover that, plus one more for the answer. A run that
retrieves *n* times is *n + 2* model calls.

Measured against the configured analyst endpoint on 2026-09-10, over a real
capture's real 4 964-character rendering, with `steps = 2` and `live_queries = 1`:

| Run | Tokens | Wall clock | Outcome |
| --- | --- | --- | --- |
| `tokens = 20 000` | 16 215 prompt, 7 946 completion | 70 s | **typed failure** — the last attempt came back with empty content |
| `tokens = 60 000` | 11 797 prompt, 10 734 completion | 109 s | an `AgentResult`, no retries |

The failure at 20 000 is the one worth carrying: `max_tokens` on each call is
what the ledger has **left**, and this model spends thousands of completion tokens
on reasoning before it writes a character of the answer — so a budget that looks
generous for one call is a truncated, empty completion by the third. It arrives as
`schema_invalid` with "the answer is not JSON", which is exactly what an empty
completion is. `config/policy.toml`'s `[budgets.analyst] tokens = 60000` was a
candidate written from a shape argument; this is the first measurement against it,
and it says the order of magnitude is right and 20 000 is not.

## 2. LangChain, reopened and refused again

`helena.agents` recorded that tool binding was *"the half of LangChain's
justification this module does not supply"* and that the increment which needed it
would have to answer the question again. It does, and the answer is unchanged for
the reason it was unchanged before: `langchain-openai` resolves 37 distributions
including `langsmith`, `concept/06` and `concept/07` both settle hosted tracing as
**rejected, not deferred**, and
`tests/test_dependency_boundary.py::test_no_hosted_tracing_sdk_is_even_importable_from_the_environment`
asserts the module does not resolve at all. Adopting it here would mean weakening
that test in the session that introduced the thing it guards against.

What tool binding actually amounted to: a `tools` key on the way out, a
`tool_calls` list on the way back, and a translation from the tool layer's
provider-agnostic `declaration()` into the OpenAI-compatible `{"type":
"function", ...}` shape. Sixty lines in `helena.agents`. The conflict between
`concept/06`'s technology table and `concept/07`'s tracing rule stands and is the
operator's to resolve; nothing here resolves it.

## 3. The transcript is rebuilt every turn, and there is no `assistant` turn on the wire

The conversation the model sees each turn is the frozen instructions, the
rendering, optionally the triage block, and **one line of JSON per retrieval so
far** — rebuilt from the prompt module every time rather than accumulated.

Three properties follow, and the first two are the ones that matter:

- **The repair call stays impossible.** `helena.agents._attempt_messages` refuses
  a repair by construction: no answer a model gave is ever an input to anything.
  Appending the model's `assistant` tool-call turns to a growing transcript would
  have put the model's own output back on the wire, which is the thing
  `tests/test_agents.py::test_no_repair_call_path_exists` asserts cannot happen.
- **Retrieved provider text is data, in a frame.** Each retrieval is one
  `json.dumps` line, so a newline in a provider's string is `\n` and no answer can
  start a line of its own or forge the `<<<END UNTRUSTED RETRIEVED DATA>>>` marker.
  It is the same mechanism `helena.rendering.v1.token` gives the rendering,
  obtained from the serializer rather than from a second escaper.
- It costs prompt tokens, which the budget charges. The measurement above is what
  that looks like.

The price is that the model does not see its own previous tool calls, only their
results — so a repetition is visible to it only because the line records what was
asked. A repeated call is a cache hit, costs a step and discloses nothing, and the
step budget bounds how many of them there can be.

## 4. The retrieval trace is written by code and is never offered to the model

`concept/07` makes the trace a record of *what the retrieval did* — cache hit or
live query, and the retrieval time of the underlying record. Every one of those is
measured by `helena.tools`, so it is the same kind of fact as the truncation gap:
something the code knows and the model cannot see.

It is not merely unnecessary to ask for it; asking would be unsafe.
`check_exchange` resolves an analyst's citations against *the rendering's evidence
ids or its own retrieval trace* — so a model that could write the trace could
authorise its own citations. `helena.analyst.TRACE_FIELD` is excluded from the
prompt's field set and `run` refuses a prompt version that offers it.

## 5. An indicator the context never observed is never sent

`helena.tools` named this as the sharpest gap it could not close: *"the send
policy governs what KINDS of thing and WHICH FIELDS may be sent and never asks
where the value came from ... closing it needs the host context beside the tool,
which is the analyst runner's shape rather than this layer's."*

`run` takes the `ContextProjection` the request was rendered from, and a tool call
whose indicator does not appear in it is refused with `indicator_not_observed`
before the send policy, the cache or the adapter is reached. The comparison is on
`helena.tools.normalize_indicator`'s fold, so a name retyped in another case is
the same question.

**This makes the analyst unable to pivot**, and that is a decision rather than an
oversight. An indicator learned from a provider's answer — a second address for
the same malware family — cannot be looked up, because the monitored network never
observed it. `concept/` does not say whether such a pivot is permitted; the
conservative direction is the one where a made-up indicator cannot be disclosed to
a third party, and reversing it is a decision, not a bug fix.

It also makes the composition rule **total**: every analyst-tier claim is about an
entity the context holds, so every claim has traffic beside it and
`helena.policy.supports_for` can always build the input the rule needs. Without
this rule there would be a class of citation the rule could not weigh at all, and
the only honest thing to do with one is refuse the run.

## 6. The composition rule is applied and the verdict is not rewritten

`prds/prd.json` task 39 step 6 asks the runner to *"apply the composition rule
policy to the returned verdict and **downgrade** with a recorded reason when the
evidence does not support it."* The rule is applied. The verdict is not
overwritten, and the difference is [0022](0022-the-composition-rule.md)'s and
`concept/07`'s:

> inference is appended, never overwriting a fact

and, operationally, an evaluation that could not tell a model's answer from a
policy's correction of it would be scoring the policy while reporting on the
model. So `Analysis` carries two records: `outcome` is what the model said, and
`decision` is what the cited evidence permits — `decision.proposed`,
`decision.permits`, and `decision.findings`, which names the rule that cut it down
and the evidence ids it read. That **is** the downgrade and the recorded reason;
it is a row beside the verdict rather than an edit of it.

**One rewrite does happen and it is not this one.** `helena.budgets.degraded` is
`concept/07`'s own: a run that exhausted a budget may not return `normal` — *"it
established the absence of nothing"* — so it degrades to `unknown` with the
exhaustion explicit. That is a rule about what a truncated run may *claim*, not
about what its evidence supports, and the concept states it as a rewrite.

## 7. Two rules the contract cannot state, enforced by the runner

Both are `concept/`'s and neither is expressible on `AgentResult` alone, because
both are about a distinction the contract permits on either side:

| Rule | Why the contract cannot hold it |
| --- | --- |
| an `unknown` verdict's gaps must include something the run could not **see** — `missing`, `in_flight`, `failed`, `truncated` or `budget_exhausted` — and not only `no_match` or `stale` | `no_match` and `stale` are perfectly good gaps on a verdict that *was* settled. `concept/02` makes `unknown` "unassessable" and "deliberately distinct from `suspicious`, which means analysis ran and could not settle it" |
| a non-`normal` verdict's evidence package must name a pattern or carry a narrative | the contract permits an empty package because `helena.budgets.degraded` attaches one to a verdict the **code** rewrote. One the *model* returned empty is the verdict without the assembly `concept/02` calls an evidence package |

A verdict that fails either is a typed failure with `schema_invalid`, the same
treatment [0021](0021-the-triage-runner.md) §5 gives a citation that does not
resolve, and with the same recorded cost: it is **not** retried, because the retry
loop feeds back what *validation* said and this is a rule about the run. What
would settle whether that is worth changing is a measured rate, which needs
assessments to be stored.

## 8. The inheritance switch is configuration and not a contract field

`concept/04` asks for *"a configuration switch rather than a contract change"* in
so many words. `config/agents.toml`'s `[analyst] inherit_triage_rationale` is that
switch, `false` is `concept/04`'s own default, and there is no default in the
code: `helena.analyst.inheritance()` fails at startup naming the file, because an
arm that was assumed is a measurement reported as something it is not.

The triage outcome reaches `run` as an argument. Putting it on `AgentRequest`
would have made every request carry the other stage's answer — a change to the
agent contract (`concept/instruction.md` §3), and one that would put the thing
being measured inside the thing measuring it.

What is shown, when it is on, is the typed fields and nothing else — the verdict,
the confidence, the citations and the gaps, or a typed failure's reason and detail
— as one line of JSON in a frame of its own. The field list is in the **frozen**
prompt module, because what the model was shown is part of the question a recorded
`prompt_version` pins.

## 9. What is not decided here

- **Whether a pivot should be permitted.** §5 takes the conservative direction and
  says so. What would settle it is a case where an analyst demonstrably needed to
  follow an indicator out of the context, which needs the pipeline to have run.
- **Whether the extra retrieval turn is worth removing.** §1 measures it at one
  model call per run. A cheaper shape would need the endpoint to accept a schema
  and tools together, which it does not.
- **Whether the `unknown` gap rule catches the right thing.** Measured twice, on a
  deliberately tight budget. Before the prompt named the gap kinds, the configured
  model answered `unknown` with *no* gaps at all, twice running, and the
  **contract** refused it before this rule was reached. After, the same run
  produced a validating `unknown` that this rule admitted — so the model named
  something it could not see. That is one measurement each way and not a rate;
  what it does establish is that the rule is reachable and that the wording moves
  the outcome.
- **Storing any of it.** No assessment row, no `Decision` row, no disclosure row
  and no `Cost` row exists. `Analysis` is the shape a later increment stores, and
  every claim about replay in this file is a claim about shapes being ready.
