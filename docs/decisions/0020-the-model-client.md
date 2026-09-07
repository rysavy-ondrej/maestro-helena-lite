# 0020 — The model client, structured output, and the bounded schema retry

**Status: accepted, with one escalation open.** Task 30 (D4 Agents).
**Authority:** `concept/04-the-two-agents.md`, `concept/06-technology.md`,
`concept/07-principles.md`, `concept/instruction.md` §2–§3.

This is the increment that first *calls* a model. It adds
`helena.agents.ModelClient` and `helena.agents.assess`, `config/agents.toml`, and
no runtime dependency.

---

## 1. LangChain is not here, and that is a conflict rather than a preference

`concept/06-technology.md`'s technology table names **LangChain** for "model
client, tool binding, structured output", with the justification *"earns its
place: tool binding and structured-output validation are needed on day one"*. The
same file, three rows down, settles tracing as **local structured logs only**,
because *"a hosted tracer is a second egress channel for prompts and retrieved
text"*, and `concept/07-principles.md` says the same. `concept/instruction.md` §3
makes a second egress channel — hosted tracing named explicitly — an escalation.

Those two rows cannot both be satisfied here. Measured on 2026-09-07 with
`uv pip compile`, not read off a page:

| Fact | Value |
| --- | --- |
| Distributions `langchain-openai` resolves to | **37** |
| Among them | `langsmith`, `openai`, `httpx`, `requests`, `tiktoken` |
| Why `langsmith` | a **hard** dependency of `langchain-core`, not an extra |

`tests/test_dependency_boundary.py::test_no_hosted_tracing_sdk_is_even_importable_from_the_environment`
asserts that `import langsmith` does not resolve *anywhere in the environment*,
and its failure message says what to do about a transitive arrival: *"find which,
and record the decision before leaving it there."* Adopting LangChain in this
increment would have meant weakening that test in the same session that
introduced the thing it guards against, on a session's own authority.

**So the conflict is recorded and not resolved.** What this increment does
instead is what the project already does for the feed loaders:
`docs/decisions/0002-dependency-set.md` keeps `requests` and `httpx` absent, and
`helena.enrichment.fetch_public_suffix_list` says in as many words that *"one GET
does not earn a dependency."* The endpoint is an ordinary OpenAI-compatible HTTP
API; `urllib` speaks it; Pydantic — approved, and the contract's own validator —
validates the structured output.

**The half of LangChain's justification that this increment does not supply is
tool binding, and it has no caller.** Triage binds no tools at all
(`concept/04`), and the analyst's tool loop is a later increment. That increment
is where the question actually has to be answered, and it is the operator's:
either langsmith's presence in the environment is acceptable and the boundary
test is narrowed with a recorded decision, or the tool loop is written against
the same `urllib` client. Nothing in this increment forecloses either —
`concept/06` itself says *"because the contract is the architectural commitment
and the library is a technology-table entry"*.

## 2. What the model is asked for, and what it is never asked for

`AgentResult` has ten fields. Three of them — `emitter`, `cost` and `versions` —
are `helena.agents.CODE_OWNED_FIELDS`: what the run *spent* and what *produced*
it, measured by the code that ran the assessment. `Cost`'s own docstring already
says "measured by orchestration, never by the model", and a model reporting its
own schema version would be recording a version that was assumed.

The remaining seven are what a model may propose. There is **no second schema**:

- the JSON schema sent to the endpoint is `AgentResult.model_json_schema()` with
  the three owned fields removed (`proposal_schema`);
- what comes back is validated by constructing that same frozen class.

A `v2` contract moves both at once, and
`test_the_proposable_and_code_owned_fields_partition_the_result` fails if a field
is ever in neither set.

An answer that *sets* one of the owned fields is refused by name and fed back,
rather than dropped: a model that reported its own cost has been asked the wrong
question, and dropping the field would hide that.

## 3. Two things measured against the configured endpoint

Both on 2026-09-07, against the endpoint in `.env`. Neither was predictable from
a documentation page.

**The schema belongs in `response_format`, not in the prompt.** The same triage
question cost **122 prompt tokens** with the schema in
`response_format: {"type": "json_schema", "strict": true}` and **694** with the
schema written into a system message — the server compiles it to a grammar rather
than reading it as text. Triage is the high-volume path where cost per call
dominates, and it pays that difference on every context.

**The contract's closed vocabularies are invisible to `model_json_schema()`, and
the model invents values for them.** `Citation.stance` is one of exactly two
words, checked in `model_post_init` — which is *code*, so the generated schema
says `{"type": "string"}`. Against the live endpoint the model filled `stance`
with the host's rendered line, three attempts running, and the assessment became
a typed failure for a vocabulary nobody had shown it.

So `helena.agents.CLOSED_VOCABULARIES` injects each one as a JSON Schema `enum`,
read from **the contract's own constant** — `STANCES`, `GAP_KINDS`,
`RETRIEVAL_OUTCOMES`, `ENTITY_TYPES`, `QUERY_FAILURE_REASONS`. That is one copy
and not two, and a rename in a future contract raises rather than silently
leaving a field open. With the enums in place the same live call validated on the
**first** attempt.

`$defs` are pruned to what the selected fields reference, because the schema is
sent on every call: the triage subset is **2 195 bytes** against **13 309** for
the full proposable set.

## 4. Validated in JSON mode, which is the mode the answer arrived in

The contract is `strict=True`. In Pydantic's *python* validation mode that
refuses a `list` where a `tuple[...]` is declared and an `int` where a `float`
is — so `{"citations": [...]}` and `{"confidence": 1}` would be **permanent**
schema violations no model could ever get past, and the bounded retry would spend
three attempts on a difference between JSON and Python rather than on anything
the model did.

`AgentResult.model_validate_json` keeps every strictness that is about the data —
a string where a number is declared is still refused — and drops the one that is
about the host language's type vocabulary. This was found by running it, not by
reading about it.

## 5. The bounded retry, and the repair call

`concept/07`: *schema-invalid model output is retried with the validation error
fed back, a small bounded number of times, and then becomes a typed failure.
Retries count against the budget, and the retry count per model is itself a
quality metric. **A second-pass "repair" call is rejected.***

The difference between the two is **what is sent back**:

| | Retry (implemented) | Repair (rejected) |
| --- | --- | --- |
| What the model is sent | the original question, plus what was wrong | its own invalid answer, to fix |
| What comes back | a fresh answer to the original question | an edit of the previous one |

`_attempt_messages` rebuilds the list from the *original* messages plus one
feedback message each attempt, so the invalid answer is discarded and is never an
input to anything, and the prompt does not grow with the retries.
`test_no_repair_call_path_exists` asserts that over the bytes the endpoint
received: the discarded answer never appears in a later request, no attempt
carries an `assistant` turn, and every attempt asks the same question. **A repair
path cannot pass it — it has nothing to repair without sending the answer back.**

The bound is `config/agents.toml`, not a constant: `concept/07` makes budget
values "policy, not constants in a branch". `attempts = 3` is a candidate and not
a decision — the schema-violation rate per model is what would settle it, and no
evaluation corpus exists. The file says so.

## 6. The exits, and why none of them is collapsed

`assess` returns an `AgentResult` **or** an `AgentFailure` and never raises for
anything the model or the endpoint did.

| What happened | Reason | Reported model version | Gap |
| --- | --- | --- | --- |
| An answer validated | — (an `AgentResult`) | the response's | — |
| Every attempt failed validation | `schema_invalid` | the response's | — |
| The token budget ran out mid-retry | `schema_invalid` | the response's | `budget_exhausted` |
| Nothing ever answered | `model_unavailable` | **none** — nothing answered | — |
| The endpoint stopped answering *after* one answer | `schema_invalid` | the response's | `failed` |
| The wall clock ran out | `timed_out` | the response's, if any | — |
| The response is not a chat completion, or carries no `usage` | `model_unavailable` | none | — |

Three of those rows are distinctions the contract would otherwise let a caller
collapse:

- **A budget exhaustion is not a failure reason.** `AgentFailure` has three
  reasons and `budget_exhausted` is deliberately not among them — the contract's
  own comment says why. It is a gap beside the reason, so "no answer validated"
  and "there was no budget left to ask again" stay two facts.
- **`model_unavailable` means nothing answered**, which is why the contract
  refuses a reported model version there. When something *did* answer and the
  endpoint then went away, saying `model_unavailable` would be false; the run
  produced no verdict because no answer validated, and the transport failure is a
  `failed` gap explaining why there were no more attempts.
- **An unreadable response is the endpoint, not the model.** A deployment pointed
  at the wrong service is not a model that needs retrying, and retrying it three
  times would spend a budget to learn nothing.

`usage` is **required** rather than defaulted to zero. A token budget silently
unenforced is invisible in exactly the deployment where the budget mattered.

## 7. What is recorded about what produced a result

`concept/07`: *what is recorded on an assessment is the **endpoint host** and the
**model identity and version** — enough to know what produced a result, with
nothing that authenticates as anyone. Because endpoints are configurable per
agent, cross-wiring is possible, and recording endpoint and model per assessment
is what makes it detectable.*

- **Model identity** is on the contract already: `versions.model_requested` is
  what was asked for, `VersionSet.model_version` is what the response said
  answered, and `RequestVersions.completed_by` is given the *reported* value and
  never the configured one.
- **The endpoint host** has no field on the frozen contract, and adding one is an
  escalation, not an increment. It is `ModelClient.endpoint_host` — host and
  port, with userinfo, path and query **dropped rather than masked**, because the
  rule is about what is kept. The code that stores an assessment has it without
  the contract growing a field.

Every call also logs `agents.model.call` and `agents.model.answered` through
`helena.observability`, carrying the endpoint host, both model identities, the
attempt number and the token counts. **No message content is ever logged**: the
rendering is attacker-influenced text and a prompt is not a diagnostic.

**Open, and owed by D5:** an `endpoint_host` column on the assessment row. Until
that table exists the structured log is the only record, which is a weaker claim
than `concept/07` makes and is recorded here rather than smoothed over.

## 8. Model selection is configuration, and the module cannot name an agent

`ModelClient.for_agent(settings, agent)` is `getattr(settings, agent)` after
checking the name against `helena.config.AGENTS` — a lookup, not a branch.
`test_the_module_never_names_an_agent` parses `src/helena/agents.py` and asserts
that neither `"triage"` nor `"analyst"` appears as a string constant outside a
docstring, so "model choice stays a configuration value, never a code path"
(`concept/04`) is a property of the source rather than of a review.

`helena.config.AGENTS` and `helena.taxonomy.EMITTERS` are two copies of one closed
set, and `for_agent` is the first code that crosses from an emitter to a
configuration section. They are now asserted equal by
`test_the_configured_agents_and_the_taxonomy_emitters_are_one_vocabulary`.

## 9. What this increment deliberately does not do

- **It does not call `contract.check_exchange`.** That is where the rule *a
  rendering that truncated requires a `truncated` gap* lives, and the gap is a
  fact **code** knows rather than one the model reported. The runner emits it and
  then checks the exchange; doing it here would mean this module writing a gap
  into a verdict it did not produce. Task 31 owns it, and
  `tests/test_rendering.py::test_the_truncation_reaches_the_request_and_forces_a_gap`
  is the worked example.
- **It does not choose a prompt.** `assess` takes the messages. The versioned
  prompt file, the triage root-set constraint and the "rendering framed as data"
  framing are task 31's.
- **It does not narrow the root set.** A classification outside the emitter's
  roots is already a schema violation — `AgentResult` raises `TaxonomyError` and
  the loop retries it — but the *schema* does not yet enumerate the permitted
  paths, so the model is not shown them. Given §3's measurement, showing them is
  likely to matter; it is task 31's step and belongs with the triage prompt.
- **It does not aggregate the retry count per model.** `Cost.retries` is on every
  outcome and the log carries it per call, but "the retry count per model is
  itself a quality metric" is a query over stored assessments, and no assessment
  table exists. D5's.
- **It does not count tokens itself.** The endpoint's `usage` is what is spent
  against the budget. A tokenizer per model is a dependency for a number that
  would be wrong for the next model, for the same reason
  `docs/decisions/0019-the-rendering-size-budget.md` bounds characters.
