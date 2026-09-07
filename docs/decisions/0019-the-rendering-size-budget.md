# 0019 — The rendering size budget, and what a truncated section says

**Status: accepted.** Task 29 (D4 Rendering).
**Authority:** `concept/04-the-two-agents.md` (the rendering "is bounded, and
truncation that is invisible is a correctness bug, not a formatting choice"; the
request carries "the rendering with explicit truncation"; deterministic
escalation is independent of triage), `concept/07-principles.md` ("rendering too
large → truncated **visibly**"; "budget values are **policy**, not constants in a
branch"), `concept/08-open-questions.md` (the numeric budget values are open, and
"the list of contributing events is unbounded and nothing truncates it"),
`concept/instruction.md` §2 (truncation is visible or it is a bug; the five
statuses stay distinct including in whatever is rendered to an agent) and
`docs/decisions/0017-the-agent-contract.md` (`Truncation`, and `check_exchange`'s
rule that a truncated rendering forces a `truncated` gap).

Supersedes the last bullet of `0018-the-triage-rendering.md` §9, which recorded
the budget as deferred.

---

## 1. What was measured, because it was not known

Task 29's own words: *"how many entity rows a busy host produces is unmeasured —
the fixture is one host for two minutes."* So it was measured first, and
`scripts/measure_rendering.py` (`make rendering-size`) is the instrument. It puts
a capture through the real normalizer into a throwaway schema on the configured
engine, shifts every timestamp forward by a whole number of context windows so
the retention boundary shows the result, and reports entity rows and characters
per section. Shifting by a **multiple of the window** rather than into one window
is deliberate: the flow sample crosses a boundary and produces two contexts, and
collapsing them would measure a host that does not exist.

`data/ingest/flow-sample.jsonl` — 62 real flow records, one managed Windows 10
endpoint, 130.8 seconds, no feed loaded:

| Window | Entity rows | domain | address | fingerprint | url | TLS tuples | Characters |
| --- | --- | --- | --- | --- | --- | --- | --- |
| first | **122** | 55 | 31 | 4 | 32 | 3 | **12 115** |
| second | 10 | 6 | 2 | 2 | 0 | 1 | 1 770 |

Three things worth keeping:

- **122 entity rows for two minutes of one quiet endpoint.** ADR-0018 measured
  the ten-record layer-coverage capture at 4 964 characters and that turned out
  to be the small case: the whole sample is 2.4× it, from the same host.
- **32 of the 122 are `url` entities and `v1` renders none of them** (ADR-0018
  §9). The rendering is smaller than the context, before any budget applies.
- **Every lookup here is `missing`** because no feed was loaded, so these are a
  lower bound. ADR-0018 measured a ThreatFox load adding 922 characters to the
  layer-coverage rendering — about 19 % — of which the single hit is 190 and the
  rest is the `classification=no_match` token that then appears on every record.

## 2. Characters, not tokens

A token count is what a model service charges for, and counting tokens means a
tokenizer per model. The OpenAI-compatible endpoint this project uses does not
publish its vocabulary, and adding a tokenizer is a runtime dependency
(`concept/instruction.md` §3) for a number that would still be wrong for the next
model. Characters need nothing, are identical on every machine, and bound the
token count from above for every tokenizer that exists.

What they are **not** is proportional to it. This rendering is unusually
token-hostile text — 64-character hex digests, domain labels, long `key=value`
runs — so a ratio converting this budget to tokens would be a guess, and it is
deliberately not written down anywhere. If a token budget is ever wanted, it is a
measurement against the endpoint, not an arithmetic on this number.

## 3. Where 25 000 came from, and what it is not

`config/rendering.toml` holds it, `helena.rendering.budget()` reads it, and there
is **no default in the code**: `concept/07` makes budget values policy rather
than constants in a branch, and a module-level number a caller may leave alone is
exactly such a constant. `render` takes the budget as a required argument and
refuses anything that is not a `RenderingBudget`.

The criterion is one sentence: **a real quiet host's window renders whole, with
headroom.** 25 000 is over twice the 12 115 measured above, so the project's own
fixture never truncates and truncation stays the busy-host case. A budget that
truncated the fixture would make the truncation record the thing nobody reads.

It is a **candidate, not a decision**, in the same sense
`sql/migrations/0009_retention_boundary.sql` means it of the 24-hour retention
horizon. `concept/08` lists the numeric budget values as open; what settles this
one is a busy host observed through its truncation records, not an argument. And
one thing is entirely unmeasured: **no model has read one of these renderings**,
so whether 25 000 characters is a comfortable input for a small fast model on the
high-volume path is not known.

## 4. The four rules the selection follows

`helena.rendering.v1` turns the number into a decision about lines. A record is
one line (ADR-0018 §4), so the whole selection is over lines.

**Rule 1 — two sections and two kinds of line are never dropped.** The host
section and the connection statistics are closed field sets whose size does not
depend on what the host did. The source header lines are not records either: they
carry `status=` and the snapshot digest, and a budget that dropped a header would
hide a `missing` or a `failed` lookup — the exact collapse `concept/instruction.md`
§2 forbids "including in whatever is rendered to an agent". A budget too small
for these is a `RenderingError` and **not** a smaller rendering.

**Rule 2 — what is kept is a prefix of the section's own order.** That order is
the projection's neutral `(entity_type, entity_value)`, chosen in ADR-0018 §9
precisely so that a later truncation would not be selective. Hits-first was
rejected: an enriched context is mostly negative space, and a rendering selected
for its claims hands triage a store that looks like nothing but threats, which is
the same misreading as one that looks clean.

The obvious objection is that a neutral prefix can drop a malicious hit because
its name starts with `z`. It can — and **that is not a lost alert**, because
`concept/04`'s second escalation input is deterministic and independent: *"the
enrichment evidence escalates on its own — a Tier A, or a high-confidence Tier B,
malicious classification whose traffic characteristics support it — regardless of
the triage verdict."* That path reads the store, not the rendering. The rendering
is what a model reasons over; it is not the alerting path, and a selection rule
that tried to make it one would be prejudging the composition rule (task 32)
inside a formatter.

**Rule 3 — the budget is shared max-min fair between the three record-carrying
sections.** Every section that wants no more than an equal share gets all of it,
and the remainder is shared again among those that want more. The alternative —
"in section order, take what you need" — starves the last section, so a host that
contacted six hundred domains would render no TLS parameters at all. A remainder
that will not divide goes to the earliest section in the contract's own order, so
the split is a function of the inputs and not of dictionary order.

**Rule 4 — a truncated section says so twice.** Structurally, in the
`helena.contracts.v1.Truncation` the section carries, which is what code, the
request and (when D5 builds it) the stored assessment read. And in text, as the
section's **first** line:

```
truncated kept=10 total=55 dropped=45
```

Both because they are read by different readers. `Truncation` is refused if it
dropped nothing, so the structured record cannot be a no-op; the line is first
because a reader has to know a list is partial *before* reading it. `truncated`
is not a record kind and not `source`, and a record line's first token is its
entity type from a closed vocabulary, so no value a host can influence can forge
one.

## 5. The two things the budget must not get wrong, and what stops it

**A section that shrinks without saying so.** One function builds every section
from its draft, and it derives the body, the `Truncation` and the `evidence_ids`
from the same kept count — there is no path that drops a line without producing
the record. `tests/test_rendering.py` sweeps a real context from a budget that
fits everything down to the smallest that renders at all and asserts, at every
step, that each section's record-line count equals its `total` or its
`Truncation.kept`.

**A citation for a claim that was dropped.** The evidence identifiers travel on
the `_Line` that carries them, so a dropped record takes its citations with it
and `RenderedSection.evidence_ids` lists only what was rendered. This one matters
because `check_exchange` resolves a result's citations against that list: a
section that advertised an identifier it dropped would let a model cite evidence
it was never shown, and the contract would accept it.

## 6. What is not done here

- **Nothing stores a truncation.** There is no assessment table yet (deferred to
  D5 by task 26), so a `Truncation` reaches an `AgentRequest` in memory and no
  further. The contract rule that a truncated rendering forces a `truncated` gap
  on the outcome is already enforced by `check_exchange` and is exercised here;
  what is missing is a row it lands on, and a count of truncations per section
  that would make a wrong budget observable the way
  `helena_signal_retention_rejections` makes a wrong horizon observable.
- **The budget is one number.** Not a per-section cap, not a record cap, not a
  per-source paragraph allowance. A second knob is warranted when something
  measured says the single one is wrong; `SourceDescriptor.caveat` (ADR-0018 §9)
  is the first candidate, and it stays deferred.
- **A `v2`.** `v1` was extended rather than superseded, because nothing has
  recorded `rendering_version = "v1"` — there is no store for an assessment yet,
  so no reader is pinned to the unbounded shape. The moment D5 writes one, this
  file is frozen and boundedness changes are a `v2`.
