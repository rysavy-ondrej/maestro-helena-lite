# 0030 — Untrusted-text isolation: one wrapper, one escaper, and a pin on the frozen prompts

**Status:** accepted, 2026-09-10. Extends
[0008](0008-version-registry.md) (what "frozen" means and what it costs here),
[0018](0018-the-triage-rendering.md) (the line grammar the escaper protects),
[0021](0021-the-triage-runner.md) and
[0029](0029-the-analyst-runner.md) (the two runners whose prompts this reaches),
[0024](0024-provider-tools-and-the-mcp-boundary.md) (what a tool may show a
model). Supersedes nothing.

`concept/07-principles.md`, *Untrusted input*:

> **External text and model-visible fields are data, never instructions**, and
> **isolation is implemented and tested, not asserted.** The concrete surfaces:
> advisory and report text, provider descriptions, engine names, category labels,
> feed tags and comment fields, and **registration records, which in a malicious
> case are written by the adversary**.

Before this decision the isolation existed and was **duplicated**: two prompt
versions each held their own copy of the marker lines and their own forged-line
check, the rendering held its own escaper, and three call sites held their own
`json.dumps` spelling of "one line". Each copy was correct. What was missing was
any reason they would stay correct together, and any way to tell whether a
*fourth* surface had been added without one.

---

## 1. What the wrapper is, and why it is four functions and not one

`helena.untrusted` holds every mechanism that makes external text data:

| Function | What it does | The forgery it stops |
| --- | --- | --- |
| `token` | percent-encodes everything outside printable non-space ASCII | a rendered value starting a line of its own |
| `line` | one line of JSON, sorted keys, no spaces | a provider or model string starting a line of its own |
| `vocabulary` | joins a closed vocabulary after checking each member is one bare token | whitespace reaching the **instruction** turn, which has no frame |
| `block` | wraps a body between a `Frame`'s two whole lines | a body closing its own frame and continuing outside it |

The task that produced this asked for *"a single wrapping function"*. `block` is
that function and it is the only thing that builds a delimited untrusted block.
The other three are there because `block` is a **checker, not an escaper**: by the
time a body reaches it every value in that body has been through one of the three,
so a marker line in a body is an escaper that stopped escaping rather than an
input that needs rejecting. Collapsing them into one function would mean `block`
guessing which of three escapes a caller wanted, which is the config key with one
value `concept/instruction.md` §1 refuses, one level up.

**`block` checks against every frame in the project, not against its own.**
Triage shows one frame and the analyst shows three over the same rendering, so a
per-prompt check would let a rendering carry the analyst's retrieved marker
through triage — which checks fewer — and arrive as a line nobody looked at.

## 2. The frame is a pair of whole lines, and that is the whole property

A delimiter inside a line would need every value checked for that delimiter. A
delimiter that **is** a line needs one property: no value can contain a line
break. `token` gives it (a newline is outside the safe set), `line` gives it
(`json.dumps` renders a newline as `\n` and escapes every non-ASCII character),
and `vocabulary` gives it by refusing rather than escaping.

So the isolation does not rest on the model reading the frame and believing it.
The prompt says the text is data because saying so is worth something, but a
model can be talked out of an instruction and nothing here depends on it not
being.

## 3. The four surfaces, and what each one's isolation actually is

| Surface (`concept/07`'s words) | Where it is in this tree | The mechanism |
| --- | --- | --- |
| feed tags and comment fields | ThreatFox `tags`, `malware`, `reporter`, `reference` → `ProviderClaim.native_evidence` → the retrieved block | typed field, `line`, `block` |
| advisory text, category labels, engine names | domain names, SNI, cipher names → the rendering | `token`, then `block` |
| provider descriptions | `ProviderTool.declaration()` | derived entirely from a validated registration record; no provider string reaches it |
| registration records | `helena.enrichment.SourceDescriptor` | `SOURCE_ID` — one bare token, checked where it is registered |

Two of them are worth stating as decisions rather than as table rows.

**A provider description is not escaped, because no provider writes one.** The
declaration a model is offered is built from the source id, the offered entity
types, the declared emit subset, the taxonomy versions and the tier — every one
of them a validated vocabulary. The isolation is that the provider has no route
into it at all, which is stronger than escaping and is asserted as such.

**`SourceDescriptor.source_id` is now `^[a-z0-9][a-z0-9_-]*$`.** It reaches
`ProviderTool.name` — the identifier a model addresses a tool by — and the
description it is shown, and it was previously checked only for surrounding
whitespace. `caveat` is the one genuinely free-text field a registration record
has, and it is deliberately **not** in the declaration; the test asserts the
absence so a later version cannot add the route quietly.

## 4. What routing the frozen prompts through a shared module costs

`helena.triage.v1` and `helena.analyst.v1` are frozen the moment an assessment
records their version ([0008](0008-version-registry.md)). They now import
`helena.untrusted`, so an edit there can reach a frozen file — which is exactly
the hazard `tests/test_package_layout.py` names when it refuses a shared helper
*inside* a versioned package. Moving the helper to the top level does not remove
the hazard; it only moves the file.

**What pays for it is a pin, and before this decision there was none.** The
freeze was a comment in a docstring. Now
`tests/test_untrusted.py::test_the_frozen_prompt_bytes_are_what_they_were` holds
the exact bytes each frozen prompt builds for a fixed request, so a change in the
shared module that would change what `v1` asks is a failing test.

**The refactor changed nothing.** The two fixtures were generated by the same
builder against the tree at `3d28be4` — before `helena.untrusted` existed — and
against the tree after: byte for byte identical.

| Prompt | sha256 |
| --- | --- |
| `tests/fixtures/prompts/triage-v1.json` | `db70e04728e2ccf1400ac1291d54d194260b4909285a0f2510d42c64022574bb` |
| `tests/fixtures/prompts/analyst-v1.json` | `a6c37b917d750bc97ff6db5cf9f36e3e248c6e8805e9f40c87bc40b2df826c33` |

The alternative — leave the two frozen files holding their own copies of the
markers and the check — was rejected because it makes "no externally sourced
field reaches a prompt outside the wrapper" unenforceable: the boundary test
would have to trust each version to have remembered, which is the thing
`concept/07` says is not enough.

## 5. One thing changed on the wire, and it is not a frozen prompt

`helena.agents._attempt_messages` builds the retry feedback turn, and it
interpolated the validation error into a sentence. A Pydantic error quotes the
`input_value` that failed; the value that failed is what a **model** wrote; and
what a model wrote can be a verbatim copy of a domain name or a provider string it
was shown. That is a route from attacker-influenced text back into a prompt with
no frame around it, and `concept/07` puts model-visible fields under the same rule
as retrieved text.

So the error now crosses as `untrusted.line(...)` inside a new
`DISCARDED_ANSWER` frame, and the sentence around it is a module constant.
`helena.agents` is not a versioned module and no assessment records its wording,
so this is an edit rather than a `v2` — but it **is** a change to what a model is
sent on a retry, and it is recorded here rather than left to be discovered.

## 6. The boundary test, which is the part no behavioural test can do

`tests/test_untrusted.py::test_no_prompt_interpolates_anything_outside_the_wrapper`
reads the package's own AST. Every `helena.agents.Message` any module builds must
carry one of three things as its `content`: a literal, a frozen instruction
constant filled entirely from code-owned values, or a call into
`helena.untrusted`. An f-string is refused outright — it is how all of these
started, and it is one edit away from carrying a rendered value into the
instruction position.

Two smaller lints go with it: the marker lines exist as string literals in exactly
one module, and neither prompt version serializes model-visible text itself.

And the set of modules that build a prompt is **asserted**, not discovered: a new
prompt surface arrives as a failing test rather than as a file the lint happened
not to read.

## 7. What the corpus demonstrates, and what it does not

Twelve adversarial strings — override text, a forged system turn, a forged line
for each of the four frames, a forged section heading, a forged `evidence=`
citation, a JSON escape, a forged tool call, a bidi override and control
characters — are placed in feed tags and comment fields, in a rendered domain
name, and in registration fields, and driven through the real triage and analyst
runners against a scripted endpoint.

For each, the injected run and a benign control are compared: same verdict, same
citations, same tool call with the same arguments, same tool declarations, and —
line for line — identical text outside the frames. Each case also asserts the
payload *did* reach the model, so a run that dropped it would fail rather than
pass.

**What is not demonstrated is that a model resists an injection.** There is no
labelled corpus ([`concept/08-open-questions.md`](../../concept/08-open-questions.md))
and nothing here measures model behaviour. The claim is the structural one:
attacker-chosen text cannot reach the instruction turn, cannot forge a frame,
cannot forge a section heading, cannot forge a citation, cannot add a tool and
cannot change which tools were called. What bounds the damage if a model *is*
persuaded is the code's own guards, which predate this decision and are tested
where they live: a citation the rendering never showed is a typed failure, a
lookup about an indicator the context never observed never leaves, and a verdict
outside the taxonomy is refused.

Maturity: **experimental**. The mechanisms are exercised; the resistance is
unmeasured and stays unmeasured until there is a corpus.
