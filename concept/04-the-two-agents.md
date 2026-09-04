# 04 — The two agents

There are two agents in the automatic pipeline — **Triage** and **Analyst** — and
a third, the cloud **Investigation Agent**, that is deferred. The two that exist
are deliberately asymmetric, and the asymmetry is the design, not an accident of
sizing.

## Asymmetric access, on purpose

| | Triage Agent | Analyst Agent |
| --- | --- | --- |
| Question it answers | *Is this worth analysing?* | *What is it?* |
| Input | A bounded rendering, **and nothing else** | The rendering, plus (when built) bounded cited case memory and infrastructure knowledge |
| Tools | **None at all** | Budgeted tool loop over MCP provider tools |
| Retrieval | None — no lookups, no waiting | Live, on demand, case-driven |
| Host knowledge | A closed, versioned field set from **fixed configuration only** | The full description |
| Verdicts | `normal` or `suspicious` | `normal`, `suspicious`, `unknown` or `malicious`, with a classification path |
| Writes | Nothing | Nothing — it proposes |
| Evidence tier visible | `enrichment` only | `enrichment` and `analyst` |
| Model | Small, fast — the high-volume path, where latency and cost per call dominate | Larger, tool-calling, structured output with citations |

**The separation is not "the analyst gets more time".** The two stages differ in
**where their information comes from**, and that is what makes basic enrichment
affordable at stream rates: the expensive, selective and narrative sources are
consulted only for the small fraction of contexts that reach analysis.

**Agents differ by model, not by framework.** Both run the same contract against
the same OpenAI-compatible endpoint; which model each uses is a configuration
value, never a code path.

## What the Triage Agent sees

A bounded, versioned projection of the enriched host context, in five parts:

1. **The host** — address and device type, from a closed versioned attribute set
   sourced from fixed configuration only. When unknown it is rendered as unknown —
   never omitted, never guessed.
2. **Domains contacted** — one record per domain, with the layers that observed it,
   security enrichment, and type or class.
3. **Addresses contacted** — one record per destination address, with security
   information, classification and service identification.
4. **Selected TLS parameters** — a subset, not everything the record carries.
5. **Connection statistics** — duration, packets and octets, kept **bidirectional**,
   because direction is signal.

Four properties the rendering must have:

- **Every enriched value is citable**, carrying a stable evidence identifier, or
  triage cannot cite its reasoning and the finding cannot be replayed.
- **Missing, stale, in-flight and failed enrichment are visible and distinct from
  "enriched, found nothing".** A domain nobody could look up must not read as a
  clean domain.
- **The rendering is versioned**, so what triage saw is pinned rather than
  re-derived later.
- **It is bounded**, and truncation that is invisible is a correctness bug, not a
  formatting choice.

Because the host attribute set comes from fixed configuration and nothing else,
triage input stays **independent of any prior agent output** — which is what keeps
assessments comparable across hosts and across time.

## What escalates

Two independent inputs reach the Analyst Agent, and the second is the one that
matters:

- **Triage returned `suspicious`.**
- **The enrichment evidence escalates on its own** — a Tier A, or a
  high-confidence Tier B, malicious classification whose traffic characteristics
  support it — **regardless of the triage verdict**.

**An LLM returning `normal` may not bury a high-confidence match.** That is why
the deterministic escalation input exists and why it is evaluated by code rather
than inside the prompt.

**A triage failure does not escalate.** Failing closed is safe precisely because
deterministic escalation is independent of whether triage ran at all; failing open
would flood the expensive stage exactly when the model service is already failing.

## One contract for both

One versioned typed request / result pair covers every agent. Agents never
exchange free-form natural-language messages, and nothing crosses an agent
boundary except validated typed fields.

**The request** carries the tenant, the host and window in event time, the context
reference **and its version** (which is what makes replay possible), the trigger
(scheduled triage, triage-suspicious, or deterministic escalation), the rendering
with explicit truncation, the budgets, and the full version set — prompt, schema,
rendering, taxonomy and model identity.

**The result** carries the root and classification path, confidence (a number to
measure, not a routing constant), citations by stable evidence id marked
supporting or contradicting, an evidence package for the analyst's non-`normal`
verdicts, the retrieval trace, the gaps, any proposed claims, the cost, the echoed
versions, and — where there is no verdict — a typed failure.

**Three fields were deliberately not adopted**, and the reasons are concept-level:

- A free-text **task** per invocation would be a varying instruction channel into
  the model: it would make triage input non-uniform, make assessments incomparable
  across hosts and time, and give attacker-influenced content a route into the
  instruction position.
- Loose **observations** or **relevant context** fields would carry the same
  content as the bounded, versioned, citation-carrying rendering **without** the
  guarantees that make an assessment replayable.
- **Recommended actions** has no consumer and invites the remediation channel the
  concept excludes.

**Citations are required except on two paths.** A `normal` triage decision returns
verdict and confidence only — that costs nothing on the overwhelmingly common path
and gives auditability exactly where a decision was made to spend analysis.
`unknown` is exempt too, because a run whose enrichment entirely failed has no
evidence row to point at; its audit trail is the **mandatory** gaps list, which is
what stops the exemption becoming an unfalsifiable shrug.

## The analyst forms an independent second opinion

**The analyst does not inherit the triage rationale by default.** It re-reads the
enriched context and decides for itself — because the analyst's `normal` verdict is
the direct measurement of triage precision, and that measurement is worthless if
the analyst was anchored on triage's framing. The other arm stays measurable as a
configuration switch rather than a contract change.

## The deferred third agent

The cloud **Investigation Agent** is analyst-initiated: a human opens a case, works
it interactively against a redacted view with a cloud model, and the session is
appended to the finding without overwriting the local assessment. It is
deliberately underspecified, because what analysts need there depends on what the
local pipeline turns out to leave unanswered — and because its redaction gate has
nothing to gate until it exists.

Its cost profile is also different in kind: **cloud cost scales with analyst
attention, not with telemetry volume.**
