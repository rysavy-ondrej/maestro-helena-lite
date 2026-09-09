# 0023 — Deterministic escalation, and the thresholds that are not in the code

**Status: accepted.** Task 33 (D4 Policy).
**Authority:** `concept/04-the-two-agents.md` ("What escalates"),
`concept/02-concepts-and-taxonomy.md` ("Source tiers A–D" and its four
normalization rules), `concept/03-architecture.md` (the routing `if`),
`concept/07-principles.md`, `concept/instruction.md` §2, and
`docs/decisions/0022-the-composition-rule.md`.

This increment adds `helena.policy.v1.escalate` and the machinery it needs —
`helena.policy.supports_in`, `Thresholds` and the loader for `config/policy.toml`.
It adds no runtime dependency, no store, no egress channel, no SQL and no
contract field.

---

## 1. Why this is evaluated by code and not by the prompt

`concept/04-the-two-agents.md`, "What escalates":

> Two independent inputs reach the Analyst Agent, and the second is the one that
> matters:
>
> - **Triage returned `suspicious`.**
> - **The enrichment evidence escalates on its own** — a Tier A, or a
>   high-confidence Tier B, malicious classification whose traffic
>   characteristics support it — **regardless of the triage verdict**.
>
> **An LLM returning `normal` may not bury a high-confidence match.** That is why
> the deterministic escalation input exists and why it is evaluated by code
> rather than inside the prompt.

`concept/03-architecture.md` writes the consequence as the routing `if`, with the
evidence branch **first**:

```text
if evidence escalates independently (tier A, or tier B above threshold):
    run_analyst(trigger="deterministic_signal")   # independent of triage
elif triage.root == "suspicious":
    run_analyst(trigger="triage_suspicious")
```

`escalate` is the left-hand side of the first line. It is the half that makes
failing closed safe: `docs/decisions/0021-the-triage-runner.md` §6 recorded that
until this existed, a context whose model call failed was dropped and nothing
else looked at it, which is the only genuinely unsafe thing the triage stage
shipped with. `helena.triage.escalates` remains the second line, unchanged and
still returning `False` for every typed failure.

## 2. It takes no result, and that is enforced rather than intended

`escalate(supports, thresholds)`. There is no parameter a verdict could arrive
through, and `tests/test_policy.py::test_the_evaluator_has_no_parameter_a_verdict_could_arrive_through`
asserts it over the signature **and** over the AST of the three functions the
rule reaches, refusing any reference to `AgentResult`, `AgentFailure`, `Decision`
or `constrain`.

That test is not ceremony. The way this invariant gets broken is not a rule that
reads a verdict on purpose — it is a later increment passing the triage result in
so the evaluator can *skip work* when triage already said `normal`. That looks
like an optimisation and it is the suppression `concept/instruction.md` §2
forbids.

The input is therefore built by a **second** constructor beside `supports_for`:

| | `supports_for` | `supports_in` |
| --- | --- | --- |
| Asks | what the evidence a model **cited** can support | what the store holds |
| Reads | an `AgentResult` and a projection | a projection |
| Stance | the citation's | always `supporting` — a claim read out of the store is evidence for what it says, and nothing here is arguing |

## 3. The three clauses, and where each one is tested

`concept/04`'s sentence has three clauses and each is a separate test:

| Clause | Where |
| --- | --- |
| *a Tier A, or a high-confidence Tier B* | `ESCALATING_TIERS`, and `Thresholds.for_source` for the tier `concept/02` qualifies with "when high confidence" |
| *malicious classification* | the claim's own evidence-level root; nothing else becomes a candidate |
| *whose traffic characteristics support it* | the composition rule of ADR-0022, applied per claim |

The third clause is the task's own step — *"a hit whose traffic does not support
it does not escalate as `malicious`"* — and it is **the same four predicates**
`constrain` applies, reading the same `_contacted_with_traffic_both_ways` and
`_is_shared_infrastructure` helpers. Two copies of the composition rule under one
`policy_version` is precisely the drift the version rules exist to prevent, which
is also why `escalate` lives in `v1.py` beside `constrain` rather than in a module
of its own: one frozen version, one set of rules, one identifier a stored row
records.

**Every malicious claim becomes a `Candidate`**, escalating or not, with every
rule that held it back named in `ESCALATION_RULES` order. A record of only the
escalating ones would answer *why did this run the analyst* and not *why did this
one not* — and `concept/07-principles.md`'s named failure mode ("triage returning
`normal` suppresses a Tier A match") looks exactly like a context with no
candidates until somebody can see the candidates.

## 4. The thresholds are a file, and the file carries two versions

`concept/08-open-questions.md` lists *"the per-source confidence thresholds that
decide when a Tier B match escalates independently"* as blocking and open. So the
number is not settled here; what is settled is **where it lives and what records
it**.

`config/policy.toml` is the same shape ADR-0019 established for the rendering
budget: policy that is a *location*, not an environment variable. It carries two
versions and the reason there are two is the freeze:

- `policy_version` says which frozen rule module the numbers are *for*.
  `escalate` refuses a threshold set recording another one, exactly as
  `constrain` refuses a result recording another one — a number applied by rules
  it was not written for is a decision nobody made.
- `thresholds_version` is the file's own, and it is recorded on **every**
  `Escalation`. `src/helena/policy/v1.py` is frozen and this file is not, so an
  escalation that recorded only `policy_version` could not be replayed against
  the number that actually decided it.

The loader fails loudly, and the coverage check is the point of it: every
registered Tier B source must have an entry — a feed whose threshold nobody set
would otherwise escalate on whatever the code guessed — and a source that is not
Tier B must not have one, because a threshold nothing reads is a decision
somebody recorded and nothing applies. Tier A takes no entry at all: `concept/02`
conditions it on scope and freshness and not on a number.

**Where 0.80 came from.** Measured over `data/threatfox/` on 2026-09-09, 4 095
entries, `confidence_level ÷ 100`:

| | `>= 0.75` | `>= 0.80` | `= 1.00` |
| --- | --- | --- | --- |
| 3 375 `ip:port` | 3 184 (94.3 %) | 930 (27.6 %) | 918 (27.2 %) |
| 433 `domain` | 234 (54.0 %) | 230 (53.1 %) | 180 (41.6 %) |
| 287 `url` | 280 (97.6 %) | 217 (75.6 %) | 202 (70.4 %) |

The distribution is bimodal and 0.75 carries two thirds of the address side on
its own. A threshold at or below it admits 94 % of every ThreatFox hit, which
makes the threshold decorative and puts the whole of the over-alerting risk on
the traffic test. 0.80 is the first value above that mode. **It is a candidate,
not a decision** — what settles it is an escalation rate measured against
labelled outcomes, and there is no labelled corpus.

## 5. The aggregator rule: counted correctly, and it changes nothing yet

`concept/02` normalization rule 2: *"Do not double-count correlated sources.
Evidence copied through an aggregator is not an independent vote; retain the
origin and count source diversity. **An aggregator is never counted as many
votes.**"*

Every candidate records `independent_sources`, counted by
`helena.enrichment.source_diversity` rather than re-implemented here — so one
source's forty rows about one address are one vote, an aggregator republishing
forty entries is one, and the same origin reaching us twice is one, without any
of that being restated in a second place.

**No rule in `v1` raises anything on that count, and that is deliberate.**
`concept/04` conditions independent escalation on the tier and the source's own
confidence and on nothing else; `concept/02`'s "two independent sources may raise
confidence" is written for **tier C**, which `concept/04` excludes from
independent escalation entirely. A corroboration rule that lifted a
below-threshold Tier B claim would be inventing a requirement
(`concept/instruction.md` §4). What the count does is prohibitive: it is what
stops a below-threshold claim being lifted by the *number of rows* behind it,
which is the one way a confidence could be raised here without anyone deciding
to.

**Two honest limits.** No registered source is an aggregator
(`helena.enrichment.SOURCES` has `aggregator=False` twice), and no evidence row
carries an `origin` — the mapping views in
`sql/migrations/0014_feed_mapping_views.sql` have no such column. So the
origin-retention half of rule 2 is exercised by `tests/test_sources.py` at the
`Claim` level and **cannot be exercised end to end here**. Adding an aggregator
source is a governed decision (`concept/05`), and adding an origin column is a
change to the evidence row. Both are named rather than approximated.

## 6. Freshness is the third clause of tier A, and it is not tested

`concept/02` lets a Tier A source establish `malicious` by itself *"if scope and
freshness are adequate"*. Scope is the whole composition rule. **Adequate**
freshness is not tested: what this version has is `status`, which says the
snapshot the claim matched is older than the feed's own refresh interval, and no
rule for what that costs.

It does **not** suppress. `concept/02` normalization rule 3 is explicit —
*"Removal from a feed is not exoneration"*, and delisting *may* reduce confidence
— and reducing it by an amount nobody has measured would be inventing the very
threshold this gap exists to say is missing. So a claim from a superseded
snapshot escalates and the escalation records `freshness_adequacy_untested`, the
third kind in `helena.policy.v1.GAP_KINDS`.

## 7. Where this will under-fire, said out loud

**Domain hits do not escalate.** The composition rule caps domain-only support at
`suspicious` — *"a name carries the traffic of the flows that mentioned it, not
of the connection to the address it resolved to"* — and `concept/04` escalates a
malicious classification *whose traffic characteristics support it*. Those two
sentences together mean a Tier A hit on a name never reaches the analyst through
this input, however confident the source is.

`concept/02` names this as the place *"that bites precisely where it matters
most, since the feeds most likely to hit list domains"*, and 433 of the ThreatFox
snapshot's entries are domains. The alternative considered and rejected was to
let a name observed in TLS SNI or HTTP satisfy the traffic clause on the grounds
that *"a name in TLS SNI was connected to"* — rejected because it would be a
**second** definition of "the traffic supports it" under one `policy_version`,
disagreeing with `constrain` about the same claim. Fixing it properly needs the
resolution edge (a name to the address the host actually connected to), which
this store does not carry.

`tests/test_policy.py::test_a_real_domain_hit_does_not_escalate_and_records_the_limitation`
is that limit as a passing test rather than a paragraph, and every such
escalation records `domain_scope_untestable`.

## 8. What is not claimed

- **Nothing calls this.** No routing `if` exists yet — that is D6 orchestration's
  — and no escalation has been stored, because no assessment table exists (task
  26 deferred it to D5). The `Escalation` is typed and countable in memory and in
  nothing else.
- **No threshold is calibrated.** 0.80 is a measured position in a feed's
  distribution, not a measured escalation rate. Whether it over- or under-alerts
  is unknown and stays unknown until there is a corpus.
- **The shared-infrastructure test is still one case out of four.** Every
  escalation that stands records `shared_infrastructure_undetermined`, exactly as
  every permitted `malicious` decision does (ADR-0022 §6).
- **The evaluator has never run beside a real triage answer**, because nothing
  assembles the pair. What is demonstrated is that the two inputs are computed
  from different things and that this one does not read the other.
