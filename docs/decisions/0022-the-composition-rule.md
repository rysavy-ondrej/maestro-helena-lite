# 0022 — The composition rule, and where it runs relative to the prompt

**Status: accepted.** Task 32 (D4 Policy).
**Authority:** `concept/02-concepts-and-taxonomy.md` ("The composition rule —
scope before severity"), `concept/04-the-two-agents.md`,
`concept/07-principles.md`, `concept/instruction.md` §2, and
`docs/decisions/0008-version-registry.md`.

This increment adds `helena.policy` — the machinery — and `helena.policy.v1` —
the composition rule, frozen the moment an assessment records
`policy_version = "v1"`. It adds no runtime dependency, no store, no egress
channel, no SQL and no contract field.

---

## 1. Where the rule runs, and why it is not in the prompt

`concept/02` is explicit about the *form* the rule has to take:

> The composition rule should live as **explicit, testable policy** rather than
> in the model's judgement: the model classifies, the policy constrains what
> evidence can support what verdict. **This is where over-alerting will come from
> if it is wrong.**

The order is fixed, and each step is a different actor:

| Step | Who | What it decides |
| --- | --- | --- |
| 1 | `helena.triage.v1` (the prompt) | how to *read* the rendering |
| 2 | `helena.agents.assess` | whether the answer validates against the frozen contract |
| 3 | `helena.triage.run` → `check_exchange` | whether the answer holds against its own request |
| 4 | **`helena.policy.v1.constrain`** | **whether the cited evidence can support the verdict** |

So the rule runs **after** the model, on the model's own answer, and never inside
the prompt. Three reasons, in decreasing order of how much they matter:

- **A rule in a prompt is a suggestion.** The prompt's job is to survive being
  read alongside attacker-influenced data; a constraint stated there is one more
  sentence in the instruction position that the data is trying to talk the model
  out of. A constraint in code is not negotiable by anything in the rendering.
- **It would not be testable.** `concept/02` asks for *explicit, testable*
  policy. A rule inside `INSTRUCTIONS` can be tested for its presence in a string
  and for nothing else; there is no case, no table and no counter-example.
- **It would move with the wording.** `prompt_version` and `policy_version` are
  separate dimensions of `helena.versions.VersionSet` precisely so that
  rewording an instruction and changing what evidence may support what verdict
  are two different recorded changes.

The prompt is not silent about the *distinction* — `helena.triage.v1` tells the
model that "an indicator being classified says something about that indicator,
not about this host", which is how to read the data. It does not state the rule,
and this file is why.

**The policy does not rewrite the result.** `concept/07` keeps inference
append-only, and `AgentResult` is the record of what the model said. `constrain`
returns a **second** typed record, a `Decision`, saying what that answer is
permitted to be read as. Two records rather than one, because an evaluation that
could not tell a model's answer from a policy's correction of it would be
measuring the wrong thing.

**This is not the escalation evaluator.** `concept/04`'s second, independent input
to the analyst — a Tier A or high-confidence Tier B classification escalating
*regardless of the triage verdict* — reads the store rather than a model's
answer. It is task 33's, it will read the same `Support` records, and its third
step ("a hit whose traffic does not support it does not escalate as `malicious`")
is this rule applied there.

## 2. `helena.policy` is the sixth versioned package

`policy_version` is one of the nine dimensions every citable row records
(`helena.versions`), and until now it was the dimension with **no owner** — every
test filled it with a placeholder. A stored assessment is entitled to have the
rule that constrained it stay exactly as it was, so the rules are a frozen module
and a revision is `v2` beside `v1`.

The split follows `helena.rendering`'s, for the same reason:

- **`__init__.py`, machinery.** `Support` — one cited claim with the per-entity
  traffic beside it — and `supports_for`, the read that fuses a result's
  citations with a `helena.rendering.ContextProjection`. That is *how the input is
  assembled*, and it moves when the store's shape moves.
- **`vN.py`, frozen.** The rules, their names, the severity ordering, the paths
  that assert something about the host, and the `Decision` a run records.

`Support` carries the claim **and** the traffic on one object because `concept/02`
says the rule needs them together: *"This is why per-entity traffic columns exist
at all, and why they sit on the same row as the verdict: a row carrying only a
classification cannot tell those cases apart."* Every predicate over those fields
— what counts as contact, what counts as traffic in both directions, what counts
as shared infrastructure — is in the **version**, because those are the
thresholds the rule *is*.

## 3. The seven rules, and the sentence each one is

| Rule | `concept/02` |
| --- | --- |
| `normal_is_not_established_by_absent_adverse_evidence` | *"`normal` on contacted indicators **never** establishes `normal` for the context on its own"* |
| `malicious_needs_a_supporting_citation` | *"An evidence-level classification about a contacted indicator does not become the context verdict"* — with nothing supporting it there is not even one to compose from |
| `contact_is_not_compromise` | *"A phishing domain contacted means the *user was targeted*, not that the host is compromised"* |
| `address_support_needs_bidirectional_traffic` | *"A C2 hit on a contacted address **with actual bidirectional traffic** supports `malicious.c2`. The same hit with one failed connection and no bytes returned does not. That is `suspicious` at most"* |
| `a_port_scoped_claim_needs_the_port_the_host_reached` | scope before severity, in its narrowest form — and the decision `sql/migrations/0015_enriched_context.sql` explicitly deferred to this rule |
| `a_name_carries_no_traffic_of_its_own` | *"The scope test works on **address** entities and not on **domain** ones"* |
| `shared_infrastructure_transfers_nothing_without_corroboration` | *"A malicious indicator on **shared infrastructure** — a CDN, a cloud tenant, a resolver, a shared subdomain — transfers nothing to the host without corroboration"* |

Three of these are worth their own paragraph.

**The phishing sentence is generalised through the taxonomy rather than through a
threat type.** The evidence level in `helena/taxonomy/v1.py` is **roots-only** —
a ThreatFox hit emits `malicious`, not `malicious.c2` or `malicious.phishing` —
so no rule here can key on "this is a phishing indicator". What it keys on
instead is the *proposed context path*: `concept/02`'s malicious family splits
into contact (`c2`, `payload`, `phishing`) and host state (`compromised`,
`hostile`, `spam`, `exfiltration`), and `malicious.phishing`'s own gloss is *"a
targeted user, not necessarily a compromised host"*. So contact reaches
`malicious.phishing` and cannot reach `malicious.compromised`, which is the
sentence. `tests/test_policy.py` puts the two cases side by side over the same
evidence.

**A cap is a bare root, never a path.** `concept/02`'s syntax rule is *"emit the
parent rather than guessing a child — a mapping with a threat type it has never
seen emits `malicious`, not an invented `malicious.something`."* Naming which
kind of `suspicious` a capped verdict is would be exactly that, one level up. The
cap is also checked against `helena.taxonomy.for_emission` for the emitter the
result came from, so a policy that capped to something the emitter could not have
said fails rather than inventing a label.

**`unknown` is off the severity scale and no rule reaches it.** `concept/02`
keeps `unknown` *"deliberately distinct from `suspicious`, which means analysis
ran and could not settle it"*: unassessability is not a severity. `SEVERITY`
holds three roots and no rule has a precondition that fires on `unknown`, so such
a verdict passes through unconstrained.

## 4. `permits` is three-valued, and the third value is not a verdict

| `permits` | Meaning |
| --- | --- |
| the proposed path | the cited evidence can support what the model said |
| a weaker root | the evidence supports at most this |
| `None` | the cited evidence supports **no** context verdict at all |

`None` is not `normal` and it is not `unknown`. Two of the rules reach it — the
`normal`-by-absence rule and the shared-infrastructure rule, whose sentence is
*transfers nothing* rather than *transfers less* — and in both cases the honest
statement is that this evidence establishes nothing about this host. Turning that
into a verdict is a decision for whatever routes on it; a policy that made it
would be choosing between two claims the evidence does not carry.

**Two things this leaves for later, stated rather than approximated:**

- The failure mode the `normal` rule is named for — reading a context of nothing
  but `no_match` as a clean bill of health — is **not visible from citations**.
  A `no_match` carries no evidence identifier, so it cannot be cited, so the rule
  cannot see it. What the rule catches is a `normal` whose cited support is
  entirely evidence-level `normal` or `no_match`. Catching the other half needs
  the store rather than the result, and that is the escalation evaluator's read.
- **No registered source can emit evidence-level `normal` today.** ThreatFox
  declares `{malicious, no_match}` and `sslbl-ja3` declares `{suspicious,
  no_match}` (`helena.enrichment.SOURCES`), so the rule is written against the
  vocabulary and exercised against a constructed claim. It is here because
  `concept/02` requires it and because the first Tier A/B source that maps a
  known-good listing would otherwise arrive with nobody applying it.

## 5. The gaps are the policy's own vocabulary, and one contract question is open

Two limitations are recorded as a first-class `helena.policy.v1.Gap` on the
decision:

| Kind | When |
| --- | --- |
| `domain_scope_untestable` | the verdict was capped because no supporting claim is about an address |
| `shared_infrastructure_undetermined` | a `malicious` verdict **survived**, and the shared-infrastructure test that could have withheld it was only run for the one case this version can see |

The second is recorded exactly where it changed nothing visible, which is the
point: a permitted `malicious` verdict is the one place a reader needs to know
that a test which could have withheld it was not run.

**These are not `helena.contracts.v1.GAP_KINDS`, and that is deliberate.** The
contract's seven kinds are `missing`, `stale`, `in_flight`, `failed`, `no_match`,
`truncated` and `budget_exhausted`, and none of them names *a test that does not
apply*. `missing` is the tempting one and it would be a collapse:
`concept/instruction.md` §2 keeps `missing` distinct at every layer, and "the
lookup did not happen" is not "the rule could not be run".

**Open, and escalated rather than guessed:** attaching one of these to an
`AgentResult` — so a stored assessment carries it beside the model's own gaps —
would need either a contract `v2` with an eighth gap kind or a decision to spell
one of the seven. Adding a gap kind is a change to the agent contract, which
`concept/instruction.md` §3 makes an escalation. Until it is decided, the
policy's gaps live on the `Decision`, which is the record D5 will store beside
the assessment anyway.

## 6. Shared infrastructure: one case observed, three recorded as undetermined

`concept/02` names four kinds — *a CDN, a cloud tenant, a resolver, a shared
subdomain*. Three of them are **external facts about the address or the name**,
and nothing in this repository holds one:

- `helena.enrichment.SOURCES` has two feeds and neither says so.
- The Public Suffix List is deliberately **not** in that registry, and
  `helena/enrichment.py` says why in terms that settle the question: *"it makes
  no claim about any entity, and it can neither escalate nor suppress."* Using
  its private section to withhold severity would be using it to suppress.
- Netify is Tier D and supplies *"application identity and category and **never**
  a threat classification or a decision about an entity"*
  (`docs/decisions/0009-netify-application-identification.md`), and it is not
  loaded as a source at all.

A **resolver** is different: it is observable. `helena_signal_context_entity_ports`
records the destination ports the host actually reached, so "this host used that
address as a resolver" is a fact about this capture rather than a claim about the
address. That case is tested; the other three are `shared_infrastructure_undetermined`.

Inventing the rest would be exactly the class of error this project has already
had to correct — a plausible external fact, asserted from a documentation page
rather than measured. What would settle it is a source that declares
infrastructure roles, which is a governed decision (`concept/05`) and not a
session's.

## 7. What is not claimed

Nothing calls this in a running pipeline: no decision is stored, nothing routes
on one, and no rule's behaviour on real traffic has been measured against a
label, because there is no labelled corpus (`concept/08-open-questions.md`).
`concept/02` says over-alerting is what a wrong composition rule produces, and
whether these rules produce the right rate is precisely the thing this increment
cannot answer. What is demonstrated is narrower and is what a table can carry:
each sentence of the composition rule refuses what it says it refuses, over
fixtures for the shape and over a real capture, a real ThreatFox load and the
view's own `port_matched` for the port-scoped case.
