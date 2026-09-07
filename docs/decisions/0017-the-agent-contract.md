# 0017 — The agent contract: one versioned pair, and the four things it says that `concept/04` does not

**Status: accepted.** Task 26 (D4 Contract).
**Authority:** `concept/04-the-two-agents.md` ("One contract for both", the three
fields deliberately not adopted, the citation rule and its two exemptions),
`concept/02-concepts-and-taxonomy.md` (citation, evidence package, gap, typed
failure, the context level), `concept/07-principles.md` (the agent boundary,
partial results and failure, budgets, caching), `concept/03-architecture.md`
(agent output as typed rows with citation joins),
`docs/decisions/0008-version-registry.md` (agent output schemas retained as
frozen Pydantic classes) and `concept/instruction.md` §2 (typed boundaries,
truncation, the five statuses, reproducibility).

`helena.contracts` is a versioned package: `__init__.py` holds the loader and the
two exceptions, `v1.py` holds `AgentRequest`, `AgentResult`, `AgentFailure` and
the constants they validate against. `tests/test_contracts.py` exercises it.
Nothing here touches the engine — an assessment is not stored yet.

## One pair, and the asymmetry as rules rather than as a second shape

`concept/04` makes Triage and Analyst deliberately asymmetric and in the same
breath gives them *one* contract. So there is no `TriageResult` class. The
asymmetry is validation on `AgentResult`, keyed by `emitter`:

| `concept/04` says | Where it is enforced |
| --- | --- |
| Triage tools: "none at all"; retrieval "none" | `AgentRequest` refuses a triage request with a non-zero step or live-query budget; `AgentResult`/`AgentFailure` refuse a triage cost reporting steps, live queries or cache hits |
| Triage verdicts `normal`/`suspicious`; analyst four roots | `helena.taxonomy.for_emission(..., emitter=...)` — one closed root set per emitter, already frozen per taxonomy version |
| "Evidence tier visible": enrichment only for triage | **Not enforced here.** The rendering carries no tier, so this is the renderer's rule (D4 Rendering) |
| Analyst "writes nothing — it proposes" | `ProposedClaim` requires at least one citation, and nothing in this module performs a side effect |

Two classes would be two places every later rule has to be written, and the first
one forgotten is a triage run that quietly returned `malicious`.

## The three fields that were deliberately not adopted

A free-text **task**, loose **observations** / **relevant context**, and
**recommended actions**. `concept/04` gives the reasons; what this ADR records is
that they are refused *three* ways, because a field absent by convention comes
back:

1. no such field exists on any model;
2. `extra="forbid"` on every model, so no caller can add one at runtime;
3. `tests/test_contracts.py` asserts the absence by name over every model **and**
   over the module's AST, so a model this test file forgot to list cannot smuggle
   one in.

## Four things this contract says that `concept/04` does not

Each was needed to make an existing rule checkable, and each is written here
rather than assumed.

### 1. `sensor` on the request

`concept/04` names the tenant. `helena.context.FrozenContext` is keyed by
`(tenant, sensor, context_id, context_version)`, so a request carrying the tenant
alone names a context that may exist under several sensors — and "the context
reference **and its version** … is what makes replay possible" is exactly the
sentence that stops being true without it.

### 2. `emitter` on both the request and the result

The closed root set is per emitter and the tool rules are per emitter; a request
that did not say which agent it is for would leave every one of those rules with
nothing to key on. It is on the **result** as well, not only the request, because
a stored result has to be validatable on its own — which is what replay does.

### 3. `RequestVersions` is not a `VersionSet`, and the difference is one field

`VersionSet.model_version` is "the model as the endpoint reported it **in the
response**" (ADR-0008). A request is written before any response exists. Putting
the configured model name in that field would be the exact substitution the
version registry exists to prevent: a recorded version that looks measured and
was assumed.

So the request carries the eight dimensions that are known plus
`model_requested`, and `RequestVersions.completed_by(model_version)` produces the
nine-dimension `VersionSet` once something has answered. `AgentResult` carries
that `VersionSet`. **`AgentFailure` carries the `RequestVersions` and an optional
`model_version`**, because a `model_unavailable` failure is a run where nothing
answered and there is no reported identity to record; `schema_invalid` is the
opposite case and requires one.

`REQUEST_VERSION_DIMENSIONS` is the eight, and a test asserts those plus
`model_version` are exactly `helena.versions.VERSION_COLUMNS` — so a tenth
dimension added to the registry is a failing test here rather than a version this
contract quietly stops carrying.

### 4. `RenderedSection.evidence_ids`, and the rule it buys

`concept/04`'s first property of the rendering is that "**every enriched value is
citable**, carrying a stable evidence identifier, or triage cannot cite its
reasoning and the finding cannot be replayed." Listing the identifiers per
section makes that checkable: `check_exchange` refuses a result citing an
identifier the rendering never showed and the retrieval trace never produced. A
model citing evidence it was not handed is precisely the failure a stable
evidence identifier exists to make detectable, and without this the identifier
would only be an identifier for whoever already believed the citation.

## Two readings of `concept/02` that could have gone the other way

### The evidence package holds neither the citations nor the gaps

`concept/02`: "**evidence package** — assembled cited evidence: indicators,
patterns, missing information, narrative." The indicators *are*
`AgentResult.citations` and the missing information *is* `AgentResult.gaps`;
`concept/04` lists the package, the citations and the gaps as three separate
result fields. Copying either into the package would be two copies of one fact
that can disagree — the same objection `concept/instruction.md` §2 raises about
version constants — so `EvidencePackage` holds what the package *adds*:
`patterns` and `narrative`.

### The `normal` exemption is triage's alone

`concept/04`: "a `normal` **triage** decision returns verdict and confidence
only". An analyst `normal` is not exempt, and that is deliberate rather than an
oversight in the reading: the analyst reached it by spending analysis, and
`concept/02`'s composition rule says "`normal` on contacted indicators **never**
establishes `normal` for the context on its own". An uncited analyst `normal`
would be the one verdict in the system with nothing behind it.

`unknown` is exempt from citations and its `gaps` list is **mandatory** —
"which is what stops the exemption becoming an unfalsifiable shrug".

## Frozen by reference, and what that costs

A version module may hold no shared helper (`tests/test_package_layout.py`
refuses any file in the package that is not `__init__.py` or `vN.py`), so the
constants `v1` validates against — the triggers, the section names, the stances,
the gap kinds, the retrieval outcomes, the failure reasons — live in `v1.py` and
not in the package. A constant in `__init__.py` would be one every frozen version
imports, and editing it would edit `v1` through a side door.

Three shapes still come from outside and are **frozen by reference**: changing one
of them changes what `v1` validates.

| Imported | Why not re-spelled in `v1` |
| --- | --- |
| `helena.versions.VersionSet`, `Version` | The nine dimensions are the version registry's, and a second copy is the drift ADR-0008 exists to prevent |
| `helena.taxonomy` (`EMITTERS`, `CONTEXT`, `for_emission`) | The vocabulary is already versioned and already frozen per version; the contract records *which* version and defers to it |
| `helena.enrichment.QueryFailure`, `ENTITY_TYPES`, `MAX_FAILURE_DETAIL` | A provider query's typed failure is one shape for the whole system; a per-contract copy would be a second spelling of `concept/05` rule 4 |

This is a real hazard and it is recorded rather than designed away: a change to
any of those three is a change to what a `v1` row was validated as. The
alternative — a self-contained `v1` — would put four vocabularies in every future
contract version and guarantee they diverge.

## What `check_exchange` enforces, and why it is a function

Three rules hold between a request and its outcome and none of them can be
checked by either object alone: the emitter matches, the eight known version
dimensions come back unchanged (which is what "echoed versions" means), and every
citation resolves to something the run was given. A fourth is about visibility
rather than pairing: **a rendering that truncated something requires a
`truncated` gap on the outcome**, because `concept/instruction.md` §2's
"truncation is visible or it is a bug" has to hold in the record of the run and
not only in the input to it.

It is a function rather than a method because it is symmetrical in its two
arguments and belongs to neither.

## What was not done

- **No assessment table, no sink message, no citation join rows.**
  `concept/03` describes all three; they belong to the increment that first
  stores an assessment. This task defines the shapes that increment will write.
  Consequently the typed failure is **typed but not yet stored or counted** — the
  `concept/instruction.md` §7 item about countable failure paths is satisfied for
  the enrichment layer and is open for the agent layer until D5.
- **No structure inside `RenderedSection.body`.** The five section *names* are
  the contract's; what goes in one is `rendering_version`'s, and the renderer is
  the next increment. A body shape decided here would be a rendering built before
  anything had been measured about how large one is.
- **No size budget.** `concept/08-open-questions.md` lists the numeric budget
  values as open, and `concept/07` makes budget values "policy, not constants in
  a branch". `Truncation` guarantees that dropping something is recorded; how much
  may be dropped is set elsewhere.
- **No check of cost against budgets.** A run that overshot its wall clock by a
  hair would then be a contract error rather than the typed failure it is.
  Enforcement is at the tool boundary (`concept/07`), which is the tool layer's
  increment.
- **No monetary cost field.** `concept/06`: monetary cost is *derived*, and no
  price table exists in this repository. A currency column filled from a guessed
  rate would be an invented external fact.
- **No disclosure record.** `concept/02` and `concept/07` put it on the
  assessment, and what is disclosed is decided at the provider-tool boundary; the
  retrieval trace here records cache-hit versus live query, which is what a
  disclosure record will be derived from.
- **No `v2`, and no comparison between versions.** The identifiers are opaque
  tokens, as ADR-0008 left them.
