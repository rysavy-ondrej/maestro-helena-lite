# 0035 — Assessment replay from the stored versioned inputs

**Status: accepted.** Task 45 (D6 Replay).
**Authority:** `concept/instruction.md` §2 ("Reproducibility"),
`concept/03-architecture.md` ("Orchestration": *replays from stored results*),
`concept/04-the-two-agents.md` (the context version *"is what makes replay
possible"*), `concept/07-principles.md` (caching, disclosure),
`concept/08-open-questions.md` (the silent-record-loss hazard), and
`docs/decisions/0008-version-registry.md`, `0031-replay-at-the-tool-boundary.md`,
`0033-assessment-persistence.md`.

This increment adds the read half of `helena.orchestration` — `read_assessment`,
`reconstruct`, `rerun`, `compare` and the shapes around them —
`helena.contracts.rules`, `scripts/replay_assessment.py`, and
`tests/test_assessment_replay.py`. It adds **no runtime dependency, no second
store, no egress channel, no contract field, no table and no view**.

---

## 1. What a replay is here

One stored **agent run**, not one routed pass. `sql/migrations/0018` makes a row
one run — the cost, the latency, the nine versions, the endpoint and the verdict
are all properties of one — so replaying a pass is replaying its rows, and
`assessment_id` addresses exactly one of them.

Four steps, and each resolves a version rather than importing one:

| | |
| --- | --- |
| `read_assessment` | the row and its child rows, validated against `contracts.version(row["schema_version"])` — the classes the assessment recorded |
| `reconstruct` | the request, rebuilt by rendering the recorded `context_version` under the recorded `rendering_version`, then paired with the stored outcome under `contracts.rules(schema_version)` |
| `rerun` | the same question asked again, under the recorded `prompt_version`, with provider tools that may only be replays |
| `compare` | which of six dimensions moved |

## 2. Why the rendering is rebuilt rather than stored

The stored assessment carries no rendering, and this increment did not add one.
`concept/04` puts the context reference **and its version** on the request
precisely so that it does not have to: the version is what pins the numbers, and
the renderer is frozen per version. Storing the rendered bytes as well would be a
second copy of a fact that cannot disagree in the model and can in a table — the
reading `docs/decisions/0033` §4 already took for the verdict column — and it
would put a model-facing text blob in the analytical layer, which
`tests/test_assessments.py::test_nothing_that_builds_a_prompt_can_read_a_stored_assessment`
exists to prevent.

The cost is that a reconstruction can fail, and it must fail **loudly**:

- a projection at another `context_version` is refused outright;
- a citation the rebuilt rendering no longer shows is refused by the recorded
  version's own `check_exchange`.

Both are tested. Neither is repaired, because a repaired replay is a different
assessment wearing an old one's identifier.

## 3. `contracts.rules`, and why it is a function rather than a fourth member

`ContractVersion` holds three classes. The pairing rules — `check_exchange` — are
the fourth thing a version owns, and a replay needs them addressed **by recorded
version** for the same reason the classes are: current code's rules are not the
rules the row was written under. They are exposed as `contracts.rules(identifier)`
rather than as a field on `ContractVersion` so that **no version module had to be
edited to be found**: `v1.py` already defines `check_exchange`, and
`docs/decisions/0008` forbids editing a frozen version in place — including for
something as innocent as adding a name to a constructor call.

## 4. The provider half was already built, and is enforced at the entry point

Task 41 (`docs/decisions/0031`) made a replaying `ProviderTool` resolve every
lookup from the stored response, serve an expired record explicitly `stale`, and
refuse a miss with `no_stored_response` — with `helena.network.no_network` armed
around the dispatch. This increment does not re-litigate any of that. What it
adds is the refusal one level up: `rerun` rejects the **set** of tools if any of
them is not a replay, before a model is called, because a mode a caller could vary
per tool is one a tool loop could vary per turn.

**The model is still called, and `no_network` is deliberately not armed around a
replay.** Hosted inference is egress (`concept/03`); arming the guard would block
the very thing a replay re-asks. What replay makes offline is the retrieval, and
the measurement of it is task 35's: the adapter raises on contact, so there is no
path in which a provider was reached and the assertions still hold.

## 5. What a replay does not reconstruct — four gaps, stated

1. **The escalation, and therefore the routing.** Unchanged and still unowned
   (`docs/decisions/0033` §7): `Escalation.thresholds_version` reaches no row, so
   a replay reproduces a run's *outcome* and not the decision to make it, except
   in a deployment whose thresholds have not moved.
2. **The host attribute set.** `config/hosts.toml` is fixed configuration read at
   render time, and its `version` is not one of the nine dimensions
   `helena.versions.VERSION_COLUMNS` names. A rendering rebuilt after that file
   changed differs in its host section and nothing on the row says so. Either the
   set version becomes a tenth recorded dimension — a change to the version
   registry and to the agent contract, so an escalation — or a deployment treats
   the file as frozen. Recorded, not resolved.
3. **The citation order.** `helena_analytical_assessment_citation` has no ordinal
   (its key is `(assessment_id, evidence_id)`), so the order the model listed its
   citations in is not stored. The contract validates the set and `compare`
   compares the set; a reader that needed the order would need a column.
4. **An empty evidence package, and proposed claims.** A package is stored as its
   parts, so one with no patterns and no narrative leaves no trace — such a row
   refuses to assemble rather than being handed a package it may never have had.
   `AgentResult.proposed_claims` is written nowhere at all (`docs/decisions/0033`
   §7), so a replayed result carries none and a stored assessment that made one
   cannot say it did.

## 6. The diff is a measurement, not a verdict on the replay

Six dimensions: `outcome_kind`, `failure_reason`, `verdict`, `path`, `confidence`,
`citations`. The four `prd.json` names, plus two that keep them honest —
`concept/instruction.md` §2 refuses to collapse a typed failure into a verdict, so
a replay that failed where the original answered reads as the **kind** of outcome
moving, with the verdict dimensions `None` beside it, and never as a verdict that
changed into a reason.

A difference is not a failure. The model is not deterministic and nothing here
makes it so (`docs/decisions/0034` §4: *a re-run is idempotent in its record, not
in its verdict*). Measured by hand against the configured endpoint on 2026-09-11:
a stored triage verdict of `suspicious` at confidence 0.7 replayed as `suspicious`
at 0.9 — one dimension moved, zero provider disclosures, and the command printed
exactly that.

## 7. Replayability is a goal, and this increment does not make it a claim

`concept/08-open-questions.md`, under *Cross-cutting and urgent*:

> A record was silently lost once at a catch-up boundary — **replayability is a
> goal rather than a claim while that stands**.

Nothing here measures that hazard, so nothing here clears it. What is
demonstrated, by execution, is narrower and is the whole of what may be said:

- a stored assessment reads back as the outcome it stored, field for field, with
  the citation **set** and not its order;
- it is validated against the contract version the row recorded — including a
  version that is no longer the current one — and a version this tree does not
  hold is refused rather than migrated forward;
- the request is rebuilt from the recorded context version and rendering version,
  and a feed snapshot loaded after the assessment was made does not reach it;
- re-asking it queries no provider and reveals no credential.

Whether the store holds every record it should is a different question, and it is
the one `concept/08` is about. Until it is measured, the word for the property
stays *goal* — in `helena.orchestration`'s docstring, in the script's, and here.

## 8. What would reverse any of this

- **Storing the rendering** would become right the moment a deployment could not
  keep its context versions long enough to rebuild one — that is a retention
  decision (`concept/08`, still open), not a replay decision, and the number that
  would settle it is how often a reconstruction is refused in practice. Nothing
  counts that yet.
- **A second contract version** would turn §3's `rules` from a mechanism into
  something exercised in anger; today it is exercised by a stand-in `v0` a test
  installs.
- **A `--schema` flag on the command** stays refused. The suite's per-run schema
  is a test device, and RisingWave ignores the libpq `options=-csearch_path=`
  startup parameter (measured: a connection made with it reports `public`), so
  the wrapper is exercised against a stored assessment by hand rather than by
  growing a configuration key that exists for a test.
