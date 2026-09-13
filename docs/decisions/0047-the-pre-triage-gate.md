# 0047 — The pre-triage gate: clearing a context without a model

Status: accepted — 2026-09-13, **by the operator, over a recorded objection**.
The objection is kept in full below rather than summarised away, because
`concept/instruction.md` §5 says a negative result is a result and because a
decision whose cost is only in a chat log is a decision nobody can revisit.

## The question this answers

**Triage runs on every context, and that is what it costs.** One measured network
day is 12 089 contexts over 287 five-minute windows from 3 199 hosts
(`scripts/corpus_sizing.py`, `docs/evaluation-corpus.md`). At `[budgets.triage]`'s
8 000 tokens that is ~97 M tokens per day of inference before a single
escalation, and every one of those calls is spent on a context that, in the
overwhelming majority of cases, holds nothing at all.

That cost is real and it is not what anyone wants to pay to learn that a host
browsed the internet.

## The decision

**A context holding fewer than `min_suspicious_indicators` suspicious indicators
is cleared without triage**, emitted as a `normal` verdict, and no model is
called for it.

1. **The threshold is policy, not a constant** — `[triage_gate]` in
   `config/policy.toml`, with its own `triage_gate_version`, recorded on every
   assessment the gate decided. The same rule `0023` follows for the escalation
   thresholds and for the same reason: a number that decided something has to be
   on the row it decided.
2. **The gate is subordinate to deterministic escalation, and this is not
   negotiable.** The escalation is evaluated first, from the frozen rules the
   request recorded, exactly as `assess` already orders it. **A context that
   escalates on its own is never gated**, whatever its indicator count. Without
   this the gate would break `concept/07`'s *"Triage returning `normal`
   suppresses a Tier A match"* — the gate would suppress it without even the
   courtesy of a model saying so.
3. **A gated assessment stores no model version.** `model_version` is NULL
   "exactly where nothing answered" (`helena.orchestration`), and nothing
   answered. Inventing a version for a run that did not happen would be the
   fabricated-provenance failure `0008` exists to prevent, and the NULL is what
   lets a consumer, a query and the observability views tell a gated clear from a
   triaged one.
4. **No new outcome kind.** `outcome_kind` is derived in SQL from
   `classification IS NOT NULL`, and a gated clear has a classification, so it is
   a `verdict`. The operator's decision was that a gated context is *cleared*,
   and a third kind would be a different decision wearing this one's name.

## The objection, recorded because it was overruled rather than answered

Raised 2026-09-13 before implementation and reaffirmed by the operator. Three
findings, none of which the decision disputes:

**1. It contradicted `concept/01` as written.** The note committed to a pipeline
that *"triages every context cheaply"*, and its selectivity tier was
triage → analyst. The note has been amended with the gate rather than left to
disagree with the code, which is the only part of this the implementation could
fix.

**2. The gate skips essentially everything, measured rather than predicted.**
`demo/assess_a_slice.py` pass A, real traffic against a feed minutes old: **131
entities, every one `no_match`**. ThreatFox's recent export is a two-day sighting
window of a few thousand indicators (`evaluation-corpus.md` §4). At the smallest
threshold the gate admits, essentially every context in a normal deployment is
cleared without inference. This is not a 90 % saving on a long tail; it is the
ordinary path.

**3. What remains is a feed lookup.** The model then only ever reads traffic the
feed already flagged. Beaconing, DGA-shaped names, odd TLS parameters and the
never-listed domain — the things a language model was brought in to notice and a
join cannot — are exactly what is skipped. `hazards.md` §6 names the shape of the
result: *"a classifier that always answers `normal` will score well on accuracy
and be worthless."* The gate makes that classifier the default path.

**What the objection is not.** It is not a claim that the cost is acceptable, and
it is not a claim that no gate could work. Three alternatives were offered and
declined, and they remain the obvious places to look if this is revisited:
coarsening the assessment unit from the five-minute window to the host-hour or
host-day (~3 199 calls for the measured day rather than 12 089, a ~74 % cut with
**no** loss of coverage); emitting skipped contexts as a distinct *not assessed*
outcome rather than as `normal`; and deterministic scoring that decides **order**
under a daily budget rather than deciding *whether*.

## What this costs, in the vocabulary the project uses

`concept/01` now carries *"that a `normal` verdict on a gated context means
anything was assessed"* on the **not-claimable** list, and
[`../hazards.md`](../hazards.md) §11 is the accepted risk. A gated clear is the
deterministic statement *"fewer than N suspicious indicators were found in this
context"* and nothing more. It **establishes the absence of nothing** — the same
sentence `concept/07` uses to forbid a budget-truncated analyst run returning
`normal`, which is the closest existing rule and is worth reading beside this
record.

## What would reverse it

A measured false-negative rate for gated contexts — how much of what matters is
in the set the gate clears. That needs the evaluation corpus, which does not
exist, so **the saving is known and the cost is unknown**. That asymmetry is the
decision, stated as plainly as it can be: this trades an unmeasured amount of
detection for a measured amount of money, and it was taken with that understood.
