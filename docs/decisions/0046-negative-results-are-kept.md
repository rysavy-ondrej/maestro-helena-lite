# 0046 — Failed and inconclusive experiments are results, and they are kept where they happened

Status: accepted — 2026-09-12 (task 55, D9 Governance).

## The rule

`concept/instruction.md` §5:

> **Failed and inconclusive experiments are valid results.** Record what was
> measured and why it failed. **Never rewrite or delete one.**

And §4: *"a discrepancy between two records is investigated, never papered
over."* This record says where such a result lives, so that "never delete one" is
a location rather than a sentiment.

## Where a negative result lives

**Beside the thing it is about, and in the artifact that made the claim.** There
is no `failures.md`, deliberately: a register of negative results away from the
code they concern is a register nobody reads at the moment it would change a
decision.

| Kind of result | Where it is kept | Example |
| --- | --- | --- |
| An approach that was tried and did not work | the task report's `failed_approaches`, folded by the runner into `prds/session-memory.json`'s `failedApproaches` | task 0's Kafka consumer group against `bin/blink` 0.2.0: polled 30 s, got nothing, no error |
| An alternative considered and rejected, with the reason | an **Alternatives rejected** section in the decision record | [0040](0040-durability-and-backup.md)'s `backup-meta` plus a state-store copy |
| A measurement that came out the wrong way | inline, in the record or module that depends on it, **with the number** | `concept/05`'s "narrowest feed" — counted, it carries five rows, so the join would never fire |
| A statement later found false | **corrected in place beside the original, marked as a correction** — never overwritten | `concept/05`'s *"no per-indicator lookup endpoint appears in the public documentation"*, and the 2026-09-10 correction printed under it |
| A measurement that could not be taken | recorded as **not measured**, with what it would need | the base rate, `docs/evaluation-corpus.md` §5; residual risk 3 in `docs/runbook.md` §15 |
| A capability that was built and then rejected | the `deprecated` maturity label, plus its record | none yet |

**The "corrected in place beside the original" row is the load-bearing one.**
Three source records in this project were each wrong for the same reason —
written from a documentation page, then propagated before anyone fetched the
thing it described. Overwriting one leaves a repository that looks as if it was
always right, which is how the next session learns nothing from it. `concept/05`
carries its own correction under the sentence it corrects, labelled *"recorded
rather than overwritten"*, and that is the pattern.

## What is enforced by execution

`tests/test_governance.py`:

- every `prds/reports/task-*.json` carries `failed_approaches`, `deferred` and
  `lessons` — the fields that hold this, so the shape cannot quietly disappear
  from a report;
- `concept/instruction.md` §5 still contains the rule, so a rewrite of the
  instruction file that dropped it fails rather than silently licensing deletion.

What is **not** enforced is that no existing record was ever deleted. A test
cannot see a file that is gone; `git` can, and the history is the enforcement.
Said here rather than implied, because a test that appeared to guarantee it would
be worse than none.

## A consequence worth stating

An **inconclusive** result is not a failure to be retried until it comes out.
`docs/evaluation-corpus.md` says the corpus does not exist and every measurement
gated on it is *unmeasured*; `docs/hazards.md` records the measurement gap as
accepted. Neither is a to-do. The project's claim ceiling —
*"never claim more than was demonstrated"* — is what those records buy.
