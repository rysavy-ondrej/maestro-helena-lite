# MAESTRO HELENA — concept notes

**Host-context Enrichment and LLM-Enhanced Network Analysis.**

HELENA turns network connection telemetry into **evidence-backed host contexts**,
enriches the entities in them against threat intelligence, triages every context
cheaply, analyses the ones that warrant it, and emits the result — with the
provenance and honest gap-reporting that make each verdict inspectable and each
run reproducible.

It is a **research prototype**. Architecture, requirements and algorithms are
expected to change as experiments produce evidence.

## The shape of the system

```text
1 ingest → 2 host context + entities → 3 enrich → 4 triage → 5 analyse → 6 emit
```

Every verdict cites stored evidence; degradation is visible; nothing is
remediated autonomously.

## The notes

| # | Note | Covers |
| --- | --- | --- |
| 01 | [Goal and scope](01-goal-and-scope.md) | The problem, the desired outcome, the research questions, what is in and out |
| 02 | [Concepts and taxonomy](02-concepts-and-taxonomy.md) | The vocabulary; the two levels of classification; evidence tiers; scope before severity |
| 03 | [Architecture](03-architecture.md) | The six stages, the single store, providers, interfaces, trust boundaries |
| 04 | [The two agents](04-the-two-agents.md) | Triage and Analyst — and why they are deliberately asymmetric |
| 05 | [Threat intelligence sources](05-threat-intelligence.md) | Which sources, in which tier, with what limitations |
| 06 | [Technology](06-technology.md) | Language, tools, models, and what was deliberately not adopted |
| 07 | [Principles](07-principles.md) | The rules an implementation may not break |
| 08 | [Open questions](08-open-questions.md) | What is genuinely unsettled, and what that blocks |
| — | [**Instructions for the implementation agent**](instruction.md) | **Binding rules for anyone building this.** Read before writing code |

## What "the prototype works" means

That the stages compose and cite. **Never that the verdicts are right** — the
measurement that would establish that needs a labelled evaluation corpus the
project does not have.
