# 01 — Goal and scope

## The problem

An analyst investigating a suspicious host does the same work every time: collect
the traffic around it, enrich each observed indicator across several sources,
compare current behaviour against history, and decide whether deeper analysis is
justified. That work is repetitive, expensive and inconsistent — particularly
against subtle or multi-stage activity, where the decisive evidence is a pattern
across several windows rather than a single hit.

## Why the obvious automation is not enough

The routine parts are automatable, but naive automation fails in a way that makes
it worse than nothing: a model that produces a confident verdict with no
traceable evidence cannot be audited, cannot be replayed, and cannot be improved.

Two commitments follow, and they are the project's reason for existing:

1. **Every verdict remains traceable to stored evidence.** Facts stay separate
   from inference; assessments cite stable evidence identifiers.
2. **Expensive reasoning is spent selectively.** Cheap triage decides what is
   worth analysing; deeper analysis runs only on what triage escalates.

## The desired outcome

A staged pipeline that turns connection records into evidence-backed host
contexts, enriches the entities in them, triages every context cheaply, analyses
the ones that warrant it, and emits the result — with the provenance, versioning
and honest gap-reporting that make each verdict inspectable and each run
reproducible.

## The research questions

The project exists to answer questions, not only to ship software. Each is meant
to be answered by an experiment, not by argument.

- Can a short, bounded host context built from connection metadata carry enough
  information for a useful threat assessment?
- Can cached, provenance-tracked entity enrichment be kept fresh and
  conflict-preserving at stream rates?
- Does a local LLM assessment improve on deterministic signals and a classifier
  baseline in accuracy, escalation rate, latency and cost?
- Can an autonomous Analyst Agent turn evidence gaps into bounded retrieval that
  measurably improves verdicts or reduces false positives?
- Does cheap triage in front of expensive analysis materially reduce the cases
  reaching the Analyst Agent, without suppressing high-confidence deterministic
  detections?
- Can evidence-cited assessments be replayed reproducibly from versioned inputs,
  models, prompts and policy?
- Does analyst-initiated cloud investigation answer questions the local pipeline
  left open, and on which kinds of case?
- Does cross-context memory measurably improve detection of multi-stage activity,
  or does it mainly add cost and anchoring bias?

**Most of these are not answerable yet**, because they are comparative
measurements and the labelled evaluation corpus does not exist.

**One confound is worth naming up front.** The same publisher supplies both the
bulk feeds behind triage and the live API the analyst queries. For any indicator
already in the tables, the analyst mostly re-confirms what triage saw. The delta
is real — freshness between snapshots, indicators added since the last load,
per-indicator context the export omits — but narrower than an independent second
opinion would be.

## Who it is for

| Actor | Relationship |
| --- | --- |
| **Security analyst** | The reason the system exists. Reads assessments and decides which cases to investigate. **No analyst workflow is built yet** — the analyst is served indirectly, through the output topic |
| **Downstream consumer** | Whatever reads the output topic — an operator with a Kafka client, a SIEM connector, a future UI or evaluation harness. The first version's actual audience |
| **Deployment operator** | Configures tenant and sensor identity, endpoints and credentials; runs the binaries; watches the counters |
| **Researcher / maintainer** | Runs increments and experiments and decides retain / refine / replace / discard. The primary user today |
| **Telemetry producer** | Publishes flow records. Outside the system boundary |

## Scope

**In scope for the project:** network connection telemetry, host-centred context
construction, entity enrichment, deterministic and learned detection, local and
cloud LLM assessment, bounded read-only investigation, findings and analyst
feedback, evaluation and replay.

**The first useful version is six stages and nothing beside them:**

| Stage | What it is |
| --- | --- |
| 1 ingest | Flow records over the Kafka wire protocol into the streaming engine |
| 2 context | One host context per host per 5-minute window, with entity rows beside it |
| 3 enrich | A join against snapshot-versioned reference tables producing enrichment evidence |
| 4 triage | A cheap rendering, one model call, no tools: `normal` or `suspicious` |
| 5 analyse | `suspicious` reaches the Analyst Agent, which retrieves live and returns a verdict |
| 6 emit | The enriched context, the verdict and the evidence leave through a sink topic |

**Deferred — not cancelled.** Each keeps its record, and the test for re-entry is
the test that governs entry: an experiment or a measured need, not a gap in a
diagram.

- the analyst feedback loop, and agent memory / dynamic infrastructure knowledge;
- a demonstration UI, a finding store, an evidence graph and a query API;
- the evaluation harness;
- a detection tier of rules and classifiers;
- threat-intelligence feeds beyond the first;
- context retention and freezing;
- the cloud Investigation Agent and its redaction gate;
- multi-tenancy *enforcement* — tenant and sensor are stamped on every event and
  carried through, but the isolation machinery is not built.

**Out of scope for the system entirely:**

- autonomous blocking, containment or remediation;
- endpoint, memory or file-based malware analysis; malware download or detonation;
- sending unrestricted raw telemetry to cloud models or public services;
- treating an LLM verdict as the only escalation or suppression control;
- generating and deploying network detectors — that is a sibling project's job.

A "Response Agent" performing containment is rejected **even as a future lane in
a diagram**. Widening that boundary is an explicit change to the concept.

## What the first version may and may not claim

**Claimable:** every verdict and explanation cites stored evidence; source
outages, stale evidence, invalid model responses and partial context are visible
rather than absorbed; a new enrichment source can be added without changing
identity, provenance or assessment contracts; no autonomous remediation occurs.

**Not claimable:** accuracy, recall, false-positive rate, escalation rate,
latency or cost; that triage reduces caseload without suppressing high-confidence
detections; that identical inputs replay identically.

> **The risk this accepts, stated plainly.** A pipeline built without an
> evaluation harness can be demonstrably *running* and undemonstrably *correct*.
