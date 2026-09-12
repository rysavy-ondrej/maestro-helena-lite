# The deferred register

Maturity: `stable` as a register — it is complete against
`concept/01-goal-and-scope.md`'s *deferred — not cancelled* list, and
`tests/test_governance.py` fails if a module declares `Maturity: deferred`
without naming a key below, or if an entry loses its re-entry test.

**Deferred means decided and recorded, deliberately not built yet.** It is a
maturity label with a meaning (`concept/instruction.md` §5) and it is the label
that makes the others mean something: *"a deferred component that loses its label
makes every other label a lie."*

`concept/01` sets the bar for coming back, and this register exists to hold each
capability to it:

> Each keeps its record, and **the test for re-entry is the test that governs
> entry: an experiment or a measured need, not a gap in a diagram.**

So every entry below carries a **re-entry test** that is falsifiable. "It would be
useful", "the diagram has a box for it" and "a reviewer asked" are not re-entry
tests and are refused here on purpose. Several entries' re-entry tests depend on
the evaluation corpus, which does not exist — that is the honest answer and not a
drafting failure.

An entry names what **exists instead**, where that is a seam rather than nothing,
because mistaking a seam for a guarantee is the specific way this register fails.

---

## 1. The analyst feedback loop

Key: `analyst-feedback-loop`
Recorded in: `concept/01-goal-and-scope.md`; `concept/05-threat-intelligence.md`
(the false-positive list, as *evidence about evidence*)

**What it is.** An analyst's judgement on a finding entering the system as
evidence — including an upstream publisher's false-positive list, which is the
same shape arriving from outside.

**What exists instead.** The rule the loop would have to obey is already written
and is the hard part: *a claim is never deleted, suppression is explicit policy,
and a suppressed match is still recorded as having matched* — **not** a quiet
filter before anything sees it. `helena.disclosure` and `helena.policy` are where
an entry would land; both record rather than filter.

**Measured 2026-09-10:** ThreatFox publishes **no** false-positive feed on either
surface this project can reach — three plausible operation names each answered
`unknown_operation`, and the export offers JSON, CSV, MISP, RPZ, host-file and
Suricata and no FP file. What the publisher does instead is *expire* IOCs, and an
expired IOC is simply absent from both surfaces, which is a deletion and is
exactly the mechanism the design forbids. So this is **deferred for absence of
the artifact, not for effort** ([0028 §8](decisions/0028-the-threatfox-hunting-api.md)).

**Re-entry test.** A source of feedback that exists as an artifact — a published
FP list, or a human workflow producing judgements at a rate worth ingesting —
**and** a measured disagreement rate between it and the stored claims. Without
the second, suppression policy is uncalibrated by construction.

## 2. Agent memory and dynamic infrastructure knowledge

Key: `agent-memory`
Recorded in: `concept/01-goal-and-scope.md`; `concept/03-architecture.md`
(file-backed agent memory as the convenient default)

**What it is.** Knowledge accumulated across runs — that this address is the
organisation's own resolver, that this `*.trafficmanager.net` name is normal
here.

**What exists instead.** Ephemeral state, and that is a decision rather than a
lack: `concept/07`'s working memory is *"for one assessment, never the durable
record"*, and re-run is the whole of recovery
([0034](decisions/0034-ephemeral-state-and-re-run.md)). The single-store rule
names this capability's obvious implementation as the thing it forbids — **no
file-backed agent memory** — so memory would have to be typed rows in the engine,
and then it is reference data with a snapshot version like any other.

**Re-entry test.** A measured error attributable to the *absence* of cross-run
knowledge: a set of assessments the pipeline got wrong that a stated, storable
fact would have fixed. Needs the corpus. Until then, an agent memory would be an
unversioned second opinion competing with the reference tables.

## 3. The demonstration UI

Key: `demonstration-ui`
Recorded in: `concept/01-goal-and-scope.md`; `concept/03-architecture.md` (*"the
output topic replaced the UI as the delivered surface"*)

**What it is.** A screen showing contexts, verdicts and evidence.

**What exists instead.** The output topic, the engine's SQL, `helena.status` and
`docs/runbook.md`. `concept/03` is explicit that the absence of any HTTP surface
is *"a consequence of the deferrals, not an oversight"*, and adding one is an
escalation (`concept/instruction.md` §3).

**Re-entry test.** A demonstration that the output topic and SQL cannot serve —
named, with what it has to show. A UI is also a new egress surface, so it is an
escalation regardless of how small it looks.

## 4. The finding store

Key: `finding-store`
Recorded in: `concept/01-goal-and-scope.md`; `concept/03-architecture.md` (its API
is deferred with the UI)

**What it is.** Findings as first-class durable objects with a lifecycle — open,
triaged, closed — as distinct from assessments, which are what a run produced.

**What exists instead.** Assessments are typed rows with citations as join rows
([0033](decisions/0033-assessment-persistence.md)) and they are durable. What is
missing is *state over time*: nothing reopens, merges or closes anything.

**Re-entry test.** A consumer that needs finding state the assessment rows cannot
express, **and** an answer to the question `concept/08` leaves open beside it — a
finding already issued may cite a `context_id` whose counters have since changed
in place, and what that means for the finding is unsettled. Building the store
first would freeze that question in a schema.

## 5. The evidence graph

Key: `evidence-graph`
Recorded in: `concept/01-goal-and-scope.md`

**What it is.** Entities, claims and findings as a traversable graph — this
address and that domain and the host that reached both.

**What exists instead.** The relational shape the graph would be built over:
`host context 1—n entity 1—n enrichment evidence`
([0009](decisions/0009-netify-application-identification.md)), with citations as
join rows. A graph query over it is a join.

**Re-entry test.** A question that has been asked and cannot be answered by a
join over the existing rows. Note the standing constraint: a graph **database**
is a second store and is refused (`concept/instruction.md` §2), so re-entry means
graph *queries*, not a graph engine.

## 6. The query API

Key: `query-api`
Recorded in: `concept/01-goal-and-scope.md`; `concept/03-architecture.md` (the
interfaces table)

**What it is.** A programmatic read surface over contexts, evidence and verdicts.

**What exists instead.** The engine's PostgreSQL wire protocol, which *is* a query
API — it is in `concept/03`'s interfaces table as a delivered surface.

**Re-entry test.** A consumer that cannot speak the PostgreSQL wire protocol and
whose need is measured rather than assumed. A new HTTP surface is an escalation.

## 7. The evaluation harness

Key: `evaluation-harness`
Recorded in: `concept/01-goal-and-scope.md`; `docs/evaluation-corpus.md`
(the requirement and its twelve-item acceptance checklist)

**What it is.** The thing that reads labels, scores verdicts and compares arms.

**What exists instead.** Its **requirement**, written in full, and
`scripts/corpus_sizing.py`, which computes the corpus size and the provider quota
ceiling from `config/policy.toml` rather than from a number in a document.
`docs/evaluation-corpus.md` is the requirement and not the beginning.

**Re-entry test.** The corpus. This is the one entry whose re-entry test is a
single external artifact, and it is the blocker `concept/08` puts above every
other: *"it does not block building the pipeline. What it blocks is the claim
that the pipeline is right."*

**Executable half:** `tests/test_evaluation_corpus.py::test_the_harness_is_still_deferred`
fails if `concept/01` stops deferring it, if the document stops saying so, or if a
module named for one appears inside `helena/`.

## 8. The detection tier

Key: `detection-tier`
Recorded in: `concept/01-goal-and-scope.md`

**What it is.** Rules and classifiers producing detections before or beside
triage.

**What exists instead.** Deterministic escalation, which is the part of a
detection tier that the invariants *require* rather than defer: a high-confidence
Tier A or B match escalates independently of triage, and a model's `normal` may
not suppress it ([0023](decisions/0023-deterministic-escalation.md)). That is a
rule tier of exactly one rule shape, on purpose.

**Re-entry test.** A measured class of activity that enrichment plus triage
misses and a stated rule catches — measured, so it needs the corpus. Note the
boundary: **generating and deploying network detectors is a sibling project's
job** and is out of scope for the system entirely, not deferred.

## 9. Threat-intelligence feeds beyond the first

Key: `further-feeds`
Recorded in: `concept/01-goal-and-scope.md`; `concept/05-threat-intelligence.md`
(the catalogue, which is kept *"because it is where the next feed comes from"*)

**What it is.** The eight-odd catalogue entries marked deferred — national CERT
warning lists, URLhaus, Feodo Tracker, Spamhaus DROP, Emerging Threats
compromised IPs, the Tor exit list, cloud and CDN ranges, domain popularity.

**What exists instead.** Two registered sources (`threatfox` Tier B, `sslbl-ja3`
Tier C), one built reference dataset (the Public Suffix List, tier N/A) and one
admitted local snapshot (Netify, Tier D). Crucially, the *shape* does not assume
one feed: one snapshot ledger for every source
([0044](decisions/0044-the-snapshot-scheme.md)), per-source tier, emit subset and
refresh schedule, and per-source thresholds with **no default**
(`config/policy.toml`). `docs/sources/` is one record per source.

**Re-entry test.** For each: a fetched artifact, counted — `concept/05`'s own
lesson is that *"the narrowest feed"* turned out to have five rows, so the join
would never have fired. Plus a licence or agreement where one is needed. **Adding
a source is a governed decision, not a configuration convenience**, so it is an
escalation and it needs a record in `docs/sources/`.

## 10. Context retention and freezing

Key: `retention-and-freezing`
Recorded in: `concept/01-goal-and-scope.md`; `concept/07-principles.md`
(*"a context cited by a finding is copied out, never evicted"*)

**What it is.** Two halves, and only one is deferred.

**What exists instead.** The **temporal filter** is built:
`sql/migrations/0009_retention_boundary.sql` is a declarative, engine-enforced
predicate on the context views, not a delete; the horizon is also the late-record
tolerance, one parameter and not two; and the boundary **reports what it drops**
in `helena_signal_retention_rejections`, so a misconfigured horizon shows up as a
rejection rate. **24 hours is a candidate in the code, not a decision**, chosen to
be observed rather than committed to.

**What is deferred is freezing.** Nothing copies a cited context out before it
leaves the horizon, which is what makes a citation stable rather than merely
current. Measured 2026-09-04 (task 16): a late record *inside* the boundary does
still revise a retained context, with the `context_id` unchanged. **The boundary
crossing itself is untested** — a record arriving for a window that has just left
the horizon.

**Re-entry test.** A finding that outlives the horizon: the first citation whose
context would be filtered out while the finding still refers to it. That is also
the trigger `concept/08` names for the identity question beside it.

## 11. The cloud Investigation Agent and its redaction gate

Key: `investigation-agent`
Recorded in: `concept/01-goal-and-scope.md`; `concept/04-the-two-agents.md`;
`concept/03-architecture.md` (*"the redaction gate has nothing to gate yet"*)

**What it is.** A third, analyst-initiated agent: a human opens a case and works
it in the cloud. **The only cloud component in the design.**

**What exists instead.** Two agents, both local in the sense that matters — their
*decisions and control* are local. `concept/03` insists on the distinction this
entry is most often confused with: **a local pipeline is not zero network
egress.** Model prompts already leave the network, because inference is hosted,
and no document may describe the pipeline as running models locally while it does
not. Analyst-time provider queries leave too. Static enrichment is genuinely
zero-egress, and that property is conditional on holding a local copy of each
feed.

**The gate is deferred with the agent, and the obligation is not.** The sink
writes to the *local* broker, so no redaction is performed — but that is a
property of the deployment, not of the message: the payload contains internal
addresses, hostnames and retrieved external text, and **any consumer that
forwards it off-site inherits the redaction, minimization and disclosure
obligations. The pipeline cannot enforce that.**

**Re-entry test.** A question the local pipeline demonstrably leaves unanswered,
**and** the redaction gate, which cannot be deferred separately — the agent
without the gate is the escalation `concept/instruction.md` §3 forbids
(*sending unrestricted raw telemetry to cloud models* is out of scope entirely).
The model service's data-handling terms are also unconfirmed: `concept/08` says
check the terms before sending anything but a purpose-built replay dataset.

## 12. Multi-tenancy enforcement

Key: `multi-tenancy-enforcement`
Recorded in: `concept/01-goal-and-scope.md`; `concept/03-architecture.md`
(*"tenant isolation is a seam, not yet enforcement"*)

**What it is.** Scoped retrieval, per-tenant policy, isolation tests.

**What exists instead — and this is the entry most at risk of being read as a
guarantee.** `tenant` and `sensor` are stamped on every event and carried to the
output; every stored row **carries** them, and every ingest- and reference-layer
primary key **includes** them, so two deployments loading the same feed or
enriching the same entity cannot silently upsert over each other. The assessment
tables key on `assessment_id` instead — a sha256 taken **over** tenant and sensor
among other things, so there the isolation is in the digest rather than in the
key's columns. Every agent request is tenant-scoped by contract. **The isolation machinery is not built.** `concept/03` states this
"so the field's presence is not mistaken for a guarantee", and
`concept/instruction.md` §6 names the failure mode: *a defaulted tenant is an
isolation failure that looks like it is working* — which is why
`helena.config` fails at startup naming the variable rather than defaulting it.

Also standing: tenant and sensor come from **deployment configuration**, which
does not scale to multiple sensors sharing one normalizer (`concept/08`,
assumptions in force).

**Re-entry test.** A second tenant, or a second sensor, actually present in a
deployment. That is also the trigger for three other assumptions
`concept/08` parks on the same condition — the host key, sensor resolution, and
topic layout.

## 13. The second live provider (multi-engine reputation)

Key: `second-live-provider`
Recorded in: `concept/05-threat-intelligence.md` (*multi-engine reputation —
deferred, with a narrow role*); [0045](decisions/0045-who-decides-the-analyst-is-unsure.md)

**What it is.** Not a routine second opinion — **a last step**, consulted when the
analyst would otherwise be unable to settle a context. Two lookups only, address
and domain; no file, hash, relationship or graph queries; **no sample submission
ever**.

**What exists instead.** One live provider, the ThreatFox hunting API
([0028](decisions/0028-the-threatfox-hunting-api.md)), behind the tool layer's
send policy and budget guard. The credential is required configuration and its
quota is **deliberately unspent** —
[0004 §why `VIRUSTOTAL_AUTH_KEY` is required although VirusTotal is deferred](decisions/0004-configuration-variables.md).

**Re-entry test, two halves, and both are needed.**

1. A **measured need**: a set of runs that could not settle with the tables and
   the primary provider, and that a second opinion would have settled. The
   retrieval confound ([`hazards.md`](hazards.md) §3) is why this must be measured
   rather than assumed — the primary provider mostly re-confirms the tables, and a
   second organisation is the only thing that adds information.
2. An **engine-side daily ledger**. The free tier is a few hundred lookups per
   day *shared across every host the pipeline assesses*, and `RunBudget` is
   per-run and ephemeral by decision. A cross-run count must be typed rows in the
   engine; a file or a module-level counter is the second store
   `concept/instruction.md` §2 forbids. [0045](decisions/0045-who-decides-the-analyst-is-unsure.md)
   settles who decides the lookup happens: deterministic code, never a tool in
   the model's list.

**Also deferred beside it:** registration and infrastructure history (domain age
and registration pattern), whose registration fields are **the sharpest instance
of untrusted input in the project** — supplied by whoever registered the domain,
which in a malicious case is the adversary. `helena.untrusted` is the isolation it
would arrive through, and that isolation is built and tested
([0030](decisions/0030-untrusted-text-isolation.md)).

---

## What is *not* deferred, and must not be listed as if it were

`concept/01`'s *out of scope for the system entirely*, plus two rejections:

- autonomous **blocking, containment or remediation** — a "Response Agent" is
  rejected *even as a future lane in a diagram*;
- endpoint, memory or file-based malware analysis; malware download or
  detonation;
- sending unrestricted raw telemetry to cloud models or public services;
- treating an LLM verdict as the only escalation or suppression control;
- generating and deploying network detectors — a sibling project's job;
- **hosted tracing** — rejected, not deferred (`concept/03`, `concept/07`), and
  kept absent by `tests/test_dependency_boundary.py`;
- a **graph database**, a **vector store**, a **checkpoint store** and any
  file-backed state — the single-store invariant, kept by
  `tests/test_architecture_boundary.py`.

Moving anything from that list into this one is a change to the concept, not a
task.
