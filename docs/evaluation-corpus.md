# The evaluation corpus — what one would have to be, and what it would cost

`concept/08-open-questions.md` opens with the one unknown it calls *the one that
blocks everything*:

> A labelled, multi-host, time-correct evaluation corpus containing genuine
> malicious and multi-stage activity does not exist.

This file is the requirement that unknown implies, written down before anything
is built against it: **what a corpus would have to be** for the project's
measurements to mean anything, **what an evaluation over it would spend** against
the provider quota, and **which research question each missing piece blocks**.

Two things it is not.

- **It is not the evaluation harness.** The harness is deferred
  (`concept/01-goal-and-scope.md`, *Deferred — not cancelled*) and stays deferred.
  Nothing here reads a label, scores a verdict or compares an arm.
  `scripts/corpus_sizing.py` computes what an evaluation would cost; it does not
  run one. Partially building a harness against a corpus that does not exist would
  fix the harness's shape around guesses about the corpus, which is the wrong
  order.
- **It is not a claim that a corpus is coming.** Acquiring one is outside this
  project's control. What is inside it is being precise about what would be
  needed, so that a corpus offered later can be checked against something written
  down rather than accepted because it is the only one available.

Everything numeric below is either measured — with the date and the artifact — or
computed by `scripts/corpus_sizing.py` from `config/policy.toml`.
`tests/test_evaluation_corpus.py` recomputes every table here on every run, so a
budget change that moves a ceiling fails this document rather than leaving it
quietly wrong.

```bash
make corpus-sizing                                    # the ceiling, against our own rate limit
uv run scripts/corpus_sizing.py --daily-quota 500     # ... against a published quota
uv run scripts/corpus_sizing.py --daily-quota self-imposed --snapshot
```

---

## 1. The labelling scheme

**The unit of a label is the unit of an assessment: one context.** A context is
`(tenant, sensor, host, window_start)` at a `context_version`, which is what
`helena.orchestration` writes an assessment row against and what the output
message carries. A corpus labelled at any other granularity — per flow, per host
per day, per incident — cannot be joined to the thing the pipeline produces
without an interpretation step, and an interpretation step is where a measurement
quietly becomes an opinion.

**A label records the context version it was made against.** Context identity is
*stable across revisions* (`concept/07-principles.md`, settled 2026-09-04): a late
record folds into a context that already exists and the counters change in place
while the id does not. So a label attached to an id alone is a label attached to
whatever that context last became — someone labels a context of three flows and
scores it against a context of three hundred. The version is the whole of the fix
and it costs one column.

**The vocabulary is `helena.taxonomy.v1`, and the label records
`taxonomy_version`.** Ground truth is one of `CONTEXT_ROOTS` — `normal`,
`suspicious`, `malicious`, `unknown` — optionally narrowed to a path
(`malicious.c2`, `suspicious.low_reputation`, …). A corpus in its own vocabulary
would need a mapping onto this one, and a mapping is a place to hide
disagreement. The taxonomy is versioned and a revision is a new module rather than
an edit (`docs/decisions/0008-version-registry.md`), so a label naming its version
stays interpretable after one.

**`unknown` is a label, not a gap.** A labeller who could not decide records
`unknown`, and `unknown` is excluded from the denominator of a scored metric
rather than folded into `normal`. This is the `stale` / `failed` / `missing` /
`no_match` rule (`concept/instruction.md` §2) applied to ground truth, and the
base rate (§6) is what makes it expensive to get wrong: folding `unknown` into
`normal` inflates exactly the class that is already overwhelming.

**Four states the label must be able to tell apart**, because a two-valued label
cannot and every comparative question needs the distinction:

| | The host's behaviour | The evidence available at event time |
| --- | --- | --- |
| 1 | benign | an enrichment claim existed (a listed but harmless destination) |
| 2 | benign | nothing was listed — `no_match` |
| 3 | malicious | an enrichment claim existed |
| 4 | malicious | **nothing was listed** |

Case 4 is the only one that measures whether the assessment adds anything over the
feed, and case 1 is the only one that measures over-alerting on listed-but-benign
infrastructure. A corpus that cannot separate them can answer *did the pipeline
agree with the feed*, which nobody needs a pipeline for.

**Labels for the citations, not only for the verdict.** The project's first
claimable property is that every verdict cites stored evidence
(`docs/acceptance.md`, CLAIM-1). Scoring only the root would give full marks to a
verdict that was right for reasons it did not cite, and the traceability
commitment is the thing the project exists for. So the corpus carries, beside the
context label, a truth value per entity in it — *was this address / name / URL
malicious at this time* — and a scored run reports agreement at both levels.

**Provenance, and a measured agreement rate.** Every label records who or what
produced it, when, and from what: a confirmed incident, a controlled detonation,
a synthetic injection with a known ground truth, an analyst's judgement. A sample
is labelled twice by different labellers and the agreement is **measured and
recorded**, not asserted — a corpus whose own labellers disagree 20 % of the time
cannot demonstrate a 10 % difference between two models. Labels are versioned and
corrected by addition, never by edit, for the same reason an assessment is
(`concept/07`: facts are appended, inference never overwrites).

**Where labels live.** In the single store, as typed rows, keyed by context id and
version — `concept/instruction.md` §2 admits no second store, and a corpus in a
spreadsheet beside the engine is exactly the second store that rule names. This
is a requirement on the deferred harness, recorded here so that the harness does
not decide it by accident.

---

## 2. Host and time coverage

**Multi-host is not a preference.** The host key is the source address
(`concept/08`, assumptions in force), so a host that appears only as a destination
gets no context at all, and lateral movement — one host reaching another inside
the same capture — is only visible if both are sources in the same corpus. A
single-host capture can measure rendering and cost; it cannot measure detection.

**What one real network day is, measured.** `data/demo/20250920`, 2026-09-05: 143
captures, 239 850 records, **3 199 source addresses**, 23.97 hours, producing
**12 089 contexts** across 287 five-minute windows — 1.3 % of that grid, because a
context exists only where a host sent something. Entity rows per context are a
distribution and not a number: **median 1, p90 3, p99 441, max 1 822**. The day's
**2 490 distinct names** collapse to 726 registrable domains.

Those numbers are the anchor `scripts/corpus_sizing.py` reports against, and they
say two things about coverage. Most contexts are nearly empty, so the corpus's
size in contexts overstates how much is in it; and the tail is two orders of
magnitude above the median, so a corpus that misses the busy hosts misses exactly
the contexts triage exists for.

**How much is enough is a function of the base rate, and the base rate is
unmeasured.** §6 has the arithmetic: 62 labelled positives for a ±10 % interval on
a rate near 0.8, which at a 0.1 % base rate is 62 000 contexts — about **five days
of the measured network**, and at a 1 % base rate about half a day. The honest
statement is therefore conditional: *the corpus must hold enough positives for the
interval the claim needs*, and nobody can convert that into a number of hours
until somebody has measured how often anything is there at all.

**Continuity matters as much as volume.** A diurnal baseline needs contiguous
days rather than sampled hours: "this host does this every night at 02:00" is not
visible in an hour of traffic, and the six-hour slice of the measured day peaked
at 795 entity rows where the whole day peaked at 1 822 — the tail needs the whole
day to see.

**The retention boundary is a parameter of an evaluation, not a constant.** The
shipped horizon is 24 hours (`sql/migrations/0009_retention_boundary.sql`, a
candidate rather than a decision), and it is why the measured day produces *no*
retained contexts at all: every one of them is outside the horizon, the retained
view is empty and `helena_signal_retention_rejections` reports the rate. An
archived corpus is by definition old, so an evaluation either moves the horizon or
measures nothing. Moving the horizon is not the same as shifting the capture's
timestamps — see §4.

---

## 3. Multi-stage activity

The project's stated reason for existing is the case where *"the decisive evidence
is a pattern across several windows rather than a single hit"*
(`concept/01-goal-and-scope.md`). Two of the eight research questions are about
exactly that, and neither can be answered by a corpus of independently labelled
contexts.

**The corpus needs an episode identifier**: a label that says *these contexts, on
these hosts, in this order, are one activity* — delivery, then beaconing, then
exfiltration. Without it there is no ground truth for "multi-stage", and the
question about cross-context memory has nothing to be measured against.

**The stages are taxonomy paths, not a new vocabulary.** An episode is a sequence
of per-context labels drawn from `MALICIOUS_PATHS` — `malicious.payload`,
`malicious.c2`, `malicious.exfiltration` — so the episode adds a grouping and an
order, and invents no second classification scheme to reconcile.

**The decisive window is marked.** For each episode the corpus records which
context, or contexts, carried the evidence a correct verdict depends on. That is
what turns two otherwise unanswerable questions into measurements:

- **Window coherence** — how often the decisive evidence is split across a
  5-minute tumbling boundary, which `concept/08` lists as the trigger for
  revisiting the window length and which cannot be computed without knowing where
  the evidence was.
- **Single-window sufficiency** — what fraction of episodes are detectable from
  one context alone. That fraction is the ceiling on what the pipeline as built
  can achieve, because triage sees one context and nothing else; anything above it
  requires the deferred cross-context memory, and anything below it is not a
  memory problem.

**An episode may span hosts.** One host downloads, another beacons. The episode
identifier therefore groups contexts across hosts, and a corpus that labels hosts
independently cannot express it.

---

## 4. Time correctness

A corpus is a set of records *and* the state of the world when they were captured.
The second half is the one that is missing, and it is not recoverable later.

**Measured, 2026-09-12, over the snapshot in `data/threatfox/`
(`uv run scripts/corpus_sizing.py --daily-quota self-imposed --snapshot`):** the
export holds **4 095 entries whose last activity falls between 2026-08-31 and
2026-09-02** — a **two-day span**. **3 104 of them were first seen before that
window** and are in the export because they were seen again; the rest are new in
it. The "recent" export is therefore a *sighting window*, not a listing: an
indicator listed a year ago and quiet since is on neither the export nor,
per `docs/decisions/0028-the-threatfox-hunting-api.md` §7, the live API.

Three consequences, and they are the whole of this section:

1. **A corpus must be captured and enriched contemporaneously.** Enriching
   2025-09-20 traffic with a 2026-09 snapshot is not "slightly stale" — the entire
   contents of the snapshot post-date the traffic by a year, so every join result
   is meaningless in both directions. Nothing in this repository archives past
   exports, so a corpus captured today cannot be enriched retroactively, and one
   captured tomorrow must have its snapshot kept beside it.
2. **The snapshot is part of the corpus.** `concept/07` already requires an
   assessment to record `enrichment_snapshot_version`, and replay to validate
   against the version the assessment recorded. A corpus that keeps the traffic
   and not the snapshots can be replayed only against whatever the feed says
   later, which is a different experiment with the same name.
3. **Timestamps may not be shifted.** `scripts/measure_rendering.py` deliberately
   shifts a capture forward by whole windows to get past the retention boundary,
   and it is right to for sizing a rendering. For an evaluation it is fatal: it
   moves event time away from snapshot time and destroys the correspondence this
   section is about. An old corpus needs the horizon moved (§2), not the clock.

**What time-correct means for a label, too.** Case 3 and case 4 of §1's table are
distinguished by *what was listed at event time*, so the labeller needs the
snapshot as it was, not as it is. A label written against today's feed about last
year's traffic is measuring the feed's memory.

---

## 5. The quota ceiling

`concept/08`: *"the live provider's daily quota must be sized against the corpus
**before the corpus is chosen**, or the comparison's arms stop being
contemporaneous."* This is that sizing.

**The inputs, none of them invented.** The analyst's live-query budget is **8 per
run** — derived by `helena.budgets.load()` from the 120 retrieval seconds and the
4 queries/minute in `config/policy.toml`, and enforced at the tool boundary. The
rate the tool layer holds itself to is **4/minute**, which is a self-imposed
ceiling under fair-use terms that publish no number. **abuse.ch publishes no daily
quota at all**, so `scripts/corpus_sizing.py` has no default for one: it takes the
published number, or `self-imposed` for the ceiling the rate implies, which is
**5 760/day** run flat out for 24 hours. The one published daily quota this
project holds is VirusTotal's **500/day** (`.env`, `prds/CONTEXT.md` §3), and
VirusTotal is a deferred provider.

**What one measured network day would spend**, at 8 live queries per analyst run
and 4/minute:

| Escalation | Analyst runs | Live queries | Retrieval at 4/min | Days of 5 760/day | Days of 500/day |
| --- | --- | --- | --- | --- | --- |
| 1 % | 121 | 968 | 4.0 h | 0.17 | 1.94 |
| 5 % | 605 | 4 840 | 20.2 h | 0.84 | 9.68 |
| 10 % | 1 209 | 9 672 | 40.3 h | 1.68 | 19.34 |
| 100 % | 12 089 | 96 712 | 403.0 h | 16.79 | 193.42 |

**The escalation rate is not a measurement.** Nothing has run against labelled
outcomes, so the fraction of contexts triage sends to the analyst is unknown; the
table shows what each would cost rather than picking one. That unknown is itself
one of the research questions (§8, RQ5).

**The ceiling, stated as the task asks:**

| Daily quota | Analyst runs a day | Contexts a day at 1 % | at 5 % | at 10 % | at 100 % |
| --- | --- | --- | --- | --- | --- |
| 5 760 (self-imposed) | 720 | 72 000 | 14 400 | 7 200 | 720 |
| 500 (a published quota) | 62 | 6 200 | 1 240 | 620 | 62 |

**Four things follow, and they constrain any evaluation before it is designed.**

- **Retrieve once and replay for every other arm.** A comparison of *k* arms that
  each retrieve live costs *k* times the table above, and the later arms are no
  longer contemporaneous with the earlier ones — the feed moved underneath them.
  `helena.tools.ProviderTool`'s replay mode exists and refuses to reach the network
  (`docs/decisions/0031-replay-at-the-tool-boundary.md`), so the design is: one
  retrieval pass, stored responses, every other arm replayed. This is the single
  largest lever on the quota in this document.
- **The cache bound is the real one, and it is lower.** A hit costs no quota and a
  negative result *is* cached (`docs/decisions/0025-the-lookup-cache.md` §3), so the
  live queries an evaluation spends are bounded by the corpus's **distinct**
  indicators, not by runs × 8. On the measured day the whole network produced 2 490
  distinct names; the cache is what stands between a sparse corpus and paying for
  the same miss repeatedly. It is also why the retrieval pass must be one pass:
  cache entries expire per source and endpoint, and an evaluation spread over
  weeks re-pays for what it already knows.
- **Adding an independent source lowers the ceiling by an order of magnitude.**
  §7's confound is answered by querying an organisation other than abuse.ch, and
  the one this project has a credential for is VirusTotal at 500/day — 62 analyst
  runs a day against 720. The experiment that removes the confound is the one the
  quota binds hardest.
- **The provider quota is not the only ceiling, and the other one is unmeasured.**
  Triage runs on *every* context — 12 089 model calls for one network day, at 8 000
  tokens each — and the model endpoint's rate limits are listed as unconfirmed in
  `concept/08`. The number above sizes provider queries only.

---

## 6. The base rate

Stated plainly, because it is the hazard most likely to produce a number that
looks like a result:

> **Coverage is sparse; most contexts have no hit on anything. A classifier that
> always answers `normal` will score well on accuracy and be worthless.**

The measured shape of the sparsity: a feed snapshot of **4 095 indicators over a
two-day sighting window** (§4) against **12 089 contexts from 3 199 hosts** in one
network day (§2), where the median context holds **one** entity row. Nobody has
measured the overlap — the one multi-host capture in this repository is from
2025-09-20 and the one feed snapshot covers 2026-08-31 to 2026-09-02, so a hit
rate computed between them would be an artefact of the year between them and not a
base rate. **That measurement is itself blocked by the corpus**, which is the
point: the hazard cannot be quantified in advance, so it has to be designed around.

**What follows for any evaluation over this corpus:**

- **Accuracy is not reported alone**, and never as the headline. Per-class recall
  and precision, the escalation rate, and the confusion matrix are what a sparse
  problem is scored with.
- **The always-`normal` baseline is scored in every run and printed beside the
  result.** Not discussed — computed, from the same labels, in the same table. A
  model that does not beat it has not done anything, and the cheapest way to
  notice is to make it impossible to omit.
- **The deterministic arm is a baseline, not a control.** `helena.policy.v1`
  escalates a high-confidence tier-A or tier-B match independently of triage, so
  "does the LLM improve on deterministic signals" is a comparison against a
  baseline that is already in the pipeline and already escalating.
- **The corpus is sized by its positives, not by its contexts.**
  `scripts/corpus_sizing.py` computes it: **62 labelled positives** for a 95 %
  interval of ±10 % on a rate near 0.8, **246** for ±5 %. At a 0.1 % base rate that
  is 62 000 contexts — five days of the measured network — and at 1 %, 6 200.
- **Case 4 of §1's table is the measurement that matters.** On a sparse corpus,
  agreeing with the feed is cheap; the question is what the pipeline says where the
  feed is silent.

---

## 7. The retrieval confound

> **One organisation feeds both tiers, so analyst retrieval mostly re-confirms
> what triage saw. Know what the experiment is measuring before it runs, not after
> it produces a number.**

This one is **measured rather than argued**
(`docs/decisions/0028-the-threatfox-hunting-api.md` §7). Three indicators — one
domain, one `ip:port`, one URL — present in the committed snapshot were asked of
the hunting API on 2026-09-10. For all three, **every field the two surfaces share
was identical**: same record id, threat type, malware, confidence, first seen,
compromised flag, reporter. N = 3, and the sample is small because each comparison
spends a live query against a fair-use service; what makes it more than three data
points is that the export is a dump of the same dataset, so agreement is the
structural expectation.

**So an analyst-tier ThreatFox lookup about an indicator triage already saw adds
nothing to the classification, the confidence or the scope.** What it does add is
short and specific: freshness between snapshot loads, the `sightings` count the
export does not carry, and — cutting the other way — nothing at all for an
indicator the publisher has expired, which the §4 measurement shows is most of
what a year-old capture would need.

**What an experiment over this corpus is therefore measuring**, if it is not
designed around the confound: *the value of a fresher copy of the same data*. Not
the value of a second opinion. The consequences for a comparative evaluation:

- **`source_diversity` counts by `source_id` and both tiers carry `threatfox`**
  (`helena.enrichment`), so two agreeing claims about one indicator are correctly
  counted as one source agreeing with itself. That arithmetic is right today and
  has to stay right; an evaluation that silently counted them as two would report
  corroboration that does not exist.
- **The analyst arm's measurable delta is the freshness window**, which is bounded
  by the loader's own schedule. An evaluation whose snapshot is loaded immediately
  before the run has designed the delta down to nearly zero and will measure
  nothing; one whose snapshot is deliberately aged is measuring the loader's
  schedule, which is a legitimate experiment provided it is called that.
- **Answering "does live retrieval improve verdicts" in general needs a second
  organisation**, and that is a quota decision before it is an experiment design
  (§5): the independent source this project holds a credential for costs an order
  of magnitude more per query.

---

## 8. The research questions, and what each is blocked on

The eight questions are `concept/01-goal-and-scope.md`'s, verbatim.
`tests/test_evaluation_corpus.py` parses that note on every run, so a question
added, reworded or removed there fails here until this section is brought across
with it. Each has the measurement that would answer it, and the blocker that
prevents the measurement today.

**RQ1 — Can a short, bounded host context built from connection metadata carry
enough information for a useful threat assessment?**

- *Measurement:* verdict agreement with the label, per class, over labelled
  contexts, reported against the rendering's truncation record — the contexts
  where the budget dropped records are where "short and bounded" is being tested,
  and `helena.rendering` already makes truncation visible and countable.
- *Blocker:* no labels. The rendering and its budget exist and are measured
  (`docs/decisions/0019-the-rendering-size-budget.md`); what is missing is anything
  to score the verdict against.

**RQ2 — Can cached, provenance-tracked entity enrichment be kept fresh and
conflict-preserving at stream rates?**

- *Measurement:* the two halves are separable. *Conflict-preserving* is testable
  today — contradictory claims from two sources about one entity, both surviving to
  the rendering — and does not need the corpus. *Fresh at stream rates* needs a
  corpus that arrives at a rate, with snapshots loading beside it, so that the
  staleness distribution at assessment time can be measured rather than configured.
- *Blocker:* partial. The freshness half needs a corpus that is a stream and not a
  file, and the shipped horizon (§2) means it must be recent traffic.

**RQ3 — Does a local LLM assessment improve on deterministic signals and a
classifier baseline in accuracy, escalation rate, latency and cost?**

- *Measurement:* three arms over identical contexts — `helena.policy.v1`'s
  deterministic escalation alone, a classifier baseline, and triage — scored on
  per-class recall and precision, escalation rate, latency and derived cost, with
  the always-`normal` baseline printed beside them (§6).
- *Blocker:* labels, and two absent arms — **no classifier tier exists** (deferred,
  `concept/01`) and no cost figure is derivable while `[model_prices]` is empty.
  Model selection and threshold calibration hang off this question and are blocked
  with it.

**RQ4 — Can an autonomous Analyst Agent turn evidence gaps into bounded retrieval
that measurably improves verdicts or reduces false positives?**

- *Measurement:* the same contexts assessed with and without the analyst stage,
  compared on false positives and on verdicts that changed, with the retrieval
  trace beside each change so that an improvement can be attributed to what was
  retrieved.
- *Blocker:* labels **and the confound** (§7). On this provider set the measured
  delta is freshness, not a second opinion, so the experiment must either be named
  as a freshness experiment or wait for an independent source — which the quota
  binds hardest (§5).

**RQ5 — Does cheap triage in front of expensive analysis materially reduce the
cases reaching the Analyst Agent, without suppressing high-confidence
deterministic detections?**

- *Measurement:* the escalation rate, and the count of high-confidence
  deterministic matches that triage answered `normal` on. The second half is
  **already structurally impossible** — `helena.policy.v1.escalate` runs
  independently of triage and a `normal` cannot suppress it, enforced by
  `tests/test_conformance.py` — so what the corpus adds is the *rate* half: how
  much caseload triage actually removes, and at what cost in missed positives.
- *Blocker:* labels, for the missed-positive half. The rate half needs only
  representative traffic and is the cheapest measurement in this list.

**RQ6 — Can evidence-cited assessments be replayed reproducibly from versioned
inputs, models, prompts and policy?**

- *Measurement:* replay every stored assessment and compare the reconstructed
  result field by field; report the fraction that reproduce and the fields that
  differ when they do not.
- *Blocker:* **not the corpus.** This one needs assessments, not labels, and the
  machinery exists (`helena.orchestration`'s replay, the nine version columns, the
  tool-boundary replay guard). What is unmeasured is the *rate* over a population
  of real runs, because no population of real runs exists yet. `concept/01` still
  refuses the claim that identical inputs replay identically, and it is right to:
  a non-deterministic model is expected to differ, and the measurement is how
  often and where.

**RQ7 — Does analyst-initiated cloud investigation answer questions the local
pipeline left open, and on which kinds of case?**

- *Measurement:* cases where the local pipeline returned `unknown` or a gap,
  investigated with the cloud tier, scored on how many resolved and into what.
- *Blocker:* **the component, before the corpus.** The cloud Investigation Agent
  and its redaction gate are deferred (`concept/01`), so there is nothing to
  measure; the corpus is the second blocker, not the first.

**RQ8 — Does cross-context memory measurably improve detection of multi-stage
activity, or does it mainly add cost and anchoring bias?**

- *Measurement:* episode-level detection with and without memory (§3), plus the
  anchoring half — how often a prior context's verdict changes the verdict on a
  context whose own evidence did not change. The second half is what makes this a
  question rather than an assumption, and it needs episodes with a known decisive
  window.
- *Blocker:* episode labels (§3) **and** the component — agent memory is deferred,
  and `concept/07`'s ephemeral-state rule means anything that remembers is a
  design decision this project has not made.

**The pattern across all eight.** Two are blocked by a missing component before
they are blocked by the corpus (RQ7, RQ8). One is not blocked by the corpus at all
and is waiting on a population of runs (RQ6). One is half-answered structurally
today (RQ5). The remaining four are blocked squarely on labels, and no amount of
building changes that.

---

## 9. What stays deferred, and what it would take to start

**Deferred, and still labelled deferred:**

| Thing | Why it is not built |
| --- | --- |
| The evaluation harness | There is nothing to evaluate against. Building it now would fix its shape around guesses about a corpus's schema, its labels and its size |
| A classifier baseline tier | `concept/01` defers the detection tier; RQ3's second arm needs it |
| Cross-context memory | Deferred, and RQ8 needs it before it needs episodes |
| The cloud Investigation Agent | Deferred, and RQ7 needs it before it needs the corpus |
| A second, independent provider | VirusTotal is deferred and its quota is the binding constraint (§5) |

**What `scripts/corpus_sizing.py` is, precisely:** three arithmetic reports and a
snapshot reader. It computes the envelope, the ceiling, and the positives a
confidence interval needs. It reads no label, runs no stage and scores nothing.
Calling it the beginning of the harness would be the maturity-label drift
`concept/instruction.md` §5 warns about.

**What would have to be true before a corpus is accepted**, as a checklist:

- [ ] Labels at context granularity, carrying `context_version` and
      `taxonomy_version`, in `helena.taxonomy.v1`'s vocabulary (§1).
- [ ] `unknown` present as a label and excluded from scored denominators (§1).
- [ ] Entity-level truth beside context-level truth (§1).
- [ ] Label provenance, and a measured inter-labeller agreement rate (§1).
- [ ] More than one host, and enough positives for the interval the claim needs
      (§2, §6).
- [ ] Contiguous time, not sampled hours, with a stated retention horizon (§2).
- [ ] Episode identifiers, stage labels and a marked decisive window (§3).
- [ ] The feed snapshots that were current at event time, kept beside the traffic
      (§4).
- [ ] Unshifted timestamps (§4).
- [ ] A retrieval plan that fits the quota: one live pass, every other arm replayed
      (§5).
- [ ] A scoring plan that reports the always-`normal` baseline beside the result
      (§6).
- [ ] A stated answer to what the analyst arm is measuring, given the confound
      (§7).

Until then, `concept/01-goal-and-scope.md`'s refusal stands unchanged: accuracy,
recall, false-positive rate, escalation rate, latency and cost are **not
claimable**, and the pipeline is demonstrably running and undemonstrably correct.
