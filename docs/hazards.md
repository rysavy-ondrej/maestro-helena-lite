# Accepted hazards

Maturity: this file is `stable` in the sense that matters for a register — it is
complete against `concept/08-open-questions.md`'s *known hazards* table, and
`tests/test_governance.py` fails if that table grows an entry this file does not
have.

**These are not open questions and they are not to-do items.** They are risks the
concept must not be read as denying: each one is real, each one is accepted for a
prototype, and each one has a line saying what is actually done about it — which
for several is *nothing, and the claim is narrowed instead*.

An entry leaves this file when it stops being true, not when it stops being
convenient. If a hazard is mitigated, the mitigation is named here and the entry
stays, because the reason it was accepted is what a later reader needs.

---

## 1. The measurement gap

**A pipeline built without an evaluation harness can be demonstrably *running*
and undemonstrably *correct*.**

This is the parent of most of the others. The labelled corpus does not exist
(`concept/08`, first section), so accuracy, recall, false-positive rate,
escalation rate, latency and cost are **not claimable** — `concept/01` lists them
under *not claimable* and the project holds to that wording everywhere.

*What is done:* the requirement is written (`docs/evaluation-corpus.md`), the
harness stays `deferred` with an executable label test, and every artifact that
depends on a measurement says *unmeasured* rather than estimating. *What would
change it:* the corpus. Nothing else.

## 2. Silent record loss

**One record vanished at a catch-up boundary, and that class of silence has
already been caught once on the same broker in the other direction.**

`concept/08` draws the consequence and it is a claim ceiling, not a fix:
**replayability is a goal rather than a claim while that stands.**

*What is done:* emission is countable from the engine side rather than from the
broker ([0037](decisions/0037-at-least-once-emission.md),
[0038](decisions/0038-pipeline-metrics-and-reconciliation.md)), the retention
boundary reports what it drops (`sql/migrations/0009`), and quarantine is a typed
row in the store ([0013](decisions/0013-quarantine-in-the-single-store.md)) so
input drift surfaces. *What is not done:* nothing reproduces the original loss,
and the durability model says so — `docs/decisions/0040` closes the single
store's half of `concept/08`'s cross-cutting paragraph and explicitly **not** this
half.

## 3. The retrieval confound

**One organisation feeds both tiers, so analyst retrieval mostly re-confirms what
triage saw. Know what the experiment is measuring before it runs, not after it
produces a number.**

*Measured 2026-09-10, and it is now stronger than "mostly":* three indicators
present in the loaded snapshot — one `domain`, one `ip:port`, one `url` — were
asked of the hunting API, and **every field the two surfaces share was
identical**. Same record id, threat type, malware, confidence, first-seen,
compromised flag, reporter. The one field the API carries that the export does
not is `sightings`.

*What is done:* `source_diversity` counts by `source_id`, and both tiers carry
`threatfox`, so a ThreatFox analyst claim corroborating a ThreatFox enrichment
claim counts as **one** source agreeing with itself. That arithmetic has to stay
as it is. [0028 §7](decisions/0028-the-threatfox-hunting-api.md).

## 4. Concentration risk

**One provider supplies most of the prototype's threat intelligence; if its
terms, availability or coverage change, the evidence base changes with it.**

*What is done:* nothing that reduces it, and that is the honest answer — a second
feed is `deferred` ([`deferred.md`](deferred.md), *further feeds*) and the
smallest coherent slice is one feed working end to end. What exists instead is
that the source layer does not assume one: the tier, the declared emit subset and
the refresh schedule are per source (`helena.enrichment.SOURCES`), the snapshot
ledger is one table for every feed ([0044](decisions/0044-the-snapshot-scheme.md)),
and `missing` is a first-class status, so a provider going away is a visible
status rather than an empty table.

Also worth keeping in view: abuse.ch **changes its auth on its own schedule**.
The bulk export answered with no credential on 2026-09-03 and an earlier record
said the opposite. Re-measure; never infer.

## 5. The scope-test gap on domains

**The composition rule works on `address` entities and not on `domain` ones — and
the feeds most likely to be added list domains.**

`concept/02` names the limit: *"the scope test works on address entities and not
on domain ones."* `helena.policy.v1.ADDRESS` is that sentence as a constant, and
the traffic tests behind it (`_traffic_not_bidirectional`, `_port_not_reached`)
need bytes and ports, which a domain entity does not have.

*What is done:* `_name_carries_no_traffic` and `_shared_infrastructure` are the
domain-side rules that do exist, and they are weaker by construction — a resolved
name with no traffic behind it and `*.workers.dev`-style shared infrastructure.
*What would change it:* a domain-side traffic test would need the flow join from
name to connection, which the input supports and nothing builds yet.

## 6. The base rate

**Coverage is sparse; most contexts have no hit on anything. A classifier that
always answers `normal` will score well on accuracy and be worthless.**

*What is done:* both frozen prompts say it in the prompt itself — *"coverage is
sparse, so most entities have no hit on anything: a context that is mostly
`no_match` is the ordinary case and not a clean bill of health"* — and
`docs/evaluation-corpus.md` requires the base-rate check as an acceptance item
rather than a nice-to-have.

*What is deliberately not done:* the base rate is **not measured**, and it cannot
be with the artifacts here. The one multi-host capture is 2025-09-20 and the one
feed snapshot covers 2026-08-31 to 2026-09-02, so an overlap computed between
them would be an artefact of the year between them. Running the join anyway would
have produced a plausible number with nothing behind it.

## 7. The interface that hardens on first use

**The output payload becomes an interface the moment anything consumes it, and it
duplicates state by construction — the same assessment exists as rows and as a
message, so the two can disagree if the view is edited carelessly.**

*What is done:* the message is a projection of the sink view rather than a
serializer in Python, the payload's shape is asserted against the view by
execution, and the message carries the full version set so a consumer can tell
which shape it received ([0036](decisions/0036-the-output-message.md)). The
output topic is egress and **nothing is recoverable only from it**
(`concept/03`), which is what keeps the rows the authority when the two disagree.

*What is not done:* no schema registry, no consumer contract test, no
compatibility policy. There is no consumer.

## 8. Framework defaults

**A model framework's conveniences must be checked against the single-store,
agents-propose and ephemeral-state rules rather than enabled because they are one
flag away.**

*What is done:* this one is an executable boundary rather than a caution.
`tests/test_dependency_boundary.py` and `tests/test_architecture_boundary.py`
keep the agent frameworks absent, keep hosted tracing **rejected rather than
deferred** (`concept/03`, `concept/07`), and assert the package writes to no file
and starts no process. A framework arrives by a decision record, or it fails the
suite.

## 9. Output volume

**Emitting `normal` verdicts means the topic carries the full context volume.
Intended at prototype scale; it would need revisiting at real rates.**

*What is done:* it is intended, not tolerated — every assessed context is emitted
exactly once per terminal outcome, `normal` verdicts and typed failures included,
because *"nothing arrived" must not be indistinguishable from "nothing was
assessed"*. Measured for shape at fixture scale only; no rate has been measured
on real traffic. `concept/08`'s assumptions table is where a real bound would
start: over a measured day a context holds a median of **1** entity row, p90 3,
p99 441 and a **maximum of 1 822** — so the volume is not the mean.

## 10. Deferred records outnumber code

**Every deferred component must stay labelled `deferred`, or the maturity labels
start lying.**

This is the hazard this file's own register answers. Thirteen deferred capabilities
are recorded in [`deferred.md`](deferred.md) against a package of some thirty
modules, so the deferred set is comparable in size to the built set — which is
the normal condition of a prototype and the reason the labels have to be exact.

*What is done:* `Maturity:` is required in every module docstring by
`tests/test_package_layout.py`, every module labelled `deferred` must name a
register entry that exists (`tests/test_governance.py`), and the two
capabilities that already have an executable absence test keep it
(`test_the_harness_is_still_deferred`, and the framework boundary above).
