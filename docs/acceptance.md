# Acceptance — what "the prototype works" is allowed to mean

This is the checklist for the end-to-end run, and it is deliberately two lists.
The first is what the run demonstrates. The second is what it does not, written
beside the first rather than left to be inferred from its absence — because a
checklist that only lists successes is read as a claim about everything it did
not mention.

The source of both lists is [`concept/01-goal-and-scope.md`](../concept/01-goal-and-scope.md),
which closes with the paragraph this file is the executable index of.
`tests/test_end_to_end.py` parses that note on every run, so a claim that is
added, removed or reworded there fails here until this file and that module are
brought across with it.

> **This checklist is not evidence that the verdicts are right.** It is evidence
> that the stages compose and cite. The measurement that would establish the
> other thing needs a labelled evaluation corpus, and the project does not have
> one ([`concept/08-open-questions.md`](../concept/08-open-questions.md)).

## Running it

```bash
make acceptance      # the gate: the D3 enrichment states and the D9 run, alone
make test            # the whole suite, which includes both
make conformance     # the twenty behaviours that must be impossible
```

`make acceptance` needs the pinned engine and broker; the suite's fixtures start
them when nothing is already listening (`tests/conftest.py`), so it needs no
infrastructure to have been brought up first. The run takes about forty seconds.

## What one run is

One pass of `tests/test_end_to_end.py::run_pipeline`, every stage the shipped
code path:

| | Stage | Through |
| --- | --- | --- |
| 0 | The Public Suffix List snapshot | `helena.enrichment.load_public_suffix_list`, over a `file:` URL |
| 1 | The ten-record capture published record by record and consumed back | `helena.broker` over the Kafka wire protocol, then `helena.normalizer` |
| 2 | The host context and its entity rows | the engine's own views, from `sql/migrations/` |
| 3 | A feed snapshot, joined at the window it was current for | `helena.enrichment.load_threatfox`, `helena_analytical_enriched_context` |
| 4 | The rendering and the triage call | `helena.rendering`, `helena.triage` |
| 5 | The analyst call, where the route reaches it | `helena.orchestration.assess`, `helena.analyst` |
| 6 | The message on the output topic, drained back off it | `helena.sink`, `helena.broker` |

**The model is the one scripted thing**, and it is a real OpenAI-compatible
endpoint on the loopback interface rather than a mock object. A run against the
configured endpoint would measure that model's mood rather than the pipeline's
composition; what the live endpoint is for is `tests/test_agents.py`,
`tests/test_triage.py` and `tests/test_analyst.py`, which call it.

## Claimable — and the test that demonstrates each

**CLAIM-1 — every verdict and explanation cites stored evidence.**

- `test_end_to_end::test_claim1_every_citation_on_the_topic_resolves_to_a_stored_evidence_row`
  — every identifier off the topic is looked up in the store and comes back as
  one row with a source, a tier and the snapshot it matched.
- `test_end_to_end::test_claim1_the_cited_rows_are_the_ones_the_rendering_showed`
  — the mechanism: an agent can cite only what the rendering showed, and what it
  showed came out of the enriched context.
- `test_end_to_end::test_claim1_the_explanation_on_the_topic_carries_its_citations_and_its_path`
  — narrative, patterns, the triage decision that led there, and all nine version
  dimensions.
- `test_end_to_end::test_claim1_the_evidence_the_message_carries_is_the_store_field_for_field`
  — the message is a projection of stored rows, not a second account of them.
- `test_end_to_end::test_claim1_a_citation_to_evidence_the_rendering_did_not_show_is_refused`
  — the other direction: a model citing a well-formed identifier it was never
  shown produces a typed failure with no verdict, not a verdict nobody can
  resolve.

**CLAIM-2 — source outages, stale evidence, invalid model responses and partial
context are visible rather than absorbed.** Four conditions, four runs, each read
off the output topic rather than out of the store, because "visible" means
visible to whoever reads the message.

- `test_end_to_end::test_claim2_a_source_outage_reaches_the_topic_as_failed_and_never_as_no_match`
  — `failed`, with no classification at all, beside a source that answered.
- `test_end_to_end::test_claim2_stale_evidence_reaches_the_topic_as_stale_and_keeps_its_claim`
  — `stale`, and the claim still there: an aged snapshot is evidence with a date
  on it, not evidence withdrawn.
- `test_end_to_end::test_claim2_an_invalid_model_response_reaches_the_topic_as_a_typed_failure`
  — a typed failure with no verdict, emitted rather than dropped, versions intact.
- `test_end_to_end::test_claim2_partial_context_reaches_the_topic_as_gaps_and_negative_space`
  — the agent's declared gaps with their kinds intact, and a completed negative
  that reads as an answer rather than as an absence.

**CLAIM-3 — a new enrichment source can be added without changing identity,
provenance or assessment contracts.** Demonstrated by adding one: a second
source's reference table, mapping view and line in the union, applied into a
schema of its own, loaded, and run all the way to the topic.

- `test_end_to_end::test_claim3_the_second_sources_claim_reaches_the_agent_and_the_topic`
  — into the enriched context, the rendering, a citation and the message,
  carrying its own source, tier and snapshot.
- `test_end_to_end::test_claim3_the_second_sources_identifier_is_the_contracts_and_not_its_own`
  — its `evidence_id` is the evidence contract's construction; its loader
  computed no identifier at all.
- `test_end_to_end::test_claim3_adding_a_source_touched_one_migration_and_no_contract`
  — the diff is one file, the feed-mapping migration, and the agent contract, the
  version dimensions and the output message's field set are unchanged.

**CLAIM-4 — no autonomous remediation occurs.**

- `test_end_to_end::test_claim4_the_only_address_python_code_dialled_in_the_run_was_the_model`
  — every outbound connection Python opened during the run, recorded at the
  socket, is the model endpoint and nothing else.
- `test_end_to_end::test_claim4_the_only_thing_that_left_the_network_was_a_prompt`
  — the disclosure ledger on the message carries one channel, `model_inference`.
- `test_end_to_end::test_claim4_nothing_on_the_output_topic_names_an_action_to_take`
  — no field in the output message, at any depth, that a consumer could read as
  an instruction to act.

## Not claimable

These are the words of the note, and they are not hedges. Each is a measurement
that has not been made, and the reason is the same one in every case: **the
labelled evaluation corpus does not exist**, so there is nothing to measure
against.

| Not claimable | Why not |
| --- | --- |
| accuracy, recall, false-positive rate, escalation rate, latency or cost | No labelled corpus, and no evaluation harness. The model in this run is scripted, so even its answers are an input rather than evidence |
| that triage reduces caseload without suppressing high-confidence detections | The second half is enforced structurally — deterministic escalation is evaluated before triage runs and cannot be suppressed by it (`tests/test_conformance.py`, MNH-04) — but the first half is a rate, and a rate needs a corpus |
| that identical inputs replay identically | The model is not deterministic. `helena.orchestration.compare` reports which of six dimensions moved, and a difference is a measurement rather than a failure; `concept/08` also still carries the silent-record-loss hazard at a catch-up boundary |

Nothing committed to this repository may claim one of these anyway: MNH-20 in
`tests/test_conformance.py` scans every markdown file and every module of the
package on each run, and this file is scanned with them.

## What this run does not demonstrate

Findings, not caveats. Each was produced by building the run, each is pinned by a
test so that it cannot quietly change, and each is a decision somebody has to
make rather than a thing this increment could fix on its own.

**1. A deployment whose only enrichment source has never loaded cannot build a
request at all.** `RequestVersions.enrichment_snapshot_version` is one required
identifier — "the feed snapshot the enrichment join matched against"
([ADR-0008](decisions/0008-version-registry.md)) — and a source whose every load
failed has no snapshot to name. The context is perfectly assessable otherwise:
every entity's status is `failed`, which is exactly the state the pipeline exists
to carry through and emit. Nothing is invented to get past it; the harness
raises, and `test_end_to_end::test_a_deployment_whose_only_source_is_out_cannot_record_a_snapshot_version`
is the refusal. This is why CLAIM-2's outage case is demonstrated with two
sources. The same field is why a run with **two** current snapshots has no single
value to record either, which `snapshot_at` refuses rather than picks from. The
snapshot and versioning scheme is still open in
[`concept/08-open-questions.md`](../concept/08-open-questions.md).

**2. The enrichment join asks every source about every entity, including the
entity types that source declares it does not cover.**
`helena.enrichment.SourceDescriptor` refuses a *claim* outside a source's
declared `entity_types`; `sql/migrations/0015_enriched_context.sql` takes its
source list from the load ledger and joins every entity against it, so ThreatFox
— which declares `address`, `domain` and `url` — produces `ok` / `no_match` rows
for the `fingerprint` entities in this capture. It does not break the rule
`no_match` exists for: the row is a lookup outcome and is not a statement of
safety. What it does is **overstate coverage**, and `source_diversity` counts over
claims, so a future composition rule reading these rows would count a source that
could not have consulted anything.
`test_end_to_end::test_a_source_answers_no_match_about_entity_types_it_declares_it_does_not_cover`
pins it in both directions. Fixing it needs the declared entity types on the SQL
side, and 0015's head refuses a second copy of the registry in SQL because a copy
can disagree with the decision it copies — so it is a decision, not a patch.

**3. Adding a source to a *running* deployment is not what was demonstrated.**
What was demonstrated is the migration set a second source ships as, applied to a
fresh schema. `helena_reference_evidence` is a `UNION ALL` created in
`sql/migrations/0014`, and a later migration cannot extend it without dropping
and recreating everything that reads it. So the in-place upgrade path for a new
feed is untested and is likely to be a rebuild of the enrichment view chain.

**4. The run is one host, one window, ten records, and one snapshot.** The
capture is the committed layer-coverage one — every layer combination the real
sample contains, which is what it was chosen for — but it is not a load test, a
multi-tenant test or a long-window test. What a busy host renders to is measured
separately by `make rendering-size`.

**5. The recorder behind CLAIM-4 sees Python, not C.** `socket.socket.connect` is
what it patches, so librdkafka (under `confluent_kafka`) and libpq (under
`psycopg`) do not pass through it — measured, and asserted in both directions by
the test itself, so a change in that blind spot is noticed. Those two clients are
closed off separately: `tests/test_dependency_boundary.py` holds the approved
distribution set by equality, and `tests/test_broker.py` holds which module may
hold a Kafka client at all.

**6. Truncation reaches a consumer only as a declared gap.** A truncated
rendering is visible to the agent and in the request contract
(`helena.contracts.v1.Truncation`), and the output message has no truncation
field — the path from there to the topic is the agent declaring a `truncated`
gap. That truncation is never invisible *to the agent* is MNH-06 in
`tests/test_conformance.py`, which is where that property lives.

## Where the rest of the guarantees are

This checklist is the end-to-end layer. Three other gates carry properties this
run rests on rather than re-demonstrates, and each is a suite of its own:

| Gate | What it holds |
| --- | --- |
| `make conformance` | `concept/07`'s twenty must-never-happen rows, one test per row |
| `tests/test_acceptance_enrichment.py` | the six enrichment states, and that no query which did not complete carries a classification |
| `tests/test_dependency_boundary.py`, `tests/test_broker.py`, `tests/test_architecture_boundary.py` | what may be imported, what may reach the network, and the five architectural rejections |
| `tests/test_secrets.py` | the five channels a credential could reach, including the repository |

Maturity: **experimental**. Every claim above is executed on every run of the
suite; none of them is a measurement of verdict quality, and there is no
increment in this repository that could make one until the corpus exists.
