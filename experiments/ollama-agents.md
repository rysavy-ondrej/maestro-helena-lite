# Experimental Design for Evaluating Ollama Models in Network Security Triage and Analysis

## Executive overview

This document defines a focused experiment for selecting local Ollama models for a two-level network-security agent architecture:

1. **Triage agent:** a fast, inexpensive classifier operating on structured host and network context. Its job is to identify clearly benign activity, preserve useful host observations, and escalate suspicious, malicious, unknown, or insufficiently supported cases. The decisive safety constraint is false-negative risk; among models that meet that constraint, latency and operating cost determine the winner.
2. **Analyst reasoning agent:** a slower, tool-using investigator for escalated cases. Its job is to test competing hypotheses, correlate current activity with historical context and threat intelligence, identify missing evidence, and produce a grounded, actionable assessment.

The source material names a broad set of open and open-weight model families available through Ollama. The focused experiment uses five model packages from four vendors and three origin groupings:

- `qwen3.5:4b` — Alibaba/Qwen Team, China
- `ministral-3:3b` — Mistral AI, France
- `granite4:3b` — IBM, United States
- `phi4-mini` — Microsoft, United States
- `qwen3.5:9b` — Alibaba/Qwen Team, China

The repeated Qwen vendor is intentional: the 4B package is a leading triage candidate, while the 9B package supplies the experiment's source-supported higher-quality analyst tier and a triage quality ceiling. The other three vendors reduce the risk of selecting a model based only on one family's strengths or one provenance path.

The experiment should not choose a single model by generic benchmark score. It should select each role separately using identical cases, prompts, schemas, runtime conditions, and provenance records. Model choice should follow a gate-and-optimize rule:

> **Triage:** meet the approved false-negative and reliability gates first; then minimize warm and cold latency, resource use, and cost.
>
> **Analyst:** meet grounding and investigation-quality gates first; then optimize latency and resource use.

## Source basis and limits

This design is derived from the supplied discussion. Model-family attribution, the proposed two-level architecture, the five-minute host-context concept, the distinction between observations and evidence, the structured triage output, and the thinking/non-thinking split all come from that source.

The Ollama catalog is time-sensitive. Package names and headline size/context information for the five candidates were cross-checked against the official Ollama library on **2026-09-14**, but the experiment must still freeze exact tags, digests, quantizations, licenses, runtime version, and context settings before execution. The source does not establish training-data provenance, license acceptability, cybersecurity benchmark performance, or deployment approval. Those items are therefore evaluation or governance questions, not assumed facts.

In this document, **open/open-weight** is a neutral umbrella term. A downloadable model is not necessarily open source under every definition, and family membership does not by itself establish license, training-data, or supply-chain acceptability.

## Major open and open-weight model families named in the source

Ollama is the runtime and distribution layer; it is not the developer of the models below. The table is a concise landscape of the major families enumerated in the source, not a permanent or exhaustive inventory of the Ollama library.

| Model family | Developer or vendor | Origin stated in source | Main orientation noted in source |
|---|---|---|---|
| Qwen, Qwen2.5, Qwen3, Qwen3.5, Qwen3.6 | Alibaba / Qwen Team | China | General, reasoning, coding, vision, embedding, tools |
| DeepSeek, DeepSeek-R1, V3, V4 | DeepSeek | China | Reasoning and coding; includes distilled variants |
| GLM | Z.ai / Zhipu AI | China | General, reasoning, and agentic models |
| Kimi | Moonshot AI | China | Large agentic and reasoning models |
| MiniMax | MiniMax | China | Agentic and reasoning models |
| Llama 2, 3, 3.1, 3.2 | Meta | United States | General-purpose open-weight family |
| Gemma, Gemma 2, 3, 4 | Google DeepMind | United States / United Kingdom | General open-weight family; some variants are multimodal |
| Phi, Phi-3, Phi-4 | Microsoft | United States | Small models, including latency-constrained reasoning use cases |
| GPT-OSS | OpenAI | United States | Open-weight reasoning and agentic models |
| Granite | IBM | United States | Enterprise-oriented classification, extraction, RAG, tools, and structured output |
| Nemotron | NVIDIA | United States | Reasoning and agentic models, often optimized for efficient inference |
| OLMo and Tülu | Allen Institute for AI | United States | Research-oriented base and instruction-tuned models |
| DBRX | Databricks | United States | Mixture-of-experts model |
| Arctic and Arctic Embed | Snowflake | United States | Enterprise and embedding models |
| Nomic Embed | Nomic AI | United States | Embedding models |
| LFM and LFM2 | Liquid AI | United States | Efficient and on-device hybrid architectures |
| Mistral and Mixtral | Mistral AI | France | General-purpose dense and mixture-of-experts models |
| Ministral | Mistral AI | France | Small, edge-oriented models; especially relevant to triage |
| Magistral | Mistral AI | France | Reasoning models |
| Devstral | Mistral AI | France | Software-engineering agents |
| Command R | Cohere | Canada | Retrieval-augmented generation and tool use |
| Falcon and Falcon 3 | Technology Innovation Institute | United Arab Emirates | Efficient general models |
| EXAONE | LG AI Research | South Korea | Korean/English general models |
| StarCoder and StarCoder2 | BigCode collaboration | International | Code-specialized models |
| LLaVA | Academic/open-source collaboration | United States, as stated in source | Vision-language family; underlying language model varies |
| Dolphin | Cognitive Computations / Eric Hartford | United States | Community fine-tunes of other base models |

The source also identifies `qwen3-embedding` variants as a possible future component for retrieving similar historical host behavior. Embedding models are outside the five-model inference benchmark and should be evaluated separately if behavioral retrieval becomes part of the production design.

## Provenance model

Vendor and country are useful fields, but they are not a complete provenance record. Each tested artifact should be recorded at the following layers:

| Layer | Required record | Why it matters |
|---|---|---|
| Runtime and distributor | Ollama version, host platform, download source | Reproducibility and runtime supply chain |
| Package | Exact model tag, manifest digest, file digest, quantization, package size | Prevents a mutable tag or different quantization from being treated as the same test subject |
| Model developer | Organization and country or countries of origin | Vendor concentration, policy, and jurisdiction review |
| Base model | Family, version, and original developer | A fine-tuner's identity may differ from the underlying model's origin |
| Adaptation | Distiller, fine-tuner, multimodal adapter, and post-training organization | Captures the party that changed model behavior |
| License and use terms | License text/version for the exact artifact; commercial and redistribution conditions | Downloadability does not prove deployment eligibility |
| Documentation | Model card, release notes, known limitations, supported features | Establishes what is claimed and what still needs testing |

Two examples from the source show why layered provenance matters:

- A `DeepSeek-R1-Distill-Qwen` artifact combines DeepSeek reasoning/post-training with an Alibaba Qwen base model.
- A `LLaVA-Phi` artifact combines a LLaVA multimodal adaptation with a Microsoft Phi language model.

Country-of-origin policy should therefore define whether it applies to the base model, post-training organization, packager, hosting/runtime, or all of them. The experiment should report these layers without turning country alone into a quality score.

## Focused candidate set

### Selection rationale

The shortlist preserves the source's strongest small-model recommendations while adding an analyst-sized reference. It covers four vendors, includes three compact triage-oriented packages, includes Microsoft's reasoning-oriented small-model baseline, and retains a larger Qwen variant for deeper reasoning and for measuring the quality lost by using a 3–4B triage model.

| Candidate | Vendor and origin | Source and official-library facts used in this design | Primary experimental role | Secondary role |
|---|---|---|---|---|
| `qwen3.5:4b` | Alibaba / Qwen Team — China | Source: strong structured instruction following, tools, thinking/non-thinking, 256K context. Official Ollama listing at validation time: approximately 3.4 GB. | Triage in non-thinking mode | Analyst lower-cost candidate; thinking-mode ablation |
| `ministral-3:3b` | Mistral AI — France | Source: edge-oriented, strong system-prompt adherence, native function calling and JSON output. Official listing: approximately 3.0 GB and 256K context. | Triage | Analyst lower-bound candidate |
| `granite4:3b` | IBM — United States | Source: enterprise-oriented classification, extraction, RAG, tools, and structured JSON. Official listing: approximately 2.1 GB and 128K context. | Triage | Analyst lower-bound candidate |
| `phi4-mini` | Microsoft — United States | Source: 3.8B-class model for latency-constrained environments with reasoning/logic strengths. Official listing: approximately 2.5 GB and 128K context. | Triage comparator | Compact analyst candidate |
| `qwen3.5:9b` | Alibaba / Qwen Team — China | Source: higher-quality triage/small-analyst tier, tools, thinking, 256K context. Official listing: approximately 6.6 GB. | Analyst in thinking mode | Triage quality ceiling in non-thinking mode |

Official library references used for the validation snapshot: [Qwen3.5](https://ollama.com/library/qwen3.5), [Ministral 3](https://ollama.com/library/ministral-3), [Granite 4](https://ollama.com/library/granite4), and [Phi-4 Mini](https://ollama.com/library/phi4-mini).

Package size and maximum advertised context do not predict task quality or achieved throughput. They should be treated as deployment descriptors and measured under the intended hardware and context length.

### Comparison matrix

Legend: **P** = primary candidate for the role, **B** = benchmark or lower-bound candidate, **Q** = quality-ceiling/reference candidate, and **A** = controlled ablation where supported.

| Candidate | Vendor diversity | Triage direct/non-thinking | Analyst reasoning | Structured-output interest | Key question to answer |
|---|---:|---:|---:|---:|---|
| `qwen3.5:4b` | Alibaba / China | P | B, A | High, per source | Can it meet the false-negative gate at substantially lower latency than 9B? |
| `ministral-3:3b` | Mistral / France | P | B | High, per source | Does edge orientation and JSON/function support produce the most reliable low-cost classifier? |
| `granite4:3b` | IBM / US | P | B | High, per source | Do enterprise classification/extraction strengths translate to grounded network triage? |
| `phi4-mini` | Microsoft / US | P | B | Moderate to high, to be measured | Does its compact reasoning strength improve ambiguous-case handling without excess latency? |
| `qwen3.5:9b` | Alibaba / China | Q | P, A | High, per source | How much safety and investigation quality does the larger model add, and at what cost? |

The matrix records hypotheses to test, not conclusions.

## Two-level agent architecture

```text
Raw host and network telemetry
        |
        v
Deterministic preprocessing
  - aggregate a fixed time window
  - extract connection statistics
  - summarize DNS and TLS activity
  - identify unusual ports and services
  - attach IoC matches and their source confidence
  - load stable host profile and prior observations
        |
        v
Fast triage agent
  - strict structured input and output
  - direct or non-thinking mode
  - no external investigation tools
        |
        +---------------------------+
        |                           |
        v                           v
Clearly benign and supported   Suspicious, malicious,
  - store decision             unknown, invalid, or uncertain
  - update observations             |
                                      v
                              Analyst reasoning agent
                                - current and historical context
                                - triage evidence and uncertainty
                                - approved enrichment tools
                                - hypothesis-driven investigation
                                      |
                                      v
                              Grounded assessment and actions
```

Deterministic preprocessing should do work that does not require a language model: aggregation, normalization, validation, deduplication, feature extraction, and threat-intelligence attachment. The model should receive a compact representation of current activity plus a bounded host profile, not an indefinitely growing raw connection history.

### Role 1 fast and cheap triage agent

The triage agent is an intelligent classifier, not a full investigator. It should:

- classify the supplied window using only supplied evidence;
- distinguish direct evidence from descriptive host observations;
- avoid treating an IoC match as proof by itself;
- escalate suspicious, malicious, unknown, insufficient, contradictory, or schema-invalid cases;
- produce valid machine-readable output with bounded prose; and
- avoid calling enrichment tools or spending compute on open-ended investigation.

The intended optimization objective is:

```text
minimize latency and operating cost
subject to weighted false-negative rate <= epsilon
and required reliability gates being met
```

`epsilon` is deliberately not assigned a value here. It must be set by the security risk owner using incident severity, operational capacity, and the consequences of a miss.

### Role 2 advanced analyst reasoning agent

The analyst agent handles escalations. It should:

- restate the problem and identify the evidence that triggered escalation;
- generate both malicious and plausible benign hypotheses;
- plan and invoke approved DNS, WHOIS, ThreatFox, and host-history queries when useful;
- distinguish tool results, source data, inference, and unresolved uncertainty;
- correlate behavior across the current window and historical observations;
- revise hypotheses when evidence conflicts; and
- return an actionable conclusion, confidence, residual uncertainty, and next steps.

The analyst agent should not be rewarded for long answers or exposed chain-of-thought. Evaluation should use the final assessment, concise rationale, cited evidence, tool-call trace, and consistency with ground truth.

## Structured contracts

The schemas below are proposed experimental contracts derived from the source examples. Exact optionality and enumerations should be frozen before the benchmark begins.

### Triage input

```json
{
  "schema_version": "1.0",
  "case_id": "case-0001",
  "host": {
    "host_id": "host-023",
    "profile_observations": [
      "Likely Windows workstation",
      "Regular Microsoft 365 activity"
    ]
  },
  "window": {
    "duration": "5m",
    "connection_statistics": {},
    "unusual_ports_or_services": [],
    "dns_summary": [],
    "tls_summary": []
  },
  "ioc_matches": [
    {
      "indicator": "redacted-example",
      "source": "ThreatFox",
      "associated_threat": "example-family",
      "source_confidence": 80
    }
  ],
  "prior_observations": [],
  "missing_or_unavailable_fields": []
}
```

The test corpus should use synthetic or appropriately sanitized indicators where production data cannot be safely retained. Fields must preserve source timestamps and confidence semantics when those are material to the label.

### Triage output

```json
{
  "schema_version": "1.0",
  "classification": "SUSPICIOUS",
  "confidence": 0.82,
  "risk_score": 67,
  "evidence": [
    {
      "evidence_id": "ioc-1",
      "type": "ioc_match",
      "severity": "high",
      "statement": "Destination is associated with the named threat in the supplied ThreatFox match"
    },
    {
      "evidence_id": "conn-4",
      "type": "behavior",
      "severity": "medium",
      "statement": "Supplied connection summary shows periodic outbound activity"
    }
  ],
  "observations": [
    "Activity is consistent with a Windows workstation profile"
  ],
  "uncertainties": [
    "The supplied context does not establish whether the destination is shared infrastructure"
  ],
  "requires_analysis": true
}
```

Allowed classifications:

- `BENIGN`
- `LOW_RISK`
- `SUSPICIOUS`
- `LIKELY_MALICIOUS`
- `UNKNOWN`

All output strings must refer to supplied fields or clearly identify an inference. An invalid schema, missing classification, or missing escalation flag should fail closed to analyst review.

### Analyst input

```json
{
  "schema_version": "1.0",
  "case_id": "case-0001",
  "triage_result": {},
  "current_host_context": {},
  "host_profile_and_history": {},
  "retrieved_similar_behaviors": [],
  "available_tools": [
    "dns_lookup",
    "whois_lookup",
    "threatfox_lookup",
    "host_history_query"
  ]
}
```

`retrieved_similar_behaviors` is optional and should be omitted in the core benchmark unless a retrieval experiment is explicitly enabled. This prevents an untested embedding or vector-search component from confounding the initial model comparison.

### Analyst output

```json
{
  "schema_version": "1.0",
  "case_summary": "Concise description of the escalated activity",
  "hypotheses": [
    {
      "hypothesis": "Potential command-and-control beaconing",
      "status": "supported",
      "supporting_evidence_ids": ["ioc-1", "conn-4"],
      "contradicting_evidence_ids": []
    },
    {
      "hypothesis": "Benign updater using shared infrastructure",
      "status": "unresolved",
      "supporting_evidence_ids": [],
      "contradicting_evidence_ids": ["conn-4"]
    }
  ],
  "tool_actions": [],
  "final_assessment": "SUSPICIOUS",
  "confidence": 0.78,
  "key_evidence_ids": ["ioc-1", "conn-4"],
  "unresolved_questions": [],
  "recommended_next_steps": []
}
```

## Experimental scenarios

Each case should have a ground-truth label, severity, minimum acceptable escalation behavior, decisive evidence, plausible distractors, missing-data flags, and an explanation written before model execution. Cases should be parameterized into multiple variants so the benchmark measures a behavior rather than memorization of one narrative.

### Triage scenarios

| ID | Scenario | Evidence pattern | Expected safe behavior | Primary stress dimension |
|---|---|---|---|---|
| T1 | Stable benign baseline | Known recurring enterprise traffic and no meaningful anomalies | `BENIGN` or `LOW_RISK`; no escalation when the evidence is sufficient | False positives and latency |
| T2 | Noisy but benign cloud activity | Many destinations, CDN/shared infrastructure, routine DNS and TLS variation | Avoid equating volume or rarity with malice; escalate only if ambiguity is material | Specificity and evidence discipline |
| T3 | Isolated IoC match | One supplied ThreatFox match without corroborating behavior | Do not claim the host is malicious solely from the match; express uncertainty or escalate according to policy | IoC over-reliance |
| T4 | Corroborated IoC and beaconing | Threat-intelligence match plus periodic outbound connections and supporting network anomalies | `SUSPICIOUS` or `LIKELY_MALICIOUS`; escalation required | False-negative risk and correlation |
| T5 | Behavioral beaconing without IoC | Regular outbound periodicity with no intelligence match | Recognize suspicious behavior and escalate without inventing a malware family | Generalization beyond IoCs |
| T6 | Unusual port or service | Rare service with either legitimate host-role context or unexplained use | Use host context; distinguish justified from unexplained rarity | Context use |
| T7 | DNS and TLS anomaly combination | Failed or unusual DNS behavior combined with unusual TLS summary | Correlate weak signals without overstating certainty | Multi-signal reasoning |
| T8 | Missing context | Important telemetry absent or a truncated window | Prefer `UNKNOWN` and escalation over unsupported benign classification | Safe abstention |
| T9 | Contradictory enrichment | High-confidence-looking IoC match conflicts with host history or other supplied context | Preserve conflict, avoid certainty inflation, and escalate | Conflict handling and calibration |
| T10 | Host-profile drift | New activity departs from a stable historical profile | Recognize change while avoiding proof-by-novelty | Temporal context |
| T11 | Adversarially worded field value | Untrusted text inside telemetry attempts to redirect the model | Treat values as data, follow system instructions, and keep valid output | Instruction robustness |
| T12 | High-volume context | Maximum planned counts of connection, DNS, TLS, and IoC records | Preserve classification and schema validity within the latency budget | Scale and truncation behavior |

T11 and the explicit high-volume stress treatment in T12 are proposed safety extensions rather than claims made in the source. They are included because structured security data can contain untrusted text and because operational windows vary in size.

### Analyst scenarios

| ID | Scenario | Investigation task | Expected behavior | Primary quality dimension |
|---|---|---|---|---|
| A1 | Single IoC with ambiguous behavior | Determine whether the match is corroborated and identify what remains unknown | Test malicious and benign explanations; use enrichment selectively | Hypothesis quality and calibration |
| A2 | Multi-window beaconing | Correlate current periodic activity with host history | Build a temporal account grounded in supplied windows | Cross-window reasoning |
| A3 | Conflicting threat intelligence | Reconcile mismatched source confidence, age, or associations | Preserve disagreement and avoid false certainty | Source evaluation |
| A4 | Benign administrative behavior versus compromise | Distinguish legitimate host-role activity from abuse using context | Compare alternatives and request discriminating evidence | Differential analysis |
| A5 | Tool-assisted enrichment | Decide which DNS, WHOIS, ThreatFox, or history query to run and integrate the result | Make relevant calls, avoid redundant calls, and update the assessment | Tool planning and result integration |
| A6 | Tool failure or unavailable enrichment | Continue when a query fails or returns no result | State the limitation, avoid fabricating results, and recommend a safe next step | Resilience and grounding |
| A7 | Misleading triage result | Detect that triage confidence or evidence is inconsistent with raw context | Reassess independently rather than anchoring on triage | Error correction |
| A8 | Retrieval-assisted comparison | Compare current behavior with similar benign and malicious histories | Use retrieved examples as context, not proof | Retrieval use; optional phase |

## Thinking and non-thinking conditions

The source highlights Qwen's ability to trade additional reasoning compute for latency through thinking and non-thinking operation. The experiment should treat mode as an explicit factor rather than silently mixing settings.

### Triage condition

- Use direct/non-thinking mode wherever the exact artifact and Ollama runtime support a controllable switch.
- Require only the structured decision, evidence, observations, uncertainty, and escalation flag.
- Do not ask for hidden or lengthy chain-of-thought.
- Keep token limits and decoding settings fixed across comparable runs.
- If a model does not expose an equivalent mode, record that fact; do not label a prompt workaround as a native feature.

### Analyst condition

- Enable native thinking for supported Qwen candidates and record reasoning-token or timing overhead when exposed by the runtime.
- Use the same analyst task, tool set, maximum steps, and final-output contract for every model.
- Evaluate final answers and tool traces, not private chain-of-thought.
- Run a matched on/off ablation for `qwen3.5:4b` and `qwen3.5:9b` if the installed artifacts expose the control. This isolates the benefit of additional reasoning compute from the effect of model size.

Thinking mode should be retained only if it improves analyst-quality measures enough to justify its latency and resource cost. For triage, any improvement must also survive the false-negative gate and operational throughput test.

## Dataset and execution methodology

### Case construction

Build the benchmark from three sources, with origin recorded per case:

1. **Controlled replay:** sanitized, analyst-confirmed historical windows where ground truth is reliable.
2. **Synthetic injection:** deterministic insertion of known behaviors, missing fields, contradictions, and volume changes into benign baselines.
3. **Purpose-built edge cases:** ambiguous and adversarial cases designed to test abstention, schema reliability, and evidence discipline.

Do not allow near-duplicate windows from one incident to cross dataset splits. Stratify by label, severity, host role, scenario family, telemetry volume, and availability of historical context. Keep a sequestered final set that is not used during prompt or threshold tuning.

### Fair-run controls

Freeze and publish an experiment manifest containing:

- exact Ollama version and host operating system;
- CPU, accelerator, memory, and power-measurement method;
- exact model tag, manifest/file digest, quantization, loaded context length, and package size;
- prompt version, JSON schema version, tool definitions, and preprocessing version;
- decoding parameters, output-token limit, thinking setting, and random seed where supported;
- cold-start procedure, warm-up procedure, repetition count, timeout, retry, and failure policy; and
- case-set version and ground-truth review status.

Use the same serialized input for each model unless a model-specific template is technically mandatory. Record every deviation. Separate cold-start latency from steady-state latency, randomize case order, and repeat cases enough to estimate run-to-run instability. The repetition count should be chosen in a pilot using observed variance rather than invented in advance.

### Evaluation stages

1. **Contract pilot:** confirm all candidates can ingest the schema and return parseable output.
2. **Triage benchmark:** run all five in direct/non-thinking conditions; treat `qwen3.5:9b` as a quality ceiling.
3. **Triage selection:** apply safety and reliability gates, then compare the passing models on the latency/cost Pareto frontier.
4. **Analyst benchmark:** run all five on escalated cases. Treat the smaller models as lower-cost baselines and `qwen3.5:9b` as the primary analyst candidate.
5. **Thinking ablation:** compare supported Qwen thinking on/off conditions without changing other factors.
6. **Robustness pass:** rerun selected candidates on high-volume, missing-data, contradictory, and adversarial cases.
7. **Final holdout:** evaluate locked prompts, thresholds, and runtime settings once on the sequestered set.

## Metrics and decision rules

### Triage metrics

Safety and correctness:

- **False-negative rate:** proportion of unsafe cases classified without required escalation.
- **Severity-weighted false-negative rate:** sum of organization-approved severity weights for missed unsafe cases divided by the total weight of unsafe cases.
- **Unsafe-case escalation recall:** proportion of malicious, suspicious, and policy-defined ambiguous cases escalated.
- **False-positive rate:** benign cases incorrectly classified or escalated as unsafe.
- **Precision by class:** reliability of `SUSPICIOUS` and `LIKELY_MALICIOUS` outputs.
- **Abstention quality:** whether `UNKNOWN` is used for genuinely insufficient cases rather than as a general escape.
- **Calibration:** agreement between reported confidence and observed correctness, measured with reliability curves and a proper scoring rule such as the Brier score.

Contract and grounding:

- valid JSON rate;
- schema-conformance rate;
- evidence-reference accuracy;
- unsupported-claim rate;
- contradiction rate between classification, risk score, evidence, and escalation flag; and
- run-to-run decision stability.

Operational efficiency:

- cold-start and warm end-to-end latency at p50, p95, and p99;
- time to first token and generation time where available;
- prompt and completion token counts;
- cases per minute at the target concurrency;
- peak RAM and accelerator memory;
- accelerator/CPU time and energy per case where measurable; and
- timeout, retry, and model-load failure rates.

Because Ollama is local, there may be no meaningful per-token purchase price. Report cost using measured resource consumption and a documented local accounting model, such as energy plus amortized hardware time. Do not import cloud API prices as a substitute.

**Triage decision rule:** reject any candidate that fails the approved severity-weighted false-negative, unsafe-case escalation, schema-conformance, or failure-rate gate. Among passing candidates, choose from the Pareto frontier of p95 latency, resource cost, and false-positive/escalation burden. Do not average a severe miss away with speed.

### Analyst metrics

Use blinded review by at least two qualified reviewers for a subset large enough to measure agreement, with adjudication for disagreements. Score the following dimensions on a pre-written anchored rubric:

- final assessment correctness;
- identification and accurate use of decisive evidence;
- evidence coverage without irrelevant padding;
- quality and diversity of competing hypotheses;
- investigation completeness and prioritization;
- relevance and efficiency of tool calls;
- correct interpretation of tool results;
- uncertainty recognition and confidence calibration;
- absence of fabricated facts, tool results, or malware attribution;
- ability to recover from misleading triage or failed tools; and
- usefulness and safety of recommended next steps.

Also report end-to-end latency, tool-call count, tokens, memory, energy, timeout rate, and run-to-run consistency. Keep quality dimensions separate in the primary report; if a composite score is later required, its weights must be approved before the holdout is opened.

**Analyst decision rule:** require minimum grounding, correctness, and unsafe-miss performance first. Among passing models, prefer the model that produces the strongest investigation-quality profile at an operationally acceptable p95 latency and resource cost. A longer rationale is not evidence of better reasoning.

### Statistical reporting

- Report confidence intervals, not only point estimates.
- Report results by scenario, label, and severity; aggregate scores can hide dangerous failure clusters.
- Use paired comparisons because every candidate sees the same cases.
- Include both per-case outcomes and incident-level outcomes when several windows belong to one incident.
- Analyze invalid output, timeout, and refusal as explicit outcomes rather than dropping them.
- Document all prompt and threshold changes made before the final holdout.

## Experiment outputs

The final benchmark package should contain:

- frozen experiment and provenance manifests;
- versioned preprocessing logic, prompts, JSON schemas, and tool contracts;
- case inventory with source type, ground truth, severity, and expected escalation;
- raw model outputs and tool traces with sensitive values sanitized;
- metric tables and per-scenario error analysis;
- latency/resource profiles for cold and warm operation;
- a triage Pareto chart and an analyst quality-versus-cost chart;
- a failure taxonomy with representative grounded examples; and
- a role-specific recommendation, fallback model, operating threshold, and revalidation trigger.

## Acceptance checklist

Before choosing a model, confirm that:

- [ ] Exact tags, digests, quantizations, licenses, and runtime compatibility are frozen.
- [ ] Base-model and post-training provenance are recorded separately.
- [ ] All candidates receive equivalent structured inputs and output contracts.
- [ ] Triage uses direct/non-thinking settings where natively supported.
- [ ] Analyst thinking settings and tool budgets are explicit.
- [ ] Ground truth and severity labels were written before model evaluation.
- [ ] False-negative and reliability gates were approved before reviewing final results.
- [ ] Cold and warm latency were measured on the intended deployment hardware.
- [ ] Invalid JSON, timeouts, and missing evidence are counted as outcomes.
- [ ] Results are reported by scenario and severity, not only as averages.
- [ ] The final holdout remained sealed until prompts and thresholds were locked.
- [ ] Selection is role-specific and includes a documented fallback and re-test condition.

## Recommended initial experiment

Begin with all five models on the same triage corpus in direct/non-thinking conditions. Use `qwen3.5:9b` as the reference for the accuracy and safety potentially lost by compact models. Promote only candidates that meet the false-negative and reliability gates. Then evaluate all five on the analyst scenario set, with `qwen3.5:9b` as the primary higher-capacity candidate and the smaller models as cost baselines. For the Qwen candidates, add a thinking on/off ablation under otherwise identical conditions.

This design keeps the experiment focused while answering three distinct questions: which compact model is safe enough for continuous triage, how much analyst quality requires additional reasoning compute, and whether the preferred technical result remains acceptable under the required model-provenance policy.
