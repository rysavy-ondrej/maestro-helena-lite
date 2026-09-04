# 0004 — The configuration variables, and what has no default

**Status: accepted.** Task 1 (D0 Foundations).
**Authority:** `concept/07-principles.md` ("Secrets and configuration"),
`concept/03-architecture.md` (the environment is an *interface*, not a
component), `concept/instruction.md` §6.

`helena.config` is the only path that reads configuration. `.env.example` lists
every variable it reads with an empty value, and
`tests/test_config.py::test_the_example_lists_exactly_the_loaders_variables`
holds the two to the same set, so a variable added to one and not the other is a
test failure rather than a startup surprise.

`concept/08-open-questions.md` records that two guessed credential names had
already propagated across six documents before being corrected. This file exists
so the names are looked up rather than guessed again.

## The variables

| Variable | Section | Notes |
| --- | --- | --- |
| `LLM_URL`, `LLM_TOKEN`, `LLM_MODEL` | model, general | The OpenAI-compatible endpoint every agent runs against. Required |
| `LLM_{URL,TOKEN,MODEL}_{TRIAGE,ANALYST}` | model, per agent | Optional overrides. Absent or blank means "use the general value" |
| `HELENA_TENANT`, `HELENA_SENSOR` | ingestion identity | Required. Stamped on every event; the flow record carries neither |
| `HELENA_INPUT_FORMAT` | ingestion | Required. Names an adapter registered in `helena.normalizer` (ADR-0012); this module does not validate the value |
| `ABUSECH_AUTH_KEY`, `VIRUSTOTAL_AUTH_KEY` | provider credentials | Required. `Secret` |
| `RISINGWAVE_DSN`, `KAFKA_BOOTSTRAP_SERVERS` | infrastructure | Required. Addresses, not credentials |

Everything but the per-agent overrides is required: a missing or blank value is
a `ConfigurationError` at startup naming every variable that is missing.

## The names that were chosen here rather than found

Seven of the names were already live in the operator's `.env` and were taken
from it unchanged. Two were not, and had to be chosen:

- **`HELENA_TENANT` / `HELENA_SENSOR`.** Prefixed, unlike the rest, because a
  bare `TENANT` in a shared environment is a name another process sets by
  accident — and a wrong tenant is an isolation failure that looks like it is
  working. Task 1 appended both to the local `.env` with non-secret values so
  the loader resolves there; a real deployment sets its own.
- **`HELENA_INPUT_FORMAT`.** Added by task 8, prefixed for the same reason, and
  required for the reason nothing here has a default: a deployment reading its
  traffic through the wrong parser quarantines every record and looks like a
  producer problem. Its value names an adapter, and the registered names live
  with the adapters rather than here — `helena.config` resolves a string and
  `helena.normalizer.adapter_for` refuses an unknown one at startup, naming this
  variable and listing what is registered. Appended to the local `.env` as
  `flow-json`, the format the sample capture is in.

## Why the per-agent overrides cover url and token, not only the model

Only `LLM_MODEL_TRIAGE` and `LLM_MODEL_ANALYST` are set today.
`concept/07-principles.md` nevertheless says endpoints are configurable per
agent, and that recording endpoint and model per assessment is what makes
cross-wiring detectable. One resolution rule applied uniformly to all three
settings is less code than special-casing the model, so all three have
overrides, and `ModelSettings.source` records which variable each value came
from.

## Why `VIRUSTOTAL_AUTH_KEY` is required although VirusTotal is deferred

`concept/05-threat-intelligence.md` defers the provider; its quota is shared
with every future run. Deferring the *call* is not the same as deferring the
*configuration*, and the concept requires the example to document every variable
name. The key is therefore required and wrapped, and nothing calls VirusTotal.

If a deployment appears that has no VirusTotal key, this is the line to revisit:
making it optional would be the first optional non-override variable, so it
needs a decision rather than an edit.

## What is deliberately not here

| Absent | Until |
| --- | --- |
| A third agent's variables (`*_INVESTIGATION`) | The Investigation Agent stops being deferred |
| Topic names, and any other broker or engine setting beyond the two addresses | The increment that wires the broker and the engine |
| A `HELENA_ENV` / profile switch | Never, as far as this decision goes: a profile is a second place a value can come from, which is the silent-default failure with more steps |
| Redaction of a credential that travels in a URL path | Task 2, structured logging with credential redaction. `Secret` keeps a value out of `str`, `repr` and serialization; a key inside a URL string is a different problem and is that task's |
