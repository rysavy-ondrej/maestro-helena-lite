# 0005 — Local structured logging, and where credentials are redacted

**Status: accepted.** Task 2 (D0 Foundations).
**Authority:** `concept/07-principles.md` ("Observability", "Secrets and
configuration"), `concept/06-technology.md` (the technology table),
`concept/05-threat-intelligence.md` ("Credentials, rate limits and terms"),
`concept/instruction.md` §3.

`helena.observability` is the one log channel. One JSON object per line on
stderr, with a fixed set of top-level keys, redacted on the way out.

## No hosted tracing, and the absence is a test

`concept/06-technology.md` records observability as **local structured logs
only**, because a hosted tracer is a **second egress channel** carrying prompts,
rendered context and retrieved provider text — needing its own send policy, its
own disclosure record and a second vendor's data-handling terms verified
alongside the first. `concept/instruction.md` §3 makes adding one an escalation.

`tests/test_dependency_boundary.py` enforces it three ways: no hosted telemetry
distribution is declared, no module in the package imports one, and none is even
*resolvable* in the environment — so a tracer arriving as a transitive
dependency of something approved is a test failure rather than one `import` line
away from working.

The audit record is the stored assessment, not a trace UI. Latency, cost,
staleness, gaps, escalation and the version set are typed columns on stored rows;
the log is for what happens between them.

## The record

Ten top-level keys, always, in this order. Anything a caller adds is nested
under `fields`, so a caller cannot shadow `tenant`.

| Key | What it carries |
| --- | --- |
| `timestamp` | UTC, ISO 8601 |
| `level` | `info`, `warning`, `error` |
| `component` | The emitting module — the architecture component |
| `event` | A dotted name for *what happened*, e.g. `feed.fetch.failed` |
| `tenant`, `sensor` | From `Settings.identity`. No logger exists without them |
| `event_id` | The normalizer-assigned identity of a flow event, or null. **Not** `event` |
| `context_id` | The identity of a host context, or null |
| `versions` | The version set the record cites, or null — an empty one is refused |
| `fields` | Everything else |

`event` and `event_id` are two different things and both were required, so both
are here under names that say which is which. `versions` is null when the record
cites no version set and a mapping when it does; passing an empty mapping raises,
because an empty version set is not a version set.

Blank is refused everywhere an identity appears — a defaulted tenant is an
isolation failure that looks like it is working — and a field that will not
serialize raises rather than falling back to `repr()`, which is exactly how an
unredactable object reaches a log line.

## Redaction happens at the emitter, not at the call site

A call site that has to remember to redact is a call site that will one day
forget. Three passes, in this order:

1. **Every value is redacted before serialization.** Strings are swept for
   registered secret values, and any URL embedded in a string is stripped
   structurally. Nested mappings and lists are walked; a `helena.config.Secret`
   becomes the marker.
2. **`outbound_request` and `exception` route the request URL through
   `Redactor.url` explicitly.** These are the two paths the concept names.
3. **The serialized line is swept once more** for registered secret values. This
   is structure-blind and therefore safe on JSON; it is what catches a value that
   arrived by a route the first pass did not know about.

`Redactor.url` is not only for logs — a loader records the URL it fetched as
provenance, and that row goes through the same helper before it is stored.

## What the redactor knows, and what it refuses to guess

**Registered values.** Every `Secret` in `Settings` — the two provider keys and
both agent tokens — is replaced wherever it appears, in a path segment, a query
value, an exception message or a nested field. This is what covers a key
travelling in a URL *path*, where nothing about the segment marks it as a
credential. `Redactor.from_settings` is the one place in the package that calls
`Secret.reveal()` for a reason other than using the credential; the values go in
and do not come out.

**Structural rules**, which cover a credential nobody registered: URL userinfo is
replaced whole, and the value of a query parameter with a credential-shaped name
(`token`, `auth_key`, `api_key`, `password`, `signature`, …) is replaced whatever
it is. Over-redacting a query parameter costs a diagnostic; under-redacting one
costs a credential.

**What it deliberately does not do is guess at path segments.** A segment that
merely *looks* like an opaque key is left alone. This project fetches URLs whose
path segments are file hashes — `https://mb-api.abuse.ch/downloads/<sha256>/` —
and a heuristic that redacted those would destroy the provenance the fetch exists
to record. The consequence, stated plainly: **an unregistered credential in a
path segment is not redacted.** Every credential this project holds is
registered, and configuration is the only way one enters the process, so the gap
is closed by `helena.config` rather than by guesswork here.

## What was verified, by execution

- `urllib.error.HTTPError.url` carries the **whole** request URL including a
  path-embedded key, while `str(exception)` does not. An exception logged by its
  attributes leaks; one logged by its message does not. Both are redacted.
  Checked against a real 404 from `threatfox.abuse.ch` and against a real local
  HTTP server in the suite.
- A real fetch of the live abuse.ch host with the real `ABUSECH_AUTH_KEY` in the
  path, logged through this module, produced
  `https://threatfox.abuse.ch/export/***redacted***/json/recent/` on both the
  request line and the failure line, with the key absent from the output.
- **The current ThreatFox bulk export does not take the key in the URL path.**
  `https://threatfox.abuse.ch/export/json/recent/` answered `200` with no
  credential at all, and both key-in-path shapes tried answered `404`. The
  redaction rule is kept as a rule about a *class* of URL, not about that
  endpoint: the concept records that a live key already reached a project
  conversation inside a pasted link, and the auth mechanism for the current API
  is an `Auth-Key` header (task 1). The feed-loader increment must establish the
  bulk endpoint and its auth for itself rather than inherit an assumption.

## One logging path

`tests/test_observability.py::test_the_package_has_no_second_logging_path`
forbids `print()` and the standard library's `logging` inside `helena`. Neither
is a second *egress* channel in the hosted sense, but both write unswept strings
to a stream, which is all a credential needs to reach a file.

Third-party libraries on the dependency list do log through the standard
library's `logging`. Nothing configures a handler for them yet, so their records
go nowhere. Routing or silencing them belongs to the increment that first runs
one against a real service.
