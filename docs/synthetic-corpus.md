# The synthetic corpus: traffic built to match real indicators

Maturity: `experimental`. The generator runs and its output is exercised by
`tests/test_plant.py`. Nothing here has been used to measure a verdict, and §5
says why it cannot be.

## 1. The problem it solves

Two facts, both measured in this repository, combine into a gap:

- **Ordinary traffic matches nothing.** `demo/assess_a_slice.py` pass A against
  the real feed is **131 entities, every one `no_match`**. ThreatFox's recent
  export is a two-day sighting window of a few thousand indicators
  ([`evaluation-corpus.md`](evaluation-corpus.md) §4), and one host's browsing
  does not intersect it.
- **Since the pre-triage gate, a context with no claims never reaches a model
  at all** ([ADR-0047](decisions/0047-the-pre-triage-gate.md)). Before the gate,
  a claim-free context was still triaged and the agents could be exercised on it.
  Now it is cleared deterministically.

So on a corpus of real traffic the agents are **unreachable**: nothing matches,
nothing is claimed, the gate clears everything and no model is ever called. To
exercise triage, the analyst, the composition rule and the escalation path at
all, some traffic has to intersect the feed. That is what this builds.

`scripts/rebase_capture.py` is the other half and runs first: it moves a capture
so its windows and a loadable snapshot overlap. This script then makes some of
those windows contain something.

## 2. What is modified, and what is not

**Real records, minimally rewritten.** A planted record is a genuine flow from
the capture with its **destination** changed to a listed indicator. Everything
else — the byte and packet counts, the duration, the TLS parameters, the timing,
the source host — is what the sensor observed. The alternative, generating flows
from nothing, produces traffic whose statistics are whatever the generator's
author imagined, and the composition rule reads those statistics.

| Indicator | What is rewritten |
| --- | --- |
| `ip:port` | `ip.dst`, and the port on `tcp`/`udp` where the scenario wants a match |
| `domain` | `dns.queries[].qn`, the matching `dns.responses[].qn`, and `tls.sni` where the flow has one |
| `url` | the `http.req[].uri` and its host |

**Identity is never rewritten.** `ip.src` stays the host that was really there,
and `tenant`/`sensor` are stamped by the normalizer from configuration, not from
a record. A generator that could write an identity would be writing the one field
`concept/instruction.md` §6 says must never silently default.

## 3. The scenarios, and what each is for

A single "plant a match" case tests the join and nothing else. These five exist
because each one turns a **different** rule on or off, so a failure names which:

| Scenario | Built as | What it should exercise |
| --- | --- | --- |
| `contacted-address` | a listed `ip:port` as `ip.dst` of a real TCP flow, on the listed port | the ordinary path: claim, scope satisfied, deterministic escalation if confidence clears the configured threshold |
| `resolved-only` | the same address as a DNS **answer** only, never as `ip.dst` | **scope before severity.** The claim exists and the host never contacted it, so it must *not* escalate on its own |
| `port-mismatch` | a listed `ip:port` as `ip.dst` on a **different** port | `port_matched = false` — the port qualifies the match rather than filtering it ([ADR-0042](decisions/0042-port-qualification-of-an-address-match.md)) |
| `queried-domain` | a listed domain in the DNS query and the TLS SNI | the domain side, where the composition rule's scope test does **not** reach — `hazards.md` §5 |
| `below-threshold` | an indicator whose `confidence_level` is under `[thresholds]` | a claim that reaches triage but does **not** escalate deterministically; with the gate on, this is what proves the gate admits on claim *count*, not on confidence |

## 4. The labels, and what they are labels *of*

Every run writes `LABELS.json`: one entry per planted record, naming the capture,
the record `id`, the host, the indicator, its type and confidence, the scenario,
and two expectations — `expects_claim` and `expects_deterministic_escalation`.

**Those expectations are about the pipeline's deterministic layer, and about
nothing else.** They are derived from the configured threshold and the
composition rule, so they are checkable: if a `contacted-address` plant at
confidence 1.0 does not escalate, something is broken. They are **not** labels of
whether the traffic is malicious, because the traffic is a real benign flow with
a rewritten destination.

There is deliberately **no** `expected_verdict` field. A model's answer on
synthetic traffic is not a thing this corpus can be right or wrong about, and a
column inviting someone to fill one in is how a test fixture becomes a
"benchmark" nobody meant to publish.

## 5. What this cannot measure, stated before anyone tries

- **Not accuracy, recall or false-positive rate.** The positives are planted and
  the negatives are unlabelled real traffic that nobody has checked. A context
  with no plant is not known-benign; it is unexamined.
- **Not the escalation rate.** The rate here is a function of how many plants the
  generator was asked for.
- **Not detection quality.** Every plant is an exact-match join against a feed.
  Nothing here tests whether the pipeline finds something the feed has never
  heard of, which is the capability the gate removed and the one a real corpus
  would have to measure.
- **Not a substitute for [`evaluation-corpus.md`](evaluation-corpus.md).** That
  document's requirements — labelled by an analyst, time-correct, multi-host,
  containing genuine multi-stage activity — are all still unmet. This corpus
  makes the agents *reachable*. It does not make their answers *measurable*.

## 6. Using it

```bash
# 1. move the traffic so a loadable snapshot can cover its windows
uv run scripts/rebase_capture.py --source data/demo/20250920 --out .corpus/day --ending-now

# 2. plant indicators from the feed the deployment actually loads
uv run scripts/plant_indicators.py --captures .corpus/day --export data/threatfox \
    --out .corpus/planted --per-scenario 2

# 3. load a snapshot dated before the traffic, then replay
uv run scripts/load_threatfox.py
uv run scripts/replay_capture.py --captures .corpus/planted <sha256> --ingest
```

Step 3's ordering is the one that is easy to get wrong: a snapshot's validity
interval begins when it was fetched, so **a snapshot loaded after the traffic does
not enrich it**. `rebase_capture.py` prints the instant the snapshot must predate,
and `helena.enrichment.load_threatfox` takes `now=` for exactly that.

`.corpus/` is gitignored. The generated corpus is **not** committed: it is derived
from a capture that is itself not in this repository, and a planted capture in
source control is a file that looks like evidence of an intrusion.
