# Demo — ingest and context, end to end

One script that puts `data/ingest/flow-sample.jsonl` through the pipeline as it
exists today and prints what came out the other side.

```bash
demo/run-demo            # start the engine and broker, then run it
demo/run-demo --down     # ... and stop them again afterwards

uv run demo/ingest_and_context.py    # if scripts/dev-up already ran
```

## What it actually does

Six stages, each one the real code path rather than a narration of it:

| | Stage | Through |
| --- | --- | --- |
| 1 | Resolve configuration | `helena.config.Settings.load()` |
| 2 | Apply the engine's schema | `helena.migrations` over `sql/migrations/` |
| 3 | Stage the sample as a capture, addressed by its own sha256 | `helena.normalizer.describe_capture` |
| 4 | Publish every record over the Kafka wire protocol | `helena.broker` + `publish_capture` |
| 5 | Consume, parse, stamp identity, store | `Normalizer.ingest_messages` into `EventStore` / `Quarantine` |
| 6 | Read back the contexts and entities | views the engine computed |

Nothing here reimplements a stage in order to show it, and nothing is mocked.
The records really cross the broker, and the contexts are really computed by
RisingWave from the view definitions in `sql/migrations/`.

## What it leaves behind

Nothing. It creates a schema named for the run, applies the migrations into it,
publishes to a topic named for the run, and drops the schema at the end. So it
is safe against an engine that already holds data, and it does not care what the
store's migration ledger says — including a store migrated before task 17's
declaration retrofit, which `uv run scripts/migrate.py` now refuses by checksum.

## What the output shows, and why each part is there

**The flatten trap, in the first record.** The sample's first flow is a DNS
lookup whose answer chain is CNAME → CNAME → A, so the address that was actually
resolved is at **index 2**. Reading `[0]` is the first entry in
`concept/instruction.md` §6's table of traps that have already cost this project
something.

**Identity is assigned, never read.** The raw record carries no tenant, sensor,
schema version or capture reference. All four are stamped at ingestion from
configuration, which is why a defaulted tenant would be an isolation failure that
looks like it is working.

**The counters reconcile against the file, not the topic.** The broker is
consume-once, so "did every record arrive" can only be answered against the
retained capture. The demo prints all four numbers and says whether they add up.

**Two windows, from one capture.** The sample is 130.8 seconds and straddles a
five-minute boundary, so it produces contexts at `21:30:00Z` (59 flows) and
`21:35:00Z` (3 flows). Traffic stays **bidirectional and is never summed** — a
beacon and a download differ by direction, and a single total would hide that.

**Scope, which is what the composition rule turns on.** Of the addresses in the
capture, some were contacted and some were only ever seen as a DNS answer. The
demo counts both. An address a host resolved but never talked to is a weaker
claim than one it connected to, and a row that could not tell those apart could
not support the rule.

**Which layer observed a name.** A domain seen in TLS SNI was connected to; one
seen only in a DNS query may never have been. That distinction is what the
rendering gets instead of per-domain byte counts, because a name carries the
traffic of the flows that *mentioned* it — an honest limitation
`concept/02-concepts-and-taxonomy.md` records rather than hides.

## What it does not show

**No enrichment and no assessment.** Nothing is matched against a feed, no agent
is called, and no verdict exists. Those are D3 and D4. The entity rows the demo
prints are the join target enrichment will use, not enrichment itself.

**Nothing about verdict quality.** There is no labelled corpus, so no claim about
whether any of this produces good answers is available from this or any other
script in the repository.

## Requirements

The pinned binaries in `bin/` and a populated `.env` — the same two things the
test suite needs. `demo/run-demo` calls `scripts/dev-up`, which verifies both
binaries against `docs/versions.md` and refuses to start anything that does not
match. It downloads nothing.
