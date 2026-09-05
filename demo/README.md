# Demos

Two scripts, both running the pipeline as it exists today rather than narrating
it. They answer different questions and the second is not a bigger version of the
first.

| | Script | Input | The question it answers |
| --- | --- | --- | --- |
| 1 | `ingest_and_context.py` | `data/ingest/flow-sample.jsonl` — 62 records, one host, 130.8 s | *what happens to a record*, at a size where every number can be checked by eye |
| 2 | `context_over_a_day.py` | `data/demo/20250920/` — 143 captures, 239 850 records, 3 199 sources, 23.97 h | *what a context looks like* when there is enough traffic for the answer to be interesting |

```bash
demo/run-demo            # start the engine and broker, then run demo 1
demo/run-demo --down     # ... and stop them again afterwards

uv run demo/ingest_and_context.py           # demo 1, if scripts/dev-up already ran
uv run demo/context_over_a_day.py           # demo 2, the whole day (~20 min)
uv run demo/context_over_a_day.py --files 12   # demo 2, the first two hours
```

---

# Demo 1 — ingest and context, end to end

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


---

# Demo 2 — context computation over a day of a network

`uv run demo/context_over_a_day.py`. Seven stages, the same real code paths,
against 143 ten-minute captures of one network's traffic for 2025-09-20 —
239 850 records, 3 199 source addresses, 23.97 hours.

## Where the capture is, and why it is not here

**`data/demo/` is in `.gitignore` and the capture is not in this repository.**
`data/ingest/flow-sample.jsonl` is 62 records of the maintainer's own host,
assessed by them as carrying nothing sensitive and cleared for publication with
a datasheet (`data/ingest/README.md`). This capture is a whole network for a
whole day and carries no such record. That is a reason to leave it in place, not
a claim about it: it is measured where it lies and nothing copies it into the
tree — not the demo, and not the test suite, which skips its two day-capture
tests when the directory is absent rather than depending on it. Committing an
extract is a decision for whoever can make it, and this branch does not make
it.

`--captures DIR` points the script somewhere else.

## What it does that demo 1 does not

**143 captures, not one file.** Each ten-minute archive is decompressed into a
capture named by its own sha256, and the directory is then read back through
`scan_captures`, which re-checks every name against its bytes. The capture
contract is not bent to fit a compressed file: the digest is over the records as
written out, so two archives that decompress to the same bytes are one capture.

**Reconciliation that can actually fail — and did.** `consumed` is a property of
the run, and a batch carries several captures, so there is no per-capture
consumed count and `ingest_counts` is not asked to invent one. What is checked
per capture is `normalized + quarantined == records`, read out of the engine's
own two counter views; the run-level check is `consumed == records`.

The first full run failed that check, and it is the most useful thing this demo
has produced. Publishing all 239 850 records up front takes 7.6 s; draining them
through one INSERT per record takes 11 minutes; the broker's `RETENTION` default
is **5 minutes**. 43 858 records — 18 % — were obliterated before the consumer
reached them, and the run said `INCOMPLETE` and named the number.

The fix is not a longer retention. `docs/runbook.md` §3 says not to reach for it
— "a longer retention would make a topic look like a store for a while" — and
`concept/03-architecture.md` is what that protects: the broker is consume-once
and restart-volatile, and a backlog on it is a durability assumption the design
does not make. A sensor produces while the normalizer consumes; it does not hand
over a day in one go. So the demo publishes and drains in batches of at most
25 000 records, each on its own topic — about 70 s of ingestion against a
5-minute window. A capture is never split across batches, because a capture is
the unit a record's provenance is expressed in.

The general point is worth keeping: **at 62 records this failure mode does not
exist, and at 239 850 it is the default outcome.** Nothing about the pipeline
changed between the two; the backlog did.

**Scale changes what the numbers mean.** 62 records made two contexts; this day
makes 12 089, over 3 199 hosts and 287 five-minute windows — 1.3 % of that grid,
because a context exists only where a host actually sent something. The demo
prints the shape of the day by hour, the busiest hosts, and the in/out ratios
that separate a host pulling a download from one broadcasting into a network
that never answers.

**And it prints how many entity rows one context holds**, which is the question
`concept/08-open-questions.md` records against the rendering bounds. The answer
is a distribution rather than a number: median 1, p90 3, p99 441, max 1 822.
Most host-windows are nearly empty and a small tail is enormous, so whatever
renders a context to an agent has to survive the busiest one — and a bound taken
from the mean of 14.6 is wrong by two orders of magnitude on exactly the contexts
triage is for. Six hours of this capture peaked at 795; the tail needs the whole
day to see, which is why the demo prints the percentiles and not an average.

**The Public Suffix List, on names worth normalizing.** The day's 2 490 distinct
names collapse to 726 registrable domains — and the table is worth reading for
the suffixes that are themselves registrable domains in it, like a CDN's
`com.akadns.net`, where every name underneath belongs to a different customer.
That is the difference between a feed that lists a name and one that lists a
domain. The list is fetched over the network; `--no-suffix-list` skips it.

## What it found

A pipeline built and measured against 62 records of one host met a day of a whole
network. What broke is more useful than what worked, and this is the rest of it —
the broker-retention loss above belongs on the same list.

**The retention boundary drops all of it.** The horizon is 24 hours and the
capture is from 2025-09-20, so every context is outside it: the retained view is
empty, `helena_signal_retention_rejections` reports the rate, and nothing here
can be frozen or cited. That is the boundary working — the signal layer computed
every context and the layer above it dropped them all — and it is the only half
of the boundary an archived capture can demonstrate. Showing it pass traffic
through needs a capture from today.

**Multicast and broadcast senders are hosts.** `helena_signal_host_context`
groups by `src_address` and filters nothing, so `224.0.0.251` and
`255.255.255.255` are near the top of the busiest-hosts table. With one Windows
endpoint that never came up; on a LAN it is most of the table, and any reader of
that view has to know it.

**1 043 entities had no value at all** — until `sql/migrations/0010_entity_value_null_guard.sql`.
Four branches of `helena_signal_entity_observations` read `tls.sni`, `tls.ja3`,
`tls.ja4` and a request `uri` with no NULL guard, which was safe only while the
flow-record contract required all four. It does not any more: a flow captured
mid-connection has TLS records and no handshake, so there is no name and no
fingerprint to extract. Because `helena_signal_context_entities` groups by
`entity_value`, every handshake-less flow in a context collapsed into one
phantom row carrying their combined traffic and joinable to no feed.

Fixing it cost more than four predicates. RisingWave has no `CREATE OR REPLACE
VIEW`, so changing a view means dropping it and everything standing on it —
seven objects — and recreating all seven. And `migrations.declarations()` refused
any relation created twice anywhere in the migration set, which made the
recreate-to-change pattern that 0009's own header prescribes impossible. It now
walks the `CREATE`s and `DROP`s in the order they run and refuses a create only
when something of that name is live, which brought three more refusals with it: a
drop of something nothing created, a drop of something still read, and `CASCADE`
— because a drop that takes six objects the file does not name cannot be
reviewed. 0010 drops all seven by name, in order.

The demo still prints the NULL count; it is zero now, and the note says what it
used to be.

## What it does not show

The same two things demo 1 does not: **no enrichment and no assessment**, and
**nothing about verdict quality**. There is still no labelled corpus, and a day
of unlabelled traffic is not one — it is a great deal more input, which is a
different thing from evidence about output.
