# `data/`

Two kinds of thing live here and they are separated at the top level, because
they enter the pipeline at different ends and carry different obligations:

| | What it is | How it enters |
| --- | --- | --- |
| [`connections/`](connections/) | **Connection records** — the input. Bidirectional flow records, one per connection, in the `flow-json` contract | published onto the ingest topic and normalized (`helena.normalizer`) |
| [`enrichment/`](enrichment/) | **Enrichment lists** — reference data the context is joined *against*. Indicator feeds and identification lists | loaded by `helena.enrichment` into snapshot-versioned tables |

**One subfolder per source.** A source is where the data came from, not what
stage reads it — so there is no `ingest/`, which named a stage rather than a
provenance.

```
data/
├── connections/
│   ├── maintainer-host/   62 records, one host, 2.2 min   COMMITTED
│   ├── network-day/       143 captures, 239 850 records   not committed
│   └── malware-traffic/   Malware-Traffic-Analysis.net    placeholder
└── enrichment/
    ├── threatfox/         abuse.ch indicator exports      not committed
    └── netify/            application identification      not committed
```

Each source directory carries its own README where one exists; that is the
datasheet, and it is where provenance, clearance and content inventory live.

---

## What is committed, and why the rest is not

**Only `connections/maintainer-host/` is in the repository.** It is 62 records of
the maintainer's own host, captured by them and **cleared by them for
publication**, with a datasheet recording that clearance.

Everything else is deliberately absent:

- **`connections/network-day/`** is a whole network's traffic for a day. No
  clearance is recorded for it, so it is measured in place and never committed.
  An extract goes in only once a clearance does.
- **`enrichment/threatfox/`** and **`enrichment/netify/`** are third-party lists
  whose fair-use terms bind redistribution. A small extract as a test fixture is
  fine — `tests/fixtures/threatfox/` is one — and the full files are not.

`.gitignore` holds those three paths. A demo or script that needs one says so in
its own header, and [`../docs/demos.md`](../docs/demos.md) §3 marks which demos
need the uncommitted capture.

## The format is not this project's invention

`flow-json` is the output of [`shark-tools`](https://github.com/rysavy-ondrej/shark-tools)'s
**Enjoy**, which extracts bidirectional flow records from PCAP. Its schema is the
input contract field for field —
[`../docs/decisions/0012-input-format-adapters.md`](../docs/decisions/0012-input-format-adapters.md)
has the comparison. That is what makes a public PCAP dataset adoptable without
writing a converter, which
[`../docs/evaluation-corpus.md`](../docs/evaluation-corpus.md) §10 is about.

    python py/enjoy.py --mode batch --input-file capture.pcapng \
        --protocols dns,tls,http --stdout-file out.ndjson

## None of this is evaluation data

**There is no labelled corpus here, and every claim about verdict quality is
blocked on one that does not exist.** These files are for building, measuring and
demonstrating. `connections/network-day/` is a great deal more input than
`connections/maintainer-host/`, which is a different thing from evidence about
output.
[`../docs/evaluation-corpus.md`](../docs/evaluation-corpus.md) is what a corpus
would have to be; [`../docs/synthetic-corpus.md`](../docs/synthetic-corpus.md) §5
is what the generated one cannot measure.

## Handling captures from elsewhere

`connections/malware-traffic/` is a placeholder for
[Malware-Traffic-Analysis.net](https://www.malware-traffic-analysis.net/training-exercises.html)
exercises and holds no traffic yet. When it does, and for any dataset in
`../docs/evaluation-corpus.md` §10:

> **Treat those PCAPs as hazardous.** They may contain recoverable malicious
> payloads. Convert or replay them only in an isolated lab with outbound traffic
> blocked — **never onto a production network**, and never onto the network a
> HELENA deployment is monitoring, which would write attacker-controlled traffic
> into the store as though it had been observed.

## The rename, and where old paths survive

Reorganised **2026-09-13**. The previous layout was flat:

| Was | Is |
| --- | --- |
| `data/ingest/` | `data/connections/maintainer-host/` |
| `data/demo/` | `data/connections/network-day/` |
| `data/malware-traffic/` | `data/connections/malware-traffic/` |
| `data/threatfox/` | `data/enrichment/threatfox/` |
| `data/netify/` | `data/enrichment/netify/` |

**Seven comments in `sql/migrations/` still name the old paths, and they were
left there on purpose.** An applied migration is addressed by its checksum: the
ledger treats a changed file as *"the engine no longer holds what the repository
says it holds"* (`helena.migrations`), so editing one — even a comment — would
break every deployment that has already applied it. The affected files are
`0004`, `0006`, `0007`, `0008`, `0009` and `0010`; the table above is how those
comments resolve. `prds/` is also left alone, for a different reason: it is the
record of what was true when each task ran, and rewriting a record to match a
later rename is the one thing a record may not do.
