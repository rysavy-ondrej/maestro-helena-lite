# Ingest fixtures

Recorded flow records used to build and test against. **Not evaluation data** —
the labelled corpus does not exist, and every claim about verdict quality is
blocked on it ([`concept/08-open-questions.md`](../../concept/08-open-questions.md)).

> Identifiers below of the form `B-nnn` or `OQ-n` come from an earlier tracking
> system and **do not resolve in this repository**. The facts they annotate —
> the clearance, the provenance, the content inventory — were verified against
> the capture and stand on their own.

---

## `flow-sample.jsonl` — datasheet

**Clearance status: CLEARED** (B-098 closed, 2026-09-01). Captured by the
project maintainer, who has assessed it as carrying no sensitive information
and authorised its publication in this repository. The *Content inventory*
below is kept as a factual description of what the fixture contains — it is
useful when reasoning about what a rendered `TriageContext` would carry, not a
clearance caveat.

### Identity and version

The checksum is the version. Any recorded experiment result that names this
fixture refers to this exact byte sequence; a re-capture is a new fixture with a
new checksum, never an update to this one.

| Property | Value |
| --- | --- |
| Path | `data/ingest/flow-sample.jsonl` |
| SHA-256 | `6c2f903e2e12117cfcc5ba5b1c3afa3a201e055a64d617db58f0ea4e19d7c39b` |
| Git blob | `0b6387c55db18b9bbe4900bad1ad1b9aec8ff199` |
| Size | 80 516 bytes |
| Records | 62 (JSONL, one flow record per line) |
| Schema | ADR-006 flow record |
| Origin | Captured by the project maintainer (Ondrej Rysavy). Own capture, own environment. |
| Terms | Published in this repository by the maintainer; the repository carries no separate `LICENSE` file, so its terms govern. |
| Entered the tree | `b44efa2`, unreferenced by any document until EXP-001 |
| Profiled by | [EXP-001](../../experiments/EXP-001-flow-record-field-population.md) |

### Capture conditions (derived from the data, not from a source statement)

Everything in this section was computed from the file itself rather than taken
from a capture log, so it describes what the bytes say.

| Property | Value |
| --- | --- |
| Window | 2024-06-01T21:32:57.777Z … 21:35:08.556Z |
| Span | 130.8 s (2.2 min) |
| Source hosts | **1** — `10.127.0.100` (RFC1918) |
| Destinations | 16, all public |
| Destination ports | 53 ×30, 443 ×25, 80 ×6, 1900 ×1 |
| Protocols | TCP 31, UDP 31 |
| Layers present | `ip` 62, `tcp` 31, `udp` 31, `dns` 30, `tls` 25, `http2` 15, `http` 11 |
| Labels | **none** — no ground truth of any kind |

**Traffic profile.** One Windows 10 endpoint performing routine Microsoft
telemetry: Windows Update (`fe3cr.delivery.mp.microsoft.com`,
`slscr.update.microsoft.com`), certificate-trust list fetches
(`ctldl.windowsupdate.com`), settings and diagnostics
(`settings-win.data.microsoft.com`, `config.edge.skype.com`), Office licensing
(`nexusrules.officeapps.live.com`), sign-in (`login.live.com`), MSN/Bing content
and advertising (`arc.msn.com`, `g.bing.com`, `tse1.mm.bing.net`), OCSP
(`ocsp.digicert.com`), a public-IP lookup (`api.ipify.org`), UPnP/SSDP on 1900,
and 11 reverse-DNS lookups. There is **no malicious activity and nothing
adversarial** in this capture.

### Content inventory

EXP-001 noted "a `deviceId` GUID" in passing. A full scan finds substantially
more. The maintainer has cleared this content, so none of it blocks use — it is
recorded because the fixture is the input the pipeline will be built against,
and these are the fields that will flow through it.

| Category | What is present |
| --- | --- |
| Stable device identifiers | `deviceId` (×6), `DeviceId`, `LocalDeviceID`, `localId`/`localid`, `sampleId`, `rid`, `uid`, `aid`, `asid`, `anid` — plus **8 distinct non-zero GUIDs** across 39 occurrences |
| Hardware inventory | CPU identifier/manufacturer (`AuthenticAMD`)/model/cores/clock speed, total RAM, primary disk type and capacity, system volume capacity, chassis type, TPM version, Secure Boot capability, display size and resolution |
| OS and configuration state | full OS version and build, install date, installation type, activation channel, retail-OS flag, virtual-device flag, VBS state, servicing branch, flight ring and flight IDs, telemetry level |
| Management posture | `IsMDMEnrolled`, `IsCloudDomainJoined`, `UpdateManagementGroup`, `BranchReadinessLevel` — a managed enterprise endpoint |
| User locale and region | install language, UI locale, default user region, country |
| Usage schedule | `ActiveHoursStart` / `ActiveHoursEnd` — the working hours of the machine's user |
| Advertising identifiers | `adUnitId`, `publisherId`, `pubid`, `anid` (MSN/Bing ad requests) |
| Software inventory | User-Agent strings with exact build numbers, an application GUID, and driver-store paths |

**Not present**, checked explicitly: no credentials, passwords, session tokens,
cookies, authorization headers, or private keys. No payload bodies — the schema
carries metadata only.

**Why this is still worth recording.** Repository clearance and pipeline
handling are different questions. A `TriageContext` rendered from this host
would carry these identifiers to the hosted model at e-infra (AC-15, AC-20),
and the same query-string content is what the Analyst Agent must treat as
untrusted data rather than instructions (AC-14). Those constraints are about
what the running system sends and trusts, and they hold regardless of the
fixture's clearance here.

It is also a reminder that stripping query strings is a **correctness**
requirement independent of privacy: storing the **host part** of a URI rather
than the whole thing is a rule of this project too
(`concept/instruction.md` §6, and `concept/05-threat-intelligence.md` for the
domain entity).

### Provenance (B-098, closed 2026-09-01)

Captured by the project maintainer in their own environment, and cleared by them
for publication in this repository as carrying no sensitive information. That
answers authorship, capture authority, and permission to publish.

Two details remain simply unrecorded rather than open questions — the capture
tool and the exact collection point are not stated anywhere in the file or in
git. Neither blocks anything; note them if a second fixture is ever captured, so
the two can be compared on equal terms.

### What it is good for, and what it is not

**Good for** (per EXP-001's ACCEPT decision): building and testing the ingestion
slice. It is real, schema-conformant, small enough to assert on record by
record, and it exercises every optional layer plus both ADR-007 defects — a
12-element `dns.responses` array and 32 full URIs where a bare domain was
assumed.

**Not** an evaluation corpus, and no measurement may rest on it: 62 records, one
host, 2.2 minutes, no labels, no malicious activity, no ground truth. Its layer
ratios describe this capture, not the schema — any expectation derived from them
will be wrong on real traffic (EXP-001, INCONCLUSIVE as a corpus).

**That warning has since been collected on.** A second capture — a day of one
network, 239 850 records, 3 199 source addresses — was refused in its entirety by
the flow-record contract measured from this fixture: a quarantine rate of 100 %.
Twenty-eight fields had been marked required on the strength of this capture
alone and are optional in reality. The addendum in
[`docs/decisions/0010-capture-identity.md`](../../docs/decisions/0010-capture-identity.md)
records what moved and what it cost. Nothing about this fixture changed; what
changed is that it is no longer the only thing requiredness rests on.
