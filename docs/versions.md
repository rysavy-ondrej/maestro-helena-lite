# Pinned third-party binaries

Blink and RisingWave are binaries the project **runs, not builds**. They are
pinned so that a recorded experiment result refers to a known artifact, and the
pin that is actually checkable is the **sha256 of the file on disk** — see
[Why the checksum is the pin](#why-the-checksum-is-the-pin).

The operational side — bringing them up, taking them down, and the hazard that
has to be checked before either — is in [`runbook.md`](runbook.md).

`scripts/dev_check.py` reads the `pins` block below and is the only code that
knows these values. `scripts/dev-up` refuses to start anything that does not
match, and `tests/test_infrastructure.py` fails the suite for the same reason.

| File | What it is | Where it came from | Version it reports |
| --- | --- | --- | --- |
| `bin/risingwave` | Streaming engine and single store. Speaks the PostgreSQL wire protocol | GitHub release `risingwavelabs/risingwave` tag `v3.0.3`, published 2026-08-17 | `risingwave 3.0.3 (ec07f2eb75)` |
| `bin/blink` | Kafka-protocol broker, ingress and egress | Built from `cleafy/blink` commit `645c814fe18edc43fc1d619d3f90f646ba18bedd` (2025-10-06) | `blink 0.2.0` |
| `bin/lib/libpython3.12.so.1.0` | The shared library `bin/risingwave` is dynamically linked against | CPython 3.12.14 | — |

## The pins

Values verified on disk on 2026-09-03. `scripts/dev_check.py` parses this block;
`key = value`, one per line, and nothing else in it.

```pins
sha256.bin/blink                    = b07ff9efec1aa42bd1559db0c50e95686ec2ca552131c63f84c06a92c795446f
sha256.bin/risingwave               = c92b2ca003e9e86d9b46a9c6774625ed8ee61a066782547ad33809225bc71d6e
sha256.bin/lib/libpython3.12.so.1.0 = f39b6f857a27e6db229fd047562c75f3ad60b34a05c83d796e3951a551399ee1
version.bin/blink                   = blink 0.2.0
version.bin/risingwave              = risingwave 3.0.3 (ec07f2eb75)
version.engine-wire                 = PostgreSQL 13.14.0-RisingWave-3.0.3 (ec07f2eb759bd2d8a12a55b030bf581b82adb4b9)
```

`version.engine-wire` is what `SELECT version()` returns over the PostgreSQL
wire protocol. It is the same pin as `version.bin/risingwave` seen from the other
side, and the smoke test asserts the running engine reports it — so a binary
swapped underneath a running deployment fails the suite rather than being
noticed later.

## Why the checksum is the pin

Neither binary can confirm its own provenance:

- **Blink does not embed its commit.** The binary reports `blink 0.2.0` and its
  banner says `v0.2.LOCAL`; `645c814f…` appears nowhere in it. The commit was
  confirmed to exist in `cleafy/blink` through the GitHub API, but nothing ties
  *this file* to *that commit* except the record in `bin/README.md`.
- **RisingWave's release tag was confirmed** through the GitHub API, and the tag
  publishes both `risingwave-v3.0.3-x86_64-unknown-linux.tar.gz` and
  `risingwave-v3.0.3-x86_64-unknown-linux-all-in-one.tar.gz`. **Which of the two
  this file was extracted from was not re-verified** — that is a 200 MB download
  — so the asset name is not recorded above.

So the version strings are a sanity check and the checksums are the pin. A file
that hashes to the value above is the file the recorded results were produced
against; a file that does not is an unknown artifact, whatever it calls itself.

## Environment

| | Pinned at | Where |
| --- | --- | --- |
| Python | 3.12.14 exactly (`>=3.12,<3.13`) | `pyproject.toml`, `.python-version` |
| uv | 0.12.7 | the machine |
| Runtime dependencies | `uv.lock` | committed |

`requires-python` carries the **upper** bound on purpose: RisingWave links
`libpython3.12.so.1.0`, and the upper bound turns a Python minor bump into a
resolution error rather than a silent runtime failure. See the runbook.

## Obtaining the binaries on a fresh node

`bin/` is not committed (`.gitignore`), and **`scripts/dev-up` does not download
anything** — it verifies what is on disk and runs it. This is deliberate:
`prds/CONTEXT.md` §3 states the binaries are third-party artifacts the project
runs and must not be downloaded, containerised or added as dependencies, which
overrides the PRD step that asked `dev-up` to fetch them.

`bin/README.md` names `scripts/build-binaries.sh` as the way to rebuild them on a
fresh node. **That script does not exist**; the reference has been dangling since
task 0. Until it does, obtaining the binaries is a manual step, and the values in
this file are how you tell whether you got the right ones.
