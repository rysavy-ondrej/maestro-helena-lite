# bin

Third-party binaries the local pipeline runs. **Not project source, not
committed** — see [`.gitignore`](../.gitignore).

Rebuild on a fresh node with:

    scripts/build-binaries.sh

**That script does not exist yet.** The authority on what a recorded experiment
result refers to is [`../docs/versions.md`](../docs/versions.md), which carries
the sha256 of each file on disk, and the check that runs against it is:

    uv run scripts/dev_check.py --binaries-only

[`../docs/runbook.md`](../docs/runbook.md) covers running them, and its first
section is the libpython hazard below, measured.

| File | What | Pinned at |
| --- | --- | --- |
| `blink` | Kafka-protocol broker HELENA produces into (ADR-003). Built from source. | commit `645c814fe18edc43fc1d619d3f90f646ba18bedd` (2025-10-06) |
| `risingwave` | Ingestion target and context store (ADR-004). Official release binary. | `v3.0.3` |
| `lib/libpython3.12.so.1.0` | RisingWave links this. Fetched only when the system has no libpython3.12. | CPython 3.12.14 |
| `env.sh` | Puts `lib/` on `LD_LIBRARY_PATH`. | — |

Blink is a third-party binary the project runs, not builds — the pinned commit
exists so results stay reproducible, not because HELENA maintains it.

## Notes worth keeping

- RisingWave's released binary is dynamically linked against
  `libpython3.12.so.1.0`. Distributions shipping a different Python minor
  version (Ubuntu 26.04 ships 3.14) cannot satisfy this from their own
  repositories. Never symlink another minor version onto that SONAME — the ABI
  differs and the failure mode is silent.
- Blink's release build links wasmtime and takes a long time on a small node.
