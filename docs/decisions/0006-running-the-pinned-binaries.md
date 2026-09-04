# 0006 — Running the pinned binaries: verify, do not fetch

**Status: accepted.** Task 3 (D0 Foundations).
**Authority:** `concept/06-technology.md` (broker and engine are binaries the
project **runs, not builds**; observability is local only), `prds/CONTEXT.md` §3
(the binaries ship with the project and must not be downloaded, containerised or
added as dependencies), `concept/instruction.md` §2 (the broker is addressed
only through the Kafka wire protocol).

## `scripts/dev-up` verifies, it does not fetch

The PRD step for this task read *"a `scripts/dev-up` that **fetches** and runs
the pinned Blink commit and pinned RisingWave release"*. `prds/CONTEXT.md` §3 is
higher authority and says the opposite: *"Do not build these, download them,
containerise them, or add them as dependencies."*

`dev-up` therefore **checks the binaries on disk against `docs/versions.md` and
runs them**, and fails loud naming the file if one is absent or does not match.
Nothing in this repository downloads a binary.

The consequence is real and is recorded rather than papered over: **there is no
automated way to obtain the binaries on a fresh node.** `bin/README.md` names
`scripts/build-binaries.sh` for that, and that script has never existed. Writing
it is a separate piece of work; whoever does it inherits the checksums in
`docs/versions.md` as the acceptance test.

## The checksum is the pin, not the version string

Neither binary can confirm its own provenance — blink does not embed its commit,
and RisingWave's tag publishes two Linux assets of which only one is on disk.
So the recorded sha256 of each file is the pin, the `--version` strings are a
sanity check, and `docs/versions.md` says which is which.

## The engine's telemetry is off

RisingWave reports to `telemetry.risingwave.dev` by default. `concept/06` puts
the whole automatic pipeline on the local node and treats a second outbound
channel as a decision; ADR-0005 already refused hosted tracing for the same
reason. `scripts/risingwave.toml` sets `[server] telemetry_enabled = false` and
holds nothing else. This is about an outbound channel, not about the vendor.

## The broker is checked over Kafka, not over its REST port

Blink exposes a REST port (default 30004) that would be a simpler health check.
It is not used. `concept/06-technology.md` makes the Kafka wire protocol the only
way the broker is addressed, on both ends, and a health check that reaches for
the easier door is how that boundary erodes. `scripts/dev_check.py` asks for
Kafka metadata.

## The hazard this task existed to record

The engine binary links a specific Python minor's shared library, and the
failure mode of getting that wrong is **nothing at all** — measured, not
inferred. `docs/runbook.md` §1 has the measurements. The defence is structural
(`ldd` plus a checksum on the resolved file), because no runtime behaviour
distinguishes a correct install from a broken one.
