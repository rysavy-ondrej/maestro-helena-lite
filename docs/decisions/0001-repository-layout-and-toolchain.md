# 0001 — One package, one test suite, one environment

**Status: accepted.** Task 0 (D0 Foundations).
**Authority:** `concept/06-technology.md` (Platform and runtime),
`concept/instruction.md` §1.

## Decision

- **Python 3.12**, pinned to that minor in `requires-python` and `.python-version`.
- **uv** for packaging, with `uv.lock` committed.
- **One package**, `helena`, in a `src/` layout, with **one module per
  architecture component** — `normalizer`, `context`, `enrichment`, `agents`,
  `tools`, `orchestration`, `sink`.
- **One pytest suite**, in `tests/`, mirroring the package.
- **A `Makefile`**, not a `justfile`: `make` is present on the node, `just` is
  not, and adding a task runner is a dependency.

## Why

**3.12 exactly, not ">=3.12".** RisingWave's released binary is dynamically
linked against `libpython3.12.so.1.0` and the ABI is not portable across minors
(`bin/README.md`). A project that resolves to 3.13 in some later environment
would fail against the engine, silently in the symlink case. The upper bound
makes that a resolution error instead.

**A `src/` layout.** The suite imports the installed package rather than
whatever happens to be adjacent to the working directory, so a module that is
missing from the distribution fails in the test run rather than in deployment.

**A module per component, not a package per component.** The components of
`concept/03-architecture.md` are the durable structure and are worth having
names now; a directory-with-`__init__` for each would be structure for one file.
A module becomes a package on the day it has a second file.

**Modules are placeholders with real docstrings.** Each states its
responsibility, the invariants that bind it, and a maturity label. That makes
the labels checkable — `tests/test_package_layout.py` fails on a module without
one, so an unlabelled component is a test failure rather than something nobody
notices (`concept/instruction.md` §5).

## What this does not decide

Lint and typecheck tooling — see
[0003](0003-lint-and-typecheck-tooling.md).
