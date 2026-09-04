# 0003 — Lint and typecheck tooling: escalated, not chosen

**Status: escalated — awaiting a decision.** Raised by task 0 (D0 Foundations).

## The conflict

The task asked for a `justfile`/Makefile with **lint, test and typecheck**
targets. A linter and a type checker are both dev dependencies, and the approved
dev set is exactly `pytest`: `prds/CONTEXT.md` §3 states the baseline as
Pydantic, a dotenv loader, a Kafka client, a PostgreSQL driver and pytest, and
that **anything beyond that set is an escalation**. `concept/instruction.md` §3
says the same about reaching for tooling.

The task's steps rank below both, so the tools were not added.

## What was done instead

`make test` and `make check` are real. `make lint` and `make typecheck` exist and
**fail loud**, naming this file — rather than being absent, or silently doing
nothing, which is the failure mode the project's own rules single out.

`make check` runs what needs no new dependency and is worth running:
`uv lock --check`, `python -m compileall` over `src` and `tests`, and the suite —
which includes the dependency boundary test and the maturity-label test.

## What a decision needs to say

Which tools, and what they are for. A linter here would mostly be enforcing
formatting; the checks that have actually caught something in this project are
the executable ones — SQL run against a throwaway engine, a probe against the
real binary. A type checker has a stronger case, because the contracts are typed
and Pydantic models are where drift would show up first. Both are dev-only:
neither would enter `[project.dependencies]`.

Until then the targets stay failing, and this file stays `escalated`.
