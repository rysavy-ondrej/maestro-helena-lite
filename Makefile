# HELENA — the whole toolchain. One package, one test suite, one environment.
#
# Everything runs through `uv run`, against the `.venv/` that is already at the
# project root. Never `pip`, never a second virtualenv, never a system python.

.PHONY: help sync test check acceptance conformance lint typecheck dev-up dev-down migrate storage rendering-size status

help:
	@echo "sync       install the locked environment (uv sync)"
	@echo "test       run the one pytest suite"
	@echo "acceptance run the enrichment-status gate alone (a subset of test)"
	@echo "conformance  run the must-never-happen table alone (a subset of test)"
	@echo "check      lockfile is in sync, sources compile, suite passes"
	@echo "dev-up     verify the pinned binaries and run the engine and broker"
	@echo "dev-down   stop them again"
	@echo "migrate    apply sql/migrations/ to the configured engine"
	@echo "storage    what each relation of the migrated schema stores"
	@echo "status     the pipeline's own numbers, read out of the engine"
	@echo "rendering-size  what a real capture renders to, against the configured budget"
	@echo "lint       not yet available - see docs/decisions/0003-lint-and-typecheck-tooling.md"
	@echo "typecheck  not yet available - see docs/decisions/0003-lint-and-typecheck-tooling.md"

sync:
	uv sync

test:
	uv run pytest -q

# The D3 gate. Not a second suite - these tests are part of `make test` and are
# marked so they can be run alone, because "the triage stage is not buildable
# until this passes" needs something a person can actually run. See the head of
# tests/test_acceptance_enrichment.py.
acceptance:
	uv run pytest -q -m acceptance

# The D8 gate: `concept/07-principles.md`'s "Behaviour that must be impossible",
# one named test per row of the table. Like `acceptance` this is not a second
# suite - it is part of `make test` and therefore of `make check`, which is what
# makes it required. The marker exists because "do the guarantees still hold" is
# a question someone needs to be able to ask on its own, and because the answer
# takes half a minute rather than twelve.
#
# ADDING A ROW TO THE TABLE MEANS ADDING A TEST, and that is enforced rather than
# asked for: tests/test_conformance.py parses the note on every run and fails
# when a row has no test named for it. Its module docstring is the whole rule.
conformance:
	uv run pytest -q -m conformance

dev-up:
	scripts/dev-up

dev-down:
	scripts/dev-down

# The engine's schema. Apply it before anything is ingested - the broker is
# consume-once, so a view created later starts empty. See docs/runbook.md.
migrate:
	uv run scripts/migrate.py

# What the materialization policy costs, read off the running engine rather
# than argued from the note. A plain view never appears with a number - see
# docs/decisions/0016-view-layering-and-materialization-policy.md.
storage:
	uv run scripts/dev_check.py --storage

# What a real capture actually renders to - entity rows per host and characters
# per section, read off the engine rather than assumed. config/rendering.toml
# cites what this produced; see docs/decisions/0019-the-rendering-size-budget.md.
rendering-size:
	uv run scripts/measure_rendering.py

# `helena status`: latency, cost, staleness, escalation, the typed failures and
# the end-to-end record reconciliation, every one of them a plain SELECT over the
# single store. Not a health check - it prints numbers and does not decide which
# are bad; docs/runbook.md §13 explains them. Pass the retained capture directory
# to include how many records existed:
#
#     uv run scripts/status.py --captures data/ingest
status:
	uv run scripts/status.py

check:
	uv lock --check
	uv run python -m compileall -q src tests scripts
	uv run pytest -q

# Fail loud rather than quietly do nothing. Lint and typecheck tooling is a dev
# dependency beyond the approved set, so it needs a recorded decision first.
lint typecheck:
	@echo "$@: no tooling approved yet."
	@echo "Adding a linter or a type checker is a dependency decision - see"
	@echo "docs/decisions/0003-lint-and-typecheck-tooling.md before adding one."
	@exit 1
