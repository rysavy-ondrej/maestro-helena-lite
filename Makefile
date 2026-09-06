# HELENA — the whole toolchain. One package, one test suite, one environment.
#
# Everything runs through `uv run`, against the `.venv/` that is already at the
# project root. Never `pip`, never a second virtualenv, never a system python.

.PHONY: help sync test check acceptance lint typecheck dev-up dev-down migrate storage

help:
	@echo "sync       install the locked environment (uv sync)"
	@echo "test       run the one pytest suite"
	@echo "acceptance run the enrichment-status gate alone (a subset of test)"
	@echo "check      lockfile is in sync, sources compile, suite passes"
	@echo "dev-up     verify the pinned binaries and run the engine and broker"
	@echo "dev-down   stop them again"
	@echo "migrate    apply sql/migrations/ to the configured engine"
	@echo "storage    what each relation of the migrated schema stores"
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
