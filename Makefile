# HELENA — the whole toolchain. One package, one test suite, one environment.
#
# Everything runs through `uv run`, against the `.venv/` that is already at the
# project root. Never `pip`, never a second virtualenv, never a system python.

.PHONY: help sync test check lint typecheck dev-up dev-down migrate

help:
	@echo "sync       install the locked environment (uv sync)"
	@echo "test       run the one pytest suite"
	@echo "check      lockfile is in sync, sources compile, suite passes"
	@echo "dev-up     verify the pinned binaries and run the engine and broker"
	@echo "dev-down   stop them again"
	@echo "migrate    apply sql/migrations/ to the configured engine"
	@echo "lint       not yet available - see docs/decisions/0003-lint-and-typecheck-tooling.md"
	@echo "typecheck  not yet available - see docs/decisions/0003-lint-and-typecheck-tooling.md"

sync:
	uv sync

test:
	uv run pytest -q

dev-up:
	scripts/dev-up

dev-down:
	scripts/dev-down

# The engine's schema. Apply it before anything is ingested - the broker is
# consume-once, so a view created later starts empty. See docs/runbook.md.
migrate:
	uv run scripts/migrate.py

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
