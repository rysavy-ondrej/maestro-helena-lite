# HELENA — the whole toolchain. One package, one test suite, one environment.
#
# Everything runs through `uv run`, against the `.venv/` that is already at the
# project root. Never `pip`, never a second virtualenv, never a system python.

.PHONY: help sync test check acceptance conformance lint typecheck dev-up dev-down migrate storage rendering-size corpus-sizing status backup

help:
	@echo "sync       install the locked environment (uv sync)"
	@echo "test       run the one pytest suite"
	@echo "acceptance run the acceptance gate alone (a subset of test) - see docs/acceptance.md"
	@echo "conformance  run the must-never-happen table alone (a subset of test)"
	@echo "check      lockfile is in sync, sources compile, suite passes"
	@echo "dev-up     verify the pinned binaries and run the engine and broker"
	@echo "dev-down   stop them again"
	@echo "migrate    apply sql/migrations/ to the configured engine"
	@echo "storage    what each relation of the migrated schema stores"
	@echo "status     the pipeline's own numbers, read out of the engine"
	@echo "backup     copy the engine's durable tables into .backups/"
	@echo "rendering-size  what a real capture renders to, against the configured budget"
	@echo "corpus-sizing   what an evaluation would spend in live queries - see docs/evaluation-corpus.md"
	@echo "lint       not yet available - see docs/decisions/0003-lint-and-typecheck-tooling.md"
	@echo "typecheck  not yet available - see docs/decisions/0003-lint-and-typecheck-tooling.md"

sync:
	uv sync

test:
	uv run pytest -q

# The acceptance gate: two modules, and docs/acceptance.md is what they are for.
# tests/test_acceptance_enrichment.py is the D3 half - the six enrichment states,
# and "the triage stage is not buildable until this passes".
# tests/test_end_to_end.py is the D9 half - the six stages composed over the wire,
# one test per claimable property in concept/01-goal-and-scope.md, and the
# not-claimable list beside them.
#
# Not a second suite: both are part of `make test` and therefore of `make check`,
# which is what makes them required. The marker exists because "does the prototype
# do what we say it does" is a question someone needs to be able to ask directly,
# and because the answer takes under a minute rather than twelve.
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

# What an evaluation over a labelled corpus would cost in live queries, and the
# ceiling the provider's quota puts on one. Sized against config/policy.toml, not
# against a number in a document; docs/evaluation-corpus.md cites what it prints.
# There is no default daily quota - abuse.ch publishes fair-use terms and no
# number - so this target passes the ceiling our own [rate_limits] implies:
#
#     uv run scripts/corpus_sizing.py --daily-quota 500       # ... a published one
#     uv run scripts/corpus_sizing.py --daily-quota self-imposed --snapshot
corpus-sizing:
	uv run scripts/corpus_sizing.py --daily-quota self-imposed

# `helena status`: latency, cost, staleness, escalation, the typed failures and
# the end-to-end record reconciliation, every one of them a plain SELECT over the
# single store. Not a health check - it prints numbers and does not decide which
# are bad; docs/runbook.md §13 explains them. Pass the retained capture directory
# to include how many records existed:
#
#     uv run scripts/status.py --captures data/ingest
status:
	uv run scripts/status.py

# The engine's durable tables, copied out. The other half of the durable record
# is the retained captures, and `uv run scripts/dev_check.py --captures DIR`
# verifies those - there is no default directory, deliberately. Restoring takes
# a path and optionally a schema, so it is not a make target:
#
#     uv run scripts/backup.py --verify .backups/<file>
#     uv run scripts/backup.py --restore .backups/<file> --schema <throwaway>
#
# docs/runbook.md §15 is the procedure, the residual risk and the recovery time.
backup:
	uv run scripts/backup.py --out .backups

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
