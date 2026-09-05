"""Versions — the nine dimensions a citable row records, and the constant with two homes.

`concept/07-principles.md` gives the reason in one line: **a hosted endpoint can
change beneath a stable API name, and an unrecorded change silently breaks
replay.** So an assessment records what produced it — model, prompt, schema,
rendering, taxonomy, enrichment snapshot, policy and aggregation — and replay
validates a stored assessment against *the version that assessment recorded*,
never against current code. That is also why nothing here migrates a row
forward: reshaping a stored field would make replay reproduce the migration
rather than the original run.

`VersionSet` is that record, and its **field names are the column names** of the
version columns on any row that carries it. One name, so a row written by
`VersionSet.stamp` and read back by `VersionSet.from_row` cannot disagree about
what a column is called.

**The aggregation version lives here and in SQL, and the two are asserted equal
by execution.** `AGGREGATION_VERSION` is the Python copy;
`sql/migrations/0002_aggregation_version.sql` is the engine's, and
`tests/test_versions.py` asks the engine what it holds rather than reading the
file — two copies of a version that can drift apart are worse than none. Bump it
when the aggregation changes what a context *means*, in a new migration: the
runner refuses an edit to an applied file, so on the SQL side "a revision is a
new version, never an edit" is structural rather than a convention.

**A revision is a new version module, never an edit.** The taxonomy and the
agent schemas are frozen once a version is recorded on a row: a revision adds
`v2` beside `v1` and leaves `v1` importable exactly as it was, because a stored
assessment that recorded `v1` has to keep validating against the `v1` it saw.
Editing a version in place silently changes what every historical row claims.
`docs/decisions/0008-version-registry.md` has the rule and its consequences.

What this module does **not** do: choose the values. Only the aggregation version
is known here, because only the aggregation is defined here. The model version is
the identity the model's *response* reported — not the configured name, which is
the thing that can change beneath you — and the prompt, schema, rendering,
enrichment snapshot and policy versions belong to the increments that first
define one. **The taxonomy version now has such an increment**: `helena.taxonomy`
holds one module per version and `helena.taxonomy.version("v1")` is the frozen
vocabulary a row recording `v1` is replayed against. Nothing here imports it — a
version set records an identifier and does not resolve it, because resolving one
is what replay does and this module is written by every stage. A dimension without a value is a missing version, and a missing
version fails loudly at construction rather than defaulting to something plausible.

Reads: nothing. Writes: nothing — it returns rows for a caller to write.

Maturity: experimental — exercised by `tests/test_versions.py`, including the
SQL copy against a real engine. No assessment has been stamped with it yet;
nothing has been replayed from one.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, StringConstraints

__all__ = [
    "AGGREGATION_VERSION",
    "AGGREGATION_VERSION_VIEW",
    "VERSION_COLUMNS",
    "Version",
    "VersionSet",
]

# The aggregation version, bumped whenever the aggregation changes what a context
# *means* — not when a view is reformulated with the same meaning.
# `sql/migrations/0002_aggregation_version.sql` holds the same value, and
# `tests/test_versions.py` asserts the two equal by querying the engine.
AGGREGATION_VERSION = "v1"

# The view that migration 0002 creates. Here so the equality test names it once.
AGGREGATION_VERSION_VIEW = "helena_aggregation_version"

# A version identifier: a non-empty token with no whitespace in it. Deliberately
# permissive about the rest — a model version is whatever the endpoint calls
# itself, which is routinely `vendor/Model-Name-70B-Instruct`, and inventing a
# format for it would mean rewriting the one fact that has to be recorded exactly
# as it was reported. What it refuses is the empty string, a blank, and anything
# with a space in it, which is free text rather than an identifier.
Version = Annotated[str, StringConstraints(pattern=r"^\S+$", max_length=200)]


class VersionSet(BaseModel):
    """The versions recorded on one citable row. Every dimension, or an error.

    Frozen, because a version set describes a run that has already happened.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        # A rejected value is echoed in a Pydantic ValidationError, and the
        # accident this guards against is a real one (task 01 measured it): a
        # credential passed to the wrong field lands in a traceback.
        hide_input_in_errors=True,
        # `model_version` is a field name, and Pydantic reserves the `model_`
        # prefix for its own methods. Nothing here shadows one, and the suite
        # turns the warning it would otherwise emit into an error.
        protected_namespaces=(),
    )

    # The model as the endpoint reported it in the response, not as it was
    # configured — the configured name is the thing that stays stable while what
    # answers to it changes.
    model_version: Version
    prompt_version: Version
    # The agent output schema. Its historical versions are retained as frozen
    # classes; replay validates against this one.
    schema_version: Version
    # How the context was rendered for the agent — what triage saw is pinned by
    # this, not reconstructed from current code.
    rendering_version: Version
    # The classification vocabulary. `helena.taxonomy` holds one module per
    # version -- `v1` is the first -- and `helena.taxonomy.version(identifier)`
    # returns the frozen vocabulary a row recorded. Replay validates a stored
    # path against *that* module, so a `v2` that renames or drops a path cannot
    # change what a `v1` row claims, and a version whose module is absent raises
    # `UnknownVersion` rather than falling back to the current one.
    taxonomy_version: Version
    # The feed snapshot the enrichment join matched against. Replay joins the
    # snapshot that was current then, not today's.
    enrichment_snapshot_version: Version
    # The Public Suffix List snapshot that decided the registrable domain, which
    # is NOT the feed snapshot above: normalization runs before enrichment and
    # settles what the join key even is. The list changes, and its wildcard and
    # exception rules mean a name can fall under a different registrable domain
    # under a later snapshot — so an assessment replayed without this could score
    # against a different scope than the one that ran.
    normalization_snapshot_version: Version
    policy_version: Version
    aggregation_version: Version

    def as_columns(self) -> dict[str, str]:
        """The version columns of a row: column name → value.

        The field names *are* the column names, so this is `model_dump` with the
        intent said out loud.
        """
        return self.model_dump()

    def stamp(self, row: Mapping[str, Any]) -> dict[str, Any]:
        """`row` with the version columns added, as a new dict.

        Refuses a row that already carries one of them. Overwriting a version
        would rewrite what the row says produced it, which is the same mistake
        as migrating a stored row forward — and a row stamped twice by two
        different code paths is exactly the drift this registry exists to make
        impossible.
        """
        already = sorted(set(row) & set(VERSION_COLUMNS))
        if already:
            raise ValueError(
                f"the row already carries {already}; a row is stamped once, and "
                f"overwriting a recorded version would change what the row says "
                f"produced it"
            )
        return {**row, **self.as_columns()}

    @classmethod
    def from_row(cls, row: Mapping[str, Any]) -> VersionSet:
        """The version set a stored row recorded. Every column, or an error.

        This is the replay direction: what an assessment must be validated
        against is what it recorded, so a row missing a dimension is a failure
        naming it rather than a set completed from current constants.
        """
        missing = [column for column in VERSION_COLUMNS if column not in row]
        if missing:
            raise ValueError(
                f"the row records no {missing}; a stored assessment is replayed "
                f"against the versions it recorded, and a version that is not "
                f"there cannot be filled in from current code"
            )
        return cls(**{column: row[column] for column in VERSION_COLUMNS})


# The version columns, in field order. Derived from the model so the two cannot
# drift; `tests/test_versions.py` names all nine literally, so dropping a
# dimension is a test failure rather than a quietly shorter row.
VERSION_COLUMNS = tuple(VersionSet.model_fields)
