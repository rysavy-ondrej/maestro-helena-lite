"""Taxonomy v1 — the first frozen vocabulary. Never edited; superseded by a `v2`.

Everything here is read off `concept/02-concepts-and-taxonomy.md`. Where that
note names a path, the path is here under that name; where it describes a family
in prose, the prose is quoted beside the path it became, so the derivation can be
checked rather than taken. Nothing is invented, and the two places the note gives
no vocabulary at all are recorded as such below rather than filled in.

**This file is frozen the moment a row records `v1`.** `docs/decisions/0008-version-registry.md`:
a revision is `v2` beside it, with this left importable exactly as it was.

## The evidence level is roots-only, and that is not an omission

`concept/02` says the evidence level *"is adopted essentially unchanged from an
existing published indicator taxonomy, so that HELENA's evidence stays comparable
with other tools' rather than re-deriving a vocabulary from the same providers."*
It then gives the five roots and their meanings — and **it does not name that
taxonomy, and no document in this repository reproduces it.**

So the sub-paths cannot be adopted, because there is nothing here to adopt them
from, and they must not be invented: the note's own rule is *"emit the parent
rather than guessing a child — a mapping with a threat type it has never seen
emits `malicious`, not an invented `malicious.something`."* Writing a plausible
`malicious.c2`/`malicious.phishing` set at the evidence level would be exactly
that, one layer up, and it would be indistinguishable from the real thing
afterwards.

v1 therefore closes the five roots and declares them as the whole evidence
vocabulary. Every mapping emits a root, which is a supported answer and a true
one. The sub-paths arrive with the first feed that needs them — the increment
that maps a real source's threat types is the one that can say what they are —
and that is a `v2`, which is what the versioning is for.

## The context level is HELENA's own, and is derived here

`concept/02` describes it in three prose sentences, one per root family. Each
path below quotes the fragment it came from. The note also says which of them the
prototype cannot justify:

> **Several paths the prototype cannot yet justify** — most anomaly and baseline
> paths need history and behavioural features the first version does not build.
> They are in the vocabulary because that is where evaluation is expected to
> push, marked as unused rather than invented later.

That is `UNUSED` below: declared, resolvable, and refused by `for_emission`.
Every one of them needs *history* — a comparison against what this host, or this
network, did before — and nothing in D1–D2 builds it: a context is one host in
one five-minute window, `helena_signal_host_context` has no previous window in
it, and the retention boundary is 24 hours.

## `unknown` has no children, and the check is structural

`concept/02`: *"There are no `unknown.*` sub-paths — a child would claim a
specificity the run does not have, and the reason belongs in the gaps."* That is
enforced by `unknown` being a root with no path under it, so a child fails the
"most-specific supported path" rule with no special case. A special case would be
a rule that could be forgotten in `v2`; an absent path cannot be.

Maturity: experimental — exercised by `tests/test_taxonomy.py`. The vocabulary
has classified nothing: no agent emits one of these yet, and whether these are
the right families is a question for evaluation against a corpus that does not
exist (`concept/08-open-questions.md`).
"""

from __future__ import annotations

from helena.taxonomy import ANALYST, CONTEXT, EVIDENCE, TRIAGE, TaxonomyVersion

__all__ = ["TAXONOMY", "TAXONOMY_VERSION"]

TAXONOMY_VERSION = "v1"

# --- Evidence level ---------------------------------------------------------
#
# `concept/02`, "Evidence level". The meanings are quoted so that a mapping
# author reads the definition beside the name rather than guessing from it.
#
#   no_match    "The source completed its query and returned no record. A lookup
#                outcome, never a statement of safety"
#   normal      "Affirmatively known to support harmless activity at that scope
#                and time. Requires positive known-good evidence -- a count of
#                zero detections is not enough"
#   suspicious  "A material risk signal, but malicious purpose is not established"
#   malicious   "Known to have performed or supported malicious activity"
#   unknown     "A record exists, but the evidence cannot support another root"
#
# `no_match` is the one that matters most here, and the note says why: with
# sparse blocklist coverage most entities have no hit on anything, so an enriched
# context is mostly negative space, and triage reading "no hit" as "clean" is the
# failure mode the whole design exists to prevent.
EVIDENCE_ROOTS = frozenset(
    {"no_match", "normal", "suspicious", "malicious", "unknown"}
)

# Roots-only. See the module docstring for why this is a decision rather than an
# unfinished list.
EVIDENCE_PATHS = frozenset(EVIDENCE_ROOTS)


# --- Context level ----------------------------------------------------------

CONTEXT_ROOTS = frozenset({"normal", "suspicious", "unknown", "malicious"})

# `concept/02`: "Triage emits `normal` or `suspicious` and nothing else. A context
# triage could not assess is a typed failure, not a third label." So triage has
# no `unknown` -- the failure is typed, not classified -- and no `malicious`,
# which is the analyst's to reach.
TRIAGE_ROOTS = frozenset({"normal", "suspicious"})
ANALYST_ROOTS = frozenset({"normal", "suspicious", "unknown", "malicious"})

# The malicious family. `concept/02`: "The malicious and suspicious families read
# as host-level statements, not indicator-level ones: contacted C2, retrieved a
# payload, reached phishing infrastructure (a targeted user, not necessarily a
# compromised host), conducted hostile activity itself, sent spam, exfiltrated, or
# shows confirmed compromise without a more specific role."
#
# `malicious.c2` is the one path the concept note writes out itself, in the
# composition rule: "A C2 hit on a contacted address with actual bidirectional
# traffic supports `malicious.c2` for the host." The rest are that sentence's
# other clauses, in its order.
MALICIOUS_PATHS = frozenset(
    {
        "malicious.c2",            # "contacted C2"
        "malicious.payload",       # "retrieved a payload"
        "malicious.phishing",      # "reached phishing infrastructure"
        "malicious.hostile",       # "conducted hostile activity itself"
        "malicious.spam",          # "sent spam"
        "malicious.exfiltration",  # "exfiltrated"
        "malicious.compromised",   # "confirmed compromise without a more specific role"
    }
)

# The suspicious family. `concept/02`: "`suspicious` covers low-reputation
# contact, a single uncorroborated detection, disagreeing sources, anomalous DNS /
# TLS / volume / periodicity, and materially new destinations."
SUSPICIOUS_PATHS = frozenset(
    {
        "suspicious.low_reputation",        # "low-reputation contact"
        "suspicious.single_detection",      # "a single uncorroborated detection"
        "suspicious.source_disagreement",   # "disagreeing sources"
        "suspicious.anomalous_dns",         # "anomalous DNS"
        "suspicious.anomalous_tls",         # "anomalous TLS"
        "suspicious.anomalous_volume",      # "anomalous volume"
        "suspicious.anomalous_periodicity", # "anomalous periodicity"
        "suspicious.new_destination",       # "materially new destinations"
    }
)

# The normal family. `concept/02`: "`normal` covers identified legitimate service
# use, baseline consistency, and the host being infrastructure behaving as such."
NORMAL_PATHS = frozenset(
    {
        "normal.known_service",   # "identified legitimate service use"
        "normal.baseline",        # "baseline consistency"
        "normal.infrastructure",  # "the host being infrastructure behaving as such"
    }
)

# `unknown` is a root and has no children -- see the module docstring.
CONTEXT_PATHS = (
    CONTEXT_ROOTS | MALICIOUS_PATHS | SUSPICIOUS_PATHS | NORMAL_PATHS
)


# --- Declared and unused ----------------------------------------------------
#
# Every one of these needs history, and the reason is the same for all of them:
# a context is one host in one five-minute window (`concept/02`, "Window"), the
# aggregate holds no previous window, and the retention boundary is 24 hours
# (`sql/migrations/0009_retention_boundary.sql`). "Anomalous" and "baseline" and
# "new" are all comparisons, and there is nothing here to compare against.
#
# They are declared because `concept/02` says to declare them -- "that is where
# evaluation is expected to push, marked as unused rather than invented later" --
# and the alternative is a later session inventing a name for the same idea and
# a stored `v1` row meaning something the name no longer says.
_NEEDS_HISTORY = (
    "it is a comparison against this host's past behaviour, and a context is one "
    "host in one five-minute window with no previous window in it."
)

UNUSED = {
    "suspicious.anomalous_dns": _NEEDS_HISTORY,
    "suspicious.anomalous_tls": _NEEDS_HISTORY,
    "suspicious.anomalous_volume": _NEEDS_HISTORY,
    "suspicious.anomalous_periodicity": _NEEDS_HISTORY,
    "suspicious.new_destination": (
        "it requires knowing which destinations are not new, which is a history "
        "of this host's destinations that nothing builds."
    ),
    "normal.baseline": (
        "baseline consistency is a comparison against a baseline, and no "
        "behavioural baseline is computed."
    ),
}


TAXONOMY = TaxonomyVersion(
    version=TAXONOMY_VERSION,
    roots={EVIDENCE: EVIDENCE_ROOTS, CONTEXT: CONTEXT_ROOTS},
    emitter_roots={TRIAGE: TRIAGE_ROOTS, ANALYST: ANALYST_ROOTS},
    paths={EVIDENCE: EVIDENCE_PATHS, CONTEXT: CONTEXT_PATHS},
    unused=UNUSED,
)
