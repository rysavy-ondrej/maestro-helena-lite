"""Taxonomy — the two classification vocabularies, frozen one version at a time.

`concept/02-concepts-and-taxonomy.md` defines two levels that share syntax,
governance and versioning and classify **different subjects**:

| | Evidence level | Context level |
| --- | --- | --- |
| Subject | an **indicator** — what a source says about an address, domain, URL or fingerprint | a **host context** — what this host did in this window |
| Emitted by | feed mapping views and provider tools | the Triage Agent and the Analyst Agent |
| Roots | `no_match`, `normal`, `suspicious`, `malicious`, `unknown` | triage: `normal`, `suspicious`; analyst: `normal`, `suspicious`, `unknown`, `malicious` |

This package holds the **machinery**; a version module holds the **vocabulary**.
`v1.py` is the first, and `helena.taxonomy.v1` is what a caller imports.

## Why a version is a module and not a row

`concept/07-principles.md` and `docs/decisions/0008-version-registry.md`:
*a revision is a new version module, never an edit* — `v2` beside `v1`, with
`v1` left importable exactly as it was, because a stored assessment that
recorded `v1` has to keep validating against the `v1` it saw. Editing a version
in place silently changes what every historical row claims, and
`concept/instruction.md` §3 makes editing the taxonomy at all an escalation
rather than an increment.

That rule is about the **vocabulary**, which is why the vocabulary is the only
thing a version module holds. The syntax is shared — the concept note says so in
as many words — so validation lives here and is a pure function of the frozen
data it is handed. A future `v2` that needed different *syntax* would be a change
to this file and therefore a change to how `v1` validates, which is exactly the
thing the rule forbids; if that day comes, the syntax has to move into the
version modules and this package becomes a dispatcher. Recorded here because it
is the one way this layout can go wrong.

## What validation actually enforces

Four rules, all from `concept/02-concepts-and-taxonomy.md`, all checked rather
than assumed:

1. **Dot-delimited, most-specific supported path.** A path not in the version's
   vocabulary is refused — *"emit the parent rather than guessing a child; a
   mapping with a threat type it has never seen emits `malicious`, not an
   invented `malicious.something`"*.
2. **Roots are closed**, and closed *per level and per emitter*: triage may not
   emit `malicious` and the evidence level has a root — `no_match` — that no
   agent has.
3. **The root must equal the first path segment** — the note says "validated,
   not assumed", so it is a check here and not a comment.
4. **No `unknown.*` sub-paths.** *"A child would claim a specificity the run does
   not have"*, and `unknown` means the context was unassessable — enrichment
   failed, the rendering was truncated, the budget ran out. The reason belongs in
   the gaps, not in a path segment.

## Declared and unused

Some paths are in the vocabulary and may not be emitted yet. `concept/02` puts
it plainly: *several paths the prototype cannot yet justify — most anomaly and
baseline paths need history and behavioural features the first version does not
build. They are in the vocabulary because that is where evaluation is expected to
push, marked as unused rather than invented later.*

So there are two questions and two functions. `resolve()` answers *is this in the
vocabulary* and hands back what it knows, `unused` included. `for_emission()`
answers *may something emit this now* and refuses an unused path with a reason.
Collapsing them would make an unused path either invisible or indistinguishable
from an invalid one, and `concept/instruction.md` §2 is what forbids that.

Reads: nothing. Writes: nothing.

Maturity: experimental — exercised by `tests/test_taxonomy.py`. No assessment has
been stamped with a taxonomy version yet and nothing has been replayed from one;
what is demonstrated is the vocabulary and its rules, not their fit to real
verdicts, which needs the corpus `concept/08-open-questions.md` is blocked on.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import ModuleType

__all__ = [
    "ANALYST",
    "CONTEXT",
    "EMITTERS",
    "EVIDENCE",
    "LEVELS",
    "TRIAGE",
    "Emitter",
    "Level",
    "ResolvedPath",
    "TaxonomyError",
    "TaxonomyVersion",
    "UnknownVersion",
    "UnusablePath",
    "for_emission",
    "resolve",
    "version",
]

# The two levels, and the two emitters the context level distinguishes. They are
# strings rather than an enum because they are written onto rows and read back
# out of them; an enum would be a second spelling of the same value.
EVIDENCE = "evidence"
CONTEXT = "context"
LEVELS = (EVIDENCE, CONTEXT)

# `concept/02`: triage emits `normal` or `suspicious` **and nothing else** -- a
# context triage could not assess is a typed failure, not a third label -- while
# the analyst has `unknown` and `malicious` as well. The evidence level has no
# emitter distinction: a feed mapping view and a provider tool draw on the same
# roots.
TRIAGE = "triage"
ANALYST = "analyst"
EMITTERS = (TRIAGE, ANALYST)

Level = str
Emitter = str


class TaxonomyError(Exception):
    """A path, level or emitter is not what the taxonomy says one is.

    One exception type with a stated reason rather than several: every case is
    the same refusal to classify, and a caller that had to catch four of these
    would be enumerating the ways it might be wrong instead of not being wrong.
    """


class UnknownVersion(TaxonomyError):
    """A version was asked for that this package does not hold.

    Distinct from a bad path, because it means something quite different: a
    stored assessment recorded a version whose module is not here, which is a
    replay that cannot be validated rather than a value that is invalid.
    """


class UnusablePath(TaxonomyError):
    """A path that is in the vocabulary and may not be emitted yet.

    Also distinct, and for the reason `concept/instruction.md` §2 gives about
    `missing` and `no_match`: "declared but unused" and "not in the vocabulary"
    are two different facts, and a caller that saw one error for both would have
    no way to tell a path evaluation is expected to reach from a typo.
    """


@dataclass(frozen=True)
class ResolvedPath:
    """One path, resolved against one version: what it is and whether it is usable."""

    path: str
    level: Level
    root: str
    version: str
    #: True where the vocabulary declares the path and the prototype cannot yet
    #: justify emitting it -- see the module docstring.
    unused: bool
    #: Why it is unused, from the version module. Empty for a usable path.
    unused_reason: str

    @property
    def segments(self) -> tuple[str, ...]:
        return tuple(self.path.split("."))

    @property
    def is_root(self) -> bool:
        """Whether this is a bare root, which is always emittable.

        `concept/02`'s "emit the parent rather than guessing a child" only means
        something if the parent is a legal answer on its own.
        """
        return self.path == self.root


@dataclass(frozen=True)
class TaxonomyVersion:
    """One version's frozen vocabulary: the shape every version module supplies.

    A version module builds exactly one of these and nothing else. It is frozen,
    its collections are `frozenset` and `mappingproxy`-free by being built once
    at import, and nothing here mutates it -- a vocabulary that could be edited
    after import is the in-place revision the whole design refuses.
    """

    version: str
    #: level -> the roots that level closes over.
    roots: dict[Level, frozenset[str]]
    #: emitter -> the roots that emitter may use, for the context level only.
    emitter_roots: dict[Emitter, frozenset[str]]
    #: level -> every path the vocabulary declares, roots included.
    paths: dict[Level, frozenset[str]]
    #: path -> why the prototype cannot yet justify emitting it.
    unused: dict[str, str]

    def __post_init__(self) -> None:
        # The invariants a version module could get wrong, checked at import
        # rather than at the first call: a vocabulary that disagrees with itself
        # should fail where it is written, not where it is used.
        if set(self.roots) != set(LEVELS):
            raise TaxonomyError(
                f"{self.version}: roots are declared for {sorted(self.roots)}, "
                f"and the levels are {list(LEVELS)}"
            )
        if set(self.emitter_roots) != set(EMITTERS):
            raise TaxonomyError(
                f"{self.version}: emitter roots are declared for "
                f"{sorted(self.emitter_roots)}, and the emitters are {list(EMITTERS)}"
            )
        for level, paths in self.paths.items():
            for path in sorted(paths):
                root = path.split(".", 1)[0]
                if root not in self.roots[level]:
                    raise TaxonomyError(
                        f"{self.version}: {level} path {path!r} has root {root!r}, "
                        f"which is not one of {sorted(self.roots[level])}"
                    )
            missing = self.roots[level] - paths
            if missing:
                # A root that is not itself a path could never be emitted, and
                # "emit the parent" would have nothing to emit.
                raise TaxonomyError(
                    f"{self.version}: {level} roots {sorted(missing)} are closed "
                    f"over but are not paths, so the parent could not be emitted"
                )
        for emitter, roots in self.emitter_roots.items():
            outside = roots - self.roots[CONTEXT]
            if outside:
                raise TaxonomyError(
                    f"{self.version}: {emitter} may emit {sorted(outside)}, which "
                    f"the context level does not close over"
                )
        declared = set().union(*self.paths.values())
        undeclared = set(self.unused) - declared
        if undeclared:
            raise TaxonomyError(
                f"{self.version}: {sorted(undeclared)} are marked unused and are "
                f"not in the vocabulary; an unused path is declared, not absent"
            )
        for path, reason in self.unused.items():
            if not reason.strip():
                raise TaxonomyError(
                    f"{self.version}: {path!r} is marked unused with no reason. "
                    f"An unused path records why the prototype cannot justify it."
                )


def _load(identifier: str) -> TaxonomyVersion:
    """The frozen vocabulary of one taxonomy version.

    Imported by name rather than held in a registry dict, so adding `v2` is
    adding a module and nothing else -- a registry would be a second place a
    version has to be listed, and the one that gets forgotten.
    """
    from importlib import import_module  # noqa: PLC0415 — one call, at the edge

    if not identifier.isidentifier():
        raise UnknownVersion(
            f"{identifier!r} is not a version identifier; versions are module "
            f"names like 'v1'"
        )
    try:
        module: ModuleType = import_module(f"{__name__}.{identifier}")
    except ModuleNotFoundError as absent:
        raise UnknownVersion(
            f"no taxonomy version {identifier!r}. A stored assessment that "
            f"recorded it cannot be validated against this tree."
        ) from absent
    vocabulary = getattr(module, "TAXONOMY", None)
    if not isinstance(vocabulary, TaxonomyVersion):
        raise UnknownVersion(
            f"{module.__name__} does not define a TaxonomyVersion named TAXONOMY"
        )
    if vocabulary.version != identifier:
        raise UnknownVersion(
            f"{module.__name__} declares version {vocabulary.version!r}; a "
            f"version module and the version it declares must agree"
        )
    return vocabulary


#: Public name for the loader. `resolve` and `for_emission` call `_load`
#: directly, so the `version` parameter they take does not shadow it.
version = _load


def resolve(
    path: str,
    *,
    level: Level,
    version: str | TaxonomyVersion,
    emitter: Emitter | None = None,
) -> ResolvedPath:
    """Resolve `path` against one version, or raise `TaxonomyError` saying why.

    This answers *is this in the vocabulary*. It does **not** answer *may
    something emit it now* -- an unused path resolves cleanly and carries
    `unused=True`, and `for_emission` is the function that refuses one.

    `emitter` is required at the context level and refused at the evidence one,
    because the roots are closed per emitter there and there is no emitter
    distinction here.
    """
    vocabulary = _load(version) if isinstance(version, str) else version
    if level not in LEVELS:
        raise TaxonomyError(f"level {level!r} is not one of {list(LEVELS)}")
    if level == CONTEXT and emitter is None:
        raise TaxonomyError(
            "the context level closes its roots per emitter, so an emitter is "
            f"required; one of {list(EMITTERS)}"
        )
    if level == EVIDENCE and emitter is not None:
        raise TaxonomyError(
            f"the evidence level has no emitter distinction, and {emitter!r} was "
            f"given; a feed mapping view and a provider tool draw on the same roots"
        )
    if emitter is not None and emitter not in EMITTERS:
        raise TaxonomyError(f"emitter {emitter!r} is not one of {list(EMITTERS)}")

    if not path or path != path.strip():
        raise TaxonomyError(f"{path!r} is not a path: it is blank or padded")
    segments = path.split(".")
    if any(not segment for segment in segments):
        raise TaxonomyError(
            f"{path!r} has an empty segment; a path is dot-delimited with no "
            f"empty parts"
        )

    root = segments[0]
    closed = vocabulary.roots[level] if emitter is None else vocabulary.emitter_roots[emitter]
    if root not in closed:
        where = level if emitter is None else f"{level}/{emitter}"
        raise TaxonomyError(
            f"{path!r} has root {root!r}, which {where} does not close over. "
            f"The roots are {sorted(closed)}."
        )
    if path not in vocabulary.paths[level]:
        raise TaxonomyError(
            f"{path!r} is not a {level} path in {vocabulary.version}. Emit the "
            f"parent rather than guessing a child: {root!r} is supported."
        )
    return ResolvedPath(
        path=path,
        level=level,
        root=root,
        version=vocabulary.version,
        unused=path in vocabulary.unused,
        unused_reason=vocabulary.unused.get(path, ""),
    )


def for_emission(
    path: str,
    *,
    level: Level,
    version: str | TaxonomyVersion,
    emitter: Emitter | None = None,
) -> ResolvedPath:
    """`resolve`, and then refuse a path nothing may emit yet.

    The function an emitter calls. `UnusablePath` rather than `TaxonomyError`
    with a message, because "declared but not yet justified" is a different fact
    from "not in the vocabulary" and a caller may reasonably treat them
    differently -- fall back to the parent for the first, fail for the second.
    """
    resolved = resolve(path, level=level, version=version, emitter=emitter)
    if resolved.unused:
        raise UnusablePath(
            f"{path!r} is declared in {resolved.version} and unused: "
            f"{resolved.unused_reason} Emit {resolved.root!r} instead, or the "
            f"most specific supported path."
        )
    return resolved
