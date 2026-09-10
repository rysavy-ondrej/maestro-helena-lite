"""Untrusted text: one frame, one escaper, one serializer, and no second copy of any of them.

`concept/07-principles.md`, *Untrusted input*:

> **External text and model-visible fields are data, never instructions**, and
> **isolation is implemented and tested, not asserted.** The concrete surfaces:
> advisory and report text, provider descriptions, engine names, category labels,
> feed tags and comment fields, and **registration records, which in a malicious
> case are written by the adversary**.

`concept/instruction.md` §6 says the same thing as a trap: *"Treating retrieved
provider text as instruction — it is data. Isolate it, and **test the
isolation**."* This module is the isolation; `tests/test_untrusted.py` is the
test, and it is the evidence for the claim rather than the claim itself.

## The four functions, and what each one actually stops

Isolation here is **four mechanisms, not a sentence in a prompt**. A model can be
talked out of an instruction, so nothing below depends on the model reading the
frame and believing it. What the frame gives is a boundary that attacker-chosen
text **cannot leave**, and each function is one half of that:

| Function | What it does | The forgery it stops |
| --- | --- | --- |
| `token` | percent-encodes every character outside printable non-space ASCII | a rendered value that starts a line of its own — a second attribute, a forged section heading, a forged frame line |
| `line` | one line of JSON, sorted keys, no spaces | a provider or model string that starts a line of its own; a native payload that was never declared |
| `vocabulary` | joins a closed vocabulary after checking every member is one bare token | a taxonomy or verdict list that carries whitespace into the instruction turn |
| `block` | wraps a body between a `Frame`'s two whole lines, refusing a body that carries **any** marker line | a body that closes its own frame and continues in the instruction position |

The order matters and it is the reason `block` is a checker and not an escaper:
by the time a body reaches it, every value in that body has been through `token`,
`line` or `vocabulary`, so **a marker line in the body is an escaper that stopped
escaping, never a party outside this network getting lucky**. `block` raising is
therefore a bug report about this package and not a rejected input.

## Why the markers are whole lines

A pair of whole lines is unforgeable exactly as long as no value can contain a
line break, which is what the three escapers guarantee. A delimiter *inside* a
line — quotes, brackets, a tag — would need every value to be checked for that
delimiter instead, which is the same problem with a larger alphabet. So: whole
lines, one property to hold, one place it is checked.

The markers live here and nowhere else. `tests/test_untrusted.py` reads the
package's AST and fails on a second copy of one, because two spellings of a
delimiter is a delimiter that can drift out of agreement with the checker.

## What this costs the frozen prompt versions, and what pays for it

`helena.triage.v1` and `helena.analyst.v1` are frozen the moment an assessment
records their version (`docs/decisions/0008-version-registry.md`), and they now
import this module — so an edit here is an edit reaching a frozen file, which is
the hazard `tests/test_package_layout.py` names for a helper *inside* a versioned
package. What pays for it is
`tests/test_untrusted.py::test_the_frozen_prompt_bytes_are_what_they_were`: the
exact bytes each frozen prompt builds for a fixed request are pinned in the
suite, so a change here that would change what `v1` asks is a failing test rather
than a silent rewrite of history. Before this module there was no such pin at
all — the freeze was a comment. `docs/decisions/0030-untrusted-text-isolation.md`
records the trade.

Maturity: experimental — every model-visible surface in the tree routes through
these four functions, and `tests/test_untrusted.py` asserts that by reading the
AST as well as by running the two agents over an injection corpus placed in feed
tags, provider descriptions, rendered values and registration records. What is
**not** demonstrated is that a model resists an injection: no corpus here measures
model behaviour, and the isolation claimed is the structural one — attacker text
cannot reach the instruction position, cannot forge a frame, cannot forge a
citation, and cannot change which tools were called. Whether a persuaded model
answers differently *inside* those bounds is unmeasured and stays unmeasured
until there is a labelled corpus (`concept/08-open-questions.md`).
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

__all__ = [
    "CONTEXT",
    "DISCARDED_ANSWER",
    "FRAMES",
    "Frame",
    "IsolationError",
    "MARKERS",
    "RETRIEVED",
    "TRIAGE",
    "block",
    "line",
    "token",
    "vocabulary",
]


class IsolationError(RuntimeError):
    """Untrusted text reached a position it could forge structure from.

    A `RuntimeError` rather than a `ValueError` for the reason the module
    docstring gives: by the time anything here raises, the input has already been
    through an escaper, so this is a defect in this package rather than a bad
    value someone passed in.
    """


@dataclass(frozen=True)
class Frame:
    """One pair of whole lines that an untrusted block sits between.

    `name` is what the block is called in a test failure and in this module's
    registry; it is never sent anywhere.
    """

    name: str
    open: str
    close: str

    def __post_init__(self) -> None:
        for role, marker in (("open", self.open), ("close", self.close)):
            if not marker.strip() or marker.splitlines() != [marker]:
                raise IsolationError(
                    f"the {role} marker of frame {self.name!r} is {marker!r}; a "
                    f"marker is one non-blank whole line, because that is the "
                    f"whole of why it cannot be forged"
                )
        if self.open == self.close:
            raise IsolationError(
                f"frame {self.name!r} opens and closes with the same line, so "
                f"nothing can tell where its data ends"
            )


#: The rendering of what a monitored host did. Values chosen by parties outside
#: this network: domain names, addresses, server names, fingerprints.
CONTEXT = Frame(
    name="context",
    open="<<<BEGIN UNTRUSTED CONTEXT DATA>>>",
    close="<<<END UNTRUSTED CONTEXT DATA>>>",
)

#: What external providers answered when the analyst asked. Feed tags, malware
#: names, reporter and reference fields — `concept/07`'s "feed tags and comment
#: fields", arriving *because the model asked for them*.
RETRIEVED = Frame(
    name="retrieved",
    open="<<<BEGIN UNTRUSTED RETRIEVED DATA>>>",
    close="<<<END UNTRUSTED RETRIEVED DATA>>>",
)

#: This project's own earlier stage, shown to the analyst only when
#: `config/agents.toml` says so. Framed anyway: a triage gap detail is text a
#: model wrote about a rendering an adversary influenced.
TRIAGE = Frame(
    name="triage",
    open="<<<BEGIN TRIAGE RESULT>>>",
    close="<<<END TRIAGE RESULT>>>",
)

#: The validation error from an answer that did not validate, fed back on the
#: next attempt. A Pydantic error quotes the input that failed, so it is a route
#: by which a model's own words — which may be a copy of what it was shown —
#: reach the next prompt. `helena.agents._attempt_messages` is the only caller.
DISCARDED_ANSWER = Frame(
    name="discarded_answer",
    open="<<<BEGIN UNTRUSTED DISCARDED ANSWER>>>",
    close="<<<END UNTRUSTED DISCARDED ANSWER>>>",
)

#: Every frame this project has. A prompt version picks the ones it shows; the
#: check in `block` is against all of them, so a rendering cannot forge the
#: analyst's retrieved marker by arriving through triage, which checks fewer.
FRAMES = (CONTEXT, RETRIEVED, TRIAGE, DISCARDED_ANSWER)

#: Every marker line, as a set, for the one membership test in `block`.
MARKERS = frozenset(
    marker for frame in FRAMES for marker in (frame.open, frame.close)
)

# The characters a rendered value may carry unescaped: printable ASCII, no space
# and no `%`, which is the escape character itself.
_SAFE = frozenset(chr(code) for code in range(0x21, 0x7F)) - {"%"}


def token(value: str) -> str:
    """One value, with anything that could forge structure escaped.

    Percent-encoding of the UTF-8 bytes, so it is reversible and no value is
    silently changed into another. Real domain names and addresses are already
    inside the safe set, so this fires on the values that would otherwise be a
    problem and on nothing else.

    `helena.rendering.v1.token` is this function under the name the frozen
    rendering version gives it — one escaper, called from both places, because
    two escapers is one that can stop agreeing with `block`.
    """
    return "".join(
        character
        if character in _SAFE
        else "".join(f"%{byte:02X}" for byte in character.encode())
        for character in value
    )


def line(payload: Any) -> str:
    """One structured object as exactly one line of JSON. Data, never instruction.

    Sorted keys and no spaces, so two identical objects are identical bytes.
    `json.dumps` renders a newline as `\\n` and escapes every non-ASCII character,
    which is what makes the result one line whatever a provider or a model wrote
    into it — the same property `token` gives a rendered value, obtained from the
    serializer rather than from a second escaper.

    The result is checked rather than assumed: a serializer that emitted a raw
    newline would defeat every frame at once, and the check costs one `in`.
    """
    rendered = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    if rendered.splitlines() != [rendered]:
        raise IsolationError(
            f"serializing {type(payload).__name__} produced "
            f"{len(rendered.splitlines())} lines; a structured block is one line "
            f"per record, and a record that spans lines can start one of its own"
        )
    return rendered


def vocabulary(values: Iterable[str]) -> str:
    """A closed vocabulary as the comma-separated list a prompt shows.

    The instruction turn is the one place with no frame around it, so the values
    that reach it are checked rather than escaped: each has to be one non-empty
    token with no whitespace, which every taxonomy path and every verdict is.
    Escaping instead would put percent-codes in front of a model as the names of
    the answers it may give.

    Empty is refused by the caller and not here — `helena.triage.v1` and
    `helena.analyst.v1` each say what an empty verdict list means to them.
    """
    listed = list(values)
    for value in listed:
        if not value or value.split() != [value]:
            raise IsolationError(
                f"{value!r} is offered to a model as one value of a closed "
                f"vocabulary, and a value with whitespace in it is one that can "
                f"carry a second line into the instruction turn. A taxonomy path "
                f"is one token"
            )
    return ", ".join(listed)


def block(frame: Frame, body: str) -> str:
    """`body`, between `frame`'s two whole lines. The single wrapper.

    Every externally sourced string a prompt shows arrives inside one of these,
    and `tests/test_untrusted.py` reads the AST of every module that builds a
    `helena.agents.Message` to assert there is no other route.

    The body is **checked, not escaped**, and the module docstring says why: each
    value in it has already been through `token`, `line` or `vocabulary`, each of
    which escapes the newline a marker line would need. So a marker line here is
    an escaper that stopped escaping, and raising is the correct response to that.
    """
    if not isinstance(frame, Frame):
        raise IsolationError(
            f"block takes a Frame, not {type(frame).__name__}; the markers are "
            f"this module's and a pair passed in as strings is a second copy of "
            f"them"
        )
    if not body.strip():
        raise IsolationError(
            f"the {frame.name} block has no body. A frame around nothing tells a "
            f"model there was data and that it was empty, which is the "
            f"absence-is-not-emptiness collapse `concept/instruction.md` §2 "
            f"refuses one layer down"
        )
    forged = sorted(MARKERS & set(body.splitlines()))
    if forged:
        raise IsolationError(
            f"the {frame.name} body carries {forged} as a line of its own, which "
            f"is the frame that says where the untrusted data ends. Every value "
            f"in a block reaches it through `token`, `line` or `vocabulary`, and "
            f"each escapes the newline that would be needed to produce one — so "
            f"this is an escaper that stopped escaping rather than a party "
            f"outside this network getting lucky."
        )
    return f"{frame.open}\n{body}\n{frame.close}"
