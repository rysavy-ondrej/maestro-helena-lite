"""Host attribute set v1 — the first frozen field set. Never edited; superseded by a `v2`.

`concept/04-the-two-agents.md` names the fields, and names two:

> **The host** — address and device type, from a closed versioned attribute set
> sourced from fixed configuration only. When unknown it is rendered as unknown —
> never omitted, never guessed.

So the set is `address` and `device_type`, and **nothing else**. The temptation
here is to add the fields an asset inventory usually has — owner, location,
business criticality, operating system, an asset tag — and every one of them
would be a requirement invented to make the set look complete, which
`concept/instruction.md` §4 forbids by name. It would also be the more expensive
mistake in this particular place: the set is *closed*, so a field nobody
populates renders as `unknown` on every host in every rendering, spending the
triage budget on a column of nothing and teaching an agent that the host section
is mostly noise.

A field arrives when an increment has something that populates it and something
that reads it — and it arrives as `v2` beside this file, because a rendering that
recorded `v1` has to keep meaning what it meant
(`docs/decisions/0008-version-registry.md`).

**This file is frozen the moment a rendering records `v1`.**

## `device_type` has no vocabulary here, and that is deliberate

`concept/04` says "device type" and no note in this repository gives a list of
them. Closing it over a guessed set — server, workstation, printer, camera —
would be the same invention one level down, and an operator whose fleet has a
kind the list forgot would have to record something false. It is bounded,
single-line, operator-supplied text; what it is *not* is a classification, and
nothing joins on it. If evaluation shows triage reasons better against a closed
vocabulary, that is a measurement and then a `v2`.

Maturity: experimental — exercised by `tests/test_hosts.py`. No agent has been
given a host section built from it, and the fit of a two-field set to real triage
reasoning is unmeasured: it is what the concept note names, not what a corpus
showed to be enough.
"""

from __future__ import annotations

from helena.hosts import ADDRESS, HostAttributeSet

ATTRIBUTES = HostAttributeSet(
    version="v1",
    fields={
        # The key, and the identity the rest of the section is about. Always
        # known — it is what the rendering was requested for — so it is the one
        # field that never renders as `unknown`.
        ADDRESS: (
            "The host's address, as the context and the agent request identify "
            "it. The key of the host's table in the configuration file, never a "
            "value inside it."
        ),
        # `concept/04`'s second field. Free text from configuration: see the
        # module docstring for why it has no closed vocabulary.
        "device_type": (
            "What kind of device this is, as the operator records it — a "
            "workstation, a server, a printer. Free text, one line: it is "
            "context for the agent, not a classification anything joins on."
        ),
    },
)
