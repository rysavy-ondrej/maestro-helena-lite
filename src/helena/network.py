"""The outbound-network guard: a context manager that makes a connection raise.

Not a client, and deliberately the opposite of one. There is no URL in this
module, no credential, no request and no response — the only thing in it is
`no_network()`, which arms a refusal in front of the three calls a new outbound
connection has to go through, and puts them back when it is done.

## Why it is a module of its own

`helena.tools` may not import `socket`. That is not a preference: an AST test in
`tests/test_tools.py` reads `tools.py` and fails if it imports `urllib`, `http`,
`socket` or `ssl`, which is what makes *"the agent sees a tool, never an HTTP
client and never a key"* a property of the code rather than a sentence in a
docstring. The tool layer's replay mode has to arm this guard, so the guard lives
where importing `socket` costs nothing — a module that holds no way to *use* one.

`helena.providers` is the module that owns the protocol and would otherwise be
the obvious home, and it cannot be: it imports `helena.tools`, so a guard defined
there would make the tool layer import its own adapter.

## What it blocks, exactly

| | |
| --- | --- |
| `socket.socket.connect` / `connect_ex` | every new TCP connection, including the one `socket.create_connection` — and therefore `http.client`, `urllib` and `ssl` — opens |
| `socket.getaddrinfo` | the name resolution in front of it, which is itself an outbound query |

**What it does not block is a read or a write on a connection that was already
open, and that is deliberate rather than an oversight.** The store a replay reads
from is the streaming engine, reached over a `psycopg` connection opened before
the guard is armed; a guard that stopped the store being read would stop a replay
being a replay. The property this buys is therefore precise and it is the one
`concept/07` asks for: *nothing new leaves the process* while it is armed. An
adapter that held a connection pool open across a live phase and a replay phase
would slip through it — no adapter in this project does, because
`helena.providers` opens a socket per call, and the tool layer's own structural
guarantee is separate and stronger: in replay the adapter is never called at all.

A UDP `sendto` on an unconnected socket is the other thing that would slip
through. Nothing here sends one, and blocking every method of every socket would
make the guard a sandbox, which this is not: it is a guard against this project's
own code doing the one thing replay forbids.

## Restoration

The patches are exact. A name the owner did not define itself — `connect` is
inherited by `socket.socket` from the C type — is *removed* on the way out rather
than assigned back, so a guarded block leaves the module exactly as it found it
and nesting restores in the right order.

It is process-wide for the duration of the block, because monkeypatching is; one
run at a time is the shape everything else here assumes, and a guard that only
covered the calling thread would be a guard that a thread could step around.

Maturity: experimental — exercised by `tests/test_replay.py`, including against
the real engine connection a replay reads its stored responses over.
"""

from __future__ import annotations

import socket
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from typing import Any

__all__ = ["NetworkAttempted", "no_network"]


class NetworkAttempted(RuntimeError):
    """Code inside a `no_network()` block tried to open an outbound connection.

    A hard failure and never a typed result: the guard is not a policy an agent
    can read and argue with, it is the assertion that a mode which promises to
    send nothing sent nothing. Something raising this is a bug in the code that
    ran under it, so it propagates to the caller rather than becoming a
    `QueryFailure` — an outage is a thing that happened to a request, and this is
    a request that must not have been made.
    """


def _refuse_connection(_sock: Any, address: Any = None, *_rest: Any) -> Any:
    raise NetworkAttempted(
        f"a connection to {address!r} was attempted while outbound network "
        f"access was refused. A replay reads stored responses and never "
        f"re-queries (`concept/07-principles.md`); a replay that reached a "
        f"provider would be a new investigation with a different answer"
    )


def _refuse_resolution(host: Any = None, port: Any = None, *_rest: Any, **_kw: Any) -> Any:
    raise NetworkAttempted(
        f"a name resolution of {host!r}:{port!r} was attempted while outbound "
        f"network access was refused. Resolving a name is itself a query sent "
        f"to somebody, so it is refused with the connection it precedes"
    )


@contextmanager
def _patched(owner: Any, name: str, replacement: Any) -> Iterator[None]:
    """Swap one attribute, and put back exactly what was there — or nothing.

    `socket.socket` inherits `connect` from the C type rather than defining it,
    so assigning the original back would leave a shadowing entry in the class
    dictionary that was not there before. Removing it instead makes the block
    leave no trace, which is what lets a test assert that the network works again
    afterwards without asserting on an implementation detail of `socket`.
    """
    defined_here = name in vars(owner)
    original = getattr(owner, name)
    setattr(owner, name, replacement)
    try:
        yield
    finally:
        if defined_here:
            setattr(owner, name, original)
        else:
            delattr(owner, name)


@contextmanager
def no_network() -> Iterator[None]:
    """No new outbound connection may be opened inside this block.

    Raises `NetworkAttempted` at the point of the attempt, so the traceback names
    the code that tried rather than a counter that noticed afterwards. Reentrant:
    nesting two blocks is harmless and the outer one still restores.
    """
    with ExitStack() as guarded:
        guarded.enter_context(_patched(socket.socket, "connect", _refuse_connection))
        guarded.enter_context(_patched(socket.socket, "connect_ex", _refuse_connection))
        guarded.enter_context(_patched(socket, "getaddrinfo", _refuse_resolution))
        yield
