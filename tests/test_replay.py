"""The outbound-network guard: what it refuses, what it deliberately does not.

`helena.network.no_network()` is what makes the tool layer's replay mode a
property rather than a claim about which branches ran. The replay *behaviour* is
in `tests/test_tools.py`; what is here is the guard itself — that it refuses a
real connection attempt, that it refuses the name resolution in front of one,
that it puts the module back exactly as it found it, and the one thing it lets
through on purpose: the already-open connection a replay reads its stored
responses over.

That last test needs the engine, because the point of it is that a *real*
`psycopg` connection to the store keeps working inside the guard. A stand-in
would be a test of the stand-in.
"""

from __future__ import annotations

import socket

import pytest

from helena.network import NetworkAttempted, no_network


def a_closed_port() -> int:
    """A port nothing is listening on: bound, read back, released.

    Cheap and deterministic — connecting to it is refused immediately rather
    than hanging — and the connection attempt itself is what the guard has to
    intercept, so it has to be one that would otherwise really be made.
    """
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def test_a_connection_attempt_inside_the_guard_raises_where_it_was_attempted():
    port = a_closed_port()
    # The socket is closed by the `with`: pytest runs under
    # `filterwarnings = ["error"]`, so a leaked one surfaces as an unraisable
    # ResourceWarning at whatever unrelated test happens to run next.
    with socket.socket() as attempt:
        with no_network(), pytest.raises(NetworkAttempted) as refused:
            attempt.connect(("127.0.0.1", port))
    assert str(port) in str(refused.value)


def test_the_name_resolution_in_front_of_a_connection_is_refused_too():
    """Resolving a name is itself a query sent to somebody."""
    with no_network(), pytest.raises(NetworkAttempted):
        socket.getaddrinfo("example.invalid", 443)


def test_the_convenience_helper_every_http_client_uses_is_covered():
    """`socket.create_connection` is what `http.client`, `urllib` and `ssl` reach."""
    with no_network(), pytest.raises(NetworkAttempted):
        socket.create_connection(("127.0.0.1", a_closed_port()), timeout=1)


def test_without_the_guard_the_same_attempt_fails_as_itself():
    """The control: the guard is what raises, not the test's own arrangement."""
    with pytest.raises(OSError) as refused:
        socket.create_connection(("127.0.0.1", a_closed_port()), timeout=1)
    assert not isinstance(refused.value, NetworkAttempted)


def test_the_guard_leaves_the_module_exactly_as_it_found_it():
    """Including the inherited names, which are removed rather than assigned back.

    `socket.socket` does not define `connect` — it inherits it from the C type —
    so putting the original back with `setattr` would leave a shadowing entry
    that was not there before. A later reader would find a socket module that
    works and is not the one Python shipped.
    """
    before = dict(vars(socket.socket))
    with no_network():
        pass
    assert dict(vars(socket.socket)) == before
    assert socket.socket.connect is not None
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", a_closed_port()), timeout=1)


def test_nesting_is_harmless_and_the_outer_block_still_restores():
    before = dict(vars(socket.socket))
    with no_network():
        with no_network(), pytest.raises(NetworkAttempted):
            socket.getaddrinfo("example.invalid", 443)
        with pytest.raises(NetworkAttempted):
            socket.getaddrinfo("example.invalid", 443)
    assert dict(vars(socket.socket)) == before


def test_an_attempt_that_raises_still_restores():
    before = dict(vars(socket.socket))
    with pytest.raises(NetworkAttempted), no_network():
        socket.getaddrinfo("example.invalid", 443)
    assert dict(vars(socket.socket)) == before


@pytest.mark.integration
def test_an_already_open_connection_to_the_store_keeps_working_inside_the_guard(
    migrated_engine,
):
    """The one thing the guard lets through, and the reason a replay can read.

    A replay resolves every lookup out of the streaming engine, which is reached
    over a connection opened before the guard was armed. Blocking writes on an
    open socket as well would make the guard airtight and make replay impossible,
    so the bound is `connect` — nothing *new* leaves the process — and this test
    is what pins that bound rather than leaving it as a remark in a docstring.
    """
    with no_network():
        (answer,) = migrated_engine.execute("SELECT 1").fetchone()
    assert answer == 1
