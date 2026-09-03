"""The forward servers must never write to stderr.

pytty hands the terminal to the remote host in raw mode. A traceback from a
tunnel thread would land in the middle of the user's shell, so socketserver's
default error handling has to be replaced, not merely tolerated.
"""

from __future__ import annotations

import socket
import threading

import pytest

from pytty.ssh import _SocksHandler, _ThreadedForwardServer


class _ExplodingTransport:
    def open_channel(self, kind, dest, origin):  # noqa: ANN001
        raise RuntimeError("boom")


@pytest.fixture
def server_and_log():
    messages: list[tuple[str, str]] = []
    handler = type(
        "H",
        (_SocksHandler,),
        {
            "transport": _ExplodingTransport(),
            "log": staticmethod(lambda level, message: messages.append((level, message))),
        },
    )
    server = _ThreadedForwardServer(("127.0.0.1", 0), handler)
    server.log = lambda level, message: messages.append((level, message))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server.server_address, messages
    server.shutdown()
    server.server_close()


def test_channel_failure_is_logged_not_printed(server_and_log, capfd):
    address, messages = server_and_log
    client = socket.create_connection(address, timeout=5)
    client.sendall(b"\x05\x01\x00")
    assert client.recv(2) == b"\x05\x00"
    client.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01\x1f\x90")
    reply = client.recv(10)
    client.close()

    assert reply[1] == 0x05  # refused, with a reason the client understands
    assert any("boom" in message for _, message in messages)
    assert capfd.readouterr().err == ""


def test_default_log_is_safe_without_configuration():
    # The class-level default must be callable with two arguments and must
    # not receive an implicit self.
    _SocksHandler.log("info", "nothing should happen")
    _ThreadedForwardServer.log("info", "nothing should happen")
