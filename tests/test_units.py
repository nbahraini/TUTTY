"""Unit tests. Run with: python -m pytest tests/test_units.py"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from pytty.cli import build_parser, parse_escape
from pytty.model import (
    Session,
    ValidationError,
    parse_dynamic,
    parse_forward,
    parse_target,
)
from pytty.store import SessionStore


# ----------------------------------------------------------------------
# model
# ----------------------------------------------------------------------
def test_target_formatting():
    assert Session(host="h", username="u").target == "u@h"
    assert Session(host="h", username="u", port=2222).target == "u@h:2222"
    assert Session(host="h").target == "h"


def test_dead_after_matches_documented_budget():
    session = Session(host="h", keepalive_interval=30, keepalive_count_max=3)
    assert session.dead_after() == 120
    assert Session(host="h", keepalive_interval=0).dead_after() == float("inf")


@pytest.mark.parametrize(
    "kwargs, fragment",
    [
        ({"name": ""}, "name"),
        ({"host": ""}, "hostname"),
        ({"port": 0}, "Port"),
        ({"port": 99999}, "Port"),
        ({"auth": "key", "key_path": ""}, "private key"),
        ({"keepalive_count_max": 0}, "missed keepalive"),
        ({"reconnect_delay": 0}, "greater than zero"),
        ({"reconnect_delay": 30, "reconnect_max_delay": 5}, "Maximum backoff"),
        ({"reconnect_attempts": -1}, "cannot be negative"),
        ({"local_forwards": ["nonsense"]}, "8080:127.0.0.1:80"),
        ({"dynamic_forwards": ["nonsense"]}, "1080"),
        ({"dynamic_forwards": ["1080:127.0.0.1:80"]}, "1080"),
        ({"dynamic_forwards": ["99999"]}, "between 1 and 65535"),
    ],
)
def test_validation_rejects(kwargs, fragment):
    base = dict(name="ok", host="example.com")
    base.update(kwargs)
    with pytest.raises(ValidationError) as info:
        Session(**base).validate()
    assert fragment in str(info.value)


def test_valid_session_passes():
    Session(name="ok", host="example.com", local_forwards=["8080:127.0.0.1:80"]).validate()


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("host", ("", "host", 22)),
        ("user@host", ("user", "host", 22)),
        ("user@host:2222", ("user", "host", 2222)),
        ("[2001:db8::1]:2200", ("", "2001:db8::1", 2200)),
    ],
)
def test_parse_target(raw, expected):
    assert parse_target(raw) == expected


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("8080:127.0.0.1:80", ("127.0.0.1", 8080, "127.0.0.1", 80)),
        ("0.0.0.0:8080:internal:80", ("0.0.0.0", 8080, "internal", 80)),
    ],
)
def test_parse_forward(raw, expected):
    assert parse_forward(raw) == expected


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("1080", ("127.0.0.1", 1080)),
        ("0.0.0.0:1080", ("0.0.0.0", 1080)),
        ("[::1]:1080", ("::1", 1080)),
    ],
)
def test_parse_dynamic(raw, expected):
    assert parse_dynamic(raw) == expected


def test_dynamic_forward_defaults_to_loopback():
    # An unqualified -D must not open a proxy to the whole network.
    assert parse_dynamic("1080")[0] == "127.0.0.1"


def test_unknown_keys_are_ignored_on_load():
    session = Session.from_dict({"name": "a", "host": "b", "invented_later": True})
    assert session.name == "a"


def test_numbers_survive_string_input():
    session = Session.from_dict({"name": "a", "host": "b", "port": "2222", "compression": "yes"})
    assert session.port == 2222 and session.compression is True


# ----------------------------------------------------------------------
# store
# ----------------------------------------------------------------------
@pytest.fixture
def store(tmp_path: Path) -> SessionStore:
    return SessionStore(tmp_path / "sessions.json")


def test_round_trip(store: SessionStore):
    store.add(Session(name="web", host="10.0.0.1", username="root", keepalive_interval=15))
    reopened = SessionStore(store.path)
    assert reopened.get("web").keepalive_interval == 15


def test_duplicate_names_rejected(store: SessionStore):
    store.add(Session(name="web", host="a"))
    with pytest.raises(ValueError):
        store.add(Session(name="web", host="b"))


def test_rename_keeps_one_entry(store: SessionStore):
    store.add(Session(name="old", host="a"))
    store.update("old", Session(name="new", host="a"))
    assert len(store) == 1 and "new" in store


def test_unique_name_suffixes(store: SessionStore):
    store.add(Session(name="web", host="a"))
    assert store.unique_name("web") == "web (2)"
    store.add(Session(name="web (2)", host="a"))
    assert store.unique_name("web") == "web (3)"


def test_file_is_not_world_readable(store: SessionStore):
    store.add(Session(name="web", host="a"))
    assert oct(store.path.stat().st_mode)[-3:] == "600"


def test_corrupt_file_reports_clearly(tmp_path: Path):
    path = tmp_path / "sessions.json"
    path.write_text("{ this is not json")
    with pytest.raises(RuntimeError) as info:
        SessionStore(path)
    assert "Cannot read" in str(info.value)


def test_save_is_atomic(store: SessionStore):
    store.add(Session(name="web", host="a"))
    leftovers = [p for p in store.path.parent.iterdir() if p.name.startswith(".sessions-")]
    assert not leftovers
    assert json.loads(store.path.read_text())["version"] == 1


def test_clone_resets_usage(store: SessionStore):
    original = Session(name="web", host="a", last_used=12345.0)
    copy = original.clone("web copy")
    assert copy.name == "web copy" and copy.last_used == 0.0 and copy.host == "a"


def test_import_ssh_config(tmp_path: Path):
    config = tmp_path / "config"
    config.write_text(
        "Host bastion\n"
        "  HostName bastion.example.com\n"
        "  User admin\n"
        "  Port 2222\n"
        "\n"
        "Host *\n"
        "  ServerAliveInterval 60\n"
    )
    store = SessionStore(tmp_path / "sessions.json")
    added = store.import_ssh_config(config)
    assert [s.name for s in added] == ["bastion"]
    assert added[0].host == "bastion.example.com"
    assert added[0].port == 2222 and added[0].username == "admin"


def test_import_ssh_config_carries_tunnels(tmp_path: Path):
    config = tmp_path / "config"
    config.write_text(
        "Host web\n"
        "  HostName web.example.com\n"
        "  User deploy\n"
        "  ProxyJump admin@bastion\n"
        "  LocalForward 8080 localhost:80\n"
        "  LocalForward 5432 db:5432\n"
        "  RemoteForward 8000 127.0.0.1:3000\n"
        "  DynamicForward 1080\n"
    )
    store = SessionStore(tmp_path / "sessions.json")
    added = store.import_ssh_config(config)
    session = added[0]
    # ssh_config separates the two halves with a space; pytty uses a colon.
    assert session.local_forwards == ["8080:localhost:80", "5432:db:5432"]
    assert session.remote_forwards == ["8000:127.0.0.1:3000"]
    assert session.dynamic_forwards == ["1080"]
    assert session.jump_host == "admin@bastion"
    session.validate()


def test_import_ssh_config_without_tunnels_leaves_them_empty(tmp_path: Path):
    config = tmp_path / "config"
    config.write_text("Host plain\n  HostName plain.example.com\n")
    store = SessionStore(tmp_path / "sessions.json")
    session = store.import_ssh_config(config)[0]
    assert session.local_forwards == []
    assert session.dynamic_forwards == []


# ----------------------------------------------------------------------
# cli
# ----------------------------------------------------------------------
@pytest.mark.parametrize(
    "text, expected", [("ctrl+]", 0x1D), ("^]", 0x1D), ("ctrl-a", 0x01), ("~", ord("~"))]
)
def test_parse_escape(text, expected):
    assert parse_escape(text) == expected


def test_cli_overrides_apply_to_a_saved_session():
    from pytty.cli import apply_overrides

    args = build_parser().parse_args(
        ["web", "--keepalive", "5", "--attempts", "3", "--no-reconnect", "-L", "9000:h:80"]
    )
    session = apply_overrides(Session(name="web", host="a"), args)
    assert session.keepalive_interval == 5
    assert session.reconnect_attempts == 3
    assert session.auto_reconnect is False
    assert session.local_forwards == ["9000:h:80"]


def test_cli_collects_every_tunnel_flag():
    from pytty.cli import apply_overrides

    args = build_parser().parse_args(
        [
            "web",
            "-J",
            "admin@bastion",
            "-L",
            "9000:h:80",
            "-L",
            "9001:h:81",
            "-R",
            "8000:127.0.0.1:3000",
            "-D",
            "1080",
            "-D",
            "127.0.0.1:1081",
        ]
    )
    session = apply_overrides(Session(name="web", host="a"), args)
    assert session.jump_host == "admin@bastion"
    assert session.local_forwards == ["9000:h:80", "9001:h:81"]
    assert session.remote_forwards == ["8000:127.0.0.1:3000"]
    assert session.dynamic_forwards == ["1080", "127.0.0.1:1081"]
    session.validate()


# ----------------------------------------------------------------------
# SOCKS (-D)
#
# The handler is driven over a real socket. The SSH transport is faked:
# open_channel hands back one end of a socketpair, which behaves like a
# paramiko Channel closely enough for the pump (sendall / recv / fileno).
# ----------------------------------------------------------------------
import socket
import struct
import threading

from pytty.ssh import _SocksHandler, _ThreadedForwardServer


class _FakeTransport:
    def __init__(self, refuse: bool = False) -> None:
        self.refuse = refuse
        self.requested: list[tuple[str, int]] = []
        self.far_end: socket.socket | None = None

    def open_channel(self, kind, dest, origin):  # noqa: ANN001
        assert kind == "direct-tcpip"
        self.requested.append((dest[0], dest[1]))
        if self.refuse:
            raise OSError("Administratively prohibited")
        near, far = socket.socketpair()
        self.far_end = far
        return near


@pytest.fixture
def socks_server():
    servers = []

    def start(transport):
        handler = type(
            "H", (_SocksHandler,), {"transport": transport, "log": staticmethod(lambda *a: None)}
        )
        server = _ThreadedForwardServer(("127.0.0.1", 0), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        return server.server_address

    yield start
    for server in servers:
        server.shutdown()
        server.server_close()


def _socks5_connect(address, host: bytes, port: int) -> tuple[socket.socket, bytes]:
    client = socket.create_connection(address, timeout=5)
    client.sendall(b"\x05\x01\x00")
    assert client.recv(2) == b"\x05\x00"
    request = b"\x05\x01\x00\x03" + bytes([len(host)]) + host + struct.pack(">H", port)
    client.sendall(request)
    return client, client.recv(10)


def test_socks5_connect_opens_a_channel_and_relays(socks_server):
    transport = _FakeTransport()
    address = socks_server(transport)
    client, reply = _socks5_connect(address, b"internal.example.com", 8080)

    assert reply[0] == 0x05 and reply[1] == 0x00
    assert transport.requested == [("internal.example.com", 8080)]

    client.sendall(b"ping")
    assert transport.far_end.recv(4) == b"ping"
    transport.far_end.sendall(b"pong")
    assert client.recv(4) == b"pong"
    client.close()


def test_socks5_reports_a_refused_tunnel(socks_server):
    address = socks_server(_FakeTransport(refuse=True))
    _, reply = _socks5_connect(address, b"blocked.example.com", 80)
    # 0x05 is "connection refused by destination host".
    assert reply[0] == 0x05 and reply[1] == 0x05


def test_socks5_rejects_bind_and_udp(socks_server):
    address = socks_server(_FakeTransport())
    client = socket.create_connection(address, timeout=5)
    client.sendall(b"\x05\x01\x00")
    client.recv(2)
    client.sendall(b"\x05\x02\x00\x01\x7f\x00\x00\x01\x00\x50")  # BIND
    reply = client.recv(10)
    assert reply[1] == 0x07  # command not supported
    client.close()


def test_socks5_refuses_when_no_shared_auth_method(socks_server):
    address = socks_server(_FakeTransport())
    client = socket.create_connection(address, timeout=5)
    client.sendall(b"\x05\x01\x02")  # username/password only
    assert client.recv(2) == b"\x05\xff"
    client.close()


def test_socks4a_hostname_request(socks_server):
    transport = _FakeTransport()
    address = socks_server(transport)
    client = socket.create_connection(address, timeout=5)
    # 0.0.0.1 as the address marks this as SOCKS4a with a hostname to follow.
    client.sendall(
        b"\x04\x01" + struct.pack(">H", 443) + b"\x00\x00\x00\x01" + b"user\x00"
        b"secure.example.com\x00"
    )
    reply = client.recv(8)
    assert reply[0] == 0x00 and reply[1] == 0x5A
    assert transport.requested == [("secure.example.com", 443)]
    client.close()


def test_socks4_numeric_request(socks_server):
    transport = _FakeTransport()
    address = socks_server(transport)
    client = socket.create_connection(address, timeout=5)
    client.sendall(b"\x04\x01" + struct.pack(">H", 22) + socket.inet_aton("10.0.0.5") + b"\x00")
    reply = client.recv(8)
    assert reply[1] == 0x5A
    assert transport.requested == [("10.0.0.5", 22)]
    client.close()


def test_unknown_socks_version_is_dropped(socks_server):
    address = socks_server(_FakeTransport())
    client = socket.create_connection(address, timeout=5)
    client.sendall(b"\x09\x01\x00")
    # Closed without a reply. Unread bytes in the receive buffer mean the
    # close may surface as a reset rather than a clean EOF.
    try:
        assert client.recv(16) == b""
    except ConnectionResetError:
        pass
    client.close()


def test_cli_leaves_unset_options_alone():
    from pytty.cli import apply_overrides

    args = build_parser().parse_args(["web"])
    session = apply_overrides(Session(name="web", host="a", keepalive_interval=42), args)
    assert session.keepalive_interval == 42 and session.auto_reconnect is True
