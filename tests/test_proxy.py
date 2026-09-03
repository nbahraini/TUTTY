"""Proxy client tests. Run with: python -m pytest tests/test_proxy.py

The handshake tests drive the real client over a real socket against a fake
proxy, so the bytes on the wire are exercised rather than mocked out.
"""

from __future__ import annotations

import socket
import threading

import pytest

from pytty.model import Session, ValidationError
from pytty.proxy import (
    ProxyAuthError,
    ProxyConfig,
    ProxyError,
    from_environment,
    open_socket,
    parse_proxy_url,
    should_bypass,
    split_proxy_url,
)
from pytty.settings import Settings, SettingsStore


# ----------------------------------------------------------------------
# URL parsing
# ----------------------------------------------------------------------
@pytest.mark.parametrize(
    "url, scheme, host, port, user, remote_dns",
    [
        ("http://proxy:3128", "http", "proxy", 3128, "", True),
        ("https://secure.proxy:8443", "https", "secure.proxy", 8443, "", True),
        ("socks5://10.0.0.1:1080", "socks5", "10.0.0.1", 1080, "", False),
        ("socks5h://10.0.0.1:1080", "socks5", "10.0.0.1", 1080, "", True),
        ("socks4a://box:1080", "socks4", "box", 1080, "", True),
        ("socks5://bob@host:1080", "socks5", "host", 1080, "bob", False),
    ],
)
def test_parse_proxy_url(url, scheme, host, port, user, remote_dns):
    config = parse_proxy_url(url)
    assert (config.scheme, config.host, config.port) == (scheme, host, port)
    assert config.username == user
    assert config.remote_dns is remote_dns


def test_bare_host_is_treated_as_http():
    # http_proxy variables have always allowed this spelling.
    config = parse_proxy_url("proxy.example:3128")
    assert config.scheme == "http"
    assert config.port == 3128


def test_missing_port_falls_back_to_the_scheme_default():
    assert parse_proxy_url("socks5://box").effective_port == 1080
    assert parse_proxy_url("http://box").effective_port == 8080


def test_password_is_split_out_and_url_decoded():
    config, password = split_proxy_url("http://user:p%40ss%3Aword@proxy:3128")
    assert config.username == "user"
    assert password == "p@ss:word"
    # The config that gets written to disk must not carry the secret.
    assert "p@ss" not in str(config.to_dict())


def test_url_round_trips():
    config = parse_proxy_url("socks5h://bob@host:1080")
    assert parse_proxy_url(config.to_url()).to_dict() == config.to_dict()


def test_unknown_scheme_is_rejected():
    with pytest.raises(ValueError, match="Unknown proxy type"):
        parse_proxy_url("ftp://proxy:21")


def test_environment_is_read_in_priority_order():
    config, _ = from_environment({"HTTP_PROXY": "http://a:1", "ALL_PROXY": "socks5://b:2"})
    assert (config.scheme, config.host) == ("socks5", "b")


def test_no_proxy_becomes_an_exclusion_list():
    config, _ = from_environment(
        {"ALL_PROXY": "socks5://b:2", "NO_PROXY": "*.internal, 10.0.0.0/8"}
    )
    assert "*.internal" in config.exclude
    assert should_bypass(config, "db.internal")


# ----------------------------------------------------------------------
# Exclusions
# ----------------------------------------------------------------------
@pytest.mark.parametrize(
    "patterns, host, expected",
    [
        (["<local>"], "localhost", True),
        (["<local>"], "127.0.0.1", True),
        (["<local>"], "buildbox", True),  # no dot, so it is a local name
        (["<local>"], "example.com", False),
        (["*.internal"], "db.internal", True),
        (["*.internal"], "db.internal.example.com", False),
        ([".example.com"], "host.example.com", True),
        (["10.0.0.0/8"], "10.2.3.4", True),
        (["10.0.0.0/8"], "11.2.3.4", False),
        (["10.0.0.0/8"], "not-an-ip", False),
    ],
)
def test_should_bypass(patterns, host, expected):
    assert should_bypass(ProxyConfig(exclude=patterns), host) is expected


# ----------------------------------------------------------------------
# A fake proxy, so the handshakes run over a real socket
# ----------------------------------------------------------------------
class FakeProxy:
    """Speaks just enough of each protocol to answer one CONNECT."""

    def __init__(self, script) -> None:
        self.script = script
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.host, self.port = self.listener.getsockname()
        self.request = bytearray()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        try:
            conn, _ = self.listener.accept()
        except OSError:
            return
        try:
            self.script(self, conn)
        except OSError:
            pass
        finally:
            conn.close()

    def close(self) -> None:
        self.listener.close()

    def config(self, scheme: str, **kwargs) -> ProxyConfig:
        return ProxyConfig(scheme=scheme, host=self.host, port=self.port, **kwargs)


@pytest.fixture
def proxy_factory():
    made: list[FakeProxy] = []

    def make(script) -> FakeProxy:
        proxy = FakeProxy(script)
        made.append(proxy)
        return proxy

    yield make
    for proxy in made:
        proxy.close()


def _recv_n(conn: socket.socket, count: int) -> bytes:
    """Exact read: recv is free to return short, even on loopback."""
    out = bytearray()
    while len(out) < count:
        chunk = conn.recv(count - len(out))
        if not chunk:
            break
        out += chunk
    return bytes(out)


def _read_http_head(conn: socket.socket) -> bytes:
    buffer = bytearray()
    while b"\r\n\r\n" not in buffer:
        chunk = conn.recv(1024)
        if not chunk:
            break
        buffer += chunk
    return bytes(buffer)


# -- HTTP ---------------------------------------------------------------
def test_http_connect_succeeds_and_relays(proxy_factory):
    def script(proxy: FakeProxy, conn: socket.socket) -> None:
        proxy.request += _read_http_head(conn)
        conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        conn.sendall(b"SSH-2.0-fake")

    proxy = proxy_factory(script)
    sock = open_socket(proxy.config("http"), "target.internal", 22, timeout=5)
    try:
        assert sock.recv(32) == b"SSH-2.0-fake"
    finally:
        sock.close()
    assert b"CONNECT target.internal:22 HTTP/1.1" in bytes(proxy.request)
    # The socket handed to paramiko must be blocking with no timeout.
    assert sock.gettimeout() is None


def test_http_connect_keeps_data_coalesced_with_the_response(proxy_factory):
    """Regression: the response head and the first tunnelled bytes in one write.

    A buffered read of the head swallows whatever follows it, and the socket
    goes straight to paramiko afterwards, so those bytes are gone for good —
    the SSH banner among them.
    """

    def script(proxy: FakeProxy, conn: socket.socket) -> None:
        _read_http_head(conn)
        conn.sendall(b"HTTP/1.1 200 OK\r\n\r\nSSH-2.0-OpenSSH_9.6\r\n")

    proxy = proxy_factory(script)
    sock = open_socket(proxy.config("http"), "host", 22, timeout=5)
    try:
        assert sock.recv(64).startswith(b"SSH-2.0-OpenSSH_9.6")
    finally:
        sock.close()


def test_http_connect_sends_basic_credentials(proxy_factory):
    def script(proxy: FakeProxy, conn: socket.socket) -> None:
        proxy.request += _read_http_head(conn)
        conn.sendall(b"HTTP/1.1 200 OK\r\n\r\n")

    proxy = proxy_factory(script)
    config = proxy.config("http", username="alice")
    open_socket(config, "host", 22, timeout=5, password="secret").close()
    # base64("alice:secret")
    assert b"Proxy-Authorization: Basic YWxpY2U6c2VjcmV0" in bytes(proxy.request)


def test_http_407_is_an_auth_error(proxy_factory):
    def script(proxy: FakeProxy, conn: socket.socket) -> None:
        _read_http_head(conn)
        conn.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")

    proxy = proxy_factory(script)
    with pytest.raises(ProxyAuthError, match="requires authentication"):
        open_socket(proxy.config("http"), "host", 22, timeout=5)


def test_http_403_on_an_odd_port_explains_the_usual_cause(proxy_factory):
    def script(proxy: FakeProxy, conn: socket.socket) -> None:
        _read_http_head(conn)
        conn.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n")

    proxy = proxy_factory(script)
    with pytest.raises(ProxyError, match="only allow CONNECT to 443"):
        open_socket(proxy.config("http"), "host", 22, timeout=5)


def test_http_garbage_is_reported_not_swallowed(proxy_factory):
    def script(proxy: FakeProxy, conn: socket.socket) -> None:
        _read_http_head(conn)
        conn.sendall(b"not http at all\r\n\r\n")

    proxy = proxy_factory(script)
    with pytest.raises(ProxyError, match="not HTTP"):
        open_socket(proxy.config("http"), "host", 22, timeout=5)


# -- SOCKS5 -------------------------------------------------------------
def test_socks5_sends_the_hostname_when_remote_dns_is_on(proxy_factory):
    def script(proxy: FakeProxy, conn: socket.socket) -> None:
        proxy.request += conn.recv(3)  # greeting
        conn.sendall(b"\x05\x00")
        proxy.request += conn.recv(512)  # request
        conn.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        conn.sendall(b"through")

    proxy = proxy_factory(script)
    sock = open_socket(proxy.config("socks5", remote_dns=True), "db.internal", 5432, timeout=5)
    try:
        assert sock.recv(16) == b"through"
    finally:
        sock.close()
    # The full request: ATYP 3, length, name, then the port. The port is the
    # part that is easy to leave off, so assert the whole tail.
    assert bytes(proxy.request).endswith(
        b"\x05\x01\x00\x03\x0bdb.internal" + (5432).to_bytes(2, "big")
    )


def test_socks5_sends_an_ip_literal_as_an_address(proxy_factory):
    def script(proxy: FakeProxy, conn: socket.socket) -> None:
        conn.recv(3)
        conn.sendall(b"\x05\x00")
        proxy.request += conn.recv(512)
        conn.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")

    proxy = proxy_factory(script)
    open_socket(proxy.config("socks5"), "10.1.2.3", 22, timeout=5).close()
    # ATYP 1, the four octets, then the port.
    assert bytes(proxy.request).endswith(
        b"\x05\x01\x00\x01\x0a\x01\x02\x03" + (22).to_bytes(2, "big")
    )


def test_socks5_request_is_exactly_the_length_the_protocol_requires(proxy_factory):
    """Regression: the destination port was once left off the request entirely.

    A proxy reading a short request silently takes the last two address bytes
    as the port, so the failure is a connection to the wrong place rather than
    an error — which is why this asserts the byte count.
    """
    received: list[bytes] = []

    def script(proxy: FakeProxy, conn: socket.socket) -> None:
        conn.recv(3)
        conn.sendall(b"\x05\x00")
        head = _recv_n(conn, 4)
        host = _recv_n(conn, _recv_n(conn, 1)[0])
        port = _recv_n(conn, 2)
        received.append(head + host + port)
        conn.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)

    proxy = proxy_factory(script)
    open_socket(proxy.config("socks5"), "example.internal", 2222, timeout=5).close()
    assert received, "the proxy never received a complete request"
    request = received[0]
    assert request[:4] == b"\x05\x01\x00\x03"
    assert request[4:-2].decode() == "example.internal"
    assert int.from_bytes(request[-2:], "big") == 2222


def test_socks5_username_password_subnegotiation(proxy_factory):
    def script(proxy: FakeProxy, conn: socket.socket) -> None:
        proxy.request += conn.recv(4)
        conn.sendall(b"\x05\x02")  # demand username/password
        proxy.request += conn.recv(512)
        conn.sendall(b"\x01\x00")  # accepted
        conn.recv(512)
        conn.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")

    proxy = proxy_factory(script)
    config = proxy.config("socks5", username="bob")
    open_socket(config, "host", 22, timeout=5, password="hunter2").close()
    sent = bytes(proxy.request)
    assert b"\x02" in sent[:4]  # we offered method 2
    assert b"\x03bob\x07hunter2" in sent


def test_socks5_rejected_credentials_raise_auth_error(proxy_factory):
    def script(proxy: FakeProxy, conn: socket.socket) -> None:
        conn.recv(4)
        conn.sendall(b"\x05\x02")
        conn.recv(512)
        conn.sendall(b"\x01\x01")  # rejected

    proxy = proxy_factory(script)
    config = proxy.config("socks5", username="bob")
    with pytest.raises(ProxyAuthError, match="rejected the username"):
        open_socket(config, "host", 22, timeout=5, password="wrong")


def test_socks5_no_acceptable_method_mentions_credentials(proxy_factory):
    def script(proxy: FakeProxy, conn: socket.socket) -> None:
        conn.recv(3)
        conn.sendall(b"\x05\xff")

    proxy = proxy_factory(script)
    with pytest.raises(ProxyAuthError, match="username and password"):
        open_socket(proxy.config("socks5"), "host", 22, timeout=5)


@pytest.mark.parametrize(
    "code, fragment",
    [
        (0x02, "not allowed by ruleset"),
        (0x03, "network unreachable"),
        (0x04, "host unreachable"),
        (0x05, "connection refused"),
    ],
)
def test_socks5_failure_codes_are_translated(proxy_factory, code, fragment):
    def script(proxy: FakeProxy, conn: socket.socket) -> None:
        conn.recv(3)
        conn.sendall(b"\x05\x00")
        conn.recv(512)
        conn.sendall(bytes([0x05, code, 0x00, 0x01]) + b"\x00" * 6)

    proxy = proxy_factory(script)
    with pytest.raises(ProxyError, match=fragment):
        open_socket(proxy.config("socks5"), "host", 22, timeout=5)


def test_socks5_hangup_midway_is_reported(proxy_factory):
    def script(proxy: FakeProxy, conn: socket.socket) -> None:
        conn.recv(3)
        conn.close()

    proxy = proxy_factory(script)
    with pytest.raises(ProxyError, match="closed the connection"):
        open_socket(proxy.config("socks5"), "host", 22, timeout=5)


# -- SOCKS4 -------------------------------------------------------------
def test_socks4a_sends_the_hostname_after_the_user_id(proxy_factory):
    def script(proxy: FakeProxy, conn: socket.socket) -> None:
        proxy.request += conn.recv(512)
        conn.sendall(b"\x00\x5a" + b"\x00" * 6)

    proxy = proxy_factory(script)
    open_socket(proxy.config("socks4", username="me"), "db.internal", 5432, timeout=5).close()
    sent = bytes(proxy.request)
    assert sent[:2] == b"\x04\x01"
    assert sent[4:8] == b"\x00\x00\x00\x01"  # 0.0.0.x marks SOCKS4a
    assert sent.endswith(b"me\x00db.internal\x00")


def test_socks4_rejection_is_translated(proxy_factory):
    def script(proxy: FakeProxy, conn: socket.socket) -> None:
        conn.recv(512)
        conn.sendall(b"\x00\x5b" + b"\x00" * 6)

    proxy = proxy_factory(script)
    with pytest.raises(ProxyError, match="rejected or failed"):
        open_socket(proxy.config("socks4"), "host", 22, timeout=5)


def test_socks4_refuses_ipv6_rather_than_sending_nonsense(proxy_factory):
    def script(proxy: FakeProxy, conn: socket.socket) -> None:
        conn.recv(512)

    proxy = proxy_factory(script)
    with pytest.raises(ProxyError, match="cannot carry IPv6"):
        open_socket(proxy.config("socks4"), "2001:db8::1", 22, timeout=5)


def test_unreachable_proxy_names_the_proxy_not_the_target():
    # Port 1 on loopback has nothing on it.
    config = ProxyConfig(scheme="socks5", host="127.0.0.1", port=1)
    with pytest.raises(ProxyError, match="Cannot reach proxy"):
        open_socket(config, "host", 22, timeout=2)


# ----------------------------------------------------------------------
# Session and settings wiring
# ----------------------------------------------------------------------
def test_session_proxy_modes_resolve_correctly():
    app_proxy = parse_proxy_url("socks5://app:1080")
    own = parse_proxy_url("http://own:3128")

    globally = Session(name="a", host="h")
    assert globally.effective_proxy(app_proxy) is app_proxy

    direct = Session(name="a", host="h", proxy_mode="none", proxy=own)
    assert direct.effective_proxy(app_proxy) is None

    custom = Session(name="a", host="h", proxy_mode="custom", proxy=own)
    assert custom.effective_proxy(app_proxy) is own

    # No app proxy configured means no proxy, not a broken one.
    assert Session(name="a", host="h").effective_proxy(ProxyConfig()) is None


def test_custom_mode_without_a_proxy_is_rejected():
    session = Session(name="a", host="h", proxy_mode="custom")
    with pytest.raises(ValidationError, match="no proxy is configured"):
        session.validate()


def test_session_proxy_survives_a_round_trip():
    session = Session(
        name="a", host="h", proxy_mode="custom", proxy=parse_proxy_url("socks5h://bob@p:1080")
    )
    restored = Session.from_dict(session.to_dict())
    assert restored.proxy.to_dict() == session.proxy.to_dict()
    assert restored.proxy_mode == "custom"


def test_a_proxy_written_as_a_bare_url_is_still_read():
    # Someone hand-editing sessions.json is likely to write the URL form.
    session = Session.from_dict(
        {"name": "a", "host": "h", "proxy_mode": "custom", "proxy": "socks5://p:1080"}
    )
    assert session.proxy.host == "p"


def test_settings_round_trip(tmp_path):
    store = SettingsStore(tmp_path / "settings.json")
    store.update(Settings(proxy=parse_proxy_url("http://corp:3128")))
    assert SettingsStore(tmp_path / "settings.json").settings.proxy.host == "corp"


def test_settings_file_is_not_world_readable(tmp_path):
    path = tmp_path / "settings.json"
    store = SettingsStore(path)
    store.update(Settings(proxy=parse_proxy_url("http://corp:3128")))
    assert path.stat().st_mode & 0o077 == 0


def test_a_configured_proxy_beats_the_environment(monkeypatch):
    monkeypatch.setenv("ALL_PROXY", "socks5://env:1080")
    settings = Settings(proxy=parse_proxy_url("http://configured:3128"))
    assert settings.resolved_proxy()[0].host == "configured"
    assert settings.proxy_origin() == "settings"


def test_the_environment_is_used_when_nothing_is_configured(monkeypatch):
    monkeypatch.setenv("ALL_PROXY", "socks5://env:1080")
    settings = Settings()
    assert settings.resolved_proxy()[0].host == "env"
    assert settings.proxy_origin() == "environment"


def test_turning_the_environment_fallback_off_really_turns_it_off(monkeypatch):
    monkeypatch.setenv("ALL_PROXY", "socks5://env:1080")
    settings = Settings(use_environment_proxy=False)
    assert settings.resolved_proxy()[0].enabled is False
    assert settings.proxy_origin() == "none"


# ----------------------------------------------------------------------
# Connector wiring: Session settings actually reaching the proxy layer
# ----------------------------------------------------------------------
class _Echo:
    """A real TCP listener, so _dial can be checked end to end."""

    def __init__(self) -> None:
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.host, self.port = self.listener.getsockname()
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        try:
            conn, _ = self.listener.accept()
        except OSError:
            return
        with conn:
            try:
                conn.sendall(b"hello")
            except OSError:
                pass

    def close(self) -> None:
        self.listener.close()


def _connector(session, proxy=None, password=None):
    from pytty.ssh import Connector

    return Connector(session, prompter=None, log=lambda *a: None,
                     proxy=proxy, proxy_password=password)


def test_dial_returns_none_when_there_is_nothing_to_customise():
    # Without a proxy, a bind address or a family, paramiko should make its
    # own socket exactly as it did before any of this existed.
    assert _connector(Session(name="a", host="h"))._dial("h", 22) is None


def test_dial_goes_through_the_proxy(proxy_factory):
    def script(proxy: FakeProxy, conn: socket.socket) -> None:
        proxy.request += conn.recv(3)
        conn.sendall(b"\x05\x00")
        proxy.request += conn.recv(512)
        conn.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        conn.sendall(b"hello")

    proxy = proxy_factory(script)
    session = Session(name="a", host="db.internal", port=22)
    sock = _connector(session, proxy.config("socks5"))._dial("db.internal", 22)
    try:
        assert sock.recv(8) == b"hello"
    finally:
        sock.close()
    assert b"db.internal" in bytes(proxy.request)


def test_dial_skips_the_proxy_for_an_excluded_host():
    echo = _Echo()
    try:
        # The proxy points at a dead port; if it were used, this would fail.
        proxy = ProxyConfig(
            scheme="socks5", host="127.0.0.1", port=1, exclude=["<local>"]
        )
        session = Session(name="a", host=echo.host, port=echo.port)
        session.bind_address = "127.0.0.1"  # force a socket we can inspect
        sock = _connector(session, proxy)._dial(echo.host, echo.port)
        try:
            assert sock.recv(8) == b"hello"
        finally:
            sock.close()
    finally:
        echo.close()


def test_dial_honours_the_bind_address_without_a_proxy():
    echo = _Echo()
    try:
        session = Session(name="a", host=echo.host, port=echo.port)
        session.bind_address = "127.0.0.1"
        sock = _connector(session)._dial(echo.host, echo.port)
        try:
            assert sock.getsockname()[0] == "127.0.0.1"
            assert sock.recv(8) == b"hello"
        finally:
            sock.close()
    finally:
        echo.close()


def test_dial_honours_the_address_family():
    echo = _Echo()
    try:
        session = Session(name="a", host="localhost", port=echo.port)
        session.address_family = "ipv4"
        sock = _connector(session)._dial("localhost", echo.port)
        try:
            assert sock.family == socket.AF_INET
        finally:
            sock.close()
    finally:
        echo.close()


def test_a_proxy_password_reaches_the_handshake(proxy_factory):
    def script(proxy: FakeProxy, conn: socket.socket) -> None:
        conn.recv(4)
        conn.sendall(b"\x05\x02")
        proxy.request += conn.recv(512)
        conn.sendall(b"\x01\x00")
        conn.recv(512)
        conn.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")

    proxy = proxy_factory(script)
    # A dotted name, because a bare one matches the default <local> exclusion
    # and would be dialled directly.
    session = Session(name="a", host="host.example")
    config = proxy.config("socks5", username="bob")
    _connector(session, config, "hunter2")._dial("host.example", 22).close()
    assert b"\x03bob\x07hunter2" in bytes(proxy.request)


def test_a_bare_hostname_matches_the_default_local_exclusion(proxy_factory):
    """<local> covers dotless names, so an intranet short name goes direct.

    This is the same rule browsers and curl use, and it is easy to trip over:
    "myserver" bypasses the proxy while "myserver.corp.example" does not.
    """
    proxy = proxy_factory(lambda p, c: None)
    session = Session(name="a", host="myserver")
    assert _connector(session, proxy.config("socks5"))._dial("myserver", 22) is None
