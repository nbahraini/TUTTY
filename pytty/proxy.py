"""Reaching the SSH server through a proxy.

This is the client side of a proxy, not to be confused with the ``-D`` SOCKS
listener in :mod:`pytty.ssh`, which is the server side. The two are opposite
ends of the same idea and it is easy to mix them up:

    -D 1080          pytty *offers* a SOCKS proxy, tunnelled over SSH
    --proxy socks5://…   pytty *uses* a proxy to reach the SSH server

Only the first outbound connection goes through here — the SSH server, or the
first host in a ``-J`` chain. Later hops already travel inside the SSH
connection that the proxy carried, so proxying them again would be wrapping a
tunnel in itself.
"""

from __future__ import annotations

import base64
import fnmatch
import ipaddress
import socket
import ssl
from dataclasses import asdict, dataclass, field
from typing import Any, Callable
from urllib.parse import unquote, urlsplit

PROXY_SCHEMES = ("none", "http", "https", "socks4", "socks5")

SCHEME_LABELS = {
    "none": "No proxy — connect directly",
    "http": "HTTP CONNECT",
    "https": "HTTP CONNECT over TLS",
    "socks4": "SOCKS4 / 4a",
    "socks5": "SOCKS5",
}

DEFAULT_PORTS = {"http": 8080, "https": 8443, "socks4": 1080, "socks5": 1080}

# Aliases people actually type. socks5h is curl's spelling for "resolve the
# hostname at the proxy", which is what remote_dns turns on.
SCHEME_ALIASES = {
    "socks": "socks5",
    "socks5h": "socks5",
    "socks4a": "socks4",
    "connect": "http",
}

Logger = Callable[[str, str], None]


class ProxyError(OSError):
    """The proxy refused, or could not be reached.

    Subclasses OSError so the supervisor's existing retry logic treats a
    proxy failure the same as any other connection failure.
    """


class ProxyAuthError(ProxyError):
    """The proxy wants credentials, or rejected the ones it was given."""


@dataclass
class ProxyConfig:
    """Where to find a proxy and how to talk to it."""

    scheme: str = "none"
    host: str = ""
    port: int = 0
    username: str = ""
    # The password itself never lives here. It goes to the OS keyring under
    # the account name in `secret_name`, exactly like session passwords.
    save_password: bool = False
    # Send the hostname to the proxy rather than resolving it locally. This
    # is the point of a proxy for most people: names that only mean something
    # on the far side still resolve.
    remote_dns: bool = True
    # Only consulted for the https scheme, where TLS is to the proxy itself.
    tls_verify: bool = True
    # Hosts reached directly. "<local>" covers loopback and bare hostnames.
    exclude: list[str] = field(default_factory=lambda: ["<local>"])

    # ------------------------------------------------------------------
    @property
    def enabled(self) -> bool:
        return self.scheme in PROXY_SCHEMES and self.scheme != "none" and bool(self.host)

    @property
    def effective_port(self) -> int:
        return self.port or DEFAULT_PORTS.get(self.scheme, 0)

    def describe(self) -> str:
        """One line for the session list and the detail pane."""
        if not self.enabled:
            return "direct"
        auth = f"{self.username}@" if self.username else ""
        return f"{self.scheme}://{auth}{self.host}:{self.effective_port}"

    def to_url(self) -> str:
        """A URL that round-trips through :func:`parse_proxy_url`."""
        if not self.enabled:
            return ""
        scheme = "socks5h" if self.scheme == "socks5" and self.remote_dns else self.scheme
        auth = f"{self.username}@" if self.username else ""
        return f"{scheme}://{auth}{self.host}:{self.effective_port}"

    def validate(self) -> None:
        if self.scheme not in PROXY_SCHEMES:
            raise ValueError(f"Unknown proxy type {self.scheme!r}.")
        if self.scheme == "none":
            return
        if not self.host.strip():
            raise ValueError("A proxy needs a hostname or IP address.")
        if not (0 < self.effective_port < 65536):
            raise ValueError("Proxy port must be between 1 and 65535.")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: Any) -> "ProxyConfig":
        if isinstance(raw, ProxyConfig):
            return raw
        if isinstance(raw, str):
            # Tolerate a bare URL where a mapping was expected, since that is
            # what a human hand-editing the config file is likely to write.
            return parse_proxy_url(raw)
        if not isinstance(raw, dict):
            return cls()
        config = cls()
        for key, value in raw.items():
            if not hasattr(config, key):
                continue
            current = getattr(config, key)
            try:
                if isinstance(current, bool):
                    if isinstance(value, str):
                        value = value.strip().lower() in ("1", "true", "yes", "on")
                    else:
                        value = bool(value)
                elif isinstance(current, int):
                    value = int(value)
                elif isinstance(current, list):
                    value = [] if value is None else list(value)
                elif isinstance(current, str):
                    value = "" if value is None else str(value)
            except (TypeError, ValueError):
                continue
            setattr(config, key, value)
        config.scheme = SCHEME_ALIASES.get(config.scheme, config.scheme)
        return config


def parse_proxy_url(url: str) -> ProxyConfig:
    """Parse ``scheme://[user[:pass]@]host[:port]``.

    Returns the config only. Any password in the URL is deliberately dropped
    on the floor here — :func:`split_proxy_url` is the entry point that hands
    it back, so a password cannot reach a config object that gets written to
    disk by accident.
    """
    config, _ = split_proxy_url(url)
    return config


def split_proxy_url(url: str) -> tuple[ProxyConfig, str | None]:
    """Parse a proxy URL into a config and the password it carried, if any."""
    text = (url or "").strip()
    if not text:
        return ProxyConfig(), None
    if "://" not in text:
        # A bare host:port is almost always meant as HTTP, which is what
        # http_proxy variables have always implied.
        text = f"http://{text}"
    parts = urlsplit(text)
    scheme = SCHEME_ALIASES.get(parts.scheme.lower(), parts.scheme.lower())
    if scheme not in PROXY_SCHEMES:
        raise ValueError(
            f"Unknown proxy type {parts.scheme!r}. Use one of: "
            + ", ".join(s for s in PROXY_SCHEMES if s != "none")
        )
    if not parts.hostname:
        raise ValueError(f"No proxy host in {url!r}.")

    config = ProxyConfig(
        scheme=scheme,
        host=parts.hostname,
        port=parts.port or DEFAULT_PORTS.get(scheme, 0),
        username=unquote(parts.username or ""),
        # Plain "socks5://" means resolve locally, "socks5h://" means resolve
        # at the proxy. Every other scheme resolves at the proxy by nature.
        remote_dns=parts.scheme.lower() != "socks5",
    )
    password = unquote(parts.password) if parts.password else None
    return config, password


def from_environment(environ: dict[str, str] | None = None) -> tuple[ProxyConfig, str | None]:
    """Read ALL_PROXY / HTTPS_PROXY / HTTP_PROXY, in that order.

    Honouring these means pytty works out of the box on a machine that is
    already set up for a proxy, which is most machines that need one.
    """
    import os

    env = environ if environ is not None else dict(os.environ)
    for name in ("ALL_PROXY", "all_proxy", "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
        value = env.get(name, "").strip()
        if not value:
            continue
        try:
            config, password = split_proxy_url(value)
        except ValueError:
            continue
        no_proxy = env.get("NO_PROXY") or env.get("no_proxy") or ""
        extra = [item.strip() for item in no_proxy.split(",") if item.strip()]
        if extra:
            config.exclude = ["<local>", *extra]
        return config, password
    return ProxyConfig(), None


# ----------------------------------------------------------------------
# Exclusions
# ----------------------------------------------------------------------
def should_bypass(config: ProxyConfig, host: str) -> bool:
    """True when `host` is on the exclusion list and should be dialled direct."""
    target = (host or "").strip().lower().strip("[]")
    if not target:
        return False
    for raw in config.exclude:
        pattern = raw.strip().lower()
        if not pattern:
            continue
        if pattern == "<local>":
            if target in ("localhost", "127.0.0.1", "::1") or "." not in target:
                return True
            try:
                if ipaddress.ip_address(target).is_loopback:
                    return True
            except ValueError:
                pass
            continue
        if "/" in pattern:
            try:
                if ipaddress.ip_address(target) in ipaddress.ip_network(pattern, strict=False):
                    return True
            except ValueError:
                pass
            continue
        # A leading dot is the curl/NO_PROXY spelling for "and subdomains".
        if pattern.startswith(".") and target.endswith(pattern):
            return True
        if fnmatch.fnmatch(target, pattern):
            return True
    return False


# ----------------------------------------------------------------------
# Dialling out
# ----------------------------------------------------------------------
def open_socket(
    config: ProxyConfig,
    host: str,
    port: int,
    timeout: float = 15.0,
    password: str | None = None,
    log: Logger | None = None,
    bind_address: str = "",
    family: int = socket.AF_UNSPEC,
) -> socket.socket:
    """Return a socket already connected *through* the proxy to host:port.

    The socket comes back in blocking mode with no timeout, because that is
    what paramiko expects to be handed. Handshake timeouts apply only to the
    handshake.
    """
    note: Logger = log or (lambda level, message: None)

    proxy_host = config.host
    proxy_port = config.effective_port
    note("info", f"Connecting to {host}:{port} through {config.describe()}")

    sock = _connect(proxy_host, proxy_port, timeout, bind_address, family)
    try:
        sock.settimeout(timeout)
        if config.scheme == "https":
            sock = _wrap_tls(sock, config)
        if config.scheme in ("http", "https"):
            _http_connect(sock, config, host, port, password)
        elif config.scheme == "socks5":
            _socks5_connect(sock, config, host, port, password)
        elif config.scheme == "socks4":
            _socks4_connect(sock, config, host, port)
        else:
            raise ProxyError(f"Cannot proxy through scheme {config.scheme!r}")
    except BaseException:
        try:
            sock.close()
        except OSError:
            pass
        raise
    sock.settimeout(None)
    note("info", f"Proxy opened a tunnel to {host}:{port}")
    return sock


def _connect(
    host: str, port: int, timeout: float, bind_address: str, family: int
) -> socket.socket:
    """socket.create_connection, but honouring an address family and -b."""
    source = (bind_address, 0) if bind_address else None
    if family == socket.AF_UNSPEC:
        try:
            return socket.create_connection((host, port), timeout=timeout, source_address=source)
        except OSError as exc:
            raise ProxyError(f"Cannot reach proxy {host}:{port}: {_reason(exc)}") from exc

    last: OSError | None = None
    try:
        candidates = socket.getaddrinfo(host, port, family, socket.SOCK_STREAM)
    except OSError as exc:
        raise ProxyError(f"Cannot resolve proxy {host}: {_reason(exc)}") from exc
    for af, socktype, proto, _canon, address in candidates:
        sock = socket.socket(af, socktype, proto)
        try:
            sock.settimeout(timeout)
            if source:
                sock.bind(source)
            sock.connect(address)
            return sock
        except OSError as exc:
            last = exc
            sock.close()
    raise ProxyError(
        f"Cannot reach proxy {host}:{port}: {_reason(last) if last else 'no address'}"
    )


def _wrap_tls(sock: socket.socket, config: ProxyConfig) -> socket.socket:
    """TLS to the proxy itself, which is what an https:// proxy means.

    Note this is not the same as proxying an HTTPS connection: an ordinary
    http:// proxy does that too. Here the hop to the proxy is encrypted, so
    the CONNECT line and any Basic credentials are not on the wire in clear.
    """
    context = ssl.create_default_context()
    if not config.tls_verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    try:
        return context.wrap_socket(sock, server_hostname=config.host)
    except ssl.SSLError as exc:
        raise ProxyError(f"TLS to proxy {config.host} failed: {exc}") from exc


# -- HTTP ---------------------------------------------------------------
def _http_connect(
    sock: socket.socket, config: ProxyConfig, host: str, port: int, password: str | None
) -> None:
    target = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    lines = [
        f"CONNECT {target} HTTP/1.1",
        f"Host: {target}",
        "Proxy-Connection: Keep-Alive",
        "User-Agent: pytty",
    ]
    if config.username:
        token = base64.b64encode(f"{config.username}:{password or ''}".encode()).decode()
        lines.append(f"Proxy-Authorization: Basic {token}")
    request = ("\r\n".join(lines) + "\r\n\r\n").encode()
    try:
        sock.sendall(request)
    except OSError as exc:
        raise ProxyError(f"Proxy closed during CONNECT: {_reason(exc)}") from exc

    header = _read_headers(sock)
    status_line = header.split("\r\n", 1)[0]
    parts = status_line.split(None, 2)
    if len(parts) < 2 or not parts[0].upper().startswith("HTTP/"):
        raise ProxyError(f"Proxy sent something that is not HTTP: {status_line[:80]!r}")
    try:
        code = int(parts[1])
    except ValueError as exc:
        raise ProxyError(f"Proxy sent a bad status line: {status_line[:80]!r}") from exc
    if code == 200:
        return

    detail = parts[2].strip() if len(parts) > 2 else ""
    if code in (407, 401):
        raise ProxyAuthError(
            f"Proxy requires authentication ({code} {detail})."
            + ("" if config.username else " No proxy username is set.")
        )
    if code == 403 and port != 443:
        # By far the most common cause: the proxy's CONNECT allow-list only
        # has 443 on it. Saying so saves a long debugging session.
        raise ProxyError(
            f"Proxy refused CONNECT to port {port} ({code} {detail}). Many proxies "
            "only allow CONNECT to 443 — running sshd on 443 is the usual answer."
        )
    raise ProxyError(f"Proxy refused CONNECT: {code} {detail}".strip())


def _read_headers(sock: socket.socket, limit: int = 16384) -> str:
    """Read up to the blank line that ends the response head, and no further.

    One byte at a time, deliberately. A proxy is free to put the end of the
    head and the first bytes of the tunnelled stream in the same segment, and
    a buffered read would swallow them — the socket is handed straight to
    paramiko afterwards, so there is nowhere to put bytes back. The head is a
    few hundred bytes against an SSH handshake, so the cost is nothing.
    """
    buffer = bytearray()
    while not buffer.endswith(b"\r\n\r\n"):
        try:
            chunk = sock.recv(1)
        except socket.timeout as exc:
            raise ProxyError("Proxy did not answer the CONNECT request in time") from exc
        except OSError as exc:
            raise ProxyError(f"Proxy connection failed: {_reason(exc)}") from exc
        if not chunk:
            raise ProxyError("Proxy closed the connection without answering")
        buffer += chunk
        if len(buffer) > limit:
            raise ProxyError("Proxy sent an over-long response head")
    return buffer[:-4].decode("latin-1")


# -- SOCKS5 -------------------------------------------------------------
SOCKS5_ERRORS = {
    0x01: "general failure",
    0x02: "connection not allowed by ruleset",
    0x03: "network unreachable",
    0x04: "host unreachable",
    0x05: "connection refused",
    0x06: "TTL expired",
    0x07: "command not supported",
    0x08: "address type not supported",
}


def _socks5_connect(
    sock: socket.socket, config: ProxyConfig, host: str, port: int, password: str | None
) -> None:
    methods = bytearray([0x00])
    if config.username:
        methods.append(0x02)
    _send(sock, bytes([0x05, len(methods)]) + bytes(methods))

    reply = _recv_exact(sock, 2)
    if reply[0] != 0x05:
        raise ProxyError(f"Proxy answered SOCKS version {reply[0]}, not 5")
    chosen = reply[1]
    if chosen == 0xFF:
        raise ProxyAuthError(
            "Proxy rejected every authentication method we offered."
            + ("" if config.username else " It probably wants a username and password.")
        )
    if chosen == 0x02:
        _socks5_userpass(sock, config.username, password or "")
    elif chosen != 0x00:
        raise ProxyError(f"Proxy chose SOCKS5 method {chosen}, which pytty does not implement")

    # VER CMD RSV ATYP ADDR PORT — the port is two bytes, big endian, and
    # omitting it leaves the proxy reading the address as short by two.
    _send(
        sock,
        b"\x05\x01\x00"
        + _socks5_address(host, config.remote_dns)
        + port.to_bytes(2, "big"),
    )

    head = _recv_exact(sock, 4)
    if head[0] != 0x05:
        raise ProxyError("Malformed SOCKS5 reply")
    if head[1] != 0x00:
        reason = SOCKS5_ERRORS.get(head[1], f"code {head[1]}")
        raise ProxyError(f"Proxy could not reach {host}:{port}: {reason}")
    # Drain the bound address, which we do not need but must consume.
    kind = head[3]
    if kind == 0x01:
        _recv_exact(sock, 4)
    elif kind == 0x03:
        _recv_exact(sock, _recv_exact(sock, 1)[0])
    elif kind == 0x04:
        _recv_exact(sock, 16)
    else:
        raise ProxyError(f"Proxy replied with unknown address type {kind}")
    _recv_exact(sock, 2)


def _socks5_address(host: str, remote_dns: bool) -> bytes:
    """Encode the destination, preferring a hostname when remote DNS is on."""
    literal = host.strip("[]")
    if not remote_dns:
        try:
            address = ipaddress.ip_address(literal)
        except ValueError:
            # Resolve here, because the caller asked for local resolution.
            try:
                info = socket.getaddrinfo(literal, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            except OSError as exc:
                raise ProxyError(f"Cannot resolve {host} locally: {_reason(exc)}") from exc
            address = ipaddress.ip_address(info[0][4][0])
        return _packed(address)
    try:
        return _packed(ipaddress.ip_address(literal))
    except ValueError:
        pass
    encoded = literal.encode("idna") if _needs_idna(literal) else literal.encode("ascii", "ignore")
    if not encoded or len(encoded) > 255:
        raise ProxyError(f"Cannot send {host!r} to the proxy as a hostname")
    return bytes([0x03, len(encoded)]) + encoded


def _needs_idna(host: str) -> bool:
    return any(ord(ch) > 127 for ch in host)


def _packed(address: ipaddress._BaseAddress) -> bytes:
    if address.version == 4:
        return b"\x01" + address.packed
    return b"\x04" + address.packed


def _socks5_userpass(sock: socket.socket, username: str, password: str) -> None:
    """RFC 1929 username/password sub-negotiation."""
    user = username.encode("utf-8")
    secret = password.encode("utf-8")
    if len(user) > 255 or len(secret) > 255:
        raise ProxyAuthError("SOCKS5 username and password must be 255 bytes or fewer")
    _send(sock, bytes([0x01, len(user)]) + user + bytes([len(secret)]) + secret)
    reply = _recv_exact(sock, 2)
    if reply[1] != 0x00:
        raise ProxyAuthError("Proxy rejected the username and password")


# -- SOCKS4 -------------------------------------------------------------
def _socks4_connect(sock: socket.socket, config: ProxyConfig, host: str, port: int) -> None:
    literal = host.strip("[]")
    user = config.username.encode("utf-8", "ignore")
    try:
        address = ipaddress.ip_address(literal)
        if address.version == 6:
            raise ProxyError("SOCKS4 cannot carry IPv6 addresses — use SOCKS5")
        packed = address.packed
        trailer = b""
    except ValueError:
        if not config.remote_dns:
            try:
                packed = socket.inet_aton(socket.gethostbyname(literal))
            except OSError as exc:
                raise ProxyError(f"Cannot resolve {host} locally: {_reason(exc)}") from exc
            trailer = b""
        else:
            # SOCKS4a: an address of 0.0.0.x means "the hostname follows".
            packed = b"\x00\x00\x00\x01"
            trailer = literal.encode("ascii", "ignore") + b"\x00"

    _send(sock, b"\x04\x01" + port.to_bytes(2, "big") + packed + user + b"\x00" + trailer)
    reply = _recv_exact(sock, 8)
    if reply[1] != 0x5A:
        meaning = {
            0x5B: "request rejected or failed",
            0x5C: "proxy could not reach identd",
            0x5D: "identd said the user IDs differ",
        }.get(reply[1], f"code {reply[1]}")
        raise ProxyError(f"Proxy could not reach {host}:{port}: {meaning}")


# -- shared -------------------------------------------------------------
def _send(sock: socket.socket, data: bytes) -> None:
    try:
        sock.sendall(data)
    except socket.timeout as exc:
        raise ProxyError("Timed out talking to the proxy") from exc
    except OSError as exc:
        raise ProxyError(f"Proxy connection failed: {_reason(exc)}") from exc


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    chunks: list[bytes] = []
    remaining = count
    while remaining:
        try:
            chunk = sock.recv(remaining)
        except socket.timeout as exc:
            raise ProxyError("Proxy stopped answering mid-handshake") from exc
        except OSError as exc:
            raise ProxyError(f"Proxy connection failed: {_reason(exc)}") from exc
        if not chunk:
            raise ProxyError("Proxy closed the connection mid-handshake")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _reason(exc: BaseException | None) -> str:
    if exc is None:
        return "unknown error"
    if isinstance(exc, socket.timeout):
        return "timed out"
    if isinstance(exc, ConnectionRefusedError):
        return "connection refused"
    if isinstance(exc, socket.gaierror):
        return "hostname could not be resolved"
    text = str(exc).strip()
    return text or exc.__class__.__name__


def probe(
    config: ProxyConfig,
    host: str,
    port: int,
    timeout: float = 10.0,
    password: str | None = None,
) -> str:
    """Open and immediately close a tunnel, to check the proxy works.

    Returns a human-readable line for the interface. Raises ProxyError with a
    specific message when it does not, which is the whole point: a "Test"
    button that only says "failed" is not worth having.
    """
    import time

    started = time.monotonic()
    sock = open_socket(config, host, port, timeout=timeout, password=password)
    elapsed = (time.monotonic() - started) * 1000
    try:
        sock.close()
    except OSError:
        pass
    return f"Proxy opened a tunnel to {host}:{port} in {elapsed:.0f} ms"
