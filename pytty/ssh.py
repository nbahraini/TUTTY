"""SSH plumbing: authentication, host keys, tunnels and liveness probing."""

from __future__ import annotations

import base64
import hashlib
import os
import select
import shutil
import socket
import socketserver
import subprocess
import threading
from pathlib import Path
from typing import Callable, Protocol

import paramiko

from .model import Session, has_explicit_bind, parse_dynamic, parse_forward, parse_target
from .proxy import ProxyConfig
from .proxy import open_socket as open_proxied_socket
from .proxy import should_bypass
from .store import known_hosts_path, load_password, store_password

Logger = Callable[[str, str], None]  # (level, message)


class AuthCancelled(Exception):
    """The user declined to supply a credential."""


class HostKeyRejected(Exception):
    """The user refused an unrecognised host key."""


class Prompter(Protocol):
    """Everything the connector may need to ask a human."""

    def ask_password(self, prompt: str) -> str | None: ...
    def ask_passphrase(self, key_path: str) -> str | None: ...
    def confirm_host_key(self, host: str, key_type: str, fingerprint: str, changed: bool) -> bool: ...
    def ask_save_password(self) -> bool: ...


def fingerprint(key: paramiko.PKey) -> str:
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


class _AskPolicy(paramiko.MissingHostKeyPolicy):
    def __init__(self, prompter: Prompter, log: Logger) -> None:
        self.prompter = prompter
        self.log = log

    def missing_host_key(self, client, hostname, key):  # noqa: ANN001
        if not self.prompter.confirm_host_key(
            hostname, key.get_name(), fingerprint(key), changed=False
        ):
            raise HostKeyRejected(f"Host key for {hostname} was not accepted.")
        client.get_host_keys().add(hostname, key.get_name(), key)
        path = known_hosts_path()
        try:
            client.get_host_keys().save(str(path))
            self.log("info", f"Added host key for {hostname} to {path}")
        except OSError as exc:
            self.log("warn", f"Could not write {path}: {exc}")


class _AutoPolicy(paramiko.MissingHostKeyPolicy):
    def __init__(self, log: Logger) -> None:
        self.log = log

    def missing_host_key(self, client, hostname, key):  # noqa: ANN001
        client.get_host_keys().add(hostname, key.get_name(), key)
        self.log("warn", f"Accepted unverified host key for {hostname} ({fingerprint(key)})")
        try:
            client.get_host_keys().save(str(known_hosts_path()))
        except OSError:
            pass


# ----------------------------------------------------------------------
# Keepalive
# ----------------------------------------------------------------------
class KeepAlive(threading.Thread):
    """Probes the peer and closes the transport once it stops answering.

    paramiko's own ``set_keepalive`` only sends probes; nothing gives up when
    the replies stop. This thread sends ``keepalive@openssh.com`` global
    requests and counts unanswered ones, which is what OpenSSH's
    ServerAliveInterval / ServerAliveCountMax pair actually does.
    """

    def __init__(
        self,
        transport: paramiko.Transport,
        interval: int,
        count_max: int,
        log: Logger,
        channel: paramiko.Channel | None = None,
        null_packets: bool = False,
    ) -> None:
        super().__init__(name="pytty-keepalive", daemon=True)
        self.transport = transport
        self.interval = max(1, int(interval))
        self.count_max = max(1, int(count_max))
        self.log = log
        self.channel = channel
        self.null_packets = null_packets
        self.missed = 0
        self.declared_dead = threading.Event()
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()

    def _probe(self) -> bool:
        """Send one global request and wait up to one interval for a reply."""
        answered = threading.Event()

        def run() -> None:
            try:
                # Any reply proves liveness, including an explicit refusal.
                self.transport.global_request("keepalive@openssh.com", wait=True)
            except Exception:
                pass
            finally:
                answered.set()

        threading.Thread(target=run, daemon=True, name="pytty-probe").start()
        return answered.wait(self.interval)

    def run(self) -> None:
        # After a missed probe the interval of silence has already elapsed, so
        # the next probe goes out immediately. That keeps the worst case at
        # interval × (count_max + 1), which is what the UI promises.
        pause = self.interval
        while True:
            if self._stop.wait(pause):
                return
            if not self.transport.is_active():
                return
            if self.null_packets and self.channel is not None:
                try:
                    self.channel.send(b"\x00")
                except Exception:
                    pass
            if self._probe():
                if self.missed:
                    self.log("info", f"Peer answered again after {self.missed} missed probe(s)")
                self.missed = 0
                pause = self.interval
                continue
            pause = 0.0
            self.missed += 1
            self.log(
                "warn",
                f"No keepalive reply ({self.missed}/{self.count_max})",
            )
            if self.missed >= self.count_max:
                self.declared_dead.set()
                self.log("error", "Peer stopped answering — dropping the link")
                try:
                    self.transport.close()
                except Exception:
                    pass
                return


def apply_tcp_keepalive(sock: socket.socket, idle: int, interval: int, count: int) -> None:
    """Ask the OS to notice a half-open TCP connection."""
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except OSError:
        return
    for name, value in (
        ("TCP_KEEPIDLE", max(1, idle)),
        ("TCP_KEEPINTVL", max(1, interval)),
        ("TCP_KEEPCNT", max(1, count)),
    ):
        option = getattr(socket, name, None)
        if option is not None:
            try:
                sock.setsockopt(socket.IPPROTO_TCP, option, value)
            except OSError:
                pass


# ----------------------------------------------------------------------
# X11
# ----------------------------------------------------------------------
def parse_display(display: str) -> tuple[str, int, int]:
    """Split a DISPLAY value into (host, display number, screen number).

    ``:0``, ``:0.1``, ``unix:0`` and ``box.example:12`` are all valid, and an
    empty host means the local Unix socket.
    """
    text = (display or "").strip()
    if not text:
        raise ValueError("DISPLAY is not set")
    host, _, tail = text.rpartition(":")
    if not tail:
        raise ValueError(f"Cannot parse DISPLAY {display!r}")
    if host in ("unix", "localhost", "127.0.0.1"):
        host = ""
    number, _, screen = tail.partition(".")
    try:
        return host, int(number), int(screen or 0)
    except ValueError as exc:
        raise ValueError(f"Cannot parse DISPLAY {display!r}") from exc


def local_x11_cookie(display: str) -> tuple[str, str] | None:
    """Ask xauth for the local display's cookie.

    Returns (protocol, hex cookie), or None when xauth is missing or has
    nothing for this display — which is normal on a machine with no X server.
    """
    xauth = shutil.which("xauth")
    if not xauth:
        return None
    try:
        result = subprocess.run(
            [xauth, "list", display],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            return parts[-2], parts[-1]
    return None


def connect_to_display(display: str, timeout: float = 5.0) -> socket.socket:
    """Open a socket to the local X server."""
    host, number, _screen = parse_display(display)
    if not host:
        path = f"/tmp/.X11-unix/X{number}"
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect(path)
        return sock
    return socket.create_connection((host, 6000 + number), timeout=timeout)


class X11Forwarder:
    """Relays forwarded X11 channels to the local display.

    The local cookie is handed to the server as-is, which is what OpenSSH
    calls *trusted* forwarding (``-Y``). Untrusted forwarding needs a second,
    restricted cookie minted by xauth and swapped into each connection;
    pytty does not do that, so anything you forward to has full access to
    your display. The interface says so next to the switch.
    """

    def __init__(self, display: str, log: Logger) -> None:
        self.display = display
        self.log = log
        self.protocol = "MIT-MAGIC-COOKIE-1"
        self.cookie: str | None = None
        found = local_x11_cookie(display)
        if found:
            self.protocol, self.cookie = found

    def request(self, channel: paramiko.Channel) -> None:
        """Ask the server to forward X11 over this channel."""
        cookie = bytes.fromhex(self.cookie) if self.cookie else None
        channel.request_x11(
            auth_protocol=self.protocol,
            auth_cookie=cookie,
            handler=self._handle,
        )
        if self.cookie:
            self.log("info", f"X11 forwarding to {self.display}")
        else:
            self.log(
                "warn",
                f"X11 forwarding to {self.display} without an xauth cookie — "
                "the display will probably refuse the connection",
            )

    def _handle(self, channel: paramiko.Channel, origin) -> None:  # noqa: ANN001
        try:
            sock = connect_to_display(self.display)
        except (OSError, ValueError) as exc:
            self.log("warn", f"X11 client refused: {exc}")
            try:
                channel.close()
            except Exception:
                pass
            return
        thread = threading.Thread(
            target=self._pump, args=(sock, channel), daemon=True, name="pytty-x11"
        )
        thread.start()

    def _pump(self, sock: socket.socket, channel: paramiko.Channel) -> None:
        try:
            sock.settimeout(None)
            _pump(sock, channel)
        except OSError:
            pass
        finally:
            try:
                channel.close()
            finally:
                sock.close()


# ----------------------------------------------------------------------
# Port forwarding
# ----------------------------------------------------------------------
class _ForwardHandler(socketserver.BaseRequestHandler):
    dest_host = "127.0.0.1"
    dest_port = 0
    transport: paramiko.Transport | None = None
    log: Logger = lambda level, message: None  # type: ignore[assignment]

    def handle(self) -> None:
        assert self.transport is not None
        try:
            channel = self.transport.open_channel(
                "direct-tcpip",
                (self.dest_host, self.dest_port),
                self.request.getpeername(),
            )
        except Exception as exc:
            self.log("warn", f"Tunnel to {self.dest_host}:{self.dest_port} refused: {exc}")
            return
        if channel is None:
            return
        try:
            _pump(self.request, channel)
        finally:
            channel.close()
            self.request.close()


class SocksError(Exception):
    """A SOCKS request could not be honoured.

    ``code`` is the reply byte to send back before hanging up, so the client
    sees a real refusal instead of a silent close.
    """

    def __init__(self, message: str, code: int = 0x01) -> None:
        super().__init__(message)
        self.code = code


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    """Read exactly ``count`` bytes or raise. recv() may return short."""
    chunks: list[bytes] = []
    remaining = count
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise SocksError("Client closed the connection mid-handshake")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


class _SocksHandler(socketserver.BaseRequestHandler):
    """A SOCKS4/4a/5 CONNECT proxy that dials out over the SSH transport.

    This is the ``-D`` equivalent: rather than one fixed destination per
    listener, the client names host and port per connection and each one
    becomes its own ``direct-tcpip`` channel.
    """

    transport: paramiko.Transport | None = None
    log: Logger = staticmethod(lambda level, message: None)
    handshake_timeout: float = 10.0

    def handle(self) -> None:
        assert self.transport is not None
        sock: socket.socket = self.request
        version = 0
        try:
            sock.settimeout(self.handshake_timeout)
            version = _recv_exact(sock, 1)[0]
            if version == 5:
                host, port = self._socks5_request(sock)
            elif version == 4:
                host, port = self._socks4_request(sock)
            else:
                raise SocksError(f"Unsupported SOCKS version {version}")
            channel = self._open(host, port)
            self._reply(sock, version, 0x00, channel)
        except SocksError as exc:
            self.log("warn", f"SOCKS: {exc}")
            self._reply_failure(sock, version, exc.code)
            return
        except (OSError, IndexError) as exc:
            self.log("warn", f"SOCKS: {exc}")
            return

        try:
            sock.settimeout(None)
            _pump(sock, channel)
        except OSError:
            pass  # either side hanging up is the normal way this ends
        finally:
            channel.close()
            sock.close()

    # -- protocol -------------------------------------------------------
    def _socks5_request(self, sock: socket.socket) -> tuple[str, int]:
        count = _recv_exact(sock, 1)[0]
        methods = _recv_exact(sock, count) if count else b""
        if 0x00 not in methods:
            # No shared method. Say so properly, then close.
            sock.sendall(b"\x05\xff")
            raise SocksError("Client offered no authentication method we accept")
        sock.sendall(b"\x05\x00")

        header = _recv_exact(sock, 4)
        if header[0] != 0x05:
            raise SocksError("Bad SOCKS5 request header")
        command = header[1]
        if command != 0x01:
            # BIND and UDP ASSOCIATE are out of scope, same as OpenSSH.
            raise SocksError(f"SOCKS5 command {command} is not supported", code=0x07)

        kind = header[3]
        if kind == 0x01:
            host = socket.inet_ntoa(_recv_exact(sock, 4))
        elif kind == 0x03:
            length = _recv_exact(sock, 1)[0]
            # Already punycode on the wire, so this is plain ASCII in practice.
            host = _recv_exact(sock, length).decode("utf-8", errors="replace")
        elif kind == 0x04:
            host = socket.inet_ntop(socket.AF_INET6, _recv_exact(sock, 16))
        else:
            raise SocksError(f"Unknown address type {kind}", code=0x08)
        port = int.from_bytes(_recv_exact(sock, 2), "big")
        return host, port

    def _socks4_request(self, sock: socket.socket) -> tuple[str, int]:
        command = _recv_exact(sock, 1)[0]
        if command != 0x01:
            raise SocksError(f"SOCKS4 command {command} is not supported", code=0x5B)
        port = int.from_bytes(_recv_exact(sock, 2), "big")
        raw_ip = _recv_exact(sock, 4)
        self._read_until_nul(sock)  # user id, which we do not check
        if raw_ip[:3] == b"\x00\x00\x00" and raw_ip[3] != 0:
            # 0.0.0.x means SOCKS4a: the hostname follows the user id.
            host = self._read_until_nul(sock).decode("utf-8", errors="replace")
        else:
            host = socket.inet_ntoa(raw_ip)
        return host, port

    @staticmethod
    def _read_until_nul(sock: socket.socket, limit: int = 512) -> bytes:
        out = bytearray()
        while len(out) <= limit:
            byte = sock.recv(1)
            if not byte:
                raise SocksError("Client closed the connection mid-handshake")
            if byte == b"\x00":
                return bytes(out)
            out += byte
        raise SocksError("Over-long SOCKS4 field")

    # -- tunnelling -----------------------------------------------------
    def _open(self, host: str, port: int) -> paramiko.Channel:
        assert self.transport is not None
        try:
            origin = self.request.getpeername()[:2]
        except OSError:
            origin = ("127.0.0.1", 0)
        try:
            channel = self.transport.open_channel("direct-tcpip", (host, port), origin)
        except Exception as exc:
            raise SocksError(f"Tunnel to {host}:{port} refused: {exc}", code=0x05) from exc
        if channel is None:
            raise SocksError(f"Tunnel to {host}:{port} was not opened", code=0x05)
        self.log("info", f"SOCKS → {host}:{port}")
        return channel

    # -- replies --------------------------------------------------------
    def _reply(
        self, sock: socket.socket, version: int, code: int, channel: paramiko.Channel | None
    ) -> None:
        if version == 4:
            # SOCKS4 has no failure taxonomy: 0x5A granted, 0x5B rejected.
            status = 0x5A if code == 0x00 else 0x5B
            sock.sendall(b"\x00" + bytes([status]) + b"\x00\x00\x00\x00\x00\x00")
            return
        # The bound address is informational and clients ignore it, so send
        # the unspecified IPv4 address rather than inventing one.
        sock.sendall(b"\x05" + bytes([code]) + b"\x00\x01\x00\x00\x00\x00\x00\x00")

    def _reply_failure(self, sock: socket.socket, version: int, code: int) -> None:
        try:
            if version in (4, 5):
                self._reply(sock, version, code, None)
        except OSError:
            pass
        finally:
            try:
                sock.close()
            except OSError:
                pass


def _pump(sock: socket.socket, channel: paramiko.Channel) -> None:
    while True:
        readable, _, _ = select.select([sock, channel], [], [], 1.0)
        if sock in readable:
            data = sock.recv(32768)
            if not data:
                break
            channel.sendall(data)
        if channel in readable:
            data = channel.recv(32768)
            if not data:
                break
            sock.sendall(data)


class _ThreadedForwardServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True
    # staticmethod, so an unset default is not handed an implicit self.
    log: Logger = staticmethod(lambda level, message: None)

    def handle_error(self, request, client_address) -> None:  # noqa: ANN001
        # The default prints a traceback to stderr. The session owns the
        # terminal in raw mode, so that would land in the middle of the
        # user's shell. A tunnel dying is normal; log it and move on.
        import sys

        exc = sys.exc_info()[1]
        self.log("warn", f"Tunnel closed: {exc.__class__.__name__}: {exc}")


class ForwardManager:
    """Owns every tunnel opened for one connection attempt."""

    def __init__(self, log: Logger) -> None:
        self.log = log
        self._servers: list[_ThreadedForwardServer] = []
        self._transport: paramiko.Transport | None = None
        self._remote_ports: list[tuple[str, int]] = []
        self._gateway = False

    def start(self, session: Session, transport: paramiko.Transport) -> None:
        self._transport = transport
        self._gateway = session.gateway_ports
        for spec in session.local_forwards:
            self._start_local(spec, transport)
        for spec in session.remote_forwards:
            self._start_remote(spec, transport)
        for spec in session.dynamic_forwards:
            self._start_dynamic(spec, transport)

    def _bind_for(self, spec: str, bind: str) -> str:
        """Widen a loopback bind to every interface when gateway ports are on.

        An explicit bind address in the spec always wins, so
        ``-L 127.0.0.1:8080:…`` stays on loopback even with the switch on.
        """
        if not self._gateway or has_explicit_bind(spec):
            return bind
        return "0.0.0.0"

    def _start_local(self, spec: str, transport: paramiko.Transport) -> None:
        bind, port, dest_host, dest_port = parse_forward(spec)
        bind = self._bind_for(spec, bind)
        handler = type(
            "Handler",
            (_ForwardHandler,),
            {
                "dest_host": dest_host,
                "dest_port": dest_port,
                "transport": transport,
                "log": staticmethod(self.log),
            },
        )
        try:
            server = _ThreadedForwardServer((bind, port), handler)
        except OSError as exc:
            self.log("error", f"Local forward {spec} failed: {exc}")
            return
        server.log = self.log  # type: ignore[assignment]
        threading.Thread(target=server.serve_forever, daemon=True, name=f"fwd-{port}").start()
        self._servers.append(server)
        self.log("info", f"Listening on {bind}:{port} → {dest_host}:{dest_port}")

    def _start_dynamic(self, spec: str, transport: paramiko.Transport) -> None:
        bind, port = parse_dynamic(spec)
        bind = self._bind_for(spec, bind)
        handler = type(
            "SocksHandler",
            (_SocksHandler,),
            {"transport": transport, "log": staticmethod(self.log)},
        )
        try:
            server = _ThreadedForwardServer((bind, port), handler)
        except OSError as exc:
            self.log("error", f"Dynamic forward {spec} failed: {exc}")
            return
        server.log = self.log  # type: ignore[assignment]
        threading.Thread(target=server.serve_forever, daemon=True, name=f"socks-{port}").start()
        self._servers.append(server)
        self.log("info", f"SOCKS proxy on {bind}:{port}")
        if bind not in ("127.0.0.1", "::1", "localhost"):
            # The listener authenticates nobody, so this is worth saying out
            # loud every time rather than only in the documentation.
            self.log(
                "warn",
                f"SOCKS on {bind}:{port} is reachable from the network — anyone who "
                "can connect gets everything the remote host can reach",
            )

    def _start_remote(self, spec: str, transport: paramiko.Transport) -> None:
        bind, port, dest_host, dest_port = parse_forward(spec)

        def handler(channel: paramiko.Channel, origin, destination) -> None:  # noqa: ANN001
            try:
                sock = socket.create_connection((dest_host, dest_port), timeout=10)
            except OSError as exc:
                self.log("warn", f"Remote tunnel target unreachable: {exc}")
                channel.close()
                return
            try:
                _pump(sock, channel)
            finally:
                sock.close()
                channel.close()

        try:
            transport.request_port_forward(bind, port, handler)
        except Exception as exc:
            self.log("error", f"Remote forward {spec} failed: {exc}")
            return
        self._remote_ports.append((bind, port))
        self.log("info", f"Remote {bind}:{port} → {dest_host}:{dest_port}")

    def stop(self) -> None:
        for server in self._servers:
            try:
                server.shutdown()
                server.server_close()
            except Exception:
                pass
        self._servers.clear()
        if self._transport is not None and self._transport.is_active():
            for bind, port in self._remote_ports:
                try:
                    self._transport.cancel_port_forward(bind, port)
                except Exception:
                    pass
        self._remote_ports.clear()
        self._transport = None


# ----------------------------------------------------------------------
# Connector
# ----------------------------------------------------------------------
class Connector:
    """Turns a `Session` into a live `paramiko.SSHClient`."""

    def __init__(
        self,
        session: Session,
        prompter: Prompter,
        log: Logger,
        proxy: ProxyConfig | None = None,
        proxy_password: str | None = None,
    ) -> None:
        self.session = session
        self.prompter = prompter
        self.log = log
        self.proxy = proxy
        self.proxy_password = proxy_password
        self._cached_password: str | None = None
        self._cached_passphrase: str | None = None

    # -- outbound socket ------------------------------------------------
    @property
    def _family(self) -> int:
        return {
            "ipv4": socket.AF_INET,
            "ipv6": socket.AF_INET6,
        }.get(self.session.address_family, socket.AF_UNSPEC)

    def _dial(self, host: str, port: int) -> socket.socket | None:
        """The outgoing TCP connection for the first hop.

        Returns None when there is nothing special to do, which lets paramiko
        make its own socket exactly as before. Only the first hop is dialled
        here: everything after it travels inside the SSH connection this
        socket carries.
        """
        session = self.session
        proxy = self.proxy
        if proxy is not None and proxy.enabled:
            if should_bypass(proxy, host):
                self.log("info", f"{host} is on the proxy exclusion list — connecting directly")
            else:
                return open_proxied_socket(
                    proxy,
                    host,
                    port,
                    timeout=session.connect_timeout,
                    password=self.proxy_password,
                    log=self.log,
                    bind_address=session.bind_address,
                    family=self._family,
                )

        if not session.bind_address and self._family == socket.AF_UNSPEC:
            return None  # nothing to customise; let paramiko dial

        source = (session.bind_address, 0) if session.bind_address else None
        if self._family == socket.AF_UNSPEC:
            return socket.create_connection(
                (host, port), timeout=session.connect_timeout, source_address=source
            )
        last: OSError | None = None
        for af, socktype, proto, _canon, address in socket.getaddrinfo(
            host, port, self._family, socket.SOCK_STREAM
        ):
            sock = socket.socket(af, socktype, proto)
            try:
                sock.settimeout(session.connect_timeout)
                if source:
                    sock.bind(source)
                sock.connect(address)
                sock.settimeout(None)
                return sock
            except OSError as exc:
                last = exc
                sock.close()
        raise last or OSError(f"Cannot reach {host}:{port}")

    # -- host keys ------------------------------------------------------
    def _new_client(self) -> paramiko.SSHClient:
        client = paramiko.SSHClient()
        system_known_hosts = Path.home() / ".ssh" / "known_hosts"
        if system_known_hosts.exists():
            try:
                client.load_system_host_keys(str(system_known_hosts))
            except Exception as exc:
                self.log("warn", f"Ignoring unreadable {system_known_hosts}: {exc}")
        # Ours is loaded second and is the file new keys get written back to.
        try:
            client.load_host_keys(str(known_hosts_path()))
        except OSError:
            pass
        policy = self.session.host_key_policy
        if policy == "auto":
            client.set_missing_host_key_policy(_AutoPolicy(self.log))
        elif policy == "strict":
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
        else:
            client.set_missing_host_key_policy(_AskPolicy(self.prompter, self.log))
        return client

    # -- jump hosts -----------------------------------------------------
    def _jump_socket(self) -> tuple[paramiko.Channel | None, list[paramiko.SSHClient]]:
        chain = [hop.strip() for hop in self.session.jump_host.split(",") if hop.strip()]
        if not chain:
            return None, []
        clients: list[paramiko.SSHClient] = []
        sock: paramiko.Channel | None = None
        try:
            for index, hop in enumerate(chain):
                user, host, port = parse_target(hop, self.session.username)
                self.log("info", f"Hopping through {host}:{port}")
                client = self._new_client()
                # Only the first hop is dialled locally, so only it can go
                # through the proxy. The rest are already inside the tunnel.
                hop_sock = sock if index else self._dial(host, port)
                client.connect(
                    hostname=host,
                    port=port,
                    username=user or None,
                    sock=hop_sock,
                    timeout=self.session.connect_timeout,
                    allow_agent=True,
                    look_for_keys=True,
                )
                clients.append(client)
                transport = client.get_transport()
                assert transport is not None
                if index + 1 < len(chain):
                    _, next_host, next_port = parse_target(chain[index + 1], self.session.username)
                else:
                    next_host, next_port = self.session.host, self.session.port
                sock = transport.open_channel(
                    "direct-tcpip", (next_host, next_port), ("127.0.0.1", 0)
                )
        except Exception:
            for client in clients:
                client.close()
            raise
        return sock, clients

    # -- authentication -------------------------------------------------
    def connect(self) -> tuple[paramiko.SSHClient, list[paramiko.SSHClient]]:
        session = self.session
        sock, jump_clients = self._jump_socket()
        if sock is None:
            # No jump chain, so this is the first hop and the proxy applies.
            sock = self._dial(session.host, session.port)
        client = self._new_client()

        common: dict = dict(
            hostname=session.host,
            port=session.port,
            username=session.username or None,
            timeout=session.connect_timeout,
            banner_timeout=max(15.0, session.connect_timeout),
            auth_timeout=max(20.0, session.connect_timeout),
            compress=session.compression,
            sock=sock,
        )

        try:
            self._authenticate(client, common)
        except BaseException:
            client.close()
            for jump in jump_clients:
                jump.close()
            raise

        transport = client.get_transport()
        assert transport is not None
        transport.use_compression(session.compression)
        if transport.sock is not None:
            # PuTTY's "disable Nagle's algorithm", on by default: an
            # interactive session cares about latency, not packet efficiency.
            # paramiko leaves this alone, so both states are ours to set.
            try:
                transport.sock.setsockopt(
                    socket.IPPROTO_TCP, socket.TCP_NODELAY, 1 if session.tcp_nodelay else 0
                )
            except (OSError, AttributeError):
                pass
        if session.tcp_keepalive and transport.sock is not None:
            try:
                apply_tcp_keepalive(
                    transport.sock,
                    idle=max(10, session.keepalive_interval or 30),
                    interval=max(5, (session.keepalive_interval or 30) // 2),
                    count=session.keepalive_count_max,
                )
            except Exception:
                pass
        return client, jump_clients

    def _authenticate(self, client: paramiko.SSHClient, common: dict) -> None:
        session = self.session
        method = session.auth

        if method == "agent":
            client.connect(**common, allow_agent=True, look_for_keys=False)
            return

        if method == "key":
            key_path = str(Path(session.key_path).expanduser())
            try:
                client.connect(
                    **common,
                    key_filename=key_path,
                    passphrase=self._cached_passphrase,
                    allow_agent=False,
                    look_for_keys=False,
                )
                return
            except paramiko.PasswordRequiredException:
                pass
            except paramiko.SSHException as exc:
                if "encrypted" not in str(exc).lower():
                    raise
            passphrase = self.prompter.ask_passphrase(key_path)
            if passphrase is None:
                raise AuthCancelled("No passphrase supplied.")
            self._cached_passphrase = passphrase
            client.connect(
                **common,
                key_filename=key_path,
                passphrase=passphrase,
                allow_agent=False,
                look_for_keys=False,
            )
            return

        if method in ("password", "ask"):
            self._password_auth(client, common, allow_saved=(method == "password"))
            return

        # auto: keys and agent first, password only if those are refused.
        try:
            client.connect(**common, allow_agent=True, look_for_keys=True)
            return
        except paramiko.AuthenticationException:
            self.log("info", "Key and agent authentication refused, asking for a password")
        self._password_auth(client, common, allow_saved=True)

    def _password_auth(self, client: paramiko.SSHClient, common: dict, allow_saved: bool) -> None:
        session = self.session
        password = self._cached_password
        from_store = False
        if password is None and allow_saved and session.save_password:
            password = load_password(session.name)
            from_store = password is not None

        for attempt in range(3):
            if password is None:
                label = f"{session.username or 'user'}@{session.host}"
                password = self.prompter.ask_password(f"Password for {label}: ")
                from_store = False
            if password is None:
                raise AuthCancelled("No password supplied.")
            try:
                client.connect(
                    **common,
                    password=password,
                    allow_agent=False,
                    look_for_keys=False,
                )
            except paramiko.AuthenticationException:
                self.log("warn", f"Authentication failed (attempt {attempt + 1} of 3)")
                password = None
                continue
            self._cached_password = password
            if session.save_password and not from_store:
                if store_password(session.name, password):
                    self.log("info", "Password saved to the system keyring")
            return
        raise paramiko.AuthenticationException("Authentication failed three times.")


def open_shell(
    client: paramiko.SSHClient,
    session: Session,
    cols: int,
    rows: int,
    log: Logger | None = None,
) -> paramiko.Channel:
    """Open an interactive channel, honouring the session's remote command."""
    note: Logger = log or (lambda level, message: None)
    transport = client.get_transport()
    assert transport is not None
    channel = transport.open_session(timeout=session.connect_timeout)

    environment = session.environment_map()
    if environment:
        try:
            channel.update_environment(environment)
            note("info", f"Sent {len(environment)} environment variable(s)")
        except paramiko.SSHException as exc:
            # Servers only accept what AcceptEnv permits, and refusing is the
            # common case. Not worth failing the session over.
            note("warn", f"Server declined the environment variables: {exc}")

    channel.get_pty(term=session.term, width=cols, height=rows)

    if session.x11_forward:
        display = session.x11_display or os.environ.get("DISPLAY", "")
        if not display:
            note("warn", "X11 forwarding is on but DISPLAY is not set — skipping")
        else:
            try:
                X11Forwarder(display, note).request(channel)
            except Exception as exc:
                note("warn", f"X11 forwarding refused: {exc}")

    if session.forward_agent:
        try:
            paramiko.agent.AgentRequestHandler(channel)
        except Exception:
            pass
    if session.remote_command.strip():
        channel.exec_command(session.remote_command)
    else:
        channel.invoke_shell()
    channel.settimeout(0.0)
    return channel
