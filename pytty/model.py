"""Session data model."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field, fields
from typing import Any

from .proxy import ProxyConfig

AUTH_METHODS = ("auto", "agent", "key", "password", "ask")
HOST_KEY_POLICIES = ("ask", "strict", "auto")

# Where a session gets its proxy from. "global" is the default so that
# changing the app-wide proxy moves every session at once, which is the whole
# reason for having an app-wide proxy.
PROXY_MODES = ("global", "none", "custom")
ADDRESS_FAMILIES = ("auto", "ipv4", "ipv6")
# PuTTY's session logging, minus the SSH packet dumps, which belong in a
# protocol analyser rather than here.
LOG_MODES = ("off", "output", "all")

_ENV_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")

_FORWARD_RE = re.compile(
    # The bind alternatives both carry their trailing colon, so a bracketed
    # IPv6 bind parses the same way it already does for a dynamic forward.
    r"^(?P<bind>\[[^\]]+\]:|[^:]+:)?(?P<lport>\d+):(?P<dhost>\[[^\]]+\]|[^:]+):(?P<dport>\d+)$"
)

# A dynamic forward names no destination — the SOCKS client supplies that at
# runtime — so the spec is just an optional bind address and a port.
_DYNAMIC_RE = re.compile(r"^(?:(?P<bind>\[[^\]]+\]|[^:]+):)?(?P<lport>\d+)$")


class ValidationError(ValueError):
    """Raised when a session cannot be used as configured."""


@dataclass
class Session:
    """A saved connection profile.

    Everything PuTTY keeps in a saved session, plus the two behaviours this
    tool exists for: keepalive probing and automatic reconnection.
    """

    name: str = ""
    group: str = "Ungrouped"
    host: str = ""
    port: int = 22
    username: str = ""

    # --- authentication -------------------------------------------------
    auth: str = "auto"  # auto | agent | key | password | ask
    key_path: str = ""
    save_password: bool = False
    host_key_policy: str = "ask"  # ask | strict | auto

    # --- keepalive ------------------------------------------------------
    # Seconds between liveness probes. 0 turns probing off.
    keepalive_interval: int = 30
    # Missed probes tolerated before the link is declared dead.
    keepalive_count_max: int = 3
    # SO_KEEPALIVE on the underlying socket, so the OS notices half-open TCP.
    tcp_keepalive: bool = True
    # PuTTY's "null packets" trick: some middleboxes only count channel data.
    null_packets: bool = False

    # --- reconnect ------------------------------------------------------
    auto_reconnect: bool = True
    reconnect_delay: float = 2.0
    reconnect_max_delay: float = 60.0
    reconnect_attempts: int = 0  # 0 = keep trying forever
    # Reconnect even when the remote shell exited cleanly (useful for kiosks).
    reconnect_on_remote_exit: bool = False

    # --- session --------------------------------------------------------
    term: str = "xterm-256color"
    remote_command: str = ""
    # Sent to the shell after every successful login, including reconnects.
    login_commands: list[str] = field(default_factory=list)
    compression: bool = False
    forward_agent: bool = False
    connect_timeout: float = 15.0

    # --- tunnels --------------------------------------------------------
    jump_host: str = ""  # user@host[:port], chained with commas
    local_forwards: list[str] = field(default_factory=list)
    remote_forwards: list[str] = field(default_factory=list)
    # SOCKS listeners: "[bind:]port". The client picks the destination.
    dynamic_forwards: list[str] = field(default_factory=list)
    # Let other machines use the forwards we listen on. Off by default, the
    # same way OpenSSH's GatewayPorts is.
    gateway_ports: bool = False
    # Hold the tunnels open without a shell — plink's -N.
    no_shell: bool = False

    # --- proxy ----------------------------------------------------------
    # How this session reaches the SSH server: through the app-wide proxy,
    # directly, or through one of its own.
    proxy_mode: str = "global"  # global | none | custom
    proxy: ProxyConfig = field(default_factory=ProxyConfig)

    # --- X11 ------------------------------------------------------------
    x11_forward: bool = False
    x11_display: str = ""  # empty means $DISPLAY

    # --- advanced -------------------------------------------------------
    # Sent with the channel request. Most servers only accept what their
    # AcceptEnv allows, so a refusal here is normal and not fatal.
    environment: list[str] = field(default_factory=list)
    bind_address: str = ""  # source address for outgoing connections
    address_family: str = "auto"  # auto | ipv4 | ipv6
    # PuTTY calls this "disable Nagle's algorithm" and defaults it on, which
    # is right for an interactive session: latency beats packet efficiency.
    tcp_nodelay: bool = True

    # --- logging --------------------------------------------------------
    log_path: str = ""
    log_mode: str = "off"  # off | output | all

    # --- bookkeeping ----------------------------------------------------
    notes: str = ""
    last_used: float = 0.0

    # ------------------------------------------------------------------
    @property
    def target(self) -> str:
        user = f"{self.username}@" if self.username else ""
        port = f":{self.port}" if self.port != 22 else ""
        return f"{user}{self.host}{port}"

    @property
    def keepalive_summary(self) -> str:
        if not self.keepalive_interval:
            return "off"
        return f"{self.keepalive_interval}s ×{self.keepalive_count_max}"

    @property
    def reconnect_summary(self) -> str:
        if not self.auto_reconnect:
            return "off"
        limit = "unlimited" if not self.reconnect_attempts else f"{self.reconnect_attempts} tries"
        return f"{self.reconnect_delay:g}–{self.reconnect_max_delay:g}s, {limit}"

    @property
    def proxy_summary(self) -> str:
        if self.proxy_mode == "none":
            return "direct"
        if self.proxy_mode == "custom":
            return self.proxy.describe() if self.proxy.enabled else "custom, not configured"
        return "app default"

    @property
    def has_tunnels(self) -> bool:
        return bool(self.local_forwards or self.remote_forwards or self.dynamic_forwards)

    def dead_after(self) -> float:
        """Worst-case seconds before a silent link is declared dead."""
        if not self.keepalive_interval:
            return float("inf")
        return self.keepalive_interval * (self.keepalive_count_max + 1)

    def effective_proxy(self, app_proxy: ProxyConfig | None = None) -> ProxyConfig | None:
        """The proxy this session should dial through, if any.

        Returns None for a direct connection, so callers can test the result
        rather than having to know what an empty ProxyConfig means.
        """
        if self.proxy_mode == "none":
            return None
        if self.proxy_mode == "custom":
            return self.proxy if self.proxy.enabled else None
        if app_proxy is not None and app_proxy.enabled:
            return app_proxy
        return None

    def environment_map(self) -> dict[str, str]:
        """The KEY=VALUE lines as a mapping, last one winning."""
        out: dict[str, str] = {}
        for entry in self.environment:
            line = entry.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            out[key.strip()] = value
        return out

    # ------------------------------------------------------------------
    def validate(self) -> None:
        if not self.name.strip():
            raise ValidationError("Give the session a name.")
        if not self.host.strip():
            raise ValidationError("Enter a hostname or IP address.")
        if not (0 < self.port < 65536):
            raise ValidationError("Port must be between 1 and 65535.")
        if self.auth not in AUTH_METHODS:
            raise ValidationError(f"Unknown authentication method {self.auth!r}.")
        if self.auth == "key" and not self.key_path.strip():
            raise ValidationError("Key authentication needs a path to a private key.")
        if self.host_key_policy not in HOST_KEY_POLICIES:
            raise ValidationError(f"Unknown host key policy {self.host_key_policy!r}.")
        if self.keepalive_interval < 0:
            raise ValidationError("Keepalive interval cannot be negative.")
        if self.keepalive_count_max < 1:
            raise ValidationError("Allow at least one missed keepalive before dropping.")
        if self.reconnect_delay <= 0:
            raise ValidationError("Reconnect delay must be greater than zero.")
        if self.reconnect_max_delay < self.reconnect_delay:
            raise ValidationError("Maximum backoff must be at least the initial delay.")
        if self.reconnect_attempts < 0:
            raise ValidationError("Reconnect attempts cannot be negative.")
        for spec in self.local_forwards:
            if not _FORWARD_RE.match(spec.strip()):
                raise ValidationError(
                    f"Local forward {spec!r} should look like 8080:127.0.0.1:80"
                )
        for spec in self.remote_forwards:
            if not _FORWARD_RE.match(spec.strip()):
                raise ValidationError(
                    f"Remote forward {spec!r} should look like 9000:127.0.0.1:3000"
                )
        for spec in self.dynamic_forwards:
            match = _DYNAMIC_RE.match(spec.strip())
            if not match:
                raise ValidationError(
                    f"Dynamic forward {spec!r} should look like 1080 or 127.0.0.1:1080"
                )
            if not (0 < int(match.group("lport")) < 65536):
                raise ValidationError(
                    f"Dynamic forward {spec!r} must use a port between 1 and 65535."
                )
        if self.proxy_mode not in PROXY_MODES:
            raise ValidationError(f"Unknown proxy mode {self.proxy_mode!r}.")
        if self.proxy_mode == "custom":
            try:
                self.proxy.validate()
            except ValueError as exc:
                raise ValidationError(str(exc)) from exc
            if not self.proxy.enabled:
                raise ValidationError(
                    "This session is set to use its own proxy but no proxy is configured."
                )
        if self.address_family not in ADDRESS_FAMILIES:
            raise ValidationError(f"Unknown address family {self.address_family!r}.")
        if self.log_mode not in LOG_MODES:
            raise ValidationError(f"Unknown logging mode {self.log_mode!r}.")
        if self.log_mode != "off" and not self.log_path.strip():
            raise ValidationError("Session logging needs a file to write to.")
        for entry in self.environment:
            line = entry.strip()
            if line and not line.startswith("#") and not _ENV_RE.match(line):
                raise ValidationError(
                    f"Environment entry {entry!r} should look like LANG=en_GB.UTF-8"
                )
        if self.no_shell and not self.has_tunnels:
            # A tunnel-only session with no tunnels connects and then sits
            # there doing nothing at all, which is never what was meant.
            raise ValidationError(
                "Tunnel-only sessions need at least one forward to be worth opening."
            )

    # ------------------------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Session":
        known = {f.name: f for f in fields(cls)}
        kwargs: dict[str, Any] = {}
        for key, value in raw.items():
            spec = known.get(key)
            if spec is None:
                continue  # forward compatible: ignore keys we do not know
            kwargs[key] = _coerce(value, spec.type)
        return cls(**kwargs)

    def clone(self, new_name: str) -> "Session":
        data = self.to_dict()
        data["name"] = new_name
        data["last_used"] = 0.0
        return Session.from_dict(data)


def _coerce(value: Any, type_hint: Any) -> Any:
    hint = type_hint if isinstance(type_hint, str) else getattr(type_hint, "__name__", "")
    # `from __future__ import annotations` means the hints arrive as strings,
    # so the nested dataclass is matched by name rather than by identity.
    if hint == "ProxyConfig":
        return ProxyConfig.from_dict(value)
    try:
        if hint == "int":
            return int(value)
        if hint == "float":
            return float(value)
        if hint == "bool":
            if isinstance(value, str):
                return value.strip().lower() in ("1", "true", "yes", "on")
            return bool(value)
        if hint == "str":
            return "" if value is None else str(value)
        if hint.startswith("list"):
            if value is None:
                return []
            if isinstance(value, str):
                return [line for line in value.splitlines() if line.strip()]
            return list(value)
    except (TypeError, ValueError):
        pass
    return value


def parse_target(target: str, default_user: str = "") -> tuple[str, str, int]:
    """Split ``user@host:port`` into its parts."""
    user = default_user
    rest = target.strip()
    if "@" in rest:
        user, rest = rest.rsplit("@", 1)
    port = 22
    if rest.startswith("["):  # bracketed IPv6
        close = rest.find("]")
        host = rest[1:close]
        if rest[close + 1 :].startswith(":"):
            port = int(rest[close + 2 :])
    elif ":" in rest and rest.count(":") == 1:
        host, raw_port = rest.split(":", 1)
        port = int(raw_port)
    else:
        host = rest
    return user, host, port


def parse_forward(spec: str) -> tuple[str, int, str, int]:
    """Parse ``[bind:]port:host:port`` into (bind, port, dest_host, dest_port)."""
    match = _FORWARD_RE.match(spec.strip())
    if not match:
        raise ValidationError(f"Cannot parse forward {spec!r}")
    bind = (match.group("bind") or "127.0.0.1:").rstrip(":").strip("[]") or "127.0.0.1"
    dest = match.group("dhost").strip("[]")
    return bind, int(match.group("lport")), dest, int(match.group("dport"))


def has_explicit_bind(spec: str) -> bool:
    """True when the spec names a bind address rather than defaulting to loopback.

    Colon counting gets this wrong for bracketed IPv6, so ask the same
    regexes that do the parsing.
    """
    text = spec.strip()
    match = _FORWARD_RE.match(text) or _DYNAMIC_RE.match(text)
    return bool(match and match.group("bind"))


def parse_dynamic(spec: str) -> tuple[str, int]:
    """Parse ``[bind:]port`` into (bind, port).

    Defaults to 127.0.0.1 like OpenSSH: a SOCKS proxy reachable from the
    whole network is an open relay into everything the far end can see.
    """
    match = _DYNAMIC_RE.match(spec.strip())
    if not match:
        raise ValidationError(f"Cannot parse dynamic forward {spec!r}")
    bind = (match.group("bind") or "127.0.0.1").strip("[]") or "127.0.0.1"
    return bind, int(match.group("lport"))
