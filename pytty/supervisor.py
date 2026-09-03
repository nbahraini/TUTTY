"""The connect → run → drop → reconnect loop."""

from __future__ import annotations

import random
import socket
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Callable

import paramiko

from .model import Session
from .ssh import (
    AuthCancelled,
    Connector,
    ForwardManager,
    HostKeyRejected,
    KeepAlive,
    Prompter,
    open_shell,
)
from .proxy import ProxyAuthError, ProxyConfig, ProxyError
from .terminal import (
    CbreakTerminal,
    Console,
    Outcome,
    RawTerminal,
    SessionLog,
    TerminalBridge,
    idle_wait,
    terminal_size,
    wait_for_key,
)

# A proxy that refuses our credentials will refuse them again on every retry,
# so it belongs with the authentication failures rather than the transient ones.
FATAL = (AuthCancelled, HostKeyRejected, paramiko.AuthenticationException, ProxyAuthError)


@dataclass
class LogEntry:
    when: float
    level: str
    message: str

    def format(self) -> str:
        stamp = time.strftime("%H:%M:%S", time.localtime(self.when))
        return f"{stamp}  {self.message}"


@dataclass
class RunReport:
    """What happened across the whole supervised session."""

    session_name: str
    connects: int = 0
    reconnects: int = 0
    failed_attempts: int = 0
    connected_seconds: float = 0.0
    ended_because: str = ""
    error: str = ""
    log: list[LogEntry] = field(default_factory=list)

    @property
    def uptime_text(self) -> str:
        seconds = int(self.connected_seconds)
        hours, remainder = divmod(seconds, 3600)
        minutes, secs = divmod(remainder, 60)
        if hours:
            return f"{hours}h {minutes}m"
        if minutes:
            return f"{minutes}m {secs}s"
        return f"{secs}s"


class Supervisor:
    """Keeps one session connected for as long as the user wants it connected.

    A session ends for exactly three reasons, and only one of them is worth
    reconnecting after:

      detached     the user pressed the escape key      → stop
      remote exit  the shell exited on its own          → stop, unless asked
      dropped      the link died                        → reconnect with backoff
    """

    def __init__(
        self,
        session: Session,
        prompter: Prompter,
        console: Console | None = None,
        escape_byte: int = 0x1D,
        on_log: Callable[[LogEntry], None] | None = None,
        proxy: ProxyConfig | None = None,
        proxy_password: str | None = None,
    ) -> None:
        self.session = session
        self.prompter = prompter
        self.console = console or Console()
        self.escape_byte = escape_byte
        self.on_log = on_log
        self.proxy = proxy
        self.proxy_password = proxy_password
        self.report = RunReport(session_name=session.name or session.host)
        self._recent: deque[LogEntry] = deque(maxlen=500)
        self._abort = False

    # ------------------------------------------------------------------
    def log(self, level: str, message: str) -> None:
        entry = LogEntry(time.time(), level, message)
        self._recent.append(entry)
        self.report.log.append(entry)
        colour = {
            "error": Console.RED,
            "warn": Console.AMBER,
            "ok": Console.GREEN,
        }.get(level, Console.DIM)
        self.console.status(entry.format(), colour)
        if self.on_log:
            self.on_log(entry)

    # ------------------------------------------------------------------
    def run(self) -> RunReport:
        session = self.session
        connector = Connector(
            session, self.prompter, self.log, self.proxy, self.proxy_password
        )
        attempt = 0
        delay = session.reconnect_delay

        escape_name = _key_name(self.escape_byte)
        self.console.rule(f"{session.name or session.host} — {escape_name} to disconnect")
        if self.proxy is not None and self.proxy.enabled:
            self.log("info", f"Using proxy {self.proxy.describe()}")

        while not self._abort:
            client = None
            jumps: list[paramiko.SSHClient] = []
            forwards = ForwardManager(self.log)
            keepalive: KeepAlive | None = None

            try:
                self.log("info", f"Connecting to {session.target}")
                client, jumps = connector.connect()
            except FATAL as exc:
                self.report.ended_because = "authentication"
                self.report.error = str(exc)
                self.log("error", f"Cannot authenticate: {exc}")
                break
            except KeyboardInterrupt:
                self.report.ended_because = "cancelled"
                self.log("warn", "Cancelled")
                break
            except (OSError, socket.error, paramiko.SSHException) as exc:
                self.report.failed_attempts += 1
                label = "Proxy failed" if isinstance(exc, ProxyError) else "Connection failed"
                self.log("error", f"{label}: {_describe(exc)}")
                if not self._should_retry(attempt):
                    self.report.ended_because = "unreachable"
                    self.report.error = _describe(exc)
                    break
                attempt += 1
                if not self._countdown(delay, attempt):
                    self.report.ended_because = "cancelled"
                    break
                delay = self._next_delay(delay)
                continue

            # --- connected -------------------------------------------
            attempt = 0
            delay = session.reconnect_delay
            self.report.connects += 1
            if self.report.connects > 1:
                self.report.reconnects += 1
            started = time.monotonic()
            outcome = Outcome.DROPPED
            session_log: SessionLog | None = None

            try:
                cols, rows = terminal_size()
                transport = client.get_transport()
                assert transport is not None
                channel = None

                if session.no_shell:
                    # plink -N: the tunnels are the point, so no channel is
                    # opened at all and there is nothing to bridge.
                    self.log("ok", f"Connected to {session.host} — tunnels only, no shell")
                else:
                    channel = open_shell(client, session, cols, rows, self.log)
                    self.log("ok", f"Connected to {session.host} ({cols}×{rows})")

                forwards.start(session, transport)

                if session.keepalive_interval:
                    keepalive = KeepAlive(
                        transport,
                        session.keepalive_interval,
                        session.keepalive_count_max,
                        self.log,
                        channel=channel,
                        null_packets=session.null_packets,
                    )
                    keepalive.start()
                    self.log(
                        "info",
                        f"Keepalive every {session.keepalive_interval}s, "
                        f"dropping after {session.keepalive_count_max} missed "
                        f"({int(session.dead_after())}s worst case)",
                    )

                if channel is None:
                    self.console.status(
                        f"Tunnels are up. {_key_name(self.escape_byte)} or q to disconnect.",
                        Console.GREEN,
                    )
                    outcome = idle_wait(transport, self.escape_byte)
                else:
                    session_log = self._open_log()
                    self._send_login_commands(channel)

                    bridge = TerminalBridge(self.escape_byte, log=session_log)
                    with RawTerminal():
                        outcome = bridge.run(channel)

                if keepalive is not None and keepalive.declared_dead.is_set():
                    outcome = Outcome.DROPPED

                if outcome is Outcome.REMOTE_EXIT and channel is not None:
                    status = channel.recv_exit_status() if channel.exit_status_ready() else None
                    if status is not None:
                        self.log("info", f"Remote shell exited with status {status}")
            except KeyboardInterrupt:
                outcome = Outcome.DETACHED
            except (OSError, paramiko.SSHException) as exc:
                self.log("error", f"Session error: {_describe(exc)}")
                outcome = Outcome.DROPPED
            finally:
                elapsed = time.monotonic() - started
                self.report.connected_seconds += elapsed
                if session_log is not None:
                    session_log.close()
                    if session_log.error:
                        self.log("warn", f"Session log: {session_log.error}")
                if keepalive is not None:
                    keepalive.stop()
                forwards.stop()
                _close_all(client, jumps)

            # --- decide what happens next ----------------------------
            if outcome is Outcome.DETACHED:
                self.report.ended_because = "detached"
                self.log("info", f"Disconnected after {_short(elapsed)}")
                break

            if outcome is Outcome.REMOTE_EXIT and not session.reconnect_on_remote_exit:
                self.report.ended_because = "remote exit"
                self.log("info", f"Session closed after {_short(elapsed)}")
                break

            reason = "Link dropped" if outcome is Outcome.DROPPED else "Remote shell exited"
            self.log("warn", f"{reason} after {_short(elapsed)}")

            if not self._should_retry(attempt):
                self.report.ended_because = "gave up"
                break
            attempt += 1
            if not self._countdown(delay, attempt):
                self.report.ended_because = "cancelled"
                break
            delay = self._next_delay(delay)

        self.console.rule("")
        return self.report

    # ------------------------------------------------------------------
    def _open_log(self) -> SessionLog | None:
        session = self.session
        if session.log_mode == "off" or not session.log_path.strip():
            return None
        log = SessionLog(
            session.log_path, session.log_mode, session.host, session.name
        )
        if not log.open():
            self.log("warn", f"Could not open session log: {log.error}")
            return None
        what = "output" if session.log_mode == "output" else "output and keystrokes"
        self.log("info", f"Logging {what} to {log.path}")
        return log

    def _send_login_commands(self, channel: paramiko.Channel) -> None:
        commands = [c for c in self.session.login_commands if c.strip()]
        if not commands or self.session.remote_command.strip():
            return
        time.sleep(0.35)  # let the remote shell print its prompt first
        for command in commands:
            try:
                channel.sendall(command.encode() + b"\n")
            except OSError:
                return
            time.sleep(0.1)
        self.log("info", f"Replayed {len(commands)} login command(s)")

    def _should_retry(self, attempt: int) -> bool:
        session = self.session
        if not session.auto_reconnect:
            return False
        if session.reconnect_attempts and attempt >= session.reconnect_attempts:
            self.log(
                "error",
                f"Giving up after {session.reconnect_attempts} reconnect attempt(s)",
            )
            return False
        return True

    def _next_delay(self, delay: float) -> float:
        return min(delay * 2, self.session.reconnect_max_delay)

    def _countdown(self, delay: float, attempt: int) -> bool:
        """Wait before retrying. Returns False if the user gave up.

        Full jitter is applied so a rack of clients coming back after the same
        outage does not stampede the server in lockstep.
        """
        limit = self.session.reconnect_attempts
        of = f" of {limit}" if limit else ""
        wait = delay * (0.5 + random.random() * 0.5)
        deadline = time.monotonic() + wait

        with CbreakTerminal():
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self.console.transient(
                    f"Reconnecting in {remaining:4.1f}s  "
                    f"(attempt {attempt}{of})  ·  Enter retries now, q gives up"
                )
                try:
                    key = wait_for_key(min(0.2, remaining))
                except KeyboardInterrupt:
                    self.console.clear_transient()
                    return False
                if key is None:
                    continue
                if key in (b"q", b"Q", b"\x03"):
                    self.console.clear_transient()
                    self.log("info", "Reconnect cancelled")
                    return False
                if key in (b"\r", b"\n", b" "):
                    break
        self.console.clear_transient()
        return True

    def abort(self) -> None:
        self._abort = True


def _close_all(client: paramiko.SSHClient | None, jumps: list[paramiko.SSHClient]) -> None:
    for item in [client, *jumps]:
        if item is None:
            continue
        try:
            item.close()
        except Exception:
            pass


def _describe(exc: BaseException) -> str:
    if isinstance(exc, socket.timeout):
        return "timed out"
    if isinstance(exc, ConnectionRefusedError):
        return "connection refused"
    if isinstance(exc, socket.gaierror):
        return "hostname could not be resolved"
    text = str(exc).strip()
    return text or exc.__class__.__name__


def _short(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.0f}s"
    minutes, secs = divmod(int(seconds), 60)
    if minutes < 60:
        return f"{minutes}m {secs}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes}m"


def _key_name(byte: int) -> str:
    if byte < 32:
        return f"Ctrl-{chr(byte + 64)}"
    return repr(chr(byte))
