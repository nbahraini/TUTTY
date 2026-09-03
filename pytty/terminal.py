"""Bridge between the local terminal and a remote SSH channel."""

from __future__ import annotations

import enum
import os
import shutil
import sys
import threading
import time
from typing import Callable

import paramiko

IS_WINDOWS = os.name == "nt"
DEFAULT_ESCAPE = 0x1D  # Ctrl-]


class Outcome(enum.Enum):
    """Why the interactive session stopped."""

    DETACHED = "detached"  # local escape key
    REMOTE_EXIT = "remote_exit"  # the remote shell finished
    DROPPED = "dropped"  # the link died under us


def terminal_size() -> tuple[int, int]:
    size = shutil.get_terminal_size(fallback=(80, 24))
    return max(20, size.columns), max(5, size.lines)


class Console:
    """Small helper for the messages printed around a session."""

    DIM = "\x1b[38;5;245m"
    AMBER = "\x1b[38;5;214m"
    GREEN = "\x1b[38;5;71m"
    RED = "\x1b[38;5;167m"
    RESET = "\x1b[0m"

    def __init__(self, stream=None, color: bool = True) -> None:
        self.stream = stream or sys.stdout
        self.color = color and self.stream.isatty()

    def _paint(self, text: str, color: str) -> str:
        return f"{color}{text}{self.RESET}" if self.color else text

    def status(self, text: str, color: str | None = None) -> None:
        self.stream.write("\r\x1b[2K" if self.color else "\r")
        self.stream.write(self._paint(text, color or self.DIM))
        self.stream.write("\n")
        self.stream.flush()

    def transient(self, text: str) -> None:
        """Overwrite the current line without leaving it in the scrollback."""
        if not self.color:
            return
        self.stream.write(f"\r\x1b[2K{self.DIM}{text}{self.RESET}")
        self.stream.flush()

    def clear_transient(self) -> None:
        if self.color:
            self.stream.write("\r\x1b[2K")
            self.stream.flush()

    def rule(self, text: str) -> None:
        width = terminal_size()[0]
        body = f"── {text} " if text else ""
        line = body + "─" * max(0, width - len(body))
        self.stream.write(self._paint(line, self.DIM) + "\n")
        self.stream.flush()


# ----------------------------------------------------------------------
# Session logging
# ----------------------------------------------------------------------
def expand_log_path(path: str, host: str = "", name: str = "") -> str:
    """Expand PuTTY's ``&`` placeholders in a log file name.

    ``&H`` host, ``&N`` session name, ``&Y`` ``&M`` ``&D`` date parts and
    ``&T`` time. Keeping PuTTY's spelling means a log path copied out of a
    PuTTY configuration still does what it did there.
    """
    now = time.localtime()
    replacements = {
        "&H": host or "unknown",
        "&N": name or host or "session",
        "&Y": time.strftime("%Y", now),
        "&M": time.strftime("%m", now),
        "&D": time.strftime("%d", now),
        "&T": time.strftime("%H%M%S", now),
        "&&": "&",
    }
    out = path
    for token, value in replacements.items():
        out = out.replace(token, value)
    return os.path.expanduser(out)


class SessionLog:
    """Writes the session to a file, the way PuTTY's logging pane does.

    Two modes: ``output`` records what the server sent, ``all`` records your
    keystrokes as well. The bytes go down raw, escape sequences and all, so
    replaying the file with ``cat`` reproduces the session — which is the
    thing a stripped log cannot do.
    """

    def __init__(self, path: str, mode: str, host: str = "", name: str = "") -> None:
        self.mode = mode
        self.path = expand_log_path(path, host, name)
        self._handle = None
        self._lock = threading.Lock()
        self.error: str | None = None

    def open(self) -> bool:
        if self.mode == "off" or not self.path:
            return False
        try:
            directory = os.path.dirname(self.path)
            if directory:
                os.makedirs(directory, exist_ok=True)
            # Append, so a reconnect adds to the log rather than truncating
            # the record of the connection that just died.
            self._handle = open(self.path, "ab", buffering=0)
        except OSError as exc:
            self.error = str(exc)
            return False
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        self._write(f"\n=== pytty session log started {stamp} ===\n".encode())
        return True

    def _write(self, data: bytes) -> None:
        handle = self._handle
        if handle is None:
            return
        with self._lock:
            try:
                handle.write(data)
            except OSError as exc:
                self.error = str(exc)
                self._handle = None

    def output(self, data: bytes) -> None:
        if self._handle is not None:
            self._write(data)

    def input(self, data: bytes) -> None:
        if self._handle is not None and self.mode == "all":
            self._write(data)

    def close(self) -> None:
        handle = self._handle
        if handle is None:
            return
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        self._write(f"\n=== pytty session log ended {stamp} ===\n".encode())
        with self._lock:
            self._handle = None
            try:
                handle.close()
            except OSError:
                pass


# ----------------------------------------------------------------------
# Local terminal raw mode
# ----------------------------------------------------------------------
class RawTerminal:
    """Puts the local tty into raw mode for the duration of a session."""

    def __init__(self) -> None:
        self._restore: Callable[[], None] | None = None

    def __enter__(self) -> "RawTerminal":
        if IS_WINDOWS:
            self._restore = _enable_windows_vt()
        else:
            self._restore = _enable_posix_raw()
        return self

    def __exit__(self, *exc_info) -> None:
        if self._restore:
            self._restore()
            self._restore = None


class CbreakTerminal:
    """Single-keypress input that still lets Ctrl-C through.

    Used while a countdown is on screen, where the user should be able to
    press a key to retry now or give up, but Ctrl-C must still interrupt.
    """

    def __init__(self) -> None:
        self._restore: Callable[[], None] | None = None

    def __enter__(self) -> "CbreakTerminal":
        if IS_WINDOWS or not sys.stdin.isatty():
            return self
        import termios
        import tty

        fd = sys.stdin.fileno()
        saved = termios.tcgetattr(fd)
        tty.setcbreak(fd, termios.TCSANOW)
        self._restore = lambda: termios.tcsetattr(fd, termios.TCSADRAIN, saved)
        return self

    def __exit__(self, *exc_info) -> None:
        if self._restore:
            self._restore()
            self._restore = None


def _enable_posix_raw() -> Callable[[], None]:
    import termios
    import tty

    fd = sys.stdin.fileno()
    if not os.isatty(fd):
        return lambda: None
    saved = termios.tcgetattr(fd)
    tty.setraw(fd, termios.TCSANOW)

    def restore() -> None:
        termios.tcsetattr(fd, termios.TCSADRAIN, saved)

    return restore


def _enable_windows_vt() -> Callable[[], None]:
    """Turn on VT input and output so escape sequences pass through."""
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
    ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
    ENABLE_VIRTUAL_TERMINAL_INPUT = 0x0200
    ENABLE_PROCESSED_INPUT = 0x0001
    ENABLE_LINE_INPUT = 0x0002
    ENABLE_ECHO_INPUT = 0x0004

    stdin_handle = kernel32.GetStdHandle(-10)
    stdout_handle = kernel32.GetStdHandle(-11)
    old_in = wintypes.DWORD()
    old_out = wintypes.DWORD()
    kernel32.GetConsoleMode(stdin_handle, ctypes.byref(old_in))
    kernel32.GetConsoleMode(stdout_handle, ctypes.byref(old_out))

    new_in = (old_in.value & ~(ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT))
    new_in |= ENABLE_VIRTUAL_TERMINAL_INPUT
    kernel32.SetConsoleMode(stdin_handle, new_in)
    kernel32.SetConsoleMode(stdout_handle, old_out.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING)

    def restore() -> None:
        kernel32.SetConsoleMode(stdin_handle, old_in.value)
        kernel32.SetConsoleMode(stdout_handle, old_out.value)

    return restore


# ----------------------------------------------------------------------
# The bridge
# ----------------------------------------------------------------------
class TerminalBridge:
    """Copies bytes both ways until someone hangs up."""

    def __init__(
        self, escape_byte: int = DEFAULT_ESCAPE, log: "SessionLog | None" = None
    ) -> None:
        self.escape_byte = escape_byte
        self.log = log
        self.bytes_in = 0
        self.bytes_out = 0
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()

    def run(self, channel: paramiko.Channel) -> Outcome:
        self._stop.clear()
        if IS_WINDOWS:
            return self._run_windows(channel)
        return self._run_posix(channel)

    # -- shared -------------------------------------------------------
    def _write_out(self, data: bytes) -> None:
        self.bytes_in += len(data)
        if self.log is not None:
            self.log.output(data)
        stream = sys.stdout.buffer
        stream.write(data)
        stream.flush()

    def _drain(self, channel: paramiko.Channel) -> bool:
        """Read whatever is buffered. Returns False on remote EOF."""
        alive = True
        while channel.recv_ready():
            data = channel.recv(65536)
            if not data:
                alive = False
                break
            self._write_out(data)
        while channel.recv_stderr_ready():
            data = channel.recv_stderr(65536)
            if not data:
                break
            self._write_out(data)
        return alive

    def _classify(self, channel: paramiko.Channel) -> Outcome:
        transport = channel.get_transport()
        if transport is None or not transport.is_active():
            return Outcome.DROPPED
        return Outcome.REMOTE_EXIT

    def _handle_input(self, data: bytes, channel: paramiko.Channel) -> bool:
        """Forward keystrokes. Returns False when the escape key was pressed."""
        index = data.find(bytes([self.escape_byte]))
        if index >= 0:
            if index:
                channel.sendall(data[:index])
                self.bytes_out += index
                if self.log is not None:
                    self.log.input(data[:index])
            return False
        channel.sendall(data)
        self.bytes_out += len(data)
        if self.log is not None:
            self.log.input(data)
        return True

    # -- posix --------------------------------------------------------
    def _run_posix(self, channel: paramiko.Channel) -> Outcome:
        import select
        import signal

        stdin_fd = sys.stdin.fileno()
        resized = threading.Event()

        def on_winch(signum, frame) -> None:  # noqa: ANN001
            resized.set()

        previous = None
        if hasattr(signal, "SIGWINCH"):
            previous = signal.signal(signal.SIGWINCH, on_winch)

        try:
            while not self._stop.is_set():
                if resized.is_set():
                    resized.clear()
                    cols, rows = terminal_size()
                    try:
                        channel.resize_pty(width=cols, height=rows)
                    except Exception:
                        pass

                try:
                    readable, _, _ = select.select([stdin_fd, channel], [], [], 0.2)
                except (InterruptedError, OSError):
                    continue

                if channel in readable:
                    if not self._drain(channel):
                        return self._classify(channel)

                if stdin_fd in readable:
                    try:
                        data = os.read(stdin_fd, 4096)
                    except OSError:
                        data = b""
                    if not data:
                        return Outcome.DETACHED
                    try:
                        if not self._handle_input(data, channel):
                            return Outcome.DETACHED
                    except OSError:
                        return self._classify(channel)

                transport = channel.get_transport()
                if transport is None or not transport.is_active():
                    self._drain(channel)
                    return Outcome.DROPPED
                if channel.exit_status_ready() and not channel.recv_ready():
                    self._drain(channel)
                    return Outcome.REMOTE_EXIT
            return Outcome.DETACHED
        finally:
            if previous is not None and hasattr(signal, "SIGWINCH"):
                signal.signal(signal.SIGWINCH, previous)

    # -- windows ------------------------------------------------------
    def _run_windows(self, channel: paramiko.Channel) -> Outcome:
        import msvcrt
        import queue

        keys: "queue.Queue[bytes]" = queue.Queue()
        reading = threading.Event()
        reading.set()

        def reader() -> None:
            while reading.is_set():
                if msvcrt.kbhit():
                    keys.put(msvcrt.getch())
                else:
                    time.sleep(0.01)

        thread = threading.Thread(target=reader, daemon=True, name="pytty-stdin")
        thread.start()
        last_size = terminal_size()

        try:
            while not self._stop.is_set():
                size = terminal_size()
                if size != last_size:
                    last_size = size
                    try:
                        channel.resize_pty(width=size[0], height=size[1])
                    except Exception:
                        pass

                if not self._drain(channel):
                    return self._classify(channel)

                chunk = b""
                try:
                    chunk += keys.get(timeout=0.02)
                    while True:
                        chunk += keys.get_nowait()
                except queue.Empty:
                    pass

                if chunk:
                    try:
                        if not self._handle_input(chunk, channel):
                            return Outcome.DETACHED
                    except OSError:
                        return self._classify(channel)

                transport = channel.get_transport()
                if transport is None or not transport.is_active():
                    self._drain(channel)
                    return Outcome.DROPPED
                if channel.exit_status_ready() and not channel.recv_ready():
                    self._drain(channel)
                    return Outcome.REMOTE_EXIT
            return Outcome.DETACHED
        finally:
            reading.clear()


def idle_wait(
    transport: paramiko.Transport,
    escape_byte: int = DEFAULT_ESCAPE,
    on_tick: Callable[[], None] | None = None,
) -> Outcome:
    """Hold a session open with no shell — plink's ``-N``.

    There is no channel to bridge, so the only two things that can end this
    are the escape key and the link dying. Cbreak rather than raw mode, so
    Ctrl-C still interrupts the way it would in any other foreground process.
    """
    with CbreakTerminal():
        while True:
            if not transport.is_active():
                return Outcome.DROPPED
            if on_tick is not None:
                on_tick()
            try:
                key = wait_for_key(0.25)
            except KeyboardInterrupt:
                return Outcome.DETACHED
            if key is None:
                continue
            if key == bytes([escape_byte]) or key in (b"q", b"Q", b"\x03"):
                return Outcome.DETACHED


def wait_for_key(timeout: float, accept: bytes = b"") -> bytes | None:
    """Poll the terminal for a single keypress. Used by the reconnect countdown."""
    deadline = time.monotonic() + timeout
    if IS_WINDOWS:
        import msvcrt

        while time.monotonic() < deadline:
            if msvcrt.kbhit():
                key = msvcrt.getch()
                if not accept or key in accept:
                    return key
            time.sleep(0.05)
        return None

    import select

    fd = sys.stdin.fileno()
    if not os.isatty(fd):
        time.sleep(max(0.0, deadline - time.monotonic()))
        return None
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        readable, _, _ = select.select([fd], [], [], min(0.2, remaining))
        if readable:
            key = os.read(fd, 1)
            if not accept or key in accept:
                return key
