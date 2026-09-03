"""End-to-end check: connect, run a command, survive a killed link, detach.

Drives the real CLI through a real pty against a real sshd. Run it with a
local sshd listening on 127.0.0.1:2222 that accepts the key in --identity.
"""

from __future__ import annotations

import json
import os
import pty
import re
import select
import signal
import struct
import subprocess
import sys
import termios
import time
from fcntl import ioctl
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ANSI = re.compile(rb"\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07]*\x07|\r")


class Pty:
    def __init__(self, argv: list[str], env: dict[str, str]) -> None:
        self.master, slave = pty.openpty()
        ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))
        self.proc = subprocess.Popen(
            argv, stdin=slave, stdout=slave, stderr=slave, env=env, cwd=str(ROOT),
            preexec_fn=os.setsid,
        )
        os.close(slave)
        self.buffer = b""

    def read(self, timeout: float = 0.3) -> bytes:
        readable, _, _ = select.select([self.master], [], [], timeout)
        if not readable:
            return b""
        try:
            chunk = os.read(self.master, 65536)
        except OSError:
            return b""
        self.buffer += chunk
        return chunk

    def expect(self, pattern: str, timeout: float = 25.0) -> str:
        needle = re.compile(pattern.encode())
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.read(0.2)
            clean = ANSI.sub(b"", self.buffer)
            match = needle.search(clean)
            if match:
                return match.group(0).decode(errors="replace")
        raise AssertionError(
            f"Timed out waiting for {pattern!r}.\n"
            f"--- output ---\n{ANSI.sub(b'', self.buffer).decode(errors='replace')[-3000:]}"
        )

    def send(self, data: bytes) -> None:
        os.write(self.master, data)

    def close(self) -> None:
        try:
            os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        os.close(self.master)

    @property
    def text(self) -> str:
        return ANSI.sub(b"", self.buffer).decode(errors="replace")


def build_store(tmp: Path, key: Path) -> Path:
    sessions = {
        "version": 1,
        "sessions": [
            {
                "name": "loopback",
                "group": "Test",
                "host": "127.0.0.1",
                "port": 2222,
                "username": os.environ.get("USER", "root"),
                "auth": "key",
                "key_path": str(key),
                "host_key_policy": "auto",
                "keepalive_interval": 5,
                "keepalive_count_max": 2,
                "auto_reconnect": True,
                "reconnect_delay": 1.0,
                "reconnect_max_delay": 4.0,
                "reconnect_attempts": 5,
                "login_commands": ["export PS1='pytty$ '"],
            }
        ],
    }
    path = tmp / "sessions.json"
    path.write_text(json.dumps(sessions, indent=2))
    return path


def kill_remote_side() -> None:
    """Kill the sshd child serving our session, imitating a link failure."""
    subprocess.run(["pkill", "-9", "-f", "sshd: .*@pts"], check=False)
    subprocess.run(["pkill", "-9", "-f", "sshd-session"], check=False)


def main() -> int:
    tmp = Path("/tmp/pytty-e2e")
    tmp.mkdir(exist_ok=True)
    key = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.home() / ".ssh" / "id_test"
    store = build_store(tmp, key)

    env = dict(os.environ, PYTTY_HOME=str(tmp), TERM="xterm-256color", PYTHONUNBUFFERED="1")
    session = Pty([sys.executable, "-m", "pytty", "loopback", "--config", str(store)], env)

    failures: list[str] = []
    try:
        print("· waiting for the first connection")
        session.expect(r"Connected to 127\.0\.0\.1")
        session.expect(r"Keepalive every 5s")

        print("· running a command on the remote side")
        time.sleep(1.0)
        session.send(b"echo PYTTY_MARKER_$((6*7))\n")
        session.expect(r"PYTTY_MARKER_42")

        print("· killing the remote end of the link")
        session.buffer = b""
        kill_remote_side()

        print("· waiting for the drop to be noticed")
        session.expect(r"Link dropped", timeout=30)
        session.expect(r"Reconnecting in", timeout=15)

        print("· waiting for the automatic reconnect")
        session.expect(r"Connected to 127\.0\.0\.1", timeout=40)

        print("· checking the reconnected session works")
        time.sleep(1.0)
        session.send(b"echo AFTER_RECONNECT_$((3*5))\n")
        session.expect(r"AFTER_RECONNECT_15")

        print("· detaching with the escape key")
        session.send(b"\x1d")
        session.expect(r"Disconnected after", timeout=10)
        session.expect(r"loopback: detached", timeout=10)
        code = session.proc.wait(timeout=10)
        if code != 0:
            failures.append(f"exit code was {code}, expected 0")
    except AssertionError as exc:
        failures.append(str(exc))
    finally:
        session.close()

    if failures:
        print("\nFAILED")
        for failure in failures:
            print(failure)
        return 1
    print("\nAll end-to-end checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
