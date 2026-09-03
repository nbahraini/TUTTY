"""End-to-end check: -D opens a working SOCKS proxy, and it survives a drop.

Drives the real CLI through a real pty against a real sshd. A throwaway HTTP
server stands in for "something only reachable from the far end" — it binds a
port on loopback and the proxy has to reach it through the SSH transport.

Run it with a local sshd listening on 127.0.0.1:2222 that accepts the key in
the first argument:

    python tests/e2e_socks.py ~/.ssh/id_test
"""

from __future__ import annotations

import json
import os
import pty
import re
import select
import signal
import socket
import struct
import subprocess
import sys
import termios
import threading
import time
from fcntl import ioctl
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ANSI = re.compile(rb"\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07]*\x07|\r")

SOCKS_PORT = 11080
BODY = b"pytty-socks-ok"


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
            match = needle.search(ANSI.sub(b"", self.buffer))
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


# ----------------------------------------------------------------------
# The thing we tunnel to
# ----------------------------------------------------------------------
class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, *args) -> None:  # noqa: ANN002
        pass


def start_target() -> tuple[HTTPServer, int]:
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


# ----------------------------------------------------------------------
# A minimal SOCKS5 client, so the test does not need PySocks
# ----------------------------------------------------------------------
def socks5_get(proxy_port: int, host: str, port: int, timeout: float = 10.0) -> bytes:
    sock = socket.create_connection(("127.0.0.1", proxy_port), timeout=timeout)
    try:
        sock.sendall(b"\x05\x01\x00")
        greeting = sock.recv(2)
        if greeting != b"\x05\x00":
            raise AssertionError(f"Proxy refused the greeting: {greeting!r}")
        target = host.encode()
        sock.sendall(
            b"\x05\x01\x00\x03" + bytes([len(target)]) + target + struct.pack(">H", port)
        )
        reply = sock.recv(10)
        if len(reply) < 2 or reply[1] != 0x00:
            raise AssertionError(f"Proxy refused the connect: {reply!r}")
        sock.sendall(f"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
        chunks = []
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        sock.close()


def wait_for_port(port: int, timeout: float = 20.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
            return
        except OSError:
            time.sleep(0.2)
    raise AssertionError(f"Nothing listening on 127.0.0.1:{port} after {timeout}s")


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
    subprocess.run(["pkill", "-9", "-f", "sshd: .*@pts"], check=False)
    subprocess.run(["pkill", "-9", "-f", "sshd-session"], check=False)


def main() -> int:
    tmp = Path("/tmp/pytty-e2e")
    tmp.mkdir(exist_ok=True)
    key = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.home() / ".ssh" / "id_test"
    store = build_store(tmp, key)

    target, target_port = start_target()
    print(f"· target http server on 127.0.0.1:{target_port}")

    env = dict(os.environ, PYTTY_HOME=str(tmp), TERM="xterm-256color", PYTHONUNBUFFERED="1")
    session = Pty(
        [
            sys.executable, "-m", "pytty", "loopback",
            "--config", str(store),
            "-D", str(SOCKS_PORT),
        ],
        env,
    )

    failures: list[str] = []
    try:
        print("· waiting for the connection")
        session.expect(r"Connected to 127\.0\.0\.1")
        session.expect(rf"SOCKS proxy on 127\.0\.0\.1:{SOCKS_PORT}")
        wait_for_port(SOCKS_PORT)

        print("· fetching through the proxy")
        response = socks5_get(SOCKS_PORT, "127.0.0.1", target_port)
        if BODY not in response:
            failures.append(f"proxied response did not contain {BODY!r}: {response[:200]!r}")

        print("· checking a refused destination is reported, not hung")
        closed = socket.socket()
        closed.bind(("127.0.0.1", 0))
        dead_port = closed.getsockname()[1]
        closed.close()
        try:
            socks5_get(SOCKS_PORT, "127.0.0.1", dead_port, timeout=15)
            failures.append("a connection to a closed port was not refused")
        except AssertionError as exc:
            if "refused the connect" not in str(exc):
                failures.append(f"unexpected failure for a closed port: {exc}")

        print("· killing the link")
        session.buffer = b""
        kill_remote_side()
        session.expect(r"Link dropped", timeout=30)

        print("· waiting for the reconnect to rebuild the proxy")
        session.expect(r"Connected to 127\.0\.0\.1", timeout=40)
        session.expect(rf"SOCKS proxy on 127\.0\.0\.1:{SOCKS_PORT}", timeout=15)
        wait_for_port(SOCKS_PORT)

        print("· fetching through the rebuilt proxy")
        time.sleep(0.5)
        response = socks5_get(SOCKS_PORT, "127.0.0.1", target_port)
        if BODY not in response:
            failures.append(f"post-reconnect response was wrong: {response[:200]!r}")

        print("· detaching")
        session.send(b"\x1d")
        session.expect(r"loopback: detached", timeout=10)
        code = session.proc.wait(timeout=10)
        if code != 0:
            failures.append(f"exit code was {code}, expected 0")

        print("· checking the proxy port is released on exit")
        time.sleep(1.0)
        try:
            socket.create_connection(("127.0.0.1", SOCKS_PORT), timeout=1).close()
            failures.append("the SOCKS port was still accepting after the session ended")
        except OSError:
            pass
    except AssertionError as exc:
        failures.append(str(exc))
    finally:
        session.close()
        target.shutdown()

    if failures:
        print("\nFAILED")
        for failure in failures:
            print(failure)
        return 1
    print("\nAll end-to-end checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
