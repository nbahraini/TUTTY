"""End-to-end check of dead peer detection.

A clean disconnect is easy: the kernel sends a FIN and everyone notices. The
case keepalive exists for is the silent one — a NAT box forgets the flow, a
Wi-Fi bridge drops, and the socket stays open forever with nothing arriving.

This test puts a proxy in front of sshd and then makes it stop forwarding
without closing anything, which is exactly that failure. The session should be
declared dead after keepalive_interval × (count_max + 1) seconds and come back
on its own.
"""

from __future__ import annotations

import json
import os
import socket
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from e2e_reconnect import Pty  # noqa: E402

UPSTREAM = ("127.0.0.1", 2222)
LISTEN = ("127.0.0.1", 2223)


class BlackholeProxy(threading.Thread):
    """Forwards TCP until told to go quiet, then holds the sockets open."""

    def __init__(self) -> None:
        super().__init__(daemon=True, name="blackhole-proxy")
        self.blackhole = threading.Event()
        self.connections = 0
        self._server = socket.socket()
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind(LISTEN)
        self._server.listen(8)
        self._running = True

    def run(self) -> None:
        while self._running:
            try:
                client, _ = self._server.accept()
            except OSError:
                return
            self.connections += 1
            try:
                upstream = socket.create_connection(UPSTREAM, timeout=5)
            except OSError:
                client.close()
                continue
            for src, dst in ((client, upstream), (upstream, client)):
                threading.Thread(target=self._pump, args=(src, dst), daemon=True).start()

    def _pump(self, src: socket.socket, dst: socket.socket) -> None:
        src.settimeout(0.5)
        while self._running:
            try:
                data = src.recv(65536)
            except socket.timeout:
                continue
            except OSError:
                break
            if not data:
                break
            # The point of the test: swallow the bytes, keep the socket open.
            if self.blackhole.is_set():
                continue
            try:
                dst.sendall(data)
            except OSError:
                break
        if not self.blackhole.is_set():
            for sock in (src, dst):
                try:
                    sock.close()
                except OSError:
                    pass

    def stop(self) -> None:
        self._running = False
        try:
            self._server.close()
        except OSError:
            pass


def build_store(tmp: Path, key: Path) -> Path:
    payload = {
        "version": 1,
        "sessions": [
            {
                "name": "flaky",
                "host": LISTEN[0],
                "port": LISTEN[1],
                "username": os.environ.get("USER", "root"),
                "auth": "key",
                "key_path": str(key),
                "host_key_policy": "auto",
                "keepalive_interval": 4,
                "keepalive_count_max": 2,
                "tcp_keepalive": True,
                "auto_reconnect": True,
                "reconnect_delay": 1.0,
                "reconnect_max_delay": 3.0,
                "reconnect_attempts": 4,
            }
        ],
    }
    path = tmp / "sessions-keepalive.json"
    path.write_text(json.dumps(payload, indent=2))
    return path


def main() -> int:
    key = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.home() / ".ssh" / "id_test"
    tmp = Path("/tmp/pytty-e2e")
    tmp.mkdir(exist_ok=True)
    store = build_store(tmp, key)

    proxy = BlackholeProxy()
    proxy.start()

    env = dict(os.environ, PYTTY_HOME=str(tmp), TERM="xterm-256color", PYTHONUNBUFFERED="1")
    session = Pty([sys.executable, "-m", "pytty", "flaky", "--config", str(store)], env)

    failures: list[str] = []
    try:
        print("· connecting through the proxy")
        session.expect(r"Connected to 127\.0\.0\.1")
        time.sleep(1.0)
        session.send(b"echo BEFORE_BLACKHOLE_$((2*11))\n")
        session.expect(r"BEFORE_BLACKHOLE_22")

        print("· black-holing the link, no FIN and no RST")
        session.buffer = b""
        blackholed_at = time.monotonic()
        proxy.blackhole.set()

        print("· waiting for missed keepalives")
        session.expect(r"No keepalive reply \(1/2\)", timeout=25)
        session.expect(r"No keepalive reply \(2/2\)", timeout=25)
        session.expect(r"Peer stopped answering", timeout=25)
        detected = time.monotonic() - blackholed_at
        print(f"  dead peer detected after {detected:.1f}s (budget 4 × 3 = 12s)")
        if detected > 20:
            failures.append(f"detection took {detected:.1f}s, expected under 20s")

        print("· waiting for the automatic reconnect")
        proxy.blackhole.clear()
        session.expect(r"Connected to 127\.0\.0\.1", timeout=40)
        time.sleep(1.0)
        session.send(b"echo AFTER_BLACKHOLE_$((9*9))\n")
        session.expect(r"AFTER_BLACKHOLE_81")

        print("· detaching")
        session.send(b"\x1d")
        session.expect(r"flaky: detached", timeout=10)
        if session.proc.wait(timeout=10) != 0:
            failures.append("non-zero exit code")
    except AssertionError as exc:
        failures.append(str(exc))
    finally:
        session.close()
        proxy.stop()

    if failures:
        print("\nFAILED")
        for failure in failures:
            print(failure)
        return 1
    print("\nDead peer detection works.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
