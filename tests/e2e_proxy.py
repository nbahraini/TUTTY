"""End to end: the real CLI reaching a real sshd through a real proxy.

Needs an sshd on 127.0.0.1:2222 and a key it accepts, the same as the other
e2e scripts:

    python tests/e2e_proxy.py KEYFILE

Both proxies are stood up in this process, so there is nothing to install.
The point is to prove the whole path — argument parsing, proxy handshake,
socket handover to paramiko, SSH banner, login, command — rather than any one
layer of it.
"""

from __future__ import annotations

import os
import pty
import re
import select
import socket
import socketserver
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

SSH_HOST = "127.0.0.1"
SSH_PORT = 2222


# ----------------------------------------------------------------------
# Throwaway proxies
# ----------------------------------------------------------------------
def recv_n(sock: socket.socket, count: int) -> bytes:
    """Exact read. recv is free to return short even on loopback."""
    out = bytearray()
    while len(out) < count:
        chunk = sock.recv(count - len(out))
        if not chunk:
            break
        out += chunk
    return bytes(out)


def _pump(a: socket.socket, b: socket.socket) -> None:
    try:
        while True:
            readable, _, _ = select.select([a, b], [], [], 30)
            if not readable:
                return
            for source in readable:
                target = b if source is a else a
                data = source.recv(65536)
                if not data:
                    return
                target.sendall(data)
    except OSError:
        pass


class Socks5Handler(socketserver.BaseRequestHandler):
    """A minimal SOCKS5 CONNECT proxy, optionally demanding a password."""

    username = ""
    password = ""
    seen: list[str] = []

    def handle(self) -> None:
        sock = self.request
        try:
            head = recv_n(sock, 2)
            count = head[1]
            methods = recv_n(sock, count)
            if self.username:
                if 0x02 not in methods:
                    sock.sendall(b"\x05\xff")
                    return
                sock.sendall(b"\x05\x02")
                recv_n(sock, 1)
                user = recv_n(sock, recv_n(sock, 1)[0]).decode()
                secret = recv_n(sock, recv_n(sock, 1)[0]).decode()
                if (user, secret) != (self.username, self.password):
                    sock.sendall(b"\x01\x01")
                    return
                sock.sendall(b"\x01\x00")
            else:
                sock.sendall(b"\x05\x00")

            request = recv_n(sock, 4)
            kind = request[3]
            if kind == 0x01:
                host = socket.inet_ntoa(recv_n(sock, 4))
            elif kind == 0x03:
                host = recv_n(sock, recv_n(sock, 1)[0]).decode()
            else:
                sock.sendall(b"\x05\x08" + b"\x00" * 8)
                return
            port = int.from_bytes(recv_n(sock, 2), "big")
            if not port:
                # A short request means the client left the port off.
                raise OSError("incomplete SOCKS5 request: no destination port")
            type(self).seen.append(f"{host}:{port}")

            upstream = socket.create_connection((host, port), timeout=10)
            sock.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)
            _pump(sock, upstream)
            upstream.close()
        except (OSError, IndexError):
            pass


class HttpHandler(socketserver.BaseRequestHandler):
    """A minimal HTTP CONNECT proxy."""

    seen: list[str] = []

    def handle(self) -> None:
        sock = self.request
        try:
            head = bytearray()
            while not head.endswith(b"\r\n\r\n"):
                chunk = sock.recv(1)
                if not chunk:
                    return
                head += chunk
            match = re.match(rb"CONNECT ([^:]+):(\d+)", bytes(head))
            if not match:
                sock.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                return
            host = match.group(1).decode()
            port = int(match.group(2))
            type(self).seen.append(f"{host}:{port}")
            upstream = socket.create_connection((host, port), timeout=10)
            sock.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            _pump(sock, upstream)
            upstream.close()
        except OSError:
            pass


class Proxy(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address) -> None:  # noqa: ANN001
        pass


def start(handler) -> tuple[Proxy, int]:
    server = Proxy(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


# ----------------------------------------------------------------------
# Driving the real CLI through a pty
# ----------------------------------------------------------------------
def run_cli(args: list[str], expect: str, timeout: float = 40.0) -> tuple[bool, str]:
    """Run pytty on a real pty, send a command, and look for its output."""
    marker = f"PROXY-OK-{os.getpid()}"
    primary, secondary = pty.openpty()
    process = subprocess.Popen(
        [sys.executable, "-m", "pytty", *args],
        stdin=secondary,
        stdout=secondary,
        stderr=secondary,
        close_fds=True,
        cwd=str(Path(__file__).resolve().parent.parent),
        env={**os.environ, "TERM": "xterm-256color"},
    )
    os.close(secondary)

    output = bytearray()
    deadline = time.monotonic() + timeout
    sent = False
    found = False
    try:
        while time.monotonic() < deadline:
            readable, _, _ = select.select([primary], [], [], 0.5)
            if readable:
                try:
                    chunk = os.read(primary, 65536)
                except OSError:
                    break
                if not chunk:
                    break
                output += chunk
            text = output.decode("utf-8", "replace")
            if not sent and "Connected to" in text:
                time.sleep(1.5)  # let the remote prompt settle
                os.write(primary, f"echo {marker}\n".encode())
                sent = True
            if marker in text and text.count(marker) >= 2:
                found = True
                break
            if process.poll() is not None and not readable:
                break
    finally:
        try:
            os.write(primary, b"\x1d")  # ctrl+] detaches
            time.sleep(0.5)
        except OSError:
            pass
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
        os.close(primary)

    text = output.decode("utf-8", "replace")
    if expect and expect not in text:
        return False, text
    return found, text


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    key = str(Path(argv[1]).expanduser())
    user = os.environ.get("USER") or "root"
    target = f"{user}@{SSH_HOST}"
    # The test sshd is on loopback, which the default <local> exclusion would
    # send direct — clear the list so the proxy is genuinely exercised.
    base = [
        target, "-p", str(SSH_PORT), "-i", key,
        "--no-reconnect", "--yes", "--proxy-exclude", "none",
    ]

    problems: list[str] = []

    # 1. SOCKS5, no credentials.
    Socks5Handler.seen = []
    server, port = start(Socks5Handler)
    ok, text = run_cli(base + ["--proxy", f"socks5h://127.0.0.1:{port}"], "Connected to")
    server.shutdown()
    if not ok:
        problems.append(f"socks5: no command output\n{text[-1200:]}")
    elif not Socks5Handler.seen:
        problems.append("socks5: the proxy was never asked to connect")
    else:
        print(f"  socks5   proxy saw {Socks5Handler.seen[0]}")

    # 2. SOCKS5 with username and password.
    Socks5Handler.seen = []
    Socks5Handler.username, Socks5Handler.password = "bob", "hunter2"
    server, port = start(Socks5Handler)
    ok, text = run_cli(
        base + ["--proxy", f"socks5h://bob:hunter2@127.0.0.1:{port}"], "Connected to"
    )
    server.shutdown()
    Socks5Handler.username = Socks5Handler.password = ""
    if not ok:
        problems.append(f"socks5 auth: no command output\n{text[-1200:]}")
    else:
        print("  socks5   username and password accepted")

    # 3. Wrong password must fail, and say so rather than hanging.
    Socks5Handler.username, Socks5Handler.password = "bob", "hunter2"
    server, port = start(Socks5Handler)
    ok, text = run_cli(base + ["--proxy", f"socks5://bob:wrong@127.0.0.1:{port}"], "")
    server.shutdown()
    Socks5Handler.username = Socks5Handler.password = ""
    if "rejected the username" not in text:
        problems.append(f"socks5 bad password was not reported clearly\n{text[-800:]}")
    else:
        print("  socks5   a bad password is reported, not hung on")

    # 4. HTTP CONNECT.
    HttpHandler.seen = []
    server, port = start(HttpHandler)
    ok, text = run_cli(base + ["--proxy", f"http://127.0.0.1:{port}"], "Connected to")
    server.shutdown()
    if not ok:
        problems.append(f"http: no command output\n{text[-1200:]}")
    elif not HttpHandler.seen:
        problems.append("http: the proxy was never asked to connect")
    else:
        print(f"  http     proxy saw {HttpHandler.seen[0]}")

    # 5. A dead proxy must fail fast with a message naming the proxy.
    ok, text = run_cli(base + ["--proxy", "socks5://127.0.0.1:1"], "")
    if "Cannot reach proxy" not in text:
        problems.append(f"a dead proxy was not reported clearly\n{text[-800:]}")
    else:
        print("  error    an unreachable proxy names the proxy, not the host")

    # 6. --no-proxy must ignore a proxy in the environment.
    os.environ["ALL_PROXY"] = "socks5://127.0.0.1:1"
    try:
        ok, text = run_cli(base + ["--no-proxy"], "Connected to")
    finally:
        os.environ.pop("ALL_PROXY", None)
    if not ok:
        problems.append(f"--no-proxy did not bypass ALL_PROXY\n{text[-1200:]}")
    else:
        print("  env      --no-proxy ignores ALL_PROXY")

    if problems:
        print("\nFAILED")
        for problem in problems:
            print(" ", problem)
        return 1
    print("\nProxy end-to-end checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
