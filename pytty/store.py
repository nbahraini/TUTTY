"""Persistence for sessions, passwords and host keys."""

from __future__ import annotations

import json
import os
import stat
import tempfile
import time
from pathlib import Path

from .model import Session

APP_NAME = "pytty"
KEYRING_SERVICE = "pytty"
KEYRING_PROXY_SERVICE = "pytty-proxy"


def config_home() -> Path:
    override = os.environ.get("PYTTY_HOME")
    if override:
        return Path(override).expanduser()
    if os.name == "nt":
        base = os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming"
        return Path(base) / APP_NAME
    base = os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config"
    return Path(base) / APP_NAME


def atomic_write_json(path: Path, payload: object) -> None:
    """Write JSON to `path` atomically and chmod 600.

    Both the session list and the settings file name hosts and usernames, so
    both get the same treatment: no half-written file after a crash, and no
    world-readable copy left behind.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.stem}-")
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
            handle.write("\n")
        os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def _as_list(value: object) -> list[str]:
    """paramiko returns some directives as a list and some as a bare string."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return [str(item) for item in value]


def _forward_specs(value: object) -> list[str]:
    """Turn ssh_config's ``8080 localhost:80`` into pytty's ``8080:localhost:80``."""
    specs: list[str] = []
    for entry in _as_list(value):
        parts = entry.split()
        if len(parts) == 2:
            specs.append(f"{parts[0]}:{parts[1]}")
        elif len(parts) == 1 and parts[0].count(":") >= 2:
            specs.append(parts[0])
    return specs


class SessionStore:
    """Reads and writes ``sessions.json``.

    Files are written atomically and chmod 600, because a session file names
    every host you care about even when it holds no secrets.
    """

    def __init__(self, path: Path | None = None) -> None:
        self.path = Path(path) if path else config_home() / "sessions.json"
        self._sessions: dict[str, Session] = {}
        self.load()

    # ------------------------------------------------------------------
    def load(self) -> None:
        self._sessions = {}
        if not self.path.exists():
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"Cannot read {self.path}: {exc}") from exc
        for entry in raw.get("sessions", []):
            try:
                session = Session.from_dict(entry)
            except TypeError:
                continue
            if session.name:
                self._sessions[session.name] = session

    def save(self) -> None:
        atomic_write_json(
            self.path,
            {"version": 1, "sessions": [s.to_dict() for s in self.sorted()]},
        )

    # ------------------------------------------------------------------
    def sorted(self) -> list[Session]:
        return sorted(self._sessions.values(), key=lambda s: (s.group.lower(), s.name.lower()))

    def groups(self) -> list[str]:
        return sorted({s.group or "Ungrouped" for s in self._sessions.values()}, key=str.lower)

    def get(self, name: str) -> Session | None:
        return self._sessions.get(name)

    def __contains__(self, name: object) -> bool:
        return name in self._sessions

    def __len__(self) -> int:
        return len(self._sessions)

    def add(self, session: Session) -> None:
        session.validate()
        if session.name in self._sessions:
            raise ValueError(f"A session named {session.name!r} already exists.")
        self._sessions[session.name] = session
        self.save()

    def update(self, original_name: str, session: Session) -> None:
        session.validate()
        if original_name != session.name and session.name in self._sessions:
            raise ValueError(f"A session named {session.name!r} already exists.")
        self._sessions.pop(original_name, None)
        self._sessions[session.name] = session
        self.save()

    def delete(self, name: str) -> None:
        if self._sessions.pop(name, None) is not None:
            forget_password(name)
            forget_proxy_password(name)
            self.save()

    def touch(self, name: str) -> None:
        session = self._sessions.get(name)
        if session:
            session.last_used = time.time()
            self.save()

    def unique_name(self, base: str) -> str:
        if base not in self._sessions:
            return base
        index = 2
        while f"{base} ({index})" in self._sessions:
            index += 1
        return f"{base} ({index})"

    # ------------------------------------------------------------------
    def import_ssh_config(self, path: Path | None = None) -> list[Session]:
        """Pull hosts out of ~/.ssh/config. Wildcard entries are skipped."""
        import paramiko

        path = path or Path.home() / ".ssh" / "config"
        if not path.exists():
            return []
        config = paramiko.SSHConfig()
        with path.open(encoding="utf-8") as handle:
            config.parse(handle)
        added: list[Session] = []
        for host in config.get_hostnames():
            if "*" in host or "?" in host or host in self._sessions:
                continue
            entry = config.lookup(host)
            session = Session(
                name=host,
                group="Imported",
                host=entry.get("hostname", host),
                port=int(entry.get("port", 22)),
                username=entry.get("user", ""),
            )
            identity = entry.get("identityfile")
            if identity:
                session.auth = "key"
                session.key_path = str(Path(identity[0]).expanduser())
            proxy_jump = entry.get("proxyjump")
            if proxy_jump:
                session.jump_host = proxy_jump
            session.local_forwards = _forward_specs(entry.get("localforward"))
            session.remote_forwards = _forward_specs(entry.get("remoteforward"))
            session.dynamic_forwards = [
                spec.strip()
                for spec in _as_list(entry.get("dynamicforward"))
                if spec.strip()
            ]
            try:
                session.validate()
            except Exception:
                continue
            self._sessions[session.name] = session
            added.append(session)
        if added:
            self.save()
        return added


# ----------------------------------------------------------------------
# Passwords. Stored in the OS keyring when one is available, never in the
# session file.
# ----------------------------------------------------------------------
def keyring_available() -> bool:
    try:
        import keyring
        from keyring.backends.fail import Keyring as FailKeyring
    except Exception:
        return False
    try:
        return not isinstance(keyring.get_keyring(), FailKeyring)
    except Exception:
        return False


def load_password(session_name: str) -> str | None:
    if not keyring_available():
        return None
    import keyring

    try:
        return keyring.get_password(KEYRING_SERVICE, session_name)
    except Exception:
        return None


def store_password(session_name: str, password: str) -> bool:
    if not keyring_available():
        return False
    import keyring

    try:
        keyring.set_password(KEYRING_SERVICE, session_name, password)
        return True
    except Exception:
        return False


def forget_password(session_name: str) -> None:
    if not keyring_available():
        return
    import keyring

    try:
        keyring.delete_password(KEYRING_SERVICE, session_name)
    except Exception:
        pass


# ----------------------------------------------------------------------
# Proxy passwords. A separate keyring service, so a proxy credential can
# never collide with a session that happens to share its name.
# ----------------------------------------------------------------------
GLOBAL_PROXY_ACCOUNT = "global"


def proxy_account(session_name: str | None = None) -> str:
    return f"session:{session_name}" if session_name else GLOBAL_PROXY_ACCOUNT


def load_proxy_password(session_name: str | None = None) -> str | None:
    if not keyring_available():
        return None
    import keyring

    try:
        return keyring.get_password(KEYRING_PROXY_SERVICE, proxy_account(session_name))
    except Exception:
        return None


def store_proxy_password(password: str, session_name: str | None = None) -> bool:
    if not keyring_available():
        return False
    import keyring

    try:
        keyring.set_password(KEYRING_PROXY_SERVICE, proxy_account(session_name), password)
        return True
    except Exception:
        return False


def forget_proxy_password(session_name: str | None = None) -> None:
    if not keyring_available():
        return
    import keyring

    try:
        keyring.delete_password(KEYRING_PROXY_SERVICE, proxy_account(session_name))
    except Exception:
        pass


def known_hosts_path() -> Path:
    path = config_home() / "known_hosts"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path
