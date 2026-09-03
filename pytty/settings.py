"""Application-wide settings, kept apart from the session list.

The proxy lives here rather than on every session because it is a property of
where you are sitting, not of the machine you are dialling. Move your laptop
behind a corporate proxy and one setting changes, not forty.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .proxy import ProxyConfig, from_environment
from .store import atomic_write_json, config_home


@dataclass
class Settings:
    """Everything that applies to the whole application."""

    proxy: ProxyConfig = field(default_factory=ProxyConfig)
    # When no proxy is configured, fall back to ALL_PROXY / HTTPS_PROXY /
    # HTTP_PROXY from the environment.
    use_environment_proxy: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "proxy": self.proxy.to_dict(),
            "use_environment_proxy": self.use_environment_proxy,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Settings":
        settings = cls()
        if isinstance(raw.get("proxy"), (dict, str)):
            settings.proxy = ProxyConfig.from_dict(raw["proxy"])
        if "use_environment_proxy" in raw:
            settings.use_environment_proxy = bool(raw["use_environment_proxy"])
        return settings

    # ------------------------------------------------------------------
    def resolved_proxy(self) -> tuple[ProxyConfig, str | None]:
        """The proxy actually in force, and any password that came with it.

        An explicitly configured proxy always wins. The environment is only
        consulted when nothing is configured, so setting the proxy to "none"
        in the interface really does mean none.
        """
        if self.proxy.enabled:
            return self.proxy, None
        if self.use_environment_proxy:
            return from_environment()
        return ProxyConfig(), None

    def proxy_origin(self) -> str:
        """Where the proxy in force came from, for the interface to display."""
        if self.proxy.enabled:
            return "settings"
        if self.use_environment_proxy and from_environment()[0].enabled:
            return "environment"
        return "none"


class SettingsStore:
    """Reads and writes ``settings.json`` next to the session list."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = Path(path) if path else config_home() / "settings.json"
        self.settings = Settings()
        self.load()

    def load(self) -> None:
        if not self.path.exists():
            self.settings = Settings()
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            # A broken settings file must not stop you connecting. Fall back
            # to defaults and let the caller surface the problem.
            raise RuntimeError(f"Cannot read {self.path}: {exc}") from exc
        if not isinstance(raw, dict):
            raw = {}
        self.settings = Settings.from_dict(raw.get("settings", raw))

    def save(self) -> None:
        self.settings.proxy.validate()
        atomic_write_json(self.path, {"version": 1, "settings": self.settings.to_dict()})

    def update(self, settings: Settings) -> None:
        self.settings = settings
        self.save()
