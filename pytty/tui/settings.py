"""Application settings: the proxy that every session uses by default."""

from __future__ import annotations

import threading
from dataclasses import replace

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Static, Switch

from ..proxy import ProxyError, probe
from ..settings import Settings
from ..store import load_proxy_password, store_proxy_password
from .edit import ProxyFieldSet, field


class SettingsScreen(ModalScreen["Settings | None"]):
    """Edit the application-wide proxy.

    The proxy lives here rather than on each session because it describes
    where you are sitting, not what you are dialling: move behind a corporate
    proxy and one setting changes instead of forty.
    """

    BINDINGS = [
        ("escape", "cancel", "Cancel"),
        ("ctrl+s", "save", "Save"),
        ("ctrl+t", "test", "Test"),
    ]

    def __init__(self, settings: Settings, test_target: str = "") -> None:
        super().__init__()
        self.settings = settings
        # Something real to test against, so the button proves the whole path
        # rather than only that the proxy is listening.
        self.test_target = test_target
        self.proxy_fields = ProxyFieldSet(
            settings.proxy,
            prefix="s-proxy",
            password=load_proxy_password() or "" if settings.proxy.save_password else "",
        )

    # ------------------------------------------------------------------
    def compose(self) -> ComposeResult:
        with Vertical(id="editor"):
            yield Static("Settings", id="editor-title")
            with VerticalScroll():
                yield Static(
                    "Every session set to “use the application proxy” goes through "
                    "this. Sessions can override it individually on their Proxy tab.",
                    classes="hint",
                )
                yield from self.proxy_fields.compose()
                yield from field(
                    "Fall back to the environment",
                    Switch(
                        self.settings.use_environment_proxy,
                        id="s-use-environment",
                        classes="field-switch",
                    ),
                    "When no proxy is set here, use ALL_PROXY, HTTPS_PROXY or "
                    "HTTP_PROXY if they are set.",
                )
                yield Static("", id="settings-origin", classes="hint")
                yield from field(
                    "Test against",
                    Input(
                        self.test_target,
                        placeholder="host:port to try, e.g. github.com:22",
                        id="s-test-target",
                        classes="field-input",
                    ),
                    "Test opens a tunnel to this host and closes it again.",
                )
            yield Static("", id="editor-status")
            with Horizontal(id="editor-buttons"):
                yield Button("Cancel", id="cancel")
                yield Button("Test", id="test")
                yield Button("Save", id="save", classes="primary")

    def on_mount(self) -> None:
        self.query_one("#s-proxy-scheme").focus()
        self._refresh_origin()

    def _refresh_origin(self) -> None:
        origin = self.settings.proxy_origin()
        text = {
            "settings": "In force: the proxy configured here.",
            "environment": (
                "In force: a proxy from the environment, because none is set here."
            ),
            "none": "In force: none. Sessions connect directly.",
        }.get(origin, "")
        self.query_one("#settings-origin", Static).update(text)

    # ------------------------------------------------------------------
    def _collect(self) -> Settings:
        return replace(
            self.settings,
            proxy=self.proxy_fields.collect(self),
            use_environment_proxy=self.query_one("#s-use-environment", Switch).value,
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "save":
            self.action_save()
        elif event.button.id == "test":
            self.action_test()
        else:
            self.action_cancel()

    # ------------------------------------------------------------------
    def action_save(self) -> None:
        candidate = self._collect()
        try:
            candidate.proxy.validate()
        except ValueError as exc:
            self.query_one("#editor-status", Static).update(str(exc))
            return
        if candidate.proxy.enabled and candidate.proxy.save_password:
            password = self.proxy_fields.collect_password(self)
            if password:
                store_proxy_password(password)
        self.dismiss(candidate)

    def action_cancel(self) -> None:
        self.dismiss(None)

    # ------------------------------------------------------------------
    def action_test(self) -> None:
        """Open and drop a tunnel through the proxy, to prove it works.

        A test that only says "failed" is not worth having, so the specific
        error from the handshake is what gets shown.
        """
        status = self.query_one("#editor-status", Static)
        try:
            candidate = self._collect()
            candidate.proxy.validate()
        except ValueError as exc:
            status.update(str(exc))
            return
        if not candidate.proxy.enabled:
            status.update("No proxy configured, so there is nothing to test.")
            return

        target = self.query_one("#s-test-target", Input).value.strip() or self.test_target
        if not target:
            status.update("Nothing to test against — highlight a session first.")
            return
        host, _, raw_port = target.rpartition(":")
        if not host:
            host, raw_port = target, "22"
        try:
            port = int(raw_port)
        except ValueError:
            status.update(f"Cannot read a port from {target!r}.")
            return

        status.update(f"Testing {candidate.proxy.describe()} → {host}:{port}…")
        password = self.proxy_fields.collect_password(self) or load_proxy_password()
        self._run_probe(candidate, host, port, password)

    def _run_probe(self, settings: Settings, host: str, port: int, password: str | None) -> None:
        """Probe on a worker thread, because the handshake can block for seconds.

        Doing this inline would freeze the interface for as long as the proxy
        takes to answer, which on a broken proxy is the whole timeout.
        """
        status = self.query_one("#editor-status", Static)
        app = self.app

        def work() -> None:
            try:
                message = probe(settings.proxy, host, port, password=password)
            except (ProxyError, OSError) as exc:
                message = f"Test failed: {exc}"
            except Exception as exc:  # a bug here must not kill the thread silently
                message = f"Test failed: {exc.__class__.__name__}: {exc}"
            try:
                app.call_from_thread(status.update, message)
            except Exception:
                pass

        threading.Thread(target=work, daemon=True, name="pytty-proxy-test").start()
