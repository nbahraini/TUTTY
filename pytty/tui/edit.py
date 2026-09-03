"""The session editor."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
    Input,
    Select,
    Static,
    Switch,
    TabbedContent,
    TabPane,
    TextArea,
)

from ..model import (
    ADDRESS_FAMILIES,
    AUTH_METHODS,
    HOST_KEY_POLICIES,
    LOG_MODES,
    PROXY_MODES,
    Session,
    ValidationError,
)
from ..proxy import PROXY_SCHEMES, SCHEME_LABELS, ProxyConfig
from ..store import keyring_available, load_proxy_password, store_proxy_password

AUTH_LABELS = {
    "auto": "Try keys and agent, then ask",
    "agent": "SSH agent only",
    "key": "Private key file",
    "password": "Password",
    "ask": "Always ask for a password",
}

PROXY_MODE_LABELS = {
    "global": "Use the application proxy",
    "none": "Connect directly, ignore the application proxy",
    "custom": "Use a proxy just for this session",
}

FAMILY_LABELS = {
    "auto": "Whatever the name resolves to",
    "ipv4": "IPv4 only",
    "ipv6": "IPv6 only",
}

LOG_MODE_LABELS = {
    "off": "Do not log this session",
    "output": "Log what the server sends",
    "all": "Log server output and my keystrokes",
}

POLICY_LABELS = {
    "ask": "Ask before trusting a new host",
    "strict": "Refuse unknown hosts",
    "auto": "Trust any host key (unsafe)",
}


def field(label: str, widget: Any, hint: str = "") -> ComposeResult:
    """One labelled row, with an optional line of explanation beneath it."""
    with Horizontal(classes="field" if hint else "field spaced"):
        yield Static(label, classes="field-label")
        yield widget
    if hint:
        yield Static(hint, classes="hint")


class ProxyFieldSet:
    """The proxy controls, shared by the session editor and the settings screen.

    Both places need exactly the same eight fields, and a proxy dialog that
    disagrees with itself depending on where you opened it would be its own
    kind of bug.
    """

    def __init__(self, config: ProxyConfig, prefix: str, password: str = "") -> None:
        self.config = config
        self.prefix = prefix
        self.password = password

    def _id(self, name: str) -> str:
        return f"{self.prefix}-{name}"

    def compose(self) -> ComposeResult:
        c = self.config
        yield from field(
            "Proxy type",
            Select(
                [(SCHEME_LABELS[s], s) for s in PROXY_SCHEMES],
                value=c.scheme if c.scheme in PROXY_SCHEMES else "none",
                allow_blank=False,
                id=self._id("scheme"),
                classes="field-input",
            ),
        )
        yield from field(
            "Proxy host",
            Input(c.host, placeholder="proxy.example.com", id=self._id("host"),
                  classes="field-input"),
        )
        yield from field(
            "Proxy port",
            Input(
                str(c.port or ""),
                type="integer",
                placeholder="8080 for HTTP, 1080 for SOCKS",
                id=self._id("port"),
                classes="field-input",
            ),
        )
        yield from field(
            "Username",
            Input(c.username, placeholder="leave empty if the proxy is open",
                  id=self._id("username"), classes="field-input"),
        )
        yield from field(
            "Password",
            Input(
                self.password,
                password=True,
                placeholder="asked for if left empty",
                id=self._id("password"),
                classes="field-input",
            ),
        )
        yield from field(
            "Remember password",
            Switch(c.save_password, id=self._id("save-password"), classes="field-switch"),
            self._keyring_hint(),
        )
        yield from field(
            "Resolve names at the proxy",
            Switch(c.remote_dns, id=self._id("remote-dns"), classes="field-switch"),
            "Usually what you want: internal names resolve on the far side.",
        )
        yield from field(
            "Check the proxy's certificate",
            Switch(c.tls_verify, id=self._id("tls-verify"), classes="field-switch"),
            "Only applies to an HTTPS proxy, where TLS is to the proxy itself.",
        )
        yield Static(
            "Reached directly, one per line: <local>, *.internal, 10.0.0.0/8",
            classes="hint",
        )
        yield TextArea(
            "\n".join(c.exclude), id=self._id("exclude"), classes="field-area"
        )

    @staticmethod
    def _keyring_hint() -> str:
        if keyring_available():
            return "Stored in the system keyring, never in a configuration file."
        return "No system keyring found, so the password is asked for each time."

    # ------------------------------------------------------------------
    def collect(self, screen: ModalScreen) -> ProxyConfig:
        def text(name: str) -> str:
            return screen.query_one(f"#{self._id(name)}", Input).value.strip()

        def switch(name: str) -> bool:
            return screen.query_one(f"#{self._id(name)}", Switch).value

        raw_port = text("port")
        exclude = [
            line.strip()
            for line in screen.query_one(f"#{self._id('exclude')}", TextArea).text.splitlines()
            if line.strip()
        ]
        return ProxyConfig(
            scheme=str(screen.query_one(f"#{self._id('scheme')}", Select).value),
            host=text("host"),
            port=int(raw_port) if raw_port.isdigit() else 0,
            username=text("username"),
            save_password=switch("save-password"),
            remote_dns=switch("remote-dns"),
            tls_verify=switch("tls-verify"),
            exclude=exclude,
        )

    def collect_password(self, screen: ModalScreen) -> str:
        return screen.query_one(f"#{self._id('password')}", Input).value


class EditScreen(ModalScreen["Session | None"]):
    """Edit one session. Returns the edited copy, or None if cancelled."""

    BINDINGS = [
        ("escape", "cancel", "Cancel"),
        ("ctrl+s", "save", "Save"),
    ]

    def __init__(self, session: Session, title: str = "Edit session") -> None:
        super().__init__()
        self.session = session
        self.title_text = title
        self.proxy_fields = ProxyFieldSet(
            session.proxy,
            prefix="f-proxy",
            password=(
                load_proxy_password(session.name) or ""
                if session.proxy.save_password
                else ""
            ),
        )

    # ------------------------------------------------------------------
    def compose(self) -> ComposeResult:
        s = self.session
        with Vertical(id="editor"):
            yield Static(self.title_text, id="editor-title")

            with TabbedContent():
                with TabPane("Connection", id="tab-connection"):
                    with VerticalScroll():
                        yield from field(
                            "Name",
                            Input(s.name, id="f-name", classes="field-input"),
                        )
                        yield from field(
                            "Group",
                            Input(
                                s.group,
                                placeholder="Ungrouped",
                                id="f-group",
                                classes="field-input",
                            ),
                        )
                        yield from field(
                            "Host",
                            Input(
                                s.host,
                                placeholder="hostname or IP",
                                id="f-host",
                                classes="field-input",
                            ),
                        )
                        yield from field(
                            "Port",
                            Input(
                                str(s.port), type="integer", id="f-port", classes="field-input"
                            ),
                        )
                        yield from field(
                            "Username",
                            Input(s.username, id="f-username", classes="field-input"),
                        )
                        yield from field(
                            "Terminal type",
                            Input(s.term, id="f-term", classes="field-input"),
                        )
                        yield from field(
                            "Run instead of shell",
                            Input(
                                s.remote_command,
                                placeholder="leave empty for a login shell",
                                id="f-remote-command",
                                classes="field-input",
                            ),
                        )

                with TabPane("Authentication", id="tab-auth"):
                    with VerticalScroll():
                        yield from field(
                            "Method",
                            Select(
                                [(AUTH_LABELS[m], m) for m in AUTH_METHODS],
                                value=s.auth,
                                allow_blank=False,
                                id="f-auth",
                                classes="field-input",
                            ),
                        )
                        yield from field(
                            "Private key",
                            Input(
                                s.key_path,
                                placeholder="~/.ssh/id_ed25519",
                                id="f-key-path",
                                classes="field-input",
                            ),
                        )
                        yield from field(
                            "Remember password",
                            Switch(s.save_password, id="f-save-password", classes="field-switch"),
                            self._keyring_hint(),
                        )
                        yield from field(
                            "Host keys",
                            Select(
                                [(POLICY_LABELS[p], p) for p in HOST_KEY_POLICIES],
                                value=s.host_key_policy,
                                allow_blank=False,
                                id="f-host-key-policy",
                                classes="field-input",
                            ),
                        )
                        yield from field(
                            "Forward the agent",
                            Switch(s.forward_agent, id="f-forward-agent", classes="field-switch"),
                        )

                with TabPane("Keepalive", id="tab-keepalive"):
                    with VerticalScroll():
                        yield Static("", id="keepalive-summary", classes="hint")
                        yield from field(
                            "Probe every",
                            Input(
                                str(s.keepalive_interval),
                                type="integer",
                                id="f-keepalive-interval",
                                classes="field-input",
                            ),
                            "Seconds between liveness probes. 0 turns probing off.",
                        )
                        yield from field(
                            "Drop after",
                            Input(
                                str(s.keepalive_count_max),
                                type="integer",
                                id="f-keepalive-count-max",
                                classes="field-input",
                            ),
                            "Unanswered probes tolerated before the link counts as dead.",
                        )
                        yield from field(
                            "TCP keepalive",
                            Switch(s.tcp_keepalive, id="f-tcp-keepalive", classes="field-switch"),
                            "Also ask the operating system to watch the socket.",
                        )
                        yield from field(
                            "Null packets",
                            Switch(s.null_packets, id="f-null-packets", classes="field-switch"),
                            "For firewalls that only count terminal data as traffic.",
                        )

                with TabPane("Reconnect", id="tab-reconnect"):
                    with VerticalScroll():
                        yield Static("", id="reconnect-summary", classes="hint")
                        yield from field(
                            "Reconnect on drop",
                            Switch(
                                s.auto_reconnect, id="f-auto-reconnect", classes="field-switch"
                            ),
                        )
                        yield from field(
                            "First wait",
                            Input(
                                f"{s.reconnect_delay:g}",
                                type="number",
                                id="f-reconnect-delay",
                                classes="field-input",
                            ),
                            "Seconds before the first retry. Doubles after each failure.",
                        )
                        yield from field(
                            "Longest wait",
                            Input(
                                f"{s.reconnect_max_delay:g}",
                                type="number",
                                id="f-reconnect-max-delay",
                                classes="field-input",
                            ),
                        )
                        yield from field(
                            "Attempt limit",
                            Input(
                                str(s.reconnect_attempts),
                                type="integer",
                                id="f-reconnect-attempts",
                                classes="field-input",
                            ),
                            "0 keeps retrying until you stop it.",
                        )
                        yield from field(
                            "Also on clean exit",
                            Switch(
                                s.reconnect_on_remote_exit,
                                id="f-reconnect-on-remote-exit",
                                classes="field-switch",
                            ),
                            "Reconnect even when the remote shell exits normally.",
                        )
                        yield Static("Commands to replay after every login", classes="hint")
                        yield TextArea(
                            "\n".join(s.login_commands),
                            id="f-login-commands",
                            classes="field-area",
                        )

                with TabPane("Tunnels", id="tab-tunnels"):
                    with VerticalScroll():
                        yield from field(
                            "Jump hosts",
                            Input(
                                s.jump_host,
                                placeholder="user@bastion:22, user@inner",
                                id="f-jump-host",
                                classes="field-input",
                            ),
                            "Comma separated, connected in order.",
                        )
                        yield from field(
                            "Compression",
                            Switch(s.compression, id="f-compression", classes="field-switch"),
                        )
                        yield from field(
                            "Connect timeout",
                            Input(
                                f"{s.connect_timeout:g}",
                                type="number",
                                id="f-connect-timeout",
                                classes="field-input",
                            ),
                        )
                        yield Static(
                            "Local forwards, one per line: 8080:127.0.0.1:80", classes="hint"
                        )
                        yield TextArea(
                            "\n".join(s.local_forwards),
                            id="f-local-forwards",
                            classes="field-area",
                        )
                        yield Static(
                            "Remote forwards, one per line: 9000:127.0.0.1:3000", classes="hint"
                        )
                        yield TextArea(
                            "\n".join(s.remote_forwards),
                            id="f-remote-forwards",
                            classes="field-area",
                        )
                        yield Static(
                            "Dynamic SOCKS proxies, one per line: 1080", classes="hint"
                        )
                        yield TextArea(
                            "\n".join(s.dynamic_forwards),
                            id="f-dynamic-forwards",
                            classes="field-area",
                        )
                        yield from field(
                            "Reachable from the network",
                            Switch(
                                s.gateway_ports,
                                id="f-gateway-ports",
                                classes="field-switch",
                            ),
                            "Off means forwards listen on loopback only, like OpenSSH.",
                        )
                        yield from field(
                            "Tunnels only, no shell",
                            Switch(s.no_shell, id="f-no-shell", classes="field-switch"),
                            "The -N flag: hold the forwards open without a terminal.",
                        )

                with TabPane("Proxy", id="tab-proxy"):
                    with VerticalScroll():
                        yield from field(
                            "For this session",
                            Select(
                                [(PROXY_MODE_LABELS[m], m) for m in PROXY_MODES],
                                value=s.proxy_mode,
                                allow_blank=False,
                                id="f-proxy-mode",
                                classes="field-input",
                            ),
                        )
                        yield Static("", id="proxy-summary", classes="hint")
                        with Vertical(id="proxy-fields"):
                            yield from self.proxy_fields.compose()

                with TabPane("Advanced", id="tab-advanced"):
                    with VerticalScroll():
                        yield from field(
                            "Forward X11",
                            Switch(s.x11_forward, id="f-x11-forward", classes="field-switch"),
                            "Trusted forwarding, like ssh -Y: the remote host gets "
                            "full access to your display.",
                        )
                        yield from field(
                            "X display",
                            Input(
                                s.x11_display,
                                placeholder="empty uses $DISPLAY",
                                id="f-x11-display",
                                classes="field-input",
                            ),
                        )
                        yield from field(
                            "Address family",
                            Select(
                                [(FAMILY_LABELS[f], f) for f in ADDRESS_FAMILIES],
                                value=s.address_family,
                                allow_blank=False,
                                id="f-address-family",
                                classes="field-input",
                            ),
                        )
                        yield from field(
                            "Connect from",
                            Input(
                                s.bind_address,
                                placeholder="source address, empty for any",
                                id="f-bind-address",
                                classes="field-input",
                            ),
                        )
                        yield from field(
                            "Disable Nagle",
                            Switch(s.tcp_nodelay, id="f-tcp-nodelay", classes="field-switch"),
                            "On by default: an interactive session wants latency, "
                            "not full packets.",
                        )
                        yield from field(
                            "Log this session",
                            Select(
                                [(LOG_MODE_LABELS[m], m) for m in LOG_MODES],
                                value=s.log_mode,
                                allow_blank=False,
                                id="f-log-mode",
                                classes="field-input",
                            ),
                        )
                        yield from field(
                            "Log file",
                            Input(
                                s.log_path,
                                placeholder="~/logs/&N-&Y&M&D-&T.log",
                                id="f-log-path",
                                classes="field-input",
                            ),
                            "&H host, &N name, &Y &M &D date, &T time.",
                        )
                        yield Static(
                            "Environment variables, one per line: LANG=en_GB.UTF-8",
                            classes="hint",
                        )
                        yield TextArea(
                            "\n".join(s.environment),
                            id="f-environment",
                            classes="field-area",
                        )

            yield Static("", id="editor-status")
            with Horizontal(id="editor-buttons"):
                yield Button("Cancel", id="cancel")
                yield Button("Save", id="save", classes="primary")

    # ------------------------------------------------------------------
    def on_mount(self) -> None:
        self.query_one("#f-name", Input).focus()
        self._refresh_summaries()
        self._refresh_proxy()

    def _keyring_hint(self) -> str:
        if keyring_available():
            return "Stored in the system keyring, never in sessions.json."
        return "No system keyring found, so the password is asked for each time."

    def on_input_changed(self, event: Input.Changed) -> None:
        widget_id = event.input.id or ""
        if "keepalive" in widget_id or "reconnect" in widget_id:
            self._refresh_summaries()

    def on_switch_changed(self, event: Switch.Changed) -> None:
        self._refresh_summaries()

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "f-proxy-mode":
            self._refresh_proxy()

    def _refresh_proxy(self) -> None:
        """Only show the proxy fields when this session has its own."""
        try:
            mode = str(self.query_one("#f-proxy-mode", Select).value)
            summary = self.query_one("#proxy-summary", Static)
            fields = self.query_one("#proxy-fields", Vertical)
        except Exception:
            return
        fields.display = mode == "custom"
        if mode == "custom":
            # "Use a proxy just for this session" sitting above "No proxy" is
            # a contradiction, so pick a type the moment the mode is chosen.
            scheme = self.query_one("#f-proxy-scheme", Select)
            if str(scheme.value) == "none":
                scheme.value = "socks5"
        summary.update(
            {
                "global": "Whatever is set under Settings (p in the session list).",
                "none": "This session always dials directly, whatever the app proxy is.",
                "custom": "Used for this session only.",
            }.get(mode, "")
        )

    def _refresh_summaries(self) -> None:
        try:
            interval = self._int("f-keepalive-interval", 0)
            count = self._int("f-keepalive-count-max", 1)
        except Exception:
            return
        keepalive = self.query_one("#keepalive-summary", Static)
        if interval <= 0:
            keepalive.update("Probing is off. A dead link is only noticed when you type.")
        else:
            keepalive.update(
                f"A silent link is declared dead after about {interval * (count + 1)} seconds."
            )

        summary = self.query_one("#reconnect-summary", Static)
        if not self.query_one("#f-auto-reconnect", Switch).value:
            summary.update("Dropped sessions end. You come straight back to the list.")
            return
        first = self._float("f-reconnect-delay", 2.0)
        longest = self._float("f-reconnect-max-delay", 60.0)
        limit = self._int("f-reconnect-attempts", 0)
        tail = "until you stop it" if limit == 0 else f"up to {limit} time(s)"
        summary.update(
            f"Retries after {first:g}s, doubling to {longest:g}s, {tail}."
        )

    # -- reading widgets ------------------------------------------------
    def _text(self, widget_id: str) -> str:
        return self.query_one(f"#{widget_id}", Input).value.strip()

    def _int(self, widget_id: str, fallback: int) -> int:
        raw = self.query_one(f"#{widget_id}", Input).value.strip()
        try:
            return int(raw)
        except ValueError:
            return fallback

    def _float(self, widget_id: str, fallback: float) -> float:
        raw = self.query_one(f"#{widget_id}", Input).value.strip()
        try:
            return float(raw)
        except ValueError:
            return fallback

    def _switch(self, widget_id: str) -> bool:
        return self.query_one(f"#{widget_id}", Switch).value

    def _lines(self, widget_id: str) -> list[str]:
        text = self.query_one(f"#{widget_id}", TextArea).text
        return [line.strip() for line in text.splitlines() if line.strip()]

    def _collect(self) -> Session:
        return replace(
            self.session,
            name=self._text("f-name"),
            group=self._text("f-group") or "Ungrouped",
            host=self._text("f-host"),
            port=self._int("f-port", 22),
            username=self._text("f-username"),
            term=self._text("f-term") or "xterm-256color",
            remote_command=self._text("f-remote-command"),
            auth=str(self.query_one("#f-auth", Select).value),
            key_path=self._text("f-key-path"),
            save_password=self._switch("f-save-password"),
            host_key_policy=str(self.query_one("#f-host-key-policy", Select).value),
            forward_agent=self._switch("f-forward-agent"),
            keepalive_interval=self._int("f-keepalive-interval", 0),
            keepalive_count_max=self._int("f-keepalive-count-max", 3),
            tcp_keepalive=self._switch("f-tcp-keepalive"),
            null_packets=self._switch("f-null-packets"),
            auto_reconnect=self._switch("f-auto-reconnect"),
            reconnect_delay=self._float("f-reconnect-delay", 2.0),
            reconnect_max_delay=self._float("f-reconnect-max-delay", 60.0),
            reconnect_attempts=self._int("f-reconnect-attempts", 0),
            reconnect_on_remote_exit=self._switch("f-reconnect-on-remote-exit"),
            login_commands=self._lines("f-login-commands"),
            jump_host=self._text("f-jump-host"),
            compression=self._switch("f-compression"),
            connect_timeout=self._float("f-connect-timeout", 15.0),
            local_forwards=self._lines("f-local-forwards"),
            remote_forwards=self._lines("f-remote-forwards"),
            dynamic_forwards=self._lines("f-dynamic-forwards"),
            gateway_ports=self._switch("f-gateway-ports"),
            no_shell=self._switch("f-no-shell"),
            proxy_mode=str(self.query_one("#f-proxy-mode", Select).value),
            proxy=self.proxy_fields.collect(self),
            x11_forward=self._switch("f-x11-forward"),
            x11_display=self._text("f-x11-display"),
            address_family=str(self.query_one("#f-address-family", Select).value),
            bind_address=self._text("f-bind-address"),
            tcp_nodelay=self._switch("f-tcp-nodelay"),
            log_mode=str(self.query_one("#f-log-mode", Select).value),
            log_path=self._text("f-log-path"),
            environment=self._lines("f-environment"),
        )

    # ------------------------------------------------------------------
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "save":
            self.action_save()
        else:
            self.action_cancel()

    def action_save(self) -> None:
        candidate = self._collect()
        try:
            candidate.validate()
        except ValidationError as exc:
            self.query_one("#editor-status", Static).update(str(exc))
            return
        if candidate.proxy_mode == "custom" and candidate.proxy.save_password:
            password = self.proxy_fields.collect_password(self)
            if password:
                store_proxy_password(password, candidate.name)
        self.dismiss(candidate)

    def action_cancel(self) -> None:
        self.dismiss(None)
