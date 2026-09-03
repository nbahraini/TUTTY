"""The session manager screen."""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

from rich.table import Table
from rich.text import Text
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Footer, Header, Input, OptionList, RichLog, Static
from textual.widgets.option_list import Option

from ..model import Session
from ..prompts import TerminalPrompter
from ..settings import Settings, SettingsStore
from ..store import SessionStore, keyring_available, load_proxy_password
from ..supervisor import RunReport, Supervisor
from ..terminal import Console
from .dialogs import ConfirmScreen, HelpScreen
from .edit import EditScreen
from .settings import SettingsScreen

STEEL = "#151c24"
INK = "#c6d0da"
MUTED = "#6d7d8f"
AMBER = "#e0a13a"
UP = "#4fb477"
DOWN = "#d9534f"

# The gutter reads like the link lights on a switch: one glyph per session,
# same column every time, so the state of the whole estate is one glance.
GLYPHS = {
    "idle": ("·", MUTED),
    "up": ("●", UP),
    "down": ("○", MUTED),
    "retrying": ("◐", AMBER),
    "failed": ("✕", DOWN),
}

STATE_TEXT = {
    "idle": "never connected",
    "up": "connected",
    "down": "disconnected",
    "retrying": "reconnecting",
    "failed": "last attempt failed",
}


class SessionList(OptionList):
    """The list itself. Group headings are disabled rows."""


class PyttyApp(App[None]):
    """A terminal session manager that keeps SSH links up."""

    CSS_PATH = "pytty.tcss"
    TITLE = "pytty"

    BINDINGS = [
        ("enter", "connect", "Connect"),
        ("n", "new", "New"),
        ("e", "edit", "Edit"),
        ("u", "duplicate", "Duplicate"),
        ("d", "delete", "Delete"),
        ("slash", "filter", "Filter"),
        ("i", "import_config", "Import"),
        ("p", "settings", "Settings"),
        ("r", "reload", "Reload"),
        ("question_mark", "help", "Keys"),
        ("q", "quit", "Quit"),
        ("escape", "clear_filter", ""),
    ]

    def __init__(
        self,
        store: SessionStore,
        escape_byte: int = 0x1D,
        settings_store: SettingsStore | None = None,
    ) -> None:
        super().__init__()
        self.store = store
        self.escape_byte = escape_byte
        self.settings_store = settings_store or SettingsStore()
        self.states: dict[str, str] = {}
        self.summaries: dict[str, str] = {}
        self._rows: list[Session | None] = []

    # ------------------------------------------------------------------
    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="body"):
            with Vertical(id="list-pane"):
                yield Input(placeholder="Filter by name, host or group", id="filter")
                yield SessionList(id="sessions")
            with Vertical(id="detail-pane"):
                yield Static(id="detail-title")
                yield Static(id="detail-body")
                yield Static("Activity", id="activity-heading")
                # min_width defaults to 78, which is wider than this pane; without
                # lowering it every line is laid out at 78 columns and clipped.
                yield RichLog(
                    id="activity", markup=True, wrap=True, min_width=20, max_lines=400
                )
        yield Footer()

    def on_mount(self) -> None:
        self.sub_title = str(self.store.path)
        self.refresh_list()
        self.query_one(SessionList).focus()
        self.note(f"Loaded {len(self.store)} session(s) from {self.store.path}")
        if not keyring_available():
            self.note("No system keyring found — passwords will be asked for each time.", MUTED)
        self._note_proxy()

    # ------------------------------------------------------------------
    def note(self, message: str, colour: str = MUTED) -> None:
        stamp = time.strftime("%H:%M:%S")
        self.query_one("#activity", RichLog).write(
            f"[{MUTED}]{stamp}[/]  [{colour}]{message}[/]"
        )

    # ------------------------------------------------------------------
    def refresh_list(self, keep_name: str | None = None) -> None:
        option_list = self.query_one(SessionList)
        needle = self.query_one("#filter", Input).value.strip().lower()
        keep_name = keep_name or (self.current_session.name if self.current_session else None)

        sessions = [s for s in self.store.sorted() if self._matches(s, needle)]
        option_list.clear_options()
        self._rows = []
        options: list[Option] = []

        if not sessions:
            message = (
                "Nothing matches that filter."
                if needle
                else "No sessions yet. Press n to add one."
            )
            options.append(Option(Text(f"  {message}", style=MUTED), disabled=True))
            self._rows.append(None)
        else:
            current_group = None
            for session in sessions:
                group = session.group or "Ungrouped"
                if group != current_group:
                    current_group = group
                    options.append(Option(self._render_group(group), disabled=True))
                    self._rows.append(None)
                options.append(self._render_row(session))
                self._rows.append(session)

        option_list.add_options(options)

        target = 0
        if keep_name:
            for index, session in enumerate(self._rows):
                if session is not None and session.name == keep_name:
                    target = index
                    break
        if target == 0:
            target = next((i for i, s in enumerate(self._rows) if s is not None), 0)
        try:
            option_list.highlighted = target
        except Exception:
            pass
        self.update_detail()

    @staticmethod
    def _matches(session: Session, needle: str) -> bool:
        if not needle:
            return True
        haystack = " ".join(
            [session.name, session.host, session.username, session.group, session.notes]
        ).lower()
        return needle in haystack

    def _render_group(self, group: str) -> Text:
        text = Text()
        text.append("  ")
        text.append(group, style=f"bold {MUTED}")
        text.append("  ")
        text.append("─" * max(0, 40 - len(group)), style="#2b3744")
        return text

    def _render_row(self, session: Session) -> Option:
        state = self.states.get(session.name, "idle")
        glyph, colour = GLYPHS.get(state, GLYPHS["idle"])

        grid = Table.grid(expand=True, padding=(0, 1))
        grid.add_column(width=3, justify="center")
        grid.add_column(ratio=3, no_wrap=True, overflow="ellipsis")
        grid.add_column(ratio=4, no_wrap=True, overflow="ellipsis")
        grid.add_column(width=12, justify="right", no_wrap=True)

        badges = Text()
        if session.keepalive_interval:
            badges.append("ka", style=UP)
        else:
            badges.append("ka", style="#2b3744")
        badges.append(" ")
        badges.append("↻", style=AMBER if session.auto_reconnect else "#2b3744")
        badges.append(" ")
        proxy, _ = self._resolve_proxy(session)
        badges.append("⇢", style=AMBER if proxy is not None else "#2b3744")

        grid.add_row(
            Text(glyph, style=colour),
            Text(session.name, style=INK),
            Text(session.target, style=MUTED),
            badges,
        )
        return Option(grid, id=f"session:{session.name}")

    # ------------------------------------------------------------------
    @property
    def current_session(self) -> Session | None:
        try:
            option_list = self.query_one(SessionList)
        except Exception:
            return None
        index = option_list.highlighted
        if index is None or index >= len(self._rows):
            return None
        return self._rows[index]

    def on_option_list_option_highlighted(self, event: OptionList.OptionHighlighted) -> None:
        self.update_detail()

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        self.action_connect()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "filter":
            self.refresh_list()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "filter":
            self.query_one(SessionList).focus()

    # ------------------------------------------------------------------
    def update_detail(self) -> None:
        title = self.query_one("#detail-title", Static)
        body = self.query_one("#detail-body", Static)
        session = self.current_session

        if session is None:
            title.update(Text("No session selected", style=MUTED))
            body.update(
                Text(
                    "Press n to create one, or i to import the hosts "
                    "already in your ~/.ssh/config.",
                    style=MUTED,
                )
            )
            return

        state = self.states.get(session.name, "idle")
        glyph, colour = GLYPHS.get(state, GLYPHS["idle"])
        heading = Text(no_wrap=True, overflow="ellipsis")
        heading.append(f"{glyph} ", style=colour)
        heading.append(session.name, style=f"bold {INK}")
        heading.append(f"\n  {STATE_TEXT[state]}", style=colour)
        summary = self.summaries.get(session.name)
        if summary:
            heading.append(f"\n  {summary}", style=MUTED)
        title.update(heading)

        grid = Table.grid(padding=(0, 2))
        grid.add_column(justify="right", style=MUTED, width=14)
        grid.add_column(style=INK, overflow="fold")

        rows: list[tuple[str, str]] = [
            ("Target", session.target),
            ("Sign in", self._auth_text(session)),
            ("Host keys", session.host_key_policy),
            ("Proxy", self._proxy_text(session)),
            ("Keepalive", session.keepalive_summary),
            ("Dead after", self._dead_after_text(session)),
            ("Reconnect", session.reconnect_summary),
            ("Terminal", session.term),
        ]
        if session.no_shell:
            rows.append(("Mode", "tunnels only, no shell"))
        if session.remote_command:
            rows.append(("Runs", session.remote_command))
        if session.jump_host:
            rows.append(("Via", session.jump_host))
        if session.local_forwards:
            rows.append(("Local", "\n".join(session.local_forwards)))
        if session.remote_forwards:
            rows.append(("Remote", "\n".join(session.remote_forwards)))
        if session.dynamic_forwards:
            rows.append(("SOCKS", "\n".join(session.dynamic_forwards)))
        if session.gateway_ports:
            rows.append(("Forwards", "reachable from the network"))
        if session.x11_forward:
            rows.append(("X11", session.x11_display or "$DISPLAY"))
        if session.environment:
            rows.append(("Environment", "\n".join(session.environment)))
        if session.address_family != "auto":
            rows.append(("Family", session.address_family))
        if session.bind_address:
            rows.append(("Connect from", session.bind_address))
        if session.log_mode != "off":
            rows.append(("Logging", f"{session.log_mode} → {session.log_path}"))
        if session.login_commands:
            rows.append(("On login", "\n".join(session.login_commands)))
        if session.last_used:
            rows.append(
                ("Last used", time.strftime("%d %b %H:%M", time.localtime(session.last_used)))
            )
        if session.notes:
            rows.append(("Notes", session.notes))

        for label, value in rows:
            grid.add_row(label, value)
        body.update(grid)

    def _proxy_text(self, session: Session) -> str:
        """What this session will actually dial through, not just its setting."""
        proxy, _ = self._resolve_proxy(session)
        if proxy is None:
            if session.proxy_mode == "none":
                return "direct (session overrides the app proxy)"
            return "direct"
        if session.proxy_mode == "custom":
            return f"{proxy.describe()} (this session only)"
        origin = self.settings_store.settings.proxy_origin()
        return f"{proxy.describe()} ({'environment' if origin == 'environment' else 'app'})"

    def _resolve_proxy(self, session: Session):
        settings = self.settings_store.settings
        if session.proxy_mode == "custom":
            proxy = session.proxy if session.proxy.enabled else None
            password = (
                load_proxy_password(session.name)
                if proxy is not None and proxy.save_password
                else None
            )
            return proxy, password
        if session.proxy_mode == "none":
            return None, None
        proxy, password = settings.resolved_proxy()
        if not proxy.enabled:
            return None, None
        if proxy.save_password and password is None:
            password = load_proxy_password()
        return proxy, password

    @staticmethod
    def _auth_text(session: Session) -> str:
        if session.auth == "key":
            return f"key · {session.key_path or 'no key set'}"
        if session.auth == "agent":
            return "ssh agent"
        if session.auth == "password":
            return "password" + (" · remembered" if session.save_password else "")
        if session.auth == "ask":
            return "password, asked every time"
        return "keys and agent, then password"

    @staticmethod
    def _dead_after_text(session: Session) -> str:
        limit = session.dead_after()
        if limit == float("inf"):
            return "only when you type"
        return f"~{int(limit)}s of silence"

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------
    def action_filter(self) -> None:
        field = self.query_one("#filter", Input)
        field.add_class("visible")
        field.focus()

    def action_clear_filter(self) -> None:
        field = self.query_one("#filter", Input)
        if field.value:
            field.value = ""
        field.remove_class("visible")
        self.query_one(SessionList).focus()
        self.refresh_list()

    def action_reload(self) -> None:
        try:
            self.store.load()
        except RuntimeError as exc:
            self.note(str(exc), DOWN)
            return
        self.refresh_list()
        self.note(f"Reloaded {len(self.store)} session(s)")

    def action_new(self) -> None:
        draft = Session(
            name=self.store.unique_name("New session"),
            group=self.current_session.group if self.current_session else "Ungrouped",
            username=os.environ.get("USER") or os.environ.get("USERNAME") or "",
        )

        def finish(result: Session | None) -> None:
            if result is None:
                return
            try:
                self.store.add(result)
            except ValueError as exc:
                self.note(str(exc), DOWN)
                return
            self.refresh_list(keep_name=result.name)
            self.note(f"Added {result.name}")

        self.push_screen(EditScreen(draft, "New session"), finish)

    def action_edit(self) -> None:
        session = self.current_session
        if session is None:
            return
        original = session.name

        def finish(result: Session | None) -> None:
            if result is None:
                return
            try:
                self.store.update(original, result)
            except ValueError as exc:
                self.note(str(exc), DOWN)
                return
            if original != result.name:
                self.states[result.name] = self.states.pop(original, "idle")
                self.summaries[result.name] = self.summaries.pop(original, "")
            self.refresh_list(keep_name=result.name)
            self.note(f"Saved {result.name}")

        self.push_screen(EditScreen(session, f"Edit {session.name}"), finish)

    def action_duplicate(self) -> None:
        session = self.current_session
        if session is None:
            return
        copy = session.clone(self.store.unique_name(session.name))
        self.store.add(copy)
        self.refresh_list(keep_name=copy.name)
        self.note(f"Duplicated {session.name} as {copy.name}")

    def action_delete(self) -> None:
        session = self.current_session
        if session is None:
            return
        name = session.name

        def finish(confirmed: bool | None) -> None:
            if not confirmed:
                return
            self.store.delete(name)
            self.states.pop(name, None)
            self.summaries.pop(name, None)
            self.refresh_list()
            self.note(f"Deleted {name}")

        self.push_screen(
            ConfirmScreen(f"Delete the session {name}?\nThis also forgets any saved password."),
            finish,
        )

    def action_import_config(self) -> None:
        try:
            added = self.store.import_ssh_config()
        except Exception as exc:
            self.note(f"Could not read ~/.ssh/config: {exc}", DOWN)
            return
        if not added:
            self.note("Nothing new in ~/.ssh/config")
            return
        self.refresh_list()
        self.note(f"Imported {len(added)} host(s) from ~/.ssh/config", UP)

    def _note_proxy(self) -> None:
        settings = self.settings_store.settings
        proxy, _ = settings.resolved_proxy()
        if not proxy.enabled:
            return
        origin = settings.proxy_origin()
        where = "from the environment" if origin == "environment" else "from settings"
        self.note(f"Proxy {where}: {proxy.describe()}", AMBER)

    def action_settings(self) -> None:
        session = self.current_session
        target = f"{session.host}:{session.port}" if session and session.host else ""

        def finish(result: Settings | None) -> None:
            if result is None:
                return
            try:
                self.settings_store.update(result)
            except (ValueError, OSError) as exc:
                self.note(f"Could not save settings: {exc}", DOWN)
                return
            proxy, _ = result.resolved_proxy()
            self.note(
                f"Settings saved — proxy {proxy.describe()}",
                AMBER if proxy.enabled else MUTED,
            )
            self.refresh_list()

        self.push_screen(SettingsScreen(self.settings_store.settings, target), finish)

    def action_help(self) -> None:
        self.push_screen(HelpScreen())

    # ------------------------------------------------------------------
    def action_connect(self) -> None:
        session = self.current_session
        if session is None:
            return
        self.store.touch(session.name)
        report = self._run_session(session)
        self._apply_report(session.name, report)

    def _run_session(self, session: Session) -> RunReport:
        """Hand the terminal over to the SSH session, then take it back."""
        proxy, proxy_password = self._resolve_proxy(session)
        with self.suspend():
            sys.stdout.write("\x1b[2J\x1b[H")
            sys.stdout.flush()
            supervisor = Supervisor(
                session,
                TerminalPrompter(),
                Console(),
                escape_byte=self.escape_byte,
                proxy=proxy,
                proxy_password=proxy_password,
            )
            try:
                report = supervisor.run()
            except KeyboardInterrupt:
                report = supervisor.report
                report.ended_because = "interrupted"
            _pause()
        return report

    def _apply_report(self, name: str, report: RunReport) -> None:
        if report.ended_because in ("detached", "remote exit"):
            self.states[name] = "down"
            colour = MUTED
        elif report.connects:
            self.states[name] = "down"
            colour = AMBER
        else:
            self.states[name] = "failed"
            colour = DOWN

        parts = [f"{report.uptime_text} connected"]
        if report.reconnects:
            parts.append(f"{report.reconnects} reconnect(s)")
        if report.failed_attempts:
            parts.append(f"{report.failed_attempts} failed attempt(s)")
        self.summaries[name] = ", ".join(parts)

        reason = report.ended_because or "ended"
        self.note(f"{name}: {reason} — {self.summaries[name]}", colour)
        if report.error:
            self.note(f"{name}: {report.error}", DOWN)
        self.refresh_list(keep_name=name)


def _pause() -> None:
    try:
        input("\nPress Enter to return to pytty… ")
    except (EOFError, KeyboardInterrupt):
        pass


def run(
    store: SessionStore | None = None,
    escape_byte: int = 0x1D,
    settings_store: SettingsStore | None = None,
) -> None:
    PyttyApp(store or SessionStore(), escape_byte, settings_store).run()
