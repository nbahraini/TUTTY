"""Confirmation and help modals."""

from __future__ import annotations

from rich.table import Table
from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Static


class ConfirmScreen(ModalScreen[bool]):
    """Yes/no, with the destructive answer never on the default focus."""

    BINDINGS = [("escape", "dismiss_false", "Cancel")]

    def __init__(self, message: str, confirm_label: str = "Delete", danger: bool = True) -> None:
        super().__init__()
        self.message = message
        self.confirm_label = confirm_label
        self.danger = danger

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Static(self.message, id="dialog-message")
            with Horizontal(id="dialog-buttons"):
                yield Button("Cancel", id="cancel")
                yield Button(
                    self.confirm_label,
                    id="confirm",
                    classes="danger" if self.danger else "",
                )

    def on_mount(self) -> None:
        self.query_one("#cancel", Button).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "confirm")

    def action_dismiss_false(self) -> None:
        self.dismiss(False)


class HelpScreen(ModalScreen[None]):
    """Keyboard reference, including the keys that only exist inside a session."""

    BINDINGS = [
        ("escape", "dismiss_none", "Close"),
        ("question_mark", "dismiss_none", "Close"),
    ]

    ROWS = [
        ("In the session list", ""),
        ("enter", "Connect to the highlighted session"),
        ("n", "New session"),
        ("e", "Edit"),
        ("u", "Duplicate"),
        ("d", "Delete"),
        ("/", "Filter the list"),
        ("i", "Import hosts from ~/.ssh/config"),
        ("p", "Application settings, including the proxy"),
        ("r", "Reload sessions.json from disk"),
        ("q", "Quit"),
        ("", ""),
        ("In the editor", ""),
        ("ctrl+s", "Save"),
        ("escape", "Cancel"),
        ("", ""),
        ("In settings", ""),
        ("ctrl+t", "Test the proxy against the highlighted host"),
        ("ctrl+s", "Save"),
        ("", ""),
        ("While connected", ""),
        ("ctrl+]", "Close the session and come back here"),
        ("enter", "During a countdown, reconnect immediately"),
        ("q", "During a countdown, stop retrying"),
        ("", ""),
        ("Tunnels only (-N)", ""),
        ("ctrl+] or q", "Close a session that has no shell"),
    ]

    def compose(self) -> ComposeResult:
        table = Table.grid(padding=(0, 3))
        table.add_column(justify="right", width=12, style="#e0a13a")
        table.add_column()
        for key, description in self.ROWS:
            if not key and not description:
                table.add_row("", "")
            elif not description:
                table.add_row("", Text(key, style="#6d7d8f"))
            else:
                table.add_row(key, description)
        with VerticalScroll(id="help"):
            yield Static(table)

    def action_dismiss_none(self) -> None:
        self.dismiss(None)
