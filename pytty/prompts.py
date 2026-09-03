"""Credential prompts, asked on the plain terminal outside the TUI."""

from __future__ import annotations

import getpass
import sys


class TerminalPrompter:
    """Asks for secrets on the real tty, so nothing is echoed or logged."""

    def __init__(self, assume_yes: bool = False) -> None:
        self.assume_yes = assume_yes

    def ask_password(self, prompt: str) -> str | None:
        try:
            return getpass.getpass(prompt)
        except (EOFError, KeyboardInterrupt):
            sys.stdout.write("\n")
            return None

    def ask_passphrase(self, key_path: str) -> str | None:
        return self.ask_password(f"Passphrase for {key_path}: ")

    def confirm_host_key(
        self, host: str, key_type: str, fingerprint: str, changed: bool
    ) -> bool:
        if self.assume_yes:
            return True
        headline = (
            f"The host key for {host} has changed."
            if changed
            else f"{host} is not in your known hosts file."
        )
        sys.stdout.write(
            f"\n{headline}\n"
            f"  Key type    {key_type}\n"
            f"  Fingerprint {fingerprint}\n"
            "Check this against a fingerprint you obtained from the server itself.\n"
        )
        sys.stdout.flush()
        try:
            answer = input("Trust this key and continue? [y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            sys.stdout.write("\n")
            return False
        return answer in ("y", "yes")

    def ask_save_password(self) -> bool:
        try:
            return input("Save this password in the system keyring? [y/N] ").strip().lower() in (
                "y",
                "yes",
            )
        except (EOFError, KeyboardInterrupt):
            return False
