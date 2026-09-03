"""Drive the TUI headlessly and write screenshots to /tmp/pytty-shots."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pytty.model import Session  # noqa: E402
from pytty.settings import SettingsStore  # noqa: E402
from pytty.store import SessionStore  # noqa: E402
from pytty.tui.app import PyttyApp  # noqa: E402

SHOTS = Path("/tmp/pytty-shots")
SIZE = (124, 38)

FIXTURES = [
    Session(
        name="edge-router",
        group="Network",
        host="10.20.0.1",
        username="admin",
        keepalive_interval=15,
        keepalive_count_max=2,
        auto_reconnect=True,
        reconnect_delay=2,
        notes="Flaps during the nightly backup window.",
    ),
    Session(
        name="core-switch",
        group="Network",
        host="10.20.0.2",
        username="admin",
        auth="key",
        key_path="~/.ssh/id_ed25519",
        keepalive_interval=30,
        null_packets=True,
    ),
    Session(
        name="app-01",
        group="Production",
        host="app01.internal",
        username="deploy",
        jump_host="deploy@bastion.example.com",
        keepalive_interval=30,
        local_forwards=["9090:127.0.0.1:9090"],
        login_commands=["tmux attach -t work || tmux new -s work"],
    ),
    Session(
        name="app-02",
        group="Production",
        host="app02.internal",
        username="deploy",
        jump_host="deploy@bastion.example.com",
        auto_reconnect=False,
        keepalive_interval=0,
    ),
    Session(
        name="db-primary",
        group="Production",
        host="db01.internal",
        username="postgres",
        keepalive_interval=20,
        reconnect_attempts=10,
        local_forwards=["5433:127.0.0.1:5432"],
    ),
    Session(
        name="pi-shed",
        group="Home",
        host="192.168.1.40",
        username="pi",
        port=2222,
        keepalive_interval=10,
        keepalive_count_max=2,
        reconnect_on_remote_exit=True,
    ),
]


async def main() -> int:
    SHOTS.mkdir(exist_ok=True)
    store = SessionStore(SHOTS / "sessions.json")
    for session in FIXTURES:
        if session.name not in store:
            store.add(session)

    app = PyttyApp(store, settings_store=SettingsStore(SHOTS / "settings.json"))
    problems: list[str] = []

    async with app.run_test(size=SIZE) as pilot:
        # Pretend a couple of sessions have already been used, so the gutter
        # shows more than one state.
        app.states["edge-router"] = "retrying"
        app.summaries["edge-router"] = "4m 12s connected, 3 reconnect(s)"
        app.states["app-01"] = "down"
        app.summaries["app-01"] = "1h 20m connected"
        app.states["db-primary"] = "failed"
        app.refresh_list(keep_name="edge-router")
        await pilot.pause()
        (SHOTS / "01-list.svg").write_text(app.export_screenshot(title="pytty"))

        # Detail pane should follow the highlight.
        await pilot.press("down", "down")
        await pilot.pause()
        if app.current_session is None:
            problems.append("moving down left nothing highlighted")

        # Filtering.
        await pilot.press("slash")
        for key in "app":
            await pilot.press(key)
        await pilot.pause()
        visible = [s.name for s in app._rows if s is not None]
        if visible != ["app-01", "app-02"]:
            problems.append(f"filter returned {visible}")
        (SHOTS / "02-filter.svg").write_text(app.export_screenshot(title="pytty — filter"))
        await pilot.press("escape")
        await pilot.pause()

        # Editor.
        await pilot.press("e")
        await pilot.pause()
        (SHOTS / "03-edit.svg").write_text(app.export_screenshot(title="pytty — editor"))
        from textual.widgets import TabbedContent

        tabs = app.screen.query_one(TabbedContent)
        tabs.active = "tab-keepalive"
        await pilot.pause()
        (SHOTS / "04-keepalive.svg").write_text(app.export_screenshot(title="pytty — keepalive"))
        tabs.active = "tab-reconnect"
        await pilot.pause()
        (SHOTS / "05-reconnect.svg").write_text(app.export_screenshot(title="pytty — reconnect"))

        # Tunnels, proxy and advanced tabs.
        from textual.widgets import Select

        tabs.active = "tab-tunnels"
        await pilot.pause()
        (SHOTS / "08-tunnels.svg").write_text(app.export_screenshot(title="pytty — tunnels"))

        tabs.active = "tab-proxy"
        await pilot.pause()
        # The per-session proxy fields stay out of the way until the session
        # is actually set to use its own proxy.
        fields = app.screen.query_one("#proxy-fields")
        if fields.display:
            problems.append("proxy fields are visible while the mode is 'global'")
        (SHOTS / "09-proxy-global.svg").write_text(
            app.export_screenshot(title="pytty — proxy")
        )
        app.screen.query_one("#f-proxy-mode", Select).value = "custom"
        await pilot.pause()
        if not app.screen.query_one("#proxy-fields").display:
            problems.append("proxy fields stayed hidden after choosing 'custom'")
        (SHOTS / "10-proxy-custom.svg").write_text(
            app.export_screenshot(title="pytty — session proxy")
        )
        app.screen.query_one("#f-proxy-mode", Select).value = "global"
        await pilot.pause()

        tabs.active = "tab-advanced"
        await pilot.pause()
        (SHOTS / "11-advanced.svg").write_text(app.export_screenshot(title="pytty — advanced"))

        tabs.active = "tab-connection"
        await pilot.pause()
        await pilot.press("escape")
        await pilot.pause()

        # Application settings, and the proxy actually reaching the store.
        await pilot.press("p")
        await pilot.pause()
        (SHOTS / "12-settings.svg").write_text(app.export_screenshot(title="pytty — settings"))
        from textual.widgets import Input as TextInput

        app.screen.query_one("#s-proxy-scheme", Select).value = "socks5"
        app.screen.query_one("#s-proxy-host", TextInput).value = "proxy.corp.example"
        app.screen.query_one("#s-proxy-port", TextInput).value = "1080"
        app.screen.query_one("#s-proxy-username", TextInput).value = "alice"
        await pilot.pause()
        (SHOTS / "13-settings-socks.svg").write_text(
            app.export_screenshot(title="pytty — proxy configured")
        )
        await pilot.press("ctrl+s")
        await pilot.pause()
        saved = app.settings_store.settings.proxy
        if not saved.enabled or saved.host != "proxy.corp.example" or saved.port != 1080:
            problems.append(f"settings did not save the proxy: {saved}")
        if saved.scheme != "socks5":
            problems.append(f"settings saved the wrong scheme: {saved.scheme}")

        # The detail pane must report the proxy a session will really use.
        app.refresh_list(keep_name="app-01")
        await pilot.pause()
        detail = app._proxy_text(store.get("app-01"))
        if "proxy.corp.example" not in detail:
            problems.append(f"detail pane does not show the app proxy: {detail!r}")
        (SHOTS / "14-list-proxied.svg").write_text(
            app.export_screenshot(title="pytty — proxy in force")
        )

        # A session set to "none" must ignore the app proxy.
        none_proxy = store.get("app-02")
        none_proxy.proxy_mode = "none"
        store.update("app-02", none_proxy)
        if app._resolve_proxy(store.get("app-02"))[0] is not None:
            problems.append("a session set to 'none' still resolved a proxy")

        tabs = None  # the editor is closed; do not reuse the stale reference

        # Help.
        await pilot.press("question_mark")
        await pilot.pause()
        (SHOTS / "06-help.svg").write_text(app.export_screenshot(title="pytty — keys"))
        await pilot.press("escape")
        await pilot.pause()

        # Round-trip an edit through the store.
        app.refresh_list(keep_name="pi-shed")
        await pilot.pause()
        if app.current_session is None or app.current_session.name != "pi-shed":
            problems.append("could not select pi-shed")
        else:
            await pilot.press("e")
            await pilot.pause()
            from textual.widgets import Input

            field = app.screen.query_one("#f-keepalive-interval", Input)
            field.value = "45"
            await pilot.pause()
            await pilot.press("ctrl+s")
            await pilot.pause()
            if store.get("pi-shed").keepalive_interval != 45:
                problems.append("editing keepalive did not reach the store")

        # Delete confirmation should be reversible.
        await pilot.press("d")
        await pilot.pause()
        (SHOTS / "07-confirm.svg").write_text(app.export_screenshot(title="pytty — confirm"))
        await pilot.press("escape")
        await pilot.pause()
        if "pi-shed" not in store:
            problems.append("cancelling the confirm dialog still deleted the session")

    for path in sorted(SHOTS.glob("*.svg")):
        try:
            import cairosvg

            cairosvg.svg2png(url=str(path), write_to=str(path.with_suffix(".png")), scale=1.4)
        except Exception as exc:  # pragma: no cover
            print(f"could not rasterise {path.name}: {exc}")

    if problems:
        print("FAILED")
        for problem in problems:
            print(" ", problem)
        return 1
    print(f"TUI checks passed. Screenshots in {SHOTS}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
