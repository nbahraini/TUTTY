"""Command line entry point."""

from __future__ import annotations

import argparse
import sys
from dataclasses import replace
from pathlib import Path

from .model import Session, ValidationError, parse_target
from .prompts import TerminalPrompter
from .proxy import ProxyConfig, split_proxy_url
from .settings import Settings, SettingsStore
from .store import SessionStore, load_proxy_password
from .supervisor import Supervisor
from .terminal import Console

__version__ = "1.1.0"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pytty",
        description=(
            "A terminal session manager for SSH, with keepalive probing and "
            "automatic reconnection."
        ),
        epilog=(
            "Run with no arguments to open the session manager. "
            "Give a saved session name to connect straight to it, or a "
            "user@host target to connect without saving anything."
        ),
    )
    parser.add_argument("target", nargs="?", help="saved session name, or user@host[:port]")
    parser.add_argument("--version", action="version", version=f"pytty {__version__}")
    parser.add_argument("-l", "--list", action="store_true", help="print saved sessions and exit")
    parser.add_argument(
        "--import-ssh-config",
        action="store_true",
        help="add hosts from ~/.ssh/config to the session store",
    )
    parser.add_argument("--config", type=Path, help="path to an alternative sessions.json")

    connection = parser.add_argument_group("ad-hoc connection")
    connection.add_argument("-p", "--port", type=int, help="port, default 22")
    connection.add_argument("-u", "--user", help="username")
    connection.add_argument("-i", "--identity", help="private key file")
    connection.add_argument("-J", "--jump", default="", help="jump host, user@bastion[:port]")
    connection.add_argument(
        "-L",
        dest="local_forwards",
        action="append",
        default=[],
        metavar="PORT:HOST:PORT",
        help="local port forward, repeatable",
    )
    connection.add_argument(
        "-R",
        dest="remote_forwards",
        action="append",
        default=[],
        metavar="PORT:HOST:PORT",
        help="remote port forward, repeatable",
    )
    connection.add_argument(
        "-D",
        dest="dynamic_forwards",
        action="append",
        default=[],
        metavar="[BIND:]PORT",
        help="dynamic SOCKS4/5 proxy on a local port, repeatable",
    )
    connection.add_argument(
        "-N",
        "--no-shell",
        action="store_true",
        help="open the tunnels but no shell, and hold the link open",
    )
    connection.add_argument(
        "-X", "--x11", action="store_true", help="forward X11 to the local display"
    )
    connection.add_argument(
        "-A", "--forward-agent", action="store_true", help="forward the SSH agent"
    )
    connection.add_argument("-C", "--compress", action="store_true", help="compress the session")
    connection.add_argument(
        "-b", "--bind", metavar="ADDRESS", help="source address for outgoing connections"
    )
    connection.add_argument(
        "-4", dest="ipv4", action="store_true", help="use IPv4 only"
    )
    connection.add_argument(
        "-6", dest="ipv6", action="store_true", help="use IPv6 only"
    )
    connection.add_argument(
        "-g",
        "--gateway-ports",
        action="store_true",
        help="let other hosts use the local forwards (they are loopback-only by default)",
    )
    connection.add_argument(
        "--env",
        dest="environment",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="send an environment variable, repeatable",
    )

    proxy_group = parser.add_argument_group("proxy")
    proxy_group.add_argument(
        "--proxy",
        metavar="URL",
        help=(
            "reach the SSH server through a proxy: "
            "http://, https://, socks4://, socks5:// or socks5h://, "
            "optionally with user:password@"
        ),
    )
    proxy_group.add_argument(
        "--no-proxy",
        action="store_true",
        help="ignore the configured and environment proxies for this connection",
    )
    proxy_group.add_argument(
        "--proxy-exclude",
        action="append",
        default=[],
        metavar="PATTERN",
        help=(
            "host reached directly rather than through the proxy, repeatable; "
            "'none' clears the defaults so even loopback is proxied"
        ),
    )

    logging_group = parser.add_argument_group("logging")
    logging_group.add_argument(
        "--log",
        metavar="PATH",
        help="write the session to a file (&H host, &N name, &Y &M &D date, &T time)",
    )
    logging_group.add_argument(
        "--log-mode",
        choices=("output", "all"),
        help="log server output only, or output and keystrokes (default output)",
    )

    behaviour = parser.add_argument_group("keepalive and reconnect")
    behaviour.add_argument(
        "--keepalive",
        type=int,
        metavar="SECONDS",
        help="seconds between liveness probes, 0 to disable",
    )
    behaviour.add_argument(
        "--keepalive-count",
        type=int,
        metavar="N",
        help="unanswered probes tolerated before the link is dropped",
    )
    behaviour.add_argument(
        "--no-reconnect", action="store_true", help="do not reconnect after a drop"
    )
    behaviour.add_argument(
        "--reconnect-delay", type=float, metavar="SECONDS", help="wait before the first retry"
    )
    behaviour.add_argument(
        "--max-delay", type=float, metavar="SECONDS", help="longest backoff between retries"
    )
    behaviour.add_argument(
        "--attempts", type=int, metavar="N", help="reconnect attempt limit, 0 for unlimited"
    )
    behaviour.add_argument(
        "--escape",
        default="ctrl+]",
        metavar="KEY",
        help="key that closes the session, default ctrl+]",
    )
    behaviour.add_argument(
        "--yes",
        action="store_true",
        help="accept unknown host keys without asking (use only on trusted networks)",
    )
    return parser


def parse_escape(text: str) -> int:
    value = text.strip().lower()
    for prefix in ("ctrl+", "ctrl-", "^"):
        if value.startswith(prefix):
            letter = value[len(prefix) :]
            if len(letter) == 1:
                return ord(letter.upper()) ^ 0x40
    if len(value) == 1:
        return ord(value)
    raise argparse.ArgumentTypeError(f"Cannot interpret escape key {text!r}")


def apply_overrides(session: Session, args: argparse.Namespace) -> Session:
    if args.port:
        session.port = args.port
    if args.user:
        session.username = args.user
    if args.identity:
        session.auth = "key"
        session.key_path = args.identity
    if args.jump:
        session.jump_host = args.jump
    if args.local_forwards:
        session.local_forwards = list(args.local_forwards)
    if args.remote_forwards:
        session.remote_forwards = list(args.remote_forwards)
    if args.dynamic_forwards:
        session.dynamic_forwards = list(args.dynamic_forwards)
    if args.no_shell:
        session.no_shell = True
    if args.x11:
        session.x11_forward = True
    if args.forward_agent:
        session.forward_agent = True
    if args.compress:
        session.compression = True
    if args.bind:
        session.bind_address = args.bind
    if args.ipv4:
        session.address_family = "ipv4"
    if args.ipv6:
        session.address_family = "ipv6"
    if args.gateway_ports:
        session.gateway_ports = True
    if args.environment:
        session.environment = list(args.environment)
    if args.log:
        session.log_path = args.log
        session.log_mode = args.log_mode or "output"
    elif args.log_mode:
        session.log_mode = args.log_mode
    if args.no_proxy:
        session.proxy_mode = "none"
    if args.keepalive is not None:
        session.keepalive_interval = args.keepalive
    if args.keepalive_count is not None:
        session.keepalive_count_max = args.keepalive_count
    if args.no_reconnect:
        session.auto_reconnect = False
    if args.reconnect_delay is not None:
        session.reconnect_delay = args.reconnect_delay
    if args.max_delay is not None:
        session.reconnect_max_delay = args.max_delay
    if args.attempts is not None:
        session.reconnect_attempts = args.attempts
    if args.yes:
        session.host_key_policy = "auto"
    return session


def resolve_proxy(
    session: Session,
    args: argparse.Namespace,
    settings: Settings,
    prompter: TerminalPrompter | None = None,
) -> tuple[ProxyConfig | None, str | None]:
    """Work out the proxy for this run, and the password to use with it.

    Precedence runs from most specific to least: an explicit flag, then the
    session's own setting, then the application setting, then the
    environment. `--no-proxy` short-circuits all of it.
    """
    if args.no_proxy:
        return None, None

    password: str | None = None
    config: ProxyConfig | None

    if args.proxy:
        config, password = split_proxy_url(args.proxy)
    elif session.proxy_mode == "none":
        return None, None
    elif session.proxy_mode == "custom":
        config = session.proxy if session.proxy.enabled else None
        if config is not None and config.save_password:
            password = load_proxy_password(session.name)
    else:
        config, password = settings.resolved_proxy()
        if config.enabled and config.save_password and password is None:
            password = load_proxy_password()
        config = config if config.enabled else None

    if config is None or not config.enabled:
        return None, None

    if args.proxy_exclude:
        # "none" clears the list rather than adding to it, which is the only
        # way to proxy a loopback or dotless address — both of which the
        # default <local> entry would otherwise send direct.
        if any(item.strip().lower() == "none" for item in args.proxy_exclude):
            extra = [i for i in args.proxy_exclude if i.strip().lower() != "none"]
            config = replace(config, exclude=extra)
        else:
            config = replace(config, exclude=[*config.exclude, *args.proxy_exclude])

    # A username with no password is almost always an oversight rather than a
    # proxy that wants an empty one, so ask rather than failing the handshake.
    if config.username and password is None and prompter is not None:
        password = prompter.ask_password(f"Password for proxy {config.describe()}: ")

    return config, password
    if not len(store):
        print("No saved sessions. Run pytty with no arguments to add one.")
        return
    width = max(len(s.name) for s in store.sorted())
    group = None
    for session in store.sorted():
        if session.group != group:
            group = session.group
            print(f"\n{group}")
        print(
            f"  {session.name.ljust(width)}  {session.target:<32}"
            f"  keepalive {session.keepalive_summary:<10}"
            f"  reconnect {session.reconnect_summary}"
        )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.proxy and args.no_proxy:
        parser.error("--proxy and --no-proxy contradict each other.")
        return 2
    if args.proxy:
        try:
            split_proxy_url(args.proxy)
        except ValueError as exc:
            parser.error(str(exc))
            return 2

    try:
        escape_byte = parse_escape(args.escape)
    except argparse.ArgumentTypeError as exc:
        parser.error(str(exc))
        return 2

    try:
        store = SessionStore(args.config)
    except RuntimeError as exc:
        print(exc, file=sys.stderr)
        return 1

    try:
        settings = SettingsStore().settings
    except RuntimeError as exc:
        # A broken settings file should not stop you connecting; say so and
        # carry on with defaults.
        print(f"{exc} — carrying on without it.", file=sys.stderr)
        settings = Settings()

    if args.import_ssh_config:
        added = store.import_ssh_config()
        print(f"Imported {len(added)} host(s).")
        if not args.target:
            return 0

    if args.list:
        print_sessions(store)
        return 0

    if not args.target:
        from .tui.app import run

        run(store, escape_byte)
        return 0

    session = store.get(args.target)
    if session is None:
        user, host, port = parse_target(args.target)
        if not host:
            parser.error(f"No saved session named {args.target!r}.")
            return 2
        session = Session(name=host, host=host, username=user, port=port)
    else:
        store.touch(session.name)

    session = apply_overrides(session, args)
    try:
        session.validate()
    except ValidationError as exc:
        print(exc, file=sys.stderr)
        return 2

    prompter = TerminalPrompter(assume_yes=args.yes)
    proxy, proxy_password = resolve_proxy(session, args, settings, prompter)

    supervisor = Supervisor(
        session,
        prompter,
        Console(),
        escape_byte=escape_byte,
        proxy=proxy,
        proxy_password=proxy_password,
    )
    try:
        report = supervisor.run()
    except KeyboardInterrupt:
        print()
        return 130

    if report.connects:
        print(
            f"{report.session_name}: {report.ended_because} after "
            f"{report.uptime_text} connected, {report.reconnects} reconnect(s)."
        )
        return 0
    print(f"{report.session_name}: {report.ended_because or 'failed'}.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
