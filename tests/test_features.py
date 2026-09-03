"""Tests for the PuTTY-equivalent options. Run with: python -m pytest tests/test_features.py"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from pytty.cli import build_parser, apply_overrides, resolve_proxy
from pytty.model import Session, ValidationError, has_explicit_bind
from pytty.proxy import parse_proxy_url
from pytty.settings import Settings
from pytty.ssh import parse_display
from pytty.terminal import SessionLog, expand_log_path


def _session(**kwargs) -> Session:
    base = dict(name="s", host="h", username="u")
    base.update(kwargs)
    return Session(**base)


# ----------------------------------------------------------------------
# Environment variables
# ----------------------------------------------------------------------
def test_environment_map_parses_and_lets_the_last_one_win():
    session = _session(
        environment=["LANG=en_GB.UTF-8", "# a comment", "", "TZ=UTC", "LANG=C"]
    )
    assert session.environment_map() == {"LANG": "C", "TZ": "UTC"}


def test_environment_keeps_values_containing_equals():
    session = _session(environment=["OPTS=-a=1 -b=2"])
    assert session.environment_map()["OPTS"] == "-a=1 -b=2"


def test_malformed_environment_entries_are_rejected():
    with pytest.raises(ValidationError, match="LANG=en_GB.UTF-8"):
        _session(environment=["not a variable"]).validate()


def test_comments_and_blanks_are_allowed_in_the_environment():
    _session(environment=["# note", "", "TZ=UTC"]).validate()


# ----------------------------------------------------------------------
# Gateway ports
# ----------------------------------------------------------------------
@pytest.mark.parametrize(
    "spec, expected",
    [
        ("8080:host:80", False),
        ("0.0.0.0:8080:host:80", True),
        ("127.0.0.1:8080:host:80", True),
        ("[::1]:8080:host:80", True),
        ("8080:[2001:db8::1]:80", False),  # bracketed destination, no bind
        ("1080", False),
        ("0.0.0.0:1080", True),
    ],
)
def test_has_explicit_bind(spec, expected):
    assert has_explicit_bind(spec) is expected


# ----------------------------------------------------------------------
# Tunnel-only sessions
# ----------------------------------------------------------------------
def test_tunnel_only_without_tunnels_is_rejected():
    with pytest.raises(ValidationError, match="at least one forward"):
        _session(no_shell=True).validate()


def test_tunnel_only_with_a_forward_is_fine():
    _session(no_shell=True, dynamic_forwards=["1080"]).validate()


# ----------------------------------------------------------------------
# Logging
# ----------------------------------------------------------------------
def test_log_path_placeholders_expand():
    expanded = expand_log_path("/tmp/&N-&H.log", host="db01", name="prod")
    assert expanded == "/tmp/prod-db01.log"


def test_log_path_expands_dates_and_escapes():
    expanded = expand_log_path("/tmp/&Y&M&D-&&.log", host="h", name="n")
    assert expanded.endswith("-&.log")
    assert len(Path(expanded).name) == len("20240101-&.log")


def test_logging_needs_a_path():
    with pytest.raises(ValidationError, match="needs a file"):
        _session(log_mode="output").validate()


def test_session_log_writes_output_and_honours_the_mode(tmp_path):
    path = tmp_path / "session.log"
    log = SessionLog(str(path), "output", host="h", name="n")
    assert log.open()
    log.output(b"from the server\n")
    log.input(b"typed\n")
    log.close()
    body = path.read_text()
    assert "from the server" in body
    assert "typed" not in body  # mode is output-only
    assert "session log started" in body


def test_session_log_in_all_mode_records_keystrokes(tmp_path):
    path = tmp_path / "session.log"
    log = SessionLog(str(path), "all")
    assert log.open()
    log.input(b"whoami\n")
    log.close()
    assert "whoami" in path.read_text()


def test_session_log_appends_across_reconnects(tmp_path):
    path = tmp_path / "session.log"
    for _ in range(2):
        log = SessionLog(str(path), "output")
        log.open()
        log.output(b"x")
        log.close()
    # Truncating here would throw away the record of the link that just died.
    assert path.read_text().count("session log started") == 2


def test_session_log_reports_an_unwritable_path(tmp_path):
    # A plain file where a directory is expected fails for everyone,
    # including root, unlike a permission bit.
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory")
    log = SessionLog(str(blocker / "sub" / "s.log"), "output")
    assert log.open() is False
    assert log.error


# ----------------------------------------------------------------------
# X11
# ----------------------------------------------------------------------
@pytest.mark.parametrize(
    "display, expected",
    [
        (":0", ("", 0, 0)),
        (":0.1", ("", 0, 1)),
        ("unix:12", ("", 12, 0)),
        ("localhost:10.0", ("", 10, 0)),
        ("box.example:1", ("box.example", 1, 0)),
    ],
)
def test_parse_display(display, expected):
    assert parse_display(display) == expected


@pytest.mark.parametrize("bad", ["", "nonsense", ":x"])
def test_parse_display_rejects_rubbish(bad):
    with pytest.raises(ValueError):
        parse_display(bad)


# ----------------------------------------------------------------------
# Address family and validation
# ----------------------------------------------------------------------
def test_unknown_address_family_is_rejected():
    with pytest.raises(ValidationError, match="address family"):
        _session(address_family="ipv7").validate()


def test_unknown_proxy_mode_is_rejected():
    with pytest.raises(ValidationError, match="proxy mode"):
        _session(proxy_mode="sometimes").validate()


# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------
def test_cli_collects_the_new_flags():
    args = build_parser().parse_args(
        [
            "host",
            "-N",
            "-X",
            "-A",
            "-C",
            "-g",
            "-4",
            "-b",
            "10.0.0.9",
            "--env",
            "LANG=C",
            "--env",
            "TZ=UTC",
            "--log",
            "/tmp/s.log",
            "--log-mode",
            "all",
            "--proxy",
            "socks5h://bob@proxy:1080",
        ]
    )
    session = apply_overrides(_session(dynamic_forwards=["1080"]), args)
    assert session.no_shell and session.x11_forward and session.forward_agent
    assert session.compression and session.gateway_ports
    assert session.address_family == "ipv4"
    assert session.bind_address == "10.0.0.9"
    assert session.environment == ["LANG=C", "TZ=UTC"]
    assert session.log_path == "/tmp/s.log"
    assert session.log_mode == "all"
    session.validate()


def test_log_defaults_to_output_mode_when_only_a_path_is_given():
    args = build_parser().parse_args(["host", "--log", "/tmp/s.log"])
    assert apply_overrides(_session(), args).log_mode == "output"


def test_cli_leaves_the_new_options_alone_when_unset():
    args = build_parser().parse_args(["host"])
    original = _session(
        no_shell=True,
        dynamic_forwards=["1080"],
        x11_forward=True,
        gateway_ports=True,
        environment=["TZ=UTC"],
        log_path="/tmp/x.log",
        log_mode="all",
        address_family="ipv6",
    )
    after = apply_overrides(original, args)
    assert after.no_shell and after.x11_forward and after.gateway_ports
    assert after.environment == ["TZ=UTC"]
    assert after.log_mode == "all"
    assert after.address_family == "ipv6"


# ----------------------------------------------------------------------
# Proxy resolution precedence
# ----------------------------------------------------------------------
def _args(*argv):
    return build_parser().parse_args(["host", *argv])


def test_the_proxy_flag_beats_everything():
    settings = Settings(proxy=parse_proxy_url("http://app:3128"))
    session = _session(proxy_mode="custom", proxy=parse_proxy_url("http://own:1"))
    config, password = resolve_proxy(session, _args("--proxy", "socks5://cli:1080"), settings)
    assert config.host == "cli"
    assert password is None


def test_the_proxy_flag_carries_its_password():
    config, password = resolve_proxy(
        _session(), _args("--proxy", "http://u:pw@cli:3128"), Settings()
    )
    assert config.username == "u"
    assert password == "pw"


def test_no_proxy_beats_the_proxy_flag_being_absent():
    settings = Settings(proxy=parse_proxy_url("http://app:3128"))
    config, _ = resolve_proxy(_session(), _args("--no-proxy"), settings)
    assert config is None


def test_a_session_set_to_none_ignores_the_app_proxy():
    settings = Settings(proxy=parse_proxy_url("http://app:3128"))
    config, _ = resolve_proxy(_session(proxy_mode="none"), _args(), settings)
    assert config is None


def test_a_session_uses_the_app_proxy_by_default():
    settings = Settings(proxy=parse_proxy_url("http://app:3128"))
    config, _ = resolve_proxy(_session(), _args(), settings)
    assert config.host == "app"


def test_proxy_exclude_flags_are_appended():
    settings = Settings(proxy=parse_proxy_url("http://app:3128"))
    config, _ = resolve_proxy(
        _session(), _args("--proxy-exclude", "*.internal"), settings
    )
    assert "*.internal" in config.exclude
    assert "<local>" in config.exclude  # the defaults are kept


def test_excluding_does_not_mutate_the_stored_settings():
    settings = Settings(proxy=parse_proxy_url("http://app:3128"))
    resolve_proxy(_session(), _args("--proxy-exclude", "*.internal"), settings)
    assert settings.proxy.exclude == ["<local>"]


def test_proxy_exclude_none_clears_the_defaults():
    # Without this there is no way to proxy loopback or a dotless name,
    # because the default <local> entry always sends them direct.
    settings = Settings(proxy=parse_proxy_url("http://app:3128"))
    config, _ = resolve_proxy(_session(), _args("--proxy-exclude", "none"), settings)
    assert config.exclude == []


def test_proxy_exclude_none_still_keeps_any_others_given():
    settings = Settings(proxy=parse_proxy_url("http://app:3128"))
    config, _ = resolve_proxy(
        _session(), _args("--proxy-exclude", "none", "--proxy-exclude", "*.dmz"), settings
    )
    assert config.exclude == ["*.dmz"]
