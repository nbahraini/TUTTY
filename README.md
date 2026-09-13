# tutty (pytty)

A terminal session manager for SSH. Saved connection profiles like PuTTY, a
keyboard-driven interface that runs in your terminal, the two things that keep
a session alive across a bad network — liveness probing and automatic
reconnection — and the tunnels to get you in: `-L`, `-R`, `-D` and `-J`
outward, and an HTTP or SOCKS proxy inward when port 22 is not reachable from
where you are sitting.

```
  Network
  ◐ edge-router      admin@10.20.0.1          ka ↻ ⇢
  · core-switch      admin@10.20.0.2          ka ↻ ⇢
  Production
  ○ app-01           deploy@app01.internal    ka ↻ ⇢
  · app-02           deploy@app02.internal    ka ↻
  ✕ db-primary       postgres@db01.internal   ka ↻ ⇢
```

Each row carries its own state in the left gutter, and the `ka` / `↻` / `⇢`
badges light up only when keepalive, reconnect and a proxy are actually in
force for that host, so you can see which machines are protected — and which
are going out through a proxy — without opening anything.

##  Simple Usage (install, Setup and use) 
```
run-tutty.bat   #in windows system (tested on win11)
run_tutty.sh    #in Linux system (tested and used for Long term on Denian 12)
```
## Install

```sh
pip install -e .            # from a clone
pip install -e '.[keyring]' # also store passwords in the OS keyring
```

Python 3.10 or newer. Depends on `paramiko` and `textual`.

## Use

```sh
pytty                       # open the session manager
pytty prod-web              # connect straight to a saved session
pytty deploy@10.0.0.5       # connect without saving anything
pytty --list                # print saved sessions
pytty --import-ssh-config   # add the hosts from ~/.ssh/config
```

The import understands `ProxyJump`, `LocalForward`, `RemoteForward` and
`DynamicForward`, so hosts that already had tunnels configured keep them.

Useful one-off flags:

```sh
pytty prod-web --keepalive 15 --keepalive-count 2
pytty prod-web --no-reconnect
pytty prod-web --attempts 5 --reconnect-delay 1 --max-delay 30
pytty deploy@app01 -J deploy@bastion -L 9090:127.0.0.1:9090
pytty deploy@app01 -D 1080
pytty deploy@app01 --proxy socks5h://proxy.corp:1080
```

### Keys

In the session list: `enter` connects, `n` new, `e` edit, `u` duplicate,
`d` delete, `/` filter, `i` import, `p` settings, `r` reload, `?` all keys,
`q` quit. In settings, `ctrl+t` tests the proxy and `ctrl+s` saves.

While connected, `ctrl+]` closes the session and returns you to the list. In a
tunnel-only session (`-N`) there is no shell, so `ctrl+]` or `q` closes it.
Everything else goes to the remote host untouched. During a reconnect
countdown, `enter` retries immediately and `q` stops retrying.

## Tunnels

Four flags, all repeatable except `-J`, all also editable per session on the
tunnels tab so they come back on every reconnect:

| Flag | Spec | What it does |
|---|---|---|
| `-L` | `[bind:]port:host:port` | listens locally, forwards to one fixed destination |
| `-R` | `[bind:]port:host:port` | listens on the remote host, forwards back to you |
| `-D` | `[bind:]port` | SOCKS proxy; the client picks the destination |
| `-J` | `user@host[:port]` | connect through a bastion, comma separated to chain |

```sh
pytty prod-web -L 5432:db01.internal:5432    # one service
pytty prod-web -R 8000:127.0.0.1:3000        # expose your local dev server
pytty prod-web -D 1080                       # everything, via SOCKS
pytty prod-web -J admin@bastion,admin@inner  # two hops
```

`-D` is the one to reach for when you do not know the destinations in
advance. It speaks SOCKS5 and SOCKS4/4a `CONNECT`, so browsers, `curl
--socks5-hostname`, and anything honouring `ALL_PROXY` can use it:

```sh
curl --socks5-hostname 127.0.0.1:1080 http://internal.example.com/
```

Hostnames are resolved at the far end, which is usually the point — internal
names that mean nothing on your machine resolve correctly inside the network
you are tunnelling into. `--socks5-hostname` rather than `--socks5` is what
keeps that true for curl; the plain form resolves locally first.

Like OpenSSH, a bare `-D 1080` binds to loopback only. Write `-D
0.0.0.0:1080` if you really want the whole network using your session as an
exit — the listener authenticates nobody, so anyone who can reach the port
gets everything the remote host can reach.

Only `CONNECT` is implemented. SOCKS `BIND` and UDP association are refused
with the proper reply code rather than left to hang, which is also what
OpenSSH does. There is no proxy authentication: the listener is on loopback
by default and adding a password to a local socket buys nothing.

Tunnels are torn down and rebuilt around a reconnect, so the SOCKS port stops
accepting for the few seconds the link is down rather than accepting
connections it cannot service. Anything in flight when the link dies is lost —
the proxy cannot replay a TCP stream it does not buffer.

## Going through a proxy

The tunnel flags above make pytty *offer* a proxy. This is the opposite: using
one to reach the SSH server in the first place, for when the machine you are
sitting at cannot open port 22 to the outside world.

```sh
pytty prod-web --proxy socks5h://proxy.corp:1080
pytty prod-web --proxy http://user:pass@proxy.corp:3128
pytty prod-web --proxy https://secure-proxy.corp:8443
pytty prod-web --no-proxy                       # ignore whatever is configured
```

Four kinds are supported: `http` and `https` (both `CONNECT`), `socks4` (with
4a hostnames) and `socks5`. `https` means TLS to the proxy *itself*, so the
`CONNECT` line and any credentials are not in clear on the first hop — it is
not about the traffic inside, which is SSH either way.

`socks5://` resolves the hostname locally; `socks5h://` sends the name to the
proxy, which is usually what you want, since internal names rarely resolve on
your machine. `http`, `https` and `socks4a` always resolve at the far end.

### Setting it once

A proxy is a property of where you are sitting, not of the machine you are
dialling, so it lives in the application settings rather than on every
session. Press `p` in the session list, fill it in, and press `ctrl+t` to test
it against the highlighted host before saving — the test opens a real tunnel
and closes it, and reports the actual handshake error when it cannot.

Individual sessions override this on their Proxy tab: **use the application
proxy** (the default), **connect directly**, or **use a proxy just for this
session**. So a laptop that moves between a corporate network and home needs
one setting changed, not forty.

If no proxy is configured, `ALL_PROXY`, `HTTPS_PROXY` and `HTTP_PROXY` are
honoured, along with `NO_PROXY`. Setting the proxy to "none" in the interface
really does mean none — the environment is only consulted when nothing is
configured.

### What is proxied, and what is not

Only the first outbound connection: the SSH server, or the first host in a
`-J` chain. Later hops already travel inside the connection the proxy carried,
and the destinations of `-L`, `-R` and `-D` are reached from the remote end.
Wrapping any of those in the proxy again would be tunnelling a tunnel.

Proxying stacks with everything else, so the awkward case works:

```sh
pytty deploy@app01 --proxy socks5h://proxy.corp:1080 -J deploy@bastion -D 1080
```

That is: reach the bastion through the corporate proxy, hop to app01, and
serve a local SOCKS proxy on 1080 out the far side.

### Exclusions

Hosts on the exclusion list are dialled directly. The default list is
`<local>`, which covers loopback and any name with no dot in it — the same
rule browsers use, and an easy one to trip over: `myserver` bypasses the proxy
while `myserver.corp.example` does not. Patterns can be globs (`*.internal`),
suffixes (`.corp.example`) or CIDR (`10.0.0.0/8`).

```sh
pytty prod-web --proxy-exclude '*.internal'   # add to the list
pytty prod-web --proxy-exclude none           # clear it, proxy even loopback
```

Proxy passwords go to the OS keyring under their own service name, never into
a configuration file. A proxy username with no stored password is asked for
once, rather than being sent as empty and failing the handshake.

## More of PuTTY

```sh
pytty prod-web -N                    # tunnels only, no shell
pytty prod-web -X                    # forward X11
pytty prod-web -A                    # forward the agent
pytty prod-web -g                    # let other hosts use the forwards
pytty prod-web -4                    # IPv4 only, -6 for IPv6
pytty prod-web -b 10.0.0.9           # connect from a particular address
pytty prod-web --env LANG=en_GB.UTF-8
pytty prod-web --log '~/logs/&N-&Y&M&D-&T.log' --log-mode all
```

Everything here is also editable per session, on the **Tunnels**, **Proxy**
and **Advanced** tabs, so it comes back on every reconnect.

| Option | PuTTY's name for it | Notes |
|---|---|---|
| `-N` | "Don't start a shell or command at all" | needs at least one forward to be worth opening |
| `-X` | X11 forwarding | trusted, see below |
| `-g` | "Local ports accept connections from other hosts" | an explicit bind in the spec still wins |
| `-b` | logical source address | |
| `--env` | Connection → Data → Environment | most servers only accept what `AcceptEnv` allows, and a refusal is logged rather than fatal |
| `--log` | Session logging | `&H` host, `&N` name, `&Y&M&D` date, `&T` time, `&&` a literal `&` |
| Disable Nagle | Connection → "Disable Nagle's algorithm" | on by default; an interactive session wants latency, not full packets |

Session logs are raw, escape sequences and all, so `cat`ting one replays the
session — which a stripped log cannot do. A reconnect appends rather than
truncating, so the record of the link that just died survives.

X11 forwarding hands your real xauth cookie to the server, which makes it
*trusted* forwarding, equivalent to `ssh -Y` rather than `-X`. Anything you
forward to has full access to your display: it can read your keystrokes in
other windows and take screenshots. Untrusted forwarding needs a second
restricted cookie swapped into each connection, which pytty does not do. The
switch says so in the interface.

Terminal appearance — fonts, colours, the bell, backspace behaviour — is not
here and will not be. pytty hands your existing terminal to the remote host in
raw mode, so those are your terminal emulator's settings, not pytty's.

## How the keepalive works

paramiko has a `set_keepalive` method, but it only *sends* probes — nothing
ever gives up when the replies stop. That is fine for holding a NAT mapping
open and useless for noticing a dead peer.

pytty sends `keepalive@openssh.com` global requests on a worker thread and
counts the ones that go unanswered, which is what OpenSSH's
`ServerAliveInterval` and `ServerAliveCountMax` do together. Any reply proves
liveness, including an explicit refusal from a server that does not implement
the extension. After a missed probe the next one goes out immediately rather
than after another full interval, because the interval of silence has already
elapsed. That keeps the worst case at:

```
interval × (count_max + 1)
```

which is the number the editor shows you as you type. With the default 30s and
3 misses, a silent link is dropped after about two minutes.

`SO_KEEPALIVE` is also set on the socket, with `TCP_KEEPIDLE`, `TCP_KEEPINTVL`
and `TCP_KEEPCNT` where the platform supports them, so the operating system
watches the connection too. For firewalls that only count terminal data as
traffic, the "null packets" option sends a NUL byte down the channel the way
PuTTY does.

## How the reconnect works

A session ends for exactly three reasons and only one of them is worth
retrying:

| Ending | What happened | Default |
|---|---|---|
| detached | you pressed `ctrl+]` | stop |
| remote exit | the shell exited on its own | stop |
| dropped | the link died | reconnect |

Reconnecting after a clean `exit` would trap you in a session you asked to
leave, so it is off unless you turn it on — worth having for a kiosk or a
serial console that should always be up.

Backoff doubles from the first wait up to the ceiling, with full jitter
applied. The jitter matters when a rack of machines comes back from one
outage: without it they all retry in lockstep and hit the server together.

Commands listed under "on login" are replayed after *every* successful login,
including reconnects. Setting that to `tmux attach -t work || tmux new -s work`
gets you back to the same screen you lost, which is the part of a reconnect
that people actually care about.

## Where things are stored

Sessions live in `~/.config/pytty/sessions.json` (`%APPDATA%\pytty` on
Windows), written atomically and `chmod 600` — the file names every host you
care about even when it holds no secrets. Override with `PYTTY_HOME` or
`--config`. Application settings, including the proxy, live beside it in
`settings.json` and get the same treatment.

Passwords are never written to those files. With the `keyring` extra installed
they go to the OS keyring; without it, pytty asks each time and says so on
startup rather than failing quietly. Proxy passwords use their own keyring
service, so a proxy credential can never collide with a session that happens
to share its name.

Host keys are checked against `~/.ssh/known_hosts` and pytty's own
`known_hosts`. New keys prompt with the SHA256 fingerprint by default. You can
set a session to refuse unknown hosts outright, or to trust anything — the
latter is labelled unsafe in the interface because it is.

## Tests

```sh
python -m pytest tests/                  # 157 unit tests
python tests/tui_snapshot.py             # headless interface checks
python tests/e2e_reconnect.py KEYFILE    # needs sshd on 127.0.0.1:2222
python tests/e2e_keepalive.py KEYFILE    # needs sshd on 127.0.0.1:2222
python tests/e2e_socks.py KEYFILE        # needs sshd on 127.0.0.1:2222
python tests/e2e_proxy.py KEYFILE        # needs sshd on 127.0.0.1:2222
```

The proxy tests come in two halves. The unit tests drive the real client over
a real socket against a fake proxy, so the bytes on the wire are checked
rather than mocked — including that the SOCKS5 request carries its destination
port, and that an HTTP proxy which puts the end of its response head and the
first tunnelled bytes in one segment does not lose them.

`e2e_proxy` stands up SOCKS5 and HTTP proxies in-process and drives the real
CLI through a real pty at a real sshd: connect through each, check a command
runs, check a wrong proxy password is reported rather than hung on, check an
unreachable proxy names the proxy rather than the host, and check `--no-proxy`
ignores `ALL_PROXY`. Both halves earned their keep — the missing SOCKS5 port
passed the unit tests of the time and was caught here.

The SOCKS unit tests drive the real handler over a real socket against a fake
transport whose `open_channel` returns one end of a socketpair, so the
protocol parsing and the byte pump are exercised without a server. One of them
asserts that a failed tunnel writes nothing to stderr, because pytty holds the
terminal in raw mode and a stray traceback would land in the user's shell.
`e2e_socks` is the complete path: it stands up a throwaway HTTP server,
fetches it through the proxy, kills the link, and fetches again after the
reconnect rebuilds the listener.

The two end-to-end tests drive the real CLI through a real pty against a real
sshd. `e2e_reconnect` connects, runs a command, kills the server side of the
link, and checks the session comes back and still works. `e2e_keepalive` is the
more interesting one: it puts a proxy in front of sshd and makes it stop
forwarding bytes *without closing anything*, which is what a forgetful NAT box
or a dropped Wi-Fi bridge looks like. There is no FIN and no RST, so nothing
below the application layer notices. That is the failure keepalive exists for,
and it is detected in about 11 seconds against a 12 second budget.

To set up a local sshd for those:

```sh
ssh-keygen -t ed25519 -f host_key -N ''
ssh-keygen -t ed25519 -f id_test -N ''
cat id_test.pub >> ~/.ssh/authorized_keys
/usr/sbin/sshd -f sshd_config   # Port 2222, ListenAddress 127.0.0.1
```

## Known gaps

The Windows input path (`msvcrt` plus a `ctypes` call to enable virtual
terminal input) is written but has not been run on Windows — everything here
was tested on Linux. The rest of the code is platform-neutral.

pytty is a session manager, not a terminal emulator. It hands your existing
terminal to the remote host in raw mode, so the fidelity of the session is
whatever your terminal already gives you.
