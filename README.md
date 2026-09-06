# porthole

Open a port to your local network, temporarily and on purpose — and let it close
itself.

On a laptop, exposing a dev server to the local network is an all-or-nothing
choice that every existing tool handles badly. Fedora Workstation opens ports
1025-65535 by default, so every high port is reachable by anyone on the hotel
wifi. Closing that range is the right thing to do, but from then on testing a
site from your phone means remembering `firewall-cmd` syntax, remembering to
close it again, and knowing which firewall the machine you are on actually uses.

porthole does one thing: it opens a single port towards the network you are on
right now, for a bounded amount of time, and closes it again.

```console
$ porthole open 5173 --for 30m
Opened 5173/tcp towards 10.10.10.0/24 · closes 30m 0s

$ porthole list
PORT      TOWARDS        BACKEND    CLOSES IN
5173/tcp  10.10.10.0/24  firewalld  29m 41s

$ porthole close 5173
Closed 5173/tcp towards 10.10.10.0/24
```

Opening and closing no longer need root: a privileged helper does the work — a
system D-Bus service authorised by polkit, rather than the CLI holding
privilege itself. Installing it does need root, **once**: a helper binary, a
polkit policy, a D-Bus configuration and a systemd unit. See
[docs/installing.md](docs/installing.md) for where each one goes; until a
distribution packages porthole, you place them by hand.

`porthole list`, `porthole status` and anything with `--dry-run` need none of
that installed at all — they never touch the bus. Once it is, opening towards
your own subnet asks polkit to authenticate the first time and not again that
session; opening towards everyone (`--to any`) asks every time, because it is
the more dangerous request; closing never asks, because closing only ever
reduces what is exposed.

## What it is not

porthole is not a firewall manager. It does not do zones, services, NAT, port
forwarding or permanent rules. If you need those, use `firewall-config`, `ufw`
or `nft` directly.

**It never writes a permanent rule.** A reboot closes everything porthole
opened. That is the whole design, not a limitation.

## Design

- **The default scope is the subnet you are on**, not "anyone who can reach this
  interface". Opening towards everyone is possible, but you have to ask for it.
- **The default duration is one hour, and the maximum is eight.** Past that
  there is only `--until-reboot`, which still dies by itself. A low ceiling is
  what makes "temporary" true.
- **Automatic close runs on a systemd transient timer**, so you can see it with
  `systemctl list-timers` and it does not depend on any process staying alive.

## Install

Distribution packages are not published yet. To build from source you need Rust
1.87 or newer — the privileged helper depends on `zbus`, and every `zbus 5.19`
component declares `rust-version = "1.87"`. **Debian 13 ships rustc 1.85**, so
packaging porthole for it means bringing a newer toolchain along, not just
running `cargo build` with the system one.

```bash
git clone https://github.com/jmbriccola/porthole
cd porthole
cargo build --release
sudo install -m 0755 target/release/porthole /usr/local/bin/porthole
```

That gives you `porthole list`, `porthole status`, `porthole doctor` and
`--dry-run`. `open` and `close` also need the privileged helper installed —
see [docs/installing.md](docs/installing.md).

## Usage

```
porthole open <PORT> [--proto tcp|udp] [--for 30m | --until-reboot]
                     [--to subnet|any|<CIDR>|<IP>]
porthole close <PORT> | --id <ID> | --all
porthole list
porthole status
porthole doctor
```

Global flags:

- `--json` — machine-readable output, on every command. See
  [docs/json-schema.md](docs/json-schema.md).
- `--dry-run` — print the commands porthole would run, and change nothing. Needs
  no privileges.

Defaults: `--proto tcp`, `--for 1h`, `--to subnet`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Unexpected failure |
| 2 | Invalid arguments |
| 3 | An operation needed a usable firewall and there was none. `porthole status` does not use this code: it reports the situation in its own output and exits 0. |
| 4 | Polkit refused the request. Never `sudo`: the CLI holds no privilege of its own to grant. |
| 5 | That port is already open |
| 6 | The named device is not reachable on this network |
| 7 | No porthole-managed rule matches |
| 8 | No usable network |

These are a public interface. New codes are added at the end; existing ones are
never renumbered.

## Limitations

- **IPv6 is out of scope for version 1.** porthole only manages IPv4 rules. On a
  network with IPv6 enabled, opening or closing an IPv4 port tells you nothing
  about IPv6 reachability. Do not assume you are protected.
- **Three backends, chosen for you, never asked about.** porthole detects and
  drives whichever firewall this machine already runs — firewalld, then ufw,
  then nftables, in that order — and each one is honestly weaker than
  firewalld in a way you cannot see from the CLI alone: ufw's rules survive a
  reboot until the next porthole command sweeps them, and nftables refuses to
  guess when it cannot prove which chain decides a packet's fate. See
  [docs/backends.md](docs/backends.md) for what each backend can do, what it
  cannot, and why — `porthole doctor` also names the one it found.
- **Docker publishes ports below the firewall.** Docker writes its own iptables
  rules, evaluated before firewalld, so a container published on `0.0.0.0` is
  already reachable and closing that port with porthole will not close it.
  Detecting and explaining this is planned; right now porthole does not warn
  you. Publish container ports on `127.0.0.1` in your compose files.
- **Reconciliation runs before every command, not continuously.** A
  `firewall-cmd --reload`, a reboot, or a rule removed by hand between two
  porthole commands is invisible until the next one runs — `porthole list`
  can briefly claim a port is open that the firewall already dropped. That is
  the safe direction: porthole over-reports exposure rather than
  under-reporting it, and the next command corrects it on its own, with
  nothing to run by hand. The one direction reconciliation deliberately does
  not perform is removing a firewalld rich rule state does not know about —
  firewalld rich rules carry no marker, so porthole can never prove such a
  rule is its own to remove. See [docs/backends.md](docs/backends.md).
- **No Flatpak, and there will not be one.** The privileged half of porthole is
  a polkit policy and a system D-Bus service; a Flatpak cannot install either.

## Licence

GNU General Public License v3.0 or later. See [LICENSE](LICENSE).
