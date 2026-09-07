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

`porthole list` and `porthole status` need none of that installed at all —
they never touch the bus. `--dry-run` changes nothing and needs no privileges
either, with one exception: `open --dry-run` makes the one read-only call
every `open` makes, asking the helper whether Docker has already published
that port. That call is best-effort — no helper, no answer, no complaint, and
the dry run goes ahead. Once the helper is installed, opening towards
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

**It does not manage IPv6.** Version 1 opens and closes IPv4 rules and
nothing else. On a network with IPv6 active, a port porthole reports as
closed can still be reachable over IPv6, and opening one changes nothing for
IPv6 traffic. porthole's own account of what it did says nothing either way.
`porthole listen` marks the services it can see bound to a real IPv6 address
and `porthole doctor` repeats the caveat, but neither is a rule porthole can
act on.

## Design

- **The default scope is the subnet you are on**, not "anyone who can reach this
  interface". Opening towards everyone is possible, but you have to ask for it.
- **The default duration is one hour, and the maximum is eight.** Past that
  there is only `--until-reboot`, which still dies by itself. A low ceiling is
  what makes "temporary" true.
- **Automatic close runs on a systemd transient timer**, so you can see it with
  `systemctl list-timers` and it does not depend on any process staying alive.

## The GUI

Everything above is also a window. `porthole-gui` shows what is open now with
a live countdown, shows what is listening on this machine so you can open a
port without typing a number, opens one in two clicks, and saves a device to
open towards. It talks to the
same privileged helper over the same D-Bus interface the CLI uses, so it
inherits the 8-hour ceiling and the polkit prompts without restating either —
nothing about *what* porthole will do changes depending on which one you run.
A window has no exit code to inherit; a failed request shows the helper's own
message in the GUI instead, the same wording the CLI would have printed.

![The Porthole window: two rules under "Open now", one with a live countdown and one until reboot, and six services under "Listening", one of them already open and one reachable only over IPv6](docs/screenshot.png)

*Rendered by the app itself, under Xvfb, from invented example data — not a
real machine's, which would either show nothing on a machine with no ports
open or leak whatever is genuinely listening on the machine that took it.*

GTK4/libadwaita is not required to build or run the CLI or the helper — the
GUI lives in its own crate, `porthole-gui`, built and tested in a container
(`tests/container/Containerfile.gui`) because this project's own development
host has no GTK4 installed. See [docs/installing.md](docs/installing.md) for
the desktop file, icon and AppStream metadata that make it appear in an app
grid or a software centre once installed.

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

That gives you `porthole list`, `porthole status`, `porthole doctor`,
`porthole devices` and `--dry-run`. `open` and `close` need the privileged
helper installed; so does the Docker half of `porthole listen`, `porthole
open` and `porthole doctor`, since reading Docker's own rules needs root. The
same `cargo build --release` also produces `porthole-agent`, which is what
turns a close nobody asked for into a desktop notification.

For all of it at once — the three binaries, the polkit policy, the D-Bus
files, the systemd units, the icons, the man pages and the shell completions
— the `Makefile` installs the layout every package of this project uses:

```bash
make                                  # cargo build --release, plus the
                                      # man pages and completions
make build-gui                        # needs GTK4/libadwaita headers
sudo make install PREFIX=/usr
```

`DESTDIR` is honoured by every rule, so a packager stages into one and never
touches the live system: `make install DESTDIR=/tmp/stage PREFIX=/usr`.
`make check-install` does exactly that into a throwaway directory and prints
what landed. `WITH_GUI=0` leaves out the GUI binary, its desktop entry and
its AppStream metainfo, for a machine with no desktop. `PREFIX` defaults to
`/usr` rather than `/usr/local` because the D-Bus activation file names
`/usr/libexec/porthole-helper` literally; see
[docs/installing.md](docs/installing.md), which also covers installing each
piece by hand.

### Removing it

Removing the package closes every port porthole still has open, first. That is
not a courtesy: uninstalling is the one action that ends every other way a
porthole rule could close. The timer that would have closed it re-executes
`/usr/bin/porthole`; `close`, the network-change monitor and reconciliation
all go through the helper. Take those away and the rule stays in the firewall,
with the record of it on a tmpfs and nothing left that can act on it.

So each of the three packages runs `porthole close --all` on the way out, and
only on the way out: `%preun` when `$1` is 0 (RPM), `prerm remove` (Debian),
`pre_remove` (Arch). An **upgrade** closes nothing — losing the access you
arranged would be a bad way to learn a new version had shipped.

It is best effort, and it says so when it fails. A removal must not fail
because a port could not be closed, so if the helper cannot be reached — no
system bus, polkit not running, a helper left broken by an earlier failed
upgrade — the removal continues and prints:

```
porthole: WARNING: `porthole close --all` failed (exit 1).
porthole: Any port porthole had open is still open, and removing this
porthole: package leaves nothing behind that would close it. Check with
porthole: `firewall-cmd --list-rich-rules`, `ufw status numbered` or
porthole: `nft list ruleset` and remove what is left by hand.
```

That warning is the residual gap, and it is a real one. On firewalld and
nftables the rule porthole added is a runtime rule, so a reboot is the last
thing left that will close it. On ufw not even that: `ufw allow` writes into
`/etc/ufw/user.rules` and `ufw.service` reloads that file at every boot, and
the reconciliation that would otherwise sweep the rule runs inside a
`porthole` command there will never be another of. If you would rather not
depend on the removal reaching the helper, run `porthole close --all`
yourself first.

A `make install` installation has no scriptlets at all, and `make uninstall`
closes nothing — close first, by hand.

## Usage

```
porthole open <PORT> [--proto tcp|udp] [--for 30m | --until-reboot]
                     [--to subnet|any|<CIDR>|<IP>|<device name>]
porthole close <PORT> | --id <ID> | --all
porthole list
porthole status
porthole doctor
porthole listen
porthole devices list | add | rm <name>
```

`--to <name>` opens towards a saved device — see [Saved
devices](#saved-devices) below. `porthole listen` lists what is listening on
this machine, so you can pick a port instead of typing one.

Global flags:

- `--json` — machine-readable output. Every command that reports something
  honours it, and so does every failure. `devices add` is interactive, so its
  prompts go to stderr and stdout carries only the device it saved. See
  [docs/json-schema.md](docs/json-schema.md).
- `--dry-run` — print the commands porthole would run, and change nothing. Needs
  no privileges.

Defaults: `--proto tcp`, `--for 1h`, `--to subnet`.

## Saved devices

Opening towards one machine rather than the whole subnet means knowing its
address, and under DHCP that address changes. A saved device records a **MAC
address** instead, and `--to <name>` looks it up in the kernel's neighbour
table at the moment the port is opened — never earlier.

```console
$ porthole devices add
Seen on this network:
  1) bc:24:11:5e:1c:6e  10.10.10.245  (wlo1)
  2) 50:e6:36:1a:9f:04  10.10.10.1    (wlo1)
Pick a number: 1
Name this device: phone
Saved `phone` as bc:24:11:5e:1c:6e.

$ porthole devices list
phone    bc:24:11:5e:1c:6e  resolves to 10.10.10.245
printer  printer.local      not on this network right now

$ porthole open 5173 --to phone --for 30m
Opened 5173/tcp towards 10.10.10.245/32 · closes 30m 0s
```

`devices add` is an interactive prompt and offers the kernel's neighbour
table, minus the entries that carry no mapping worth acting on (`FAILED` and
`INCOMPLETE`, below) and minus every entry on a virtual interface. So a device
that has not spoken to this machine recently is not in the list, and neither
is one the kernel probed without getting an answer: make it talk to this
machine — load something from it, or ping it — and run the command again. It
saves a MAC and nothing else.

Docker containers, libvirt guests, podman pods and VPN peers all sit in the
kernel's neighbour table, on the interfaces that carry them. None of them is
on the network porthole opens a port towards, and the picker excludes exactly
the interfaces subnet detection already excludes (`docker*`, `br-*`,
`virbr*`, `veth*`, `podman*`, `tun*`, `tap*`, `wg*`, `tailscale*`, `zt*`,
`cni*`, `vboxnet*`, `lo`). A traditional `br0` bridging this machine's own
NIC is not one of them and is still offered. The same exclusion applies at
resolution time, so a MAC that is only in the table on one of those
interfaces reports as not on this network rather than resolving to an address
outside every subnet this machine holds. A device
named by hostname (`host = "printer.local"`, resolved through `getent`) is
added by editing `~/.config/porthole/devices.toml` by hand.

The GUI writes the same file, through **Saved Devices** in its menu or the
button beside the open dialog's target list. It offers the same picker and
adds a field for typing a MAC by hand, for a device that is switched off and
so cannot be picked. Such a device is saved without being found: the dialog
says at that moment that it did not resolve, and `open --to <name>` fails
with exit code 6 until it does.

That file is the whole address book, and it lives client-side. **The
privileged helper never reads it**: `--to <name>` is resolved in the CLI, and
what crosses D-Bus is an address. The rule that comes back records that
address as a `/32`, not the name — `porthole list` shows `10.10.10.245/32`,
and nothing porthole stores remembers that you asked for `phone`.

A few narrow edges worth knowing before you hit them:

- A device name that `--to` would read as a scope is refused when you save
  it, and refused again when the book is read back: `subnet`, `any`, an IP
  address or a CIDR, and any name containing `/` or `:`. Each of those would
  be taken as a scope rather than looked up, leaving the device saved and
  unreachable.
- A device that does not resolve right now is not an error in `devices list`,
  which says so per row. It is one for `open`, which fails with `device
  unreachable` and exit code 6 rather than opening towards a guess.
- `resolves to <address>` reports what the neighbour table holds, not a
  reachability test — porthole sends nothing to check. Entries the kernel
  marks `FAILED` or `INCOMPLETE` are rejected, since neither carries a mapping
  worth acting on. A `STALE` entry is accepted, because that is the ordinary
  state of an idle device — so a device that has just left can still be opened
  towards, until the kernel drops or rewrites its entry. **And the address it
  left behind may no longer be its own.** DHCP hands an address out again once
  the lease is gone, so `--to phone` can open a port towards whatever took
  that address next — a visitor's laptop on the same network. porthole cannot
  tell the two apart, and the rule stands for its whole duration either way.
  Keep the durations short, and prefer `porthole close` to waiting one out.

## Docker

Docker publishes ports by writing its own iptables rules, and those are
evaluated before firewalld, ufw or nftables ever see the packet. So a
container published on `0.0.0.0` is already reachable and `porthole close`
will not close it, and a container published on `127.0.0.1` is not made
reachable by `porthole open`, because the firewall was never what was stopping
it. **porthole only ever diagnoses this. It never changes a Docker rule.**

Three commands say so:

- `porthole listen` marks each published row `docker: published on
  <address>`, or `published on every interface`.
- `porthole open <port>` prints a note when Docker has published that exact
  port and protocol. It still opens the rule.
- `porthole doctor`'s `Docker` check names the published ports it could read.

All three read the `DOCKER` chain of iptables' `nat` table directly. porthole
never runs `docker` and never looks at `docker` group membership, so it
behaves the same whether or not you can query Docker at all. That read needs
root, so it goes through the privileged helper. **With the helper not
installed or not answering, `listen` and `doctor` say they could not check**
rather than reporting that Docker touches nothing. `open` does not: it prints
its note when it has one and says nothing otherwise, so silence there means
either that no container holds that port or that Docker could not be asked.
`listen` is what tells those apart. `doctor` has one narrower
condition of its own — it looks for the interface `docker0` first, and reports
`not present` without asking the helper when there is none, so a daemon
configured with no default bridge reads as absent there.

Publish container ports on `127.0.0.1` in your compose files if you do not
want them reachable from the network. porthole cannot do that for you.

## When the network changes

A rule opened towards `10.10.10.0/24` in a café means nothing at home, and
leaving it in place would be a rule aimed at whoever holds those addresses
next. So the helper watches the machine's own subnet and closes what no longer
belongs to it.

It wakes on two things: NetworkManager's `StateChanged` signal, and a poll
every 60 seconds that does not depend on NetworkManager at all. Every wake-up
reads every subnet this machine currently holds on a non-virtual interface —
wifi, ethernet, anything that is not a bridge, a container network or a VPN
tunnel — and compares that whole set with the set the previous wake-up saw.

- **A subnet is gone.** A subnet counts as gone only when no non-virtual
  interface still carries it — not when it merely stops being the one the
  default route names. Rules whose target lies *inside* a subnet that is gone
  are closed. A rule towards a wider or unrelated range — a deliberate
  `--to 10.0.0.0/8` — is left alone, and so is `--to any`.
- **There is no usable network.** Every subnet-scoped rule closes. `--to any`
  survives.

Each close is written to the helper's journal and announced on the bus, which
is where the [notification](#desktop-notifications) below comes from.

What this does not cover, and you should not assume otherwise:

- **Only subnets the helper observed itself.** The first wake-up after the
  helper starts records what it finds and closes nothing — there is nothing to
  compare against yet. A wake-up that finds nothing open skips the check and
  forgets what it had seen too, so the first rule opened after that also
  starts from no baseline. A rule opened on a network the helper never saw is
  never closed by a subnet change, however many wake-ups follow. It still ends at its
  expiry, at a `close`, or on a confirmed loss of every network.
- **Docking closes nothing, and neither does any other change that leaves a
  subnet in place.** A machine with wifi and ethernet both up holds both
  subnets, and a subnet is gone only when no non-virtual interface still
  carries it. So docking a laptop — ethernet takes the default route, wifi
  stays up — leaves every rule aimed inside the wifi subnet open. Those rules
  end when wifi itself goes down, at their expiry, or when you close them. Do
  not read "the network changed" as having closed them for you.
- **The monitor lives only as long as the helper process.** The helper is
  D-Bus activated and is not started at boot; if it is stopped or crashes,
  nothing restarts it until the next porthole command, and a network change in
  that window is not noticed. Automatic expiry does not share this gap — it is
  a systemd timer outside the process.

## Desktop notifications

A port that expires while the window that opened it is long gone closes
silently. `porthole-agent` is what says so: one per logged-in session, no
window and no interface of its own, listening on the system bus and showing a
desktop notification through `org.freedesktop.Notifications`.

It announces the closes **nobody asked for** — an expiry, a network change,
and a rule the firewall no longer had when porthole next looked — and only for
rules opened by your own uid. A close you asked for is not announced: you were
there, and the client you ran told you.

An **expiry** notification carries a `Reopen` button that re-sends the same
port, protocol, scope and duration. That is a fresh request to open a port, so
polkit asks again wherever the scope warrants it. The other two offer no
button: after a network change the machine is somewhere else and the rule
would reach nobody, and after a reconciliation something outside porthole
removed the rule and porthole cannot tell what.

The agent ships two start files, a systemd user unit and an XDG autostart
entry, because desktops differ in which they honour — see
[docs/installing.md](docs/installing.md). Installing both does not double
anything: it takes a session bus name, and a second copy finds the name taken
and exits. A session with no notification service running is survived rather
than reported: it keeps listening, and the closes are still in the helper's
journal.

**Neither start file runs in a session that is already open, so notifications
begin at the next login.** Installing porthole — from a package or by hand —
puts both files in place and starts nothing. The user unit is reached through
`graphical-session.target` and the autostart entry when a desktop session
begins; both of those have already happened. Since an announced close is the
*only* signal a timed port has gone — the window that opened it is usually
shut by then — a port opened in the session that installed porthole closes
without a word. To have notifications in the session you are in:

```bash
systemctl --user start porthole-agent.service
```

That works whether or not the unit is enabled, and whether or not your desktop
starts user units at all: it starts the one unit, now.

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
| 9 | There was nothing to choose from. `porthole devices add` found no device on this network to offer. |

These are a public interface. New codes are added at the end; existing ones are
never renumbered.

## Limitations

- **IPv6 is out of scope for version 1.** porthole only manages IPv4 rules. On a
  network with IPv6 enabled, opening or closing an IPv4 port tells you nothing
  about IPv6 reachability. Do not assume you are protected. See [What it is
  not](#what-it-is-not).
- **Three backends, chosen for you, never asked about.** porthole detects and
  drives whichever firewall this machine already has installed — firewalld,
  then ufw, then nftables, in that order — and each one has its own honest
  limitation the others do not share, in a way you cannot see from the CLI
  alone: firewalld can never prove which of its rich rules are porthole's, so
  it will not remove one it did not create even after losing track of it;
  ufw's rules survive a reboot until the next porthole command sweeps them;
  and nftables refuses to guess when it cannot prove which chain decides a
  packet's fate. See [docs/backends.md](docs/backends.md) for what each
  backend can do, what it cannot, and why — `porthole doctor` also names the
  one it found.
- **Docker publishes ports below the firewall, in both directions.** A
  container published on `0.0.0.0` is already reachable and porthole cannot
  close it; one published on `127.0.0.1` is not made reachable by opening the
  firewall. porthole reports this and never changes a Docker rule — and the
  report itself needs the privileged helper. See [Docker](#docker) above.
- **A network change is noticed, not guaranteed to be.** The helper closes
  rules tied to a subnet the machine has left, but only for subnets it
  observed itself, and only while the helper process is running. A subnet
  counts as left only when no non-virtual interface still carries it, so a
  rule survives any change that leaves its own subnet in place — docking a
  laptop with wifi still up is the ordinary case. See [When the network
  changes](#when-the-network-changes) above for each of those in full.
- **Reconciliation runs before every command, not continuously.** A
  `firewall-cmd --reload`, a reboot, or a rule removed by hand between two
  porthole commands is invisible until the next one runs — `porthole list`
  can briefly claim a port is open that the firewall already dropped. That is
  the safe direction: porthole over-reports exposure rather than
  under-reporting it, and the next command corrects it on its own, with
  nothing to run by hand. The one direction that never runs on firewalld is
  the other one — removing a rich rule state does not know about. firewalld's
  rich rules carry no marker, so porthole can never prove such a rule is its
  own; the sweep is not attempted there at all, rather than attempted
  carefully. It does run on ufw and nftables, where the marker exists. See
  [docs/backends.md](docs/backends.md).
- **No Flatpak, and there will not be one.** The privileged half of porthole is
  a polkit policy and a system D-Bus service; a Flatpak cannot install either.

## Licence

GNU General Public License v3.0 or later. See [LICENSE](LICENSE).
