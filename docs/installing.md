# Installing the privileged half

`porthole` — the CLI — is one binary and needs nothing else: `porthole list`,
`porthole status`, and `--dry-run` on `open` and `close`, work as soon as it
is on your `$PATH`. `porthole open`, `porthole forward` and `porthole close`
are different: they ask a privileged helper to act, and that helper has to be
installed once, as root, before they work. `porthole listen` and `porthole
doctor` need it too, though only for one part of what they report — reading
Docker's own rules needs root, and without the helper they say they could not
check rather than reporting that Docker touches nothing. This is that
installation.

**`forward --dry-run` is the one dry run that is not in the first group**, and
it is not the helper it wants: it builds the engine in your own process, and
that engine reads Docker's `DOCKER` chain directly, which needs root. So it
exits 10 (`docker_unreadable`) for an ordinary user whether or not the helper
is installed. Saying it could not check is the intended answer — the
alternative is a dry run that reports a forward it never verified.

porthole is in no distribution's repositories yet, and there is no release to
download. What the repository does carry is the packaging for three formats,
each building from this source tree and each installing through the `Makefile`
below rather than listing files of its own: a Debian package under `debian/`,
an Arch `PKGBUILD` under `packaging/aur/`, and an RPM spec under
`packaging/rpm/`. Until one of them is published — and on any distribution
none of them covers — the `Makefile` installs every piece into a `DESTDIR`:

```bash
make                                  # the CLI, the helper and the agent,
                                      # plus the man pages and completions
make build-gui                        # needs GTK4/libadwaita headers
sudo make install PREFIX=/usr
```

`make check-install` stages the same layout into a throwaway directory and
prints what landed, without root. `PREFIX` defaults to `/usr`, not
`/usr/local`, because two of the files below name `/usr/libexec/porthole-helper`
literally. The `Makefile` compares `LIBEXECDIR` against those two files while
it is being read, before any recipe runs, and stops there when they disagree —
so a wrong `PREFIX` leaves nothing at all installed rather than half of it, and
a `PREFIX=/usr/local` install needs `LIBEXECDIR=/usr/libexec` passed alongside
it. `WITH_GUI=0` leaves out the GUI binary, its desktop entry and its AppStream
metainfo.

`make install` also rewrites one line it does not copy verbatim: the agent's
user unit ships `ExecStart=/usr/local/bin/porthole-agent`, the path the
by-hand steps below use, and the installed copy names `$(BINDIR)` instead. A
systemd unit's `ExecStart=` is an absolute path and is never looked up on
`$PATH`.

The rest of this document is the by-hand equivalent — what each file is for
and where it goes, one `install` command at a time.

## The pieces

Building the workspace (`cargo build --release`) produces the helper binary,
the CLI and the session agent; the workspace's own `default-members` leaves
the GUI out of that command, so it needs its own
`cargo build --release -p porthole-gui`, and (see
"The GUI", below) GTK4/libadwaita development headers installed first, unlike
the helper and CLI. This project's own development host has no GTK4 installed
and builds/tests the GUI only inside the container described in the top-level
README, but that is a statement about this host, not a requirement — any
machine with those headers builds it the same way `cargo build --release`
already builds the other two. Ten more pieces are checked into `data/` and
are not installed by anything automatically — you copy them into place
yourself.

| Piece | Goes to | What it does |
|---|---|---|
| `target/release/porthole` (built, not in `data/` — install it per the top-level README, not by the commands below) | `/usr/local/bin/porthole` (a packaged install may instead use `/usr/bin/porthole`) | The CLI. Listed here, not just in the README, because its path is no longer only a `$PATH` convenience: `porthole open --for` schedules its own close with a transient systemd timer whose `ExecStart` is this exact absolute path, run **as root**, and `porthole forward` does so unconditionally — it has no `--until-reboot`, so every forward gets a timer. The helper looks for it at `/usr/bin/porthole` first, then `/usr/local/bin/porthole`, and refuses to start at all if neither is a regular file owned by root and unwritable by anyone else — so install it at one of those two paths, not somewhere else. |
| `target/release/porthole-helper` (built, not in `data/`) | `/usr/libexec/porthole-helper` | The privileged binary itself. It is never setuid and never run directly — only D-Bus activation or systemd starts it, always as root. |
| `target/release/porthole-gui` (built with `cargo build --release -p porthole-gui`, not in `data/`) | `/usr/local/bin/porthole-gui` (a packaged install may instead use `/usr/bin/porthole-gui`) | The GTK4/libadwaita application. Unlike `porthole`'s own install path, nothing else on the system reads this one back — it only has to be on `$PATH` for the desktop file below to find it. |
| `data/com.jacopobriccola.Porthole.service` | `/usr/share/dbus-1/system-services/` | Tells the system bus daemon how to start the helper the first time something addresses `com.jacopobriccola.Porthole`: which binary to run, and — via `SystemdService=` — which systemd unit actually owns the process. |
| `data/porthole-helper.service` | `/usr/lib/systemd/system/` | The systemd unit the activation file names. `Type=dbus` plus `BusName=` makes systemd wait until the name is actually claimed before treating the service as started; `RuntimeDirectory=porthole` creates `/run/porthole` mode `0755` so an unprivileged `porthole list` can read the state file that only the helper writes, and `RuntimeDirectoryPreserve=yes` keeps `state.json` there across a restart or a crash instead of systemd deleting it with the directory; the unit has no `WantedBy=`, so nothing starts it at boot — D-Bus activation starts it the first time something addresses the bus name. It does not exit on its own once running: it stops only when something stops it. |
| `data/com.jacopobriccola.Porthole.conf` | `/usr/share/dbus-1/system.d/` | The bus's own policy: only `root` may own the name — a bus-level guard against anything else posing as the helper — and any user may address it, because deciding *who may do what* is the next file's job, not the bus's. It also lets any user *receive* what the helper sends, which is the direction the `RuleOpened`, `RuleClosed` and `NetworkChanged` signals travel in. On a stock system bus that clause changes nothing — `/usr/share/dbus-1/system.conf`'s own default policy already allows every user to receive signals — but it is what carries them on a bus configured more strictly, and it says in porthole's own file that these signals are meant to be listened to. |
| `data/com.jacopobriccola.Porthole.policy` | `/usr/share/polkit-1/actions/` | The polkit actions and their severities — five of them. Opening towards your own subnet (`open-subnet`) asks once per session (`auth_admin_keep`); opening towards everyone (`open-any`, `--to any`) asks every time (`auth_admin`); **redirecting a port to a container (`forward`) asks every time too (`auth_admin`), whatever its scope** — there is no `_keep` variant of it to choose, because an answer given minutes ago for an ordinary open must not carry over to making a port answer to something that was not on the network at all; and closing (`close`) or listing (`list`) never ask (`yes` for `allow_any`, `allow_active` and `allow_inactive` alike), which is also what lets a non-interactive package removal run `porthole close --all` without a prompt. Without this file, polkit falls back to its own default for an unrecognised action and every one of those severity choices disappears — `porthole doctor` is what notices and says so. |
| `data/com.jacopobriccola.Porthole.desktop` | `/usr/share/applications/` | The desktop entry: what `Name=`, icon and `Exec=` line a launcher (GNOME's Activities overview, an app grid, `gtk-launch`) uses to show and start the GUI. Unrelated to the D-Bus files above — this is what makes the app *appear*, not what lets it *talk to the helper*, which it still does exactly as the CLI does, over the system bus. |
| `data/icons/hicolor/scalable/apps/com.jacopobriccola.Porthole.svg` | `/usr/share/icons/hicolor/scalable/apps/` | The full-colour app icon the desktop file's `Icon=com.jacopobriccola.Porthole` resolves to via the freedesktop icon theme spec — the basename is what has to match, not the path. |
| `data/icons/hicolor/symbolic/apps/com.jacopobriccola.Porthole-symbolic.svg` | `/usr/share/icons/hicolor/symbolic/apps/` | The single-colour variant the same spec expects alongside the full-colour icon, used in menus, lists and high-contrast themes rather than shown standalone. |
| `target/release/porthole-agent` (built, not in `data/`) | `/usr/local/bin/porthole-agent` (a packaged install may instead use `/usr/bin/porthole-agent`) | The session agent: it listens on the system bus for the helper's `RuleClosed` signal and turns each one into a desktop notification. Nothing reads this path back the way the helper reads the CLI's, but the systemd unit below names it absolutely: install it here, or change that unit's `ExecStart=` to wherever you put it. The autostart entry needs no such edit — a desktop entry's `Exec=` is looked up on `$PATH`. |
| `data/porthole-agent.service` | `/usr/lib/systemd/user/` | The systemd **user** unit for the agent — user, not system: one agent per logged-in session, running as that user, because a notification goes to a session and not to a machine. `WantedBy=graphical-session.target` is what starts it, so it needs enabling once per user (`systemctl --user enable porthole-agent.service`), unlike the helper, which nothing has to enable. |
| `data/porthole-agent.desktop` | `/etc/xdg/autostart/` | The same job for desktops that start session services from XDG autostart rather than through systemd. Both are shipped on purpose: desktops differ in which they honour, and one that honours both starts two agents — the one started last takes the agent's session bus name and the other stops, so installing both never doubles a notification. |
| `data/com.jacopobriccola.Porthole.metainfo.xml` | `/usr/share/metainfo/` | AppStream metadata: what a software centre (GNOME Software, KDE Discover) reads for the name, summary, description and screenshot it shows *before* anyone has installed anything. Without this file the desktop entry above still makes the app launchable once installed, but a software centre listing it has nothing to show beside a bare name. |

These paths mirror where `firewalld` — one of the three firewalls porthole
can drive (see [docs/backends.md](backends.md) for the other two, ufw and
nftables), and the one this project used as the reference for its own D-Bus
system service, since it already ships one — installs the equivalent pieces
of itself on this project's reference distribution (Fedora); a distribution
that keeps D-Bus system policy under `/etc/dbus-1/system.d/` instead of
`/usr/share/dbus-1/system.d/` still reads it from either location, so use
whichever your distribution's dbus-daemon documents.

## Installing by hand

```bash
cargo build --release

sudo install -Dm755 target/release/porthole-helper \
  /usr/libexec/porthole-helper
sudo install -Dm644 data/com.jacopobriccola.Porthole.service \
  /usr/share/dbus-1/system-services/com.jacopobriccola.Porthole.service
sudo install -Dm644 data/porthole-helper.service \
  /usr/lib/systemd/system/porthole-helper.service
sudo install -Dm644 data/com.jacopobriccola.Porthole.conf \
  /usr/share/dbus-1/system.d/com.jacopobriccola.Porthole.conf
sudo install -Dm644 data/com.jacopobriccola.Porthole.policy \
  /usr/share/polkit-1/actions/com.jacopobriccola.Porthole.policy

sudo systemctl daemon-reload
# Picks up the new bus policy without a full reboot. dbus-broker reloads its
# service-activation directory on its own; the system.d policy fragment is
# the one file here that some setups need told about explicitly.
sudo systemctl reload dbus-broker.service 2>/dev/null || sudo systemctl reload dbus.service
```

Nothing here needs to be started or enabled by hand: `porthole-helper.service`
has no `WantedBy=`, so it only ever runs because D-Bus activated it. The next
command that addresses the bus name is what actually starts it for the first
time — `porthole open`, `forward`, `close`, `listen` or `doctor`, or the
session agent below, whose start-up `List` exists partly to do exactly that.
`porthole list` and `porthole status` are not among them: they answer from the
state file and never touch the bus.

Verify with `porthole doctor`: a fresh install should show `Firewall`, `State`
and `Network` unaffected by any of this, `Helper` going from "not answering on
the bus" to "answering", and `polkit` going from "not installed" to naming the
file that now exists.

## The agent: being told when a port closes

`porthole-agent` is the session half: unprivileged, one per logged-in
session, no window and no interface of its own. It listens on the system bus
for the helper's `RuleClosed` signal and shows a desktop notification for the
closes nobody asked for — an expiry, a network change, a rule the firewall no
longer had when porthole next looked, and a forward whose container is no
longer the one it was created against — filtered to rules opened by that
session's own uid. It has nothing to listen to until the helper above is
installed. It closes nothing and keeps no view of what is open.

**What it can cause at the helper**, in full, and it is two things. (On the
bus daemon itself it also does what any client does — `Hello`, `AddMatch`, a
name lookup — and none of that reaches porthole.)

The first is a bare `List` at start-up, once, whose answer it throws away.
Calling the helper is what D-Bus-activates it, and the agent has already
subscribed by then, so whatever the helper's own start-up sweep announces
arrives at a listener instead of being sent to nobody. `List` is `yes` in the
policy above for everyone, reads the state file and changes nothing; a failure
is ordinary (no helper installed, or none activatable) and the agent goes on
listening. It is worth naming rather than glossing over, because it means the
agent starting is enough to start the privileged helper.

The second is a `Reopen` click on a notification it is currently showing. Two
of the four reasons above carry that button — an expiry, and a container that
moved — and what it re-sends depends on the rule the notification was about:

- a rule that only permitted re-sends `open`, with the same port, protocol,
  scope and duration;
- a rule that redirected re-sends `forward`, with the same external port,
  scope and duration, and the **published port** the original request named.
  The container's address is never sent: the helper resolves it again from
  Docker's own table at the moment it acts, which is why a container that
  moved is something a click can recover from.

Both go through polkit like any other request, and a `forward` is
`auth_admin` **every time**, whatever its scope — so a click on that button
always produces an administrator prompt. The agent cannot skip it and does
not decide it. Those two calls are the whole of what it sends: everything else
it does is *receiving* — the helper's `RuleClosed`, and the notification
service's own `ActionInvoked`, `NotificationClosed` and owner changes. It
subscribes to no other porthole signal: `RuleOpened` and `NetworkChanged` go
past it unread.

Three files. The last two commands below are **not** run as root:

```bash
sudo install -Dm755 target/release/porthole-agent \
  /usr/local/bin/porthole-agent
sudo install -Dm644 data/porthole-agent.service \
  /usr/lib/systemd/user/porthole-agent.service
sudo install -Dm644 data/porthole-agent.desktop \
  /etc/xdg/autostart/porthole-agent.desktop

# As your own user, not root: a user unit is enabled per account, and the
# agent that matters is the one running as the person who opened the port.
systemctl --user daemon-reload
systemctl --user enable --now porthole-agent.service
```

`/usr/local/bin/porthole-agent` is the path the unit's `ExecStart=` names
literally; a packaged install that puts the binary in `/usr/bin` has to change
that line. The autostart entry needs no such edit — a desktop entry's `Exec=`
is looked up on `$PATH`.

**Both start files, on purpose.** Desktops differ in which of the two they
honour, and there is no way to tell from here which yours does. A desktop
that honours only one starts one agent; a desktop that honours both starts a
second, which takes the session bus name `com.jacopobriccola.PortholeAgent`
from the first, whereupon the first stops — so installing both does not
announce every close twice. If you know your desktop starts XDG autostart
entries and not user units, the `systemctl --user enable` above is redundant
rather than wrong.

**The name goes to the agent started last**, which is what makes
`systemctl --user restart porthole-agent.service` work after a package
upgrade. The user bus outlives a login session, so an agent from a previous
login can still be running and still holding the name; before this, every
newly started agent found the name taken and exited, and `restart` could not
help — the stale process is not the unit's, so systemd had nothing to stop.
The result was an upgrade that silently left the old agent in charge.

One case that cannot be taken over remains, and it is the last time you
should see it: an agent from *before* this change does not offer its name for
replacement, so the first restart after upgrading past it still meets a
holder that will not yield. That agent now says so on the screen rather than
only in the journal — "Porthole notifications did not start" — and logging
out and back in clears it for good.

`WantedBy=graphical-session.target` is what starts the unit, so whether
`enable` alone is enough depends on your desktop actually reaching that
target (GNOME does). `--now` above sidesteps the question for the session you
are in. `PartOf=graphical-session.target` stops it again with the session:
this exists to put a notification on a screen, and after the session there is
no screen.

`Restart=on-failure` covers exactly one case: the system bus connection
ending while the agent is running. The agent cannot rebuild it, so closes
would otherwise stop being announced with nothing to show anything had gone
wrong. Every other reason the agent stops exits 0 on purpose — no session
bus, no system bus at start-up, no notification service, a holder of the bus
name that will not yield it, or a newer agent taking that name — so the unit
stays stopped rather than looping, and a headless login does not fight
systemd's start limit. The last of those is why the restart must not happen:
a replaced agent that came back would take the name straight off the agent
that replaced it, and the two would trade it. That also bounds
the restart itself: a replacement agent that still finds no system bus fails
during start-up, which exits 0, and `on-failure` does not restart a success.

Verify:

```bash
systemctl --user status porthole-agent.service
journalctl --user -u porthole-agent.service -n 20
```

Expect `porthole-agent: listening for uid <your uid>`. For an end-to-end
check, `porthole open 5173 --for 70s` and wait: the notification appears when
the expiry timer closes the port, and the journal above records either the
notification the agent sent or the reason it could not show one.

On a desktop that honours **both** start files, `status` can say
`inactive (dead)` while notifications work perfectly well: the two agents
start moments apart, the later one takes the name, and the earlier one stops
with a success status, which is what keeps the unit from restarting into a
tug of war. Its journal says `a newer agent took this session's agent name`.
Which unit the survivor belongs to is a race, so `status` on the unit is not
the question to ask; who owns the name is:

```bash
busctl --user status com.jacopobriccola.PortholeAgent
```

### From a package: notifications start at the next login

The `--now` above is what a by-hand install has and a package install does
not. Installing a package puts the unit and the autostart entry down and
starts neither, because neither start file runs in a session that is already
open: `WantedBy=graphical-session.target` is reached when a session begins,
and so is `/etc/xdg/autostart`. Reported by the first person to install the
RPM: `porthole-agent.service` was `inactive (dead)` straight afterwards, and a
port opened in that session closed with no notification at all.

The three packages differ in whether they enable the unit, and it makes no
difference to that. The .deb enables it (`dh_installsystemduser`); the RPM
does not, because on Fedora a user unit is enabled through a preset and
`/usr/lib/systemd/user-preset/99-default-disable.preset` is `disable *`, with
the exceptions kept centrally in `fedora-release` rather than shipped by the
package that owns the unit; the Arch package enables nothing either. Enabling
settles whether a symlink exists under `/etc/systemd/user` and starts nothing
in a session that is already running — an install runs as root, where there
is no user session to start a user unit in — so an enabled unit and a
disabled one both leave that first port unannounced.

Each of the three says so when it is installed, and the way out is the same
for all three:

```bash
systemctl --user start porthole-agent.service
```

`start`, not `enable`: it needs no enablement and no `graphical-session.target`,
and it is per user — run it as the person who will be opening ports. From the
next login onwards, whichever of the two start files your desktop honours
takes over.

## The GUI: making it appear in the app grid

Building it needs GTK4/libadwaita development headers installed first — the
helper and CLI built above need none of this. On Fedora:

```bash
sudo dnf install gtk4-devel libadwaita-devel pkgconf-pkg-config
cargo build --release -p porthole-gui
```

Once built, the GUI works with none of what follows below — run
`porthole-gui` from a terminal and it talks to the helper over the system bus
exactly as `porthole` does, needing that half installed but nothing else.
Putting the binary itself on `$PATH`, plus the four files after it, is what
makes it *appear* anywhere without a terminal instead — GNOME's Activities
overview, an app grid, a software centre — five `install` commands below.

```bash
sudo install -Dm755 target/release/porthole-gui /usr/local/bin/porthole-gui

sudo install -Dm644 data/com.jacopobriccola.Porthole.desktop \
  /usr/share/applications/com.jacopobriccola.Porthole.desktop
sudo install -Dm644 data/icons/hicolor/scalable/apps/com.jacopobriccola.Porthole.svg \
  /usr/share/icons/hicolor/scalable/apps/com.jacopobriccola.Porthole.svg
sudo install -Dm644 data/icons/hicolor/symbolic/apps/com.jacopobriccola.Porthole-symbolic.svg \
  /usr/share/icons/hicolor/symbolic/apps/com.jacopobriccola.Porthole-symbolic.svg
sudo install -Dm644 data/com.jacopobriccola.Porthole.metainfo.xml \
  /usr/share/metainfo/com.jacopobriccola.Porthole.metainfo.xml

# Neither is strictly required for the desktop entry to work -- most desktop
# environments notice a new file under these directories on their own -- but
# without them an icon or a software-centre listing can lag behind an
# install until something else happens to trigger a rescan.
sudo gtk-update-icon-cache -f /usr/share/icons/hicolor 2>/dev/null || true
sudo update-desktop-database /usr/share/applications 2>/dev/null || true
```

Verify by opening the Activities overview and typing "Porthole": the icon
above should appear, launching the same window `cargo run -p porthole-gui`
would inside the container this project builds and tests it in. A software
centre that reads AppStream metadata (GNOME Software, KDE Discover) should
show the summary and description from the `.metainfo.xml` file once you find
the app there, not just a bare name.

## Upgrading: the helper restarts, the ports stay

`porthole-helper` has no idle timeout and no last-rule-closed shutdown. Once
the bus has activated it, it runs until something stops it — so unless the
upgrade ends that process, the machine goes on serving the new version's
clients from the **previous version's** root daemon, out of a binary that is
no longer on disk. On a Debian machine, `readlink /proc/$(systemctl show -p
MainPID --value porthole-helper.service)/exe` said
`/usr/libexec/porthole-helper (deleted)` after exactly that.

The reason it is worth a maintainer script is that the failure is silent.
porthole's D-Bus wire format has already changed incompatibly once — adding a
forward's three members to `WireRule` moved the `RuleClosed` signal from
`((sqssssttu)s)` to `((sqssssttusqq)s)` — and zbus drops a signal whose
signature does not match rather than raising anything. A stale component does
not fail, it goes quiet, and the first thing you notice is closes no longer
being announced.

So all three packages end the old helper process on an upgrade, and start no
helper on a first install:

| | |
| --- | --- |
| RPM | `%systemd_postun_with_restart porthole-helper.service`, guarded by rpm's own "this is an upgrade, not an erase" test |
| Debian | `dh_installsystemd --no-start --restart-after-upgrade`, which puts `deb-systemd-invoke try-restart` in `postinst` behind dpkg's "was there a previous version" test |
| Arch | `post_upgrade` in the pacman scriptlet: `systemctl daemon-reload`, then `systemctl try-restart` |

Try-restart semantics on all three, and not plain `restart`: a machine whose
helper was not running acquires no root daemon as the price of a version bump.
Debian and Arch call `try-restart` by name; the RPM macro instead marks the
unit `needs-restart` for systemd's own rpm trigger to act on at the end of the
transaction, which on systemd 259 leaves an inactive unit inactive and gives
an active one a new PID — measured, because "marked" and "started" are not the
same word. Each does a `daemon-reload` before its restart, since the unit file
may be the thing that changed; on Arch that reload is in the scriptlet rather
than left to pacman's own `daemon-reload` hook, which is `PostTransaction` and
so runs after the scriptlet, not before it.

**An upgrade closes nothing.** Every port porthole had open is still open when
it finishes, in the firewall and in the record of it: `RuntimeDirectoryPreserve=yes`
in `porthole-helper.service` is what keeps `/run/porthole` and the state file
across the restart, and each opening's automatic close is a transient systemd
timer living outside the helper process. Losing the access you arranged would
be a bad way to learn a new version had shipped.

What the restart does cost is a moment. The network-change monitor runs
**inside** the helper, so a subnet change landing between the old process
ending and the new one starting is not seen; expiry is unaffected, being
systemd's timer rather than the helper's.

## Uninstalling: what closes the ports, and when it does not

The three packages each close every port porthole has open before their files
go — every redirect `porthole forward` made included, since a forward is an
ordinary porthole rule to `close --all` — and only on a real removal: `%preun`
guarded by `$1 -eq 0` (RPM), `prerm remove` (Debian), `pre_remove` (Arch). An
upgrade closes nothing; the same scripts run, and each distinguishes the two
cases the way its packaging system provides for.

What each of them runs is `porthole close --all`, not a shell that guesses at
rules. The helper owns the firewall and holds the record of what it opened,
and closing through it also cancels each opening's transient `systemd-run`
timer — the timer that would otherwise fire after the removal into a
`/usr/bin/porthole` no longer on disk. Nothing authenticates: the
`com.jacopobriccola.Porthole.close` polkit action is `yes` for `allow_any`,
`allow_active` and `allow_inactive`, so a non-interactive removal is never
prompted.

The close happens **before** the helper is stopped. Stopping it first would
leave the close to D-Bus-activate it again, and the helper started that way
would still be running, from a deleted binary, when the removal finished.

None of it can fail the removal. An un-removable package is a worse problem
than an open port, so a `close --all` that does not succeed — no system bus,
polkit not running, a helper left broken by an earlier failed upgrade — prints
a warning naming the three commands that list what is left, and the removal
continues. Those ports stay open, and after the removal nothing is left that
would close them. `porthole close --all`, run yourself before uninstalling, is
the way not to depend on any of this.

An installation made by `make install` has none of this: the `Makefile`
installs files and nothing else, and `make uninstall` removes files and
nothing else. Close first.

## Why there is no Flatpak, and there will not be one

A Flatpak sandbox has no mechanism to install a polkit `.policy` file into
`/usr/share/polkit-1/actions/`, nor to register a system D-Bus service in
`/usr/share/dbus-1/system-services/` — both are host-level configuration a
sandboxed app is specifically prevented from touching, which is the entire
point of the sandbox. porthole's privileged half is exactly those two things.
There is no portal, no permission grant and no future flag that changes this:
the spec ruled out Flatpak packaging for this reason from the start, not as an
oversight to fix later.
