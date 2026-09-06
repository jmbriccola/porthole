# Installing the privileged half

`porthole` — the CLI — is one binary and needs nothing else: `porthole list`,
`porthole status` and anything with `--dry-run` work as soon as it is on your
`$PATH`. `porthole open` and `porthole close` are different: they ask a
privileged helper to act, and that helper has to be installed once, as root,
before they work. This is that installation.

There is no installer yet — porthole is not packaged for any distribution.
Until it is, do the steps below by hand.

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
| `target/release/porthole` (built, not in `data/` — install it per the top-level README, not by the commands below) | `/usr/local/bin/porthole` (a packaged install may instead use `/usr/bin/porthole`) | The CLI. Listed here, not just in the README, because its path is no longer only a `$PATH` convenience: `porthole open --for` schedules its own close with a transient systemd timer whose `ExecStart` is this exact absolute path, run **as root**. The helper looks for it at `/usr/bin/porthole` first, then `/usr/local/bin/porthole`, and refuses to start at all if neither is a regular file owned by root and unwritable by anyone else — so install it at one of those two paths, not somewhere else. |
| `target/release/porthole-helper` (built, not in `data/`) | `/usr/libexec/porthole-helper` | The privileged binary itself. It is never setuid and never run directly — only D-Bus activation or systemd starts it, always as root. |
| `target/release/porthole-gui` (built with `cargo build --release -p porthole-gui`, not in `data/`) | `/usr/local/bin/porthole-gui` (a packaged install may instead use `/usr/bin/porthole-gui`) | The GTK4/libadwaita application. Unlike `porthole`'s own install path, nothing else on the system reads this one back — it only has to be on `$PATH` for the desktop file below to find it. |
| `data/com.jacopobriccola.Porthole.service` | `/usr/share/dbus-1/system-services/` | Tells the system bus daemon how to start the helper the first time something addresses `com.jacopobriccola.Porthole`: which binary to run, and — via `SystemdService=` — which systemd unit actually owns the process. |
| `data/porthole-helper.service` | `/usr/lib/systemd/system/` | The systemd unit the activation file names. `Type=dbus` plus `BusName=` makes systemd wait until the name is actually claimed before treating the service as started; `RuntimeDirectory=porthole` creates `/run/porthole` mode `0755` so an unprivileged `porthole list` can read the state file that only the helper writes, and `RuntimeDirectoryPreserve=yes` keeps `state.json` there across a restart or a crash instead of systemd deleting it with the directory; the unit has no `WantedBy=`, so nothing starts it at boot — D-Bus activation starts it the first time something addresses the bus name. It does not exit on its own once running: it stops only when something stops it. |
| `data/com.jacopobriccola.Porthole.conf` | `/usr/share/dbus-1/system.d/` | The bus's own policy: only `root` may own the name — a bus-level guard against anything else posing as the helper — and any user may address it, because deciding *who may do what* is the next file's job, not the bus's. It also lets any user *receive* what the helper sends, which is the direction the `RuleOpened`, `RuleClosed` and `NetworkChanged` signals travel in. On a stock system bus that clause changes nothing — `/usr/share/dbus-1/system.conf`'s own default policy already allows every user to receive signals — but it is what carries them on a bus configured more strictly, and it says in porthole's own file that these signals are meant to be listened to. |
| `data/com.jacopobriccola.Porthole.policy` | `/usr/share/polkit-1/actions/` | The polkit actions and their severities: opening towards your own subnet asks once per session, opening towards everyone (`--to any`) asks every time, and closing or listing never ask. Without this file, polkit falls back to its own default for an unrecognised action and every one of those severity choices disappears — `porthole doctor` is what notices and says so. |
| `data/com.jacopobriccola.Porthole.desktop` | `/usr/share/applications/` | The desktop entry: what `Name=`, icon and `Exec=` line a launcher (GNOME's Activities overview, an app grid, `gtk-launch`) uses to show and start the GUI. Unrelated to the D-Bus files above — this is what makes the app *appear*, not what lets it *talk to the helper*, which it still does exactly as the CLI does, over the system bus. |
| `data/icons/hicolor/scalable/apps/com.jacopobriccola.Porthole.svg` | `/usr/share/icons/hicolor/scalable/apps/` | The full-colour app icon the desktop file's `Icon=com.jacopobriccola.Porthole` resolves to via the freedesktop icon theme spec — the basename is what has to match, not the path. |
| `data/icons/hicolor/symbolic/apps/com.jacopobriccola.Porthole-symbolic.svg` | `/usr/share/icons/hicolor/symbolic/apps/` | The single-colour variant the same spec expects alongside the full-colour icon, used in menus, lists and high-contrast themes rather than shown standalone. |
| `target/release/porthole-agent` (built, not in `data/`) | `/usr/local/bin/porthole-agent` (a packaged install may instead use `/usr/bin/porthole-agent`) | The session agent: it listens on the system bus for the helper's `RuleClosed` signal and turns each one into a desktop notification. Nothing reads this path back the way the helper reads the CLI's, but the systemd unit below names it absolutely: install it here, or change that unit's `ExecStart=` to wherever you put it. The autostart entry needs no such edit — a desktop entry's `Exec=` is looked up on `$PATH`. |
| `data/porthole-agent.service` | `/usr/lib/systemd/user/` | The systemd **user** unit for the agent — user, not system: one agent per logged-in session, running as that user, because a notification goes to a session and not to a machine. `WantedBy=graphical-session.target` is what starts it, so it needs enabling once per user (`systemctl --user enable porthole-agent.service`), unlike the helper, which nothing has to enable. |
| `data/porthole-agent.desktop` | `/etc/xdg/autostart/` | The same job for desktops that start session services from XDG autostart rather than through systemd. Both are shipped on purpose: desktops differ in which they honour, and one that honours both starts two agents — the second finds the agent's session bus name already taken and exits, so installing both never doubles a notification. |
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
`porthole open` or `porthole close` is what actually starts it for the first
time.

Verify with `porthole doctor`: a fresh install should show `Firewall`, `State`
and `Network` unaffected by any of this, `Helper` going from "not answering on
the bus" to "answering", and `polkit` going from "not installed" to naming the
file that now exists.

## The agent: being told when a port closes

`porthole-agent` is the session half: unprivileged, one per logged-in
session, no window and no interface of its own. It listens on the system bus
for the helper's `RuleClosed` signal and shows a desktop notification for the
closes nobody asked for — an expiry, a network change, and a rule the
firewall no longer had when porthole next looked — filtered to rules opened by
that session's own uid. It has nothing to listen to until the helper above is
installed. It closes nothing and keeps no view of what is open; the one thing
it can cause is the `Reopen` button on an expiry notification, which re-sends
an ordinary `open` request to the helper, polkit prompt and all.

Three files, and one of the three commands below is **not** run as root:

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
second, which finds the session bus name
`com.jacopobriccola.PortholeAgent` already taken, says so in the journal and
exits — so installing both does not announce every close twice. If you know
your desktop starts XDG autostart entries and not user units, the
`systemctl --user enable` above is redundant rather than wrong.

`WantedBy=graphical-session.target` is what starts the unit, so whether
`enable` alone is enough depends on your desktop actually reaching that
target (GNOME does). `--now` above sidesteps the question for the session you
are in. `PartOf=graphical-session.target` stops it again with the session:
this exists to put a notification on a screen, and after the session there is
no screen. There is deliberately no `Restart=` — every reason this binary
stops is one a restart would meet again immediately, and the one failure it
must survive (a session with no notification service) it survives by carrying
on rather than by exiting.

Verify:

```bash
systemctl --user status porthole-agent.service
journalctl --user -u porthole-agent.service -n 20
```

Expect `porthole-agent: listening for uid <your uid>`. For an end-to-end
check, `porthole open 5173 --for 70s` and wait: the notification appears when
the expiry timer closes the port, and the journal above records either the
notification the agent sent or the reason it could not show one.

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

## Why there is no Flatpak, and there will not be one

A Flatpak sandbox has no mechanism to install a polkit `.policy` file into
`/usr/share/polkit-1/actions/`, nor to register a system D-Bus service in
`/usr/share/dbus-1/system-services/` — both are host-level configuration a
sandboxed app is specifically prevented from touching, which is the entire
point of the sandbox. porthole's privileged half is exactly those two things.
There is no portal, no permission grant and no future flag that changes this:
the spec ruled out Flatpak packaging for this reason from the start, not as an
oversight to fix later.
