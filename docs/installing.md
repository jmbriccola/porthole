# Installing the privileged half

`porthole` — the CLI — is one binary and needs nothing else: `porthole list`,
`porthole status` and anything with `--dry-run` work as soon as it is on your
`$PATH`. `porthole open` and `porthole close` are different: they ask a
privileged helper to act, and that helper has to be installed once, as root,
before they work. This is that installation.

There is no installer yet — porthole is not packaged for any distribution.
Until it is, do the five steps below by hand.

## The five pieces

Building the workspace (`cargo build --release`) produces the helper binary.
The other four are checked into `data/` and are not installed by anything
automatically — you copy them into place yourself.

| Piece | Goes to | What it does |
|---|---|---|
| `target/release/porthole-helper` (built, not in `data/`) | `/usr/libexec/porthole-helper` | The privileged binary itself. It is never setuid and never run directly — only D-Bus activation or systemd starts it, always as root. |
| `data/com.jacopobriccola.Porthole.service` | `/usr/share/dbus-1/system-services/` | Tells the system bus daemon how to start the helper the first time something addresses `com.jacopobriccola.Porthole`: which binary to run, and — via `SystemdService=` — which systemd unit actually owns the process. |
| `data/porthole-helper.service` | `/usr/lib/systemd/system/` | The systemd unit the activation file names. `Type=dbus` plus `BusName=` makes systemd wait until the name is actually claimed before treating the service as started; `RuntimeDirectory=porthole` creates `/run/porthole` mode `0755` so an unprivileged `porthole list` can read the state file that only the helper writes; the unit has no `WantedBy=`, so it is never running except while something needs it — D-Bus activation restarts it on the next call after it exits idle. |
| `data/com.jacopobriccola.Porthole.conf` | `/usr/share/dbus-1/system.d/` | The bus's own policy: only `root` may own the name — a bus-level guard against anything else posing as the helper — and any user may address it, because deciding *who may do what* is the next file's job, not the bus's. |
| `data/com.jacopobriccola.Porthole.policy` | `/usr/share/polkit-1/actions/` | The polkit actions and their severities: opening towards your own subnet asks once per session, opening towards everyone (`--to any`) asks every time, and closing or listing never ask. Without this file, polkit falls back to its own default for an unrecognised action and every one of those severity choices disappears — `porthole doctor` is what notices and says so. |

These paths mirror where `firewalld` — the only backend porthole drives —
installs the equivalent pieces of itself on this project's reference
distribution (Fedora); a distribution that keeps D-Bus system policy under
`/etc/dbus-1/system.d/` instead of `/usr/share/dbus-1/system.d/` still reads
it from either location, so use whichever your distribution's dbus-daemon
documents.

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

## Why there is no Flatpak, and there will not be one

A Flatpak sandbox has no mechanism to install a polkit `.policy` file into
`/usr/share/polkit-1/actions/`, nor to register a system D-Bus service in
`/usr/share/dbus-1/system-services/` — both are host-level configuration a
sandboxed app is specifically prevented from touching, which is the entire
point of the sandbox. porthole's privileged half is exactly those two things.
There is no portal, no permission grant and no future flag that changes this:
the spec ruled out Flatpak packaging for this reason from the start, not as an
oversight to fix later.
