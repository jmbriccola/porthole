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
PORT      TOWARDS         BACKEND    CLOSES IN
5173/tcp  10.10.10.0/24   firewalld  29m 41s

$ porthole close 5173
Closed 5173/tcp towards 10.10.10.0/24
```

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
1.85 or newer:

```bash
git clone https://github.com/jacopobriccola/porthole
cd porthole
cargo build --release
sudo install -m 0755 target/release/porthole /usr/local/bin/porthole
```

## Usage

```
porthole open <PORT> [--proto tcp|udp] [--for 30m | --until-reboot]
                     [--to subnet|any|<CIDR>|<IP>]
porthole close <PORT> | --id <ID> | --all
porthole list
porthole status
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
| 4 | Not authorized |
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
- **Only firewalld is supported so far.** ufw and nftables are next.
- **Docker publishes ports below the firewall.** Docker writes its own iptables
  rules, evaluated before firewalld, so a container published on `0.0.0.0` is
  already reachable and closing that port with porthole will not close it.
  Detecting and explaining this is planned; right now porthole does not warn
  you. Publish container ports on `127.0.0.1` in your compose files.
- **`firewall-cmd --reload` wipes porthole's rules without telling porthole.**
  Until reconciliation lands, `porthole list` can show a rule that firewalld no
  longer has. `porthole close --all` clears the stale entries.
- **No Flatpak, and there will not be one.** The privileged half of porthole is
  a polkit policy and a system D-Bus service; a Flatpak cannot install either.

## Licence

GNU General Public License v3.0 or later. See [LICENSE](LICENSE).
