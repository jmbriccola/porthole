# `--json` output

Every command accepts `--json`, and every failure honours it — see
[Errors](#errors). Each prints one JSON object on stdout.

`porthole devices add` is interactive, and its prompts are not output: the
list of neighbours and the two questions go to **stderr**, so stdout carries
only the object below. That does not make the command scriptable — something
still has to answer the prompts — but it does mean a caller that answers them
can parse the result.

The shape is versioned by the top-level `schema` field, currently `1`. Fields
are added, never renamed or removed.

All timestamps are **seconds since the Unix epoch**, as integers. Convert with
`date -d @1757000000`.

## Rule object

Used in `list`, `status`, `open`, `forward` and `close`.

```json
{
  "id": "1f0c8b6e-0000-4000-8000-000000000001",
  "port": 5173,
  "protocol": "tcp",
  "target": "10.10.10.0/24",
  "scope": "network",
  "backend": "firewalld",
  "opened_at": 1757000000,
  "expires_at": 1757003600,
  "expires_in_seconds": 3421,
  "uid": 1000,
  "forward": null
}
```

- `protocol` — `"tcp"` or `"udp"`.
- `scope` — `"network"` or `"anywhere"`. When it is `"anywhere"`, `target` is
  the string `"anywhere"`; otherwise `target` is a CIDR.
- `backend` — `"firewalld"`, `"ufw"` or `"nftables"`: whichever backend
  created this rule. See [docs/backends.md](backends.md) for what each one
  can and cannot do.
- `expires_at` and `expires_in_seconds` are `null` for an `--until-reboot` rule.
- `forward` — `null` when the rule only **permits** traffic, and an object
  when it **redirects** it. The two are different things and the rest of this
  object cannot tell them apart, so a script that treats every rule alike will
  report a redirect as a permission.

`forward: null` is every rule `porthole open` creates, and every rule
recorded before forwards existed. It says this rule redirects nothing; it says
nothing about Docker, about the port, or about what else may be reachable.

When it is not `null` — only `porthole forward` creates such a rule — it is:

```json
{
  "container_addr": "172.17.0.9",
  "container_port": 80,
  "published_port": 3000
}
```

- `container_addr` and `container_port` are where the traffic actually
  arrives: an address on Docker's own network, and the port inside the
  container. Neither is a port on this machine.
- `published_port` is the port Docker published on this machine — the number
  shown by `porthole listen` and the number typed at `porthole forward`.
- The rule's own `port`, above, is what the **local network** connects to.
  It is `published_port` unless `--as` set it to something else, and the whole
  point of a forward is that the two may differ.

There is no protocol in this object. A forward whose two ends disagree about
protocol is refused before the rule exists, so the rule's own `protocol`
governs both.

A rule opened with `--to <device name>` is indistinguishable here from one
opened with `--to <IP>`: both record `scope: "network"` and a `target` of
`<address>/32`, resolved at the moment of the open. Nothing in a rule records
which saved device, if any, the request named — see
[`porthole devices list --json`](#porthole-devices-list---json).

## `porthole list --json`

```json
{ "schema": 1, "rules": [ /* rule objects */ ] }
```

## `porthole status --json`

```json
{
  "schema": 1,
  "backend": "firewalld",
  "firewall_available": true,
  "firewall_active": true,
  "firewall_active_unknown": false,
  "firewall_version": "2.4.4",
  "firewall_caveat": null,
  "location": "FedoraWorkstation",
  "network": { "interface": "wlo1", "address": "10.10.10.119", "cidr": "10.10.10.0/24" },
  "rules": [ /* rule objects */ ]
}
```

`network` is `null` when the machine is not on a usable network.

`backend` is one of `"firewalld"`, `"ufw"` or `"nftables"` — whichever
porthole detected on this machine, in that priority order, **when
`firewall_available` is `true`**. When it is `false`, `backend` still holds
`"firewalld"`, but that value is arbitrary and carries no information:
nothing was actually detected, and a script must not read anything into it
in that case.

`firewall_available: false` itself folds two facts into one bit, for the
same reason `porthole status` always exits `0` and answers in this one
shape rather than failing outright: **no supported firewall is installed**
(the ordinary case a script will actually meet) and, more broadly, **porthole
could not detect a backend at all**, for whatever reason — today those are
the same thing in practice, since every backend's own detection step
degrades rather than errors (see `firewall_active_unknown` below), but nothing
guarantees a future backend's detection can only ever fail that one way.
Neither case has a field of its own here to tell them apart: plain `porthole
status` prints the distinguishing sentence (porthole's own `detail`) as
prose; `--json` does not carry it, on the judgment that this collapse is not
live today and a script gains nothing from a field for a case that cannot
currently happen — `firewall_available: false` is reason enough on its own
to stop reading the rest of this object as meaningful.

`firewall_active: false` is two different facts, and `firewall_active_unknown`
is what tells them apart. `firewall_active_unknown: false` — every case that
existed before this field was added, `firewall_active` either `true` or
`false` — means porthole actually read the firewall's state and got a
definite answer, whichever way it came out. `firewall_active_unknown: true`
means it could not **confirm** activity, one way or the other — not
specifically "permission denied," though that is the most common reason:
ufw's and nftables' own reads both need more privilege than `porthole
status` runs with, so a permission-denied read sets it. So does an `nft -j
list chains` that returns something porthole cannot parse — an installed
`nft` porthole cannot make sense of is still installed, not absent, and
porthole did not confirm anything either way about it. Neither cause has a
field of its own here; `porthole doctor` (plain or `--json`) names the
actual reason in its `Firewall` check's `detail` when that matters. Treat
`firewall_active_unknown` as "could not confirm," not as a synonym for one
specific cause. It is always `false` for firewalld (its reads never need
more privilege than any user has, and it has no unparseable-output case) and
always `false` when `firewall_available` is itself `false` (there is
nothing to have failed to confirm). A script that only reads
`firewall_active` behaves exactly as it always has; one that reads
`firewall_active_unknown` too can avoid treating "porthole could not tell"
as "porthole confirmed this is off."

`location` means something different for each, and a script that assumes it
is always a firewalld zone will misread the other two:

| `backend` | what `location` holds |
|---|---|
| `firewalld` | the zone porthole manages, e.g. `"FedoraWorkstation"` |
| `ufw` | the literal string `"ufw"` — ufw has no zone concept |
| `nftables` | the input-hook chain porthole found and would insert into, e.g. `"inet filter input"` |

`location` is `null` when it could not be determined — on nftables this
happens when there is no input-hook chain, or more than one, since porthole
has not picked a single chain to name; see [docs/backends.md](backends.md).
Plain `porthole status` labels this line to match: `Zone` for firewalld,
`Chain` for nftables, `Location` for ufw.

`firewall_caveat` is a standing warning about the detected backend that is
true regardless of `firewall_active`, and `null` when there is nothing more
to say beyond the fields above. Today the only backend that ever sets it is
nftables, when the single chain it found has policy `accept` and no rule of
its own that drops or rejects — e.g. `"its policy is accept and no rule in
this chain drops or rejects (a chain it jumps to might still), so closing a
port here is not on its own evidence that it becomes unreachable"`. This is
the direction that misleads someone into feeling safe, so it is surfaced
here even while `firewall_active` is `true` — see
[docs/backends.md](backends.md#nftables). Plain `porthole status` prints the
same sentence, without a label, directly under the `Firewall`/location/
`Network` lines.

## `porthole open --json`

```json
{
  "schema": 1,
  "dry_run": false,
  "rule": { /* rule object */ },
  "commands": [ "firewall-cmd --zone=... '--add-rich-rule=...'" ],
  "docker_note": null
}
```

`commands` lists the withheld commands under `--dry-run`, and is empty
otherwise.

`docker_note` is `null` on almost every open — Docker has an opinion about
the exact port/protocol just opened only rarely. When it is not `null`, it
says one of two things, and porthole still went ahead and opened the rule
either way (diagnosing Docker's own rules is all porthole ever does; it
never touches them):

- the port is already published by a container on every interface, or on one
  specific address other than `127.0.0.1`: opening it here changed nothing,
  because it was already reachable, and closing it later will not close it
  either — Docker's own iptables rules are evaluated before firewalld's,
  ufw's or nftables'.
- the port is published by a container on `127.0.0.1` only: the firewall was
  never what was stopping it from being reachable, so opening it here does
  not make it reachable — the fix is in the container's own port binding, not
  in porthole.

`null` is therefore two facts, and `open --json` carries nothing to tell them
apart: **Docker was asked about and has no rule for this port**, and
**Docker could not be asked at all**. Reading the `DOCKER` chain needs root,
so it goes through the privileged helper; a helper that is absent or errors
leaves `docker_note` at `null` and `open` proceeds regardless, since a missing
warning is not a reason to refuse to open a port. A script that must not read
`null` as "no container has this port" checks
`porthole listen --json`'s `docker_checked` before believing it.

Getting a container port reachable, or closed, when Docker itself has
published or restricted it is outside what porthole can do — see
`porthole doctor`'s own `Docker` check for the same two facts, named for
whichever ports it could actually read. This is a plain string, not a
structured object: a script that needs the underlying fact reads it from
`porthole listen --json`'s own `docker` field instead, which names the exact
address rather than a rendered sentence.

## `porthole forward --json`

The same object `open --json` prints, from the same rule:

```json
{
  "schema": 1,
  "dry_run": false,
  "rule": { /* rule object, whose `forward` is not null */ },
  "commands": [],
  "docker_note": null
}
```

`rule.forward` is what distinguishes this from an open — see [Rule
object](#rule-object) for its three members and for which of the numbers is
which.

`docker_note` is always `null` here, and carries no information at all.
`open`'s note warns that Docker may already have made a port reachable; a
forward that got as far as printing this object has had that same question
asked and answered, and would have failed with `already_reachable` (exit
`14`) if the answer had been yes.

`forward` has refusals `open` does not, each with its own `kind` and exit
code in the error object below: `forward_unsupported` (`12`) when the
detected firewall cannot redirect a port at all, `not_published_by_container`,
`nothing_listening` and `docker_unreadable` (all three `10`, and told apart by
`kind` alone) when there is no container to redirect to — respectively:
something on this machine is listening on the port and no container publishes
it, so it cannot be forwarded as it stands; nothing is listening on it at all,
which is usually a mistyped number or a service that was never started; or
Docker could not be read, so porthole never found out,
`external_port_in_use` (`11`) when the port the local network would connect
to already carries something a redirect would take traffic from — a porthole
rule, a container Docker publishes on that port at an address the network
reaches, or a service listening on `0.0.0.0` or on one address the network
reaches; restricted to loopback, neither the mapping nor the listener refuses,
and the message says which of the three sources found it —
`forward_check_unavailable` (`13`) when a
check porthole makes before creating a redirect has no answer for what was
asked, and `already_reachable` (`14`) when Docker publishes the container on
an address other than loopback. What that last one reads is the `-d` flag on
Docker's own DNAT rule for the port and nothing else: no `-d` is every
interface, and a `-d` naming any other address is that one address, whether
or not this machine holds it — so a container published on an address no
interface here carries is refused too. Every one of them is decided by
porthole, not by
this CLI, and each arrives with the same `code` and `kind` whether the work
was attempted locally under `--dry-run` or over the bus.

## `porthole close --json`

```json
{
  "schema": 1,
  "dry_run": false,
  "closed": [ /* rule objects */ ],
  "forgotten": [ /* rule objects */ ],
  "errors": [ /* error objects, see below */ ],
  "commands": []
}
```

`--all` can partly succeed: rules that closed appear in `closed`, and each
failure appears in `errors` with the same `{code, kind, message}` shape used
below. The output is always a single object — the exit code carries the first
failure's code.

`forgotten` is `close --id <id> --forget` (see [docs/backends.md](backends.md)
and `porthole close --help`): a rule that appears here was **not** closed in
any firewall, only porthole's own record of it was dropped, because it was
recorded under a backend this machine no longer has. It is always empty
except on a `--forget` call, and `closed` is always empty on one — the two
never share an entry, and a script must not treat an entry in `forgotten` the
way it would treat one in `closed`: the port it named may still be open in
whatever firewall created it.

## `porthole listen --json`

```json
{
  "schema": 1,
  "docker_checked": true,
  "services": [
    {
      "port": 5173,
      "protocol": "tcp",
      "address": "0.0.0.0",
      "binding": "all_interfaces",
      "process": "node",
      "pid": 12043,
      "docker": null
    },
    {
      "port": 46715,
      "protocol": "tcp",
      "address": "127.0.0.1",
      "binding": "loopback_only",
      "process": "code",
      "pid": 9816,
      "docker": null
    },
    {
      "port": 8443,
      "protocol": "tcp",
      "address": "2001:db8::1",
      "binding": "beyond_reach",
      "process": null,
      "pid": null,
      "docker": null
    },
    {
      "port": 8080,
      "protocol": "tcp",
      "address": "0.0.0.0",
      "binding": "all_interfaces",
      "process": null,
      "pid": null,
      "docker": { "published_on": null }
    }
  ]
}
```

Every TCP socket in `LISTEN` state on this machine, from `/proc/net/tcp` and
`/proc/net/tcp6`. `protocol` is always `"tcp"` today — the underlying `udp`
files are not read.

`address` is the literal bound address: `"0.0.0.0"`, `"127.0.0.1"`, `"::"`,
`"::1"`, or a specific interface address.

`binding` is the derived fact that actually matters: not just whether opening
porthole's firewall for this port could change anything, but whether the
service is even reachable from outside this machine in the first place.

| `binding` | meaning |
|---|---|
| `"loopback_only"` | bound to `127.0.0.0/8`, or its IPv6 loopback equivalent (`::1`) — only this machine can reach it, and no firewall rule changes that. |
| `"all_interfaces"` | bound to `0.0.0.0` or `::` — every interface, including whichever one the local network is reachable through. |
| `"specific"` | bound to one interface's own IPv4 address rather than the wildcard — still network-facing. |
| `"beyond_reach"` | bound to a genuine IPv6 address — not the wildcard, not loopback, not v4-mapped. This service **is** reachable over IPv6, but porthole v1 manages IPv4 rules only and can neither open nor close a firewall rule for it. |

`"loopback_only"` and `"beyond_reach"` both mean "porthole cannot act on
this port", but for opposite reasons a script or a person must not conflate:
a loopback-only service is safe — nothing outside this machine can reach it
regardless of any firewall — while a `beyond_reach` service is exposed to the
network and porthole is simply blind to it. Reading `beyond_reach` as a
variant of "safe to ignore" is exactly the false-in-the-dangerous-direction
mistake this field exists to prevent; a caller that only branches on whether
`binding` is `"loopback_only"` to decide "nothing to worry about" must treat
`"beyond_reach"` as its own case, not fold it in.

On an ordinary desktop `loopback_only` is typically the *majority* of the
list, not an edge case: on the machine this was built and measured on, six of
the seven listening TCP sockets were loopback-only. `porthole listen` (plain
or `--json`) marks them so that opening the firewall for one is never mistaken
for a fix.

A `::` listener is included as `all_interfaces`, not filtered out for being
IPv6: on most systems it also accepts IPv4-mapped connections, so it is
reachable over IPv4 too. porthole itself only ever opens IPv4 rules — see
`porthole doctor`'s `IPv6` check for that standing caveat, which is exactly
the caveat that makes `beyond_reach` possible: porthole can **see** a service
bound to a real IPv6 address — it is in this very listing — but has no rule it
can open or close for it, whether or not it is actually reachable from the
public internet. Seeing it and being unable to act on it is the whole point of
reporting the binding separately.

`process` and `pid` are `null` — never the string `"unknown"` — when the
owning process could not be identified. Resolving a listening socket to a
process needs read access to that process's own `/proc/<pid>/fd`, which an
unprivileged `porthole listen` only has for its own user's processes; a
socket owned by another user (or root) still appears, with `process` and
`pid` both `null`, so the list is never quietly incomplete. A script that
needs to tell "not resolved" from "a process actually named that" can rely on
this: the field is `null` in the first case and always a real string in the
second.

`docker_checked` says whether porthole could actually ask about Docker at
all — reading Docker's own DNAT rules needs root, which `porthole listen`
does not have, so it goes through the privileged helper, and `listen` still
completes without one (exactly as it already does with no firewall backend
installed). `false` means the helper could not be reached or errored, and
every row's own `docker` field is `null` regardless of whether any of them
are actually Docker-published — a script must check `docker_checked` before
reading anything into a row's `docker: null`, or it cannot tell "checked,
and Docker does not touch this port" from "not checked at all". When
`docker_checked` is `true`, a row's `docker` is `{ "published_on": <addr or
null> }` for a port a container has published, and `null` for one Docker
does not touch. A row is matched to a Docker rule on **both** the port and the
protocol, so a published UDP port leaves a TCP row on the same number at
`null`. `published_on` is the address Docker's own rule restricts
the port to — `null` means every interface (no `-d` on the rule, i.e.
published on `0.0.0.0`), a string like `"127.0.0.1"` means only that address.

One host port can carry more than one DNAT rule — `-p 127.0.0.1:5432:80 -p
0.0.0.0:5432:80` is two — and this field holds one object. It reports the
**most exposing** of them: every interface first, then a specific address,
then loopback. So `published_on: null` on a port that is also bound to
loopback is not a contradiction, and the field never understates how
reachable a port is.

A rule that publishes a range (`-p 8000-8010:9000-9010`) or a multiport list
counts as published for every port it names, each matched on its own.
See `porthole open --json`'s own `docker_note` for the two-sentence version
of what this means for a person opening that exact port, and
`porthole_core::docker`'s own module doc for why both directions — already
reachable, and not made reachable by opening it — matter.

## `porthole devices list --json`

```json
{
  "schema": 1,
  "devices": [
    {
      "name": "phone",
      "kind": "mac",
      "address": "bc:24:11:5e:1c:6e",
      "resolvable": true,
      "resolved_address": "10.10.10.245"
    },
    {
      "name": "printer",
      "kind": "host",
      "address": "printer.local",
      "resolvable": false,
      "resolved_address": null
    }
  ]
}
```

Saved devices live client-side, in `~/.config/porthole/devices.toml` -- the
privileged helper never reads this file, and `--to <name>` resolves a saved
device to an address before anything crosses the D-Bus boundary.

`kind` is `"mac"` (resolved through the kernel's neighbour table) or `"host"`
(resolved through the system resolver, e.g. an mDNS `.local` name); `address`
is the saved MAC or hostname, unchanged. `resolvable` is whether porthole can
turn the saved MAC or hostname into an address right now -- a saved device is
not always present, and this is not an error, only a fact: opening `--to` an
unresolvable device
fails with the `device_unreachable` kind and exit code 6, in the same
`{code, kind, message}` shape the Errors section below describes for every
other failure. `resolved_address` is the address it currently resolves to, or
`null` when it does not resolve right now.

`resolvable` is a live attempt, made once per row while this command runs:
`ip -4 neigh show` for a `"mac"` device, `getent ahostsv4` for a `"host"` one.
A MAC the neighbour table shows on two interfaces at once is settled by
whichever interface currently carries the default route; a MAC on two
interfaces where neither is that one reports `resolvable: false`, the same as
a MAC that is not there at all.

Read both values narrowly. `false` means the lookup ran and found nothing
here and now -- the neighbour table only holds what has spoken to this
machine recently -- not "no such device", and never "porthole could not find
out". A lookup that could not be made at all -- no `ip` or `getent` to run,
or either of them exiting non-zero -- fails the whole command with the error
object below, rather than reporting `false` for a row it never checked.
`true` means the kernel has a mapping recorded for that MAC and has not
disproved it, and no more than that.

Two neighbour states are rejected outright: `INCOMPLETE`, which has no
link-layer address at all because resolution is still in flight, and
`FAILED`, which is the kernel's record that it probed the address and got no
answer -- an entry that may still carry the MAC it last knew, which is
precisely the mapping the probe disproved.

Entries on a virtual interface are rejected too, on the same list of
interface prefixes subnet detection uses. A Docker container, a libvirt guest
and a VPN peer are each in the kernel's table and none of them is on the
network porthole opens a port towards, so a MAC found only there reports
`resolvable: false` rather than an address outside every subnet this machine
holds.

`STALE` entries are accepted, deliberately. `STALE` is what the kernel marks
an entry once it has not been confirmed for roughly 30 seconds, which is the
ordinary condition of an idle device rather than a sign anything is wrong.
The consequence is that a device that has just left still resolves until the
kernel drops or rewrites its entry, and on a small network that can take a
while: the table is garbage-collected only above `gc_thresh1` entries, 128 by
default. **Within that window the address may already belong to something
else**: a DHCP lease that expired can be handed to the next machine that
asks, so a rule opened towards a saved device can end up aimed at a stranger
on the same network. Usually the correction arrives on its own -- whatever
takes the address next announces itself by ARP, the kernel rewrites that row,
and the saved MAC stops mapping to it -- but "usually" and "on its own" are
not "before the rule was written".

Requiring `REACHABLE` instead would narrow that window without closing it,
for a reason that has nothing to do with neighbour states: a rule outlives
the check that authorized it. Nothing is re-examined once the rule is
written, so a device may leave a second later and the rule stands until it
expires. Neither value is a reachability test, and porthole sends no packet
to make one.

A malformed `devices.toml` is a different failure from an unresolvable device
and does not appear in this shape at all: it exits `2` with the
`invalid_argument` error object below, naming the offending device.

## `porthole devices add --json` and `porthole devices rm --json`

```json
{
  "schema": 1,
  "action": "added",
  "device": {
    "name": "phone",
    "kind": "mac",
    "address": "bc:24:11:5e:1c:6e"
  }
}
```

`action` is `"added"` or `"forgotten"`. `name` is the saved name; `kind` and
`address` are as in `devices list` above, and both are `null` for
`"forgotten"`, which names the device it removed and reports nothing about an
address it no longer holds.

Neither object carries `resolvable` or `resolved_address`. Those are a live
lookup `devices list` performs and neither of these commands does, so
reporting them would mean resolving a device nobody asked to resolve.

`devices add`'s picker prints a name beside an address when `getent hosts`
answers for it, on stderr with the rest of the prompt -- stdout is unchanged,
and no name reaches the address book or any JSON field. Each lookup is
bounded at one second and the pass at two; an address with no answer is
printed without a name.

`devices add` has one refusal of its own: an empty neighbour table, with
nothing to put in front of you to pick. It exits `9` with the
`nothing_to_offer` error object below, on stdout, like every other failure —
it does not print a list of nothing and ask you to choose from it.

## `porthole doctor --json`

```json
{
  "schema": 1,
  "checks": [
    {
      "name": "Firewall",
      "ok": true,
      "detail": "firewalld 2.4.4 is running",
      "remedy": ""
    },
    {
      "name": "Helper",
      "ok": false,
      "detail": "not answering on the bus",
      "remedy": "Either /usr/libexec/porthole-helper is not installed, or its dbus activation file is missing…"
    }
  ]
}
```

One object per check, always in the same order — the order a failure cascades
in: `Firewall`, `Helper`, `Expiry timer`, `polkit`, `State`, `Network`, `Docker`,
`IPv6`. `remedy` is `""` when there is nothing to do. The process exits `1` if
any check's `ok` is `false`, `0` if every check passed — a script can gate on
the exit code without parsing the JSON at all.

## Errors

On failure, the JSON goes to **stdout** and the process exits with `code`.

```json
{
  "schema": 1,
  "error": { "code": 5, "kind": "already_open", "message": "5173/tcp is already open (…)" }
}
```

`kind` is a stable slug; `message` is human text and may change wording.

This shape is identical whether `open` or `close` did the work locally
(`--dry-run`) or asked the privileged helper over D-Bus to do it: the helper
sends back the same `code` and the same `kind` slug milestone 1 defined, and
the CLI reports them verbatim rather than re-deriving them. A script reading
`--json` output cannot tell, and does not need to, whether the work happened
in-process or across the bus — with two exceptions: `command_spawn_failed`
and `io_error` are distinct kinds locally, but both collapse into the same
`unexpected` kind once they cross the bus, since the helper's own error type
has no request-specific meaning worth distinguishing on the wire for either
one.
