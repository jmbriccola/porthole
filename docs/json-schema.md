# `--json` output

Every command accepts `--json`. The shape is versioned by the top-level
`schema` field, currently `1`. Fields are added, never renamed or removed.

All timestamps are **seconds since the Unix epoch**, as integers. Convert with
`date -d @1757000000`.

## Rule object

Used in `list`, `status`, `open` and `close`.

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
  "uid": 1000
}
```

- `protocol` — `"tcp"` or `"udp"`.
- `scope` — `"network"` or `"anywhere"`. When it is `"anywhere"`, `target` is
  the string `"anywhere"`; otherwise `target` is a CIDR.
- `backend` — `"firewalld"`, `"ufw"` or `"nftables"`: whichever backend
  created this rule. See [docs/backends.md](backends.md) for what each one
  can and cannot do.
- `expires_at` and `expires_in_seconds` are `null` for an `--until-reboot` rule.

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
  "commands": [ "firewall-cmd --zone=... '--add-rich-rule=...'" ]
}
```

`commands` lists the withheld commands under `--dry-run`, and is empty
otherwise.

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
  "services": [
    {
      "port": 5173,
      "protocol": "tcp",
      "address": "0.0.0.0",
      "binding": "all_interfaces",
      "process": "node",
      "pid": 12043
    },
    {
      "port": 46715,
      "protocol": "tcp",
      "address": "127.0.0.1",
      "binding": "loopback_only",
      "process": "code",
      "pid": 9816
    }
  ]
}
```

Every TCP socket in `LISTEN` state on this machine, from `/proc/net/tcp` and
`/proc/net/tcp6`. `protocol` is always `"tcp"` today — the underlying `udp`
files are not read.

`address` is the literal bound address: `"0.0.0.0"`, `"127.0.0.1"`, `"::"`,
`"::1"`, or a specific interface address.

`binding` is the derived fact that actually matters: whether opening
porthole's firewall for this port could change anything.

| `binding` | meaning |
|---|---|
| `"loopback_only"` | bound to `127.0.0.0/8` (or its IPv6 loopback/non-IPv4-reachable equivalent) — only this machine can reach it, and no firewall rule changes that. |
| `"all_interfaces"` | bound to `0.0.0.0` or `::` — every interface, including whichever one the local network is reachable through. |
| `"specific"` | bound to one interface's own address rather than the wildcard — still network-facing. |

On an ordinary desktop `loopback_only` is typically the *majority* of the
list, not an edge case: on the machine this was built and measured on, six of
the seven listening TCP sockets were loopback-only. `porthole listen` (plain
or `--json`) marks them so that opening the firewall for one is never mistaken
for a fix.

A `::` listener is included as `all_interfaces`, not filtered out for being
IPv6: on most systems it also accepts IPv4-mapped connections, so it is
reachable over IPv4 too. porthole itself only ever opens IPv4 rules — see
`porthole doctor`'s `IPv6` check for that standing caveat.

`process` and `pid` are `null` — never the string `"unknown"` — when the
owning process could not be identified. Resolving a listening socket to a
process needs read access to that process's own `/proc/<pid>/fd`, which an
unprivileged `porthole listen` only has for its own user's processes; a
socket owned by another user (or root) still appears, with `process` and
`pid` both `null`, so the list is never quietly incomplete. A script that
needs to tell "not resolved" from "a process actually named that" can rely on
this: the field is `null` in the first case and always a real string in the
second.

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
