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
  "firewall_version": "2.4.4",
  "location": "FedoraWorkstation",
  "network": { "interface": "wlo1", "address": "10.10.10.119", "cidr": "10.10.10.0/24" },
  "rules": [ /* rule objects */ ]
}
```

`network` is `null` when the machine is not on a usable network.

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
  "errors": [ /* error objects, see below */ ],
  "commands": []
}
```

`--all` can partly succeed: rules that closed appear in `closed`, and each
failure appears in `errors` with the same `{code, kind, message}` shape used
below. The output is always a single object — the exit code carries the first
failure's code.

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
