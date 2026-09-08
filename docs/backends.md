# The three backends

porthole never asks which firewall to drive. `porthole doctor` and `porthole
status` say which one it found: [firewalld](#firewalld), then [ufw](#ufw),
then [nftables](#nftables) — nftables last because its mere presence says
nothing (`nft` ships on nearly every modern Linux whether or not anyone uses
it as a policy manager), while installing firewalld or ufw is a decision
about how the machine is meant to be managed.

Every one of the three is picked on being **installed**, never on being
**active**. An installed-but-stopped firewalld still outranks a running ufw:
"firewalld is installed but not running" is a more useful thing to tell you
than silently managing a different firewall than the one this machine
settled on, and refusing to act while the chosen one is stopped is `open`
and `close`'s job, not detection's. nftables gets no such exception — mere
presence is exactly what puts it last, not what would otherwise keep it out
of consideration.

Every backend keeps the same two promises: no permanent rule, ever, and a
rule porthole did not create is never touched. What differs between them —
what each one can do, what it cannot, and the caveat that would otherwise
surprise you later — is everything below.

**Only one of the three can redirect.** `porthole forward` is implemented on
firewalld and nowhere else. ufw and nftables refuse it, with exit code 12 and
a message of their own; the two refusals have different reasons and say
different things, and each backend's section below gives its own. A machine
whose firewall cannot redirect is told so before porthole reads Docker, the
state file or `/proc` — nothing about any of those changes the answer, and
reporting one of them instead would send you looking for a container on a
machine that could not have forwarded to it either way.

Reconciliation runs before every command, `--dry-run` included, so the list of
commands a dry-run `open` prints can contain one you did not ask for: an
orphan close (a `ufw --force delete ...` or `nft delete rule ...`) for a
`porthole:`-marked rule reconciliation found and state no longer claims. That
command belongs to the sweep that always runs alongside your request, not to
the `open` itself — seeing it is honest, not a bug, but it can look like one
if you are only expecting commands for the port you named.

## firewalld

porthole writes **runtime** rich rules only, never `--permanent`: a reload or
a reboot removes them by firewalld's own design, which is exactly the
"nothing survives" porthole promises for free on this backend.

**porthole can never prove which rich rules are its own.** firewalld's rich
rule language has no comment element to mark them with, so a rule porthole
wrote is textually identical to one you add by hand with the same source,
port and protocol. Two things follow from that directly:

- `porthole list` and `porthole status` can briefly show a rule that a
  `firewall-cmd --reload` (or a reboot) already dropped. Reconciliation runs
  before every command and corrects the state file the moment it notices —
  but the moment in between is real. This is the safe direction: porthole
  over-reports what is exposed rather than under-reporting it, and the very
  next command corrects it.
- The opposite direction — "the firewall has a rich rule state does not know
  about, so remove it" — **is never attempted on firewalld.** Applied
  naively it would delete rich rules you wrote yourself, for your own
  reasons, the moment porthole lost track of one of its own. That is the
  worst failure a tool whose entire promise is "reversible and narrow" could
  ship, so this half of reconciliation simply does not run here. It does run
  on ufw and nftables, where a `porthole:<uuid>` marker makes ownership
  provable — see below.

**All of that is equally true of a forward.** A `forward-port` rich rule
carries no comment element either, so porthole cannot prove one is its own any
more than it can an accept, and the orphan sweep is just as unavailable for
it. Do not read the extra machinery around forwards — the mapping recorded in
the state file, the wake-up that compares it against Docker's table — as
closer tracking of the rule in the firewall: it is tracking of the
*container*, and it acts through the same state file every other rule uses. A
`firewall-cmd --reload` drops a redirect exactly as it drops an accept, and
the record of it is corrected on the next porthole command by the same
reconciliation, in the same direction, with the same silence in the other.

That same asymmetry reaches `porthole close --id <id> --forget` (the escape
hatch for a rule recorded under a backend this machine no longer has — see
`porthole close --help`). Forgetting a **ufw or nftables** rule is not
permanent: both can prove a rule is their own, so the next `porthole open` or
`porthole close` run while that backend is current finds the still-marked rule
and sweeps it away. Note which commands those are: `status` and `list`
deliberately never touch the firewall, so running them will not clean it up --
the rule waits for something that opens or closes. Forgetting a **firewalld** rule is permanent:
firewalld can never prove a rich rule is its own, so that sweep never runs
for it, on any account — nothing ever closes it automatically, even after
firewalld is current again.

### The one backend that can redirect

`porthole forward` writes **one** rich rule here: the `forward-port` redirect,
scoped to the same `source address` an ordinary open would carry. Not two.

That is a measurement, not a reading of the manual. A redirect plus an accept
for the external port was the original design, and a spike with firewalld
2.4.4, nftables 1.1.6 and Docker 29.8.0 — packet counters at each netfilter
hook, a client in its own network namespace — took it apart in both
directions:

- **The accept is unnecessary.** With the redirect in the zone, *zero* packets
  reach the input hook at all: the DNAT has already happened in prerouting, so
  the connection arrives at the forward hook instead, where firewalld's own
  `filter_FORWARD` accepts `ct status dnat` traffic ahead of the jump to any
  zone chain. Setting the zone's target to `DROP` did not stop it. With and
  without the accept, every counter was identical. (Docker's own chains permit
  it too, for their own reason: Docker writes an ACCEPT keyed on the container
  address and port for every published mapping, and porthole only ever
  redirects to a mapping Docker has published.)
- **The accept is not inert.** With a service of the host's own bound to
  `0.0.0.0` on that port, the accept *alone* makes **that service** reachable
  from the local network. It is a working accept for something else. Writing
  one beside every redirect would quietly open the host's own port each time.

So there is nothing to roll back in two steps, no removal order to get right,
and no second rule to look for: `porthole close` removes the one rule it
wrote. The container test
`a_forward_is_one_rich_rule_and_closing_takes_exactly_it_back_out` is what
holds this, against a real firewalld, and
`the_lan_reaches_the_container_through_the_forward_hook_and_only_on_the_port_it_was_given`
is what shows the traffic really travels the forward path -- it counts **zero
packets addressed to the external port** at the input hook while the forward
hook carries the connection. (The other two bullets above are the spike's
alone: nothing committed compares the counters with and without an accept, and
nothing committed binds a host service to show the accept exposing it. What
keeps that accept from being written at all is a unit test,
`a_forward_writes_no_accept_for_the_external_port`.)

porthole writes nothing into Docker's own chains — not `DOCKER`, not
`DOCKER-USER`. It has never needed to, and an unmarked rule in another
daemon's chain is not something it would leave behind.

## ufw

**ufw's rules are permanent by construction.** `ufw allow` writes straight
into `/etc/ufw/user.rules`, and `ufw.service` reloads that file at every
boot — ufw has no runtime-only concept at all, unlike firewalld. So
porthole's "nothing survives a reboot" promise is upheld here by
reconciliation actively cleaning up, not by any flag ufw itself offers.

**If porthole is killed between opening and closing a port** — the process
killed, the machine losing power, anything short of its own `close` actually
running — **the rule survives a reboot and stays enforced** until the next
`porthole` command notices and removes it. Reconciliation runs before every
command precisely to close that gap quickly in practice, but the underlying
property does not go away: a rule can outlive the process that made it. This
is the one honest weakness ufw has that firewalld does not.

Every rule porthole adds carries `comment "porthole:<uuid>"`, and that
marker is how reconciliation tells its own rules from yours. Read it back
with `ufw status numbered` — **never by grepping `/etc/ufw/user.rules`
directly.** ufw stores the comment hex-encoded in that file:
`comment=706f7274686f6c653a6162632d313233` is `porthole:abc-123`, and it
will never turn up in a plain-text search of the file that holds it.
`ufw status numbered` is the interface that decodes it, and the one
porthole itself parses.

ufw's own exit code is not useful for telling any of this apart: adding a
rule that is already there, deleting a rule that is not, and checking status
while ufw is disabled all exit `0`. porthole reads ufw's stdout instead, the
same way it already has to for firewalld's own exit-0-for-everything
shortcuts.

**`porthole forward` refuses here, and the reason is the permanence above.**
ufw has no forwarding command at all: its port forwarding is a hand-edited
`*nat` block in `/etc/ufw/before.rules`, a file ufw reloads at every boot.
Writing one would be writing a permanent firewall rule, which is the one thing
porthole never does — and unlike an `ufw allow`, reconciliation could not sweep
it away afterwards, because a `before.rules` block carries no
`porthole:<uuid>` comment and is not a rule ufw lists at all. So there is no
temporary redirect for ufw to offer, and porthole says so:

```
$ porthole forward 3000
porthole: ufw cannot redirect a port: porthole has no forward for this backend
$ echo $?
12
```

## nftables

nftables is the fallback: chosen when neither firewalld nor ufw is
installed, and by presence rather than activity, because `nft` existing on a
machine says nothing about whether anyone uses it directly.

**porthole edits your own input chain, not a table of its own.** The obvious
design — an isolated `table inet porthole` at a higher hook priority — does
not work: in netfilter, `accept` ends traversal of the chain it is in, not
the hook itself, so evaluation continues into whatever base chain your own
ruleset registered at the same hook afterwards. Nothing short of the chain
that already holds your `drop` can make a packet actually reach your
service. So porthole finds that chain and inserts its own accept rule ahead
of the drop, marked with a `porthole:<uuid>` comment for reconciliation to
recognise later — the same provable-ownership marker ufw's rules carry.

Two situations make porthole refuse outright rather than guess:

- **No chain is registered at the input hook at all.** Nothing is filtering
  incoming traffic, so the port a user asks to open is already reachable —
  adding a rule here would be theatre, and porthole says so instead of
  pretending to open anything.
- **More than one chain is registered at the input hook.** porthole cannot
  prove which one actually decides a packet's fate, so it will not insert
  into either one on a guess. `porthole doctor` names the chains it found.

And one situation porthole can see but only partially: **a chain whose
policy is `accept`, with no rule in the chain itself that drops or
rejects.** porthole only inspects this one chain — it does not follow `jump`
or `goto` targets, which is exactly how firewalld and ufw structure their
own rulesets internally — so a chain this one jumps to could still be doing
the actual dropping. That means porthole cannot say the port becomes
unreachable once closed; it can only say what it actually checked: **no rule
in this chain drops or rejects, so closing a port here is not, on its own,
evidence that it becomes unreachable.** That is the direction that misleads
someone into feeling safe, so `porthole doctor` and `porthole status` say it
plainly — but they say no more than they checked. The wording is
deliberately this weaker, true claim, never the stronger and potentially
false "closing a port here makes it unreachable".

**`porthole forward` refuses here too, and not for ufw's reason.** Nothing
about permanence is in the way: nftables rules are as runtime-only as
firewalld's. What is in the way is the *accept*. A redirect on its own was
measured unreachable on a ruleset whose forward chain drops — and unlike
firewalld, plain nftables has no `ct status dnat accept` underneath to carry
it. The accept that would carry it has to sit in a base chain registered at
the **forward** hook, which is not the hook porthole writes at: this backend
finds the single chain at the *input* hook and inserts there, and an accept
put there does nothing for a redirect (measured: identical counters, still
unreachable). An accept in a table of porthole's own does not help either, for
the same reason an isolated accept never does — a drop in any forward base
chain decides the packet.

Applying the "exactly one chain, or refuse" discipline to the forward hook is
the shape a future implementation would take. It was not built, because the
ruleset a forward actually meets on a machine that also runs Docker has a
second forward base chain of Docker's own (`ip filter FORWARD`, at nft
priority 0, jumping to `DOCKER-USER` before anything porthole inserted would
be reached), and which combinations of those chains would work was never
measured. A forward that silently does not forward is the worst of the
available outcomes, so this backend says what it cannot do instead:

```
$ porthole forward 3000
porthole: nftables cannot redirect a port: a redirect on its own does not
reach a container through a forward chain that drops, and the accept that
would carry it belongs in the chain deciding forwarded traffic, where porthole
does not write
$ echo $?
12
```
