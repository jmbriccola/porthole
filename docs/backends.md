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
