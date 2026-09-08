//! The nftables backend.
//!
//! # Why porthole edits the user's chain instead of keeping its own
//!
//! The obvious design — a `table inet porthole` of our own, isolated from the
//! user's rules, at a higher precedence — **does not open the port.** Measured
//! with two network namespaces, a veth pair, a real listener and a real TCP
//! connect:
//!
//! | arrangement | result |
//! |---|---|
//! | accept in porthole's own table at `hook input priority -10`, user's table drops at 0 | BLOCKED |
//! | accept inserted into the user's own input chain | REACHABLE |
//!
//! In netfilter `accept` is not terminal for the hook: it ends traversal of
//! that chain, then evaluation continues through the other base chains at the
//! same hook. Only `drop` is terminal. So precedence cannot beat someone
//! else's drop, and an isolated table would make porthole report an opening
//! that never happened.
//!
//! Everything awkward about this file follows from that: finding the user's
//! chain, refusing when there is more than one, inserting rather than adding,
//! and re-reading kernel handles instead of storing them.
//!
//! # Why there is no `forward` here
//!
//! A forward would be a `dnat` in a nat prerouting chain plus, where
//! something drops forwarded traffic, an accept that lets the redirected
//! packet through. The accept is the problem.
//!
//! It cannot go in a table of porthole's own, for the reason above. That was
//! measured at the forward hook in the mirror direction: an unrelated `inet`
//! table with `hook forward ... policy drop`, added beside a working
//! forward, made it unreachable, and removing the table restored it. A drop
//! in any forward base chain decides the packet; by the same rule an accept
//! in one cannot rescue a packet another drops.
//!
//! So it would have to go in a forward base chain the host already has. The
//! arrangement measured to work was a hand-built ruleset with exactly one
//! such chain and no container runtime anywhere: an accept on the post-DNAT
//! tuple (`ip saddr <scope> ip daddr <container> tcp dport <container port>`)
//! in that chain made a redirect reachable that was otherwise dropped.
//!
//! That is not the ruleset a forward meets. Docker registers a forward base
//! chain of its own — `ip filter FORWARD`, at nft priority 0 — which starts
//! by jumping to `DOCKER-USER`, and which was measured to accept the
//! redirected traffic already: in a chain it reaches, a rule keyed on the
//! container's address and port counted the packet, and deleting that one
//! rule left the connection dying at Docker's own `DROP`. porthole only ever
//! redirects to a mapping Docker has published, which is exactly what that
//! rule covers. An accept porthole inserted would land ahead of the jump to
//! `DOCKER-USER`, where a user's own container policy goes, and no
//! measurement here shows it carrying anything.
//!
//! This backend on a host also running Docker was never measured working
//! either way; which combinations of the forward base chains such a host
//! carries would pass was not established. So `forward` refuses. A redirect on its own is
//! not the smaller alternative: on a ruleset whose forward chain has `policy
//! drop`, it was measured unreachable.
//!
use super::{BackendHealth, BackendId, FirewallBackend, Ownership, RuleHandle};
use crate::command::{Command, CommandRunner};
use crate::error::{Error, Result};
use crate::forward::ForwardTo;
use crate::model::{OpenRequest, Target};
use serde::Deserialize;

/// A base chain porthole may write into, named for the hook it is used at:
/// the input hook, the only place an inserted accept can be reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputChain {
    pub family: String,
    pub table: String,
    pub name: String,
    pub policy: Option<String>,
}

impl std::fmt::Display for InputChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {} {}", self.family, self.table, self.name)
    }
}

/// The heterogeneous top-level envelope `nft -j` always wraps its output in:
/// a list of objects, each carrying exactly one of `metainfo`, `chain`,
/// `rule`, `table`, and so on. Fields this backend never asks about are read
/// as opaque [`serde_json::Value`]s and simply skipped.
#[derive(Deserialize)]
struct Envelope {
    nftables: Vec<serde_json::Value>,
}

/// The subset of a chain object's fields porthole cares about.
///
/// A base chain carries `hook`, `type` and `policy`; a regular chain carries
/// none of them. Selecting on the chain's *name* instead would pick a plain
/// chain someone happened to call `input`, and porthole would insert an
/// accept into a chain nothing jumps to.
#[derive(Deserialize)]
struct ChainJson {
    family: String,
    table: String,
    name: String,
    #[serde(default)]
    hook: Option<String>,
    /// `hook == "input"` alone is not enough: nat has its own `input` hook
    /// (used for locally-destined DNAT/REDIRECT), so a `type nat hook input`
    /// chain is a real base chain there that filters nothing.
    ///
    /// `type == "filter"` alone is not enough either. `man nft`: bridge
    /// family's filter priority applies to all hooks including `input`, and
    /// arp family "supports only the input and output hooks, both in chains
    /// of type filter". Both are genuine `type filter hook input` base
    /// chains and neither has anything to do with whether a routed IPv4
    /// packet is delivered locally -- see the family check where this field
    /// is used, which is what actually narrows the candidates down to
    /// chains porthole's own rule could ever be reached through.
    #[serde(default, rename = "type")]
    kind: Option<String>,
    #[serde(default)]
    policy: Option<String>,
}

/// The subset of a rule object's fields porthole cares about.
#[derive(Deserialize)]
struct RuleJson {
    handle: u64,
    #[serde(default)]
    comment: Option<String>,
    #[serde(default)]
    expr: Vec<serde_json::Value>,
}

/// Parse `nft -j list chains` into every base chain it reports, each paired
/// with the hook and type it is registered at.
///
/// A regular chain carries neither, so it comes back with two `None`s and is
/// filtered out by any caller that asks for a hook — which is what keeps a
/// plain chain someone happened to name `input` out of the candidates.
type BaseChain = (InputChain, Option<String>, Option<String>);

fn parse_base_chains(json: &str) -> Result<Vec<BaseChain>> {
    let envelope: Envelope = serde_json::from_str(json).map_err(|e| {
        Error::Unexpected(format!("could not parse `nft -j list chains` output: {e}"))
    })?;

    let mut chains = Vec::new();
    for entry in envelope.nftables {
        let Some(chain_value) = entry.get("chain") else {
            continue;
        };
        let chain: ChainJson = serde_json::from_value(chain_value.clone()).map_err(|e| {
            Error::Unexpected(format!(
                "could not parse a chain in `nft -j list chains` output: {e}"
            ))
        })?;
        chains.push((
            InputChain {
                family: chain.family,
                table: chain.table,
                name: chain.name,
                policy: chain.policy,
            },
            chain.hook,
            chain.kind,
        ));
    }
    Ok(chains)
}

/// Parse `nft -j list chains`, returning only chains registered at the input
/// hook.
fn parse_input_chains(json: &str) -> Result<Vec<InputChain>> {
    Ok(parse_base_chains(json)?
        .into_iter()
        // `inet` and `ip` are the only families porthole's own rule can ever
        // land in -- a `tcp`/`udp dport` plus `ip saddr` match is not a
        // bridge or arp match. A bridge chain's own `type filter hook input`
        // (bridge's filter priority applies at every hook, `input` included)
        // or an arp chain's (arp supports only input/output, both `type
        // filter`) is real, but filters a different kind of traffic
        // entirely; counting either as a candidate would turn a normal
        // machine that happens to have a bridge into a spurious refusal.
        .filter(|(chain, hook, kind)| {
            hook.as_deref() == Some("input")
                && kind.as_deref() == Some("filter")
                && matches!(chain.family.as_str(), "inet" | "ip")
        })
        .map(|(chain, _, _)| chain)
        .collect())
}

/// Parse `nft -j list chain <family> <table> <chain>` into its rule objects.
fn parse_rules(json: &str) -> Result<Vec<RuleJson>> {
    let envelope: Envelope = serde_json::from_str(json).map_err(|e| {
        Error::Unexpected(format!("could not parse `nft -j list chain` output: {e}"))
    })?;

    let mut rules = Vec::new();
    for entry in envelope.nftables {
        let Some(rule_value) = entry.get("rule") else {
            continue;
        };
        let rule: RuleJson = serde_json::from_value(rule_value.clone()).map_err(|e| {
            Error::Unexpected(format!(
                "could not parse a rule in `nft -j list chain` output: {e}"
            ))
        })?;
        rules.push(rule);
    }
    Ok(rules)
}

/// The kernel-assigned handle of the rule carrying `marker` as its comment, if
/// any. Never cached: handles are reassigned after a ruleset flush, so one
/// read now can name a different rule later.
///
/// Matches against the *unquoted* comment string `nft -j` reports. The
/// literal quotes `open_impl` puts in the argv element are syntax for nft's
/// own command-line grammar, not part of the comment itself, and `nft`
/// strips them before this value ever reaches JSON.
fn find_rule_handle(json: &str, marker: &str) -> Result<Option<u64>> {
    Ok(parse_rules(json)?
        .into_iter()
        .find(|rule| rule.comment.as_deref() == Some(marker))
        .map(|rule| rule.handle))
}

/// Whether a `match` statement's `right` value is one of the two shapes an
/// `ip saddr` match against a single porthole-written target actually takes
/// in `nft -j` output. Neither is a bare scalar the way `tcp dport`'s is.
///
/// Captured directly from a real `nft -j list chain` (root, in a container),
/// not composed from the schema documentation -- reasoning about the format
/// instead of observing it is exactly how the bug this function fixes got
/// written in the first place:
///
/// - a subnet (`ip saddr 10.10.10.0/24`, porthole's default scope) comes
///   back as an object, `{"prefix": {"addr": "10.10.10.0", "len": 24}}`;
/// - a single host (`ip saddr 10.10.10.42/32`) comes back as a bare string,
///   `"10.10.10.42"` -- nft does not distinguish a host address from a `/32`
///   prefix in its JSON output, so the `/32` is simply gone, and a bare
///   string here always means one.
fn is_ip_saddr_shape(right: &serde_json::Value) -> bool {
    if right.is_string() {
        return true;
    }
    right
        .get("prefix")
        .is_some_and(|prefix| prefix.get("addr").is_some() && prefix.get("len").is_some())
}

/// Whether a rule's expression list has the shape `open_impl` writes: a
/// single tcp/udp `dport` match, an optional `ip saddr` match, and a
/// terminal `accept` -- nothing else recognisable as a different statement.
///
/// Not a proof of an exact match: this does not check `match.op` (so a
/// hand-written rule using `!=` where `open_impl` always writes `==` still
/// passes) or statement order. Both gaps are only reachable through a
/// hand-marked `porthole:`-commented rule crafted to exploit them, so they
/// are negligible in practice -- but say so, rather than call this "exactly"
/// the shape `open_impl` writes, which it does not actually verify.
///
/// Mirrors `Ufw::parse_status`'s `is_porthole_shape`: a `porthole:`-commented
/// rule of any other shape is a hand-edited rule or a marker collision, not
/// something reconciliation may remove. Without this, `owned_rules` claims a
/// rule on the comment alone, and that list is what task 5's orphan sweep
/// deletes from — the one place where getting ownership wrong deletes the
/// user's firewall.
fn rule_matches_porthole_shape(rule: &RuleJson) -> bool {
    let mut has_dport = false;
    let mut has_saddr = false;
    let mut has_accept = false;

    for stmt in &rule.expr {
        if let Some(m) = stmt.get("match") {
            let payload = m.get("left").and_then(|l| l.get("payload"));
            let protocol = payload
                .and_then(|p| p.get("protocol"))
                .and_then(|v| v.as_str());
            let field = payload
                .and_then(|p| p.get("field"))
                .and_then(|v| v.as_str());
            let right = m.get("right");

            match (protocol, field) {
                // `tcp`/`udp dport` is always a bare port number in `nft -j`
                // output -- a range or a named set is a different shape
                // porthole never writes, and disqualifies the rule.
                (Some("tcp") | Some("udp"), Some("dport"))
                    if !has_dport && right.is_some_and(|r| r.is_number()) =>
                {
                    has_dport = true;
                }
                // `ip saddr` is never a bare scalar -- see `is_ip_saddr_shape`
                // for the two real shapes and why an earlier version of this
                // function, which required one, rejected every subnet-scoped
                // rule porthole writes (the default scope, i.e. the common
                // case).
                (Some("ip"), Some("saddr"))
                    if !has_saddr && right.is_some_and(is_ip_saddr_shape) =>
                {
                    has_saddr = true;
                }
                _ => return false,
            }
        } else if stmt.get("accept").is_some() && !has_accept {
            has_accept = true;
        } else {
            // Any other statement -- a second accept, a counter, a log, a
            // different verdict -- is not a shape `open_impl` produces.
            return false;
        }
    }

    // No `ip saddr` match at all is a valid shape, not a failed one: it is
    // exactly what `open_impl` writes for `Target::Anywhere` (confirmed
    // against the same real `nft -j` capture -- there is no saddr match in
    // `expr` at all, not an empty or null one), and must not be confused
    // with the "extra unexpected statement" case above that disqualifies a
    // rule. `has_saddr` is therefore never checked here.
    has_dport && has_accept
}

/// Discover every base chain registered at the input hook.
///
/// A free function, not a method, so `porthole doctor` can ask this question
/// without constructing a [`Nftables`].
pub fn input_chains(runner: &dyn CommandRunner) -> Result<Vec<InputChain>> {
    let cmd = Command::read("nft", ["-j", "list", "chains"]);
    let out = runner.run(&cmd)?.into_ok(&cmd)?;
    parse_input_chains(&out.stdout)
}

pub struct Nftables<'a> {
    runner: &'a dyn CommandRunner,
}

impl<'a> Nftables<'a> {
    pub fn new(runner: &'a dyn CommandRunner) -> Self {
        Self { runner }
    }

    fn list_chains(&self) -> Result<Vec<InputChain>> {
        input_chains(self.runner)
    }

    /// The one chain porthole may safely insert into, or a refusal that names
    /// why not.
    ///
    /// Zero candidates means nothing is filtering the input hook at all — the
    /// port is already reachable, and adding a rule would be theatre. More
    /// than one candidate means porthole cannot prove which chain decides a
    /// packet's fate, so inserting into just one of them would be a guess
    /// dressed as a fact. Neither case mutates anything.
    fn discover_single_input_chain(&self) -> Result<InputChain> {
        let mut chains = self.list_chains()?;
        if chains.is_empty() {
            return Err(Error::BackendUnavailable(
                "no nftables chain is registered at the input hook, so nothing is filtering \
                 incoming traffic; the port is already reachable and porthole has not changed \
                 anything"
                    .to_string(),
            ));
        }
        if chains.len() > 1 {
            let names: Vec<String> = chains.iter().map(ToString::to_string).collect();
            return Err(Error::BackendUnavailable(format!(
                "more than one nftables chain is registered at the input hook ({}); porthole \
                 cannot prove which one decides a packet's fate, so it will not claim to have \
                 opened the port",
                names.join(", ")
            )));
        }
        Ok(chains.remove(0))
    }

    /// Every rule in every chain registered at the input hook, paired with
    /// the chain it came from.
    ///
    /// For `list_rules` only, which is diagnostic and documented as such:
    /// unlike `open` and `owned_rules`, a chain count other than one is not
    /// refused here, because merely listing what exists must not require the
    /// same proof that mutating -- or claiming ownership of -- it does.
    fn all_rules(&self) -> Result<Vec<(InputChain, RuleJson)>> {
        let chains = self.list_chains()?;
        let mut all = Vec::new();
        for chain in chains {
            let cmd = Command::read(
                "nft",
                [
                    "-j",
                    "list",
                    "chain",
                    &chain.family,
                    &chain.table,
                    &chain.name,
                ],
            );
            let out = self.runner.run(&cmd)?.into_ok(&cmd)?;
            for rule in parse_rules(&out.stdout)? {
                all.push((chain.clone(), rule));
            }
        }
        Ok(all)
    }

    /// Whether any rule *in this chain itself* drops or rejects.
    ///
    /// Deliberately does not follow `jump`/`goto`: a chain with `policy
    /// accept` that jumps to a chain which does the actual dropping is
    /// exactly how firewalld and ufw lay out their rulesets, and walking
    /// jump targets to see through that is real work this round does not do.
    /// Callers must phrase what they say about the result accordingly -- "no
    /// drop found in this chain", never "nothing here drops", since the
    /// latter is false on a very common ruleset shape.
    fn chain_itself_has_a_drop_or_reject(&self, chain: &InputChain) -> Result<bool> {
        let cmd = Command::read(
            "nft",
            [
                "-j",
                "list",
                "chain",
                &chain.family,
                &chain.table,
                &chain.name,
            ],
        );
        let out = self.runner.run(&cmd)?.into_ok(&cmd)?;
        let rules = parse_rules(&out.stdout)?;
        Ok(rules.iter().any(|rule| {
            rule.expr
                .iter()
                .any(|e| e.get("drop").is_some() || e.get("reject").is_some())
        }))
    }

    fn open_impl(&self, req: &OpenRequest, marker: &str) -> Result<RuleHandle> {
        let chain = self.discover_single_input_chain()?;

        // `insert`, not `add`: `add` appends after the user's drop, where the
        // rule is never reached. This is the entire point of this backend.
        let cmd = Command::mutate("nft", Self::open_args(&chain, req, marker));
        self.runner.run(&cmd)?.into_ok(&cmd)?;

        Ok(RuleHandle::Nftables {
            family: chain.family,
            table: chain.table,
            chain: chain.name,
            marker: marker.to_string(),
        })
    }

    /// The argv for the accept `open_impl` writes, into an already-chosen
    /// chain.
    fn open_args(chain: &InputChain, req: &OpenRequest, marker: &str) -> Vec<String> {
        let mut args: Vec<String> = vec![
            "insert".to_string(),
            "rule".to_string(),
            chain.family.clone(),
            chain.table.clone(),
            chain.name.clone(),
            req.protocol.to_string(),
            "dport".to_string(),
            req.port.to_string(),
        ];
        if let Target::Network { cidr } = req.target {
            args.push("ip".to_string());
            args.push("saddr".to_string());
            args.push(cidr.to_string());
        }
        args.push("accept".to_string());
        args.push("comment".to_string());
        // The quotes here are literal characters in the argv element, not
        // shell quoting: `RealRunner` spawns via `StdCommand::args`, with no
        // shell in between to add or strip anything. `nft` re-lexes argv
        // with its own grammar, in which an unquoted token cannot contain a
        // colon -- and the marker is always `porthole:<uuid>`. Confirmed
        // against the real binary, unprivileged, in check mode: `nft -c ...
        // comment porthole:abc` is a syntax error ("unexpected colon");
        // `nft -c ... comment '"porthole:abc"'` reaches netlink, i.e. it
        // parsed. Do not "clean up" these quotes -- they are load-bearing.
        args.push(format!("\"{marker}\""));
        args
    }

    fn close_impl(&self, family: &str, table: &str, chain: &str, marker: &str) -> Result<()> {
        let cmd = Command::read("nft", ["-j", "list", "chain", family, table, chain]);
        let out = self.runner.run(&cmd)?.into_ok(&cmd)?;

        // Never trust a handle stored at open time: the kernel reassigns
        // handles after a ruleset flush, so a stale one can by now name the
        // user's rule, not porthole's.
        let Some(handle) = find_rule_handle(&out.stdout, marker)? else {
            return Err(Error::RuleNotFound(format!(
                "nftables has no rule marked {marker} in {family} {table} {chain}"
            )));
        };

        let handle_str = handle.to_string();
        let cmd = Command::mutate(
            "nft",
            [
                "delete",
                "rule",
                family,
                table,
                chain,
                "handle",
                handle_str.as_str(),
            ],
        );
        self.runner.run(&cmd)?.into_ok(&cmd)?;
        Ok(())
    }
}

impl FirewallBackend for Nftables<'_> {
    fn id(&self) -> BackendId {
        BackendId::Nftables
    }

    fn open(&self, req: &OpenRequest, marker: &str) -> Result<RuleHandle> {
        self.open_impl(req, marker)
    }

    /// Refused, and nothing is run at all -- not even a read.
    ///
    /// The module docs carry what was measured and what follows from it.
    fn forward(&self, _req: &OpenRequest, _to: &ForwardTo, _marker: &str) -> Result<RuleHandle> {
        Err(Error::ForwardUnsupported(
            "nftables cannot redirect a port: a redirect on its own does not reach a \
             container through a forward chain that drops, and the accept that would carry \
             it belongs in the chain deciding forwarded traffic, where porthole does not \
             write"
                .to_string(),
        ))
    }

    fn close(&self, handle: &RuleHandle) -> Result<()> {
        match handle {
            RuleHandle::Nftables {
                family,
                table,
                chain,
                marker,
            } => self.close_impl(family, table, chain, marker),
            other @ (RuleHandle::Firewalld { .. } | RuleHandle::Ufw { .. }) => Err(
                Error::Unexpected(format!("the nftables backend was handed a {other:?}")),
            ),
        }
    }

    fn list_rules(&self) -> Result<Vec<RuleHandle>> {
        Ok(self
            .all_rules()?
            .into_iter()
            // An uncommented rule becomes a handle with `marker: ""`, which
            // names no rule `close` could ever find (it would read back
            // `RuleNotFound`, never someone else's rule). That's acceptable
            // here specifically because this list is diagnostic, never
            // consumed to decide what to delete: the trait's own contract
            // for `list_rules` is "every rule visible in the place porthole
            // writes to", the user's un-marked rules included, so skipping
            // them would violate that contract for no safety gain. Contrast
            // `owned_rules`, which requires a real `porthole:` marker before
            // a rule is ever named as something reconciliation may remove.
            .map(|(chain, rule)| RuleHandle::Nftables {
                family: chain.family,
                table: chain.table,
                chain: chain.name,
                marker: rule.comment.unwrap_or_default(),
            })
            .collect())
    }

    /// The rules porthole can prove it created: a `porthole:`-commented rule,
    /// of exactly the shape `open_impl` writes, in the one chain `open` would
    /// insert into.
    ///
    /// This deliberately uses the same single-chain discovery `open` uses,
    /// and returns the same refusal when it is ambiguous -- rather than
    /// `all_rules`'s "walk every input-hook chain", which `list_rules` uses.
    /// This list is what reconciliation's orphan sweep (task 5) deletes from;
    /// on a two-chain ruleset, `open` refuses to touch either chain because
    /// it cannot prove which one decides a packet's fate, and a rule marked
    /// `porthole:` sitting in one of them is equally unprovable -- it could
    /// be a leftover from before the ruleset grew a second chain, or a marker
    /// collision. Claiming it anyway, the way `all_rules` does for the
    /// diagnostic `list_rules`, would hand the orphan sweep a rule to delete
    /// on exactly the same guess `open` already declined to make.
    ///
    fn owned_rules(&self) -> Result<Option<Vec<RuleHandle>>> {
        let chain = self.discover_single_input_chain()?;
        let cmd = Command::read(
            "nft",
            [
                "-j",
                "list",
                "chain",
                &chain.family,
                &chain.table,
                &chain.name,
            ],
        );
        let out = self.runner.run(&cmd)?.into_ok(&cmd)?;
        let rules = parse_rules(&out.stdout)?;

        Ok(Some(
            rules
                .into_iter()
                .filter(|rule| {
                    rule.comment
                        .as_deref()
                        .is_some_and(|c| c.starts_with("porthole:"))
                        && rule_matches_porthole_shape(rule)
                })
                .map(|rule| RuleHandle::Nftables {
                    family: chain.family.clone(),
                    table: chain.table.clone(),
                    chain: chain.name.clone(),
                    marker: rule.comment.unwrap_or_default(),
                })
                .collect(),
        ))
    }

    fn ownership(&self) -> Ownership {
        Ownership::Marked
    }

    fn health(&self) -> Result<BackendHealth> {
        let version_cmd = Command::read("nft", ["--version"]);
        let version = match self.runner.run(&version_cmd) {
            Ok(out) if out.success() => Some(
                out.stdout
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .trim()
                    .to_string(),
            ),
            Err(Error::CommandSpawn { .. }) => {
                return Ok(BackendHealth {
                    available: false,
                    active: false,
                    active_unknown: false,
                    version: None,
                    detail: "nft is not installed".to_string(),
                    caveat: None,
                })
            }
            // Anything else is not proof the binary is absent -- only
            // `CommandSpawn` is, and that already returned above.
            // `RealRunner` can only ever fail this specific call with
            // `CommandSpawn`, so this arm is dead through it -- but
            // `CommandRunner` is a trait, and a hypothetical different
            // failure here means only that this one read did not answer,
            // not that nft is not installed. Fall through with no version
            // known and let the next read -- `nft -j list chains`, a call
            // this backend already has to make -- decide
            // `available`/`active` on its own evidence.
            Ok(_) | Err(_) => None,
        };

        // `nft -j list chains` needs root even just to summarise what is
        // registered ("Operation not permitted (you must be root)" for an
        // ordinary user, verified against the real binary) -- `available`
        // must never depend on this succeeding: the binary being present is
        // already established above, and reading the ruleset is a separate
        // fact that needs separate privilege. Before this fix, a permission
        // failure here propagated with `?`, so `detect()` returned `Err` for
        // an ordinary user on a genuinely installed and possibly enforcing
        // nftables setup -- see C1 in the milestone 3 merge-wave review.
        // Degrading to `active: false` with an explanation, rather than
        // propagating, is what keeps that from reading as "no firewall at
        // all".
        //
        // Every failure from here degrades, not only `Error::CommandFailed`
        // (the permission-denied shape). An earlier version of this comment
        // said a malformed-JSON parse failure (`Error::Unexpected`, from a
        // genuinely successful exit whose stdout porthole cannot parse)
        // needed to propagate so `porthole doctor` could tell it apart from
        // "needs root" -- but doctor never gets the chance: it gets its
        // backend from `backend::detect`, which propagates any `health()`
        // error with `?` before `firewall_check` is ever called (see
        // `detect_does_not_report_no_firewall_when_nftables_output_is_unparseable`
        // in `backend/mod.rs`, which exercises exactly that path). An
        // installed `nft` whose output porthole cannot parse is still an
        // installed `nft` -- propagating turned it into "no firewall found",
        // the last remaining way this backend could report a running
        // firewall as absent. The two failure shapes still get different
        // `detail` wording below, for whoever reads it by hand; only the
        // wording differs, not whether this degrades.
        match self.list_chains() {
            Ok(chains) => {
                let (active, detail) = match chains.as_slice() {
                    [] => (
                        false,
                        "no nftables chain is registered at the input hook, so nothing is \
                         filtering incoming traffic and the port is already reachable"
                            .to_string(),
                    ),
                    [chain] => (
                        true,
                        match &version {
                            Some(v) => format!("{v}: {chain} is enforcing"),
                            None => format!("{chain} is enforcing"),
                        },
                    ),
                    many => {
                        let names: Vec<String> = many.iter().map(ToString::to_string).collect();
                        (
                            true,
                            format!(
                                "more than one nftables chain is registered at the input hook \
                                 ({}); porthole cannot tell which one decides a packet's fate",
                                names.join(", ")
                            ),
                        )
                    }
                };

                // The direction that misleads: a chain whose policy is accept
                // and holds no drop or reject *of its own* might still not be
                // enforcing anything -- but it might also jump to a chain
                // that does the actual dropping (exactly how firewalld and
                // ufw lay out their rulesets), which this backend does not
                // check. Say only what was actually inspected, with the
                // hedge spelled out, rather than let a user read a confident
                // guarantee into `active: true` that the chain alone cannot
                // support. This lives in `caveat`, not appended to `detail`:
                // it is true regardless of `active` (both are `true` here,
                // but the distinction matters to callers such as `porthole
                // status`, which must surface a caveat even when everything
                // else reads as healthy) and callers that want the standing
                // caution -- `status`, and `doctor`'s own `remedy` -- read a
                // dedicated field rather than parsing prose for a "; "
                // separator.
                // `chain_itself_has_a_drop_or_reject` is one more read (`nft
                // -j list chain ...` for this one chain's own rules), and a
                // `?` here would be one more way `health()` could still
                // return `Err` -- the same shape of gap this function's
                // other two reads were just fixed for. In practice this read
                // needs no more privilege than the `list_chains()` call that
                // already succeeded to reach this arm at all, so a failure
                // here is resource-level (the same category as firewalld's
                // own `--state` spawn failure), not a live, reachable
                // permission gap -- but propagating it would still turn a
                // confirmed `active: true` nftables setup into "no firewall
                // found" the moment this optional caveat could not be
                // computed, which is a strictly worse outcome than simply
                // not knowing the caveat. Report the failure as the caveat
                // itself instead: honest about what could not be confirmed,
                // never silently dropped and never fatal to the read that
                // already succeeded.
                let mut caveat = None;
                if let [chain] = chains.as_slice() {
                    if chain.policy.as_deref() == Some("accept") {
                        match self.chain_itself_has_a_drop_or_reject(chain) {
                            Ok(false) => {
                                caveat = Some(
                                    "its policy is accept and no rule in this chain drops or \
                                     rejects (a chain it jumps to might still), so closing a \
                                     port here is not on its own evidence that it becomes \
                                     unreachable"
                                        .to_string(),
                                );
                            }
                            Ok(true) => {}
                            Err(e) => {
                                caveat = Some(format!(
                                    "its policy is accept, but porthole could not read this \
                                     chain's own rules to check whether one of them drops or \
                                     rejects ({e}) -- treat closing a port here as unconfirmed, \
                                     not as evidence it becomes unreachable"
                                ));
                            }
                        }
                    }
                }

                Ok(BackendHealth {
                    available: true,
                    active,
                    active_unknown: false,
                    version,
                    detail,
                    caveat,
                })
            }
            // Does not claim *why* the exit was non-zero: permission denial
            // is the common cause (verified against the real binary, see
            // the comment above this match), but not the only one a
            // non-zero exit can mean, and porthole has not established
            // which this is. Say only that nothing was confirmed, and name
            // the real stderr `{e}` already carries.
            Err(e @ Error::CommandFailed { .. }) => Ok(BackendHealth {
                available: true,
                active: false,
                active_unknown: true,
                version,
                detail: format!(
                    "nft is installed, but listing its chains could not be confirmed ({e}) -- \
                     that is not the same as nothing being registered at the input hook, it \
                     may already be enforcing traffic porthole could not read from here"
                ),
                caveat: None,
            }),
            Err(e) => Ok(BackendHealth {
                available: true,
                active: false,
                active_unknown: true,
                version,
                detail: format!(
                    "nft is installed, but porthole could not make sense of its ruleset ({e}) \
                     -- that is not the same as nothing being registered at the input hook, \
                     it may already be enforcing traffic porthole cannot see from here; run \
                     `nft -j list chains` by hand to see what it actually returned"
                ),
                caveat: None,
            }),
        }
    }

    fn location(&self) -> Result<Option<String>> {
        match self.discover_single_input_chain() {
            Ok(chain) => Ok(Some(chain.to_string())),
            Err(_) => Ok(None),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::command::{CommandRunner, Effect, Output, RecordingRunner};
    use crate::error::ExitCode;
    use crate::model::{Lifetime, Protocol, Target};
    use std::time::Duration;

    /// Captured from `nft -j list chains`. One base chain at the input hook,
    /// one regular chain that must not be mistaken for one, and a nat chain at
    /// a different hook.
    ///
    /// Reused by `reconcile::tests` -- the sweep's agreement with
    /// `owned_rules` has to be exercised against a real backend, and a
    /// retyped copy of this fixture could drift from the one the backend's
    /// own tests use.
    pub(crate) const CHAINS_ONE_INPUT: &str = r#"{"nftables":[
      {"metainfo":{"version":"1.1.3","json_schema_version":1}},
      {"chain":{"family":"inet","table":"filter","name":"input","handle":1,
                "type":"filter","hook":"input","prio":0,"policy":"drop"}},
      {"chain":{"family":"inet","table":"filter","name":"helper","handle":2}},
      {"chain":{"family":"ip","table":"nat","name":"prerouting","handle":1,
                "type":"nat","hook":"prerouting","prio":-100,"policy":"accept"}}
    ]}"#;

    const CHAINS_NONE: &str = r#"{"nftables":[
      {"metainfo":{"version":"1.1.3","json_schema_version":1}},
      {"chain":{"family":"inet","table":"filter","name":"helper","handle":2}}
    ]}"#;

    const CHAINS_TWO_INPUTS: &str = r#"{"nftables":[
      {"metainfo":{"version":"1.1.3","json_schema_version":1}},
      {"chain":{"family":"inet","table":"filter","name":"input","handle":1,
                "type":"filter","hook":"input","prio":0,"policy":"drop"}},
      {"chain":{"family":"ip","table":"legacy","name":"INPUT","handle":1,
                "type":"filter","hook":"input","prio":0,"policy":"drop"}}
    ]}"#;

    fn request(port: u16, target: Target) -> OpenRequest {
        OpenRequest {
            port,
            protocol: Protocol::Tcp,
            target,
            lifetime: Lifetime::For(Duration::from_secs(300)),
        }
    }

    fn subnet() -> Target {
        Target::Network {
            cidr: "10.10.10.0/24".parse().unwrap(),
        }
    }

    #[test]
    fn a_regular_chain_is_never_mistaken_for_a_base_chain() {
        // A regular chain has no `hook` key at all. Reading `name == "input"`
        // instead of the hook would pick the wrong chain on any ruleset whose
        // author happened to name a plain chain "input" -- and porthole would
        // insert an accept somewhere nothing ever jumps to.
        let found = parse_input_chains(CHAINS_ONE_INPUT).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "input");
        assert_eq!(found[0].family, "inet");
        assert_eq!(found[0].policy.as_deref(), Some("drop"));
    }

    #[test]
    fn a_same_named_chain_at_a_different_hook_is_not_a_candidate() {
        // Both chains here are named "input" -- one really is registered at
        // the input hook, the other is a nat chain at prerouting that merely
        // shares the name. A version of this test that only checked `len()`
        // and the surviving chain's `name` (as an earlier draft of this test
        // did, against a fixture where the *other* chain was named
        // "prerouting") would pass even if the parser mistakenly kept both
        // chains under whichever name collided, or admitted the prerouting
        // chain under a different field. Pinning `table` as well as the
        // count is what actually proves discovery keyed on `hook`, not name.
        const CHAINS_ONE_INPUT_SAME_NAMED_OTHER_HOOK: &str = r#"{"nftables":[
          {"metainfo":{"version":"1.1.3","json_schema_version":1}},
          {"chain":{"family":"inet","table":"filter","name":"input","handle":1,
                    "type":"filter","hook":"input","prio":0,"policy":"drop"}},
          {"chain":{"family":"ip","table":"nat","name":"input","handle":1,
                    "type":"nat","hook":"prerouting","prio":-100,"policy":"accept"}}
        ]}"#;
        let found = parse_input_chains(CHAINS_ONE_INPUT_SAME_NAMED_OTHER_HOOK).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].table, "filter",
            "the same-named prerouting chain must not be counted"
        );
    }

    #[test]
    fn a_base_chain_at_the_input_hook_that_is_not_type_filter_is_not_a_candidate() {
        // nat has its own "input" hook -- used for locally-destined
        // DNAT/REDIRECT -- so `type nat hook input` is a real base chain
        // there, not a malformed fixture. It has nothing to do with whether
        // the packet is filtered. Keying on `hook` alone would count it as a
        // candidate and turn an openable system into a refusal.
        const CHAINS_NAT_AT_INPUT_HOOK: &str = r#"{"nftables":[
          {"metainfo":{"version":"1.1.3","json_schema_version":1}},
          {"chain":{"family":"ip","table":"nat","name":"redirect","handle":1,
                    "type":"nat","hook":"input","prio":100,"policy":"accept"}}
        ]}"#;
        let found = parse_input_chains(CHAINS_NAT_AT_INPUT_HOOK).unwrap();
        assert!(
            found.is_empty(),
            "a nat chain at the input hook filters nothing: {found:?}"
        );
    }

    #[test]
    fn a_bridge_family_filter_chain_at_the_input_hook_is_not_a_candidate() {
        // `man nft`: bridge family's filter priority applies to all hooks
        // including `input`, so this is a genuine `type filter hook input`
        // base chain -- the round-1 `type == "filter"` fix does not exclude
        // it, unlike the nat case above. It filters bridged traffic, not
        // whether a routed IPv4 packet is delivered locally; counting it as
        // a candidate would turn a normal machine that happens to have a
        // bridge into a spurious refusal. (arp family chains are the same
        // shape for the same reason -- arp supports only the input/output
        // hooks, both `type filter` -- and are excluded by the same family
        // check, so a second fixture for arp would exercise no new code
        // path.)
        const CHAINS_WITH_A_BRIDGE_INPUT_CHAIN: &str = r#"{"nftables":[
          {"metainfo":{"version":"1.1.3","json_schema_version":1}},
          {"chain":{"family":"inet","table":"filter","name":"input","handle":1,
                    "type":"filter","hook":"input","prio":0,"policy":"drop"}},
          {"chain":{"family":"bridge","table":"filter","name":"input","handle":1,
                    "type":"filter","hook":"input","prio":-200,"policy":"accept"}}
        ]}"#;
        let found = parse_input_chains(CHAINS_WITH_A_BRIDGE_INPUT_CHAIN).unwrap();
        assert_eq!(
            found.len(),
            1,
            "the bridge chain must not be counted as a candidate: {found:?}"
        );
        assert_eq!(found[0].family, "inet");
    }

    #[test]
    fn open_inserts_into_the_users_chain_not_a_table_of_our_own() {
        // The whole point. `insert` prepends, so the accept precedes any drop
        // already in the chain. `add` would append it after the drop, where it
        // is never reached.
        let runner = RecordingRunner::with_responses(vec![
            Output::stdout(CHAINS_ONE_INPUT),
            Output::empty(),
        ]);
        let handle = Nftables::new(&runner)
            .open(&request(5173, subnet()), "porthole:abc")
            .unwrap();

        let mutating: Vec<_> = runner
            .recorded()
            .iter()
            .filter(|c| c.effect == Effect::Mutate)
            .map(|c| c.display())
            .collect();
        assert_eq!(mutating.len(), 1);
        // The exact string, table and all, is the whole assertion: it pins
        // both "no table of porthole's own" (there is nothing here but
        // `insert rule` into the discovered chain) and "insert, not add" at
        // once, so a separate `!contains("add table")` check on top of it
        // would test nothing this equality doesn't already cover.
        //
        // The marker is wrapped in literal `"` characters -- see the comment
        // at the `args.push(format!("\"{marker}\""))` call site for why: an
        // unquoted `:` is a syntax error in nft's own argv grammar, and
        // `Command::display()`'s shell-quoting then wraps that whole token
        // in single quotes because it treats `"` as unsafe.
        assert_eq!(
            mutating[0],
            "nft insert rule inet filter input tcp dport 5173 \
             ip saddr 10.10.10.0/24 accept comment '\"porthole:abc\"'"
        );
        assert_eq!(
            handle,
            RuleHandle::Nftables {
                family: "inet".to_string(),
                table: "filter".to_string(),
                chain: "input".to_string(),
                marker: "porthole:abc".to_string(),
            }
        );
    }

    #[test]
    fn the_marker_argv_element_carries_literal_quote_characters() {
        // `RealRunner` spawns via `StdCommand::args`, with no shell in
        // between to add or strip quoting. `nft` re-lexes argv with its own
        // grammar, in which an unquoted token cannot contain a colon, and
        // the marker is always `porthole:<uuid>`. Verified against the real
        // binary, unprivileged, in check mode (nothing was modified):
        //
        //   $ nft -c insert rule inet filter input tcp dport 5173 accept \
        //         comment porthole:abc
        //   Error: syntax error, unexpected colon, ...
        //
        //   $ nft -c insert rule inet filter input tcp dport 5173 accept \
        //         comment '"porthole:abc"'
        //   netlink: Error: cache initialization failed: Operation not permitted
        //
        // The second one reaches netlink -- it parsed. A future reader must
        // not see the quotes in the argv element below as redundant noise
        // left over from `display()`'s shell-quoting and remove them: they
        // are literal characters this backend puts there on purpose.
        let runner = RecordingRunner::with_responses(vec![
            Output::stdout(CHAINS_ONE_INPUT),
            Output::empty(),
        ]);
        Nftables::new(&runner)
            .open(&request(5173, subnet()), "porthole:abc")
            .unwrap();
        let mutate = runner
            .recorded()
            .into_iter()
            .find(|c| c.effect == Effect::Mutate)
            .expect("open issues exactly one mutating command");
        assert_eq!(
            mutate.args.last(),
            Some(&"\"porthole:abc\"".to_string()),
            "the argv element itself must carry literal quote characters, \
             not just its shell-quoted display"
        );
    }

    #[test]
    fn open_targets_whatever_chain_discovery_found_not_a_hardcoded_name() {
        // Every fixture above happens to have its only base chain named
        // `inet filter input` -- exactly the string a hardcoding regression
        // would write, and the exact-string assertions above would not catch
        // it. A real iptables-nft system's chain is `ip filter INPUT`; if
        // `open_impl` ever stopped using what `discover_single_input_chain`
        // returned and hardcoded the common case instead, this is the
        // fixture that catches it.
        const CHAINS_IPTABLES_NFT_STYLE: &str = r#"{"nftables":[
          {"metainfo":{"version":"1.1.3","json_schema_version":1}},
          {"chain":{"family":"ip","table":"filter","name":"INPUT","handle":1,
                    "type":"filter","hook":"input","prio":0,"policy":"drop"}}
        ]}"#;
        let runner = RecordingRunner::with_responses(vec![
            Output::stdout(CHAINS_IPTABLES_NFT_STYLE),
            Output::empty(),
        ]);
        let handle = Nftables::new(&runner)
            .open(&request(5173, subnet()), "porthole:abc")
            .unwrap();

        let mutate = runner
            .recorded()
            .into_iter()
            .find(|c| c.effect == Effect::Mutate)
            .expect("open issues exactly one mutating command");
        assert_eq!(
            mutate.display(),
            "nft insert rule ip filter INPUT tcp dport 5173 \
             ip saddr 10.10.10.0/24 accept comment '\"porthole:abc\"'"
        );
        assert_eq!(
            handle,
            RuleHandle::Nftables {
                family: "ip".to_string(),
                table: "filter".to_string(),
                chain: "INPUT".to_string(),
                marker: "porthole:abc".to_string(),
            }
        );
    }

    #[test]
    fn anywhere_omits_the_source_match_entirely() {
        let runner = RecordingRunner::with_responses(vec![
            Output::stdout(CHAINS_ONE_INPUT),
            Output::empty(),
        ]);
        Nftables::new(&runner)
            .open(&request(5173, Target::Anywhere), "porthole:abc")
            .unwrap();
        let shown = runner.recorded()[1].display();
        assert!(!shown.contains("saddr"), "anywhere means no source match");
        assert!(shown.contains("tcp dport 5173"));
    }

    #[test]
    fn a_rule_open_writes_round_trips_through_list_rules_with_an_identical_handle() {
        // C1: reconciliation compares handles structurally, so whatever
        // `open` returns must be exactly what `list_rules` reconstructs for
        // the same rule, or a live rule looks stale the moment the next
        // sweep runs. ufw needed this fixed for real -- its own version of
        // this test is `ufw::tests::
        // a_host_scoped_open_round_trips_through_list_rules_despite_ufws_bare_slash_32`.
        // nftables' `RuleHandle` carries no address at all, only
        // family/table/chain/marker, so nothing here depends on how an
        // address is spelled; this is a belt-and-braces proof, not a
        // regression this backend was found to have.
        let open_runner = RecordingRunner::with_responses(vec![
            Output::stdout(CHAINS_ONE_INPUT),
            Output::empty(),
        ]);
        let host = Target::Network {
            cidr: "10.10.10.42/32".parse().unwrap(),
        };
        let opened = Nftables::new(&open_runner)
            .open(&request(5173, host), "porthole:host")
            .unwrap();

        const RULES_AFTER: &str = r#"{"nftables":[
            {"metainfo":{"version":"1.1.3","json_schema_version":1}},
            {"rule":{"family":"inet","table":"filter","chain":"input","handle":9,
                     "comment":"porthole:host",
                     "expr":[
                       {"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":5173}},
                       {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":"10.10.10.42"}},
                       {"accept":null}
                     ]}}
        ]}"#;
        let list_runner = RecordingRunner::with_responses(vec![
            Output::stdout(CHAINS_ONE_INPUT),
            Output::stdout(RULES_AFTER),
        ]);
        let listed = Nftables::new(&list_runner).list_rules().unwrap();

        assert_eq!(
            listed,
            vec![opened],
            "list_rules must reconstruct the identical handle open returned"
        );
    }

    #[test]
    fn no_input_chain_means_nothing_is_filtering_and_porthole_says_so() {
        // With no base chain at the input hook the port is already reachable.
        // Adding a rule would be theatre, and reporting success would tell the
        // user porthole had changed something it had not.
        let runner = RecordingRunner::with_responses(vec![Output::stdout(CHAINS_NONE)]);
        let err = Nftables::new(&runner)
            .open(&request(5173, subnet()), "porthole:abc")
            .unwrap_err();
        assert_eq!(err.exit_code(), ExitCode::BackendUnavailable);
        let text = err.to_string();
        assert!(
            text.contains("already reachable"),
            "the message must say the port is already reachable, got: {text}"
        );
        assert!(runner.recorded().iter().all(|c| c.effect == Effect::Read));
    }

    #[test]
    fn several_input_chains_is_a_refusal_not_a_guess() {
        // Inserting into one of two dropping chains is not provably enough:
        // the other one can still drop the packet. Reporting success there
        // would be a guess dressed as a fact.
        let runner = RecordingRunner::with_responses(vec![Output::stdout(CHAINS_TWO_INPUTS)]);
        let err = Nftables::new(&runner)
            .open(&request(5173, subnet()), "porthole:abc")
            .unwrap_err();
        assert_eq!(err.exit_code(), ExitCode::BackendUnavailable);
        let text = err.to_string();
        assert!(text.contains("inet filter input"), "name them: {text}");
        assert!(text.contains("ip legacy INPUT"), "name them: {text}");
        assert!(runner.recorded().iter().all(|c| c.effect == Effect::Read));
    }

    #[test]
    fn close_re_reads_the_handle_and_never_trusts_a_stored_one() {
        // Handles are kernel-assigned and are reassigned after a flush. A
        // handle stored at open time can, by close time, name a different
        // rule -- the user's.
        const CHAIN_WITH_RULES: &str = r#"{"nftables":[
          {"metainfo":{"version":"1.1.3","json_schema_version":1}},
          {"rule":{"family":"inet","table":"filter","chain":"input","handle":7,
                   "comment":"porthole:abc","expr":[]}},
          {"rule":{"family":"inet","table":"filter","chain":"input","handle":8,
                   "expr":[]}}
        ]}"#;
        let runner = RecordingRunner::with_responses(vec![
            Output::stdout(CHAIN_WITH_RULES),
            Output::empty(),
        ]);
        Nftables::new(&runner)
            .close(&RuleHandle::Nftables {
                family: "inet".to_string(),
                table: "filter".to_string(),
                chain: "input".to_string(),
                marker: "porthole:abc".to_string(),
            })
            .unwrap();
        let mutating: Vec<_> = runner
            .recorded()
            .iter()
            .filter(|c| c.effect == Effect::Mutate)
            .map(|c| c.display())
            .collect();
        assert_eq!(
            mutating,
            vec!["nft delete rule inet filter input handle 7"],
            "handle 7 is the marked rule; 8 is the user's"
        );
    }

    #[test]
    fn close_targets_whatever_chain_the_handle_names_not_a_hardcoded_one() {
        // Same concern as `open_targets_whatever_chain_discovery_found...`,
        // for the other direction: `close` has no discovery step of its own
        // -- it must act on exactly the family/table/chain the `RuleHandle`
        // carries. Every other close test happens to use `inet filter
        // input`; this one uses the differently-named, differently-cased
        // `ip filter INPUT` a real iptables-nft system would have, so a
        // hardcoded "inet"/"filter"/"input" anywhere in `close_impl` would
        // read and delete from the wrong place and this test would catch it.
        const CHAIN_WITH_RULES_IPTABLES_NFT_STYLE: &str = r#"{"nftables":[
          {"metainfo":{"version":"1.1.3","json_schema_version":1}},
          {"rule":{"family":"ip","table":"filter","chain":"INPUT","handle":7,
                   "comment":"porthole:abc","expr":[]}}
        ]}"#;
        let runner = RecordingRunner::with_responses(vec![
            Output::stdout(CHAIN_WITH_RULES_IPTABLES_NFT_STYLE),
            Output::empty(),
        ]);
        Nftables::new(&runner)
            .close(&RuleHandle::Nftables {
                family: "ip".to_string(),
                table: "filter".to_string(),
                chain: "INPUT".to_string(),
                marker: "porthole:abc".to_string(),
            })
            .unwrap();
        let mutating: Vec<_> = runner
            .recorded()
            .iter()
            .filter(|c| c.effect == Effect::Mutate)
            .map(|c| c.display())
            .collect();
        assert_eq!(mutating, vec!["nft delete rule ip filter INPUT handle 7"]);
    }

    #[test]
    fn closing_a_rule_whose_marker_is_gone_is_rule_not_found() {
        const CHAIN_EMPTY: &str = r#"{"nftables":[
          {"metainfo":{"version":"1.1.3","json_schema_version":1}}
        ]}"#;
        let runner = RecordingRunner::with_responses(vec![Output::stdout(CHAIN_EMPTY)]);
        let err = Nftables::new(&runner)
            .close(&RuleHandle::Nftables {
                family: "inet".to_string(),
                table: "filter".to_string(),
                chain: "input".to_string(),
                marker: "porthole:abc".to_string(),
            })
            .unwrap_err();
        assert_eq!(err.exit_code(), ExitCode::RuleNotFound);
        assert!(runner.recorded().iter().all(|c| c.effect == Effect::Read));
    }

    #[test]
    fn nftables_refuses_to_forward_and_runs_nothing_at_all() {
        // "Runs nothing at all" is the load-bearing half. A refusal that
        // first discovered a chain, or wrote a redirect and then gave up,
        // would leave the ruleset changed by a call that reports having
        // done nothing.
        //
        // The message is pinned because it is what a user is left with. It
        // says where the missing rule would have to go, not that porthole
        // cannot find a chain -- it can; the module docs carry why writing
        // there was not something this backend could stand behind.
        let runner = RecordingRunner::new();
        let err = Nftables::new(&runner)
            .forward(&request(3000, subnet()), &to(), "porthole:abc")
            .unwrap_err();

        assert_eq!(err.exit_code(), ExitCode::ForwardUnsupported);
        assert!(
            err.to_string().contains("nftables cannot redirect a port"),
            "got: {err}"
        );
        assert!(
            runner.recorded().is_empty(),
            "refusing must run no command at all, not even a read: {:#?}",
            runner.recorded()
        );
    }

    #[test]
    fn no_nat_chain_is_ever_written_to() {
        // The refusal above only pins that `forward` runs nothing. This
        // drives the two calls that do write -- `open`, then `forward` --
        // and asserts no command from either names a nat chain or a dnat.
        // `close` is not driven here; it deletes by the handle it is given
        // and builds no rule of its own.
        let runner = RecordingRunner::with_responses(vec![
            Output::stdout(CHAINS_ONE_INPUT),
            Output::empty(),
        ]);
        let backend = Nftables::new(&runner);
        backend
            .open(&request(5173, subnet()), "porthole:abc")
            .unwrap();
        let _ = backend.forward(&request(3000, subnet()), &to(), "porthole:abc");

        for cmd in runner.recorded() {
            let shown = cmd.display();
            assert!(!shown.contains("dnat"), "a dnat was issued: {shown}");
            assert!(
                !shown.contains("nat prerouting"),
                "a nat chain was named: {shown}"
            );
        }
    }

    fn to() -> ForwardTo {
        ForwardTo {
            container_addr: std::net::Ipv4Addr::new(172, 18, 0, 2),
            container_port: 8080,
            published_port: 3000,
            protocol: Protocol::Tcp,
        }
    }

    #[test]
    fn nothing_is_ever_written_to_disk() {
        // The invariant: nftables rules live in the running ruleset only.
        // `nft -f`, a redirect into /etc/nftables.conf, or `nft list ruleset >`
        // would all make a rule survive a reboot.
        let runner = RecordingRunner::with_responses(vec![
            Output::stdout(CHAINS_ONE_INPUT),
            Output::empty(),
        ]);
        Nftables::new(&runner)
            .open(&request(5173, subnet()), "porthole:abc")
            .unwrap();
        for cmd in runner.recorded() {
            let shown = cmd.display();
            assert!(!shown.contains("/etc/nftables"), "{shown}");
            assert!(!shown.contains(" -f "), "{shown}");
            assert!(!shown.contains('>'), "{shown}");
        }
    }

    #[test]
    fn owned_rules_recognises_a_subnet_saddr_match_captured_as_a_nested_prefix_object() {
        // The `right` value here -- `{"prefix":{"addr":"10.10.10.0","len":24}}`
        // -- is transcribed verbatim from a real `nft -j list chain`, inserting
        // exactly the rule `open_impl` emits for a subnet target and dumping
        // the result, not composed from the schema documentation. A subnet is
        // porthole's default scope, so this is the common case a rule with a
        // stray `is_string() || is_number()` check on this field silently
        // failed to recognise as its own.
        const CHAIN_WITH_A_SUBNET_SCOPED_RULE: &str = r#"{"nftables":[
          {"metainfo":{"version":"1.1.3","json_schema_version":1}},
          {"rule":{"family":"inet","table":"filter","chain":"input","handle":4,
                   "comment":"porthole:abc",
                   "expr":[
                     {"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":5173}},
                     {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":{"prefix":{"addr":"10.10.10.0","len":24}}}},
                     {"accept":null}
                   ]}}
        ]}"#;
        let runner = RecordingRunner::with_responses(vec![
            Output::stdout(CHAINS_ONE_INPUT),
            Output::stdout(CHAIN_WITH_A_SUBNET_SCOPED_RULE),
        ]);
        let owned = Nftables::new(&runner).owned_rules().unwrap().unwrap();
        assert_eq!(
            owned.len(),
            1,
            "a subnet-scoped rule -- porthole's default scope -- must be recognised as its own"
        );
    }

    #[test]
    fn owned_rules_recognises_a_host_saddr_match_captured_as_a_bare_string() {
        // The `right` value here -- the bare string `"10.10.10.42"`, with the
        // `/32` gone entirely -- is transcribed verbatim from a real `nft -j
        // list chain` dump of the rule `open_impl` emits for a single-host
        // target. nft does not distinguish a host address from a /32 prefix
        // in its JSON output, so a bare string here always means one.
        const CHAIN_WITH_A_HOST_SCOPED_RULE: &str = r#"{"nftables":[
          {"metainfo":{"version":"1.1.3","json_schema_version":1}},
          {"rule":{"family":"inet","table":"filter","chain":"input","handle":4,
                   "comment":"porthole:abc",
                   "expr":[
                     {"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":5173}},
                     {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":"10.10.10.42"}},
                     {"accept":null}
                   ]}}
        ]}"#;
        let runner = RecordingRunner::with_responses(vec![
            Output::stdout(CHAINS_ONE_INPUT),
            Output::stdout(CHAIN_WITH_A_HOST_SCOPED_RULE),
        ]);
        let owned = Nftables::new(&runner).owned_rules().unwrap().unwrap();
        assert_eq!(
            owned.len(),
            1,
            "a host-scoped rule (bare-string saddr) must be recognised as its own"
        );
    }

    #[test]
    fn owned_rules_recognises_an_anywhere_rule_with_no_saddr_match_at_all() {
        // Captured the same way: for `Target::Anywhere`, `open_impl` never
        // writes an `ip saddr` statement at all, so `expr` holds only the
        // dport match and the accept. Absence of a saddr match is a valid
        // shape, not a failed one, and must not be confused with the "extra
        // unexpected statement" case that disqualifies a rule of some other
        // shape.
        const CHAIN_WITH_AN_ANYWHERE_SCOPED_RULE: &str = r#"{"nftables":[
          {"metainfo":{"version":"1.1.3","json_schema_version":1}},
          {"rule":{"family":"inet","table":"filter","chain":"input","handle":4,
                   "comment":"porthole:abc",
                   "expr":[
                     {"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":5173}},
                     {"accept":null}
                   ]}}
        ]}"#;
        let runner = RecordingRunner::with_responses(vec![
            Output::stdout(CHAINS_ONE_INPUT),
            Output::stdout(CHAIN_WITH_AN_ANYWHERE_SCOPED_RULE),
        ]);
        let owned = Nftables::new(&runner).owned_rules().unwrap().unwrap();
        assert_eq!(
            owned.len(),
            1,
            "an anywhere-scoped rule (no saddr match at all) must be recognised as its own"
        );
    }

    #[test]
    fn owned_rules_requires_the_exact_shape_not_just_the_comment() {
        // Mirrors `Ufw::parse_status`'s own requirement: a `porthole:`
        // comment on a rule of any other shape is a hand-edited rule or a
        // marker collision, not something reconciliation may remove. This
        // rule matches the right port but also carries a `log` statement
        // `open_impl` never writes.
        const CHAIN_WITH_A_MARKED_BUT_WRONGLY_SHAPED_RULE: &str = r#"{"nftables":[
          {"metainfo":{"version":"1.1.3","json_schema_version":1}},
          {"rule":{"family":"inet","table":"filter","chain":"input","handle":9,
                   "comment":"porthole:evil",
                   "expr":[
                     {"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":5173}},
                     {"log":null},
                     {"accept":null}
                   ]}}
        ]}"#;
        let runner = RecordingRunner::with_responses(vec![
            Output::stdout(CHAINS_ONE_INPUT),
            Output::stdout(CHAIN_WITH_A_MARKED_BUT_WRONGLY_SHAPED_RULE),
        ]);
        let owned = Nftables::new(&runner).owned_rules().unwrap().unwrap();
        assert!(
            owned.is_empty(),
            "a `porthole:`-commented rule of the wrong shape must not be claimed: {owned:?}"
        );
    }

    #[test]
    fn owned_rules_refuses_the_same_ambiguity_open_refuses() {
        // `all_rules` (which backs the diagnostic `list_rules`) walks every
        // input-hook chain regardless of count. `owned_rules` must not: its
        // output is what task 5's orphan sweep deletes from, and `open`
        // already decided that a two-chain ruleset is not provably safe to
        // touch. A rule marked `porthole:` sitting in one of those chains is
        // equally unprovable -- it could be a leftover from before the
        // ruleset grew a second chain -- so `owned_rules` must refuse
        // exactly as `open` does, not guess which chain matters.
        let runner = RecordingRunner::with_responses(vec![Output::stdout(CHAINS_TWO_INPUTS)]);
        let err = Nftables::new(&runner).owned_rules().unwrap_err();
        assert_eq!(err.exit_code(), ExitCode::BackendUnavailable);
    }

    #[test]
    fn health_scopes_the_no_drop_claim_to_this_chain_only() {
        // A chain with `policy accept` and no rules of its own is exactly
        // how firewalld and ufw commonly implement enforcement: the actual
        // dropping happens in a chain this one jumps to, which this backend
        // does not follow. The message must say what was actually inspected
        // ("in this chain"), never a blanket "closing a port here does not
        // make it unreachable" -- that sentence is false on this very common
        // layout. This lives in `caveat`, not `detail` -- see `health()`'s
        // own comment on why a caveat true regardless of `active` gets its
        // own field rather than being appended to the prose `detail`.
        const CHAINS_ACCEPT_POLICY_SINGLE_INPUT: &str = r#"{"nftables":[
          {"metainfo":{"version":"1.1.3","json_schema_version":1}},
          {"chain":{"family":"inet","table":"filter","name":"input","handle":1,
                    "type":"filter","hook":"input","prio":0,"policy":"accept"}}
        ]}"#;
        const CHAIN_ACCEPT_POLICY_NO_RULES: &str = r#"{"nftables":[
          {"metainfo":{"version":"1.1.3","json_schema_version":1}}
        ]}"#;
        let runner = RecordingRunner::with_responses(vec![
            Output::stdout("nftables v1.1.3 (Commodore Bullmoose)"),
            Output::stdout(CHAINS_ACCEPT_POLICY_SINGLE_INPUT),
            Output::stdout(CHAIN_ACCEPT_POLICY_NO_RULES),
        ]);
        let health = Nftables::new(&runner).health().unwrap();
        assert!(health.active);
        let caveat = health
            .caveat
            .as_deref()
            .expect("an accepting chain with no drop of its own must carry a caveat");
        assert!(
            caveat.contains("in this chain"),
            "must scope the claim to what was actually inspected: {caveat}"
        );
        assert!(
            !caveat.contains("does not make it unreachable"),
            "must not promise unreachability outright -- a jump target may \
             still drop, and this backend does not follow jump/goto: {caveat}"
        );
    }

    #[test]
    fn a_permission_denied_chain_listing_is_still_available_not_an_error() {
        // C1: `nft --version` works unprivileged; `nft -j list chains`
        // refuses for a non-root caller ("Operation not permitted (you must
        // be root)", verified against the real binary). Before this fix,
        // `health()` propagated that failure with `?`, so `detect()` returned
        // `Err` for an ordinary user on a genuinely installed and possibly
        // enforcing nftables setup -- turning `status`, `doctor` and
        // `--dry-run` into hard failures on exactly the machines the README
        // promises they need no privilege on. `available` must come from
        // `--version` alone, and a permission failure on the second call must
        // degrade to `active: false` with an explanation, never propagate as
        // an `Err` that makes a running firewall look absent.
        let runner = RecordingRunner::with_responses(vec![
            Output::stdout("nftables v1.1.6 (Old Doc Yak)"),
            Output {
                status: 1,
                stdout: String::new(),
                stderr: "Error: Operation not permitted (you must be root)".to_string(),
            },
        ]);
        let health = Nftables::new(&runner).health().unwrap();
        assert!(
            health.available,
            "the binary is there; that must stand alone"
        );
        assert!(
            !health.active,
            "porthole cannot claim it is enforcing anything it could not read"
        );
        assert!(
            health.active_unknown,
            "this is the unknown case, not a confirmed-empty-input-hook one -- doctor's \
             remedy selection depends on telling the two apart"
        );
        assert!(
            health.detail.contains("root") || health.detail.contains("privilege"),
            "the detail must say the answer needs privilege, not that nothing is \
             registered at the input hook: {}",
            health.detail
        );
        assert!(
            health.caveat.is_none(),
            "there is nothing to scope a caveat to when the chain could not even be read"
        );
    }
}
