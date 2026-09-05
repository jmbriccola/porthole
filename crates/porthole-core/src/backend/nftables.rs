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

use super::{BackendHealth, BackendId, FirewallBackend, Ownership, RuleHandle};
use crate::command::{Command, CommandRunner};
use crate::error::{Error, Result};
use crate::model::{OpenRequest, Target};
use serde::Deserialize;

/// A base chain registered at the input hook — the only place an inserted
/// accept can be reached.
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

/// Parse `nft -j list chains`, returning only chains registered at the input
/// hook.
fn parse_input_chains(json: &str) -> Result<Vec<InputChain>> {
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
        if chain.hook.as_deref() == Some("input") {
            chains.push(InputChain {
                family: chain.family,
                table: chain.table,
                name: chain.name,
                policy: chain.policy,
            });
        }
    }
    Ok(chains)
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
fn find_rule_handle(json: &str, marker: &str) -> Result<Option<u64>> {
    Ok(parse_rules(json)?
        .into_iter()
        .find(|rule| rule.comment.as_deref() == Some(marker))
        .map(|rule| rule.handle))
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
    /// the chain it came from. Diagnostic: unlike `open`, a chain count other
    /// than one is not refused here, because listing what exists must not
    /// itself require the same proof that mutating it does.
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

    fn chain_has_a_drop_or_reject(&self, chain: &InputChain) -> Result<bool> {
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
        args.push(marker.to_string());

        // `insert`, not `add`: `add` appends after the user's drop, where the
        // rule is never reached. This is the entire point of this backend.
        let cmd = Command::mutate("nft", args);
        self.runner.run(&cmd)?.into_ok(&cmd)?;

        Ok(RuleHandle::Nftables {
            family: chain.family,
            table: chain.table,
            chain: chain.name,
            marker: marker.to_string(),
        })
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

    fn close(&self, handle: &RuleHandle) -> Result<()> {
        let RuleHandle::Nftables {
            family,
            table,
            chain,
            marker,
        } = handle
        else {
            return Err(Error::Unexpected(format!(
                "the nftables backend was handed a {handle:?}"
            )));
        };
        self.close_impl(family, table, chain, marker)
    }

    fn list_rules(&self) -> Result<Vec<RuleHandle>> {
        Ok(self
            .all_rules()?
            .into_iter()
            .map(|(chain, rule)| RuleHandle::Nftables {
                family: chain.family,
                table: chain.table,
                chain: chain.name,
                marker: rule.comment.unwrap_or_default(),
            })
            .collect())
    }

    fn owned_rules(&self) -> Result<Option<Vec<RuleHandle>>> {
        Ok(Some(
            self.all_rules()?
                .into_iter()
                .filter(|(_, rule)| {
                    rule.comment
                        .as_deref()
                        .is_some_and(|c| c.starts_with("porthole:"))
                })
                .map(|(chain, rule)| RuleHandle::Nftables {
                    family: chain.family,
                    table: chain.table,
                    chain: chain.name,
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
            Ok(_) => None,
            Err(Error::CommandSpawn { .. }) => {
                return Ok(BackendHealth {
                    available: false,
                    active: false,
                    version: None,
                    detail: "nft is not installed".to_string(),
                })
            }
            Err(other) => return Err(other),
        };

        let chains = self.list_chains()?;
        let (active, mut detail) = match chains.as_slice() {
            [] => (
                false,
                "no nftables chain is registered at the input hook, so nothing is filtering \
                 incoming traffic and the port is already reachable"
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
                        "more than one nftables chain is registered at the input hook ({}); \
                         porthole cannot tell which one decides a packet's fate",
                        names.join(", ")
                    ),
                )
            }
        };

        // The direction that misleads: a chain whose policy is accept and
        // holds no drop or reject is not enforcing anything, so closing a
        // port there does not make it unreachable. Say that out loud rather
        // than let a user infer the opposite from `active: true`.
        if let [chain] = chains.as_slice() {
            if chain.policy.as_deref() == Some("accept")
                && !self.chain_has_a_drop_or_reject(chain)?
            {
                detail.push_str(
                    "; its policy is accept and it holds no drop or reject rule, so closing a \
                     port here does not make it unreachable",
                );
            }
        }

        Ok(BackendHealth {
            available: true,
            active,
            version,
            detail,
        })
    }

    fn location(&self) -> Result<Option<String>> {
        match self.discover_single_input_chain() {
            Ok(chain) => Ok(Some(chain.to_string())),
            Err(_) => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::{CommandRunner, Effect, Output, RecordingRunner};
    use crate::error::ExitCode;
    use crate::model::{Lifetime, Protocol, Target};
    use std::time::Duration;

    /// Captured from `nft -j list chains`. One base chain at the input hook,
    /// one regular chain that must not be mistaken for one, and a nat chain at
    /// a different hook.
    const CHAINS_ONE_INPUT: &str = r#"{"nftables":[
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
    fn chains_at_other_hooks_are_not_candidates() {
        // The nat prerouting chain in the fixture is a base chain, but nothing
        // arriving for a local port is filtered by it.
        let found = parse_input_chains(CHAINS_ONE_INPUT).unwrap();
        assert!(found.iter().all(|c| c.name != "prerouting"));
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
        assert_eq!(
            mutating[0],
            "nft insert rule inet filter input tcp dport 5173 \
             ip saddr 10.10.10.0/24 accept comment porthole:abc"
        );
        assert!(
            !mutating[0].contains("add table"),
            "porthole must not create a table of its own: an accept there \
             does not override the user's drop"
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
}
