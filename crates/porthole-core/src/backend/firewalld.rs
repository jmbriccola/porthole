//! The firewalld backend.
//!
//! Every rule is a **runtime** rich rule: never `--permanent`. firewalld drops
//! runtime rules on reboot and on `firewall-cmd --reload`, which is exactly the
//! semantics porthole wants.
//!
//! Two firewalld details shape this code.
//!
//! **Rich rules cannot carry a comment.** `firewalld.richlanguage(5)` has no
//! comment element, so porthole cannot mark its rules the way it will mark ufw
//! and nftables rules. Instead, `open` captures the rule string *as firewalld
//! normalised it* by diffing `--list-rich-rules` before and after the add, and
//! stores that in the [`RuleHandle`]. That string is both the removal spec and
//! the identity.
//!
//! **firewalld has its own `--timeout` and porthole does not use it.** It would
//! expire a rich rule with no systemd unit involved, but it exists only on
//! firewalld — ufw has no equivalent — and mixing it with porthole's own timer
//! would race: firewalld would drop the rule and the later `close` would fail.
//! Expiry stays uniform across backends, in `crate::expiry`.

use super::{BackendHealth, BackendId, FirewallBackend, Ownership, RuleHandle};
use crate::command::{Command, CommandRunner, Output};
use crate::error::{Error, Result};
use crate::forward::ForwardTo;
use crate::model::{OpenRequest, Protocol, Target};
use crate::net;

/// `firewall-cmd`'s exit for "firewalld is not running" -- `NOT_RUNNING` in
/// firewalld's own `firewall/errors.py`, the same value in 2.1.1 (Ubuntu
/// 24.04) and 2.4.4 (Fedora 44). The one exit of `--state` that confirms the
/// daemon is stopped.
const NOT_RUNNING: i32 = 252;

/// `NOT_AUTHORIZED`, same file: firewalld refused to answer the caller.
const NOT_AUTHORIZED: i32 = 253;

pub struct Firewalld<'a> {
    runner: &'a dyn CommandRunner,
}

impl<'a> Firewalld<'a> {
    pub fn new(runner: &'a dyn CommandRunner) -> Self {
        Firewalld { runner }
    }

    /// The zone porthole manages: the one bound to the interface carrying the
    /// default route, falling back to the default zone.
    pub fn managed_zone(&self) -> Result<String> {
        let interface = net::default_route_interface(self.runner)?;
        let cmd = Command::read(
            "firewall-cmd",
            [format!("--get-zone-of-interface={interface}")],
        );
        let out = self.runner.run(&cmd)?;
        if out.success() && !out.stdout.trim().is_empty() {
            return Ok(out.stdout.trim().to_string());
        }

        let cmd = Command::read("firewall-cmd", ["--get-default-zone"]);
        let out = self.runner.run(&cmd)?.into_ok(&cmd)?;
        let zone = out.stdout.trim();
        if zone.is_empty() {
            return Err(Error::Unexpected(
                "firewalld reported no default zone".to_string(),
            ));
        }
        Ok(zone.to_string())
    }

    /// The rich rule for a request. Deterministic: same request, same string.
    pub fn rich_rule(req: &OpenRequest) -> String {
        // family="ipv4" is explicit because porthole v1 does not manage IPv6,
        // and an unqualified rich rule would be added for both families.
        match req.target {
            Target::Network { cidr } => format!(
                r#"rule family="ipv4" source address="{cidr}" port port="{port}" protocol="{proto}" accept"#,
                port = req.port,
                proto = req.protocol,
            ),
            Target::Anywhere => format!(
                r#"rule family="ipv4" port port="{port}" protocol="{proto}" accept"#,
                port = req.port,
                proto = req.protocol,
            ),
        }
    }

    /// The rich rule for a forward's redirect half. Deterministic, like
    /// [`Firewalld::rich_rule`].
    ///
    /// firewalld's rich language spells a redirect as `forward-port`, and a
    /// `forward-port` rule takes the same `source address` element an accept
    /// rule does — so unlike the zone-wide `--add-forward-port` option, this
    /// scopes the redirect itself to `req.target`.
    ///
    /// `port` is the external port, what the local network connects to.
    /// `to-addr` is the container's own address on Docker's network.
    /// Loopback cannot stand there: a redirect to `127.0.0.0/8` is only
    /// delivered when `route_localnet` is set, and porthole changes no
    /// sysctl.
    pub fn forward_rich_rule(req: &OpenRequest, to: &ForwardTo, protocol: Protocol) -> String {
        let redirect = format!(
            r#"forward-port port="{port}" protocol="{protocol}" to-port="{to_port}" to-addr="{to_addr}""#,
            port = req.port,
            to_port = to.container_port,
            to_addr = to.container_addr,
        );
        match req.target {
            Target::Network { cidr } => {
                format!(r#"rule family="ipv4" source address="{cidr}" {redirect}"#)
            }
            Target::Anywhere => format!(r#"rule family="ipv4" {redirect}"#),
        }
    }

    /// Add one rich rule to `zone` and return the handle that removes it.
    ///
    /// `port` and `protocol` are the clauses the read-back matches on, not
    /// necessarily anything about the rule's effect: both an accept rule and
    /// a `forward-port` rule name the external port and the protocol that
    /// way, which is what lets one read-back serve `open` and `forward`
    /// alike.
    fn add_rich_rule(
        &self,
        zone: String,
        rule: &str,
        port: u16,
        protocol: Protocol,
    ) -> Result<RuleHandle> {
        let before = self.list_rich_rules(&zone)?;

        let add = Command::mutate(
            "firewall-cmd",
            [format!("--zone={zone}"), format!("--add-rich-rule={rule}")],
        );
        self.runner.run(&add)?.into_ok(&add)?;

        if self.runner.is_dry_run() {
            // Nothing was added, so there is nothing to read back. Return the
            // rule as constructed; a dry run is not going to remove it anyway.
            return Ok(RuleHandle::Firewalld {
                zone,
                rich_rule: rule.to_string(),
            });
        }

        let after = self.list_rich_rules(&zone)?;
        // Only a line mentioning this port and protocol can be the rule we just
        // asked for. Without this, a rule another process added in the same
        // window would be adopted — and porthole would then schedule a timer to
        // delete a rule it did not create.
        let port_clause = format!(r#"port="{port}""#);
        let proto_clause = format!(r#"protocol="{protocol}""#);
        let added: Vec<&String> = after
            .iter()
            .filter(|r| !before.contains(r))
            .filter(|r| r.contains(&port_clause) && r.contains(&proto_clause))
            .collect();

        match added.as_slice() {
            [one] => Ok(RuleHandle::Firewalld {
                zone,
                rich_rule: (*one).clone(),
            }),
            // Reachable because firewall-cmd downgrades ALREADY_ENABLED to exit 0
            // for a single-item invocation, so the add above succeeds and simply
            // adds no new line. Verified in firewall/command.py, __cmd_sequence.
            [] => Err(Error::AlreadyOpen {
                port,
                protocol,
                detail: format!("an identical rich rule already exists in zone {zone}"),
            }),
            _ => Err(Error::Unexpected(format!(
                "zone {zone} gained {} rich rules while porthole added one; \
                 something else is changing the firewall at the same time",
                added.len()
            ))),
        }
    }

    /// Remove one rich rule from `zone`, treating an already-absent rule as
    /// the desired end state.
    fn remove_rich_rule(&self, zone: &str, rich_rule: &str) -> Result<()> {
        let cmd = Command::mutate(
            "firewall-cmd",
            [
                format!("--zone={zone}"),
                format!("--remove-rich-rule={rich_rule}"),
            ],
        );
        let out = self.runner.run(&cmd)?;
        if out.success() || is_already_absent(&out) {
            Ok(())
        } else {
            Err(Error::CommandFailed {
                command: cmd.display(),
                status: out.status,
                stderr: out.stderr.trim().to_string(),
            })
        }
    }

    fn list_rich_rules(&self, zone: &str) -> Result<Vec<String>> {
        let cmd = Command::read(
            "firewall-cmd",
            [format!("--zone={zone}"), "--list-rich-rules".into()],
        );
        let out = self.runner.run(&cmd)?.into_ok(&cmd)?;
        Ok(out
            .stdout
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_string)
            .collect())
    }
}

impl FirewallBackend for Firewalld<'_> {
    fn id(&self) -> BackendId {
        BackendId::Firewalld
    }

    fn open(&self, req: &OpenRequest, _marker: &str) -> Result<RuleHandle> {
        // Rich rules have no comment element, so there is nowhere to put the
        // marker; this is exactly why `ownership()` reports `Unprovable`.
        let zone = self.managed_zone()?;
        let rule = Self::rich_rule(req);
        self.add_rich_rule(zone, &rule, req.port, req.protocol)
    }

    /// The one backend that can redirect. What it writes is a rich rule;
    /// [`Firewalld::forward`] below is what writes it, and carries the
    /// measurement that decided there is exactly one.
    fn forward_capability(&self) -> Result<()> {
        Ok(())
    }

    /// One rich rule: the `forward-port` redirect.
    ///
    /// Measured on firewalld 2.4.4 in a container, against a real Docker
    /// 29.8.0 container published on loopback and a client in its own
    /// network namespace, with counter-only rules at the input and forward
    /// hooks:
    ///
    /// - With the redirect in the zone, the client's connection completed
    ///   and **zero** packets were counted at the input hook. The SYN
    ///   arrived at the forward hook already carrying `ct status dnat`, and
    ///   `filter_FORWARD`'s second rule is `ct status dnat accept`, ahead of
    ///   the jump to any zone chain. Setting the zone's target to `DROP` did
    ///   not stop it.
    /// - Adding an accept for the external port beside the redirect changed
    ///   nothing: the two arrangements were byte-for-byte identical in every
    ///   counter.
    /// - That accept on its own, with a service of the host's own bound to
    ///   `0.0.0.0` on the external port, let a client on the local network
    ///   reach *that* service. It is a working accept for something else.
    ///
    /// So a forward here is one rule, and its handle is the ordinary
    /// firewalld handle for it. Nothing porthole writes permits the
    /// forwarded traffic; what does was measured to be already there, and
    /// is not porthole's to write.
    ///
    /// **What the container suite reproduces, and what it does not.**
    /// `the_lan_reaches_the_container_through_the_forward_hook_and_only_on_the_port_it_was_given`
    /// counts **zero packets addressed to the external port** at the input
    /// hook while the forward hook carries the connection. That is the first
    /// bullet above, on this same design rather than on the throwaway one it
    /// was first measured against, and it is the half that matters for
    /// whether an accept in a zone's input chain could be carrying anything.
    ///
    /// The second and third bullets rest on that first measurement alone.
    /// Nothing committed compares packet counters with and without the
    /// accept, and nothing committed binds a host service to `0.0.0.0` to
    /// show the accept exposing it. One committed test does write an accept
    /// beside a
    /// redirect — `a_redirect_rich_rule_renders_to_a_dnat_and_no_filter_rule`
    /// adds it as the control that makes its first assertion mean something —
    /// but it sends no packet and nothing listens behind that port, so it
    /// shows where the accept lands in the ruleset, not what it exposes.
    /// What keeps that accept from coming back is the unit test
    /// `a_forward_writes_no_accept_for_the_external_port` below, which
    /// asserts it is absent from every command a forward issues.
    fn forward(&self, req: &OpenRequest, to: &ForwardTo, _marker: &str) -> Result<RuleHandle> {
        // The marker goes nowhere, for the same reason `open` drops it: the
        // rich language has no comment element. The stored rule string is
        // the identity, and `ownership()` reports `Unprovable`.
        let protocol = super::forward_protocol(req, to)?;
        let zone = self.managed_zone()?;
        self.add_rich_rule(
            zone,
            &Self::forward_rich_rule(req, to, protocol),
            req.port,
            protocol,
        )
    }

    fn close(&self, handle: &RuleHandle) -> Result<()> {
        match handle {
            RuleHandle::Firewalld { zone, rich_rule } => self.remove_rich_rule(zone, rich_rule),
            // A caller bug, not a firewall state: the engine only ever hands a
            // backend the handle it itself produced. Enumerated rather than a
            // wildcard so the next variant this enum gains breaks the build
            // here instead of being silently absorbed.
            other @ (RuleHandle::Ufw { .. } | RuleHandle::Nftables { .. }) => {
                Err(Error::Unexpected(format!(
                    "firewalld cannot close a handle from another backend: {other:?}"
                )))
            }
        }
    }

    /// Every rich rule in the managed zone.
    ///
    /// firewalld gives porthole no way to tell its own rules apart from a
    /// user's, so this returns all of them and the caller intersects with the
    /// state file. See the module docs.
    fn list_rules(&self) -> Result<Vec<RuleHandle>> {
        let zone = self.managed_zone()?;
        Ok(self
            .list_rich_rules(&zone)?
            .into_iter()
            .map(|rich_rule| RuleHandle::Firewalld {
                zone: zone.clone(),
                rich_rule,
            })
            .collect())
    }

    fn owned_rules(&self) -> Result<Option<Vec<RuleHandle>>> {
        // firewalld rich rules carry no marker; see `Ownership::Unprovable`.
        Ok(None)
    }

    fn ownership(&self) -> Ownership {
        Ownership::Unprovable
    }

    fn health(&self) -> Result<BackendHealth> {
        let version_cmd = Command::read("firewall-cmd", ["--version"]);
        let version = match self.runner.run(&version_cmd) {
            Ok(out) if out.success() => Some(out.stdout.trim().to_string()),
            Err(Error::CommandSpawn { .. }) => {
                return Ok(BackendHealth {
                    available: false,
                    active: false,
                    active_unknown: false,
                    version: None,
                    detail: "firewalld is not installed".to_string(),
                    caveat: None,
                })
            }
            // Anything else is not proof the binary is absent -- only
            // `CommandSpawn` is, and that already returned above. A non-zero
            // exit is real and common: firewall-cmd connects to the daemon
            // before it gets to `--version`, so where firewalld refuses an
            // unprivileged caller it refuses `--version` too (exit 253,
            // measured). Any other runner error cannot come from
            // `RealRunner`, but `CommandRunner` is a trait. Either way this
            // one read did not answer, which says nothing about whether
            // firewalld is installed: fall through with no version known and
            // let `--state` decide `available`/`active` on its own evidence.
            Ok(_) | Err(_) => None,
        };

        // Only one answer from `firewall-cmd --state` confirms that firewalld
        // is stopped: exit 252, its own NOT_RUNNING. Every other non-zero exit
        // is a read that did not answer, and degrades to "could not confirm"
        // rather than being taken for the daemon's reply. The common one is
        // 253, NOT_AUTHORIZED. Measured on ubuntu:24.04 under systemd, with
        // firewalld active and holding its default zone and polkit running: a
        // non-root `--state` exits 253, root's exits 0 -- and reading that 253
        // as "stopped" had `doctor` tell an ordinary user that nothing was
        // being enforced, and `open --dry-run` refuse on the same premise. A
        // failure to run the command at all (a resource-level `CommandSpawn`:
        // EAGAIN, ENOMEM, EMFILE, or the binary swapped mid-upgrade between
        // this call and the one above) degrades the same way. None of these
        // propagates: an installed firewalld this process could not currently
        // ask is not the same fact as "no firewall found" once this reaches
        // `detect`.
        let state_cmd = Command::read("firewall-cmd", ["--state"]);
        let (active, active_unknown, detail) = match self.runner.run(&state_cmd) {
            Ok(state) if state.success() && state.stdout.trim() == "running" => {
                let detail = match &version {
                    Some(v) => format!("firewalld {v} is running"),
                    None => "firewalld is running".to_string(),
                };
                (true, false, detail)
            }
            Ok(state) if state.status == NOT_RUNNING => (
                false,
                false,
                "firewalld is installed but not running, so no rule it holds is being \
                 enforced"
                    .to_string(),
            ),
            Ok(state) => {
                let said = if state.status == NOT_AUTHORIZED {
                    "NOT_AUTHORIZED: firewalld refused to answer this process".to_string()
                } else {
                    [state.stderr.trim(), state.stdout.trim()]
                        .into_iter()
                        .find(|s| !s.is_empty())
                        .and_then(|s| s.lines().next())
                        .unwrap_or("no output")
                        .to_string()
                };
                (
                    false,
                    true,
                    format!(
                        "firewalld is installed, but `firewall-cmd --state` exited {} ({said}) \
                         -- that is not the same as firewalld being stopped, it may already be \
                         running and enforcing rules porthole could not confirm just now",
                        state.status
                    ),
                )
            }
            Err(e) => (
                false,
                true,
                format!(
                    "firewalld is installed, but checking whether it is running failed ({e}) \
                     -- that is not the same as firewalld being stopped, it may already be \
                     running and enforcing rules porthole could not confirm just now"
                ),
            ),
        };

        Ok(BackendHealth {
            available: true,
            active,
            active_unknown,
            version,
            detail,
            caveat: None,
        })
    }

    fn location(&self) -> Result<Option<String>> {
        self.managed_zone().map(Some)
    }
}

/// firewalld's way of saying "that rule is not there".
fn is_already_absent(out: &Output) -> bool {
    out.stderr.contains("NOT_ENABLED")
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::command::{Effect, Output, RecordingRunner};
    use crate::error::Error;
    use crate::model::{Lifetime, Protocol, Target};
    use std::time::Duration;

    // Reused by `backend::tests` — the ownership seam's tests need a backend
    // that has actually gone through a real firewalld exchange, and retyping
    // these fixtures would risk them drifting apart.
    pub(crate) const ROUTE_JSON: &str = r#"[{"dst":"default","dev":"wlo1","metric":600}]"#;
    pub(crate) const ZONE: &str = "FedoraWorkstation";

    pub(crate) const SUBNET_RULE: &str = r#"rule family="ipv4" source address="10.10.10.0/24" port port="5173" protocol="tcp" accept"#;
    const ANY_RULE: &str = r#"rule family="ipv4" port port="5173" protocol="tcp" accept"#;

    fn subnet_request() -> OpenRequest {
        OpenRequest {
            port: 5173,
            protocol: Protocol::Tcp,
            target: Target::Network {
                cidr: "10.10.10.0/24".parse().unwrap(),
            },
            lifetime: Lifetime::For(Duration::from_secs(3600)),
        }
    }

    fn anywhere_request() -> OpenRequest {
        OpenRequest {
            target: Target::Anywhere,
            ..subnet_request()
        }
    }

    /// Scripted responses for a successful `open`, in the order the backend
    /// asks for them.
    fn open_script(before: &str, after: &str) -> Vec<Output> {
        vec![
            Output::stdout(ROUTE_JSON), // ip -j route show default
            Output::stdout(ZONE),       // firewall-cmd --get-zone-of-interface=wlo1
            Output::stdout(before),     // --list-rich-rules, before
            Output::stdout("success"),  // --add-rich-rule
            Output::stdout(after),      // --list-rich-rules, after
        ]
    }

    #[test]
    fn builds_a_source_scoped_rich_rule() {
        assert_eq!(Firewalld::rich_rule(&subnet_request()), SUBNET_RULE);
    }

    #[test]
    fn builds_an_unscoped_rich_rule_for_anywhere() {
        assert_eq!(Firewalld::rich_rule(&anywhere_request()), ANY_RULE);
    }

    #[test]
    fn open_adds_the_rule_to_the_zone_of_the_default_route_interface() {
        let runner = RecordingRunner::with_responses(open_script("", SUBNET_RULE));
        let handle = Firewalld::new(&runner)
            .open(&subnet_request(), "porthole:test")
            .unwrap();

        assert_eq!(
            handle,
            RuleHandle::Firewalld {
                zone: ZONE.to_string(),
                rich_rule: SUBNET_RULE.to_string(),
            }
        );

        let commands = runner.recorded();
        assert_eq!(commands[0].display(), "ip -j route show default");
        assert_eq!(
            commands[1].display(),
            "firewall-cmd --get-zone-of-interface=wlo1"
        );
        assert_eq!(
            commands[3].display(),
            format!("firewall-cmd --zone={ZONE} '--add-rich-rule={SUBNET_RULE}'")
        );
        assert_eq!(commands[3].effect, Effect::Mutate);
    }

    #[test]
    fn open_stores_the_string_firewalld_normalised_not_the_one_we_sent() {
        // firewalld may spell a rule differently from the way porthole builds it,
        // and --remove-rich-rule needs firewalld's spelling. This fixture is
        // deliberately NOT the string `rich_rule` constructs: if it were, the
        // assertion would hold even when `open` wrongly returned its own string,
        // and the test would prove nothing about the behaviour it is named for.
        let normalised = r#"rule family="ipv4" source address="10.10.10.0/24" port protocol="tcp" port="5173" accept"#;
        assert_ne!(
            normalised,
            Firewalld::rich_rule(&subnet_request()),
            "this fixture must differ from the constructed rule, or the test is vacuous"
        );

        let runner = RecordingRunner::with_responses(open_script("", normalised));
        let handle = Firewalld::new(&runner)
            .open(&subnet_request(), "porthole:test")
            .unwrap();

        let RuleHandle::Firewalld { rich_rule, .. } = handle else {
            panic!("firewalld always returns a Firewalld handle: {handle:?}");
        };
        assert_eq!(rich_rule, normalised);
    }

    #[test]
    fn open_never_writes_a_permanent_rule() {
        let runner = RecordingRunner::with_responses(open_script("", SUBNET_RULE));
        Firewalld::new(&runner)
            .open(&subnet_request(), "porthole:test")
            .unwrap();
        for cmd in runner.recorded() {
            assert!(
                !cmd.args.iter().any(|a| a.contains("--permanent")),
                "porthole must never write a permanent rule: {}",
                cmd.display()
            );
        }
    }

    #[test]
    fn open_ignores_an_unrelated_rule_added_by_someone_else_in_the_same_window() {
        // If another process adds an unrelated rich rule in the window between
        // porthole's own add and its read-back, an unfiltered before/after diff
        // would see two new lines and either error out or — worse, when
        // porthole's own add is a no-op because its rule already exists —
        // adopt the stranger's rule as if it were porthole's own, then
        // schedule a timer to delete a rule porthole never created.
        let other_rule = r#"rule family="ipv4" port port="9999" protocol="tcp" accept"#;
        let after = format!("{SUBNET_RULE}\n{other_rule}");
        let runner = RecordingRunner::with_responses(open_script("", &after));
        let handle = Firewalld::new(&runner)
            .open(&subnet_request(), "porthole:test")
            .unwrap();

        assert_eq!(
            handle,
            RuleHandle::Firewalld {
                zone: ZONE.to_string(),
                rich_rule: SUBNET_RULE.to_string(),
            }
        );
    }

    #[test]
    fn open_reports_already_open_when_no_new_rule_appeared() {
        let runner = RecordingRunner::with_responses(open_script(SUBNET_RULE, SUBNET_RULE));
        let err = Firewalld::new(&runner)
            .open(&subnet_request(), "porthole:test")
            .unwrap_err();
        assert!(
            matches!(err, Error::AlreadyOpen { port: 5173, .. }),
            "got: {err}"
        );
    }

    #[test]
    fn open_skips_the_read_back_under_dry_run() {
        use crate::command::DryRunRunner;
        // Under dry-run the add never happens, so a before/after diff would be
        // empty and would be misread as "already open".
        let inner = RecordingRunner::with_responses(vec![
            Output::stdout(ROUTE_JSON),
            Output::stdout(ZONE),
            Output::stdout(""),
        ]);
        let runner = DryRunRunner::new(Box::new(inner));
        let handle = Firewalld::new(&runner)
            .open(&subnet_request(), "porthole:test")
            .unwrap();
        assert_eq!(
            handle,
            RuleHandle::Firewalld {
                zone: ZONE.to_string(),
                rich_rule: SUBNET_RULE.to_string(),
            }
        );
        assert_eq!(runner.recorded().len(), 1, "one withheld mutation");
    }

    // --- forward -------------------------------------------------------

    /// Captured verbatim from firewalld 2.4.4 in a container: this is the
    /// string `--list-rich-rules` prints back after adding the rule
    /// `forward` builds, byte for byte. If `forward_rich_rule` ever stops
    /// producing it, firewalld is being asked for something other than what
    /// was measured.
    pub(crate) const FORWARD_REDIRECT: &str = r#"rule family="ipv4" source address="10.10.10.0/24" forward-port port="3000" protocol="tcp" to-port="8080" to-addr="172.18.0.2""#;

    /// The accept a forward must **not** write, spelled as firewalld would
    /// print it back. It is exactly what `open` writes for the same request
    /// -- `a_forward_writes_no_accept_for_the_external_port` asserts that
    /// equality rather than trusting this literal -- and adding it beside
    /// the redirect was measured to carry none of the forwarded traffic
    /// while exposing a host service on the external port to the local
    /// network.
    const THE_ACCEPT_A_FORWARD_MUST_NOT_WRITE: &str = r#"rule family="ipv4" source address="10.10.10.0/24" port port="3000" protocol="tcp" accept"#;

    fn forward_request() -> OpenRequest {
        OpenRequest {
            port: 3000,
            ..subnet_request()
        }
    }

    fn forward_to() -> ForwardTo {
        ForwardTo {
            container_addr: std::net::Ipv4Addr::new(172, 18, 0, 2),
            container_port: 8080,
            published_port: 3000,
            protocol: Protocol::Tcp,
        }
    }

    /// Scripted responses for a successful `forward`: the zone lookup, then
    /// one add-and-read-back.
    fn forward_script() -> Vec<Output> {
        vec![
            Output::stdout(ROUTE_JSON),
            Output::stdout(ZONE),
            Output::stdout(""),               // --list-rich-rules, before
            Output::stdout("success"),        // --add-rich-rule
            Output::stdout(FORWARD_REDIRECT), // after
        ]
    }

    /// `porthole forward 3000 --as 4000`: the local network connects to
    /// **4000** and Docker published **3000**. Every other fixture in this
    /// file has the two equal, which is the one arrangement in which a
    /// confusion between them is invisible.
    ///
    /// Three numbers, three roles, and the rule has to put each in its own
    /// place: `port=` is the external port (4000, what the LAN connects to),
    /// `to-port=` is the **container's** port (8080), and the published port
    /// (3000) appears **nowhere at all** -- it is how porthole found the
    /// container, not part of what it writes.
    ///
    /// This is what closes the hole. Before it, no test at any level asserted
    /// the rule built for a differing pair: the host test for `--as` checks
    /// two JSON fields that both come from the `OpenRequest`, the container
    /// tests all forwarded 3000 to a container published as 3000, and every
    /// fixture here used `published_port == req.port`. `forward_rich_rule`
    /// could have read `to.published_port` where it reads `req.port` and the
    /// entire workspace would have stayed green while `--as` silently
    /// forwarded the wrong number.
    fn forward_request_as_4000() -> OpenRequest {
        OpenRequest {
            port: 4000,
            ..subnet_request()
        }
    }

    #[test]
    fn a_forward_writes_the_external_port_not_the_published_one() {
        let rule = Firewalld::forward_rich_rule(
            &forward_request_as_4000(),
            &forward_to(), // published_port: 3000, container_port: 8080
            Protocol::Tcp,
        );
        assert_eq!(
            rule,
            r#"rule family="ipv4" source address="10.10.10.0/24" forward-port port="4000" protocol="tcp" to-port="8080" to-addr="172.18.0.2""#,
            "the rule must match on the port the local network connects to and send to \
             the container's own port"
        );
        // The discriminating assertion, and the reason the numbers were
        // chosen so that no two roles share one: the published port is not
        // part of the rule in any position. Swap `req.port` for
        // `to.published_port` anywhere in `forward_rich_rule` and 3000
        // appears here.
        assert!(
            !rule.contains("3000"),
            "the published port has no place in the rule -- it is how the container was \
             found, not what the rule matches or sends to: {rule}"
        );
    }

    #[test]
    fn a_forward_with_differing_ports_asks_firewalld_for_that_same_rule() {
        // The rule string above is what `forward` must actually hand
        // firewall-cmd, and what `add_rich_rule` must then match its
        // read-back on -- which it does by `req.port`, so a confusion there
        // would leave `forward` unable to recognise its own new rule at all.
        const REDIRECT_AS_4000: &str = r#"rule family="ipv4" source address="10.10.10.0/24" forward-port port="4000" protocol="tcp" to-port="8080" to-addr="172.18.0.2""#;
        let runner = RecordingRunner::with_responses(vec![
            Output::stdout(ROUTE_JSON),
            Output::stdout(ZONE),
            Output::stdout(""),
            Output::stdout("success"),
            Output::stdout(REDIRECT_AS_4000),
        ]);
        let handle = Firewalld::new(&runner)
            .forward(&forward_request_as_4000(), &forward_to(), "porthole:test")
            .expect("the read-back names port 4000, which is what add_rich_rule matches on");

        assert_eq!(
            handle,
            RuleHandle::Firewalld {
                zone: ZONE.to_string(),
                rich_rule: REDIRECT_AS_4000.to_string(),
            }
        );
        let adds: Vec<String> = runner
            .recorded()
            .iter()
            .filter(|c| c.args.iter().any(|a| a.starts_with("--add-rich-rule=")))
            .map(|c| c.display())
            .collect();
        assert_eq!(adds.len(), 1, "still one rule: {adds:#?}");
        assert!(
            adds[0].contains(r#"port="4000""#) && adds[0].contains(r#"to-port="8080""#),
            "the issued command must carry the external port and the container port: {}",
            adds[0]
        );
        assert!(
            !adds[0].contains("3000"),
            "the issued command must not carry the published port anywhere: {}",
            adds[0]
        );
    }

    #[test]
    fn a_forward_names_the_container_address_not_loopback() {
        // The whole point: traffic goes to the container's own address on
        // Docker's network. 127.0.0.1 would need route_localnet, which
        // porthole does not touch.
        let runner = RecordingRunner::with_responses(forward_script());
        Firewalld::new(&runner)
            .forward(&forward_request(), &forward_to(), "porthole:test")
            .unwrap();

        let issued = runner.recorded();
        assert!(
            issued
                .iter()
                .any(|c| c.display().contains(r#"to-addr="172.18.0.2""#)),
            "no command named the container's address: {issued:#?}",
        );
        assert!(
            !issued.iter().any(|c| c.display().contains("127.0.0.1")),
            "a command named loopback, which cannot be a redirect destination here: {issued:#?}",
        );
    }

    #[test]
    fn a_forward_is_one_rule_and_its_handle_is_that_rule() {
        let runner = RecordingRunner::with_responses(forward_script());
        let handle = Firewalld::new(&runner)
            .forward(&forward_request(), &forward_to(), "porthole:test")
            .unwrap();

        assert_eq!(
            handle,
            RuleHandle::Firewalld {
                zone: ZONE.to_string(),
                rich_rule: FORWARD_REDIRECT.to_string(),
            },
            "a forward's handle is the ordinary handle for the one rule it wrote"
        );
        let adds: Vec<String> = runner
            .recorded()
            .iter()
            .filter(|c| c.args.iter().any(|a| a.starts_with("--add-rich-rule=")))
            .map(|c| c.display())
            .collect();
        assert_eq!(adds.len(), 1, "a forward is one rule: {adds:#?}");
        assert!(adds[0].contains("forward-port"), "got: {}", adds[0]);
    }

    #[test]
    fn a_forward_writes_no_accept_for_the_external_port() {
        // The rule this asserts the absence of is a real accept: measured
        // on firewalld 2.4.4, with a service of the host's own bound to
        // `0.0.0.0:3000` and only this rule installed, a client on the
        // local network reached that service. Measured in the same
        // container, it carries none of the forwarded traffic -- with the
        // redirect present, zero packets reach the input hook at all.
        //
        // So this is the whole difference between a forward and a forward
        // that also opens the host's own port 3000 to the local network,
        // and nothing about which commands are issued would show it. Note
        // what this does *not* assert: that the forward works. No packet
        // was sent here.
        assert_eq!(
            THE_ACCEPT_A_FORWARD_MUST_NOT_WRITE,
            Firewalld::rich_rule(&forward_request()),
            "the literal below must stay the rule `open` writes, or this test \
             asserts the absence of something porthole never wrote anyway"
        );

        let runner = RecordingRunner::with_responses(forward_script());
        Firewalld::new(&runner)
            .forward(&forward_request(), &forward_to(), "porthole:test")
            .unwrap();

        for cmd in runner.recorded() {
            let shown = cmd.display();
            assert!(
                !shown.contains(THE_ACCEPT_A_FORWARD_MUST_NOT_WRITE),
                "a forward wrote the accept that opens the host's own port: {shown}"
            );
            assert!(
                !shown.contains("--add-rich-rule=") || shown.contains("forward-port"),
                "a forward added a rich rule that is not the redirect: {shown}"
            );
        }
    }

    #[test]
    fn a_forward_never_writes_a_permanent_rule() {
        let runner = RecordingRunner::with_responses(forward_script());
        Firewalld::new(&runner)
            .forward(&forward_request(), &forward_to(), "porthole:test")
            .unwrap();
        for cmd in runner.recorded() {
            assert!(
                !cmd.args.iter().any(|a| a.contains("--permanent")),
                "porthole must never write a permanent rule: {}",
                cmd.display()
            );
        }
    }

    #[test]
    fn an_unscoped_forward_omits_the_source_address() {
        // firewalld accepts a `forward-port` rich rule with no source
        // element -- measured, same container -- and porthole must not
        // invent a `source address="0.0.0.0/0"` it never verified.
        let req = OpenRequest {
            target: Target::Anywhere,
            ..forward_request()
        };
        assert_eq!(
            Firewalld::forward_rich_rule(&req, &forward_to(), Protocol::Tcp),
            r#"rule family="ipv4" forward-port port="3000" protocol="tcp" to-port="8080" to-addr="172.18.0.2""#
        );
    }

    #[test]
    fn a_forward_whose_outside_and_inside_protocols_disagree_is_refused() {
        // One rich rule carries one `protocol=`, and it governs both the
        // match on the external port and the destination. There is no
        // spelling for a disagreement, so it must not be silently resolved.
        let to = ForwardTo {
            protocol: Protocol::Udp,
            ..forward_to()
        };
        let runner = RecordingRunner::with_responses(forward_script());
        let err = Firewalld::new(&runner)
            .forward(&forward_request(), &to, "porthole:test")
            .unwrap_err();
        assert_eq!(err.exit_code(), crate::error::ExitCode::InvalidArguments);
        assert!(
            runner.recorded().is_empty(),
            "refusing must not run any command: {:#?}",
            runner.recorded()
        );
    }

    #[test]
    fn closing_a_forward_removes_the_one_rule_it_wrote() {
        let runner = RecordingRunner::new();
        Firewalld::new(&runner).close(&forward_handle()).unwrap();

        let cmds = runner.recorded();
        assert_eq!(cmds.len(), 1, "a forward is one rule: {cmds:#?}");
        assert_eq!(
            cmds[0].display(),
            format!("firewall-cmd --zone={ZONE} '--remove-rich-rule={FORWARD_REDIRECT}'")
        );
    }

    fn forward_handle() -> RuleHandle {
        RuleHandle::Firewalld {
            zone: ZONE.to_string(),
            rich_rule: FORWARD_REDIRECT.to_string(),
        }
    }

    #[test]
    fn a_forward_under_dry_run_withholds_its_add() {
        use crate::command::DryRunRunner;
        let inner = RecordingRunner::with_responses(vec![
            Output::stdout(ROUTE_JSON),
            Output::stdout(ZONE),
            Output::stdout(""), // --list-rich-rules, before
        ]);
        let runner = DryRunRunner::new(Box::new(inner));
        let handle = Firewalld::new(&runner)
            .forward(&forward_request(), &forward_to(), "porthole:test")
            .unwrap();

        // Under dry-run nothing is added, so the read-back is skipped and
        // the handle carries the rule as constructed rather than as
        // firewalld would normalise it.
        assert_eq!(
            handle,
            RuleHandle::Firewalld {
                zone: ZONE.to_string(),
                rich_rule: Firewalld::forward_rich_rule(
                    &forward_request(),
                    &forward_to(),
                    Protocol::Tcp
                ),
            }
        );
        assert_eq!(runner.recorded().len(), 1, "one withheld mutation");
    }

    #[test]
    fn close_removes_the_stored_rule_verbatim() {
        let runner = RecordingRunner::new();
        let handle = RuleHandle::Firewalld {
            zone: ZONE.to_string(),
            rich_rule: SUBNET_RULE.to_string(),
        };
        Firewalld::new(&runner).close(&handle).unwrap();

        let commands = runner.recorded();
        assert_eq!(commands.len(), 1);
        assert_eq!(
            commands[0].display(),
            format!("firewall-cmd --zone={ZONE} '--remove-rich-rule={SUBNET_RULE}'")
        );
    }

    #[test]
    fn close_treats_an_already_absent_rule_as_success() {
        // firewall-cmd --reload wipes runtime rules. Closing something that is
        // already closed is the desired end state, not a failure.
        let runner = RecordingRunner::with_responses(vec![Output {
            status: 13,
            stdout: String::new(),
            stderr: "Error: NOT_ENABLED: rule family=\"ipv4\" ...".into(),
        }]);
        let handle = RuleHandle::Firewalld {
            zone: ZONE.to_string(),
            rich_rule: SUBNET_RULE.to_string(),
        };
        assert!(Firewalld::new(&runner).close(&handle).is_ok());
    }

    #[test]
    fn close_accepts_firewalld_s_real_already_absent_response() {
        // firewall-cmd downgrades ALREADY_ENABLED and NOT_ENABLED to exit 0 for a
        // single-item invocation (firewall/command.py, __cmd_sequence), so the
        // response porthole will actually meet is a zero exit with a warning on
        // stderr. The status-13 case above stays as defence: the firewalld D-Bus
        // API, which a later milestone may use instead of the CLI, raises the
        // error rather than downgrading it.
        let runner = RecordingRunner::with_responses(vec![Output {
            status: 0,
            stdout: String::new(),
            stderr: "Warning: NOT_ENABLED: rule family=\"ipv4\" ...".into(),
        }]);
        let handle = RuleHandle::Firewalld {
            zone: ZONE.to_string(),
            rich_rule: SUBNET_RULE.to_string(),
        };
        assert!(Firewalld::new(&runner).close(&handle).is_ok());
    }

    #[test]
    fn close_still_fails_on_a_real_error() {
        let runner = RecordingRunner::with_responses(vec![Output {
            status: 1,
            stdout: String::new(),
            stderr: "Error: INVALID_ZONE: NoSuchZone".into(),
        }]);
        let handle = RuleHandle::Firewalld {
            zone: "NoSuchZone".to_string(),
            rich_rule: SUBNET_RULE.to_string(),
        };
        assert!(Firewalld::new(&runner).close(&handle).is_err());
    }

    #[test]
    fn list_rules_returns_every_rich_rule_in_the_zone() {
        let runner = RecordingRunner::with_responses(vec![
            Output::stdout(ROUTE_JSON),
            Output::stdout(ZONE),
            Output::stdout(&format!("{SUBNET_RULE}\n{ANY_RULE}")),
        ]);
        let handles = Firewalld::new(&runner).list_rules().unwrap();
        assert_eq!(handles.len(), 2);
        assert_eq!(
            handles[0],
            RuleHandle::Firewalld {
                zone: ZONE.to_string(),
                rich_rule: SUBNET_RULE.to_string()
            }
        );
    }

    #[test]
    fn health_reports_running() {
        let runner = RecordingRunner::with_responses(vec![
            Output::stdout("2.4.4"),
            Output::stdout("running"),
        ]);
        let health = Firewalld::new(&runner).health().unwrap();
        assert!(health.available);
        assert!(health.active);
        assert_eq!(health.version.as_deref(), Some("2.4.4"));
    }

    #[test]
    fn health_reports_installed_but_stopped() {
        let runner = RecordingRunner::with_responses(vec![
            Output::stdout("2.4.4"),
            Output {
                status: 252,
                stdout: "not running".into(),
                stderr: String::new(),
            },
        ]);
        let health = Firewalld::new(&runner).health().unwrap();
        assert!(health.available);
        assert!(!health.active);
        assert!(
            !health.active_unknown,
            "252 is firewalld's own NOT_RUNNING: a definite answer, not an unknown"
        );
        assert!(
            health.detail.contains("not running"),
            "got: {}",
            health.detail
        );
    }

    /// What a real firewalld answers an unprivileged caller where it refuses
    /// one. Measured on ubuntu:24.04 under systemd, firewalld active and
    /// holding its default zone: each read tried -- `--version`, `--state`,
    /// `--list-rich-rules` -- exits 253, and `--state` prints nothing on
    /// stdout. Root, same machine, same moment: 0.
    fn refused() -> Output {
        Output {
            status: 253,
            stdout: String::new(),
            stderr: "Authorization failed.\n    Make sure polkit agent is running or run \
                     the application as superuser."
                .into(),
        }
    }

    #[test]
    fn a_refused_state_read_is_unknown_not_stopped() {
        // Any non-zero `--state` used to be read as the daemon's answer, so
        // `doctor` told an ordinary user that no rule firewalld held was being
        // enforced -- on a machine where firewalld was running and enforcing
        // them -- and `open --dry-run` refused on the same false premise.
        let runner = RecordingRunner::with_responses(vec![refused(), refused()]);
        let health = Firewalld::new(&runner).health().unwrap();
        assert!(health.available, "a refusal proves firewalld is there");
        assert!(!health.active, "and proves nothing about whether it runs");
        assert!(
            health.active_unknown,
            "this is the unknown case: {}",
            health.detail
        );
        assert!(
            !health.detail.contains("not running") && !health.detail.contains("no rule"),
            "must not state what a refusal cannot support: {}",
            health.detail
        );
        assert!(
            health.detail.contains("253"),
            "must name what firewall-cmd actually answered: {}",
            health.detail
        );
    }

    #[test]
    fn only_not_running_counts_as_stopped() {
        // 252 is the one exit firewalld defines as "not running". Anything
        // else from `--state` -- its RUNNING_BUT_FAILED (251) and UNKNOWN_ERROR
        // (254), or a Python traceback's 1 -- is a read that did not answer.
        for status in [1, 251, 254] {
            let runner = RecordingRunner::with_responses(vec![
                Output::stdout("2.4.4"),
                Output {
                    status,
                    stdout: String::new(),
                    stderr: "something went wrong".into(),
                },
            ]);
            let health = Firewalld::new(&runner).health().unwrap();
            assert!(!health.active, "exit {status}");
            assert!(health.active_unknown, "exit {status}: {}", health.detail);
            assert!(
                health.detail.contains(&status.to_string()),
                "exit {status}: {}",
                health.detail
            );
        }
    }

    #[test]
    fn a_state_spawn_failure_after_a_successful_version_is_still_available_not_an_error() {
        // `--version` succeeding already proves firewalld is installed; a
        // resource-level failure to even run `--state` afterwards (EAGAIN,
        // ENOMEM, EMFILE, the binary swapped
        // mid-upgrade) is a different fact from "not installed" and must
        // degrade the same way ufw's and nftables' own permission-denied
        // reads do, not propagate with `?` -- which used to turn this into
        // `detect()` reporting no firewall found at all on a machine running
        // firewalld, the one backend that earlier fix did not cover.
        struct VersionOkThenSpawnFails;
        impl CommandRunner for VersionOkThenSpawnFails {
            fn run(&self, cmd: &Command) -> Result<Output> {
                if cmd.args.iter().any(|a| a == "--version") {
                    Ok(Output::stdout("2.4.4"))
                } else {
                    Err(Error::CommandSpawn {
                        command: cmd.display(),
                        source: std::io::Error::other("resource busy"),
                    })
                }
            }
        }
        let health = Firewalld::new(&VersionOkThenSpawnFails).health().unwrap();
        assert!(
            health.available,
            "the binary is there; that must stand alone"
        );
        assert!(
            !health.active,
            "porthole cannot claim it is running when it could not check"
        );
        assert!(
            health.active_unknown,
            "this is the unknown case, not a confirmed-stopped one"
        );
        assert!(
            health.detail.contains("resource busy"),
            "must name the real failure: {}",
            health.detail
        );
    }

    #[test]
    fn health_reports_absent_when_firewall_cmd_is_missing() {
        struct MissingProgram;
        impl CommandRunner for MissingProgram {
            fn run(&self, cmd: &Command) -> Result<Output> {
                Err(Error::CommandSpawn {
                    command: cmd.display(),
                    source: std::io::Error::new(std::io::ErrorKind::NotFound, "no such file"),
                })
            }
        }
        let health = Firewalld::new(&MissingProgram).health().unwrap();
        assert!(!health.available);
        assert!(!health.active);
    }

    #[test]
    fn managed_zone_falls_back_to_the_default_zone() {
        let runner = RecordingRunner::with_responses(vec![
            Output::stdout(ROUTE_JSON),
            Output {
                status: 2,
                stdout: String::new(),
                stderr: "no zone".into(),
            },
            Output::stdout("public"),
        ]);
        assert_eq!(Firewalld::new(&runner).managed_zone().unwrap(), "public");
        assert_eq!(
            runner.recorded()[2].display(),
            "firewall-cmd --get-default-zone"
        );
    }
}
