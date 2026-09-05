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

use super::{BackendHealth, BackendId, FirewallBackend, RuleHandle};
use crate::command::{Command, CommandRunner, Output};
use crate::error::{Error, Result};
use crate::model::{OpenRequest, Target};
use crate::net;

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

    fn open(&self, req: &OpenRequest) -> Result<RuleHandle> {
        let zone = self.managed_zone()?;
        let rule = Self::rich_rule(req);

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
                rich_rule: rule,
            });
        }

        let after = self.list_rich_rules(&zone)?;
        let added: Vec<&String> = after.iter().filter(|r| !before.contains(r)).collect();

        match added.as_slice() {
            [one] => Ok(RuleHandle::Firewalld {
                zone,
                rich_rule: (*one).clone(),
            }),
            // Reachable because firewall-cmd downgrades ALREADY_ENABLED to exit 0
            // for a single-item invocation, so the add above succeeds and simply
            // adds no new line. Verified in firewall/command.py, __cmd_sequence.
            [] => Err(Error::AlreadyOpen {
                port: req.port,
                protocol: req.protocol,
                detail: format!("an identical rich rule already exists in zone {zone}"),
            }),
            _ => Err(Error::Unexpected(format!(
                "zone {zone} gained {} rich rules while porthole added one; \
                 something else is changing the firewall at the same time",
                added.len()
            ))),
        }
    }

    fn close(&self, handle: &RuleHandle) -> Result<()> {
        // One arm today. Milestones 3 adds Ufw and Nftables, and the compiler
        // will point here when they do.
        match handle {
            RuleHandle::Firewalld { zone, rich_rule } => {
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
        }
    }

    /// Every rich rule in the managed zone.
    ///
    /// firewalld gives porthole no way to tell its own rules apart from a
    /// user's, so this returns all of them and the caller intersects with the
    /// state file. See the module docs.
    fn list_managed(&self) -> Result<Vec<RuleHandle>> {
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

    fn health(&self) -> Result<BackendHealth> {
        let version_cmd = Command::read("firewall-cmd", ["--version"]);
        let version = match self.runner.run(&version_cmd) {
            Ok(out) if out.success() => Some(out.stdout.trim().to_string()),
            Ok(_) => None,
            Err(Error::CommandSpawn { .. }) => {
                return Ok(BackendHealth {
                    available: false,
                    active: false,
                    version: None,
                    detail: "firewalld is not installed".to_string(),
                })
            }
            Err(other) => return Err(other),
        };

        // `firewall-cmd --state` exits non-zero when the daemon is stopped, so
        // the status is the answer, not an error.
        let state_cmd = Command::read("firewall-cmd", ["--state"]);
        let state = self.runner.run(&state_cmd)?;
        let active = state.success() && state.stdout.trim() == "running";

        let detail = if active {
            match &version {
                Some(v) => format!("firewalld {v} is running"),
                None => "firewalld is running".to_string(),
            }
        } else {
            "firewalld is installed but not running, so no rule it holds is being enforced"
                .to_string()
        };

        Ok(BackendHealth {
            available: true,
            active,
            version,
            detail,
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
mod tests {
    use super::*;
    use crate::command::{Effect, Output, RecordingRunner};
    use crate::error::Error;
    use crate::model::{Lifetime, Protocol, Target};
    use std::time::Duration;

    const ROUTE_JSON: &str = r#"[{"dst":"default","dev":"wlo1","metric":600}]"#;
    const ZONE: &str = "FedoraWorkstation";

    const SUBNET_RULE: &str = r#"rule family="ipv4" source address="10.10.10.0/24" port port="5173" protocol="tcp" accept"#;
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
        let handle = Firewalld::new(&runner).open(&subnet_request()).unwrap();

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
        let handle = Firewalld::new(&runner).open(&subnet_request()).unwrap();

        match handle {
            RuleHandle::Firewalld { rich_rule, .. } => assert_eq!(rich_rule, normalised),
        }
    }

    #[test]
    fn open_never_writes_a_permanent_rule() {
        let runner = RecordingRunner::with_responses(open_script("", SUBNET_RULE));
        Firewalld::new(&runner).open(&subnet_request()).unwrap();
        for cmd in runner.recorded() {
            assert!(
                !cmd.args.iter().any(|a| a.contains("--permanent")),
                "porthole must never write a permanent rule: {}",
                cmd.display()
            );
        }
    }

    #[test]
    fn open_reports_already_open_when_no_new_rule_appeared() {
        let runner = RecordingRunner::with_responses(open_script(SUBNET_RULE, SUBNET_RULE));
        let err = Firewalld::new(&runner).open(&subnet_request()).unwrap_err();
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
        let handle = Firewalld::new(&runner).open(&subnet_request()).unwrap();
        assert_eq!(
            handle,
            RuleHandle::Firewalld {
                zone: ZONE.to_string(),
                rich_rule: SUBNET_RULE.to_string(),
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
    fn list_managed_returns_every_rich_rule_in_the_zone() {
        let runner = RecordingRunner::with_responses(vec![
            Output::stdout(ROUTE_JSON),
            Output::stdout(ZONE),
            Output::stdout(&format!("{SUBNET_RULE}\n{ANY_RULE}")),
        ]);
        let handles = Firewalld::new(&runner).list_managed().unwrap();
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
            health.detail.contains("not running"),
            "got: {}",
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
