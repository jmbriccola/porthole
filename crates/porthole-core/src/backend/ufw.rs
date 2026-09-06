//! The ufw backend.
//!
//! Two things make ufw unlike the others.
//!
//! **It exits 0 for everything.** Adding a duplicate prints "Skipping adding
//! existing rule" and exits 0; deleting a rule that is not there prints "Could
//! not delete non-existent rule" and exits 0. So every result here comes from
//! reading stdout, never from the status code.
//!
//! **Its rules are permanent.** `ufw allow` writes to `/etc/ufw/user.rules`
//! and `ufw.service` reloads them at boot. ufw has no runtime-only concept at
//! all, so porthole's "nothing survives a reboot" invariant is upheld here by
//! reconciliation removing what is left over, not by a flag. There is no flag.
//!
//! Deletion is **by specification, never by number**. `ufw status numbered`
//! numbers shift as soon as any other rule is removed, so a stored number
//! deletes whatever later occupies that slot — the user's rules included.

use super::{BackendHealth, BackendId, FirewallBackend, Ownership, RuleHandle};
use crate::command::{Command, CommandRunner};
use crate::error::{Error, Result};
use crate::model::{OpenRequest, Target};
use ipnet::Ipv4Net;

pub struct Ufw<'a> {
    runner: &'a dyn CommandRunner,
}

impl<'a> Ufw<'a> {
    pub fn new(runner: &'a dyn CommandRunner) -> Self {
        Self { runner }
    }

    /// The argument list after `allow`, and the same text `delete allow` takes.
    ///
    /// `Target::Anywhere` becomes `0.0.0.0/0` rather than being omitted: the
    /// bare form would make ufw add an IPv6 rule too, and porthole v1 manages
    /// IPv4 only. One shape for both targets also means the stored delete spec
    /// is built the same way every time.
    fn spec(req: &OpenRequest) -> String {
        let source = match req.target {
            Target::Network { cidr } => cidr.to_string(),
            Target::Anywhere => "0.0.0.0/0".to_string(),
        };
        format!(
            "from {source} to any port {} proto {}",
            req.port, req.protocol
        )
    }

    fn open_impl(&self, req: &OpenRequest, marker: &str) -> Result<RuleHandle> {
        let spec = Self::spec(req);
        let mut args: Vec<String> = vec!["allow".to_string()];
        args.extend(spec.split(' ').map(str::to_string));
        args.push("comment".to_string());
        args.push(marker.to_string());

        let cmd = Command::mutate("ufw", args);
        let out = self.runner.run(&cmd)?.into_ok(&cmd)?;

        if self.runner.is_dry_run() {
            // The add was withheld, so there is no stdout to read a
            // confirmation from -- ufw's success signal is its words, not its
            // exit code (see the module docs), and a withheld mutation's
            // `Output` is empty. Report the rule dry-run would have added.
            return Ok(RuleHandle::Ufw {
                spec,
                marker: marker.to_string(),
            });
        }

        // ufw's exit code says nothing; its words do.
        if out.stdout.contains("Skipping adding existing rule") {
            return Err(Error::AlreadyOpen {
                port: req.port,
                protocol: req.protocol,
                detail: format!("ufw already has a rule for {spec}"),
            });
        }
        if !out.stdout.contains("Rule added") {
            // Not CommandFailed: ufw exited 0. That variant carries a status
            // and a stderr, and inventing a non-zero one here would make the
            // error message contradict what actually happened.
            return Err(Error::Unexpected(format!(
                "ufw did not confirm the rule was added; it said: {}",
                out.stdout.trim()
            )));
        }

        Ok(RuleHandle::Ufw {
            spec,
            marker: marker.to_string(),
        })
    }

    fn close_impl(&self, spec: &str) -> Result<()> {
        let mut args: Vec<String> = vec![
            "--force".to_string(),
            "delete".to_string(),
            "allow".to_string(),
        ];
        args.extend(spec.split(' ').map(str::to_string));

        let cmd = Command::mutate("ufw", args);
        let out = self.runner.run(&cmd)?.into_ok(&cmd)?;

        if self.runner.is_dry_run() {
            // Same reasoning as `open_impl`: the delete was withheld, so
            // there is nothing on stdout to confirm it against. This matters
            // beyond an explicit `close --dry-run`: reconciliation's own
            // sweep calls this for every orphan it finds, including under a
            // dry-run `open` or `close`, and without this a withheld orphan
            // close would land in `Report::failures` instead of the
            // withheld-command list a dry run is supposed to show.
            return Ok(());
        }

        if out.stdout.contains("Could not delete non-existent rule") {
            return Err(Error::RuleNotFound(format!("ufw has no rule {spec}")));
        }
        if !out.stdout.contains("Rule deleted") {
            return Err(Error::Unexpected(format!(
                "ufw did not confirm the rule was deleted; it said: {}",
                out.stdout.trim()
            )));
        }
        Ok(())
    }

    /// Normalise a source address the way `spec` already writes one, so a
    /// stored handle and one reconstructed from ufw's own output compare
    /// equal.
    ///
    /// `ufw status numbered` renders a `/32` source with the prefix
    /// dropped -- `10.10.10.42`, not `10.10.10.42/32` -- while `spec` always
    /// writes the network form via `Ipv4Net::to_string`, which never omits
    /// it. Left alone, a host-scoped `open`'s stored handle and the one this
    /// function's caller reconstructs are never equal, and reconciliation
    /// -- which compares handles structurally -- treats a rule ufw still
    /// enforces as stale, drops it from state, and (see `owned_rules`) could
    /// not even have recognised it as porthole's own to protect it, because
    /// a bare address fails to parse as `Ipv4Net` at all.
    fn canonical_source(text: &str) -> String {
        if let Ok(net) = text.parse::<Ipv4Net>() {
            return net.to_string();
        }
        if let Ok(addr) = text.parse::<std::net::Ipv4Addr>() {
            if let Ok(net) = Ipv4Net::new(addr, 32) {
                return net.to_string();
            }
        }
        // Not a recognisable IPv4 address at all (shouldn't happen -- v6 rows
        // are filtered out before this runs) -- pass it through unchanged
        // rather than inventing a shape for it.
        text.to_string()
    }

    fn status_numbered(&self) -> Result<String> {
        let cmd = Command::read("ufw", ["status", "numbered"]);
        let out = self.runner.run(&cmd)?.into_ok(&cmd)?;
        Ok(out.stdout)
    }

    /// Parse `ufw status numbered` output into rule handles.
    ///
    /// A row looks like:
    ///
    /// ```text
    /// [ 1] 5173/tcp                   ALLOW IN    Anywhere                   # porthole:a1
    /// ```
    ///
    /// Parsed by structure, not by column offsets: skip anything that does not
    /// start with `[`, take the text after `]`, split on `#` to pull the
    /// trailing comment away from the rule, then read the port/protocol
    /// column, the two-word action, and everything left over as the source.
    ///
    /// Real ufw output is not this tidy. A row can have no protocol suffix
    /// (`80`), a port range (`8000:8010/tcp`), an IPv6 flavour that appends
    /// `(v6)` to both the port column and the source column, or an action
    /// other than `ALLOW IN`. `list_rules` (`owned_only = false`) reports
    /// every row regardless of shape — it is diagnostic, not evidence. Only a
    /// row that is marked with a `porthole:` comment *and* has exactly the
    /// shape `open_impl` produces — `ALLOW IN`, a single tcp or udp port, an
    /// IPv4 source or `Anywhere` — is claimed when `owned_only` is set. A
    /// `porthole:` comment on a row of any other shape is a hand-edited rule
    /// or a marker collision, not something reconciliation may remove.
    fn parse_status(&self, text: &str, owned_only: bool) -> Result<Vec<RuleHandle>> {
        let mut handles = Vec::new();

        for line in text.lines() {
            let trimmed = line.trim_start();
            if !trimmed.starts_with('[') {
                continue;
            }
            let Some((_, after_bracket)) = trimmed.split_once(']') else {
                continue;
            };

            let (rule_part, comment) = match after_bracket.split_once('#') {
                Some((rule, c)) => (rule, Some(c.trim().to_string())),
                None => (after_bracket, None),
            };

            let fields: Vec<&str> = rule_part.split_whitespace().collect();
            if fields.is_empty() {
                continue;
            }

            let mut idx = 1;
            let mut to = fields[0].to_string();
            if fields.get(idx) == Some(&"(v6)") {
                to.push_str(" (v6)");
                idx += 1;
            }

            let action = fields
                .get(idx..(idx + 2).min(fields.len()))
                .map(|w| w.join(" "))
                .unwrap_or_default();
            idx = (idx + 2).min(fields.len());

            let from = fields[idx..].join(" ");

            let is_v6 = to.ends_with("(v6)") || from.ends_with("(v6)");
            let to_base = to.strip_suffix(" (v6)").unwrap_or(&to);
            let (port_text, proto_text) = match to_base.split_once('/') {
                Some((port, proto)) => (port.to_string(), proto.to_string()),
                None => (to_base.to_string(), String::new()),
            };

            let from_base = from.strip_suffix(" (v6)").unwrap_or(&from);
            let source = if from_base == "Anywhere" {
                "0.0.0.0/0".to_string()
            } else {
                Self::canonical_source(from_base)
            };

            let spec = format!("from {source} to any port {port_text} proto {proto_text}");
            let marker = comment.filter(|c| c.starts_with("porthole:"));

            if owned_only {
                let is_porthole_shape = !is_v6
                    && action == "ALLOW IN"
                    && (proto_text == "tcp" || proto_text == "udp")
                    && port_text.parse::<u16>().is_ok()
                    && (source == "0.0.0.0/0" || source.parse::<Ipv4Net>().is_ok());

                if let (Some(marker), true) = (marker, is_porthole_shape) {
                    handles.push(RuleHandle::Ufw { spec, marker });
                }
                continue;
            }

            handles.push(RuleHandle::Ufw {
                spec,
                marker: marker.unwrap_or_default(),
            });
        }

        Ok(handles)
    }
}

impl FirewallBackend for Ufw<'_> {
    fn id(&self) -> BackendId {
        BackendId::Ufw
    }

    fn open(&self, req: &OpenRequest, marker: &str) -> Result<RuleHandle> {
        self.open_impl(req, marker)
    }

    fn close(&self, handle: &RuleHandle) -> Result<()> {
        let RuleHandle::Ufw { spec, .. } = handle else {
            return Err(Error::Unexpected(format!(
                "the ufw backend was handed a {handle:?}"
            )));
        };
        self.close_impl(spec)
    }

    fn list_rules(&self) -> Result<Vec<RuleHandle>> {
        let text = self.status_numbered()?;
        self.parse_status(&text, false)
    }

    fn owned_rules(&self) -> Result<Option<Vec<RuleHandle>>> {
        let text = self.status_numbered()?;
        Ok(Some(self.parse_status(&text, true)?))
    }

    fn ownership(&self) -> Ownership {
        Ownership::Marked
    }

    fn health(&self) -> Result<BackendHealth> {
        let version_cmd = Command::read("ufw", ["version"]);
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
                    detail: "ufw is not installed".to_string(),
                    caveat: None,
                })
            }
            Err(other) => return Err(other),
        };

        // `ufw status` exits 0 whether the firewall is enabled or not, so the
        // status is the answer, not an error.
        let status_cmd = Command::read("ufw", ["status"]);
        let status_out = self.runner.run(&status_cmd)?.into_ok(&status_cmd)?;
        let active = status_out.stdout.contains("Status: active");

        let detail = if active {
            match &version {
                Some(v) => format!("{v} is active"),
                None => "ufw is active".to_string(),
            }
        } else {
            "ufw is installed but not active, so no rule it holds is being enforced".to_string()
        };

        Ok(BackendHealth {
            available: true,
            active,
            version,
            detail,
            // ufw's standing persistence caveat ("a rule survives a reboot
            // until reconciliation notices") is true regardless of `active`,
            // but it is stated by `porthole-cli`'s doctor.rs and
            // docs/backends.md, not threaded through here -- unlike
            // nftables' caveat, it is not something `health()` had to
            // inspect the ruleset to discover.
            caveat: None,
        })
    }

    fn location(&self) -> Result<Option<String>> {
        Ok(Some("ufw".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::{CommandRunner, Output, RecordingRunner};
    use crate::error::ExitCode;
    use crate::model::{Lifetime, Protocol, Target};
    use std::time::Duration;

    /// Captured verbatim from ufw 0.36.2 in a container, with real user rules
    /// alongside porthole's. Do not tidy the spacing, and do not drop a row:
    /// each of the last five is a shape a naive parser gets wrong. Row 7 is a
    /// `/32` host source rendered bare (no prefix) -- exactly the shape that
    /// made a host-scoped `open` compare unequal to itself after a round trip
    /// through `list_rules`, before `canonical_source` existed.
    const STATUS_NUMBERED: &str = "Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 5173/tcp                   ALLOW IN    Anywhere                   # porthole:a1
[ 2] 6000/udp                   ALLOW IN    10.10.10.0/24              # porthole:b2
[ 3] 22/tcp                     ALLOW IN    Anywhere
[ 4] 80                         DENY IN     192.168.5.0/24
[ 5] 8000:8010/tcp              ALLOW IN    Anywhere
[ 6] 22/tcp (v6)                LIMIT IN    Anywhere (v6)
[ 7] 5174/tcp                   ALLOW IN    10.10.10.42                # porthole:c3
";

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
    fn open_builds_the_command_ufw_actually_accepts() {
        let runner = RecordingRunner::with_responses(vec![Output::stdout("Rule added")]);
        let handle = Ufw::new(&runner)
            .open(&request(5173, subnet()), "porthole:abc")
            .unwrap();

        let cmds = runner.recorded();
        assert_eq!(cmds.len(), 1);
        assert_eq!(
            cmds[0].display(),
            "ufw allow from 10.10.10.0/24 to any port 5173 proto tcp \
             comment porthole:abc"
        );
        assert_eq!(
            handle,
            RuleHandle::Ufw {
                spec: "from 10.10.10.0/24 to any port 5173 proto tcp".to_string(),
                marker: "porthole:abc".to_string(),
            }
        );
    }

    #[test]
    fn anywhere_is_spelled_as_a_zero_prefix_so_the_shape_never_varies() {
        // The bare form `ufw allow 5173/tcp` would also add an IPv6 rule, and
        // porthole v1 is IPv4 only. An explicit v4 source keeps it v4.
        let runner = RecordingRunner::with_responses(vec![Output::stdout("Rule added")]);
        Ufw::new(&runner)
            .open(&request(5173, Target::Anywhere), "porthole:abc")
            .unwrap();
        assert!(runner.recorded()[0].display().contains("from 0.0.0.0/0"));
    }

    #[test]
    fn an_existing_rule_is_already_open_even_though_ufw_exits_zero() {
        // ufw prints "Skipping adding existing rule" and exits 0. Trusting the
        // exit code here reports a success that never happened, and porthole
        // would then write a state entry and a close timer for a rule it does
        // not own.
        let runner =
            RecordingRunner::with_responses(vec![Output::stdout("Skipping adding existing rule")]);
        let err = Ufw::new(&runner)
            .open(&request(5173, subnet()), "porthole:abc")
            .unwrap_err();
        assert_eq!(err.exit_code(), ExitCode::AlreadyOpen);
    }

    #[test]
    fn deleting_a_rule_that_is_gone_is_rule_not_found_not_success() {
        let runner = RecordingRunner::with_responses(vec![Output::stdout(
            "Could not delete non-existent rule",
        )]);
        let err = Ufw::new(&runner)
            .close(&RuleHandle::Ufw {
                spec: "from 10.10.10.0/24 to any port 5173 proto tcp".to_string(),
                marker: "porthole:abc".to_string(),
            })
            .unwrap_err();
        assert_eq!(err.exit_code(), ExitCode::RuleNotFound);
    }

    #[test]
    fn close_deletes_by_specification_never_by_number() {
        // Rule numbers shift whenever any other rule is removed, so a stored
        // number removes whatever happens to occupy that slot later. That is
        // the one bug in this backend that would silently delete the user's
        // rules.
        let runner = RecordingRunner::with_responses(vec![Output::stdout("Rule deleted")]);
        Ufw::new(&runner)
            .close(&RuleHandle::Ufw {
                spec: "from 10.10.10.0/24 to any port 5173 proto tcp".to_string(),
                marker: "porthole:abc".to_string(),
            })
            .unwrap();
        let shown = runner.recorded()[0].display();
        assert_eq!(
            shown,
            "ufw --force delete allow from 10.10.10.0/24 to any port 5173 proto tcp"
        );
        assert!(
            !shown.contains(char::is_numeric) || !shown.contains("delete 1"),
            "must not delete by index"
        );
    }

    #[test]
    fn the_shapes_a_naive_parser_gets_wrong_do_not_break_the_listing() {
        // Row 4 has no protocol suffix at all, so splitting on '/' and taking
        // [1] finds nothing. Row 5 is a port range, so u16::from_str fails on
        // the whole token. Row 6 is IPv6, carrying " (v6)" in both columns.
        // Rows 4 and 6 are DENY and LIMIT, so a parser keying on the literal
        // "ALLOW" drops them and one keying on column position reads the
        // action as part of the address. All four are real ufw output.
        let runner = RecordingRunner::with_responses(vec![Output::stdout(STATUS_NUMBERED)]);
        let all = Ufw::new(&runner).list_rules().unwrap();
        assert_eq!(all.len(), 7, "every row is reported, none silently dropped");
    }

    #[test]
    fn a_marked_row_that_is_not_portholes_shape_is_not_claimed() {
        // porthole writes exactly one shape: <port>/<tcp|udp>, ALLOW IN, an
        // IPv4 source or Anywhere. A row carrying a porthole: comment that is
        // a range, or v6, or DENY, was not written by porthole -- it is a
        // hand-edited rule or a marker collision. Reconstructing a delete
        // spec from it would delete something the user wanted.
        const ODD: &str = "Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 8000:8010/tcp              ALLOW IN    Anywhere                   # porthole:fake
[ 2] 80                         DENY IN     192.168.5.0/24             # porthole:fake2
";
        let runner = RecordingRunner::with_responses(vec![Output::stdout(ODD)]);
        assert!(Ufw::new(&runner).owned_rules().unwrap().unwrap().is_empty());
    }

    #[test]
    fn owned_rules_finds_only_the_marked_ones() {
        // Entries 3 to 6 are the user's own rules. None may come back from
        // owned_rules, and reconciliation must therefore never remove one.
        // Entry 7 is porthole's own host-scoped rule, rendered bare -- it
        // must be recognised despite that, or a leftover host-scoped ufw
        // rule could never be cleaned up by reconciliation at all.
        let runner = RecordingRunner::with_responses(vec![Output::stdout(STATUS_NUMBERED)]);
        let owned = Ufw::new(&runner).owned_rules().unwrap().unwrap();
        assert_eq!(owned.len(), 3);
        let markers: Vec<_> = owned
            .iter()
            .map(|h| match h {
                RuleHandle::Ufw { marker, .. } => marker.clone(),
                other => panic!("unexpected handle: {other:?}"),
            })
            .collect();
        assert_eq!(markers, vec!["porthole:a1", "porthole:b2", "porthole:c3"]);
    }

    #[test]
    fn a_listed_rule_yields_a_spec_that_would_delete_it() {
        // Reconciliation removes an orphan by feeding this spec straight back
        // to `ufw delete`. If the reconstruction is wrong, the sweep silently
        // does nothing and the port stays open forever. Entry 7's `/32` must
        // come back with an explicit prefix -- the bare form `ufw delete`
        // would be fed is not what `spec` ever writes, and would not match.
        let runner = RecordingRunner::with_responses(vec![Output::stdout(STATUS_NUMBERED)]);
        let owned = Ufw::new(&runner).owned_rules().unwrap().unwrap();
        let specs: Vec<_> = owned
            .iter()
            .map(|h| match h {
                RuleHandle::Ufw { spec, .. } => spec.clone(),
                other => panic!("unexpected handle: {other:?}"),
            })
            .collect();
        assert_eq!(
            specs,
            vec![
                "from 0.0.0.0/0 to any port 5173 proto tcp",
                "from 10.10.10.0/24 to any port 6000 proto udp",
                "from 10.10.10.42/32 to any port 5174 proto tcp",
            ]
        );
    }

    #[test]
    fn a_host_scoped_open_round_trips_through_list_rules_despite_ufws_bare_slash_32() {
        // C1: ufw renders a `/32` source without its prefix in `status
        // numbered` (`10.10.10.42`, not `10.10.10.42/32`), while `spec`
        // always writes the network form with an explicit one. Without
        // normalising both sides, the handle `open` returns and the one
        // `list_rules` reconstructs from ufw's own output are never equal --
        // and reconciliation, which compares handles structurally, would
        // drop a rule ufw still enforces as stale on the very next sweep,
        // then close it as an unrecognised orphan: porthole silently closing
        // a port it just opened.
        let open_runner = RecordingRunner::with_responses(vec![Output::stdout("Rule added")]);
        let host = Target::Network {
            cidr: "10.10.10.42/32".parse().unwrap(),
        };
        let opened = Ufw::new(&open_runner)
            .open(&request(5173, host), "porthole:host")
            .unwrap();

        const RENDERED: &str = "Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 5173/tcp                   ALLOW IN    10.10.10.42                # porthole:host
";
        let list_runner = RecordingRunner::with_responses(vec![Output::stdout(RENDERED)]);
        let listed = Ufw::new(&list_runner).list_rules().unwrap();

        assert_eq!(
            listed,
            vec![opened],
            "a host-scoped rule must round-trip through list_rules identically \
             to what open returned, or reconciliation treats a live rule as stale"
        );
    }

    #[test]
    fn status_inactive_is_installed_but_not_enforcing() {
        let runner = RecordingRunner::with_responses(vec![
            Output::stdout("ufw 0.36.2"),
            Output::stdout("Status: inactive"),
        ]);
        let health = Ufw::new(&runner).health().unwrap();
        assert!(health.available);
        assert!(!health.active, "inactive ufw enforces nothing");
    }

    #[test]
    fn never_a_permanent_flag_because_every_ufw_rule_already_is_one() {
        // ufw has no runtime-only mode: `ufw allow` is permanent by
        // construction and survives a reboot. porthole's invariant is
        // therefore upheld by reconciliation, not by a flag — this test exists
        // so that anyone who "fixes" it by reaching for a flag finds out ufw
        // has none.
        let runner = RecordingRunner::with_responses(vec![Output::stdout("Rule added")]);
        Ufw::new(&runner)
            .open(&request(5173, subnet()), "porthole:abc")
            .unwrap();
        for cmd in runner.recorded() {
            assert!(!cmd.display().contains("--permanent"));
        }
    }

    #[test]
    fn open_and_close_succeed_under_dry_run_with_nothing_to_confirm() {
        // Unlike firewalld and nftables, ufw decides success by reading
        // stdout, never the exit code -- and a withheld mutation's `Output`
        // is empty. Without a dry-run check of its own, `open_impl` reads
        // that emptiness as "did not confirm the rule was added" and
        // `close_impl` reads it as "did not confirm the rule was deleted",
        // turning every withheld ufw mutation into a hard error under
        // `--dry-run` -- including reconciliation's own orphan closes, which
        // now run inside every dry-run `open` and `close` too.
        use crate::command::DryRunRunner;

        let open_runner = DryRunRunner::new(Box::new(RecordingRunner::new()));
        let handle = Ufw::new(&open_runner)
            .open(&request(5173, subnet()), "porthole:abc")
            .unwrap();
        assert_eq!(
            handle,
            RuleHandle::Ufw {
                spec: "from 10.10.10.0/24 to any port 5173 proto tcp".to_string(),
                marker: "porthole:abc".to_string(),
            }
        );
        assert_eq!(open_runner.recorded().len(), 1, "one withheld mutation");

        let close_runner = DryRunRunner::new(Box::new(RecordingRunner::new()));
        Ufw::new(&close_runner)
            .close(&handle)
            .expect("a withheld close must not be reported as a failure");
        assert_eq!(close_runner.recorded().len(), 1, "one withheld mutation");
    }
}
