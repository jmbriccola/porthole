//! Docker's published ports, read from iptables' own `DOCKER` chain in the
//! `nat` table — never from Docker itself.
//!
//! Docker writes its own DNAT rules into iptables, and those rules are
//! evaluated **before** any of porthole's own backends: the `DOCKER` chain
//! in the `nat` table is reached from `PREROUTING`, long before a packet
//! ever meets the `filter` table firewalld, ufw and nftables all manage.
//! Two consequences follow, and they point in opposite directions:
//!
//! - a container port published on `0.0.0.0` is **already reachable** from
//!   the network, whatever porthole's firewall backend says — and closing
//!   it with porthole does not close it, because porthole never opened it.
//! - a container port published on `127.0.0.1` does **not** become
//!   reachable by opening it with porthole: the firewall was never what was
//!   stopping it. Docker's own DNAT rule only forwards traffic that already
//!   arrived addressed to `127.0.0.1`, which nothing outside this machine
//!   can send in the first place.
//!
//! In both cases a user who trusts porthole's own account of what it just
//! did would be wrong, and the spec is blunt that this is worse than not
//! having the tool at all. [`advise`] is what says so, when it matters, and
//! says nothing at all otherwise — noise on every open would train a user to
//! skip the one message that does.
//!
//! This module never runs `docker` itself, and never checks `docker` group
//! membership: porthole must behave identically for someone who has never
//! heard of Docker and someone who cannot query it. Reading the `DOCKER`
//! chain needs root — an ordinary user cannot read the `nat` table at all —
//! so [`published`] is meant to be called from the privileged helper, over
//! the same [`crate::command::CommandRunner`] seam every other privileged
//! read in this codebase already goes through, never directly from the CLI.

use crate::command::{Command, CommandRunner};
use crate::error::{Error, Result};
use crate::model::Protocol;
use std::net::Ipv4Addr;

/// One port Docker has published from a container onto this host, exactly as
/// its own DNAT rule in the `DOCKER` chain says — not as anything Docker
/// itself reports, since this module never asks Docker anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Published {
    /// The host address the rule restricts matching traffic to, via `-d`.
    /// `None` means the rule carries no `-d` at all: every interface, i.e.
    /// published on `0.0.0.0`.
    pub host_addr: Option<Ipv4Addr>,
    pub host_port: u16,
    pub protocol: Protocol,
    pub container_addr: Ipv4Addr,
    pub container_port: u16,
}

/// Read the `DOCKER` chain's own DNAT rules through `iptables -t nat -S
/// DOCKER`.
///
/// `iptables(8)`'s own DIAGNOSTICS section (this machine's installed man
/// page, `iptables v1.8.11 (nf_tables)`, quoted here rather than trusted
/// from memory) assigns exit `2` to invalid or abused command line
/// parameters, `3` to an incompatibility between kernel and user space, `4`
/// to a resource problem "such as a busy lock, failing memory allocation or
/// error messages from kernel", and `1` to "other errors". An absent chain —
/// "No chain/target/match by that name", the shape of a machine where Docker
/// has never run — falls in that last, catch-all class.
///
/// So exit `1` is the single non-zero status read as "nothing published",
/// reported exactly the way an installed-but-empty chain is: an empty `Vec`.
/// (The chain persists, declared but ruleless, for as long as the Docker
/// daemon runs with nothing published — captured live on this machine as `-N
/// DOCKER` with no `-A` lines at all, exit 0.)
///
/// Every other non-zero status is an `Err` — `2`, `3`, `4`, the `-1`
/// [`crate::command::RealRunner`] reports for a process killed by a signal,
/// and any code this function has no name for. The benign set is an
/// allowlist, not the complement of a denylist of known failures, because
/// the two differ exactly on the codes nobody anticipated; and for those,
/// "checked, and Docker touches nothing here" describes a read that did not
/// happen. That is worse here than a spurious error: a user told porthole
/// could not check knows to look, while a user told Docker is uninvolved
/// opens the port believing it.
///
/// One gap this does not close: exit `1` stays benign whatever its message
/// says. This function branches on the status alone, never on
/// locale-dependent error text, so a genuine failure that exits `1` is still
/// read as an empty chain.
pub fn published(runner: &dyn CommandRunner) -> Result<Vec<Published>> {
    /// The one non-zero exit read as "nothing to find" rather than "could
    /// not check" — `iptables(8)`'s catch-all, which an absent chain uses.
    const NO_SUCH_CHAIN: i32 = 1;

    let cmd = Command::read("iptables", ["-t", "nat", "-S", "DOCKER"]);
    let out = runner.run(&cmd)?;
    if out.success() {
        return parse_docker_chain(&out.stdout);
    }
    if out.status == NO_SUCH_CHAIN {
        return Ok(Vec::new());
    }
    Err(Error::CommandFailed {
        command: cmd.display(),
        status: out.status,
        stderr: out.stderr.trim().to_string(),
    })
}

/// `iptables -t nat -S DOCKER`, captured live from this machine's own
/// Docker (29.8.0, `iptables v1.8.10 (nf_tables)`) by publishing two real
/// containers — one on the daemon's default host address (this machine's
/// own `daemon.json` sets `"ip": "127.0.0.1"`, so an ordinary `-p 5432:80`
/// lands here), one explicitly on `-p 0.0.0.0:8080:80` — and reading the
/// chain back through a second, `--net=host` container (no host root was
/// used or needed: `docker run --net=host` reads the host's own netfilter
/// tables through the daemon's own existing privilege, the same as any
/// other Docker command).
///
/// Two things a fixture written from documentation, rather than captured,
/// got wrong here, and both are fixed by this capture rather than left for
/// this comment to merely flag:
///
/// - There is no `-A DOCKER -i docker0 -j RETURN` rule anywhere in this
///   version's `nat` table, checked both filtered to the `DOCKER` chain and
///   unfiltered (`iptables -t nat -S`) — the unfiltered read also showed a
///   second bridge network already on this machine (`br-...`, from an
///   unrelated project, no containers of this capture's own attached to it),
///   with no `RETURN` rule for it either. [`parse_docker_chain`] still skips
///   any line that is not a `-j DNAT --to-destination` rule regardless,
///   since other Docker versions are documented elsewhere as emitting one
///   and the parser must not choke on it if it ever appears.
/// - `-d 127.0.0.1/32` appears *before* `! -i docker0`, not after `-p tcp -m
///   tcp` as a hand-written guess placed it. [`parse_docker_chain`] finds
///   every flag by its own keyword — the same convention `net::
///   parse_neighbours` already uses for `ip neigh show` — so this position
///   never mattered to the parser; it matters to this fixture's own claim
///   to be real.
#[cfg(test)]
const DOCKER_CHAIN: &str = "\
-N DOCKER
-A DOCKER ! -i docker0 -p tcp -m tcp --dport 8080 -j DNAT --to-destination 172.17.0.2:80
-A DOCKER -d 127.0.0.1/32 ! -i docker0 -p tcp -m tcp --dport 5432 -j DNAT --to-destination 172.17.0.3:80
";

/// The token following `flag` in `tokens`, found by the flag's own keyword —
/// not by position. `iptables -S` does not print its flags in a fixed order
/// (see [`DOCKER_CHAIN`]'s own doc comment for a real example: `-d` moves
/// depending on rule shape), so a parse that assumed a fixed column would be
/// exactly as fragile here as it would for `ip neigh show`
/// (`net::parse_neighbours`).
fn flag_value<'a>(tokens: &[&'a str], flag: &str) -> Option<&'a str> {
    tokens
        .iter()
        .position(|&t| t == flag)
        .and_then(|i| tokens.get(i + 1).copied())
}

/// Parse `iptables -t nat -S DOCKER`'s text output into the ports it
/// actually publishes.
///
/// Only a rule that both jumps to `DNAT` and carries `--to-destination` is a
/// published port — the chain's own declaration (`-N DOCKER`) is not, and
/// neither is any other jump a rule in this chain might make (a `RETURN`
/// back to the caller, on Docker versions that still emit one; see
/// [`DOCKER_CHAIN`]'s own doc comment). A line that looks like it should be
/// a DNAT rule but is missing a piece this parser needs (an unparseable
/// port, a malformed destination) is skipped rather than failing the whole
/// read — the same policy `listening::parse_proc_net_tcp` applies to a
/// stray unparseable `/proc/net/tcp` row, for the same reason: one
/// unexpected line must not blank out every port this machine actually has
/// published.
fn parse_docker_chain(text: &str) -> Result<Vec<Published>> {
    let mut out = Vec::new();
    for line in text.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();

        // The actual jump check: a `RETURN` (or anything else) never carries
        // `-j DNAT`, so this alone would already exclude it, but checking the
        // target explicitly is what makes that true by construction rather
        // than by accident of which flags a non-DNAT rule happens to carry.
        if flag_value(&tokens, "-j") != Some("DNAT") {
            continue;
        }

        let Some(to_destination) = flag_value(&tokens, "--to-destination") else {
            continue;
        };
        let Some((container_addr, container_port)) = to_destination.split_once(':') else {
            continue;
        };
        let Ok(container_addr) = container_addr.parse::<Ipv4Addr>() else {
            continue;
        };
        let Ok(container_port) = container_port.parse::<u16>() else {
            continue;
        };

        let Some(dport) = flag_value(&tokens, "--dport") else {
            continue;
        };
        let Ok(host_port) = dport.parse::<u16>() else {
            continue;
        };

        let Some(proto_str) = flag_value(&tokens, "-p") else {
            continue;
        };
        let Ok(protocol) = crate::validate::parse_protocol(proto_str) else {
            continue;
        };

        // `-d 127.0.0.1/32` -- the mask is always present on a real rule but
        // is not part of the address itself. Absent `-d` entirely is `None`
        // (every interface); present but not a parseable IPv4 address is
        // `continue`d, *not* folded into that same `None` -- collapsing the
        // two would report a rule that is in fact restricted as reachable
        // from everywhere, the false-in-the-dangerous-direction mistake this
        // whole module exists to avoid. Nothing has been observed to trigger
        // this on this machine (only ever plain IPv4/32 addresses); it is
        // defensive.
        let host_addr = match flag_value(&tokens, "-d") {
            None => None,
            Some(d) => {
                let Some(ip) = d.split('/').next() else {
                    continue;
                };
                let Ok(addr) = ip.parse::<Ipv4Addr>() else {
                    continue;
                };
                Some(addr)
            }
        };

        out.push(Published {
            host_addr,
            host_port,
            protocol,
            container_addr,
            container_port,
        });
    }
    Ok(out)
}

/// What to tell someone opening `port`/`protocol` when Docker already has an
/// opinion about it — or nothing at all, when Docker has never heard of this
/// port. The silence in the ordinary case matters as much as the words in
/// the two exceptional ones: warning on every single open, docker-affected
/// or not, would train a user to skip the one message that actually matters.
pub fn advise(port: u16, protocol: Protocol, published: &[Published]) -> Option<String> {
    let entry = published
        .iter()
        .find(|p| p.host_port == port && p.protocol == protocol)?;

    Some(match entry.host_addr {
        // Restricted to loopback: Docker's own DNAT rule only matches
        // traffic already addressed to that one address, which nothing
        // outside this machine can ever send. Opening porthole's firewall
        // does not change that -- the firewall was never what was stopping
        // it, so nothing here should be read as a promise porthole can act
        // on this rule at all.
        Some(addr) if addr.is_loopback() => format!(
            "Docker already publishes {port}/{protocol} on {addr} -- not on this network. \
             Opening this port here does not make it reachable, because the firewall was \
             never what was stopping it. To publish it to the network instead, change the \
             port binding in your docker-compose.yml (or `docker run -p`) from \
             {addr}:{port}:... to 0.0.0.0:{port}:...; porthole cannot do that for you."
        ),
        Some(addr) => format!(
            "Docker already publishes {port}/{protocol} on {addr}: it is already reachable \
             from your network, and porthole cannot close it -- Docker's own iptables rules \
             are evaluated before firewalld's."
        ),
        None => format!(
            "Docker already publishes {port}/{protocol} on every interface (0.0.0.0): it is \
             already reachable from your network, and porthole cannot close it -- Docker's \
             own iptables rules are evaluated before firewalld's."
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn published_on_all(port: u16) -> Vec<Published> {
        vec![Published {
            host_addr: None,
            host_port: port,
            protocol: Protocol::Tcp,
            container_addr: "172.17.0.2".parse().unwrap(),
            container_port: 80,
        }]
    }

    fn published_on_loopback(port: u16) -> Vec<Published> {
        vec![Published {
            host_addr: Some(Ipv4Addr::LOCALHOST),
            host_port: port,
            protocol: Protocol::Tcp,
            container_addr: "172.17.0.3".parse().unwrap(),
            container_port: 80,
        }]
    }

    #[test]
    fn a_port_published_on_all_interfaces_is_recognised() {
        let found = parse_docker_chain(DOCKER_CHAIN).unwrap();
        let p = found.iter().find(|p| p.host_port == 8080).unwrap();
        assert_eq!(p.host_addr, None, "no -d means every interface");
    }

    #[test]
    fn a_port_published_on_loopback_carries_the_address_it_was_bound_to() {
        let found = parse_docker_chain(DOCKER_CHAIN).unwrap();
        let p = found.iter().find(|p| p.host_port == 5432).unwrap();
        assert_eq!(p.host_addr, Some("127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn the_chain_declaration_line_is_not_a_port() {
        // `DOCKER_CHAIN` is captured from a real Docker that emits no
        // `RETURN` rule at all (see its own doc comment) -- that case is
        // exercised separately, on a synthetic fixture, by
        // `a_non_dnat_line_such_as_return_is_silently_not_a_port` below.
        // This is the one fact the real capture can check directly: `-N
        // DOCKER` itself must never be counted alongside the two real DNAT
        // rules.
        let found = parse_docker_chain(DOCKER_CHAIN).unwrap();
        assert_eq!(found.len(), 2);
    }

    #[test]
    fn opening_a_port_docker_already_publishes_everywhere_explains_before_acting() {
        // The user asked to open something that is already open. Doing it
        // silently teaches them porthole controls a port it does not.
        let advice = advise(8080, Protocol::Tcp, &published_on_all(8080));
        assert!(advice.is_some());
        let text = advice.unwrap();
        assert!(text.contains("already reachable"));
        assert!(text.contains("porthole cannot close it"));
    }

    #[test]
    fn opening_a_port_docker_publishes_on_loopback_says_the_firewall_is_not_the_obstacle() {
        let advice = advise(5432, Protocol::Tcp, &published_on_loopback(5432)).unwrap();
        assert!(advice.contains("127.0.0.1"));
        assert!(advice.contains("compose"), "say what to change instead");
        assert!(
            !advice.contains("porthole will"),
            "do not promise a fix porthole cannot make"
        );
    }

    #[test]
    fn a_port_docker_does_not_touch_gets_no_advice_at_all() {
        // Noise on every open would train the user to skip the message that
        // matters.
        assert!(advise(5173, Protocol::Tcp, &[]).is_none());
    }

    #[test]
    fn a_protocol_mismatch_on_the_same_port_number_gets_no_advice() {
        // Docker publishes a *protocol*, not just a port number -- a UDP
        // service on the same port number as a container's TCP publish must
        // not borrow that container's advice.
        assert!(advise(8080, Protocol::Udp, &published_on_all(8080)).is_none());
    }

    #[test]
    fn a_non_dnat_line_such_as_return_is_silently_not_a_port() {
        // Exercises `parse_docker_chain`'s own `-j DNAT` check directly: some
        // Docker versions do emit a plain jump back to the caller for
        // traffic already on docker0 (this machine's own capture,
        // `DOCKER_CHAIN`'s own doc comment, does not), and it must never be
        // mistaken for a published port.
        let text = "\
-N DOCKER
-A DOCKER -i docker0 -j RETURN
-A DOCKER ! -i docker0 -p tcp -m tcp --dport 8080 -j DNAT --to-destination 172.17.0.2:80
";
        let found = parse_docker_chain(text).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].host_port, 8080);
    }

    #[test]
    fn an_unparseable_d_address_skips_the_rule_rather_than_reading_it_as_unrestricted() {
        // If `-d` is present but is not a plain IPv4 address (never actually
        // observed on this machine's own `DOCKER` chain -- purely
        // defensive), folding that into the same `None` this parser uses for
        // "no `-d` at all" would report a rule that is in fact restricted as
        // reachable from every interface: the exact false-in-the-dangerous-
        // direction mistake this whole module exists to avoid. Skipping the
        // rule entirely is the safe reading instead.
        let text = "\
-N DOCKER
-A DOCKER -d not-an-address/32 ! -i docker0 -p tcp -m tcp --dport 8080 -j DNAT --to-destination 172.17.0.2:80
";
        assert!(parse_docker_chain(text).unwrap().is_empty());
    }

    #[test]
    fn published_reads_an_empty_chain_as_no_ports_not_an_error() {
        use crate::command::{Output, RecordingRunner};
        // Captured live on this machine while the Docker daemon was running
        // with no container publishing anything: `-N DOCKER` with no `-A`
        // lines at all, exit 0.
        let runner = RecordingRunner::with_responses(vec![Output::stdout("-N DOCKER\n")]);
        assert!(published(&runner).unwrap().is_empty());
    }

    #[test]
    fn published_reads_a_missing_chain_as_no_ports_not_an_error() {
        use crate::command::{Output, RecordingRunner};
        // The shape for "Docker has never run here": the command exits
        // non-zero because the chain does not exist at all. `published`
        // branches on the exit status alone, not the message, so the exact
        // wording below is a plausible stand-in, not something captured on
        // this machine (which has Docker installed and could not exercise
        // this case for real -- see `published`'s own doc comment).
        let runner = RecordingRunner::with_responses(vec![Output::failure(
            "iptables: No chain/target/match by that name.",
        )]);
        assert!(published(&runner).unwrap().is_empty());
    }

    #[test]
    fn published_propagates_a_resource_problem_rather_than_reading_it_as_no_docker() {
        use crate::command::{Output, RecordingRunner};
        // Real output, captured directly on this machine (no container
        // involved -- this is what an ordinary, unprivileged shell gets):
        // `iptables -t nat -S DOCKER` as a non-root user. `iptables(8)`'s own
        // DIAGNOSTICS section documents exit 4 as its resource-problem code,
        // which this is -- a real failure to check, not evidence that Docker
        // has nothing published. Folding it into the same empty result as
        // "no such chain" would report `docker_checked: true` with nothing
        // to show for a machine porthole simply could not read -- exactly
        // the confident-looking wrong answer this module exists to avoid.
        let runner = RecordingRunner::with_responses(vec![Output {
            status: 4,
            stdout: String::new(),
            stderr: "iptables v1.8.11: Could not fetch rule set generation id: \
                     Permission denied (you must be root)"
                .to_string(),
        }]);
        let err = published(&runner).unwrap_err();
        assert!(err.to_string().contains("status 4"), "got: {err}");
    }

    #[test]
    fn published_propagates_a_kernel_userspace_mismatch_rather_than_reading_it_as_no_docker() {
        use crate::command::{Output, RecordingRunner};
        // `iptables(8)` documents exit 3 for "an incompatibility between
        // kernel and user space" -- the iptables/nftables mismatch porthole's
        // own README warns about. Not reproduced on this machine: the status
        // and message below are constructed to the documented shape, and what
        // this test pins is `published`'s branch on the status, which is the
        // part that was wrong.
        //
        // Reading this as an empty chain would tell a user Docker publishes
        // nothing on a machine porthole could not read at all, and they would
        // open the port believing it.
        let runner = RecordingRunner::with_responses(vec![Output {
            status: 3,
            stdout: String::new(),
            stderr: "iptables v1.8.11 (nf_tables): Incompatible with this kernel".to_string(),
        }]);
        let err = published(&runner).unwrap_err();
        assert!(err.to_string().contains("status 3"), "got: {err}");
    }

    #[test]
    fn published_propagates_a_signal_killed_read_rather_than_reading_it_as_no_docker() {
        use crate::command::{Output, RecordingRunner};
        // A process killed by a signal has no exit code, and
        // `command::RealRunner` maps that absence to -1. It is not a status
        // `iptables(8)` documents at all, which is the point: an allowlist of
        // benign codes has to reject what it has no name for.
        let runner = RecordingRunner::with_responses(vec![Output {
            status: -1,
            stdout: String::new(),
            stderr: String::new(),
        }]);
        let err = published(&runner).unwrap_err();
        assert!(err.to_string().contains("status -1"), "got: {err}");
    }

    #[test]
    fn published_reads_only_exit_one_as_an_absent_chain() {
        use crate::command::{Output, RecordingRunner};
        // The allowlist itself, stated as a test rather than only as prose:
        // 1 is benign, every other non-zero status this loop tries is an
        // error. 2, 3 and 4 are `iptables(8)`'s documented codes; -1 is a
        // signal kill; 5 and 127 stand for codes with no documented meaning
        // here -- 127 being what a shell reports for a missing binary.
        for status in [-1, 2, 3, 4, 5, 127] {
            let runner = RecordingRunner::with_responses(vec![Output {
                status,
                stdout: String::new(),
                stderr: String::new(),
            }]);
            assert!(
                published(&runner).is_err(),
                "exit {status} must not be read as an absent chain"
            );
        }

        let runner = RecordingRunner::with_responses(vec![Output::failure(
            "iptables: No chain/target/match by that name.",
        )]);
        assert!(
            published(&runner).unwrap().is_empty(),
            "exit 1 stays benign"
        );
    }
}
