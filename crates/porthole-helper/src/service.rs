//! The privileged object clients talk to.
//!
//! Every method follows the same shape, and the order is deliberate:
//!
//! 1. **Validate**, treating everything the client sent as untrusted. The
//!    helper never accepts a rule string and never acts on a value it would
//!    not have accepted from a person.
//! 2. **Resolve the scope**, because which polkit action applies depends on
//!    what the request actually amounts to — `0.0.0.0/0` is "everyone"
//!    however it was spelled.
//! 3. **Authorize**, before touching anything.
//! 4. **Take the state lock and act.** Not before: a polkit check can block
//!    for as long as a human takes to type a password, and the lock would
//!    stall every other writer for that whole time.
//! 5. **Log to the journal with the requesting uid**, which comes from the bus
//!    daemon rather than from the client.

use crate::authz::{caller_uid, Action, Authorizer, Details};
use crate::error::HelperError;
use porthole_core::backend::{self, BackendHealth, BackendId};
use porthole_core::clock::SystemClock;
use porthole_core::command::RealRunner;
use porthole_core::engine::{is_open_any, resolve_scope, Engine, Status};
use porthole_core::error::Error;
use porthole_core::ipc::{WireDockerPort, WireError, WireRule, WireStatus};
use porthole_core::model::Lifetime;
use porthole_core::net;
use porthole_core::state::StateStore;
use porthole_core::validate;
use std::path::PathBuf;

static SYSTEM_CLOCK: SystemClock = SystemClock;

pub struct Porthole {
    authorizer: Box<dyn Authorizer>,
    /// A second connection to the same bus, used only to ask the daemon which
    /// uid is behind a caller's name. Separate from the connection the object
    /// is served on, which the builder owns.
    bus: zbus::Connection,
    state_path: PathBuf,
    executable: PathBuf,
}

impl Porthole {
    pub fn new(
        authorizer: Box<dyn Authorizer>,
        bus: zbus::Connection,
        state_path: PathBuf,
        executable: PathBuf,
    ) -> Self {
        Porthole {
            authorizer,
            bus,
            state_path,
            executable,
        }
    }
}

#[zbus::interface(name = "com.jacopobriccola.Porthole1")]
impl Porthole {
    /// `scope` is what the user typed — `subnet`, `any`, a CIDR, an IP — and
    /// the helper parses it itself. `seconds` is 0 for until-reboot.
    async fn open(
        &self,
        port: u16,
        protocol: &str,
        scope: &str,
        seconds: u32,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> Result<WireRule, HelperError> {
        // 1. Validate. Nothing the client sent is trusted.
        if port == 0 {
            return Err(HelperError::InvalidArgument(
                "port 0 is not a port; valid ports are 1-65535".to_string(),
            ));
        }
        let protocol = validate::parse_protocol(protocol).map_err(HelperError::from)?;
        let spec = validate::parse_scope(scope).map_err(HelperError::from)?;
        let lifetime = if seconds == 0 {
            Lifetime::UntilReboot
        } else {
            Lifetime::For(
                validate::parse_duration(&format!("{seconds}s")).map_err(HelperError::from)?,
            )
        };

        // 2. Resolve before choosing the action, and before taking any lock.
        let runner = RealRunner;
        let target = resolve_scope(&runner, &spec).map_err(HelperError::from)?;
        // Whether this amounts to the same exposure as "everyone" depends on
        // the local network, not just on how the target was spelled: a
        // network broader than the local subnet, or one this machine is not
        // even on, is not "the network you are on" no matter what the client
        // called it. `Ok()` on failure, not `?`: not being on a network is a
        // fact `is_open_any` already treats as the safe (stronger) direction,
        // not a reason to fail the whole request before authorization.
        let local = net::current_network(&runner).ok();
        let action = if is_open_any(&target, local.as_ref()) {
            Action::OpenAny
        } else {
            Action::OpenSubnet
        };
        // What the polkit dialog's `$(key)` substitutions can show: the port,
        // protocol and resolved target, so a person can tell an expected
        // prompt from an unexpected one rather than reading a static
        // sentence that could belong to any request.
        let details = crate::polkit::open_details(port, protocol, &target);

        // 3. Authorize.
        self.authorizer
            .check(action, &details, &header)
            .await
            .map_err(HelperError::from)?;

        let uid = caller_uid(&self.bus, &header)
            .await
            .map_err(HelperError::from)?;

        // 4. Only now take the lock and act.
        let backend = backend::detect(&runner).map_err(HelperError::from)?;
        let state = StateStore::open_exclusive(&self.state_path).map_err(HelperError::from)?;
        let mut engine = Engine::new(
            backend.as_ref(),
            &runner,
            &SYSTEM_CLOCK,
            state,
            self.executable.clone(),
        );
        let rule = engine
            .open(port, protocol, &spec, lifetime, uid)
            .map_err(HelperError::from)?;

        // 5. The journal. The helper is a system service, so stderr lands there.
        eprintln!(
            "porthole: uid={} opened {}/{} towards {} until {}",
            rule.uid,
            rule.port,
            rule.protocol,
            rule.target,
            rule.expires_at
                .map(|t| t.to_string())
                .unwrap_or_else(|| "reboot".to_string())
        );

        Ok(WireRule::from_rule(&rule))
    }

    async fn close(
        &self,
        port: u16,
        protocol: &str,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> Result<WireRule, HelperError> {
        let protocol = validate::parse_protocol(protocol).map_err(HelperError::from)?;
        self.authorizer
            .check(Action::Close, &Details::new(), &header)
            .await
            .map_err(HelperError::from)?;

        // The audit trail names who asked for *this* close, which is not
        // necessarily who opened the rule: `close` is `yes` in the polkit
        // policy, reachable by any local user with no prompt at all, which is
        // exactly why it is the one operation where recording the requester
        // matters most.
        let closed_by = caller_uid(&self.bus, &header)
            .await
            .map_err(HelperError::from)?;

        let runner = RealRunner;
        let backend = backend::detect(&runner).map_err(HelperError::from)?;
        let state = StateStore::open_exclusive(&self.state_path).map_err(HelperError::from)?;
        let mut engine = Engine::new(
            backend.as_ref(),
            &runner,
            &SYSTEM_CLOCK,
            state,
            self.executable.clone(),
        );
        let rule = engine
            .close_by_port(port, protocol, false)
            .map_err(HelperError::from)?;
        Self::log_close(&rule, closed_by, false);
        Ok(WireRule::from_rule(&rule))
    }

    /// `from_timer` is a claim the client makes about itself, accepted rather
    /// than independently verified. It is safe to accept: the only thing it
    /// changes is (a) whether this close also tries to stop the very timer
    /// unit that is calling it, and (b) the `, expired` marker in the journal
    /// line below. A client that lies and says `true` when it is not the
    /// timer merely skips cancelling a timer that either does not exist or
    /// was going to fire and find nothing anyway; a client that lies and says
    /// `false` merely leaves a stray timer behind, which fires later, finds
    /// no such rule, and exits. Neither lie reaches the firewall, the state
    /// file, or authorization above.
    async fn close_by_id(
        &self,
        id: &str,
        from_timer: bool,
        forget: bool,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> Result<WireRule, HelperError> {
        self.authorizer
            .check(Action::Close, &Details::new(), &header)
            .await
            .map_err(HelperError::from)?;

        let closed_by = caller_uid(&self.bus, &header)
            .await
            .map_err(HelperError::from)?;

        let runner = RealRunner;
        let backend = backend::detect(&runner).map_err(HelperError::from)?;
        let state = StateStore::open_exclusive(&self.state_path).map_err(HelperError::from)?;
        let mut engine = Engine::new(
            backend.as_ref(),
            &runner,
            &SYSTEM_CLOCK,
            state,
            self.executable.clone(),
        );
        let rule = engine
            .close_by_id(id, from_timer, forget)
            .map_err(HelperError::from)?;
        // `forget` never touched any firewall -- `Engine::forget_rule`
        // refuses it for anything a real close could still reach -- so the
        // journal must not say "closed", which `format_close_log` always
        // does. A different, explicit line for a different, explicit action.
        if forget {
            Self::log_forget(&rule, closed_by);
        } else {
            Self::log_close(&rule, closed_by, from_timer);
        }
        Ok(WireRule::from_rule(&rule))
    }

    /// Returns what closed and, separately, the failures — so one stuck rule
    /// cannot hide the others.
    async fn close_all(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> Result<(Vec<WireRule>, Vec<WireError>), HelperError> {
        self.authorizer
            .check(Action::Close, &Details::new(), &header)
            .await
            .map_err(HelperError::from)?;

        let closed_by = caller_uid(&self.bus, &header)
            .await
            .map_err(HelperError::from)?;

        let runner = RealRunner;
        let backend = backend::detect(&runner).map_err(HelperError::from)?;
        let state = StateStore::open_exclusive(&self.state_path).map_err(HelperError::from)?;
        let mut engine = Engine::new(
            backend.as_ref(),
            &runner,
            &SYSTEM_CLOCK,
            state,
            self.executable.clone(),
        );
        // `close --all` is never what the expiry timer invokes -- it always
        // closes a single rule by id -- so there is no `from_timer` to thread
        // through here.
        let (closed, errors) = engine.close_all(false);
        for rule in &closed {
            Self::log_close(rule, closed_by, false);
        }
        Ok((
            closed.iter().map(WireRule::from_rule).collect(),
            // Structured, not `.to_string()`'d away: a script must not be
            // able to tell a `close --all` failure over the bus apart from
            // the same failure reported locally, and a bare string discards
            // exactly the `kind` and exit code that comparison needs.
            errors
                .iter()
                .map(|e| WireError {
                    message: e.to_string(),
                    kind: e.kind().to_string(),
                    code: e.exit_code() as i32,
                })
                .collect(),
        ))
    }

    async fn list(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> Result<Vec<WireRule>, HelperError> {
        self.authorizer
            .check(Action::List, &Details::new(), &header)
            .await
            .map_err(HelperError::from)?;
        // Read-only: the plain constructor, so a reader never blocks behind a
        // writer and never creates the state directory.
        let state = StateStore::open(&self.state_path).map_err(HelperError::from)?;
        Ok(state.rules().iter().map(WireRule::from_rule).collect())
    }

    async fn status(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> Result<WireStatus, HelperError> {
        self.authorizer
            .check(Action::List, &Details::new(), &header)
            .await
            .map_err(HelperError::from)?;

        let runner = RealRunner;
        // Mirrors `porthole-cli`'s own `run.rs::Commands::Status` handling,
        // which a prior review already fixed this same collapse in: a
        // backend that could not be *detected* at all (a machine with no
        // firewall installed is the common case, but not the only one) is a
        // different, confirmed fact from one that was detected but could not
        // be *read* (`BackendHealth::active_unknown`'s own case) -- and it
        // must reach the wire as that fact, not as a bare method error. Left
        // as a `?` propagating through `HelperError`, this `detect` failure
        // became indistinguishable, on every client, from "the helper itself
        // could not be reached" -- exactly the collapse the GUI's own
        // `StatusBar` was caught rendering: a confirmed "no firewall" status,
        // wrapped in "could not reach the porthole helper". Synthesizing a
        // `Status` here, the same shape `run.rs` already does locally, means
        // every client -- this GUI and any future one -- renders the real
        // fact instead of each rediscovering the trap.
        let status = match backend::detect(&runner) {
            Ok(backend) => {
                // Read-only open: `Engine::status` reconciles read-only
                // (`SweepMode::ReadOnly`), so it never saves and never
                // touches the firewall -- see `reconcile.rs`. status must
                // not block behind a writer either, which is the other
                // reason this is the plain, non-exclusive open.
                let state = StateStore::open(&self.state_path).map_err(HelperError::from)?;
                let mut engine = Engine::new(
                    backend.as_ref(),
                    &runner,
                    &SYSTEM_CLOCK,
                    state,
                    self.executable.clone(),
                );
                engine.status().map_err(HelperError::from)?
            }
            Err(e) => status_for_undetected_backend(
                &e,
                net::current_network(&runner).ok(),
                StateStore::open(&self.state_path)
                    .map_err(HelperError::from)?
                    .rules()
                    .to_vec(),
            ),
        };
        Ok(WireStatus::from_status(&status))
    }

    /// Every port Docker currently has published, read from the `DOCKER`
    /// chain in the `nat` table -- see `porthole_core::docker`'s own module
    /// doc for why this needs to live behind the helper at all: reading the
    /// `nat` table needs root, which an unprivileged CLI process does not
    /// have. Gated on `Action::List`, exactly as unprivileged a read as
    /// `list`/`status` already are -- there is nothing here a caller could
    /// use to change anything.
    async fn docker_ports(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> Result<Vec<WireDockerPort>, HelperError> {
        self.authorizer
            .check(Action::List, &Details::new(), &header)
            .await
            .map_err(HelperError::from)?;

        let runner = RealRunner;
        let published = porthole_core::docker::published(&runner).map_err(HelperError::from)?;
        Ok(published
            .iter()
            .map(WireDockerPort::from_published)
            .collect())
    }
}

impl Porthole {
    /// `closed_by` is the uid that asked for *this* close — not necessarily
    /// `rule.uid`, since any local user may close any rule. `from_timer`
    /// controls only the trailing `, expired` marker: milestone 1 added it so
    /// a timer-triggered close reads differently in the journal from one a
    /// person asked for, and it must survive the request now crossing the bus
    /// rather than being handled in-process.
    fn log_close(rule: &porthole_core::state::ManagedRule, closed_by: u32, from_timer: bool) {
        eprintln!("{}", format_close_log(rule, closed_by, from_timer));
    }

    /// The `--forget` audit line: distinct from [`Porthole::log_close`]
    /// because nothing was closed -- `Engine::forget_rule` only ever runs
    /// for a rule recorded under a backend this machine no longer has, and
    /// removes porthole's own record of it without touching any firewall.
    fn log_forget(rule: &porthole_core::state::ManagedRule, forgotten_by: u32) {
        eprintln!(
            "porthole: forgot {}/{} towards {} (recorded under backend {}, opened by uid={}, \
             forgotten by uid={}) -- no firewall was touched",
            rule.port, rule.protocol, rule.target, rule.backend, rule.uid, forgotten_by
        );
    }
}

/// The `Status` a `detect` failure becomes on the wire -- split out from
/// [`Porthole::status`] so this mapping is testable without a real bus, a
/// real backend, or root (`tests/service.rs`'s own end-to-end suite runs
/// against whatever firewall this machine actually has, which cannot be
/// made to fail `detect` on demand). `error` is `detect`'s own error,
/// verbatim, as `BackendHealth::detail` -- never reworded, and never
/// silently reaching a client as "could not reach the helper": see
/// [`Porthole::status`]'s own comment for the collapse this exists to
/// avoid. `network` and `rules` are supplied by the caller rather than
/// looked up here, since neither depends on whether a backend was
/// detected -- the network probe and the state file are both independent
/// of that.
fn status_for_undetected_backend(
    error: &Error,
    network: Option<porthole_core::net::LocalNetwork>,
    rules: Vec<porthole_core::state::ManagedRule>,
) -> Status {
    Status {
        backend: BackendId::Firewalld,
        health: BackendHealth {
            available: false,
            active: false,
            // A backend that could not even be detected is not the same
            // fact as one that was detected and could not be read -- see
            // `active_unknown`'s own doc comment. `detect` failing this
            // way means no backend was ever available to ask, so there is
            // nothing left unresolved to call "unknown".
            active_unknown: false,
            version: None,
            detail: error.to_string(),
            caveat: None,
        },
        network,
        location: None,
        rules,
    }
}

/// Split out from [`Porthole::log_close`] so the line itself is testable
/// without capturing stderr from a live process.
fn format_close_log(
    rule: &porthole_core::state::ManagedRule,
    closed_by: u32,
    from_timer: bool,
) -> String {
    format!(
        "porthole: closed {}/{} towards {} (opened by uid={}, closed by uid={}){}",
        rule.port,
        rule.protocol,
        rule.target,
        rule.uid,
        closed_by,
        if from_timer { ", expired" } else { "" }
    )
}

// `Box<dyn Authorizer>` from an Arc, so tests can keep a handle on what the
// authorizer was asked while the service owns it.
#[async_trait::async_trait]
impl Authorizer for std::sync::Arc<crate::authz::AlwaysAllow> {
    async fn check(
        &self,
        action: Action,
        details: &crate::authz::Details,
        header: &zbus::message::Header<'_>,
    ) -> Result<(), Error> {
        (**self).check(action, details, header).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use porthole_core::backend::{BackendId, RuleHandle};
    use porthole_core::model::{Protocol, Target};
    use porthole_core::state::ManagedRule;

    fn rule(opener_uid: u32) -> ManagedRule {
        ManagedRule {
            id: "abc".to_string(),
            port: 5173,
            protocol: Protocol::Tcp,
            target: Target::Network {
                cidr: "10.10.10.0/24".parse().unwrap(),
            },
            backend: BackendId::Firewalld,
            opened_at: 1_757_000_000,
            expires_at: None,
            uid: opener_uid,
            handle: RuleHandle::Firewalld {
                zone: "FedoraWorkstation".to_string(),
                rich_rule: "rule ...".to_string(),
            },
        }
    }

    #[test]
    fn the_close_line_names_both_uids_when_they_differ() {
        // I1: `close`, `close_by_id` and `close_all` must all log who *asked*
        // for the close, separately from who *opened* the rule — a test
        // where the two happen to be the same value would pass even if the
        // closer's uid were never wired in at all.
        let line = format_close_log(&rule(1000), 1001, false);
        assert!(line.contains("opened by uid=1000"), "got: {line}");
        assert!(line.contains("closed by uid=1001"), "got: {line}");
    }

    #[test]
    fn a_timer_triggered_close_carries_the_expired_marker() {
        // Milestone 1 added `, expired` so a close the timer fired reads
        // differently in the journal from one a person asked for. I2 wires
        // `from_timer` back across the bus so this survives the move to the
        // helper.
        let line = format_close_log(&rule(1000), 1000, true);
        assert!(line.ends_with(", expired"), "got: {line}");
    }

    #[test]
    fn a_human_initiated_close_carries_no_expired_marker() {
        let line = format_close_log(&rule(1000), 1000, false);
        assert!(!line.contains("expired"), "got: {line}");
    }

    #[test]
    fn an_undetected_backend_reports_as_no_firewall_not_as_a_bare_error() {
        // C1: `Porthole::status` used to `?`-propagate a `detect` failure
        // straight through `HelperError`, indistinguishable, on the one
        // client that exists today (the GUI), from "the helper itself
        // could not be reached" -- a confirmed "no firewall" collapsed into
        // an absence of information, the milestone-3 defect run backwards.
        let error = Error::BackendUnavailable(
            "no firewall found: none of firewalld, ufw or nftables is installed. \
             Without a firewall this port is already reachable from your network."
                .to_string(),
        );
        let status = status_for_undetected_backend(&error, None, Vec::new());
        assert!(
            !status.health.available,
            "a detect failure must report available: false"
        );
        assert!(!status.health.active);
        assert!(
            !status.health.active_unknown,
            "no backend was ever available to ask, so there is nothing left unresolved to \
             call \"unknown\""
        );
        assert!(
            status.health.detail.contains("already reachable"),
            "detect's own message must survive verbatim, not be reworded: {}",
            status.health.detail
        );

        // The fact this whole change exists to put on the wire correctly:
        // `firewall_available: false`, not a bare method error a client
        // could fold into "could not reach the helper at all".
        let wire = WireStatus::from_status(&status);
        assert!(!wire.firewall_available);
        assert!(
            wire.firewall_version.is_empty(),
            "no version was ever read for a backend that was never detected"
        );
    }
}
