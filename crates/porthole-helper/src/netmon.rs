//! Notices when the machine's subnet changes, so a rule scoped to one is
//! closed rather than left open, re-aimed at the new network, or reported as
//! still valid when it is not.
//!
//! `org.freedesktop.NetworkManager`'s `StateChanged` signal fires on connect
//! and disconnect, not when the machine stays connected but roams onto a
//! different subnet on the same interface -- a new access point, or a fresh
//! DHCP lease -- which is exactly the case porthole's CIDR-scoped rules are
//! exposed to. So the signal here is only ever a prompt to look again: every
//! wake-up re-resolves the current subnet and compares it against the subnet
//! this module last saw. Two wake-up sources feed the same check, so a
//! machine with no NetworkManager is still covered: `StateChanged` when
//! NetworkManager answers on the bus, and a fixed-interval poll that does not
//! depend on NetworkManager at all.
//!
//! # What "the subnet this module last saw" means, and what it does not
//!
//! `ManagedRule` records the resolved `Target` a rule was opened towards, not
//! the `ScopeSpec` that produced it -- there is no stored fact distinguishing
//! "opened towards whatever subnet I'm on" from "opened towards this exact
//! CIDR, deliberately". [`porthole_core::engine::Engine::close_rules_outside`]
//! is built around that limit rather than against it: it closes a rule when
//! the rule's own CIDR sits inside the subnet that was just lost, not when
//! the rule's CIDR merely differs from the new one -- see its own doc
//! comment for the case that distinction protects.
//!
//! A consequence of the same limit: this module cannot tell "a rule scoped
//! to 10.10.10.0/24, tied to the machine being on 10.10.10.0/24" apart from
//! "a rule scoped to 10.10.10.0/24, deliberately, wherever the machine is"
//! until the machine actually leaves 10.10.10.0/24 -- at which point both
//! close, because from this module's own vantage point they are the same
//! fact. Before that point, on the very first wake-up after the helper
//! starts, this module has not yet observed any subnet at all, so it
//! records whatever it finds and closes nothing: there is no way to prove a
//! rule already in the state file is tied to a subnet nothing here has ever
//! seen.
//!
//! # This module's own lifetime
//!
//! `main` spawns [`run`] onto the same runtime that serves the D-Bus
//! interface and never awaits it there. Nothing in the helper exits the
//! process early on its own -- there is no idle timeout and no
//! "last-rule-closed" shutdown -- so [`run`] lives exactly as long as the
//! process does, no more and no less. That is not the same as covering
//! every open rule continuously: a crash, an OOM kill, a plain `systemctl
//! stop`, or a package `try-restart` ends the process (and this module with
//! it) while `RuntimeDirectoryPreserve=yes` keeps the state file and the
//! firewall keeps every rule, and nothing restarts the helper until a
//! client next addresses the bus name -- see `data/porthole-helper.service`'s
//! own comment on why `Restart=` is not set there. Automatic close
//! (`porthole_core::expiry`) does not share this gap: it is a systemd
//! transient timer that lives outside this process, so a helper restart
//! cannot lose it. A network change this module would have caught can be
//! lost that way.

use crate::service::Porthole;
use ipnet::Ipv4Net;
use porthole_core::backend;
use porthole_core::clock::SystemClock;
use porthole_core::command::{CommandRunner, RealRunner};
use porthole_core::engine::Engine;
use porthole_core::error::Error;
use porthole_core::ipc::{CloseReason, PATH};
use porthole_core::net;
use porthole_core::state::{ManagedRule, StateStore};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;
use zbus::object_server::SignalEmitter;

/// How often the fallback poll re-checks the subnet. Two read-only `ip`
/// commands, cheap enough to repeat this often; long enough that it is rare,
/// short enough that a roam NetworkManager itself misses (or a machine with
/// no NetworkManager at all) is still noticed within about a minute.
const POLL_INTERVAL: Duration = Duration::from_secs(60);

/// Test-only opt-in that makes the monitor run under `--session` too.
/// Honoured in debug builds only, the same rule
/// `porthole_core::state::STATE_FILE_ENV` follows: a release binary runs
/// privileged and must not take behaviour from the environment. See
/// [`should_run`] for what the pair of conditions is actually for.
pub const NETMON_ENV: &str = "PORTHOLE_NETMON";

/// Whether [`run`] should be spawned at all.
///
/// The monitor closes rules in whatever firewall this machine actually has,
/// on its own timer, with no client asking. What decides whether that is
/// acceptable is not which bus the helper is on, it is whether the firewall
/// is disposable.
///
/// A production helper is on the system bus, and its firewall is the one it
/// is meant to manage: it runs. `--session` is the test-only mode, and a
/// `--session` helper started on a developer's own machine talks to that
/// machine's real firewall, so it does not -- see
/// `crates/porthole-cli/tests/helper_e2e.rs`, which spawns exactly that. A
/// `--session` helper inside a disposable container has a firewall of its
/// own that nothing outside the container shares, and says so by setting
/// [`NETMON_ENV`]; `crates/porthole-cli/tests/container.rs` is the only
/// thing in this workspace that does.
pub fn should_run(session: bool) -> bool {
    decide(
        session,
        std::env::var_os(NETMON_ENV).is_some(),
        cfg!(debug_assertions),
    )
}

/// [`should_run`] with the environment and the build profile as plain
/// values, so both halves -- including the one a test binary can never be
/// (`debug_build: false`) -- are testable without touching either.
fn decide(session: bool, opted_in: bool, debug_build: bool) -> bool {
    !session || (debug_build && opted_in)
}

static SYSTEM_CLOCK: SystemClock = SystemClock;

/// The subnet [`wake_up_blocking`] last resolved successfully. `None` before
/// the first successful resolution, and again after a resolution finds no
/// network at all -- both share the same status: nothing to prove a rule in
/// the state file is tied to. Read and written only from [`wake_up_blocking`]
/// (always inside `spawn_blocking`, never concurrently with a unit test):
/// [`check_network`] takes and returns this value as a plain parameter
/// instead of touching the static directly, precisely so it stays testable
/// without one test's run colliding with another's through shared state.
static LAST_KNOWN_SUBNET: Mutex<Option<Ipv4Net>> = Mutex::new(None);

#[zbus::proxy(
    interface = "org.freedesktop.NetworkManager",
    default_service = "org.freedesktop.NetworkManager",
    default_path = "/org/freedesktop/NetworkManager"
)]
trait NetworkManager {
    /// The `u` payload is never read -- see the module docs for why this
    /// signal is only ever a prompt to look again, never a description of
    /// what changed.
    #[zbus(signal)]
    fn state_changed(&self, state: u32) -> zbus::Result<()>;
}

/// What one wake-up decided.
struct CheckOutcome {
    /// Rules closed because they no longer belong to the network the machine
    /// is on.
    closed: Vec<ManagedRule>,
    /// `(old_cidr, new_cidr)` for the `NetworkChanged` signal, in the wire
    /// format's own convention -- empty string for "no usable network" --
    /// or `None` when nothing changed enough to report (including the
    /// "first observation" and "still on the same subnet" cases).
    transition: Option<(String, String)>,
    /// What [`LAST_KNOWN_SUBNET`] should hold after this wake-up.
    last_known: Option<Ipv4Net>,
    /// Records the engine's own reconciliation dropped while this wake-up was
    /// closing things -- rules the firewall no longer had at all. Nothing to
    /// do with the network changing; collected here because this is the one
    /// place that holds the engine, and announced as
    /// [`CloseReason::Reconciled`], never as a network-change close. See
    /// [`porthole_core::engine::Engine::take_reconciled`].
    reconciled: Vec<ManagedRule>,
}

/// Re-resolve the current subnet, decide what changed relative to `previous`,
/// and close whatever no longer belongs to what was there before.
///
/// Split out from [`wake_up_blocking`] so the decision is testable without a
/// bus, a timer, or root: everything here is exactly the seam
/// `porthole_core::engine`'s own tests already use, plus `previous` as a
/// plain value rather than the module's own tracked state.
///
/// A resolution failure other than [`Error::NoNetwork`] (a spawned `ip` that
/// could not run, a non-zero exit, a malformed JSON body) leaves `previous`
/// and every rule untouched: the current subnet is simply unknown for this
/// one wake-up, not confirmed absent, and treating every such failure as
/// "no network" would close every subnet-scoped rule on a parse error alone.
/// Only [`Error::NoNetwork`] -- porthole's own confirmed "no default route"
/// or "no global address" -- means there is genuinely no network right now,
/// and that closes every subnet-scoped rule regardless of `previous`: unlike
/// "the subnet changed", "there is no network" needs no prior observation to
/// be true.
fn check_network(
    engine: &mut Engine<'_>,
    runner: &dyn CommandRunner,
    previous: Option<Ipv4Net>,
) -> CheckOutcome {
    let mut outcome = match net::current_network(runner) {
        Ok(network) => match previous {
            Some(lost) if lost != network.cidr => CheckOutcome {
                closed: engine.close_rules_outside(lost),
                transition: Some((lost.to_string(), network.cidr.to_string())),
                last_known: Some(network.cidr),
                reconciled: Vec::new(),
            },
            _ => CheckOutcome {
                closed: Vec::new(),
                transition: None,
                last_known: Some(network.cidr),
                reconciled: Vec::new(),
            },
        },
        Err(Error::NoNetwork(_)) => CheckOutcome {
            closed: engine.close_rules_on_network_loss(),
            transition: previous.map(|lost| (lost.to_string(), String::new())),
            last_known: None,
            reconciled: Vec::new(),
        },
        Err(_) => CheckOutcome {
            closed: Vec::new(),
            transition: None,
            last_known: previous,
            reconciled: Vec::new(),
        },
    };
    // Taken after the match, not inside it: only the two arms that close
    // anything reconcile at all, and this way a third arm added later cannot
    // silently drop what its own sweep found.
    outcome.reconciled = engine.take_reconciled();
    outcome
}

/// One wake-up's synchronous half: detect the backend, take the state lock,
/// run [`check_network`]. Runs only inside `tokio::task::spawn_blocking` (see
/// [`wake_up`]) -- `backend::detect`'s subprocesses, the state lock's own
/// bounded retry loop, and a `close` that can sit on firewalld's polkit
/// timeout are all real blocking work, and this crate already documents why
/// that must never run on an async worker thread
/// (`porthole_core::state`'s own `LOCK_TIMEOUT` doc comment).
fn wake_up_blocking(state_path: &Path, executable: &Path) -> CheckOutcome {
    let previous = *LAST_KNOWN_SUBNET.lock().expect("not poisoned");
    let unchanged = CheckOutcome {
        reconciled: Vec::new(),
        closed: Vec::new(),
        transition: None,
        last_known: previous,
    };

    // Nothing recorded means nothing a network change could invalidate --
    // skip the two `ip` reads on every idle tick, not only the close itself.
    // An unreadable state file is a different fact from an empty one, so it
    // does not take this shortcut; the detect/lock attempts below fail
    // loudly (and harmlessly) on their own in that case instead.
    if let Ok(state) = StateStore::open(state_path) {
        if state.rules().is_empty() {
            return unchanged;
        }
    }

    let runner = RealRunner;
    let Ok(backend) = backend::detect(&runner) else {
        return unchanged; // No firewall to close anything in; try the next wake-up.
    };
    let Ok(state) = StateStore::open_exclusive(state_path) else {
        return unchanged; // Lock momentarily held elsewhere; try the next wake-up.
    };

    let mut engine = Engine::new(
        backend.as_ref(),
        &runner,
        &SYSTEM_CLOCK,
        state,
        executable.to_path_buf(),
    );
    let outcome = check_network(&mut engine, &runner, previous);
    *LAST_KNOWN_SUBNET.lock().expect("not poisoned") = outcome.last_known;
    outcome
}

/// One full wake-up: the blocking half on a dedicated thread, then the
/// journal line and bus signals for whatever it decided, on the async
/// runtime that called this. `emitter` is `None` when this process could not
/// build one at all (see [`make_emitter`]); the journal still records
/// everything either way.
async fn wake_up(state_path: &Path, executable: &Path, emitter: Option<&SignalEmitter<'_>>) {
    let owned_state = state_path.to_path_buf();
    let owned_executable = executable.to_path_buf();
    let outcome = match tokio::task::spawn_blocking(move || {
        wake_up_blocking(&owned_state, &owned_executable)
    })
    .await
    {
        Ok(outcome) => outcome,
        Err(e) => {
            eprintln!("porthole-helper: network-change check panicked, continuing: {e}");
            return;
        }
    };

    // First, and separately from anything about the network: these rules had
    // already stopped being open before this wake-up looked at anything.
    Porthole::announce_reconciled(emitter, &outcome.reconciled).await;

    if let Some((old, new)) = &outcome.transition {
        match emitter {
            Some(emitter) => Porthole::announce_network_change(emitter, old, new).await,
            None => eprintln!(
                "porthole-helper: subnet changed (from \"{old}\" to \"{new}\"), but no signal \
                 emitter is available to announce it"
            ),
        }
    }
    for rule in &outcome.closed {
        Porthole::announce_autoclose(emitter, rule, CloseReason::NetworkChanged).await;
    }
}

/// A signal emitter for this helper's own object, or `None` (logged once)
/// when `bus` cannot produce one. Matches `main.rs`'s own
/// `announce_reconciled` -- the other caller with no client request, and no
/// requesting uid, behind it.
fn make_emitter(bus: &zbus::Connection) -> Option<SignalEmitter<'_>> {
    match SignalEmitter::new(bus, PATH) {
        Ok(emitter) => Some(emitter),
        Err(e) => {
            eprintln!(
                "porthole-helper: no signal emitter for the network monitor -- its closes and \
                 subnet changes will not reach the bus, though the journal still records each \
                 one: {e}"
            );
            None
        }
    }
}

/// Runs for as long as the process does -- see the module docs for what that
/// does and does not cover. Two wake-up sources: NetworkManager's
/// `StateChanged` on `bus`, subscribed to on `bus` directly since it lives
/// for this whole call, and a fixed interval poll on its own clone of `bus`,
/// spawned as an independent task so it keeps running for as long as the
/// process does regardless of whether the subscription above ever yields
/// anything.
pub async fn run(bus: zbus::Connection, state_path: PathBuf, executable: PathBuf) {
    let poll_bus = bus.clone();
    let poll_state = state_path.clone();
    let poll_executable = executable.clone();
    let poll = tokio::spawn(async move {
        let emitter = make_emitter(&poll_bus);
        let mut ticker = tokio::time::interval(POLL_INTERVAL);
        // The first tick fires immediately; the helper's own start-up sweep
        // already covered this instant, so skip it rather than repeat it.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            wake_up(&poll_state, &poll_executable, emitter.as_ref()).await;
        }
    });

    if let Ok(nm) = NetworkManagerProxy::new(&bus).await {
        if let Ok(mut signals) = nm.receive_state_changed().await {
            use futures_util::StreamExt;
            let emitter = make_emitter(&bus);
            while signals.next().await.is_some() {
                wake_up(&state_path, &executable, emitter.as_ref()).await;
            }
            // The stream ended -- NetworkManager left the bus, or the
            // connection dropped. Both are routine (a package upgrade
            // restarts NetworkManager); the poll task above does not depend
            // on either and keeps covering every future wake-up by itself.
        }
    }

    let _ = poll.await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use porthole_core::backend::fake::FakeBackend;
    use porthole_core::clock::FixedClock;
    use porthole_core::command::{Output, RecordingRunner};
    use porthole_core::model::{Lifetime, Protocol, ScopeSpec};
    use tempfile::TempDir;

    const NOW: u64 = 1_757_000_000;
    const ROUTE_JSON: &str = r#"[{"dst":"default","dev":"wlo1","metric":600}]"#;
    const ADDR_JSON: &str = r#"[{"ifindex":2,"ifname":"wlo1","addr_info":[{"family":"inet","local":"10.10.10.119","prefixlen":24,"scope":"global"}]}]"#;
    const ADDR_JSON_OTHER_SUBNET: &str = r#"[{"ifindex":2,"ifname":"wlo1","addr_info":[{"family":"inet","local":"192.168.1.50","prefixlen":24,"scope":"global"}]}]"#;

    #[test]
    fn the_monitor_runs_on_the_system_bus_and_only_opts_in_on_a_session_one() {
        // The distinction is not session-versus-system, it is
        // disposable-versus-real: a `--session` helper on a developer's own
        // machine talks to that machine's real firewall, so it needs the
        // opt-in; one inside a container sets it.
        assert!(
            decide(false, false, true),
            "a system-bus helper always runs"
        );
        assert!(decide(false, false, false));
        assert!(
            !decide(true, false, true),
            "`--session` alone is not enough"
        );
        assert!(decide(true, true, true), "`--session` plus the opt-in runs");

        // A release binary runs privileged and must not take this from the
        // environment -- the same rule `PORTHOLE_STATE_FILE` follows. A test
        // binary is always a debug build, so passing the profile in is the
        // only way to check the release half at all.
        assert!(
            !decide(true, true, false),
            "a release build must ignore the opt-in entirely"
        );
    }

    fn engine_with_rule<'a>(
        backend: &'a FakeBackend,
        open_runner: &'a RecordingRunner,
        clock: &'a FixedClock,
        store: porthole_core::state::StateStore,
        scope: ScopeSpec,
    ) -> Engine<'a> {
        let mut engine = Engine::new(
            backend,
            open_runner,
            clock,
            store,
            PathBuf::from("/usr/bin/porthole"),
        );
        engine
            .open(5173, Protocol::Tcp, &scope, Lifetime::UntilReboot, 1000)
            .unwrap();
        engine
    }

    #[test]
    fn check_network_closes_nothing_on_the_first_observation() {
        // Nothing here has ever seen a subnet before, so nothing can be
        // proven tied to one -- even a rule scoped to exactly the subnet
        // that resolves now must survive this first look.
        let dir = TempDir::new().unwrap();
        let store = StateStore::open(dir.path().join("state.json")).unwrap();
        let backend = FakeBackend::new();
        let clock = FixedClock(NOW);
        let open_runner = RecordingRunner::new();
        let mut engine = engine_with_rule(
            &backend,
            &open_runner,
            &clock,
            store,
            ScopeSpec::Network("10.10.10.0/24".parse().unwrap()),
        );

        let probe = RecordingRunner::with_responses(vec![
            Output::stdout(ROUTE_JSON),
            Output::stdout(ADDR_JSON),
        ]);
        let outcome = check_network(&mut engine, &probe, None);

        assert!(outcome.closed.is_empty());
        assert!(outcome.transition.is_none());
        assert_eq!(outcome.last_known, Some("10.10.10.0/24".parse().unwrap()));
        assert_eq!(engine.rules().len(), 1);
    }

    #[test]
    fn check_network_closes_nothing_when_the_subnet_is_unchanged() {
        let dir = TempDir::new().unwrap();
        let store = StateStore::open(dir.path().join("state.json")).unwrap();
        let backend = FakeBackend::new();
        let clock = FixedClock(NOW);
        let open_runner = RecordingRunner::new();
        let mut engine = engine_with_rule(
            &backend,
            &open_runner,
            &clock,
            store,
            ScopeSpec::Network("10.10.10.0/24".parse().unwrap()),
        );

        let probe = RecordingRunner::with_responses(vec![
            Output::stdout(ROUTE_JSON),
            Output::stdout(ADDR_JSON),
        ]);
        let outcome = check_network(&mut engine, &probe, Some("10.10.10.0/24".parse().unwrap()));

        assert!(outcome.closed.is_empty());
        assert!(outcome.transition.is_none());
        assert_eq!(engine.rules().len(), 1);
    }

    #[test]
    fn check_network_closes_a_rule_for_the_subnet_it_just_left_and_announces_the_move() {
        let dir = TempDir::new().unwrap();
        let store = StateStore::open(dir.path().join("state.json")).unwrap();
        let backend = FakeBackend::new();
        let clock = FixedClock(NOW);
        let open_runner = RecordingRunner::new();
        let mut engine = engine_with_rule(
            &backend,
            &open_runner,
            &clock,
            store,
            ScopeSpec::Network("10.10.10.0/24".parse().unwrap()),
        );

        let probe = RecordingRunner::with_responses(vec![
            Output::stdout(ROUTE_JSON),
            Output::stdout(ADDR_JSON_OTHER_SUBNET),
        ]);
        let outcome = check_network(&mut engine, &probe, Some("10.10.10.0/24".parse().unwrap()));

        assert_eq!(outcome.closed.len(), 1);
        assert_eq!(
            outcome.transition,
            Some(("10.10.10.0/24".to_string(), "192.168.1.0/24".to_string()))
        );
        assert_eq!(outcome.last_known, Some("192.168.1.0/24".parse().unwrap()));
        assert!(engine.rules().is_empty());
    }

    #[test]
    fn check_network_leaves_a_rule_broader_than_the_lost_subnet_alone() {
        // The same C1 case as `porthole_core::engine`'s own test, exercised
        // through this module's own entry point.
        let dir = TempDir::new().unwrap();
        let store = StateStore::open(dir.path().join("state.json")).unwrap();
        let backend = FakeBackend::new();
        let clock = FixedClock(NOW);
        let open_runner = RecordingRunner::new();
        let mut engine = engine_with_rule(
            &backend,
            &open_runner,
            &clock,
            store,
            ScopeSpec::Network("10.0.0.0/8".parse().unwrap()),
        );

        let probe = RecordingRunner::with_responses(vec![
            Output::stdout(ROUTE_JSON),
            Output::stdout(ADDR_JSON_OTHER_SUBNET),
        ]);
        let outcome = check_network(&mut engine, &probe, Some("10.10.10.0/24".parse().unwrap()));

        assert!(
            outcome.closed.is_empty(),
            "must survive: {:?}",
            outcome.closed
        );
        assert_eq!(engine.rules().len(), 1);
    }

    #[test]
    fn check_network_closes_every_subnet_rule_and_announces_no_network_on_confirmed_loss() {
        let dir = TempDir::new().unwrap();
        let store = StateStore::open(dir.path().join("state.json")).unwrap();
        let backend = FakeBackend::new();
        let clock = FixedClock(NOW);
        let open_runner = RecordingRunner::new();
        let mut engine = engine_with_rule(
            &backend,
            &open_runner,
            &clock,
            store,
            ScopeSpec::Network("10.10.10.0/24".parse().unwrap()),
        );

        // No default route at all: a real "no default route" response, the
        // same shape `porthole_core::net`'s own tests capture.
        let probe = RecordingRunner::with_responses(vec![Output::stdout("[]")]);
        let outcome = check_network(&mut engine, &probe, Some("10.10.10.0/24".parse().unwrap()));

        assert_eq!(outcome.closed.len(), 1);
        assert_eq!(
            outcome.transition,
            Some(("10.10.10.0/24".to_string(), String::new()))
        );
        assert_eq!(outcome.last_known, None);
        assert!(engine.rules().is_empty());
    }

    #[test]
    fn check_network_leaves_rules_alone_when_resolution_fails_for_a_reason_other_than_no_network() {
        // I1: a spawn failure, a non-zero exit, or a malformed `ip` body are
        // not "no network" -- they are "porthole could not tell this time".
        // Only `Error::NoNetwork` may close anything.
        let dir = TempDir::new().unwrap();
        let store = StateStore::open(dir.path().join("state.json")).unwrap();
        let backend = FakeBackend::new();
        let clock = FixedClock(NOW);
        let open_runner = RecordingRunner::new();
        let mut engine = engine_with_rule(
            &backend,
            &open_runner,
            &clock,
            store,
            ScopeSpec::Network("10.10.10.0/24".parse().unwrap()),
        );

        let probe = RecordingRunner::with_responses(vec![Output {
            status: 1,
            stdout: String::new(),
            stderr: "ip: command not found".to_string(),
        }]);
        let previous = Some("10.10.10.0/24".parse().unwrap());
        let outcome = check_network(&mut engine, &probe, previous);

        assert!(outcome.closed.is_empty());
        assert!(outcome.transition.is_none());
        assert_eq!(
            outcome.last_known, previous,
            "the tracked subnet must not be disturbed by an unrelated failure"
        );
        assert_eq!(engine.rules().len(), 1);
    }

    #[test]
    fn check_network_leaves_an_anywhere_rule_alone_on_every_path() {
        for (probe, previous) in [
            (
                RecordingRunner::with_responses(vec![
                    Output::stdout(ROUTE_JSON),
                    Output::stdout(ADDR_JSON_OTHER_SUBNET),
                ]),
                Some("10.10.10.0/24".parse().unwrap()),
            ),
            (
                RecordingRunner::with_responses(vec![Output::stdout("[]")]),
                Some("10.10.10.0/24".parse().unwrap()),
            ),
            (
                RecordingRunner::with_responses(vec![
                    Output::stdout(ROUTE_JSON),
                    Output::stdout(ADDR_JSON),
                ]),
                None,
            ),
        ] {
            let dir = TempDir::new().unwrap();
            let store = StateStore::open(dir.path().join("state.json")).unwrap();
            let backend = FakeBackend::new();
            let clock = FixedClock(NOW);
            let open_runner = RecordingRunner::new();
            let mut engine =
                engine_with_rule(&backend, &open_runner, &clock, store, ScopeSpec::Anywhere);

            let outcome = check_network(&mut engine, &probe, previous);
            assert!(outcome.closed.is_empty());
            assert_eq!(engine.rules().len(), 1);
        }
    }
}
