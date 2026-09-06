//! Notices when the machine's subnet changes, so a rule scoped to one is
//! closed rather than left open, re-aimed at the new network, or reported as
//! still valid when it is not.
//!
//! `org.freedesktop.NetworkManager`'s `StateChanged` signal fires on connect
//! and disconnect, not when the machine stays connected but roams onto a
//! different subnet on the same interface -- a new access point, or a fresh
//! DHCP lease -- which is exactly the case porthole's CIDR-scoped rules are
//! exposed to. So the signal here is only ever a prompt to look again: every
//! wake-up re-resolves the current subnet and compares it against each
//! rule's own stored CIDR (see
//! [`porthole_core::engine::Engine::close_rules_outside`]), and it is that
//! comparison, not the signal's own payload, that decides anything.
//!
//! Two wake-up sources feed the same check, so a machine with no
//! NetworkManager is still covered: `StateChanged` when NetworkManager
//! answers on the bus, and a plain fixed-interval poll regardless of whether
//! it does. The poll is not a netlink subscription -- it is the same two
//! read-only `ip` commands `porthole status` already runs, cheap enough to
//! repeat every few seconds -- and it is what keeps a machine with no
//! NetworkManager covered at all, and what catches anything the signal alone
//! missed.
//!
//! # Why this keeps the helper alive while a rule is open
//!
//! `main` spawns [`run`] onto the same runtime that serves the D-Bus
//! interface and never awaits it there -- the process's own lifetime is not
//! this task's problem to manage. Nothing in the helper today exits it
//! early on its own: there is no idle timeout and no "last rule closed"
//! shutdown, so once started it keeps running until something outside it
//! stops it, whether or not any rule is open. The requirement this module
//! exists to satisfy -- the helper must stay alive for as long as any rule
//! is open, since it is the only thing left watching for the network
//! changing under it -- therefore already holds, unconditionally, before
//! this module adds anything; [`run`]'s own loop then simply lives exactly
//! as long as the process that spawned it.

use crate::service::Porthole;
use porthole_core::backend;
use porthole_core::clock::SystemClock;
use porthole_core::command::{CommandRunner, RealRunner};
use porthole_core::engine::Engine;
use porthole_core::ipc::{CloseReason, PATH};
use porthole_core::net;
use porthole_core::state::{ManagedRule, StateStore};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use zbus::object_server::SignalEmitter;

/// How often the fallback poll re-checks the subnet. Two read-only `ip`
/// commands, cheap enough to repeat this often; chosen with a comfortable
/// margin over this workspace's own slowest end-to-end test that spawns a
/// real helper process (`porthole-cli/tests/helper_e2e.rs`'s
/// `an_open_reaches_the_firewall_and_changes_nothing_when_refused`, measured
/// at ~28s -- firewalld's own polkit timeout, not this module's doing), so
/// that test suite never has a real helper process alive long enough for
/// this poll to fire even once.
const POLL_INTERVAL: Duration = Duration::from_secs(60);

static SYSTEM_CLOCK: SystemClock = SystemClock;

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

/// What one look at the network found.
#[derive(Debug)]
pub struct Check {
    /// The subnet the machine is on right now, rendered exactly as it
    /// crosses the bus: a CIDR, or **empty for "no usable network"**. D-Bus
    /// has no optional types, the same reason `WireRule::expires_at` uses
    /// `0`, and the empty string can never be a CIDR.
    pub cidr: String,
    /// The rules this look closed, all of them for the same reason:
    /// [`CloseReason::NetworkChanged`].
    pub closed: Vec<ManagedRule>,
}

/// Re-resolve the current subnet and close whatever no longer belongs to it.
///
/// Split out from [`wake_up`] so the decision is testable without a bus, a
/// timer, or root: everything below this point is exactly the seam
/// `porthole_core::engine`'s own tests already use. A resolution failure
/// (no default route, no global address -- see `porthole_core::net`) is
/// treated the same as "no usable network", regardless of which specific
/// reason it failed for: either way there is no current subnet left to
/// honestly compare a rule's CIDR against.
pub fn check_network(engine: &mut Engine<'_>, runner: &dyn CommandRunner) -> Check {
    match net::current_network(runner) {
        Ok(network) => Check {
            cidr: network.cidr.to_string(),
            closed: engine.close_rules_outside(network.cidr),
        },
        Err(_) => Check {
            cidr: String::new(),
            closed: engine.close_rules_on_network_loss(),
        },
    }
}

/// The subnet porthole saw the last time it looked, as [`Check::cidr`]
/// renders it. `None` means it has not looked yet, which is a different fact
/// from having looked and found nothing: there is no "old" network to name
/// in a `NetworkChanged` on the very first look, so the first look never
/// emits one.
type LastSeen = Mutex<Option<String>>;

/// Detect the backend, take the state lock, run the check. `None` when
/// there was nothing to check or nothing to check it with. Best-effort
/// throughout, the same policy `Engine::reconcile` already applies to its own
/// sweep -- a backend that cannot be detected, or a lock that is momentarily
/// busy, is a reason to wait for the next wake-up, not to bring down the
/// helper that is the only thing left watching for it.
///
/// Synchronous, and separate from [`wake_up`]'s announcements, because the
/// `Engine` it builds borrows `&dyn CommandRunner` and `&dyn Clock`, neither
/// of them `Sync`: it must be gone before anything is awaited, or [`run`]'s
/// future stops being `Send` and `tokio::spawn` will not take it.
fn look(state_path: &Path, executable: &Path) -> Option<Check> {
    let runner = RealRunner;

    // Nothing recorded means nothing a network change could invalidate --
    // skip the two `ip` reads on every idle tick, not only the close itself.
    // An unreadable state file is a different fact from an empty one, so it
    // does not take this shortcut; the detect/lock attempts below will fail
    // loudly (and harmlessly) on their own in that case instead.
    //
    // It also means porthole does not look at the network at all while
    // nothing is open, which is what makes `NetworkChanged`'s `old_cidr` the
    // previous *look* rather than the previous *state of the world*: see
    // [`wake_up`].
    if let Ok(state) = StateStore::open(state_path) {
        if state.rules().is_empty() {
            return None;
        }
    }

    let backend = backend::detect(&runner).ok()?; // No firewall to close anything in.
    let state = StateStore::open_exclusive(state_path).ok()?; // Lock busy elsewhere.

    let mut engine = Engine::new(
        backend.as_ref(),
        &runner,
        &SYSTEM_CLOCK,
        state,
        executable.to_path_buf(),
    );
    Some(check_network(&mut engine, &runner))
}

/// One wake-up: [`look`], then say what happened -- to the journal and, when
/// there is a bus to say it on, to whoever is subscribed.
///
/// `NetworkChanged` compares this look against the previous one, not against
/// what was true an instant ago: porthole only looks when something is
/// recorded (see [`look`]), so `old_cidr` is the subnet as of porthole's last
/// look and may be older than the change itself. The signal's own
/// documentation in `porthole_core::ipc` says the same thing to the client
/// that reads it.
///
/// It is emitted before the closes it explains, so a subscriber that shows
/// both has them in the order they make sense in.
async fn wake_up(
    state_path: &Path,
    executable: &Path,
    emitter: Option<&SignalEmitter<'_>>,
    last_seen: &LastSeen,
) {
    let Some(check) = look(state_path, executable) else {
        return;
    };

    // Held only long enough to swap; nothing is awaited under it.
    let previous = last_seen
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .replace(check.cidr.clone());

    if let (Some(emitter), Some(previous)) = (emitter, previous.as_ref()) {
        if previous != &check.cidr {
            Porthole::announce_network_change(emitter, previous, &check.cidr).await;
        }
    }

    for rule in &check.closed {
        Porthole::announce_autoclose(emitter, rule, CloseReason::NetworkChanged).await;
    }
}

/// Runs for as long as the process does -- see the module docs for why that
/// is exactly long enough. Subscribes to NetworkManager's `StateChanged` on
/// `bus` when NetworkManager answers there at all (it does not on the
/// session bus `--session` serves for tests, which is fine: the poll below
/// does not depend on it either way) and always runs the fallback poll
/// alongside it.
pub async fn run(bus: zbus::Connection, state_path: PathBuf, executable: PathBuf) {
    // One emitter for both wake-up sources, and one record of what the last
    // look saw, shared between them: the poll and the NetworkManager signal
    // are two prompts to do the same thing, so a change noticed by one must
    // not be re-announced by the other.
    let emitter = match SignalEmitter::new(&bus, PATH) {
        Ok(emitter) => Some(emitter.into_owned()),
        Err(e) => {
            eprintln!(
                "porthole-helper: no signal emitter, network changes will go unannounced \
                 (they are still acted on): {e}"
            );
            None
        }
    };
    let last_seen: Arc<LastSeen> = Arc::new(Mutex::new(None));

    let poll_state = state_path.clone();
    let poll_executable = executable.clone();
    let poll_emitter = emitter.clone();
    let poll_last_seen = Arc::clone(&last_seen);
    let poll = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(POLL_INTERVAL);
        // The first tick fires immediately; the helper's own start-up sweep
        // already covered this instant, so skip it rather than repeat it.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            wake_up(
                &poll_state,
                &poll_executable,
                poll_emitter.as_ref(),
                &poll_last_seen,
            )
            .await;
        }
    });

    if let Ok(nm) = NetworkManagerProxy::new(&bus).await {
        if let Ok(mut signals) = nm.receive_state_changed().await {
            use futures_util::StreamExt;
            while signals.next().await.is_some() {
                wake_up(&state_path, &executable, emitter.as_ref(), &last_seen).await;
            }
            // The stream ended -- NetworkManager left the bus, or the
            // connection dropped. The poll task above does not depend on it
            // in any way and keeps covering every future wake-up by itself.
        }
    }

    // Reached only once there is no signal subscription left to drive (in
    // production, where NetworkManager is present, never). The poll keeps
    // the process doing useful work regardless.
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

    #[test]
    fn check_network_closes_a_rule_for_a_subnet_the_resolution_says_we_left() {
        let dir = TempDir::new().unwrap();
        let store = StateStore::open(dir.path().join("state.json")).unwrap();
        let backend = FakeBackend::new();
        let clock = FixedClock(NOW);
        let open_runner = RecordingRunner::new();
        let mut engine = Engine::new(
            &backend,
            &open_runner,
            &clock,
            store,
            PathBuf::from("/usr/bin/porthole"),
        );
        engine
            .open(
                5173,
                Protocol::Tcp,
                &ScopeSpec::Network("192.168.1.0/24".parse().unwrap()),
                Lifetime::UntilReboot,
                1000,
            )
            .unwrap();

        // The machine is actually on 10.10.10.0/24, not the rule's own
        // 192.168.1.0/24.
        let probe_runner = RecordingRunner::with_responses(vec![
            Output::stdout(ROUTE_JSON),
            Output::stdout(ADDR_JSON),
        ]);
        let check = check_network(&mut engine, &probe_runner);

        assert_eq!(check.closed.len(), 1);
        assert!(engine.rules().is_empty());
    }

    #[test]
    fn check_network_closes_every_subnet_rule_when_resolution_finds_no_network() {
        let dir = TempDir::new().unwrap();
        let store = StateStore::open(dir.path().join("state.json")).unwrap();
        let backend = FakeBackend::new();
        let clock = FixedClock(NOW);
        let open_runner = RecordingRunner::new();
        let mut engine = Engine::new(
            &backend,
            &open_runner,
            &clock,
            store,
            PathBuf::from("/usr/bin/porthole"),
        );
        engine
            .open(
                5173,
                Protocol::Tcp,
                &ScopeSpec::Network("10.10.10.0/24".parse().unwrap()),
                Lifetime::UntilReboot,
                1000,
            )
            .unwrap();

        // No default route at all: a real "no default route" response, the
        // same shape `porthole_core::net`'s own tests capture.
        let probe_runner = RecordingRunner::with_responses(vec![Output::stdout("[]")]);
        let check = check_network(&mut engine, &probe_runner);

        assert_eq!(check.closed.len(), 1);
        assert!(engine.rules().is_empty());
    }

    #[test]
    fn a_look_reports_the_subnet_it_found_or_the_empty_sentinel() {
        // `Check::cidr` is what `NetworkChanged` puts on the wire, so the
        // "no usable network" case has to be the empty string and not, say,
        // `0.0.0.0/0` -- which is a real CIDR meaning the opposite of
        // "nowhere".
        for (probe, expected) in [
            (
                RecordingRunner::with_responses(vec![
                    Output::stdout(ROUTE_JSON),
                    Output::stdout(ADDR_JSON),
                ]),
                "10.10.10.0/24",
            ),
            (
                RecordingRunner::with_responses(vec![Output::stdout("[]")]),
                "",
            ),
        ] {
            let dir = TempDir::new().unwrap();
            let store = StateStore::open(dir.path().join("state.json")).unwrap();
            let backend = FakeBackend::new();
            let clock = FixedClock(NOW);
            let mut engine = Engine::new(
                &backend,
                &probe,
                &clock,
                store,
                PathBuf::from("/usr/bin/porthole"),
            );

            assert_eq!(check_network(&mut engine, &probe).cidr, expected);
        }
    }

    #[test]
    fn check_network_leaves_an_anywhere_rule_alone_on_either_path() {
        for probe in [
            RecordingRunner::with_responses(vec![
                Output::stdout(ROUTE_JSON),
                Output::stdout(ADDR_JSON),
            ]),
            RecordingRunner::with_responses(vec![Output::stdout("[]")]),
        ] {
            let dir = TempDir::new().unwrap();
            let store = StateStore::open(dir.path().join("state.json")).unwrap();
            let backend = FakeBackend::new();
            let clock = FixedClock(NOW);
            let open_runner = RecordingRunner::new();
            let mut engine = Engine::new(
                &backend,
                &open_runner,
                &clock,
                store,
                PathBuf::from("/usr/bin/porthole"),
            );
            engine
                .open(
                    5173,
                    Protocol::Tcp,
                    &ScopeSpec::Anywhere,
                    Lifetime::UntilReboot,
                    1000,
                )
                .unwrap();

            let check = check_network(&mut engine, &probe);
            assert!(check.closed.is_empty());
            assert_eq!(engine.rules().len(), 1);
        }
    }
}
