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

use porthole_core::backend;
use porthole_core::clock::SystemClock;
use porthole_core::command::{CommandRunner, RealRunner};
use porthole_core::engine::Engine;
use porthole_core::net;
use porthole_core::state::{ManagedRule, StateStore};
use std::path::{Path, PathBuf};
use std::time::Duration;

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

/// Re-resolve the current subnet and close whatever no longer belongs to it.
///
/// Split out from [`wake_up`] so the decision is testable without a bus, a
/// timer, or root: everything below this point is exactly the seam
/// `porthole_core::engine`'s own tests already use. A resolution failure
/// (no default route, no global address -- see `porthole_core::net`) is
/// treated the same as "no usable network", regardless of which specific
/// reason it failed for: either way there is no current subnet left to
/// honestly compare a rule's CIDR against.
pub fn check_network(engine: &mut Engine<'_>, runner: &dyn CommandRunner) -> Vec<ManagedRule> {
    match net::current_network(runner) {
        Ok(network) => engine.close_rules_outside(network.cidr),
        Err(_) => engine.close_rules_on_network_loss(),
    }
}

/// One wake-up: detect the backend, take the state lock, run the check, log
/// what closed. Best-effort throughout, the same policy `Engine::reconcile`
/// already applies to its own sweep -- a backend that cannot be detected, or
/// a lock that is momentarily busy, is a reason to wait for the next
/// wake-up, not to bring down the helper that is the only thing left
/// watching for it.
fn wake_up(state_path: &PathBuf, executable: &Path) {
    let runner = RealRunner;

    // Nothing recorded means nothing a network change could invalidate --
    // skip the two `ip` reads on every idle tick, not only the close itself.
    // An unreadable state file is a different fact from an empty one, so it
    // does not take this shortcut; the detect/lock attempts below will fail
    // loudly (and harmlessly) on their own in that case instead.
    if let Ok(state) = StateStore::open(state_path) {
        if state.rules().is_empty() {
            return;
        }
    }

    let backend = match backend::detect(&runner) {
        Ok(backend) => backend,
        Err(_) => return, // No firewall to close anything in; try the next wake-up.
    };
    let state = match StateStore::open_exclusive(state_path) {
        Ok(state) => state,
        Err(_) => return, // Lock momentarily held elsewhere; try the next wake-up.
    };

    let mut engine = Engine::new(
        backend.as_ref(),
        &runner,
        &SYSTEM_CLOCK,
        state,
        executable.to_path_buf(),
    );
    for rule in check_network(&mut engine, &runner) {
        eprintln!(
            "porthole-helper: network changed, closed {}/{} towards {} (opened by uid={})",
            rule.port, rule.protocol, rule.target, rule.uid
        );
    }
}

/// Runs for as long as the process does -- see the module docs for why that
/// is exactly long enough. Subscribes to NetworkManager's `StateChanged` on
/// `bus` when NetworkManager answers there at all (it does not on the
/// session bus `--session` serves for tests, which is fine: the poll below
/// does not depend on it either way) and always runs the fallback poll
/// alongside it.
pub async fn run(bus: zbus::Connection, state_path: PathBuf, executable: PathBuf) {
    let poll_state = state_path.clone();
    let poll_executable = executable.clone();
    let poll = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(POLL_INTERVAL);
        // The first tick fires immediately; the helper's own start-up sweep
        // already covered this instant, so skip it rather than repeat it.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            wake_up(&poll_state, &poll_executable);
        }
    });

    if let Ok(nm) = NetworkManagerProxy::new(&bus).await {
        if let Ok(mut signals) = nm.receive_state_changed().await {
            use futures_util::StreamExt;
            while signals.next().await.is_some() {
                wake_up(&state_path, &executable);
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
        let closed = check_network(&mut engine, &probe_runner);

        assert_eq!(closed.len(), 1);
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
        let closed = check_network(&mut engine, &probe_runner);

        assert_eq!(closed.len(), 1);
        assert!(engine.rules().is_empty());
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

            let closed = check_network(&mut engine, &probe);
            assert!(closed.is_empty());
            assert_eq!(engine.rules().len(), 1);
        }
    }
}
