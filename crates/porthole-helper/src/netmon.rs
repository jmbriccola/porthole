//! Notices when the machine's surroundings stop matching what a rule was
//! opened against, so the rule is closed rather than left open, re-aimed, or
//! reported as still valid when it is not. Two things can stop matching, and
//! one wake-up checks both: the subnet a rule is scoped to, and the container
//! a forward redirects to -- both in one pass, and
//! [`porthole_core::engine::Engine::close_stale_forwards`] for the second.
//! The second runs only when the state file actually holds a forward: it
//! costs a Docker read and a reconciliation sweep, and on a machine that has
//! never forwarded anything it can only ever answer "nothing". Everything
//! below is about the first, which is the one that needs the bookkeeping.
//!
//! `org.freedesktop.NetworkManager`'s `StateChanged` signal fires on connect
//! and disconnect, not when the machine stays connected but roams onto a
//! different subnet on the same interface -- a new access point, or a fresh
//! DHCP lease -- which is exactly the case porthole's CIDR-scoped rules are
//! exposed to. So the signal here is only ever a prompt to look again: every
//! wake-up re-reads every subnet this machine holds and compares that set
//! against the set this module last saw. Two wake-up sources feed the same
//! check, so a machine with no NetworkManager is still covered:
//! `StateChanged` when NetworkManager answers on the bus, and a
//! fixed-interval poll that does not depend on NetworkManager at all.
//!
//! # What "the subnets this module last saw" means, and what it does not
//!
//! `ManagedRule` records the resolved `Target` a rule was opened towards, not
//! the `ScopeSpec` that produced it -- there is no stored fact distinguishing
//! "opened towards whatever subnet I'm on" from "opened towards this exact
//! CIDR, deliberately". [`porthole_core::engine::Engine::close_rules_outside`]
//! is built around that limit rather than against it: it closes a rule when
//! the rule's own CIDR sits inside the subnet this module last saw, once
//! that subnet stops matching the one resolving now, not when the rule's
//! CIDR merely differs from the new one -- see its own doc comment for the
//! case that distinction protects.
//!
//! A machine can hold several subnets at once, and a subnet counts as lost
//! only when it is absent from every non-virtual interface -- not when it
//! merely stops being the one the default route names.
//! [`porthole_core::net::present_networks`] is what enumerates them, so
//! docking a laptop, which hands the default route to ethernet while wifi
//! stays up, closes nothing: the wifi subnet is still there to be found.
//! What this module tracks between wake-ups is therefore the whole set it
//! last saw, and a rule closes when the subnet it sits inside has left that
//! set.
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
//! That costs more than the one tick it sounds like. The only subnet a
//! change can close rules inside is one this module observed itself, and
//! the first observation after a restart is the subnet the machine is on
//! now -- so a rule towards a subnet the machine had already left before
//! the helper started is never closed by a subnet change at all, no matter
//! how many wake-ups follow. Such a rule still ends at its own expiry, at a
//! `close`, or on a confirmed loss of every network, none of which need a
//! prior observation.
//!
//! # This module's own lifetime
//!
//! `main` spawns [`run`] onto the same runtime that serves the D-Bus
//! interface and never awaits it there, so [`run`] lives exactly as long as
//! the process does, no more and no less.
//!
//! The process does end on its own now: with **no rule recorded** and nothing
//! in flight, [`crate::retire`] gives up the bus name and exits after a grace
//! period, and the bus starts a new helper the moment a client wants one. That
//! never costs this module anything it was doing, and the reason is the
//! empty-state shortcut in [`wake_up_tracking`] rather than a promise made
//! elsewhere: with nothing recorded, a wake-up returns before detecting a
//! backend and before a single `ip` runs, and clears the subnet it tracked on
//! the way out. So the one piece of in-process memory this module keeps is, by
//! construction, already empty exactly when the helper becomes eligible to
//! exit -- there is nothing for an exit to lose, and nothing for the next
//! process to rebuild that it would not have had to rebuild anyway.
//! `a_wake_up_with_nothing_recorded_clears_the_tracked_subnet` is what pins
//! that. **With a rule recorded the helper never retires**, for exactly this
//! module's sake.
//!
//! What that is still not is covering every open rule continuously: a crash,
//! an OOM kill, a plain `systemctl stop`, or a package `try-restart` ends the
//! process (and this module with it) while `RuntimeDirectoryPreserve=yes`
//! keeps the state file and the firewall keeps every rule, and nothing
//! restarts the helper until a client next addresses the bus name -- see
//! `data/porthole-helper.service`'s own comment on why `Restart=` is not set
//! there. Automatic close (`porthole_core::expiry`) does not share this gap:
//! it is a systemd transient timer that lives outside this process, so
//! neither a helper restart nor a retirement can lose it. A network change
//! this module would have caught can be lost that way.

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

/// Every subnet the last wake-up resolved successfully. Empty before the
/// first successful resolution, again after a resolution finds no network at
/// all, and again after a wake-up that skipped resolving because no rule was
/// recorded -- all three share the same status: nothing to prove a rule in
/// the state file is tied to. Touched only by [`wake_up_blocking`], which
/// passes it to [`wake_up_tracking`]; every decision below takes the value
/// as a plain parameter instead of reading the static, so a test drives the
/// same code over a mutex of its own without colliding with another test's
/// run through shared state.
static LAST_KNOWN_SUBNETS: Mutex<Vec<Ipv4Net>> = Mutex::new(Vec::new());

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
    /// One `(old_cidr, new_cidr)` per subnet that has gone, for the
    /// `NetworkChanged` signal, in the wire format's own convention --
    /// empty string for "no usable network". Empty when nothing changed
    /// enough to report, which includes the "first observation" and "every
    /// subnet still up" cases.
    ///
    /// One entry per lost subnet, rather than one entry naming several,
    /// because `network_changed`'s own contract is that each argument is a
    /// single CIDR or the empty string.
    transitions: Vec<(String, String)>,
    /// What [`LAST_KNOWN_SUBNETS`] should hold after this wake-up: every
    /// subnet seen on a non-virtual interface, or empty for "nothing
    /// observed".
    last_known: Vec<Ipv4Net>,
    /// Records the engine's own reconciliation dropped while this wake-up was
    /// closing things -- rules the firewall no longer had at all. Nothing to
    /// do with the network changing; collected here because this is the one
    /// place that holds the engine, and announced as
    /// [`CloseReason::Reconciled`], never as a network-change close. See
    /// [`porthole_core::engine::Engine::take_reconciled`].
    reconciled: Vec<ManagedRule>,
    /// Forwards closed because the container they named is no longer the one
    /// they were created against. Kept apart from `closed` because they are
    /// announced as [`CloseReason::TargetGone`], and a user told "the network
    /// changed" about a container that restarted would go looking at their
    /// wifi. See [`porthole_core::engine::Engine::close_stale_forwards`].
    stale: Vec<ManagedRule>,
}

/// Re-resolve every subnet this machine currently holds, decide which of
/// `previous` have gone, and close whatever sat inside one of those.
///
/// Split out from [`wake_up_blocking`] so the decision is testable without a
/// bus, a timer, or root: everything here is exactly the seam
/// `porthole_core::engine`'s own tests already use, plus `previous` as a
/// plain value rather than the module's own tracked state.
///
/// A resolution failure other than [`Error::NoNetwork`] (a spawned `ip` that
/// could not run, a non-zero exit, a malformed JSON body) leaves `previous`
/// and every rule untouched: which subnets this machine holds is simply
/// unknown for this one wake-up, not confirmed absent, and treating every
/// such failure as "no network" would close every subnet-scoped rule on a
/// parse error alone. Only [`Error::NoNetwork`] -- porthole's own confirmed
/// "no default route" or "no global address" -- means there is genuinely no
/// network right now, and that closes every subnet-scoped rule regardless of
/// `previous`: unlike "a subnet is gone", "there is no network" needs no
/// prior observation to be true.
fn check_network(
    engine: &mut Engine<'_>,
    runner: &dyn CommandRunner,
    previous: &[Ipv4Net],
) -> CheckOutcome {
    let mut outcome = match net::present_networks(runner) {
        Ok(present) => {
            // Absent from every non-virtual interface, not merely absent
            // from the default route: an interface that is still up and
            // still carrying a rule's traffic keeps its subnet here even
            // when another interface has taken the route.
            let mut closed = Vec::new();
            let mut transitions = Vec::new();
            for gone in previous.iter().filter(|p| !present.all.contains(p)) {
                closed.extend(engine.close_rules_outside(*gone));
                transitions.push((gone.to_string(), present.primary.cidr.to_string()));
            }
            CheckOutcome {
                closed,
                transitions,
                last_known: present.all,
                reconciled: Vec::new(),
                stale: Vec::new(),
            }
        }
        Err(Error::NoNetwork(_)) => CheckOutcome {
            closed: engine.close_rules_on_network_loss(),
            transitions: previous
                .iter()
                .map(|lost| (lost.to_string(), String::new()))
                .collect(),
            last_known: Vec::new(),
            reconciled: Vec::new(),
            stale: Vec::new(),
        },
        Err(_) => CheckOutcome {
            closed: Vec::new(),
            transitions: Vec::new(),
            last_known: previous.to_vec(),
            reconciled: Vec::new(),
            stale: Vec::new(),
        },
    };
    // Taken after the match, not inside it: only the two arms that close
    // anything reconcile at all, and this way a third arm added later cannot
    // silently drop what its own sweep found.
    outcome.reconciled = engine.take_reconciled();
    outcome
}

/// Everything one wake-up decides: the subnet check, then the forwards whose
/// container is no longer the one they named.
///
/// Two independent questions sharing one wake-up, because the work around
/// them -- detecting the backend, taking the state lock, building an engine
/// -- is the expensive part and is the same for both. They are kept as
/// separate closes in the outcome because they are announced differently.
///
/// The subnet check runs first, so a rule that is closing anyway because the
/// machine left its network is not also read against Docker's table. The
/// second sweep reconciles again and can drop records of its own, so what it
/// found is collected on top of what the first did rather than replacing it.
fn check(
    engine: &mut Engine<'_>,
    runner: &dyn CommandRunner,
    previous: &[Ipv4Net],
) -> CheckOutcome {
    let mut outcome = check_network(engine, runner, previous);
    // Only when there is something for it to compare. `close_stale_forwards`
    // runs `iptables -t nat -S DOCKER` and a full reconciliation sweep, and
    // this wakes every 60 seconds forever: on a machine holding one ordinary
    // `open` and no forward, that was a second sweep and a Docker read on
    // every tick, permanently, for an answer that cannot be anything but
    // "nothing". The empty-state shortcut in `wake_up_tracking` covers the
    // idle machine and covers nothing here.
    //
    // Reads the state file this engine already has open and nothing else, so
    // the guard costs nothing it saves.
    if engine.rules_hold_a_forward() {
        outcome.stale = engine.close_stale_forwards();
    }
    outcome.reconciled.extend(engine.take_reconciled());
    outcome
}

/// One wake-up's synchronous half: detect the backend, take the state lock,
/// run [`check`]. Runs only inside `tokio::task::spawn_blocking` (see
/// [`wake_up`]) -- `backend::detect`'s subprocesses, the state lock's own
/// bounded retry loop, and a `close` that can sit on firewalld's polkit
/// timeout are all real blocking work, and this crate already documents why
/// that must never run on an async worker thread
/// (`porthole_core::state`'s own `LOCK_TIMEOUT` doc comment).
fn wake_up_blocking(state_path: &Path, executable: &Path) -> CheckOutcome {
    wake_up_tracking(state_path, executable, &LAST_KNOWN_SUBNETS)
}

/// [`wake_up_blocking`] with the tracked subnet as a parameter, so a test can
/// drive it over a mutex of its own.
///
/// One path through here is driven by a test and one is not. The
/// "nothing recorded" return below happens before a backend is detected and
/// before any `ip` runs, so a test can enter it with a temporary directory
/// and reach nothing outside it. Everything after that point builds a
/// `RealRunner`: it detects whichever firewall this machine actually has and
/// can close rules in it, so no test in this workspace goes past the return
/// below, and the only coverage that half has is [`check_network`]'s, which
/// takes its runner as a parameter.
fn wake_up_tracking(
    state_path: &Path,
    executable: &Path,
    tracked: &Mutex<Vec<Ipv4Net>>,
) -> CheckOutcome {
    // One guard for the whole wake-up rather than one to read and another to
    // write. The two wake-up sources can fire at once; with a gap between the
    // read and the write, both would see the same previous subnet, both would
    // decide the same transition, and both would announce it. Held across a
    // state lock, a `backend::detect` and a close, which is only safe because
    // this whole function is synchronous and runs on a blocking thread --
    // there is no await here to hold it across. Poisoning is taken rather
    // than panicked on: what is behind the lock is one `Vec<Ipv4Net>` with no
    // invariant of its own to be left half-updated, and a panic in one
    // wake-up must not stop every later one -- `wake_up` already treats a
    // panicking check as survivable.
    let mut tracked = tracked.lock().unwrap_or_else(|e| e.into_inner());
    let previous = tracked.clone();
    let unchanged = CheckOutcome {
        reconciled: Vec::new(),
        closed: Vec::new(),
        transitions: Vec::new(),
        last_known: previous.clone(),
        stale: Vec::new(),
    };

    // Nothing recorded means nothing a network change could invalidate --
    // skip the two `ip` reads on every idle tick, not only the close itself.
    // This wake-up therefore observes no subnet, and says so by clearing the
    // tracked set instead of leaving the last observation standing. Keeping
    // it would let a subnet observed before the state file emptied be
    // compared against one resolved after it: a rule opened in between, on a
    // different network, towards a CIDR that stale value contains, would be
    // closed as if the machine had left a subnet it was never on while the
    // rule existed. Clearing it makes the next wake-up that does resolve a
    // subnet baseline on it instead, closing nothing.
    // An unreadable state file is a different fact from an empty one, so it
    // does not take this shortcut; the detect/lock attempts below fail
    // loudly (and harmlessly) on their own in that case instead.
    if let Ok(state) = StateStore::open(state_path) {
        if state.rules().is_empty() {
            tracked.clear();
            return CheckOutcome {
                last_known: Vec::new(),
                ..unchanged
            };
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
    let outcome = check(&mut engine, &runner, &previous);
    tracked.clone_from(&outcome.last_known);
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

    announce_outcome(&outcome, emitter).await;
}

/// The signal half of a wake-up: what `outcome` decided, over the bus.
///
/// Split out of [`wake_up`] so this can be driven directly against a real
/// emitter and a real subscriber, without also going through
/// `wake_up_blocking`'s real backend detection -- see this module's own
/// tests, which build an `outcome` by hand and check the reason a stale
/// forward's close actually carries once it is decoded off the bus, not
/// merely the `CheckOutcome` field it came from.
async fn announce_outcome(outcome: &CheckOutcome, emitter: Option<&SignalEmitter<'_>>) {
    // First, and separately from anything about the network: these rules had
    // already stopped being open before this wake-up looked at anything.
    Porthole::announce_reconciled(emitter, &outcome.reconciled).await;

    for (old, new) in &outcome.transitions {
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
    for rule in &outcome.stale {
        Porthole::announce_autoclose(emitter, rule, CloseReason::TargetGone).await;
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
    use crate::authz::AlwaysAllow;
    use futures_util::StreamExt;
    use porthole_core::backend::fake::FakeBackend;
    use porthole_core::clock::FixedClock;
    use porthole_core::command::{Output, RecordingRunner};
    use porthole_core::ipc::PortholeProxy;
    use porthole_core::listening::FakeProcFs;
    use porthole_core::model::{Lifetime, OpenRequest, Protocol, ScopeSpec, Target};
    use std::sync::Arc;
    use tempfile::TempDir;

    const NOW: u64 = 1_757_000_000;
    const ROUTE_JSON: &str = r#"[{"dst":"default","dev":"wlo1","metric":600}]"#;
    const ADDR_JSON: &str = r#"[{"ifindex":2,"ifname":"wlo1","addr_info":[{"family":"inet","local":"10.10.10.119","prefixlen":24,"scope":"global"}]}]"#;
    const ADDR_JSON_OTHER_SUBNET: &str = r#"[{"ifindex":2,"ifname":"wlo1","addr_info":[{"family":"inet","local":"192.168.1.50","prefixlen":24,"scope":"global"}]}]"#;

    /// Two default routes at once, the multi-homed case the fixtures above
    /// cannot express. The `wlo1` entry is verbatim `ip -j route show
    /// default` from a real machine (Fedora 44, iproute2); the second entry
    /// is that same entry with its own values -- an ethernet interface at a
    /// lower metric, as docking produces -- and not one key more or fewer.
    const ROUTE_JSON_ETHERNET_ONLY: &str =
        r#"[{"dst":"default","gateway":"192.168.1.1","dev":"enp0s31f6","metric":100}]"#;

    const ROUTE_JSON_TWO_DEFAULT_ROUTES: &str = r#"[{"dst":"default","gateway":"10.10.10.1","dev":"wlo1","protocol":"dhcp","prefsrc":"10.10.10.119","metric":600,"flags":[]},{"dst":"default","gateway":"192.168.1.1","dev":"enp0s31f6","protocol":"dhcp","prefsrc":"192.168.1.50","metric":100,"flags":[]}]"#;

    /// `ip -j -4 addr show` on the docked laptop: both physical interfaces
    /// up at once, plus the `docker0` this machine really carries. The
    /// `wlo1` and `docker0` entries are verbatim from this machine; the
    /// `enp0s31f6` entry is the `wlo1` shape carrying its own values.
    ///
    /// This is the fixture the multi-homed case turns on. The route above
    /// names only `enp0s31f6`, so anything reading the default route alone
    /// cannot see that `wlo1` is still up -- here it is, in the same output
    /// the resolution already reads.
    const ADDR_JSON_DOCKED: &str = r#"[{"ifindex":2,"ifname":"wlo1","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"mtu":1500,"qdisc":"noqueue","operstate":"UP","group":"default","txqlen":1000,"altnames":["wlp0s20f3","wlxe8bfb85d9152"],"addr_info":[{"family":"inet","local":"10.10.10.119","prefixlen":24,"broadcast":"10.10.10.255","scope":"global","dynamic":true,"noprefixroute":true,"label":"wlo1","valid_life_time":726888,"preferred_life_time":726888}]},{"ifindex":5,"ifname":"enp0s31f6","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"mtu":1500,"qdisc":"noqueue","operstate":"UP","group":"default","txqlen":1000,"altnames":["enxe8bfb85d9153"],"addr_info":[{"family":"inet","local":"192.168.1.50","prefixlen":24,"broadcast":"192.168.1.255","scope":"global","dynamic":true,"noprefixroute":true,"label":"enp0s31f6","valid_life_time":42300,"preferred_life_time":42300}]},{"ifindex":3,"ifname":"docker0","flags":["NO-CARRIER","BROADCAST","MULTICAST","UP"],"mtu":1500,"qdisc":"noqueue","operstate":"DOWN","group":"default","addr_info":[{"family":"inet","local":"172.17.0.1","prefixlen":16,"broadcast":"172.17.255.255","scope":"global","label":"docker0","valid_life_time":4294967295,"preferred_life_time":4294967295}]}]"#;

    /// The same laptop after wifi actually goes away: ethernet alone.
    /// `ip -j -4 addr show dev enp0s31f6`, which is what the resolution runs
    /// once the route above has named that interface. Same provenance: the
    /// real `wlo1` reply from that machine, carrying its own values.
    const ADDR_JSON_DOCKED_ETHERNET: &str = r#"[{"ifindex":3,"ifname":"enp0s31f6","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"mtu":1500,"qdisc":"noqueue","operstate":"UP","group":"default","txqlen":1000,"altnames":["enxe8bfb85d9153"],"addr_info":[{"family":"inet","local":"192.168.1.50","prefixlen":24,"broadcast":"192.168.1.255","scope":"global","dynamic":true,"noprefixroute":true,"label":"enp0s31f6","valid_life_time":42300,"preferred_life_time":42300}]}]"#;

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
        let outcome = check_network(&mut engine, &probe, &[]);

        assert!(outcome.closed.is_empty());
        assert!(outcome.transitions.is_empty());
        assert_eq!(
            outcome.last_known,
            vec!["10.10.10.0/24".parse::<Ipv4Net>().unwrap()]
        );
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
        let outcome = check_network(&mut engine, &probe, &["10.10.10.0/24".parse().unwrap()]);

        assert!(outcome.closed.is_empty());
        assert!(outcome.transitions.is_empty());
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
        let outcome = check_network(&mut engine, &probe, &["10.10.10.0/24".parse().unwrap()]);

        assert_eq!(outcome.closed.len(), 1);
        assert_eq!(
            outcome.transitions,
            vec![("10.10.10.0/24".to_string(), "192.168.1.0/24".to_string())]
        );
        assert_eq!(
            outcome.last_known,
            vec!["192.168.1.0/24".parse::<Ipv4Net>().unwrap()]
        );
        assert!(engine.rules().is_empty());
    }

    #[test]
    fn check_network_leaves_a_rule_broader_than_the_lost_subnet_alone() {
        // The same case as `porthole_core::engine`'s own
        // `close_rules_outside_leaves_a_rule_broader_than_the_lost_subnet_alone`,
        // exercised through this module's own entry point.
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
        let outcome = check_network(&mut engine, &probe, &["10.10.10.0/24".parse().unwrap()]);

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
        let outcome = check_network(&mut engine, &probe, &["10.10.10.0/24".parse().unwrap()]);

        assert_eq!(outcome.closed.len(), 1);
        assert_eq!(
            outcome.transitions,
            vec![("10.10.10.0/24".to_string(), String::new())]
        );
        assert!(outcome.last_known.is_empty());
        assert!(engine.rules().is_empty());
    }

    #[test]
    fn check_network_leaves_rules_alone_when_resolution_fails_for_a_reason_other_than_no_network() {
        // A spawn failure, a non-zero exit, or a malformed `ip` body are
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
        let previous: Vec<Ipv4Net> = vec!["10.10.10.0/24".parse().unwrap()];
        let outcome = check_network(&mut engine, &probe, &previous);

        assert!(outcome.closed.is_empty());
        assert!(outcome.transitions.is_empty());
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
                vec!["10.10.10.0/24".parse::<Ipv4Net>().unwrap()],
            ),
            (
                RecordingRunner::with_responses(vec![Output::stdout("[]")]),
                vec!["10.10.10.0/24".parse::<Ipv4Net>().unwrap()],
            ),
            (
                RecordingRunner::with_responses(vec![
                    Output::stdout(ROUTE_JSON),
                    Output::stdout(ADDR_JSON),
                ]),
                Vec::new(),
            ),
        ] {
            let dir = TempDir::new().unwrap();
            let store = StateStore::open(dir.path().join("state.json")).unwrap();
            let backend = FakeBackend::new();
            let clock = FixedClock(NOW);
            let open_runner = RecordingRunner::new();
            let mut engine =
                engine_with_rule(&backend, &open_runner, &clock, store, ScopeSpec::Anywhere);

            let outcome = check_network(&mut engine, &probe, &previous);
            assert!(outcome.closed.is_empty());
            assert_eq!(engine.rules().len(), 1);
        }
    }

    #[test]
    fn a_rule_opened_after_the_state_file_emptied_survives_the_move_that_emptied_it() {
        // The sequence, in order:
        //   1. the machine is on 10.10.10.0/24, and a wake-up records it;
        //   2. `close --all` empties the state file, and a wake-up runs with
        //      nothing recorded;
        //   3. the machine is now on 192.168.1.0/24, and the user opens a
        //      rule towards 10.10.10.0/24 -- a subnet it is not on, which is
        //      the stronger polkit prompt, answered on purpose;
        //   4. the next wake-up must leave that rule alone.
        // Step 2 is where this went wrong: skipping the resolve left
        // 10.10.10.0/24 tracked, so step 4 compared it against the subnet
        // resolving now, called the difference a move off 10.10.10.0/24, and
        // closed a rule that had never been open while the machine was there.
        //
        // Only step 2 runs `wake_up_tracking`, which is the code the fix is
        // in. Steps 1 and 4 call `check_network` and move the tracked value
        // by hand, the way `wake_up_tracking` would: the rest of that
        // function reaches a real firewall and no test enters it. So what
        // this pins is the decision the four steps make in sequence, not
        // that one function performs all four.
        let dir = TempDir::new().unwrap();
        let state_path = dir.path().join("state.json");
        let executable = PathBuf::from("/usr/bin/porthole");
        let tracked: Mutex<Vec<Ipv4Net>> = Mutex::new(Vec::new());
        let clock = FixedClock(NOW);

        // 1. On the office network, with a rule towards it.
        let backend = FakeBackend::new();
        let open_runner = RecordingRunner::new();
        let mut engine = engine_with_rule(
            &backend,
            &open_runner,
            &clock,
            StateStore::open(&state_path).unwrap(),
            ScopeSpec::Network("10.10.10.0/24".parse().unwrap()),
        );
        let probe = RecordingRunner::with_responses(vec![
            Output::stdout(ROUTE_JSON),
            Output::stdout(ADDR_JSON),
        ]);
        let previous = tracked.lock().unwrap().clone();
        let outcome = check_network(&mut engine, &probe, &previous);
        tracked.lock().unwrap().clone_from(&outcome.last_known);
        assert_eq!(
            *tracked.lock().unwrap(),
            vec!["10.10.10.0/24".parse::<Ipv4Net>().unwrap()]
        );

        // 2. `close --all`, then a wake-up over the emptied state file. It
        //    returns before detecting a backend or running a single `ip`, so
        //    no firewall is touched -- and it must not leave the office
        //    subnet standing as though it were still an observation.
        let (closed, errors) = engine.close_all(false);
        assert_eq!(closed.len(), 1);
        assert!(errors.is_empty(), "{errors:?}");
        drop(engine);
        assert!(StateStore::open(&state_path).unwrap().rules().is_empty());

        let outcome = wake_up_tracking(&state_path, &executable, &tracked);
        assert!(outcome.closed.is_empty());
        assert!(outcome.transitions.is_empty());
        assert!(outcome.last_known.is_empty());
        assert!(
            tracked.lock().unwrap().is_empty(),
            "a wake-up that resolved no subnet must leave none tracked"
        );

        // 3. Home now, and a deliberate rule towards the office subnet.
        let backend = FakeBackend::new();
        let open_runner = RecordingRunner::new();
        let mut engine = engine_with_rule(
            &backend,
            &open_runner,
            &clock,
            StateStore::open(&state_path).unwrap(),
            ScopeSpec::Network("10.10.10.0/24".parse().unwrap()),
        );

        // 4. The next wake-up baselines instead of comparing.
        let probe = RecordingRunner::with_responses(vec![
            Output::stdout(ROUTE_JSON),
            Output::stdout(ADDR_JSON_OTHER_SUBNET),
        ]);
        let previous = tracked.lock().unwrap().clone();
        let outcome = check_network(&mut engine, &probe, &previous);
        assert!(
            outcome.closed.is_empty(),
            "the rule the user just authorised must survive: {:?}",
            outcome.closed
        );
        assert!(
            outcome.transitions.is_empty(),
            "nothing was observed before this, so there is no move to announce"
        );
        assert_eq!(
            outcome.last_known,
            vec!["192.168.1.0/24".parse::<Ipv4Net>().unwrap()]
        );
        assert_eq!(engine.rules().len(), 1);

        // The contrast that makes step 2 load-bearing: the very same step 4,
        // with the office subnet still tracked, destroys that rule.
        let stale_dir = TempDir::new().unwrap();
        let backend = FakeBackend::new();
        let open_runner = RecordingRunner::new();
        let mut engine = engine_with_rule(
            &backend,
            &open_runner,
            &clock,
            StateStore::open(stale_dir.path().join("state.json")).unwrap(),
            ScopeSpec::Network("10.10.10.0/24".parse().unwrap()),
        );
        let probe = RecordingRunner::with_responses(vec![
            Output::stdout(ROUTE_JSON),
            Output::stdout(ADDR_JSON_OTHER_SUBNET),
        ]);
        let outcome = check_network(&mut engine, &probe, &["10.10.10.0/24".parse().unwrap()]);
        assert_eq!(outcome.closed.len(), 1);
    }

    #[test]
    fn a_wake_up_with_nothing_recorded_clears_the_tracked_subnet() {
        // The narrow half of the sequence above, on its own: an empty state
        // file resolves nothing, and "nothing resolved" is recorded as
        // nothing rather than as the last thing that was.
        let dir = TempDir::new().unwrap();
        let tracked = Mutex::new(vec!["10.10.10.0/24".parse::<Ipv4Net>().unwrap()]);

        let outcome = wake_up_tracking(
            &dir.path().join("state.json"),
            &PathBuf::from("/usr/bin/porthole"),
            &tracked,
        );

        assert!(outcome.closed.is_empty());
        assert!(outcome.transitions.is_empty());
        assert!(outcome.last_known.is_empty());
        assert!(tracked.lock().unwrap().is_empty());
    }

    #[test]
    fn docking_leaves_a_rule_for_the_wifi_subnet_that_is_still_up_alone() {
        // A laptop with wifi (10.10.10.0/24, metric 600) and ethernet
        // (192.168.1.0/24, metric 100) both up. Ethernet wins the default
        // route, so the route alone would say the machine is on
        // 192.168.1.0/24 and nothing else -- and a rule aimed at the wifi
        // subnet would close while wifi was still up and still carrying its
        // traffic. The subnet sweep sees both, so nothing closes.
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
            Output::stdout(ROUTE_JSON_TWO_DEFAULT_ROUTES),
            Output::stdout(ADDR_JSON_DOCKED),
        ]);
        let outcome = check_network(&mut engine, &probe, &["10.10.10.0/24".parse().unwrap()]);

        assert!(
            outcome.closed.is_empty(),
            "wifi is still up: {:?}",
            outcome.closed
        );
        assert!(
            outcome.transitions.is_empty(),
            "nothing was lost, so there is no move to announce"
        );
        assert_eq!(
            outcome.last_known,
            vec![
                "10.10.10.0/24".parse::<Ipv4Net>().unwrap(),
                "192.168.1.0/24".parse::<Ipv4Net>().unwrap(),
            ],
            "both subnets are now tracked, and `docker0` is not one of them"
        );
        assert_eq!(engine.rules().len(), 1);
    }

    #[test]
    fn a_subnet_that_leaves_every_interface_still_closes_its_rules() {
        // The other half, and the reason tracking a set rather than one
        // subnet matters: after docking, both subnets are tracked. When wifi
        // then actually goes away, its rule must close -- a check that only
        // compared against the default route's subnet would find ethernet
        // unchanged and never notice.
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
            Output::stdout(ROUTE_JSON_ETHERNET_ONLY),
            Output::stdout(ADDR_JSON_DOCKED_ETHERNET),
        ]);
        let outcome = check_network(
            &mut engine,
            &probe,
            &[
                "10.10.10.0/24".parse().unwrap(),
                "192.168.1.0/24".parse().unwrap(),
            ],
        );

        assert_eq!(outcome.closed.len(), 1, "wifi is gone from every interface");
        assert_eq!(
            outcome.transitions,
            vec![("10.10.10.0/24".to_string(), "192.168.1.0/24".to_string())],
            "the subnet that left is named, and the one still up is where the machine is"
        );
        assert_eq!(
            outcome.last_known,
            vec!["192.168.1.0/24".parse::<Ipv4Net>().unwrap()]
        );
        assert!(engine.rules().is_empty());
    }

    /// What `iptables -t nat -S DOCKER` answers, or `None` for a read that
    /// did not happen. Exit 4 is `iptables(8)`'s "resource problem", which
    /// `porthole_core::docker::published` refuses to read as an empty chain
    /// -- unlike exit 1, which it reads as exactly that.
    struct DockerRunner {
        chain: Mutex<Option<&'static str>>,
        inner: RecordingRunner,
        /// Its own recording, so the intercepted read is visible too: a test
        /// asserting only that nothing closed would pass just as well
        /// against a wake-up that never ran the read at all.
        seen: Mutex<Vec<porthole_core::command::Command>>,
    }

    impl DockerRunner {
        fn new(chain: &'static str) -> Self {
            DockerRunner {
                chain: Mutex::new(Some(chain)),
                inner: RecordingRunner::new(),
                seen: Mutex::new(Vec::new()),
            }
        }

        /// How many times the `DOCKER` chain has been read.
        fn docker_reads(&self) -> usize {
            self.seen
                .lock()
                .expect("not poisoned")
                .iter()
                .filter(|c| c.program == "iptables" && c.args.iter().any(|a| a == "DOCKER"))
                .count()
        }

        fn answers(&self, chain: Option<&'static str>) {
            *self.chain.lock().expect("not poisoned") = chain;
        }
    }

    impl CommandRunner for DockerRunner {
        fn run(
            &self,
            cmd: &porthole_core::command::Command,
        ) -> porthole_core::error::Result<Output> {
            self.seen.lock().expect("not poisoned").push(cmd.clone());
            if cmd.program == "iptables" {
                return Ok(match *self.chain.lock().expect("not poisoned") {
                    Some(text) => Output::stdout(text),
                    None => Output {
                        status: 4,
                        stdout: String::new(),
                        stderr: "iptables: Resource temporarily unavailable.".to_string(),
                    },
                });
            }
            self.inner.run(cmd)
        }

        fn recorded(&self) -> Vec<porthole_core::command::Command> {
            self.seen.lock().expect("not poisoned").clone()
        }
    }

    /// One container publishing 3000 on loopback, towards 172.18.0.2:8080.
    const DOCKER_CHAIN: &str = "\
-N DOCKER
-A DOCKER -d 127.0.0.1/32 ! -i docker0 -p tcp -m tcp --dport 3000 -j DNAT --to-destination 172.18.0.2:8080
";

    /// The same host port, published again, by a container at a different
    /// address -- a restart that took a new lease.
    const DOCKER_CHAIN_MOVED: &str = "\
-N DOCKER
-A DOCKER -d 127.0.0.1/32 ! -i docker0 -p tcp -m tcp --dport 3000 -j DNAT --to-destination 172.18.0.9:8080
";

    /// `/proc/net/tcp`'s header, which is all a machine with nothing
    /// listening has.
    const PROC_NET_TCP_EMPTY: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
";

    /// An engine holding one live forward on 8443 towards the container in
    /// [`DOCKER_CHAIN`], created through `forward` so the backend really
    /// holds the rule.
    fn engine_with_a_forward<'a>(
        backend: &'a FakeBackend,
        runner: &'a DockerRunner,
        clock: &'a FixedClock,
        store: StateStore,
    ) -> Engine<'a> {
        let mut engine = Engine::new(
            backend,
            runner,
            clock,
            store,
            PathBuf::from("/usr/bin/porthole"),
        );
        engine
            .forward(
                &OpenRequest {
                    port: 8443,
                    protocol: Protocol::Tcp,
                    target: "10.10.10.0/24"
                        .parse::<Ipv4Net>()
                        .map(|cidr| Target::Network { cidr })
                        .unwrap(),
                    lifetime: Lifetime::UntilReboot,
                },
                3000,
                1000,
                &FakeProcFs::new(PROC_NET_TCP_EMPTY),
            )
            .unwrap();
        engine
    }

    /// The two `ip` reads one wake-up makes, answering with the subnet the
    /// forward above was opened on -- so nothing in the network half of the
    /// check moves.
    fn subnet_unchanged() -> RecordingRunner {
        RecordingRunner::with_responses(vec![Output::stdout(ROUTE_JSON), Output::stdout(ADDR_JSON)])
    }

    #[test]
    fn a_wake_up_closes_a_forward_whose_container_moved_and_does_not_call_it_a_network_change() {
        // The wiring, not the decision -- `porthole_core::engine`'s own tests
        // own that. What this pins is that the timer's wake-up reaches the
        // check at all, and that what it closes is reported apart from the
        // network-change closes: a user told "the network changed" about a
        // container that restarted would go looking at their wifi.
        let dir = TempDir::new().unwrap();
        let store = StateStore::open(dir.path().join("state.json")).unwrap();
        let backend = FakeBackend::new();
        let clock = FixedClock(NOW);
        let runner = DockerRunner::new(DOCKER_CHAIN);
        let mut engine = engine_with_a_forward(&backend, &runner, &clock, store);

        runner.answers(Some(DOCKER_CHAIN_MOVED));
        let outcome = check(
            &mut engine,
            &subnet_unchanged(),
            &["10.10.10.0/24".parse().unwrap()],
        );

        assert_eq!(outcome.stale.len(), 1, "the moved forward must close");
        assert_eq!(outcome.stale[0].port, 8443);
        assert!(
            outcome.closed.is_empty(),
            "and must not be reported as a network change: {:?}",
            outcome.closed
        );
        assert!(outcome.transitions.is_empty(), "the subnet did not move");
        assert!(engine.rules().is_empty());
        assert!(backend.handles().is_empty(), "gone from the firewall too");
    }

    #[test]
    fn a_wake_up_that_cannot_read_docker_closes_no_forward() {
        // Not knowing is not knowing it changed. The same property
        // `porthole_core::engine`'s own `an_unreadable_docker_table_closes_nothing`
        // pins, checked once more where the timer actually reaches it: a
        // wake-up that ran the read and got nothing must leave the rule
        // exactly where it was.
        let dir = TempDir::new().unwrap();
        let store = StateStore::open(dir.path().join("state.json")).unwrap();
        let backend = FakeBackend::new();
        let clock = FixedClock(NOW);
        let runner = DockerRunner::new(DOCKER_CHAIN);
        let mut engine = engine_with_a_forward(&backend, &runner, &clock, store);

        runner.answers(None);
        let outcome = check(
            &mut engine,
            &subnet_unchanged(),
            &["10.10.10.0/24".parse().unwrap()],
        );

        assert!(outcome.stale.is_empty(), "a failed read must close nothing");
        assert!(outcome.closed.is_empty());
        assert_eq!(engine.rules().len(), 1, "the record must survive");
        assert_eq!(backend.handles().len(), 1, "and so must the rule itself");
        assert_eq!(
            runner.docker_reads(),
            2,
            "one read to create the forward and one for the sweep -- without the \
             second this test would pass against a wake-up that never checked"
        );
    }

    #[test]
    fn a_wake_up_reads_docker_only_when_a_forward_exists_to_compare() {
        // The monitor wakes every 60 seconds forever. On a machine holding
        // one ordinary `open` and no forward, the stale-forward sweep ran on
        // every one of those wake-ups -- an `iptables -t nat -S DOCKER` and
        // a second full reconciliation, permanently, for an answer that
        // cannot be anything but "nothing". The empty-state shortcut in
        // `wake_up_tracking` covers a machine with no rules at all and
        // covers this not at all.
        let dir = TempDir::new().unwrap();
        let store = StateStore::open(dir.path().join("state.json")).unwrap();
        let backend = FakeBackend::new();
        let clock = FixedClock(NOW);
        let runner = DockerRunner::new(DOCKER_CHAIN);

        // An ordinary open and nothing else. `DockerRunner` passes anything
        // that is not `iptables` through, so this is the same open every
        // other test here makes.
        let mut engine = Engine::new(
            &backend,
            &runner,
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

        let outcome = check(
            &mut engine,
            &subnet_unchanged(),
            &["10.10.10.0/24".parse().unwrap()],
        );

        assert!(outcome.stale.is_empty());
        assert_eq!(engine.rules().len(), 1, "the open is untouched");
        assert_eq!(
            runner.docker_reads(),
            0,
            "nothing in state redirects, so there is nothing to compare and \
             nothing to read"
        );

        // The control, and it is the point: with a forward in state the same
        // wake-up does read. Without it this test would pass just as well
        // against a monitor that had stopped sweeping altogether.
        let dir = TempDir::new().unwrap();
        let store = StateStore::open(dir.path().join("state.json")).unwrap();
        let runner = DockerRunner::new(DOCKER_CHAIN);
        let mut engine = engine_with_a_forward(&backend, &runner, &clock, store);
        let before = runner.docker_reads();
        check(
            &mut engine,
            &subnet_unchanged(),
            &["10.10.10.0/24".parse().unwrap()],
        );
        assert_eq!(
            runner.docker_reads(),
            before + 1,
            "a forward in state is what the sweep is for"
        );
    }

    #[test]
    fn a_wake_up_leaves_a_forward_towards_a_container_that_has_not_moved_alone() {
        // Without this every assertion above is satisfied by a wake-up that
        // closes every forward it finds.
        let dir = TempDir::new().unwrap();
        let store = StateStore::open(dir.path().join("state.json")).unwrap();
        let backend = FakeBackend::new();
        let clock = FixedClock(NOW);
        let runner = DockerRunner::new(DOCKER_CHAIN);
        let mut engine = engine_with_a_forward(&backend, &runner, &clock, store);

        let outcome = check(
            &mut engine,
            &subnet_unchanged(),
            &["10.10.10.0/24".parse().unwrap()],
        );

        assert!(outcome.stale.is_empty(), "stale: {:?}", outcome.stale);
        assert_eq!(engine.rules().len(), 1);
        assert_eq!(backend.handles().len(), 1);
        assert_eq!(runner.docker_reads(), 2, "the sweep has to have looked");
    }

    /// The one session bus this crate's unit tests touch, started once and
    /// shared by every test in this binary.
    ///
    /// The same shape as `tests/common/mod.rs`'s, written out again because a
    /// `#[cfg(test)]` module inside the library cannot see a file under
    /// `tests/` — integration tests link the library as an external crate, so
    /// there is no direction in which one definition can serve both. It is
    /// here for the same reason it is there: the test below used
    /// `Connection::session()`, which is the *developer's* bus, and two
    /// concurrent `cargo test` runs then delivered each other's `RuleClosed`
    /// to each other's subscribers. Measured, with the two runs' rule ids
    /// swapped:
    ///
    /// ```text
    /// assertion `left == right` failed: the reason travels with its rule
    ///   left: "9fe1a756-588a-4559-9f24-5fb44b708925"
    ///  right: "726f37d1-8364-4f1d-8a84-0e76d9528b73"
    /// ```
    ///
    /// Addressed rather than by environment variable: `session()` reads this
    /// process's own `DBUS_SESSION_BUS_ADDRESS`, and `std::env::set_var` is
    /// unsound with other tests' threads running, so an in-process connection
    /// has to be handed the address at the call site.
    fn private_bus_address() -> &'static str {
        use std::io::BufRead as _;
        use std::process::{Child, Command, Stdio};
        use std::sync::OnceLock;

        // The daemon is alive for as long as the pipe its inner shell reads
        // stays open. This process exiting closes that pipe, the shell exits,
        // and the daemon goes down with it -- so nothing is left behind even
        // though this value is never dropped.
        static BUS: OnceLock<(Child, String)> = OnceLock::new();
        &BUS.get_or_init(|| {
            // Asserted, not skipped: a test that cannot get its own bus must
            // fail rather than quietly run against this machine's.
            let mut daemon = Command::new("dbus-run-session")
                .args([
                    "--",
                    "sh",
                    "-c",
                    r#"echo "$DBUS_SESSION_BUS_ADDRESS"; exec cat >/dev/null"#,
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .expect("dbus-run-session is installed");
            let mut address = String::new();
            std::io::BufReader::new(daemon.stdout.take().expect("stdout was piped"))
                .read_line(&mut address)
                .expect("the private bus prints its address");
            let address = address.trim().to_string();
            assert!(!address.is_empty(), "dbus-run-session printed no address");
            (daemon, address)
        })
        .1
    }

    #[tokio::test]
    async fn a_stale_forwards_close_reaches_the_bus_as_target_gone_not_a_network_change() {
        // The tests above pin which list -- `stale` or `closed` -- a moved
        // container's forward lands in. None of them call
        // `announce_outcome`, the function that turns that list into a
        // `CloseReason` on the wire, so none of them would notice a mutant
        // that swapped which reason each loop announces. This one does: a
        // real subscriber on a real bus, decoding the signal
        // `announce_outcome` actually sent.
        let name = "com.jacopobriccola.PortholeTestNetmonStaleReason";
        let address = private_bus_address();
        let bus = zbus::connection::Builder::address(address)
            .unwrap()
            .build()
            .await
            .unwrap();
        let service = Porthole::new(
            Box::new(Arc::new(AlwaysAllow::default())),
            bus,
            PathBuf::from("/nonexistent/state.json"),
            PathBuf::from("/usr/bin/porthole"),
            crate::retire::Retirement::never(),
        );
        let server = zbus::connection::Builder::address(address)
            .unwrap()
            .name(name)
            .unwrap()
            .serve_at(PATH, service)
            .unwrap()
            .build()
            .await
            .unwrap();
        let emitter = SignalEmitter::new(&server, PATH).unwrap().into_owned();

        let client = zbus::connection::Builder::address(address)
            .unwrap()
            .build()
            .await
            .unwrap();
        let proxy = PortholeProxy::builder(&client)
            .destination(name)
            .unwrap()
            .build()
            .await
            .unwrap();
        let mut signals = proxy.receive_rule_closed().await.unwrap();

        // A real forward, built through `forward` the same way
        // `engine_with_a_forward` builds it for every other test in this
        // file -- a hand-written `ManagedRule` would prove nothing about
        // what `close_stale_forwards` itself hands `announce_outcome`.
        let dir = TempDir::new().unwrap();
        let store = StateStore::open(dir.path().join("state.json")).unwrap();
        let backend = FakeBackend::new();
        let clock = FixedClock(NOW);
        let runner = DockerRunner::new(DOCKER_CHAIN);
        let mut engine = engine_with_a_forward(&backend, &runner, &clock, store);
        let rule = engine.rules()[0].clone();

        let outcome = CheckOutcome {
            closed: Vec::new(),
            transitions: Vec::new(),
            last_known: Vec::new(),
            reconciled: Vec::new(),
            stale: vec![rule.clone()],
        };
        announce_outcome(&outcome, Some(&emitter)).await;

        let signal = tokio::time::timeout(Duration::from_secs(5), signals.next())
            .await
            .expect("no signal arrived before the timeout")
            .expect("the signal stream ended instead of yielding");
        let args = signal.args().unwrap();
        assert_eq!(
            args.reason.as_str(),
            "target-gone",
            "a forward closed because its container moved must not be announced \
             as a network change"
        );
        assert_eq!(args.rule.id, rule.id, "the reason travels with its rule");
    }
}
