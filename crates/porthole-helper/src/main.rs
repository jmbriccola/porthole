//! porthole's privileged half.
//!
//! Serves `com.jacopobriccola.Porthole` on the **system** bus, where polkit
//! decides who may do what. `--session` serves the same interface on the
//! session bus instead, which is how every integration test in this milestone
//! runs without root — and because polkit does not exist there, that flag
//! forces the always-allow authorizer. A helper therefore cannot be tricked
//! into serving the real bus without authorization, nor the session bus with
//! it.

use porthole_core::backend;
use porthole_core::cli_path;
use porthole_core::command::RealRunner;
use porthole_core::ipc::{PATH, SERVICE};
use porthole_core::reconcile::{self, SweepMode};
use porthole_core::state::{ManagedRule, StateStore};
use porthole_helper::authz::{AlwaysAllow, Authorizer};
use porthole_helper::netmon;
use porthole_helper::polkit::PolkitAuthorizer;
use porthole_helper::retire::Retirement;
use porthole_helper::service::Porthole;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let session = std::env::args().any(|a| a == "--session");

    // Debug builds only. A release helper honouring this would let anyone who
    // could start it as root serve a privileged interface on a session bus
    // with no polkit anywhere — contrived, but free to close. Same reasoning
    // and same guard as PORTHOLE_STATE_FILE in porthole-core::state.
    if session && !cfg!(debug_assertions) {
        eprintln!(
            "porthole-helper: --session exists for tests and is not available in release builds"
        );
        std::process::exit(2);
    }

    // Fail loudly here, before ever claiming the bus name: a helper that
    // starts, accepts openings, and only discovers it cannot schedule their
    // close once the first timer is due is worse than one that refuses to
    // start.
    let cli = match cli_path::resolve_cli() {
        Ok(path) => path,
        Err(e) => {
            eprintln!("porthole-helper: refusing to start: {e}");
            std::process::exit(1);
        }
    };

    // Reconcile once now, before anything can reach the bus. Per-operation
    // reconciliation (`Engine::reconcile`) covers a `firewall-cmd --reload`
    // mid-session, but nothing runs between a reboot and the first client
    // request -- which, for a D-Bus-activated helper, may be a long time
    // coming, or may never come before the next reboot. The spec's mandatory
    // acceptance test is "open a port on ufw, reboot, verify it is closed",
    // and only a start-up sweep, not the per-operation one, is what makes
    // that true.
    //
    // What it dropped is announced further down, once there is a bus to
    // announce it on -- the sweep itself still runs first, before anything
    // can reach the name.
    let reconciled = reconcile_at_startup();

    let (bus, serving) = if session {
        eprintln!("porthole-helper: session bus, authorization disabled — tests only");
        (
            zbus::Connection::session().await?,
            zbus::connection::Builder::session()?,
        )
    } else {
        (
            zbus::Connection::system().await?,
            zbus::connection::Builder::system()?,
        )
    };

    // The session bus has no polkit, so serving there without AlwaysAllow
    // would be serving a privileged interface with nothing guarding it.
    let authorizer: Box<dyn Authorizer> = if session {
        Box::new(AlwaysAllow::default())
    } else {
        Box::new(PolkitAuthorizer::new(&bus).await?)
    };

    let state_path = StateStore::default_path();
    // Built before the object is served, because every interface method asks
    // it for admission -- see `porthole_helper::retire` for the whole of what
    // it decides and why the obvious sequence is wrong.
    let retirement = Retirement::from_env(session);
    let service = Porthole::new(
        authorizer,
        bus,
        state_path.clone(),
        cli.clone(),
        retirement.clone(),
    );

    let conn = serving
        .name(SERVICE)?
        .serve_at(PATH, service)?
        .build()
        .await?;

    eprintln!("porthole-helper: serving {SERVICE}");

    // Only now: the start-up sweep ran before the bus name existed, on
    // purpose (see `reconcile_at_startup`), and a signal emitted before that
    // has no sender name for a subscriber to match on. Announced here
    // instead, which does mean a client that connects after this line has
    // already missed them -- `list` is what such a client reads to find out
    // what is open, and these rules are exactly the ones that are not in it.
    announce_reconciled(&conn, &reconciled).await;

    // The monitor closes rules in whatever firewall this machine has, on its
    // own timer, with no client asking -- so it runs on the system bus, and
    // under `--session` only when `PORTHOLE_NETMON` says the firewall is
    // disposable. `netmon::should_run` holds the whole rule and the reasons
    // for it.
    //
    // Its own connection, not the one just moved into `service`: that one is
    // already spoken for (`Porthole` uses it to ask the bus daemon who a
    // caller is).
    if netmon::should_run(session) {
        tokio::spawn(netmon::run(conn.clone(), state_path.clone(), cli));
    }

    // Three ways this process ends, and they race on purpose.
    //
    // `retirement.run` never returns: with no rule open and nothing in
    // flight, it gives up the bus name and ends the process itself, and the
    // bus starts a new helper the moment one is wanted again. On a helper
    // that is not eligible to retire it simply never completes.
    //
    // The two signals are the ways somebody else ends it. `SIGTERM` is new
    // here and is not a nicety: systemd sends one to a `Type=dbus` unit
    // **40 microseconds** after it releases its `BusName`, measured, so a
    // helper that handled only `SIGINT` would be killed by the default
    // disposition in the middle of its own retirement -- the drain would
    // never run. `terminated` therefore asks whether this particular
    // `SIGTERM` is systemd acknowledging a retirement already under way, and
    // lets that retirement finish; any other one ends the process here, which
    // is what `systemctl stop` and a package `try-restart` expect and get
    // today.
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = terminated(&retirement) => {}
        _ = retirement.clone().run(conn, state_path) => {}
    }
    Ok(())
}

/// Wait for a `SIGTERM` that is somebody asking this process to stop, rather
/// than systemd acknowledging the retirement it is already carrying out.
///
/// Returns on the first of the former. A `SIGTERM` that arrives while
/// [`Retirement::is_retiring`] holds is dropped and the wait resumes: the
/// retirement is a few tens of milliseconds from calling `exit(0)` itself,
/// and systemd's own `TimeoutStopSec=90s` is ample room for it. The exit is
/// still recorded as `Deactivated successfully` either way -- measured.
async fn terminated(retirement: &Retirement) {
    let mut term = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        Ok(term) => term,
        Err(e) => {
            // Without a handler the default disposition kills the process,
            // which is the behaviour this helper had until now: say so, and
            // let the other two arms of the race carry on.
            eprintln!(
                "porthole-helper: could not install a SIGTERM handler ({e}); a stop arriving \
                 during a retirement will end this process before it has finished draining"
            );
            std::future::pending().await
        }
    };
    while term.recv().await.is_some() {
        if !retirement.is_retiring() {
            return;
        }
    }
}

/// Reconcile once, under the exclusive lock, before the helper is reachable
/// on the bus at all.
///
/// This is the only sweep that ever runs without a client asking for
/// anything, and it is the one that makes "open a port on ufw, reboot,
/// verify it is closed" actually true: nothing else runs between a reboot
/// and the first client request, which for a D-Bus-activated helper may not
/// come for a long time, if ever, before the machine reboots again.
/// `Engine::reconcile`'s per-operation sweep covers everything that happens
/// *after* the helper is already up (a `firewall-cmd --reload` mid-session,
/// say) — it cannot cover the gap before the first request exists to trigger
/// it.
///
/// Every failure here is logged and otherwise ignored, the same policy
/// `Engine::reconcile` already applies to the per-operation sweep: a helper
/// that refused to start because an unrelated stale rule would not clean up
/// is a worse outcome than one that starts anyway and leaves the rule for
/// the next sweep to find.
///
/// **If the exclusive lock is held by another process** (`state::
/// lock_exclusive`'s bounded, non-blocking wait — see its own doc comment
/// for why that bound exists at all), this waits out that same bound and
/// then does exactly what every other failure here does: logs it and skips
/// the start-up sweep entirely, rather than delaying the helper's own start
/// by any more than that bound. The helper still starts and still serves the
/// bus; only the extra staleness-shortening this sweep would have bought is
/// lost, and the per-operation sweep catches up on the next request.
fn reconcile_at_startup() -> Vec<ManagedRule> {
    let runner = RealRunner;
    let backend = match backend::detect(&runner) {
        Ok(backend) => backend,
        Err(e) => {
            eprintln!("porthole-helper: start-up reconciliation skipped, no firewall backend: {e}");
            return Vec::new();
        }
    };
    let mut state = match StateStore::open_exclusive(StateStore::default_path()) {
        Ok(state) => state,
        Err(e) => {
            eprintln!(
                "porthole-helper: start-up reconciliation skipped, could not take the state \
                 lock: {e}"
            );
            return Vec::new();
        }
    };
    let backend_id = backend.id();
    match reconcile::sweep(
        backend.as_ref(),
        &mut state,
        SweepMode::Apply { dry_run: false },
    ) {
        Ok(report) => {
            for failure in &report.failures {
                eprintln!(
                    "porthole-helper: start-up reconciliation could not remove one orphaned \
                     rule, continuing: {failure}"
                );
            }
            if let Some(e) = &report.orphan_sweep_error {
                eprintln!(
                    "porthole-helper: start-up reconciliation could not check for orphaned \
                     rules, continuing: {e}"
                );
            }
            for rule in &report.foreign_backend {
                eprintln!(
                    "porthole-helper: start-up reconciliation found {}/{} recorded under \
                     backend {}, but {backend_id} is what this machine has now -- leaving it \
                     in state unclosed rather than guessing whether it is still open in the \
                     old firewall",
                    rule.port, rule.protocol, rule.backend,
                );
            }
            // The state entries whose rule the firewall no longer had. Not
            // logged here: `announce_reconciled` writes the journal line and
            // the signal together, so neither can happen without the other.
            report.dropped_from_state
        }
        Err(e) => {
            eprintln!("porthole-helper: start-up reconciliation failed, continuing anyway: {e}");
            Vec::new()
        }
    }
}

/// Say what the start-up sweep dropped, on the journal and on the bus.
///
/// [`CloseReason::Reconciled`] rather than any of the other three: porthole
/// did not close these, and does not know when they stopped being open. It
/// found its own record of a rule the firewall no longer had, and dropped
/// the record -- which is a real thing to tell someone who opened a port
/// before the last reboot, and a different thing from "your port has just
/// been closed".
///
/// This sweep is not the only one that can drop a record: every operation
/// reconciles too, and those drops reach the bus the same way, through
/// `Porthole::announce_reconciled`. Only the emitter differs -- this one is
/// built here because there is no client request to have supplied one.
async fn announce_reconciled(conn: &zbus::Connection, rules: &[ManagedRule]) {
    if rules.is_empty() {
        return;
    }
    let emitter = match zbus::object_server::SignalEmitter::new(conn, PATH) {
        Ok(emitter) => Some(emitter),
        Err(e) => {
            eprintln!(
                "porthole-helper: no signal emitter, what the start-up sweep dropped will go \
                 unannounced (the journal below still records it): {e}"
            );
            None
        }
    };
    Porthole::announce_reconciled(emitter.as_ref(), rules).await;
}
