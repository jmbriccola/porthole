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
use porthole_core::state::StateStore;
use porthole_helper::authz::{AlwaysAllow, Authorizer};
use porthole_helper::polkit::PolkitAuthorizer;
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
    reconcile_at_startup();

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

    let service = Porthole::new(authorizer, bus, StateStore::default_path(), cli);

    let _conn = serving
        .name(SERVICE)?
        .serve_at(PATH, service)?
        .build()
        .await?;

    eprintln!("porthole-helper: serving {SERVICE}");
    tokio::signal::ctrl_c().await?;
    Ok(())
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
fn reconcile_at_startup() {
    let runner = RealRunner;
    let backend = match backend::detect(&runner) {
        Ok(backend) => backend,
        Err(e) => {
            eprintln!("porthole-helper: start-up reconciliation skipped, no firewall backend: {e}");
            return;
        }
    };
    let mut state = match StateStore::open_exclusive(StateStore::default_path()) {
        Ok(state) => state,
        Err(e) => {
            eprintln!(
                "porthole-helper: start-up reconciliation skipped, could not take the state \
                 lock: {e}"
            );
            return;
        }
    };
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
        }
        Err(e) => {
            eprintln!("porthole-helper: start-up reconciliation failed, continuing anyway: {e}");
        }
    }
}
