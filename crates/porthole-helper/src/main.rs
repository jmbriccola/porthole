//! porthole's privileged half.
//!
//! Serves `com.jacopobriccola.Porthole` on the **system** bus, where polkit
//! decides who may do what. `--session` serves the same interface on the
//! session bus instead, which is how every integration test in this milestone
//! runs without root — and because polkit does not exist there, that flag
//! forces the always-allow authorizer. A helper therefore cannot be tricked
//! into serving the real bus without authorization, nor the session bus with
//! it.

use porthole_core::ipc::{PATH, SERVICE};
use porthole_core::state::StateStore;
use porthole_helper::authz::{AlwaysAllow, Authorizer};
use porthole_core::cli_path;
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
