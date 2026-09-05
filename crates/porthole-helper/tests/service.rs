//! Drives the real service object over a real session bus with a fake
//! authorizer, so every method is exercised end to end without root, without
//! polkit, and without touching the firewall.

use porthole_core::ipc::{PortholeProxy, PATH};
use porthole_helper::authz::{Action, AlwaysAllow};
use porthole_helper::cli_path::CLI_CANDIDATES;
use porthole_helper::service::Porthole;
use std::sync::Arc;
use tempfile::TempDir;

/// A unique bus name per test, so tests can run in parallel and none of them
/// ever squats the production name.
fn probe_name(suffix: &str) -> String {
    format!("com.jacopobriccola.PortholeTest{suffix}")
}

async fn serve(
    suffix: &str,
    state: &std::path::Path,
) -> (zbus::Connection, Arc<AlwaysAllow>, String) {
    let authorizer = Arc::new(AlwaysAllow::default());
    let bus = zbus::Connection::session().await.unwrap();
    let service = Porthole::new(
        Box::new(Arc::clone(&authorizer)),
        bus,
        state.to_path_buf(),
        // Not a second hardcoded literal: this must track however
        // `cli_path::resolve_cli` actually picks a candidate, or the two can
        // silently drift apart the way the CLI's install path and the timer's
        // once did.
        std::path::PathBuf::from(CLI_CANDIDATES[0]),
    );
    let name = probe_name(suffix);
    let conn = zbus::connection::Builder::session()
        .unwrap()
        .name(name.clone())
        .unwrap()
        .serve_at(PATH, service)
        .unwrap()
        .build()
        .await
        .unwrap();
    (conn, authorizer, name)
}

#[tokio::test]
async fn list_is_empty_before_anything_is_opened() {
    let dir = TempDir::new().unwrap();
    let (_server, _authz, name) = serve("List", &dir.path().join("state.json")).await;

    let client = zbus::Connection::session().await.unwrap();
    let proxy = PortholeProxy::builder(&client)
        .destination(name)
        .unwrap()
        .build()
        .await
        .unwrap();

    assert!(proxy.list().await.unwrap().is_empty());
}

/// This test drives the *real* engine against the *real* `firewall-cmd`,
/// relying on firewalld's own polkit refusing an unprivileged caller so
/// nothing is actually added. Under root that assumption is false: the open
/// would genuinely succeed, and the temp state directory vanishing at the end
/// of the test would leave a real rule in the firewall with nothing able to
/// close it. `cli.rs` already guards its own real-firewall tests the same way.
fn is_root() -> bool {
    // SAFETY: geteuid takes no arguments and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

#[tokio::test]
async fn opening_towards_everyone_asks_for_the_stronger_action() {
    if is_root() {
        eprintln!("skipped: running as root, where firewalld would not refuse this open");
        return;
    }
    // `--to any` and `--to 0.0.0.0/0` produce identical exposure, so both must
    // reach open-any. A client must not get the weaker authorization by
    // spelling "everyone" as a CIDR.
    let dir = TempDir::new().unwrap();
    let (_server, authz, name) = serve("Any", &dir.path().join("state.json")).await;

    let client = zbus::Connection::session().await.unwrap();
    let proxy = PortholeProxy::builder(&client)
        .destination(name)
        .unwrap()
        .build()
        .await
        .unwrap();

    // The firewall is not touched: this environment has firewalld, so the open
    // may fail at the backend — what matters is which action was checked
    // first, which happens before any firewall call.
    let _ = proxy.open(15173, "tcp", "0.0.0.0/0", 60).await;

    let asked: Vec<String> = authz.asked().into_iter().map(|(a, _)| a).collect();
    assert_eq!(
        asked,
        vec![Action::OpenAny.id().to_string()],
        "a /0 must take the same action as `any`"
    );
}

#[tokio::test]
async fn an_invalid_protocol_is_refused_before_anything_is_authorized() {
    // The helper validates for itself. A client cannot make it act on a value
    // it would not have accepted from a person.
    let dir = TempDir::new().unwrap();
    let (_server, authz, name) = serve("Proto", &dir.path().join("state.json")).await;

    let client = zbus::Connection::session().await.unwrap();
    let proxy = PortholeProxy::builder(&client)
        .destination(name)
        .unwrap()
        .build()
        .await
        .unwrap();

    let err = proxy.open(5173, "sctp", "subnet", 60).await.unwrap_err();
    assert!(
        format!("{err:?}").contains("InvalidArgument"),
        "expected a typed InvalidArgument, got: {err:?}"
    );
    assert!(
        authz.asked().is_empty(),
        "nothing may be authorized before the input is known to be valid"
    );
}

#[tokio::test]
async fn a_duration_over_the_ceiling_is_refused() {
    let dir = TempDir::new().unwrap();
    let (_server, authz, name) = serve("Ceiling", &dir.path().join("state.json")).await;

    let client = zbus::Connection::session().await.unwrap();
    let proxy = PortholeProxy::builder(&client)
        .destination(name)
        .unwrap()
        .build()
        .await
        .unwrap();

    // 8 hours and one second. The ceiling is the promise, not a preference.
    let err = proxy.open(5173, "tcp", "subnet", 28801).await.unwrap_err();
    assert!(
        format!("{err:?}").contains("InvalidArgument"),
        "got: {err:?}"
    );
    assert!(authz.asked().is_empty());
}

#[tokio::test]
async fn port_zero_is_not_a_port() {
    let dir = TempDir::new().unwrap();
    let (_server, _authz, name) = serve("Zero", &dir.path().join("state.json")).await;

    let client = zbus::Connection::session().await.unwrap();
    let proxy = PortholeProxy::builder(&client)
        .destination(name)
        .unwrap()
        .build()
        .await
        .unwrap();

    let err = proxy.open(0, "tcp", "subnet", 60).await.unwrap_err();
    assert!(
        format!("{err:?}").contains("InvalidArgument"),
        "got: {err:?}"
    );
}

#[tokio::test]
async fn closing_something_that_is_not_open_says_so() {
    let dir = TempDir::new().unwrap();
    let (_server, _authz, name) = serve("Missing", &dir.path().join("state.json")).await;

    let client = zbus::Connection::session().await.unwrap();
    let proxy = PortholeProxy::builder(&client)
        .destination(name)
        .unwrap()
        .build()
        .await
        .unwrap();

    let err = proxy.close(5173, "tcp").await.unwrap_err();
    assert!(format!("{err:?}").contains("RuleNotFound"), "got: {err:?}");
}
