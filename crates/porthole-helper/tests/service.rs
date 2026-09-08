//! Drives the real service object over a real session bus with a fake
//! authorizer, so every method is exercised end to end without root and
//! without polkit.
//!
//! Nothing here asks a firewall to change. The reads that reach one are
//! `backend::detect`'s (`firewall-cmd --version` and `--state`, or their
//! ufw/nftables equivalents) and, below, one `iptables -t nat -S DOCKER`.
//! What an open a firewall performs, and one it refuses, actually do is in
//! `crates/porthole-cli/tests/container.rs`, where the firewall goes away
//! with its container.

use porthole_core::cli_path::CLI_CANDIDATES;
use porthole_core::ipc::{PortholeProxy, PATH};
use porthole_helper::authz::{Action, AlwaysAllow};
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

/// The typed refusals that can only come from `Porthole::open` *before* it
/// builds an `Engine`: `backend::detect` finding no firewall at all, and the
/// exclusive state lock refusing to open. Nothing past either of them is
/// reached, and every `firewall-cmd` that could change something is past both.
fn stopped_before_the_engine(err: &zbus::Error) -> bool {
    match err {
        zbus::Error::MethodError(name, _, _) => {
            name.as_str().ends_with("State") || name.as_str().ends_with("BackendUnavailable")
        }
        _ => false,
    }
}

#[tokio::test]
async fn opening_towards_everyone_asks_for_the_stronger_action() {
    // `--to any` and `--to 0.0.0.0/0` produce identical exposure, so both must
    // reach open-any. A client must not get the weaker authorization by
    // spelling "everyone" as a CIDR.
    //
    // The action is chosen and checked before the state lock is taken, and
    // the state lock is taken before an `Engine` exists — so a state path
    // whose parent is a regular file rather than a directory ends each
    // request there, with the authorization already recorded and no
    // firewall command that could change anything ever run. This test used
    // to let both opens run all the way through to a real
    // `firewall-cmd --add-rich-rule` against whatever firewall the machine
    // running the suite has, which on firewalld put two polkit password
    // prompts on the developer's screen every time it ran. What is under
    // test here is which action was asked for, which nothing downstream of
    // that point can change.
    let dir = TempDir::new().unwrap();
    let not_a_directory = dir.path().join("not-a-directory");
    std::fs::write(&not_a_directory, "").expect("the temp dir is writable");
    let (_server, authz, name) = serve("Any", &not_a_directory.join("state.json")).await;

    let client = zbus::Connection::session().await.unwrap();
    let proxy = PortholeProxy::builder(&client)
        .destination(name)
        .unwrap()
        .build()
        .await
        .unwrap();

    let any = proxy
        .open(15173, "tcp", "0.0.0.0/0", 60)
        .await
        .expect_err("the state path is unusable, so this cannot succeed");

    // I4's classifier (`is_open_any`) also treats a half of the address space
    // as open-any — 0.0.0.0/1 and 128.0.0.0/1 together are total exposure,
    // and neither one is literally 0.0.0.0/0 — and that half is covered by a
    // unit test on the classifier directly (`engine.rs`'s
    // `splitting_the_whole_address_space_in_half_does_not_hide_it_from_open_any`).
    // Nothing exercised it through the service, which is where the action is
    // actually chosen, until this call.
    let half = proxy
        .open(25173, "tcp", "0.0.0.0/1", 60)
        .await
        .expect_err("the state path is unusable, so this cannot succeed");

    // Not decoration: this is what shows each request ended where the comment
    // above says it did, rather than having gone on to ask a real firewall
    // for something.
    for err in [&any, &half] {
        assert!(
            stopped_before_the_engine(err),
            "the open must end before an engine exists, got: {err}"
        );
    }

    let asked: Vec<String> = authz.asked().into_iter().map(|(a, _)| a).collect();
    assert_eq!(
        asked,
        vec![
            Action::OpenAny.id().to_string(),
            Action::OpenAny.id().to_string(),
        ],
        "both a /0 and a /1 must take the same action as `any`"
    );
}

/// `a_forward_asks_every_time_whatever_it_is_towards` used to sit here. It
/// moved to `tests/forward_gate.rs`, whose own module doc says why: a
/// forward now asks the detected firewall whether it can redirect *before*
/// it authorizes, so "a forward reaches the authorizer" holds only where
/// that firewall can. The moved test puts a stub `firewall-cmd` on `PATH`
/// and asserts the same thing on every machine.

#[tokio::test]
async fn a_forward_of_a_port_no_container_could_publish_is_refused_unauthorized() {
    // published_port 0 is not a port. Refused where every other invalid
    // argument is -- before anything is authorized, so a client cannot make
    // the helper put a prompt on someone's screen for a request it was never
    // going to act on.
    let dir = TempDir::new().unwrap();
    let (_server, authz, name) = serve("ForwardZero", &dir.path().join("state.json")).await;

    let client = zbus::Connection::session().await.unwrap();
    let proxy = PortholeProxy::builder(&client)
        .destination(name)
        .unwrap()
        .build()
        .await
        .unwrap();

    for (port, published) in [(0u16, 3000u16), (18080, 0)] {
        let err = proxy
            .forward(port, "tcp", "subnet", 60, published)
            .await
            .unwrap_err();
        assert!(
            format!("{err:?}").contains("InvalidArgument"),
            "expected a typed InvalidArgument for {port}/{published}, got: {err:?}"
        );
    }
    let err = proxy
        .forward(18080, "sctp", "subnet", 60, 3000)
        .await
        .unwrap_err();
    assert!(
        format!("{err:?}").contains("InvalidArgument"),
        "got: {err:?}"
    );
    assert!(
        authz.asked().is_empty(),
        "nothing may be authorized before the input is known to be valid"
    );
}

/// `docker_ports` reaches the real `Porthole::docker_ports` method over a
/// real bus, exactly the way `list` does above -- what this actually proves
/// is that the method is wired onto the interface and authorized the same
/// way `list`/`status` are. It is authorized first: `authz.asked()` records
/// the check regardless of what the read itself does next. This helper runs
/// unprivileged, so `iptables -t nat -S DOCKER` itself fails with permission
/// denied here (exit 4, `iptables(8)`'s own resource-problem code) whether
/// or not Docker is installed, and `porthole_core::docker::published`
/// propagates that as a real error rather than reading it as "no ports" --
/// see its own doc comment -- so this call is expected to fail. The
/// production helper always runs as root, where this permission error never
/// happens. `iptables -S` is a listing either way: there is no argument here
/// that could change a rule, whatever privilege the process has.
#[tokio::test]
async fn docker_ports_is_reachable_and_authorized_like_list() {
    let dir = TempDir::new().unwrap();
    let (_server, authz, name) = serve("Docker", &dir.path().join("state.json")).await;

    let client = zbus::Connection::session().await.unwrap();
    let proxy = PortholeProxy::builder(&client)
        .destination(name)
        .unwrap()
        .build()
        .await
        .unwrap();

    let err = proxy.docker_ports().await.unwrap_err();
    assert!(
        format!("{err:?}").contains("CommandFailed"),
        "expected a typed CommandFailed (this helper cannot read iptables unprivileged), \
         got: {err:?}"
    );
    let asked: Vec<String> = authz.asked().into_iter().map(|(a, _)| a).collect();
    assert_eq!(asked, vec![Action::List.id().to_string()]);
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
