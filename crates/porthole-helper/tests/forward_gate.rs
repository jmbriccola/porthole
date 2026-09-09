//! Whether `Porthole::forward` asks the firewall what it can do before it
//! asks a person for a password.
//!
//! # Why this is a file of its own, with exactly one test in it
//!
//! The helper detects its firewall through `RealRunner`, which spawns real
//! processes off the real `PATH`. There is no seam to inject a backend
//! through, so the only way to put this process in front of a firewall that
//! cannot redirect -- and, in the second half, in front of one that can --
//! is to change `PATH` itself. `std::env::set_var` is process-wide, and
//! `tests/service.rs` runs its tests on threads in parallel, so a `PATH`
//! switch there would race with every other test's own subprocesses.
//!
//! Cargo gives each integration test file its own process. One test in this
//! one means the switch has nobody to race with, and the two halves run in
//! sequence inside it.
//!
//! # Why the second half is here rather than in `tests/service.rs`
//!
//! It used to be `a_forward_asks_every_time_whatever_it_is_towards` there,
//! and it passed on any machine because the authorization came first. Now
//! that the capability question comes first, that test's premise -- that a
//! forward reaches the authorizer at all -- holds only where the detected
//! firewall can redirect. On a ufw or nftables developer machine it would
//! have started failing for a reason that has nothing to do with what it
//! asserts. With a stub `firewall-cmd` on `PATH` it holds everywhere, which
//! is a better test than the one it replaces.
//!
//! Nothing here reaches a real firewall: both halves stop at the exclusive
//! state lock, whose path is deliberately unusable, and the only programs on
//! `PATH` are the two stubs this file writes. Nothing here reaches a real
//! *bus* either: both halves serve on this binary's own session bus, so a
//! second `cargo test` cannot answer this one's calls. See
//! `tests/common/mod.rs`.

mod common;

use porthole_core::cli_path::CLI_CANDIDATES;
use porthole_core::ipc::{PortholeProxy, PATH};
use porthole_helper::authz::{Action, AlwaysAllow};
use porthole_helper::retire::Retirement;
use porthole_helper::service::Porthole;
use std::path::Path;
use std::sync::Arc;
use tempfile::TempDir;

/// A `#!/bin/sh` stub named `name`, executable, in `dir`.
///
/// The bodies below use shell builtins only: `PATH` is set to `dir` alone
/// for the first half of the test, so nothing else is reachable, which is
/// the point.
fn stub(dir: &Path, name: &str, body: &str) {
    let path = dir.join(name);
    std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("the temp dir is writable");
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
        .expect("the stub can be made executable");
}

/// A `ufw` that answers `backend::detect`'s two reads of it -- `ufw version`
/// and `ufw status` -- the way an installed, enabled ufw does. ufw inherits
/// `FirewallBackend::forward_capability`'s refusing default.
fn stub_ufw(dir: &Path) {
    stub(
        dir,
        "ufw",
        "case \"$1\" in\n\
         version) echo 'ufw 0.36.2' ;;\n\
         status) echo 'Status: active' ;;\n\
         *) exit 0 ;;\n\
         esac",
    );
}

/// A `firewall-cmd` that answers the three reads porthole makes of it.
/// firewalld is the one backend that can redirect.
fn stub_firewalld(dir: &Path) {
    stub(
        dir,
        "firewall-cmd",
        "case \"$1\" in\n\
         --version) echo '2.4.4' ;;\n\
         --state) echo 'running' ;;\n\
         --get-default-zone) echo 'public' ;;\n\
         *) exit 0 ;;\n\
         esac",
    );
}

async fn serve(
    suffix: &str,
    state: &std::path::Path,
) -> (zbus::Connection, Arc<AlwaysAllow>, String) {
    let authorizer = Arc::new(AlwaysAllow::default());
    let bus = common::connect().await;
    let service = Porthole::new(
        Box::new(Arc::clone(&authorizer)),
        bus,
        state.to_path_buf(),
        std::path::PathBuf::from(CLI_CANDIDATES[0]),
        Retirement::never(),
    );
    let name = format!("com.jacopobriccola.PortholeTest{suffix}");
    let conn = common::builder()
        .name(name.clone())
        .unwrap()
        .serve_at(PATH, service)
        .unwrap()
        .build()
        .await
        .unwrap();
    (conn, authorizer, name)
}

/// The scope is a literal CIDR on purpose: `resolve_scope` runs no command
/// for one, so neither half of this test needs `ip` on the stripped `PATH`,
/// and nothing but the stubs above ever runs.
const SCOPE: &str = "10.10.10.0/24";

#[tokio::test]
async fn a_forward_asks_the_firewall_before_it_asks_for_a_password() {
    let dir = TempDir::new().unwrap();
    // A path whose parent is a regular file: `StateStore::open_exclusive`
    // cannot open it, so every request that gets that far ends there --
    // with the authorization already recorded, and no command that could
    // change a firewall ever run. `tests/service.rs` uses the same device
    // for the same reason.
    let not_a_directory = dir.path().join("not-a-directory");
    std::fs::write(&not_a_directory, "").expect("the temp dir is writable");
    let state = not_a_directory.join("state.json");

    let cannot = dir.path().join("cannot-redirect");
    std::fs::create_dir(&cannot).unwrap();
    stub_ufw(&cannot);

    let can = dir.path().join("can-redirect");
    std::fs::create_dir(&can).unwrap();
    stub_firewalld(&can);

    // Started before `PATH` is stripped, and that ordering is load-bearing:
    // `dbus-run-session` is resolved off this process's own `PATH` at the
    // moment of the first call, and the next statement removes it from
    // `PATH`. Doing this lazily inside `serve` below fails with NotFound.
    let _bus = common::private_bus();

    // --- Half one: a firewall with no redirect in it. --------------------
    //
    // `PATH` is this directory alone, so `firewall-cmd` and `nft` are
    // genuinely absent and `backend::detect` finds ufw.
    std::env::set_var("PATH", &cannot);

    let (_server, authz, name) = serve("ForwardGateUfw", &state).await;
    let client = common::connect().await;
    let proxy = PortholeProxy::builder(&client)
        .destination(name)
        .unwrap()
        .build()
        .await
        .unwrap();

    let refused = proxy
        .forward(18080, "tcp", SCOPE, 60, 3000)
        .await
        .expect_err("ufw has no redirect, so this cannot succeed");
    assert!(
        format!("{refused:?}").contains("ForwardUnsupported"),
        "a machine whose firewall cannot redirect must be told that, and not \
         something downstream of it: {refused:?}"
    );
    assert!(
        authz.asked().is_empty(),
        "the capability question needs no privilege, no input and no read -- \
         asking it after the authorization charges a person an administrator \
         password to be told their firewall was never going to do this. \
         Asked: {:?}",
        authz.asked()
    );

    // --- Half two: a firewall that can redirect. -------------------------
    //
    // The control on the assertion above: it shows the empty `asked()` came
    // from the capability refusal and not from the request stopping earlier
    // for some reason of its own. It is also what
    // `a_forward_asks_every_time_whatever_it_is_towards` used to assert in
    // `tests/service.rs` -- that a forward takes its own action whichever
    // scope it is towards, never one of the `open-*` pair, one of which has
    // a keep window a password can be reused through.
    std::env::set_var("PATH", &can);

    let (_server, authz, name) = serve("ForwardGateFirewalld", &state).await;
    let proxy = PortholeProxy::builder(&client)
        .destination(name)
        .unwrap()
        .build()
        .await
        .unwrap();

    for scope in [SCOPE, "any"] {
        let err = proxy
            .forward(18081, "tcp", scope, 60, 3000)
            .await
            .expect_err("the state path is unusable, so this cannot succeed");
        assert!(
            format!("{err:?}").contains("State"),
            "past the capability gate, a forward must end at the exclusive \
             state lock rather than at a firewall: {err:?}"
        );
    }

    let asked: Vec<String> = authz.asked().into_iter().map(|(a, _)| a).collect();
    assert_eq!(
        asked,
        vec![
            Action::Forward.id().to_string(),
            Action::Forward.id().to_string(),
        ],
        "a forward that gets past the capability question is authorized, and \
         takes its own action whatever it is towards"
    );
}
