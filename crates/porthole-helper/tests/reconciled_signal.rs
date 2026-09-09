//! A record the firewall no longer has is announced by the operation that
//! finds it -- proved against a firewall this test supplies, not one the
//! machine happens to be running.
//!
//! # Why this is a file of its own, with exactly one test in it
//!
//! Same reason as `tests/forward_gate.rs`, and the same technique. The
//! helper detects its firewall through `RealRunner`, which spawns real
//! processes off the real `PATH`, and there is no seam to inject a backend
//! through. The only way to put this process in front of a firewall that
//! answers is to change `PATH` itself; `std::env::set_var` is process-wide,
//! and `tests/signals.rs` runs its tests on threads in parallel, so a `PATH`
//! switch there would race with every other test's own subprocesses. Cargo
//! gives each integration test file its own process, and one test in this
//! one means the switch has nobody to race with.
//!
//! # What this replaces, and why the old shape was wrong
//!
//! This test used to live in `tests/signals.rs` behind
//!
//! ```ignore
//! match porthole_core::backend::detect(&runner) {
//!     Ok(backend) if backend.id() == BackendId::Firewalld => {}
//!     Ok(backend) => { eprintln!("skipped: this host detects {}", backend.id()); return }
//!     Err(e)      => { eprintln!("skipped: no firewall backend on this host: {e}"); return }
//! }
//! ```
//!
//! which is wrong twice over. `return`ing out of a test is counted by
//! libtest as `ok`, so on every ufw and nftables machine -- and in every
//! build chroot -- this reported success having executed nothing; that is
//! the defect `tests/cli.rs`'s `stub_firewalld_and_ip` was written to remove
//! and `tests/container.rs`'s `require_environment!` documents. And the
//! question it asked was not the one it needed: `backend::detect` selects on
//! `BackendHealth::available`, which firewalld sets from `firewall-cmd`
//! merely being installed. What this test needs is a firewalld that
//! *answers* -- reconciliation reads the live rich-rule listing -- and those
//! are two different facts. Measured: in a Fedora build chroot with the
//! firewalld package installed and no daemon running, the guard let the test
//! through and it failed on
//! `firewall-cmd --get-default-zone` exiting 252, "FirewallD is not
//! running".
//!
//! The cure is the one `tests/cli.rs` already chose: stop needing the
//! machine to have a firewall. Every command porthole issues to
//! `firewall-cmd` and `ip` on this path is a *read* of a handful of fixed
//! shapes, so this file carries its own answers and an unrecognised argument
//! exits non-zero rather than answering. What is being measured -- that
//! `reconcile::sweep` drops a record the listing does not contain, and that
//! `Porthole::close` announces the drop even though the close itself then
//! fails -- is porthole's own code either way.
//!
//! Nothing here reaches a real firewall: `PATH` is the stub directory alone,
//! so `firewall-cmd`, `ip`, `nft` and `ufw` as this machine has them are
//! unreachable for the whole of this process's life.

use futures_util::StreamExt;
use porthole_core::backend::{BackendId, RuleHandle};
use porthole_core::cli_path::CLI_CANDIDATES;
use porthole_core::ipc::{CloseReason, PortholeProxy, PATH};
use porthole_core::model::{Protocol, Target};
use porthole_core::state::{ManagedRule, StateStore};
use porthole_helper::authz::AlwaysAllow;
use porthole_helper::service::Porthole;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;

/// Long enough that a loaded machine does not fail a test that would have
/// passed, short enough that a genuinely missing signal is not a five-minute
/// wait. Same value, and the same reasoning, as `tests/signals.rs`.
const ARRIVES_WITHIN: Duration = Duration::from_secs(5);

/// The zone the stub `firewall-cmd` answers with, and the zone the seeded
/// record's handle names. They agree so that the record is one this backend
/// would have listed had the firewall still held it -- the record is stale
/// because the listing is empty, not because it was addressed to some other
/// zone.
const ZONE: &str = "FedoraWorkstation";

/// A `#!/bin/sh` stub named `name`, executable, in `dir`.
fn stub(dir: &Path, name: &str, body: &str) {
    let path = dir.join(name);
    std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("the temp dir is writable");
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
        .expect("the stub can be made executable");
}

/// A `firewall-cmd` and an `ip` that answer the reads porthole makes of them
/// on this path, with the same fixtures `porthole-core`'s own unit tests and
/// `porthole-cli/tests/cli.rs`'s `stub_firewalld_and_ip` use.
///
/// `--version` and `--state` are `Firewalld::health`, which is what
/// `backend::detect` selects on; `--get-zone-of-interface=` and
/// `--get-default-zone` are `managed_zone`; `--list-rich-rules` is the
/// listing `reconcile::sweep` compares porthole's records against, and it is
/// deliberately empty -- that emptiness is what makes the seeded record
/// stale. An argument this stub has not been taught about exits non-zero
/// rather than answering, so a read it does not know surfaces as a failure
/// instead of as an empty string.
fn stub_firewalld_and_ip(dir: &Path) {
    stub(
        dir,
        "firewall-cmd",
        &format!(
            "for arg in \"$@\"; do\n\
             case \"$arg\" in\n\
             --version) echo '2.4.4'; exit 0 ;;\n\
             --state) echo 'running'; exit 0 ;;\n\
             --get-default-zone) echo '{ZONE}'; exit 0 ;;\n\
             --list-rich-rules) exit 0 ;;\n\
             esac\n\
             done\n\
             echo \"reconciled-signal stub firewall-cmd: unhandled $*\" >&2\n\
             exit 2"
        ),
    );
    stub(
        dir,
        "ip",
        "case \"$*\" in\n\
         *'route show default'*)\n\
         echo '[{\"dst\":\"default\",\"dev\":\"wlo1\",\"metric\":600}]' ;;\n\
         *) echo \"reconciled-signal stub ip: unhandled $*\" >&2; exit 2 ;;\n\
         esac",
    );
}

/// The record porthole's state file holds and the firewall does not: the
/// shape a helper writes, with the id minted, the target already resolved to
/// a CIDR and the expiry already an absolute epoch.
///
/// `expires_at` is `None` deliberately: a timed record's drop would try to
/// cancel a transient systemd timer, which is not this test's business and
/// is not on the stripped `PATH`.
fn orphaned_record() -> ManagedRule {
    ManagedRule {
        id: "9f1c0e6a-3d21-4a77-9c4e-5d2b7a0f8e13".to_string(),
        port: 5173,
        protocol: Protocol::Tcp,
        target: Target::Network {
            cidr: "10.10.10.0/24".parse().unwrap(),
        },
        backend: BackendId::Firewalld,
        opened_at: 1_757_000_000,
        expires_at: None,
        uid: 1000,
        handle: RuleHandle::Firewalld {
            zone: ZONE.to_string(),
            rich_rule: r#"rule family="ipv4" source address="10.10.10.0/24" port port="5173" protocol="tcp" accept"#
                .to_string(),
        },
        forward: None,
    }
}

/// Serve the real service object under a probe name on the ambient session
/// bus. Never the production name, and never the system bus.
async fn serve(state: &Path) -> (zbus::Connection, String) {
    let bus = zbus::Connection::session().await.unwrap();
    let service = Porthole::new(
        Box::new(Arc::new(AlwaysAllow::default())),
        bus,
        state.to_path_buf(),
        std::path::PathBuf::from(CLI_CANDIDATES[0]),
    );
    let name = "com.jacopobriccola.PortholeTestSigReconciled".to_string();
    let conn = zbus::connection::Builder::session()
        .unwrap()
        .name(name.clone())
        .unwrap()
        .serve_at(PATH, service)
        .unwrap()
        .build()
        .await
        .unwrap();
    (conn, name)
}

#[tokio::test]
async fn a_record_the_firewall_no_longer_has_is_announced_by_the_operation_that_finds_it() {
    // The reload case, with no restart anywhere: the firewall has forgotten
    // a rule, porthole's state file has not, and the next operation's own
    // reconciliation sweep drops the record. Before this was plumbed the
    // drop was silent on the journal and on the bus, so a client that keeps
    // its view from signals showed the port as open forever.
    //
    // The close below *fails* -- the sweep dropped the rule a moment before
    // it looked -- which is the case that matters most and the one a naive
    // wiring would miss, because the method returns early.
    //
    // firewalld is the backend the stub presents because it is the one whose
    // rule listing needs no privilege, and because its `Ownership` is
    // `Unprovable`: the orphan direction of the sweep never runs on it, so
    // there is no direction in which this test could ask a firewall to
    // remove anything. The counterpart against a real firewalld, with a real
    // `firewall-cmd --reload` producing the orphan rather than a seeded
    // state file, is
    // `porthole-cli/tests/container.rs`'s
    // `a_reload_under_a_running_helper_announces_the_records_it_orphaned`.
    let dir = TempDir::new().unwrap();
    let bin = dir.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    stub_firewalld_and_ip(&bin);
    // The stub directory alone, so the machine's own firewall tooling is
    // unreachable for the rest of this process. One test in this file, so
    // there is no other thread whose subprocess this could race with.
    std::env::set_var("PATH", &bin);

    let state_path = dir.path().join("state.json");
    let orphan = orphaned_record();
    let mut store = StateStore::open(&state_path).unwrap();
    store.insert(orphan.clone());
    store.save().unwrap();

    let (_server, name) = serve(&state_path).await;
    let client = zbus::Connection::session().await.unwrap();
    let proxy = PortholeProxy::builder(&client)
        .destination(name)
        .unwrap()
        .build()
        .await
        .unwrap();
    let mut signals = proxy.receive_rule_closed().await.unwrap();

    let failed = proxy.close(orphan.port, "tcp").await;
    assert!(
        failed.is_err(),
        "the sweep dropped the record first, so the close has nothing to find"
    );

    let signal = tokio::time::timeout(ARRIVES_WITHIN, signals.next())
        .await
        .expect("no signal arrived before the timeout")
        .expect("the signal stream ended instead of yielding");
    let args = signal.args().unwrap();
    assert_eq!(
        args.reason,
        CloseReason::Reconciled,
        "porthole did not close this one -- it found the record of a rule the \
         firewall no longer had"
    );
    assert_eq!(args.rule.id, orphan.id);
    assert_eq!(args.rule.port, orphan.port);

    // And the record really is gone, so a `list` and the signal agree.
    assert!(proxy.list().await.unwrap().is_empty());
}
