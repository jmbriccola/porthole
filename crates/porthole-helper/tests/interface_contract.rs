//! What the helper actually serves, against what
//! `porthole_core::ipc::SIGNATURE` says it serves.
//!
//! The second of the two guards on [`porthole_core::ipc::PROTOCOL_VERSION`],
//! and the one that catches what the first cannot. `porthole-core`'s own
//! `the_wire_types_are_the_ones_this_digest_names` rebuilds every line that
//! carries a wire type from that type's own `Type::SIGNATURE`, which is
//! enough for the change that produced this contract -- three members added
//! to `WireRule` -- and blind to everything else: nothing in Rust's type
//! system says that `Open` takes `qssu`, that a member is called `List`
//! rather than `Rules`, that a member exists at all, or that the interface
//! is still named `com.jacopobriccola.Porthole1`.
//!
//! So this one asks the object. It serves the real
//! `porthole_helper::service::Porthole` on a private session bus under a
//! probe name of its own, calls `org.freedesktop.DBus.Introspectable.
//! Introspect` on it exactly as any client would, and reduces the answer to
//! the same normal form the constant is written in.
//!
//! **Not a snapshot of the XML**, which is what
//! `.superpowers/sdd/2026-09-07-docker-forward/spike-protocol-version.md`
//! was written to decide and decided against: that document is byte-stable
//! across processes, rebuilds, profiles and libcs, and it embeds every
//! rustdoc comment and every parameter name, so it changes when prose
//! improves. `porthole_core::ipc::signature_digest` strips both, which is
//! also what makes it work on a document `xmllint` refuses -- five of this
//! interface's doc comments contain `--`.
//!
//! Nothing here touches this machine's real buses, no firewall is read or
//! written, and the object is never asked to do anything: `Introspect` is
//! answered by zbus itself.

mod common;

use porthole_core::cli_path::CLI_CANDIDATES;
use porthole_core::ipc::{signature_digest, INTERFACE, PATH, PROTOCOL_VERSION, SIGNATURE};
use porthole_helper::authz::AlwaysAllow;
use porthole_helper::service::Porthole;
use std::sync::Arc;
use tempfile::TempDir;

/// A unique bus name per test, so nothing here ever squats the production
/// name and two of these can run at once -- the same rule every other test
/// binary in this crate follows.
fn probe_name(suffix: &str) -> String {
    format!("com.jacopobriccola.PortholeTest{suffix}")
}

/// The real service object, served on this binary's private bus.
async fn serve(suffix: &str, state: &TempDir) -> (zbus::Connection, String) {
    let bus = common::connect().await;
    let service = Porthole::new(
        Box::new(Arc::new(AlwaysAllow::default())),
        bus,
        state.path().join("state.json"),
        std::path::PathBuf::from(CLI_CANDIDATES[0]),
    );
    let name = probe_name(suffix);
    let conn = common::builder()
        .name(name.clone())
        .unwrap()
        .serve_at(PATH, service)
        .unwrap()
        .build()
        .await
        .unwrap();
    (conn, name)
}

async fn introspect(name: &str) -> String {
    let client = common::connect().await;
    zbus::fdo::IntrospectableProxy::builder(&client)
        .destination(name.to_string())
        .unwrap()
        .path(PATH)
        .unwrap()
        .build()
        .await
        .unwrap()
        .introspect()
        .await
        .unwrap()
}

#[tokio::test]
async fn the_served_interface_is_the_one_this_digest_names() {
    let state = TempDir::new().unwrap();
    let (_conn, name) = serve("Contract", &state).await;
    let xml = introspect(&name).await;

    let served = signature_digest(&xml, INTERFACE).expect("the helper serves its own interface");
    assert_eq!(
        served, SIGNATURE,
        "the interface this helper serves is not the one \
         `porthole_core::ipc::SIGNATURE` describes. If you changed a method or a signal \
         on purpose, write the new digest into that constant **and raise \
         PROTOCOL_VERSION** (it is {PROTOCOL_VERSION} now): a contract that changed \
         while the number stayed put is a client that says \"we are level\" while the \
         signatures have diverged, which is the one thing this pair of constants exists \
         to prevent."
    );
}

#[tokio::test]
async fn the_version_is_readable_without_authorization_and_says_what_this_build_speaks() {
    // Outside polkit on purpose -- see `Porthole::protocol_version`. What
    // this can show on a private bus is the half that is testable at all:
    // the call takes no arguments, touches no state file and no firewall
    // (the `TempDir` below stays empty), and answers the constant. The
    // authorizer here is `AlwaysAllow`, so it cannot prove a real polkit
    // would not be consulted; what proves that is the method body, which
    // has no `authorizer.check` in it, and `tests/authz.rs`, which records
    // every check that is made.
    let state = TempDir::new().unwrap();
    let (_conn, name) = serve("ContractVersion", &state).await;

    let client = common::connect().await;
    let proxy = porthole_core::ipc::PortholeProxy::builder(&client)
        .destination(name)
        .unwrap()
        .build()
        .await
        .unwrap();
    assert_eq!(proxy.protocol_version().await.unwrap(), PROTOCOL_VERSION);
    assert!(
        !state.path().join("state.json").exists(),
        "reading the version must not create a state file: it is the one call that has \
         to work when nothing else on this interface does"
    );
}

#[tokio::test]
async fn a_client_that_disagrees_about_every_other_type_still_reads_the_version() {
    // The situation the whole contract exists for, on a real bus: a client
    // built against the `WireRule` from before the forward feature. Its
    // `list` cannot be read -- that is the measured defect -- and the
    // version must cross anyway, which is why it is `() -> u` and shares no
    // type with anything else here.
    #[derive(Debug, serde::Serialize, serde::Deserialize, zbus::zvariant::Type)]
    struct RuleBeforeForward {
        id: String,
        port: u16,
        protocol: String,
        target: String,
        scope: String,
        backend: String,
        opened_at: u64,
        expires_at: u64,
        uid: u32,
    }

    #[zbus::proxy(interface = "com.jacopobriccola.Porthole1", assume_defaults = false)]
    trait StaleClient {
        async fn list(&self) -> zbus::Result<Vec<RuleBeforeForward>>;
        async fn protocol_version(&self) -> zbus::Result<u32>;
    }

    let state = TempDir::new().unwrap();
    let (_conn, name) = serve("ContractStaleClient", &state).await;
    let client = common::connect().await;
    let stale = StaleClientProxy::builder(&client)
        .destination(name)
        .unwrap()
        .path(PATH)
        .unwrap()
        .build()
        .await
        .unwrap();

    let e = stale
        .list()
        .await
        .expect_err("this client's rule shape is not the helper's");
    assert!(
        porthole_core::ipc::is_undecodable(&e),
        "the negative control for the assertion below: without a real mismatch here, \
         reading the version would prove nothing about reading it *despite* one. Got: {e}"
    );
    assert_eq!(
        stale.protocol_version().await.unwrap(),
        PROTOCOL_VERSION,
        "the one member a mismatched pair still has to agree on"
    );
}
