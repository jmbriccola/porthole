//! What the helper actually serves, against what
//! `porthole_core::ipc::SIGNATURE` says it serves.
//!
//! The second of the two guards on [`porthole_core::ipc::SIGNATURE`], and
//! the one that catches what the first cannot. (Neither guards
//! `PROTOCOL_VERSION`: what holds the *number* to the digest is
//! `porthole_core::ipc::CONTRACTS`, which commits the pair, and its own test
//! `the_version_and_the_signature_are_a_pair_that_was_shipped`. An earlier
//! version of this sentence said otherwise and was measured wrong.)
//! `porthole-core`'s own
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
//! written, and the object is never asked to do anything beyond answering
//! its own version: `Introspect` is answered by zbus itself.
//!
//! Three of the four tests below serve the object under a probe name of
//! their own, the rule every test binary in this crate follows. The fourth
//! claims `com.jacopobriccola.Porthole` itself, and has to: the function it
//! exercises -- `porthole_core::ipc::read_protocol_version`, which is what
//! every component actually calls -- asks for that name by default, and the
//! three answers it can get are distinguished by who owns it. The bus is
//! this binary's own private one, so the name is nobody else's here, and the
//! three answers are one test rather than three so that they cannot race
//! each other for it.

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
        served,
        SIGNATURE,
        "the interface this helper serves is not the one \
         `porthole_core::ipc::SIGNATURE` describes. If you changed a method or a signal \
         on purpose, write the new digest into that constant: \
         `the_version_and_the_signature_are_a_pair_that_was_shipped` will then ask you \
         for the version it belongs to, which is {} rather than the \
         {PROTOCOL_VERSION} this build speaks -- a contract that changed while the \
         number stayed put is a client saying \"we are level\" while the signatures \
         have diverged, and committing the pair is what stops it.",
        PROTOCOL_VERSION + 1
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

/// A helper with none of this: the interface as it stood before the version
/// member existed, which is every helper installed today.
struct HelperFromBeforeVersions;

#[zbus::interface(name = "com.jacopobriccola.Porthole1")]
impl HelperFromBeforeVersions {
    async fn list(&self) -> Vec<porthole_core::ipc::WireRule> {
        Vec::new()
    }
}

/// [`porthole_core::ipc::read_protocol_version`] itself -- the function
/// every component calls -- against the three answers it can get, over a
/// real bus.
///
/// **One test for all three, and it claims the production name.** The three
/// answers are distinguished by *who owns
/// `com.jacopobriccola.Porthole`*, which is what that function asks for by
/// default, so they cannot be separate tests in one binary without racing
/// each other for the name. The bus is this binary's own private one (see
/// `tests/common`), so the name is nobody else's here.
#[tokio::test]
async fn the_three_answers_a_version_read_can_get_are_told_apart() {
    let client = common::connect().await;

    // Nothing owns the name and nothing can be activated to it: a machine
    // where porthole is not installed. This must stay an error -- reading it
    // as version 0 would turn "not installed" into "out of date", and the
    // agent goes on listening for the first and says something about the
    // second.
    let absent = porthole_core::ipc::read_protocol_version(&client)
        .await
        .expect_err("nothing owns the helper's name on this bus");
    assert!(
        !porthole_core::ipc::is_undecodable(&absent),
        "and it is not a decode failure either: {absent}"
    );

    // A helper from before the member existed. Its answer -- `UnknownMethod`
    // from zbus's own object server -- is information, not a failure.
    let old = common::builder()
        .name(porthole_core::ipc::SERVICE)
        .unwrap()
        .serve_at(PATH, HelperFromBeforeVersions)
        .unwrap()
        .build()
        .await
        .unwrap();
    assert_eq!(
        porthole_core::ipc::read_protocol_version(&client)
            .await
            .expect("an absent member is an answer"),
        porthole_core::ipc::PROTOCOL_VERSION_ABSENT
    );
    assert_eq!(
        porthole_core::ipc::alignment(porthole_core::ipc::PROTOCOL_VERSION_ABSENT),
        porthole_core::ipc::Alignment::HelperIsOlder
    );
    old.release_name(porthole_core::ipc::SERVICE)
        .await
        .expect("and gives the name back");

    // And the real object, which answers with the constant.
    let state = TempDir::new().unwrap();
    let bus = common::connect().await;
    let service = Porthole::new(
        Box::new(Arc::new(AlwaysAllow::default())),
        bus,
        state.path().join("state.json"),
        std::path::PathBuf::from(CLI_CANDIDATES[0]),
    );
    let _current = common::builder()
        .name(porthole_core::ipc::SERVICE)
        .unwrap()
        .serve_at(PATH, service)
        .unwrap()
        .build()
        .await
        .unwrap();
    assert_eq!(
        porthole_core::ipc::read_protocol_version(&client)
            .await
            .expect("the current helper answers"),
        PROTOCOL_VERSION
    );
}
