//! Proves the second D-Bus shape this milestone needs: turning the message
//! header — which `Authorizer::check` and `caller_uid` now take instead of a
//! bare sender string, because the bus daemon stamps it and a client cannot
//! forge it — into the sender bus name and the uid every audit line has to
//! carry.
//!
//! `zbus::message::Header` cannot be built outside the `zbus` crate itself
//! (its inner `Fields` type is crate-private), so the only way to hand one to
//! `AlwaysAllow::check` or `caller_uid` from a test is to receive one for
//! real: serve a tiny probe object on the session bus and call it.

use porthole_helper::authz::{caller_uid, Action, AlwaysAllow, Authorizer};
use std::sync::Arc;

#[test]
fn action_ids_match_the_polkit_policy() {
    // These strings are also written into the .policy file installed under
    // /usr/share/polkit-1/actions/. If they drift apart, polkit silently
    // falls back to its default and the severity distinction is lost.
    assert_eq!(
        Action::OpenSubnet.id(),
        "com.jacopobriccola.Porthole.open-subnet"
    );
    assert_eq!(Action::OpenAny.id(), "com.jacopobriccola.Porthole.open-any");
    assert_eq!(Action::Close.id(), "com.jacopobriccola.Porthole.close");
    assert_eq!(Action::List.id(), "com.jacopobriccola.Porthole.list");
}

/// Hands a real, bus-daemon-stamped header to whichever of `AlwaysAllow` or
/// `caller_uid` a test wants to exercise.
struct Probe {
    conn: zbus::Connection,
    authorizer: Arc<AlwaysAllow>,
}

#[zbus::interface(name = "com.jacopobriccola.PortholeTest.Probe1")]
impl Probe {
    async fn check_open_any(&self, #[zbus(header)] header: zbus::message::Header<'_>) {
        self.authorizer
            .check(Action::OpenAny, &header)
            .await
            .expect("AlwaysAllow never refuses");
    }

    async fn check_close(&self, #[zbus(header)] header: zbus::message::Header<'_>) {
        self.authorizer
            .check(Action::Close, &header)
            .await
            .expect("AlwaysAllow never refuses");
    }

    async fn my_uid(&self, #[zbus(header)] header: zbus::message::Header<'_>) -> u32 {
        caller_uid(&self.conn, &header)
            .await
            .expect("the bus knows our uid")
    }
}

/// A unique bus name per test, so tests can run in parallel and none of them
/// ever squats another's.
async fn serve(suffix: &str, authorizer: Arc<AlwaysAllow>) -> (zbus::Connection, String) {
    let conn = zbus::Connection::session()
        .await
        .expect("a session bus is available");
    let probe = Probe {
        conn: conn.clone(),
        authorizer,
    };
    let name = format!("com.jacopobriccola.PortholeTestProbe{suffix}");
    let server = zbus::connection::Builder::session()
        .unwrap()
        .name(name.clone())
        .unwrap()
        .serve_at("/com/jacopobriccola/PortholeTest/Probe", probe)
        .unwrap()
        .build()
        .await
        .unwrap();
    (server, name)
}

async fn probe_proxy(name: String) -> zbus::Proxy<'static> {
    let client = zbus::Connection::session().await.unwrap();
    zbus::Proxy::new_owned(
        client,
        name,
        "/com/jacopobriccola/PortholeTest/Probe",
        "com.jacopobriccola.PortholeTest.Probe1",
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn always_allow_records_what_it_was_asked() {
    let authorizer = Arc::new(AlwaysAllow::default());
    let (_server, name) = serve("Allow", Arc::clone(&authorizer)).await;
    let proxy = probe_proxy(name).await;

    proxy.call::<_, _, ()>("CheckOpenAny", &()).await.unwrap();
    proxy.call::<_, _, ()>("CheckClose", &()).await.unwrap();

    let asked = authorizer.asked();
    assert_eq!(asked.len(), 2, "both calls must be recorded: {asked:?}");
    assert_eq!(asked[0].0, Action::OpenAny.id());
    assert_eq!(asked[1].0, Action::Close.id());
    // Both calls came from the same client connection, so the sender the
    // header carried must be the same unique name both times, and it must
    // actually look like one (`AlwaysAllow` would otherwise silently record
    // an empty string for a header with no sender).
    assert_eq!(asked[0].1, asked[1].1);
    assert!(
        asked[0].1.starts_with(':'),
        "expected a unique bus name, got {:?}",
        asked[0].1
    );
}

#[tokio::test]
async fn the_bus_can_tell_us_the_callers_uid() {
    // The audit trail the spec asks for names the requesting uid, and the
    // helper cannot take the client's word for it. It asks the bus daemon
    // about the sender of the real message it received.
    let (_server, name) = serve("Uid", Arc::new(AlwaysAllow::default())).await;
    let proxy = probe_proxy(name).await;

    let uid: u32 = proxy.call("MyUid", &()).await.unwrap();

    // SAFETY: getuid takes no arguments and cannot fail.
    let expected = unsafe { libc::getuid() };
    assert_eq!(uid, expected, "the bus must report the uid we actually are");
}
