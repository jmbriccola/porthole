//! Proves the second D-Bus shape this milestone needs: turning the caller's
//! bus name — which task 1 proved is available from the message header — into
//! the uid that every audit line has to carry.

use porthole_helper::authz::{caller_uid, Action, AlwaysAllow, Authorizer};

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

#[tokio::test]
async fn always_allow_records_what_it_was_asked() {
    let authorizer = AlwaysAllow::default();
    authorizer.check(Action::OpenAny, ":1.42").await.unwrap();
    authorizer.check(Action::Close, ":1.42").await.unwrap();
    assert_eq!(
        authorizer.asked(),
        vec![
            (
                "com.jacopobriccola.Porthole.open-any".to_string(),
                ":1.42".to_string()
            ),
            (
                "com.jacopobriccola.Porthole.close".to_string(),
                ":1.42".to_string()
            ),
        ]
    );
}

#[tokio::test]
async fn the_bus_can_tell_us_the_callers_uid() {
    // The audit trail the spec asks for names the requesting uid, and the
    // helper cannot take the client's word for it. It asks the bus daemon
    // about the sender name instead.
    let conn = zbus::Connection::session()
        .await
        .expect("a session bus is available");
    let me = conn
        .unique_name()
        .expect("we have a unique name")
        .to_string();

    let uid = caller_uid(&conn, &me).await.expect("the bus knows our uid");

    // SAFETY: getuid takes no arguments and cannot fail.
    let expected = unsafe { libc::getuid() };
    assert_eq!(uid, expected, "the bus must report the uid we actually are");
}
