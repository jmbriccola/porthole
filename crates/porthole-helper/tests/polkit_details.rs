//! The polkit prompt must let a human tell an expected request from an
//! unexpected one -- naming the port, the protocol, and the resolved target,
//! not just a static sentence any request could have produced.
//!
//! polkit substitutes `$(key)` in an action's `<message>` from the details
//! map `check_authorization` is called with. A `$(key)` with nothing backing
//! it renders as literal text in the dialog rather than the value a person
//! needs to see, so this proves two things together: `open_details` actually
//! supplies `port`, `protocol` and `target`, and every `$(key)` the installed
//! policy's two `open-*` messages reference is one of those three.

use porthole_core::model::{Protocol, Target};
use porthole_helper::polkit::open_details;

fn policy() -> String {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../data/com.jacopobriccola.Porthole.policy"
    );
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// The `<message>` text for one `<action id="...name...">` block.
fn message_for(policy: &str, action_id: &str) -> String {
    let section = policy
        .split(&format!(r#"<action id="{action_id}">"#))
        .nth(1)
        .unwrap_or_else(|| panic!("{action_id} is not declared in the policy"));
    section
        .split("<message>")
        .nth(1)
        .and_then(|s| s.split("</message>").next())
        .unwrap_or_else(|| panic!("{action_id} has no <message>"))
        .to_string()
}

/// Every `$(...)` token's inner key, in order.
fn dollar_keys(message: &str) -> Vec<String> {
    let mut keys = Vec::new();
    let mut rest = message;
    while let Some(start) = rest.find("$(") {
        let after = &rest[start + 2..];
        let end = after
            .find(')')
            .unwrap_or_else(|| panic!("unterminated $( in: {message}"));
        keys.push(after[..end].to_string());
        rest = &after[end + 1..];
    }
    keys
}

#[test]
fn open_details_supplies_port_protocol_and_target() {
    let target = Target::Network {
        cidr: "10.10.10.0/24".parse().unwrap(),
    };
    let details = open_details(5173, Protocol::Tcp, &target);
    assert_eq!(details.get("port").map(String::as_str), Some("5173"));
    assert_eq!(details.get("protocol").map(String::as_str), Some("tcp"));
    assert_eq!(
        details.get("target").map(String::as_str),
        Some("10.10.10.0/24")
    );
}

#[test]
fn open_details_reports_anywhere_by_name_too() {
    let details = open_details(22, Protocol::Udp, &Target::Anywhere);
    assert_eq!(details.get("target").map(String::as_str), Some("anywhere"));
}

#[test]
fn both_open_messages_name_at_least_the_port_or_the_target() {
    // The defect this fixes: `&HashMap::new()` as the details map meant the
    // dialog showed only the static sentence, with nothing distinguishing an
    // expected request from an unexpected one.
    let policy = policy();
    for action in [
        "com.jacopobriccola.Porthole.open-subnet",
        "com.jacopobriccola.Porthole.open-any",
    ] {
        let message = message_for(&policy, action);
        assert!(
            message.contains("$(port)") || message.contains("$(target)"),
            "{action}'s message names neither the port nor the target: {message}"
        );
    }
}

#[test]
fn every_dollar_key_the_open_messages_reference_is_actually_supplied() {
    let policy = policy();
    let details = open_details(5173, Protocol::Tcp, &Target::Anywhere);
    for action in [
        "com.jacopobriccola.Porthole.open-subnet",
        "com.jacopobriccola.Porthole.open-any",
    ] {
        let message = message_for(&policy, action);
        for key in dollar_keys(&message) {
            assert!(
                details.contains_key(key.as_str()),
                "{action}'s message references $({key}), which open_details \
                 never supplies -- it would render as literal text in the \
                 polkit dialog: {message}"
            );
        }
    }
}

#[test]
fn close_and_list_messages_reference_nothing_open_details_does_not_supply() {
    // Close and list pass an empty details map (see `service.rs`): their
    // messages must not reference any key at all, or polkit would show
    // literal, un-substituted text for them.
    let policy = policy();
    for action in [
        "com.jacopobriccola.Porthole.close",
        "com.jacopobriccola.Porthole.list",
    ] {
        let message = message_for(&policy, action);
        assert!(
            dollar_keys(&message).is_empty(),
            "{action} is authorized with an empty details map but its message \
             references a key: {message}"
        );
    }
}
