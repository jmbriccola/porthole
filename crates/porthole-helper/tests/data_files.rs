//! The installed files are as much a part of the security model as the code.
//! A typo in an action id disables a severity distinction silently: polkit
//! falls back to its default and nothing errors.

use porthole_helper::authz::Action;

fn data(name: &str) -> String {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../data/");
    std::fs::read_to_string(format!("{path}{name}")).unwrap_or_else(|e| panic!("{path}{name}: {e}"))
}

#[test]
fn the_policy_declares_every_action_the_code_checks() {
    let policy = data("com.jacopobriccola.Porthole.policy");
    for action in [
        Action::OpenSubnet,
        Action::OpenAny,
        Action::Close,
        Action::List,
    ] {
        assert!(
            policy.contains(&format!(r#"<action id="{}">"#, action.id())),
            "{} is checked in code but not declared in the policy — polkit \
             would silently fall back to its default",
            action.id()
        );
    }
}

#[test]
fn the_severities_are_the_ones_the_spec_chose() {
    let policy = data("com.jacopobriccola.Porthole.policy");
    // Opening towards the current subnet: authenticate once, then valid for
    // the session. Towards everyone: every single time. Closing and listing:
    // never — closing reduces exposure and must never be discouraged.
    let open_subnet = policy
        .split(r#"<action id="com.jacopobriccola.Porthole.open-subnet">"#)
        .nth(1)
        .expect("open-subnet is declared");
    assert!(
        open_subnet.contains("auth_admin_keep"),
        "got: {open_subnet}"
    );

    let open_any = policy
        .split(r#"<action id="com.jacopobriccola.Porthole.open-any">"#)
        .nth(1)
        .expect("open-any is declared");
    let open_any_head = &open_any[..open_any.len().min(400)];
    assert!(
        open_any_head.contains("auth_admin") && !open_any_head.contains("auth_admin_keep"),
        "open-any must ask every time, got: {open_any_head}"
    );

    for yes_action in ["close", "list"] {
        let section = policy
            .split(&format!(
                r#"<action id="com.jacopobriccola.Porthole.{yes_action}">"#
            ))
            .nth(1)
            .unwrap_or_else(|| panic!("{yes_action} is declared"));
        let head = &section[..section.len().min(400)];
        assert!(
            head.contains("<allow_active>yes</allow_active>"),
            "{yes_action} must never prompt, got: {head}"
        );
    }
}

#[test]
fn the_bus_configuration_names_the_service_the_code_owns() {
    let conf = data("com.jacopobriccola.Porthole.conf");
    assert!(conf.contains(porthole_core::ipc::SERVICE), "got: {conf}");
    // Only root may own the name; anyone may talk to it. Authorization is
    // polkit's job, not the bus's.
    assert!(conf.contains(r#"<policy user="root">"#), "got: {conf}");
    assert!(conf.contains("<allow own="), "got: {conf}");
}

#[test]
fn activation_and_the_unit_agree_on_where_the_binary_lives() {
    let service = data("com.jacopobriccola.Porthole.service");
    let unit = data("porthole-helper.service");
    assert!(
        service.contains("/usr/libexec/porthole-helper"),
        "got: {service}"
    );
    assert!(unit.contains("/usr/libexec/porthole-helper"), "got: {unit}");
    assert!(
        service.contains(porthole_core::ipc::SERVICE),
        "got: {service}"
    );
}

#[test]
fn the_policy_is_well_formed_xml() {
    // A malformed policy is ignored by polkit without complaint, which would
    // silently disable every severity distinction in the project.
    let policy = data("com.jacopobriccola.Porthole.policy");
    let opens = policy.matches("<action ").count();
    let closes = policy.matches("</action>").count();
    assert_eq!(opens, closes, "unbalanced <action> elements");
    assert_eq!(opens, 4, "expected exactly the four actions");
    assert!(
        policy.trim_end().ends_with("</policyconfig>"),
        "got the tail: {}",
        &policy[policy.len().saturating_sub(80)..]
    );
}
