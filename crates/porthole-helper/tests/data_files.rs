//! The installed files are as much a part of the security model as the code.
//! A typo in an action id disables a severity distinction silently: polkit
//! falls back to its default and nothing errors.

use porthole_core::cli_path::CLI_CANDIDATES;
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
    // Bounded like the others: an unbounded search would pass merely because
    // `auth_admin_keep` appears somewhere later in the file, which is exactly
    // the "matches the wrong section" trap this test exists to avoid.
    let open_subnet = policy
        .split(r#"<action id="com.jacopobriccola.Porthole.open-subnet">"#)
        .nth(1)
        .expect("open-subnet is declared");
    let open_subnet_head = &open_subnet[..open_subnet.len().min(400)];
    assert!(
        open_subnet_head.contains("auth_admin_keep"),
        "got: {open_subnet_head}"
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
    // polkit's job, not the bus's — so `close` stays reachable by everyone.
    //
    // Confined to the root block: `<allow own=` appearing anywhere in the file
    // would also satisfy a loose check, including inside a policy that granted
    // ownership to somebody else.
    let root_block = conf
        .split(r#"<policy user="root">"#)
        .nth(1)
        .expect("a root policy block")
        .split("</policy>")
        .next()
        .expect("the root block is closed");
    assert!(
        root_block.contains(&format!(
            r#"<allow own="{}"/>"#,
            porthole_core::ipc::SERVICE
        )),
        "only root may own the name, got: {root_block}"
    );
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
fn the_unit_preserves_state_across_restarts_and_crashes() {
    // RuntimeDirectoryPreserve defaults to `no`, which makes systemd delete
    // /run/porthole -- and state.json with it -- on every stop, restart, or
    // crash, while every rich rule porthole added stays live in firewalld
    // regardless: `list` shows nothing, `close --all` closes nothing, and a
    // close already scheduled on a transient timer fires into RuleNotFound.
    // A port left open until reboot with nothing able to close it is exactly
    // what this project exists to prevent, so this pins the fix rather than
    // trusting a comment in the unit file to survive the next edit.
    let unit = data("porthole-helper.service");
    assert!(unit.contains("RuntimeDirectory=porthole"), "got: {unit}");
    assert!(unit.contains("RuntimeDirectoryMode=0755"), "got: {unit}");

    let preserve = unit
        .split("RuntimeDirectoryPreserve=")
        .nth(1)
        .expect("RuntimeDirectoryPreserve is set")
        .split_whitespace()
        .next()
        .expect("a value follows the key");
    assert_ne!(
        preserve, "no",
        "RuntimeDirectoryPreserve=no (systemd's own default) deletes \
         /run/porthole -- and state.json with it -- on every stop, restart, \
         or crash, while the firewall rules stay live in firewalld: a port \
         left open with nothing able to close it. got: {unit}"
    );
}

#[test]
fn the_activation_files_systemd_service_names_a_real_unit_file() {
    // A typo here would let D-Bus activation and the systemd unit silently
    // stop agreeing on which unit owns the process -- the same class of
    // drift C3 hit with the CLI path, just one file over.
    let service = data("com.jacopobriccola.Porthole.service");
    let unit_file = service
        .lines()
        .find_map(|l| l.strip_prefix("SystemdService="))
        .expect("SystemdService= is set")
        .trim();
    let data_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../data");
    assert!(
        std::path::Path::new(data_dir).join(unit_file).is_file(),
        "SystemdService={unit_file} names a file that does not exist in data/"
    );
}

#[test]
fn the_cli_path_the_helper_resolves_is_documented() {
    // Coupling code to documentation is an unusual thing for a test to do,
    // but this exact drift -- the expiry timer pointed at a path the install
    // docs never named at all, while the README installed somewhere else --
    // is what C3 was. Importing CLI_CANDIDATES (in
    // crates/porthole-core/src/cli_path.rs) rather than repeating its two
    // literals here means a change to one automatically reopens the exact bug
    // this test exists to catch, instead of quietly checking stale literals
    // forever.
    let installing = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/installing.md"
    ))
    .unwrap_or_else(|e| panic!("docs/installing.md: {e}"));
    for candidate in CLI_CANDIDATES {
        assert!(
            installing.contains(candidate),
            "docs/installing.md must document {candidate} as a path the \
             expiry timer's CLI resolution checks — got no match"
        );
    }
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

/// gdk-pixbuf picks a loader by sniffing the start of a file, and its window is
/// 128 bytes. An SVG whose root element begins after that is reported as
/// "couldn't recognize the image file format" — the file is never parsed, so a
/// well-formed icon can be invisible everywhere while every other check passes.
///
/// Both shipped icons started with a five-line comment above `<svg`, which put
/// the element at byte 337 and 619. The application had no icon in the shell,
/// in the dock, on Wayland or on X11.
#[test]
fn every_shipped_icon_is_recognisable_as_an_svg() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../data/icons");
    let mut checked = 0;
    let mut stack = vec![std::path::PathBuf::from(dir)];
    while let Some(path) = stack.pop() {
        for entry in std::fs::read_dir(&path).unwrap_or_else(|e| panic!("{path:?}: {e}")) {
            let entry = entry.expect("readable directory entry").path();
            if entry.is_dir() {
                stack.push(entry);
                continue;
            }
            if entry.extension().is_none_or(|e| e != "svg") {
                continue;
            }
            let bytes = std::fs::read(&entry).expect("readable icon");
            let at = bytes
                .windows(4)
                .position(|w| w == b"<svg")
                .unwrap_or_else(|| panic!("{entry:?} has no <svg element at all"));
            assert!(
                at < 128,
                "{entry:?} puts <svg at byte {at}; gdk-pixbuf sniffs 128 and \
                 reports the file as an unrecognised format, so the icon never \
                 renders. Move anything above it below the opening tag.",
            );
            checked += 1;
        }
    }
    assert!(
        checked >= 2,
        "expected to find the shipped icons, checked {checked}"
    );
}
