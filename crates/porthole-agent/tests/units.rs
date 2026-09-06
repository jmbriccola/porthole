//! The two files that start this binary.
//!
//! porthole ships a systemd user unit *and* an XDG autostart entry, because
//! desktops differ in which they honour. Two files naming one binary is two
//! chances for a rename to reach only one of them, and neither is compiled,
//! so nothing else in this workspace would notice.

fn data(name: &str) -> String {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../data/");
    std::fs::read_to_string(format!("{path}{name}")).unwrap_or_else(|e| panic!("{path}{name}: {e}"))
}

fn directives(unit: &str) -> Vec<&str> {
    unit.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect()
}

#[test]
fn the_user_unit_is_started_by_the_graphical_session_and_never_restarted() {
    let unit = data("porthole-agent.service");
    let directives = directives(&unit);

    // A *user* unit: one agent per logged-in session, as that user. A system
    // unit would have no session bus to notify on and no uid to filter by.
    assert!(
        directives.contains(&"WantedBy=graphical-session.target"),
        "nothing would start it: {directives:?}"
    );
    assert!(directives.contains(&"PartOf=graphical-session.target"));

    // No Restart=. A session with no notification service is survived by
    // carrying on, and every reason this binary does stop is one a restart
    // would hit again immediately.
    assert!(
        !directives.iter().any(|d| d.starts_with("Restart=")),
        "a Restart= here turns a headless login into a loop: {directives:?}"
    );
}

#[test]
fn both_files_start_the_same_binary() {
    let unit = data("porthole-agent.service");
    let desktop = data("porthole-agent.desktop");

    assert!(
        directives(&unit).contains(&"ExecStart=/usr/local/bin/porthole-agent"),
        "the unit must name the path docs/installing.md installs to: {unit}"
    );
    // A desktop entry's `Exec=` is looked up on `$PATH`, so this one is a
    // bare name on purpose rather than the absolute path above.
    assert!(
        directives(&desktop).contains(&"Exec=porthole-agent"),
        "{desktop}"
    );
    // Not a launcher: it has no window, and an app grid showing it would
    // offer to start a second copy that immediately exits.
    assert!(
        directives(&desktop).contains(&"NoDisplay=true"),
        "{desktop}"
    );
}
