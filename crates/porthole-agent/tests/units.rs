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
fn the_user_unit_is_started_by_the_graphical_session_and_restarted_only_on_failure() {
    let unit = data("porthole-agent.service");
    let directives = directives(&unit);

    // A *user* unit: one agent per logged-in session, as that user. A system
    // unit would have no session bus to notify on and no uid to filter by.
    assert!(
        directives.contains(&"WantedBy=graphical-session.target"),
        "nothing would start it: {directives:?}"
    );
    assert!(directives.contains(&"PartOf=graphical-session.target"));

    // Losing the system bus leaves an agent nothing will ever wake again,
    // and notifications stop with no sign anything is wrong. That is the
    // one exit worth restarting, and `main` gives it the only non-zero
    // status the binary produces.
    assert!(
        directives.contains(&"Restart=on-failure"),
        "a lost system bus must bring a new agent: {directives:?}"
    );
    assert!(
        directives.iter().any(|d| d.starts_with("RestartSec=")),
        "an unpaced restart hammers a bus that has genuinely gone: {directives:?}"
    );

    // Never `Restart=always`. Every start-up failure exits 0 on purpose --
    // no session bus, no system bus, a holder of the name that will not
    // yield it -- and so does being replaced by a newer agent, so that the
    // unit stays stopped instead of looping. `always` would restart those
    // too: the headless-login loop the exit statuses are arranged to avoid,
    // and a pair of agents trading the name between them.
    assert!(
        !directives.contains(&"Restart=always"),
        "`always` restarts the exits that are deliberately 0: {directives:?}"
    );
}

#[test]
fn both_files_start_the_same_binary() {
    let unit = data("porthole-agent.service");
    let desktop = data("porthole-agent.desktop");

    // Read, not merely named: the same coupling `data_files.rs` keeps
    // between the helper's CLI path and this file. An `ExecStart=` pointing
    // somewhere the install instructions never put the binary is a unit that
    // fails to start on a by-hand install, and nothing else in this
    // workspace compiles either file.
    const EXEC_START: &str = "/usr/local/bin/porthole-agent";
    let installing = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/installing.md"
    ))
    .unwrap_or_else(|e| panic!("docs/installing.md: {e}"));
    assert!(
        directives(&unit).contains(&format!("ExecStart={EXEC_START}").as_str()),
        "{unit}"
    );
    assert!(
        installing.contains(EXEC_START),
        "docs/installing.md never names {EXEC_START}, so a by-hand install \
         puts the binary somewhere ExecStart= does not look"
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
