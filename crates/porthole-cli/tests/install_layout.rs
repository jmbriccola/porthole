//! What `make install` puts on disk.
//!
//! The install layout is written down in the Makefile at the top of the
//! tree. These tests stage real `make install` runs into throwaway DESTDIRs
//! and pin what those runs produce. The failure they exist to catch is an
//! install that puts down the helper binary without its polkit policy:
//! nothing fails to build, nothing fails to install, and the first
//! `porthole open` on a user's machine is refused by a polkit that never
//! heard of the action.
//!
//! The expected set below is compared for equality, not containment, and
//! twice: against the whole `make install`, and against the union of what
//! `make install WITH_GUI=0` and `make install-gui` put down separately,
//! which must also share no path between them. A row added to the Makefile
//! and not added here fails just as loudly as a row dropped from it.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository root is reachable from this crate")
}

/// Where `crates/porthole-cli/build.rs` left the man pages and completions
/// for this build: beside the test's own binary, whatever `CARGO_TARGET_DIR`
/// happens to be.
fn assets_dir() -> PathBuf {
    Path::new(env!("CARGO_BIN_EXE_porthole"))
        .parent()
        .expect("the CLI binary has a parent directory")
        .join("assets")
}

/// Stand-ins for the four binaries, so this test needs no release build.
///
/// `install` copies whatever it is pointed at; what is inside these files
/// changes nothing about where they land, and where they land is the whole
/// subject here. The binaries themselves are exercised everywhere else in
/// this crate's tests.
fn binary_stubs(dir: &Path) {
    std::fs::create_dir_all(dir).unwrap();
    for name in [
        "porthole",
        "porthole-gui",
        "porthole-helper",
        "porthole-agent",
    ] {
        std::fs::write(dir.join(name), b"stand-in\n").unwrap();
    }
}

/// `make <goal> DESTDIR=<scratch>/<into> PREFIX=/usr <extra...>`, returning
/// the directory it installed into.
fn staged(scratch: &Path, into: &str, goal: &str, extra: &[&str]) -> PathBuf {
    let destdir = scratch.join(into);
    let bindir = scratch.join("bin");
    binary_stubs(&bindir);

    let output = Command::new("make")
        .current_dir(repo_root())
        .arg(goal)
        .arg("PREFIX=/usr")
        .arg(format!("DESTDIR={}", destdir.display()))
        .arg(format!("BINSRC={}", bindir.display()))
        .arg(format!("ASSETSDIR={}", assets_dir().display()))
        .arg(format!(
            "TARGETDIR={}",
            scratch.join("maketarget").display()
        ))
        .args(extra)
        .output()
        .expect("`make` runs; it is how every package in this project installs");
    assert!(
        output.status.success(),
        "make {goal} failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    destdir
}

/// `make install DESTDIR=<a temporary directory> PREFIX=/usr`, returning the
/// directory it installed into.
fn staged_install(scratch: &Path) -> PathBuf {
    staged(scratch, "destdir", "install", &[])
}

fn installed_files(destdir: &Path) -> BTreeSet<String> {
    fn walk(dir: &Path, root: &Path, into: &mut BTreeSet<String>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(&path, root, into);
            } else {
                into.insert(format!("/{}", path.strip_prefix(root).unwrap().display()));
            }
        }
    }
    let mut found = BTreeSet::new();
    walk(destdir, destdir, &mut found);
    found
}

/// Everything `make install PREFIX=/usr` lays down, and nothing more.
const EXPECTED: &[&str] = &[
    "/etc/xdg/autostart/porthole-agent.desktop",
    "/usr/bin/porthole",
    "/usr/bin/porthole-agent",
    "/usr/bin/porthole-gui",
    "/usr/lib/systemd/system/porthole-helper.service",
    "/usr/lib/systemd/user/porthole-agent.service",
    "/usr/libexec/porthole-helper",
    "/usr/share/applications/com.jacopobriccola.Porthole.desktop",
    "/usr/share/bash-completion/completions/porthole",
    "/usr/share/dbus-1/system-services/com.jacopobriccola.Porthole.service",
    "/usr/share/dbus-1/system.d/com.jacopobriccola.Porthole.conf",
    "/usr/share/fish/vendor_completions.d/porthole.fish",
    "/usr/share/icons/hicolor/scalable/apps/com.jacopobriccola.Porthole.svg",
    "/usr/share/icons/hicolor/symbolic/apps/com.jacopobriccola.Porthole-symbolic.svg",
    "/usr/share/man/man1/porthole-close.1",
    "/usr/share/man/man1/porthole-devices-add.1",
    "/usr/share/man/man1/porthole-devices-list.1",
    "/usr/share/man/man1/porthole-devices-rm.1",
    "/usr/share/man/man1/porthole-devices.1",
    "/usr/share/man/man1/porthole-doctor.1",
    "/usr/share/man/man1/porthole-forward.1",
    "/usr/share/man/man1/porthole-list.1",
    "/usr/share/man/man1/porthole-listen.1",
    "/usr/share/man/man1/porthole-open.1",
    "/usr/share/man/man1/porthole-status.1",
    "/usr/share/man/man1/porthole-update.1",
    "/usr/share/man/man1/porthole.1",
    "/usr/share/metainfo/com.jacopobriccola.Porthole.metainfo.xml",
    "/usr/share/polkit-1/actions/com.jacopobriccola.Porthole.policy",
    "/usr/share/zsh/site-functions/_porthole",
];

#[test]
fn make_install_produces_exactly_the_documented_layout() {
    let scratch = tempfile::tempdir().unwrap();
    let destdir = staged_install(scratch.path());

    let found = installed_files(&destdir);
    let expected: BTreeSet<String> = EXPECTED.iter().map(|s| (*s).to_string()).collect();

    let missing: Vec<_> = expected.difference(&found).collect();
    let extra: Vec<_> = found.difference(&expected).collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "make install and this test disagree.\n  never installed: {missing:?}\n  \
         installed but undocumented: {extra:?}"
    );
}

#[test]
fn the_two_packages_split_the_whole_install_between_them_and_share_nothing() {
    // Every packaging format here builds two packages out of this one layout:
    // the base package runs `make install WITH_GUI=0`, the GUI package runs
    // `make install-gui`. Two properties both packages rest on, and neither
    // is the union the test above checks:
    //
    //   disjoint  dpkg refuses to unpack a file another package already owns
    //             ("trying to overwrite ..., which is also in package ..."),
    //             and pacman reports the same as a file conflict. A row added
    //             to install-cli *and* install-gui leaves the union unchanged,
    //             so the test above stays green while every upgrade of the two
    //             packages together fails.
    //
    //   complete  a row in neither half is installed by the full `make
    //             install` and by no package at all, so it exists on a
    //             developer's machine and nowhere a user can reach.
    let scratch = tempfile::tempdir().unwrap();
    let base = installed_files(&staged(scratch.path(), "base", "install", &["WITH_GUI=0"]));
    let gui = installed_files(&staged(scratch.path(), "gui", "install-gui", &[]));

    let shared: Vec<_> = base.intersection(&gui).collect();
    assert!(
        shared.is_empty(),
        "`make install WITH_GUI=0` and `make install-gui` both install \
         {shared:?}; dpkg and pacman each refuse two packages owning one path"
    );

    let union: BTreeSet<String> = base.union(&gui).cloned().collect();
    let expected: BTreeSet<String> = EXPECTED.iter().map(|s| (*s).to_string()).collect();
    let missing: Vec<_> = expected.difference(&union).collect();
    let extra: Vec<_> = union.difference(&expected).collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "the two halves do not add up to the full install.\n  \
         in the full install and in neither package: {missing:?}\n  \
         in a package and not in the full install: {extra:?}"
    );
}

#[test]
fn the_helper_is_installed_beside_its_policy_and_its_two_activation_files() {
    // Named on their own rather than left to the set comparison above: these
    // four are the ones that have to arrive together. A helper without the
    // polkit policy is refused by a polkit that never heard of the action; a
    // helper without the bus policy cannot own the name; a helper without the
    // activation file is never started at all. Each fails in a way that looks
    // like a porthole bug rather than a packaging one.
    let scratch = tempfile::tempdir().unwrap();
    let destdir = staged_install(scratch.path());
    for path in [
        "/usr/libexec/porthole-helper",
        "/usr/share/polkit-1/actions/com.jacopobriccola.Porthole.policy",
        "/usr/share/dbus-1/system.d/com.jacopobriccola.Porthole.conf",
        "/usr/share/dbus-1/system-services/com.jacopobriccola.Porthole.service",
        "/usr/lib/systemd/system/porthole-helper.service",
    ] {
        assert!(
            destdir.join(path.trim_start_matches('/')).is_file(),
            "{path} was not installed"
        );
    }
}

#[test]
fn the_installed_binaries_are_executable_and_the_data_files_are_not() {
    use std::os::unix::fs::PermissionsExt;
    let scratch = tempfile::tempdir().unwrap();
    let destdir = staged_install(scratch.path());

    for (path, want) in [
        ("/usr/bin/porthole", 0o755),
        ("/usr/bin/porthole-gui", 0o755),
        ("/usr/bin/porthole-agent", 0o755),
        ("/usr/libexec/porthole-helper", 0o755),
        (
            "/usr/share/polkit-1/actions/com.jacopobriccola.Porthole.policy",
            0o644,
        ),
        ("/usr/lib/systemd/system/porthole-helper.service", 0o644),
        ("/usr/share/man/man1/porthole.1", 0o644),
    ] {
        let mode = std::fs::metadata(destdir.join(path.trim_start_matches('/')))
            .unwrap_or_else(|e| panic!("{path}: {e}"))
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, want,
            "{path} installed mode {mode:o}, wanted {want:o}"
        );
    }
}

#[test]
fn the_installed_agent_unit_names_the_bindir_the_agent_was_installed_into() {
    // data/porthole-agent.service carries the by-hand install's
    // /usr/local/bin path, and crates/porthole-agent/tests/units.rs pins it
    // there against docs/installing.md. A systemd unit's ExecStart= is an
    // absolute path and is never looked up on $PATH, so a PREFIX=/usr
    // install has to rewrite it or the unit points at a binary the package
    // did not install.
    let scratch = tempfile::tempdir().unwrap();
    let destdir = staged_install(scratch.path());
    let unit = std::fs::read_to_string(destdir.join("usr/lib/systemd/user/porthole-agent.service"))
        .unwrap();
    assert!(
        unit.lines()
            .any(|l| l == "ExecStart=/usr/bin/porthole-agent"),
        "the installed unit does not start the installed binary: {unit}"
    );
    assert!(
        destdir.join("usr/bin/porthole-agent").is_file(),
        "the unit names a binary the install did not produce"
    );
    // Restart=on-failure is a decision of its own -- see that unit's comment
    // and crates/porthole-agent/tests/units.rs. The rewrite must not disturb it.
    assert!(
        unit.lines().any(|l| l == "Restart=on-failure"),
        "the rewrite lost Restart=: {unit}"
    );
}

#[test]
fn the_installed_cli_sits_where_the_expiry_timer_looks_for_it() {
    // `porthole open --for` schedules its own close as a transient systemd
    // timer whose ExecStart is an absolute path, run as root, and
    // `porthole_core::cli_path::resolve_cli` picks that path from
    // CLI_CANDIDATES. A previous milestone shipped a timer pointing at
    // /usr/bin/porthole while the install instructions used /usr/local/bin;
    // reading the constant rather than repeating its literals is what makes a
    // change to either side reopen that here.
    use porthole_core::cli_path::CLI_CANDIDATES;

    let scratch = tempfile::tempdir().unwrap();
    let destdir = staged_install(scratch.path());
    assert!(
        CLI_CANDIDATES
            .iter()
            .any(|c| destdir.join(c.trim_start_matches('/')).is_file()),
        "make install PREFIX=/usr put the CLI somewhere resolve_cli never \
         looks; it checks {CLI_CANDIDATES:?}"
    );
}

#[test]
fn every_file_checked_into_data_is_installed_by_something() {
    // A file added to data/ that no Makefile row copies is invisible: it
    // builds, it installs, and the feature it belongs to is simply absent
    // from every package.
    //
    // Checked against the file set a real `make install` produces, not
    // against the Makefile's text: a data/ file named anywhere in that text
    // satisfies a text search, and the Makefile's comments name data/ files
    // in prose several lines away from the rules that install them.
    //
    // Matched on the file name rather than the whole path, because the path
    // is what the layout chooses: data/porthole-agent.service is installed
    // under /usr/lib/systemd/user/, and with its ExecStart= line rewritten,
    // so the name is what survives the trip.
    let root = repo_root();
    let scratch = tempfile::tempdir().unwrap();
    let installed = installed_files(&staged_install(scratch.path()));
    let names: BTreeSet<&str> = installed
        .iter()
        .filter_map(|path| path.rsplit('/').next())
        .collect();

    fn walk(dir: &Path, into: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(&path, into);
            } else {
                into.push(path);
            }
        }
    }
    let mut files = Vec::new();
    walk(&root.join("data"), &mut files);
    assert!(!files.is_empty(), "data/ is empty");

    for file in files {
        let relative = file.strip_prefix(&root).unwrap().display().to_string();
        let name = file.file_name().unwrap().to_str().unwrap();
        assert!(
            names.contains(name),
            "{relative} exists and `make install` installs nothing called \
             {name}; add a row to the Makefile"
        );
    }
}

/// `porthole --help`, as a package's user would see it.
fn help_text() -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_porthole"))
        .arg("--help")
        .output()
        .unwrap();
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn every_subcommand_the_binary_has_gets_a_man_page() {
    // The pages are rendered by build.rs from the same clap definition this
    // help text comes from, so a new subcommand produces a page on its own --
    // but only if the Makefile's MAN1 list names it, and that list is written
    // by hand. Walks the command tree the way `--help` presents it, so
    // `porthole devices rm` is checked as `porthole-devices-rm.1`.
    let scratch = tempfile::tempdir().unwrap();
    let destdir = staged_install(scratch.path());
    let man1 = destdir.join("usr/share/man/man1");

    fn walk(path: &[String], man1: &Path, seen: &mut usize) {
        let page = format!(
            "porthole{}.1",
            path.iter().map(|p| format!("-{p}")).collect::<String>()
        );
        assert!(
            man1.join(&page).is_file(),
            "`porthole {}` has no installed man page ({page}); add it to MAN1 \
             in the Makefile",
            path.join(" ")
        );
        *seen += 1;
        for child in subcommands_of(path) {
            let mut deeper = path.to_vec();
            deeper.push(child);
            walk(&deeper, man1, seen);
        }
    }

    assert!(man1.join("porthole.1").is_file());
    let mut seen = 1;
    for top in subcommands_of(&[]) {
        walk(&[top], &man1, &mut seen);
    }
    assert!(
        seen >= 11,
        "walked only {seen} commands; --help parsing has stopped finding them"
    );
}

/// The subcommands `porthole <path> --help` lists, minus clap's own `help`.
fn subcommands_of(path: &[String]) -> Vec<String> {
    let output = Command::new(env!("CARGO_BIN_EXE_porthole"))
        .args(path)
        .arg("--help")
        .output()
        .unwrap();
    let help = String::from_utf8(output.stdout).unwrap();
    let Some(block) = help.split("Commands:\n").nth(1) else {
        return Vec::new();
    };
    block
        .lines()
        .take_while(|l| !l.trim().is_empty())
        .filter_map(|l| l.split_whitespace().next())
        .filter(|name| *name != "help")
        .map(str::to_string)
        .collect()
}

#[test]
fn no_installed_man_page_points_at_one_that_was_not_installed() {
    // Every page's SUBCOMMANDS section names its children as
    // `porthole-devices-list(1)`. Installing a subset leaves references to
    // pages that are not there -- which reads, on a user's machine, as a
    // package that forgot to ship half its documentation.
    let scratch = tempfile::tempdir().unwrap();
    let destdir = staged_install(scratch.path());
    let man1 = destdir.join("usr/share/man/man1");

    for entry in std::fs::read_dir(&man1).unwrap() {
        let page = entry.unwrap().path();
        let text = std::fs::read_to_string(&page).unwrap();
        for line in text.lines() {
            let Some(referenced) = line.strip_suffix("(1)") else {
                continue;
            };
            // roff writes a literal hyphen as `\-`.
            let referenced = referenced.replace("\\-", "-");
            if !referenced.starts_with("porthole") {
                continue;
            }
            assert!(
                man1.join(format!("{referenced}.1")).is_file(),
                "{} references {referenced}(1), which nothing installed",
                page.display()
            );
        }
    }
}

#[test]
fn the_long_help_documents_every_exit_code() {
    use porthole_core::error::ExitCode;

    // The exit codes are a public interface -- scripts branch on them -- and
    // the same text is `after_long_help` on the clap command and the EXTRA
    // section of porthole.1.
    //
    // The list is written out rather than derived from a range, and the
    // `match` below is what keeps it honest: a variant added to `ExitCode`
    // stops this file compiling until it is named there, which is the prompt
    // to add it here too. Codes 10 to 14 were added to `ExitCode` while this
    // list still stopped at 9, and this test passed the whole time.
    let help = help_text();
    for code in [
        ExitCode::Success,
        ExitCode::Failure,
        ExitCode::InvalidArguments,
        ExitCode::BackendUnavailable,
        ExitCode::NotAuthorized,
        ExitCode::AlreadyOpen,
        ExitCode::DeviceUnreachable,
        ExitCode::RuleNotFound,
        ExitCode::NoNetwork,
        ExitCode::NothingToOffer,
        ExitCode::NotForwardable,
        ExitCode::ExternalPortInUse,
        ExitCode::ForwardUnsupported,
        ExitCode::ForwardCheckUnavailable,
        ExitCode::AlreadyReachable,
        ExitCode::VersionMismatch,
    ] {
        // No wildcard: this arm is here to fail to compile, not to run.
        match code {
            ExitCode::Success
            | ExitCode::Failure
            | ExitCode::InvalidArguments
            | ExitCode::BackendUnavailable
            | ExitCode::NotAuthorized
            | ExitCode::AlreadyOpen
            | ExitCode::DeviceUnreachable
            | ExitCode::RuleNotFound
            | ExitCode::NoNetwork
            | ExitCode::NothingToOffer
            | ExitCode::NotForwardable
            | ExitCode::ExternalPortInUse
            | ExitCode::ForwardUnsupported
            | ExitCode::ForwardCheckUnavailable
            | ExitCode::AlreadyReachable
            | ExitCode::VersionMismatch => {}
        }
        // Found by its number, not by its spacing: a two-digit code takes one
        // space after it rather than two, so that the text stays in one
        // column. Pinning the exact indentation is what made adding a
        // ten-and-up row look like a test failure rather than documentation.
        let row = format!("{} ", code as i32);
        assert!(
            help.lines().any(|l| l.trim_start().starts_with(&row)),
            "exit code {} has no row in `porthole --help`",
            code as i32
        );
    }
}

#[test]
fn the_man_page_and_the_long_help_carry_the_same_prose() {
    // Two renderings of one `after_long_help`. Checked rather than asserted
    // in a comment, because the man page is generated at build time and
    // nothing else would notice the two coming apart.
    let man = std::fs::read_to_string(assets_dir().join("man/porthole.1"))
        .expect("build.rs rendered porthole.1");
    let help = help_text();
    for phrase in [
        "Exit codes:",
        "No permanent rules:",
        "Docker:",
        "IPv6:",
        "Polkit refused the request",
        "porthole manages IPv4 rules only",
    ] {
        assert!(help.contains(phrase), "`--help` is missing: {phrase}");
        // roff escapes `-` as `\-`; compare on a form that survives that.
        let escaped = phrase.replace('-', "\\-");
        assert!(
            man.contains(phrase) || man.contains(&escaped),
            "porthole.1 is missing: {phrase}"
        );
    }
}
