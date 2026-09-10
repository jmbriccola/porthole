//! porthole's version, in the four places it is written down by hand.
//!
//! `Cargo.toml`, `packaging/rpm/porthole.spec`, `packaging/aur/PKGBUILD` and
//! `debian/changelog` each carry it, and until this file existed nothing
//! compared them. A release could ship an RPM calling itself 0.2.0 beside a
//! PKGBUILD still on 0.1.0 and every check in this repository would have been
//! green: CI reads two of the four (`ci.yml` extracts the spec's `Version:` to
//! name a tarball and `pkgver` to name another) and compares neither.
//!
//! **Four readers, four files, four different spellings**, and that is the
//! design rather than an accident of it. A guard that reads one value and
//! compares it against itself has proved nothing, which is the shape of most
//! of the checks this project has caught executing nothing. Each function
//! below opens a different file and parses the syntax that file actually uses.
//!
//! **Each reader fails rather than returning nothing.** A parse that stops
//! matching its file and quietly yields an empty string would make every
//! comparison here trivially true — two blind readers agree perfectly. So the
//! readers `expect` with a message naming what they looked for, `include_str!`
//! makes a moved file a compile error rather than a test that finds nothing,
//! and `is_shaped_like_a_version` rejects what a broken parse returns before
//! anything is compared.
//!
//! Same shape as `porthole_core::error`'s two README guards, which read the
//! `ExitCode` enum out of its own source instead of keeping a second list of
//! it, and the same division of labour as `porthole_core::ipc::CONTRACTS`:
//! **nothing here knows which of the four numbers is the right one.** It says
//! they disagree, names all four with the file each came from, and leaves
//! choosing the version to a person. A release that deliberately spells itself
//! differently on different distributions — a `~rc1` Debian takes and RPM puts
//! in `Release:` instead — fails this and should: that is a decision, and it
//! belongs in a diff that says so.
//!
//! It lives in `porthole-core` so that it runs in the two package builds that
//! run any tests at all: the RPM's `%check` runs the whole workspace, and the
//! AUR's `check()` runs `-p porthole-core` and nothing else.

use std::path::{Path, PathBuf};

/// One place a version is written, and what was read out of it.
struct Declared {
    /// The path as a reader would type it, so a failure says where to look.
    file: &'static str,
    /// The syntax the reader matched on, so a failure also says what stopped
    /// matching if the number is not the thing that moved.
    syntax: &'static str,
    version: String,
}

/// `[workspace.package]`'s `version`.
///
/// Scoped to that one table deliberately. `[workspace.dependencies]` below it
/// holds `clap = { version = "4", … }` and half a dozen more, and the same
/// table holds `rust-version = "1.87"`; a search of the whole file for
/// `version = "` finds whichever of those comes first and calls it porthole's.
fn cargo_manifest() -> Declared {
    let manifest = include_str!("../../../Cargo.toml");
    let after = manifest
        .split_once("\n[workspace.package]\n")
        .expect("Cargo.toml has a `[workspace.package]` table")
        .1;
    let table = match after.split_once("\n[") {
        Some((table, _)) => table,
        None => after,
    };
    let line = table
        .lines()
        .find(|line| line.starts_with("version = "))
        .expect("`[workspace.package]` declares `version = \"…\"` at the start of a line");
    Declared {
        file: "Cargo.toml",
        syntax: "`version = \"…\"` inside `[workspace.package]`",
        version: between_quotes(line, "Cargo.toml"),
    }
}

/// The spec's `Version:` tag: the first one at the start of a line.
///
/// The same value `ci.yml`'s `rpm` job reads to name its tarball and
/// `.copr/Makefile` reads to name its SRPM, in a third spelling.
fn rpm_spec() -> Declared {
    let spec = include_str!("../../../packaging/rpm/porthole.spec");
    let line = spec
        .lines()
        .find(|line| line.starts_with("Version:"))
        .expect("packaging/rpm/porthole.spec has a `Version:` tag at the start of a line");
    Declared {
        file: "packaging/rpm/porthole.spec",
        syntax: "the `Version:` tag",
        version: line
            .strip_prefix("Version:")
            .expect("just matched")
            .trim()
            .to_string(),
    }
}

/// `pkgver`, which pacman forbids a hyphen in — so an upstream version Debian
/// would spell `1.0~rc1` is already a place where the four can legitimately
/// diverge. See this file's own header.
fn pkgbuild() -> Declared {
    let pkgbuild = include_str!("../../../packaging/aur/PKGBUILD");
    let line = pkgbuild
        .lines()
        .find(|line| line.starts_with("pkgver="))
        .expect("packaging/aur/PKGBUILD assigns `pkgver=` at the start of a line");
    Declared {
        file: "packaging/aur/PKGBUILD",
        syntax: "the `pkgver=` assignment",
        version: line
            .strip_prefix("pkgver=")
            .expect("just matched")
            .trim()
            .trim_matches(['\'', '"'])
            .to_string(),
    }
}

/// The upstream half of the newest `debian/changelog` entry.
///
/// `porthole (0.1.0-1) unstable; urgency=medium` — the `-1` after it is the
/// Debian revision, which is Debian's own number and not one of the four: it
/// moves when the packaging changes and upstream does not. The source package
/// name is checked too, because a changelog whose first line names some other
/// source is a file that has been replaced rather than edited.
fn debian_changelog() -> Declared {
    let changelog = include_str!("../../../debian/changelog");
    let first = changelog
        .lines()
        .next()
        .expect("debian/changelog is not empty");
    let inside = first
        .split_once('(')
        .and_then(|(name, rest)| (name.trim() == "porthole").then_some(rest)?.split_once(')'))
        .map(|(inside, _)| inside)
        .unwrap_or_else(|| {
            panic!("debian/changelog's first line reads `porthole (<version>) …`, got: {first}")
        });
    let upstream = match inside.rsplit_once('-') {
        Some((upstream, _revision)) => upstream,
        None => inside,
    };
    Declared {
        file: "debian/changelog",
        syntax: "the version in the newest entry's first line",
        version: upstream.to_string(),
    }
}

/// The `"…"` on a `key = "value"` line.
fn between_quotes(line: &str, file: &str) -> String {
    let after = line
        .split_once('"')
        .unwrap_or_else(|| panic!("{file}: expected a quoted value, got: {line}"))
        .1;
    after
        .split_once('"')
        .unwrap_or_else(|| panic!("{file}: unterminated quoted value: {line}"))
        .0
        .to_string()
}

/// What a version looks like, so that a reader which has stopped matching its
/// file cannot pass its failure off as agreement.
///
/// Deliberately a shape and not a pattern for today's `0.1.0`: it has to keep
/// accepting whatever the next release calls itself. What it rejects is what a
/// broken parse actually produces — an empty string, a whole line, a tag name,
/// a value with the Debian revision still stuck to it.
fn is_shaped_like_a_version(value: &str) -> bool {
    value.contains('.')
        && value.starts_with(|c: char| c.is_ascii_digit())
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '~' | '+'))
}

fn all_four() -> Vec<Declared> {
    vec![cargo_manifest(), rpm_spec(), pkgbuild(), debian_changelog()]
}

/// The negative control this whole file needs: before comparing four values,
/// establish that four values were actually read.
#[test]
fn every_version_was_read_from_its_own_file_and_is_a_version() {
    let declared = all_four();
    assert_eq!(declared.len(), 4, "four files carry porthole's version");
    for one in &declared {
        assert!(
            is_shaped_like_a_version(&one.version),
            "{}: {} yielded {:?}, which is not a version. The number is not what \
             moved here — the parse is. Fix the reader in this file before reading \
             anything into the comparison it feeds.",
            one.file,
            one.syntax,
            one.version
        );
    }
}

#[test]
fn the_four_hand_kept_versions_are_the_same_version() {
    let declared = all_four();
    let (first, rest) = declared
        .split_first()
        .expect("`all_four` returns four of them");
    let disagreeing: Vec<&Declared> = rest
        .iter()
        .filter(|other| other.version != first.version)
        .collect();
    assert!(
        disagreeing.is_empty(),
        "porthole's version is written down in four files by hand and they no \
         longer agree:\n{}\nA release built from this tree would ship packages \
         that disagree about what they are. Nothing here knows which number is \
         the right one — choose it, and put it in all four.",
        declared
            .iter()
            .map(|one| format!("  {} = {} ({})", one.file, one.version, one.syntax))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// What makes `Cargo.toml`'s number the one the binaries report.
///
/// `porthole --version` prints `CARGO_PKG_VERSION`, which is the crate's own
/// `version`, not the workspace's. They are the same number only because every
/// member manifest says `version.workspace = true` — and a member that stopped
/// saying it would leave the test above comparing three packaging files
/// against a value no binary carries.
///
/// The member list is read out of the workspace manifest rather than written
/// down again here, so a crate added to the workspace is covered without a
/// second edit. Read at run time, not `include_str!`ed, because that is what
/// lets the list drive the reads; the floor below is what stands in for the
/// compile error `include_str!` would have given.
#[test]
fn every_crate_in_the_workspace_takes_the_workspace_version() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository root is reachable from this crate");
    let members = workspace_members(&root);
    // The workspace had five members when this was written and only ever
    // grows. A shorter list means the parse above stopped matching, not that
    // crates were deleted — the same ratchet `declared_exit_codes` uses.
    const LOWEST_TOLERABLE: usize = 5;
    assert!(
        members.len() >= LOWEST_TOLERABLE,
        "`[workspace] members` parsed as {} entries, fewer than the \
         {LOWEST_TOLERABLE} it had when this assertion was last raised: the \
         parse has stopped matching Cargo.toml. Parsed: {members:?}",
        members.len()
    );
    let workspace_version = cargo_manifest().version;
    for member in &members {
        let path = root.join(member).join("Cargo.toml");
        let manifest =
            std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        assert!(
            manifest
                .lines()
                .any(|line| line.trim() == "version.workspace = true"),
            "{}/Cargo.toml does not say `version.workspace = true`, so this \
             crate's version is its own and the {workspace_version} in Cargo.toml's \
             `[workspace.package]` is not what it reports. Either restore the \
             inheritance or add this crate's version to the comparison in this file.",
            member.display()
        );
    }
}

/// The paths in `[workspace] members`, relative to the repository root.
fn workspace_members(root: &Path) -> Vec<PathBuf> {
    let manifest = include_str!("../../../Cargo.toml");
    let list = manifest
        .split_once("\nmembers = [")
        .expect("Cargo.toml's `[workspace]` table lists `members = [`")
        .1
        .split_once(']')
        .expect("the members list is closed with `]`")
        .0;
    let members: Vec<PathBuf> = list
        .split(',')
        .map(|entry| entry.trim().trim_matches('"'))
        .filter(|entry| !entry.is_empty())
        .map(PathBuf::from)
        .collect();
    for member in &members {
        assert!(
            root.join(member).join("Cargo.toml").is_file(),
            "`members` names {}, which has no Cargo.toml: the parse of the \
             members list has stopped matching",
            member.display()
        );
    }
    members
}
