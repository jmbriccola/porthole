//! porthole's version, in the ten places it is written down by hand.
//!
//! Six files carry it. `Cargo.toml`, `packaging/rpm/porthole.spec` (twice: the
//! `Version:` tag and the newest `%changelog` entry), `packaging/aur/PKGBUILD`,
//! `packaging/aur/.SRCINFO` (four times: `pkgver`, the source tarball's name,
//! the git tag inside the source URL, and the exact base package the
//! `porthole-gui` split depends on), `debian/changelog` and
//! `data/com.jacopobriccola.Porthole.metainfo.xml`. Until this file existed
//! nothing compared them. A release could ship an RPM calling itself 0.2.0
//! beside a PKGBUILD still on 0.1.0 and every check in this repository would
//! have been green: CI reads two of them (`ci.yml` extracts the spec's
//! `Version:` to name a tarball and `pkgver` to name another) and compares
//! neither.
//!
//! **Ten readers, six files, ten different spellings**, and that is the design
//! rather than an accident of it. A guard that reads one value and compares it
//! against itself has proved nothing, which is the shape of most of the checks
//! this project has caught executing nothing. Each function below opens a
//! file and parses the syntax that file actually uses, at the position that
//! file actually puts it.
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
//! **nothing here knows which of the ten numbers is the right one.** It says
//! they disagree, names all ten with the file each came from, and leaves
//! choosing the version to a person. A release that deliberately spells itself
//! differently on different distributions — a `~rc1` Debian takes and RPM puts
//! in `Release:` instead — fails this and should: that is a decision, and it
//! belongs in a diff that says so.
//!
//! **What is deliberately not compared: the packaging revision.**
//! `debian/changelog`'s `-1`, the spec's `Release:`, `.SRCINFO`'s `pkgrel`.
//! Those are each packaging system's own number, moved when the packaging
//! changes and upstream does not, and requiring them to agree with each other
//! would be requiring three unrelated counters to march in step.
//!
//! It lives in `porthole-core` so that it runs in the two package builds that
//! run any tests at all: the RPM's `%check` runs the whole workspace, and the
//! AUR's `check()` runs `-p porthole-core` and nothing else. The second of
//! those is why the `.SRCINFO` readers are worth having here rather than in a
//! script somebody remembers to run: an AUR build of a PKGBUILD whose
//! `.SRCINFO` was left behind fails in the builder's own `makepkg`.

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

/// The newest `%changelog` entry's own version.
///
/// `* Sun Sep 06 2026 Jacopo Maria Briccola <…> - 0.1.0-1`. rpm reads that
/// number: `rpm -q --changelog` prints it, and rpmlint raises
/// `incoherent-version-in-changelog` when it does not match `Version:` —
/// which is a check that runs on the packager's machine and not in this
/// repository. The `-1` is the spec's `Release:` and is not compared; see
/// this file's header on packaging revisions.
///
/// Newest first is rpm's own convention for this section, so "the first `*`
/// line below `%changelog`" is the entry describing the version being built.
fn rpm_spec_changelog() -> Declared {
    let spec = include_str!("../../../packaging/rpm/porthole.spec");
    let section = spec
        .split_once("\n%changelog\n")
        .expect("packaging/rpm/porthole.spec has a `%changelog` section")
        .1;
    let first = section.lines().find(|line| line.starts_with("* ")).expect(
        "packaging/rpm/porthole.spec's `%changelog` opens with a \
         `* <date> <name> <email> - <version>-<release>` entry",
    );
    let evr = first
        .rsplit_once(" - ")
        .unwrap_or_else(|| {
            panic!(
                "packaging/rpm/porthole.spec: the newest %changelog entry ends in \
                 ` - <version>-<release>`, got: {first}"
            )
        })
        .1
        .trim();
    Declared {
        file: "packaging/rpm/porthole.spec",
        syntax: "the newest `%changelog` entry's version",
        version: without_packaging_revision(evr).to_string(),
    }
}

/// `pkgver`, which pacman forbids a hyphen in — so an upstream version Debian
/// would spell `1.0~rc1` is already a place where these can legitimately
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
/// Debian revision, which is Debian's own number and not one of these: it
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
    Declared {
        file: "debian/changelog",
        syntax: "the version in the newest entry's first line",
        version: without_packaging_revision(inside).to_string(),
    }
}

// ---------------------------------------------------------------------------
// packaging/aur/.SRCINFO
// ---------------------------------------------------------------------------
//
// A generated file that is nonetheless committed and read by strangers: the
// AUR serves `.SRCINFO` — not the PKGBUILD — to everything that lists,
// searches or resolves dependencies on a package, so a `.SRCINFO` left behind
// is a package the AUR describes as the previous release while the PKGBUILD
// beside it builds the new one. `makepkg --printsrcinfo > .SRCINFO`
// regenerates it, and the four readers below are what say it was not
// forgotten. That it is generated is exactly why it needs guarding: a file
// nobody edits by hand is a file nobody remembers to regenerate.

const SRCINFO: &str = include_str!("../../../packaging/aur/.SRCINFO");

/// The remainder of the one `.SRCINFO` line beginning with `prefix`.
///
/// `.SRCINFO` indents every line under its `pkgbase`/`pkgname` headers with a
/// tab, so the search is on the trimmed line. Several keys repeat (`depends`
/// appears eight times across the two packages), which is why callers pass a
/// prefix specific enough to name the line they mean rather than just a key.
fn srcinfo_line(prefix: &str) -> &'static str {
    SRCINFO
        .lines()
        .map(str::trim)
        .find_map(|line| line.strip_prefix(prefix))
        .unwrap_or_else(|| panic!("packaging/aur/.SRCINFO has no line starting `{prefix}`"))
        .trim()
}

/// `.SRCINFO`'s own `pkgver`, which must be the PKGBUILD's.
fn srcinfo_pkgver() -> Declared {
    Declared {
        file: "packaging/aur/.SRCINFO",
        syntax: "the `pkgver =` line",
        version: srcinfo_line("pkgver = ").to_string(),
    }
}

/// The name `source =` gives the downloaded tarball: `porthole-<version>.tar.gz`.
///
/// In the PKGBUILD this is `$pkgbase-$pkgver.tar.gz` and cannot drift;
/// `.SRCINFO` holds the expansion, where it can.
fn srcinfo_source_tarball() -> Declared {
    let source = srcinfo_line("source = ");
    let name = match source.split_once("::") {
        Some((name, _url)) => name,
        None => source,
    };
    let version = name
        .strip_prefix("porthole-")
        .and_then(|rest| rest.strip_suffix(".tar.gz"))
        .unwrap_or_else(|| {
            panic!(
                "packaging/aur/.SRCINFO: `source =` names a tarball \
                 `porthole-<version>.tar.gz`, got: {name}"
            )
        });
    Declared {
        file: "packaging/aur/.SRCINFO",
        syntax: "the tarball name in `source =`",
        version: version.to_string(),
    }
}

/// The **git tag** inside the `source =` URL: `…/archive/refs/tags/v<version>.tar.gz`.
///
/// The one number in this repository that names something outside it. Every
/// other place here is a string a build reads; this is what an AUR user's
/// `makepkg` will actually fetch, and a tag that does not exist is a package
/// nobody can build. It is also the only check that says which tag this
/// release must be cut at, so a `v` that stopped being the prefix, or a tag
/// left at the previous release, fails here rather than on a stranger's
/// machine.
fn srcinfo_source_tag() -> Declared {
    let source = srcinfo_line("source = ");
    let after = source
        .split_once("/archive/refs/tags/v")
        .unwrap_or_else(|| {
            panic!(
                "packaging/aur/.SRCINFO: `source =`'s URL names a git tag as \
                 `/archive/refs/tags/v<version>.tar.gz`, got: {source}"
            )
        })
        .1;
    let version = after.strip_suffix(".tar.gz").unwrap_or_else(|| {
        panic!("packaging/aur/.SRCINFO: the tag in `source =` ends in `.tar.gz`, got: {after}")
    });
    Declared {
        file: "packaging/aur/.SRCINFO",
        syntax: "the `v<version>` git tag in `source =`'s URL",
        version: version.to_string(),
    }
}

/// What the `porthole-gui` split package pins the base package to.
///
/// `depends = porthole=<version>-<pkgrel>`. In the PKGBUILD it is
/// `"porthole=$pkgver-$pkgrel"`; here it is expanded, and a stale expansion
/// makes pacman refuse to install the pair. The `-<pkgrel>` is pacman's own
/// number and is not compared — see this file's header.
fn srcinfo_gui_depends() -> Declared {
    let pinned = srcinfo_line("depends = porthole=");
    Declared {
        file: "packaging/aur/.SRCINFO",
        syntax: "`porthole-gui`'s `depends = porthole=…` pin",
        version: without_packaging_revision(pinned).to_string(),
    }
}

// ---------------------------------------------------------------------------
// data/com.jacopobriccola.Porthole.metainfo.xml
// ---------------------------------------------------------------------------

const METAINFO: &str = include_str!("../../../data/com.jacopobriccola.Porthole.metainfo.xml");

/// One `<release version="…" date="…">` entry.
struct AppstreamRelease {
    version: String,
    date: String,
}

/// Every `<release>` in the AppStream file, in the order the file lists them.
fn appstream_releases() -> Vec<AppstreamRelease> {
    let releases: Vec<AppstreamRelease> = METAINFO
        .match_indices("<release ")
        .map(|(at, _)| {
            let rest = &METAINFO[at..];
            let tag = &rest[..rest
                .find('>')
                .unwrap_or_else(|| panic!("an unclosed `<release` tag in {METAINFO_PATH}"))];
            AppstreamRelease {
                version: xml_attribute(tag, "version"),
                date: xml_attribute(tag, "date"),
            }
        })
        .collect();
    assert!(
        !releases.is_empty(),
        "{METAINFO_PATH} lists no `<release version=… date=…>` at all: either the \
         release history was deleted or this reader has stopped matching the file."
    );
    releases
}

const METAINFO_PATH: &str = "data/com.jacopobriccola.Porthole.metainfo.xml";

/// The value of `name="…"` in an opening tag.
fn xml_attribute(tag: &str, name: &str) -> String {
    let needle = format!(" {name}=\"");
    let after = tag
        .split_once(&needle)
        .unwrap_or_else(|| panic!("{METAINFO_PATH}: no `{name}=\"…\"` in `{tag}>`"))
        .1;
    after
        .split_once('"')
        .unwrap_or_else(|| panic!("{METAINFO_PATH}: unterminated `{name}=\"` in `{tag}>`"))
        .0
        .to_string()
}

/// The **newest** release the AppStream file lists, and only that one.
///
/// This file is different in kind from the other five: it is a *history*. Its
/// older `<release>` entries record versions that shipped, with the dates they
/// shipped on, and a software centre shows them as the changelog. Requiring
/// every entry to carry today's version would require rewriting history on
/// each release, which would destroy the only thing the file is for and make
/// this guard the reason. So the comparison is against the first entry alone,
/// and `the_appstream_history_is_newest_first_and_lists_each_release_once`
/// below is what earns the word "first": newest-first is AppStream's
/// convention rather than a rule anything enforces, so the ordering that makes
/// "the first entry" mean "this release" is asserted rather than assumed.
fn metainfo_newest_release() -> Declared {
    Declared {
        file: METAINFO_PATH,
        syntax: "the newest `<release version=…>` entry",
        version: appstream_releases()
            .into_iter()
            .next()
            .expect("`appstream_releases` refuses an empty history")
            .version,
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

/// `1.0.0-1` -> `1.0.0`, and `1.0.0` -> `1.0.0`.
///
/// Debian's revision, rpm's `Release:` and pacman's `pkgrel` are each their
/// own packaging system's counter; what is compared here is the upstream
/// version in front of them.
fn without_packaging_revision(value: &str) -> &str {
    match value.rsplit_once('-') {
        Some((upstream, _revision)) => upstream,
        None => value,
    }
}

/// What a version looks like, so that a reader which has stopped matching its
/// file cannot pass its failure off as agreement.
///
/// Deliberately a shape and not a pattern for today's version: it has to keep
/// accepting whatever the next release calls itself. What it rejects is what a
/// broken parse actually produces — an empty string, a whole line, a tag name,
/// a URL, a value with the packaging revision still stuck to it.
fn is_shaped_like_a_version(value: &str) -> bool {
    value.contains('.')
        && value.starts_with(|c: char| c.is_ascii_digit())
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '~' | '+'))
}

/// Every hand-kept spelling of porthole's version, each read from its own file.
fn all_declared() -> Vec<Declared> {
    vec![
        cargo_manifest(),
        rpm_spec(),
        rpm_spec_changelog(),
        pkgbuild(),
        debian_changelog(),
        srcinfo_pkgver(),
        srcinfo_source_tarball(),
        srcinfo_source_tag(),
        srcinfo_gui_depends(),
        metainfo_newest_release(),
    ]
}

/// How many there are. A number that only ever grows: a reader deleted, or a
/// `vec![]` that stopped being built, must fail here rather than leave the
/// comparison below quietly checking fewer files than it names.
const DECLARATIONS: usize = 10;

/// The negative control this whole file needs: before comparing ten values,
/// establish that ten values were actually read.
#[test]
fn every_version_was_read_from_its_own_file_and_is_a_version() {
    let declared = all_declared();
    assert_eq!(
        declared.len(),
        DECLARATIONS,
        "six files carry porthole's version in {DECLARATIONS} places"
    );
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
fn the_hand_kept_versions_are_the_same_version() {
    let declared = all_declared();
    let (first, rest) = declared
        .split_first()
        .expect("`all_declared` returns a version from every file");
    let disagreeing: Vec<&Declared> = rest
        .iter()
        .filter(|other| other.version != first.version)
        .collect();
    assert!(
        disagreeing.is_empty(),
        "porthole's version is written down by hand in {DECLARATIONS} places across six \
         files and they no longer agree:\n{}\nA release built from this tree would ship \
         packages that disagree about what they are. Nothing here knows which number is \
         the right one — choose it, and put it in all of them. docs/releasing.md lists \
         them in the order to edit.",
        declared
            .iter()
            .map(|one| format!("  {} = {} ({})", one.file, one.version, one.syntax))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// What makes "the newest `<release>`" a thing that can be read at all.
///
/// The AppStream file is a history, so the guard above compares its *first*
/// entry and leaves the rest alone. That is only sound while the file really
/// is newest-first: an entry appended at the bottom would leave the previous
/// release's number at the top, and while the comparison above would fail, it
/// would fail saying the version is wrong rather than that the entry is in the
/// wrong place. Dates are ISO-8601 (`YYYY-MM-DD`), which AppStream requires
/// and which therefore sort lexically.
///
/// Uniqueness is the other half: two `<release>` entries for one version is a
/// bump applied twice, which a software centre renders as a duplicate
/// changelog entry and which nothing else here would notice.
#[test]
fn the_appstream_history_is_newest_first_and_lists_each_release_once() {
    let releases = appstream_releases();

    for release in &releases {
        assert!(
            is_shaped_like_a_version(&release.version),
            "{METAINFO_PATH}: `<release version=\"{}\">` is not a version",
            release.version
        );
        let iso = release.date.len() == 10
            && release.date.chars().enumerate().all(|(i, c)| {
                if i == 4 || i == 7 {
                    c == '-'
                } else {
                    c.is_ascii_digit()
                }
            });
        assert!(
            iso,
            "{METAINFO_PATH}: release {} is dated {:?}, which is not `YYYY-MM-DD`. \
             AppStream requires that spelling, and the ordering checked below only \
             means anything while the dates sort.",
            release.version, release.date
        );
    }

    let newest = &releases[0];
    for older in &releases[1..] {
        assert!(
            newest.date >= older.date,
            "{METAINFO_PATH} lists release {} ({}) above {} ({}), so the entry at the \
             top is not the newest one. A new release goes at the top of <releases>: \
             everything that reads this file — and the guard in this file that compares \
             the first entry against the rest of the tree — takes the first entry to be \
             the current release.",
            newest.version,
            newest.date,
            older.version,
            older.date
        );
        assert_ne!(
            newest.version, older.version,
            "{METAINFO_PATH} lists release {} twice. One release, one entry.",
            newest.version
        );
    }
}

/// What makes `Cargo.toml`'s number the one the binaries report.
///
/// `porthole --version` prints `CARGO_PKG_VERSION`, which is the crate's own
/// `version`, not the workspace's. They are the same number only because every
/// member manifest says `version.workspace = true` — and a member that stopped
/// saying it would leave the test above comparing packaging files against a
/// value no binary carries.
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
