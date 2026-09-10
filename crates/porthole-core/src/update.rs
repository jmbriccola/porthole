//! Noticing that a newer porthole exists, and asking once whether to look.
//!
//! porthole makes no network request of its own, and this does not add one.
//! The question is put to the **local package manager**, which is the only
//! thing that can answer the question worth asking: not "does 0.2.0 exist
//! somewhere" but "can this machine install it now". The design that decided
//! that is `docs/superpowers/specs/2026-09-09-update-notifier-design.md`.
//!
//! Nothing here installs anything, and nothing here is privileged. This
//! module runs two kinds of read-only query through [`CommandRunner`] and
//! reads one file in the user's own config directory. The installing is
//! PackageKit's, under PackageKit's own polkit action -- see
//! `porthole-agent`'s `update` module. The privileged helper is not involved
//! in any of it and must never be: it accepts a narrow, validated set of
//! firewall operations and never a command from a client, which is the
//! property porthole's security rests on.
//!
//! # Two questions, and only one of them has a contract
//!
//! **How porthole was installed.** [`how_installed`] asks each package
//! manager present on the machine whether it owns porthole's own binary. A
//! manager that is not installed is skipped -- the same `CommandSpawn`
//! signal `porthole_core::backend`'s own `health()` reads as "not installed".
//! If a manager answers and does not claim the file, this is a source
//! install: the check stops, silently, and porthole never offers to
//! overwrite a hand-installed tree.
//!
//! **Whether an update exists.** [`check`] asks the manager that owns
//! porthole, and reads its **exit code**, never its text: a message is
//! localised and changes between versions, an exit code is a contract.
//!
//! That is where this module has a finding rather than an implementation.
//! Each contract below was established by reading the tool's own
//! documentation, on the distribution that ships it, rather than assumed:
//!
//! - **dnf** (`dnf check-update <pkg>`). `dnf5-check-upgrade(8)`, dnf5
//!   5.4.3.0: *"DNF5 will exit with code 100 if updates are available and
//!   list them; 0 if no updates are available."* The sentence follows the one
//!   about `<package-spec-N>`, so it is the answer for the packages named.
//!   `dnf5(8)`'s own EXIT CODES adds 1 for an error during processing and 2
//!   for a parsing error. **A contract, and porthole uses it.**
//! - **apt** (`apt-get`, `apt`). `apt-get(8)` and `apt(8)` DIAGNOSTICS, read
//!   in a `debian:13` container, both say the whole of it: *"returns zero on
//!   normal operation, decimal 100 on error."* There is **no** exit code
//!   meaning "an update is available", for any apt subcommand. Asking and
//!   reading `0` would be reading "no error", not "nothing to update", and
//!   reporting it as the latter is a claim the tool never made.
//! - **pacman**. `pacman(8)`, read in an `archlinux:latest` container, has no
//!   EXIT STATUS and no DIAGNOSTICS section at all -- the whole page mentions
//!   an exit exactly once, in `-V, --version` ("Display version and exit").
//!   `checkupdates(8)` from pacman-contrib *does* document one (0 normal, 1
//!   unknown failure, **2 no updates available**), but it answers a different
//!   question: whether *anything* on the system has an update. Reporting that
//!   as "porthole has an update" would be an overclaim, and narrowing it means
//!   grepping its output, which is the text this design refuses to read.
//!
//! So [`Verdict::NoContract`] is a real answer this module gives, on two of
//! the three packagings, and it is not a failure: it says porthole will not
//! guess, and hands over the command a person can run themselves. It is
//! reported as such and never as "nothing to update".
//!
//! # What the exit code decides, and what the text is allowed to do
//!
//! The **verdict** comes from the exit code alone. A version string, when one
//! can be picked out of the manager's output, is carried on
//! [`Verdict::Available`] as a **label** -- it is what a notification says and
//! what "once per version" is keyed on. It never decides anything: an
//! unreadable, reworded or translated listing yields
//! `Available { version: None }` and the answer is still "an update is
//! available", because 100 is what said so.

use crate::command::{Command, CommandRunner};
use crate::error::Error;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// The name all three packagings give porthole: `Name:` in
/// `packaging/rpm/porthole.spec`, `Package:` in `debian/control`, and
/// `pkgname` in `packaging/aur/PKGBUILD`. Asked about by name, because that
/// is what a package manager takes.
pub const PACKAGE: &str = "porthole";

/// Test-only override of the update settings' location. Honoured in debug
/// builds only, exactly as [`crate::devices::DEVICES_FILE_ENV`] and
/// [`crate::state::STATE_FILE_ENV`] are, and for the same reason: a release
/// binary must not take a config path from its environment.
pub const UPDATE_FILE_ENV: &str = "PORTHOLE_UPDATE_FILE";

/// Which package manager installed porthole, and therefore which one to ask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Packaging {
    Rpm,
    Dpkg,
    Pacman,
}

impl Packaging {
    /// The three, in the order [`how_installed`] tries them. Written once so
    /// that a manager added here reaches every caller and every test.
    pub const ALL: [Packaging; 3] = [Packaging::Rpm, Packaging::Dpkg, Packaging::Pacman];

    pub fn as_str(self) -> &'static str {
        match self {
            Packaging::Rpm => "rpm",
            Packaging::Dpkg => "dpkg",
            Packaging::Pacman => "pacman",
        }
    }

    /// "Which package owns this file?", as a read-only command.
    ///
    /// `dpkg-query -S` rather than `dpkg -S`, which the design names: the two
    /// perform the same search (`dpkg(1)`: *"-S, --search: Search for a
    /// filename from installed packages"*, which it forwards), but only
    /// `dpkg-query(1)` documents what each code means -- 0 the query was
    /// successfully performed, **1 no file or package being found**, 2 a
    /// fatal error. `dpkg(1)`'s own table calls 1 "a check or assertion
    /// command returned false", which covers this case less exactly. Where a
    /// spec and a documented contract disagree, this follows the contract.
    fn owner_query(self, binary: &Path) -> Command {
        let path = binary.display().to_string();
        match self {
            Packaging::Rpm => Command::read("rpm", ["-qf", &path]),
            Packaging::Dpkg => Command::read("dpkg-query", ["-S", &path]),
            Packaging::Pacman => Command::read("pacman", ["-Qo", &path]),
        }
    }

    /// What a person can run by hand to see for themselves, and what porthole
    /// prints wherever it will not answer for them.
    ///
    /// Not a command porthole runs. `update` and `upgrade` both change the
    /// machine, which is exactly what porthole does not do: the installing is
    /// PackageKit's, under PackageKit's own polkit action, or it is the
    /// person's.
    pub fn manual_command(self) -> &'static str {
        match self {
            Packaging::Rpm => "sudo dnf upgrade porthole",
            Packaging::Dpkg => {
                "sudo apt-get update && sudo apt-get install --only-upgrade porthole"
            }
            Packaging::Pacman => "sudo pacman -Syu",
        }
    }
}

/// How porthole got onto this machine, as far as the machine itself can say.
///
/// Three answers and not two, because "no manager claims this binary" and
/// "no manager could be asked" are different facts and only the first is
/// evidence of anything. Both stop the check; only the first is a source
/// install, and only [`Install::Packaged`] goes on to ask about updates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Install {
    /// A package manager claims porthole's binary.
    Packaged(Packaging),
    /// At least one manager was asked, and none of the ones present claims
    /// it. A source install: porthole must never offer to overwrite a
    /// hand-installed tree, so the check ends here and does not retry.
    Unpackaged,
    /// No package manager could be asked at all -- none installed, or each
    /// answered in a way that is not an answer. Not a source install, and not
    /// reported as one.
    Undetermined(String),
}

/// Ask each package manager present whether it owns `binary`.
///
/// **Exit code, not output.** `rpm(8)`'s EXIT STATUS is *"On success, 0 is
/// returned, a nonzero failure code otherwise"*, and `dpkg-query(1)`'s is the
/// three-way table quoted on [`Packaging::owner_query`]. `pacman(8)`
/// documents no exit status at all, so its zero/non-zero is this module
/// reading a universal convention rather than a stated contract -- said out
/// loud rather than glossed, and safe in the direction it fails: a wrong
/// answer here can only *withhold* a notification, since claiming ownership
/// takes an exit of 0 and porthole installs nothing itself either way.
///
/// A manager that is not installed is skipped, on [`Error::CommandSpawn`] and
/// on that alone -- the same signal `porthole_core::backend`'s own `health()`
/// reads as "not installed", and the only one that is proof the binary is
/// absent.
pub fn how_installed(runner: &dyn CommandRunner, binary: &Path) -> Install {
    let mut asked = 0usize;
    let mut trouble: Vec<String> = Vec::new();
    for packaging in Packaging::ALL {
        let cmd = packaging.owner_query(binary);
        match runner.run(&cmd) {
            Ok(out) if out.success() => return Install::Packaged(packaging),
            Ok(_) => asked += 1,
            // The one failure that means the manager is not on this machine.
            Err(Error::CommandSpawn { .. }) => {}
            // Anything else is this one read not answering, which is not
            // evidence that the manager does not own the file.
            Err(e) => trouble.push(format!("{}: {e}", packaging.as_str())),
        }
    }
    if asked > 0 {
        return Install::Unpackaged;
    }
    Install::Undetermined(if trouble.is_empty() {
        format!(
            "no package manager is installed on this machine, so nothing can say whether \
             {} came from a package",
            binary.display()
        )
    } else {
        format!(
            "no package manager could be asked whether it owns {}: {}",
            binary.display(),
            trouble.join("; ")
        )
    })
}

/// What asking about updates produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The manager's own exit code says an update is available. `version` is
    /// a label read out of its output where one could be, and decides
    /// nothing -- see this module's own doc comment.
    Available { version: Option<String> },
    /// The manager's own exit code says there is nothing to install.
    UpToDate,
    /// This packaging documents no exit code for the question. Carries the
    /// sentence that says so, naming the documentation it was read from.
    NoContract(String),
    /// The manager was asked and did not answer either way.
    Unknown(String),
}

/// dnf's documented "updates available" code. `dnf5-check-upgrade(8)`:
/// *"DNF5 will exit with code 100 if updates are available and list them; 0
/// if no updates are available."*
const DNF_UPDATES_AVAILABLE: i32 = 100;

/// Ask the manager that owns porthole whether it has a newer one.
///
/// `package` rather than a hardcoded [`PACKAGE`] so a test can drive this
/// against a name of its own; every caller in porthole passes [`PACKAGE`].
pub fn check(runner: &dyn CommandRunner, packaging: Packaging, package: &str) -> Verdict {
    match packaging {
        Packaging::Rpm => check_dnf(runner, package),
        // See this module's own doc comment. Neither of these is a gap in
        // porthole: it is what those two tools' documentation does and does
        // not define, and porthole will not read a localised listing to
        // invent the difference.
        Packaging::Dpkg => Verdict::NoContract(
            "apt documents no exit code meaning `an update is available`: apt-get(8) and \
             apt(8) both state only that apt returns zero on normal operation and 100 on \
             error. porthole reads exit codes and not messages, so it will not answer this \
             on a Debian-packaged install."
                .to_string(),
        ),
        Packaging::Pacman => Verdict::NoContract(
            "pacman documents no exit status at all -- pacman(8) has neither an EXIT \
             STATUS nor a DIAGNOSTICS section. checkupdates(8) from pacman-contrib does \
             document one (2 means no updates available), but it answers whether anything \
             on the system has an update, not whether porthole does. porthole reads exit \
             codes and not messages, so it will not answer this on an Arch-packaged \
             install."
                .to_string(),
        ),
    }
}

fn check_dnf(runner: &dyn CommandRunner, package: &str) -> Verdict {
    // `check-update`, which dnf5 accepts (verified against `dnf5 check-update
    // --help` on dnf5 5.4.3.0) and which is dnf4's own name for the command
    // dnf5's man page calls `check-upgrade`. One spelling that reaches both.
    let cmd = Command::read("dnf", ["check-update", package]);
    let out = match runner.run(&cmd) {
        Ok(out) => out,
        Err(e) => return Verdict::Unknown(format!("could not ask dnf about {package}: {e}")),
    };
    match out.status {
        DNF_UPDATES_AVAILABLE => Verdict::Available {
            version: version_from_dnf(&out.stdout, package),
        },
        0 => Verdict::UpToDate,
        other => Verdict::Unknown(format!(
            "dnf answered {other} for `{}`, which is neither {DNF_UPDATES_AVAILABLE} \
             (updates available) nor 0 (none). dnf5(8) documents 1 for an error during \
             processing and 2 for a parsing error.",
            cmd.display()
        )),
    }
}

/// The version `dnf check-update` listed for `package`, if the listing can be
/// read.
///
/// **A label, never a verdict.** The exit code has already decided that an
/// update exists by the time this runs; all this adds is a string for a
/// notification to show and for "once per version" to be keyed on. `None` is
/// an ordinary answer -- a reworded, translated or colourised listing gives
/// one, and the update is no less available for it.
///
/// `check-update`'s rows are `<name>.<arch>  <version>  <repo>`, so the row
/// for a package is the one whose first field is the name or the name plus a
/// dotted architecture.
fn version_from_dnf(stdout: &str, package: &str) -> Option<String> {
    stdout.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        let name = fields.next()?;
        let matches = name == package
            || name
                .strip_prefix(package)
                .is_some_and(|rest| rest.starts_with('.'));
        if !matches {
            return None;
        }
        let version = fields.next()?;
        (!version.is_empty()).then(|| version.to_string())
    })
}

/// Whether the user has been asked, and what they said.
///
/// **Three states and not two.** Telling *never asked* from *no* is the whole
/// of what stops porthole asking again somebody who has already declined.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Consent {
    /// Nobody has put the question. The window asks it at first launch.
    #[default]
    NeverAsked,
    Yes,
    No,
}

impl Consent {
    /// Whether the periodic check may run at all. Only an explicit yes.
    pub fn permits_checking(self) -> bool {
        matches!(self, Consent::Yes)
    }

    /// Whether the window should put the question. Only *never asked* --
    /// a person who declined is not asked a second time.
    pub fn should_ask(self) -> bool {
        matches!(self, Consent::NeverAsked)
    }
}

/// What `~/.config/porthole/update.toml` holds.
///
/// Both fields are optional, and an absent file parses as this default: that
/// is what makes "never asked" the state of a machine nobody has asked
/// anything on, rather than something that has to be written down first.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settings {
    /// `"yes"` or `"no"`; absent, or anything else, is [`Consent::NeverAsked`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consent: Option<String>,
    /// The available version last announced, so a notification appears once
    /// per version and not once per check. Cleared the moment a check finds
    /// nothing to install -- see [`Settings::record_announced`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub announced: Option<String>,
}

/// What a notification is remembered by when the manager's listing named no
/// version. It is not a version and does not pretend to be one: it is the
/// key that makes one continuous run of "an update is available" produce one
/// notification.
const UNVERSIONED_KEY: &str = "an update with no version porthole could read";

impl Settings {
    pub fn consent(&self) -> Consent {
        match self.consent.as_deref() {
            Some("yes") => Consent::Yes,
            Some("no") => Consent::No,
            // Absent, and also anything this build does not recognise: a
            // value porthole did not write is not a person's answer, and
            // reading it as one would either check without being told to or
            // silence a question nobody has answered. `NeverAsked` is the
            // state that asks again, which is the direction that cannot act
            // on a consent nobody gave.
            _ => Consent::NeverAsked,
        }
    }

    pub fn set_consent(&mut self, consent: Consent) {
        self.consent = match consent {
            Consent::Yes => Some("yes".to_string()),
            Consent::No => Some("no".to_string()),
            Consent::NeverAsked => None,
        };
    }

    /// Whether this verdict is worth putting on screen now, and remember that
    /// it was.
    ///
    /// `true` at most once per available version. An `UpToDate` verdict
    /// forgets what was announced, so the *next* version announces itself --
    /// which is also what makes the unversioned key above behave: one
    /// notification per continuous run of "there is something to install".
    ///
    /// Every other verdict leaves the record alone. `NoContract` and
    /// `Unknown` are not "nothing to update", and treating either as one
    /// would clear a record that is still true.
    pub fn record_announced(&mut self, verdict: &Verdict) -> bool {
        match verdict {
            Verdict::Available { version } => {
                let key = version
                    .clone()
                    .unwrap_or_else(|| UNVERSIONED_KEY.to_string());
                if self.announced.as_deref() == Some(key.as_str()) {
                    return false;
                }
                self.announced = Some(key);
                true
            }
            Verdict::UpToDate => {
                self.announced = None;
                false
            }
            Verdict::NoContract(_) | Verdict::Unknown(_) => false,
        }
    }

    /// Load the settings, or start with the default if the file is not there.
    ///
    /// A file that will not parse is **not** a failure here, unlike
    /// `devices.toml`, and the difference is what each one costs. A bad
    /// address book means opening a port towards the wrong machine, so it
    /// fails loudly and names the device. This file holds one answer to one
    /// question; refusing to start over it would take the window away from
    /// somebody whose only mistake was editing a file they were invited to
    /// edit. A file this cannot read is a machine nobody has answered for,
    /// which is where every machine starts.
    pub fn load(path: &Path) -> Settings {
        let Ok(text) = std::fs::read_to_string(path) else {
            return Settings::default();
        };
        toml::from_str(&text).unwrap_or_default()
    }

    /// Write the settings atomically -- a temporary file beside the real one,
    /// then a rename, exactly as `devices::Book::save` does and for the same
    /// reason: a crash mid-write must not leave a half-written file behind.
    pub fn save(&self, path: &Path) -> crate::error::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                Error::Unexpected(format!("could not create {}: {e}", parent.display()))
            })?;
        }
        let text = toml::to_string_pretty(self)
            .map_err(|e| Error::Unexpected(format!("could not serialise update.toml: {e}")))?;
        let temp = path.with_extension("toml.tmp");
        std::fs::write(&temp, &text)
            .map_err(|e| Error::Unexpected(format!("could not write {}: {e}", temp.display())))?;
        std::fs::rename(&temp, path)
            .map_err(|e| Error::Unexpected(format!("could not save {}: {e}", path.display())))?;
        Ok(())
    }
}

/// Where the settings live: `~/.config/porthole/update.toml`, honouring
/// `$XDG_CONFIG_HOME` -- **beside `devices.toml`**, and by the same rule, so
/// that a person who has set `$XDG_CONFIG_HOME` finds porthole's two files in
/// one place rather than one of them in their home directory.
pub fn default_path() -> PathBuf {
    default_path_from(
        std::env::var(UPDATE_FILE_ENV).ok().as_deref(),
        std::env::var("XDG_CONFIG_HOME").ok().as_deref(),
        std::env::var("HOME").ok().as_deref(),
    )
}

/// [`default_path`]'s decision, split out so it can be tested without
/// mutating process-global environment state -- `crate::devices::
/// default_path_from` is split out for the same reason and makes the same
/// decision, and `the_two_config_files_are_decided_by_one_rule` below is what
/// holds the two copies together.
fn default_path_from(
    override_value: Option<&str>,
    xdg_config_home: Option<&str>,
    home: Option<&str>,
) -> PathBuf {
    if cfg!(debug_assertions) {
        if let Some(path) = override_value {
            if !path.is_empty() {
                return PathBuf::from(path);
            }
        }
    }
    let base = match xdg_config_home {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => match home {
            Some(dir) if !dir.is_empty() => PathBuf::from(dir).join(".config"),
            _ => PathBuf::from(".config"),
        },
    };
    base.join("porthole").join("update.toml")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::Output;
    use tempfile::TempDir;

    /// A runner that answers each program with one scripted [`Output`],
    /// however often it is asked, and reports every other program as absent
    /// the way [`crate::command::RealRunner`] does.
    ///
    /// `RecordingRunner`'s own script is positional, which is the wrong shape
    /// here: `how_installed` asks up to three different programs and which of
    /// them is even present is the thing under test.
    struct Managers {
        answers: Vec<(&'static str, Result<Output, ()>)>,
        asked: std::cell::RefCell<Vec<String>>,
    }

    impl Managers {
        fn new(answers: Vec<(&'static str, Result<Output, ()>)>) -> Managers {
            Managers {
                answers,
                asked: std::cell::RefCell::new(Vec::new()),
            }
        }

        fn asked(&self) -> Vec<String> {
            self.asked.borrow().clone()
        }
    }

    impl CommandRunner for Managers {
        fn run(&self, cmd: &Command) -> crate::error::Result<Output> {
            self.asked.borrow_mut().push(cmd.display());
            match self
                .answers
                .iter()
                .find(|(program, _)| *program == cmd.program)
            {
                Some((_, Ok(out))) => Ok(out.clone()),
                Some((_, Err(()))) => Err(Error::Unexpected("the read did not answer".to_string())),
                // Not installed, which is the one failure that is proof of
                // it -- `RealRunner` reports exactly this.
                None => Err(Error::CommandSpawn {
                    command: cmd.display(),
                    source: std::io::Error::from(std::io::ErrorKind::NotFound),
                }),
            }
        }
    }

    fn exited(status: i32) -> Output {
        Output {
            status,
            stdout: String::new(),
            stderr: String::new(),
        }
    }

    const BINARY: &str = "/usr/bin/porthole";

    #[test]
    fn the_manager_that_claims_the_binary_is_the_one_porthole_asks() {
        // rpm(8): "On success, 0 is returned, a nonzero failure code
        // otherwise." An exit of 0 from `rpm -qf` is the claim.
        let runner = Managers::new(vec![("rpm", Ok(exited(0)))]);
        assert_eq!(
            how_installed(&runner, Path::new(BINARY)),
            Install::Packaged(Packaging::Rpm)
        );
        assert_eq!(
            runner.asked(),
            vec![format!("rpm -qf {BINARY}")],
            "and it stops at the one that answered: asking the others afterwards \
             would run two more subprocesses for an answer already in hand"
        );

        // dpkg-query(1): 1 is "no file or package being found", so a machine
        // with both rpm and dpkg where only dpkg claims the file is dpkg's.
        let runner = Managers::new(vec![
            ("rpm", Ok(exited(1))),
            ("dpkg-query", Ok(exited(0))),
            ("pacman", Ok(exited(0))),
        ]);
        assert_eq!(
            how_installed(&runner, Path::new(BINARY)),
            Install::Packaged(Packaging::Dpkg),
            "the first manager that claims it wins, and rpm did not claim it"
        );

        let runner = Managers::new(vec![("pacman", Ok(exited(0)))]);
        assert_eq!(
            how_installed(&runner, Path::new(BINARY)),
            Install::Packaged(Packaging::Pacman)
        );
    }

    #[test]
    fn a_manager_that_answers_and_does_not_claim_the_binary_makes_it_a_source_install() {
        // The case the whole feature is gated on: porthole must never offer
        // to overwrite a tree somebody built and installed by hand.
        let runner = Managers::new(vec![("rpm", Ok(exited(1)))]);
        assert_eq!(
            how_installed(&runner, Path::new(BINARY)),
            Install::Unpackaged
        );
    }

    #[test]
    fn no_manager_at_all_is_not_reported_as_a_source_install() {
        // "Nothing claims this binary" and "nothing could be asked" are
        // different facts, and only the first is evidence. Both stop the
        // check; collapsing them would have porthole state, about a machine
        // it learned nothing from, that porthole was built from source there.
        let runner = Managers::new(Vec::new());
        let Install::Undetermined(reason) = how_installed(&runner, Path::new(BINARY)) else {
            panic!("no manager was installed, so nothing answered either way");
        };
        assert!(reason.contains("no package manager"), "{reason}");
        assert!(reason.contains(BINARY), "{reason}");

        // And a manager that is present but whose read did not answer is the
        // same: not a claim, and not a denial either.
        let runner = Managers::new(vec![("rpm", Err(()))]);
        let Install::Undetermined(reason) = how_installed(&runner, Path::new(BINARY)) else {
            panic!("the one manager present did not answer, so nothing denied ownership");
        };
        assert!(reason.contains("rpm"), "{reason}");
    }

    #[test]
    fn the_verdict_comes_from_the_exit_code_and_not_from_the_message() {
        // The spec's own verification item: a change in the message must not
        // alter the answer. Same exit code, three unrelated listings --
        // English, an invented translation, and nothing at all.
        for stdout in [
            "porthole.x86_64    0.2.0-1.fc44    updates\n",
            "porthole.x86_64    0.2.0-1.fc44    aggiornamenti\n",
            "",
        ] {
            let runner = Managers::new(vec![(
                "dnf",
                Ok(Output {
                    status: DNF_UPDATES_AVAILABLE,
                    stdout: stdout.to_string(),
                    stderr: String::new(),
                }),
            )]);
            let verdict = check(&runner, Packaging::Rpm, PACKAGE);
            assert!(
                matches!(verdict, Verdict::Available { .. }),
                "100 is what says an update exists, whatever the listing reads: \
                 {stdout:?} gave {verdict:?}"
            );
        }

        // And the other half: text that reads exactly like an update, with
        // the exit code that says there is none.
        let runner = Managers::new(vec![(
            "dnf",
            Ok(Output {
                status: 0,
                stdout: "porthole.x86_64    0.2.0-1.fc44    updates\n".to_string(),
                stderr: String::new(),
            }),
        )]);
        assert_eq!(
            check(&runner, Packaging::Rpm, PACKAGE),
            Verdict::UpToDate,
            "0 is what says there is nothing, whatever the listing reads"
        );
    }

    #[test]
    fn a_version_is_a_label_and_an_unreadable_listing_is_still_an_update() {
        let runner = Managers::new(vec![(
            "dnf",
            Ok(Output {
                status: DNF_UPDATES_AVAILABLE,
                stdout: "\nporthole.x86_64    0.2.0-1.fc44    porthole\n".to_string(),
                stderr: String::new(),
            }),
        )]);
        assert_eq!(
            check(&runner, Packaging::Rpm, PACKAGE),
            Verdict::Available {
                version: Some("0.2.0-1.fc44".to_string())
            }
        );

        // A listing this build cannot read yields no label and the same
        // verdict. It must not become `UpToDate`, and it must not become an
        // error: the exit code already answered.
        let runner = Managers::new(vec![(
            "dnf",
            Ok(Output {
                status: DNF_UPDATES_AVAILABLE,
                stdout: "Obsoleting Packages\nsomething-else.noarch  1.0  repo\n".to_string(),
                stderr: String::new(),
            }),
        )]);
        assert_eq!(
            check(&runner, Packaging::Rpm, PACKAGE),
            Verdict::Available { version: None }
        );
    }

    #[test]
    fn an_exit_code_dnf_does_not_document_for_this_question_is_not_an_answer() {
        // dnf5(8) documents 1 for an error during processing and 2 for a
        // parsing error. Neither says anything about updates, and reading
        // either as "up to date" is the direction that goes quiet on a
        // machine that has an update waiting.
        for status in [1, 2, 127] {
            let runner = Managers::new(vec![("dnf", Ok(exited(status)))]);
            let Verdict::Unknown(reason) = check(&runner, Packaging::Rpm, PACKAGE) else {
                panic!("dnf exited {status}, which answers neither way");
            };
            assert!(reason.contains(&status.to_string()), "{reason}");
        }
    }

    #[test]
    fn apt_and_pacman_are_answered_with_the_absence_of_a_contract_not_with_up_to_date() {
        // The finding this module exists to state honestly. Neither is
        // "nothing to update": porthole has not asked, because there is no
        // documented code to read, and saying otherwise would be a claim
        // those tools never made.
        let runner = Managers::new(Vec::new());
        for packaging in [Packaging::Dpkg, Packaging::Pacman] {
            let Verdict::NoContract(reason) = check(&runner, packaging, PACKAGE) else {
                panic!("{packaging:?} has no documented exit code for this question");
            };
            assert!(
                reason.contains("exit code"),
                "the sentence has to say what is missing: {reason}"
            );
            assert!(
                !reason.contains("up to date"),
                "and must not read as an answer: {reason}"
            );
        }
        assert!(
            runner.asked().is_empty(),
            "nothing is run for an answer that could not be read: {:?}",
            runner.asked()
        );

        // Each names the documentation it was read from, so a reader can
        // check it rather than take porthole's word.
        let Verdict::NoContract(apt) = check(&runner, Packaging::Dpkg, PACKAGE) else {
            unreachable!("checked above");
        };
        assert!(apt.contains("apt-get(8)"), "{apt}");
        let Verdict::NoContract(pacman) = check(&runner, Packaging::Pacman, PACKAGE) else {
            unreachable!("checked above");
        };
        assert!(pacman.contains("pacman(8)"), "{pacman}");
        assert!(pacman.contains("checkupdates(8)"), "{pacman}");
    }

    #[test]
    fn consent_has_three_states_and_a_refusal_is_not_a_question_unasked() {
        // Telling `NeverAsked` from `No` is the whole of what stops porthole
        // asking again somebody who declined.
        assert!(Consent::NeverAsked.should_ask());
        assert!(!Consent::No.should_ask());
        assert!(!Consent::Yes.should_ask());

        // And only an explicit yes lets the check run. A machine nobody has
        // asked must not be checking.
        assert!(Consent::Yes.permits_checking());
        assert!(!Consent::NeverAsked.permits_checking());
        assert!(!Consent::No.permits_checking());
    }

    #[test]
    fn the_three_states_survive_a_round_trip_and_an_absent_file_is_never_asked() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("update.toml");

        assert_eq!(
            Settings::load(&path).consent(),
            Consent::NeverAsked,
            "a machine nobody has asked anything on"
        );

        for consent in [Consent::Yes, Consent::No, Consent::NeverAsked] {
            let mut settings = Settings::default();
            settings.set_consent(consent);
            settings.save(&path).unwrap();
            assert_eq!(Settings::load(&path).consent(), consent);
        }

        // A file that will not parse is a machine nobody has answered for,
        // not a reason to refuse to run -- see `Settings::load`.
        std::fs::write(&path, "consent = [this is not toml\n").unwrap();
        assert_eq!(Settings::load(&path).consent(), Consent::NeverAsked);

        // And a value porthole never wrote is not read as a person's answer.
        std::fs::write(&path, "consent = \"maybe\"\n").unwrap();
        assert_eq!(Settings::load(&path).consent(), Consent::NeverAsked);
    }

    #[test]
    fn a_notification_is_recorded_once_per_version_and_not_once_per_check() {
        // The spec's own verification item: two consecutive checks against
        // the same available version produce one announcement.
        let mut settings = Settings::default();
        let available = |v: &str| Verdict::Available {
            version: Some(v.to_string()),
        };

        assert!(settings.record_announced(&available("0.2.0")));
        assert!(
            !settings.record_announced(&available("0.2.0")),
            "the same version again is the same news"
        );
        assert!(
            settings.record_announced(&available("0.3.0")),
            "a different version is different news"
        );

        // An update that arrived and was installed clears the record, so the
        // *next* one announces itself.
        assert!(!settings.record_announced(&Verdict::UpToDate));
        assert_eq!(settings.announced, None);
        assert!(settings.record_announced(&available("0.3.0")));

        // Neither of the two answers that are not answers may clear it: both
        // leave a real, still-unannounced update recorded as announced, or
        // the other way round.
        let before = settings.announced.clone();
        assert!(!settings.record_announced(&Verdict::NoContract("no code".to_string())));
        assert!(!settings.record_announced(&Verdict::Unknown("dnf exited 1".to_string())));
        assert_eq!(settings.announced, before);
    }

    #[test]
    fn an_update_with_no_readable_version_is_announced_once_rather_than_daily() {
        // The unversioned key's whole job. Without it, every check of a
        // machine whose listing porthole cannot read would notify again.
        let mut settings = Settings::default();
        let unlabelled = Verdict::Available { version: None };
        assert!(settings.record_announced(&unlabelled));
        assert!(!settings.record_announced(&unlabelled));

        // And the key is not mistaken for a version somebody could read.
        assert!(settings
            .announced
            .as_deref()
            .is_some_and(|k| !k.starts_with(char::is_numeric)));
    }

    #[test]
    fn the_two_config_files_are_decided_by_one_rule() {
        // `devices.toml` and `update.toml` are two files in one directory,
        // and the rule that finds them is written out twice -- once here and
        // once in `crate::devices`, each private to its own module. This is
        // what stops the two drifting: a person who has set
        // `$XDG_CONFIG_HOME` must not find one of porthole's files there and
        // the other in their home directory.
        let devices = crate::devices::default_path();
        let update = default_path();
        assert_eq!(
            devices.parent(),
            update.parent(),
            "porthole's two config files must live in one directory"
        );
        assert_eq!(update.file_name().unwrap(), "update.toml");
    }

    #[test]
    fn default_path_prefers_xdg_config_home() {
        assert_eq!(
            default_path_from(None, Some("/x/cfg"), Some("/home/j")),
            PathBuf::from("/x/cfg/porthole/update.toml")
        );
        assert_eq!(
            default_path_from(None, None, Some("/home/j")),
            PathBuf::from("/home/j/.config/porthole/update.toml")
        );
    }

    #[cfg(debug_assertions)]
    #[test]
    fn the_update_file_override_is_honoured_in_debug_builds() {
        assert_eq!(
            default_path_from(Some("/tmp/porthole-test/update.toml"), Some("/x"), None),
            PathBuf::from("/tmp/porthole-test/update.toml")
        );
    }

    #[test]
    fn every_packaging_names_a_command_a_person_can_run() {
        // Printed wherever porthole will not act: on a `NoContract` verdict,
        // and where PackageKit is absent. A blank there leaves a person told
        // there is an update and given nothing to do about it.
        for packaging in Packaging::ALL {
            let command = packaging.manual_command();
            assert!(!command.is_empty(), "{packaging:?}");
            assert!(
                command.contains(PACKAGE) || command.contains("-Syu"),
                "{packaging:?}: {command}"
            );
        }
    }

    /// The package name porthole asks about, read out of the three packaging
    /// files that define it.
    ///
    /// Not compiled by anything, so nothing else in this workspace notices
    /// when one of them is renamed -- and a check that asks a package manager
    /// about a name no package has is a check that can only ever answer
    /// "nothing".
    #[test]
    fn the_name_porthole_asks_about_is_the_name_all_three_packages_have() {
        let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
        for (file, line) in [
            (
                "packaging/rpm/porthole.spec",
                format!("Name:           {PACKAGE}"),
            ),
            ("debian/control", format!("Package: {PACKAGE}")),
            ("packaging/aur/PKGBUILD", format!("pkgbase={PACKAGE}")),
        ] {
            let path = format!("{root}/{file}");
            let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
            assert!(
                text.lines().any(|l| l.trim_end() == line),
                "{file} has no line `{line}`, so `{PACKAGE}` is not what that package \
                 is called and porthole would ask about a name nothing provides"
            );
        }
    }
}
