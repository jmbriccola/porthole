//! The daily question, the notification it produces, and the one button on
//! it.
//!
//! What decides *whether* there is an update is
//! `porthole_core::update`, which asks the package manager that installed
//! porthole and reads its exit code. This module is the session half: when to
//! ask, what to put on screen, and what pressing the button does.
//!
//! # Nothing here gains a privilege
//!
//! The button hands the request to **PackageKit**, on the system bus, through
//! PackageKit's own `org.freedesktop.PackageKit` interface. PackageKit raises
//! its own polkit prompt under its own action -- the policy this machine
//! ships names it `org.freedesktop.packagekit.system-update`, "Authentication
//! is required to update software" -- so the password a person sees is the
//! one PackageKit asks to install any package, not one porthole invented.
//! porthole holds no privilege of its own here and asks for none.
//!
//! **The privileged porthole helper is not involved and must never be.** It
//! accepts a narrow, validated set of firewall operations and never a command
//! from a client, which is the property porthole's whole security rests on;
//! making it install packages would mean anyone who can address its bus name
//! can run code as root. The update goes through PackageKit or it does not
//! go.
//!
//! Where PackageKit is absent, the notification carries no button and the
//! exact command is what it shows instead. That is the whole of the fallback:
//! porthole does not download, does not verify signatures, does not write to
//! `/usr`, and does not ask anybody's password on its own account.

use porthole_core::update::{Install, Packaging, Verdict};
use zbus::zvariant::OwnedObjectPath;

use crate::notify::Notification;

/// The action key an "update now" click comes back as, in `ActionInvoked`'s
/// second argument. Deliberately not [`crate::notify::REOPEN`]: a click on
/// one must never be answered by the other, and the two notifications can be
/// on screen together.
pub const UPDATE_NOW: &str = "update-now";

/// How long after start-up the first check runs.
///
/// Not zero: an agent's first job is to subscribe and start announcing
/// closes, and spawning package-manager subprocesses in the same breath
/// competes with a login that is already busy. Not long either -- a person
/// who has just logged in after an upgrade is exactly who this is for.
pub const FIRST_CHECK_AFTER: std::time::Duration = std::time::Duration::from_secs(90);

/// Once a day, as the design asks. The agent is the thing that wakes for it,
/// which is also what makes the binary-mtime check below cost nothing extra.
pub const CHECK_EVERY: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);

/// Test-only override of both intervals above, in milliseconds.
///
/// Honoured in **debug builds only**, exactly as
/// `porthole_core::state::STATE_FILE_ENV` and
/// `porthole_core::update::UPDATE_FILE_ENV` are, and for the same reason: a
/// release binary must not take its behaviour from its environment. Here the
/// need is plainer than usual -- a test cannot wait a day for the second
/// tick, and cannot wait ninety seconds for the first either, and a check
/// that is never exercised end to end is a check nobody has seen work.
pub const INTERVAL_ENV: &str = "PORTHOLE_UPDATE_INTERVAL_MS";

/// How long after start-up the first check runs, honouring [`INTERVAL_ENV`].
pub fn first_check_after() -> std::time::Duration {
    interval_override().unwrap_or(FIRST_CHECK_AFTER)
}

/// How often the check runs after that, honouring [`INTERVAL_ENV`].
pub fn check_every() -> std::time::Duration {
    interval_override().unwrap_or(CHECK_EVERY)
}

/// One override for both, because a test that wants a fast first check wants
/// a fast second one too, and two variables would be two things to get
/// wrong.
///
/// A value that is not a positive number is ignored rather than treated as
/// zero: an interval of zero would spin this agent's loop at whatever speed
/// the machine allows, which is a worse answer to a malformed variable than
/// keeping the shipped one.
fn interval_override() -> Option<std::time::Duration> {
    if !cfg!(debug_assertions) {
        return None;
    }
    let raw = std::env::var(INTERVAL_ENV).ok()?;
    let millis: u64 = raw.trim().parse().ok()?;
    (millis > 0).then(|| std::time::Duration::from_millis(millis))
}

/// What to say about an update that is available.
///
/// The button is offered only where PackageKit could be reached, because a
/// button that cannot act is worse than no button: it teaches a person that
/// porthole's notifications do nothing. Where it is absent the exact command
/// goes in the body instead, which is the one thing that is always true and
/// always actionable.
pub fn available_notice(
    version: Option<&str>,
    packaging: Packaging,
    packagekit: bool,
) -> Notification {
    let subject = match version {
        Some(v) => format!("porthole {v} is available"),
        // No version rather than a guessed one. The exit code is what said an
        // update exists; the listing named nothing this build could read, and
        // inventing a number here would be porthole stating something no
        // package manager told it.
        None => "A newer porthole is available".to_string(),
    };
    let body = if packagekit {
        format!(
            "{subject}. Updating installs it through PackageKit, which will ask for a \
             password of its own — the same one it asks to install any package. porthole \
             asked your own package manager; nothing left this machine."
        )
    } else {
        format!(
            "{subject}. PackageKit is not available on this machine, so porthole cannot \
             start the update for you. Run: {}",
            packaging.manual_command()
        )
    };
    Notification {
        summary: "A porthole update is available".to_string(),
        body,
        actions: if packagekit {
            vec![(UPDATE_NOW.to_string(), "Update".to_string())]
        } else {
            Vec::new()
        },
    }
}

/// What to say when the click did not end in an installed package.
///
/// Never "updated". PackageKit reporting anything but success means the
/// machine is where it was, and a notification claiming otherwise would send
/// a person looking for a version they do not have.
pub fn update_failed_notice(detail: &str, packaging: Packaging) -> Notification {
    Notification {
        summary: "The porthole update did not go through".to_string(),
        body: format!(
            "{detail} Nothing was installed and porthole is the version it was. To do it \
             yourself: {}",
            packaging.manual_command()
        ),
        actions: Vec::new(),
    }
}

/// What to say when it did.
///
/// It says the files are new and says nothing about the running processes,
/// because that is what is known at this point: the agent re-executes itself
/// from the binary on disk once PackageKit reports success, and the helper is
/// a root service this has no way to restart.
pub fn update_succeeded_notice() -> Notification {
    Notification {
        summary: "porthole was updated".to_string(),
        body: "PackageKit reports the new porthole is installed. The notification agent \
               has started again from the new binary; a porthole window that is open is \
               still the old one until you close and reopen it."
            .to_string(),
        actions: Vec::new(),
    }
}

/// Whether this outcome is worth waking a person for, and what to say.
///
/// One function so that the four verdicts are answered in one place, and so
/// that the three that are not "there is an update" are answered the same
/// way: with nothing on screen. A daily check that announced "porthole could
/// not find out" every day would be a daily interruption reporting no news.
///
/// The journal records each of them, and that is the caller's doing rather
/// than this function's: `crate::check_for_an_update` writes one line per
/// verdict before it ever gets here. It matters most for the verdict that
/// never becomes a notification and never goes away -- on a Debian or Arch
/// machine `NoContract` is the permanent answer, and without that line the
/// daily check would be invisible as well as inert.
pub fn notice_for(install: &Install, verdict: &Verdict, packagekit: bool) -> Option<Notification> {
    let Install::Packaged(packaging) = install else {
        return None;
    };
    match verdict {
        Verdict::Available { version } => {
            Some(available_notice(version.as_deref(), *packaging, packagekit))
        }
        Verdict::UpToDate | Verdict::NoContract(_) | Verdict::Unknown(_) => None,
    }
}

/// PackageKit's own daemon interface, on the **system** bus.
///
/// Read off `/usr/share/dbus-1/interfaces/org.freedesktop.PackageKit.xml`
/// rather than transcribed from memory: `CreateTransaction` takes nothing and
/// returns the object path of a transaction.
#[zbus::proxy(
    interface = "org.freedesktop.PackageKit",
    default_service = "org.freedesktop.PackageKit",
    default_path = "/org/freedesktop/PackageKit"
)]
pub trait PackageKit {
    fn create_transaction(&self) -> zbus::Result<OwnedObjectPath>;
}

/// One PackageKit transaction.
///
/// Signatures read off
/// `/usr/share/dbus-1/interfaces/org.freedesktop.PackageKit.Transaction.xml`:
/// `GetUpdates(t filter)`, `UpdatePackages(t transaction_flags, as
/// package_ids)`, and the three signals a transaction answers through --
/// `Package(u info, s package_id, s summary)`, `ErrorCode(u code, s details)`
/// and `Finished(u exit, u runtime)`.
///
/// `default_service` only; the path is per transaction and is given at build
/// time.
#[zbus::proxy(
    interface = "org.freedesktop.PackageKit.Transaction",
    default_service = "org.freedesktop.PackageKit"
)]
pub trait PackageKitTransaction {
    fn get_updates(&self, filter: u64) -> zbus::Result<()>;

    fn update_packages(&self, transaction_flags: u64, package_ids: &[&str]) -> zbus::Result<()>;

    #[zbus(signal)]
    fn package(&self, info: u32, package_id: &str, summary: &str) -> zbus::Result<()>;

    #[zbus(signal)]
    fn error_code(&self, code: u32, details: &str) -> zbus::Result<()>;

    #[zbus(signal)]
    fn finished(&self, exit: u32, runtime: u32) -> zbus::Result<()>;
}

/// PackageKit's `PK_FILTER_ENUM_NONE`: ask for everything and filter here.
/// porthole wants one package by name, and no filter bit says that.
const FILTER_NONE: u64 = 0;

/// PackageKit's `PK_TRANSACTION_FLAG_ENUM_NONE`. Deliberately not
/// `ONLY_TRUSTED`: that flag is PackageKit's own default policy to apply, and
/// porthole overriding it either way would be porthole having an opinion
/// about signature trust, which is exactly what this design refuses to take
/// on. Whatever the distribution configured is what happens.
const FLAGS_NONE: u64 = 0;

/// PackageKit's `PK_EXIT_ENUM_SUCCESS`.
const EXIT_SUCCESS: u32 = 1;

/// The name half of a PackageKit `package_id`, which is
/// `name;version;arch;data`.
fn package_id_name(package_id: &str) -> &str {
    package_id.split(';').next().unwrap_or(package_id)
}

/// PackageKit's well-known name, asked about by name below rather than
/// addressed.
const PACKAGEKIT_NAME: &str = "org.freedesktop.PackageKit";

/// Whether PackageKit is there at all, **without starting it**.
///
/// This is asked once a day, on a machine where nothing may have happened, to
/// decide one thing: whether the notification carries a button or a command.
/// So it must not be a call to PackageKit. An earlier draft made it one --
/// building the proxy and introspecting it -- and that is not a question, it
/// is an activation: PackageKit is a D-Bus activated **root** service, so
/// merely asking whether it exists would have started a privileged daemon on
/// a timer, on an idle machine, to draw a button. Measured while writing the
/// tests for this file, where the same call started this machine's
/// session-bus provider of that name (`gnome-software`) on a throwaway bus.
///
/// The bus's own directory is what answers instead: a name somebody owns
/// right now, or one the daemon is configured to start on demand. Both are
/// reads of the bus daemon's own tables and start nothing.
pub async fn is_available(system: &zbus::Connection) -> bool {
    let Ok(dbus) = zbus::fdo::DBusProxy::new(system).await else {
        return false;
    };
    let Ok(name) = zbus::names::BusName::try_from(PACKAGEKIT_NAME) else {
        return false;
    };
    if dbus.name_has_owner(name).await.unwrap_or(false) {
        return true;
    }
    dbus.list_activatable_names()
        .await
        .map(|names| names.iter().any(|n| n.as_str() == PACKAGEKIT_NAME))
        .unwrap_or(false)
}

/// What a click on the button did.
pub enum Outcome {
    Installed,
    /// PackageKit was reached and the update did not happen. Carries what it
    /// said, for the notification to repeat verbatim.
    Failed(String),
}

/// Hand the update to PackageKit and wait for it to finish.
///
/// Two transactions, because PackageKit's own interface is two calls: one to
/// learn the `package_id` of the update -- `UpdatePackages` takes ids, not
/// names -- and one to install it. Each is a fresh transaction, which is what
/// `CreateTransaction`'s own documentation asks for.
///
/// The polkit prompt happens inside the second one, raised by PackageKit
/// under PackageKit's own action. porthole neither raises it nor can skip it.
pub async fn install(system: &zbus::Connection, package: &str) -> Result<Outcome, String> {
    let daemon = PackageKitProxy::new(system)
        .await
        .map_err(|e| format!("could not reach PackageKit: {e}"))?;

    let ids = updates_for(system, &daemon, package).await?;
    if ids.is_empty() {
        // Between the check and the click, the update stopped being
        // available -- somebody else installed it, or the repository moved.
        // Not a failure of the click, and not a success either.
        return Ok(Outcome::Failed(format!(
            "PackageKit no longer lists an update for {package}."
        )));
    }

    let path = daemon
        .create_transaction()
        .await
        .map_err(|e| format!("PackageKit would not start a transaction: {e}"))?;
    let transaction = transaction_at(system, &path).await?;
    let mut errors = transaction
        .receive_error_code()
        .await
        .map_err(|e| format!("could not listen to PackageKit's transaction: {e}"))?;
    let mut finished = transaction
        .receive_finished()
        .await
        .map_err(|e| format!("could not listen to PackageKit's transaction: {e}"))?;

    let borrowed: Vec<&str> = ids.iter().map(String::as_str).collect();
    // This is the call polkit gates. A refusal comes back as an error here or
    // as an `ErrorCode` below, depending on how PackageKit was configured;
    // both end as `Failed`, and neither is reported as an update.
    transaction
        .update_packages(FLAGS_NONE, &borrowed)
        .await
        .map_err(|e| format!("PackageKit refused the update: {e}"))?;

    // Wait for the transaction to end, and say which way it ended.
    //
    // An `ErrorCode` is remembered rather than returned at once: PackageKit
    // sends it *and then* `Finished`, and a caller that returned on the first
    // would leave a transaction it started still running.
    //
    // Written here rather than in a function of its own so that nothing has
    // to name the signal-stream types zbus generates for the proxy above --
    // the streams are built before `UpdatePackages` is called, which is the
    // ordering that matters, and inlining is what keeps that ordering
    // visible in one place.
    use futures_util::StreamExt as _;
    let mut reported: Option<String> = None;
    loop {
        tokio::select! {
            biased;
            Some(signal) = errors.next() => {
                if let Ok(args) = signal.args() {
                    reported = Some(args.details.to_string());
                }
            }
            signal = finished.next() => {
                let Some(signal) = signal else {
                    return Err(
                        "PackageKit's connection ended before the update finished".to_string()
                    );
                };
                let exit = signal.args().map(|a| *a.exit()).unwrap_or(0);
                if exit == EXIT_SUCCESS && reported.is_none() {
                    return Ok(Outcome::Installed);
                }
                return Ok(Outcome::Failed(reported.unwrap_or_else(|| format!(
                    "PackageKit ended the transaction with status {exit}, which is not \
                     success."
                ))));
            }
        }
    }
}

/// The `package_id`s PackageKit has for `package`, if any.
async fn updates_for(
    system: &zbus::Connection,
    daemon: &PackageKitProxy<'_>,
    package: &str,
) -> Result<Vec<String>, String> {
    use futures_util::StreamExt as _;

    let path = daemon
        .create_transaction()
        .await
        .map_err(|e| format!("PackageKit would not start a transaction: {e}"))?;
    let transaction = transaction_at(system, &path).await?;
    let mut packages = transaction
        .receive_package()
        .await
        .map_err(|e| format!("could not listen to PackageKit's transaction: {e}"))?;
    let mut errors = transaction
        .receive_error_code()
        .await
        .map_err(|e| format!("could not listen to PackageKit's transaction: {e}"))?;
    let mut finished = transaction
        .receive_finished()
        .await
        .map_err(|e| format!("could not listen to PackageKit's transaction: {e}"))?;

    transaction
        .get_updates(FILTER_NONE)
        .await
        .map_err(|e| format!("PackageKit would not list updates: {e}"))?;

    let mut ids: Vec<String> = Vec::new();
    loop {
        tokio::select! {
            biased;
            Some(signal) = packages.next() => {
                let Ok(args) = signal.args() else { continue };
                if package_id_name(args.package_id) == package {
                    ids.push(args.package_id.to_string());
                }
            }
            Some(signal) = errors.next() => {
                let detail = signal
                    .args()
                    .map(|a| a.details.to_string())
                    .unwrap_or_else(|_| "PackageKit reported an error".to_string());
                return Err(detail);
            }
            signal = finished.next() => {
                // The stream ending is the connection ending; either way
                // there is nothing more coming.
                let _ = signal;
                break;
            }
        }
    }
    Ok(ids)
}

async fn transaction_at(
    system: &zbus::Connection,
    path: &OwnedObjectPath,
) -> Result<PackageKitTransactionProxy<'static>, String> {
    PackageKitTransactionProxy::builder(system)
        .path(path.clone())
        .map_err(|e| format!("PackageKit gave a transaction path that is not one: {e}"))?
        .build()
        .await
        .map_err(|e| format!("could not bind PackageKit's transaction: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_version_that_could_not_be_read_is_not_invented() {
        // The exit code said there is an update; the listing named nothing
        // this build could read. Putting a number here that no package
        // manager gave would be porthole stating a version that may not
        // exist.
        let unlabelled = available_notice(None, Packaging::Rpm, true);
        assert!(
            unlabelled.body.contains("A newer porthole is available"),
            "{}",
            unlabelled.body
        );
        assert!(
            !unlabelled.body.contains("0."),
            "no version number may appear: {}",
            unlabelled.body
        );

        let labelled = available_notice(Some("0.2.0-1.fc44"), Packaging::Rpm, true);
        assert!(labelled.body.contains("0.2.0-1.fc44"), "{}", labelled.body);
    }

    #[test]
    fn the_button_appears_only_where_something_can_answer_it() {
        // A button that cannot act teaches a person that porthole's
        // notifications do nothing. Without PackageKit the exact command
        // goes in the body instead, which is always true and always
        // actionable.
        let with = available_notice(Some("0.2.0"), Packaging::Rpm, true);
        assert_eq!(
            with.actions,
            vec![(UPDATE_NOW.to_string(), "Update".to_string())]
        );
        assert!(
            !with.body.contains("dnf upgrade"),
            "the button is what to do here, not a command to retype: {}",
            with.body
        );

        let without = available_notice(Some("0.2.0"), Packaging::Rpm, false);
        assert!(without.actions.is_empty());
        assert!(
            without.body.contains("sudo dnf upgrade porthole"),
            "the exact command, since there is no button: {}",
            without.body
        );

        // And each packaging shows its own command rather than one spelling
        // for all three.
        for packaging in Packaging::ALL {
            let notice = available_notice(None, packaging, false);
            assert!(
                notice.body.contains(packaging.manual_command()),
                "{packaging:?}: {}",
                notice.body
            );
        }
    }

    #[test]
    fn the_update_key_is_not_the_reopen_key() {
        // Both notifications can be on screen at once, and a click carries
        // only a key. If these collided, pressing "Update" would reopen a
        // firewall port.
        assert_ne!(UPDATE_NOW, crate::notify::REOPEN);
    }

    #[test]
    fn only_an_available_update_is_worth_waking_somebody_for() {
        let packaged = Install::Packaged(Packaging::Rpm);
        assert!(notice_for(
            &packaged,
            &Verdict::Available {
                version: Some("0.2.0".to_string())
            },
            true
        )
        .is_some());

        // The three that are not news, each of which a daily check would
        // otherwise announce every day.
        for verdict in [
            Verdict::UpToDate,
            Verdict::NoContract("apt documents no exit code".to_string()),
            Verdict::Unknown("dnf exited 1".to_string()),
        ] {
            assert!(
                notice_for(&packaged, &verdict, true).is_none(),
                "{verdict:?} is not something to interrupt a person with"
            );
        }

        // And a source install is offered nothing at all, whatever a verdict
        // might say -- porthole must never propose replacing a tree it did
        // not install.
        for install in [
            Install::Unpackaged,
            Install::Undetermined("no package manager".to_string()),
        ] {
            assert!(
                notice_for(
                    &install,
                    &Verdict::Available {
                        version: Some("0.2.0".to_string())
                    },
                    true
                )
                .is_none(),
                "{install:?} must be offered nothing"
            );
        }
    }

    #[test]
    fn a_failed_update_never_reads_as_a_successful_one() {
        let failed = update_failed_notice("PackageKit said no.", Packaging::Dpkg);
        assert!(failed.summary.contains("did not go through"), "{failed:?}");
        assert!(
            failed.body.contains("Nothing was installed"),
            "{}",
            failed.body
        );
        assert!(
            failed.body.contains("apt-get"),
            "and it hands over the command: {}",
            failed.body
        );
        assert!(failed.actions.is_empty());

        let ok = update_succeeded_notice();
        assert_ne!(ok.summary, failed.summary);
        assert!(
            ok.body.contains("still the old one"),
            "an open window is not restarted by any of this, and the notice says so: {}",
            ok.body
        );
    }

    #[test]
    fn a_package_id_is_split_on_its_own_separator() {
        // PackageKit's ids are `name;version;arch;data`, and matching on a
        // prefix instead would let `porthole-gui` answer for `porthole`.
        assert_eq!(
            package_id_name("porthole;0.2.0-1.fc44;x86_64;updates"),
            "porthole"
        );
        assert_eq!(
            package_id_name("porthole-gui;0.2.0-1.fc44;x86_64;updates"),
            "porthole-gui"
        );
        assert_ne!(
            package_id_name("porthole-gui;0.2.0;x86_64;updates"),
            "porthole"
        );
        // A malformed id is itself, not a panic.
        assert_eq!(package_id_name("porthole"), "porthole");
    }
}
